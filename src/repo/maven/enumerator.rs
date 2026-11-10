//! Enumerating a Maven repository through its directory autoindex.
//!
//! ```text
//!   GET {base}/                         org/  com/
//!   GET {base}/org/example/             lib/
//!   GET {base}/org/example/lib/         1.0/  1.1-SNAPSHOT/  maven-metadata.xml
//!   GET {base}/org/example/lib/maven-metadata.xml
//!   GET {base}/org/example/lib/1.0/     lib-1.0.jar  lib-1.0.pom  ...
//! ```
//!
//! Host-agnostic: any server answering a directory with an HTML index of
//! links will do. **Never Maven Central**, whose terms forbid enumerating
//! its catalog; a Central host is refused when the enumerator is opened.
//!
//! # What makes a directory an artifact
//!
//! Its own `maven-metadata.xml`, naming the directory as its
//! `artifactId`. A snapshot version directory and a plugin group hold one
//! too, and neither names itself; see `metadata::parse_artifact_index`.
//! The versions are those the document lists, each one directory below.
//!
//! **A version the document forgot is still listed.** Metadata goes stale
//! when a version is deployed by hand, so a child directory the document
//! does not list, holding `{artifact}-{child}.pom`, is a version too, and
//! reported as unlisted. Somebody migrating every version should get every
//! version. Snapshots are listed like any other version, with every
//! timestamped build their directory holds.
//!
//! # Cursors
//!
//! The cursor is the path of the last directory the walk emitted, such as
//! `org/example/lib`. A walk resumes by listing from the root again and
//! descending along that path, skipping every child that sorts before it.
//! Nothing held grows with the repository -- only one directory's children
//! per level of depth -- and a cursor survives a restart, at the cost of
//! re-listing a handful of directories the host cache already holds.
//!
//! # What a listing cannot say
//!
//! Names only: sizes sit in each server's free text, and digests are left
//! to `copy`, which fetches each file's sidecar as it verifies. There is no
//! usage data and no total.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;

use super::listing::{self, Entry};
use super::{is_safe_segment, metadata};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::maven::{LISTING_DOCUMENT, METADATA_DOCUMENT, Maven};
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{ArtifactId, EcosystemId, ListingDepth};
use crate::net::{ByteLimit, Req, encode_unreserved, normalized_base};
use crate::repo::enumerate::{Cursor, Enumerator, Found, Listed, Page};
use crate::repo::pep503;
use crate::version::VersionHandler;

/// The option bounding how many versions one page holds.
const PAGE_SIZE: &str = "page-size";

/// Versions per page when `page-size` is absent. Each is one request.
const DEFAULT_PAGE_SIZE: usize = 100;

/// One directory's index. A group directory can list thousands of
/// children, so this is well past a version directory's.
const INDEX_LIMIT: ByteLimit = ByteLimit::mib(8);

/// How deep the walk descends. Real group paths are a handful of segments;
/// the cap stops a server whose index links a directory to itself.
const MAX_DEPTH: usize = 32;

/// What separates a cursor's segments, as a path does.
const SEPARATOR: char = '/';

/// The hosts serving Maven Central, which must not be enumerated.
const CENTRAL_HOSTS: [&str; 3] = [
    "repo1.maven.org",
    "repo.maven.apache.org",
    "central.sonatype.com",
];

pub struct MavenIndexEnumerator {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,

    /// Versions a page holds before it ends at the next artifact boundary.
    page_size: usize,

    ecosystems: [EcosystemId; 1],
}

/// One directory on the walk's path, and the children still to visit.
struct Frame {
    path: Vec<String>,

    /// Sorted, so a cursor can find its place again.
    children: Vec<String>,
    next: usize,

    /// The artifact this directory is, when it is one: an unlisted child
    /// holding its POM is then a version.
    artifact: Option<String>,
}

/// One directory's index, decoded.
#[derive(Debug, Default)]
struct Index {
    files: Vec<String>,

    /// Sorted and without repeats.
    children: Vec<String>,
}

/// What one directory is to the walk.
enum Visit {
    /// An artifact directory, its versions, and the children left to walk.
    Artifact {
        versions: Vec<String>,
        children: Vec<String>,
    },

    /// A version directory its artifact's metadata did not list.
    Unlisted { files: Vec<String> },

    /// Anything else; only its children matter.
    Other { children: Vec<String> },
}

impl MavenIndexEnumerator {
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let base_url = normalized_base(base_url);
        let page_size = Self::check(&base_url, options)?;

        Ok(Self {
            base_url,
            host,
            page_size,
            ecosystems: [EcosystemId::maven()],
        })
    }

    /// Refuse a Central host or a bad `page-size` without opening, for
    /// `validate-config`; the page size on success.
    pub(crate) fn check(base_url: &str, options: &Options) -> Result<usize> {
        if is_central(base_url) {
            return Err(Error::Config(format!(
                "the maven-html-index enumerator may not walk {base_url}: Maven Central's \
                 terms forbid enumerating its catalog"
            )));
        }

        match options.integer(PAGE_SIZE)? {
            None => Ok(DEFAULT_PAGE_SIZE),
            Some(size) => usize::try_from(size)
                .ok()
                .filter(|size| *size > 0)
                .ok_or_else(|| {
                    Error::Config(format!("{PAGE_SIZE:?} must be at least 1, not {size}"))
                }),
        }
    }

    /// `{base}/{segments}/`, with the trailing `/` an autoindex answers on.
    fn dir_url(&self, path: &[String]) -> String {
        let mut url = format!("{}/", self.base_url);

        for segment in path {
            url.push_str(&encode_unreserved(segment));
            url.push(SEPARATOR);
        }

        url
    }

    /// One directory's index; `None` when it is gone.
    async fn index(&self, path: &[String], ctx: &Ctx) -> Result<Option<Index>> {
        let url = self.dir_url(path);

        let body = match crate::ext::document(
            &*self.host,
            &Req::get(&url),
            LISTING_DOCUMENT,
            INDEX_LIMIT,
            ctx,
        )
        .await
        {
            // HTTP 404: no such directory.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                return Ok(None);
            }
            other => other?,
        };

        let html = String::from_utf8_lossy(&body);
        let links = pep503::links(&html).map_err(|detail| Error::Malformed {
            what: "maven directory index",
            url: url.clone(),
            detail,
        })?;

        let mut index = Index::default();

        for link in &links {
            // Some servers link a child by its whole URL.
            let href = link.href.strip_prefix(url.as_str()).unwrap_or(&link.href);

            match listing::entry(href) {
                Some(Entry::File(name)) => index.files.extend(segment(name)),
                Some(Entry::Directory(name)) => index.children.extend(segment(name)),
                None => {}
            }
        }

        index.children.sort();
        index.children.dedup();

        Ok(Some(index))
    }

    /// What the directory at `path` is. `parent` is the artifact its
    /// parent is, if any.
    async fn visit(&self, path: &[String], parent: Option<&str>, ctx: &Ctx) -> Result<Visit> {
        let Some(index) = self.index(path, ctx).await? else {
            return Ok(Visit::Other {
                children: Vec::new(),
            });
        };

        let name = path.last().map(String::as_str).unwrap_or_default();

        // `lib/1.2/lib-1.2.pom`: a version the metadata never named.
        if let Some(artifact) = parent {
            let pom = format!("{artifact}-{name}.pom");

            if index.files.contains(&pom) {
                return Ok(Visit::Unlisted { files: index.files });
            }
        }

        // An artifact needs a group above it.
        let held = index.files.iter().any(|file| file == METADATA_DOCUMENT);

        if !held || path.len() < 2 {
            return Ok(Visit::Other {
                children: index.children,
            });
        }

        let Some(listed) = self.artifact_versions(path, name, ctx).await? else {
            return Ok(Visit::Other {
                children: index.children,
            });
        };

        // Listed versions are emitted from the metadata; every other child
        // is walked, and may be an unlisted version or a nested artifact.
        let (versions, children) = index
            .children
            .into_iter()
            .partition(|child| listed.contains(child));

        Ok(Visit::Artifact { versions, children })
    }

    /// The versions the directory's `maven-metadata.xml` lists, or `None`
    /// when the document is not an artifact's.
    async fn artifact_versions(
        &self,
        path: &[String],
        name: &str,
        ctx: &Ctx,
    ) -> Result<Option<Vec<String>>> {
        let url = format!("{}{METADATA_DOCUMENT}", self.dir_url(path));

        let body = match crate::ext::document(
            &*self.host,
            &Req::get(&url),
            METADATA_DOCUMENT,
            ByteLimit::METADATA,
            ctx,
        )
        .await
        {
            // HTTP 404: no such directory.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                return Ok(None);
            }
            other => other?,
        };

        // A malformed document is one directory's problem, not the walk's:
        // its children are still walked.
        match metadata::parse_artifact_index(&String::from_utf8_lossy(&body), name) {
            Ok(versions) => Ok(versions),

            Err(detail) => {
                ctx.report(
                    Code::MetadataMalformed,
                    message!(
                        "maven-index-metadata-malformed",
                        "{url} could not be read ({detail}); the directory is walked \
                         as a plain directory",
                        url = &url,
                        detail = &detail,
                    ),
                );

                Ok(None)
            }
        }
    }

    /// One version directory's artifact, or `None` when it is gone.
    async fn version(&self, path: &[String], version: &str, ctx: &Ctx) -> Result<Option<Found>> {
        let mut at = path.to_vec();
        at.push(version.to_owned());

        let Some(index) = self.index(&at, ctx).await? else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "maven-index-version-missing",
                    "{url} lists version {version}, which has no directory; it is skipped",
                    url = &self.dir_url(path),
                    version = version,
                ),
            );

            return Ok(None);
        };

        Ok(self.found(&at, index.files))
    }

    /// The artifact a version directory at `path` holds `files` for;
    /// `None` without a group, artifact, and version in the path.
    fn found(&self, path: &[String], files: Vec<String>) -> Option<Found> {
        let [group @ .., artifact, version] = path else {
            return None;
        };

        if group.is_empty() {
            return None;
        }

        let id = ArtifactId::new(EcosystemId::maven(), Some(&group.join(".")), artifact);
        let url = self.dir_url(path);

        // Sidecars, `_remote.repositories`, and `maven-metadata.xml` are
        // listed, and left out by `repo::Omit`, which wraps every
        // enumerator.
        let listed = files
            .into_iter()
            .map(|name| Listed {
                url: format!("{url}{}", encode_unreserved(&name)),
                name,
                size: None,
                digests: Vec::new(),
            })
            .collect();

        Some(Found::new(id).version(Maven.version(version)).files(listed))
    }

    /// The walk's stack, positioned just after `cursor`'s directory has
    /// been emitted: inside it, at its first child.
    async fn resume(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Vec<Frame>> {
        let segments: Vec<&str> = match cursor {
            Some(cursor) => cursor.as_str().split(SEPARATOR).collect(),
            None => Vec::new(),
        };

        if segments.iter().any(|segment| !is_safe_segment(segment)) {
            return Err(Error::Config(format!(
                "cursor {} was not issued by the maven-html-index enumerator",
                cursor.map(Cursor::as_str).unwrap_or_default()
            )));
        }

        let mut stack = vec![self.frame(Vec::new(), None, ctx).await?];

        for segment in segments {
            let Some(top) = stack.last_mut() else {
                break;
            };

            let at = top
                .children
                .partition_point(|child| child.as_str() < segment);
            let exact = top.children.get(at).is_some_and(|child| child == segment);

            // Gone since the cursor was issued: continue with whatever now
            // sorts after it.
            top.next = if exact { at + 1 } else { at };

            if !exact {
                break;
            }

            let mut path = top.path.clone();
            path.push(segment.to_owned());

            let parent = top.artifact.clone();
            stack.push(self.frame(path, parent.as_deref(), ctx).await?);
        }

        Ok(stack)
    }

    /// The frame for a directory already emitted, or not worth emitting.
    async fn frame(&self, path: Vec<String>, parent: Option<&str>, ctx: &Ctx) -> Result<Frame> {
        let (children, artifact) = match self.visit(&path, parent, ctx).await? {
            Visit::Artifact { children, .. } => (children, path.last().cloned()),
            Visit::Unlisted { .. } => (Vec::new(), None),
            Visit::Other { children } => (children, None),
        };

        Ok(Frame {
            path,
            children,
            next: 0,
            artifact,
        })
    }
}

#[async_trait]
impl Enumerator for MavenIndexEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        &self.ecosystems
    }

    fn depth(&self) -> ListingDepth {
        ListingDepth::Files
    }

    /// Depth first, each directory's children in name order, until a page
    /// holds `page-size` versions. A page ends only after a whole
    /// directory, so an artifact is never split across two.
    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        let mut stack = self.resume(cursor, ctx).await?;
        let mut found = Vec::new();

        loop {
            let Some(top) = stack.last_mut() else {
                return Ok(Page::last(found));
            };

            let Some(child) = top.children.get(top.next).cloned() else {
                stack.pop();
                continue;
            };

            top.next += 1;

            let mut path = top.path.clone();
            path.push(child);

            if path.len() > MAX_DEPTH {
                ctx.report(
                    Code::MetadataMalformed,
                    message!(
                        "maven-index-too-deep",
                        "{url} is more than {depth} directories deep; it is skipped",
                        url = &self.dir_url(&path),
                        depth = MAX_DEPTH,
                    ),
                );

                continue;
            }

            let parent = top.artifact.clone();
            let before = found.len();

            let (children, artifact) = match self.visit(&path, parent.as_deref(), ctx).await? {
                Visit::Artifact { versions, children } => {
                    for version in &versions {
                        found.extend(self.version(&path, version, ctx).await?);
                    }

                    (children, path.last().cloned())
                }

                Visit::Unlisted { files } => {
                    ctx.report(
                        Code::MetadataMalformed,
                        message!(
                            "maven-index-version-unlisted",
                            "{url} holds a version its artifact's maven-metadata.xml does \
                             not list; it is listed anyway",
                            url = &self.dir_url(&path),
                        ),
                    );

                    found.extend(self.found(&path, files));

                    (Vec::new(), None)
                }

                Visit::Other { children } => (children, None),
            };

            let emitted = found.len() > before;
            let full = found.len() >= self.page_size;
            let cursor = path.join("/");

            stack.push(Frame {
                path,
                children,
                next: 0,
                artifact,
            });

            if emitted && full {
                return Ok(Page::more(found, Cursor::new(cursor)));
            }
        }
    }
}

/// A link's name, percent-decoded, or `None` when it could never be a
/// coordinate part.
fn segment(text: &str) -> Option<String> {
    let decoded = percent_decoded(text)?;

    is_safe_segment(&decoded).then_some(decoded)
}

/// `%2B` as `+`. `None` for a malformed escape or a result that is not
/// UTF-8.
fn percent_decoded(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_owned());
    }

    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;

    while at < bytes.len() {
        if bytes[at] != b'%' {
            out.push(bytes[at]);
            at += 1;
            continue;
        }

        let hex = text.get(at + 1..at + 3)?;
        out.push(u8::from_str_radix(hex, 16).ok()?);
        at += 3;
    }

    String::from_utf8(out).ok()
}

/// Whether `base_url` is one of Maven Central's hosts.
fn is_central(base_url: &str) -> bool {
    let after_scheme = base_url
        .split_once("://")
        .map_or(base_url, |(_, rest)| rest);

    let authority = after_scheme.split(SEPARATOR).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = host
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    CENTRAL_HOSTS.contains(&host.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{TestHost, options};
    use crate::model::Cause;
    use crate::net::FixtureClient;

    const BASE: &str = "h://maven.test/repo";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "walk".into() })
    }

    /// An autoindex page linking each name, with a parent link and a sort
    /// control as real servers send.
    fn index(names: &[&str]) -> String {
        let links: String = names
            .iter()
            .map(|name| format!("<a href=\"{name}\">{name}</a>\n"))
            .collect();

        format!(
            "<html><body><a href=\"../\">../</a><a href=\"?C=N;O=D\">Name</a>{links}</body></html>"
        )
    }

    fn metadata(artifact: &str, versions: &[&str]) -> String {
        let versions: String = versions
            .iter()
            .map(|version| format!("<version>{version}</version>"))
            .collect();

        format!(
            "<metadata><groupId>org.example</groupId><artifactId>{artifact}</artifactId>\
             <versioning><versions>{versions}</versions></versioning></metadata>"
        )
    }

    /// `org/example/lib` at 1.0 and 1.1-SNAPSHOT, with 1.2 deployed by
    /// hand, and `org/example/tool` at 2.0.
    fn tree() -> FixtureClient {
        FixtureClient::new()
            .with_body(format!("{BASE}/"), index(&["org/", "readme.txt"]))
            .with_body(format!("{BASE}/org/"), index(&["example/"]))
            .with_body(
                format!("{BASE}/org/example/"),
                index(&["lib/", "tool/", "maven-metadata.xml"]),
            )
            .with_body(
                format!("{BASE}/org/example/maven-metadata.xml"),
                "<metadata><plugins/></metadata>",
            )
            .with_body(
                format!("{BASE}/org/example/lib/"),
                index(&["1.0/", "1.1-SNAPSHOT/", "1.2/", "maven-metadata.xml"]),
            )
            .with_body(
                format!("{BASE}/org/example/lib/maven-metadata.xml"),
                metadata("lib", &["1.0", "1.1-SNAPSHOT"]),
            )
            .with_body(
                format!("{BASE}/org/example/lib/1.0/"),
                index(&[
                    "lib-1.0.jar",
                    "lib-1.0.jar.sha1",
                    "lib-1.0.pom",
                    "lib-1.0-sources.jar",
                    "_remote.repositories",
                    "maven-metadata.xml",
                ]),
            )
            .with_body(
                format!("{BASE}/org/example/lib/1.1-SNAPSHOT/"),
                index(&[
                    "lib-1.1-20240101.120000-1.jar",
                    "lib-1.1-20240102.120000-2.jar",
                    "maven-metadata.xml",
                ]),
            )
            .with_body(
                format!("{BASE}/org/example/lib/1.2/"),
                index(&["lib-1.2.jar", "lib-1.2.pom"]),
            )
            .with_body(
                format!("{BASE}/org/example/tool/"),
                index(&["2.0/", "maven-metadata.xml"]),
            )
            .with_body(
                format!("{BASE}/org/example/tool/maven-metadata.xml"),
                metadata("tool", &["2.0"]),
            )
            .with_body(
                format!("{BASE}/org/example/tool/2.0/"),
                index(&["tool-2.0.jar"]),
            )
    }

    fn enumerator(client: FixtureClient, page_size: usize) -> MavenIndexEnumerator {
        let host = Arc::new(TestHost::allowing(client, "h://maven.test/"));

        MavenIndexEnumerator::open(
            BASE,
            &options(serde_json::json!({ PAGE_SIZE: page_size })),
            host,
        )
        .expect("opens")
    }

    fn purls(found: &[Found]) -> Vec<String> {
        found
            .iter()
            .map(|one| {
                one.id
                    .purl_at(one.version.as_ref().expect("versioned").text())
            })
            .collect()
    }

    /// Every version, the snapshot and the unlisted one included.
    #[tokio::test]
    async fn versions_every_listed() {
        let subject = enumerator(tree(), 100);
        let ctx = ctx();

        let page = subject.walk(None, &ctx).await.expect("walked");

        assert!(!page.has_more());
        assert_eq!(
            purls(&page.found),
            [
                "pkg:maven/org.example/lib@1.0",
                "pkg:maven/org.example/lib@1.1-SNAPSHOT",
                "pkg:maven/org.example/lib@1.2",
                "pkg:maven/org.example/tool@2.0",
            ]
        );
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// Sidecars and the repository's own files stay out, through the
    /// wrapper every built enumerator gets.
    #[tokio::test]
    async fn versions_files_are_artifact_files() {
        let subject = crate::repo::OmittingEnumerator::new(
            Arc::new(enumerator(tree(), 100)),
            crate::repo::Omit::default(),
        );
        let page = subject.walk(None, &ctx()).await.expect("walked");

        let names: Vec<&str> = page.found[0]
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["lib-1.0.jar", "lib-1.0.pom", "lib-1.0-sources.jar"]);
        assert_eq!(
            page.found[0].files[0].url,
            format!("{BASE}/org/example/lib/1.0/lib-1.0.jar")
        );

        // The snapshot keeps every timestamped build.
        assert_eq!(page.found[1].files.len(), 2);
    }

    /// A page ends after a whole directory, and the cursor picks up where
    /// it stopped without repeating or skipping anything.
    #[tokio::test]
    async fn cursor_resumes_walk() {
        let subject = enumerator(tree(), 1);
        let ctx = ctx();
        let mut cursor = None;
        let mut all = Vec::new();
        let mut pages = 0;

        loop {
            let page = subject.walk(cursor.as_ref(), &ctx).await.expect("walked");
            pages += 1;

            all.extend(purls(&page.found));

            let Some(next) = page.next else {
                break;
            };

            cursor = Some(next);
        }

        assert_eq!(pages, 4, "lib's two listed versions share one page");
        assert_eq!(
            all,
            [
                "pkg:maven/org.example/lib@1.0",
                "pkg:maven/org.example/lib@1.1-SNAPSHOT",
                "pkg:maven/org.example/lib@1.2",
                "pkg:maven/org.example/tool@2.0",
            ]
        );
    }

    #[tokio::test]
    async fn versions_missing_directory_skipped() {
        let client = FixtureClient::new()
            .with_body(format!("{BASE}/"), index(&["org/"]))
            .with_body(format!("{BASE}/org/"), index(&["lib/"]))
            .with_body(
                format!("{BASE}/org/lib/"),
                index(&["1.0/", "maven-metadata.xml"]),
            )
            .with_body(
                format!("{BASE}/org/lib/maven-metadata.xml"),
                metadata("lib", &["1.0"]),
            );

        let subject = enumerator(client, 100);
        let ctx = ctx();

        let page = subject.walk(None, &ctx).await.expect("walked");

        assert!(page.found.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// A segment that would escape its directory is never followed.
    #[test]
    fn unsafe_segments_dropped() {
        assert_eq!(segment("1.0"), Some("1.0".to_owned()));
        assert_eq!(segment("1.0%2B1"), Some("1.0+1".to_owned()));
        assert_eq!(segment("a%2Fb"), None);
        assert_eq!(segment("1.0 "), None);
        assert_eq!(segment("%zz"), None);
    }

    #[test]
    fn link_entries() {
        assert_eq!(listing::entry("lib/"), Some(Entry::Directory("lib")));
        assert_eq!(listing::entry("./lib/"), Some(Entry::Directory("lib")));
        assert_eq!(listing::entry("lib.jar"), Some(Entry::File("lib.jar")));
        assert_eq!(listing::entry("../"), None);
        assert_eq!(listing::entry("a/b/"), None);
        assert_eq!(listing::entry("?C=N;O=D"), None);
        assert_eq!(listing::entry("https://elsewhere/"), None);
    }

    #[test]
    fn central_refused() {
        for url in [
            "https://repo1.maven.org/maven2/",
            "https://REPO.maven.apache.org:443/maven2",
            "https://user@central.sonatype.com/",
        ] {
            assert!(is_central(url), "{url}");
        }

        assert!(!is_central("https://nexus.example.com/repository/maven/"));
    }

    #[tokio::test]
    async fn cursor_foreign_refused() {
        let subject = enumerator(tree(), 1);

        let refused = subject.walk(Some(&Cursor::new("org/../etc")), &ctx()).await;

        assert!(refused.is_err());
    }
}
