//! What a Maven version directory holds, from the server's HTML index.
//!
//! ```text
//!   GET {base}/{group path}/{artifact}/{version}/
//!   <a href="commons-lang3-3.14.0-sources.jar">commons-lang3-3.14.0-sources.jar</a>  2023-11-18 15:03  705432
//! ```
//!
//! The POM names one payload, so a source reading only the layout misses
//! classifiers (`-sources`, `-javadoc`), Gradle's `.module`, and anything
//! else published beside them.  A directory autoindex lists them all, and
//! Central, Apache, and nginx serve one.  One request per version, for an
//! artifact already being resolved, which is inspection rather than the
//! catalog enumeration Central's terms forbid.
//!
//! Names only.  Sizes sit in the page's free text in a server-specific
//! layout, and digests are left to `copy`, which fetches each file's
//! sidecar when it verifies, exactly as it does for the payload.
//!
//! Snapshots ask nothing: the directory holds every timestamped build, and
//! `ManagedSource` adds no files to one.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cache::Coalesced;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, FileRef, Version};
use crate::net::{ByteLimit, Req, encode_unreserved};
use crate::repo::manager::{Lister, Listing};
use crate::repo::pep503;

/// One version directory's index.
const INDEX_LIMIT: ByteLimit = ByteLimit::mib(1);

pub(super) struct IndexLister {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,

    /// File names from version directory indexes, keyed by URL. Coalesced
    /// so tasks resolving one version at once share one fetch.
    names: Coalesced<Vec<String>>,
}

impl IndexLister {
    pub(super) fn new(base_url: String, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url,
            host,
            names: Coalesced::new(super::DOCUMENT_CACHE),
        }
    }

    /// The file names one version directory's index lists; none when there
    /// is no directory.
    async fn names(&self, url: &str, ctx: &Ctx) -> Result<Arc<Vec<String>>> {
        self.names
            .get_or_try_init(url, || async {
                let body = match crate::ext::document(
                    &*self.host,
                    &Req::get(url),
                    crate::ecosystem::maven::LISTING_DOCUMENT,
                    INDEX_LIMIT,
                    ctx,
                )
                .await
                {
                    // No such directory. A 404 with a retry time is a
                    // throttle, not an absence, and stays an error: read as
                    // empty, the copy would silently drop the files it lists.
                    Err(err) if err.code() == Code::ArtifactNotFound => {
                        return Ok(Vec::new());
                    }
                    other => other?,
                };

                let html = String::from_utf8_lossy(&body);
                let links = pep503::links(&html).map_err(|detail| Error::Malformed {
                    what: "maven directory index",
                    url: url.to_owned(),
                    detail,
                })?;

                Ok(links
                    .iter()
                    .filter_map(|link| file_name(&link.href))
                    .map(str::to_owned)
                    .collect())
            })
            .await
    }

    /// `{base}/{group path}/{artifact}/{version}/`, with the trailing `/`
    /// an autoindex answers on.
    fn directory_url(&self, id: &ArtifactId, version: &Version) -> String {
        let path = id
            .namespace()
            .unwrap_or_default()
            .split('.')
            .chain([id.name(), version.text()])
            .map(encode_unreserved)
            .collect::<Vec<_>>()
            .join("/");

        format!("{}/{path}/", self.base_url)
    }
}

/// A link naming a file in this directory, rather than a parent, a
/// sub-directory, a sort control, or another site.
fn file_name(href: &str) -> Option<&str> {
    match entry(href)? {
        Entry::File(name) => Some(name),
        Entry::Directory(_) => None,
    }
}

/// What a directory index link names, as it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Entry<'h> {
    File(&'h str),

    /// A child directory, without its trailing `/`.
    Directory(&'h str),
}

/// A link naming a file or child directory of this directory, rather than
/// a parent, a sort control, or another site.
///
/// ```text
///   lib-1.0.jar   File        1.0/   Directory     ../   none
///   ?C=N;O=D      none        https://elsewhere/   none
/// ```
pub(super) fn entry(href: &str) -> Option<Entry<'_>> {
    let name = href.strip_prefix("./").unwrap_or(href);

    let elsewhere =
        name.is_empty() || name.contains(':') || name.starts_with('?') || name.starts_with('#');

    if elsewhere {
        return None;
    }

    let Some(directory) = name.strip_suffix('/') else {
        return (!name.contains('/')).then_some(Entry::File(name));
    };

    let child =
        !directory.is_empty() && !directory.contains('/') && directory != "." && directory != "..";

    child.then_some(Entry::Directory(directory))
}

#[async_trait]
impl Lister for IndexLister {
    /// `maven-metadata.xml` is the index of versions; a directory listing
    /// adds nothing to it.
    async fn versions(&self, _: &ArtifactId, _: &Ctx) -> Result<Option<Vec<String>>> {
        Ok(None)
    }

    async fn listing(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Result<Listing> {
        let mut listing = Listing {
            files: Vec::new(),
            published: None,
        };

        if crate::ecosystem::maven::is_snapshot(version.text()) {
            return Ok(listing);
        }

        let url = self.directory_url(id, version);

        for name in self.names(&url, ctx).await?.iter() {
            // Taken as written: Maven file names are plain ASCII, so the
            // href is both the name and the path that serves it.
            listing
                .files
                .push(FileRef::new(name, format!("{url}{name}")));
        }

        Ok(listing)
    }
}

/// Option: whether to read each version directory's HTML index for the
/// files the POM does not name.
const FILE_LISTING: &str = "file-listing";

/// The `file-listing` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileListing {
    /// The POM's payload and the POM; no extra request.
    None,

    /// Every file the version directory's autoindex lists; one request per
    /// version.
    HtmlIndex,
}

impl FileListing {
    pub(super) fn read(options: &Options) -> Result<Self> {
        match options.string(FILE_LISTING)? {
            None | Some("none") => Ok(Self::None),
            Some("html-index") => Ok(Self::HtmlIndex),

            Some(other) => Err(Error::Config(format!(
                "the maven source's {FILE_LISTING:?} option is \"none\" or \"html-index\", \
                 not {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::TestHost;
    use crate::model::{Cause, EcosystemId, Release};
    use crate::net::{Canned, FixtureClient};
    use http::StatusCode;

    const BASE: &str = "h://central.test/maven2";
    const DIR: &str = "h://central.test/maven2/org/example/lib/1.0/";

    /// A trimmed copy of what repo1.maven.org served.
    const PAGE: &str = r#"<!DOCTYPE html>
<html><head><title>Central Repository: org/example/lib/1.0</title></head>
<body><main><pre id="contents">
<a href="../">../</a>
<a href="lib-1.0-sources.jar" title="lib-1.0-sources.jar">lib-1.0-sources.jar</a>    2023-11-18 15:03    705432
<a href="lib-1.0-sources.jar.sha1" title="lib-1.0-sources.jar.sha1">lib-1.0-sources.jar.sha1</a>    2023-11-18 15:03    40
<a href="lib-1.0.jar" title="lib-1.0.jar">lib-1.0.jar</a>    2023-11-18 15:03    652584
<a href="sub/" title="sub/">sub/</a>
<a href="?C=N;O=D">Name</a>
<a href="https://elsewhere.test/">elsewhere</a>
</pre></main></body></html>"#;

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    fn lister(client: FixtureClient) -> IndexLister {
        IndexLister::new(BASE.into(), Arc::new(TestHost::new(client)))
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    #[tokio::test]
    async fn files_from_index() {
        let listing = lister(FixtureClient::new().with_body(DIR, PAGE))
            .listing(&id(), &Version::new("1.0", Release::General), &ctx())
            .await
            .expect("lists");

        let names: Vec<&str> = listing.files.iter().map(|f| f.name.as_str()).collect();

        // The sidecar is listed; `ManagedSource` drops it.
        assert_eq!(
            names,
            [
                "lib-1.0-sources.jar",
                "lib-1.0-sources.jar.sha1",
                "lib-1.0.jar"
            ]
        );
        assert_eq!(listing.files[0].url, format!("{DIR}lib-1.0-sources.jar"));
    }

    #[tokio::test]
    async fn directory_missing_lists_nothing() {
        let client = FixtureClient::new().with(DIR, Canned::status(StatusCode::NOT_FOUND));

        let listing = lister(client)
            .listing(&id(), &Version::new("1.0", Release::General), &ctx())
            .await
            .expect("lists");

        assert!(listing.files.is_empty());
    }

    /// A 404 with a retry time is Central throttling, not a missing
    /// directory: read as empty, the copy would drop the files it lists.
    #[tokio::test]
    async fn index_throttled_is_error() {
        let throttled = Canned::status(StatusCode::NOT_FOUND).header("retry-after", "120");
        let client = FixtureClient::new().with(DIR, throttled);

        let listed = lister(client)
            .listing(&id(), &Version::new("1.0", Release::General), &ctx())
            .await;

        let Err(err) = listed else {
            panic!("a throttled index lists nothing rather than failing");
        };

        assert_eq!(err.code(), Code::HostUnreachable);
    }

    /// Listings of one version at once share one index fetch.
    #[tokio::test]
    async fn index_fetched_once() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(DIR, PAGE)));
        let lister = IndexLister::new(BASE.into(), host.clone());
        let version = Version::new("1.0", Release::General);
        let (id, ctx) = (id(), ctx());

        let (first, second) = tokio::join!(
            lister.listing(&id, &version, &ctx),
            lister.listing(&id, &version, &ctx)
        );

        assert_eq!(first.expect("lists").files.len(), 3);
        assert_eq!(second.expect("lists").files.len(), 3);
        assert_eq!(host.hits(DIR), 1);
    }

    #[tokio::test]
    async fn snapshot_asks_nothing() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));
        let lister = IndexLister::new(BASE.into(), host.clone());

        lister
            .listing(
                &id(),
                &Version::new("1.0-SNAPSHOT", Release::PreRelease),
                &ctx(),
            )
            .await
            .expect("lists");

        assert!(host.requested().is_empty());
    }

    #[test]
    fn file_listing_option_checked() {
        let with = |value: &str| {
            crate::ext::testing::options(serde_json::json!({ "file-listing": value }))
        };

        assert_eq!(
            FileListing::read(&with("html-index")).expect("reads"),
            FileListing::HtmlIndex
        );
        assert_eq!(
            FileListing::read(&crate::ext::Options::default()).expect("reads"),
            FileListing::None
        );
        assert!(
            FileListing::read(&with("sometimes"))
                .expect_err("refused")
                .to_string()
                .contains("file-listing")
        );
    }
}
