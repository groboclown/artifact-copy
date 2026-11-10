//! Enumerating an Artifact Keeper repository.
//!
//! ```text
//!   GET {base}/api/v1/repositories/{repository}/artifacts?per_page=100
//!   GET {base}/api/v1/repositories/{repository}/artifacts?per_page=100&cursor={token}
//!   GET {base}/api/v1/artifacts/{id}/stats                 (last-download: stats)
//! ```
//!
//! One flat listing serves every format, sorted by path and paged by a
//! keyset cursor.  A remote repository's legacy listing sends no cursor and
//! no `has_more`, only page totals, so the walk falls back to page numbers
//! there.  The cursor records which:
//!
//! ```text
//!   (none)      the first page
//!   c:{token}   the server's keyset cursor
//!   p:{n}       page n of a numbered listing
//! ```
//!
//! # Coordinates come from the path
//!
//! The listing's `name` and `version` are guessed by the server and are not
//! trusted.  The path is the layout the server stored:
//!
//! | Ecosystem | Path |
//! | --- | --- |
//! | maven | `org/example/lib/1.0/lib-1.0.jar` |
//! | npm | `@scope/name/-/name-1.0.0.tgz` (the listing rewrites the stored `name/1.0.0/...`) |
//! | pypi | `{normalized}/{version}/{file}` |
//! | raw | whatever the `mapping` option reads |
//!
//! # Usage
//!
//! The listing carries no last-download time.  Only the stats endpoint
//! does, at one request per file, so it is opt-in through
//! `last-download: stats`; otherwise every artifact is `Unknown`.
//!
//! # A Remote repository
//!
//! `mode: proxy` or `mode: proxy-cache` says the repository is a Remote,
//! whose listing is its cache catalog.  Coordinates and file URLs then come
//! from the cache layout (see `cache`), and `last-download: stats` is
//! refused: a cached row's id is synthetic, with no stats behind it.

use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;

use super::api::Mode;
use super::cache::{self, npm_coordinate};
use super::listing::{Item, Listing, Stats};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{ArtifactId, EcosystemId, LastDownload, ListingDepth, Release, Version};
use crate::net::{ByteLimit, Req, encode_unreserved, normalized_base};
use crate::repo::Mapping;
use crate::repo::enumerate::{Cursor, Enumerator, Found, Listed, Page};

/// The kind, as configuration names it.
const KIND: &str = "artifact-keeper";

/// The per-artifact endpoints, relative to the server root.
const ARTIFACTS: &str = "api/v1/artifacts";

/// Listing rows per page; the server's maximum.
const PER_PAGE: u32 = 100;

/// One listing page of a hundred rows.
const PAGE_LIMIT: ByteLimit = ByteLimit::mib(8);

/// One file's stats: four fields.
const STATS_LIMIT: ByteLimit = ByteLimit::kib(64);

/// Whether to ask for each file's last download.
const LAST_DOWNLOAD: &str = "last-download";

/// Cursor prefixes; see the module documentation.
const KEYSET: &str = "c:";
const NUMBERED: &str = "p:";

/// The ecosystems whose paths this enumerator can read.
const SUPPORTED: [&str; 4] = [
    EcosystemId::MAVEN,
    EcosystemId::NPM,
    EcosystemId::PYPI,
    EcosystemId::RAW,
];

/// Where last-download times come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Usage {
    /// Nowhere: every artifact is `Unknown`, and no request is spent.
    Unknown,

    /// One stats request per listed file.
    Stats,
}

impl Usage {
    fn read(options: &Options) -> Result<Self> {
        match options.string(LAST_DOWNLOAD)? {
            None | Some("unknown") => Ok(Self::Unknown),
            Some("stats") => Ok(Self::Stats),

            Some(other) => Err(Error::Config(format!(
                "the {KIND} enumerator's {LAST_DOWNLOAD:?} option is \"unknown\" or \
                 \"stats\", not {other:?}"
            ))),
        }
    }
}

/// Which page to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Position {
    First,
    Keyset(String),
    Numbered(u64),
}

impl Position {
    /// Refused rather than restarted on a cursor this enumerator did not
    /// issue: a silent restart re-walks the whole repository.
    fn read(cursor: Option<&Cursor>) -> Result<Self> {
        let Some(cursor) = cursor else {
            return Ok(Self::First);
        };

        let text = cursor.as_str();

        if let Some(token) = text.strip_prefix(KEYSET) {
            return Ok(Self::Keyset(token.to_owned()));
        }

        if let Some(page) = text.strip_prefix(NUMBERED).and_then(|n| n.parse().ok()) {
            return Ok(Self::Numbered(page));
        }

        Err(Error::Config(format!(
            "the {KIND} enumerator cannot resume from cursor {text:?}, which it did not issue"
        )))
    }

    /// The page number this position reads, counting from one.
    fn page(&self) -> u64 {
        match self {
            Self::Numbered(page) => *page,
            _ => 1,
        }
    }
}

pub struct ArtifactKeeperEnumerator {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
    ecosystem: EcosystemId,

    /// How a raw repository's paths become coordinates.  Refused on every
    /// other ecosystem.
    mapping: Mapping,
    usage: Usage,

    /// Whether the listing is a Remote's cache catalog.
    mode: Mode,
}

impl ArtifactKeeperEnumerator {
    /// Build from configuration: `repository` and `ecosystem` are required,
    /// `mapping` is for raw only, and `last-download` defaults to
    /// `unknown`.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let (repository, ecosystem) = crate::repo::manager::config(options, KIND)?;

        if !SUPPORTED.contains(&ecosystem.as_str()) {
            return Err(Error::UnknownKind {
                collection: "ecosystem for the artifact-keeper enumerator",
                kind: ecosystem.to_string(),
            });
        }

        let mapping = crate::repo::manager::raw_mapping(options, &ecosystem)?;
        let usage = Usage::read(options)?;
        let mode = Mode::read(options, KIND)?;

        if mode.cached() && usage == Usage::Stats {
            return Err(Error::Config(format!(
                "the {KIND} enumerator cannot read {LAST_DOWNLOAD:?} \"stats\" for a \
                 proxy repository: its cached files carry no stats; remove one of \
                 {LAST_DOWNLOAD:?} or \"mode\""
            )));
        }

        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            repository,
            ecosystem,
            mapping,
            usage,
            mode,
        })
    }

    fn repository_url(&self) -> String {
        super::repository_url(&self.base_url, &self.repository)
    }

    fn page_url(&self, position: &Position) -> String {
        let listing = format!("{}/artifacts?per_page={PER_PAGE}", self.repository_url());

        match position {
            Position::First => listing,
            Position::Keyset(token) => format!("{listing}&cursor={}", encode_unreserved(token)),
            Position::Numbered(page) => format!("{listing}&page={page}"),
        }
    }

    /// The generic download route, which serves every format by its
    /// stored or its URL-shaped path; a cached file goes through its
    /// format's route instead.
    fn file_url(&self, item: &Item) -> String {
        if self.mode.cached() {
            return cache::file_url(
                &self.base_url,
                &self.ecosystem,
                &self.repository,
                &item.path,
            );
        }

        super::download_url(&self.base_url, &self.repository, &item.path)
    }

    fn stats_url(&self, id: &str) -> String {
        format!(
            "{}/{ARTIFACTS}/{}/stats",
            self.base_url,
            encode_unreserved(id)
        )
    }

    /// The server hides a repository the caller may not read behind the
    /// same 404 as one that does not exist, so the error names both.
    fn missing(&self, url: String) -> Error {
        Error::Absent {
            what: "repository (or one these credentials may not read)",
            url,
            name: self.repository.clone(),
        }
    }

    /// Turn one listed file into an artifact holding it, or explain why
    /// not.
    fn found(&self, item: &Item, ctx: &Ctx) -> Option<Found> {
        // Checksum sidecars and Maven's own index are not files of an
        // artifact, and `maven-metadata.xml` would read as a bogus one.
        if !crate::ecosystem::joins_listing(&self.ecosystem, item.name())
            || (self.mode.cached() && cache::skipped(&self.ecosystem, item.name()))
        {
            return None;
        }

        let Some((id, version)) = self.coordinate(&item.path) else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "artifact-keeper-unreadable-path",
                    "{path} in {repository} is not a {ecosystem} layout path, so no \
                     coordinate can be read from it; it is skipped",
                    path = &item.path,
                    repository = &self.repository,
                    ecosystem = &self.ecosystem,
                ),
            );

            return None;
        };

        let listed = Listed {
            name: item.name().to_owned(),
            url: self.file_url(item),
            size: item.size(),
            digests: item.digests(),
        };

        Some(Found::new(id).maybe_version(version).files(vec![listed]))
    }

    /// The coordinate a stored path names, per ecosystem.
    fn coordinate(&self, path: &str) -> Option<(ArtifactId, Option<Version>)> {
        if self.mode.cached() {
            let at = cache::coordinate(&self.ecosystem, self.mapping, path)?;

            return Some((
                ArtifactId::new(self.ecosystem.clone(), at.namespace.as_deref(), &at.name),
                at.version.as_deref().map(|text| self.classify(text)),
            ));
        }

        let path = path.trim_matches('/');

        match self.ecosystem.as_str() {
            EcosystemId::MAVEN => {
                let (directory, _) = path.rsplit_once('/')?;
                let (group, artifact, version) = crate::repo::maven::layout_of(directory)?;

                Some((
                    ArtifactId::new(self.ecosystem.clone(), Some(&group), artifact),
                    Some(self.classify(version)),
                ))
            }

            EcosystemId::NPM => {
                let (scope, name, version) = npm_coordinate(path)?;

                Some((
                    ArtifactId::new(self.ecosystem.clone(), scope, name),
                    Some(self.classify(version)),
                ))
            }

            EcosystemId::PYPI => {
                let (name, version) = pypi_coordinate(path)?;

                Some((
                    ArtifactId::new(self.ecosystem.clone(), None, name),
                    Some(self.classify(version)),
                ))
            }

            // Raw, the only other ecosystem `open` accepts.
            _ => {
                let at = self.mapping.read(path)?;

                Some((
                    ArtifactId::new(self.ecosystem.clone(), None, &at.name),
                    at.version.as_deref().map(|text| self.classify(text)),
                ))
            }
        }
    }

    fn classify(&self, version: &str) -> Version {
        match crate::ecosystem::open(self.ecosystem.as_str()) {
            Ok(ecosystem) => ecosystem.version(version),

            // Unreachable: `open` refused an unknown ecosystem.
            Err(_) => Version::new(version, Release::PreRelease),
        }
    }

    /// When one file was last served, as configured.
    async fn usage_of(&self, item: &Item, ctx: &Ctx) -> Result<LastDownload> {
        if self.usage == Usage::Unknown {
            return Ok(LastDownload::Unknown);
        }

        // A remote repository's cached rows carry a synthetic id with no
        // stats behind it.
        let Some(id) = item.id.as_deref() else {
            return Ok(LastDownload::Unknown);
        };

        let fetched: Result<Stats> = crate::ext::fetch_json(
            &*self.host,
            &Req::get(self.stats_url(id)),
            STATS_LIMIT,
            "artifact keeper stats",
            ctx,
        )
        .await;

        match fetched {
            Ok(stats) => Ok(stats.last_download()),
            // HTTP 404: missing, or hidden from these credentials.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                Ok(LastDownload::Unknown)
            }
            Err(err) => Err(err),
        }
    }

    /// Where the walk goes after this page.
    ///
    /// Only a server that says "no more" ends it.  One that says nothing
    /// at all is an error, not an end, because reading silence as the end
    /// truncates the catalog without a word.
    fn next(&self, position: &Position, listing: &Listing, url: &str) -> Result<Option<Cursor>> {
        let more = listing
            .more_after(position.page())
            .ok_or_else(|| Error::Malformed {
                what: "artifact keeper listing",
                url: url.to_owned(),
                detail: "it says neither whether more pages follow nor how many there are".into(),
            })?;

        if !more {
            return Ok(None);
        }

        if let Some(token) = listing.next_cursor.as_deref().filter(|t| !t.is_empty()) {
            return Ok(Some(Cursor::new(format!("{KEYSET}{token}"))));
        }

        // A keyset walk that loses its cursor cannot switch to page
        // numbers: page two of a numbered listing is not what follows a
        // keyset position.
        if let Position::Keyset(_) = position {
            return Err(Error::Malformed {
                what: "artifact keeper listing",
                url: url.to_owned(),
                detail: "it says more pages follow but gives no cursor to reach them".into(),
            });
        }

        Ok(Some(Cursor::new(format!(
            "{NUMBERED}{}",
            position.page() + 1
        ))))
    }
}

/// `{normalized}/{version}/{file}`, as the server stores an upload.
///
/// The file's own name must start with the project's, which turns away a
/// remote repository's cached `simple/{project}/{file}`: there the first
/// segment is not a project at all, and `mode: proxy` reads it instead.
fn pypi_coordinate(path: &str) -> Option<(&str, &str)> {
    let segments: Vec<&str> = path.split('/').collect();

    let [project, version, file] = segments.as_slice() else {
        return None;
    };

    let project_prefix = format!("{}-", crate::ecosystem::pypi::normalize(project));

    if version.is_empty() || !crate::ecosystem::pypi::normalize(file).starts_with(&project_prefix) {
        return None;
    }

    Some((project, version))
}

#[async_trait]
impl Enumerator for ArtifactKeeperEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        std::slice::from_ref(&self.ecosystem)
    }

    fn reports_last_download(&self) -> bool {
        self.usage == Usage::Stats
    }

    fn depth(&self) -> ListingDepth {
        crate::repo::manager::LISTING_DEPTH
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        let position = Position::read(cursor)?;
        let url = self.page_url(&position);

        let fetched: Result<Listing> = crate::ext::fetch_json(
            &*self.host,
            &Req::get(&url),
            PAGE_LIMIT,
            "artifact keeper listing",
            ctx,
        )
        .await;

        let listing = match fetched {
            // HTTP 404: missing, or hidden from these credentials.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                return Err(self.missing(url));
            }
            other => other?,
        };

        // One file per item; the fold makes one artifact of a version's
        // files where the page holds several.
        let mut found = Vec::new();

        for item in &listing.items {
            let Some(one) = self.found(item, ctx) else {
                continue;
            };

            found.push(one.last_download(self.usage_of(item, ctx).await?));
        }

        let found = crate::repo::manager::fold(found.into_iter());

        match self.next(&position, &listing, &url)? {
            Some(next) => Ok(Page::more(found, next)),
            None => Ok(Page::last(found)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::API;
    use super::*;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::Cause;
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://keeper.test";
    const REPO: &str = "libs";

    fn listing(query: &str) -> String {
        format!("{BASE}/{API}/{REPO}/artifacts?per_page={PER_PAGE}{query}")
    }

    fn config(extra: serde_json::Value) -> Options {
        let mut json = serde_json::json!({"repository": REPO});

        json.as_object_mut()
            .expect("an object")
            .extend(extra.as_object().expect("an object").clone());

        options(json)
    }

    fn enumerator(extra: serde_json::Value, host: Arc<dyn ExtHost>) -> ArtifactKeeperEnumerator {
        ArtifactKeeperEnumerator::open(BASE, &config(extra), host).expect("opens")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Enumerated {
            enumerator: KIND.into(),
        })
    }

    fn refused(options: &Options) -> Error {
        match ArtifactKeeperEnumerator::open(BASE, options, idle()) {
            Err(err) => err,
            Ok(_) => panic!("should have been refused"),
        }
    }

    /// Walk one first page whose body is `body`.
    async fn walk_with(extra: serde_json::Value, body: &str, ctx: &Ctx) -> Page {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(listing(""), body.to_owned()),
        ));

        enumerator(extra, host)
            .walk(None, ctx)
            .await
            .expect("walked")
    }

    // -- Configuration ----------------------------------------------------

    #[test]
    fn repository_and_ecosystem_required() {
        assert!(
            refused(&Options::default())
                .to_string()
                .contains("repository")
        );
        assert!(
            refused(&config(serde_json::json!({})))
                .to_string()
                .contains("ecosystem")
        );
    }

    #[test]
    fn ecosystem_unreadable_refused() {
        let err = refused(&config(serde_json::json!({"ecosystem": "github"})));

        assert!(err.to_string().contains("github"), "{err}");
    }

    #[test]
    fn mapping_raw_only() {
        let err = refused(&config(
            serde_json::json!({"ecosystem": "maven", "mapping": "as-is"}),
        ));

        assert!(err.to_string().contains("mapping"), "{err}");
    }

    #[test]
    fn stats_last_download_option_checked() {
        let err = refused(&config(
            serde_json::json!({"ecosystem": "maven", "last-download": "sometimes"}),
        ));

        assert!(err.to_string().contains("last-download"), "{err}");
    }

    #[test]
    fn stats_usage_follows_option() {
        let quiet = enumerator(serde_json::json!({"ecosystem": "maven"}), idle());
        let asking = enumerator(
            serde_json::json!({"ecosystem": "maven", "last-download": "stats"}),
            idle(),
        );

        assert!(!quiet.reports_last_download());
        assert!(asking.reports_last_download());
        assert_eq!(quiet.depth(), ListingDepth::Files);
    }

    // -- Coordinates ------------------------------------------------------

    #[tokio::test]
    async fn path_maven_files_fold_into_one_version() {
        let body = r#"{"items": [
            {"id": "1", "path": "org/example/lib/1.0/lib-1.0.jar",
             "size_bytes": 42, "checksum_sha256": "aa"},
            {"id": "2", "path": "org/example/lib/1.0/lib-1.0.jar.sha1"},
            {"id": "3", "path": "org/example/lib/1.0/lib-1.0.pom"},
            {"id": "4", "path": "org/example/lib/maven-metadata.xml"}
        ], "has_more": false}"#;
        let ctx = ctx();
        let page = walk_with(serde_json::json!({"ecosystem": "maven"}), body, &ctx).await;

        assert_eq!(page.found.len(), 1, "{:?}", page.found);

        let found = &page.found[0];
        let names: Vec<&str> = found.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(found.id.purl(), "pkg:maven/org.example/lib");
        assert_eq!(found.version.as_ref().map(Version::text), Some("1.0"));
        assert_eq!(names, ["lib-1.0.jar", "lib-1.0.pom"]);
        assert_eq!(
            found.files[0].url,
            format!("{BASE}/{API}/{REPO}/download/org/example/lib/1.0/lib-1.0.jar")
        );
        assert_eq!(found.files[0].size, Some(42));
        assert_eq!(found.files[0].digests.len(), 1);
        assert_eq!(found.last_download, LastDownload::Unknown);
    }

    #[test]
    fn path_npm_read_in_both_shapes() {
        assert_eq!(
            npm_coordinate("left-pad/-/left-pad-1.3.0.tgz"),
            Some((None, "left-pad", "1.3.0"))
        );
        assert_eq!(
            npm_coordinate("@acme/widget/-/widget-2.0.0-rc.1.tgz"),
            Some((Some("@acme"), "widget", "2.0.0-rc.1"))
        );
        assert_eq!(
            npm_coordinate("left-pad/1.3.0/left-pad-1.3.0.tgz"),
            Some((None, "left-pad", "1.3.0"))
        );

        // The middle segment disagrees with the file's version.
        assert_eq!(npm_coordinate("left-pad/9.9.9/left-pad-1.3.0.tgz"), None);
        assert_eq!(npm_coordinate("left-pad/package.json"), None);
    }

    #[test]
    fn path_pypi_needs_project_in_file() {
        assert_eq!(
            pypi_coordinate("my-pkg/1.0/my_pkg-1.0-py3-none-any.whl"),
            Some(("my-pkg", "1.0"))
        );
        assert_eq!(
            pypi_coordinate("my-pkg/1.0/my-pkg-1.0.tar.gz"),
            Some(("my-pkg", "1.0"))
        );

        // A remote repository's cache.
        assert_eq!(pypi_coordinate("simple/requests/requests-2.0.tar.gz"), None);
    }

    #[tokio::test]
    async fn path_npm_scope_becomes_namespace() {
        let body = r#"{"items": [
            {"id": "1", "path": "@acme/widget/-/widget-2.0.0.tgz"}
        ], "has_more": false}"#;
        let ctx = ctx();
        let page = walk_with(serde_json::json!({"ecosystem": "npm"}), body, &ctx).await;

        assert_eq!(page.found[0].id.purl(), "pkg:npm/%40acme/widget");
    }

    #[tokio::test]
    async fn path_raw_reads_through_mapping() {
        let body = r#"{"items": [
            {"id": "1", "path": "tools/fmt/2.1/fmt.zip"}
        ], "has_more": false}"#;
        let ctx = ctx();
        let page = walk_with(
            serde_json::json!({"ecosystem": "raw", "mapping": "name-version-file"}),
            body,
            &ctx,
        )
        .await;

        assert_eq!(page.found[0].id.name(), "tools/fmt");
        assert_eq!(
            page.found[0].version.as_ref().map(Version::text),
            Some("2.1")
        );
    }

    #[tokio::test]
    async fn path_unreadable_skipped_reported() {
        let body = r#"{"items": [
            {"id": "1", "path": "lib-1.0.jar"}
        ], "has_more": false}"#;
        let ctx = ctx();
        let page = walk_with(serde_json::json!({"ecosystem": "maven"}), body, &ctx).await;

        assert!(page.found.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    // -- Paging -----------------------------------------------------------

    #[tokio::test]
    async fn cursor_keyset_continues_walk() {
        let body = r#"{"items": [], "has_more": true, "next_cursor": "abc="}"#;
        let ctx = ctx();
        let page = walk_with(serde_json::json!({"ecosystem": "maven"}), body, &ctx).await;

        // Empty, and still not the end.
        assert!(page.found.is_empty());
        assert_eq!(page.next, Some(Cursor::new("c:abc=")));
    }

    #[tokio::test]
    async fn cursor_keyset_sent_encoded() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            listing("&cursor=abc%3D"),
            r#"{"items": [], "has_more": false}"#.to_owned(),
        )));

        let page = enumerator(serde_json::json!({"ecosystem": "maven"}), host.clone())
            .walk(Some(&Cursor::new("c:abc=")), &ctx())
            .await
            .expect("walked");

        assert!(!page.has_more());
        assert_eq!(host.hits(&listing("&cursor=abc%3D")), 1);
    }

    #[tokio::test]
    async fn cursor_legacy_pages_by_number() {
        let body = r#"{"items": [], "pagination": {"page": 1, "total_pages": 3}}"#;
        let ctx = ctx();
        let page = walk_with(serde_json::json!({"ecosystem": "maven"}), body, &ctx).await;

        assert_eq!(page.next, Some(Cursor::new("p:2")));

        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            listing("&page=3"),
            r#"{"items": [], "pagination": {"page": 3, "total_pages": 3}}"#.to_owned(),
        )));

        let last = enumerator(serde_json::json!({"ecosystem": "maven"}), host)
            .walk(Some(&Cursor::new("p:3")), &ctx)
            .await
            .expect("walked");

        assert!(!last.has_more());
    }

    #[tokio::test]
    async fn silence_is_not_the_end() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(listing(""), r#"{"items": []}"#.to_owned()),
        ));

        let err = enumerator(serde_json::json!({"ecosystem": "maven"}), host)
            .walk(None, &ctx())
            .await
            .expect_err("no paging fields");

        assert!(matches!(err, Error::Malformed { .. }), "{err}");
    }

    #[tokio::test]
    async fn cursor_keyset_missing_is_error() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            listing("&cursor=abc"),
            r#"{"items": [], "has_more": true}"#.to_owned(),
        )));

        let err = enumerator(serde_json::json!({"ecosystem": "maven"}), host)
            .walk(Some(&Cursor::new("c:abc")), &ctx())
            .await
            .expect_err("lost its cursor");

        assert!(matches!(err, Error::Malformed { .. }), "{err}");
    }

    #[tokio::test]
    async fn cursor_foreign_refused() {
        let err = enumerator(serde_json::json!({"ecosystem": "maven"}), idle())
            .walk(Some(&Cursor::new("500")), &ctx())
            .await
            .expect_err("not ours");

        assert!(err.to_string().contains("500"), "{err}");
    }

    #[tokio::test]
    async fn repository_hidden_names_both_causes() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with(listing(""), Canned::status(StatusCode::NOT_FOUND)),
        ));

        let err = enumerator(serde_json::json!({"ecosystem": "maven"}), host)
            .walk(None, &ctx())
            .await
            .expect_err("404");

        assert!(err.to_string().contains("credentials"), "{err}");
    }

    // -- Usage ------------------------------------------------------------

    #[tokio::test]
    async fn stats_report_latest_download() {
        let jar = format!("{BASE}/{ARTIFACTS}/1/stats");
        let pom = format!("{BASE}/{ARTIFACTS}/2/stats");
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(
                    listing(""),
                    r#"{"items": [
                        {"id": "1", "path": "org/example/lib/1.0/lib-1.0.jar"},
                        {"id": "2", "path": "org/example/lib/1.0/lib-1.0.pom"}
                    ], "has_more": false}"#
                        .to_owned(),
                )
                .with_body(
                    jar.clone(),
                    r#"{"last_downloaded": "2024-06-01T12:00:00Z"}"#.to_owned(),
                )
                .with_body(pom.clone(), r#"{"last_downloaded": null}"#.to_owned()),
        ));

        let page = enumerator(
            serde_json::json!({"ecosystem": "maven", "last-download": "stats"}),
            host.clone(),
        )
        .walk(None, &ctx())
        .await
        .expect("walked");

        let expected = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(page.found[0].last_download, LastDownload::At(expected));
        assert_eq!(host.hits(&jar), 1);
        assert_eq!(host.hits(&pom), 1);
    }

    #[tokio::test]
    async fn stats_none_without_option() {
        let ctx = ctx();
        let page = walk_with(
            serde_json::json!({"ecosystem": "maven"}),
            r#"{"items": [{"id": "1", "path": "org/example/lib/1.0/lib-1.0.jar"}],
                "has_more": false}"#,
            &ctx,
        )
        .await;

        // An unasked stats URL would have failed the walk against the
        // fixture, so reaching here means none was requested.
        assert_eq!(page.found[0].last_download, LastDownload::Unknown);
    }

    #[tokio::test]
    async fn stats_missing_unknown() {
        let stats = format!("{BASE}/{ARTIFACTS}/1/stats");
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(
                    listing(""),
                    r#"{"items": [{"id": "1", "path": "org/example/lib/1.0/lib-1.0.jar"}],
                        "has_more": false}"#
                        .to_owned(),
                )
                .with(stats, Canned::status(StatusCode::NOT_FOUND)),
        ));

        let page = enumerator(
            serde_json::json!({"ecosystem": "maven", "last-download": "stats"}),
            host,
        )
        .walk(None, &ctx())
        .await
        .expect("walked");

        assert_eq!(page.found[0].last_download, LastDownload::Unknown);
    }

    // -- Proxy repositories -----------------------------------------------

    #[test]
    fn mode_unknown_refused() {
        let err = refused(&config(
            serde_json::json!({"ecosystem": "pypi", "mode": "mirror"}),
        ));

        assert!(err.to_string().contains("mode"), "{err}");
    }

    #[test]
    fn mode_cached_refuses_stats() {
        for mode in ["proxy", "proxy-cache"] {
            let err = refused(&config(serde_json::json!({
                "ecosystem": "maven", "mode": mode, "last-download": "stats"
            })));

            assert!(err.to_string().contains("stats"), "{mode}: {err}");
        }
    }

    #[tokio::test]
    async fn mode_cached_pypi_reads_simple_paths() {
        let body = r#"{"items": [
            {"id": "a", "path": "simple/requests/requests-2.31.0.tar.gz",
             "size_bytes": 9, "checksum_sha256": "bb"},
            {"id": "b", "path": "simple/requests/requests-2.31.0-py3-none-any.whl"},
            {"id": "c", "path": "simple/requests/requests-2.31.0-py3-none-any.whl.metadata"}
        ], "has_more": false}"#;
        let ctx = ctx();
        let page = walk_with(
            serde_json::json!({"ecosystem": "pypi", "mode": "proxy-cache"}),
            body,
            &ctx,
        )
        .await;

        assert_eq!(page.found.len(), 1, "{:?}", page.found);

        let found = &page.found[0];

        assert_eq!(found.id.purl(), "pkg:pypi/requests");
        assert_eq!(found.version.as_ref().map(Version::text), Some("2.31.0"));
        assert_eq!(found.files.len(), 2);
        assert_eq!(
            found.files[0].url,
            format!("{BASE}/pypi/{REPO}/simple/requests/requests-2.31.0.tar.gz")
        );

        // The core-metadata file is passed over, not reported.
        assert!(ctx.problems().counts().is_empty());
    }

    #[tokio::test]
    async fn mode_hosted_pypi_refuses_simple_paths() {
        let body = r#"{"items": [
            {"id": "a", "path": "simple/requests/requests-2.31.0.tar.gz"}
        ], "has_more": false}"#;
        let ctx = ctx();
        let page = walk_with(serde_json::json!({"ecosystem": "pypi"}), body, &ctx).await;

        assert!(page.found.is_empty());
    }

    #[tokio::test]
    async fn mode_cached_npm_and_maven() {
        let ctx = ctx();
        let npm = walk_with(
            serde_json::json!({"ecosystem": "npm", "mode": "proxy"}),
            r#"{"items": [{"id": "a", "path": "@acme/widget/-/widget-2.0.0.tgz"}],
                "has_more": false}"#,
            &ctx,
        )
        .await;

        assert_eq!(npm.found[0].id.purl(), "pkg:npm/%40acme/widget");
        assert_eq!(
            npm.found[0].files[0].url,
            format!("{BASE}/npm/{REPO}/@acme/widget/-/widget-2.0.0.tgz")
        );

        let maven = walk_with(
            serde_json::json!({"ecosystem": "maven", "mode": "proxy"}),
            r#"{"items": [{"id": "a", "path": "org/example/lib/1.0/lib-1.0.jar"}],
                "has_more": false}"#,
            &ctx,
        )
        .await;

        assert_eq!(maven.found[0].id.purl(), "pkg:maven/org.example/lib");
        assert_eq!(
            maven.found[0].files[0].url,
            format!("{BASE}/maven/{REPO}/org/example/lib/1.0/lib-1.0.jar")
        );
    }

    #[tokio::test]
    async fn mode_cached_legacy_listing_pages_by_number() {
        let ctx = ctx();
        let page = walk_with(
            serde_json::json!({"ecosystem": "maven", "mode": "proxy-cache"}),
            r#"{"items": [{"id": "a", "path": "org/example/lib/1.0/lib-1.0.jar"}],
                "pagination": {"page": 1, "total_pages": 2}}"#,
            &ctx,
        )
        .await;

        assert_eq!(page.found.len(), 1);
        assert_eq!(page.next, Some(Cursor::new("p:2")));
    }
}
