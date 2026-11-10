//! Enumerating a JFrog Artifactory repository, over AQL.
//!
//! ```text
//!   POST {base}/api/search/aql
//!   items.find({"repo":"NAME","type":"file"})
//!        .include("repo","path","name","stat.downloaded","property.*")
//!        .sort({"$asc":["path","name"]})
//!        .offset(N).limit(M)
//! ```
//!
//! AQL rather than `/api/storage`, which is the other way to list a
//! repository, because only AQL returns download statistics. The storage
//! API would mean a further request per artifact to learn the same thing,
//! over a catalog that may hold millions.
//!
//! # AQL enumerates files, this enumerates artifacts
//!
//! The difference matters more than it sounds. One Maven artifact is a jar,
//! a POM, two checksums for each of those and often a signature -- six or
//! more rows for one thing worth reporting. An enumerator that emitted a row
//! per file would report an artifact six times and make `--sample-size`
//! meaningless.
//!
//! So rows are folded into artifacts, and the fold is what most of this
//! module is about. It also means a page of rows is **not** a page of
//! artifacts, and the two counts have no fixed ratio.
//!
//! # Recovering coordinates
//!
//! Artifactory stores files by layout, not by coordinate, so the coordinate
//! has to be recovered -- and how differs per ecosystem:
//!
//! - **Maven** from the layout path, which is a published specification:
//!   `org/apache/commons/commons-lang3/3.14.0/...` is unambiguous.
//! - **npm and PyPI** from the properties Artifactory attaches when it
//!   indexes a package (`npm.name`, `pypi.version`, and so on), because
//!   their layouts are not coordinate-bearing in the same way.
//!
//! The property route is the part worth checking against a real instance
//! before trusting at scale; the Maven route follows a spec.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::fold::{Folder, INCLUDE};
use super::row::Results;
use super::{KIND, PAGE_LIMIT, PAGE_ROWS, SEARCH, aql_time, login};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ext::{ExtHost, Options};
use crate::model::{EcosystemId, ListingDepth};
use crate::net::{Req, normalized_base};
use crate::repo::enumerate::{Cursor, Enumerator, Login, Narrowing, Page};

pub struct ArtifactoryEnumerator {
    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    folder: Folder,
}

impl ArtifactoryEnumerator {
    /// Build from configuration.
    ///
    /// The repository name and the ecosystem are both **required**. The
    /// ecosystem could in principle be inferred from the properties
    /// Artifactory attaches when it indexes a package -- but an enumerator has
    /// to describe itself before it walks anything, and a description that
    /// could not be produced until after the first page arrived would be no
    /// description at all. Auto-detection is a later convenience; declaring
    /// it is the first cut.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let (repository, ecosystem) = crate::repo::manager::config(options, KIND)?;
        let mapping = crate::repo::manager::raw_mapping(options, &ecosystem)?;

        // Read for its refusal of a misspelling; `login` acts on it.
        login(options, KIND)?;

        Ok(Self {
            host,
            folder: Folder::new(normalized_base(base_url), repository, ecosystem, mapping),
        })
    }

    /// A login unless the `anonymous` option says to try without one.
    pub(crate) fn login(options: &Options) -> Result<Login> {
        login(options, KIND)
    }

    /// The AQL query for one page, of the files modified at or after
    /// `since` when one is given.
    ///
    /// Sorted, and deliberately so. AQL paginates by offset, and an offset
    /// into an unordered result set is not a position -- rows would shift
    /// between pages and the walk would both repeat and skip artifacts.
    fn query(&self, offset: usize, since: Option<DateTime<Utc>>) -> String {
        let modified = since
            .map(|since| {
                format!(
                    r#","modified":{{"$gte":"{}"}}"#,
                    aql_time(since.timestamp_millis())
                )
            })
            .unwrap_or_default();

        format!(
            r#"items.find({{"repo":"{repo}","type":"file"{modified}}}){INCLUDE}\
.sort({{"$asc":["path","name"]}})\
.offset({offset}).limit({PAGE_ROWS})"#,
            repo = self.folder.repository().replace('"', ""),
        )
        .replace("\\\n", "")
    }

    /// One page, narrowed to `since` when one is given.
    async fn page(
        &self,
        since: Option<DateTime<Utc>>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        let offset: usize = cursor
            .map(Cursor::as_str)
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);

        let url = self.search_url();
        let results: Results = crate::ext::fetch_json(
            &*self.host,
            &Req::post(&url, self.query(offset, since)),
            PAGE_LIMIT,
            "artifactory aql results",
            ctx,
        )
        .await?;

        let found = self.folder.fold(&results.results, ctx);

        // The **row** count decides whether to continue, not the artifact
        // count. A short page of rows means the repository is exhausted; a
        // full page that folded into few artifacts does not.
        match results.results.len() < PAGE_ROWS {
            true => Ok(Page::last(found)),
            false => Ok(Page::more(
                found,
                Cursor::new((offset + PAGE_ROWS).to_string()),
            )),
        }
    }

    fn search_url(&self) -> String {
        format!("{}/{SEARCH}", self.folder.base_url())
    }
}

#[async_trait]
impl Enumerator for ArtifactoryEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        std::slice::from_ref(self.folder.ecosystem())
    }

    fn reports_last_download(&self) -> bool {
        crate::repo::manager::REPORTS_LAST_DOWNLOAD
    }

    fn depth(&self) -> ListingDepth {
        crate::repo::manager::LISTING_DEPTH
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        self.page(None, cursor, ctx).await
    }

    fn narrowing(&self) -> Narrowing {
        Narrowing::Modified
    }

    async fn walk_since(
        &self,
        since: DateTime<Utc>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        self.page(Some(since), cursor, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::core::error::Error;
    use crate::core::problem::Code;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::Cause;
    use crate::model::LastDownload;
    use crate::net::FixtureClient;

    const BASE: &str = "h://artifactory.test";
    const REPO: &str = "libs-release-local";

    fn search() -> String {
        format!("{BASE}/{SEARCH}")
    }

    fn enumerator(ecosystem: &str, host: Arc<dyn ExtHost>) -> ArtifactoryEnumerator {
        ArtifactoryEnumerator::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "ecosystem": ecosystem})),
            host,
        )
        .expect("opens")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Enumerated {
            enumerator: "artifactory".into(),
        })
    }

    async fn walk_with(body: &str, ecosystem: &str, ctx: &Ctx) -> (Page, Arc<TestHost>) {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), body.to_owned()),
        ));
        let page = enumerator(ecosystem, host.clone())
            .walk(None, ctx)
            .await
            .expect("walked");

        (page, host)
    }

    // -- The query --------------------------------------------------------

    /// AQL paginates by offset, and an offset into an unordered result set
    /// is not a position: rows would shift between pages and the walk would
    /// both repeat and skip artifacts.
    #[test]
    fn query_sorted_for_stable_offsets() {
        let query = enumerator("maven", idle()).query(0, None);

        assert!(
            query.contains(r#".sort({"$asc":["path","name"]})"#),
            "{query}"
        );
        assert!(query.contains(".offset(0)"), "{query}");
        assert!(query.contains(&format!(".limit({PAGE_ROWS})")), "{query}");
    }

    /// The query is one line with no stray continuation characters -- the
    /// raw string that builds it spans source lines, and AQL would not
    /// forgive a literal backslash.
    #[test]
    fn query_renders_as_one_line() {
        let query = enumerator("maven", idle()).query(0, None);

        assert!(!query.contains('\\'), "{query}");
        assert!(!query.contains('\n'), "{query}");
        assert!(query.starts_with("items.find("), "{query}");
        assert!(query.ends_with(&format!(".limit({PAGE_ROWS})")), "{query}");
    }

    /// A walk since a date asks only for files modified at or after it,
    /// which a redeploy moves and `created` does not.
    #[test]
    fn query_narrowed_filters_on_modified() {
        let since = DateTime::<Utc>::from_timestamp_millis(1_000).expect("valid");
        let query = enumerator("maven", idle()).query(0, Some(since));

        assert!(
            query.contains(r#""modified":{"$gte":"1970-01-01T00:00:01.000Z"}"#),
            "{query}"
        );
        assert!(
            !enumerator("maven", idle())
                .query(0, None)
                .contains("modified"),
            "a full walk is not narrowed"
        );
        assert_eq!(enumerator("maven", idle()).narrowing(), Narrowing::Modified);
    }

    #[test]
    fn query_asks_for_download_statistics() {
        let query = enumerator("maven", idle()).query(0, None);

        assert!(query.contains("stat.downloaded"), "{query}");
        assert!(query.contains("property.*"), "{query}");
        assert!(query.contains(&format!(r#""repo":"{REPO}""#)), "{query}");
    }

    /// It is a body, not a path, which is the whole reason `Method::Post`
    /// exists.
    #[tokio::test]
    async fn query_sent_as_body() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), r#"{"results":[]}"#.to_owned()),
        ));

        enumerator("maven", host.clone())
            .walk(None, &ctx)
            .await
            .expect("walked");

        assert_eq!(host.hits(&search()), 1);
    }

    // -- Folding files into artifacts -------------------------------------

    const MAVEN_ROWS: &str = r#"{"results": [
        {
            "path": "org/apache/commons/commons-lang3/3.14.0",
            "name": "commons-lang3-3.14.0.jar",
            "stats": [{"downloaded": "2024-06-01T12:00:00.000Z"}]
        },
        {
            "path": "org/apache/commons/commons-lang3/3.14.0",
            "name": "commons-lang3-3.14.0.pom",
            "stats": [{"downloaded": "2024-07-01T12:00:00.000Z"}]
        },
        {
            "path": "org/apache/commons/commons-lang3/3.14.0",
            "name": "commons-lang3-3.14.0.jar.sha1"
        },
        {
            "path": "org/apache/commons/commons-lang3",
            "name": "maven-metadata.xml"
        },
        {
            "path": "org/example/lib/1.0",
            "name": "lib-1.0.jar"
        }
    ]}"#;

    /// Each row that belongs to its artifact is listed, with where it is
    /// served and the checksums Artifactory computed. The checksum rows
    /// and the index are not files of the artifact; the signature is.
    #[tokio::test]
    async fn maven_rows_listed() {
        let body = r#"{"results": [
            {"path": "org/example/lib/1.0", "name": "lib-1.0.jar.asc"},
            {"path": "org/example/lib/1.0", "name": "lib-1.0.jar",
             "size": 42, "actual_sha1": "aa", "sha256": "bb"},
            {"path": "org/example/lib/1.0", "name": "lib-1.0.jar.sha1"},
            {"path": "org/example/lib/1.0", "name": "lib-1.0-sources.jar"},
            {"path": "org/example/lib", "name": "maven-metadata.xml"},
            {"path": "org/example/other/2.0", "name": "other-2.0.jar.asc"}
        ]}"#;
        let ctx = ctx();
        let (page, _) = walk_with(body, "maven", &ctx).await;

        // The lone signature made no artifact of its own.
        assert_eq!(page.found.len(), 1, "{:?}", page.found);

        let files = &page.found[0].files;
        let names: Vec<&str> = files.iter().map(|file| file.name.as_str()).collect();

        assert_eq!(
            names,
            ["lib-1.0.jar", "lib-1.0-sources.jar", "lib-1.0.jar.asc"]
        );
        assert_eq!(
            files[0].url,
            format!("{BASE}/{REPO}/org/example/lib/1.0/lib-1.0.jar")
        );
        assert_eq!(files[0].size, Some(42));
        assert_eq!(files[0].digests.len(), 2);
    }

    /// Six rows can be one artifact. An enumerator emitting a row each would
    /// report it six times and make `--sample-size` meaningless.
    #[tokio::test]
    async fn artifact_folds_files_of_one_version() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_ROWS, "maven", &ctx).await;

        assert_eq!(page.found.len(), 2);

        let purls: Vec<String> = page.found.iter().map(|f| f.id.purl()).collect();
        assert!(purls.contains(&"pkg:maven/org.apache.commons/commons-lang3".to_owned()));
        assert!(purls.contains(&"pkg:maven/org.example/lib".to_owned()));
    }

    /// Fetching any file of an artifact is using it, so the most recent
    /// across them wins -- here the POM, not the jar.
    #[tokio::test]
    async fn download_latest_across_files_wins() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_ROWS, "maven", &ctx).await;

        let lang3 = page
            .found
            .iter()
            .find(|f| f.id.name() == "commons-lang3")
            .expect("found");

        let expected = chrono::DateTime::parse_from_rfc3339("2024-07-01T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(lang3.last_download, LastDownload::At(expected));
    }

    /// Checksums and signatures are *about* an artifact and never are one;
    /// `maven-metadata.xml` belongs to the repository. None may be emitted.
    #[tokio::test]
    async fn artifact_excludes_sidecars_and_repository_files() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_ROWS, "maven", &ctx).await;

        assert!(
            !page.found.iter().any(|f| f.id.name().contains("metadata")),
            "{:?}",
            page.found.iter().map(|f| f.id.purl()).collect::<Vec<_>>()
        );
    }

    // -- Coordinates ------------------------------------------------------

    /// Maven's layout is a published specification, so the coordinate can
    /// be read from the path without guessing.
    #[tokio::test]
    async fn coordinate_maven_from_layout_path() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_ROWS, "maven", &ctx).await;

        let lang3 = page
            .found
            .iter()
            .find(|f| f.id.name() == "commons-lang3")
            .expect("found");

        assert_eq!(lang3.id.namespace(), Some("org.apache.commons"));
        assert_eq!(lang3.version.as_ref().expect("versioned").text(), "3.14.0");
    }

    /// A path too short to hold a group, an artifact and a version cannot
    /// be read, and inventing a coordinate would be worse than skipping it.
    #[tokio::test]
    async fn coordinate_maven_non_layout_path_skipped_reported() {
        let ctx = ctx();
        let (page, _) = walk_with(
            r#"{"results": [{"path": "loose", "name": "thing.jar"}]}"#,
            "maven",
            &ctx,
        )
        .await;

        assert!(page.found.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// npm and PyPI layouts are not coordinate-bearing, so the coordinate
    /// comes from the properties Artifactory attaches when it indexes.
    #[tokio::test]
    async fn coordinate_npm_from_properties() {
        let body = r#"{"results": [
            {
                "path": "@angular/core/-",
                "name": "core-17.0.0.tgz",
                "properties": [
                    {"key": "npm.name", "value": "@angular/core"},
                    {"key": "npm.version", "value": "17.0.0"}
                ]
            },
            {
                "path": "lodash/-",
                "name": "lodash-4.17.21.tgz",
                "properties": [
                    {"key": "npm.name", "value": "lodash"},
                    {"key": "npm.version", "value": "4.17.21"}
                ]
            }
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "npm", &ctx).await;

        let purls: Vec<String> = page.found.iter().map(|f| f.id.purl()).collect();

        assert!(
            purls.contains(&"pkg:npm/%40angular/core".to_owned()),
            "{purls:?}"
        );
        assert!(purls.contains(&"pkg:npm/lodash".to_owned()), "{purls:?}");
    }

    #[tokio::test]
    async fn coordinate_pypi_from_properties() {
        let body = r#"{"results": [
            {
                "path": "requests",
                "name": "requests-2.31.0.tar.gz",
                "properties": [
                    {"key": "pypi.name", "value": "requests"},
                    {"key": "pypi.version", "value": "2.31.0"}
                ]
            }
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "pypi", &ctx).await;

        assert_eq!(page.found[0].id.purl(), "pkg:pypi/requests");
        assert_eq!(page.found[0].version.as_ref().unwrap().text(), "2.31.0");
    }

    /// A file Artifactory has not indexed as a package carries no
    /// properties, and a coordinate cannot be invented for it.
    #[tokio::test]
    async fn coordinate_without_package_properties_skipped_reported() {
        let ctx = ctx();
        let (page, _) = walk_with(
            r#"{"results": [{"path": "x", "name": "mystery.tgz"}]}"#,
            "npm",
            &ctx,
        )
        .await;

        assert!(page.found.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    // -- Raw ----------------------------------------------------------------

    fn raw_enumerator(mapping: &str, body: &str) -> (ArtifactoryEnumerator, Arc<TestHost>) {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), body.to_owned()),
        ));
        let enumerator = ArtifactoryEnumerator::open(
            BASE,
            &options(serde_json::json!(
                {"repository": REPO, "ecosystem": "raw", "mapping": mapping}
            )),
            host.clone(),
        )
        .expect("opens");

        (enumerator, host)
    }

    async fn raw_walk(mapping: &str, body: &str, ctx: &Ctx) -> Page {
        let (enumerator, _) = raw_enumerator(mapping, body);

        enumerator.walk(None, ctx).await.expect("walked")
    }

    fn raw_names(page: &Page) -> Vec<String> {
        page.found.iter().map(|f| f.id.name().to_owned()).collect()
    }

    /// A raw sidecar is a published file of its folder's artifact, and a
    /// sub-folder is a different artifact.
    #[tokio::test]
    async fn raw_directory_folds_its_files() {
        let body = r#"{"results": [
            {"path": "tools/fmt", "name": "fmt.zip"},
            {"path": "tools/fmt", "name": "fmt.zip.sha256"},
            {"path": "tools/fmt/sub", "name": "other.zip"}
        ]}"#;
        let ctx = ctx();
        let page = raw_walk("directory", body, &ctx).await;

        assert_eq!(raw_names(&page), ["tools/fmt", "tools/fmt/sub"]);

        let files: Vec<&str> = page.found[0]
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(files, ["fmt.zip", "fmt.zip.sha256"]);
        assert!(page.found[0].version.is_none());
    }

    /// AQL spells the root `.`; a root file is its own artifact.
    #[tokio::test]
    async fn raw_root_file_is_its_own() {
        let body = r#"{"results": [{"path": ".", "name": "notes.txt"}]}"#;
        let ctx = ctx();
        let page = raw_walk("directory", body, &ctx).await;

        assert_eq!(raw_names(&page), ["notes.txt"]);
        assert_eq!(
            page.found[0].files[0].url,
            format!("{BASE}/{REPO}/notes.txt")
        );
    }

    #[tokio::test]
    async fn raw_as_is_file_is_its_own() {
        let body = r#"{"results": [
            {"path": "tools/fmt", "name": "fmt.zip"},
            {"path": "tools/fmt", "name": "fmt.zip.sha256"}
        ]}"#;
        let ctx = ctx();
        let page = raw_walk("as-is", body, &ctx).await;

        assert_eq!(
            raw_names(&page),
            ["tools/fmt/fmt.zip", "tools/fmt/fmt.zip.sha256"]
        );
    }

    #[tokio::test]
    async fn raw_name_version_file_reads_versions() {
        let body = r#"{"results": [
            {"path": "tools/fmt/2.0", "name": "fmt.zip"},
            {"path": "tools/fmt/2.1", "name": "fmt.zip"}
        ]}"#;
        let ctx = ctx();
        let page = raw_walk("name-version-file", body, &ctx).await;

        let versions: Vec<&str> = page
            .found
            .iter()
            .map(|f| f.version.as_ref().expect("versioned").text())
            .collect();

        assert_eq!(raw_names(&page), ["tools/fmt", "tools/fmt"]);
        assert_eq!(versions, ["2.0", "2.1"]);
    }

    /// One stray file must not fail the walk.
    #[tokio::test]
    async fn raw_unmapped_path_is_skipped_and_reported() {
        let body = r#"{"results": [
            {"path": "loose", "name": "thing.zip"},
            {"path": "tools/fmt/2.0", "name": "fmt.zip"}
        ]}"#;
        let ctx = ctx();
        let page = raw_walk("name-version-file", body, &ctx).await;

        assert_eq!(raw_names(&page), ["tools/fmt"]);
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// A mapping on a registry format is a mistake, not a no-op.
    #[test]
    fn mapping_raw_only() {
        let maven = options(serde_json::json!(
            {"repository": REPO, "ecosystem": "maven", "mapping": "directory"}
        ));
        let misspelled = options(serde_json::json!(
            {"repository": REPO, "ecosystem": "raw", "mapping": "regex"}
        ));

        assert!(refused(&maven).to_string().contains("mapping"));
        assert!(matches!(refused(&misspelled), Error::UnknownKind { .. }));
    }

    // -- Usage ------------------------------------------------------------

    /// Artifactory omits the stats entry for a file nothing has downloaded.
    /// Because this enumerator always asks for `stat.downloaded`, an absent
    /// entry means never served rather than never requested.
    #[tokio::test]
    async fn download_without_statistics_never_served() {
        let ctx = ctx();
        let (page, _) = walk_with(
            r#"{"results": [{"path": "g/a/1.0", "name": "a-1.0.jar"}]}"#,
            "maven",
            &ctx,
        )
        .await;

        assert_eq!(page.found[0].last_download, LastDownload::Never);
    }

    // -- Pagination -------------------------------------------------------

    /// A short page of **rows** ends the walk. The artifact count cannot
    /// decide it: a full page that folded into two artifacts is not the end
    /// of the repository.
    #[tokio::test]
    async fn page_short_ends_walk() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_ROWS, "maven", &ctx).await;

        assert!(!page.has_more());
        assert_eq!(page.found.len(), 2);
    }

    #[tokio::test]
    async fn page_full_continues_walk() {
        let rows: Vec<String> = (0..PAGE_ROWS)
            .map(|index| format!(r#"{{"path": "g/a/1.{index}", "name": "a-1.{index}.jar"}}"#))
            .collect();

        let ctx = ctx();
        let (page, _) = walk_with(
            &format!(r#"{{"results": [{}]}}"#, rows.join(",")),
            "maven",
            &ctx,
        )
        .await;

        assert!(page.has_more());
        assert_eq!(page.next.expect("cursor").as_str(), PAGE_ROWS.to_string());
    }

    #[tokio::test]
    async fn cursor_becomes_next_offset() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), r#"{"results":[]}"#.to_owned()),
        ));

        enumerator("maven", host.clone())
            .walk(Some(&Cursor::new("1000")), &ctx)
            .await
            .expect("walked");

        assert!(
            enumerator("maven", host.clone())
                .query(1000, None)
                .contains(".offset(1000)")
        );
    }

    /// A cursor this enumerator did not issue must not crash the walk.
    #[tokio::test]
    async fn cursor_nonsense_restarts_not_fails() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), r#"{"results":[]}"#.to_owned()),
        ));

        assert!(
            enumerator("maven", host.clone())
                .walk(Some(&Cursor::new("not-a-number")), &ctx)
                .await
                .is_ok()
        );
    }

    // -- Configuration ----------------------------------------------------

    fn refused(options: &Options) -> Error {
        match ArtifactoryEnumerator::open(BASE, options, idle()) {
            Err(err) => err,
            Ok(_) => panic!("should have been refused"),
        }
    }

    /// Pro refuses anonymous AQL as OSS does, with the same override.
    #[test]
    fn login_required_unless_attempted() {
        let with = |anonymous: serde_json::Value| {
            options(serde_json::json!(
                {"repository": REPO, "ecosystem": "maven", "anonymous": anonymous}
            ))
        };

        assert_eq!(
            ArtifactoryEnumerator::login(&with(serde_json::Value::Null)).expect("reads"),
            Login::Required
        );
        assert_eq!(
            ArtifactoryEnumerator::login(&with("attempt".into())).expect("reads"),
            Login::Optional
        );
        assert!(
            refused(&with("sometimes".into()))
                .to_string()
                .contains("anonymous")
        );
    }

    #[test]
    fn repository_and_ecosystem_required() {
        assert!(
            refused(&Options::default())
                .to_string()
                .contains("repository")
        );

        let no_ecosystem = options(serde_json::json!({"repository": REPO}));
        assert!(refused(&no_ecosystem).to_string().contains("ecosystem"));
    }

    #[test]
    fn ecosystem_declared_as_pointed_at() {
        let enumerator = enumerator("maven", idle());

        assert_eq!(enumerator.ecosystems(), [EcosystemId::maven()]);
        assert!(enumerator.reports_last_download());
    }

    #[tokio::test]
    async fn response_malformed_is_error() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), "{[".to_owned()),
        ));

        let err = enumerator("maven", host.clone())
            .walk(None, &ctx)
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::MetadataMalformed);
    }
}
