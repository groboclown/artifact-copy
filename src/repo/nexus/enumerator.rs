//! Enumerating a Sonatype Nexus 3 repository.
//!
//! Nexus is a **product hosting registries**, not a registry: one REST API,
//! one credential and one pagination cursor serve Maven, npm and PyPI
//! alike. That is why this is one enumerator declaring the ecosystem it was
//! pointed at, rather than `nexus-maven` and `nexus-npm` and `nexus-pypi`
//! sharing state they would have no way to share.
//!
//! ```text
//!   GET {base}/service/rest/v1/components?repository={name}
//!   GET {base}/service/rest/v1/components?repository={name}&continuationToken={token}
//! ```
//!
//! # Why this enumerator can answer the usage question
//!
//! Nexus records `lastDownloaded` per asset, which almost nothing else
//! does -- a Maven HTML index, npm's replication feed and PyPI's simple
//! index carry no usage data at all. That is what
//! [`LastDownload`](crate::model::LastDownload) exists to express, and this
//! is the first enumerator able to say anything but `Unknown`.
//!
//! The distinction it can draw is worth stating precisely, because getting
//! it wrong is how a retention tool deletes things people are using:
//!
//! | Nexus says | Meaning | Reported as |
//! | --- | --- | --- |
//! | a timestamp | last served then | `At` |
//! | `null` | tracked, never served | `Never` |
//! | nothing at all | this server does not report it | `Unknown` |
//!
//! The last row is not hypothetical -- the field arrived during the 3.x
//! series, and an older server omits it. Treating "omitted" as "never
//! downloaded" would mark an entire repository's contents as unused.

use std::sync::Arc;

use async_trait::async_trait;

use self::component::{Component, ComponentPage};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ext::{ExtHost, Options};
use crate::model::{EcosystemId, ListingDepth, Release, Version};
use crate::net::{ByteLimit, Req, encode_unreserved, normalized_base};
use crate::repo::Mapping;
use crate::repo::enumerate::{Cursor, Enumerator, Found, Page};

mod component;
mod raw;
mod registry;
#[cfg(test)]
mod testing;

/// The components endpoint, relative to the Nexus base URL.
const COMPONENTS: &str = "service/rest/v1/components";

/// A page of components with their assets. Nexus returns a fixed page size
/// of ten components; a page of them with every asset is small.
const PAGE_LIMIT: ByteLimit = ByteLimit::mib(8);

pub struct NexusEnumerator {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
    ecosystem: EcosystemId,

    /// How a raw repository's paths become coordinates.
    ///
    /// Meaningless for every other format, which is why it is refused
    /// there: a `mapping` on a Maven enumerator is a mistake somebody made,
    /// and silently ignoring it would leave them believing it took effect.
    mapping: Mapping,
}

impl NexusEnumerator {
    /// Build from configuration.
    ///
    /// The repository name and the ecosystem are both **required**. Nexus
    /// reports a format per component, so the ecosystem could in principle
    /// be inferred -- but an enumerator has to describe itself before it walks
    /// anything, and a description that could not be produced until after
    /// the first page arrived would be no description at all.
    /// Auto-detection is a later convenience; declaring it is the first
    /// cut.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let (repository, ecosystem) = crate::repo::manager::config(options, "nexus")?;
        let mapping = crate::repo::manager::raw_mapping(options, &ecosystem)?;

        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            repository,
            ecosystem,
            mapping,
        })
    }

    fn page_url(&self, cursor: Option<&Cursor>) -> String {
        let mut url = format!(
            "{}/{COMPONENTS}?repository={}",
            self.base_url,
            encode_unreserved(&self.repository)
        );

        if let Some(cursor) = cursor {
            url.push_str("&continuationToken=");
            url.push_str(&encode_unreserved(cursor.as_str()));
        }

        url
    }

    /// Turn one component into its artifacts, or explain why not.
    ///
    /// Read as raw, any format will do: a path is a path whatever wrote
    /// it, so a Maven repository can be walked as raw files. Each asset is
    /// read on its own, and `manager::fold` joins those the mapping puts in
    /// one artifact.
    fn found(&self, component: &Component, ctx: &Ctx) -> Vec<Found> {
        if self.ecosystem.as_str() == EcosystemId::RAW {
            return component
                .per_asset()
                .iter()
                .filter_map(|one| self.raw_found(one, ctx))
                .collect();
        }

        self.registry_found(component, ctx).into_iter().collect()
    }

    /// The component's files. A Maven component holds its checksum
    /// sidecars as assets of their own; `repo::Omit` leaves them out.
    fn listed(&self, component: &Component) -> Vec<crate::repo::enumerate::Listed> {
        component.listed()
    }

    fn classify(&self, version: &str) -> Version {
        // Nexus lists each snapshot build as a component of its own, under
        // its timestamped version. Named by its snapshot instead, the
        // builds fold into one artifact, as the layout holds them.
        let snapshot = match self.ecosystem.as_str() {
            EcosystemId::MAVEN => crate::ecosystem::maven::snapshot_of(version),
            _ => None,
        };
        let version = snapshot.as_deref().unwrap_or(version);

        match crate::ecosystem::open(self.ecosystem.as_str()) {
            Ok(ecosystem) => ecosystem.version(version),

            // Unreachable: `open` refused an unknown ecosystem. Kept
            // total rather than panicking on a path a future ecosystem
            // registry change could reach.
            Err(_) => Version::new(version, Release::PreRelease),
        }
    }
}

#[async_trait]
impl Enumerator for NexusEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        std::slice::from_ref(&self.ecosystem)
    }

    fn reports_last_download(&self) -> bool {
        crate::repo::manager::REPORTS_LAST_DOWNLOAD
    }

    fn depth(&self) -> ListingDepth {
        crate::repo::manager::LISTING_DEPTH
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        let url = self.page_url(cursor);
        let page: ComponentPage = crate::ext::fetch_json(
            &*self.host,
            &Req::get(&url),
            PAGE_LIMIT,
            "nexus component page",
            ctx,
        )
        .await?;

        let found = crate::repo::manager::fold(
            page.items
                .iter()
                .flat_map(|component| self.found(component, ctx)),
        );

        // An empty page is **not** the end of the walk. Nexus filters after
        // paging, so a page can come back with no items and a cursor that
        // still has the rest of the repository behind it; stopping here
        // would silently truncate the catalog.
        match page.continuation_token {
            Some(token) if !token.is_empty() => Ok(Page::more(found, Cursor::new(token))),
            _ => Ok(Page::last(found)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::Error;
    use crate::core::problem::Code;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::LastDownload;
    use crate::net::FixtureClient;
    use crate::repo::enumerate::Enumerator;
    use crate::repo::nexus::enumerator::testing::*;
    use std::sync::Arc;

    // -- Configuration ----------------------------------------------------

    /// An enumerator has to describe itself before it walks anything, so the
    /// ecosystem cannot wait for the first page.
    /// `Result<NexusEnumerator>` is not `Debug`, so the error has to come out
    /// by hand.
    fn refused(options: &Options) -> Error {
        match NexusEnumerator::open(BASE, options, idle()) {
            Err(err) => err,
            Ok(_) => panic!("should have been refused"),
        }
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
    fn ecosystem_unknown_refused() {
        let bogus = options(serde_json::json!({
            "repository": REPO,
            "ecosystem": "cargo",
        }));

        assert!(refused(&bogus).to_string().contains("cargo"));
    }

    #[test]
    fn ecosystem_declared_as_pointed_at() {
        let enumerator = enumerator("maven", idle());

        assert_eq!(enumerator.ecosystems(), [EcosystemId::maven()]);

        // The claim that separates a manager from every registry index.
        assert!(enumerator.reports_last_download());
    }

    // -- Walking ----------------------------------------------------------

    const MAVEN_PAGE: &str = r#"{
        "items": [
            {
                "format": "maven2",
                "group": "org.apache.commons",
                "name": "commons-lang3",
                "version": "3.14.0",
                "assets": [
                    {"lastDownloaded": "2024-06-01T12:00:00.000+00:00"},
                    {"lastDownloaded": "2024-07-01T12:00:00.000+00:00"}
                ]
            },
            {
                "format": "maven2",
                "group": "org.example",
                "name": "unused",
                "version": "1.0",
                "assets": [{"lastDownloaded": null}]
            },
            {
                "format": "maven2",
                "group": "org.example",
                "name": "silent",
                "version": "1.0",
                "assets": [{}]
            }
        ],
        "continuationToken": "next-page"
    }"#;

    #[tokio::test]
    async fn component_becomes_artifact() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_PAGE, "maven", &ctx).await;

        assert_eq!(page.found.len(), 3);
        assert_eq!(
            page.found[0].id.purl(),
            "pkg:maven/org.apache.commons/commons-lang3"
        );
        assert_eq!(
            page.found[0].version.as_ref().expect("versioned").text(),
            "3.14.0"
        );
    }

    /// A component's files join its artifact, less the checksum sidecars
    /// a target writes for itself, through the wrapper every built
    /// enumerator gets.
    #[tokio::test]
    async fn component_maven_assets_listed() {
        let body = r#"{"items": [{
            "format": "maven2", "group": "example.lib", "name": "echo", "version": "1.0",
            "assets": [
                {"path": "example/lib/echo/1.0/echo-1.0.jar",
                 "downloadUrl": "h://nexus.test/r/example/lib/echo/1.0/echo-1.0.jar",
                 "checksum": {"sha1": "aa"}},
                {"path": "example/lib/echo/1.0/echo-1.0.jar.sha1",
                 "downloadUrl": "h://nexus.test/r/example/lib/echo/1.0/echo-1.0.jar.sha1"},
                {"path": "example/lib/echo/1.0/echo-1.0.module",
                 "downloadUrl": "h://nexus.test/r/example/lib/echo/1.0/echo-1.0.module"},
                {"path": "example/lib/echo/1.0/echo-1.0-sources.jar.asc",
                 "downloadUrl": "h://nexus.test/r/example/lib/echo/1.0/echo-1.0-sources.jar.asc"}
            ]}]}"#;
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(url(None), body.to_owned()),
        ));
        let subject = crate::repo::OmittingEnumerator::new(
            Arc::new(enumerator("maven", host)),
            crate::repo::Omit::default(),
        );
        let page = subject.walk(None, &ctx).await.expect("walked");

        let names: Vec<&str> = page.found[0]
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(
            names,
            [
                "echo-1.0.jar",
                "echo-1.0.module",
                "echo-1.0-sources.jar.asc"
            ]
        );
    }

    /// Each snapshot build is a component of its own in Nexus. Named by
    /// their snapshot, the builds fold into one artifact holding every
    /// build's files.
    #[tokio::test]
    async fn component_snapshot_builds_fold_into_one() {
        let body = r#"{"items": [
            {"format": "maven2", "group": "g", "name": "echo", "version": "2.0-20240101.123456-1",
             "assets": [{"path": "g/echo/2.0-SNAPSHOT/echo-2.0-20240101.123456-1.jar",
                         "downloadUrl": "h://nexus.test/r/g/echo/2.0-SNAPSHOT/echo-2.0-20240101.123456-1.jar"}]},
            {"format": "maven2", "group": "g", "name": "echo", "version": "2.0-20240102.000000-2",
             "assets": [{"path": "g/echo/2.0-SNAPSHOT/echo-2.0-20240102.000000-2.jar",
                         "downloadUrl": "h://nexus.test/r/g/echo/2.0-SNAPSHOT/echo-2.0-20240102.000000-2.jar"}]}
        ]}"#;
        let ctx = ctx();
        let (page, _) = walk_with(body, "maven", &ctx).await;

        let [found] = page.found.as_slice() else {
            panic!("expected one artifact, got {:?}", page.found);
        };

        assert_eq!(
            found.version.as_ref().map(Version::text),
            Some("2.0-SNAPSHOT")
        );
        assert_eq!(found.files.len(), 2);
    }

    /// The three states Nexus can distinguish, and the reason this enumerator
    /// was worth building.
    #[tokio::test]
    async fn usage_three_states_reported() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_PAGE, "maven", &ctx).await;

        // A timestamp: the most recent across the component's assets, since
        // downloading any file of it is using the artifact.
        let expected = chrono::DateTime::parse_from_rfc3339("2024-07-01T12:00:00.000+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(page.found[0].last_download, LastDownload::At(expected));

        // An explicit null: Nexus tracks downloads and has recorded none.
        assert_eq!(page.found[1].last_download, LastDownload::Never);

        // The field absent entirely: an older server that does not report
        // it. Not evidence of disuse, and a retention tool must not read it
        // as such.
        assert_eq!(page.found[2].last_download, LastDownload::Unknown);
    }

    /// The distinction the doubled `Option` exists for. Without it serde
    /// folds both into `None` and a whole repository reads as unused.
    #[tokio::test]
    async fn usage_absent_field_and_null_differ() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_PAGE, "maven", &ctx).await;

        assert_ne!(
            page.found[1].last_download, page.found[2].last_download,
            "'never downloaded' and 'not reported' must not collapse"
        );

        assert!(
            !page.found[2]
                .last_download
                .known_unused_since(chrono::Utc::now())
        );
        assert!(
            page.found[1]
                .last_download
                .known_unused_since(chrono::Utc::now())
        );
    }

    #[tokio::test]
    async fn token_continues_walk() {
        let ctx = ctx();
        let (page, _) = walk_with(MAVEN_PAGE, "maven", &ctx).await;

        assert!(page.has_more());
        assert_eq!(page.next.expect("token").as_str(), "next-page");
    }

    /// Nexus filters after paging, so a page can be empty and still have
    /// the rest of the repository behind it.
    #[tokio::test]
    async fn token_empty_page_not_end() {
        let ctx = ctx();
        let (page, _) = walk_with(
            r#"{"items": [], "continuationToken": "more"}"#,
            "maven",
            &ctx,
        )
        .await;

        assert!(page.found.is_empty());
        assert!(page.has_more());
    }

    #[tokio::test]
    async fn token_missing_ends_walk() {
        let ctx = ctx();

        for body in [
            r#"{"items": []}"#,
            r#"{"items": [], "continuationToken": null}"#,
            r#"{"items": [], "continuationToken": ""}"#,
        ] {
            let (page, _) = walk_with(body, "maven", &ctx).await;

            assert!(!page.has_more(), "{body}");
        }
    }

    #[tokio::test]
    async fn token_sent_back_encoded() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(url(Some("a%2Fb%3D")), r#"{"items": []}"#),
        ));

        enumerator("maven", host.clone())
            .walk(Some(&Cursor::new("a/b=")), &ctx)
            .await
            .expect("walked");

        assert_eq!(host.hits(&url(Some("a%2Fb%3D"))), 1);
    }

    /// Release status is the ecosystem's judgment. `31.1-jre` is a Maven
    /// release and `1.0-rc1` is not, and neither is knowable from the
    /// string alone.
    #[tokio::test]
    async fn component_versions_classified_by_ecosystem() {
        let body = r#"{"items": [
            {"format": "maven2", "group": "g", "name": "a", "version": "31.1-jre"},
            {"format": "maven2", "group": "g", "name": "b", "version": "1.0-rc1"}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "maven", &ctx).await;

        assert!(!page.found[0].version.as_ref().unwrap().is_pre_release());
        assert!(page.found[1].version.as_ref().unwrap().is_pre_release());
    }

    // -- Edges ------------------------------------------------------------

    #[tokio::test]
    async fn component_without_version_found() {
        let body = r#"{"items": [{"format": "maven2", "group": "g", "name": "a"}]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "maven", &ctx).await;

        assert_eq!(page.found.len(), 1);
        assert_eq!(page.found[0].version, None);
    }

    #[tokio::test]
    async fn page_malformed_is_error() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(url(None), "{["),
        ));

        let err = enumerator("maven", host.clone())
            .walk(None, &ctx)
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    /// Nexus offers no cheap total, so `--sample-size=N%` is a clear error
    /// rather than a guess against an invented one.
    #[tokio::test]
    async fn count_none_claimed() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(FixtureClient::new()));

        assert_eq!(
            enumerator("maven", host.clone())
                .count(&ctx)
                .await
                .expect("counted"),
            None
        );
    }

    #[test]
    fn query_values_encoded() {
        assert_eq!(encode_unreserved("maven-releases"), "maven-releases");
        assert_eq!(encode_unreserved("a/b=c&d"), "a%2Fb%3Dc%26d");
        assert_eq!(encode_unreserved("sp ace"), "sp%20ace");
    }

    /// The mapping decides the coordinate, and defaults to the reading that
    /// matches how a raw repository is actually laid out.
    #[test]
    fn mapping_read_defaults_to_directory() {
        assert_eq!(
            NexusEnumerator::open(BASE, &config("raw"), idle())
                .expect("opens")
                .mapping,
            Mapping::Directory
        );

        let declared = options(serde_json::json!({
            "repository": REPO,
            "ecosystem": "raw",
            "mapping": "as-is",
        }));

        assert_eq!(
            NexusEnumerator::open(BASE, &declared, idle())
                .expect("opens")
                .mapping,
            Mapping::AsIs
        );
    }

    /// A `mapping` where it means nothing is refused rather than ignored.
    ///
    /// A setting that is silently ignored leaves whoever wrote it believing
    /// it took effect, which surfaces only as a report that looks subtly
    /// wrong.
    #[test]
    fn mapping_on_non_raw_refused() {
        let confused = options(serde_json::json!({
            "repository": REPO,
            "ecosystem": "maven",
            "mapping": "directory",
        }));

        let err = refused(&confused).to_string();

        assert!(err.contains("mapping"), "{err}");
        assert!(err.contains("maven"), "{err}");
    }

    /// An unknown mapping names the alternatives rather than defaulting.
    #[test]
    fn mapping_unknown_refused() {
        let bogus = options(serde_json::json!({
            "repository": REPO,
            "ecosystem": "raw",
            "mapping": "regex",
        }));

        assert!(refused(&bogus).to_string().contains("regex"));
    }
}
