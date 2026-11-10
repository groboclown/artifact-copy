//! What an Artifact Keeper repository stores for one version, from its
//! artifact listing.
//!
//! ```text
//!   GET {base}/api/v1/repositories/{repository}/artifacts?path_prefix={directory}/&per_page=100
//! ```
//!
//! The prefix is the directory the server stores a version under, which is
//! its own layout rather than the URL a client fetches:
//!
//! | Ecosystem | Stored under |
//! | --- | --- |
//! | maven | `org/example/lib/1.0/` |
//! | npm | `@scope/name/1.0.0/` (listed back as `@scope/name/-/...`) |
//! | pypi | `{normalized}/{version}/` |
//!
//! Versions stay with the protocol source: the server rebuilds
//! `maven-metadata.xml` itself (measured on the local server), and npm's
//! packument and PyPI's simple index are generated from what it holds.
//!
//! # A proxy repository
//!
//! Under `mode: proxy` the listing is a Remote's cache catalog, in the
//! layout `cache` describes.  Its protocol route answers with the
//! upstream's versions and files, so the cache decides both instead: the
//! versions are those it holds a file of, and a version's files are the
//! ones it holds ([`Lister::restricts`]).

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::api::Mode;
use super::cache;
use super::listing::Item;

use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ext::ExtHost;
use crate::model::{ArtifactId, EcosystemId, FileRef, Version};
use crate::repo::PageCap;
use crate::repo::manager::{Lister, Listing};

pub(super) struct ArtifactKeeperLister {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
    ecosystem: EcosystemId,
    page_cap: PageCap,

    /// Whether the listing is a Remote's cache catalog.
    mode: Mode,
}

impl ArtifactKeeperLister {
    pub(super) fn new(
        base_url: String,
        host: Arc<dyn ExtHost>,
        repository: String,
        ecosystem: EcosystemId,
        page_cap: PageCap,
    ) -> Self {
        Self {
            base_url,
            host,
            repository,
            ecosystem,
            page_cap,
            mode: Mode::Hosted,
        }
    }

    /// Read the listing in `mode`'s layout.
    pub(super) fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    async fn under(&self, prefix: &str, ctx: &Ctx) -> Result<Vec<Item>> {
        super::prefixed(
            &*self.host,
            &self.base_url,
            &self.repository,
            prefix,
            self.page_cap,
            ctx,
        )
        .await
    }

    /// The cached files of one version, with their fetch URLs.
    async fn cached(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Result<Vec<Item>> {
        let prefix = cache::version_prefix(id, version, Default::default());
        let items = self.under(&prefix, ctx).await?;

        Ok(items
            .into_iter()
            .filter(|item| !cache::skipped(&self.ecosystem, item.name()))
            .filter(|item| {
                cache::coordinate(&self.ecosystem, Default::default(), &item.path)
                    .is_some_and(|at| at.is(id) && at.version.as_deref() == Some(version.text()))
            })
            .collect())
    }

    /// The directory one version is stored under, with its trailing `/` so
    /// `1.0` does not reach `1.0.1`.
    fn directory(&self, id: &ArtifactId, version: &Version) -> String {
        let name = match self.ecosystem.as_str() {
            EcosystemId::MAVEN => format!(
                "{}/{}",
                id.namespace().unwrap_or_default().replace('.', "/"),
                id.name()
            ),
            EcosystemId::PYPI => crate::ecosystem::pypi::normalize(id.name()),

            // npm: a scope is its own directory.
            _ => match id.namespace() {
                Some(scope) => format!("{scope}/{}", id.name()),
                None => id.name().to_owned(),
            },
        };

        format!("{name}/{}/", version.text())
    }
}

#[async_trait]
impl Lister for ArtifactKeeperLister {
    /// The cached versions, under a proxy; otherwise the protocol's.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Option<Vec<String>>> {
        if !self.mode.cached() {
            return Ok(None);
        }

        let items = self
            .under(&cache::name_prefix(id, Default::default()), ctx)
            .await?;

        // Sorted by text rather than kept in listing order: the caller
        // orders them by the ecosystem's rules.
        let found: BTreeSet<String> = items
            .iter()
            .filter(|item| crate::ecosystem::joins_listing(&self.ecosystem, item.name()))
            .filter_map(|item| cache::coordinate(&self.ecosystem, Default::default(), &item.path))
            .filter(|at| at.is(id))
            .filter_map(|at| at.version)
            .collect();

        Ok(Some(found.into_iter().collect()))
    }

    async fn listing(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Result<Listing> {
        let items = if self.mode.cached() {
            self.cached(id, version, ctx).await?
        } else {
            self.under(&self.directory(id, version), ctx).await?
        };

        let mut listing = Listing {
            files: Vec::new(),
            published: None,
        };

        for item in &items {
            listing.published = listing.published.max(item.published());

            let url = match self.mode.cached() {
                true => cache::file_url(
                    &self.base_url,
                    &self.ecosystem,
                    &self.repository,
                    &item.path,
                ),
                false => super::download_url(&self.base_url, &self.repository, &item.path),
            };
            let mut file = FileRef::new(item.name(), url);

            file.size = item.size();
            file.digests = item.digests();
            listing.files.push(file);
        }

        Ok(listing)
    }

    fn restricts(&self) -> bool {
        self.mode.cached()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::TestHost;
    use crate::model::{Cause, Release};
    use crate::net::FixtureClient;

    const BASE: &str = "h://keeper.test";
    const REPO: &str = "maven-a";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    fn lister(client: FixtureClient, ecosystem: EcosystemId) -> ArtifactKeeperLister {
        ArtifactKeeperLister::new(
            BASE.into(),
            Arc::new(TestHost::new(client)),
            REPO.into(),
            ecosystem,
            super::super::page_cap(&crate::ext::Options::default()).expect("default cap"),
        )
    }

    fn version(text: &str) -> Version {
        Version::new(text, Release::General)
    }

    #[test]
    fn directory_follows_stored_layout() {
        let maven = ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib");
        let npm = ArtifactId::new(EcosystemId::npm(), Some("@acme"), "widget");
        let pypi = ArtifactId::new(EcosystemId::pypi(), None, "My_Pkg");

        let idle = || FixtureClient::new();

        assert_eq!(
            lister(idle(), EcosystemId::maven()).directory(&maven, &version("1.0")),
            "org/example/lib/1.0/"
        );
        assert_eq!(
            lister(idle(), EcosystemId::npm()).directory(&npm, &version("2.0.0")),
            "@acme/widget/2.0.0/"
        );
        assert_eq!(
            lister(idle(), EcosystemId::pypi()).directory(&pypi, &version("1.0")),
            "my-pkg/1.0/"
        );
    }

    #[tokio::test]
    async fn listing_follows_cursor() {
        let first = format!(
            "{BASE}/api/v1/repositories/{REPO}/artifacts?path_prefix=org%2Fexample%2Flib%2F1.0%2F&per_page=100"
        );
        let client = FixtureClient::new()
            .with_body(
                first.clone(),
                r#"{"items": [{"path": "org/example/lib/1.0/lib-1.0.jar", "size_bytes": 42,
                     "checksum_sha256": "aa", "created_at": "2026-10-05T16:15:14.905661Z"}],
                    "has_more": true, "next_cursor": "abc"}"#,
            )
            .with_body(
                format!("{first}&cursor=abc"),
                r#"{"items": [{"path": "org/example/lib/1.0/lib-1.0.module",
                     "created_at": "2026-10-05T16:15:17.128427Z"}],
                    "has_more": false}"#,
            );

        let id = ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib");
        let listing = lister(client, EcosystemId::maven())
            .listing(&id, &version("1.0"), &ctx())
            .await
            .expect("lists");

        let names: Vec<&str> = listing.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(names, ["lib-1.0.jar", "lib-1.0.module"]);
        assert_eq!(listing.files[0].size, Some(42));
        assert_eq!(
            listing.files[0].url,
            format!("{BASE}/api/v1/repositories/{REPO}/download/org/example/lib/1.0/lib-1.0.jar")
        );
        assert_eq!(
            listing.published.map(|when| when.to_rfc3339()),
            Some("2026-10-05T16:15:17.128427+00:00".to_owned())
        );
    }

    fn proxy(client: FixtureClient, ecosystem: EcosystemId) -> ArtifactKeeperLister {
        lister(client, ecosystem).with_mode(Mode::Proxy)
    }

    fn cached_listing(prefix: &str) -> String {
        format!("{BASE}/api/v1/repositories/{REPO}/artifacts?path_prefix={prefix}&per_page=100")
    }

    #[tokio::test]
    async fn proxy_versions_from_cache() {
        let client = FixtureClient::new().with_body(
            cached_listing("simple%2Frequests%2F"),
            r#"{"items": [
                {"path": "simple/requests/requests-2.31.0.tar.gz"},
                {"path": "simple/requests/requests-2.31.0-py3-none-any.whl"},
                {"path": "simple/requests/requests-2.30.0.tar.gz"},
                {"path": "simple/requests/requests-2.30.0.tar.gz.sha256"}
            ], "has_more": false}"#,
        );

        let id = ArtifactId::new(EcosystemId::pypi(), None, "requests");
        let source = proxy(client, EcosystemId::pypi());

        assert!(source.restricts());
        assert_eq!(
            source.versions(&id, &ctx()).await.expect("lists"),
            Some(vec!["2.30.0".to_owned(), "2.31.0".to_owned()])
        );
    }

    #[tokio::test]
    async fn proxy_listing_keeps_own_version() {
        let client = FixtureClient::new().with_body(
            cached_listing("%40acme%2Fwidget%2F-%2Fwidget-2.0.0"),
            r#"{"items": [
                {"path": "@acme/widget/-/widget-2.0.0.tgz", "size_bytes": 5},
                {"path": "@acme/widget/-/widget-2.0.0-rc.1.tgz"}
            ], "has_more": false}"#,
        );

        let id = ArtifactId::new(EcosystemId::npm(), Some("@acme"), "widget");
        let listing = proxy(client, EcosystemId::npm())
            .listing(&id, &version("2.0.0"), &ctx())
            .await
            .expect("lists");

        assert_eq!(listing.files.len(), 1);
        assert_eq!(listing.files[0].name, "widget-2.0.0.tgz");
        assert_eq!(
            listing.files[0].url,
            format!("{BASE}/npm/{REPO}/@acme/widget/-/widget-2.0.0.tgz")
        );
    }

    #[tokio::test]
    async fn hosted_defers_versions() {
        let id = ArtifactId::new(EcosystemId::pypi(), None, "requests");
        let source = lister(FixtureClient::new(), EcosystemId::pypi());

        assert!(!source.restricts());
        assert_eq!(source.versions(&id, &ctx()).await.expect("defers"), None);
    }
}
