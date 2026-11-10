//! Reading a proxy repository from its cache catalog alone
//! (`mode: proxy-cache`).
//!
//! ```text
//!   GET {base}/api/v1/repositories/{repository}/artifacts?path_prefix={prefix}&per_page=100
//! ```
//!
//! The listing of a Remote repository is the server's cache catalog, so it
//! answers which versions and files are cached, with their digests, sizes,
//! and the time each was cached.  No protocol request is made: the
//! protocol route passes through to the upstream, which is exactly what
//! this mode stays away from.  That leaves nothing to read dependencies or
//! a license from, so an artifact here has neither; `mode: proxy` reads
//! them through the protocol and lets the catalog decide the rest.
//!
//! The prefix is a literal match and wider than the artifact (see
//! `cache`), so every path that comes back is read again and kept only
//! where it names the artifact and version asked for.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::cache;
use super::listing::Item;
use super::{page_cap, prefixed};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::{Expectation, normalized_base};
use crate::repo::{Downloaded, Mapping, PageCap, Source};

pub(super) struct ArtifactKeeperCacheSource {
    base_url: String,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    repository: String,
    ecosystem_id: EcosystemId,
    ecosystem: Arc<dyn Ecosystem>,
    page_cap: PageCap,
}

impl ArtifactKeeperCacheSource {
    /// For a registry ecosystem; a raw repository has no protocol to stay
    /// away from, and is read by the raw source.
    pub(super) fn open(
        base_url: &str,
        options: &Options,
        host: Arc<dyn ExtHost>,
        repository: String,
        ecosystem: EcosystemId,
    ) -> Result<Self> {
        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            repository,
            ecosystem: crate::ecosystem::open(ecosystem.as_str())?,
            ecosystem_id: ecosystem,
            page_cap: page_cap(options)?,
        })
    }

    async fn under(&self, prefix: &str, ctx: &Ctx) -> Result<Vec<Item>> {
        prefixed(
            &*self.host,
            &self.base_url,
            &self.repository,
            prefix,
            self.page_cap,
            ctx,
        )
        .await
    }

    /// Whether a listed file is one of an artifact's files at all.
    fn joins(&self, item: &Item) -> bool {
        crate::ecosystem::joins_listing(&self.ecosystem_id, item.name())
            && !cache::skipped(&self.ecosystem_id, item.name())
    }

    fn file_of(&self, item: &Item) -> FileRef {
        let mut file = FileRef::new(
            item.name(),
            cache::file_url(
                &self.base_url,
                &self.ecosystem_id,
                &self.repository,
                &item.path,
            ),
        );

        file.size = item.size();
        file.digests = item.digests();

        file
    }

    fn absent(&self, id: &ArtifactId, prefix: &str) -> Error {
        Error::Absent {
            what: "cached artifact",
            url: super::download_url(&self.base_url, &self.repository, prefix),
            name: id.purl(),
        }
    }
}

#[async_trait]
impl Source for ArtifactKeeperCacheSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&*self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![self.ecosystem_id.clone()]
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let items = self
            .under(&cache::name_prefix(id, Mapping::default()), ctx)
            .await?;

        // Sorted by text rather than kept in listing order: a listing order
        // is not a version order.
        let found: BTreeSet<String> = items
            .iter()
            .filter(|item| self.joins(item))
            .filter_map(|item| {
                cache::coordinate(&self.ecosystem_id, Mapping::default(), &item.path)
            })
            .filter(|at| at.is(id))
            .filter_map(|at| at.version)
            .collect();

        Ok(self
            .version_handler(id)?
            .classify(&found.into_iter().collect::<Vec<_>>()))
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        // Every ecosystem read here is versioned, so a cache holds nothing
        // that answers for no version.
        let Some(version) = version else {
            return Err(self.absent(id, &cache::name_prefix(id, Mapping::default())));
        };

        let prefix = cache::version_prefix(id, version, Mapping::default());
        let items = self.under(&prefix, ctx).await?;

        let mine: Vec<&Item> = items
            .iter()
            .filter(|item| self.joins(item))
            .filter(|item| {
                cache::coordinate(&self.ecosystem_id, Mapping::default(), &item.path)
                    .is_some_and(|at| at.is(id) && at.version.as_deref() == Some(version.text()))
            })
            .collect();

        if mine.is_empty() {
            // `Absent`, so a proxy asks its next upstream.
            return Err(self.absent(id, &prefix));
        }

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: Some(version.clone()),
            files: mine.iter().map(|item| self.file_of(item)).collect(),

            // Only the protocol carries one.
            license: None,

            // When the newest file was cached: the nearest the catalog
            // comes to a publish time.
            published: mine.iter().filter_map(|item| item.published()).max(),
        })
    }

    /// None: only the protocol carries them, and this mode makes no
    /// protocol request.
    async fn deps(&self, _: &ResolvedArtifact, _: &Ctx) -> Result<Vec<Dependency>> {
        Ok(Vec::new())
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        crate::repo::download(&*self.host, file, expect, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.host.permits(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{TestHost, options};
    use crate::model::{Cause, Release};
    use crate::net::FixtureClient;

    const BASE: &str = "h://keeper.test";
    const REPO: &str = "pypi-remote";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "requests".into(),
        })
    }

    fn listing(prefix: &str) -> String {
        format!("{BASE}/api/v1/repositories/{REPO}/artifacts?path_prefix={prefix}&per_page=100")
    }

    fn source(ecosystem: EcosystemId, client: FixtureClient) -> ArtifactKeeperCacheSource {
        ArtifactKeeperCacheSource::open(
            BASE,
            &options(serde_json::json!({"repository": REPO})),
            Arc::new(TestHost::new(client)),
            REPO.into(),
            ecosystem,
        )
        .expect("opens")
    }

    fn requests() -> ArtifactId {
        ArtifactId::new(EcosystemId::pypi(), None, "requests")
    }

    const REQUESTS: &str = r#"{"items": [
        {"path": "simple/requests/requests-2.31.0.tar.gz", "size_bytes": 9,
         "checksum_sha256": "bb", "created_at": "2026-10-05T16:15:14Z"},
        {"path": "simple/requests/requests-2.31.0-py3-none-any.whl",
         "created_at": "2026-10-06T08:00:00Z"},
        {"path": "simple/requests/requests-2.31.0-py3-none-any.whl.metadata"},
        {"path": "simple/requests/requests-2.30.0.tar.gz"}
    ], "has_more": false}"#;

    #[tokio::test]
    async fn versions_are_cached_ones() {
        let client = FixtureClient::new().with_body(listing("simple%2Frequests%2F"), REQUESTS);
        let versions = source(EcosystemId::pypi(), client)
            .versions(&requests(), &ctx())
            .await
            .expect("lists");
        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(texts.len(), 2, "{texts:?}");
        assert!(texts.contains(&"2.30.0") && texts.contains(&"2.31.0"));
    }

    #[tokio::test]
    async fn metadata_holds_cached_files_only() {
        let client = FixtureClient::new().with_body(listing("simple%2Frequests%2F"), REQUESTS);
        let artifact = source(EcosystemId::pypi(), client)
            .metadata(
                &requests(),
                Some(&Version::new("2.31.0", Release::General)),
                &ctx(),
            )
            .await
            .expect("resolves");

        let names: Vec<&str> = artifact.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(
            names,
            ["requests-2.31.0.tar.gz", "requests-2.31.0-py3-none-any.whl"]
        );
        assert_eq!(artifact.files[0].size, Some(9));
        assert_eq!(artifact.files[0].digests.len(), 1);
        assert_eq!(
            artifact.files[0].url,
            format!("{BASE}/pypi/{REPO}/simple/requests/requests-2.31.0.tar.gz")
        );
        assert_eq!(
            artifact.published.map(|when| when.to_rfc3339()),
            Some("2026-10-06T08:00:00+00:00".to_owned())
        );
        assert!(artifact.license.is_none());
    }

    #[tokio::test]
    async fn metadata_uncached_version_is_absent() {
        let client = FixtureClient::new().with_body(listing("simple%2Frequests%2F"), REQUESTS);
        let err = source(EcosystemId::pypi(), client)
            .metadata(
                &requests(),
                Some(&Version::new("1.0.0", Release::General)),
                &ctx(),
            )
            .await
            .expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    #[tokio::test]
    async fn metadata_maven_version_directory() {
        let client = FixtureClient::new().with_body(
            listing("org%2Fexample%2Flib%2F1.0%2F"),
            r#"{"items": [
                {"path": "org/example/lib/1.0/lib-1.0.jar"},
                {"path": "org/example/lib/1.0/lib-1.0.jar.sha1"},
                {"path": "org/example/lib/1.0/lib-1.0.pom"}
            ], "has_more": false}"#,
        );

        let id = ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib");
        let artifact = source(EcosystemId::maven(), client)
            .metadata(&id, Some(&Version::new("1.0", Release::General)), &ctx())
            .await
            .expect("resolves");
        let names: Vec<&str> = artifact.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(names, ["lib-1.0.jar", "lib-1.0.pom"]);
        assert_eq!(
            artifact.files[0].url,
            format!("{BASE}/maven/{REPO}/org/example/lib/1.0/lib-1.0.jar")
        );
    }
}
