//! Reading an Artifact Keeper generic repository.
//!
//! A generic repository has no protocol, so the artifact listing is the
//! whole source, as Nexus's asset search is for its raw repositories:
//!
//! ```text
//!   GET {base}/api/v1/repositories/{repository}/artifacts?path_prefix={prefix}&per_page=100
//! ```
//!
//! The prefix is a literal match and wider than the artifact, so every path
//! that comes back is read again through the [`Mapping`] and kept only
//! where it names the artifact asked for.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::listing::Item;
use super::{MAPPING, download_url, page_cap, prefix_of, prefixed};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::{Expectation, normalized_base};
use crate::repo::{Downloaded, Mapping, PageCap, Source};
use crate::version::VersionHandler;

pub(super) struct ArtifactKeeperRawSource {
    base_url: String,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    repository: String,
    mapping: Mapping,
    ecosystem: crate::ecosystem::Raw,
    page_cap: PageCap,
}

impl ArtifactKeeperRawSource {
    /// The mapping defaults to [`Mapping::Directory`], as the target's
    /// does, so a copy between two that leave it unset reads files back
    /// where they were written.
    pub(super) fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let repository = options
            .require_string(crate::ext::options::REPOSITORY)?
            .to_owned();

        let mapping = options
            .string(MAPPING)?
            .map(Mapping::parse)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            repository,
            mapping,
            ecosystem: crate::ecosystem::Raw,
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

    fn file_of(&self, item: &Item, name: &str) -> FileRef {
        let mut file = FileRef::new(
            name,
            download_url(&self.base_url, &self.repository, &item.path),
        );

        file.size = item.size();
        file.digests = item.digests();

        file
    }
}

#[async_trait]
impl Source for ArtifactKeeperRawSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![EcosystemId::raw()]
    }

    /// Only where the mapping declares a segment is a version.
    fn versioned(&self, _: &ArtifactId) -> bool {
        self.mapping == Mapping::NameVersionFile
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        if !self.versioned(id) {
            return Ok(Vec::new());
        }

        let name = id.name().trim_matches('/');
        let items = self
            .under(&prefix_of(self.mapping, name, None), ctx)
            .await?;

        // Sorted by text rather than kept in listing order: a listing order
        // is not a version order.
        let found: BTreeSet<String> = items
            .iter()
            .filter_map(|item| self.mapping.read(&item.path))
            .filter(|at| at.name == name)
            .filter_map(|at| at.version)
            .collect();

        Ok(self
            .ecosystem
            .classify(&found.into_iter().collect::<Vec<_>>()))
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let name = id.name().trim_matches('/');
        let wanted = version.map(Version::text);
        let prefix = prefix_of(self.mapping, name, version);
        let items = self.under(&prefix, ctx).await?;

        let mine: Vec<(&Item, String)> = items
            .iter()
            .filter_map(|item| {
                let at = self.mapping.read(&item.path)?;

                (at.name == name && at.version.as_deref() == wanted).then_some((item, at.file))
            })
            .collect();

        if mine.is_empty() {
            // `Absent`, so a proxy asks its next upstream.
            return Err(Error::Absent {
                what: "artifact",
                url: download_url(&self.base_url, &self.repository, &prefix),
                name: id.purl(),
            });
        }

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: version.cloned(),
            files: mine
                .iter()
                .map(|(item, file)| self.file_of(item, file))
                .collect(),

            // A generic repository declares none.
            license: None,

            // The newest: a publish window asks whether anything here is
            // too new to trust yet.
            published: mine.iter().filter_map(|(item, _)| item.published()).max(),
        })
    }

    /// None: a generic repository publishes no dependency information.
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
    use crate::model::Cause;
    use crate::net::FixtureClient;

    const BASE: &str = "h://keeper.test";
    const REPO: &str = "generic-a";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "raw".into() })
    }

    fn listing(prefix: &str) -> String {
        format!("{BASE}/api/v1/repositories/{REPO}/artifacts?path_prefix={prefix}&per_page=100")
    }

    fn source(mapping: &str, client: FixtureClient) -> ArtifactKeeperRawSource {
        ArtifactKeeperRawSource::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "mapping": mapping})),
            Arc::new(TestHost::new(client)),
        )
        .expect("opens")
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, name)
    }

    /// The prefix reaches a sibling and a sub-directory too; only the
    /// directory's own files are the artifact's.
    #[tokio::test]
    async fn directory_keeps_only_own_files() {
        let client = FixtureClient::new().with_body(
            listing("tools%2Ffmt"),
            r#"{"items": [
                {"path": "tools/fmt/fmt.zip", "size_bytes": 7, "checksum_sha256": "aa",
                 "created_at": "2026-10-05T16:15:14Z"},
                {"path": "tools/fmt/sub/other.zip"},
                {"path": "tools/fmtx/fmtx.zip"}
            ], "has_more": false}"#,
        );

        let artifact = source("directory", client)
            .metadata(&id("tools/fmt"), None, &ctx())
            .await
            .expect("resolves");

        let names: Vec<&str> = artifact.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(names, ["fmt.zip"]);
        assert_eq!(artifact.files[0].size, Some(7));
        assert!(artifact.published.is_some());
    }

    #[tokio::test]
    async fn metadata_missing_is_absent() {
        let client =
            FixtureClient::new().with_body(listing("nope"), r#"{"items": [], "has_more": false}"#);

        let err = source("directory", client)
            .metadata(&id("nope"), None, &ctx())
            .await
            .expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    #[tokio::test]
    async fn versions_from_paths() {
        let client = FixtureClient::new().with_body(
            listing("tools%2Ffmt"),
            r#"{"items": [
                {"path": "tools/fmt/2.1/fmt.zip"},
                {"path": "tools/fmt/2.0/fmt.zip"},
                {"path": "tools/fmt/2.0/fmt.sig"}
            ], "has_more": false}"#,
        );

        let source = source("name-version-file", client);
        let versions = source
            .versions(&id("tools/fmt"), &ctx())
            .await
            .expect("lists");
        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert!(source.versioned(&id("tools/fmt")));
        assert_eq!(texts.len(), 2, "{texts:?}");
    }

    #[test]
    fn directory_mapping_has_no_versions() {
        let source = source("directory", FixtureClient::new());

        assert!(!source.versioned(&id("tools/fmt")));
    }
}
