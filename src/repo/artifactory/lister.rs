//! What an Artifactory repository stores for one Maven version, from its
//! storage API.
//!
//! ```text
//!   GET {base}/api/storage/{repo}/{group path}/{artifact}/{version}          folder: children
//!   GET {base}/api/storage/{repo}/{group path}/{artifact}/{version}/{file}   one file: checksums, size
//! ```
//!
//! One folder request and one per file: the folder `?list` that would
//! answer in one is Pro only (400 on OSS 7.161.26).  Checksum sidecars are
//! not asked about.  See `storage` for why the storage API, and for the
//! publish time.
//!
//! Maven only.  npm and PyPI layouts are not coordinate-bearing, so this
//! lists nothing for them and the protocol source answers alone.

use std::sync::Arc;

use async_trait::async_trait;

use super::storage::{Entry, Storage};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ext::ExtHost;
use crate::model::{ArtifactId, EcosystemId, Version};
use crate::net::encode_unreserved;
use crate::repo::manager::{Lister, Listing};

pub(super) struct ArtifactoryLister {
    storage: Storage,
    ecosystem: EcosystemId,
}

impl ArtifactoryLister {
    pub(super) fn new(
        base_url: String,
        host: Arc<dyn ExtHost>,
        repository: String,
        ecosystem: EcosystemId,
    ) -> Self {
        Self {
            storage: Storage::new(base_url, host, repository),
            ecosystem,
        }
    }

    /// `{group path}/{artifact}/{version}`, each segment encoded.
    fn directory(id: &ArtifactId, version: &Version) -> String {
        id.namespace()
            .unwrap_or_default()
            .split('.')
            .chain([id.name(), version.text()])
            .map(encode_unreserved)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The folder's file names, or none when there is no folder.
    async fn children(&self, directory: &str, ctx: &Ctx) -> Result<Vec<String>> {
        match self.storage.entry(directory, ctx).await? {
            Entry::Folder { files, .. } => Ok(files),
            Entry::Missing | Entry::File(_) => Ok(Vec::new()),
        }
    }
}

#[async_trait]
impl Lister for ArtifactoryLister {
    /// Artifactory rebuilds `maven-metadata.xml` itself, so the protocol
    /// source's versions stand.
    async fn versions(&self, _: &ArtifactId, _: &Ctx) -> Result<Option<Vec<String>>> {
        Ok(None)
    }

    async fn listing(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Result<Listing> {
        let mut listing = Listing {
            files: Vec::new(),
            published: None,
        };

        if self.ecosystem.as_str() != EcosystemId::MAVEN {
            return Ok(listing);
        }

        let directory = Self::directory(id, version);

        for name in self.children(&directory, ctx).await? {
            // Sidecars and Maven's own index are dropped by the source
            // anyway; not asking about them saves a request each.
            if !crate::ecosystem::joins_listing(&self.ecosystem, &name) {
                continue;
            }

            let path = format!("{directory}/{}", encode_unreserved(&name));
            let info = self.storage.info(&path, ctx).await?;

            listing.published = listing.published.max(info.published());
            listing.files.push(self.storage.file(&path, &name, &info));
        }

        Ok(listing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::TestHost;
    use crate::model::{Cause, Release};
    use crate::net::{Canned, FixtureClient};
    use http::StatusCode;

    const BASE: &str = "h://artifactory.test";
    const REPO: &str = "maven-a";
    const DIR: &str = "h://artifactory.test/api/storage/maven-a/org/example/lib/1.0";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    fn lister(client: FixtureClient, ecosystem: EcosystemId) -> ArtifactoryLister {
        ArtifactoryLister::new(
            BASE.into(),
            Arc::new(TestHost::new(client)),
            REPO.into(),
            ecosystem,
        )
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    fn version() -> Version {
        Version::new("1.0", Release::General)
    }

    #[tokio::test]
    async fn listing_folder_then_each_file() {
        let client = FixtureClient::new()
            .with_body(
                DIR,
                r#"{"children": [
                    {"uri": "/lib-1.0.jar", "folder": false},
                    {"uri": "/lib-1.0.jar.sha1", "folder": false},
                    {"uri": "/sub", "folder": true}
                ]}"#,
            )
            .with_body(
                format!("{DIR}/lib-1.0.jar"),
                r#"{"downloadUri": "h://artifactory.test/maven-a/org/example/lib/1.0/lib-1.0.jar",
                    "size": "959",
                    "checksums": {"sha1": "aa", "md5": "bb", "sha256": "cc"},
                    "created": "2026-09-29T15:42:48.678Z",
                    "lastModified": "2026-10-05T16:15:05.407Z"}"#,
            );

        let listing = lister(client, EcosystemId::maven())
            .listing(&id(), &version(), &ctx())
            .await
            .expect("lists");

        assert_eq!(listing.files.len(), 1, "the sidecar is never asked about");

        let jar = &listing.files[0];

        assert_eq!(jar.name, "lib-1.0.jar");
        assert_eq!(jar.size, Some(959));
        assert_eq!(jar.digests.len(), 3);
        assert_eq!(
            listing.published.map(|when| when.to_rfc3339()),
            Some("2026-10-05T16:15:05.407+00:00".to_owned())
        );
    }

    #[tokio::test]
    async fn listing_missing_folder_empty() {
        let client = FixtureClient::new().with(DIR, Canned::status(StatusCode::NOT_FOUND));

        let listing = lister(client, EcosystemId::maven())
            .listing(&id(), &version(), &ctx())
            .await
            .expect("lists");

        assert!(listing.files.is_empty());
    }

    #[tokio::test]
    async fn listing_npm_empty_without_requests() {
        let id = ArtifactId::new(EcosystemId::npm(), None, "left-pad");

        let listing = lister(FixtureClient::new(), EcosystemId::npm())
            .listing(&id, &version(), &ctx())
            .await
            .expect("lists");

        assert!(listing.files.is_empty());
    }
}
