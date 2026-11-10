//! Reading a local directory.
//!
//! The listing is the whole source, as a repository manager's prefix search
//! is for its raw repositories. Every path that comes back is read again
//! through the [`Mapping`] and kept only where it names the artifact asked
//! for.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::{Repository, file_url, prefix_of};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{
    ArtifactId, Dependency, Digest, DigestAlg, EcosystemId, FileRef, ResolvedArtifact, Version,
};
use crate::net::Expectation;
use crate::net::emulate::generic::{Digests, Item};
use crate::repo::{Downloaded, Mapping, Source};
use crate::version::VersionHandler;

pub struct LocalDirSource {
    repository: Repository,
    ecosystem: crate::ecosystem::Raw,
}

impl LocalDirSource {
    /// The mapping defaults to [`Mapping::Directory`].
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            repository: Repository::open(base_url, options, host)?,
            ecosystem: crate::ecosystem::Raw,
        })
    }

    fn mapping(&self) -> Mapping {
        self.repository.mapping
    }

    fn file_of(&self, item: &Item, name: &str) -> FileRef {
        let mut file = FileRef::new(name, file_url(&self.repository.base, &item.path));

        file.size = Some(item.size);
        file.digests = item
            .sha256
            .iter()
            .map(|hex| Digest::new(DigestAlg::Sha256, hex.clone()))
            .collect();

        file
    }
}

#[async_trait]
impl Source for LocalDirSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![EcosystemId::raw()]
    }

    /// Only where the mapping declares a segment is a version.
    fn versioned(&self, _: &ArtifactId) -> bool {
        self.mapping() == Mapping::NameVersionFile
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        if !self.versioned(id) {
            return Ok(Vec::new());
        }

        let name = id.name().trim_matches('/');
        let listing = self
            .repository
            .listed(
                &prefix_of(self.mapping(), name, None),
                Digests::Omitted,
                ctx,
            )
            .await?;

        // Sorted by text: a listing order is not a version order.
        let found: BTreeSet<String> = listing
            .items
            .iter()
            .filter_map(|item| self.mapping().read(&item.path))
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
        let prefix = prefix_of(self.mapping(), name, version);

        // Hashed: a resolution states what a copy is about to send.
        let listing = self
            .repository
            .listed(&prefix, Digests::Sha256, ctx)
            .await?;

        let mine: Vec<(&Item, String)> = listing
            .items
            .iter()
            .filter_map(|item| {
                let at = self.mapping().read(&item.path)?;

                (at.name == name && at.version.as_deref() == wanted).then_some((item, at.file))
            })
            .collect();

        if mine.is_empty() {
            // `Absent`, so a proxy asks its next upstream.
            return Err(Error::Absent {
                what: "artifact",
                url: file_url(&self.repository.base, &prefix),
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

            // A directory declares none.
            license: None,

            // The newest modification: a publish window asks whether
            // anything here is too new to trust yet.
            published: mine.iter().filter_map(|(item, _)| item.modified).max(),
        })
    }

    /// None: a directory publishes no dependency information.
    async fn deps(&self, _: &ResolvedArtifact, _: &Ctx) -> Result<Vec<Dependency>> {
        Ok(Vec::new())
    }

    /// Copied into the host's cache, as a download is, and verified
    /// against the hash the resolution took: a file changed since then is
    /// a checksum mismatch.
    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        crate::repo::download(&*self.repository.host, file, expect, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.repository.host.permits(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::options;
    use crate::model::Cause;
    use crate::repo::local_dir::testing::Directory;

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "raw".into() })
    }

    fn source(mapping: &str, directory: &Directory) -> LocalDirSource {
        LocalDirSource::open(
            &directory.base,
            &options(serde_json::json!({ "mapping": mapping })),
            Arc::clone(&directory.host),
        )
        .expect("opens")
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, name)
    }

    fn names(artifact: &ResolvedArtifact) -> Vec<&str> {
        artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect()
    }

    /// The prefix reaches a sibling and a sub-directory too; only the
    /// directory's own files are the artifact's.
    #[tokio::test]
    async fn directory_keeps_only_own_files() {
        let directory = Directory::new();
        directory.write("tools/fmt/fmt.zip", b"zip");
        directory.write("tools/fmt/sub/other.zip", b"other");
        directory.write("tools/fmtx/fmtx.zip", b"x");

        let artifact = source("directory", &directory)
            .metadata(&id("tools/fmt"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["fmt.zip"]);
        assert_eq!(artifact.files[0].size, Some(3));
        assert_eq!(artifact.files[0].digests.len(), 1);
        assert!(artifact.published.is_some());
    }

    #[tokio::test]
    async fn as_is_names_each_file() {
        let directory = Directory::new();
        directory.write("dump/a.bin", b"a");
        directory.write("dump/b.bin", b"b");

        let artifact = source("as-is", &directory)
            .metadata(&id("dump/a.bin"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["a.bin"]);
    }

    #[tokio::test]
    async fn versions_from_paths() {
        let directory = Directory::new();
        directory.write("tools/fmt/2.1/fmt.zip", b"1");
        directory.write("tools/fmt/2.0/fmt.zip", b"2");
        directory.write("tools/fmt/2.0/fmt.sig", b"3");

        let source = source("name-version-file", &directory);
        let versions = source
            .versions(&id("tools/fmt"), &ctx())
            .await
            .expect("lists");
        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert!(source.versioned(&id("tools/fmt")));
        assert_eq!(texts, ["2.0", "2.1"]);

        let version = Version::new("2.0", crate::model::Release::General);
        let artifact = source
            .metadata(&id("tools/fmt"), Some(&version), &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["fmt.sig", "fmt.zip"]);
    }

    #[tokio::test]
    async fn metadata_missing_is_absent() {
        let directory = Directory::new();

        let err = source("directory", &directory)
            .metadata(&id("nope"), None, &ctx())
            .await
            .expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    /// The resolution's hash is the download's expectation, so a file
    /// changed in between does not reach the cache.
    #[tokio::test]
    async fn file_changed_refused() {
        let directory = Directory::new();
        directory.write("tools/fmt/fmt.zip", b"before");

        let source = source("directory", &directory);
        let ctx = ctx();
        let artifact = source
            .metadata(&id("tools/fmt"), None, &ctx)
            .await
            .expect("resolves");

        directory.write("tools/fmt/fmt.zip", b"after!");

        let file = &artifact.files[0];
        let expect = Expectation::new().with_digests(file.digests.clone());

        let err = source
            .download(file, &expect, &ctx)
            .await
            .expect_err("mismatch");

        assert!(matches!(err, Error::Integrity(_)), "{err}");
    }

    #[tokio::test]
    async fn download_lands_in_cache() {
        let directory = Directory::new();
        directory.write("tools/fmt/fmt.zip", b"zip");

        let source = source("directory", &directory);
        let ctx = ctx();
        let artifact = source
            .metadata(&id("tools/fmt"), None, &ctx)
            .await
            .expect("resolves");

        let file = &artifact.files[0];
        let expect = Expectation::new().with_digests(file.digests.clone());
        let downloaded = source.download(file, &expect, &ctx).await.expect("copied");

        assert_eq!(std::fs::read(&downloaded.path).expect("read"), b"zip");
        assert!(
            downloaded
                .path
                .starts_with(directory.dir.path().join("cache"))
        );
    }
}
