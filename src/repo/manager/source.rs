//! Reading a repository manager's repository: its own API for what it
//! stores, the ecosystem's protocol for what the files say.
//!
//! ```text
//!                 ManagedSource
//!                /             \
//!          Lister               inner Source (maven | npm | pypi)
//!     server REST API           {server}/{repository path}
//!   versions, digests,          existence, files, license, deps,
//!   sizes, publish time,        signatures, download, verify
//!   files the spec misses
//! ```
//!
//! # The protocol source stays authoritative
//!
//! It decides whether an artifact exists and which files it has, and it is
//! the only side that attaches signatures and PEP 658 metadata to a file.
//! The server's listing adds to that rather than replacing it:
//!
//! | Server file | Becomes |
//! | --- | --- |
//! | also named by the protocol source | its digests and size, merged |
//! | not named, Maven release | an extra file (classifiers, `.module`) |
//! | not named, anything else | dropped |
//!
//! Only Maven gains files.  Its source builds names from the POM, so it
//! misses classifiers and Gradle metadata; npm's packument and PyPI's
//! simple index list every distribution, and what else a server stores
//! beside them (PyPI's `.metadata`, say) is not a distribution.  A snapshot
//! gains none either: the server holds every timestamped build, and the
//! protocol source picked one.
//!
//! A digest the two sides disagree on refuses the artifact, as
//! `repo::inventory::combine` does for a listing.
//!
//! A lister that [`Lister::restricts`] turns that around for files: it
//! reads a proxy repository's cache, whose protocol route passes through to
//! the upstream, so a protocol file the server does not list is left out
//! rather than fetched, and a version left with none is absent.
//!
//! The publish time is the server's, when it has one: the time it stored
//! the newest file, where the protocol source can offer at most an HTTP
//! `Last-Modified`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ecosystem::maven::{CLASSIFIER_QUALIFIER, TYPE_QUALIFIER};
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::Expectation;
use crate::repo::{Companions, Downloaded, Source};
use crate::version::VersionHandler;

/// What a server's API says about one version.
pub(in crate::repo) struct Listing {
    pub(in crate::repo) files: Vec<FileRef>,

    /// When the server stored the newest of them.
    pub(in crate::repo) published: Option<DateTime<Utc>>,
}

/// The server half: one implementation per product.
#[async_trait]
pub(in crate::repo) trait Lister: Send + Sync {
    /// Every version the server holds, as text, or `None` to leave the
    /// question to the protocol source.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Option<Vec<String>>>;

    /// The files the server holds for one version.  Empty when it holds
    /// none it can name; existence is the protocol source's to decide,
    /// unless [`Lister::restricts`].
    async fn listing(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Result<Listing>;

    /// Whether the listing, rather than the protocol source, decides which
    /// files a version has.
    ///
    /// True for a proxy repository's cache, whose protocol route passes
    /// through to its upstream: a file the protocol names and the cache
    /// does not hold would be fetched from the upstream, which is not what
    /// reading the cache means.  A version left with no file is absent.
    fn restricts(&self) -> bool {
        false
    }
}

/// What happens to a server file the protocol source did not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unnamed {
    Append,
    Drop,
}

/// Maven releases only; see the module documentation.
///
/// A coordinate carrying a classifier or type names one file already, so
/// the rest of its version's files are other artifacts.
fn unnamed(id: &ArtifactId, version: &Version) -> Unnamed {
    let maven = id.ecosystem().as_str() == EcosystemId::MAVEN;
    let whole =
        id.qualifier(CLASSIFIER_QUALIFIER).is_none() && id.qualifier(TYPE_QUALIFIER).is_none();

    match maven && whole && !crate::ecosystem::maven::is_snapshot(version.text()) {
        true => Unnamed::Append,
        false => Unnamed::Drop,
    }
}

/// Fold the server's facts about one file into the protocol source's.
fn merge(held: &mut FileRef, listed: FileRef) -> Result<()> {
    for digest in listed.digests {
        let same_alg = held.digests.iter().find(|known| known.alg == digest.alg);

        match same_alg {
            None => held.digests.push(digest),

            Some(known) if known.hex.eq_ignore_ascii_case(&digest.hex) => {}

            Some(known) => {
                return Err(Error::Integrity(format!(
                    "{name}: the server stores {alg} {server}, and the repository \
                     declares {declared}",
                    name = held.name,
                    alg = digest.alg.as_str(),
                    server = digest.hex,
                    declared = known.hex,
                )));
            }
        }
    }

    match (held.size, listed.size) {
        (None, size) => held.size = size,

        (Some(declared), Some(stored)) if declared != stored => {
            return Err(Error::Integrity(format!(
                "{name}: the server stores {stored} bytes, and the repository declares \
                 {declared}",
                name = held.name,
            )));
        }

        _ => {}
    }

    Ok(())
}

/// A protocol source, told more by the server that hosts it.
pub(in crate::repo) struct ManagedSource<L> {
    inner: Arc<dyn Source>,
    lister: L,
}

impl<L: Lister> ManagedSource<L> {
    pub(in crate::repo) fn new(inner: Arc<dyn Source>, lister: L) -> Self {
        Self { inner, lister }
    }
}

#[async_trait]
impl<L: Lister> Source for ManagedSource<L> {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        self.inner.ecosystem(id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        self.inner.ecosystems()
    }

    fn version_handler(&self, id: &ArtifactId) -> Result<&dyn VersionHandler> {
        self.inner.version_handler(id)
    }

    fn versioned(&self, id: &ArtifactId) -> bool {
        self.inner.versioned(id)
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        match self.lister.versions(id, ctx).await? {
            Some(texts) => Ok(self.inner.version_handler(id)?.classify(&texts)),
            None => self.inner.versions(id, ctx).await,
        }
    }

    async fn confirmed(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        self.inner.confirmed(id, text, ctx).await
    }

    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        self.inner.unlisted(id, text, ctx).await
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let mut artifact = self.inner.metadata(id, version, ctx).await?;

        let Some(version) = version else {
            return Ok(artifact);
        };

        let listing = self.lister.listing(id, version, ctx).await?;
        let unnamed = unnamed(id, version);

        if self.lister.restricts() {
            artifact
                .files
                .retain(|held| listing.files.iter().any(|file| file.name == held.name));
        }

        // Checksum sidecars and Maven's own index join here and are left
        // out by `repo::Omit`, which wraps every source.
        for file in listing.files {
            match artifact
                .files
                .iter_mut()
                .find(|held| held.name == file.name)
            {
                Some(held) => merge(held, file)?,
                None if unnamed == Unnamed::Append => artifact.files.push(file),
                None => {}
            }
        }

        if listing.published.is_some() {
            artifact.published = listing.published;
        }

        if self.lister.restricts() && artifact.files.is_empty() {
            // `Absent`, so a proxy asks its next upstream.
            return Err(Error::Absent {
                what: "cached artifact",
                url: format!("{}@{}", id.purl(), version.text()),
                name: id.purl(),
            });
        }

        Ok(artifact)
    }

    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        self.inner.deps(artifact, ctx).await
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        self.inner.download(file, expect, ctx).await
    }

    async fn verify(
        &self,
        artifact: &ResolvedArtifact,
        files: &[std::path::PathBuf],
        companions: &Companions,
        ctx: &Ctx,
    ) -> Result<()> {
        self.inner.verify(artifact, files, companions, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.inner.serves(url)
    }

    fn companion(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        kind: crate::ecosystem::Companion,
    ) -> Option<(FileRef, Expectation)> {
        self.inner.companion(artifact, file, kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cause, Digest, DigestAlg, Release};

    /// A protocol source that answers from fixed data.
    struct Spec {
        files: Vec<FileRef>,
        ecosystem: crate::ecosystem::Maven,
    }

    #[async_trait]
    impl Source for Spec {
        fn ecosystem(&self, _: &ArtifactId) -> Result<&dyn Ecosystem> {
            Ok(&self.ecosystem)
        }

        fn ecosystems(&self) -> Vec<EcosystemId> {
            vec![EcosystemId::maven()]
        }

        async fn versions(&self, _: &ArtifactId, _: &Ctx) -> Result<Vec<Version>> {
            Ok(vec![Version::new("0.1", Release::General)])
        }

        async fn metadata(
            &self,
            id: &ArtifactId,
            version: Option<&Version>,
            _: &Ctx,
        ) -> Result<ResolvedArtifact> {
            Ok(ResolvedArtifact {
                id: id.clone(),
                version: version.cloned(),
                files: self.files.clone(),
                license: Some("MIT".into()),
                published: None,
            })
        }

        async fn deps(&self, _: &ResolvedArtifact, _: &Ctx) -> Result<Vec<Dependency>> {
            Ok(Vec::new())
        }

        async fn download(&self, _: &FileRef, _: &Expectation, _: &Ctx) -> Result<Downloaded> {
            unimplemented!("not downloaded in these tests")
        }

        fn serves(&self, _: &str) -> bool {
            true
        }
    }

    /// A server that lists fixed files and, optionally, versions.
    struct Server {
        versions: Option<Vec<String>>,
        files: Vec<FileRef>,
        published: Option<DateTime<Utc>>,
        restricts: bool,
    }

    #[async_trait]
    impl Lister for Server {
        async fn versions(&self, _: &ArtifactId, _: &Ctx) -> Result<Option<Vec<String>>> {
            Ok(self.versions.clone())
        }

        async fn listing(&self, _: &ArtifactId, _: &Version, _: &Ctx) -> Result<Listing> {
            Ok(Listing {
                files: self.files.clone(),
                published: self.published,
            })
        }

        fn restricts(&self) -> bool {
            self.restricts
        }
    }

    fn file(name: &str, digests: &[(DigestAlg, &str)], size: Option<u64>) -> FileRef {
        let mut file = FileRef::new(name, format!("h://server.test/{name}"));

        file.digests = digests
            .iter()
            .map(|(alg, hex)| Digest::new(*alg, *hex))
            .collect();
        file.size = size;

        file
    }

    fn source(spec: Vec<FileRef>, server: Server) -> ManagedSource<Server> {
        let inner = Spec {
            files: spec,
            ecosystem: crate::ecosystem::Maven,
        };

        ManagedSource::new(Arc::new(inner), server)
    }

    fn server(files: Vec<FileRef>) -> Server {
        Server {
            versions: None,
            files,
            published: None,
            restricts: false,
        }
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    async fn resolved(source: &ManagedSource<Server>, version: &str) -> Result<ResolvedArtifact> {
        source
            .metadata(
                &id(),
                Some(&Version::new(version, Release::General)),
                &ctx(),
            )
            .await
    }

    #[tokio::test]
    async fn server_digests_and_size_join_named_files() {
        let source = source(
            vec![file("lib-1.0.jar", &[(DigestAlg::Sha1, "AA")], None)],
            server(vec![file(
                "lib-1.0.jar",
                &[(DigestAlg::Sha1, "aa"), (DigestAlg::Sha256, "bb")],
                Some(42),
            )]),
        );

        let artifact = resolved(&source, "1.0").await.expect("resolves");
        let jar = &artifact.files[0];

        assert_eq!(jar.digests.len(), 2);
        assert_eq!(jar.size, Some(42));
        assert_eq!(artifact.license.as_deref(), Some("MIT"));
    }

    #[tokio::test]
    async fn server_digest_disagreeing_refuses_artifact() {
        let source = source(
            vec![file("lib-1.0.jar", &[(DigestAlg::Sha1, "aa")], None)],
            server(vec![file("lib-1.0.jar", &[(DigestAlg::Sha1, "cc")], None)]),
        );

        let err = resolved(&source, "1.0").await.expect_err("refused");

        assert!(matches!(err, Error::Integrity(_)), "{err}");
    }

    /// Classifiers and Gradle metadata, which the POM does not name.
    #[tokio::test]
    async fn server_adds_unnamed_files_to_release() {
        let source = source(
            vec![file("lib-1.0.pom", &[], None)],
            server(vec![
                file("lib-1.0.pom", &[], None),
                file("lib-1.0-sources.jar", &[], None),
                file("lib-1.0.module", &[], None),
                file("lib-1.0.module.sha1", &[], None),
            ]),
        );

        // Through the wrapper every built source gets, which leaves out the
        // checksum sidecar: it is not a file of the artifact.
        let source =
            crate::repo::OmittingSource::new(Arc::new(source), crate::repo::Omit::default());

        let artifact = source
            .metadata(&id(), Some(&Version::new("1.0", Release::General)), &ctx())
            .await
            .expect("resolves");
        let names: Vec<&str> = artifact.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(
            names,
            ["lib-1.0.pom", "lib-1.0-sources.jar", "lib-1.0.module"]
        );
    }

    /// The server holds every timestamped build; the protocol source chose one.
    #[tokio::test]
    async fn server_adds_nothing_to_snapshot() {
        let source = source(
            vec![file("lib-1.0-20240101.123456-2.pom", &[], None)],
            server(vec![file("lib-1.0-20240101.000000-1.pom", &[], None)]),
        );

        let artifact = resolved(&source, "1.0-SNAPSHOT").await.expect("resolves");

        assert_eq!(artifact.files.len(), 1);
    }

    #[tokio::test]
    async fn server_publish_time_wins() {
        let when = Utc::now();
        let source = source(
            vec![file("lib-1.0.pom", &[], None)],
            Server {
                published: Some(when),
                ..server(Vec::new())
            },
        );

        assert_eq!(
            resolved(&source, "1.0").await.expect("resolves").published,
            Some(when)
        );
    }

    #[tokio::test]
    async fn server_versions_win_when_given() {
        let asked = source(
            Vec::new(),
            Server {
                versions: Some(vec!["1.0".into(), "2.0".into()]),
                ..server(Vec::new())
            },
        );
        let deferred = source(Vec::new(), server(Vec::new()));

        let texts = |versions: Vec<Version>| -> Vec<String> {
            versions.iter().map(|v| v.text().to_owned()).collect()
        };

        assert_eq!(
            texts(asked.versions(&id(), &ctx()).await.expect("lists")).len(),
            2
        );
        assert_eq!(
            texts(deferred.versions(&id(), &ctx()).await.expect("lists")),
            ["0.1"]
        );
    }

    /// A proxy's cache decides: a file the protocol names and the cache
    /// does not hold is left out, and Maven extras still join.
    #[tokio::test]
    async fn restricting_keeps_only_listed_files() {
        let mut cache = server(vec![
            file("lib-1.0.jar", &[(DigestAlg::Sha256, "bb")], Some(42)),
            file("lib-1.0-sources.jar", &[], None),
        ]);
        cache.restricts = true;

        let source = source(
            vec![
                file("lib-1.0.pom", &[], None),
                file("lib-1.0.jar", &[], None),
            ],
            cache,
        );

        let artifact = resolved(&source, "1.0").await.expect("resolves");
        let names: Vec<&str> = artifact.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(names, ["lib-1.0.jar", "lib-1.0-sources.jar"]);
        assert_eq!(artifact.files[0].size, Some(42));
    }

    #[tokio::test]
    async fn restricting_with_nothing_cached_is_absent() {
        let mut cache = server(Vec::new());
        cache.restricts = true;

        let source = source(vec![file("lib-1.0.jar", &[], None)], cache);
        let err = resolved(&source, "1.0").await.expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }
}
