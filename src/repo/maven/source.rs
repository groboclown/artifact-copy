//! What a Maven repository answers as a [`Source`]: each answer delegates
//! to the file that knows how.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use std::sync::Arc;

use super::metadata::Snapshot;
use super::pom::Pom;
use super::sidecar::{self, Sidecars};
use super::versions::VersionDiscovery;
use super::{DOCUMENT_CACHE, is_safe_segment};
use crate::cache::Coalesced;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Code;
use crate::ecosystem::Ecosystem;
use crate::ecosystem::maven::Maven;
use crate::ecosystem::maven::TYPE_QUALIFIER;
use crate::ext::{ExtHost, Options};
use crate::model::DigestAlg;
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::normalized_base;
use crate::net::sig::KeyStore;
use crate::net::{Expectation, Req};
use crate::policy::SigningPolicy;
use crate::repo::{Downloaded, Source};
use crate::version::VersionHandler;

pub struct MavenSource {
    pub(super) base_url: String,

    /// Where every request goes, and whose directory caches the files.
    pub(super) host: Arc<dyn ExtHost>,
    pub(super) ecosystem: Maven,

    /// Version lists, keyed by `maven-metadata.xml` URL.
    pub(super) versions: Coalesced<Vec<String>>,

    /// Version folders from artifact directory indexes, keyed by URL;
    /// `None` where there is no index. Coalesced because a dependency walk
    /// resolves several versions of one artifact at once.
    pub(super) indexes: Coalesced<Option<Vec<String>>>,

    /// Parsed POMs, keyed by URL. Shared across the parent chain, which is
    /// where the reuse actually is.
    pub(super) poms: Coalesced<FetchedPom>,

    /// Snapshot builds, keyed by the version directory's
    /// `maven-metadata.xml` URL. A snapshot parent is shared the same way a
    /// released one is.
    pub(super) snapshots: Coalesced<Snapshot>,

    /// The keys this source checks PGP signatures against.
    ///
    /// Empty by default, which means a signature is recorded and reported
    /// as uncheckable rather than silently accepted. Populated from the
    /// `signing-keys` collection and any configured keyservers.
    pub(super) keys: KeyStore,

    /// Where the keyservers are asked, apart from `host`: a keyserver is not
    /// the repository, and its host's constraints would refuse it. `None`
    /// when no keyserver is configured, and nothing is asked.
    pub(super) keyservers: Option<Arc<dyn ExtHost>>,

    /// Which keys may vouch for which artifacts. Empty unless configured,
    /// which trusts every pinned key and no keyserver key.
    pub(super) signing: Arc<SigningPolicy>,

    /// Which checksum sidecars to probe, in order.
    ///
    /// Per source rather than global: which algorithms a repository
    /// publishes is a property of that repository, and probing for ones it
    /// does not serve costs a round trip per file across a catalog that
    /// may hold millions. Learned from the repository unless configured;
    /// see [`sidecar::Probe`].
    pub(super) checksums: sidecar::Probe,

    /// How versions `maven-metadata.xml` does not list are found.
    pub(super) discovery: VersionDiscovery,
}

/// A POM, and what the files beside it proved about it.
///
/// Kept together so the sidecars are fetched once per POM rather than once
/// per artifact that inherits from it -- a parent POM shared by fifty
/// modules would otherwise be checked fifty times.
#[derive(Debug, Clone)]
pub(super) struct FetchedPom {
    pub(super) pom: Pom,
    pub(super) sidecars: Sidecars,
}

impl MavenSource {
    /// No HTTP client: every request goes through `host`, which is what
    /// confines this to the host it was configured for.
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: normalized_base(base_url),
            host,
            ecosystem: Maven,
            versions: Coalesced::new(DOCUMENT_CACHE),
            indexes: Coalesced::new(DOCUMENT_CACHE),
            poms: Coalesced::new(DOCUMENT_CACHE),
            snapshots: Coalesced::new(DOCUMENT_CACHE),
            keys: KeyStore::new(Vec::new()),
            keyservers: None,
            signing: Arc::new(SigningPolicy::default()),
            checksums: sidecar::Probe::learned(),
            discovery: VersionDiscovery::Probe,
        }
    }

    /// Build from configuration, which is where the `checksums` option is
    /// read.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            checksums: sidecar::Probe::from_options(options)?,
            discovery: VersionDiscovery::read(options)?,
            ..Self::new(base_url, host)
        })
    }

    /// Probe these checksum sidecars, in this order, instead of learning
    /// them from the repository.
    pub fn with_checksums(mut self, checksums: Vec<DigestAlg>) -> Self {
        self.checksums = sidecar::Probe::Fixed(checksums);
        self
    }

    /// Check signatures against this key store.
    pub fn with_keys(mut self, keys: KeyStore) -> Self {
        self.keys = keys;
        self
    }

    /// Ask the keyservers through this capability.
    pub fn with_keyservers(mut self, keyservers: Option<Arc<dyn ExtHost>>) -> Self {
        self.keyservers = keyservers;
        self
    }

    /// Let only the keys this policy names vouch for its artifacts.
    pub fn with_signing(mut self, signing: Arc<SigningPolicy>) -> Self {
        self.signing = signing;
        self
    }
}

#[async_trait]
impl Source for MavenSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![self.ecosystem.id()]
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let listed = self.listed_versions(id, ctx).await?;

        Ok(self.ecosystem.classify(&listed))
    }

    /// A release version whose POM is served, read before any list.
    ///
    /// Fetched rather than probed, so a mirror can serve it and `metadata`
    /// reuses it: confirming costs no request of its own, where the list
    /// can cost an index fetch per artifact. Not under `version-discovery`
    /// `metadata`, which trusts the list alone, and not for a snapshot,
    /// whose POM is named by its build.
    async fn confirmed(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        let fetch = self.discovery.confirms()
            && is_safe_segment(text)
            && !crate::ecosystem::maven::is_snapshot(text);

        if !fetch {
            return Ok(None);
        }

        let group = Self::group_of(id)?;

        match self.pom(group, id.name(), text, ctx).await {
            Ok(_) => Ok(self.ecosystem.classify(&[text.to_owned()]).pop()),
            Err(err) if err.code() == Code::ArtifactNotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// A release version whose POM is served, under `version-discovery`
    /// `probe` or `both`. A snapshot's POM is named by its build, so one
    /// the metadata does not list cannot be probed.
    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        let probe = self.discovery.probes()
            && is_safe_segment(text)
            && !crate::ecosystem::maven::is_snapshot(text);

        if !probe {
            return Ok(None);
        }

        let group = Self::group_of(id)?;
        let url = self.pom_url(group, id.name(), text, text);

        // Presence only, so a mirror may answer.
        match self.host.exists(&Req::head(&url), ctx).await? {
            true => Ok(self.ecosystem.classify(&[text.to_owned()]).pop()),
            false => Ok(None),
        }
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let version = crate::repo::version_required(id, version)?;
        let resolved = self.effective_pom(id, version, ctx).await?;

        // An explicit `type` on the request wins: asking for
        // `g:a:pom:1.0` means the POM, whatever the project's packaging.
        let packaging = id
            .qualifier(TYPE_QUALIFIER)
            .unwrap_or(&resolved.packaging)
            .to_owned();

        let group = Self::group_of(id)?;
        let build = self.snapshot(group, id.name(), version.text(), ctx).await?;
        let mut files = self.files_of(id, version, &packaging, &build)?;

        // What the sidecars proved about the POM belongs on the POM's own
        // entry, not on the payload's: they are different files and only
        // one of them has been downloaded and checked. Attaching them to
        // the payload would claim a verification that never happened.
        let checked = self.pom(group, id.name(), version.text(), ctx).await?;

        if let Some(entry) = files.first_mut() {
            entry.digests = checked.sidecars.digests.clone();
            entry.signatures = checked.sidecars.signature.iter().cloned().collect();
        }

        // The payload, or the POM when that is all there is. Chosen before
        // the signatures join the list, so an `.asc` is never dated.
        let published = match files.last() {
            Some(file) => self.published(file, ctx).await,
            None => None,
        };

        let signatures = self.signature_files(&files, &checked, ctx).await;

        for (at, signature) in signatures.into_iter().rev() {
            files.insert(at + 1, signature);
        }

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: Some(version.clone()),
            files,

            // Free text, not SPDX -- the policy's alias table is what turns
            // "Apache License, Version 2.0" into an identifier. The URL is
            // the fallback because plenty of POMs give only that.
            license: resolved
                .licenses
                .first()
                .and_then(|license| license.name.clone().or_else(|| license.url.clone())),

            published,
        })
    }

    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        self.dependencies(artifact, ctx).await
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        crate::repo::download(&*self.host, file, expect, ctx).await
    }

    /// Each copied `.asc` against the file it signs; see
    /// [`MavenSource::verify_signatures`].
    async fn verify(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        _companions: &crate::repo::Companions,
        ctx: &Ctx,
    ) -> Result<()> {
        self.verify_signatures(artifact, files, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.host.permits(url)
    }
}

impl MavenSource {
    /// When the payload was published, from its `Last-Modified`.
    ///
    /// Maven has no publish-time metadata, so the file's own timestamp is
    /// the only answer available. A repository that does not send the
    /// header yields `None` rather than a guess.
    async fn published(&self, file: &FileRef, ctx: &Ctx) -> Option<DateTime<Utc>> {
        let head = self.host.head(&Req::head(&file.url), ctx).await.ok()?;

        DateTime::parse_from_rfc2822(head.header("last-modified")?)
            .ok()
            .map(|stamp| stamp.with_timezone(&Utc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ext::testing::TestHost;

    use crate::net::FixtureClient;

    use crate::repo::maven::testing::*;
    use crate::version::VersionHandler;

    use std::sync::Arc;

    use crate::core::problem::Code;

    use crate::ecosystem::maven::CLASSIFIER_QUALIFIER;
    use crate::model::{ArtifactId, DigestAlg, EcosystemId, ResolvedArtifact};

    use crate::repo::Source;
    use crate::repo::maven::MavenSource;
    use crate::repo::maven::metadata::Snapshot;

    #[tokio::test]
    async fn files_pom_and_payload() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        let names: Vec<&str> = artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["lib-1.0.pom", "lib-1.0.jar"]);
        assert_eq!(artifact.files[1].url, format!("{DIR}/1.0/lib-1.0.jar"));
    }

    /// `<packaging>bundle</packaging>` publishes a `.jar`, and a `test-jar`
    /// type its `-tests.jar`; neither is a file extension.
    #[tokio::test]
    async fn packaging_names_published_file() {
        let bundle = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <packaging>bundle</packaging>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), bundle)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let names = |artifact: &ResolvedArtifact| -> Vec<String> {
            artifact
                .files
                .iter()
                .map(|file| file.name.clone())
                .collect()
        };

        let plain = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(names(&plain), ["lib-1.0.pom", "lib-1.0.jar"]);

        let tests = id().with_qualifier(TYPE_QUALIFIER, "test-jar");
        let tests_jar = f
            .subject
            .metadata(&tests, Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(names(&tests_jar), ["lib-1.0.pom", "lib-1.0-tests.jar"]);
    }

    /// A `pom` project has no separate payload, and naming one would
    /// produce a request for a `.pom.pom` that does not exist.
    #[tokio::test]
    async fn packaging_pom_has_only_pom() {
        let f = fixture();
        let ctx = ctx();
        let parent = ArtifactId::new(EcosystemId::maven(), Some("org.example"), "parent");
        let version = f.subject.ecosystem.version("5.0");

        let artifact = f
            .subject
            .metadata(&parent, Some(&version), &ctx)
            .await
            .expect("read");

        let names: Vec<&str> = artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["parent-5.0.pom"]);
    }

    #[tokio::test]
    async fn classifier_reaches_file_name() {
        let f = fixture();
        let sources = id().with_qualifier(CLASSIFIER_QUALIFIER, "sources");
        let version = f.subject.ecosystem.version("1.0");

        let files = f
            .subject
            .files_of(&sources, &version, "jar", &Snapshot::default())
            .expect("built");

        assert_eq!(files[1].name, "lib-1.0-sources.jar");
    }

    /// The rule is **verify what you actually download**, and the two
    /// halves of it pull in opposite directions.
    ///
    /// The POM is downloaded -- it is the only way to learn a license and
    /// dependencies -- so its sidecars are fetched and checked. The payload
    /// is not downloaded during inspection, so fetching its checksum would
    /// buy nothing and cost a request per artifact across the catalog.
    #[tokio::test]
    async fn verify_pom_not_payload() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        f.subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        let asked = f.host.requested();

        assert!(
            asked.iter().any(|url| url.ends_with("lib-1.0.pom.sha1")),
            "the POM was downloaded, so it should have been checked: {asked:?}"
        );

        // Only the signature is asked about, so it can be copied; its
        // checksums would buy nothing for a file nobody downloaded.
        assert!(
            !asked
                .iter()
                .any(|url| url.contains("lib-1.0.jar.") && !url.ends_with(".jar.asc")),
            "the payload was not downloaded, so no checksum beside it should be: {asked:?}"
        );
    }

    /// Armored, and not a signature anything can check. Enough to list.
    const UNCHECKED_SIGNATURE: &str =
        "-----BEGIN PGP SIGNATURE-----\n\niQEc\n-----END PGP SIGNATURE-----";

    fn names_of(artifact: &ResolvedArtifact) -> Vec<&str> {
        artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect()
    }

    /// Each published `.asc` follows the file it signs, so a target copies
    /// it beside that file.
    #[tokio::test]
    async fn signatures_follow_files() {
        let f = fixture_from(
            client()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom.asc"), UNCHECKED_SIGNATURE)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar.asc"), UNCHECKED_SIGNATURE),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(
            names_of(&artifact),
            [
                "lib-1.0.pom",
                "lib-1.0.pom.asc",
                "lib-1.0.jar",
                "lib-1.0.jar.asc"
            ]
        );
        assert_eq!(artifact.files[3].url, format!("{DIR}/1.0/lib-1.0.jar.asc"));

        // Still dated by the payload, not by its signature.
        assert!(artifact.published.is_some());
    }

    const SNAPSHOT_METADATA: &str = r#"<metadata>
          <versioning>
            <snapshot><timestamp>20240101.123456</timestamp><buildNumber>3</buildNumber></snapshot>
          </versioning>
        </metadata>"#;

    /// A snapshot's files are named by its latest build, which the version
    /// directory's own index names.
    #[tokio::test]
    async fn snapshot_files_named_by_build() {
        let snapshot_dir = format!("{DIR}/2.0-SNAPSHOT");
        let f = fixture_from(
            FixtureClient::new()
                .with_body(
                    format!("{snapshot_dir}/maven-metadata.xml"),
                    SNAPSHOT_METADATA,
                )
                .with_body(
                    format!("{snapshot_dir}/lib-2.0-20240101.123456-3.pom"),
                    LIB_POM,
                )
                .with_body(
                    format!("{REPO}/org/example/parent/5.0/parent-5.0.pom"),
                    PARENT_POM,
                ),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.0-SNAPSHOT");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(
            names_of(&artifact),
            [
                "lib-2.0-20240101.123456-3.pom",
                "lib-2.0-20240101.123456-3.jar"
            ]
        );
        assert_eq!(
            artifact.files[1].url,
            format!("{snapshot_dir}/lib-2.0-20240101.123456-3.jar")
        );
    }

    /// A snapshot directory with no index is a non-unique snapshot, whose
    /// files carry the literal version.
    #[tokio::test]
    async fn snapshot_without_index_keeps_literal_names() {
        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/2.0-SNAPSHOT/lib-2.0-SNAPSHOT.pom"), LIB_POM)
                .with_body(
                    format!("{REPO}/org/example/parent/5.0/parent-5.0.pom"),
                    PARENT_POM,
                ),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.0-SNAPSHOT");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(
            names_of(&artifact),
            ["lib-2.0-SNAPSHOT.pom", "lib-2.0-SNAPSHOT.jar"]
        );
    }

    /// A parent POM is shared by every module of a multi-module build, so
    /// checking it once rather than once per module is the difference
    /// between a bounded cost and a multiple of the catalog.
    #[tokio::test]
    async fn verify_parent_pom_once() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        for _ in 0..3 {
            f.subject
                .metadata(&id(), Some(&version), &ctx)
                .await
                .expect("read");
        }

        assert_eq!(
            f.host.hits(&format!(
                "{REPO}/org/example/parent/5.0/parent-5.0.pom.sha1"
            )),
            1
        );
    }

    /// What the sidecars proved lands on the POM's own file entry, so the
    /// report carries it.
    #[tokio::test]
    async fn verify_checksum_reaches_report() {
        use sha1::{Digest as _, Sha1};

        let mut hasher = Sha1::new();
        hasher.update(LIB_POM.as_bytes());
        let digest = hex::encode(hasher.finalize());

        let f =
            fixture_from(client().with_body(format!("{DIR}/1.0/lib-1.0.pom.sha1"), digest.clone()));

        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        let pom = &artifact.files[0];

        assert_eq!(pom.name, "lib-1.0.pom");
        assert_eq!(pom.digests.len(), 1);
        assert_eq!(pom.digests[0].hex, digest);

        // And it stays on the POM rather than migrating to the payload,
        // which was never downloaded and so was never checked.
        assert!(artifact.files[1].digests.is_empty());
    }

    /// With no `checksums` configured, a repository publishing only
    /// SHA-256 is still checked: the source tries the stronger sidecars
    /// before settling on what the repository serves.
    #[tokio::test]
    async fn verify_sha256_only_repository() {
        use sha2::{Digest as _, Sha256};

        let digest = hex::encode(Sha256::digest(LIB_POM.as_bytes()));

        let f = fixture_from(
            client().with_body(format!("{DIR}/1.0/lib-1.0.pom.sha256"), digest.clone()),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("resolved");

        assert_eq!(
            artifact.files[0].digests,
            [crate::model::Digest::new(DigestAlg::Sha256, digest)]
        );
    }

    /// A POM that does not match the checksum published beside it is
    /// corrupt or tampered with, and `checksum-mismatch` aborts by default.
    #[tokio::test]
    async fn verify_pom_checksum_failure_reported() {
        let f = fixture_from(client().with_body(
            format!("{DIR}/1.0/lib-1.0.pom.sha1"),
            "0000000000000000000000000000000000000000",
        ));

        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let _ = f.subject.metadata(&id(), Some(&version), &ctx).await;

        assert_eq!(ctx.problems().counts()[&Code::ChecksumMismatch], 1);
    }

    /// Maven licenses are free text and inherited from the parent, so this
    /// exercises both at once.
    #[tokio::test]
    async fn license_inherited_as_written() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(
            artifact.license.as_deref(),
            Some("Apache License, Version 2.0")
        );
    }

    /// Maven publishes no upload timestamp, so the payload's own
    /// `Last-Modified` is the only answer there is.
    #[tokio::test]
    async fn publish_time_from_last_modified() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert_eq!(
            artifact.published.expect("dated").to_rfc3339(),
            "2015-10-21T07:28:00+00:00"
        );
    }

    /// A repository that sends no `Last-Modified` yields no date rather
    /// than a guess.
    #[tokio::test]
    async fn publish_time_absent_without_last_modified() {
        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), LIB_POM)
                .with_body(
                    format!("{REPO}/org/example/parent/5.0/parent-5.0.pom"),
                    PARENT_POM,
                )
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert!(artifact.published.is_none());
    }

    #[tokio::test]
    async fn source_cannot_reach_unconfigured_host() {
        let host = Arc::new(TestHost::allowing(client(), "h://elsewhere.test/"));
        let source = MavenSource::new(REPO, host.clone());
        let ctx = ctx();

        let err = source.versions(&id(), &ctx).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("outside what this extension may fetch")
        );
    }
}
