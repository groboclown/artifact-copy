//! Reading from and writing to a repository.
//!
//! `Source` and `Target` are **separate trait sets**. A registry that can be
//! both read and written implements both; one that is read-only implements
//! only `Source`. Nothing requires a pair, and plenty of real repositories
//! are one-way.
//!
//! Neither performs network I/O directly. Both ask the
//! [`ExtHost`] they were built with, which applies the
//! host's constraints and credentials -- see [`crate::ext`].

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::{Companion, Ecosystem};
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, ArtifactRequest, Dependency, FileRef, ResolvedArtifact, Version};
use crate::net::Expectation;

mod adapter;
mod archive;
mod artifact_keeper;
mod artifactory;
mod bound;
mod companion;
mod criteria;
mod delivery;
mod download;
pub mod enumerate;
mod extension;
mod github;
mod inventory;
mod kind;
mod lifetime;
mod local_dir;
mod manager;
mod maven;
mod names;
mod nexus;
mod npm;
mod omit;
mod overwrite;
mod page_cap;
pub mod proxy;
mod pypi;
mod raw;
mod resolve;
mod scheme;
mod sources;
mod trust;
pub mod upstream;

pub use adapter::{sole_ecosystem, version_required};
pub use artifact_keeper::ArtifactKeeperGenericTarget;
pub use bound::Bound;
#[cfg(test)]
pub(crate) use companion::CORE_METADATA_SUFFIX;
pub use companion::Companions;
pub use criteria::Criteria;
pub(crate) use criteria::criteria_for;
pub use delivery::{Delivered, Delivery};
pub(crate) use download::writable;
pub use download::{Downloaded, Obtained, download, stage};
pub use github::GitHubSource;
pub use inventory::InventorySource;
pub(crate) use lifetime::policy as cache_policy;
pub use local_dir::{LocalDirEnumerator, LocalDirSource, LocalDirTarget};
pub use maven::{MavenSource, MavenTarget, MetadataMode};
pub use names::{Lookup, NameCase, NameMap};
pub use nexus::{NexusRawSource, NexusRawTarget};
pub use npm::{DistTags, NpmSource, NpmTarget};
pub use omit::{Omission, Omit, OmittingEnumerator, OmittingSource, OmittingTarget};
pub use overwrite::OverwriteGuard;
pub use page_cap::PageCap;
pub use proxy::{Failover, SourceUpstreams, Upstream, Upstreams, open_proxy_source};
pub(crate) use proxy::{is_proxy_kind, proxy_source_kinds};
pub(crate) use pypi::pep503;
pub use pypi::{LegacyDists, PyPiSource, PyPiTarget};
pub use raw::{Coordinate, Mapping};
pub(crate) use scheme::{VersionScheme, declared_version_kinds, version_scheme};
pub use sources::Sources;
pub(crate) use sources::{MAX_PROXY_DEPTH, under};
pub use trust::Trust;

/// Reading a repository.
#[async_trait]
pub trait Source: Send + Sync {
    /// The protocol rules for one artifact.
    ///
    /// **Takes the artifact rather than returning a fixed ecosystem.** A
    /// registry adapter speaks exactly one and ignores the argument, but a
    /// repository manager -- Nexus, Artifactory -- serves Maven, npm and PyPI
    /// from one API behind one host and one credential.  Fixing the
    /// ecosystem to the source would split one implementation into three.
    ///
    /// Erroring on an ecosystem this source does not speak is the useful
    /// answer: an npm source handed a Maven purl is a bug, and saying so
    /// beats resolving it against the wrong version rules.
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem>;

    /// Which ecosystems this source speaks, without being shown an
    /// artifact.
    ///
    /// [`Source::ecosystem`] answers *will you take this one*, which is the
    /// question resolution asks. This answers *what are you*, which is the
    /// question a **composer** asks -- a proxy deciding whether its
    /// upstreams are compatible cannot invent an artifact to probe them
    /// with.
    ///
    /// Almost always one entry. A repository manager pointed at one
    /// repository still holds one format; the plural is here for a source
    /// that genuinely fronts several, and the list is bounded by what an
    /// adapter supports rather than by anything a run finds.
    fn ecosystems(&self) -> Vec<crate::model::EcosystemId>;

    /// How this source's versions are read and ordered.
    ///
    /// The artifact's ecosystem by default, which is right for every
    /// registry adapter: npm *is* semver and Maven *is* `ComparableVersion`.
    /// Overridden by [`Bound`], which is where a configured
    /// `version-handler` reaches resolution -- a repository whose contents
    /// decide its versions rather than its ecosystem.
    ///
    /// Takes the artifact for the same reason [`Source::ecosystem`] does: a
    /// repository manager fronts several ecosystems and they do not agree
    /// about ordering.
    fn version_handler(&self, id: &ArtifactId) -> Result<&dyn crate::version::VersionHandler> {
        Ok(self.ecosystem(id)?)
    }

    /// Whether this source's artifacts have versions at all.
    ///
    /// **True for every registry**, because a registry without versions is
    /// not a registry. False for a raw repository read as directories: a
    /// path has no version, and the honest answer is not "one version whose
    /// text is empty" but "this question does not apply".
    ///
    /// Asked per artifact for the same reason [`Source::ecosystem`] is --
    /// one source may front several repositories -- and it is what lets
    /// [`Source::resolve`] skip selection entirely rather than hunt through
    /// an empty candidate list.
    ///
    /// **A decorator must forward this.** Taking the default would make a
    /// wrapped raw source look versioned, and resolution would then fail on
    /// an artifact the source can perfectly well answer for.
    fn versioned(&self, id: &ArtifactId) -> bool {
        let _ = id;

        true
    }

    /// Every published version of one artifact.
    ///
    /// Ordering is the ecosystem's job, so callers must not assume the
    /// registry returned them sorted -- npm packuments and PyPI's `versions`
    /// are both unordered in practice.
    ///
    /// Empty from a source that answers [`Source::versioned`] with false,
    /// and never consulted there.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>>;

    /// An exact version confirmed by asking for it directly, **before**
    /// [`Source::versions`] is read.
    ///
    /// For a source where one direct read is cheaper than its version list
    /// and is needed anyway: a Maven POM is what `metadata` reads next,
    /// while the list can be an index per artifact. `None` by default, and
    /// whenever the version is not confirmed, which leaves the list to
    /// answer as before.
    ///
    /// **A decorator must forward this**, or a wrapped source that can
    /// confirm a version would go to its list instead.
    async fn confirmed(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        let _ = (id, text, ctx);

        Ok(None)
    }

    /// A version [`Source::versions`] does not list, confirmed by asking
    /// for it directly.
    ///
    /// For an exact request that the version list cannot satisfy: a
    /// repository's index can be stale, as Central's `maven-metadata.xml`
    /// for `qdox:qdox` omits `1.6` and `1.6.1` while their files are
    /// served. `None` by default, which trusts the list.
    ///
    /// **A decorator must forward this**, or a wrapped source that can
    /// confirm a version would look as though it cannot.
    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        let _ = (id, text, ctx);

        Ok(None)
    }

    /// Files, checksums, license, and publish time for one exact version.
    ///
    /// `version` is `None` only where [`Source::versioned`] is false. A
    /// registry adapter handed one has been asked something incoherent and
    /// should say so rather than guess.
    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact>;

    /// Direct dependencies of one exact version, tagged by kind.
    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>>;

    /// Download one file this source described into its cache.
    ///
    /// Through the source's own host, so a file is fetched with the
    /// credentials of the repository that listed it. A leaf source calls
    /// [`download`](fn@crate::repo::download); a proxy hands the file to the upstream that
    /// [`Source::serves`] its URL.
    async fn download(&self, file: &FileRef, expect: &Expectation, ctx: &Ctx)
    -> Result<Downloaded>;

    /// Check an artifact's downloaded files against each other, once every
    /// one is staged: a detached signature against the file it signs.
    ///
    /// `files` are the staged paths, one per `artifact.files` entry and in
    /// the same order; `companions` the documents already staged beside
    /// them, so a check that needs one reads it rather than fetching it
    /// again. A verdict is reported on `ctx`; an error means a staged file
    /// could not be read. Nothing to check by default.
    async fn verify(
        &self,
        _artifact: &ResolvedArtifact,
        _files: &[PathBuf],
        _companions: &Companions,
        _ctx: &Ctx,
    ) -> Result<()> {
        Ok(())
    }

    /// Whether a file at `url` is this source's to download: whether its
    /// host would send the request anywhere.
    fn serves(&self, url: &str) -> bool;

    /// Where the document of `kind` beside `file` is, and what it must
    /// match, when this source has one.
    ///
    /// By default, what the file advertises: PyPI's index names both of
    /// its documents on the file. A source that knows a URL the file does
    /// not carry answers for itself, and a wrapper forwards.
    fn companion(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        kind: Companion,
    ) -> Option<(FileRef, Expectation)> {
        let _ = artifact;

        companion::advertised(file, kind)
    }

    /// `artifact` as this source offers it: without what its `omit` rules
    /// leave out, or refused when they leave out all of it.
    ///
    /// For an artifact answered from somewhere other than this source --
    /// a report database -- which must still be what this source would
    /// offer. Unchanged by default; see [`OmittingSource`].
    async fn offered(&self, artifact: ResolvedArtifact, _ctx: &Ctx) -> Result<ResolvedArtifact> {
        Ok(artifact)
    }

    /// Resolve a request to one artifact.
    ///
    /// Always the **highest acceptable** version, per `README.md`. A request
    /// with no version at all is the ordinary case of that rather than a
    /// special one: `VersionSpec::Any` matches everything, so the newest
    /// version that satisfies the criteria wins.
    ///
    /// "Acceptable" is why this steps down rather than selecting once. The
    /// version specification can be checked against the version list, but a
    /// publish window cannot -- the publish time arrives with the metadata,
    /// after a version has been picked. So a version that turns out to be
    /// too recent is dropped and the next newest is tried, up to
    /// a bounded number of times.
    async fn resolve(
        &self,
        request: &ArtifactRequest,
        criteria: Criteria,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        resolve::resolve(self, request, criteria, ctx).await
    }
}

/// Writing to a repository.
#[async_trait]
pub trait Target: Send + Sync {
    /// The protocol rules for one artifact.  See [`Source::ecosystem`].
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem>;

    /// Whether the target already holds this exact version, asked of the
    /// repository itself.
    ///
    /// The fallback, not the first resort: a caller asks whatever it
    /// already knows before coming here -- see
    /// [`crate::session::ConfiguredTarget::holds`].
    ///
    /// `version` is `None` for a repository that declares none; see
    /// [`Source::versioned`].
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool>;

    /// Whether this target would ignore a companion its ecosystem declares,
    /// so the caller spends no request fetching it. None by default.
    fn declines(&self, _companion: Companion) -> bool {
        false
    }

    /// The configured rule leaving out the whole artifact, if one does, so
    /// the caller records it as refused before fetching anything. None by
    /// default; see [`OmittingTarget`].
    fn omitted(&self, _artifact: &ResolvedArtifact) -> Option<String> {
        None
    }

    /// Publish an artifact.
    ///
    /// `files` are the downloaded payloads, one per `artifact.files` entry
    /// and in the same order, so a multi-gigabyte upload never passes
    /// through a call boundary; `companions` are the documents its
    /// ecosystem says travel beside them.
    ///
    /// `delivery` takes what became of each file as it happens. An
    /// operation carrying no file of the artifact -- writing
    /// `maven-metadata.xml`, a checksum sidecar -- is not recorded.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()>;
}

/// Build a source for a configured entry.
///
/// Takes no HTTP client: the host it may reach is decided by the
/// `Constraints` on the `host` it is built with.
///
/// `options` is where a repository manager learns which repository it points
/// at and which ecosystem that repository holds -- see
/// [`crate::ext::options`]. A registry adapter ignores it, which is why the
/// built-ins below do.
///
/// `trust` is what signatures are checked against: Maven's detached PGP
/// signatures against its keys, PyPI's attestations against its Sigstore
/// root. Every other kind ignores it.
pub fn open_source(
    kind: &str,
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    trust: Trust,
) -> Result<Arc<dyn Source>> {
    let Some(found) = source_kind(kind) else {
        return Err(Error::UnknownKind {
            collection: "source",
            kind: kind.to_owned(),
        });
    };

    (found.open)(base_url, options, host, trust)
}

/// Build a source whose names `names` maps, for a kind that reads one.
///
/// An empty map is every kind's, so that case is [`open_source`] alone.
pub fn open_named_source(
    kind: &str,
    base_url: &str,
    options: &Options,
    names: NameMap,
    host: Arc<dyn ExtHost>,
    trust: Trust,
) -> Result<Arc<dyn Source>> {
    if names.is_empty() {
        return open_source(kind, base_url, options, host, trust);
    }

    let Some(named) = source_kind(kind).and_then(|found| found.names.as_ref()) else {
        return Err(Error::Config(format!(
            "source kind {kind:?} does not read 'names'; the kinds that do are {}",
            names_kinds().join(", ")
        )));
    };

    (named.open)(base_url, options, names, host)
}

/// The source kinds that read `names`, for a message that names them.
pub(crate) fn names_kinds() -> &'static [&'static str] {
    static NAMES_KINDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        sorted(
            source_descriptors()
                .filter(|found| found.names.is_some())
                .map(|found| found.name),
        )
    });

    &NAMES_KINDS
}

/// Build a target for a configured entry.
///
/// Deliberately a **shorter list** than [`source_kinds`]: reading a
/// repository and writing to one are separate capabilities, and plenty of
/// real repositories are read-only. A kind missing here is not an
/// oversight -- it is a registry this tool cannot publish to yet, and saying
/// so beats accepting the configuration and failing at the upload.
pub fn open_target(
    kind: &str,
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Target>> {
    let found = SERVERS
        .iter()
        .filter_map(|server| server.target.as_ref())
        .find(|found| found.name == kind);

    let Some(found) = found else {
        return Err(Error::UnknownKind {
            collection: "target",
            kind: kind.to_owned(),
        });
    };

    (found.open)(base_url, options, host)
}

/// Refuse a built-in source kind's options that could never open, without
/// building the source.
///
/// For `validate-config`, which checks a file without starting the clients
/// and caches a built source needs.
pub(crate) fn check_source_options(kind: &str, options: &Options) -> Result<()> {
    let Some(found) = source_kind(kind) else {
        return Ok(());
    };

    (found.check)(options)
}

/// Refuse a built-in source kind's `names` that could never be read, such
/// as a GitHub repository outside its `repositories`.
pub(crate) fn check_source_names(kind: &str, options: &Options, names: &NameMap) -> Result<()> {
    let Some(named) = source_kind(kind).and_then(|found| found.names.as_ref()) else {
        return Ok(());
    };

    (named.check)(options, names)
}

/// Built-in target kinds, for an error message that names the
/// alternatives.
pub(crate) fn target_kinds() -> &'static [&'static str] {
    static TARGET_KINDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        sorted(
            SERVERS
                .iter()
                .filter_map(|server| server.target.as_ref())
                .map(|found| found.name),
        )
    });

    &TARGET_KINDS
}

/// Built-in source kinds, for an error message that names the alternatives.
pub(crate) fn source_kinds() -> &'static [&'static str] {
    static SOURCE_KINDS: LazyLock<Vec<&'static str>> =
        LazyLock::new(|| sorted(source_descriptors().map(|found| found.name)));

    &SOURCE_KINDS
}

/// Every spelling a source's `kind` may take, proxies included, for a
/// message that lists all of them rather than half.
pub(crate) fn all_source_kinds() -> &'static [&'static str] {
    static ALL_SOURCE_KINDS: LazyLock<Vec<&'static str>> =
        LazyLock::new(|| sorted(source_kinds().iter().chain(proxy_source_kinds()).copied()));

    &ALL_SOURCE_KINDS
}

/// Every server module's kinds. Adding a server adds one line here.
const SERVERS: &[&kind::Kinds] = &[
    &artifact_keeper::KINDS,
    &artifactory::KINDS,
    &github::KINDS,
    &local_dir::KINDS,
    &maven::KINDS,
    &nexus::KINDS,
    &npm::KINDS,
    &pypi::KINDS,
];

/// Every server's source kind.
fn source_descriptors() -> impl Iterator<Item = &'static kind::SourceKind> {
    SERVERS.iter().filter_map(|server| server.source.as_ref())
}

/// The source kind named `kind`, if a server offers it.
fn source_kind(kind: &str) -> Option<&'static kind::SourceKind> {
    source_descriptors().find(|found| found.name == kind)
}

/// `names`, sorted for a message.
fn sorted(names: impl Iterator<Item = &'static str>) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = names.collect();

    names.sort_unstable();
    names
}

/// Options a built-in kind needs before it will open at all.
///
/// Only for the tests of [`source_kinds`] and [`target_kinds`], which ask
/// whether every advertised kind can be constructed. Most take none; a repository manager
/// is pointed at one repository of many and cannot guess which.
#[cfg(test)]
fn minimal_options(kind: &str) -> Options {
    match kind {
        "nexus" | "artifact-keeper" => crate::ext::testing::options(serde_json::json!({
            "repository": "raw-hosted",
            "ecosystem": "raw",
        })),

        "artifactory" => crate::ext::testing::options(serde_json::json!({
            "repository": "libs-release-local",
            "ecosystem": "maven",
        })),

        "github" => crate::ext::testing::options(serde_json::json!({
            "repositories": ["owner/*"],
        })),

        "artifact-keeper-generic" => crate::ext::testing::options(serde_json::json!({
            "repository": "generic-local",
        })),

        "nexus-raw" => crate::ext::testing::options(serde_json::json!({
            "repository": "raw-hosted",
        })),

        "artifactory-generic" => crate::ext::testing::options(serde_json::json!({
            "repository": "generic-local",
        })),

        _ => Options::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::problem::Code;
    use crate::ext::testing::idle;

    #[test]
    fn kind_known_opens() {
        assert!(
            open_source(
                "npm",
                "h://registry.test",
                &Options::default(),
                idle(),
                no_keys()
            )
            .is_ok()
        );
    }

    /// A registry adapter speaks one ecosystem, and being handed a foreign
    /// artifact is a bug worth naming.  Resolving a Maven coordinate against
    /// semver rules would pick a plausible-looking wrong answer.
    #[test]
    fn ecosystem_foreign_artifact_refused() {
        let source = NpmSource::new("h://registry.test", idle());

        let maven = ArtifactId::new(
            crate::model::EcosystemId::maven(),
            Some("org.example"),
            "lib",
        );

        let err = match source.ecosystem(&maven) {
            Err(err) => err,
            Ok(_) => panic!("an npm source must not claim a Maven artifact"),
        };

        assert!(err.to_string().contains("maven"));
    }

    #[test]
    fn ecosystem_own_artifact_accepted() {
        let source = NpmSource::new("h://registry.test", idle());
        let npm = ArtifactId::new(crate::model::EcosystemId::npm(), None, "lodash");

        assert!(source.ecosystem(&npm).is_ok());
    }

    fn no_keys() -> Trust {
        Trust::untrusting()
    }

    /// `dyn Source` is not `Debug`, so `unwrap_err` is unavailable.
    fn error_from(kind: &str) -> Error {
        match open_source(
            kind,
            "h://example.test/",
            &Options::default(),
            idle(),
            no_keys(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("{kind} should not have opened"),
        }
    }

    /// Every advertised kind must actually open, or `validate-config`
    /// accepts a config the run then rejects.
    #[test]
    fn every_advertised_kind_opens() {
        for kind in source_kinds() {
            assert!(
                open_source(
                    kind,
                    "h://example.test/",
                    &minimal_options(kind),
                    idle(),
                    no_keys()
                )
                .is_ok(),
                "{kind} should open"
            );
        }
    }

    /// Kinds are found by name, so a second server claiming a name would be
    /// shadowed without a word.
    #[test]
    fn kind_names_are_unique() {
        let enumerators = enumerate::enumerator_kinds();

        for kinds in [source_kinds(), target_kinds(), enumerators] {
            let mut seen = std::collections::BTreeSet::new();

            for kind in kinds {
                assert!(seen.insert(kind), "{kind} is offered twice");
            }
        }
    }

    /// The same for targets: `validate-config` checks a target's kind
    /// against [`target_kinds`], so one that cannot open is a promise the
    /// run breaks.
    #[test]
    fn every_advertised_target_kind_opens() {
        for kind in target_kinds() {
            assert!(
                open_target(kind, "h://example.test/", &minimal_options(kind), idle()).is_ok(),
                "{kind} should open"
            );
        }
    }

    /// With `kind` a free string, the schema no longer catches a typo, so
    /// the error has to carry its weight.
    #[test]
    fn kind_unknown_names_itself() {
        let err = error_from("nmp");

        assert_eq!(err.code(), Code::ConfigInvalid);
        assert!(err.to_string().contains("nmp"));
    }
}
