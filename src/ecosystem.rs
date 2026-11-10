//! Protocol rules for each package ecosystem.
//!
//! Pure knowledge: how Maven spells a coordinate, which dependency kinds npm
//! publishes, what a registry calls itself.  No I/O, no host, no
//! configuration.
//!
//! Both I/O traits reference an ecosystem rather than embedding one:
//!
//! ```text
//!   source / target  --\
//!                       >-- Ecosystem -- coordinates, identity, dep kinds
//!   enumerator       --/                       |
//!                                              +-- VersionHandler
//! ```
//!
//! # Versions are a separate trait
//!
//! Every ecosystem *is* a [`VersionHandler`], because every one of them
//! knows how its own versions order.  The trait is separate -- and
//! `Ecosystem` merely requires it -- because the converse does not hold: a
//! raw repository has no ecosystem and still needs versions, and a GitHub
//! repository whose tags happen to be semver should be able to say so.  See
//! [`crate::version`].
//!
//! Lock-file inspection is **not** here: it is its own extension point in
//! [`crate::lock`], because lock formats belong to tools rather than to
//! registries.  That separation is what leaves this trait genuinely pure --
//! no I/O of any kind.
//!
//! An extension declares which ecosystem it speaks through its own typed
//! methods, rather than the host holding a table that says
//! `maven-html-index` is a Maven enumerator.  That is what lets `kind` be a
//! free string, and what makes `inspect --enumerator=NAME` work: an enumerator
//! names a host and, through [`crate::repo::enumerate::Enumerator::ecosystems`], an ecosystem -- everything
//! needed to parse a request and resolve it, without an enumerator knowing how
//! to resolve anything.
//!
//! References: [PEP 658](https://peps.python.org/pep-0658/), [OSV schema](https://ossf.github.io/osv-schema/), [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::core::error::Result;
use crate::model::{ArtifactRequest, DepKind, EcosystemId};
use crate::version::VersionHandler;

pub mod maven;
mod npm;
pub mod pypi;
mod raw;

pub use maven::Maven;
pub use npm::Npm;
pub(crate) use npm::PACKUMENT_DOCUMENT;
pub use pypi::PyPi;
pub use raw::Raw;

/// The protocol rules for one ecosystem.
///
/// **Every operation is batched.** That looks over-built in process, where
/// a pairwise `compare` would read more naturally -- but an ecosystem is an
/// extension point, and sorting an 800-version packument through a marshaled
/// `compare` would be thousands of round trips. One call per artifact is the
/// shape that survives being out of process, so it is the shape of the
/// interface.
pub trait Ecosystem: VersionHandler + Send + Sync {
    /// Parse this ecosystem's coordinate syntax.
    fn parse_req(&self, text: &str) -> Result<ArtifactRequest>;

    /// This ecosystem's identity.
    fn id(&self) -> EcosystemId;

    /// The `pkg:<type>` segment of a purl.
    fn purl_type(&self) -> &str;

    /// The OSV name, which is capitalized differently from purl and
    /// differently again per ecosystem: `Maven`, `PyPI`, `npm`.
    ///
    /// Empty for an ecosystem OSV does not know, so nothing screens it.
    fn osv_name(&self) -> &str;

    /// Kinds this ecosystem actually publishes.
    ///
    /// `test` is Maven-only, `peer` is npm-only, and PyPI publishes neither
    /// dev nor test dependencies.  Asking for one an ecosystem lacks is an
    /// error, not an empty result that reads as "there are none".
    fn dep_kinds(&self) -> &[DepKind];

    /// Documents that travel beside each file, fetched from the source and
    /// staged with the payload for the target.
    ///
    /// Declared by the ecosystem rather than asked by a target, because
    /// which documents belong to a file is an ecosystem rule: PyPI's
    /// PEP 658 metadata belongs to every PyPI upload. A target may still
    /// decline one; see [`crate::repo::Target::declines`]. Empty by default.
    fn companions(&self) -> &[Companion] {
        &[]
    }

    /// Whether an artifact here may legitimately have no version.
    ///
    /// **This is what tells a recorded `NULL` version apart from a missing
    /// one**, and the two are opposite instructions. A `find` over
    /// npm's replication feed writes a name with no version because the
    /// versions cost a packument each and nobody has paid -- *unknown*, and
    /// resolving it to whatever is newest today would copy something the
    /// report never named. A raw repository's directory has no version
    /// because there is none -- *absent*, and skipping it would drop the
    /// artifact from the migration entirely.
    ///
    /// Nothing in the row itself distinguishes them, so the ecosystem is
    /// asked. False everywhere but `raw`, and true for `raw` whichever
    /// mapping it uses: a mapping that does supply versions puts them in
    /// the column, so a `NULL` under raw always means there is none.
    fn version_optional(&self) -> bool {
        false
    }

    /// How long the inventory documents this ecosystem's sources cache stay
    /// fresh, as `(file name pattern, fresh for)`.
    ///
    /// The last word, after a binding's own `cache-freshness` and
    /// `setup`'s, and a file none of them names is fresh forever -- which
    /// is right for a released payload, and wrong for a document that
    /// changes whenever a version is published. Empty by default.
    fn freshness(&self) -> &[(&'static str, Duration)] {
        &[]
    }
}

/// A document that travels beside a file.
///
/// A source advertises one per file, and the caller fetches it only when
/// the file's ecosystem declares it in [`Ecosystem::companions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Companion {
    /// The PEP 658 core-metadata document, `{file}.metadata`.
    CoreMetadata,

    /// The PEP 740 provenance object, at the URL the index names, holding
    /// the file's attestations.
    Provenance,

    /// npm's version document, `{registry}/{name}/{version}`: the
    /// package's manifest as its registry serves it, `dependencies`,
    /// `engines`, and `bin` included. What a faithful republish sends.
    PackageManifest,
}

/// Whether a file an enumerator listed belongs to the artifact it was found in.
///
/// A catalog lists everything in a version's place, and some of it is
/// *about* a file rather than one: a checksum sidecar, which a target
/// writes for itself, and for Maven the repository's own index. Those stay
/// out; everything else joins, signatures included.
///
/// Raw keeps every file. It has no sidecar convention, so `data.sha1` in a
/// raw repository is somebody's file and not a claim about another.
pub(crate) fn joins_listing(ecosystem: &EcosystemId, name: &str) -> bool {
    if ecosystem.as_str() == EcosystemId::RAW {
        return true;
    }

    if ecosystem.as_str() == EcosystemId::MAVEN && maven::is_repository_file(name) {
        return false;
    }

    !is_checksum_sidecar(name)
}

/// `lib-1.0.jar.sha1`, `pkg.tgz.sha512`: named for the algorithm it holds.
fn is_checksum_sidecar(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, extension)| crate::model::DigestAlg::parse(extension).is_some())
}

/// Build the ecosystem a `kind` names.
///
/// `kind` is a free string so that a third-party ecosystem can be named
/// here; the built-in registry is consulted first.
pub fn open(kind: &str) -> Result<Arc<dyn Ecosystem>> {
    let Some((_, built)) = BUILT_INS.iter().find(|(name, _)| *name == kind) else {
        return Err(crate::core::error::Error::UnknownKind {
            collection: "ecosystem",
            kind: kind.to_owned(),
        });
    };

    Ok(built())
}

/// Builds one built-in ecosystem.
type OpenEcosystem = fn() -> Arc<dyn Ecosystem>;

/// Every built-in ecosystem, by the name [`EcosystemId`] gives it. Adding
/// one adds one line here.
const BUILT_INS: &[(&str, OpenEcosystem)] = &[
    (EcosystemId::MAVEN, || Arc::new(Maven)),
    (EcosystemId::NPM, || Arc::new(Npm)),
    (EcosystemId::PYPI, || Arc::new(PyPi)),
    (EcosystemId::RAW, || Arc::new(Raw)),
];

/// Every built-in ecosystem's [`Ecosystem::freshness`] rules.
///
/// Combined rather than chosen by the binding's ecosystem, because a
/// repository manager serves several, and the document names are distinct
/// across them: `maven-metadata.xml` is never an npm document.
pub(crate) fn freshness_defaults() -> Vec<(&'static str, Duration)> {
    kinds()
        .iter()
        .filter_map(|kind| open(kind).ok())
        .flat_map(|ecosystem| ecosystem.freshness().to_vec())
        .collect()
}

/// Built-in ecosystem kinds, for an error that names the alternatives.
pub fn kinds() -> &'static [&'static str] {
    static KINDS: LazyLock<Vec<&'static str>> =
        LazyLock::new(|| BUILT_INS.iter().map(|(name, _)| *name).collect());

    &KINDS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Maven version directory's files join, less the sidecars a target
    /// writes for itself and the repository's own index.
    #[test]
    fn listing_maven_drops_sidecars() {
        let maven = EcosystemId::maven();

        for name in [
            "a-1.0.jar",
            "a-1.0.pom",
            "a-1.0.module",
            "a-1.0.jar.asc",
            "a-1.0-sources.jar",
        ] {
            assert!(joins_listing(&maven, name), "{name}");
        }

        for name in [
            "a-1.0.jar.sha1",
            "a-1.0.jar.MD5",
            "a-1.0.pom.sha512",
            "maven-metadata.xml",
        ] {
            assert!(!joins_listing(&maven, name), "{name}");
        }
    }

    /// Raw has no sidecar convention, so every file is somebody's file.
    #[test]
    fn listing_raw_keeps_everything() {
        assert!(joins_listing(&EcosystemId::raw(), "data.sha1"));
        assert!(joins_listing(&EcosystemId::raw(), "maven-metadata.xml"));
    }

    #[test]
    fn listing_npm_drops_sidecars() {
        assert!(joins_listing(&EcosystemId::npm(), "tuna-1.0.0.tgz"));
        assert!(!joins_listing(&EcosystemId::npm(), "tuna-1.0.0.tgz.sha256"));
    }

    #[test]
    fn kind_known_opens() {
        assert!(open(EcosystemId::NPM).is_ok());
    }

    /// Every built-in kind the registry advertises must actually open, or
    /// `validate-config` would accept a config the run then rejects.
    #[test]
    fn every_advertised_kind_opens() {
        for kind in kinds() {
            assert!(open(kind).is_ok(), "{kind} should open");
        }
    }

    /// `kind` is a free string now, so a typo must name the alternatives
    /// rather than being caught by a schema that no longer enumerates them.
    #[test]
    fn kind_unknown_names_itself() {
        let err = match open("nmp") {
            Err(err) => err,
            Ok(_) => panic!("should not have opened"),
        };

        assert!(err.to_string().contains("nmp"));
        assert!(kinds().contains(&EcosystemId::NPM));
    }

    #[test]
    fn npm_states_identity_and_dep_kinds() {
        assert_eq!(Npm.id(), EcosystemId::npm());
        assert_eq!(Npm.purl_type(), "npm");
        assert_eq!(Npm.osv_name(), "npm");
        assert!(Npm.dep_kinds().contains(&DepKind::Peer));
    }

    /// PyPI and npm carry companions; every other upload travels alone.
    #[test]
    fn companions_per_ecosystem() {
        for kind in kinds() {
            let ecosystem = open(kind).expect("opens");
            let expected: &[Companion] = match *kind {
                EcosystemId::PYPI => &[Companion::CoreMetadata, Companion::Provenance],
                EcosystemId::NPM => &[Companion::PackageManifest],
                _ => &[],
            };

            assert_eq!(ecosystem.companions(), expected, "{kind}");
        }
    }
}
