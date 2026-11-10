//! The raw ecosystem, which is a repository without one.
//!
//! A raw repository holds files under a path and asserts nothing about
//! them: no group, no version, no metadata document. Nexus and Artifactory
//! both offer one, and what the paths mean is entirely up to whoever
//! uploads into them.
//!
//! So this is an ecosystem in the sense the code needs -- something that
//! parses a coordinate and names a purl type -- and in no other sense. It
//! makes **no claim about versions**, because a path has no version until a
//! [`Mapping`](crate::repo::Mapping) says one of its segments is one, and
//! that is the user's declaration rather than the repository's nature.
//!
//! # Coordinates are paths
//!
//! A user names an artifact the way the repository does, with `/`
//! separators, optionally `path@version` where the mapping supplies a
//! version. Nothing is normalized: `Tools/CLI` and `tools/cli` are two
//! different directories on a server that distinguishes them, and folding
//! case would copy one and report the other missing.
//!
//! # Versions order by declaration
//!
//! [`Tags`] treats versions as an unordered set: it can say two versions
//! are equal and nothing else. That is the honest default for a path
//! segment, which might be `1.2.0`, `latest`, or `build-77`. A repository
//! whose segments do follow a convention says so with `version-handler`,
//! which is why that setting exists -- see `docs/contributors/versions.md`.

use std::sync::Arc;

use super::Ecosystem;
use crate::core::error::{Error, Result};
use crate::model::{
    ArtifactId, ArtifactRequest, Cause, DepKind, EcosystemId, Provenance, Version, VersionSpec,
};
use crate::version::{PreRelease, Ranking, Tags, VersionHandler};

/// A raw repository publishes no dependency information of any kind.
///
/// Empty rather than `runtime`, and the difference matters: asking for
/// `--dependencies=runtime` against a raw repository is an error rather
/// than an empty result that would read as "these files depend on nothing".
const DEP_KINDS: [DepKind; 0] = [];

/// There is no OSV ecosystem for arbitrary files.
///
/// Advisories are published against registries, and a file in a raw
/// repository is not in one. An empty name means nothing screens it, which
/// is the truth rather than a gap: a clean report for a raw repository says
/// only that nothing was asked.
const OSV_NAME: &str = "";

pub struct Raw;

impl Ecosystem for Raw {
    fn id(&self) -> EcosystemId {
        EcosystemId::new(EcosystemId::RAW)
    }

    fn purl_type(&self) -> &str {
        EcosystemId::RAW
    }

    fn osv_name(&self) -> &str {
        OSV_NAME
    }

    fn dep_kinds(&self) -> &[DepKind] {
        &DEP_KINDS
    }

    /// A raw artifact may have no version at all, and usually does.
    ///
    /// The default mapping makes a directory an artifact, and a directory
    /// has no version. See [`Ecosystem::version_optional`] for why this is
    /// asked of the ecosystem rather than read off the row.
    fn version_optional(&self) -> bool {
        true
    }

    /// Parse `path` or `path@version`.
    ///
    /// The `@` is the same separator a purl uses, and a path segment may
    /// legitimately contain one, so it is split from the **right** -- the
    /// last `@` is the version, anything earlier is part of the path.
    fn parse_req(&self, text: &str) -> Result<ArtifactRequest> {
        let trimmed = text.trim().trim_matches('/');

        if trimmed.is_empty() {
            return Err(Error::BadRequest {
                ecosystem: "raw",
                text: text.to_owned(),
                detail: "a raw coordinate is a repository path".to_owned(),
            });
        }

        let (name, spec) = match trimmed.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() && !version.is_empty() => {
                (name, VersionSpec::Exact(version.to_owned()))
            }

            // No version asked for, which for the directory mapping is the
            // only thing there is to ask for.
            _ => (trimmed, VersionSpec::Any),
        };

        Ok(ArtifactRequest {
            id: ArtifactId::new(EcosystemId::raw(), None, name),
            spec,
            prov: Arc::new(Provenance::root(Cause::Requested {
                arg: text.to_owned(),
            })),
        })
    }
}

/// Versions are whatever the paths say, which is to say unordered.
///
/// Delegated to [`Tags`] rather than implemented, because "this convention
/// has no ordering" is a statement a repository makes and not a property of
/// being raw. A repository whose segments are semver configures
/// `version-handler` and gets real ordering.
impl VersionHandler for Raw {
    fn version_spec(&self, text: &str) -> VersionSpec {
        Tags.version_spec(text)
    }

    fn classify(&self, texts: &[String]) -> Vec<Version> {
        Tags.classify(texts)
    }

    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
        Tags.select(spec, of, pre)
    }

    fn compare(&self, a: &Version, b: &Version) -> Ranking {
        Tags.compare(a, b)
    }

    fn sort(&self, versions: &mut [Version]) {
        Tags.sort(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> ArtifactRequest {
        Raw.parse_req(text).expect(text)
    }

    /// A coordinate is a repository path, and the purl escapes its
    /// separators so the whole path is one name.
    #[test]
    fn coordinate_path_is_name() {
        let request = parsed("some-project/arti-name");

        assert_eq!(request.id.name(), "some-project/arti-name");
        assert_eq!(request.id.namespace(), None);
        assert_eq!(request.id.purl(), "pkg:raw/some-project%2Farti-name");
        assert_eq!(request.spec, VersionSpec::Any);
    }

    /// The directory mapping has no version, so asking for a path alone is
    /// the ordinary request rather than an incomplete one.
    #[test]
    fn coordinate_path_without_version_asks_any() {
        assert_eq!(parsed("tools/cli").spec, VersionSpec::Any);
    }

    /// Split from the right, because a path segment may contain an `@` and
    /// the last one is the version.
    #[test]
    fn coordinate_version_splits_from_right() {
        let request = parsed("tools/@scoped/cli@1.2.0");

        assert_eq!(request.id.name(), "tools/@scoped/cli");
        assert_eq!(request.spec, VersionSpec::Exact("1.2.0".to_owned()));
    }

    /// Nothing is normalized: a server that distinguishes two directories
    /// by case has two directories, and folding them would copy one and
    /// report the other missing.
    #[test]
    fn coordinate_case_not_folded() {
        assert_ne!(parsed("Tools/CLI").id, parsed("tools/cli").id);
    }

    /// Leading and trailing separators are noise, exactly as they are for
    /// the path mapping, so one file does not read as two artifacts.
    #[test]
    fn coordinate_surrounding_separators_ignored() {
        assert_eq!(parsed("/tools/cli/").id, parsed("tools/cli").id);
    }

    #[test]
    fn coordinate_empty_refused() {
        for text in ["", "   ", "/", "///"] {
            assert!(Raw.parse_req(text).is_err(), "{text:?} was accepted");
        }
    }

    /// A raw repository publishes no dependency information, so asking for
    /// a kind is an error rather than an empty answer that would read as
    /// "these files depend on nothing".
    #[test]
    fn raw_publishes_no_dependency_kinds() {
        assert!(Raw.dep_kinds().is_empty());
    }
}
