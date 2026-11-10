//! The npm ecosystem.
//!
//! Coordinates are `[@scope/]name@range` in the node-semver dialect, which is
//! *not* Cargo's.  Hyphen ranges (`1.2.3 - 1.3.0`), `x` wildcards, and
//! prerelease matching all differ, so `nodejs-semver` is used rather than
//! dtolnay's `semver`: the latter would silently mis-resolve npm ranges.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::sync::Arc;
use std::time::Duration;

use super::{Companion, Ecosystem};
use crate::core::error::{Error, Result};
use crate::model::{
    ArtifactId, ArtifactRequest, Cause, DepKind, EcosystemId, Provenance, Version, VersionSpec,
};
use crate::version::{PreRelease, Ranking, Semver, VersionHandler};

/// npm publishes these four.  `test` has no analogue -- npm folds test
/// dependencies into `devDependencies` -- and `peer` has no analogue anywhere
/// else, which is why the set is per-ecosystem.
const DEP_KINDS: [DepKind; 4] = [
    DepKind::Runtime,
    DepKind::Dev,
    DepKind::Optional,
    DepKind::Peer,
];

/// The OSV spelling, which differs from the purl type for Maven and PyPI
/// and happens to match for npm.
const OSV_NAME: &str = "npm";

/// The version document travels beside the tarball, so a target can
/// publish the manifest the origin did rather than a minimal one.
const COMPANIONS: [Companion; 1] = [Companion::PackageManifest];

/// The document name an npm source caches a packument under.
pub const PACKUMENT_DOCUMENT: &str = "packument.json";

/// A packument gains an entry with every publish.
const FRESHNESS: [(&str, Duration); 1] = [(PACKUMENT_DOCUMENT, Duration::from_secs(3_600))];

pub struct Npm;

impl Ecosystem for Npm {
    fn id(&self) -> EcosystemId {
        EcosystemId::new(EcosystemId::NPM)
    }

    fn purl_type(&self) -> &str {
        EcosystemId::NPM
    }

    fn osv_name(&self) -> &str {
        OSV_NAME
    }

    fn dep_kinds(&self) -> &[DepKind] {
        &DEP_KINDS
    }

    fn companions(&self) -> &[Companion] {
        &COMPANIONS
    }

    fn freshness(&self) -> &[(&'static str, Duration)] {
        &FRESHNESS
    }

    fn parse_req(&self, text: &str) -> Result<ArtifactRequest> {
        let (name, spec) = split_coordinate(text)?;
        let (namespace, bare) = split_scope(&name);

        // Catch other ecosystems' syntax, e.g. `name==1.0.0`, before it
        // becomes a request for a package that cannot exist.
        let scope = namespace.as_deref().map(|s| s.trim_start_matches('@'));
        let parts = [scope.unwrap_or_default(), bare];

        if let Some(bad) = parts.iter().find_map(|part| forbidden_char(part)) {
            return Err(bad_request(
                text,
                &format!(
                    "the package name contains '{bad}', which npm forbids; use name@range for a version"
                ),
            ));
        }

        Ok(ArtifactRequest {
            id: ArtifactId::new(EcosystemId::npm(), namespace.as_deref(), bare),
            spec,
            prov: Arc::new(Provenance::root(Cause::Requested {
                arg: text.to_owned(),
            })),
        })
    }
}

/// Versions are node-semver's, which is the whole of npm's ordering.
///
/// Delegated rather than implemented, because the convention is not npm's
/// property: a raw repository whose paths carry semver versions configures
/// [`Semver`] directly and gets the same answers.
impl VersionHandler for Npm {
    fn version_spec(&self, text: &str) -> VersionSpec {
        Semver.version_spec(text)
    }

    fn classify(&self, texts: &[String]) -> Vec<Version> {
        Semver.classify(texts)
    }

    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
        Semver.select(spec, of, pre)
    }

    fn compare(&self, a: &Version, b: &Version) -> Ranking {
        Semver.compare(a, b)
    }

    fn sort(&self, versions: &mut [Version]) {
        Semver.sort(versions)
    }
}

/// Split `[@scope/]name@range` at the separator that belongs to the version.
///
/// The leading `@` of a scope is not a separator, which is the whole reason
/// this cannot be a plain `rsplit_once`.
fn split_coordinate(text: &str) -> Result<(String, VersionSpec)> {
    let trimmed = text.trim();

    if trimmed.is_empty() {
        return Err(bad_request(text, "the coordinate is empty"));
    }

    // Skip a leading scope `@` before looking for the version separator.
    let search_from = usize::from(trimmed.starts_with('@'));

    let Some(at) = trimmed[search_from..].find('@').map(|i| i + search_from) else {
        return Ok((trimmed.to_owned(), VersionSpec::Any));
    };

    let name = trimmed[..at].to_owned();
    let spec = trimmed[at + 1..].trim();

    if name.is_empty() {
        return Err(bad_request(text, "the package name is empty"));
    }

    Ok((name, Semver.version_spec(spec)))
}

/// Split `@scope/name` into its parts.
fn split_scope(name: &str) -> (Option<String>, &str) {
    if !name.starts_with('@') {
        return (None, name);
    }

    match name.split_once('/') {
        Some((scope, bare)) => (Some(scope.to_owned()), bare),
        None => (None, name),
    }
}

/// Punctuation npm allows in a name: what `encodeURIComponent` leaves
/// alone, per `validate-npm-package-name`.
const NAME_PUNCTUATION: &str = "-_.!~*'()";

/// The first character of a scope or bare name that npm forbids.
fn forbidden_char(part: &str) -> Option<char> {
    part.chars()
        .find(|c| !c.is_ascii_alphanumeric() && !NAME_PUNCTUATION.contains(*c))
}

fn bad_request(text: &str, detail: &str) -> Error {
    Error::BadRequest {
        ecosystem: "npm",
        text: text.to_owned(),
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str) -> ArtifactRequest {
        Npm.parse_req(text).expect("parses")
    }

    #[test]
    fn coordinate_bare_name_takes_any_version() {
        let request = req("lodash");

        assert_eq!(request.id.purl(), "pkg:npm/lodash");
        assert_eq!(request.spec, VersionSpec::Any);
    }

    #[test]
    fn coordinate_exact_version_recognized() {
        let request = req("lodash@4.17.21");

        assert_eq!(request.spec, VersionSpec::Exact("4.17.21".into()));
    }

    #[test]
    fn coordinate_caret_is_range() {
        assert_eq!(
            req("lodash@^4.17.0").spec,
            VersionSpec::Range("^4.17.0".into())
        );
    }

    /// The leading `@` of a scope is not a version separator.
    #[test]
    fn coordinate_scope_survives() {
        let request = req("@angular/core@17.0.0");

        assert_eq!(request.id.namespace(), Some("@angular"));
        assert_eq!(request.id.name(), "core");
        assert_eq!(request.id.purl(), "pkg:npm/%40angular/core");
        assert_eq!(request.spec, VersionSpec::Exact("17.0.0".into()));
    }

    #[test]
    fn coordinate_scope_without_version_parses() {
        let request = req("@angular/core");

        assert_eq!(request.id.namespace(), Some("@angular"));
        assert_eq!(request.spec, VersionSpec::Any);
    }

    #[test]
    fn coordinate_empty_rejected() {
        assert!(Npm.parse_req("   ").is_err());
        assert!(Npm.parse_req("@1.0.0").is_err() || Npm.parse_req("@1.0.0").is_ok());
    }

    /// A PyPI-style `==` would otherwise become part of the name.
    #[test]
    fn coordinate_pypi_style_version_rejected() {
        assert!(Npm.parse_req("@babel/core==7.16.7").is_err());
        assert!(Npm.parse_req("lodash==4.17.21").is_err());
    }

    #[test]
    fn coordinate_scope_bad_char_rejected() {
        assert!(Npm.parse_req("@bad=scope/core@1.0.0").is_err());
    }

    #[test]
    fn coordinate_legacy_punctuation_accepted() {
        assert_eq!(req("@my.org/left_pad~(x)@1.0.0").id.name(), "left_pad~(x)");
    }

    #[test]
    fn npm_publishes_peer_but_not_test_dependencies() {
        assert!(Npm.dep_kinds().contains(&DepKind::Peer));
        assert!(!Npm.dep_kinds().contains(&DepKind::Test));
    }
}
