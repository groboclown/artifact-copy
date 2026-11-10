//! The node-semver convention.
//!
//! Semantic versioning as **npm** reads it, which is not how Cargo reads
//! it: hyphen ranges (`1.2.3 - 1.3.0`), `x` wildcards and prerelease
//! matching all differ, so `nodejs-semver` is used rather than dtolnay's
//! `semver`.  The latter would silently mis-resolve npm ranges.
//!
//! The commonest convention by a wide margin, which is why it is the one a
//! repository with no ecosystem of its own is most likely to configure.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md), [Semantic Versioning](https://semver.org/), [node-semver](https://github.com/npm/node-semver).

use std::cmp::Ordering;

use nodejs_semver::{Range, Version as SemVer};

use super::{PreRelease, Ranking, VersionHandler};
use crate::model::{Release, Version, VersionSpec};

/// Dist-tags are names, not ranges, and must not be parsed as versions.
const DIST_TAG_LATEST: &str = "latest";

/// Versions in the node-semver dialect.
pub struct Semver;

impl VersionHandler for Semver {
    fn version_spec(&self, text: &str) -> VersionSpec {
        classify_spec(text)
    }

    fn classify(&self, texts: &[String]) -> Vec<Version> {
        texts
            .iter()
            .map(|text| Version::new(text, release_of(text)))
            .collect()
    }

    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
        let mut candidates: Vec<&Version> = of
            .iter()
            .filter(|version| matches(spec, version, pre))
            .collect();

        candidates.sort_by(|a, b| compare(a, b));

        candidates.last().map(|version| (*version).clone())
    }

    fn compare(&self, a: &Version, b: &Version) -> Ranking {
        Ranking::of(compare(a, b))
    }

    fn sort(&self, versions: &mut [Version]) {
        versions.sort_by(compare);
    }
}

/// Semver precedence.
///
/// Unparseable versions sort below every real one rather than being
/// dropped, so a malformed packument entry cannot be selected but stays
/// visible.
fn compare(a: &Version, b: &Version) -> Ordering {
    match (parse_version(a.text()), parse_version(b.text())) {
        (Some(left), Some(right)) => left.cmp(&right),

        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a.text().cmp(b.text()),
    }
}

/// Semver is explicit: a version is a pre-release exactly when its
/// prerelease field is non-empty.  A dist-tag name such as `next` is not a
/// signal; `dist-tags.next` can point at a plain release.
fn release_of(text: &str) -> Release {
    match parse_version(text) {
        Some(version) if version.pre_release().is_empty() => Release::General,
        Some(_) => Release::PreRelease,
        None => Release::PreRelease,
    }
}

/// Whether one version satisfies a constraint.
///
/// Free rather than on the trait: `select` is the batched operation the
/// interface exposes, and this is how it is implemented.
fn matches(spec: &VersionSpec, version: &Version, pre: PreRelease) -> bool {
    let Some(parsed) = parse_version(version.text()) else {
        return false;
    };

    match spec {
        VersionSpec::Any => pre == PreRelease::Include || version.release() == Release::General,

        VersionSpec::Exact(text) => parse_version(text)
            .map(|wanted| wanted == parsed)
            .unwrap_or(false),

        VersionSpec::Range(text) => range_matches(text, &parsed, version, pre),
    }
}

fn range_matches(text: &str, parsed: &SemVer, version: &Version, pre: PreRelease) -> bool {
    // A dist-tag is a name the registry resolves, not a range.  Only
    // `latest` can be answered without the packument, and it means "the
    // newest GA release".
    if text == DIST_TAG_LATEST {
        return version.release() == Release::General;
    }

    let Ok(range) = text.parse::<Range>() else {
        return false;
    };

    // node-semver excludes prereleases from a range unless asked, or
    // unless the range itself names one at the same major.minor.patch.
    // `--pre-release` wires straight to that flag, which is why the
    // decision belongs inside the range test rather than after it.
    range.satisfies_with_prerelease(parsed, pre == PreRelease::Include)
}

fn parse_version(text: &str) -> Option<SemVer> {
    text.trim().trim_start_matches('v').parse().ok()
}

/// Decide whether a version expression is exact or a range.
fn classify_spec(spec: &str) -> VersionSpec {
    if spec.is_empty() || spec == "*" {
        return VersionSpec::Any;
    }

    // An expression that parses as a bare version is exact; everything else
    // is a range for node-semver to interpret.
    match parse_version(spec) {
        Some(_) => VersionSpec::Exact(spec.to_owned()),
        None => VersionSpec::Range(spec.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Semver orders numerically; a lexical sort would put 1.10.0 below
    /// 1.2.0 and migrate the wrong artifact.
    #[test]
    fn versions_order_numerically() {
        let a = Semver.version("1.2.0");
        let b = Semver.version("1.10.0");

        assert_eq!(compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn prerelease_sorts_below_release() {
        let pre = Semver.version("2.0.0-rc.1");
        let ga = Semver.version("2.0.0");

        assert_eq!(compare(&pre, &ga), Ordering::Less);
        assert_eq!(pre.release(), Release::PreRelease);
        assert_eq!(ga.release(), Release::General);
    }

    /// Build metadata is ignored for precedence, per semver 2.0.0.
    #[test]
    fn build_metadata_does_not_affect_ordering() {
        let plain = Semver.version("1.0.0");
        let built = Semver.version("1.0.0+build.5");

        assert_eq!(compare(&plain, &built), Ordering::Equal);
        assert_eq!(built.release(), Release::General);
    }

    #[test]
    fn range_matches_within_bounds() {
        let spec = VersionSpec::Range("^4.17.0".into());

        assert!(matches(
            &spec,
            &Semver.version("4.17.21"),
            PreRelease::Exclude
        ));
        assert!(matches(
            &spec,
            &Semver.version("4.18.0"),
            PreRelease::Exclude
        ));
        assert!(!matches(
            &spec,
            &Semver.version("5.0.0"),
            PreRelease::Exclude
        ));
        assert!(!matches(
            &spec,
            &Semver.version("4.16.0"),
            PreRelease::Exclude
        ));
    }

    /// node-semver's dialect, which Cargo's `semver` does not implement.
    #[test]
    fn range_node_dialect_honored() {
        for (range, version) in [
            ("1.x", "1.5.2"),
            ("1.2.3 - 1.3.0", "1.2.9"),
            (">=4 <5", "4.9.9"),
            ("~1.2.3", "1.2.9"),
        ] {
            let spec = VersionSpec::Range(range.into());

            assert!(
                matches(&spec, &Semver.version(version), PreRelease::Exclude),
                "{range} should match {version}"
            );
        }
    }

    /// A range excludes prereleases unless they are asked for.
    #[test]
    fn select_prerelease_only_when_asked() {
        let spec = VersionSpec::Range("^2.0.0".into());
        let candidate = Semver.version("2.1.0-beta.1");

        assert!(!matches(&spec, &candidate, PreRelease::Exclude));
        assert!(matches(&spec, &candidate, PreRelease::Include));
    }

    #[test]
    fn select_any_excludes_prereleases_by_default() {
        assert!(!matches(
            &VersionSpec::Any,
            &Semver.version("2.0.0-rc.1"),
            PreRelease::Exclude
        ));
        assert!(matches(
            &VersionSpec::Any,
            &Semver.version("2.0.0"),
            PreRelease::Exclude
        ));
        assert!(matches(
            &VersionSpec::Any,
            &Semver.version("2.0.0-rc.1"),
            PreRelease::Include
        ));
    }

    /// `latest` is a dist-tag, not a range; parsing it as one would match
    /// nothing at all.
    #[test]
    fn select_latest_tag_newest_general_release() {
        let spec = VersionSpec::Range("latest".into());

        assert!(matches(
            &spec,
            &Semver.version("3.0.0"),
            PreRelease::Exclude
        ));
        assert!(!matches(
            &spec,
            &Semver.version("3.0.0-rc.1"),
            PreRelease::Exclude
        ));
    }

    #[test]
    fn unparseable_version_never_matches() {
        assert!(!matches(
            &VersionSpec::Any,
            &Semver.version("not-a-version"),
            PreRelease::Include
        ));
    }
}
