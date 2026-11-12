//! The PEP 440 convention.
//!
//! Python's own scheme, and it agrees with neither semver nor Maven: a
//! `.postN` release sorts **above** the release it follows, a `.devN`
//! segment counts as a pre-release as much as `a`, `b` or `rc` does, and
//! `1.0` and `1.0.0` are the same version.
//!
//! Kept apart from the PyPI *ecosystem* because the scheme travels: a
//! repository publishing PEP 440 versions without being a Python index
//! wants this and none of the PEP 508 requirement syntax.
//!
//! References: [PEP 440](https://peps.python.org/pep-0440/).

use std::str::FromStr;

use pep440_rs::{Version as Pep440, VersionSpecifiers};

use super::{PreRelease, Ranking, VersionHandler};
use crate::model::{Release, Version, VersionSpec};

/// Versions ordered by PEP 440.
pub struct Pep440Versions;

impl VersionHandler for Pep440Versions {
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

        // PEP 440's own rule: a specifier admits a pre-release when nothing
        // else satisfies it.  That is what pip does, and a user who asked
        // for `>=2.0` on a package with only `2.0rc1` expects to be told
        // about it rather than told there is nothing.
        if candidates.is_empty() && pre == PreRelease::Exclude {
            candidates = of
                .iter()
                .filter(|version| matches(spec, version, PreRelease::Include))
                .collect();
        }

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

/// PEP 440 precedence.
///
/// Unparseable versions sort below every real one rather than being dropped,
/// so a malformed index entry cannot be selected but stays visible.
fn compare(a: &Version, b: &Version) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    match (parse_version(a.text()), parse_version(b.text())) {
        (Some(left), Some(right)) => left.cmp(&right),

        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a.text().cmp(b.text()),
    }
}

/// PEP 440 counts a **dev** segment as a pre-release as much as an `a`, `b`
/// or `rc` segment does.  A `.postN` release is not one.
fn release_of(text: &str) -> Release {
    match parse_version(text) {
        Some(version) if version.any_prerelease() => Release::PreRelease,
        Some(_) => Release::General,
        None => Release::PreRelease,
    }
}

fn matches(spec: &VersionSpec, version: &Version, pre: PreRelease) -> bool {
    let Some(parsed) = parse_version(version.text()) else {
        return false;
    };

    if parsed.any_prerelease() && pre == PreRelease::Exclude {
        return false;
    }

    match spec {
        VersionSpec::Any => true,

        VersionSpec::Exact(text) => parse_version(text)
            .map(|wanted| wanted == parsed)
            .unwrap_or(false),

        VersionSpec::Range(text) => VersionSpecifiers::from_str(text)
            .map(|specifiers| specifiers.contains(&parsed))
            .unwrap_or(false),
    }
}

fn parse_version(text: &str) -> Option<Pep440> {
    Pep440::from_str(text.trim()).ok()
}

fn classify_spec(spec: &str) -> VersionSpec {
    if spec.is_empty() {
        return VersionSpec::Any;
    }

    // `==1.2.3` pins one version; anything else -- including `==1.2.*` -- is a
    // range for the specifier parser to interpret.
    if let Some(exact) = spec.strip_prefix("==")
        && !exact.contains('*')
        && !exact.contains(',')
        && parse_version(exact).is_some()
    {
        return VersionSpec::Exact(exact.trim().to_owned());
    }

    // A bare version is what an `Exact` holds once `==` is stripped, and
    // `repo::resolve::respecified` reads it back through here. PEP 440 has
    // no bare-version specifier, so read as a range it would match nothing.
    if parse_version(spec).is_some() {
        return VersionSpec::Exact(spec.trim().to_owned());
    }

    VersionSpec::Range(spec.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(texts: &[&str]) -> Vec<Version> {
        let owned: Vec<String> = texts.iter().map(|t| (*t).to_owned()).collect();

        Pep440Versions.classify(&owned)
    }

    #[test]
    fn versions_order_numerically() {
        let mut list = versions(&["1.9", "1.10", "1.2"]);
        Pep440Versions.sort(&mut list);

        let order: Vec<&str> = list.iter().map(|v| v.text()).collect();
        assert_eq!(order, ["1.2", "1.9", "1.10"]);
    }

    /// The trap PEP 440 sets for anyone assuming semver: a dev release is a
    /// pre-release, and a post release is not.
    #[test]
    fn pre_release_includes_dev_not_post() {
        let tagged = versions(&["1.0", "1.0a1", "1.0b2", "1.0rc1", "1.0.dev1", "1.0.post1"]);

        let by_text = |text: &str| {
            tagged
                .iter()
                .find(|v| v.text() == text)
                .unwrap_or_else(|| panic!("{text} missing"))
                .release()
        };

        assert_eq!(by_text("1.0"), Release::General);
        assert_eq!(by_text("1.0a1"), Release::PreRelease);
        assert_eq!(by_text("1.0b2"), Release::PreRelease);
        assert_eq!(by_text("1.0rc1"), Release::PreRelease);
        assert_eq!(by_text("1.0.dev1"), Release::PreRelease);

        // A post release is a release.
        assert_eq!(by_text("1.0.post1"), Release::General);
    }

    /// A pin loses its `==` on the first read and is read again by
    /// resolution, so the bare version must still be exact.
    #[test]
    fn version_spec_exact_reads_back() {
        let pinned = Pep440Versions.version_spec("==26.2.2");
        assert_eq!(pinned, VersionSpec::Exact("26.2.2".into()));

        assert_eq!(
            Pep440Versions.version_spec("26.2.2"),
            VersionSpec::Exact("26.2.2".into())
        );

        // Still ranges: a wildcard, and anything with an operator.
        assert_eq!(
            Pep440Versions.version_spec("==1.2.*"),
            VersionSpec::Range("==1.2.*".into())
        );
        assert_eq!(
            Pep440Versions.version_spec(">=1.0"),
            VersionSpec::Range(">=1.0".into())
        );
    }

    #[test]
    fn select_range_takes_highest() {
        let best = Pep440Versions
            .select(
                &VersionSpec::Range(">=2.0,<3".into()),
                &versions(&["1.9", "2.0", "2.10", "2.2", "3.0"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        assert_eq!(best.text(), "2.10");
    }

    #[test]
    fn select_excludes_pre_releases_by_default() {
        let best = Pep440Versions
            .select(
                &VersionSpec::Range(">=2.0".into()),
                &versions(&["2.0", "2.1rc1"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        assert_eq!(best.text(), "2.0");
    }

    /// PEP 440's own rule, and what pip does: when *nothing* else satisfies
    /// the specifier, a pre-release is offered rather than reporting that
    /// there is no such version.
    #[test]
    fn select_pre_release_when_nothing_else_satisfies() {
        let best = Pep440Versions
            .select(
                &VersionSpec::Range(">=1.0".into()),
                &versions(&["0.9", "2.0rc1"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        assert_eq!(best.text(), "2.0rc1");
    }

    /// The fallback admits a pre-release that the specifier *ordered* into
    /// range and the filter removed.  It does not reach one the specifier
    /// excludes on ordering: `2.0rc1` precedes `2.0` in PEP 440, so `>=2.0`
    /// never matches it, with or without the flag.
    #[test]
    fn select_fallback_keeps_ordering() {
        assert!(
            Pep440Versions
                .select(
                    &VersionSpec::Range(">=2.0".into()),
                    &versions(&["2.0rc1"]),
                    PreRelease::Exclude,
                )
                .is_none()
        );

        assert!(
            Pep440Versions
                .select(
                    &VersionSpec::Range(">=2.0".into()),
                    &versions(&["2.0rc1"]),
                    PreRelease::Include,
                )
                .is_none()
        );
    }

    #[test]
    fn select_compatible_release_honored() {
        let best = Pep440Versions
            .select(
                &VersionSpec::Range("~=2.31.0".into()),
                &versions(&["2.31.0", "2.31.4", "2.32.0"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        // `~=2.31.0` permits 2.31.x but not 2.32.
        assert_eq!(best.text(), "2.31.4");
    }
}
