//! Maven's version convention.
//!
//! Two halves, and neither is shared with anything else: `ComparableVersion`
//! ordering -- which pads, tokenizes and applies a qualifier table nothing
//! else does -- and the bracketed range syntax `[1.0,2.0)`.
//!
//! Kept apart from the Maven *ecosystem* because a repository laid out with
//! Maven-style versions need not be a Maven registry: a raw repository
//! whose paths carry them wants this and none of the coordinate syntax.
//!
//! References: [ComparableVersion](https://maven.apache.org/ref/current/maven-artifact/apidocs/org/apache/maven/artifact/versioning/ComparableVersion.html).

mod parsed;
mod range;

pub use parsed::Parsed;

use self::range::Range;
use super::{PreRelease, Ranking, VersionHandler};
use crate::model::{Version, VersionSpec};

/// Versions ordered the way Maven orders them.
pub struct MavenVersions;

impl VersionHandler for MavenVersions {
    fn version_spec(&self, text: &str) -> VersionSpec {
        version_spec(text)
    }

    fn classify(&self, texts: &[String]) -> Vec<Version> {
        texts
            .iter()
            .map(|text| Version::new(text, parsed::release_of(text)))
            .collect()
    }

    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
        // Parsed once, then consulted per candidate: a malformed range is
        // the user's mistake and should not be re-diagnosed 800 times.
        let range = match spec {
            VersionSpec::Any => None,
            VersionSpec::Exact(text) | VersionSpec::Range(text) => Some(Range::parse(text).ok()?),
        };

        let mut best: Option<(Parsed, &Version)> = None;

        for candidate in of {
            if pre == PreRelease::Exclude && candidate.is_pre_release() {
                continue;
            }

            if let Some(range) = &range
                && !range.contains(candidate.text())
            {
                continue;
            }

            let parsed = Parsed::new(candidate.text());

            // A linear scan rather than a sort: `select` is called once per
            // artifact across a whole artifact enumeration, and sorting to
            // take the last element would be the expensive way to find a
            // maximum.
            if best.as_ref().is_none_or(|(top, _)| parsed > *top) {
                best = Some((parsed, candidate));
            }
        }

        best.map(|(_, version)| version.clone())
    }

    fn compare(&self, a: &Version, b: &Version) -> Ranking {
        // The same `Parsed` ordering `sort` decorates with, so the two can
        // never disagree about which of two versions is newer.
        Ranking::of(Parsed::new(a.text()).cmp(&Parsed::new(b.text())))
    }

    fn sort(&self, versions: &mut [Version]) {
        // Decorate, sort, undecorate: parsing is the expensive half, and a
        // bare comparator would re-parse every string O(log n) times.
        let mut decorated: Vec<(Parsed, Version)> = versions
            .iter()
            .map(|version| (Parsed::new(version.text()), version.clone()))
            .collect();

        decorated.sort_by(|(left, _), (right, _)| left.cmp(right));

        for (slot, (_, version)) in versions.iter_mut().zip(decorated) {
            *slot = version;
        }
    }
}

/// A bracketed specification is a range; anything else names a version.
///
/// The distinction is kept because the two are reported differently, even
/// though [`Range`] resolves a bare version to itself either way.
fn version_spec(text: &str) -> VersionSpec {
    match text.starts_with('[') || text.starts_with('(') {
        true => VersionSpec::Range(text.to_owned()),
        false => VersionSpec::Exact(text.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Release;

    fn versions(texts: &[&str]) -> Vec<Version> {
        let owned: Vec<String> = texts.iter().map(|text| (*text).to_owned()).collect();

        MavenVersions.classify(&owned)
    }

    #[test]
    fn qualifier_five_pre_release_recognized() {
        let tagged = versions(&["1.0-alpha-1", "1.0-SNAPSHOT", "1.0-rc1", "1.0"]);

        assert_eq!(tagged[0].release(), Release::PreRelease);
        assert_eq!(tagged[1].release(), Release::PreRelease);
        assert_eq!(tagged[2].release(), Release::PreRelease);
        assert_eq!(tagged[3].release(), Release::General);
    }

    /// The asymmetry that matters most: Guava's only releases are
    /// qualified, so treating a qualifier as a pre-release would make this
    /// tool refuse to migrate Guava at all.
    #[test]
    fn qualifier_unknown_not_pre_release() {
        let tagged = versions(&["31.1-jre", "31.1-android"]);

        assert_eq!(tagged[0].release(), Release::General);
        assert_eq!(tagged[1].release(), Release::General);
    }

    // -- Selection --------------------------------------------------------

    #[test]
    fn select_highest_in_range() {
        let best = MavenVersions
            .select(
                &VersionSpec::Range("[1.0,2.0)".into()),
                &versions(&["0.9", "1.0", "1.10", "1.9", "2.0"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        // 1.10 beats 1.9: MavenVersions's numeric ordering, not lexical.
        assert_eq!(best.text(), "1.10");
    }

    #[test]
    fn select_unconstrained_takes_newest() {
        let best = MavenVersions
            .select(
                &VersionSpec::Any,
                &versions(&["1.0", "2.0", "1.5"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        assert_eq!(best.text(), "2.0");
    }

    #[test]
    fn select_excludes_pre_releases_by_default() {
        let candidates = versions(&["1.0", "2.0-SNAPSHOT"]);

        assert_eq!(
            MavenVersions
                .select(&VersionSpec::Any, &candidates, PreRelease::Exclude)
                .expect("matched")
                .text(),
            "1.0"
        );

        assert_eq!(
            MavenVersions
                .select(&VersionSpec::Any, &candidates, PreRelease::Include)
                .expect("matched")
                .text(),
            "2.0-SNAPSHOT"
        );
    }

    /// An exact version matches by MavenVersions's equality, not by string: a
    /// registry listing `1.0.0` satisfies a request for `1.0`, because in
    /// MavenVersions they are the same version.
    #[test]
    fn select_exact_spec_matches_equal_spelling() {
        let best = MavenVersions
            .select(
                &VersionSpec::Exact("1.0".into()),
                &versions(&["0.9", "1.0.0", "1.1"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        assert_eq!(best.text(), "1.0.0");
    }

    #[test]
    fn select_none_when_nothing_satisfies() {
        assert!(
            MavenVersions
                .select(
                    &VersionSpec::Range("[9.0,)".into()),
                    &versions(&["1.0"]),
                    PreRelease::Exclude
                )
                .is_none()
        );
    }

    /// A malformed range selects nothing rather than everything. Falling
    /// back to "any version" would migrate an arbitrary artifact off a
    /// typo.
    #[test]
    fn select_malformed_range_matches_nothing() {
        assert!(
            MavenVersions
                .select(
                    &VersionSpec::Range("[2.0,1.0]".into()),
                    &versions(&["1.0", "1.5"]),
                    PreRelease::Exclude
                )
                .is_none()
        );
    }

    #[test]
    fn select_empty_list_none() {
        assert!(
            MavenVersions
                .select(&VersionSpec::Any, &[], PreRelease::Exclude)
                .is_none()
        );
    }

    // -- Sorting ----------------------------------------------------------

    #[test]
    fn sort_uses_maven_order_not_generic() {
        let mut list = versions(&["1.0.1", "1.0-1", "1.0", "1.0-SNAPSHOT", "1.0-sp", "1.10"]);

        MavenVersions.sort(&mut list);

        let order: Vec<&str> = list.iter().map(|version| version.text()).collect();

        // `1.0 < 1.0-1 < 1.0.1` is the chain that catches a generic
        // comparator: semver has no `-1` build above the release at all,
        // and a lexical sort puts `1.0.1` below `1.0-1`.
        assert_eq!(
            order,
            ["1.0-SNAPSHOT", "1.0", "1.0-sp", "1.0-1", "1.0.1", "1.10"]
        );
    }

    #[test]
    fn sort_preserves_release_tag() {
        let mut list = versions(&["1.0", "1.0-SNAPSHOT"]);

        MavenVersions.sort(&mut list);

        assert!(list[0].is_pre_release());
        assert!(!list[1].is_pre_release());
    }

    // -- Description ------------------------------------------------------
}
