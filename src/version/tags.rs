//! Tags, which are text and nothing more.
//!
//! The handler for a repository that publishes named releases with no
//! version scheme at all -- a git tag may be `v2.1.0`, `nightly`,
//! `2024-06-01` or `final-FINAL-2`, and nothing may assume which.
//!
//! # Refusing is the feature
//!
//! `sort` leaves the order it was given and `select` refuses a range.  That
//! looks like a gap and is the opposite: **an ordering that is wrong is
//! worse than none**, because callers act on it.  A comparator invented to
//! make `^1.0` work against tag text would pick a release that looks
//! plausible and is not the one asked for, and `v10` would sort below `v9`.
//!
//! A repository that *does* follow a scheme says so by configuring that
//! scheme's handler instead. This one is the honest default, not a
//! limitation to work around.

use super::{PreRelease, Ranking, VersionHandler};
use crate::model::{Release, Version, VersionSpec};

/// Versions that are only names.
pub struct Tags;

impl VersionHandler for Tags {
    /// A tag is always exact: GitHub tags have no ordering to range
    /// over, which is why `select` refuses a range outright.
    fn version_spec(&self, text: &str) -> VersionSpec {
        match text.is_empty() {
            true => VersionSpec::Any,
            false => VersionSpec::Exact(text.to_owned()),
        }
    }

    /// Tag text alone cannot say whether a release is a pre-release -- the
    /// API flag can, and `repo::GitHubSource` uses it.
    ///
    /// Everything reaching this path is therefore assumed general, which is
    /// the conservative direction: a pre-release wrongly marked general
    /// would be *offered* rather than hidden, and the source overrides it
    /// with the real flag before anything is selected.
    fn classify(&self, texts: &[String]) -> Vec<Version> {
        texts
            .iter()
            .map(|text| Version::new(text, Release::General))
            .collect()
    }

    /// Exact tags only.
    ///
    /// `VersionSpec::Any` takes the first, which is meaningful only because
    /// the source supplies releases newest-first; a range matches nothing,
    /// because there is no scheme to match it against.
    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
        let admissible =
            |version: &&Version| pre == PreRelease::Include || !version.is_pre_release();

        match spec {
            VersionSpec::Any => of.iter().find(admissible).cloned(),

            // Tags are compared as text, because that is all they are.
            VersionSpec::Exact(tag) => of
                .iter()
                .find(|version| version.text() == tag && admissible(version))
                .cloned(),

            // Refused rather than approximated. A comparator invented to
            // make `^1.0` work against tag strings would pick a release
            // that looks plausible and is not the one asked for.
            VersionSpec::Range(_) => None,
        }
    }

    /// Always [`Ranking::Indeterminate`]: tags have no order.
    ///
    /// The whole reason `Ranking` has a fourth value. `nightly` and `v2.1`
    /// are both tags and neither precedes the other, so a caller asking
    /// whether a tag falls inside an advisory's affected range gets "cannot
    /// tell" rather than a plausible answer. Returning `Same` would read as
    /// a tie and returning `Before` would read as "not affected" - both are
    /// a security question answered by invention.
    fn compare(&self, _a: &Version, _b: &Version) -> Ranking {
        Ranking::Indeterminate
    }

    /// Leaves the order it was given, which is GitHub's: newest first.
    ///
    /// Sorting tag text would put `v10` below `v9` and `nightly` somewhere
    /// arbitrary. An ordering that is wrong is worse than none, because
    /// callers act on it.
    fn sort(&self, _versions: &mut [Version]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(tags: &[(&str, Release)]) -> Vec<Version> {
        tags.iter()
            .map(|(tag, release)| Version::new(*tag, *release))
            .collect()
    }

    // -- Selection --------------------------------------------------------

    /// Ranges are refused rather than approximated. A comparator invented
    /// to make `^1.0` work against tag strings would pick a release that
    /// looks plausible and is not the one asked for.
    #[test]
    fn range_matches_nothing() {
        let releases = versions(&[("v2.0.0", Release::General), ("v1.0.0", Release::General)]);

        assert!(
            Tags.select(
                &VersionSpec::Range("^1.0".into()),
                &releases,
                PreRelease::Exclude
            )
            .is_none()
        );
    }

    #[test]
    fn tag_exact_selects_release() {
        let releases = versions(&[("v2.0.0", Release::General), ("v1.0.0", Release::General)]);

        let chosen = Tags
            .select(
                &VersionSpec::Exact("v1.0.0".into()),
                &releases,
                PreRelease::Exclude,
            )
            .expect("matched");

        assert_eq!(chosen.text(), "v1.0.0");
    }

    #[test]
    fn tag_missing_selects_nothing() {
        let releases = versions(&[("v1.0.0", Release::General)]);

        assert!(
            Tags.select(
                &VersionSpec::Exact("v9.9.9".into()),
                &releases,
                PreRelease::Exclude
            )
            .is_none()
        );
    }

    /// Meaningful only because the source supplies releases newest-first.
    #[test]
    fn version_absent_takes_first_offered() {
        let releases = versions(&[("v2.0.0", Release::General), ("v1.0.0", Release::General)]);

        assert_eq!(
            Tags.select(&VersionSpec::Any, &releases, PreRelease::Exclude)
                .expect("matched")
                .text(),
            "v2.0.0"
        );
    }

    /// The only-GA requirement, which for Tags means the `prerelease`
    /// flag the API reports.
    #[test]
    fn pre_release_skipped_unless_asked() {
        let releases = versions(&[
            ("v2.0.0-rc1", Release::PreRelease),
            ("v1.0.0", Release::General),
        ]);

        assert_eq!(
            Tags.select(&VersionSpec::Any, &releases, PreRelease::Exclude)
                .expect("matched")
                .text(),
            "v1.0.0"
        );

        assert_eq!(
            Tags.select(&VersionSpec::Any, &releases, PreRelease::Include)
                .expect("matched")
                .text(),
            "v2.0.0-rc1"
        );
    }

    /// Asking for a pre-release by tag still respects the flag, so
    /// `--pre-release` means the same thing however the request was spelled.
    #[test]
    fn pre_release_exact_tag_obeys_flag() {
        let releases = versions(&[("v2.0.0-rc1", Release::PreRelease)]);
        let spec = VersionSpec::Exact("v2.0.0-rc1".into());

        assert!(Tags.select(&spec, &releases, PreRelease::Exclude).is_none());
        assert!(Tags.select(&spec, &releases, PreRelease::Include).is_some());
    }

    // -- Ordering ---------------------------------------------------------

    /// An ordering that is wrong is worse than none, because callers act on
    /// it. `v10` above `v9` is the vector a text sort gets backwards.
    #[test]
    fn sort_keeps_github_order() {
        let mut releases = versions(&[
            ("v10.0.0", Release::General),
            ("v9.0.0", Release::General),
            ("nightly", Release::General),
        ]);

        Tags.sort(&mut releases);

        let order: Vec<&str> = releases.iter().map(Version::text).collect();

        assert_eq!(order, ["v10.0.0", "v9.0.0", "nightly"]);
    }
}
