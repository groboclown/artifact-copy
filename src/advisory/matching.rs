//! Deciding whether one version falls inside an advisory's affected set.
//!
//! The part of screening that can be subtly, silently wrong, so it is its
//! own module with its own tests.
//!
//! # Three answers, not two
//!
//! A version is [`Affected`], [`Unaffected`](Match::Unaffected), or
//! [`Unknown`](Match::Unknown) - and the third is the one that matters.
//! Some conventions have no ordering at all (raw repository tags), some
//! ranges are expressed in commit hashes rather than versions, and a
//! version handler can decline to place a string it cannot parse. In every
//! one of those cases the honest answer is *this was not screened*, and a
//! caller that reads it as "unaffected" has turned an unanswered security
//! question into a clean report.
//!
//! This is the same rule `unknown-publish-time` follows, for the same
//! reason: an artifact that cannot be *shown* to be acceptable is not the
//! same as one shown to be acceptable.
//!
//! # The comparator is never substituted
//!
//! Every ordering question goes to the artifact's own
//! [`VersionHandler`]. Maven's `1.0-rc1` sorts *below* `1.0`, so it is
//! inside `[1.0-alpha, 1.0)` and outside `[1.0, 2.0)`; semver agrees here
//! and PEP 440 does not always. A generic comparator substituted for the
//! ecosystem's own is the failure this module exists to prevent, and the
//! tests pin the cases where the conventions disagree.

use crate::model::Version;
use crate::version::{Ranking, VersionHandler};

use super::osv::{self, Affected, Span};

/// Whether an artifact is affected by an advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Affected,
    Unaffected,

    /// The question could not be answered.
    ///
    /// **Not a synonym for unaffected.** See the module documentation: a
    /// caller must report this rather than pass the artifact.
    Unknown,
}

impl Match {
    /// Fold several answers into one, worst-first.
    ///
    /// `Affected` wins over `Unknown` wins over `Unaffected`: an advisory
    /// with one span that matches is a hit whatever the other spans did,
    /// and one span nobody could evaluate makes the whole answer doubtful
    /// even when the rest came back clean.
    pub fn worst(self, other: Match) -> Match {
        match (self, other) {
            (Match::Affected, _) | (_, Match::Affected) => Match::Affected,
            (Match::Unknown, _) | (_, Match::Unknown) => Match::Unknown,
            _ => Match::Unaffected,
        }
    }
}

/// Whether `version` falls in what this `affected` entry describes.
///
/// The enumeration is consulted first and answers on its own when it hits:
/// it is string equality against versions the publisher listed, so it
/// cannot be wrong about an ecosystem's ordering because it never asks.
pub fn affected(entry: &Affected, version: &Version, handler: &dyn VersionHandler) -> Match {
    if entry.versions.iter().any(|listed| listed == version.text()) {
        return Match::Affected;
    }

    let ranges: Vec<&osv::Range> = entry
        .ranges
        .iter()
        .filter(|range| range.is_versioned())
        .collect();

    // Nothing left to ask. A record that listed versions and hit none of
    // them is a genuine miss; one whose only ranges were `GIT` was never
    // screened at all, and saying so is what keeps a commit-range advisory
    // from reading as clean.
    if ranges.is_empty() {
        return match entry.versions.is_empty() && !entry.ranges.is_empty() {
            true => Match::Unknown,
            false => Match::Unaffected,
        };
    }

    ranges
        .iter()
        .flat_map(|range| range.spans())
        .map(|span| within(&span, version, handler))
        .fold(Match::Unaffected, Match::worst)
}

/// Whether `version` falls inside one span.
fn within(span: &Span, version: &Version, handler: &dyn VersionHandler) -> Match {
    // `"0"` is OSV's "from the beginning" sentinel rather than a version,
    // so it is recognised by name instead of being handed to a comparator
    // that would have to place it.
    let at_or_after = match span.from == osv::ZERO {
        true => true,
        false => {
            let from = handler.version(&span.from);

            match handler.compare(version, &from).at_or_after() {
                Some(answer) => answer,
                None => return Match::Unknown,
            }
        }
    };

    if !at_or_after {
        return Match::Unaffected;
    }

    let Some(until) = &span.until else {
        // Open-ended: everything at or after the introduction is affected,
        // which is an unpatched advisory.
        return Match::Affected;
    };

    let until = handler.version(until);
    let ranking = handler.compare(version, &until);

    let before_end = match span.inclusive {
        // `last_affected`: the boundary is itself affected.
        true => match ranking {
            Ranking::Before | Ranking::Same => true,
            Ranking::After => false,
            Ranking::Indeterminate => return Match::Unknown,
        },

        // `fixed`: the boundary is the first version that is not.
        false => match ranking.before() {
            Some(answer) => answer,
            None => return Match::Unknown,
        },
    };

    match before_end {
        true => Match::Affected,
        false => Match::Unaffected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{MavenVersions, Semver, Tags};

    fn entry(json: &str) -> Affected {
        serde_json::from_str(json).expect("parses")
    }

    fn at(handler: &dyn VersionHandler, text: &str) -> Version {
        handler.version(text)
    }

    fn ranged(kind: &str, events: &str) -> Affected {
        entry(&format!(
            r#"{{"package":{{"ecosystem":"npm","name":"tuna"}},
                "ranges":[{{"type":"{kind}","events":{events}}}]}}"#
        ))
    }

    // -- The enumeration --------------------------------------------------

    #[test]
    fn version_listed_affected() {
        let listed = entry(
            r#"{"package":{"ecosystem":"npm","name":"tuna"},
                "versions":["1.0.0","1.0.1"]}"#,
        );

        assert_eq!(
            affected(&listed, &at(&Semver, "1.0.1"), &Semver),
            Match::Affected
        );
        assert_eq!(
            affected(&listed, &at(&Semver, "1.2.0"), &Semver),
            Match::Unaffected
        );
    }

    // -- Ranges -----------------------------------------------------------

    #[test]
    fn version_inside_fixed_range_affected() {
        let range = ranged("SEMVER", r#"[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]"#);

        assert_eq!(
            affected(&range, &at(&Semver, "1.0.5"), &Semver),
            Match::Affected
        );
    }

    /// `fixed` is exclusive: the version that fixed it is not affected.
    #[test]
    fn version_fixed_not_affected() {
        let range = ranged("SEMVER", r#"[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]"#);

        assert_eq!(
            affected(&range, &at(&Semver, "1.1.0"), &Semver),
            Match::Unaffected
        );
    }

    /// `last_affected` is inclusive, where `fixed` is not.
    #[test]
    fn version_last_affected_included() {
        let range = ranged(
            "SEMVER",
            r#"[{"introduced":"1.0.0"},{"last_affected":"1.1.0"}]"#,
        );

        assert_eq!(
            affected(&range, &at(&Semver, "1.1.0"), &Semver),
            Match::Affected
        );
    }

    #[test]
    fn version_below_introduction_not_affected() {
        let range = ranged("SEMVER", r#"[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]"#);

        assert_eq!(
            affected(&range, &at(&Semver, "0.9.0"), &Semver),
            Match::Unaffected
        );
    }

    #[test]
    fn range_unpatched_affects_all_after() {
        let range = ranged("SEMVER", r#"[{"introduced":"1.0.0"}]"#);

        assert_eq!(
            affected(&range, &at(&Semver, "9.9.9"), &Semver),
            Match::Affected
        );
    }

    /// OSV's zero is a sentinel, not a version, and is never handed to a
    /// comparator.
    #[test]
    fn range_from_zero_affects_all_below_fix() {
        let range = ranged("ECOSYSTEM", r#"[{"introduced":"0"},{"fixed":"1.0.0"}]"#);

        assert_eq!(
            affected(&range, &at(&Semver, "0.0.1"), &Semver),
            Match::Affected
        );
    }

    // -- The comparator is the ecosystem's own ----------------------------

    /// The case `docs/contributors/advisories.md` names: Maven places
    /// `1.0-rc1` *below* `1.0`, so a
    /// release candidate is outside `[1.0, 2.0)`. A comparator that read it
    /// as `1.0` plus something would put it inside and condemn a release
    /// the advisory never named.
    #[test]
    fn maven_places_a_release_candidate_below_its_release() {
        let range = ranged("ECOSYSTEM", r#"[{"introduced":"1.0"},{"fixed":"2.0"}]"#);

        assert_eq!(
            affected(&range, &at(&MavenVersions, "1.0-rc1"), &MavenVersions),
            Match::Unaffected,
            "1.0-rc1 sorts below 1.0 in Maven's own order"
        );

        // And the release itself is inside it, so the range is not simply
        // matching nothing.
        assert_eq!(
            affected(&range, &at(&MavenVersions, "1.0"), &MavenVersions),
            Match::Affected
        );
    }

    /// Maven's `1.0-sp` is *above* `1.0`, which a generic comparator reading
    /// a suffix as a pre-release would get backwards.
    #[test]
    fn maven_places_a_service_pack_above_its_release() {
        let range = ranged("ECOSYSTEM", r#"[{"introduced":"1.0"},{"fixed":"1.0-sp"}]"#);

        assert_eq!(
            affected(&range, &at(&MavenVersions, "1.0"), &MavenVersions),
            Match::Affected
        );
        assert_eq!(
            affected(&range, &at(&MavenVersions, "1.0-sp"), &MavenVersions),
            Match::Unaffected,
            "the service pack is the fix, and `fixed` is exclusive"
        );
    }

    // -- What cannot be answered ------------------------------------------

    /// The reason `Match` has three values. Tags have no order, so no range
    /// can be evaluated against one - and the answer must not be "clean".
    #[test]
    fn convention_without_an_order_answers_unknown() {
        let range = ranged("ECOSYSTEM", r#"[{"introduced":"1.0"},{"fixed":"2.0"}]"#);

        assert_eq!(
            affected(&range, &at(&Tags, "nightly"), &Tags),
            Match::Unknown
        );
    }

    /// A commit range names hashes, which no version handler can place.
    #[test]
    fn range_git_alone_answers_unknown() {
        let range = ranged("GIT", r#"[{"introduced":"0"},{"fixed":"abc123"}]"#);

        assert_eq!(
            affected(&range, &at(&Semver, "1.0.0"), &Semver),
            Match::Unknown
        );
    }

    /// A record that enumerated versions and also carried a `GIT` range has
    /// already answered: the enumeration is authoritative for what it lists.
    #[test]
    fn range_git_beside_enumeration_still_answers() {
        let mixed = entry(
            r#"{"package":{"ecosystem":"npm","name":"tuna"},
                "versions":["1.0.0"],
                "ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}"#,
        );

        assert_eq!(
            affected(&mixed, &at(&Semver, "1.0.0"), &Semver),
            Match::Affected
        );
        assert_eq!(
            affected(&mixed, &at(&Semver, "2.0.0"), &Semver),
            Match::Unaffected
        );
    }

    // -- Folding ----------------------------------------------------------

    #[test]
    fn answer_worst_wins() {
        assert_eq!(
            Match::Unaffected.worst(Match::Affected),
            Match::Affected,
            "one matching span is a hit"
        );
        assert_eq!(
            Match::Unaffected.worst(Match::Unknown),
            Match::Unknown,
            "one span nobody could evaluate leaves the answer doubtful"
        );
        assert_eq!(
            Match::Unknown.worst(Match::Affected),
            Match::Affected,
            "a definite hit outranks a doubt"
        );
    }

    #[test]
    fn spans_several_checked_together() {
        let range = ranged(
            "SEMVER",
            r#"[{"introduced":"1.0.0"},{"fixed":"1.1.0"},
                {"introduced":"2.0.0"},{"fixed":"2.0.5"}]"#,
        );

        assert_eq!(
            affected(&range, &at(&Semver, "2.0.1"), &Semver),
            Match::Affected,
            "the second span matches"
        );
        assert_eq!(
            affected(&range, &at(&Semver, "1.5.0"), &Semver),
            Match::Unaffected,
            "between the two spans"
        );
    }
}
