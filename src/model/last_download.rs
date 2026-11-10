//! Whether a repository has served an artifact, and when.
//!
//! The type exists for one distinction, and it is worth the file: *this
//! repository records no download* and *this repository does not track
//! downloads* are different facts, and an `Option<DateTime>` collapses
//! them into one `None`.
//!
//! That collapse is dangerous in exactly one direction, because this field
//! gets read in order to retire things. A consumer that read `None` as
//! "never downloaded" would call every artifact in a repository that keeps
//! no statistics unused. So the safe question is
//! [`LastDownload::known_unused_since`], named for the guarantee it makes.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// When an artifact was last fetched from the repository.
///
/// **Three states, not an `Option`.** The distinction between *this
/// repository records no download* and *this repository does not track
/// downloads* is the entire point of the type, and an `Option<DateTime>`
/// collapses them into one `None`.
///
/// That collapse is dangerous in exactly one direction. The intended use of
/// this field is to tell whether an artifact is still in use -- and a
/// consumer that read `None` as "never downloaded" would conclude that
/// every artifact in a repository that keeps no statistics is unused. Most
/// enumerators cannot report this: a Maven HTML index, npm's replication feed
/// and PyPI's simple index carry no usage data whatsoever. Repository
/// managers do -- Nexus and Artifactory both record a last-downloaded
/// timestamp per asset -- which is precisely why the interface has to be
/// able to express the difference.
///
/// [`LastDownload::known_unused_since`] is the safe way to ask the
/// question, and it is named for the guarantee it makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LastDownload {
    /// The repository tracks downloads and last served this artifact then.
    At(DateTime<Utc>),

    /// The repository tracks downloads and has recorded none.
    ///
    /// Genuine evidence of disuse, unlike [`LastDownload::Unknown`].
    Never,

    /// The repository does not report download statistics.
    ///
    /// The absence of evidence. Most enumerators return this, and no
    /// conclusion about usage may be drawn from it.
    Unknown,
}

impl Default for LastDownload {
    /// [`LastDownload::Unknown`], because an enumerator that says nothing has
    /// claimed nothing.
    fn default() -> Self {
        Self::Unknown
    }
}

impl LastDownload {
    /// Fold two observations of one artifact into what is known.
    ///
    /// Two rules, and both are about *evidence* rather than about which
    /// observation arrived last:
    ///
    /// - [`Unknown`](Self::Unknown) is the absence of evidence, so it never
    ///   displaces an answer.
    /// - A timestamp beats [`Never`](Self::Never) whichever came first.
    ///   "Never downloaded" and "last downloaded on Tuesday" cannot both be
    ///   true, and only one of them is a reason to keep an artifact --
    ///   reporting disuse for something in use is the mistake that gets a
    ///   live artifact deleted.
    ///
    /// Two timestamps fold to the later, because downloading any file is
    /// using the artifact.
    ///
    /// **Not an `Ord`.** `Unknown` is not ordered against the other two --
    /// it is a statement about the server rather than about the artifact --
    /// so a comparison operator would invite `a < b` to mean something it
    /// does not.
    ///
    /// The report database's inventory upsert applies the same rule in SQL,
    /// where it cannot call this. The two are kept deliberately identical;
    /// see `report::db::inventory`.
    pub fn merged_with(self, other: Self) -> Self {
        match (self, other) {
            (Self::At(mine), Self::At(theirs)) => Self::At(mine.max(theirs)),

            (Self::At(when), _) | (_, Self::At(when)) => Self::At(when),
            (Self::Never, _) | (_, Self::Never) => Self::Never,

            (Self::Unknown, Self::Unknown) => Self::Unknown,
        }
    }

    /// Whether nothing is known about when this was last served.
    ///
    /// The default, and what a report omits: an enumerator that cannot answer
    /// and a repository nobody has asked are different facts, and only the
    /// second is worth a line.
    pub fn is_unknown(&self) -> bool {
        matches!(self, LastDownload::Unknown)
    }

    /// The recorded time, if there is one.
    pub fn at(&self) -> Option<DateTime<Utc>> {
        match self {
            LastDownload::At(when) => Some(*when),
            LastDownload::Never | LastDownload::Unknown => None,
        }
    }

    /// Whether the repository reported anything at all.
    pub fn is_known(&self) -> bool {
        !matches!(self, LastDownload::Unknown)
    }

    /// Whether this artifact is **known** to have gone unused since
    /// `cutoff`.
    ///
    /// True only on evidence: either the repository recorded no download
    /// ever, or it recorded one and it predates `cutoff`. An unknown answers
    /// `false`, because nothing is known about it.
    ///
    /// The asymmetry is the point. This question gets asked in order to
    /// retire things, so the failure that matters is deleting an artifact
    /// that is heavily used but served by a repository that keeps no
    /// statistics. Answering `false` costs a retention; answering `true`
    /// costs a broken build somewhere downstream.
    pub fn known_unused_since(&self, cutoff: DateTime<Utc>) -> bool {
        match self {
            LastDownload::Never => true,
            LastDownload::At(when) => *when < cutoff,
            LastDownload::Unknown => false,
        }
    }
}

impl fmt::Display for LastDownload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LastDownload::At(when) => write!(f, "{}", when.to_rfc3339()),
            LastDownload::Never => f.write_str("never"),
            LastDownload::Unknown => f.write_str("unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactId, EcosystemId};
    use crate::repo::enumerate::Found;

    fn when(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("a valid timestamp")
            .with_timezone(&Utc)
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), name)
    }

    /// The distinction the type exists for. A repository that records no
    /// download is evidence of disuse; one that keeps no statistics is not.
    #[test]
    fn answer_never_differs_from_untracked() {
        let cutoff = when("2024-01-01T00:00:00Z");

        assert!(LastDownload::Never.known_unused_since(cutoff));
        assert!(!LastDownload::Unknown.known_unused_since(cutoff));

        assert!(LastDownload::Never.is_known());
        assert!(!LastDownload::Unknown.is_known());
    }

    /// The asymmetry, stated as a test: retiring an artifact that is
    /// actually in use costs a broken build somewhere, so nothing is ever
    /// called unused on the strength of missing data.
    #[test]
    fn answer_unreported_never_reads_unused() {
        for cutoff in ["1970-01-01T00:00:00Z", "2099-01-01T00:00:00Z"] {
            assert!(
                !LastDownload::Unknown.known_unused_since(when(cutoff)),
                "unknown must never answer 'unused', whatever the cutoff"
            );
        }
    }

    #[test]
    fn answer_recorded_compared_to_cutoff() {
        let cutoff = when("2024-01-01T00:00:00Z");

        let old = LastDownload::At(when("2023-06-01T00:00:00Z"));
        let recent = LastDownload::At(when("2024-06-01T00:00:00Z"));

        assert!(old.known_unused_since(cutoff));
        assert!(!recent.known_unused_since(cutoff));

        // The boundary belongs to "still in use": an artifact downloaded at
        // the cutoff instant has been used since then.
        assert!(!LastDownload::At(cutoff).known_unused_since(cutoff));
    }

    #[test]
    fn timestamp_only_for_recorded() {
        let moment = when("2024-06-01T00:00:00Z");

        assert_eq!(LastDownload::At(moment).at(), Some(moment));
        assert_eq!(LastDownload::Never.at(), None);
        assert_eq!(LastDownload::Unknown.at(), None);
    }

    /// An enumerator that says nothing has claimed nothing.
    #[test]
    fn default_is_unknown() {
        assert_eq!(LastDownload::default(), LastDownload::Unknown);
        assert_eq!(Found::new(id("lib")).last_download, LastDownload::Unknown);
    }

    /// The three states have to survive the exchange format, or an
    /// out-of-process enumerator cannot report them.
    #[test]
    fn states_round_trip_through_json() {
        for original in [
            LastDownload::At(when("2024-06-01T12:00:00Z")),
            LastDownload::Never,
            LastDownload::Unknown,
        ] {
            let json = serde_json::to_string(&original).expect("serialized");
            let back: LastDownload = serde_json::from_str(&json).expect("deserialized");

            assert_eq!(back, original, "{json}");
        }
    }

    /// The Rust form and the exchange format must agree, or an
    /// out-of-process enumerator cannot report what a built-in one can. This
    /// checks the serialization against the committed schema rather than
    /// against a second hand-written copy of the shape.
    #[test]
    fn states_satisfy_protocol_schema() {
        for state in [
            LastDownload::At(when("2024-06-01T12:00:00Z")),
            LastDownload::Never,
            LastDownload::Unknown,
        ] {
            let value = serde_json::to_value(state).expect("serialized");
            let errors = crate::ext::gear::testing::validate_against("LastDownload", &value);

            assert!(errors.is_empty(), "{value}: {errors:?}");
        }
    }

    /// And the schema has to be strict enough to be worth having: a
    /// nullable timestamp, or a fourth state, must be refused.
    #[test]
    fn states_other_refused_by_protocol_schema() {
        for bad in [
            serde_json::Value::Null,
            serde_json::json!("sometimes"),
            serde_json::json!({}),
            serde_json::json!({"at": "not a timestamp", "extra": 1}),
        ] {
            let errors = crate::ext::gear::testing::validate_against("LastDownload", &bad);

            assert!(!errors.is_empty(), "{bad} should have been refused");
        }
    }

    /// The two that carry no timestamp must stay distinguishable on the
    /// wire, not both become `null`.
    #[test]
    fn states_never_unknown_distinct_on_wire() {
        let never = serde_json::to_string(&LastDownload::Never).expect("serialized");
        let unknown = serde_json::to_string(&LastDownload::Unknown).expect("serialized");

        assert_ne!(never, unknown);
        assert_eq!(never, "\"never\"");
        assert_eq!(unknown, "\"unknown\"");

        // And a recorded time is tagged, not bare, so it cannot be confused
        // with either of them.
        assert_eq!(
            serde_json::to_string(&LastDownload::At(when("2024-06-01T12:00:00Z")))
                .expect("serialized"),
            r#"{"at":"2024-06-01T12:00:00Z"}"#
        );
    }

    #[test]
    fn states_each_renders_for_report() {
        assert_eq!(LastDownload::Never.to_string(), "never");
        assert_eq!(LastDownload::Unknown.to_string(), "unknown");
        assert_eq!(
            LastDownload::At(when("2024-06-01T12:00:00Z")).to_string(),
            "2024-06-01T12:00:00+00:00"
        );
    }
}
