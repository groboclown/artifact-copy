//! Enum values, spelled the way the report format spells them.
//!
//! Through serde rather than a table of match arms. Every one of these --
//! `Code`, `Action`, `Quarantine`, `Verification`, `Decision`, `DepKind`,
//! `DigestAlg` -- already derives its kebab-case or lower-case rendering,
//! and `record.rs` calls that rendering published API. A second copy of the
//! same strings here is a second thing to keep in step, and the day it
//! drifts a database says `skipArtifact` where a report said
//! `skip-artifact`.
//!
//! So the database stores exactly what a JSONL report stores, by
//! construction.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

/// How the report format spells one value.
pub(super) fn text<T: Serialize + std::fmt::Debug>(value: &T) -> Result<String> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => Ok(text),

        // Every caller passes a unit-variant enum, so anything else is a
        // programming error rather than bad data.
        other => Err(Error::Report(format!(
            "{value:?} does not spell as one word: {other:?}"
        ))),
    }
}

/// One value back from its spelling, or `None` when this build has no such
/// value.
///
/// A newer build's vocabulary reaching an older reader is the ordinary
/// case, not a corruption, and a caller decides whether to skip the row or
/// substitute something.
pub(super) fn value<T: DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
}

/// What an outcome column calls an outcome.
///
/// The one spelling not taken from serde: an `Outcome` serializes as a
/// tagged object, not a word, so these five match the columns' CHECK
/// constraints instead.
pub(super) fn outcome(outcome: &crate::report::Outcome) -> &'static str {
    use crate::report::Outcome;

    match outcome {
        Outcome::Copied { .. } => "copied",
        Outcome::AlreadyPresent => "already-present",
        Outcome::Refused { .. } => "refused",
        Outcome::Unresolved { .. } => "unresolved",
        Outcome::Failed { .. } => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::problem::{Action, Code, Quarantine};
    use crate::model::{DepKind, DigestAlg};
    use crate::policy::Decision;
    use crate::report::record::Verification;

    /// The database and a JSONL report must agree on every word, so this
    /// walks a value of each vocabulary rather than trusting the derives.
    #[test]
    fn every_vocabulary_round_trips() {
        assert_eq!(text(&Code::ChecksumMismatch).unwrap(), "checksum-mismatch");
        assert_eq!(text(&Action::SkipArtifact).unwrap(), "skip-artifact");
        assert_eq!(text(&Quarantine::Hard).unwrap(), "hard");
        assert_eq!(
            text(&Verification::WeakDigestOnly).unwrap(),
            "weak-digest-only"
        );
        assert_eq!(text(&Decision::Forbid).unwrap(), "forbid");
        assert_eq!(text(&DepKind::Runtime).unwrap(), "runtime");
        assert_eq!(text(&DigestAlg::Sha256).unwrap(), "sha256");

        assert_eq!(
            value::<Code>("checksum-mismatch"),
            Some(Code::ChecksumMismatch)
        );
        assert_eq!(value::<Action>("skip-artifact"), Some(Action::SkipArtifact));
        assert_eq!(value::<Quarantine>("hard"), Some(Quarantine::Hard));
        assert_eq!(
            value::<Verification>("weak-digest-only"),
            Some(Verification::WeakDigestOnly)
        );
        assert_eq!(value::<Decision>("forbid"), Some(Decision::Forbid));
        assert_eq!(value::<DepKind>("runtime"), Some(DepKind::Runtime));
        assert_eq!(value::<DigestAlg>("sha256"), Some(DigestAlg::Sha256));
    }

    /// A word a newer build wrote is not corruption. The reader skips the
    /// row or substitutes; it does not fail the report.
    #[test]
    fn word_unknown_not_error() {
        assert_eq!(value::<Code>("invented-later"), None);
        assert_eq!(value::<DigestAlg>("blake3"), None);
    }

    /// `Action` also has a `Display`, and the two must not disagree -- a
    /// database written through one and read through the other would
    /// silently lose every action.
    #[test]
    fn display_agrees_with_spelling() {
        for action in [
            Action::Ignore,
            Action::Warn,
            Action::StopSpider,
            Action::SkipArtifact,
            Action::Abort,
        ] {
            assert_eq!(text(&action).unwrap(), action.to_string());
        }
    }
}
