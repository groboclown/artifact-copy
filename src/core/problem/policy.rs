//! Per-code overrides of the built-in dispositions.
//!
//! [`Code::action`] and [`Code::quarantine`] are the defaults, chosen to be
//! right for most people most of the time. This is how a user says
//! otherwise for their own situation, and it is the table
//! `Code::action`'s documentation has been anticipating.
//!
//! # Four names, two fields
//!
//! A user writes one of four classes per code, and each sets both axes:
//!
//! | Written | [`Action`] | [`Quarantine`] |
//! | --- | --- | --- |
//! | `allowed` | `warn` | none |
//! | `soft` | `warn` | soft |
//! | `hard` | `skip-artifact` | hard |
//! | `failure` | at least `skip-artifact` | none |
//!
//! Two of the four are not quarantine values at all, which the single knob
//! hides and is worth knowing: `allowed` means *carry on and say so*, and
//! `failure` means *this is not up for review*. Only `soft` and `hard`
//! populate the marker.
//!
//! # What this deliberately does not decide
//!
//! **The exit code.** Holding an artifact back and failing the run are
//! different questions, and the second is answered by how the artifact was
//! reached -- see `docs/contributors/exit-codes.md`. A `hard` on something
//! a user named fails the run; the same `hard` on a transitive dependency
//! does not.
//!
//! **Per-artifact exceptions.** Those live in the quarantine policy file,
//! not here, because nothing in the configuration is keyed by an artifact.
//! This table is per *code*, for every artifact a run touches.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Action, Bypass, Code, Quarantine};
use crate::model::{ArtifactId, Version};

/// How one code is handled: both axes, resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disposition {
    pub action: Action,
    pub quarantine: Option<Quarantine>,
}

impl Disposition {
    /// What a code does when nothing overrides it.
    pub fn of(code: Code) -> Self {
        Self {
            action: code.action(),
            quarantine: code.quarantine(),
        }
    }
}

/// What a user writes against a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Record it and carry on. Not a quarantine.
    Allowed,

    /// Take the artifact and flag it for review.
    Soft,

    /// Hold the artifact back, reviewably.
    Hard,

    /// Not up for review, and it fails.
    Failure,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Allowed => "allowed",
            Class::Soft => "soft",
            Class::Hard => "hard",
            Class::Failure => "failure",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "allowed" => Some(Class::Allowed),
            "soft" => Some(Class::Soft),
            "hard" => Some(Class::Hard),
            "failure" => Some(Class::Failure),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["allowed", "soft", "hard", "failure"]
    }

    /// The pair this class sets for `code`.
    ///
    /// Only `failure` consults the code at all, and only to avoid
    /// *weakening* it: a code that already aborts keeps aborting, because a
    /// user asking for something to be a failure did not ask for it to
    /// become a smaller one. Everything else is a flat mapping, which is
    /// what makes the four names mean the same thing wherever they appear.
    pub fn disposition(self, code: Code) -> Disposition {
        match self {
            Class::Allowed => Disposition {
                action: Action::Warn,
                quarantine: None,
            },

            Class::Soft => Disposition {
                action: Quarantine::Soft.implied_action(),
                quarantine: Some(Quarantine::Soft),
            },

            Class::Hard => Disposition {
                action: Quarantine::Hard.implied_action(),
                quarantine: Some(Quarantine::Hard),
            },

            Class::Failure => Disposition {
                action: code.action().max(Action::SkipArtifact),
                quarantine: None,
            },
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happens about one code, and who said so.
///
/// [`Disposition`] alone answers *what happens*, which is all the run needs
/// to act. This adds *who decided* -- the per-artifact rule that answered
/// and whether hardening moved it -- which is what a report needs and what
/// nothing can recover afterwards.
///
/// Owned rather than borrowing the rule, because a `Problem` outlives the
/// decision that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruling {
    pub disposition: Disposition,

    /// The acknowledgement that answered for this artifact, if one did.
    pub bypass: Option<Bypass>,

    /// Whether the run's strictness, rather than the class, decided this.
    pub hardened: bool,
}

impl Ruling {
    /// A ruling nobody wrote a rule for: the disposition and nothing else.
    pub fn of(disposition: Disposition) -> Self {
        Self {
            disposition,
            bypass: None,
            hardened: false,
        }
    }
}

/// The artifact a problem happened to.
///
/// Carried separately from [`Provenance`](crate::model::Provenance), which
/// says *why* work is happening rather than *what* it is happening to. A
/// dependency's provenance names its parent, so the artifact being worked
/// on is nowhere in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub id: ArtifactId,

    /// `None` where the repository declares there are no versions, which
    /// a rule can only match by naming no version itself.
    pub version: Option<Version>,
}

impl Subject {
    pub fn new(id: ArtifactId, version: Option<Version>) -> Self {
        Self { id, version }
    }
}

/// Decides what happens about a problem.
///
/// A trait so that [`Ctx`](crate::core::ctx::Ctx) can hold the answer
/// without `core` knowing how it is reached. The full answer needs the
/// quarantine policy file, which is a file format with a schema and lives
/// in `policy` -- and `policy` already depends on `core`, so the dependency
/// is inverted here rather than cycled. The same shape as `net::Fetch`,
/// and for the same reason.
///
/// [`Policy`] implements it for the common case of no per-artifact
/// overrides, which is what an unconfigured run has.
pub trait Decide: Send + Sync + std::fmt::Debug {
    /// What happens about `code`, for the artifact being worked on.
    ///
    /// `at` is `None` for a problem that is not about one artifact -- a
    /// policy file that will not load, a host unreachable before anything
    /// resolved.
    fn decide(&self, code: Code, at: Option<&Subject>) -> Ruling;
}

impl Decide for Policy {
    /// Per-code only: a bare table has nothing to say about one artifact,
    /// so there is never a bypass to report.
    fn decide(&self, code: Code, _at: Option<&Subject>) -> Ruling {
        Ruling::of(self.disposition(code))
    }
}

/// The resolved `problem-policy` table for one run.
///
/// Empty by default, which is the whole built-in behaviour: a run with no
/// policy configured behaves exactly as one did before this existed.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Bounded by the number of codes, not by anything a run finds.
    classes: BTreeMap<Code, Class>,
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a configured table.
    pub fn from_classes(classes: impl IntoIterator<Item = (Code, Class)>) -> Self {
        Self {
            classes: classes.into_iter().collect(),
        }
    }

    /// Set one code's class, replacing any previous setting for it.
    pub fn set(mut self, code: Code, class: Class) -> Self {
        self.classes.insert(code, class);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// The class a user configured for this code, if any.
    pub fn class(&self, code: Code) -> Option<Class> {
        self.classes.get(&code).copied()
    }

    /// How this code is handled under this policy.
    pub fn disposition(&self, code: Code) -> Disposition {
        match self.classes.get(&code) {
            Some(class) => class.disposition(code),
            None => Disposition::of(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unconfigured run behaves exactly as it did before this existed,
    /// which is what makes the table a pure addition.
    #[test]
    fn policy_empty_built_in_behavior() {
        let policy = Policy::new();

        assert!(policy.is_empty());

        for code in [
            Code::MalwareKnown,
            Code::SignatureMissing,
            Code::ChecksumMismatch,
            Code::PublishTooRecent,
        ] {
            let resolved = policy.disposition(code);

            assert_eq!(resolved.action, code.action(), "{code}");
            assert_eq!(resolved.quarantine, code.quarantine(), "{code}");
        }
    }

    #[test]
    fn class_each_sets_both_axes() {
        let code = Code::SignatureMissing;

        for (class, action, quarantine) in [
            (Class::Allowed, Action::Warn, None),
            (Class::Soft, Action::Warn, Some(Quarantine::Soft)),
            (Class::Hard, Action::SkipArtifact, Some(Quarantine::Hard)),
            (Class::Failure, Action::SkipArtifact, None),
        ] {
            let resolved = class.disposition(code);

            assert_eq!(resolved.action, action, "{class}");
            assert_eq!(resolved.quarantine, quarantine, "{class}");
        }
    }

    /// The classes stay consistent with the correspondence every code
    /// already obeys, rather than being a second opinion about it.
    #[test]
    fn class_agrees_with_implied_action() {
        for (class, quarantine) in [
            (Class::Soft, Quarantine::Soft),
            (Class::Hard, Quarantine::Hard),
        ] {
            assert_eq!(
                class.disposition(Code::SignatureMissing).action,
                quarantine.implied_action()
            );
        }
    }

    /// Asking for a failure must not turn an abort into something smaller.
    /// A user marking `checksum-mismatch` as `failure` is agreeing with the
    /// default, not asking for it to stop unwinding the run.
    #[test]
    fn class_failure_never_weakens_code() {
        assert_eq!(
            Class::Failure.disposition(Code::ChecksumMismatch).action,
            Action::Abort
        );

        // And it does strengthen one that was only a warning.
        assert_eq!(
            Class::Failure.disposition(Code::SignatureMissing).action,
            Action::SkipArtifact
        );
    }

    /// The point of the table: turning something off for a repository where
    /// it is noise, without turning it off everywhere in the code.
    #[test]
    fn class_configured_replaces_default() {
        let policy = Policy::new().set(Code::SignatureMissing, Class::Allowed);

        assert_eq!(policy.class(Code::SignatureMissing), Some(Class::Allowed));
        assert_eq!(policy.disposition(Code::SignatureMissing).quarantine, None);

        // And nothing else moved.
        assert_eq!(
            policy.disposition(Code::MalwareKnown),
            Disposition::of(Code::MalwareKnown)
        );
    }

    /// Tightening is as expressible as loosening, which is the reason the
    /// four names include `failure`.
    #[test]
    fn class_tightens_as_well_as_loosens() {
        let policy = Policy::new()
            .set(Code::SignatureMissing, Class::Failure)
            .set(Code::MalwareKnown, Class::Allowed);

        assert_eq!(
            policy.disposition(Code::SignatureMissing).action,
            Action::SkipArtifact
        );
        assert_eq!(policy.disposition(Code::MalwareKnown).action, Action::Warn);
    }

    #[test]
    fn class_round_trips_through_name() {
        for name in Class::names() {
            let class = Class::parse(name).expect("every advertised name parses");

            assert_eq!(class.as_str(), *name);
        }

        assert_eq!(Class::parse("quarantine"), None);
    }
}
