//! Graded failure handling.
//!
//! Not every failure stops a run.  A `Problem` pairs a stable [`Code`] with
//! the [`Action`] actually taken and the [`Provenance`] that explains which
//! artifact it happened to and why that artifact was being looked at.
//!
//! ```text
//!   Error  --code()-->  Code  --action()-->  Action  -->  ProblemSink
//! ```

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::message::Message;
use crate::model::Provenance;

mod code;
mod policy;
mod sink;

pub use code::{Code, Concern};
pub use policy::{Class, Decide, Disposition, Policy, Ruling, Subject};
pub use sink::{ProblemSink, Watch};

/// Whether a problem holds an artifact for review, and how firmly.
///
/// **A second axis, not a sixth [`Action`].** The two answer different
/// questions and a problem can need both: `host-unreachable` skips and is
/// *not* reviewable, `publish-too-recent` skips and *is*. Folding them into
/// one ordered scale would have forced a claim about whether "held for
/// review" is more or less severe than "dropped", which is not a question
/// with an answer.
///
/// What it does **not** decide is the exit code. Holding an artifact back
/// and failing the run are separate questions, and the second is answered
/// by how the artifact was reached -- see `docs/contributors/exit-codes.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Quarantine {
    /// Recorded and flagged; the artifact is still taken.
    ///
    /// The common case, and the reason the split exists: a repository whose
    /// signatures routinely have no available key would otherwise hold back
    /// everything it serves until someone tuned it.
    ///
    /// A user who wants these to hold artifacts back *hardens* them, which
    /// is a run-wide switch rather than a reclassification.
    Soft,

    /// The artifact is held back in all cases.
    ///
    /// Distinct from simply failing: a hard quarantine is recorded **as a
    /// quarantine**, so it appears in the quarantine list, it is
    /// reviewable, and a per-artifact override can excuse it. A failure is
    /// none of those.
    Hard,
}

impl Quarantine {
    pub fn as_str(self) -> &'static str {
        match self {
            Quarantine::Soft => "soft",
            Quarantine::Hard => "hard",
        }
    }

    /// The action a quarantine of this class implies.
    ///
    /// The single place the two axes are tied together, so that a code's
    /// two default tables cannot drift apart -- a test walks every code and
    /// checks them against this.
    pub fn implied_action(self) -> Action {
        match self {
            Quarantine::Soft => Action::Warn,
            Quarantine::Hard => Action::SkipArtifact,
        }
    }
}

impl fmt::Display for Quarantine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What was done about a problem.  Ordered least to most severe, so the
/// worst action across a run is a `max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Recorded only.
    Ignore,

    /// Recorded and logged; the run continues unaffected.
    Warn,

    /// Stop descending this artifact's dependency tree, but keep the
    /// artifact itself.
    StopSpider,

    /// Drop this artifact.  Its already-found dependencies stand.
    SkipArtifact,

    /// Unwind the entire run.
    Abort,
}

impl Action {
    /// Whether a run ending with this as its worst action should exit
    /// non-zero.  A warning is not a failure; a skipped artifact is.
    pub fn is_failure(self) -> bool {
        self >= Action::SkipArtifact
    }

    /// Whether a run ending with this as its worst action could not
    /// complete at all, the *fail-fast* exit rather than *fail-eventually*.
    ///
    /// The action decides rather than the code's concern: an abort unwinds
    /// the run whatever raised it, so `checksum-mismatch` and an unavailable
    /// advisory source are as fatal as a bad argument.
    pub fn is_fatal(self) -> bool {
        self == Action::Abort
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Action::Ignore => "ignore",
            Action::Warn => "warn",
            Action::StopSpider => "stop-spider",
            Action::SkipArtifact => "skip-artifact",
            Action::Abort => "abort",
        };

        f.write_str(text)
    }
}

/// The acknowledgement that let a problem through, or held it back.
///
/// Owned, unlike the rule it came from, because a `Problem` outlives the
/// decision that produced it: it is recorded now and written to a report
/// later, by which time nothing is still borrowing the policy file.
///
/// Carried on the problem rather than re-derived at report time because a
/// rule's expiry is evaluated **when the decision is made**. Re-deciding a
/// long run's early problems at the end would have some of them lapse
/// retroactively, and a report would then disagree with what the run
/// actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bypass {
    /// Why the person who wrote it judged this acceptable.
    pub justification: Option<String>,

    /// Which file and entry it came from, so a reader can go and look.
    pub source: String,

    /// When it lapses, if it lapses.
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
}

/// One recorded failure.
#[derive(Debug, Clone)]
pub struct Problem {
    code: Code,
    action: Action,
    prov: Arc<Provenance>,

    /// Whether this holds the artifact for review, and how firmly.
    ///
    /// `None` for most problems: a transport failure or a malformed
    /// document is nothing to review, it is something to fix.
    quarantine: Option<Quarantine>,

    /// The per-artifact rule that answered, when one did.
    ///
    /// **Present is the interesting case.** A reservation that held an
    /// artifact back is visible in the artifact's absence; one somebody
    /// waved through is visible nowhere else, and is exactly what an
    /// auditor is looking for.
    bypass: Option<Bypass>,

    /// Whether the run's strictness, rather than the class, held this back.
    ///
    /// A hardened soft and a hard both stop an artifact and are not the
    /// same statement: the first would not have stopped it yesterday.
    hardened: bool,

    /// An identifier plus named arguments, not prose.  Reports carry this
    /// verbatim, so a consumer can render it in another language without
    /// parsing English.
    message: Message,
}

impl Problem {
    /// Build a problem, resolving its action and quarantine class from the
    /// code's built-in defaults.
    pub fn new(code: Code, prov: Arc<Provenance>, message: Message) -> Self {
        Self::resolved(code, Disposition::of(code), prov, message)
    }

    /// Build a problem from an already-resolved disposition.
    ///
    /// What [`crate::core::ctx::Ctx::report`] uses, so that the
    /// `problem-policy` table is consulted once, where the context holds
    /// it, rather than every call site remembering to.
    pub fn resolved(
        code: Code,
        disposition: Disposition,
        prov: Arc<Provenance>,
        message: Message,
    ) -> Self {
        Self::ruled(code, Ruling::of(disposition), prov, message)
    }

    /// Build a problem from a full ruling, keeping who decided it.
    ///
    /// The shape [`crate::core::ctx::Ctx::report`] uses. A bare
    /// [`Disposition`] says *what happens*; a [`Ruling`] also says *who
    /// said so*, and the second half is what a report needs and cannot
    /// recover afterwards.
    pub fn ruled(code: Code, ruling: Ruling, prov: Arc<Provenance>, message: Message) -> Self {
        Self {
            code,
            action: ruling.disposition.action,
            prov,
            quarantine: ruling.disposition.quarantine,
            bypass: ruling.bypass,
            hardened: ruling.hardened,
            message,
        }
    }

    /// The acknowledgement that answered for this artifact, if one did.
    pub fn bypass(&self) -> Option<&Bypass> {
        self.bypass.as_ref()
    }

    /// Whether hardening, rather than the class, held this back.
    pub fn hardened(&self) -> bool {
        self.hardened
    }

    /// Override the resolved action.  Used where context changes severity:
    /// an oversized body is fatal while loading config but survivable for
    /// one artifact among many being enumerated.
    pub fn with_action(mut self, action: Action) -> Self {
        self.action = action;
        self
    }

    /// Override the resolved quarantine class.
    ///
    /// For the `problem-policy` table and for per-artifact overrides, which
    /// are the two things allowed to move a code off its default.
    pub fn with_quarantine(mut self, quarantine: Option<Quarantine>) -> Self {
        self.quarantine = quarantine;
        self
    }

    /// Whether this problem holds the artifact for review, and how firmly.
    pub fn quarantine(&self) -> Option<Quarantine> {
        self.quarantine
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn prov(&self) -> &Arc<Provenance> {
        &self.prov
    }

    pub fn message(&self) -> &Message {
        &self.message
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only an abort is fail-fast; a skipped artifact is fail-eventually.
    #[test]
    fn only_abort_is_fatal() {
        let fatal: Vec<Action> = [
            Action::Ignore,
            Action::Warn,
            Action::StopSpider,
            Action::SkipArtifact,
            Action::Abort,
        ]
        .into_iter()
        .filter(|action| action.is_fatal())
        .collect();

        assert_eq!(fatal, [Action::Abort]);
    }
}
