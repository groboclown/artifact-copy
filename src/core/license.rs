//! What a license policy decided about one artifact.
//!
//! The *outcome* of an evaluation, not the policy that produced it: the
//! rules, the alias table and the file format stay in
//! [`crate::policy::LicensePolicy`], which is where a file format belongs.
//!
//! Here because of who needs it. A verdict is reported as a problem, kept
//! against the artifact on a [`Ctx`](crate::core::ctx::Ctx), and written
//! into a report - three layers that must not each depend on `policy` to
//! name the thing they are passing around. It is the same argument that
//! moved `LastDownload` into `model`: domain vocabulary rather than one
//! module's private type.
//!
//! It is in `core` rather than `model` because it names a [`Message`] and a
//! [`Code`], and `model` depends on nothing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::message::Message;
use super::problem::Code;
use crate::model::DepKind;

/// What to do with an artifact.
///
/// Defaults to `Forbid`: a policy that says nothing should let nothing
/// through, not everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,

    #[default]
    Forbid,
}

/// The outcome of evaluating one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,

    /// The SPDX expression the declared text resolved to, when it did.
    pub spdx: Option<String>,

    /// Why this decision was reached.
    ///
    /// A message identifier plus named arguments rather than prose, because
    /// this reaches the report and is read by other tools.
    pub reason: Message,

    /// A problem to record alongside the verdict, when something was off.
    pub problem: Option<Code>,

    /// The per-usage decisions that produced this verdict, when a rule
    /// carried a `usage` map.  Recorded in full even though only the
    /// presence of one `allow` decided the outcome, because the report needs
    /// to say *which* usages were permitted: an artifact allowed for test
    /// use alone is migrated, and someone reading the report later has to be
    /// able to see that it was never cleared for runtime.
    pub usage: BTreeMap<DepKind, Decision>,
}

impl Verdict {
    /// A verdict reached without a usage map.
    pub(crate) fn plain(
        decision: Decision,
        spdx: Option<String>,
        reason: Message,
        problem: Option<Code>,
    ) -> Self {
        Self {
            decision,
            spdx,
            reason,
            problem,
            usage: BTreeMap::new(),
        }
    }

    /// Usages this artifact is cleared for.
    pub fn allowed_usages(&self) -> Vec<DepKind> {
        self.usage
            .iter()
            .filter(|(_, decision)| **decision == Decision::Allow)
            .map(|(kind, _)| *kind)
            .collect()
    }
}
