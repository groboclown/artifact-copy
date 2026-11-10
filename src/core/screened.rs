//! What advisory screening found about one artifact.
//!
//! The *outcome* of screening, not the corpus or the policy that produced
//! it: those stay in [`crate::advisory`] and [`crate::policy::SecurityPolicy`].
//! Here for the reason [`super::license`] is: a finding is kept against the
//! artifact on a [`Ctx`](crate::core::ctx::Ctx) and written into a report,
//! and neither layer may depend on `advisory` or `policy` to name it.

use serde::{Deserialize, Serialize};

/// What an advisory says the package is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// A `MAL-` record: the package is malicious.
    Malware,

    /// Anything else: the package carries a known vulnerability.
    Vulnerability,
}

impl Category {
    /// The kebab-case name used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Malware => "malware",
            Category::Vulnerability => "vulnerability",
        }
    }
}

/// Whether the artifact's version was shown to be affected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Certainty {
    /// The version falls in the advisory's affected set.
    Affected,

    /// The advisory names the package and lists no version the artifact's
    /// convention can compare. See `advisory-version-unusable`.
    VersionUnusable,
}

/// Why a finding was cleared: the VEX statement that answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    pub justification: Option<String>,
    pub detail: Option<String>,

    /// The document the statement was read from.
    pub source: String,
}

/// One advisory that named this artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    /// The configured advisor whose corpus supplied the record. The first
    /// corpus to carry it, when several did.
    pub advisor: String,

    pub category: Category,
    pub id: String,
    pub summary: Option<String>,
    pub certainty: Certainty,

    /// Set when a VEX statement cleared this. A suppressed finding is
    /// recorded and raises no problem.
    pub suppressed_by: Option<Suppression>,
}
