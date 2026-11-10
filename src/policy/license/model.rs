//! The shapes a license policy file is written in.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::license::Decision;
use crate::model::DepKind;

/// A license named in a policy list.
///
/// Either the bare expression or an object carrying a note beside it:
///
/// ```yaml
/// allowed-licenses:
///   - MIT
///   - spdx-id: Apache-2.0
///     $comment: approved by legal, ticket LEG-4412
/// ```
///
/// The object form adds **nothing the tool acts on**. It exists so that the
/// reason a license is on a list can live beside the license rather than in
/// a comment somebody deletes, which is the same argument the quarantine
/// file's `justification` makes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SpdxRef {
    /// `MIT`
    Plain(String),

    /// `{ spdx-id: MIT, $comment: ... }`
    Noted(NotedSpdx),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NotedSpdx {
    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    pub spdx_id: String,
}

impl SpdxRef {
    /// The expression, whichever form it was written in.
    pub fn spdx(&self) -> &str {
        match self {
            SpdxRef::Plain(expression) => expression,
            SpdxRef::Noted(noted) => &noted.spdx_id,
        }
    }
}

/// The license an artifact rule asserts.
///
/// Either the bare expression or an object that can also record a copyright
/// line and where the license text was found:
///
/// ```yaml
/// artifacts:
///   - purl: pkg:npm/odd
///     license:
///       spdx-id: MIT
///       copyright: "(c) 2019 Acme Corp"
///       uris: [https://acme.example/LICENSE]
/// ```
///
/// **Only `spdx-id` is acted on.** The copyright and the URIs are recorded
/// for whoever reads the policy file and go no further -- in particular a
/// URI here does **not** teach the tool to resolve that link, which is what
/// the `aliases` table is for. Keeping them apart means a note cannot
/// silently change which artifacts are allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LicenseDeclaration {
    /// `MIT`
    Plain(String),

    /// `{ spdx-id: MIT, copyright: ..., uris: [...] }`
    Detailed(DetailedLicense),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DetailedLicense {
    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    pub spdx_id: String,

    /// Recorded, never matched on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copyright: Option<String>,

    /// Where the license text was found. Recorded, never matched on -- see
    /// the type's documentation for why this is not an alias.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<String>,
}

impl LicenseDeclaration {
    /// The expression, whichever form it was written in.
    pub fn spdx(&self) -> &str {
        match self {
            LicenseDeclaration::Plain(expression) => expression,
            LicenseDeclaration::Detailed(detailed) => &detailed.spdx_id,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Alias {
    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    #[serde(default)]
    pub urls: Vec<String>,

    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ArtifactRule {
    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,

    /// What this artifact's license actually is, when the rule corrects a
    /// wrong or missing declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseDeclaration>,

    #[serde(default)]
    pub policy: ArtifactPolicy,

    /// Per-usage decisions, such as `{"runtime": "forbid", "test": "allow"}`.
    ///
    /// More precise than `policy`, and consulted first when present.  A
    /// single `allow` decides the whole map: the question this tool answers
    /// is whether the artifact must exist in the target, and one cleared
    /// usage is enough to require it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub usage: BTreeMap<DepKind, Decision>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// A per-artifact override, which may also defer to the general rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactPolicy {
    #[default]
    Default,
    Allow,
    Forbid,
}
