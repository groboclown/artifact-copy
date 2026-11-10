//! Security policy: what to do about known vulnerabilities and malware.
//!
//! Mirrors `schema/security-policy.schema.json`, and deliberately parallels
//! the license policy -- same shape of problem, same shape of file.  It holds
//! only the organization-wide stances: an allowance for specific artifacts
//! is a VEX statement, which arrives with the request as a lock file and is
//! handed to [`SecurityPolicy::screen`].

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::vex::{Statement, Status};
use crate::core::error::{Error, Result};
use crate::core::message::Message;
use crate::core::problem::{Action, Class, Code};
use crate::message;

/// What to do with artifacts a corpus flags as malicious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MalwareStance {
    /// Never migrate a flagged artifact.
    #[default]
    Forbid,

    /// Record it and carry on.  For someone auditing an existing mirror who
    /// needs the report before the enforcement.
    Report,
}

/// What to do with artifacts carrying known vulnerabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilityStance {
    /// Record every finding; block nothing.  The sane default until a
    /// maximum-score threshold exists, since nearly every real dependency
    /// graph carries known vulnerabilities.
    #[default]
    Report,

    Forbid,
}

/// The outcome of screening one artifact against one advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub problem: Code,

    /// The VEX statement that cleared or downgraded this, when one did.
    pub suppressed_by: Option<Suppression>,

    /// The least action this policy insists on.
    ///
    /// `Some(SkipArtifact)` for an unsuppressed vulnerability under
    /// `vulnerabilities: forbid`. The stance raises severity rather than
    /// naming a different finding, so the code stays `vulnerability-known`,
    /// and a per-artifact rule still answers; see
    /// [`crate::core::ctx::Ctx::report_at_least`].
    pub floor: Option<Action>,
}

pub use crate::core::screened::Suppression;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SecurityPolicyFile {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    #[serde(default)]
    pub malware: MalwareStance,

    #[serde(default)]
    pub vulnerabilities: VulnerabilityStance,
}

/// A loaded policy.
#[derive(Debug, Clone, Default)]
pub struct SecurityPolicy {
    malware: MalwareStance,
    vulnerabilities: VulnerabilityStance,
}

pub const SECURITY_POLICY_SCHEMA_ID: &str =
    "https://github.com/groboclown/artifact-copy/schema/security-policy.schema.json";

const SECURITY_POLICY_SCHEMA: &str = include_str!("../../schema/security-policy.schema.json");

impl SecurityPolicy {
    /// Read a policy file.
    pub fn load(path: &Path) -> Result<Self> {
        let value = super::read_validated(path, SECURITY_POLICY_SCHEMA, "security policy")?;

        let file: SecurityPolicyFile = serde_json::from_value(value).map_err(|source| {
            Error::Config(format!(
                "{} is not a usable security policy: {source}",
                path.display()
            ))
        })?;

        Ok(Self {
            malware: file.malware,
            vulnerabilities: file.vulnerabilities,
        })
    }

    /// Screen one advisory against this policy.
    ///
    /// `answer` is the VEX statement that covers the artifact and names the
    /// advisory, when the run holds one; see
    /// [`crate::advisory::Screening::answer`].
    pub fn screen(&self, id: &str, is_malware: bool, answer: Option<&Statement>) -> Finding {
        if let Some(statement) = answer {
            if statement.status.suppresses() {
                return Finding {
                    id: id.to_owned(),
                    // Still recorded, so a suppressed finding stays visible
                    // in the report with its justification attached.
                    problem: Code::VulnerabilityUnderInvestigation,
                    suppressed_by: Some(Suppression {
                        justification: statement.justification.clone(),
                        detail: statement.detail.clone(),
                        source: statement.source.clone(),
                    }),
                    floor: None,
                };
            }

            if statement.status == Status::UnderInvestigation {
                return Finding {
                    id: id.to_owned(),
                    problem: Code::VulnerabilityUnderInvestigation,
                    suppressed_by: None,
                    floor: None,
                };
            }
        }

        Finding {
            id: id.to_owned(),
            problem: self.unsuppressed_code(is_malware),
            suppressed_by: None,
            floor: match (is_malware, self.vulnerabilities) {
                (false, VulnerabilityStance::Forbid) => Some(Action::SkipArtifact),
                _ => None,
            },
        }
    }

    /// The warning for `vulnerabilities: forbid` beside a `problem-policy`
    /// entry that sets `vulnerability-known` below `skip-artifact`.
    ///
    /// `stated` is that entry, or `None` when the table does not name the
    /// code: the built-in `warn` is not a statement the stance contradicts.
    ///
    /// The stance wins, and saying so is the point: a user who wrote
    /// `vulnerability-known: warn` would otherwise watch vulnerabilities
    /// held back and find nothing in the configuration explaining it.
    pub fn stance_conflict(&self, path: &Path, stated: Option<Class>) -> Option<Message> {
        let (VulnerabilityStance::Forbid, Some(class)) = (self.vulnerabilities, stated) else {
            return None;
        };

        let action = class.disposition(Code::VulnerabilityKnown).action;

        if action >= Action::SkipArtifact {
            return None;
        }

        Some(message!(
            "security-stance-overrides-problem-policy",
            "{path} says 'vulnerabilities: forbid', which holds back every \
             vulnerability as skip-artifact although problem-policy sets \
             vulnerability-known to {action}; a per-artifact quarantine rule \
             still answers for its artifact",
            path = &path.display(),
            action = action,
        ))
    }

    fn unsuppressed_code(&self, is_malware: bool) -> Code {
        if is_malware {
            return match self.malware {
                MalwareStance::Forbid => Code::MalwareKnown,
                MalwareStance::Report => Code::VulnerabilityKnown,
            };
        }

        match self.vulnerabilities {
            VulnerabilityStance::Forbid | VulnerabilityStance::Report => Code::VulnerabilityKnown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reporting() -> SecurityPolicy {
        SecurityPolicy {
            malware: MalwareStance::Forbid,
            vulnerabilities: VulnerabilityStance::Report,
        }
    }

    fn cleared(vulnerability: &str, purl: &str) -> Statement {
        Statement {
            vulnerability: vulnerability.into(),
            products: vec![purl.into()],
            status: Status::NotAffected,
            justification: Some("vulnerable_code_not_present".into()),
            detail: None,
            source: "test".into(),
        }
    }

    fn forbidding() -> SecurityPolicy {
        SecurityPolicy {
            vulnerabilities: VulnerabilityStance::Forbid,
            ..reporting()
        }
    }

    /// Only a stated entry conflicts: the built-in `warn` is not something
    /// the user said.
    #[test]
    fn stance_conflict_needs_stated_entry() {
        let path = Path::new("security.json");

        assert!(
            forbidding()
                .stance_conflict(path, Some(Class::Allowed))
                .is_some()
        );
        assert!(
            forbidding()
                .stance_conflict(path, Some(Class::Soft))
                .is_some()
        );
        assert!(forbidding().stance_conflict(path, None).is_none());
        assert!(
            forbidding()
                .stance_conflict(path, Some(Class::Hard))
                .is_none()
        );
        assert!(
            reporting()
                .stance_conflict(path, Some(Class::Allowed))
                .is_none()
        );
    }

    #[test]
    fn finding_unsuppressed_vulnerability_reported() {
        let finding = reporting().screen("CVE-1", false, None);

        assert_eq!(finding.problem, Code::VulnerabilityKnown);
        assert!(finding.suppressed_by.is_none());
    }

    /// Malware is never merely reported under the default stance.
    #[test]
    fn finding_unsuppressed_malware_forbidden() {
        let finding = reporting().screen("MAL-2024-1", true, None);

        assert_eq!(finding.problem, Code::MalwareKnown);
    }

    #[test]
    fn answer_clearing_suppresses_with_justification() {
        let statement = cleared("CVE-1", "pkg:npm/a@1");

        let finding = reporting().screen("CVE-1", false, Some(&statement));
        let suppression = finding.suppressed_by.expect("suppressed");

        assert_eq!(
            suppression.justification.as_deref(),
            Some("vulnerable_code_not_present")
        );
    }

    #[test]
    fn answer_affected_suppresses_nothing() {
        let mut statement = cleared("CVE-1", "pkg:npm/a@1");
        statement.status = Status::Affected;

        let finding = reporting().screen("CVE-1", false, Some(&statement));

        assert!(finding.suppressed_by.is_none());
        assert_eq!(finding.problem, Code::VulnerabilityKnown);
    }

    #[test]
    fn answer_under_investigation_downgrades_only() {
        let mut statement = cleared("CVE-1", "pkg:npm/a@1");
        statement.status = Status::UnderInvestigation;

        let finding = reporting().screen("CVE-1", false, Some(&statement));

        assert_eq!(finding.problem, Code::VulnerabilityUnderInvestigation);
        assert!(finding.suppressed_by.is_none());
    }

    /// The stance raises severity only for what no statement cleared.
    #[test]
    fn finding_suppressed_has_no_floor() {
        let statement = cleared("CVE-1", "pkg:npm/a@1");

        assert_eq!(
            forbidding().screen("CVE-1", false, None).floor,
            Some(Action::SkipArtifact)
        );
        assert_eq!(
            forbidding().screen("CVE-1", false, Some(&statement)).floor,
            None
        );
    }

    #[test]
    fn stance_malware_report_downgrades_to_warning() {
        let policy = SecurityPolicy {
            malware: MalwareStance::Report,
            ..Default::default()
        };

        let finding = policy.screen("MAL-1", true, None);

        assert_eq!(finding.problem, Code::VulnerabilityKnown);
    }
}
