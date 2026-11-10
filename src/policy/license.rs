//! License policy: which artifacts may be migrated, on licensing grounds.
//!
//! Mirrors `schema/license-policy.schema.json`.
//!
//! The alias table earns its place because only npm reliably declares an
//! SPDX expression.  Maven POMs carry free text -- `"The Apache Software
//! License, Version 2.0"` -- and PyPI has three competing fields, most
//! projects populating the legacy free-text one.
//!
//! References: [SPDX license expressions](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};
// Re-exported, because these are what `evaluate` answers with: a caller
// holding a policy should not have to know the outcome type lives in
// `core`, and moving it there was about who may *depend* on it, not about
// hiding it from here.
pub use crate::core::license::{Decision, Verdict};
use crate::core::problem::Code;
use crate::message;

/// A license policy file: which licenses are allowed, and per-artifact
/// rules that override them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LicensePolicy {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    #[serde(default)]
    pub allowed_licenses: Vec<SpdxRef>,

    #[serde(default)]
    pub forbidden_licenses: Vec<SpdxRef>,

    /// What to do with a license that is neither allowed nor forbidden.
    #[serde(default = "forbid")]
    pub default_behavior: Decision,

    /// What to do when the artifact declares no license at all.
    #[serde(default = "forbid")]
    pub unknown_license: Decision,

    /// SPDX expression to the names and URLs that mean it.
    #[serde(default)]
    pub aliases: BTreeMap<String, Alias>,

    #[serde(default)]
    pub artifacts: Vec<ArtifactRule>,
}

fn forbid() -> Decision {
    Decision::Forbid
}

/// The `$schema` a license policy file must declare.
pub const LICENSE_POLICY_SCHEMA_ID: &str =
    "https://github.com/groboclown/artifact-copy/schema/license-policy.schema.json";

mod evaluate;
mod matching;
mod model;

pub use model::{
    Alias, ArtifactPolicy, ArtifactRule, DetailedLicense, LicenseDeclaration, NotedSpdx, SpdxRef,
};

const LICENSE_POLICY_SCHEMA: &str = include_str!("../../schema/license-policy.schema.json");

impl LicensePolicy {
    /// Read and validate a policy file.
    pub fn load(path: &Path) -> Result<Self> {
        let value = super::read_validated(path, LICENSE_POLICY_SCHEMA, "license policy")?;

        serde_json::from_value(value).map_err(|source| {
            Error::Config(format!(
                "{} is not a usable license policy: {source}",
                path.display()
            ))
        })
    }

    /// Decide whether an artifact may be migrated.
    ///
    /// `declared` is the license exactly as the ecosystem gave it: an SPDX
    /// expression, a human-readable name, or a URL.
    pub fn evaluate(&self, purl: &str, declared: Option<&str>) -> Verdict {
        // A per-artifact rule is a deliberate human decision, so it outranks
        // everything the general tables say.
        if let Some(rule) = self.rule_for(purl)
            && let Some(verdict) = self.apply_rule(rule, declared)
        {
            return verdict;
        }

        let Some(declared) = declared.map(str::trim).filter(|text| !text.is_empty()) else {
            return Verdict::plain(
                self.unknown_license,
                None,
                message!("license-not-declared", "the artifact declares no license"),
                Some(Code::LicenseUnknown),
            );
        };

        let Some(expression) = self.resolve(declared) else {
            return Verdict::plain(
                self.unknown_license,
                None,
                message!(
                    "license-unrecognized",
                    "{declared:?} is neither an SPDX expression nor a known alias",
                    declared = declared,
                ),
                Some(Code::LicenseUnmatched),
            );
        };

        self.judge(&expression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DepKind;

    fn policy(json: &str) -> LicensePolicy {
        serde_json::from_str(json).expect("parses")
    }

    // -- The two spellings --------------------------------------------------

    /// A list may name a license plainly or with a note beside it, and the
    /// two decide identically. The note exists so the reason a license is
    /// on a list can live beside it rather than in a comment somebody
    /// deletes.
    #[test]
    fn license_noted_decides_as_plain() {
        let plain = policy(r#"{"allowed-licenses": ["MIT"], "default-behavior": "forbid"}"#);

        let noted = policy(
            r#"{"allowed-licenses": [
                 {"spdx-id": "MIT", "$comment": "approved by legal, LEG-4412"}
               ], "default-behavior": "forbid"}"#,
        );

        assert_eq!(plain.judge("MIT").decision, Decision::Allow);
        assert_eq!(noted.judge("MIT").decision, Decision::Allow);

        // And neither allows something absent from the list.
        assert_eq!(plain.judge("AGPL-3.0-only").decision, Decision::Forbid);
        assert_eq!(noted.judge("AGPL-3.0-only").decision, Decision::Forbid);
    }

    /// The same for a forbidden list, which is the direction where getting
    /// it wrong lets something through.
    #[test]
    fn license_noted_forbidden_still_forbids() {
        let noted = policy(
            r#"{"allowed-licenses": ["MIT"],
                "forbidden-licenses": [{"spdx-id": "AGPL-3.0-only"}],
                "default-behavior": "allow"}"#,
        );

        assert_eq!(noted.judge("AGPL-3.0-only").decision, Decision::Forbid);
    }

    /// An artifact rule may declare its license either way too.
    #[test]
    fn rule_accepts_both_license_forms() {
        let plain = policy(
            r#"{"allowed-licenses": ["MIT"], "default-behavior": "forbid",
                "artifacts": [{"purl": "pkg:npm/odd", "license": "MIT"}]}"#,
        );

        let detailed = policy(
            r#"{"allowed-licenses": ["MIT"], "default-behavior": "forbid",
                "artifacts": [{"purl": "pkg:npm/odd", "license": {
                  "spdx-id": "MIT",
                  "copyright": "(c) 2019 Acme Corp",
                  "uris": ["https://acme.example/LICENSE"]
                }}]}"#,
        );

        for policy in [&plain, &detailed] {
            let verdict = policy.evaluate("pkg:npm/odd", None);

            assert_eq!(verdict.decision, Decision::Allow);
            assert_eq!(verdict.spdx.as_deref(), Some("MIT"));
        }
    }

    /// **A URI on a rule is not an alias.** It is recorded for a reader and
    /// goes no further; teaching the tool to resolve a link is what the
    /// `aliases` table is for, and keeping them apart means a note cannot
    /// quietly change which artifacts are allowed.
    #[test]
    fn rule_uri_does_not_resolve_license() {
        let policy = policy(
            r#"{"allowed-licenses": ["MIT"], "default-behavior": "forbid",
                "artifacts": [{"purl": "pkg:npm/other", "license": {
                  "spdx-id": "MIT",
                  "uris": ["https://acme.example/LICENSE"]
                }}]}"#,
        );

        // An artifact the rule does not cover, declaring that very URL, is
        // still unresolvable: the URI taught the tool nothing.
        let verdict = policy.evaluate("pkg:npm/unrelated", Some("https://acme.example/LICENSE"));

        assert_ne!(verdict.decision, Decision::Allow);
    }

    /// The object form requires the id, so a rule cannot assert a licence
    /// made only of prose.
    #[test]
    fn license_detailed_must_name_spdx_id() {
        let without = serde_json::from_str::<LicensePolicy>(
            r#"{"artifacts": [{"purl": "pkg:npm/odd", "license": {"copyright": "(c) Acme"}}]}"#,
        );

        assert!(without.is_err());
    }

    fn permissive() -> LicensePolicy {
        policy(
            r#"{
                "allowed-licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
                "forbidden-licenses": ["AGPL-3.0-only"],
                "default-behavior": "forbid",
                "unknown-license": "forbid"
            }"#,
        )
    }

    #[test]
    fn license_allowed_passes() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("MIT"));

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.spdx.as_deref(), Some("MIT"));
        assert!(verdict.problem.is_none());
    }

    #[test]
    fn license_forbidden_fails() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("AGPL-3.0-only"));

        assert_eq!(verdict.decision, Decision::Forbid);
        assert_eq!(verdict.problem, Some(Code::LicenseForbidden));
    }

    /// A dual license is a choice, and the user may take the allowed side.
    #[test]
    fn expression_or_passes_if_either_allowed() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("MIT OR AGPL-3.0-only"));

        assert_eq!(verdict.decision, Decision::Allow);
    }

    /// An `AND` is not a choice: both obligations apply.
    #[test]
    fn expression_and_fails_if_either_forbidden() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("MIT AND AGPL-3.0-only"));

        assert_eq!(verdict.decision, Decision::Forbid);
    }

    #[test]
    fn license_unlisted_takes_default() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("MPL-2.0"));

        assert_eq!(verdict.decision, Decision::Forbid);
        assert_eq!(verdict.spdx.as_deref(), Some("MPL-2.0"));
    }

    #[test]
    fn license_missing_takes_unknown_branch() {
        let verdict = permissive().evaluate("pkg:npm/x@1", None);

        assert_eq!(verdict.decision, Decision::Forbid);
        assert_eq!(verdict.problem, Some(Code::LicenseUnknown));
    }

    /// The reason the alias table exists: a Maven POM's free text.
    #[test]
    fn alias_resolves_free_text_name() {
        let policy = policy(
            r#"{
                "allowed-licenses": ["Apache-2.0"],
                "aliases": {
                    "Apache-2.0": {
                        "names": ["The Apache Software License, Version 2.0"],
                        "urls": ["https://www.apache.org/licenses/LICENSE-2.0"]
                    }
                }
            }"#,
        );

        let verdict = policy.evaluate(
            "pkg:maven/g/a@1",
            Some("The Apache Software License, Version 2.0"),
        );

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.spdx.as_deref(), Some("Apache-2.0"));
    }

    /// POMs cite the `.txt` over plain HTTP; policies cite the canonical
    /// HTTPS URL.  Treating those as different would make aliases useless.
    #[test]
    fn alias_urls_ignore_scheme_and_suffix() {
        let policy = policy(
            r#"{
                "allowed-licenses": ["Apache-2.0"],
                "aliases": {
                    "Apache-2.0": {
                        "urls": ["https://www.apache.org/licenses/LICENSE-2.0"]
                    }
                }
            }"#,
        );

        let verdict = policy.evaluate(
            "pkg:maven/g/a@1",
            Some("http://www.apache.org/licenses/LICENSE-2.0.txt"),
        );

        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn license_text_unrecognized_reported_unmatched() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("SEE LICENSE IN LICENSE"));

        assert_eq!(verdict.problem, Some(Code::LicenseUnmatched));
        assert_eq!(verdict.decision, Decision::Forbid);
    }

    /// A human decision outranks the tables, and its reason reaches the
    /// report.
    #[test]
    fn rule_per_artifact_wins() {
        let policy = policy(
            r#"{
                "forbidden-licenses": ["AGPL-3.0-only"],
                "artifacts": [{
                    "purl": "pkg:npm/special@1.0.0",
                    "policy": "allow",
                    "reason": "internal use only, reviewed by legal"
                }]
            }"#,
        );

        let verdict = policy.evaluate("pkg:npm/special@1.0.0", Some("AGPL-3.0-only"));

        assert_eq!(verdict.decision, Decision::Allow);
        assert!(verdict.reason.render().contains("reviewed by legal"));
    }

    /// A versionless rule covers every version, or policy files would need
    /// an entry per release.
    #[test]
    fn rule_versionless_covers_every_version() {
        // Allows by default, so the contrast below is about which artifacts
        // the rule matches rather than about the fallback.
        let policy = policy(
            r#"{
                "default-behavior": "allow",
                "artifacts": [{
                    "purl": "pkg:npm/special",
                    "policy": "forbid",
                    "reason": "never mirror this"
                }]
            }"#,
        );

        assert_eq!(
            policy
                .evaluate("pkg:npm/special@9.9.9", Some("MIT"))
                .decision,
            Decision::Forbid
        );
        assert_eq!(
            policy
                .evaluate("pkg:npm/specialist@1", Some("MIT"))
                .decision,
            Decision::Allow
        );
    }

    /// A rule may correct a wrong declaration without deciding the outcome.
    #[test]
    fn rule_supplies_license_and_defers() {
        let policy = policy(
            r#"{
                "allowed-licenses": ["MIT"],
                "default-behavior": "forbid",
                "artifacts": [{
                    "purl": "pkg:maven/g/a@1",
                    "license": "MIT",
                    "reason": "POM omits it; upstream README says MIT"
                }]
            }"#,
        );

        let verdict = policy.evaluate("pkg:maven/g/a@1", None);

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.spdx.as_deref(), Some("MIT"));
    }

    /// The case the version qualifier exists for: a package that changes
    /// license mid-life, where forbidding the package outright would refuse
    /// the versions that are still fine.
    #[test]
    fn rule_version_glob_splits_relicensed_package() {
        let policy = policy(
            r#"{
                "allowed-licenses": ["Apache-2.0"],
                "default-behavior": "allow",
                "artifacts": [{
                    "purl": "pkg:npm/relicensed@2.*",
                    "policy": "forbid",
                    "reason": "proprietary from 2.0 onwards"
                }]
            }"#,
        );

        // The 1.x line predates the change and stays allowed.
        assert_eq!(
            policy
                .evaluate("pkg:npm/relicensed@1.9.9", Some("Apache-2.0"))
                .decision,
            Decision::Allow
        );

        for forbidden in ["pkg:npm/relicensed@2.0.0", "pkg:npm/relicensed@2.14.3"] {
            assert_eq!(
                policy.evaluate(forbidden, Some("Apache-2.0")).decision,
                Decision::Forbid,
                "{forbidden} should be refused"
            );
        }
    }

    /// Globs overlap easily, so the ordering rule needs pinning down.
    #[test]
    fn rule_first_matching_wins() {
        let policy = policy(
            r#"{
                "default-behavior": "allow",
                "artifacts": [
                    {"purl": "pkg:npm/foo@2.*", "policy": "forbid",
                     "reason": "relicensed"},
                    {"purl": "pkg:npm/foo", "policy": "allow",
                     "reason": "everything else is fine"}
                ]
            }"#,
        );

        let narrow = policy.evaluate("pkg:npm/foo@2.1.0", Some("MIT"));
        assert_eq!(narrow.decision, Decision::Forbid);
        assert!(narrow.reason.render().contains("relicensed"));

        let broad = policy.evaluate("pkg:npm/foo@1.0.0", Some("MIT"));
        assert_eq!(broad.decision, Decision::Allow);
    }

    /// The load-bearing rule: one `allow` decides the map.  The question
    /// this tool answers is whether the artifact must exist in the target,
    /// and a package cleared for test use has to be mirrored or the tests
    /// cannot run.
    #[test]
    fn usage_one_allowed_carries_artifact() {
        let policy = policy(
            r#"{
                "forbidden-licenses": ["AGPL-3.0-only"],
                "artifacts": [{
                    "purl": "pkg:maven/com.example/tool",
                    "usage": {"runtime": "forbid", "test": "allow"},
                    "reason": "test harness only; never ships"
                }]
            }"#,
        );

        let verdict = policy.evaluate("pkg:maven/com.example/tool@1.0.0", Some("AGPL-3.0-only"));

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.allowed_usages(), vec![DepKind::Test]);
        assert!(verdict.reason.render().contains("allowed for test usage"));
    }

    /// Ninety-nine forbids and one allow still allow.
    #[test]
    fn single_allow_outweighs_every_forbid() {
        let policy = policy(
            r#"{
                "artifacts": [{
                    "purl": "pkg:npm/thing",
                    "usage": {
                        "runtime": "forbid",
                        "dev": "forbid",
                        "optional": "forbid",
                        "peer": "allow"
                    }
                }]
            }"#,
        );

        let verdict = policy.evaluate("pkg:npm/thing@1.0.0", Some("MIT"));

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.allowed_usages(), vec![DepKind::Peer]);
    }

    #[test]
    fn map_of_only_forbids_forbids() {
        let policy = policy(
            r#"{
                "artifacts": [{
                    "purl": "pkg:npm/thing",
                    "usage": {"runtime": "forbid", "dev": "forbid"}
                }]
            }"#,
        );

        let verdict = policy.evaluate("pkg:npm/thing@1.0.0", Some("MIT"));

        assert_eq!(verdict.decision, Decision::Forbid);
        assert_eq!(verdict.problem, Some(Code::LicenseForbidden));
        assert!(verdict.allowed_usages().is_empty());
    }

    /// The restriction has to survive into the report, or a reader sees only
    /// "allowed" and loses it.
    #[test]
    fn usage_refusing_kept_in_verdict() {
        let policy = policy(
            r#"{
                "artifacts": [{
                    "purl": "pkg:npm/thing",
                    "usage": {"runtime": "forbid", "test": "allow"}
                }]
            }"#,
        );

        let verdict = policy.evaluate("pkg:npm/thing@1.0.0", Some("MIT"));

        assert_eq!(verdict.usage[&DepKind::Runtime], Decision::Forbid);
        assert_eq!(verdict.usage[&DepKind::Test], Decision::Allow);
    }

    /// A usage map is the more precise statement of the two.
    #[test]
    fn usage_outranks_blanket_policy() {
        let policy = policy(
            r#"{
                "artifacts": [{
                    "purl": "pkg:npm/thing",
                    "policy": "forbid",
                    "usage": {"test": "allow"}
                }]
            }"#,
        );

        assert_eq!(
            policy.evaluate("pkg:npm/thing@1.0.0", Some("MIT")).decision,
            Decision::Allow
        );
    }

    /// No usage map means the existing behavior is untouched.
    #[test]
    fn usage_map_absent_changes_nothing() {
        let verdict = permissive().evaluate("pkg:npm/x@1", Some("MIT"));

        assert_eq!(verdict.decision, Decision::Allow);
        assert!(verdict.usage.is_empty());
    }

    /// An empty policy allows nothing by default, which is the safe way round.
    #[test]
    fn policy_empty_forbids() {
        let verdict = LicensePolicy::default().evaluate("pkg:npm/x@1", Some("MIT"));

        assert_eq!(verdict.decision, Decision::Forbid);
    }
}
