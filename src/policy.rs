//! Policy files: what may be migrated, and why.
//!
//! Two policies, deliberately the same shape.  The license policy answers
//! "are we allowed to redistribute this"; the security policy answers "is
//! this known to be dangerous".  Both are separate files referenced by path,
//! both key artifacts on purl, and both let a human record a documented
//! exception.

use std::path::Path;

use serde_json::Value;

use crate::core::error::{Error, Result};

mod disposition;
mod license;
mod quarantine;
mod security;
mod signing;
mod vex;

pub(crate) use crate::internal::purl::pattern::version_of;
pub use disposition::{Decided, Dispositions, Hardening};
pub use license::{
    Alias, ArtifactPolicy, ArtifactRule, Decision, DetailedLicense, LICENSE_POLICY_SCHEMA_ID,
    LicenseDeclaration, LicensePolicy, NotedSpdx, SpdxRef, Verdict,
};
pub use quarantine::{QUARANTINE_POLICY_SCHEMA_ID, QuarantinePolicy, Rule as QuarantineRule};
pub use security::{
    Finding, MalwareStance, SECURITY_POLICY_SCHEMA_ID, SecurityPolicy, SecurityPolicyFile,
    Suppression, VulnerabilityStance,
};
pub use signing::{Rule as SigningRule, SIGNING_POLICY_SCHEMA_ID, SigningPolicy};
pub use vex::{Document as VexDocument, Statement, Status, parse as parse_vex};

/// Read a policy file as JSON or YAML and validate it against its schema.
///
/// Shared by both policies so their error messages, format handling, and
/// all-violations-at-once reporting stay identical.
fn read_validated(path: &Path, schema_text: &str, what: &str) -> Result<Value> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    let is_json = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));

    let document: Value = if is_json {
        serde_json::from_str(&text).map_err(|source| {
            Error::Config(format!("{} is not valid JSON: {source}", path.display()))
        })?
    } else {
        serde_norway::from_str(&text).map_err(|source| {
            Error::Config(format!("{} is not valid YAML: {source}", path.display()))
        })?
    };

    let schema: Value = serde_json::from_str(schema_text)
        .map_err(|source| Error::Config(format!("built-in {what} schema is broken: {source}")))?;

    let validator = jsonschema::validator_for(&schema)
        .map_err(|source| Error::Config(format!("built-in {what} schema is broken: {source}")))?;

    // Every violation at once: a policy with four mistakes should cost one
    // run to fix, not four.
    let problems: Vec<String> = validator
        .iter_errors(&document)
        .map(|err| format!("  {}", crate::internal::schema::violation("", &err)))
        .collect();

    if !problems.is_empty() {
        return Err(Error::Config(format!(
            "{} does not match the {what} schema:\n{}",
            path.display(),
            problems.join("\n")
        )));
    }

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("configuration")
            .join(name)
    }

    /// Catches the license schema and its model drifting apart.
    #[test]
    fn shipped_license_policy_loads() {
        let policy = LicensePolicy::load(&example("license-policy.yaml"))
            .expect("the shipped example must stay loadable");

        assert_eq!(policy.default_behavior, Decision::Forbid);

        // The alias table is the reason this file exists: a Maven POM's free
        // text has to reach an SPDX expression.
        let verdict = policy.evaluate(
            "pkg:maven/g/a@1",
            Some("The Apache Software License, Version 2.0"),
        );

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.spdx.as_deref(), Some("Apache-2.0"));
    }

    /// The example's relicensed package: the 2.x line is refused and the
    /// 1.x line, which predates the change, is not.
    #[test]
    fn shipped_license_policy_honors_its_version_glob() {
        let policy = LicensePolicy::load(&example("license-policy.yaml")).expect("loads");

        assert_eq!(
            policy
                .evaluate("pkg:npm/example-relicensed@2.0.0", Some("MIT"))
                .decision,
            Decision::Forbid
        );

        assert_eq!(
            policy
                .evaluate("pkg:npm/example-relicensed@1.9.9", Some("MIT"))
                .decision,
            Decision::Allow
        );
    }

    /// The example's AGPL test harness: forbidden at runtime, allowed for
    /// test, and therefore mirrored.
    #[test]
    fn shipped_license_policy_honors_its_usage_rule() {
        use crate::model::DepKind;

        let policy = LicensePolicy::load(&example("license-policy.yaml")).expect("loads");

        let verdict = policy.evaluate(
            "pkg:maven/com.example/agpl-test-harness@1.0.0",
            Some("AGPL-3.0-only"),
        );

        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.allowed_usages(), vec![DepKind::Test]);
        assert_eq!(verdict.usage[&DepKind::Runtime], Decision::Forbid);
    }

    #[test]
    fn shipped_signing_policy_loads() {
        let policy = SigningPolicy::load(&example("signing-policy.yaml"))
            .expect("the shipped example must stay loadable");

        assert_eq!(policy.rules.len(), 2);
    }

    #[test]
    fn shipped_security_policy_loads() {
        let policy = SecurityPolicy::load(&example("security-policy.yaml"))
            .expect("the shipped example must stay loadable");

        // Malware is refused, whatever any VEX document says.
        let malware = policy.screen("MAL-2024-1", true, None);
        assert_eq!(malware.problem, crate::core::problem::Code::MalwareKnown);
    }
}
