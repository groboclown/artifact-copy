//! Per-artifact overrides of how quarantine issues are handled.
//!
//! The configuration's `problem-policy` table says what the rules are, for
//! every artifact a run touches. This file says which **specific artifacts**
//! are exceptions to them, and why.
//!
//! Keeping the two apart is the rule the whole configuration follows, and
//! it earns its keep three ways: an exception is reviewable on its own in a
//! pull request rather than buried among host definitions; it carries a
//! justification, because one nobody can re-evaluate is one nobody will
//! dare remove; and it is edited on a completely different cadence from the
//! configuration around it, usually by a different person.
//!
//! # One expiry field, two spellings
//!
//! Every rule states when it lapses: a date, or the word `never`. It is
//! required, and *never* has to be written out.
//!
//! An acknowledgement with no end date should be a decision somebody made
//! and wrote down, not what happens when a field is left out -- and one
//! field with two spellings beats two fields that can contradict each
//! other, which is what an optional date beside an `open-ended` flag would
//! have been.
//!
//! # It overrides in both directions
//!
//! Loosening is the common case -- *this one is a false positive* -- but a
//! rule may name any of the four classes, so tightening a single artifact
//! is as expressible as excusing one. That is why this is not called an
//! *allow* file.
//!
//! # Versions are ranges, not globs
//!
//! `pkg:npm/tuna@<2` means every npm version below 2 **by npm's own
//! ordering**. The license policy matches purls textually, and its own
//! documentation names the limitation: a glob cannot say "7.11 and later",
//! so covering a change means listing `@7.11.*`, `@7.12.*`, `@8.*` and
//! adding an entry at every new major. This is that successor, and the
//! motivating case is the same one -- *these versions were published before
//! the credentials leaked, and the ones after were not*.
//!
//! Which means matching here has to ask the artifact's ecosystem rather
//! than compare strings, and a rule for an ecosystem this build cannot
//! parse is refused when it is read rather than silently matching nothing.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};
use crate::core::expiry::Expiry;
use crate::core::problem::{Class, Code};
use crate::model::{ArtifactId, Version};

/// The `$schema` a quarantine policy file must declare.
pub const QUARANTINE_POLICY_SCHEMA_ID: &str =
    "https://github.com/groboclown/artifact-copy/schema/quarantine-policy.schema.json";

const QUARANTINE_POLICY_SCHEMA: &str = include_str!("../../schema/quarantine-policy.schema.json");

/// A file of per-artifact overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QuarantinePolicy {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    /// Where this was read from, for a report that can point a reader at
    /// the entry that excused an artifact.
    ///
    /// Not part of the file: set by [`QuarantinePolicy::load`], and empty
    /// for one built in memory. An acknowledgement nobody can find again is
    /// most of the way to an acknowledgement nobody reviews.
    #[serde(skip)]
    source: std::path::PathBuf,

    /// Checked in order; the first rule matching both the artifact and the
    /// code wins.
    ///
    /// Order rather than specificity, because "most specific wins" needs a
    /// definition of specific that survives ranges and nobody agrees on
    /// one. First-wins is what a reader can follow down the page.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// One artifact's exception.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,

    /// Which artifact, with an optional version **range**.
    pub purl: String,

    /// Which codes this rule answers.
    ///
    /// Required, and there is deliberately no way to say *every code for
    /// this artifact*: excusing a missing signature should not thereby
    /// excuse a malware finding on the same one.
    pub codes: Vec<Code>,

    /// How those codes are handled for this artifact.
    pub class: Class,

    /// Why this is acceptable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    /// When this lapses, or [`Expiry::Never`].
    ///
    /// Required, and *never* has to be written out. An acknowledgement with
    /// no end date should be a decision somebody made, not what happens
    /// when a field is left out.
    ///
    /// After it lapses, the artifact falls back to the `problem-policy`
    /// default.
    pub expires: Expiry,
}

impl Rule {
    /// Whether this rule still applies at `now`.
    pub fn in_force(&self, now: DateTime<Utc>) -> bool {
        self.expires.in_force(now)
    }
}

impl QuarantinePolicy {
    /// Read and validate a policy file.
    pub fn load(path: &Path) -> Result<Self> {
        let value = super::read_validated(path, QUARANTINE_POLICY_SCHEMA, "quarantine policy")?;

        let mut policy: Self = serde_json::from_value(value).map_err(|source| {
            Error::Config(format!(
                "{} is not a usable quarantine policy: {source}",
                path.display()
            ))
        })?;

        policy.source = path.to_path_buf();

        Ok(policy)
    }

    /// The file this was read from, empty for one built in memory.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Where a reader will find the rule at `index`.
    ///
    /// File and position, because a rule has no name of its own and the
    /// file is ordered: "the third rule" is how somebody finds it, and
    /// first-match-wins makes the position meaningful rather than
    /// incidental. One-based, since that is how a person counts down a
    /// page.
    pub fn cite(&self, index: usize) -> String {
        match self.source.as_os_str().is_empty() {
            true => format!("quarantine policy rule {}", index + 1),
            false => format!("{} rule {}", self.source.display(), index + 1),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rule answering this artifact and code, if any.
    ///
    /// **First match in file order wins.** Not most-specific-wins, because
    /// "specific" needs a definition that survives ranges and nobody agrees
    /// on one; first-wins is what a reader can follow down the page, and it
    /// makes a narrow rule above a broad one do what it looks like it does.
    ///
    /// The rule is returned rather than just its class, because a caller
    /// needs the justification and the expiry to put in the report -- the
    /// point of an override is not only that it happened but who decided
    /// it and on what grounds. Its **index** comes with it for the same
    /// reason: see [`QuarantinePolicy::cite`].
    pub fn rule_for(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        code: Code,
        now: DateTime<Utc>,
    ) -> Option<(usize, &Rule)> {
        // Resolved once rather than per rule: a policy with fifty entries
        // would otherwise build the ecosystem fifty times for one artifact.
        let ecosystem = crate::ecosystem::open(id.ecosystem().as_str()).ok();

        self.rules.iter().enumerate().find(|(_, rule)| {
            rule.codes.contains(&code)
                && rule.in_force(now)
                && rule.covers(id, version, ecosystem.as_deref())
        })
    }
}

impl Rule {
    /// Whether this rule's purl names this artifact at this version.
    ///
    /// Two halves, matched differently on purpose:
    ///
    /// - The **name** is a glob, so `pkg:npm/%40acme/*` covers a scope.
    ///   Same rule the license policy uses, so a user who has written one
    ///   has not learned a second syntax.
    /// - The **version** is an ecosystem range, so `@<2` means what npm
    ///   means by it. A glob could not say "below 2" without listing the
    ///   majors, which is exactly the limitation the license policy
    ///   documents and this is the successor to.
    ///
    /// A rule naming no version covers every version.
    ///
    /// An artifact with no version is covered only by such a rule. A range
    /// asks a question -- is this below 2 -- that an artifact without a
    /// version cannot answer, and answering it "yes" would let a rule
    /// written about npm versions reach every file in a raw repository.
    fn covers(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ecosystem: Option<&dyn crate::ecosystem::Ecosystem>,
    ) -> bool {
        crate::internal::purl::pattern::covers(&self.purl, id, version, ecosystem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("quarantine-policy.yaml");

        std::fs::write(
            &path,
            format!("$schema: {QUARANTINE_POLICY_SCHEMA_ID}\n{body}"),
        )
        .expect("written");

        (dir, path)
    }

    #[test]
    fn committed_schema_compiles() {
        let schema: serde_json::Value =
            serde_json::from_str(QUARANTINE_POLICY_SCHEMA).expect("parses");

        jsonschema::validator_for(&schema).expect("compiles");
    }

    /// The motivating case, written the way the user would.
    #[test]
    fn load_dated_exception() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/tuna@<2"
    codes: [signature-key-revoked]
    class: allowed
    justification: "published before the credentials leaked"
    expires: "2027-01-01T00:00:00Z"
"#,
        );

        let policy = QuarantinePolicy::load(&path).expect("loads");
        let rule = &policy.rules[0];

        assert_eq!(rule.purl, "pkg:npm/tuna@<2");
        assert_eq!(rule.codes, vec![Code::SignatureKeyRevoked]);
        assert_eq!(rule.class, Class::Allowed);
        assert!(rule.justification.is_some());
        assert_eq!(
            rule.expires,
            Expiry::At(
                DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
                    .expect("valid")
                    .with_timezone(&Utc),
            )
        );
    }

    /// Tightening one artifact is as expressible as excusing one, which is
    /// why the file is not called an *allow* file.
    #[test]
    fn rule_may_tighten_or_loosen() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/sketchy"
    codes: [signature-missing]
    class: failure
    expires: never
"#,
        );

        let policy = QuarantinePolicy::load(&path).expect("loads");

        assert_eq!(policy.rules[0].class, Class::Failure);
        assert_eq!(policy.rules[0].expires, Expiry::Never);
    }

    /// Omitting it entirely is refused: an acknowledgement with no end date
    /// has to be a decision somebody wrote down.
    #[test]
    fn load_expires_required() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/tuna"
    codes: [signature-missing]
    class: allowed
"#,
        );

        let err = QuarantinePolicy::load(&path).expect_err("no expiry");

        assert!(err.to_string().contains("expires"), "{err}");
    }

    /// Excusing a missing signature must not thereby excuse a malware
    /// finding on the same artifact, so there is no "every code" spelling.
    #[test]
    fn load_rule_needs_code() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/tuna"
    codes: []
    class: allowed
    expires: never
"#,
        );

        assert!(QuarantinePolicy::load(&path).is_err());
    }

    /// A code that says nothing about an artifact has no artifact whose
    /// exception would mean anything, so the file does not offer the
    /// choice -- the tool's own state, and requests it cannot serve.
    #[test]
    fn code_without_artifact_not_overridable() {
        for code in [
            // The tool's own state.
            "unimplemented",
            "aborted",
            // A fault in the input the run was given.
            "config-invalid",
            "config-unreadable",
            "file-unreadable",
            "enumeration-unsupported",
            "sample-percent-unsupported",
            "lock-format-unknown",
            "lock-unrecognized",
            "lock-malformed",
        ] {
            let (_dir, path) = write(&format!(
                "rules:\n  - purl: \"pkg:npm/tuna\"\n    codes: [{code}]\n    class: allowed\n    expires: never\n"
            ));

            let err = QuarantinePolicy::load(&path).expect_err("not a code about an artifact");

            assert!(err.to_string().contains(code), "{err}");
        }
    }

    /// Not a classic quarantine, and still an artifact issue a user may
    /// want to state a handling for. The file is per-artifact *problem
    /// handling*; quarantine is its main use rather than its whole subject.
    #[test]
    fn offer_artifact_issue_not_quarantine_shaped() {
        for code in [Code::DependencyUnresolved, Code::PomPropertyUnresolved] {
            assert!(code.concerns_an_artifact(), "{code}");
        }
    }

    /// The schema's list is checked against the enum, or a code added in
    /// Rust becomes one the file silently rejects.
    #[test]
    fn schema_offers_every_overridable_code() {
        let schema: serde_json::Value =
            serde_json::from_str(QUARANTINE_POLICY_SCHEMA).expect("parses");

        let offered: Vec<&str> = schema["$defs"]["Rule"]["properties"]["codes"]["items"]["enum"]
            .as_array()
            .expect("an enum")
            .iter()
            .map(|name| name.as_str().expect("a string"))
            .collect();

        for code in Code::all() {
            assert_eq!(
                offered.contains(&code.as_str()),
                code.concerns_an_artifact(),
                "{code} concerns an artifact={} but offered={}",
                code.concerns_an_artifact(),
                offered.contains(&code.as_str()),
            );
        }

        assert_eq!(
            offered.len(),
            Code::all()
                .iter()
                .filter(|code| code.concerns_an_artifact())
                .count()
        );
    }

    #[test]
    fn load_code_misspelled_refused() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/tuna"
    codes: [signature-mising]
    class: allowed
    expires: never
"#,
        );

        let err = QuarantinePolicy::load(&path).expect_err("not a code");

        assert!(err.to_string().contains("signature-mising"), "{err}");
    }

    #[test]
    fn rule_dated_lapses() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/tuna"
    codes: [signature-missing]
    class: allowed
    expires: "2020-01-01T00:00:00Z"
"#,
        );

        let policy = QuarantinePolicy::load(&path).expect("loads");

        assert!(!policy.rules[0].in_force(Utc::now()));
        assert!(
            policy.rules[0].in_force(
                DateTime::parse_from_rfc3339("2019-01-01T00:00:00Z")
                    .expect("valid")
                    .with_timezone(&Utc)
            )
        );
    }

    /// A rule saying `never` never lapses, which is what it says.
    #[test]
    fn rule_expiring_never_stays_in_force() {
        let (_dir, path) = write(
            r#"
rules:
  - purl: "pkg:npm/tuna"
    codes: [signature-missing]
    class: allowed
    expires: never
"#,
        );

        let policy = QuarantinePolicy::load(&path).expect("loads");

        assert!(policy.rules[0].in_force(Utc::now()));
    }

    /// A file with no rules is legal and means nothing is excepted, which
    /// is what an empty starting point should do.
    #[test]
    fn load_empty_policy() {
        let (_dir, path) = write("rules: []\n");

        assert!(QuarantinePolicy::load(&path).expect("loads").is_empty());
    }

    // -- Matching ----------------------------------------------------------

    use crate::model::{EcosystemId, Release};

    fn npm(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, name)
    }

    fn at(text: &str) -> Version {
        Version::new(text, Release::General)
    }

    fn policy(body: &str) -> QuarantinePolicy {
        let (_dir, path) = write(body);
        // The directory outlives the read, which is all that matters.
        QuarantinePolicy::load(&path).expect("loads")
    }

    fn rules(purl: &str) -> QuarantinePolicy {
        policy(&format!(
            "rules:\n  - purl: \"{purl}\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n"
        ))
    }

    fn matched(policy: &QuarantinePolicy, id: &ArtifactId, version: &str) -> bool {
        policy
            .rule_for(id, Some(&at(version)), Code::SignatureMissing, Utc::now())
            .is_some()
    }

    /// A rule naming no version covers every version.
    #[test]
    fn match_versionless_rule_covers_every_version() {
        let policy = rules("pkg:npm/tuna");

        assert!(matched(&policy, &npm("tuna"), "1.0.0"));
        assert!(matched(&policy, &npm("tuna"), "99.0.0"));

        // And does not reach a longer name.
        assert!(!matched(&policy, &npm("tunafish"), "1.0.0"));
    }

    /// The motivating case, and the reason the version half is a range
    /// rather than a glob: "everything before the leak" is one expression.
    #[test]
    fn match_version_range_read_by_ecosystem() {
        let policy = rules("pkg:npm/tuna@<2");

        assert!(matched(&policy, &npm("tuna"), "1.9.9"));
        assert!(!matched(&policy, &npm("tuna"), "2.0.0"));
        assert!(!matched(&policy, &npm("tuna"), "10.0.0"));
    }

    /// A glob would have had to list the majors to say the same thing, and
    /// would get this one wrong: `1.*` does not cover `1.10` in any
    /// ordering a person means by "below 2".
    #[test]
    fn match_range_orders_numerically() {
        let policy = rules("pkg:npm/tuna@<2");

        assert!(matched(&policy, &npm("tuna"), "1.10.0"));
        assert!(matched(&policy, &npm("tuna"), "1.2.0"));
    }

    #[test]
    fn match_exact_version_only_itself() {
        let policy = rules("pkg:npm/tuna@1.0.0");

        assert!(matched(&policy, &npm("tuna"), "1.0.0"));
        assert!(!matched(&policy, &npm("tuna"), "1.0.1"));
    }

    /// The name half is a glob, the same one the license policy uses, so a
    /// user who has written one has not learned a second syntax.
    #[test]
    fn match_name_half_is_glob() {
        let policy = rules("pkg:npm/%40acme/*");

        assert!(matched(
            &policy,
            &ArtifactId::new(EcosystemId::npm(), Some("@acme"), "tool"),
            "1.0.0"
        ));
        assert!(!matched(
            &policy,
            &ArtifactId::new(EcosystemId::npm(), Some("@other"), "tool"),
            "1.0.0"
        ));
    }

    /// A rule answers only the codes it names. Excusing a missing signature
    /// must not excuse a malware finding on the same artifact.
    #[test]
    fn match_rule_answers_only_own_codes() {
        let policy = rules("pkg:npm/tuna");

        assert!(
            policy
                .rule_for(
                    &npm("tuna"),
                    Some(&at("1.0.0")),
                    Code::MalwareKnown,
                    Utc::now()
                )
                .is_none()
        );
    }

    /// A lapsed rule stops matching, which is what the date is for.
    #[test]
    fn rule_lapsed_does_not_match() {
        let policy = policy(
            "rules:\n  - purl: \"pkg:npm/tuna\"\n    codes: [signature-missing]\n    class: allowed\n    expires: \"2020-01-01T00:00:00Z\"\n",
        );

        assert!(!matched(&policy, &npm("tuna"), "1.0.0"));
    }

    /// First match in file order wins, so a narrow rule above a broad one
    /// does what it looks like it does.
    #[test]
    fn match_first_rule_wins() {
        let policy = policy(
            "rules:\n\
             \x20 - purl: \"pkg:npm/tuna@<2\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n\
             \x20 - purl: \"pkg:npm/*\"\n    codes: [signature-missing]\n    class: failure\n    expires: never\n",
        );

        let narrow = policy
            .rule_for(
                &npm("tuna"),
                Some(&at("1.0.0")),
                Code::SignatureMissing,
                Utc::now(),
            )
            .expect("matched");

        assert_eq!(narrow.0, 0, "the first rule in file order");
        assert_eq!(narrow.1.class, Class::Allowed);

        // Outside the narrow rule's range, the broad one answers.
        let broad = policy
            .rule_for(
                &npm("tuna"),
                Some(&at("3.0.0")),
                Code::SignatureMissing,
                Utc::now(),
            )
            .expect("matched");

        assert_eq!(broad.0, 1);
        assert_eq!(broad.1.class, Class::Failure);
    }

    /// A matched rule carries what the report needs: who decided, and on
    /// what grounds.
    #[test]
    fn cite_matched_rule_carries_justification() {
        let policy = policy(
            "rules:\n  - purl: \"pkg:npm/tuna\"\n    codes: [signature-missing]\n    class: allowed\n    justification: \"reviewed\"\n    expires: never\n",
        );

        let rule = policy
            .rule_for(
                &npm("tuna"),
                Some(&at("1.0.0")),
                Code::SignatureMissing,
                Utc::now(),
            )
            .expect("matched");

        assert_eq!(rule.1.justification.as_deref(), Some("reviewed"));
        assert_eq!(
            rule.1.class.disposition(Code::SignatureMissing).quarantine,
            None
        );
    }

    /// A rule has no name of its own, so a report cites it by file and
    /// position -- which is how somebody actually finds it, and what makes
    /// first-match-wins visible to a reader of the report rather than only
    /// to a reader of the file.
    #[test]
    fn cite_rule_by_file_and_position() {
        let (_dir, path) = write(
            "rules:\n  - purl: \"pkg:npm/tuna\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n",
        );

        let policy = QuarantinePolicy::load(&path).expect("loads");
        let cited = policy.cite(0);

        assert!(cited.contains("quarantine-policy.yaml"), "{cited}");

        // One-based, because that is how a person counts down a page.
        assert!(cited.ends_with("rule 1"), "{cited}");
    }

    /// A policy built in memory has no file to cite, and says so rather
    /// than naming an empty path.
    #[test]
    fn cite_position_without_file() {
        assert_eq!(
            QuarantinePolicy::default().cite(2),
            "quarantine policy rule 3"
        );
    }
}
