//! The OSV record, as published.
//!
//! <https://ossf.github.io/osv-schema/>
//!
//! Only the parts a screening run reads. OSV records carry severity
//! vectors, references, credits and database-specific extensions that this
//! deliberately ignores: what matters here is *which artifact is affected*,
//! *what the finding is called*, and *whether it is malware*.
//!
//! # `versions` and `ranges` both, and why
//!
//! An `affected` entry may enumerate the affected versions exactly, express
//! them as `introduced`/`fixed` ranges, or both. Most records for npm, PyPI
//! and Maven carry the enumeration, because that is what the GitHub
//! Advisory Database ingestion produces; records for Go and many
//! distribution trackers carry only ranges.
//!
//! The enumeration is checked first and is the reliable half: it is string
//! equality against versions the publisher listed, with no comparator and
//! therefore no way to be subtly wrong. Ranges need an ordering, which is
//! where an answer can be *unavailable* rather than yes or no - see
//! [`super::match`](super).

use serde::{Deserialize, Serialize};

/// One advisory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Advisory {
    /// The identifier this record is published under, such as
    /// `GHSA-xxxx-xxxx-xxxx` or `MAL-2024-1234`.
    pub id: String,

    /// Other identifiers for the same finding.
    ///
    /// Load-bearing rather than decoration: a VEX statement is routinely
    /// written against the CVE while the corpus reports the GHSA, and
    /// [`SecurityPolicy::screen`](crate::policy::SecurityPolicy::screen)
    /// takes the alias list for exactly that reason.
    #[serde(default)]
    pub aliases: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// When this record was last modified upstream.
    ///
    /// Kept for the report's corpus age: a clean screening means nothing
    /// without knowing how stale the corpus behind it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,

    /// Whether the record has been withdrawn.
    ///
    /// A withdrawn advisory is one the publisher retracted, and screening
    /// against it would report a finding that is no longer claimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,

    #[serde(default)]
    pub affected: Vec<Affected>,
}

impl Advisory {
    /// Whether this record describes malware rather than a vulnerability.
    ///
    /// OSV has no field for it. The convention every producer follows is
    /// the `MAL-` identifier prefix, which is what OpenSSF's malicious
    /// packages feed mints and what OSV carries through when it ingests
    /// that feed. Checked on the aliases too, because a record ingested
    /// from elsewhere may carry the `MAL-` identity as an alias.
    ///
    /// It matters because the two take different actions:
    /// `malware-known` is a hard quarantine and `vulnerability-known` is a
    /// warning, and a malicious package reported as a mere vulnerability
    /// would be copied.
    pub fn is_malware(&self) -> bool {
        const MALWARE_PREFIX: &str = "MAL-";

        self.id.starts_with(MALWARE_PREFIX)
            || self
                .aliases
                .iter()
                .any(|alias| alias.starts_with(MALWARE_PREFIX))
    }

    /// Whether the publisher has retracted this record.
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_some()
    }
}

/// One package this advisory affects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Affected {
    #[serde(default)]
    pub package: Package,

    /// Versions listed one by one, when the publisher listed them.
    #[serde(default)]
    pub versions: Vec<String>,

    #[serde(default)]
    pub ranges: Vec<Range>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Package {
    /// OSV's ecosystem name: `npm`, `PyPI`, `Maven`, `Go`, `crates.io`.
    ///
    /// Not this tool's [`EcosystemId`](crate::model::EcosystemId) spelling,
    /// which is why the index translates rather than compares.
    #[serde(default)]
    pub ecosystem: String,

    #[serde(default)]
    pub name: String,

    /// The package URL, when the record carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// A contiguous span of affected versions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Range {
    /// `SEMVER`, `ECOSYSTEM` or `GIT`.
    #[serde(rename = "type", default)]
    pub kind: String,

    #[serde(default)]
    pub events: Vec<Event>,
}

impl Range {
    /// Whether this range is expressed in versions rather than commits.
    ///
    /// A `GIT` range names commit hashes, which no version comparator can
    /// place. Screening skips them rather than feeding a hash to a version
    /// handler and reading whatever comes back.
    pub fn is_versioned(&self) -> bool {
        !self.kind.eq_ignore_ascii_case("GIT")
    }

    /// The spans this range's events describe, in order.
    ///
    /// OSV expresses a range as a sequence of events sorted by version:
    /// `introduced` opens a span and `fixed` or `last_affected` closes it.
    /// A span left open by the last event runs to infinity, which is the
    /// ordinary shape of an unpatched advisory.
    pub fn spans(&self) -> Vec<Span> {
        let mut spans = Vec::new();
        let mut open: Option<String> = None;

        for event in &self.events {
            if let Some(introduced) = &event.introduced {
                open = Some(introduced.clone());
                continue;
            }

            // A close with nothing open is a malformed record rather than a
            // span from zero; treated as opening at the OSV zero so the
            // record still screens rather than being silently dropped.
            let from = open.take().unwrap_or_else(|| ZERO.to_owned());

            if let Some(fixed) = &event.fixed {
                spans.push(Span {
                    from,
                    until: Some(fixed.clone()),
                    inclusive: false,
                });
            } else if let Some(last) = &event.last_affected {
                spans.push(Span {
                    from,
                    until: Some(last.clone()),
                    inclusive: true,
                });
            }
        }

        if let Some(from) = open {
            spans.push(Span {
                from,
                until: None,
                inclusive: false,
            });
        }

        spans
    }
}

/// OSV's "from the beginning" sentinel.
///
/// A literal `"0"`, which is not a version in any convention here - Maven
/// would place it below everything, which happens to be right, and tags
/// cannot place it at all. Recognised by name instead, so no comparator is
/// asked about it.
pub const ZERO: &str = "0";

/// One boundary in a range.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
}

/// A half-open span of affected versions, resolved from a range's events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The first affected version, or [`ZERO`].
    pub from: String,

    /// The first *unaffected* version, or the last affected one when
    /// `inclusive`.  `None` runs to infinity.
    pub until: Option<String>,

    /// Whether `until` is itself affected.
    ///
    /// OSV's `fixed` is exclusive and `last_affected` is inclusive, and
    /// reading one as the other is an off-by-one that either misses a
    /// vulnerable release or condemns a patched one.
    pub inclusive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Advisory {
        serde_json::from_str(json).expect("parses")
    }

    #[test]
    fn record_keeps_what_screening_needs() {
        let advisory = parse(
            r#"{
              "id": "GHSA-aaaa-bbbb-cccc",
              "aliases": ["CVE-2024-0001"],
              "summary": "something bad",
              "modified": "2024-06-01T00:00:00Z",
              "affected": [{
                "package": {"ecosystem": "npm", "name": "tuna"},
                "versions": ["1.0.0", "1.0.1"],
                "ranges": [{"type": "SEMVER", "events": [
                  {"introduced": "1.0.0"}, {"fixed": "1.1.0"}
                ]}]
              }]
            }"#,
        );

        assert_eq!(advisory.id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(advisory.aliases, vec!["CVE-2024-0001"]);
        assert_eq!(advisory.affected[0].package.name, "tuna");
        assert_eq!(advisory.affected[0].versions, vec!["1.0.0", "1.0.1"]);
    }

    /// Unknown fields are ignored rather than refused: OSV grows, and a
    /// corpus that stopped parsing because a new key appeared would take
    /// screening down with it.
    #[test]
    fn record_unknown_fields_ignored() {
        let advisory = parse(
            r#"{"id": "X", "severity": [{"type": "CVSS_V3", "score": "..."}],
                "database_specific": {"anything": true}}"#,
        );

        assert_eq!(advisory.id, "X");
    }

    #[test]
    fn record_malware_recognized_by_identifier() {
        assert!(parse(r#"{"id": "MAL-2024-1"}"#).is_malware());
        assert!(parse(r#"{"id": "OSV-1", "aliases": ["MAL-2024-1"]}"#).is_malware());
        assert!(!parse(r#"{"id": "GHSA-x", "aliases": ["CVE-1"]}"#).is_malware());
    }

    #[test]
    fn record_withdrawn_says_so() {
        assert!(parse(r#"{"id": "X", "withdrawn": "2024-06-01T00:00:00Z"}"#).is_withdrawn());
        assert!(!parse(r#"{"id": "X"}"#).is_withdrawn());
    }

    // -- Spans ------------------------------------------------------------

    fn spans(events: &str) -> Vec<Span> {
        let range: Range =
            serde_json::from_str(&format!(r#"{{"type":"SEMVER","events":{events}}}"#))
                .expect("parses");

        range.spans()
    }

    #[test]
    fn span_introduced_fixed_half_open() {
        let spans = spans(r#"[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]"#);

        assert_eq!(
            spans,
            vec![Span {
                from: "1.0.0".into(),
                until: Some("1.1.0".into()),
                inclusive: false,
            }]
        );
    }

    /// `last_affected` is inclusive where `fixed` is not, and reading one as
    /// the other is an off-by-one in a security answer.
    #[test]
    fn span_last_affected_closes_inclusively() {
        let spans = spans(r#"[{"introduced":"1.0.0"},{"last_affected":"1.1.0"}]"#);

        assert!(spans[0].inclusive);
        assert_eq!(spans[0].until.as_deref(), Some("1.1.0"));
    }

    /// The ordinary shape of an unpatched advisory.
    #[test]
    fn span_unclosed_runs_to_infinity() {
        let spans = spans(r#"[{"introduced":"1.0.0"}]"#);

        assert_eq!(spans[0].until, None);
    }

    #[test]
    fn span_several_in_range_kept_apart() {
        let spans = spans(
            r#"[{"introduced":"1.0.0"},{"fixed":"1.1.0"},
                {"introduced":"2.0.0"},{"fixed":"2.0.5"}]"#,
        );

        assert_eq!(spans.len(), 2);
        assert_eq!(spans[1].from, "2.0.0");
    }

    #[test]
    fn span_opening_at_zero_recognized() {
        let spans = spans(r#"[{"introduced":"0"},{"fixed":"1.0.0"}]"#);

        assert_eq!(spans[0].from, ZERO);
    }

    #[test]
    fn range_git_not_versioned() {
        let range: Range = serde_json::from_str(
            r#"{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]}"#,
        )
        .expect("parses");

        assert!(!range.is_versioned());
    }
}
