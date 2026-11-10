//! What one line of a report is.
//!
//! Types and conversions only: nothing here reads or writes anything, and
//! the `From` impls are the crate's internal shapes becoming the published
//! ones. That boundary is the point of the file -- a [`Problem`] may be
//! reorganized freely, and a [`ProblemRecord`] may not, because somebody's
//! tooling reads it.
//!
//! A [`Record`] is externally tagged on `record`, so a reader that meets a
//! kind it does not know can skip the line rather than fail the file.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::advisory::{CorpusAge, Screening};
use crate::core::message::Message;
use crate::core::problem::{Action, Bypass, Code, Problem, Quarantine};
use crate::core::screened::{Category, Certainty, Flag};
use crate::model::{Cause, DepKind, Digest, LastDownload, ResolvedArtifact, SigRef};
use crate::policy::{Decision, Suppression, Verdict};

/// One line of a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "kebab-case")]
pub enum Record {
    /// Opens the stream.  States what produced it and what it screened
    /// against -- a clean report means nothing without knowing how stale the
    /// advisory data behind it was.
    Header(Header),

    Artifact(Box<ArtifactRecord>),

    Problem(ProblemRecord),

    /// Closes the stream.  Its absence means the run did not finish.
    Summary(Summary),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Header {
    pub created: DateTime<Utc>,
    pub tool_version: String,
    pub command: String,

    /// What became of each configured advisor, by advisor name.
    ///
    /// **Always written, even empty**, which is the one thing that makes the
    /// field worth having. An omitted key and "nothing screened this run"
    /// would otherwise be the same bytes, and
    /// `docs/contributors/exit-codes.md` turns on a reader being able to
    /// tell a clean run from an unscreened one: "a run that copies everything
    /// and reports nothing looks identical to a clean run, and would be read
    /// as one".
    ///
    /// An empty map with the key present says no advisor was configured,
    /// which is unambiguous. A configured advisor always has an entry, and
    /// [`CorpusAge`] says whether it answered and why not.
    #[serde(default)]
    pub corpus_age: BTreeMap<String, CorpusAge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArtifactRecord {
    pub purl: String,

    /// The exact version, when one is known.
    ///
    /// Absent for a catalog that lists **names only** -- npm's replication
    /// feed is one, and the versions would cost a packument each. A
    /// `find` inventory of such a repository honestly has no version
    /// to give, and inventing one or writing an empty string would both be
    /// worse than saying so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// What was asked for, when the request is worth keeping beside the
    /// answer.
    ///
    /// Written for a request that resolved to nothing, where `version` is
    /// absent for a second reason and a reader could not otherwise tell
    /// "this catalog lists names only" from "`tuna@^4` matched nothing".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,

    /// What the run did with this artifact, when it was a run that acts.
    ///
    /// Absent for `inspect` and `find`, which report rather than do --
    /// an outcome of "inspected" would say nothing the record's existence
    /// does not already say. `copy` writes one for every artifact it
    /// reaches, so a run can be audited afterwards for what it took and
    /// what it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,

    /// What became of the artifact at each target, in `--to` order, when a
    /// copy had several. `outcome` is then the worst of them, so a reader
    /// of one-target reports sees no change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<DestinationOutcome>,

    /// When the repository last served this artifact.
    ///
    /// Only an enumerator knows it, and only some do. It is the thing a
    /// `find` inventory exists to collect: what a repository holds and
    /// nobody has asked for in two years is what a migration leaves
    /// behind.
    #[serde(default, skip_serializing_if = "LastDownload::is_unknown")]
    pub last_download: LastDownload,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileRecord>,

    /// The license exactly as the ecosystem declared it, before evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_license: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseRecord>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<AdvisoryRecord>,

    /// Reservations held against this artifact, and what became of them.
    ///
    /// A list rather than one value, because an artifact can trip several
    /// at once -- an unsigned release inside the publish window trips two --
    /// and collapsing them would lose which one a reviewer has to answer.
    ///
    /// Shaped like [`ArtifactRecord::advisories`] deliberately: both are
    /// *findings against this artifact, each possibly cleared by an
    /// explicit statement elsewhere*, and a reader who has learned one
    /// shape should not have to learn a second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<QuarantineRecord>,

    /// Why this artifact was looked at, leaf first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<Message>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FileRecord {
    pub name: String,
    pub url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<Digest>,

    /// A PEP 658 core-metadata document beside the file, with the digests
    /// the index published for it. As `FileRef.core_metadata`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_metadata: Option<Vec<Digest>>,

    /// The signatures the registry declared for the file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SigRef>,

    /// Whether the bytes were actually checked, and how far.
    pub verification: Verification,

    /// Who named this file: an artifact enumeration, or a resolution.
    ///
    /// Defaulted for a record written before artifact enumerations listed
    /// files, when only a resolution could name one.
    #[serde(default)]
    pub origin: FileOrigin,
}

/// Who named a file of an artifact.
///
/// Kept apart because the two are different claims: a catalog saying a
/// file is there, and a source saying what the artifact is.
/// `repo::InventorySource` combines them; see
/// `docs/contributors/sources-and-targets.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileOrigin {
    /// An enumerator listed it.
    Listed,

    /// A resolution named it, including one combined with a listing.
    #[default]
    Resolved,
}

/// How much of a file's integrity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    /// Nothing was downloaded, so nothing was checked.  Expected for
    /// `inspect`, which reports rather than fetches.
    NotAttempted,

    /// The registry declared no digest to check against.
    NoDigestDeclared,

    /// Only a collision-broken digest was available.
    WeakDigestOnly,

    /// Checked against a collision-resistant digest.
    Verified,

    /// Checked, and wrong.
    Failed,
}

/// What a run that acts on artifacts did with one.
///
/// Every artifact a `copy` reaches gets one, including the ones it did not
/// take. That is the whole point: a report listing only what was copied
/// answers "what is in the target", which the target itself answers
/// better. Listing what was *not* copied, with the reason, is the question
/// only the run can answer, and only while it is running.
/// What became of an artifact at one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DestinationOutcome {
    /// The configured target's name.
    pub destination: String,

    pub outcome: Outcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Outcome {
    /// Fetched, checked and written to the target.
    Copied { verification: Verification },

    /// The target already held this exact version, so nothing was sent.
    AlreadyPresent,

    /// Resolved, and then refused by a problem's disposition.
    ///
    /// A policy decision, not a failure: the artifact exists and could have
    /// been copied. The reason is what a user needs to either accept the
    /// refusal or write a rule that overrides it.
    Refused { why: Box<ProblemRecord> },

    /// The request matched no artifact, so there was nothing to copy.
    Unresolved { why: Box<ProblemRecord> },

    /// Resolved and permitted, but the copy itself did not succeed.
    ///
    /// Distinct from `refused`: nothing decided against this artifact, the
    /// transfer just failed, and re-running may well take it.
    Failed { why: Box<ProblemRecord> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LicenseRecord {
    pub decision: Decision,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx: Option<String>,

    /// Why the decision was reached, as an identifier plus arguments.
    pub reason: Message,

    /// Per-usage decisions, when a policy rule carried a `usage` map.
    ///
    /// One allowed usage is enough to migrate the artifact, so this is where
    /// the usages that refused it are recorded.  Without it a reader would
    /// see only "allowed" and lose the restriction entirely.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub usage: BTreeMap<DepKind, Decision>,
}

impl From<&Verdict> for LicenseRecord {
    fn from(verdict: &Verdict) -> Self {
        Self {
            decision: verdict.decision,
            spdx: verdict.spdx.clone(),
            reason: verdict.reason.clone(),
            usage: verdict.usage.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AdvisoryRecord {
    pub id: String,

    /// The configured advisor whose corpus supplied the record.
    pub advisor: String,

    /// Malware or a vulnerability.
    pub kind: Category,

    /// Whether the version was shown to be affected, or could not be
    /// compared with the advisory at all.
    #[serde(rename = "match")]
    pub certainty: Certainty,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// The VEX statement that cleared this, with its justification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<SuppressionRecord>,
}

/// One reservation held against an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct QuarantineRecord {
    /// What was reserved about.
    pub code: Code,

    /// How firmly: `soft` flagged it, `hard` held it back.
    pub class: Quarantine,

    /// Whether the run's strictness, rather than the class, held this back.
    ///
    /// A hardened `soft` and a `hard` both stop an artifact, and they are
    /// not the same statement: the first says *this run was strict* and
    /// would not have stopped it yesterday, the second says *this
    /// reservation stops things*. Without this, a report cannot tell a
    /// reader which of the two happened, and the obvious fix -- recording
    /// the class as `hard` -- would be a lie about what the policy says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hardened: bool,

    /// The acknowledgement that let this through, when one did.
    ///
    /// **Present is the interesting case.** A reservation that held an
    /// artifact back is visible in the fact that the artifact is missing; a
    /// reservation somebody waved through is visible nowhere else, and is
    /// exactly what an auditor is looking for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypassed_by: Option<BypassRecord>,
}

/// An acknowledgement from the quarantine policy file.
///
/// Deliberately shaped like [`SuppressionRecord`] rather than reusing it:
/// they answer the same question -- *who decided this was acceptable, and on
/// what grounds* -- but a VEX suppression is sourced from a standard
/// document with its own vocabulary, while this is something a person wrote
/// in this tool's own file and may have dated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BypassRecord {
    /// Why the person who wrote it judged this acceptable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    /// Which file and entry it came from, so a reader can go and look.
    pub source: String,

    /// When the acknowledgement lapses, if it was dated.
    ///
    /// An undated one is not an oversight: the file requires saying
    /// open-ended out loud, so absence here means somebody chose it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SuppressionRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    pub source: String,
}

impl QuarantineRecord {
    /// The record for one recorded problem, or `None` when the problem was
    /// not a quarantine at all.
    ///
    /// **Built from the problem, not from a fresh decision.** A rule's
    /// expiry is evaluated when the decision is made, so re-deciding a long
    /// run's early problems at report time would have some of them lapse
    /// retroactively and the report would disagree with what the run did.
    ///
    /// `None` for `allowed` and `failure`, which are the two of the four
    /// classes that populate no marker -- see `core::problem::policy`. A
    /// caller can therefore hand every problem here and keep what comes
    /// back, rather than deciding twice which ones are quarantines.
    ///
    /// **A bypass is recorded whenever a rule answered**, not only when the
    /// rule loosened something. A rule that *tightened* an artifact is
    /// equally somebody's per-artifact decision, and a reader asking "why
    /// is this one different" needs the same answer either way.
    pub fn of(problem: &Problem) -> Option<Self> {
        Some(Self {
            code: problem.code(),
            class: problem.quarantine()?,
            hardened: problem.hardened(),
            bypassed_by: problem.bypass().map(BypassRecord::from),
        })
    }
}

impl From<&Bypass> for BypassRecord {
    fn from(bypass: &Bypass) -> Self {
        Self {
            justification: bypass.justification.clone(),
            source: bypass.source.clone(),
            expires: bypass.expires,
        }
    }
}

impl From<&Flag> for AdvisoryRecord {
    fn from(flag: &Flag) -> Self {
        Self {
            id: flag.id.clone(),
            advisor: flag.advisor.clone(),
            kind: flag.category,
            certainty: flag.certainty,
            summary: flag.summary.clone(),
            suppressed_by: flag.suppressed_by.as_ref().map(SuppressionRecord::from),
        }
    }
}

impl From<&Suppression> for SuppressionRecord {
    fn from(suppression: &Suppression) -> Self {
        Self {
            justification: suppression.justification.clone(),
            detail: suppression.detail.clone(),
            source: suppression.source.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProblemRecord {
    pub code: Code,
    pub action: Action,

    /// Whether this held the artifact for review, and how firmly.
    ///
    /// Present **whatever the action was**, so post-run analysis can see
    /// both what was held back and what was let through on an
    /// acknowledgement. The second list is the one an auditor wants: the
    /// things a run proceeded with despite a reservation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<Quarantine>,

    /// The acknowledgement that answered for this artifact, when one did.
    ///
    /// On the problem line as well as the artifact record because the two
    /// are reached differently: an artifact held back has no artifact
    /// record to carry it, and this is then the only place a reader learns
    /// that somebody had written a rule about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypassed_by: Option<BypassRecord>,

    /// An identifier plus named arguments, with the English as a fallback.
    /// A tool reading this report can render it in another language without
    /// parsing prose.
    pub message: Message,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<Message>,
}

impl From<&Problem> for ProblemRecord {
    fn from(problem: &Problem) -> Self {
        Self {
            code: problem.code(),
            action: problem.action(),
            quarantine: problem.quarantine(),
            bypassed_by: problem.bypass().map(BypassRecord::from),
            message: problem.message().clone(),
            provenance: problem.prov().chain().map(Cause::message).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Summary {
    pub artifacts: u64,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<Code, u64>,

    /// Problems by quarantine class, not artifacts: one artifact with two
    /// soft reservations adds two. Count artifacts from the artifact
    /// records, where an artifact is a thing that exists.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quarantined: BTreeMap<Quarantine, u64>,

    pub worst_action: Action,

    /// VEX statements this run showed to be dead policy, as
    /// `document#advisory`.
    ///
    /// Stale suppressions get cleaned up rather than accumulating until
    /// nobody dares delete one -- but **only** statements the run actually put
    /// a question to. A statement about an artifact the run never reached is
    /// absent, because nothing was learned about it: see
    /// [`SecurityPolicy::unmatched`](crate::policy::SecurityPolicy::unmatched)
    /// for why listing those would be worse than listing nothing.
    ///
    /// So an empty vector does not mean every suppression is live. It means
    /// none of the ones this run exercised were dead, which is a narrower
    /// claim and the only one a single run can make.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmatched_suppressions: Vec<String>,
}

impl ArtifactRecord {
    /// Build a record from a resolved artifact.
    ///
    /// `inspect` downloads no payloads, so files report
    /// [`Verification::NotAttempted`] unless a caller says otherwise.
    pub fn new(artifact: &ResolvedArtifact, provenance: Vec<Message>) -> Self {
        Self {
            purl: artifact.id.purl(),

            // Mapped rather than wrapped. Writing `Some("")` for an
            // artifact with no version is exactly what this field's
            // documentation forbids, and it would then be stored as a
            // version that is blank rather than absent.
            version: artifact.version.as_ref().map(ToString::to_string),
            requested: None,
            outcome: None,
            outcomes: Vec::new(),
            last_download: LastDownload::Unknown,
            files: artifact.files.iter().map(FileRecord::from).collect(),
            declared_license: artifact.license.clone(),
            license: None,
            published: artifact.published,
            advisories: Vec::new(),
            quarantine: Vec::new(),
            provenance,
        }
    }

    /// Build a record from what a **enumerator** found.
    ///
    /// An inventory entry, not a resolution: an enumerator reports what a
    /// repository holds, and the license and publish time are a source's
    /// answers costing a request each. A `find` over a
    /// million-artifact catalog is a few hundred requests because of that.
    ///
    /// The files are the ones the catalog listed, marked as such, so a
    /// later resolution is combined with them rather than replaced by them.
    pub fn found(found: &crate::repo::enumerate::Found, provenance: Vec<Message>) -> Self {
        Self {
            purl: found.id.purl(),
            version: found.version.as_ref().map(ToString::to_string),
            requested: None,
            outcome: None,
            outcomes: Vec::new(),
            last_download: found.last_download,
            files: found.files.iter().map(FileRecord::listed).collect(),
            declared_license: None,
            license: None,
            published: None,
            advisories: Vec::new(),
            quarantine: Vec::new(),
            provenance,
        }
    }

    /// Build a record for a request that resolved to nothing.
    ///
    /// There is no artifact to describe, so this carries what was asked
    /// for and why it could not be answered. `version` stays absent
    /// because none was ever chosen.
    pub fn unresolved(
        request: &crate::model::ArtifactRequest,
        why: &Problem,
        provenance: Vec<Message>,
    ) -> Self {
        Self {
            purl: request.id.purl(),
            version: None,
            requested: Some(request.spec.to_string()),
            outcome: Some(Outcome::Unresolved {
                why: Box::new(ProblemRecord::from(why)),
            }),
            outcomes: Vec::new(),
            last_download: LastDownload::Unknown,
            files: Vec::new(),
            declared_license: None,
            license: None,
            published: None,
            advisories: Vec::new(),
            quarantine: Vec::new(),
            provenance,
        }
    }
}

impl FileRecord {
    /// A file an enumerator listed. Nothing was fetched, so nothing is checked.
    fn listed(file: &crate::repo::enumerate::Listed) -> Self {
        Self {
            name: file.name.clone(),
            url: file.url.clone(),
            size: file.size,
            digests: file.digests.clone(),
            core_metadata: None,
            signatures: Vec::new(),
            verification: Verification::NotAttempted,
            origin: FileOrigin::Listed,
        }
    }
}

impl From<&crate::model::FileRef> for FileRecord {
    fn from(file: &crate::model::FileRef) -> Self {
        Self {
            name: file.name.clone(),
            url: file.url.clone(),
            size: file.size,
            digests: file.digests.clone(),
            core_metadata: file.core_metadata.clone(),
            signatures: file.signatures.clone(),
            verification: Verification::NotAttempted,
            origin: FileOrigin::Resolved,
        }
    }
}

/// Build a header for a run.
///
/// `screening` is required rather than defaulted, and that is the whole
/// reason this takes a second argument: [`Header::corpus_age`] was an empty
/// map here for as long as the function existed, and nothing would have
/// failed if a caller forgot to fill it. A parameter cannot be forgotten.
pub fn header(command: &str, screening: &Screening) -> Header {
    Header {
        created: Utc::now(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        command: command.to_owned(),
        corpus_age: screening.ages().clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Screening;

    /// An enumerator's files reach the record marked as listed, so a later
    /// resolution is combined with them rather than replaced by them.
    #[test]
    fn found_files_marked_listed() {
        let found = crate::repo::enumerate::Found::new(crate::model::ArtifactId::new(
            crate::model::EcosystemId::maven(),
            Some("g"),
            "a",
        ))
        .files(vec![crate::repo::enumerate::Listed {
            name: "a-1.0.module".to_owned(),
            url: "h://catalog.test/a-1.0.module".to_owned(),
            size: Some(3),
            digests: Vec::new(),
        }]);

        let record = ArtifactRecord::found(&found, Vec::new());

        assert_eq!(record.files.len(), 1);
        assert_eq!(record.files[0].origin, FileOrigin::Listed);
        assert_eq!(record.files[0].verification, Verification::NotAttempted);
    }

    /// Only a resolution could name a file before artifact enumerations
    /// listed them, so a record without the field reads as resolved.
    #[test]
    fn file_origin_defaults_to_resolved() {
        let file: FileRecord = serde_json::from_str(
            r#"{"name": "a.jar", "url": "h://o.test/a.jar", "verification": "not-attempted"}"#,
        )
        .expect("parsed");

        assert_eq!(file.origin, FileOrigin::Resolved);
    }

    /// **The field's whole reason for existing.** An omitted `corpus-age`
    /// and "nothing screened this run" would be the same bytes, and
    /// `docs/contributors/exit-codes.md` turns on a reader being able to
    /// tell a clean run from an unscreened one.
    #[test]
    fn corpus_age_key_kept_when_unscreened() {
        let json = serde_json::to_value(header("inspect", &Screening::none())).expect("serialized");

        assert_eq!(json["corpus-age"], serde_json::json!({}));
    }

    #[test]
    fn corpus_age_advisor_carries_reason() {
        let screening = Screening::plan(["osv".to_owned()], false);

        let json = serde_json::to_value(header("inspect", &screening)).expect("serialized");

        assert_eq!(
            json["corpus-age"]["osv"]["unavailable"]["why"],
            serde_json::json!("not loaded")
        );
    }

    /// The states have to survive the exchange format, or a report cannot be
    /// filtered on them by anything but this program.
    #[test]
    fn corpus_age_every_state_round_trips() {
        for age in [
            CorpusAge::Consulted {
                modified: Utc::now(),
            },
            CorpusAge::SkippedByRequest,
            CorpusAge::Unavailable {
                why: "host unreachable".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&age).expect("serialized");
            let back: CorpusAge = serde_json::from_str(&json).expect("deserialized");

            assert_eq!(back, age);
        }
    }

    /// A reader that meets a report from before this field existed must not
    /// fail the line, which is what `serde(default)` buys.
    #[test]
    fn corpus_age_absent_header_still_parses() {
        let header: Header = serde_json::from_value(serde_json::json!({
            "created": "2026-09-18T12:00:00Z",
            "tool-version": "0.1.0",
            "command": "inspect",
        }))
        .expect("parsed");

        assert!(header.corpus_age.is_empty());
    }

    /// `schema/report.schema.json`, which a reader of a `json-stream`
    /// report validates one line against.
    mod schema {
        use super::*;
        use crate::model::{DigestAlg, SigScheme};
        use crate::policy::Decision;

        const REPORT_SCHEMA: &str = include_str!("../../schema/report.schema.json");

        fn validator() -> jsonschema::Validator {
            let schema: serde_json::Value =
                serde_json::from_str(REPORT_SCHEMA).expect("schema parses");

            jsonschema::validator_for(&schema).expect("schema compiles")
        }

        /// Validate `record` as one report line, naming every error.
        fn assert_valid(validator: &jsonschema::Validator, record: &Record) {
            let line = serde_json::to_value(record).expect("serialized");
            let errors: Vec<String> = validator
                .iter_errors(&line)
                .map(|err| format!("{} at {}", err, err.instance_path()))
                .collect();

            assert!(errors.is_empty(), "{line}\n{}", errors.join("\n"));
        }

        fn message() -> Message {
            Message::new("example-id")
                .arg("purl", "pkg:npm/tuna@1.0.0")
                .text("an example")
        }

        fn problem(code: Code, action: Action) -> ProblemRecord {
            ProblemRecord {
                code,
                action,
                quarantine: Some(Quarantine::Soft),
                bypassed_by: Some(bypass()),
                message: message(),
                provenance: vec![message()],
            }
        }

        fn bypass() -> BypassRecord {
            BypassRecord {
                justification: Some("reviewed".to_owned()),
                source: "quarantine.yaml#rules[0]".to_owned(),
                expires: Some(Utc::now()),
            }
        }

        fn file(verification: Verification, origin: FileOrigin) -> FileRecord {
            FileRecord {
                name: "tuna-1.0.0.tgz".to_owned(),
                url: "h://registry.test/tuna-1.0.0.tgz".to_owned(),
                size: Some(42),
                digests: [
                    DigestAlg::Md5,
                    DigestAlg::Sha1,
                    DigestAlg::Sha256,
                    DigestAlg::Sha512,
                ]
                .into_iter()
                .map(|alg| Digest::new(alg, "AB01"))
                .collect(),
                core_metadata: Some(vec![Digest::new(DigestAlg::Sha256, "cd")]),
                signatures: [
                    SigScheme::NpmEcdsa,
                    SigScheme::PgpDetached,
                    SigScheme::PypiAttestation,
                ]
                .into_iter()
                .map(|scheme| SigRef {
                    scheme,
                    key_id: Some("key".to_owned()),
                    value: Some("sig".to_owned()),
                    url: Some("h://registry.test/sig".to_owned()),
                })
                .collect(),
                verification,
                origin,
            }
        }

        /// An artifact record with every optional field filled, and every
        /// variant of the enums it carries somewhere in it.
        fn artifact(outcome: Outcome, last_download: LastDownload) -> ArtifactRecord {
            let verifications = [
                Verification::NotAttempted,
                Verification::NoDigestDeclared,
                Verification::WeakDigestOnly,
                Verification::Verified,
                Verification::Failed,
            ];

            ArtifactRecord {
                purl: "pkg:npm/tuna".to_owned(),
                version: Some("1.0.0".to_owned()),
                requested: Some("^1".to_owned()),
                outcome: Some(outcome.clone()),
                outcomes: vec![DestinationOutcome {
                    destination: "mirror".to_owned(),
                    outcome,
                }],
                last_download,
                files: verifications
                    .into_iter()
                    .flat_map(|v| [file(v, FileOrigin::Listed), file(v, FileOrigin::Resolved)])
                    .collect(),
                declared_license: Some("MIT".to_owned()),
                license: Some(LicenseRecord {
                    decision: Decision::Allow,
                    spdx: Some("MIT".to_owned()),
                    reason: message(),
                    usage: [
                        DepKind::Runtime,
                        DepKind::Dev,
                        DepKind::Test,
                        DepKind::Optional,
                        DepKind::Peer,
                        DepKind::Build,
                    ]
                    .into_iter()
                    .map(|kind| (kind, Decision::Forbid))
                    .collect(),
                }),
                published: Some(Utc::now()),
                advisories: [
                    (Category::Malware, Certainty::Affected),
                    (Category::Vulnerability, Certainty::VersionUnusable),
                ]
                .into_iter()
                .map(|(kind, certainty)| AdvisoryRecord {
                    id: "GHSA-0000".to_owned(),
                    advisor: "osv".to_owned(),
                    kind,
                    certainty,
                    summary: Some("bad".to_owned()),
                    suppressed_by: Some(SuppressionRecord {
                        justification: Some("not reachable".to_owned()),
                        detail: Some("detail".to_owned()),
                        source: "vex.json".to_owned(),
                    }),
                })
                .collect(),
                quarantine: vec![QuarantineRecord {
                    code: Code::PublishTooRecent,
                    class: Quarantine::Hard,
                    hardened: true,
                    bypassed_by: Some(bypass()),
                }],
                provenance: vec![message()],
            }
        }

        /// Every record kind, with every optional field and enum variant,
        /// is a valid line.
        #[test]
        fn every_record_valid() {
            let validator = validator();
            let why = || Box::new(problem(Code::LicenseForbidden, Action::SkipArtifact));
            let outcomes = [
                Outcome::Copied {
                    verification: Verification::Verified,
                },
                Outcome::AlreadyPresent,
                Outcome::Refused { why: why() },
                Outcome::Unresolved { why: why() },
                Outcome::Failed { why: why() },
            ];
            let downloads = [LastDownload::At(Utc::now()), LastDownload::Never];

            for (outcome, download) in outcomes.into_iter().zip(downloads.into_iter().cycle()) {
                assert_valid(
                    &validator,
                    &Record::Artifact(Box::new(artifact(outcome, download))),
                );
            }

            let mut header = header("copy", &Screening::plan(["osv".to_owned()], false));
            header.corpus_age.insert(
                "consulted".to_owned(),
                CorpusAge::Consulted {
                    modified: Utc::now(),
                },
            );
            header
                .corpus_age
                .insert("skipped".to_owned(), CorpusAge::SkippedByRequest);
            assert_valid(&validator, &Record::Header(header));

            for action in [
                Action::Ignore,
                Action::Warn,
                Action::StopSpider,
                Action::SkipArtifact,
                Action::Abort,
            ] {
                assert_valid(&validator, &Record::Problem(problem(Code::Aborted, action)));
            }

            assert_valid(
                &validator,
                &Record::Summary(Summary {
                    artifacts: 3,
                    counts: Code::all().iter().map(|code| (*code, 1)).collect(),
                    quarantined: [(Quarantine::Soft, 1), (Quarantine::Hard, 2)].into(),
                    worst_action: Action::Warn,
                    unmatched_suppressions: vec!["vex.json#GHSA-0000".to_owned()],
                }),
            );
        }

        /// The fewest fields each kind may carry are enough.
        #[test]
        fn minimal_records_valid() {
            let validator = validator();
            let found = crate::repo::enumerate::Found::new(crate::model::ArtifactId::new(
                crate::model::EcosystemId::npm(),
                None,
                "tuna",
            ));

            assert_valid(
                &validator,
                &Record::Header(header("find", &Screening::none())),
            );
            assert_valid(
                &validator,
                &Record::Artifact(Box::new(ArtifactRecord::found(&found, Vec::new()))),
            );
            assert_valid(
                &validator,
                &Record::Problem(ProblemRecord {
                    code: Code::HostUnreachable,
                    action: Action::Warn,
                    quarantine: None,
                    bypassed_by: None,
                    message: Message::new("host-unreachable"),
                    provenance: Vec::new(),
                }),
            );
            assert_valid(
                &validator,
                &Record::Summary(Summary {
                    artifacts: 0,
                    counts: BTreeMap::new(),
                    quarantined: BTreeMap::new(),
                    worst_action: Action::Ignore,
                    unmatched_suppressions: Vec::new(),
                }),
            );
        }

        /// A field this version does not write is refused, so the schema
        /// cannot fall behind the records unnoticed.
        #[test]
        fn unknown_field_refused() {
            let line = serde_json::json!({
                "record": "summary",
                "artifacts": 0,
                "worst-action": "ignore",
                "surprise": true,
            });

            assert!(!validator().is_valid(&line));
        }

        /// The schema's problem codes are exactly [`Code::all`].
        #[test]
        fn codes_match() {
            let schema: serde_json::Value =
                serde_json::from_str(REPORT_SCHEMA).expect("schema parses");
            let mut listed: Vec<&str> = schema["$defs"]["Code"]["enum"]
                .as_array()
                .expect("an enum")
                .iter()
                .map(|code| code.as_str().expect("a string"))
                .collect();
            let mut known: Vec<&str> = Code::all().iter().map(|code| code.as_str()).collect();

            listed.sort_unstable();
            known.sort_unstable();

            assert_eq!(listed, known);
        }
    }
}
