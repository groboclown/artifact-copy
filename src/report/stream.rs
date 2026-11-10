//! Writing a report as a stream of lines.
//!
//! The line-oriented [`ReportWriter`]: one record per line, appended, so a
//! killed run leaves every complete line readable on its own -- the property
//! JSON Lines was chosen for over a single document. The tool never reads a
//! line report back; what a later run needs, it reads from the report
//! database. The `json` format is the one meant for other tools to ingest.

use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::error::{Error, Result};

use super::format::{Rendering, ReportFormat};
use super::record::Record;
use super::sink::ReportWriter;
use super::text;

/// Writes a report one line at a time.
///
/// The mutex is inside rather than around this, because a concurrent walk
/// hands records to one writer and interleaved lines would not parse. The
/// count sits beside it rather than under it, so asking for a tally never
/// waits on a write.
pub struct LineWriter<W: Write + Send> {
    out: Mutex<W>,
    rendering: Rendering,
    artifact_count: AtomicU64,
}

impl<W: Write + Send> LineWriter<W> {
    /// Build a writer for one of the line formats.
    pub fn new(out: W, format: ReportFormat) -> Result<Self> {
        Ok(Self {
            out: Mutex::new(out),
            rendering: format.rendering(),
            artifact_count: AtomicU64::new(0),
        })
    }

    /// Render one record the way this writer's format spells it.
    fn render(&self, record: &Record) -> Result<String> {
        match self.rendering {
            Rendering::Json => {
                serde_json::to_string(record).map_err(|source| Error::Report(source.to_string()))
            }

            // `---` separated documents: valid YAML, and it streams in both
            // directions without framing tricks. The separator also lets an
            // appending run join a file another run left off.
            Rendering::Yaml => {
                let body = serde_norway::to_string(record)
                    .map_err(|source| Error::Report(source.to_string()))?;

                Ok(format!("---\n{}", body.trim_end()))
            }

            Rendering::Text => Ok(text::render(record)),
        }
    }
}

impl<W: Write + Send> ReportWriter for LineWriter<W> {
    fn write(&self, record: &Record) -> Result<()> {
        if matches!(record, Record::Artifact(_)) {
            self.artifact_count.fetch_add(1, Ordering::Relaxed);
        }

        let rendered = self.render(record)?;

        let mut out = self.out.lock().map_err(poisoned)?;

        writeln!(out, "{rendered}").map_err(|source| Error::WriteFile {
            path: "<report>".into(),
            source,
        })
    }

    fn artifact_count(&self) -> u64 {
        self.artifact_count.load(Ordering::Relaxed)
    }

    fn flush(&self) -> Result<()> {
        let mut out = self.out.lock().map_err(poisoned)?;

        out.flush().map_err(|source| Error::WriteFile {
            path: "<report>".into(),
            source,
        })
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> Error {
    Error::Report("the report writer lock was poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Screening;
    use crate::core::message::Message;
    use crate::core::problem::{Action, Code, Problem};
    use crate::model::{Cause, DepKind, Digest, DigestAlg, Provenance};
    use crate::policy::Decision;
    use crate::report::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn artifact(purl: &str) -> Record {
        Record::Artifact(Box::new(ArtifactRecord {
            purl: purl.to_owned(),
            version: Some("1.0.0".into()),
            requested: None,
            outcome: None,
            outcomes: Vec::new(),
            last_download: crate::model::LastDownload::Unknown,
            files: vec![FileRecord {
                name: "x.tgz".into(),
                url: "https://example.test/x.tgz".into(),
                size: Some(10),
                digests: vec![Digest::new(DigestAlg::Sha256, "ab")],
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::NotAttempted,
                origin: FileOrigin::Resolved,
            }],
            declared_license: Some("MIT".into()),
            license: Some(LicenseRecord {
                decision: Decision::Allow,
                spdx: Some("MIT".into()),
                reason: Message::new("license-allowed"),
                usage: BTreeMap::new(),
            }),
            published: None,
            advisories: Vec::new(),
            quarantine: Vec::new(),
            provenance: vec![Cause::Requested { arg: "x".into() }.message()],
        }))
    }

    fn write_all(records: &[Record], format: ReportFormat) -> String {
        let mut buffer = Vec::new();

        {
            let writer = LineWriter::new(&mut buffer, format).expect("writer");

            for record in records {
                writer.write(record).expect("written");
            }

            writer.flush().expect("flushed");
        }

        String::from_utf8(buffer).expect("utf8")
    }

    /// Every record in a `json` report, parsed line by line as another
    /// tool would.
    fn read_all(text: &str) -> Vec<Record> {
        text.lines()
            .map(|line| serde_json::from_str(line).expect("each line is a record"))
            .collect()
    }

    #[test]
    fn json_reports_one_record_per_line() {
        let output = write_all(
            &[
                Record::Header(header("inspect", &Screening::none())),
                artifact("pkg:npm/a"),
                artifact("pkg:npm/b"),
            ],
            ReportFormat::Json,
        );

        assert_eq!(output.lines().count(), 3);

        for line in output.lines() {
            serde_json::from_str::<Record>(line).expect("each line stands alone");
        }
    }

    #[test]
    fn records_round_trip() {
        let output = write_all(
            &[
                Record::Header(header("inspect", &Screening::none())),
                artifact("pkg:npm/a"),
            ],
            ReportFormat::Json,
        );

        let records = read_all(&output);

        assert_eq!(records.len(), 2);

        let Record::Artifact(read) = &records[1] else {
            panic!("expected an artifact");
        };

        assert_eq!(read.purl, "pkg:npm/a");
        assert_eq!(read.files[0].digests[0].hex, "ab");
    }

    /// A killed run must leave a usable prefix: every complete line still
    /// parses on its own, and only the severed one does not.
    #[test]
    fn truncated_report_keeps_complete_lines() {
        let output = write_all(
            &[
                Record::Header(header("inspect", &Screening::none())),
                artifact("pkg:npm/a"),
                artifact("pkg:npm/b"),
            ],
            ReportFormat::Json,
        );

        // Cut in the middle of the third line.
        let truncated = &output[..output.len() - 20];
        let parsed: Vec<bool> = truncated
            .lines()
            .map(|line| serde_json::from_str::<Record>(line).is_ok())
            .collect();

        assert_eq!(parsed, [true, true, false]);
    }

    /// The artifact is in the report because one usage allowed it; the
    /// usages that refused must survive the round trip, or a reader sees
    /// only "allowed".
    #[test]
    fn usage_decisions_survive_round_trip() {
        let mut record = match artifact("pkg:npm/a") {
            Record::Artifact(record) => record,
            _ => unreachable!(),
        };

        record.license.as_mut().unwrap().usage = BTreeMap::from([
            (DepKind::Runtime, Decision::Forbid),
            (DepKind::Test, Decision::Allow),
        ]);

        let output = write_all(&[Record::Artifact(record)], ReportFormat::Json);

        let read: Record = serde_json::from_str(output.trim()).expect("reads");

        let Record::Artifact(read) = read else {
            panic!("expected an artifact");
        };

        let usage = &read.license.unwrap().usage;

        assert_eq!(usage[&DepKind::Runtime], Decision::Forbid);
        assert_eq!(usage[&DepKind::Test], Decision::Allow);
    }

    #[test]
    fn text_reports_show_refusing_usages() {
        let mut record = match artifact("pkg:npm/a") {
            Record::Artifact(record) => record,
            _ => unreachable!(),
        };

        record.license.as_mut().unwrap().usage =
            BTreeMap::from([(DepKind::Runtime, Decision::Forbid)]);

        let output = write_all(&[Record::Artifact(record)], ReportFormat::Text);

        assert!(output.contains("usage: runtime=Forbid"));
    }

    /// `text` is `copy`'s default format, and a new record field breaks no
    /// exhaustiveness check in the renderer -- so without this the default
    /// report could silently say nothing about what a copy did.
    #[test]
    fn text_reports_say_what_became_of_artifact() {
        let outcomes = [
            (
                Outcome::Copied {
                    verification: Verification::Verified,
                },
                "copied",
            ),
            (Outcome::AlreadyPresent, "already present"),
            (
                Outcome::Refused {
                    why: Box::new(problem_record()),
                },
                "refused:",
            ),
            (
                Outcome::Failed {
                    why: Box::new(problem_record()),
                },
                "failed:",
            ),
        ];

        for (outcome, expected) in outcomes {
            let mut record = match artifact("pkg:npm/a") {
                Record::Artifact(record) => record,
                _ => unreachable!(),
            };

            record.outcome = Some(outcome);

            let output = write_all(&[Record::Artifact(record)], ReportFormat::Text);

            assert!(
                output.contains(expected),
                "{expected} missing from {output}"
            );
        }
    }

    /// A copy to several targets says what became of the artifact at each.
    #[test]
    fn text_reports_each_destination() {
        let mut record = match artifact("pkg:npm/a") {
            Record::Artifact(record) => record,
            _ => unreachable!(),
        };

        record.outcome = Some(Outcome::AlreadyPresent);
        record.outcomes = vec![
            crate::report::DestinationOutcome {
                destination: "mirror".to_owned(),
                outcome: Outcome::AlreadyPresent,
            },
            crate::report::DestinationOutcome {
                destination: "backup".to_owned(),
                outcome: Outcome::AlreadyPresent,
            },
        ];

        let output = write_all(&[Record::Artifact(record)], ReportFormat::Text);

        assert!(output.contains("mirror: already present"), "{output}");
        assert!(output.contains("backup: already present"), "{output}");
    }

    /// A weaker check than the report claims elsewhere must stay visible:
    /// "copied" alone would read as fully verified.
    #[test]
    fn text_reports_qualify_weakly_checked_copy() {
        let mut record = match artifact("pkg:npm/a") {
            Record::Artifact(record) => record,
            _ => unreachable!(),
        };

        record.outcome = Some(Outcome::Copied {
            verification: Verification::WeakDigestOnly,
        });

        let output = write_all(&[Record::Artifact(record)], ReportFormat::Text);

        assert!(output.contains("copied [WeakDigestOnly]"), "{output}");
    }

    fn problem_record() -> crate::report::ProblemRecord {
        crate::report::ProblemRecord {
            code: Code::SignatureMissing,
            action: Action::SkipArtifact,
            quarantine: None,
            bypassed_by: None,
            message: crate::core::message::Message::new("unsigned"),
            provenance: Vec::new(),
        }
    }

    #[test]
    fn yaml_reports_separate_documents() {
        let output = write_all(
            &[
                Record::Header(header("inspect", &Screening::none())),
                artifact("pkg:npm/a"),
            ],
            ReportFormat::Yaml,
        );

        assert_eq!(output.matches("---").count(), 2);
    }

    #[test]
    fn text_reports_drop_quoting() {
        let output = write_all(&[artifact("pkg:npm/a")], ReportFormat::Text);

        assert!(output.contains("pkg:npm/a"));
        assert!(!output.contains("\"purl\""));
    }

    #[test]
    fn artifact_counts_track_only_artifacts() {
        let mut buffer = Vec::new();
        let writer = LineWriter::new(&mut buffer, ReportFormat::Json).expect("writer");

        writer
            .write(&Record::Header(header("inspect", &Screening::none())))
            .unwrap();
        writer.write(&artifact("pkg:npm/a")).unwrap();
        writer.write(&artifact("pkg:npm/b")).unwrap();

        assert_eq!(writer.artifact_count(), 2);
    }

    /// A problem record must carry the chain that explains which artifact it
    /// happened to and why that artifact was being looked at.
    #[test]
    fn problem_records_carry_provenance() {
        let root = Arc::new(Provenance::root(Cause::Requested { arg: "app".into() }));
        let problem = Problem::new(
            Code::ArtifactNotFound,
            root,
            crate::message!(
                "artifact-not-found",
                "{purl} was not found",
                purl = "pkg:npm/app",
            ),
        );

        let record = ProblemRecord::from(&problem);

        assert_eq!(record.code, Code::ArtifactNotFound);
        assert_eq!(record.action, Action::SkipArtifact);
        assert_eq!(record.provenance.len(), 1);
        assert_eq!(record.provenance[0].id, "cause-requested");
        assert_eq!(record.provenance[0].render(), r#"requested: "app""#);

        // The structured form is what a translating consumer reads; the
        // English is only the fallback.
        assert_eq!(record.message.id, "artifact-not-found");
        assert_eq!(
            record.message.args[crate::core::message::PURL_ARG],
            "pkg:npm/app"
        );
    }

    // -- Quarantine in the report ------------------------------------------

    /// A report format nothing can read back is useless, and the bypass is
    /// the half that matters most: a reservation that held an artifact back
    /// is visible in the artifact's absence, while one somebody waved
    /// through is visible nowhere else.
    #[test]
    fn quarantine_and_bypass_survive_round_trip() {
        use crate::core::problem::Quarantine;
        use crate::report::{BypassRecord, QuarantineRecord};

        let mut record = match artifact("pkg:npm/a") {
            Record::Artifact(record) => record,
            _ => panic!("an artifact"),
        };

        record.quarantine = vec![
            QuarantineRecord {
                hardened: false,
                code: Code::SignatureMissing,
                class: Quarantine::Soft,
                bypassed_by: None,
            },
            QuarantineRecord {
                hardened: false,
                code: Code::MalwareKnown,
                class: Quarantine::Hard,
                bypassed_by: Some(BypassRecord {
                    justification: Some("reviewed 2026-09-10".into()),
                    source: "quarantine-policy.yaml".into(),
                    expires: None,
                }),
            },
        ];

        let output = write_all(&[Record::Artifact(record)], ReportFormat::Json);

        let read = read_all(&output);

        let Record::Artifact(back) = &read[0] else {
            panic!("expected an artifact");
        };

        assert_eq!(back.quarantine.len(), 2);
        assert_eq!(back.quarantine[0].class, Quarantine::Soft);
        assert!(back.quarantine[0].bypassed_by.is_none());

        let waved = back.quarantine[1]
            .bypassed_by
            .as_ref()
            .expect("the bypass survived");

        assert_eq!(waved.source, "quarantine-policy.yaml");
        assert_eq!(waved.justification.as_deref(), Some("reviewed 2026-09-10"));
    }

    /// An artifact with no reservations carries no quarantine key at all,
    /// so the ordinary report does not grow a section of empty lists.
    #[test]
    fn quarantine_key_omitted_when_unreserved() {
        let output = write_all(&[artifact("pkg:npm/a")], ReportFormat::Json);

        assert!(!output.contains("quarantine"), "{output}");
    }

    /// The summary carries the tally, keyed by class.
    #[test]
    fn summary_carries_quarantine_counts() {
        use crate::core::problem::Quarantine;
        use std::collections::BTreeMap;

        let summary = Record::Summary(Summary {
            artifacts: 3,
            counts: BTreeMap::new(),
            quarantined: BTreeMap::from([(Quarantine::Soft, 2), (Quarantine::Hard, 1)]),
            worst_action: Action::Warn,
            unmatched_suppressions: Vec::new(),
        });

        let output = write_all(&[summary], ReportFormat::Json);

        let read = read_all(&output);

        let Record::Summary(back) = &read[0] else {
            panic!("expected a summary");
        };

        assert_eq!(back.quarantined[&Quarantine::Soft], 2);
        assert_eq!(back.quarantined[&Quarantine::Hard], 1);
    }
}
