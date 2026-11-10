//! The report as a SQLite database.
//!
//! One database holds many runs of many commands against many
//! repositories, and answers three questions a line report cannot: what a
//! source holds, what has reached a target, and what is left to do. The
//! reasoning is in `docs/contributors/report-as-database.md` and the shape
//! is in `schema/report-db.sql`.
//!
//! # The layers
//!
//! ```text
//!   sink     ReportWriter and ReportReader, behind one lock
//!   write    a Record becomes rows
//!   read     rows become a Record
//!   cache    where a payload's bytes are, and what fetching them cost
//!   inventory  what a repository holds, merged across runs
//!   enumeration  where a catalog walk stopped, and when one last finished
//!   frontier   a dependency walk's queue and claims
//!   transfer   claimed copy work, and what became of it
//!   work     what a copy still has to move
//!   ids      identity rows, de-duplicated and handed back as typed keys
//!   conn     opening a connection, and the settings it opens under
//! ```
//!
//! Each layer speaks only to the one below it. `write` never opens a
//! connection and `conn` knows nothing about records, so a change to the
//! record types cannot reach the pragma policy and a change to the pragma
//! policy cannot reach the records.

mod cache;
mod conn;
mod enumeration;
mod file_transfer;
mod frontier;
mod ids;
mod inventory;
mod read;
mod sink;
mod spell;
mod transfer;
mod work;
mod write;

pub(in crate::report) use sink::{DbReader, DbWriter};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use crate::advisory::CorpusAge;
    use crate::core::message::Message;
    use crate::core::problem::{Action, Code, Quarantine};
    use crate::core::screened::{Category, Certainty};
    use crate::model::{
        ArtifactId, Cause, DepKind, Digest, DigestAlg, EcosystemId, LastDownload, Release, Version,
    };
    use crate::policy::Decision;
    use crate::report::record::{
        AdvisoryRecord, ArtifactRecord, BypassRecord, DestinationOutcome, FileOrigin, FileRecord,
        Header, LicenseRecord, Outcome, ProblemRecord, QuarantineRecord, Record, Summary,
        SuppressionRecord, Verification,
    };
    use crate::report::sink::{ReportReader, ReportWriter};

    use super::{DbReader, DbWriter};

    /// Write records into a fresh database and read them back.
    ///
    /// The whole point of the database format is that it loses nothing a
    /// JSONL report would have kept, and the only honest way to say that is
    /// to put a record in and take the same one out.
    fn round_trip(records: Vec<Record>) -> Vec<Record> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        {
            let writer = DbWriter::open(&path).expect("opens");

            for record in &records {
                writer.write(record).expect("written");
            }

            writer.flush().expect("flushed");
        }

        DbReader::open(&path)
            .expect("reads")
            .records()
            .expect("opens")
            .collect::<crate::core::error::Result<Vec<_>>>()
            .expect("read back")
    }

    pub(super) fn header() -> Header {
        Header {
            created: Utc.timestamp_millis_opt(1_760_000_000_000).unwrap(),
            tool_version: "9.9.9".to_owned(),
            command: "inspect".to_owned(),
            corpus_age: BTreeMap::new(),
        }
    }

    fn problem() -> ProblemRecord {
        ProblemRecord {
            code: Code::SignatureMissing,
            action: Action::SkipArtifact,
            quarantine: Some(Quarantine::Soft),
            bypassed_by: Some(BypassRecord {
                justification: Some("reviewed".to_owned()),
                source: "quarantine-policy.yaml#3".to_owned(),
                expires: Some(Utc.timestamp_millis_opt(1_770_000_000_000).unwrap()),
            }),
            message: Message::new("signature-missing")
                .arg(crate::core::message::PURL_ARG, "pkg:npm/tuna")
                .text("tuna is unsigned"),
            provenance: vec![
                Cause::Dependency {
                    of: ArtifactId::new(EcosystemId::npm(), None, "app"),
                    version: Some(Version::new("1.0.0", Release::General)),
                    kind: DepKind::Runtime,
                }
                .message(),
                Cause::Requested { arg: "app".into() }.message(),
            ],
        }
    }

    /// Every field of an artifact record at once, so an omission shows up
    /// as a difference rather than as a passing test of a smaller record.
    pub(super) fn full_artifact() -> ArtifactRecord {
        ArtifactRecord {
            purl: "pkg:maven/org.example/lib?classifier=sources&type=jar".to_owned(),
            version: Some("1.2.3".to_owned()),
            requested: Some("org.example:lib:[1.0,2.0)".to_owned()),
            outcome: Some(Outcome::Copied {
                verification: Verification::WeakDigestOnly,
            }),
            outcomes: Vec::new(),
            last_download: LastDownload::At(Utc.timestamp_millis_opt(1_700_000_000_000).unwrap()),
            files: vec![
                FileRecord {
                    name: "lib-1.2.3.jar".to_owned(),
                    url: "h://origin.test/lib-1.2.3.jar".to_owned(),
                    size: Some(4096),
                    digests: vec![
                        Digest::new(DigestAlg::Sha1, "aa"),
                        Digest::new(DigestAlg::Sha256, "bb"),
                    ],
                    core_metadata: None,
                    signatures: Vec::new(),
                    verification: Verification::Verified,
                    origin: FileOrigin::Resolved,
                },
                FileRecord {
                    name: "lib-1.2.3.pom".to_owned(),
                    url: "h://origin.test/lib-1.2.3.pom".to_owned(),
                    size: None,
                    digests: Vec::new(),
                    core_metadata: None,
                    signatures: Vec::new(),
                    verification: Verification::NoDigestDeclared,
                    origin: FileOrigin::Listed,
                },
            ],
            declared_license: Some("Apache License 2.0".to_owned()),
            license: Some(LicenseRecord {
                decision: Decision::Allow,
                spdx: Some("Apache-2.0".to_owned()),
                reason: Message::new("license-allowed").arg("spdx", "Apache-2.0"),
                usage: BTreeMap::from([
                    (DepKind::Runtime, Decision::Forbid),
                    (DepKind::Test, Decision::Allow),
                ]),
            }),
            published: Some(Utc.timestamp_millis_opt(1_690_000_000_000).unwrap()),
            advisories: vec![
                AdvisoryRecord {
                    id: "CVE-2021-44228".to_owned(),
                    advisor: "osv".to_owned(),
                    kind: Category::Vulnerability,
                    certainty: Certainty::Affected,
                    summary: Some("remote code execution".to_owned()),
                    suppressed_by: Some(SuppressionRecord {
                        justification: Some("not reachable".to_owned()),
                        detail: Some("no jndi lookup".to_owned()),
                        source: "vex.json#CVE-2021-44228".to_owned(),
                    }),
                },
                AdvisoryRecord {
                    id: "MAL-0000-1".to_owned(),
                    advisor: "ossf".to_owned(),
                    kind: Category::Malware,
                    certainty: Certainty::VersionUnusable,
                    summary: None,
                    suppressed_by: None,
                },
            ],
            quarantine: vec![
                QuarantineRecord {
                    code: Code::SignatureMissing,
                    class: Quarantine::Soft,
                    hardened: true,
                    bypassed_by: None,
                },
                QuarantineRecord {
                    code: Code::MalwareKnown,
                    class: Quarantine::Hard,
                    hardened: false,
                    bypassed_by: Some(BypassRecord {
                        justification: None,
                        source: "quarantine-policy.yaml#1".to_owned(),
                        expires: None,
                    }),
                },
            ],
            provenance: vec![
                Cause::Requested {
                    arg: "org.example:lib".into(),
                }
                .message(),
            ],
        }
    }

    #[test]
    fn artifact_record_full_round_trips() {
        let original = full_artifact();
        let back = round_trip(vec![
            Record::Header(header()),
            Record::Artifact(Box::new(original.clone())),
        ]);

        let Record::Artifact(read) = &back[1] else {
            panic!("expected an artifact, got {:?}", back[1]);
        };

        // Compared as JSON, which is the published shape: a field this
        // misses is a field a reader of the JSONL report would have had.
        assert_eq!(
            serde_json::to_value(read.as_ref()).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    /// A PEP 658 document, with and without digests, and a signature come
    /// back as they went in.
    #[test]
    fn file_companions_round_trip() {
        use crate::model::{SigRef, SigScheme};

        let mut original = full_artifact();

        original.files[0].core_metadata = Some(vec![Digest::new(DigestAlg::Sha256, "cc")]);
        original.files[0].signatures = vec![SigRef {
            scheme: SigScheme::PypiAttestation,
            key_id: None,
            value: None,
            url: Some("h://origin.test/provenance".to_owned()),
        }];
        original.files[1].core_metadata = Some(Vec::new());

        let back = round_trip(vec![
            Record::Header(header()),
            Record::Artifact(Box::new(original.clone())),
        ]);

        let Record::Artifact(read) = &back[1] else {
            panic!("expected an artifact, got {:?}", back[1]);
        };

        assert_eq!(
            serde_json::to_value(read.as_ref()).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    /// The minimum an artifact record can be. An optional field that came
    /// back populated would mean the reader was inventing values.
    #[test]
    fn artifact_record_empty_round_trips() {
        let original = ArtifactRecord {
            purl: "pkg:npm/tuna".to_owned(),
            version: None,
            requested: None,
            outcome: None,
            outcomes: Vec::new(),
            last_download: LastDownload::Unknown,
            files: Vec::new(),
            declared_license: None,
            license: None,
            published: None,
            advisories: Vec::new(),
            quarantine: Vec::new(),
            provenance: Vec::new(),
        };

        let back = round_trip(vec![
            Record::Header(header()),
            Record::Artifact(Box::new(original.clone())),
        ]);

        let Record::Artifact(read) = &back[1] else {
            panic!("expected an artifact");
        };

        assert_eq!(
            serde_json::to_value(read.as_ref()).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    /// Each outcome carries something different, and three of the five
    /// carry a whole problem. A reader that flattened them would lose the
    /// reason an artifact was not taken, which is the only thing a report
    /// can say that the target cannot.
    #[test]
    fn every_outcome_round_trips() {
        let outcomes = vec![
            Outcome::Copied {
                verification: Verification::Verified,
            },
            Outcome::AlreadyPresent,
            Outcome::Refused {
                why: Box::new(problem()),
            },
            Outcome::Unresolved {
                why: Box::new(problem()),
            },
            Outcome::Failed {
                why: Box::new(problem()),
            },
        ];

        for outcome in outcomes {
            let mut record = full_artifact();
            record.outcome = Some(outcome.clone());

            let back = round_trip(vec![
                Record::Header(header()),
                Record::Artifact(Box::new(record)),
            ]);

            let Record::Artifact(read) = &back[1] else {
                panic!("expected an artifact");
            };

            assert_eq!(
                serde_json::to_value(read.outcome.as_ref().unwrap()).unwrap(),
                serde_json::to_value(&outcome).unwrap(),
                "{outcome:?}"
            );
        }
    }

    /// A copy to several targets keeps each target's outcome, reason and
    /// all, and the overall one reads back as the worst.
    #[test]
    fn destination_outcomes_round_trip() {
        let mut record = full_artifact();
        record.outcome = Some(Outcome::Failed {
            why: Box::new(problem()),
        });
        record.outcomes = vec![
            DestinationOutcome {
                destination: "mirror".to_owned(),
                outcome: Outcome::Copied {
                    verification: Verification::WeakDigestOnly,
                },
            },
            DestinationOutcome {
                destination: "backup".to_owned(),
                outcome: Outcome::Failed {
                    why: Box::new(problem()),
                },
            },
        ];

        let back = round_trip(vec![
            Record::Header(header()),
            Record::Artifact(Box::new(record.clone())),
        ]);

        let Record::Artifact(read) = &back[1] else {
            panic!("expected an artifact");
        };

        assert_eq!(
            serde_json::to_value(&read.outcomes).unwrap(),
            serde_json::to_value(&record.outcomes).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&read.outcome).unwrap(),
            serde_json::to_value(&record.outcome).unwrap()
        );
    }

    /// Three states, and flattening them into an optional time would lose
    /// the difference between evidence of disuse and absence of evidence.
    #[test]
    fn every_last_download_state_round_trips() {
        let states = [
            LastDownload::At(Utc.timestamp_millis_opt(1_700_000_000_000).unwrap()),
            LastDownload::Never,
            LastDownload::Unknown,
        ];

        for state in states {
            let mut record = full_artifact();
            record.last_download = state;

            let back = round_trip(vec![
                Record::Header(header()),
                Record::Artifact(Box::new(record)),
            ]);

            let Record::Artifact(read) = &back[1] else {
                panic!("expected an artifact");
            };

            assert_eq!(read.last_download, state);
        }
    }

    #[test]
    fn problem_record_round_trips() {
        let original = problem();
        let back = round_trip(vec![
            Record::Header(header()),
            Record::Problem(original.clone()),
        ]);

        let Record::Problem(read) = &back[1] else {
            panic!("expected a problem, got {:?}", back[1]);
        };

        assert_eq!(
            serde_json::to_value(read).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    /// Every cause kind, read back from its columns rather than its text,
    /// so a column the reader forgets shows up as a missing argument.
    #[test]
    fn every_cause_round_trips() {
        let mut original = full_artifact();
        original.provenance = vec![
            Cause::Report {
                path: "migration.db".into(),
                entry: "pkg:maven/org.example/lib@1.0".into(),
                source: "central".into(),
                destinations: vec!["mirror".into()],
                run: Some(1),
            }
            .message(),
            Cause::Report {
                path: "migration.db".into(),
                entry: "pkg:maven/org.example/lib@1.0".into(),
                source: "central".into(),
                destinations: vec!["mirror".into(), "backup".into()],
                run: None,
            }
            .message(),
            Cause::Dependency {
                of: ArtifactId::new(EcosystemId::new("generic"), None, "dir"),
                version: None,
                kind: DepKind::Test,
            }
            .message(),
            Cause::Dependency {
                of: ArtifactId::new(EcosystemId::npm(), None, "app"),
                version: Some(Version::new("2.0.0-rc.1", Release::PreRelease)),
                kind: DepKind::Peer,
            }
            .message(),
            Cause::Enumerated {
                enumerator: "nexus".into(),
            }
            .message(),
            Cause::LockFile {
                path: "pom.lock".into(),
                entry: "org.example:lib".into(),
            }
            .message(),
            Cause::Requested {
                arg: "org.example:lib".into(),
            }
            .message(),
        ];

        let back = round_trip(vec![
            Record::Header(header()),
            Record::Artifact(Box::new(original.clone())),
        ]);

        let Record::Artifact(read) = &back[1] else {
            panic!("expected an artifact, got {:?}", back[1]);
        };

        assert_eq!(read.provenance, original.provenance);
    }

    /// **A dependency edge is keyed on the parent's row at its version**,
    /// so "what pulled this in" is a join rather than a parse of English.
    #[test]
    fn dependency_links_parent_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
            writer.write(&Record::Problem(problem())).expect("problem");
            writer.flush().expect("flushed");
        }

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let (kind, purl, release): (String, String, String) = conn
            .query_row(
                "SELECT pi.kind, a.purl, a.release
                 FROM provenance_item pi
                 JOIN artifact a ON a.artifact_id = pi.parent_artifact_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("one linked edge");

        assert_eq!(kind, "dependency");
        assert_eq!(purl, "pkg:npm/app@1.0.0");
        assert_eq!(release, "general");
    }

    #[test]
    fn summary_round_trips() {
        let original = Summary {
            artifacts: 1234,
            counts: BTreeMap::from([(Code::SignatureMissing, 7), (Code::ChecksumMismatch, 1)]),
            quarantined: BTreeMap::from([(Quarantine::Soft, 5), (Quarantine::Hard, 2)]),
            worst_action: Action::SkipArtifact,
            unmatched_suppressions: vec![
                "vex.json#CVE-2021-1".to_owned(),
                "vex.json#CVE-2021-2".to_owned(),
            ],
        };

        let back = round_trip(vec![
            Record::Header(header()),
            Record::Summary(original.clone()),
        ]);

        let Record::Summary(read) = &back[1] else {
            panic!("expected a summary, got {:?}", back[1]);
        };

        assert_eq!(
            serde_json::to_value(read).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    /// **The field's whole reason for existing.** An omitted corpus age and
    /// "nothing screened this run" must not look alike, so every state has
    /// to survive the database as well as the JSON.
    #[test]
    fn every_corpus_age_round_trips() {
        let ages = BTreeMap::from([
            (
                "osv".to_owned(),
                CorpusAge::Consulted {
                    modified: Utc.timestamp_millis_opt(1_750_000_000_000).unwrap(),
                },
            ),
            ("ossf".to_owned(), CorpusAge::SkippedByRequest),
            (
                "other".to_owned(),
                CorpusAge::Unavailable {
                    why: "host unreachable".to_owned(),
                },
            ),
        ]);

        let mut opening = header();
        opening.corpus_age = ages.clone();

        let back = round_trip(vec![Record::Header(opening)]);

        let Record::Header(read) = &back[0] else {
            panic!("expected a header");
        };

        assert_eq!(read.corpus_age, ages);
        assert_eq!(read.command, "inspect");
        assert_eq!(read.tool_version, "9.9.9");
    }

    /// An unscreened run still writes the key, and the database has to keep
    /// the difference between "no advisor configured" and "not written".
    #[test]
    fn run_unscreened_reads_back_empty() {
        let back = round_trip(vec![Record::Header(header())]);

        let Record::Header(read) = &back[0] else {
            panic!("expected a header");
        };

        assert!(read.corpus_age.is_empty());
    }

    /// The stream order is what lets a database report be read as the same
    /// records a JSONL report held, in the same order.
    #[test]
    fn records_read_back_in_order() {
        let back = round_trip(vec![
            Record::Header(header()),
            Record::Artifact(Box::new(full_artifact())),
            Record::Problem(problem()),
            Record::Artifact(Box::new(full_artifact())),
            Record::Summary(Summary {
                artifacts: 2,
                counts: BTreeMap::new(),
                quarantined: BTreeMap::new(),
                worst_action: Action::Warn,
                unmatched_suppressions: Vec::new(),
            }),
        ]);

        let kinds: Vec<&str> = back
            .iter()
            .map(|record| match record {
                Record::Header(_) => "header",
                Record::Artifact(_) => "artifact",
                Record::Problem(_) => "problem",
                Record::Summary(_) => "summary",
            })
            .collect();

        assert_eq!(
            kinds,
            vec!["header", "artifact", "problem", "artifact", "summary"]
        );
    }

    /// A million observations of one package make one `package` row and one
    /// `artifact` row. That is the difference between an inventory and a
    /// log, and it is what every later inventory query depends on.
    #[test]
    fn one_artifact_seen_twice_is_one_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");

            for _ in 0..3 {
                writer
                    .write(&Record::Artifact(Box::new(full_artifact())))
                    .expect("written");
            }

            writer.flush().expect("flushed");
        }

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let count = |table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect(table)
        };

        assert_eq!(count("package"), 1);
        assert_eq!(count("artifact"), 1);
        assert_eq!(count("artifact_observation"), 3);

        // Qualifiers follow the package, not the observation.
        assert_eq!(count("package_qualifier"), 2);
    }

    /// The pieces are what a query filters on, and the rendered purl is
    /// only the key. A `LIKE` against the rendering is what splitting them
    /// exists to avoid.
    #[test]
    fn purl_is_stored_in_pieces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
            writer
                .write(&Record::Artifact(Box::new(full_artifact())))
                .expect("written");
            writer.flush().expect("flushed");
        }

        let conn = rusqlite::Connection::open(&path).expect("opens");

        let (ecosystem, namespace, name, purl): (String, String, String, String) = conn
            .query_row(
                "SELECT ecosystem, namespace, name, purl FROM package",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read");

        assert_eq!(ecosystem, "maven");
        assert_eq!(namespace, "org.example");
        assert_eq!(name, "lib");
        assert_eq!(
            purl,
            "pkg:maven/org.example/lib?classifier=sources&type=jar"
        );

        let (version, release, exact): (String, String, String) = conn
            .query_row("SELECT version, release, purl FROM artifact", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("read");

        assert_eq!(version, "1.2.3");
        assert_eq!(release, "general");

        // The version belongs between the name and the qualifiers, which is
        // why it cannot be appended to the package's purl.
        assert_eq!(
            exact,
            "pkg:maven/org.example/lib@1.2.3?classifier=sources&type=jar"
        );

        let qualifiers: Vec<String> = conn
            .prepare("SELECT key || '=' || value FROM package_qualifier ORDER BY key")
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(qualifiers, vec!["classifier=sources", "type=jar"]);
    }

    /// A record before the header would have no run to belong to, and
    /// attributing it to one that does not exist is worse than refusing it.
    #[test]
    fn record_before_header_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = DbWriter::open(&dir.path().join("report.sqlite")).expect("opens");

        assert!(writer.write(&Record::Problem(problem())).is_err());
    }

    /// A run with no finish time is how a later run recognizes a crash, so
    /// a flushed run must not look like one.
    #[test]
    fn run_closes_on_flush() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
            writer
                .write(&Record::Summary(Summary {
                    artifacts: 0,
                    counts: BTreeMap::new(),
                    quarantined: BTreeMap::new(),
                    worst_action: Action::SkipArtifact,
                    unmatched_suppressions: Vec::new(),
                }))
                .expect("summary");
            writer.flush().expect("flushed");
        }

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let (finished, completion, worst): (Option<i64>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT finished_ms, completion, worst_action FROM run",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read");

        assert!(finished.is_some());
        assert_eq!(completion.as_deref(), Some("finished"));

        // Copied from the summary rather than passed in, so the two cannot
        // disagree about what the run's worst action was.
        assert_eq!(worst.as_deref(), Some("skip-artifact"));
    }

    /// A run that said how it ended is closed that way, not as finished.
    #[test]
    fn run_closes_as_it_completed() {
        use crate::report::sink::{Completion, ReportWriter};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        for how in [Completion::Failed, Completion::Cancelled] {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
            writer
                .state()
                .expect("a database keeps state")
                .complete(how)
                .expect("completed");
            writer.flush().expect("flushed");
        }

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let completions: Vec<String> = conn
            .prepare("SELECT completion FROM run ORDER BY run_id")
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(completions, ["failed", "cancelled"]);
    }

    /// A killed run leaves no finish time, which is the claim a later run
    /// reads to know its claims can be reclaimed.
    #[test]
    fn run_unflushed_stays_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
        }

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let finished: Option<i64> = conn
            .query_row("SELECT finished_ms FROM run", [], |row| row.get(0))
            .expect("read");

        assert!(finished.is_none(), "an abandoned run looked finished");
    }

    /// Several runs accumulate rather than replacing each other, which is
    /// the whole reason a database is worth having over a line report.
    #[test]
    fn runs_accumulate_across_opens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        for command in ["find", "inspect", "copy"] {
            let writer = DbWriter::open(&path).expect("opens");
            let mut opening = header();
            opening.command = command.to_owned();

            writer.write(&Record::Header(opening)).expect("header");
            writer
                .write(&Record::Artifact(Box::new(full_artifact())))
                .expect("artifact");
            writer.flush().expect("flushed");
        }

        let back = DbReader::open(&path)
            .expect("reads")
            .records()
            .expect("opens")
            .collect::<crate::core::error::Result<Vec<_>>>()
            .expect("read back");

        let commands: Vec<String> = back
            .iter()
            .filter_map(|record| match record {
                Record::Header(header) => Some(header.command.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(commands, vec!["find", "inspect", "copy"]);
        assert_eq!(back.len(), 6);
    }
}

/// The inventory half: what a repository holds, merged across runs.
///
/// Kept apart from the round-trip tests above because they check a
/// different property. Those say the database loses nothing a JSONL report
/// would have kept; these say it answers a question no JSONL report can.
#[cfg(test)]
mod inventory_tests {
    use chrono::{TimeZone, Utc};
    use rusqlite::Connection;

    use crate::model::LastDownload;
    use crate::report::record::{FileOrigin, FileRecord, Record, Verification};
    use crate::report::sink::{Binding, ReportWriter, Role};

    use super::DbWriter;
    use super::tests::{full_artifact, header};

    /// A run, described by what it bound and what it observed.
    struct Run<'a> {
        bindings: Vec<Binding<'a>>,
        records: Vec<Record>,
    }

    /// Play several runs into one database, as several invocations would.
    fn runs(runs: Vec<Run<'_>>) -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        for run in runs {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");

            let state = writer.state().expect("a database keeps state");

            for binding in &run.bindings {
                state.bind(binding).expect("bound");
            }

            for record in &run.records {
                writer.write(record).expect("written");
            }

            writer.flush().expect("flushed");
        }

        let conn = Connection::open(&path).expect("opens");

        (dir, conn)
    }

    fn one(binding: Binding<'_>, records: Vec<Record>) -> Run<'_> {
        Run {
            bindings: vec![binding],
            records,
        }
    }

    fn artifact(purl: &str, version: Option<&str>) -> Record {
        let mut record = full_artifact();
        record.purl = purl.to_owned();
        record.version = version.map(str::to_owned);

        Record::Artifact(Box::new(record))
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect(table)
    }

    /// A problem's `purl` links it to the artifact, so a quarantine raised
    /// apart from any artifact record is still found by joining on it.
    #[test]
    fn problem_links_its_purl() {
        use crate::core::message::{Message, PURL_ARG};
        use crate::core::problem::{Action, Code};
        use crate::report::record::ProblemRecord;

        let problem = |message: Message| {
            Record::Problem(ProblemRecord {
                code: Code::MalwareKnown,
                action: Action::SkipArtifact,
                quarantine: None,
                bypassed_by: None,
                message,
                provenance: Vec::new(),
            })
        };

        let (_dir, conn) = runs(vec![Run {
            bindings: Vec::new(),
            records: vec![
                problem(Message::new("named").arg(PURL_ARG, "pkg:npm/fs@0.0.1-security")),
                problem(Message::new("unnamed")),
            ],
        }]);

        let linked: Vec<Option<String>> = conn
            .prepare(
                "SELECT a.purl FROM problem p
                 LEFT JOIN artifact a ON a.artifact_id = p.artifact_id
                 ORDER BY p.problem_id",
            )
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(linked, [Some("pkg:npm/fs@0.0.1-security".to_owned()), None]);
    }

    /// Enumerating the same repository's artifacts twice leaves one
    /// inventory row with two observations behind it. An inventory that grew
    /// a row per enumeration would be a log with extra steps.
    #[test]
    fn scan_repeated_updates_one_row() {
        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
            ),
        ]);

        assert_eq!(count(&conn, "repository"), 1);
        assert_eq!(count(&conn, "repository_artifact"), 1);
        assert_eq!(count(&conn, "artifact_observation"), 2);

        // When the repository first held it is a fact about the repository,
        // so the second look must not move it forward.
        let (first, last): (i64, i64) = conn
            .query_row(
                "SELECT first_seen_ms, last_seen_ms FROM repository_artifact",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read");

        assert!(first <= last);
    }

    /// A catalog that lists names only, then a run that resolves versions.
    /// Both rows have to exist and both have to join through the package,
    /// or the two-pass inventory the plan calls for cannot be built.
    #[test]
    fn scan_name_only_joins_versioned() {
        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Enumerator, "catalog").observing(),
                vec![artifact("pkg:npm/tuna", None)],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![
                    artifact("pkg:npm/tuna", Some("1.0.0")),
                    artifact("pkg:npm/tuna", Some("2.0.0")),
                ],
            ),
        ]);

        // One package, three artifacts under it: the name and two versions.
        assert_eq!(count(&conn, "package"), 1);
        assert_eq!(count(&conn, "artifact"), 3);

        let versions: Vec<Option<String>> = conn
            .prepare(
                "SELECT a.version FROM artifact a
                 JOIN package p ON p.package_id = a.package_id
                 WHERE p.purl = 'pkg:npm/tuna'
                 ORDER BY a.version",
            )
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(
            versions,
            vec![None, Some("1.0.0".to_owned()), Some("2.0.0".to_owned())]
        );

        // Two roles, two repositories: a catalog's answer and a source's
        // are different claims and never merge.
        assert_eq!(count(&conn, "repository"), 2);
    }

    /// **Target enumeration.** Enumerating the artifacts of a repository
    /// that is also a publish target records what the *target* holds, which
    /// is what lets a later copy ask the report instead of asking the target
    /// once per artifact.
    ///
    /// The enumerator is still bound -- its cursor belongs to it -- and is not
    /// what the records are about.
    #[test]
    fn scan_describes_its_target() {
        let (_dir, conn) = runs(vec![Run {
            bindings: vec![
                Binding::new(Role::Enumerator, "mirror-index"),
                Binding::new(Role::Target, "mirror").observing(),
            ],
            records: vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
        }]);

        // Both bindings exist; only one is what the run described.
        assert_eq!(count(&conn, "repository"), 2);

        let described: Vec<(String, String)> = conn
            .prepare(
                "SELECT r.role, r.name
                 FROM repository_artifact ra
                 JOIN repository r ON r.repository_id = ra.repository_id",
            )
            .expect("prepared")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(
            described,
            vec![("target".to_owned(), "mirror".to_owned())],
            "the scan was filed under the enumerator rather than the target"
        );
    }

    /// `find --as-source`: the same claim about a source, which is what
    /// `inspect --from-db` and `copy --from-db` read their work
    /// from. The names match, as they do when one configured repository is
    /// both an enumerator and a source.
    #[test]
    fn scan_describes_its_source() {
        let (_dir, conn) = runs(vec![Run {
            bindings: vec![
                Binding::new(Role::Enumerator, "catalog"),
                Binding::new(Role::Source, "catalog").observing(),
            ],
            records: vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
        }]);

        assert_eq!(count(&conn, "repository"), 2);

        let inventory = super::work::inventory(&conn, "catalog", 0, 10).expect("queried");

        assert_eq!(
            inventory
                .iter()
                .map(|work| work.purl.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg:npm/tuna@1.0.0"],
            "the scan was not filed under the source a report-fed run reads"
        );
    }

    /// The assertion is the user's and the run's. Enumerating the same
    /// mirror's artifacts without saying what it is files the contents under
    /// the enumerator, where a copy asking about a target will not find them.
    #[test]
    fn scan_claiming_nothing_describes_itself() {
        let (_dir, conn) = runs(vec![Run {
            bindings: vec![Binding::new(Role::Enumerator, "mirror-index").observing()],
            records: vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
        }]);

        let described: Vec<String> = conn
            .prepare(
                "SELECT r.role
                 FROM repository_artifact ra
                 JOIN repository r ON r.repository_id = ra.repository_id",
            )
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(described, vec!["enumerator".to_owned()]);
    }

    /// One name bound as both a source and a target stays two rows. A
    /// source's inventory says what can be copied from; a target's says
    /// what is already there.
    #[test]
    fn one_name_in_two_roles_is_two_repositories() {
        let (_dir, conn) = runs(vec![Run {
            bindings: vec![
                Binding::new(Role::Source, "mirror").observing(),
                Binding::new(Role::Target, "mirror"),
            ],
            records: Vec::new(),
        }]);

        assert_eq!(count(&conn, "repository"), 2);

        let roles: Vec<String> = conn
            .prepare("SELECT role FROM repository WHERE name = 'mirror' ORDER BY role")
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(roles, vec!["source", "target"]);
    }

    /// Two sources holding one purl keep two sets of facts, which is what
    /// makes "which source should a copy take this from" answerable. A
    /// merge that resolved the conflict would throw the question away.
    #[test]
    fn two_sources_keep_their_own_facts() {
        let with_license = |purl: &str, license: &str| {
            let mut record = full_artifact();
            record.purl = purl.to_owned();
            record.version = Some("1.0.0".to_owned());
            record.declared_license = Some(license.to_owned());

            Record::Artifact(Box::new(record))
        };

        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Source, "first").observing(),
                vec![with_license("pkg:npm/tuna", "MIT")],
            ),
            one(
                Binding::new(Role::Source, "second").observing(),
                vec![with_license("pkg:npm/tuna", "Apache-2.0")],
            ),
        ]);

        assert_eq!(count(&conn, "artifact"), 1, "one artifact identity");
        assert_eq!(count(&conn, "repository_artifact"), 2, "two inventories");

        let licenses: Vec<(String, String)> = conn
            .prepare(
                "SELECT r.name, ra.declared_license
                 FROM repository_artifact ra
                 JOIN repository r ON r.repository_id = ra.repository_id
                 ORDER BY r.name",
            )
            .expect("prepared")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(
            licenses,
            vec![
                ("first".to_owned(), "MIT".to_owned()),
                ("second".to_owned(), "Apache-2.0".to_owned()),
            ]
        );
    }

    /// An artifact enumeration and a resolution of one file share one row:
    /// each sets its own marker, and the resolved URL is never replaced by a
    /// listed one.
    #[test]
    fn listed_and_resolved_share_a_row() {
        let observed = |origin: FileOrigin, url: &str| {
            let mut record = full_artifact();
            record.purl = "pkg:npm/tuna".to_owned();
            record.version = Some("1.0.0".to_owned());
            record.files = vec![FileRecord {
                name: "tuna.tgz".to_owned(),
                url: url.to_owned(),
                size: None,
                digests: Vec::new(),
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::NotAttempted,
                origin,
            }];

            Record::Artifact(Box::new(record))
        };

        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![observed(FileOrigin::Listed, "h://catalog.test/tuna.tgz")],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![observed(FileOrigin::Resolved, "h://origin.test/tuna.tgz")],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![observed(FileOrigin::Listed, "h://moved.test/tuna.tgz")],
            ),
        ]);

        let (rows, url, listed, resolved): (i64, String, bool, bool) = conn
            .query_row(
                "SELECT COUNT(*), url, listed_ms IS NOT NULL, resolved_ms IS NOT NULL
                 FROM repository_file",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read");

        assert_eq!(rows, 1);
        assert_eq!(url, "h://origin.test/tuna.tgz");
        assert!(listed && resolved);
    }

    /// A later run that knows less must not erase what an earlier one
    /// learned. This is the rule the whole merge is written around: a
    /// `find` enumerates coordinates, a `inspect` resolves metadata,
    /// and running them in that order must leave the metadata standing.
    #[test]
    fn scan_later_keeps_unknown_facts() {
        let knowing = {
            let mut record = full_artifact();
            record.purl = "pkg:npm/tuna".to_owned();
            record.version = Some("1.0.0".to_owned());
            record.declared_license = Some("MIT".to_owned());
            record.published = Some(Utc.timestamp_millis_opt(1_600_000_000_000).unwrap());
            record.last_download =
                LastDownload::At(Utc.timestamp_millis_opt(1_650_000_000_000).unwrap());
            record.files = vec![FileRecord {
                name: "tuna.tgz".to_owned(),
                url: "h://origin.test/tuna.tgz".to_owned(),
                size: Some(1024),
                digests: Vec::new(),
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::Verified,
                origin: FileOrigin::Resolved,
            }];

            Record::Artifact(Box::new(record))
        };

        let knowing_less = {
            let mut record = full_artifact();
            record.purl = "pkg:npm/tuna".to_owned();
            record.version = Some("1.0.0".to_owned());
            record.declared_license = None;
            record.published = None;
            record.last_download = LastDownload::Unknown;
            record.files = vec![FileRecord {
                name: "tuna.tgz".to_owned(),
                url: "h://origin.test/tuna.tgz".to_owned(),
                size: None,
                digests: Vec::new(),
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::NotAttempted,
                origin: FileOrigin::Resolved,
            }];

            Record::Artifact(Box::new(record))
        };

        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![knowing],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![knowing_less],
            ),
        ]);

        let (license, published, state, download): (
            Option<String>,
            Option<i64>,
            String,
            Option<i64>,
        ) = conn
            .query_row(
                "SELECT declared_license, published_ms, last_download_state, last_download_ms
                 FROM repository_artifact",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read");

        assert_eq!(license.as_deref(), Some("MIT"));
        assert_eq!(published, Some(1_600_000_000_000));

        // `unknown` is the absence of evidence, not evidence of absence.
        assert_eq!(state, "at");
        assert_eq!(download, Some(1_650_000_000_000));

        let (size, verification): (Option<i64>, String) = conn
            .query_row(
                "SELECT size_bytes, verification FROM repository_file",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read");

        assert_eq!(size, Some(1024));

        // A run that fetched nothing must not downgrade a checked file.
        assert_eq!(verification, "verified");
    }

    /// A failure does replace a success: bad news about the bytes is news.
    #[test]
    fn check_failed_replaces_passing() {
        let checked = |how: Verification| {
            let mut record = full_artifact();
            record.purl = "pkg:npm/tuna".to_owned();
            record.version = Some("1.0.0".to_owned());
            record.files = vec![FileRecord {
                name: "tuna.tgz".to_owned(),
                url: "h://origin.test/tuna.tgz".to_owned(),
                size: None,
                digests: Vec::new(),
                core_metadata: None,
                signatures: Vec::new(),
                verification: how,
                origin: FileOrigin::Resolved,
            }];

            Record::Artifact(Box::new(record))
        };

        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![checked(Verification::Verified)],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![checked(Verification::Failed)],
            ),
        ]);

        let verification: String = conn
            .query_row("SELECT verification FROM repository_file", [], |row| {
                row.get(0)
            })
            .expect("read");

        assert_eq!(verification, "failed");
    }

    /// Every digest a repository has ever declared, accumulated. A
    /// repository that published a sha1 last year and a sha256 today has
    /// declared both, and a copy checking against either wants whichever it
    /// can compute.
    #[test]
    fn digests_accumulate_rather_than_replace() {
        use crate::model::{Digest, DigestAlg};

        let with_digest = |alg: DigestAlg, hex: &str| {
            let mut record = full_artifact();
            record.purl = "pkg:npm/tuna".to_owned();
            record.version = Some("1.0.0".to_owned());
            record.files = vec![FileRecord {
                name: "tuna.tgz".to_owned(),
                url: "h://origin.test/tuna.tgz".to_owned(),
                size: None,
                digests: vec![Digest::new(alg, hex)],
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::Verified,
                origin: FileOrigin::Resolved,
            }];

            Record::Artifact(Box::new(record))
        };

        let (_dir, conn) = runs(vec![
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![with_digest(DigestAlg::Sha1, "aa")],
            ),
            one(
                Binding::new(Role::Source, "origin").observing(),
                vec![with_digest(DigestAlg::Sha256, "bb")],
            ),
        ]);

        let digests: Vec<String> = conn
            .prepare(
                "SELECT algorithm || ':' || hex FROM repository_file_digest
                 ORDER BY algorithm",
            )
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(digests, vec!["sha1:aa", "sha256:bb"]);
    }

    /// Source priority is what decides which of several sources a copy
    /// takes an artifact from, so a run has to record it rather than leave
    /// it to the order the bindings happened to arrive in.
    #[test]
    fn run_records_source_priority() {
        let (_dir, conn) = runs(vec![Run {
            bindings: vec![
                Binding {
                    priority: 2,
                    ..Binding::new(Role::Source, "backup").observing()
                },
                Binding {
                    priority: 1,
                    ..Binding::new(Role::Source, "primary").observing()
                },
            ],
            records: Vec::new(),
        }]);

        let order: Vec<(String, i64)> = conn
            .prepare(
                "SELECT r.name, rr.priority
                 FROM run_repository rr
                 JOIN repository r ON r.repository_id = rr.repository_id
                 ORDER BY rr.priority",
            )
            .expect("prepared")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(
            order,
            vec![("primary".to_owned(), 1), ("backup".to_owned(), 2)]
        );
    }

    /// **The narrow rule, stated as a test.** A run that read from two
    /// sources cannot say which one an artifact came from, so nothing is
    /// attributed: the history is kept and the inventory is left alone.
    /// Filing it under a guess would corrupt the one answer the inventory
    /// exists to give.
    #[test]
    fn run_ambiguous_records_history_not_inventory() {
        let (_dir, conn) = runs(vec![Run {
            bindings: vec![
                Binding::new(Role::Source, "first").observing(),
                Binding::new(Role::Source, "second").observing(),
            ],
            records: vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
        }]);

        assert_eq!(count(&conn, "artifact_observation"), 1, "history kept");
        assert_eq!(count(&conn, "repository_artifact"), 0, "nothing guessed");

        // The identity is still recorded, so a later unambiguous run adds
        // its inventory to rows that already exist.
        assert_eq!(count(&conn, "artifact"), 1);
    }

    /// An observation points at the inventory row it fed, so a reader can
    /// go from what a run said to what the repository currently holds
    /// without matching on a purl.
    #[test]
    fn observation_links_the_inventory_row_it_fed() {
        let (_dir, conn) = runs(vec![one(
            Binding::new(Role::Source, "origin").observing(),
            vec![artifact("pkg:npm/tuna", Some("1.0.0"))],
        )]);

        let linked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM artifact_observation o
                 JOIN repository_artifact ra
                   ON ra.repository_artifact_id = o.repository_artifact_id",
                [],
                |row| row.get(0),
            )
            .expect("read");

        assert_eq!(linked, 1);
    }

    /// Several runs filling out one repository's picture, which is the use
    /// case the whole format exists for: a migration too large for one
    /// invocation.
    #[test]
    fn inventory_is_built_incrementally() {
        let names = ["tuna", "salmon", "trout"];

        let (_dir, conn) = runs(
            names
                .iter()
                .map(|name| {
                    one(
                        Binding::new(Role::Source, "origin").observing(),
                        vec![artifact(&format!("pkg:npm/{name}"), Some("1.0.0"))],
                    )
                })
                .collect(),
        );

        assert_eq!(count(&conn, "repository"), 1);
        assert_eq!(count(&conn, "repository_artifact"), 3);
        assert_eq!(count(&conn, "run"), 3);
    }
}

/// Where a catalog walk stopped, and when one last finished.
///
/// The two questions `repository_enumeration` exists for. Both are about a walk
/// that is over, asked by the run that comes after it.
#[cfg(test)]
mod enumeration_tests {
    use crate::report::record::Record;
    use crate::report::sink::{Binding, Enumeration, ReportReader, ReportWriter, Role};

    use super::tests::header;
    use super::{DbReader, DbWriter};

    const CATALOG: &str = "catalog";

    fn scan<'a>(cursor: Option<&'a str>, pages: u64, reached_end: bool) -> Enumeration<'a> {
        Enumeration {
            repository: CATALOG,
            kind: "nexus",
            depth: "files",
            scope: None,
            cursor,
            pages,
            found: pages * 100,
            reached_end,
        }
    }

    /// Play one walk into a database. `finish` says whether the run closed
    /// tidily or was killed part way.
    fn walked(path: &std::path::Path, checkpoints: &[Enumeration<'_>], finish: bool) {
        let writer = DbWriter::open(path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");

        let state = writer.state().expect("a database keeps state");
        state
            .bind(&Binding::new(Role::Enumerator, CATALOG).observing())
            .expect("bound");

        for at in checkpoints {
            state.checkpoint(at).expect("checkpointed");
        }

        if finish {
            writer.flush().expect("flushed");
        }
    }

    /// A killed walk leaves its cursor, which is the whole point: paging a
    /// million-artifact catalog from the beginning costs hours before the
    /// walk reaches ground it has not covered.
    #[test]
    fn walk_killed_leaves_cursor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        walked(
            &path,
            &[
                scan(Some("page-1"), 1, false),
                scan(Some("page-2"), 2, false),
            ],
            false,
        );

        let reader = DbReader::open(&path).expect("reads");
        let resume = reader
            .query()
            .expect("a database answers questions")
            .resume_enumeration(Role::Enumerator, CATALOG)
            .expect("asked")
            .expect("a walk to resume");

        // The latest checkpoint, not the first.
        assert_eq!(resume.cursor.as_deref(), Some("page-2"));
        assert_eq!(resume.pages, 2);
        assert_eq!(resume.found, 200);

        // The kind travels with the cursor, because a cursor handed to a
        // different implementation means nothing.
        assert_eq!(resume.kind, "nexus");
    }

    /// The depth the enumerator declared is kept with its walk, so a reader
    /// can tell a name-only inventory from one that lists versions.
    #[test]
    fn walk_keeps_its_depth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        walked(&path, &[scan(None, 1, true)], true);

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let depth: String = conn
            .query_row("SELECT depth FROM repository_enumeration", [], |row| {
                row.get(0)
            })
            .expect("one walk");

        assert_eq!(depth, "files");
    }

    /// A walk that reached the end of the catalog has nothing to resume,
    /// and neither does a run that ended tidily short of it -- that one
    /// stopped for a reason of its own, and resuming it would be the tool
    /// doing work nobody asked for.
    #[test]
    fn run_finished_offers_nothing_to_resume() {
        let dir = tempfile::tempdir().expect("tempdir");

        let cases = [
            ("complete.sqlite", vec![scan(None, 3, true)], true),
            ("stopped.sqlite", vec![scan(Some("page-1"), 1, false)], true),
        ];

        for (name, checkpoints, finish) in cases {
            let path = dir.path().join(name);
            walked(&path, &checkpoints, finish);

            let reader = DbReader::open(&path).expect("reads");
            let resume = reader
                .query()
                .expect("query")
                .resume_enumeration(Role::Enumerator, CATALOG)
                .expect("asked");

            assert!(resume.is_none(), "{name} offered a resume");
        }
    }

    /// The date a repeated artifact enumeration asks a repository for, when
    /// the repository can answer "artifacts uploaded since DATE".
    ///
    /// The **start** of the walk, not its finish: a push during the walk
    /// may have been missed, so only from the start is "everything since"
    /// an honest claim.
    #[test]
    fn walk_last_complete_dates_inventory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let started = header().created;

        walked(&path, &[scan(None, 3, true)], true);

        let reader = DbReader::open(&path).expect("reads");
        let dated = reader
            .query()
            .expect("query")
            .last_complete_enumeration(Role::Enumerator, CATALOG)
            .expect("asked");

        assert_eq!(dated, Some(started));
    }

    /// Play one run binding `bindings`, walking the catalog to its end when
    /// `walk` says so.
    fn bound_run(path: &std::path::Path, bindings: &[Binding<'_>], walk: Option<Enumeration<'_>>) {
        let writer = DbWriter::open(path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");

        let state = writer.state().expect("a database keeps state");

        for binding in bindings {
            state.bind(binding).expect("bound");
        }

        if let Some(at) = walk {
            state.checkpoint(&at).expect("checkpointed");
        }

        writer.flush().expect("flushed");
    }

    fn listed(path: &std::path::Path, source: &str) -> bool {
        DbReader::open(path)
            .expect("reads")
            .query()
            .expect("query")
            .source_listed(source)
            .expect("asked")
    }

    /// `find --as-source` that reached the end lists the source; a run that
    /// only resolved against it, or a sampled or unfinished walk, does not.
    #[test]
    fn walk_whole_needed_for_source_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scanned = [
            Binding::new(Role::Enumerator, CATALOG),
            Binding::new(Role::Source, "origin").observing(),
        ];

        let whole = dir.path().join("whole.sqlite");
        bound_run(&whole, &scanned, Some(scan(None, 3, true)));
        assert!(listed(&whole, "origin"));
        assert!(!listed(&whole, "elsewhere"));

        let resolved = dir.path().join("resolved.sqlite");
        bound_run(
            &resolved,
            &[Binding::new(Role::Source, "origin").observing()],
            None,
        );
        assert!(!listed(&resolved, "origin"));

        let unfinished = dir.path().join("unfinished.sqlite");
        bound_run(&unfinished, &scanned, Some(scan(Some("page-1"), 1, false)));
        assert!(!listed(&unfinished, "origin"));

        let sampled = dir.path().join("sampled.sqlite");
        let mut partial = scan(None, 1, true);
        partial.scope = Some("sample=10%");
        bound_run(&sampled, &scanned, Some(partial));
        assert!(!listed(&sampled, "origin"));
    }

    /// An interrupted walk dates nothing. Treating a partial catalog as an
    /// inventory would let a later run skip what it never looked at, which
    /// is the quietest way to lose artifacts in a migration.
    #[test]
    fn walk_interrupted_dates_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        walked(&path, &[scan(Some("page-1"), 1, false)], false);

        let reader = DbReader::open(&path).expect("reads");
        let dated = reader
            .query()
            .expect("query")
            .last_complete_enumeration(Role::Enumerator, CATALOG)
            .expect("asked");

        assert_eq!(dated, None);
    }

    /// One walk of one repository per run, however many pages it took. A
    /// row per page would make the history of a million-artifact walk
    /// larger than the inventory it produced.
    #[test]
    fn walk_is_one_row_however_many_pages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let checkpoints: Vec<Enumeration<'_>> = (1..=20)
            .map(|page| scan(Some("page"), page, false))
            .collect();

        walked(&path, &checkpoints, false);

        let conn = rusqlite::Connection::open(&path).expect("opens");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM repository_enumeration", [], |row| {
                row.get(0)
            })
            .expect("counted");

        assert_eq!(rows, 1);
    }

    /// A line report has nowhere to put a cursor, so it keeps no state
    /// rather than answering emptily. A walk written to JSONL cannot be
    /// resumed and must not appear to be.
    #[test]
    fn line_report_answers_no_questions() {
        use crate::report::{LineWriter, ReportFormat};

        let writer = LineWriter::new(Vec::new(), ReportFormat::Json).expect("writer");
        assert!(writer.state().is_none());
        assert!(writer.query().expect("asked").is_none());
    }
}

/// Claimed copy work, and what a resumed run makes of it.
///
/// Every test here is about one ordering: the claim is committed before the
/// network work and the outcome after it, so a run killed anywhere in
/// between leaves a row that is true.
#[cfg(test)]
mod transfer_tests {
    use rusqlite::Connection;

    use crate::report::record::Record;
    use crate::report::sink::{Binding, Claim, Claimed, ReportWriter, Role, Transfer};

    use super::DbWriter;
    use super::tests::header;

    const TUNA: &str = "pkg:npm/tuna@1.0.0";

    /// One run's worth of claiming, so a test reads as the sequence of
    /// invocations it stands for.
    struct Run {
        writer: DbWriter,
    }

    impl Run {
        fn open(path: &std::path::Path, sources: &[&str], targets: &[&str]) -> Self {
            let writer = DbWriter::open(path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");

            let state = writer.state().expect("a database keeps state");

            for (priority, source) in sources.iter().enumerate() {
                state
                    .bind(&Binding {
                        priority: priority as i64,
                        ..Binding::new(Role::Source, source).observing()
                    })
                    .expect("bound");
            }

            for target in targets {
                state
                    .bind(&Binding::new(Role::Target, target))
                    .expect("bound");
            }

            Self { writer }
        }

        fn claim(&self, purl: &str, source: &str, destination: &str) -> Option<Claimed> {
            self.writer
                .state()
                .expect("state")
                .claim(&Claim {
                    purl,
                    source: Some(source),
                    destination,
                })
                .expect("claimed")
        }

        fn close(&self, claimed: Claimed, outcome: Transfer) {
            self.writer
                .state()
                .expect("state")
                .close(claimed, outcome)
                .expect("closed");
        }

        /// End the run tidily, as a command that finished would.
        fn finish(self) {
            self.writer.flush().expect("flushed");
        }

        /// End the run the way a kill does: nothing closed.
        fn killed(self) {}
    }

    fn state_of(conn: &Connection, purl: &str, destination: &str) -> String {
        conn.query_row(
            "SELECT t.state FROM artifact_transfer t
             JOIN artifact a ON a.artifact_id = t.artifact_id
             JOIN repository r ON r.repository_id = t.destination_repository_id
             WHERE a.purl = ? AND r.name = ?",
            rusqlite::params![purl, destination],
            |row| row.get(0),
        )
        .expect("read")
    }

    /// A terminal row is the whole resume mechanism: a second run is handed
    /// nothing to do.
    #[test]
    fn claim_again_copied_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let first = Run::open(&path, &["origin"], &["mirror"]);
        let claimed = first.claim(TUNA, "origin", "mirror").expect("work");
        first.close(claimed, Transfer::Copied);
        first.finish();

        let second = Run::open(&path, &["origin"], &["mirror"]);

        assert!(second.claim(TUNA, "origin", "mirror").is_none());
        second.finish();

        let conn = Connection::open(&path).expect("opens");
        assert_eq!(state_of(&conn, TUNA, "mirror"), "copied");
    }

    /// Every terminal state stops a re-claim, not only success. A refusal
    /// is a decision somebody made, and re-deciding it every run would make
    /// a policy change invisible and a migration never finish.
    #[test]
    fn reclaim_stopped_by_every_terminal_state() {
        let terminal = [
            Transfer::Copied,
            Transfer::AlreadyPresent,
            Transfer::Refused,
            Transfer::Unresolved,
            Transfer::Skipped,
        ];

        for outcome in terminal {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("report.sqlite");

            let first = Run::open(&path, &["origin"], &["mirror"]);
            let claimed = first.claim(TUNA, "origin", "mirror").expect("work");
            first.close(claimed, outcome);
            first.finish();

            let second = Run::open(&path, &["origin"], &["mirror"]);

            assert!(
                second.claim(TUNA, "origin", "mirror").is_none(),
                "{outcome:?} was claimed again"
            );

            second.finish();
        }
    }

    /// A failure is the one non-terminal outcome: nothing decided against
    /// the artifact, the transfer just did not succeed, and re-running may
    /// well take it.
    #[test]
    fn claim_again_failed_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let first = Run::open(&path, &["origin"], &["mirror"]);
        let claimed = first.claim(TUNA, "origin", "mirror").expect("work");
        first.close(claimed, Transfer::Failed);
        first.finish();

        let second = Run::open(&path, &["origin"], &["mirror"]);
        let again = second.claim(TUNA, "origin", "mirror").expect("work again");

        second.close(again, Transfer::Copied);
        second.finish();

        let conn = Connection::open(&path).expect("opens");

        assert_eq!(state_of(&conn, TUNA, "mirror"), "copied");

        // Both attempts are kept: the history is what an audit reads.
        let attempts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM artifact_transfer_attempt",
                [],
                |row| row.get(0),
            )
            .expect("counted");

        assert_eq!(attempts, 2);
    }

    /// **The crash boundary.** A run killed between the claim and the
    /// outcome leaves an `in-progress` row, and the next run has to be able
    /// to take it. Refusing would leave a migration permanently stuck on
    /// whatever it happened to be holding, which is the failure this whole
    /// feature exists to prevent.
    #[test]
    fn reclaim_killed_runs_claim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let killed = Run::open(&path, &["origin"], &["mirror"]);
        let _abandoned = killed.claim(TUNA, "origin", "mirror").expect("work");
        killed.killed();

        let conn = Connection::open(&path).expect("opens");
        assert_eq!(state_of(&conn, TUNA, "mirror"), "in-progress");
        drop(conn);

        let next = Run::open(&path, &["origin"], &["mirror"]);
        let reclaimed = next.claim(TUNA, "origin", "mirror").expect("reclaimed");

        next.close(reclaimed, Transfer::Copied);
        next.finish();

        let conn = Connection::open(&path).expect("opens");
        assert_eq!(state_of(&conn, TUNA, "mirror"), "copied");
    }

    /// A run that finished with a claim still open -- one unwinding from an
    /// abort -- left it abandoned just as a killed run does, and the next
    /// run takes it rather than refusing it as its own.
    #[test]
    fn reclaim_finished_runs_open_claim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let aborted = Run::open(&path, &["origin"], &["mirror"]);
        let _open = aborted.claim(TUNA, "origin", "mirror").expect("work");
        aborted.finish();

        let next = Run::open(&path, &["origin"], &["mirror"]);
        let reclaimed = next.claim(TUNA, "origin", "mirror").expect("reclaimed");

        next.close(reclaimed, Transfer::Copied);
        next.finish();

        let conn = Connection::open(&path).expect("opens");
        assert_eq!(state_of(&conn, TUNA, "mirror"), "copied");
    }

    /// And a claim this run already holds is reported as a fault in the
    /// report's bookkeeping, not in the user's configuration.
    #[test]
    fn claim_double_is_report_fault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let run = Run::open(&path, &["origin"], &["mirror"]);
        run.claim(TUNA, "origin", "mirror").expect("work");

        let again = run.writer.state().expect("state").claim(&Claim {
            purl: TUNA,
            source: Some("origin"),
            destination: "mirror",
        });

        let Err(err) = again else {
            panic!("one run claimed the same artifact twice");
        };

        assert_eq!(err.code(), crate::core::problem::Code::ReportUnusable);
    }

    /// The other half of the same rule. Two workers of *one* run racing for
    /// one artifact is a bug, not a crash, and answering both would copy it
    /// twice.
    #[test]
    fn claim_same_work_twice_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let run = Run::open(&path, &["origin"], &["mirror"]);

        run.claim(TUNA, "origin", "mirror").expect("work");

        let again = run.writer.state().expect("state").claim(&Claim {
            purl: TUNA,
            source: Some("origin"),
            destination: "mirror",
        });

        assert!(again.is_err(), "one run claimed the same artifact twice");
    }

    /// Source priority, which is the reason the summary is keyed by
    /// artifact and destination rather than by source. A lower-priority
    /// source must skip what a higher-priority one already delivered, and
    /// the query that decides never names either.
    #[test]
    fn second_source_skips_delivered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let first = Run::open(&path, &["primary"], &["mirror"]);
        let claimed = first.claim(TUNA, "primary", "mirror").expect("work");
        first.close(claimed, Transfer::Copied);
        first.finish();

        let second = Run::open(&path, &["backup"], &["mirror"]);

        assert!(
            second.claim(TUNA, "backup", "mirror").is_none(),
            "a second source copied what the first already delivered"
        );

        second.finish();

        // One row, because the question is "has it reached the target".
        let conn = Connection::open(&path).expect("opens");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM artifact_transfer", [], |row| {
                row.get(0)
            })
            .expect("counted");

        assert_eq!(rows, 1);
    }

    /// Two destinations are two pieces of work, exactly as two runs to
    /// different targets would be. The schema supports this before the CLI
    /// does, so that a future story adds an argument rather than a table.
    #[test]
    fn two_destinations_keep_separate_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let run = Run::open(&path, &["origin"], &["mirror", "spare"]);

        let to_mirror = run.claim(TUNA, "origin", "mirror").expect("work");
        run.close(to_mirror, Transfer::Copied);

        let to_spare = run.claim(TUNA, "origin", "spare").expect("work");
        run.close(to_spare, Transfer::Failed);
        run.finish();

        let conn = Connection::open(&path).expect("opens");

        assert_eq!(state_of(&conn, TUNA, "mirror"), "copied");
        assert_eq!(state_of(&conn, TUNA, "spare"), "failed");

        // A later run has the failed one still to do, and not the other.
        let next = Run::open(&path, &["origin"], &["mirror", "spare"]);

        assert!(next.claim(TUNA, "origin", "mirror").is_none());
        assert!(next.claim(TUNA, "origin", "spare").is_some());
    }

    /// A terminal row records when it finished; a non-terminal one must
    /// not, or a reader counting finished work would count a failure.
    #[test]
    fn only_terminal_work_is_dated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let run = Run::open(&path, &["origin"], &["mirror"]);
        let claimed = run.claim(TUNA, "origin", "mirror").expect("work");

        run.close(claimed, Transfer::Failed);

        let conn = Connection::open(&path).expect("opens");
        let completed: Option<i64> = conn
            .query_row("SELECT completed_ms FROM artifact_transfer", [], |row| {
                row.get(0)
            })
            .expect("read");

        assert!(completed.is_none(), "a failure was dated as finished");
        drop(conn);

        let claimed = run.claim(TUNA, "origin", "mirror").expect("work again");
        run.close(claimed, Transfer::Copied);
        run.finish();

        let conn = Connection::open(&path).expect("opens");
        let completed: Option<i64> = conn
            .query_row("SELECT completed_ms FROM artifact_transfer", [], |row| {
                row.get(0)
            })
            .expect("read");

        assert!(completed.is_some());
    }

    /// A failed attempt names the problem that failed it, so a reader can
    /// go from the attempt to the reason without matching on artifact.
    #[test]
    fn attempt_failed_names_problem() {
        use crate::core::message::Message;
        use crate::core::problem::{Action, Code};
        use crate::report::record::{Outcome, ProblemRecord};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let run = Run::open(&path, &["origin"], &["mirror"]);
        let claimed = run.claim(TUNA, "origin", "mirror").expect("work");

        run.close(claimed, Transfer::Failed);

        // What the copy command writes after closing a failed claim.
        let mut record = super::tests::full_artifact();
        record.purl = "pkg:npm/tuna".to_owned();
        record.version = Some("1.0.0".to_owned());
        record.outcome = Some(Outcome::Failed {
            why: Box::new(ProblemRecord {
                code: Code::RequestRejected,
                action: Action::SkipArtifact,
                quarantine: None,
                bypassed_by: None,
                message: Message::new("request-rejected").text("mirror responded 409"),
                provenance: Vec::new(),
            }),
        });

        run.writer
            .write(&Record::Artifact(Box::new(record)))
            .expect("written");
        run.finish();

        let conn = Connection::open(&path).expect("opens");
        let code: String = conn
            .query_row(
                "SELECT p.code FROM artifact_transfer_attempt a
                 JOIN problem p ON p.problem_id = a.problem_id",
                [],
                |row| row.get(0),
            )
            .expect("the attempt names a problem");

        assert_eq!(code, "request-rejected");
    }

    /// The attempt count is what a person reads to see an artifact nobody
    /// can copy, so it counts attempts rather than runs.
    #[test]
    fn attempts_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        for _ in 0..3 {
            let run = Run::open(&path, &["origin"], &["mirror"]);
            let claimed = run.claim(TUNA, "origin", "mirror").expect("work");

            run.close(claimed, Transfer::Failed);
            run.finish();
        }

        let conn = Connection::open(&path).expect("opens");
        let attempts: i64 = conn
            .query_row("SELECT attempts FROM artifact_transfer", [], |row| {
                row.get(0)
            })
            .expect("read");

        assert_eq!(attempts, 3);
    }

    /// A report that keeps no state claims nothing, and a copy against one
    /// behaves as it did before a database existed: every artifact is work.
    #[test]
    fn line_report_claims_nothing() {
        use crate::report::{LineWriter, ReportFormat};

        let writer = LineWriter::new(Vec::new(), ReportFormat::Json).expect("writer");

        assert!(writer.state().is_none());
    }
}

/// What a copy still has to move.
///
/// The query a resumed migration runs on every page, and the one the whole
/// schema is shaped around.
#[cfg(test)]
mod upload_tests {
    use rusqlite::Connection;

    use crate::report::record::Record;
    use crate::report::sink::{Binding, ReportWriter, Role, Sent, Side, Stage, Upload};

    use super::DbWriter;
    use super::tests::header;

    const TUNA: &str = "pkg:npm/tuna@1.0.0";
    const TARBALL: &str = "tuna-1.0.0.tgz";

    /// Open a run against `path`, send the tarball to each of `sent`, and
    /// close the run.
    fn sent(path: &std::path::Path, sent: &[(&str, Sent)]) {
        let writer = DbWriter::open(path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");

        let state = writer.state().expect("a database keeps state");

        for (destination, how) in sent {
            state
                .bind(&Binding::new(Role::Target, destination))
                .expect("bound");
            state
                .uploaded(&Upload {
                    source: "origin",
                    destination,
                    purl: TUNA,
                    file: TARBALL,
                    url: "h://origin.test/tuna.tgz",
                    sent: *how,
                    claimed: None,
                })
                .expect("recorded");
        }

        writer.flush().expect("flushed");
    }

    /// One summary per file and target, moved on by each attempt.
    fn summary(conn: &Connection, destination: &str) -> (String, i64, Option<i64>) {
        conn.query_row(
            "SELECT t.state, t.attempts, t.completed_ms FROM file_transfer t
             JOIN repository r ON r.repository_id = t.destination_repository_id
             WHERE t.direction = 'upload' AND r.name = ?",
            [destination],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read")
    }

    /// A failure then a success is one summary with two attempts, completed
    /// only by the second.
    #[test]
    fn upload_retry_moves_one_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");
        let blame = Some((Side::Target, Stage::Request));

        sent(&path, &[("mirror", Sent::Failed(blame))]);

        let conn = Connection::open(&path).expect("opens");
        let (state, attempts, completed) = summary(&conn, "mirror");

        assert_eq!((state.as_str(), attempts), ("failed", 1));
        assert!(completed.is_none(), "a failure completed the transfer");

        sent(&path, &[("mirror", Sent::Uploaded)]);

        let (state, attempts, completed) = summary(&conn, "mirror");

        assert_eq!((state.as_str(), attempts), ("uploaded", 2));
        assert!(completed.is_some());

        let blamed: Vec<(String, Option<String>)> = conn
            .prepare(
                "SELECT state, error_side FROM file_transfer_attempt
                 ORDER BY file_transfer_attempt_id",
            )
            .expect("prepared")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("queried")
            .collect::<rusqlite::Result<_>>()
            .expect("read");

        assert_eq!(
            blamed,
            [
                ("failed".to_owned(), Some("target".to_owned())),
                ("uploaded".to_owned(), None),
            ]
        );
    }

    /// Each target keeps its own summary for one file.
    #[test]
    fn upload_keyed_per_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        sent(
            &path,
            &[("mirror", Sent::AlreadyPresent), ("backup", Sent::Skipped)],
        );

        let conn = Connection::open(&path).expect("opens");

        assert_eq!(summary(&conn, "mirror").0, "already-present");
        assert_eq!(summary(&conn, "backup").0, "skipped");

        let files: i64 = conn
            .query_row("SELECT COUNT(*) FROM repository_file", [], |row| row.get(0))
            .expect("counted");

        assert_eq!(files, 1, "one source file, sent twice");
    }
}

#[cfg(test)]
mod work_tests {
    use chrono::{TimeZone, Utc};

    use crate::model::{Digest, DigestAlg, LastDownload};
    use crate::report::record::{FileOrigin, FileRecord, Record, Verification};
    use crate::report::sink::{Binding, Claim, ReportReader, ReportWriter, Role, Transfer, Work};

    use super::tests::{full_artifact, header};
    use super::{DbReader, DbWriter};

    const SOURCE: &str = "origin";
    const TARGET: &str = "mirror";

    /// Put an inventory in place: one run binding a source and observing
    /// each named artifact with one file.
    fn inventoried(path: &std::path::Path, source: &str, purls: &[&str]) {
        let writer = DbWriter::open(path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");
        writer
            .state()
            .expect("state")
            .bind(&Binding::new(Role::Source, source).observing())
            .expect("bound");

        for purl in purls {
            let mut record = full_artifact();
            record.purl = (*purl).to_owned();
            record.version = Some("1.0.0".to_owned());
            record.declared_license = Some("MIT".to_owned());
            record.files = vec![FileRecord {
                name: "payload.tgz".to_owned(),
                url: format!("h://{source}.test/payload.tgz"),
                size: Some(64),
                digests: vec![Digest::new(DigestAlg::Sha256, "ab")],
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::NotAttempted,
                origin: FileOrigin::Resolved,
            }];

            writer
                .write(&Record::Artifact(Box::new(record)))
                .expect("written");
        }

        writer.flush().expect("flushed");
    }

    /// What a resolution recorded beside a file reaches a copy fed from the
    /// inventory: the core-metadata document and the signatures. A file
    /// only an artifact enumeration listed says nothing of either.
    #[test]
    fn held_carries_file_companions() {
        use crate::model::{SigRef, SigScheme};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");
        let signature = SigRef {
            scheme: SigScheme::PypiAttestation,
            key_id: None,
            value: None,
            url: Some("h://origin.test/provenance".to_owned()),
        };

        let writer = DbWriter::open(&path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");
        writer
            .state()
            .expect("state")
            .bind(&Binding::new(Role::Source, SOURCE).observing())
            .expect("bound");

        let mut record = full_artifact();
        record.purl = "pkg:pypi/echo".to_owned();
        record.version = Some("1.0".to_owned());
        record.files = vec![
            FileRecord {
                name: "echo-1.0-py3-none-any.whl".to_owned(),
                url: "h://origin.test/echo-1.0-py3-none-any.whl".to_owned(),
                size: None,
                digests: Vec::new(),
                core_metadata: Some(vec![Digest::new(DigestAlg::Sha256, "cc")]),
                signatures: vec![signature.clone()],
                verification: Verification::NotAttempted,
                origin: FileOrigin::Resolved,
            },
            FileRecord {
                name: "echo-1.0.tar.gz".to_owned(),
                url: "h://origin.test/echo-1.0.tar.gz".to_owned(),
                size: None,
                digests: Vec::new(),
                core_metadata: Some(Vec::new()),
                signatures: Vec::new(),
                verification: Verification::NotAttempted,
                origin: FileOrigin::Resolved,
            },
            FileRecord {
                name: "echo-1.0.zip".to_owned(),
                url: "h://catalog.test/echo-1.0.zip".to_owned(),
                size: None,
                digests: Vec::new(),
                core_metadata: None,
                signatures: Vec::new(),
                verification: Verification::NotAttempted,
                origin: FileOrigin::Listed,
            },
        ];

        writer
            .write(&Record::Artifact(Box::new(record)))
            .expect("written");
        writer.flush().expect("flushed");

        let work = DbReader::open(&path)
            .expect("reads")
            .query()
            .expect("query")
            .held(SOURCE, "pkg:pypi/echo@1.0")
            .expect("asked")
            .expect("held");

        let [wheel, sdist, zip] = work.files.as_slice() else {
            panic!("expected three files, got {:?}", work.files);
        };

        assert_eq!(
            wheel.core_metadata,
            Some(vec![Digest::new(DigestAlg::Sha256, "cc")])
        );
        assert_eq!(wheel.signatures, vec![signature]);
        assert_eq!(sdist.core_metadata, Some(Vec::new()));
        assert_eq!(zip.core_metadata, None);
    }

    fn outstanding(path: &std::path::Path) -> Vec<Work> {
        DbReader::open(path)
            .expect("reads")
            .query()
            .expect("query")
            .outstanding(SOURCE, &[TARGET], 0, 100)
            .expect("asked")
    }

    /// Copy one artifact to the target, as a run would.
    fn copied(path: &std::path::Path, purl: &str, outcome: Transfer) {
        let writer = DbWriter::open(path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");

        let state = writer.state().expect("state");
        state
            .bind(&Binding::new(Role::Target, TARGET))
            .expect("bound");

        let claimed = state
            .claim(&Claim {
                purl,
                source: Some(SOURCE),
                destination: TARGET,
            })
            .expect("claimed")
            .expect("work");

        state.close(claimed, outcome).expect("closed");
        writer.flush().expect("flushed");
    }

    /// An inventory nothing has copied is entirely outstanding, and each
    /// entry carries what a copy needs rather than a coordinate to go and
    /// resolve again.
    #[test]
    fn outstanding_everything_uncopied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, SOURCE, &["pkg:npm/tuna", "pkg:npm/salmon"]);

        let work = outstanding(&path);

        assert_eq!(work.len(), 2);

        let one = &work[0];

        assert_eq!(one.purl, "pkg:npm/tuna@1.0.0");
        assert_eq!(one.version.as_deref(), Some("1.0.0"));
        assert_eq!(one.declared_license.as_deref(), Some("MIT"));
        assert!(one.published.is_some());

        // The files come with it, which is what lets a copy run against an
        // inventory without asking the source again.
        let [file] = one.files.as_slice() else {
            panic!("expected one file, got {:?}", one.files);
        };

        assert_eq!(file.name, "payload.tgz");
        assert_eq!(file.size, Some(64));
        assert_eq!(file.digests, vec![Digest::new(DigestAlg::Sha256, "ab")]);
    }

    /// The anti-join. A terminal transfer leaves the artifact out, and a
    /// failure leaves it in -- nothing decided against it, so re-running may
    /// well take it.
    #[test]
    fn delivered_drops_out_failed_stays() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, SOURCE, &["pkg:npm/tuna", "pkg:npm/salmon"]);

        copied(&path, "pkg:npm/tuna@1.0.0", Transfer::Copied);
        copied(&path, "pkg:npm/salmon@1.0.0", Transfer::Failed);

        let purls: Vec<String> = outstanding(&path).into_iter().map(|one| one.purl).collect();

        assert_eq!(purls, vec!["pkg:npm/salmon@1.0.0"]);
    }

    /// The counts agree with the lists they count: the inventory holds
    /// both, and only the failed one is outstanding.
    #[test]
    fn counts_match_lists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, SOURCE, &["pkg:npm/tuna", "pkg:npm/salmon"]);
        copied(&path, "pkg:npm/tuna@1.0.0", Transfer::Copied);
        copied(&path, "pkg:npm/salmon@1.0.0", Transfer::Failed);

        let reader = DbReader::open(&path).expect("reads");
        let query = reader.query().expect("query");

        assert_eq!(
            query.outstanding_count(SOURCE, &[TARGET]).expect("asked"),
            Some(1)
        );
        assert_eq!(
            query.outstanding_count(SOURCE, &[]).expect("asked"),
            Some(0)
        );
        assert_eq!(query.inventory_count(SOURCE).expect("asked"), Some(2));
        assert_eq!(query.inventory_count("elsewhere").expect("asked"), Some(0));
    }

    /// **Source priority, settled by a query that names neither source.**
    /// An artifact a higher-priority source already delivered is not
    /// offered to a lower-priority one, because the question is whether it
    /// reached the target.
    #[test]
    fn second_source_offered_only_leftovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, "primary", &["pkg:npm/tuna", "pkg:npm/salmon"]);
        inventoried(&path, "backup", &["pkg:npm/tuna", "pkg:npm/trout"]);

        // The primary delivers one of the two it holds.
        let writer = DbWriter::open(&path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");
        let state = writer.state().expect("state");
        state
            .bind(&Binding::new(Role::Target, TARGET))
            .expect("bound");
        let claimed = state
            .claim(&Claim {
                purl: "pkg:npm/tuna@1.0.0",
                source: Some("primary"),
                destination: TARGET,
            })
            .expect("claimed")
            .expect("work");
        state.close(claimed, Transfer::Copied).expect("closed");
        writer.flush().expect("flushed");

        let reader = DbReader::open(&path).expect("reads");
        let query = reader.query().expect("query");

        let backup: Vec<String> = query
            .outstanding("backup", &[TARGET], 0, 100)
            .expect("asked")
            .into_iter()
            .map(|one| one.purl)
            .collect();

        // The backup holds tuna too, and is not offered it.
        assert_eq!(backup, vec!["pkg:npm/trout@1.0.0"]);

        let primary: Vec<String> = query
            .outstanding("primary", &[TARGET], 0, 100)
            .expect("asked")
            .into_iter()
            .map(|one| one.purl)
            .collect();

        assert_eq!(primary, vec!["pkg:npm/salmon@1.0.0"]);
    }

    /// Each destination has its own outstanding list, exactly as two runs
    /// to different targets would.
    #[test]
    fn each_destination_has_its_own_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, SOURCE, &["pkg:npm/tuna"]);
        copied(&path, "pkg:npm/tuna@1.0.0", Transfer::Copied);

        let reader = DbReader::open(&path).expect("reads");
        let query = reader.query().expect("query");

        assert!(
            query
                .outstanding(SOURCE, &[TARGET], 0, 100)
                .expect("asked")
                .is_empty()
        );

        // A target nothing has been copied to still has everything to do,
        // and its repository row does not even exist yet.
        let spare = query
            .outstanding(SOURCE, &["spare"], 0, 100)
            .expect("asked");

        assert_eq!(spare.len(), 1);
    }

    /// An artifact stays outstanding while any named destination still
    /// needs it, so a copy to several targets is handed what one lacks.
    #[test]
    fn outstanding_for_any_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, SOURCE, &["pkg:npm/tuna"]);
        copied(&path, "pkg:npm/tuna@1.0.0", Transfer::Copied);

        let reader = DbReader::open(&path).expect("reads");
        let query = reader.query().expect("query");

        let either = query
            .outstanding(SOURCE, &[TARGET, "spare"], 0, 100)
            .expect("asked");
        assert_eq!(either.len(), 1);

        let neither = query.outstanding(SOURCE, &[], 0, 100).expect("asked");
        assert!(neither.is_empty());
    }

    /// Paged on the key rather than an offset, because the run reading a
    /// page is usually the run writing the next one: an offset would skip
    /// work as rows left the outstanding set.
    #[test]
    fn work_pages_on_its_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let purls: Vec<String> = (0..7).map(|n| format!("pkg:npm/fish{n}")).collect();
        let borrowed: Vec<&str> = purls.iter().map(String::as_str).collect();

        inventoried(&path, SOURCE, &borrowed);

        let reader = DbReader::open(&path).expect("reads");
        let query = reader.query().expect("query");

        let mut seen = Vec::new();
        let mut after = 0;

        loop {
            let page = query
                .outstanding(SOURCE, &[TARGET], after, 3)
                .expect("asked");

            if page.is_empty() {
                break;
            }

            after = page.last().expect("a page").key;
            seen.extend(page.into_iter().map(|one| one.purl));
        }

        assert_eq!(seen.len(), 7);

        // Paging a second time, after delivering the first three, offers
        // only what is left rather than shifting the window.
        for purl in seen.iter().take(3) {
            copied(&path, purl, Transfer::Copied);
        }

        let left = query.outstanding(SOURCE, &[TARGET], 0, 100).expect("asked");

        assert_eq!(left.len(), 4);
    }

    /// A catalog that lists names only is **returned**, and the reader
    /// decides.
    ///
    /// This query used to carry `AND a.version IS NOT NULL`, which kept an
    /// npm name-only row out of a copy's work list and, as a side effect,
    /// kept every artifact of a raw repository out too -- recorded
    /// correctly and then invisible. The two look identical here and are
    /// opposite instructions, so `commands::inspect::asked_for` tells them
    /// apart by asking the ecosystem. See the companion test there.
    #[test]
    fn name_only_row_returned_without_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let writer = DbWriter::open(&path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");
        writer
            .state()
            .expect("state")
            .bind(&Binding::new(Role::Source, SOURCE).observing())
            .expect("bound");

        let mut record = full_artifact();
        record.purl = "pkg:npm/tuna".to_owned();
        record.version = None;
        record.files = Vec::new();

        writer
            .write(&Record::Artifact(Box::new(record)))
            .expect("written");
        writer.flush().expect("flushed");

        let work = outstanding(&path);

        assert_eq!(work.len(), 1);
        assert_eq!(work[0].purl, "pkg:npm/tuna");
        assert_eq!(work[0].version, None);
    }

    /// **An artifact with no version is copyable work.**
    ///
    /// The single row this whole design turns on. A raw repository's
    /// directory has no version because there is none, and while the query
    /// filtered `NULL` away such a repository could be walked, recorded and
    /// then never copied -- the failure mode that is invisible until
    /// somebody notices the target is empty.
    #[test]
    fn outstanding_artifact_without_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let writer = DbWriter::open(&path).expect("opens");
        writer.write(&Record::Header(header())).expect("header");
        writer
            .state()
            .expect("state")
            .bind(&Binding::new(Role::Source, SOURCE).observing())
            .expect("bound");

        let mut record = full_artifact();
        record.purl = "pkg:raw/artifact1%2F1.0".to_owned();
        record.version = None;

        writer
            .write(&Record::Artifact(Box::new(record)))
            .expect("written");
        writer.flush().expect("flushed");

        let work = outstanding(&path);

        assert_eq!(work.len(), 1);
        assert_eq!(work[0].version, None);

        // And it carries its files, which is what makes it copyable rather
        // than merely present.
        assert!(!work[0].files.is_empty());
    }

    /// **A later observation saying "never" does not erase an earlier one
    /// that saw a download.**
    ///
    /// Two observations of one artifact used to be impossible -- one
    /// component, one row, one page -- and a raw repository read as
    /// directories makes them ordinary, because a directory's files
    /// straddle pages. The merge was last-evidence-wins, so a later page
    /// reporting a file nobody had fetched would overwrite an earlier
    /// page's record of one that had been. Reporting `Never` for something
    /// used last week is exactly the mistake that gets a live artifact
    /// deleted.
    #[test]
    fn last_download_later_never_keeps_earlier() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let used = Utc.timestamp_millis_opt(1_700_000_000_000).unwrap();

        let observe = |last_download| {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
            writer
                .state()
                .expect("state")
                .bind(&Binding::new(Role::Source, SOURCE).observing())
                .expect("bound");

            let mut record = full_artifact();
            record.purl = "pkg:raw/a%2Fb".to_owned();
            record.version = None;
            record.last_download = last_download;

            writer
                .write(&Record::Artifact(Box::new(record)))
                .expect("written");
            writer.flush().expect("flushed");
        };

        observe(LastDownload::At(used));
        observe(LastDownload::Never);

        assert_eq!(
            merged_download(&path),
            ("at".to_owned(), Some(used.timestamp_millis()))
        );
    }

    /// And the reverse order agrees, which is what makes it a rule about
    /// evidence rather than about which page happened to arrive last.
    #[test]
    fn last_download_never_replaced_by_later() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let used = Utc.timestamp_millis_opt(1_700_000_000_000).unwrap();

        let observe = |last_download| {
            let writer = DbWriter::open(&path).expect("opens");
            writer.write(&Record::Header(header())).expect("header");
            writer
                .state()
                .expect("state")
                .bind(&Binding::new(Role::Source, SOURCE).observing())
                .expect("bound");

            let mut record = full_artifact();
            record.purl = "pkg:raw/a%2Fb".to_owned();
            record.version = None;
            record.last_download = last_download;

            writer
                .write(&Record::Artifact(Box::new(record)))
                .expect("written");
            writer.flush().expect("flushed");
        };

        observe(LastDownload::Never);
        observe(LastDownload::At(used));

        assert_eq!(
            merged_download(&path),
            ("at".to_owned(), Some(used.timestamp_millis()))
        );
    }

    /// What the inventory merge *stored*, which is the thing under test.
    ///
    /// Read from `repository_artifact` rather than from the record stream,
    /// and the difference is the point: the stream replays each observation
    /// verbatim, because an event log that folded its events would stop
    /// being one. The merged answer -- what this repository is now believed
    /// to hold -- lives in the table, and that is what a retention decision
    /// would read.
    fn merged_download(path: &std::path::Path) -> (String, Option<i64>) {
        let conn = rusqlite::Connection::open(path).expect("opens");

        conn.query_row(
            "SELECT last_download_state, last_download_ms FROM repository_artifact",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("one row")
    }

    /// A source nothing has inventoried has nothing outstanding, rather
    /// than erroring: asking about a repository this database has not seen
    /// is an ordinary question with an empty answer.
    #[test]
    fn unknown_source_has_no_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        inventoried(&path, SOURCE, &["pkg:npm/tuna"]);

        let work = DbReader::open(&path)
            .expect("reads")
            .query()
            .expect("query")
            .outstanding("never-configured", &[TARGET], 0, 100)
            .expect("asked");

        assert!(work.is_empty());
    }
}
