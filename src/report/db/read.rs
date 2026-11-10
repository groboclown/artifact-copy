//! Rows becoming a [`Record`] again.
//!
//! The inverse of [`super::write`], and the reason `report_record` keeps a
//! sequence: a reader hands back what a run wrote, in the order it wrote
//! it, so a database report and a JSONL report of the same run are the same
//! records. Nothing here invents a second report model.
//!
//! # Paged, never held
//!
//! A database holds every run ever written to it, so nothing here collects
//! the stream. Records come back a page at a time, keyed on the stream
//! position rather than offset by it -- a run reading a page may be the run
//! writing the next one, and `OFFSET` would skip records as rows arrive.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::advisory::CorpusAge;
use crate::core::message::Message;
use crate::core::problem::{Action, Code, Quarantine};
use crate::model::{
    CAUSE_ID_PREFIX, Digest, DigestAlg, LastDownload, SigRef, SigScheme, cause_arg,
};
use crate::policy::Decision;
use crate::report::record::{
    AdvisoryRecord, ArtifactRecord, BypassRecord, DestinationOutcome, FileRecord, Header,
    LicenseRecord, Outcome, ProblemRecord, QuarantineRecord, Record, Summary, SuppressionRecord,
    Verification,
};

use super::ids::failed;
use super::spell;

/// How many stream positions one query takes.
const PAGE: i64 = 256;

/// One row of `report_record`, before its body is read.
struct Position {
    record_id: i64,
    run_id: i64,
    kind: String,
}

/// One page of records, and the stream position the page reached.
///
/// The position comes back separately because a page can legitimately hold
/// no records: a killed run leaves stream positions with no body under
/// them, and a caller that stopped on an empty page would stop early.
pub(super) fn page(
    conn: &Connection,
    after: i64,
) -> Result<(Vec<Record>, i64), crate::core::error::Error> {
    let positions = positions(conn, after)?;
    let mut reached = after;
    let mut records = Vec::with_capacity(positions.len());

    for position in positions {
        reached = position.record_id;

        // A record whose body is missing is skipped rather than fatal, for
        // the same reason a line reader skips a line it cannot parse:
        // losing the rest of the report over one would be the wrong trade.
        if let Some(record) = body(conn, &position)? {
            records.push(record);
        }
    }

    Ok((records, reached))
}

fn positions(conn: &Connection, after: i64) -> Result<Vec<Position>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT report_record_id, run_id, kind FROM report_record
             WHERE report_record_id > ?
             ORDER BY report_record_id
             LIMIT ?",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![after, PAGE], |row| {
            Ok(Position {
                record_id: row.get(0)?,
                run_id: row.get(1)?,
                kind: row.get(2)?,
            })
        })
        .map_err(failed)?;

    rows.collect::<std::result::Result<_, _>>().map_err(failed)
}

fn body(
    conn: &Connection,
    position: &Position,
) -> Result<Option<Record>, crate::core::error::Error> {
    match position.kind.as_str() {
        "header" => header(conn, position.run_id).map(|header| header.map(Record::Header)),

        "artifact" => artifact(conn, position.record_id)
            .map(|record| record.map(|record| Record::Artifact(Box::new(record)))),

        "problem" => problem_at(conn, position.record_id).map(|record| record.map(Record::Problem)),

        "summary" => summary(conn, position.run_id).map(|record| record.map(Record::Summary)),

        // A kind this build does not know is skipped, for the same reason a
        // line reader skips a line it cannot parse.
        _ => Ok(None),
    }
}

fn header(conn: &Connection, run_id: i64) -> Result<Option<Header>, crate::core::error::Error> {
    let found: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT command, tool_version, started_ms FROM run WHERE run_id = ?",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(failed)?;

    let Some((command, tool_version, started_ms)) = found else {
        return Ok(None);
    };

    let mut statement = conn
        .prepare(
            "SELECT advisor, state, modified_ms, why FROM run_corpus
             WHERE run_id = ? ORDER BY advisor",
        )
        .map_err(failed)?;

    let ages = statement
        .query_map(params![run_id], |row| {
            let advisor: String = row.get(0)?;
            let state: String = row.get(1)?;
            let modified_ms: Option<i64> = row.get(2)?;
            let why: Option<String> = row.get(3)?;

            Ok((advisor, corpus(&state, modified_ms, why)))
        })
        .map_err(failed)?;

    let mut corpus_age = BTreeMap::new();

    for age in ages {
        let (advisor, age) = age.map_err(failed)?;

        corpus_age.insert(advisor, age);
    }

    Ok(Some(Header {
        created: at(started_ms),
        tool_version,
        command,
        corpus_age,
    }))
}

fn artifact(
    conn: &Connection,
    record_id: i64,
) -> Result<Option<ArtifactRecord>, crate::core::error::Error> {
    let found = conn
        .query_row(
            "SELECT o.artifact_observation_id, a.purl, o.version, o.requested,
                    o.last_download_state, o.last_download_ms, o.declared_license,
                    o.published_ms, o.outcome, o.outcome_verification, o.provenance_chain_id
             FROM artifact_observation o
             JOIN artifact a ON a.artifact_id = o.artifact_id
             WHERE o.report_record_id = ?",
            params![record_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    // The stored purl is the exact one, and a record's purl
                    // field is the version-less form with the version
                    // beside it, so the version is stripped back off here.
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;

    let Some((
        observation,
        purl,
        version,
        requested,
        download_state,
        download_ms,
        declared_license,
        published_ms,
        outcome,
        outcome_verification,
        chain,
    )) = found
    else {
        return Ok(None);
    };

    let parsed = crate::model::ArtifactId::parse(&purl)?;
    let outcomes = outcomes(conn, observation)?;

    // With several targets, the overall outcome is the first target's that
    // matches it, reason and all; see `copy::worst`.
    let outcome = match outcome {
        None => None,
        Some(outcome) if !outcomes.is_empty() => outcomes
            .iter()
            .find(|at| spell::outcome(&at.outcome) == outcome)
            .map(|at| at.outcome.clone()),
        Some(outcome) => Some(rebuild_outcome(
            &outcome,
            outcome_verification.as_deref(),
            || problem_of_outcome(conn, observation),
        )?),
    };

    Ok(Some(ArtifactRecord {
        purl: parsed.id.purl(),
        version,
        requested,
        outcome,
        outcomes,
        last_download: last_download(&download_state, download_ms),
        files: files(conn, observation)?,
        declared_license,
        license: license(conn, observation)?,
        published: published_ms.map(at),
        advisories: advisories(conn, observation)?,
        quarantine: quarantines(conn, observation)?,
        provenance: chain
            .map(|chain| provenance(conn, chain))
            .transpose()?
            .unwrap_or_default(),
    }))
}

/// What became of an observed artifact at each target, in `--to` order;
/// empty unless a copy had several.
fn outcomes(
    conn: &Connection,
    observation: i64,
) -> Result<Vec<DestinationOutcome>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT r.name, oo.outcome, oo.outcome_verification, oo.problem_id
             FROM observation_outcome oo
             JOIN repository r ON r.repository_id = oo.destination_repository_id
             WHERE oo.artifact_observation_id = ?
             ORDER BY oo.ordinal",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![observation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(failed)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(failed)?;

    let mut found = Vec::with_capacity(rows.len());

    for (destination, outcome, verification, problem) in rows {
        let why = || match problem {
            Some(problem) => one_problem(conn, "WHERE p.problem_id = ?", params![problem]),
            None => Ok(None),
        };

        found.push(DestinationOutcome {
            destination,
            outcome: rebuild_outcome(&outcome, verification.as_deref(), why)?,
        });
    }

    Ok(found)
}

/// An outcome from its column, with its reason from `reason` when it
/// carries one.
fn rebuild_outcome(
    outcome: &str,
    verification: Option<&str>,
    reason: impl Fn() -> Result<Option<ProblemRecord>, crate::core::error::Error>,
) -> Result<Outcome, crate::core::error::Error> {
    let why = || -> Result<Box<ProblemRecord>, crate::core::error::Error> {
        let record = reason()?.unwrap_or_else(|| ProblemRecord {
            code: Code::Unimplemented,
            action: Action::Warn,
            quarantine: None,
            bypassed_by: None,
            message: Message::new("report-reason-missing"),
            provenance: Vec::new(),
        });

        Ok(Box::new(record))
    };

    Ok(match outcome {
        "copied" => Outcome::Copied {
            verification: verification
                .map(verified)
                .unwrap_or(Verification::NotAttempted),
        },

        "already-present" => Outcome::AlreadyPresent,
        "refused" => Outcome::Refused { why: why()? },
        "unresolved" => Outcome::Unresolved { why: why()? },

        _ => Outcome::Failed { why: why()? },
    })
}

fn files(
    conn: &Connection,
    observation: i64,
) -> Result<Vec<FileRecord>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT observation_file_id, name, url, size_bytes, verification, origin,
                    core_metadata
             FROM observation_file
             WHERE artifact_observation_id = ?
             ORDER BY observation_file_id",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![observation], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<bool>>(6)?,
            ))
        })
        .map_err(failed)?;

    let mut files = Vec::new();

    for row in rows {
        let (file_id, name, url, size, how, origin, core_metadata) = row.map_err(failed)?;

        let core_metadata = match core_metadata {
            Some(true) => Some(digests(conn, CORE_METADATA_DIGESTS, file_id)?),
            _ => None,
        };

        files.push(FileRecord {
            name,
            url,
            size: size.map(|size| size as u64),
            digests: digests(conn, FILE_DIGESTS, file_id)?,
            core_metadata,
            signatures: signatures(conn, file_id)?,
            verification: how
                .as_deref()
                .map(verified)
                .unwrap_or(Verification::NotAttempted),

            // The CHECK allows only the two spellings; a newer one this
            // build does not know reads as the older, stricter claim.
            origin: spell::value(&origin).unwrap_or_default(),
        });
    }

    Ok(files)
}

/// The history table holding a file's own digests.
const FILE_DIGESTS: &str = "observation_file_digest";

/// The history table holding the digests of a file's core-metadata document.
const CORE_METADATA_DIGESTS: &str = "observation_file_core_metadata_digest";

/// One file's digests from `table`, one of the two above.
fn digests(
    conn: &Connection,
    table: &str,
    file_id: i64,
) -> Result<Vec<Digest>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT algorithm, hex FROM {table}
             WHERE observation_file_id = ? ORDER BY ordinal"
        ))
        .map_err(failed)?;

    let rows = statement
        .query_map(params![file_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(failed)?;

    let mut digests = Vec::new();

    for row in rows {
        let (algorithm, hex) = row.map_err(failed)?;

        // An algorithm this build does not know is dropped rather than
        // guessed at: a wrong algorithm on a digest is worse than a missing
        // digest, because something would check against it.
        if let Some(alg) = spell::value::<DigestAlg>(&algorithm) {
            digests.push(Digest::new(alg, hex));
        }
    }

    Ok(digests)
}

fn signatures(conn: &Connection, file_id: i64) -> Result<Vec<SigRef>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT scheme, key_id, value, url FROM observation_file_signature
             WHERE observation_file_id = ? ORDER BY ordinal",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![file_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(failed)?;

    let mut signatures = Vec::new();

    for row in rows {
        let (scheme, key_id, value, url) = row.map_err(failed)?;

        // A scheme this build does not know is dropped: nothing here could
        // check it, and guessing would claim a signature of another kind.
        let Some(scheme) = spell::value::<SigScheme>(&scheme) else {
            continue;
        };

        signatures.push(SigRef {
            scheme,
            key_id,
            value,
            url,
        });
    }

    Ok(signatures)
}

fn license(
    conn: &Connection,
    observation: i64,
) -> Result<Option<LicenseRecord>, crate::core::error::Error> {
    let found = conn
        .query_row(
            "SELECT decision, spdx, reason_id, reason_args, reason_text
             FROM observation_license WHERE artifact_observation_id = ?",
            params![observation],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;

    let Some((decided, spdx, reason_id, reason_args, reason_text)) = found else {
        return Ok(None);
    };

    let mut statement = conn
        .prepare(
            "SELECT dep_kind, decision FROM observation_license_usage
             WHERE artifact_observation_id = ? ORDER BY dep_kind",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![observation], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(failed)?;

    let mut usage = BTreeMap::new();

    for row in rows {
        let (kind, decided) = row.map_err(failed)?;

        if let Some(kind) = spell::value::<crate::model::DepKind>(&kind) {
            usage.insert(kind, spell::value(&decided).unwrap_or(Decision::Forbid));
        }
    }

    Ok(Some(LicenseRecord {
        decision: spell::value(&decided).unwrap_or(Decision::Forbid),
        spdx,
        reason: message(reason_id, reason_args, reason_text),
        usage,
    }))
}

fn advisories(
    conn: &Connection,
    observation: i64,
) -> Result<Vec<AdvisoryRecord>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT a.id, a.kind, a.summary, s.source, s.justification, s.detail,
                    oa.advisor, oa.certainty
             FROM observation_advisory oa
             JOIN advisory a ON a.advisory_id = oa.advisory_id
             LEFT JOIN suppression s ON s.suppression_id = oa.suppression_id
             WHERE oa.artifact_observation_id = ?
             ORDER BY oa.ordinal",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![observation], |row| {
            Ok(AdvisoryRecord {
                id: row.get(0)?,
                advisor: row.get(6)?,
                kind: spelled(row, 1)?,
                certainty: spelled(row, 7)?,
                summary: row.get(2)?,
                suppressed_by: suppression(row)?,
            })
        })
        .map_err(failed)?;

    rows.collect::<std::result::Result<_, _>>().map_err(failed)
}

/// A one-word enum column, refused rather than guessed when it does not
/// spell a variant this build knows.
fn spelled<T: serde::de::DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    let text: String = row.get(column)?;

    spell::value(&text).ok_or_else(|| {
        rusqlite::Error::InvalidColumnType(column, text, rusqlite::types::Type::Text)
    })
}

fn suppression(row: &Row<'_>) -> rusqlite::Result<Option<SuppressionRecord>> {
    let source: Option<String> = row.get(3)?;

    Ok(source.map(|source| SuppressionRecord {
        justification: row.get(4).unwrap_or(None),
        detail: row.get(5).unwrap_or(None),
        source,
    }))
}

fn quarantines(
    conn: &Connection,
    observation: i64,
) -> Result<Vec<QuarantineRecord>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT q.code, q.class, q.hardened, b.source, b.justification, b.expires_ms
             FROM observation_quarantine q
             LEFT JOIN bypass b ON b.bypass_id = q.bypass_id
             WHERE q.artifact_observation_id = ?
             ORDER BY q.ordinal",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![observation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                bypass(row, 3)?,
            ))
        })
        .map_err(failed)?;

    let mut held = Vec::new();

    for row in rows {
        let (code, class, hardened, bypassed_by) = row.map_err(failed)?;

        let Some(code) = spell::value::<Code>(&code) else {
            continue;
        };

        held.push(QuarantineRecord {
            code,
            class: quarantine_of(&class),
            hardened: hardened != 0,
            bypassed_by,
        });
    }

    Ok(held)
}

fn bypass(row: &Row<'_>, first: usize) -> rusqlite::Result<Option<BypassRecord>> {
    let source: Option<String> = row.get(first)?;

    Ok(source.map(|source| BypassRecord {
        justification: row.get(first + 1).unwrap_or(None),
        source,
        expires: row.get::<_, Option<i64>>(first + 2).unwrap_or(None).map(at),
    }))
}

fn problem_at(
    conn: &Connection,
    record_id: i64,
) -> Result<Option<ProblemRecord>, crate::core::error::Error> {
    one_problem(conn, "WHERE p.report_record_id = ?", params![record_id])
}

fn problem_of_outcome(
    conn: &Connection,
    observation: i64,
) -> Result<Option<ProblemRecord>, crate::core::error::Error> {
    one_problem(
        conn,
        "WHERE p.artifact_observation_id = ?",
        params![observation],
    )
}

fn one_problem(
    conn: &Connection,
    filter: &str,
    bound: impl rusqlite::Params,
) -> Result<Option<ProblemRecord>, crate::core::error::Error> {
    let found = conn
        .query_row(
            &format!(
                "SELECT p.code, p.action, p.quarantine, p.message_id, p.message_args,
                        p.message_text, p.provenance_chain_id,
                        b.source, b.justification, b.expires_ms
                 FROM problem p
                 LEFT JOIN bypass b ON b.bypass_id = p.bypass_id
                 {filter}
                 ORDER BY p.problem_id
                 LIMIT 1"
            ),
            bound,
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    bypass(row, 7)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;

    let Some((code, action, class, message_id, message_args, message_text, chain, bypassed_by)) =
        found
    else {
        return Ok(None);
    };

    Ok(Some(ProblemRecord {
        code: spell::value(&code).unwrap_or(Code::Unimplemented),
        action: action_of(&action),
        quarantine: class.as_deref().map(quarantine_of),
        bypassed_by,
        message: message(message_id, message_args, message_text),
        provenance: chain
            .map(|chain| provenance(conn, chain))
            .transpose()?
            .unwrap_or_default(),
    }))
}

/// A chain's links, leaf first, as the messages the writer was handed.
///
/// Built from the pieces rather than the English, which comes back only as
/// the fallback text. A kind this build does not know still reads, with
/// whatever arguments its columns hold.
fn provenance(conn: &Connection, chain: i64) -> Result<Vec<Message>, crate::core::error::Error> {
    let mut statement = conn
        .prepare(
            "SELECT pi.kind, pi.rendered, pi.arg, pi.lock_path, pi.lock_entry,
                    parent.purl, parent.release, pi.dep_kind, pi.enumerator,
                    pi.report_path, pi.report_entry, pi.report_source,
                    (SELECT group_concat(pd.destination, ? ORDER BY pd.position)
                     FROM provenance_destination pd
                     WHERE pd.provenance_chain_id = pi.provenance_chain_id
                       AND pd.ordinal = pi.ordinal),
                    pi.report_run_id
             FROM provenance_item pi
             LEFT JOIN artifact parent ON parent.artifact_id = pi.parent_artifact_id
             WHERE pi.provenance_chain_id = ? ORDER BY pi.ordinal",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![cause_arg::DESTINATION_SEPARATOR, chain], cause)
        .map_err(failed)?;

    rows.collect::<std::result::Result<_, _>>().map_err(failed)
}

/// One `provenance_item` row, as its cause message.
fn cause(row: &Row<'_>) -> rusqlite::Result<Message> {
    let kind: String = row.get(0)?;
    let mut message =
        Message::new(format!("{CAUSE_ID_PREFIX}{kind}")).text(row.get::<_, String>(1)?);

    // Column order as selected above, after the kind and the text.
    let pieces = [
        cause_arg::ARG,
        cause_arg::PATH,
        cause_arg::ENTRY,
        cause_arg::PURL,
        cause_arg::RELEASE,
        cause_arg::KIND,
        cause_arg::ENUMERATOR,
        cause_arg::PATH,
        cause_arg::PURL,
        cause_arg::SOURCE,
        cause_arg::DESTINATION,
    ];

    for (column, name) in pieces.into_iter().enumerate() {
        if let Some(value) = row.get::<_, Option<String>>(column + 2)? {
            message = message.arg(name, value);
        }
    }

    if let Some(run) = row.get::<_, Option<i64>>(pieces.len() + 2)? {
        message = message.arg(cause_arg::RUN, run);
    }

    Ok(message)
}

fn summary(conn: &Connection, run_id: i64) -> Result<Option<Summary>, crate::core::error::Error> {
    let found: Option<(i64, String)> = conn
        .query_row(
            "SELECT artifacts, worst_action FROM run_summary WHERE run_id = ?",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(failed)?;

    let Some((artifacts, worst_action)) = found else {
        return Ok(None);
    };

    let mut counts = BTreeMap::new();
    let mut statement = conn
        .prepare("SELECT code, count FROM summary_code_count WHERE run_id = ?")
        .map_err(failed)?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(failed)?;

    for row in rows {
        let (code, count) = row.map_err(failed)?;

        if let Some(code) = spell::value::<Code>(&code) {
            counts.insert(code, count as u64);
        }
    }

    let mut quarantined = BTreeMap::new();
    let mut statement = conn
        .prepare("SELECT class, count FROM summary_quarantine_count WHERE run_id = ?")
        .map_err(failed)?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(failed)?;

    for row in rows {
        let (class, count) = row.map_err(failed)?;

        quarantined.insert(quarantine_of(&class), count as u64);
    }

    let mut statement = conn
        .prepare(
            "SELECT statement FROM summary_unmatched_suppression
             WHERE run_id = ? ORDER BY statement",
        )
        .map_err(failed)?;
    let rows = statement
        .query_map(params![run_id], |row| row.get(0))
        .map_err(failed)?;

    let unmatched_suppressions: Vec<String> = rows
        .collect::<std::result::Result<_, _>>()
        .map_err(failed)?;

    Ok(Some(Summary {
        artifacts: artifacts as u64,
        counts,
        quarantined,
        worst_action: action_of(&worst_action),
        unmatched_suppressions,
    }))
}

fn message(id: String, args: Option<String>, text: Option<String>) -> Message {
    let args = args
        .and_then(|args| serde_json::from_str::<BTreeMap<String, String>>(&args).ok())
        .unwrap_or_default();

    Message { id, args, text }
}

fn at(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or_default()
}

fn last_download(state: &str, ms: Option<i64>) -> LastDownload {
    match (state, ms) {
        ("at", Some(ms)) => LastDownload::At(at(ms)),
        ("never", _) => LastDownload::Never,
        _ => LastDownload::Unknown,
    }
}

fn corpus(state: &str, modified_ms: Option<i64>, why: Option<String>) -> CorpusAge {
    match (state, modified_ms) {
        ("consulted", Some(ms)) => CorpusAge::Consulted { modified: at(ms) },
        ("skipped-by-request", _) => CorpusAge::SkippedByRequest,

        _ => CorpusAge::Unavailable {
            why: why.unwrap_or_default(),
        },
    }
}

fn verified(how: &str) -> Verification {
    spell::value(how).unwrap_or(Verification::NotAttempted)
}

fn quarantine_of(class: &str) -> Quarantine {
    spell::value(class).unwrap_or(Quarantine::Soft)
}

/// The weakest reading of an unknown action, so a row a newer build wrote
/// cannot quietly turn into a failure the run did not have.
fn action_of(action: &str) -> Action {
    spell::value(action).unwrap_or(Action::Warn)
}
