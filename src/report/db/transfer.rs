//! Claiming copy work, and recording what became of it.
//!
//! The half that makes a long migration restartable. Everything here turns
//! on one ordering: **the claim is committed before the network work and
//! the outcome after it.** A run killed at any point in between leaves a
//! row that says "somebody was working on this", which is true, and which
//! a later run can act on.
//!
//! # What a resumed run skips
//!
//! A terminal row at a destination, whichever source put it there. The
//! summary is keyed by artifact and destination rather than by source, so
//! the question it answers is "has this reached the target" -- which is the
//! question a copy actually has, and the one that lets a lower-priority
//! source skip what a higher-priority one already delivered.
//!
//! # Stale claims
//!
//! An `in-progress` row is not a permanent tombstone. A claim belongs to a
//! run, and a run with no finish time did not close: it crashed, or it was
//! killed. Its claims are reclaimable. A claim belonging to the *current*
//! run is not, because two workers racing for one artifact is a bug rather
//! than a crash.
//!
//! Getting this wrong in the obvious direction -- refusing every
//! `in-progress` row -- makes a killed migration permanently stuck on
//! whatever it happened to be holding, which is the failure the whole
//! feature exists to prevent.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::core::error::{Error, Result};
use crate::model::ArtifactId;
use crate::report::sink::{Claim, Claimed, Transfer};

use super::conn::now_ms;
use super::ids::{self, ArtifactRowId, ProblemId, RepositoryId, RunId, failed};

/// Claim one artifact for a destination, or answer `None` when it is done.
pub(super) fn claim(
    conn: &mut Connection,
    run: RunId,
    claim: &Claim<'_>,
) -> Result<Option<Claimed>> {
    let transaction = conn.transaction().map_err(failed)?;

    let destination = ids::repository(&transaction, "target", claim.destination, None, None, None)?;
    let source = claim
        .source
        .map(|name| ids::repository(&transaction, "source", name, None, None, None))
        .transpose()?;

    let parsed = ArtifactId::parse(claim.purl)?;
    let version = parsed
        .version
        .as_ref()
        .map(|text| crate::model::Version::new(text, crate::model::Release::General));
    let artifact = ids::artifact(&transaction, &parsed.id, version.as_ref())?;

    let held: Option<(i64, String, Option<i64>)> = transaction
        .query_row(
            "SELECT t.artifact_transfer_id, s.state, s.terminal
             FROM artifact_transfer t
             JOIN transfer_state s ON s.state = t.state
             WHERE t.artifact_id = ? AND t.destination_repository_id = ?",
            params![artifact.0, destination.0],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(failed)?;

    let transfer = match held {
        Some((transfer, state, terminal)) => {
            if terminal == Some(1) {
                return Ok(None);
            }

            if state == "in-progress" && !reclaimable(&transaction, transfer, run)? {
                return Err(Error::Report(format!(
                    "{} is already being copied to {} by this run",
                    claim.purl, claim.destination
                )));
            }

            transfer
        }

        None => new_transfer(&transaction, artifact.0, destination.0)?,
    };

    let attempt = start(&transaction, transfer, run, source)?;

    transaction.commit().map_err(failed)?;

    Ok(Some(Claimed { transfer, attempt }))
}

/// Close a claim, updating the attempt and the summary together.
pub(super) fn close(conn: &mut Connection, claimed: Claimed, outcome: Transfer) -> Result<()> {
    let transaction = conn.transaction().map_err(failed)?;
    let at = now_ms();
    let state = outcome.as_str();

    transaction
        .execute(
            "UPDATE artifact_transfer_attempt SET state = ?, finished_ms = ?
             WHERE artifact_transfer_attempt_id = ?",
            params![state, at, claimed.attempt],
        )
        .map_err(failed)?;

    // The summary and the attempt move in one transaction, so a resumed run
    // never reads a summary that disagrees with the history behind it.
    transaction
        .execute(
            "UPDATE artifact_transfer
                SET state = ?,
                    last_attempt_ms = ?,
                    completed_ms = CASE
                        WHEN (SELECT terminal FROM transfer_state WHERE state = ?) = 1
                        THEN ?
                        ELSE NULL
                    END
             WHERE artifact_transfer_id = ?",
            params![state, at, state, at, claimed.transfer],
        )
        .map_err(failed)?;

    transaction.commit().map_err(failed)
}

/// Point this run's failed attempt for an artifact at the problem that
/// failed it.
///
/// Found rather than passed: the failure record arrives through the writer,
/// which knows no claim. One claim per artifact, destination, and run
/// makes the match unique, and `in-progress` covers a record written before
/// its close.
pub(super) fn blame(
    conn: &Transaction<'_>,
    run: RunId,
    artifact: ArtifactRowId,
    destination: Option<RepositoryId>,
    problem: ProblemId,
) -> Result<()> {
    // `None` matches any destination: a copy to one target has only one.
    conn.execute(
        "UPDATE artifact_transfer_attempt SET problem_id = ?
         WHERE artifact_transfer_attempt_id = (
             SELECT a.artifact_transfer_attempt_id
             FROM artifact_transfer_attempt a
             JOIN artifact_transfer t ON t.artifact_transfer_id = a.artifact_transfer_id
             WHERE a.run_id = ? AND t.artifact_id = ? AND a.problem_id IS NULL
               AND a.state IN ('in-progress', 'failed')
               AND (?4 IS NULL OR t.destination_repository_id = ?4)
             ORDER BY a.artifact_transfer_attempt_id DESC
             LIMIT 1
         )",
        params![problem.0, run.0, artifact.0, destination.map(|at| at.0)],
    )
    .map_err(failed)?;

    Ok(())
}

/// Whether an `in-progress` claim was left by another run.
///
/// Another run's claim is abandoned whichever way that run ended: killed,
/// it never finished; finished, it left the claim open on its way out, as
/// a run unwinding from an abort can. Either way nobody is working on it,
/// and refusing it would stop every later run over the same report.
fn reclaimable(conn: &Transaction<'_>, transfer: i64, run: RunId) -> Result<bool> {
    let owner: Option<i64> = conn
        .query_row(
            "SELECT run_id
             FROM artifact_transfer_attempt
             WHERE artifact_transfer_id = ? AND state = 'in-progress'
             ORDER BY artifact_transfer_attempt_id DESC
             LIMIT 1",
            params![transfer],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?;

    let Some(owner) = owner else {
        // The summary says in-progress and no attempt does. A crash between
        // the two writes cannot produce this, but a person editing the
        // database can, and a stuck row is worse than a repeated copy.
        return Ok(true);
    };

    // This run's own claim is a race between workers, not a crash.
    Ok(owner != run.0)
}

fn new_transfer(conn: &Transaction<'_>, artifact: i64, destination: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO artifact_transfer
            (artifact_id, destination_repository_id, state, attempts)
         VALUES (?, ?, 'pending', 0)",
        params![artifact, destination],
    )
    .map_err(failed)?;

    Ok(conn.last_insert_rowid())
}

/// Mark the summary in progress and open an attempt beside it.
fn start(
    conn: &Transaction<'_>,
    transfer: i64,
    run: RunId,
    source: Option<RepositoryId>,
) -> Result<i64> {
    let at = now_ms();

    conn.execute(
        "UPDATE artifact_transfer
            SET state = 'in-progress',
                source_repository_id = COALESCE(?, source_repository_id),
                attempts = attempts + 1,
                first_attempt_ms = COALESCE(first_attempt_ms, ?),
                last_attempt_ms = ?,
                completed_ms = NULL
         WHERE artifact_transfer_id = ?",
        params![source.map(|source| source.0), at, at, transfer],
    )
    .map_err(failed)?;

    conn.execute(
        "INSERT INTO artifact_transfer_attempt
            (artifact_transfer_id, run_id, source_repository_id, started_ms, state)
         VALUES (?, ?, ?, ?, 'in-progress')",
        params![transfer, run.0, source.map(|source| source.0), at],
    )
    .map_err(failed)?;

    Ok(conn.last_insert_rowid())
}
