//! What became of moving one file, in either direction.
//!
//! A download writes two rows for one event, because they answer different
//! questions. A `cache_entry` says where the bytes live, so a later run
//! reuses them instead of fetching again. A `file_transfer` says what
//! became of the attempt, so a person reading a stalled migration can tell
//! a flaky source from a full disk.
//!
//! An upload writes only the `file_transfer`, one per file and target, from
//! what the target reported for each file: a half-published artifact then
//! says which of its files the target already has.
//!
//! # Keyed by host, not by repository
//!
//! A cache folder is keyed per host and two sources on one repository share it,
//! so a per-repository cache row would claim two files where one exists.
//! The entry is shared and each repository's file points at it.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::core::error::Result;
use crate::model::ArtifactId;
use crate::report::sink::{Download, Sent, Upload};

use super::conn::now_ms;
use super::ids::{self, RunId, failed};
use super::spell;

/// Record one payload a run fetched, or tried to.
pub(super) fn downloaded(conn: &mut Connection, run: RunId, at: &Download<'_>) -> Result<()> {
    let transaction = conn.transaction().map_err(failed)?;

    let file = repository_file(&transaction, at.source, at.purl, at.file, at.url)?;

    let cached = at
        .cached
        .as_ref()
        .map(|cached| {
            let entry = cache_entry(&transaction, cached)?;

            transaction
                .execute(
                    "UPDATE repository_file SET cache_entry_id = ?, verification = ?
                     WHERE repository_file_id = ?",
                    params![entry, spell::text(&cached.verification)?, file],
                )
                .map_err(failed)?;

            Ok::<i64, crate::core::error::Error>(entry)
        })
        .transpose()?;

    // `downloaded` and `failed` are the only two outcomes a fetch has. A
    // run that never reached the file at all writes no row, rather than a
    // pending one nothing will ever close.
    let state = match at.failure {
        None => "downloaded",
        Some(_) => "failed",
    };

    let transfer = transfer(&transaction, file, Direction::Download, cached, state)?;

    transaction
        .execute(
            "INSERT INTO file_transfer_attempt
                (file_transfer_id, run_id, started_ms, finished_ms, state,
                 verification, error_side, error_stage)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                transfer,
                run.0,
                now_ms(),
                now_ms(),
                state,
                at.cached
                    .as_ref()
                    .map(|cached| spell::text(&cached.verification))
                    .transpose()?,
                at.failure.map(|(side, _)| side.as_str()),
                at.failure.map(|(_, stage)| stage.as_str()),
            ],
        )
        .map_err(failed)?;

    transaction.commit().map_err(failed)
}

/// Record one file a run sent to a target, or tried to.
pub(super) fn uploaded(conn: &mut Connection, run: RunId, at: &Upload<'_>) -> Result<()> {
    let transaction = conn.transaction().map_err(failed)?;

    let file = repository_file(&transaction, at.source, at.purl, at.file, at.url)?;
    let destination = ids::repository(&transaction, "target", at.destination, None, None, None)?;
    let state = at.sent.as_str();

    let transfer = transfer(
        &transaction,
        file,
        Direction::Upload {
            destination: destination.0,
        },
        None,
        state,
    )?;

    let failure = match at.sent {
        Sent::Failed(blame) => blame,
        _ => None,
    };

    transaction
        .execute(
            "INSERT INTO file_transfer_attempt
                (file_transfer_id, run_id, artifact_transfer_attempt_id, started_ms,
                 finished_ms, state, error_side, error_stage)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                transfer,
                run.0,
                at.claimed.map(|claimed| claimed.attempt),
                now_ms(),
                now_ms(),
                state,
                failure.map(|(side, _)| side.as_str()),
                failure.map(|(_, stage)| stage.as_str()),
            ],
        )
        .map_err(failed)?;

    transaction.commit().map_err(failed)
}

/// The inventory row this payload belongs to, created if an artifact
/// enumeration has not already made one.
///
/// A copy can reach a file the inventory has never seen -- an artifact
/// named on the command line rather than enumerated -- and refusing to
/// record its cache entry would lose the reuse for exactly the runs that
/// did not enumerate artifacts first.
fn repository_file(
    conn: &Transaction<'_>,
    source: &str,
    purl: &str,
    file: &str,
    url: &str,
) -> Result<i64> {
    let repository = ids::repository(conn, "source", source, None, None, None)?;
    let parsed = ArtifactId::parse(purl)?;
    let version = parsed
        .version
        .as_ref()
        .map(|text| crate::model::Version::new(text, crate::model::Release::General));
    let artifact = ids::artifact(conn, &parsed.id, version.as_ref())?;

    let at_ms = now_ms();

    conn.execute(
        "INSERT INTO repository_artifact
            (repository_id, artifact_id, first_seen_ms, last_seen_ms)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (repository_id, artifact_id) DO UPDATE
            SET last_seen_ms = excluded.last_seen_ms",
        params![repository.0, artifact.0, at_ms, at_ms],
    )
    .map_err(failed)?;

    let repository_artifact: i64 = conn
        .query_row(
            "SELECT repository_artifact_id FROM repository_artifact
             WHERE repository_id = ? AND artifact_id = ?",
            params![repository.0, artifact.0],
            |row| row.get(0),
        )
        .map_err(failed)?;

    conn.execute(
        // A download is of a file a resolution named, so it carries that
        // marker; see `inventory::observed_file`.
        "INSERT INTO repository_file (repository_artifact_id, name, url, resolved_ms)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (repository_artifact_id, name) DO UPDATE
            SET url = excluded.url, resolved_ms = excluded.resolved_ms",
        params![repository_artifact, file, url, at_ms],
    )
    .map_err(failed)?;

    conn.query_row(
        "SELECT repository_file_id FROM repository_file
         WHERE repository_artifact_id = ? AND name = ?",
        params![repository_artifact, file],
        |row| row.get(0),
    )
    .map_err(failed)
}

/// The cache entry for one payload, keyed by host and relative path.
fn cache_entry(conn: &Transaction<'_>, cached: &crate::report::Cached<'_>) -> Result<i64> {
    conn.execute(
        "INSERT INTO cache_entry
            (host, cache_dir, relative_path, size_bytes, verification, downloaded_ms,
             used_ms, retain_until_ms, fresh_until_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (host, relative_path) DO UPDATE
            SET cache_dir = excluded.cache_dir,
                size_bytes = excluded.size_bytes,
                verification = excluded.verification,
                downloaded_ms = excluded.downloaded_ms,
                used_ms = excluded.used_ms,
                retain_until_ms = excluded.retain_until_ms,
                fresh_until_ms = excluded.fresh_until_ms",
        params![
            cached.host,
            cached.cache_dir,
            cached.relative_path,
            cached.size.map(|size| size as i64),
            spell::text(&cached.verification)?,
            cached.fetched_ms.unwrap_or_else(now_ms),
            cached.used_ms.unwrap_or_else(now_ms),
            cached.retain_until_ms,
            cached.fresh_until_ms,
        ],
    )
    .map_err(failed)?;

    conn.query_row(
        "SELECT cache_entry_id FROM cache_entry WHERE host = ? AND relative_path = ?",
        params![cached.host, cached.relative_path],
        |row| row.get(0),
    )
    .map_err(failed)
}

/// Which way a file moved, and for an upload, where to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Into the cache.
    Download,

    /// To a target, by its repository row.
    Upload { destination: i64 },
}

/// The summary for one file in one direction, created or moved on.
fn transfer(
    conn: &Transaction<'_>,
    file: i64,
    direction: Direction,
    cached: Option<i64>,
    state: &str,
) -> Result<i64> {
    let at_ms = now_ms();

    // `IS` rather than `=`, so a download's null destination matches.
    let (spelled, destination) = match direction {
        Direction::Download => ("download", None),
        Direction::Upload { destination } => ("upload", Some(destination)),
    };

    let existing: Option<i64> = conn
        .query_row(
            "SELECT file_transfer_id FROM file_transfer
             WHERE repository_file_id = ? AND direction = ?
               AND destination_repository_id IS ?",
            params![file, spelled, destination],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?;

    let transfer = match existing {
        Some(transfer) => transfer,

        None => {
            conn.execute(
                "INSERT INTO file_transfer
                    (repository_file_id, direction, destination_repository_id, state, attempts)
                 VALUES (?, ?, ?, ?, 0)",
                params![file, spelled, destination, state],
            )
            .map_err(failed)?;

            conn.last_insert_rowid()
        }
    };

    conn.execute(
        "UPDATE file_transfer
            SET state = ?,
                cache_entry_id = COALESCE(?, cache_entry_id),
                attempts = attempts + 1,
                first_attempt_ms = COALESCE(first_attempt_ms, ?),
                last_attempt_ms = ?,
                completed_ms = CASE
                    WHEN (SELECT terminal FROM file_state WHERE state = ?) = 1
                    THEN ?
                    ELSE NULL
                END
         WHERE file_transfer_id = ?",
        params![state, cached, at_ms, at_ms, state, at_ms, transfer],
    )
    .map_err(failed)?;

    Ok(transfer)
}
