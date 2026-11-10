//! Where a catalog walk stopped, and when one last finished.
//!
//! Two questions, and the whole reason an artifact enumeration gets a table
//! of its own.
//!
//! **Where did the interrupted walk stop.** Resuming a large catalog by
//! paging from the beginning is not a resume: a Nexus page takes about two
//! seconds, so a million-artifact repository costs hours before the walk
//! reaches ground it has not already covered.
//!
//! **When did the last complete walk start.** A repository that can answer
//! "artifacts uploaded since DATE" turns a repeated artifact enumeration
//! into a short query, and the date it needs is the start of the last walk
//! that reached the end of the catalog -- not its finish. A push during the
//! walk may have been missed, so only from the start time is "everything
//! since" honest.
//!
//! A cursor is opaque and belongs to the enumerator that issued it, so the
//! enumerator kind is stored beside it. A cursor handed to a different
//! implementation means nothing, and some repositories reject an old one
//! outright.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::core::error::Result;
use crate::report::sink::{Enumeration, Resume};

use super::conn::now_ms;
use super::ids::{self, RunId, failed};

/// Record where a walk has got to.
pub(super) fn checkpoint(
    conn: &Transaction<'_>,
    run: RunId,
    role: &str,
    scan: &Enumeration<'_>,
) -> Result<()> {
    let repository = ids::repository(conn, role, scan.repository, None, None, None)?;

    conn.execute(
        "INSERT INTO repository_enumeration
            (run_id, repository_id, enumerator_kind, depth, scope, cursor, pages,
             found, reached_end, checkpoint_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (run_id, repository_id) DO UPDATE
            SET cursor = excluded.cursor,
                pages = excluded.pages,
                found = excluded.found,
                reached_end = excluded.reached_end,
                checkpoint_ms = excluded.checkpoint_ms",
        params![
            run.0,
            repository.0,
            scan.kind,
            scan.depth,
            scan.scope,
            scan.cursor,
            scan.pages as i64,
            scan.found as i64,
            i64::from(scan.reached_end),
            now_ms(),
        ],
    )
    .map_err(failed)?;

    Ok(())
}

/// Where the latest unfinished walk of this repository stopped.
///
/// Unfinished means both halves: the walk did not reach the end of the
/// catalog, **and** its run never closed. A run that ended tidily without
/// reaching the end stopped for a reason of its own -- a sample size, a
/// cancellation the user asked for -- and resuming it would be the tool
/// deciding to do work nobody asked for.
pub(super) fn resume(conn: &Connection, role: &str, name: &str) -> Result<Option<Resume>> {
    conn.query_row(
        "SELECT s.enumerator_kind, s.cursor, s.pages, s.found, s.scope
         FROM repository_enumeration s
         JOIN repository r ON r.repository_id = s.repository_id
         JOIN run ON run.run_id = s.run_id
         WHERE r.role = ? AND r.name = ?
           AND s.reached_end = 0
           AND run.finished_ms IS NULL
         ORDER BY s.checkpoint_ms DESC
         LIMIT 1",
        params![role, name],
        |row| {
            Ok(Resume {
                kind: row.get(0)?,
                cursor: row.get(1)?,
                pages: row.get::<_, i64>(2)? as u64,
                found: row.get::<_, i64>(3)? as u64,
                scope: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(failed)
}

/// Whether a whole-catalog walk that listed versions reached its end in a
/// run that recorded `source`'s contents.
///
/// A `find` binds the enumerator it walks and the source it observes in
/// one run, and only a `find` records walks, so a source bound to a run
/// with a finished walk is one that walk listed.
pub(super) fn source_listed(conn: &Connection, source: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM repository_enumeration s
             JOIN run_repository rr ON rr.run_id = s.run_id
             JOIN repository r ON r.repository_id = rr.repository_id
             WHERE r.role = 'source' AND r.name = ?
               AND s.reached_end = 1
               AND s.scope IS NULL
               AND s.depth IN ('versions', 'files'))",
        params![source],
        |row| row.get(0),
    )
    .map_err(failed)
}

/// When the last walk that reached the end of this catalog started.
///
/// A sampled walk is excluded by construction: it never sets `reached_end`,
/// because seeing a tenth of a repository is not seeing a repository.
pub(super) fn last_complete(
    conn: &Connection,
    role: &str,
    name: &str,
) -> Result<Option<DateTime<Utc>>> {
    let started: Option<i64> = conn
        .query_row(
            "SELECT MAX(run.started_ms)
             FROM repository_enumeration s
             JOIN repository r ON r.repository_id = s.repository_id
             JOIN run ON run.run_id = s.run_id
             WHERE r.role = ? AND r.name = ? AND s.reached_end = 1",
            params![role, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?
        .flatten();

    Ok(started.and_then(|ms| Utc.timestamp_millis_opt(ms).single()))
}
