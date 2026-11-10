//! A dependency walk's frontier and claims.
//!
//! The spider's queue on disk, so a walk wider than memory still finishes,
//! and a killed one resumes. A task moves `pending` -> `in-progress` ->
//! `done`; a killed run leaves `in-progress` rows, and adopting the walk
//! returns them to `pending` and withdraws the claims they made.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::core::error::{Error, Result};
use crate::report::sink::{Enqueued, Marked, Role, WalkId, WalkTask};

use super::ids::{self, RunId, failed};

const PENDING: &str = "pending";
const IN_PROGRESS: &str = "in-progress";
const DONE: &str = "done";

/// Start a walk, or adopt the one a killed run left.
pub(super) fn start(
    conn: &Transaction<'_>,
    run: RunId,
    source: &str,
    spec: &str,
    targets: &str,
    resume: Option<WalkId>,
) -> Result<WalkId> {
    let Some(walk) = resume else {
        let repository = ids::repository(conn, Role::Source.as_str(), source, None, None, None)?;

        conn.execute(
            "INSERT INTO spider_walk (run_id, repository_id, spec, targets) VALUES (?, ?, ?, ?)",
            params![run.0, repository.0, spec, targets],
        )
        .map_err(failed)?;

        return Ok(WalkId(conn.last_insert_rowid()));
    };

    conn.execute(
        "UPDATE spider_walk SET run_id = ? WHERE spider_walk_id = ?",
        params![run.0, walk.0],
    )
    .map_err(failed)?;

    // Claims first, while the unfinished tasks can still be told apart.
    conn.execute(
        "DELETE FROM spider_claim
         WHERE spider_walk_id = ?1
           AND spider_task_id IN (
               SELECT spider_task_id FROM spider_task
               WHERE spider_walk_id = ?1 AND state = ?2
           )",
        params![walk.0, IN_PROGRESS],
    )
    .map_err(failed)?;

    conn.execute(
        "UPDATE spider_task SET state = ?1 WHERE spider_walk_id = ?2 AND state = ?3",
        params![PENDING, walk.0, IN_PROGRESS],
    )
    .map_err(failed)?;

    Ok(walk)
}

/// The walk a killed run left for `source` under `spec` for `targets`.
///
/// Killed means its run never closed, the rule enumeration resume uses. A
/// walk under another spec is not this walk: its edges are different. Nor
/// is one for other targets: what it marked visited was other work.
pub(super) fn resume(
    conn: &Connection,
    source: &str,
    spec: &str,
    targets: &str,
) -> Result<Option<WalkId>> {
    conn.query_row(
        "SELECT w.spider_walk_id
         FROM spider_walk w
         JOIN repository r ON r.repository_id = w.repository_id
         JOIN run ON run.run_id = w.run_id
         WHERE r.role = ? AND r.name = ? AND w.spec = ? AND w.targets = ?
           AND run.finished_ms IS NULL
         ORDER BY w.spider_walk_id DESC
         LIMIT 1",
        params![Role::Source.as_str(), source, spec, targets],
        |row| row.get(0),
    )
    .optional()
    .map_err(failed)
    .map(|found| found.map(WalkId))
}

pub(super) fn push(conn: &Connection, walk: WalkId, task: &WalkTask) -> Result<Enqueued> {
    let added = conn
        .execute(
            "INSERT INTO spider_task
                (spider_walk_id, request_key, purl, version_spec, provenance, depth, state)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (spider_walk_id, request_key) DO NOTHING",
            params![
                walk.0,
                task.key,
                task.purl,
                task.spec,
                task.provenance,
                i64::from(task.depth),
                PENDING,
            ],
        )
        .map_err(failed)?;

    Ok(match added {
        0 => Enqueued::Duplicate,
        _ => Enqueued::Added,
    })
}

/// The shallowest pending task, marked in progress.
pub(super) fn pop(conn: &Transaction<'_>, walk: WalkId) -> Result<Option<(i64, WalkTask)>> {
    let found = conn
        .query_row(
            "SELECT spider_task_id, request_key, purl, version_spec, provenance, depth
             FROM spider_task
             WHERE spider_walk_id = ? AND state = ?
             ORDER BY depth, spider_task_id
             LIMIT 1",
            params![walk.0, PENDING],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(failed)?;

    let Some((id, key, purl, spec, provenance, depth)) = found else {
        return Ok(None);
    };

    // Cleared only on `done`, so a pending row without them was edited by
    // hand.
    let (Some(spec), Some(provenance)) = (spec, provenance) else {
        return Err(Error::Report(format!(
            "spider task {id} is pending but has no request stored"
        )));
    };

    conn.execute(
        "UPDATE spider_task SET state = ? WHERE spider_task_id = ?",
        params![IN_PROGRESS, id],
    )
    .map_err(failed)?;

    let task = WalkTask {
        key,
        purl,
        spec,
        provenance,
        depth: depth as u32,
    };

    Ok(Some((id, task)))
}

pub(super) fn done(conn: &Connection, walk: WalkId, task: i64) -> Result<()> {
    conn.execute(
        "UPDATE spider_task
            SET state = ?, version_spec = NULL, provenance = NULL
         WHERE spider_task_id = ? AND spider_walk_id = ?",
        params![DONE, task, walk.0],
    )
    .map_err(failed)?;

    Ok(())
}

pub(super) fn pending(conn: &Connection, walk: WalkId) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM spider_task WHERE spider_walk_id = ? AND state = ?",
            params![walk.0, PENDING],
            |row| row.get(0),
        )
        .map_err(failed)?;

    Ok(count as u64)
}

pub(super) fn mark(conn: &Connection, walk: WalkId, purl: &str, task: i64) -> Result<Marked> {
    let added = conn
        .execute(
            "INSERT INTO spider_claim (spider_walk_id, resolved_purl, spider_task_id)
             VALUES (?, ?, ?)
             ON CONFLICT (spider_walk_id, resolved_purl) DO NOTHING",
            params![walk.0, purl, task],
        )
        .map_err(failed)?;

    Ok(match added {
        0 => Marked::Already,
        _ => Marked::First,
    })
}

pub(super) fn marked(conn: &Connection, walk: WalkId, purl: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM spider_claim WHERE spider_walk_id = ? AND resolved_purl = ?
         )",
        params![walk.0, purl],
        |row| row.get(0),
    )
    .map_err(failed)
}

pub(super) fn marks(conn: &Connection, walk: WalkId) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM spider_claim WHERE spider_walk_id = ?",
            params![walk.0],
            |row| row.get(0),
        )
        .map_err(failed)?;

    Ok(count as u64)
}
