//! What a report says a target holds, and where a payload's bytes are.
//!
//! Writing a fetched payload's cache entry belongs with its transfer row,
//! in `file_transfer`; this answers the questions a later run asks of them.

use rusqlite::{Connection, OptionalExtension, params};

use crate::core::error::Result;
use crate::model::ArtifactId;

use super::conn::now_ms;
use super::ids::{self, failed};
use super::spell;

/// Record that a target holds an artifact.
pub(super) fn present(conn: &mut Connection, target: &str, purl: &str) -> Result<()> {
    let transaction = conn.transaction().map_err(failed)?;

    let repository = ids::repository(&transaction, "target", target, None, None, None)?;
    let parsed = ArtifactId::parse(purl)?;
    let version = parsed
        .version
        .as_ref()
        .map(|text| crate::model::Version::new(text, crate::model::Release::General));
    let artifact = ids::artifact(&transaction, &parsed.id, version.as_ref())?;
    let at_ms = now_ms();

    transaction
        .execute(
            "INSERT INTO repository_artifact
                (repository_id, artifact_id, first_seen_ms, last_seen_ms)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (repository_id, artifact_id) DO UPDATE
                SET last_seen_ms = excluded.last_seen_ms",
            params![repository.0, artifact.0, at_ms, at_ms],
        )
        .map_err(failed)?;

    transaction.commit().map_err(failed)
}

/// Whether a target is recorded as holding an artifact.
pub(super) fn holds(conn: &Connection, target: &str, purl: &str) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1
             FROM repository_artifact ra
             JOIN artifact a ON a.artifact_id = ra.artifact_id
             JOIN repository r ON r.repository_id = ra.repository_id
             WHERE r.role = 'target' AND r.name = ? AND a.purl = ?",
            params![target, purl],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?;

    Ok(found.is_some())
}

/// What the report says about one file's cached bytes.
pub(super) fn recorded(
    conn: &Connection,
    source: &str,
    purl: &str,
    file: &str,
) -> Result<Option<crate::report::CacheRecord>> {
    conn.query_row(
        "SELECT c.host, c.cache_dir, c.relative_path, c.size_bytes, c.verification
         FROM repository_file f
         JOIN cache_entry c ON c.cache_entry_id = f.cache_entry_id
         JOIN repository_artifact ra
              ON ra.repository_artifact_id = f.repository_artifact_id
         JOIN artifact a ON a.artifact_id = ra.artifact_id
         JOIN repository r ON r.repository_id = ra.repository_id
         WHERE r.role = 'source' AND r.name = ? AND a.purl = ? AND f.name = ?",
        params![source, purl, file],
        |row| {
            Ok(crate::report::CacheRecord {
                host: row.get(0)?,
                cache_dir: row.get(1)?,
                relative_path: row.get(2)?,
                size: row.get::<_, Option<i64>>(3)?.map(|size| size as u64),
                verification: row
                    .get::<_, Option<String>>(4)?
                    .as_deref()
                    .and_then(spell::value)
                    .unwrap_or(crate::report::Verification::NotAttempted),
            })
        },
    )
    .optional()
    .map_err(failed)
}
