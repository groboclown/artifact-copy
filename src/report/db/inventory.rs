//! What a repository holds, built up over many runs.
//!
//! The observation tables beside this one are history: they keep what each
//! run said, forever. These keep the *current* answer, which is what an
//! artifact enumeration, a diff, and a resumed copy actually ask for -- and
//! what none of them could get without walking every run ever recorded.
//!
//! # Merging, and the rule behind every clause
//!
//! A second artifact enumeration of a repository knows less than the first
//! in places. A
//! `find` enumerates coordinates and no publish times; a `inspect`
//! resolves metadata; a `copy` verifies bytes. So a later run must not
//! erase what an earlier one learned, and the merge is written around that
//! one idea:
//!
//! - **`first_seen` never moves.** When a repository first held an artifact
//!   is a fact about the repository, not about the last run to look.
//! - **Absence does not overwrite.** A publish time or a license the new
//!   observation does not carry leaves the old value alone.
//! - **`unknown` is not an answer.** An enumerator that reports no download
//!   statistics must not erase a real last-download time that one which
//!   does had recorded.
//! - **`not-attempted` is not a verification.** A `inspect` that fetched
//!   nothing must not downgrade a file a `copy` checked.
//!
//! # One repository never speaks for another
//!
//! Every row here is keyed by repository, so two sources holding the same
//! purl keep two rows and two sets of facts. That is what makes the later
//! question -- which source should a copy take this from -- answerable at
//! all, and it is why a conflicting answer is not a conflict to resolve.

use rusqlite::{Transaction, params};

use crate::core::error::Result;
use crate::model::{LastDownload, SigRef};
use crate::report::record::{ArtifactRecord, FileOrigin, FileRecord};

use super::ids::{ArtifactRowId, RepositoryId, RunId, failed};
use super::spell;

/// Record what one observation says a repository holds.
pub(super) fn observed(
    conn: &Transaction<'_>,
    repository: RepositoryId,
    artifact: ArtifactRowId,
    record: &ArtifactRecord,
    run: RunId,
    at_ms: i64,
) -> Result<i64> {
    let (state, download_ms) = match record.last_download {
        LastDownload::At(when) => ("at", Some(when.timestamp_millis())),
        LastDownload::Never => ("never", None),
        LastDownload::Unknown => ("unknown", None),
    };

    conn.execute(
        "INSERT INTO repository_artifact
            (repository_id, artifact_id, first_seen_ms, last_seen_ms, published_ms,
             last_download_state, last_download_ms, declared_license, last_seen_run_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (repository_id, artifact_id) DO UPDATE
            SET last_seen_ms = excluded.last_seen_ms,
                last_seen_run_id = excluded.last_seen_run_id,
                published_ms = COALESCE(excluded.published_ms, published_ms),
                declared_license = COALESCE(excluded.declared_license, declared_license),

                -- `unknown` is the absence of evidence, so it leaves a real
                -- answer standing; anything else is evidence and replaces
                -- one.
                --
                -- And a timestamp is never replaced by the absence of one.
                -- Two observations of one artifact used to be impossible --
                -- one component, one row, one page -- and a raw repository
                -- read as directories makes them ordinary: a directory's
                -- files straddle pages, and a later page saying `never`
                -- about a file nobody fetched would erase an earlier page's
                -- record of one that was. That is the mistake that gets a
                -- live artifact deleted, which is the whole reason this
                -- three-state answer exists.
                last_download_state = CASE
                    WHEN excluded.last_download_state = 'unknown' THEN last_download_state
                    WHEN last_download_state = 'at'
                     AND excluded.last_download_state <> 'at' THEN last_download_state
                    ELSE excluded.last_download_state
                END,
                last_download_ms = CASE
                    WHEN excluded.last_download_state = 'unknown' THEN last_download_ms
                    WHEN last_download_state = 'at'
                     AND excluded.last_download_state <> 'at' THEN last_download_ms

                    -- Both are timestamps: the most recent use counts, the
                    -- same rule applied across an artifact's own assets.
                    WHEN last_download_state = 'at'
                     AND excluded.last_download_ms < last_download_ms THEN last_download_ms
                    ELSE excluded.last_download_ms
                END",
        params![
            repository.0,
            artifact.0,
            at_ms,
            at_ms,
            record.published.map(|when| when.timestamp_millis()),
            state,
            download_ms,
            record.declared_license,
            run.0,
        ],
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

    for file in &record.files {
        observed_file(conn, repository_artifact, file, at_ms)?;
    }

    Ok(repository_artifact)
}

/// Record what one observation says about a file of that artifact.
///
/// One row whoever named the file. The observation's origin sets its own
/// marker and leaves the other alone, and a resolved URL is never replaced
/// by a listed one: the source is what fetches, and a catalog's download
/// host may move under it.
fn observed_file(
    conn: &Transaction<'_>,
    repository_artifact: i64,
    record: &FileRecord,
    at_ms: i64,
) -> Result<()> {
    let verification = spell::text(&record.verification)?;

    let (listed_ms, resolved_ms) = match record.origin {
        FileOrigin::Listed => (Some(at_ms), None),
        FileOrigin::Resolved => (None, Some(at_ms)),
    };

    let core_metadata = core_metadata(record);

    conn.execute(
        "INSERT INTO repository_file
            (repository_artifact_id, name, url, size_bytes, verification, core_metadata,
             listed_ms, resolved_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (repository_artifact_id, name) DO UPDATE
            SET url = CASE
                    WHEN excluded.resolved_ms IS NOT NULL OR resolved_ms IS NULL THEN excluded.url
                    ELSE url
                END,
                listed_ms = COALESCE(excluded.listed_ms, listed_ms),
                resolved_ms = COALESCE(excluded.resolved_ms, resolved_ms),
                size_bytes = COALESCE(excluded.size_bytes, size_bytes),
                core_metadata = COALESCE(excluded.core_metadata, core_metadata),

                -- A run that fetched nothing must not downgrade a file
                -- another run checked. A failure does replace a success:
                -- bad news about the bytes is news.
                verification = CASE
                    WHEN excluded.verification = 'not-attempted' THEN verification
                    ELSE excluded.verification
                END",
        params![
            repository_artifact,
            record.name,
            record.url,
            record.size.map(|size| size as i64),
            verification,
            core_metadata,
            listed_ms,
            resolved_ms,
        ],
    )
    .map_err(failed)?;

    let file: i64 = conn
        .query_row(
            "SELECT repository_file_id FROM repository_file
             WHERE repository_artifact_id = ? AND name = ?",
            params![repository_artifact, record.name],
            |row| row.get(0),
        )
        .map_err(failed)?;

    // Accumulated rather than replaced: a repository that published a
    // sha1 last year and a sha256 today has declared both, and a copy
    // checking against either wants whichever it can compute.
    for digest in &record.digests {
        conn.execute(
            "INSERT OR IGNORE INTO repository_file_digest
                (repository_file_id, algorithm, hex)
             VALUES (?, ?, ?)",
            params![file, spell::text(&digest.alg)?, digest.hex],
        )
        .map_err(failed)?;
    }

    // Accumulated for the same reason as the file's own digests.
    for digest in record.core_metadata.iter().flatten() {
        conn.execute(
            "INSERT OR IGNORE INTO repository_file_core_metadata_digest
                (repository_file_id, algorithm, hex)
             VALUES (?, ?, ?)",
            params![file, spell::text(&digest.alg)?, digest.hex],
        )
        .map_err(failed)?;
    }

    if record.origin == FileOrigin::Resolved {
        signed(conn, file, &record.signatures)?;
    }

    Ok(())
}

/// Whether a core-metadata document sits beside the file, as a column.
///
/// A catalog says nothing of one, so only a resolution answers: `None`
/// is `NULL`, which leaves an earlier answer alone.
pub(super) fn core_metadata(record: &FileRecord) -> Option<bool> {
    match record.origin {
        FileOrigin::Listed => None,
        FileOrigin::Resolved => Some(record.core_metadata.is_some()),
    }
}

/// Replace a file's signatures with what a resolution declared.
///
/// Replaced rather than accumulated: a signature is a claim about where to
/// find one, and a stale claim sends a copy to fetch what is gone.
fn signed(conn: &Transaction<'_>, file: i64, signatures: &[SigRef]) -> Result<()> {
    conn.execute(
        "DELETE FROM repository_file_signature WHERE repository_file_id = ?",
        params![file],
    )
    .map_err(failed)?;

    for signature in signatures {
        conn.execute(
            "INSERT INTO repository_file_signature
                (repository_file_id, scheme, key_id, value, url)
             VALUES (?, ?, ?, ?, ?)",
            params![
                file,
                spell::text(&signature.scheme)?,
                signature.key_id,
                signature.value,
                signature.url,
            ],
        )
        .map_err(failed)?;
    }

    Ok(())
}
