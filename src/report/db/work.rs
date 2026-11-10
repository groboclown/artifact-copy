//! What a copy still has to move.
//!
//! The query the schema exists to answer, and the one a resumed migration
//! runs on every page. Three tables and one anti-join: the source's
//! inventory, the artifact under it, and whatever `artifact_transfer` says
//! about that artifact at the destination.
//!
//! # The anti-join is where source priority lives
//!
//! `artifact_transfer` is keyed by artifact and destination rather than by
//! source, so an artifact a higher-priority source already delivered is
//! excluded here without the query naming that source at all. There is no
//! second pass and no comparison between sources; the row either exists
//! terminal or it does not.
//!
//! # Paged by key, never by offset
//!
//! The run reading a page is usually the run writing the next one. An
//! `OFFSET` shifts as rows leave the outstanding set, so work would be
//! skipped -- silently, and in proportion to how well the copy was going.
//!
//! # Files come per page, not per artifact
//!
//! Joining them into the query above would multiply artifact rows by file
//! count and break the keyset; asking per artifact would turn one page into
//! a hundred round trips. One `IN` over the page is neither.
//!
//! # A `NULL` version is returned, not filtered
//!
//! [`outstanding`] and [`inventory`] used to carry `AND a.version IS NOT
//! NULL`, to keep a name-only row -- npm's replication feed lists names and
//! the versions cost a packument each -- out of a copy's work list. It also
//! excluded every artifact of a raw repository, where a directory has no
//! version *because there is none*, which made such a repository
//! uncopyable: recorded correctly, then invisible.
//!
//! The two cases look identical in the row and are opposite instructions,
//! so the reader decides rather than the query. `Ecosystem::version_optional`
//! is what tells them apart, and `commands::inspect` asks it.
//! [`versions`] keeps the filter, because a question *about versions* has
//! no business answering with a row that has none.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};

use crate::core::error::Result;
use crate::report::sink::{Work, WorkFile};

use super::ids::failed;
use super::spell;

/// Artifacts at `source` that have not reached every one of
/// `destinations`.
///
/// An artifact is outstanding while **any** named destination lacks a
/// terminal transfer of it, so a run copying to several targets is handed
/// what one of them still needs.
pub(super) fn outstanding(
    conn: &Connection,
    source: &str,
    destinations: &[&str],
    after: i64,
    limit: u32,
) -> Result<Vec<Work>> {
    if destinations.is_empty() {
        return Ok(Vec::new());
    }

    // `package` is not joined, though it holds the pieces: the exact purl
    // is stored precisely so a reader can recover them without one, and a
    // caller needs an `ArtifactId` rather than columns anyway.
    let mut statement = conn
        .prepare(&format!(
            "SELECT ra.repository_artifact_id, a.purl, a.version, a.release,
                    ra.declared_license, ra.published_ms, ra.last_seen_run_id
             {}
             ORDER BY ra.repository_artifact_id
             LIMIT ?",
            outstanding_rows(destinations)
        ))
        .map_err(failed)?;

    let mut values = outstanding_values(source, destinations, after);
    values.push(i64::from(limit).into());

    let rows = statement
        .query_map(params_from_iter(values), row_to_work)
        .map_err(failed)?;

    let mut work: Vec<Work> = rows
        .collect::<std::result::Result<_, _>>()
        .map_err(failed)?;

    if work.is_empty() {
        return Ok(work);
    }

    let mut files = files_for(conn, work.iter().map(|one| one.key))?;

    for one in &mut work {
        one.files = files.remove(&one.key).unwrap_or_default();
    }

    Ok(work)
}

/// How many artifacts [`outstanding`] would hand over, all pages together.
///
/// Counted once at the start of a copy, so its progress shows the whole
/// list rather than one page at a time.
pub(super) fn outstanding_count(
    conn: &Connection,
    source: &str,
    destinations: &[&str],
) -> Result<u64> {
    if destinations.is_empty() {
        return Ok(0);
    }

    let values = outstanding_values(source, destinations, FIRST_KEY_BEFORE);

    conn.query_row(
        &format!("SELECT COUNT(*) {}", outstanding_rows(destinations)),
        params_from_iter(values),
        |row| row.get(0),
    )
    .map_err(failed)
}

/// The `FROM` and `WHERE` shared by [`outstanding`] and its count, bound by
/// [`outstanding_values`].
fn outstanding_rows(destinations: &[&str]) -> String {
    // One row per destination, e.g. `VALUES (?), (?)`, which SQLite names
    // `column1`.
    let wanted = vec!["(?)"; destinations.len()].join(", ");

    format!(
        "FROM repository_artifact ra
         JOIN artifact a ON a.artifact_id = ra.artifact_id
         JOIN repository origin ON origin.repository_id = ra.repository_id
         WHERE origin.role = 'source' AND origin.name = ?
           AND ra.repository_artifact_id > ?
           AND EXISTS (
               SELECT 1 FROM (VALUES {wanted}) wanted
               LEFT JOIN repository target
                      ON target.role = 'target' AND target.name = wanted.column1
               LEFT JOIN artifact_transfer t
                      ON t.artifact_id = a.artifact_id
                     AND t.destination_repository_id = target.repository_id
               LEFT JOIN transfer_state s ON s.state = t.state
               WHERE t.state IS NULL OR s.terminal = 0
           )"
    )
}

/// The parameters [`outstanding_rows`] binds, in its order.
fn outstanding_values(
    source: &str,
    destinations: &[&str],
    after: i64,
) -> Vec<rusqlite::types::Value> {
    let mut values: Vec<rusqlite::types::Value> = vec![source.to_owned().into(), after.into()];
    values.extend(destinations.iter().map(|name| name.to_string().into()));

    values
}

/// A key below every row's, so a keyset bound by it skips nothing. SQLite
/// assigns row ids from 1.
const FIRST_KEY_BEFORE: i64 = 0;

/// Everything one repository is recorded as holding.
///
/// The same shape as [`outstanding`] without the anti-join, because the
/// question is what the repository has rather than what is left to send.
pub(super) fn inventory(
    conn: &Connection,
    source: &str,
    after: i64,
    limit: u32,
) -> Result<Vec<Work>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT ra.repository_artifact_id, a.purl, a.version, a.release,
                    ra.declared_license, ra.published_ms, ra.last_seen_run_id
             {INVENTORY_ROWS}
             ORDER BY ra.repository_artifact_id
             LIMIT ?"
        ))
        .map_err(failed)?;

    let rows = statement
        .query_map(params![source, after, limit], row_to_work)
        .map_err(failed)?;

    let mut work: Vec<Work> = rows
        .collect::<std::result::Result<_, _>>()
        .map_err(failed)?;

    if work.is_empty() {
        return Ok(work);
    }

    let mut files = files_for(conn, work.iter().map(|one| one.key))?;

    for one in &mut work {
        one.files = files.remove(&one.key).unwrap_or_default();
    }

    Ok(work)
}

/// How many artifacts [`inventory`] would hand over, all pages together.
pub(super) fn inventory_count(conn: &Connection, source: &str) -> Result<u64> {
    conn.query_row(
        &format!("SELECT COUNT(*) {INVENTORY_ROWS}"),
        params![source, FIRST_KEY_BEFORE],
        |row| row.get(0),
    )
    .map_err(failed)
}

/// The `FROM` and `WHERE` shared by [`inventory`] and its count: the
/// source's name, then the key to start after.
const INVENTORY_ROWS: &str = "FROM repository_artifact ra
     JOIN artifact a ON a.artifact_id = ra.artifact_id
     JOIN repository r ON r.repository_id = ra.repository_id
     WHERE r.role = 'source' AND r.name = ?
       AND ra.repository_artifact_id > ?";

/// What one repository holds for one exact artifact.
///
/// By purl, which is indexed, rather than by walking the outstanding list:
/// a scan of the catalog to answer one question would cost more than the
/// request it was meant to save.
///
/// Independent of any destination. This asks what the source *has*, which
/// is a different question from what is left to copy.
pub(super) fn held(conn: &Connection, source: &str, purl: &str) -> Result<Option<Work>> {
    let found = conn
        .query_row(
            "SELECT ra.repository_artifact_id, a.purl, a.version, a.release,
                    ra.declared_license, ra.published_ms, ra.last_seen_run_id
             FROM repository_artifact ra
             JOIN artifact a ON a.artifact_id = ra.artifact_id
             JOIN repository r ON r.repository_id = ra.repository_id
             WHERE r.role = 'source' AND r.name = ? AND a.purl = ?",
            params![source, purl],
            row_to_work,
        )
        .optional()
        .map_err(failed)?;

    let Some(mut work) = found else {
        return Ok(None);
    };

    let mut files = files_for(conn, std::iter::once(work.key))?;
    work.files = files.remove(&work.key).unwrap_or_default();

    Ok(Some(work))
}

/// Every version of one package that a repository holds.
///
/// `package` is the name-level purl -- everything up to the version -- so
/// this is the question `Source::versions` asks, answered from one index.
pub(super) fn versions(
    conn: &Connection,
    source: &str,
    package: &str,
) -> Result<Vec<(String, bool)>> {
    let mut statement = conn
        .prepare(
            "SELECT a.version, a.release
             FROM repository_artifact ra
             JOIN artifact a ON a.artifact_id = ra.artifact_id
             JOIN package p ON p.package_id = a.package_id
             JOIN repository r ON r.repository_id = ra.repository_id
             WHERE r.role = 'source' AND r.name = ? AND p.purl = ?
               AND a.version IS NOT NULL
             ORDER BY a.artifact_id",
        )
        .map_err(failed)?;

    let rows = statement
        .query_map(params![source, package], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?.as_deref() == Some("pre-release"),
            ))
        })
        .map_err(failed)?;

    rows.collect::<std::result::Result<_, _>>().map_err(failed)
}

/// Every file of a page's artifacts, in one query.
fn files_for(
    conn: &Connection,
    keys: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, Vec<WorkFile>>> {
    let keys: Vec<i64> = keys.collect();
    let holes = vec!["?"; keys.len()].join(", ");

    let mut statement = conn
        .prepare(&format!(
            "SELECT repository_artifact_id, repository_file_id, name, url, size_bytes,
                    listed_ms IS NOT NULL, resolved_ms IS NOT NULL, core_metadata
             FROM repository_file
             WHERE repository_artifact_id IN ({holes})
             ORDER BY repository_artifact_id, name"
        ))
        .map_err(failed)?;

    let rows = statement
        .query_map(params_from_iter(keys.iter()), |row| {
            // A document with no digest recorded is still a document, so
            // its presence is set here and its digests filled below.
            let core_metadata = row
                .get::<_, Option<bool>>(7)?
                .unwrap_or(false)
                .then(Vec::new);

            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                WorkFile {
                    name: row.get(2)?,
                    url: row.get(3)?,
                    size: row.get::<_, Option<i64>>(4)?.map(|size| size as u64),
                    digests: Vec::new(),
                    core_metadata,
                    signatures: Vec::new(),
                    listed: row.get(5)?,
                    resolved: row.get(6)?,
                },
            ))
        })
        .map_err(failed)?;

    let mut found: HashMap<i64, Vec<WorkFile>> = HashMap::new();
    let mut by_file: Vec<(i64, i64, usize)> = Vec::new();

    for row in rows {
        let (artifact, file_id, file) = row.map_err(failed)?;
        let bucket = found.entry(artifact).or_default();

        by_file.push((artifact, file_id, bucket.len()));
        bucket.push(file);
    }

    // The digests of every file on the page, also in one query. A copy
    // checks the bytes it fetches against these, so a file that arrives
    // without them is copied unverified rather than not at all.
    let file_ids = || by_file.iter().map(|(_, file, _)| *file);
    let mut digests = digests_for(conn, FILE_DIGESTS, file_ids())?;
    let mut documents = digests_for(conn, CORE_METADATA_DIGESTS, file_ids())?;
    let mut signatures = signatures_for(conn, file_ids())?;

    for (artifact, file_id, index) in by_file {
        let Some(found) = found.get_mut(&artifact) else {
            continue;
        };

        let file = &mut found[index];

        if let Some(declared) = digests.remove(&file_id) {
            file.digests = declared;
        }

        if let Some(document) = file.core_metadata.as_mut()
            && let Some(declared) = documents.remove(&file_id)
        {
            *document = declared;
        }

        if let Some(declared) = signatures.remove(&file_id) {
            file.signatures = declared;
        }
    }

    Ok(found)
}

/// The inventory table holding a file's own digests.
const FILE_DIGESTS: &str = "repository_file_digest";

/// The inventory table holding the digests of a file's core-metadata
/// document.
const CORE_METADATA_DIGESTS: &str = "repository_file_core_metadata_digest";

/// Every digest in `table`, one of the two above, of `files`.
fn digests_for(
    conn: &Connection,
    table: &str,
    files: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, Vec<crate::model::Digest>>> {
    let files: Vec<i64> = files.collect();

    if files.is_empty() {
        return Ok(HashMap::new());
    }

    let holes = vec!["?"; files.len()].join(", ");

    let mut statement = conn
        .prepare(&format!(
            "SELECT repository_file_id, algorithm, hex FROM {table}
             WHERE repository_file_id IN ({holes})
             ORDER BY repository_file_id, algorithm"
        ))
        .map_err(failed)?;

    let rows = statement
        .query_map(params_from_iter(files.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(failed)?;

    let mut found: HashMap<i64, Vec<crate::model::Digest>> = HashMap::new();

    for row in rows {
        let (file, algorithm, hex) = row.map_err(failed)?;

        // An algorithm this build does not know is dropped rather than
        // guessed at: a wrong algorithm on a digest is worse than a missing
        // one, because something would check against it.
        if let Some(alg) = spell::value(&algorithm) {
            found
                .entry(file)
                .or_default()
                .push(crate::model::Digest::new(alg, hex));
        }
    }

    Ok(found)
}

fn signatures_for(
    conn: &Connection,
    files: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, Vec<crate::model::SigRef>>> {
    let files: Vec<i64> = files.collect();

    if files.is_empty() {
        return Ok(HashMap::new());
    }

    let holes = vec!["?"; files.len()].join(", ");

    let mut statement = conn
        .prepare(&format!(
            "SELECT repository_file_id, scheme, key_id, value, url
             FROM repository_file_signature
             WHERE repository_file_id IN ({holes})
             ORDER BY repository_file_id, repository_file_signature_id"
        ))
        .map_err(failed)?;

    let rows = statement
        .query_map(params_from_iter(files.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(failed)?;

    let mut found: HashMap<i64, Vec<crate::model::SigRef>> = HashMap::new();

    for row in rows {
        let (file, scheme, key_id, value, url) = row.map_err(failed)?;

        // A scheme this build does not know is dropped: nothing here could
        // check it, and guessing would claim a signature of another kind.
        let Some(scheme) = spell::value(&scheme) else {
            continue;
        };

        found.entry(file).or_default().push(crate::model::SigRef {
            scheme,
            key_id,
            value,
            url,
        });
    }

    Ok(found)
}

/// The six columns both artifact queries select, in the same order.
fn row_to_work(row: &Row<'_>) -> rusqlite::Result<Work> {
    Ok(Work {
        key: row.get(0)?,
        purl: row.get(1)?,
        version: row.get(2)?,
        pre_release: row.get::<_, Option<String>>(3)?.as_deref() == Some("pre-release"),
        declared_license: row.get(4)?,
        published: row
            .get::<_, Option<i64>>(5)?
            .and_then(|ms| chrono::TimeZone::timestamp_millis_opt(&chrono::Utc, ms).single()),
        run: row.get(6)?,
        files: Vec::new(),
    })
}
