//! Identity rows, de-duplicated once and handed back as typed keys.
//!
//! Everything here is an upsert: ask for a row, get the key, and get the
//! same key next time. A million observations of one package make one
//! `package` row, which is the difference between an inventory and a log.
//!
//! # Why the keys are types
//!
//! Every one of these is an `i64`, and passing a `package_id` where an
//! `artifact_id` belongs would compile, insert, and produce a database that
//! is quietly wrong in a way no constraint catches -- both point at rows
//! that exist. A newtype per table makes that a build error instead.

use rusqlite::{Connection, OptionalExtension, params};

use crate::core::error::{Error, Result};
use crate::model::{ArtifactId, Version};

macro_rules! key {
    ($name:ident, $table:literal) => {
        #[doc = concat!("A `", $table, "` row's key.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(super) struct $name(pub(super) i64);
    };
}

key!(RunId, "run");
key!(RepositoryId, "repository");
key!(RecordId, "report_record");
key!(PackageId, "package");
key!(ArtifactRowId, "artifact");
key!(ObservationId, "artifact_observation");
key!(ProblemId, "problem");
key!(ChainId, "provenance_chain");
key!(AdvisoryId, "advisory");
key!(SuppressionId, "suppression");
key!(BypassId, "bypass");

/// Record a problem code, so a database written by a newer build stays
/// readable by an older one.
///
/// The codes are a lookup table rather than a `CHECK` constraint precisely
/// so that this can happen: SQLite cannot alter a constraint, and a new
/// code would otherwise mean rebuilding every table that names one.
pub(super) fn code(conn: &Connection, code: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO problem_code (code) VALUES (?)",
        params![code],
    )
    .map_err(failed)?;

    Ok(())
}

/// The `repository` row for one configured binding.
///
/// Identity is the role and the configured name, and nothing else. The
/// endpoint details are recorded as last seen and **not** checked: a user
/// may retune a configuration over time without rebuilding a database, and
/// refusing a changed base URL would cost that for a guarantee nobody
/// asked for. The assumption is that a name is not repointed at a
/// different repository while one database is reused.
///
/// A role is part of the key because one name may be both a source and a
/// target, and a source's inventory is a different claim from a target's.
pub(super) fn repository(
    conn: &Connection,
    role: &str,
    name: &str,
    host: Option<&str>,
    base_url: Option<&str>,
    ecosystem: Option<&str>,
) -> Result<RepositoryId> {
    conn.execute(
        "INSERT INTO repository (role, name, host, base_url, ecosystem)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (role, name) DO UPDATE
            SET host = COALESCE(excluded.host, host),
                base_url = COALESCE(excluded.base_url, base_url),
                ecosystem = COALESCE(excluded.ecosystem, ecosystem)",
        params![role, name, host, base_url, ecosystem],
    )
    .map_err(failed)?;

    let repository_id: i64 = conn
        .query_row(
            "SELECT repository_id FROM repository WHERE role = ? AND name = ?",
            params![role, name],
            |row| row.get(0),
        )
        .map_err(failed)?;

    Ok(RepositoryId(repository_id))
}

/// Note that a run used a repository, and at what priority.
pub(super) fn run_repository(
    conn: &Connection,
    run: RunId,
    repository: RepositoryId,
    priority: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO run_repository (run_id, repository_id, priority) VALUES (?, ?, ?)
         ON CONFLICT (run_id, repository_id) DO UPDATE SET priority = excluded.priority",
        params![run.0, repository.0, priority],
    )
    .map_err(failed)?;

    Ok(())
}

/// The `package` row for an artifact's name-level identity.
///
/// Keyed on the rendered purl, because that is the one value that captures
/// the ecosystem, the namespace, the name, and every qualifier at once. The
/// pieces are stored beside it for querying, and the qualifiers follow into
/// their own rows.
pub(super) fn package(conn: &Connection, id: &ArtifactId) -> Result<PackageId> {
    let purl = id.purl();

    let existing: Option<i64> = conn
        .query_row(
            "SELECT package_id FROM package WHERE purl = ?",
            params![purl],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?;

    if let Some(package_id) = existing {
        return Ok(PackageId(package_id));
    }

    conn.execute(
        "INSERT INTO package (purl, ecosystem, namespace, name) VALUES (?, ?, ?, ?)",
        params![purl, id.ecosystem().as_str(), id.namespace(), id.name()],
    )
    .map_err(failed)?;

    let package_id = PackageId(conn.last_insert_rowid());

    for (key, value) in id.qualifiers() {
        conn.execute(
            "INSERT OR IGNORE INTO package_qualifier (package_id, key, value) VALUES (?, ?, ?)",
            params![package_id.0, key, value],
        )
        .map_err(failed)?;
    }

    Ok(package_id)
}

/// The `artifact` row for one version, or for a name with no version.
///
/// A name-only row is what an npm replication feed or a PyPI simple index
/// honestly produces, and it is the row a later versioned enumeration joins
/// through. The rendered purl carries the distinction, so one unique index
/// covers both cases.
pub(super) fn artifact(
    conn: &Connection,
    id: &ArtifactId,
    version: Option<&Version>,
) -> Result<ArtifactRowId> {
    let package_id = package(conn, id)?;

    let purl = match version {
        Some(version) => id.purl_at(version.text()),
        None => id.purl(),
    };

    let existing: Option<i64> = conn
        .query_row(
            "SELECT artifact_id FROM artifact WHERE purl = ?",
            params![purl],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?;

    if let Some(artifact_id) = existing {
        return Ok(ArtifactRowId(artifact_id));
    }

    // Stored rather than recomputed on read, so that a reader can build a
    // `Version` without a configured session -- which the diff and
    // maintenance scripts both lack.
    let release = version.map(|version| version.release().as_str());

    conn.execute(
        "INSERT INTO artifact (package_id, purl, version, release) VALUES (?, ?, ?, ?)",
        params![package_id.0, purl, version.map(Version::text), release,],
    )
    .map_err(failed)?;

    Ok(ArtifactRowId(conn.last_insert_rowid()))
}

/// The `advisory` row for one finding, shared by every observation of it.
pub(super) fn advisory(
    conn: &Connection,
    id: &str,
    kind: &str,
    summary: Option<&str>,
) -> Result<AdvisoryId> {
    // `ON CONFLICT DO UPDATE` rather than `DO NOTHING`: a later corpus may
    // carry a summary where an earlier one had none, and the row exists to
    // be read rather than only to be pointed at.
    conn.execute(
        "INSERT INTO advisory (kind, id, summary) VALUES (?, ?, ?)
         ON CONFLICT (kind, id) DO UPDATE SET summary = COALESCE(excluded.summary, summary)",
        params![kind, id, summary],
    )
    .map_err(failed)?;

    let advisory_id: i64 = conn
        .query_row(
            "SELECT advisory_id FROM advisory WHERE kind = ? AND id = ?",
            params![kind, id],
            |row| row.get(0),
        )
        .map_err(failed)?;

    Ok(AdvisoryId(advisory_id))
}

/// The `suppression` row for one VEX statement.
pub(super) fn suppression(
    conn: &Connection,
    source: &str,
    justification: Option<&str>,
    detail: Option<&str>,
) -> Result<SuppressionId> {
    // The unique index is over the three columns with nulls folded to
    // sentinels, because a null makes every row distinct from every other
    // and two identical statements would become two rows.
    conn.execute(
        "INSERT OR IGNORE INTO suppression (source, justification, detail) VALUES (?, ?, ?)",
        params![source, justification, detail],
    )
    .map_err(failed)?;

    let suppression_id: i64 = conn
        .query_row(
            "SELECT suppression_id FROM suppression
             WHERE source = ?
               AND IFNULL(justification, '') = IFNULL(?, '')
               AND IFNULL(detail, '') = IFNULL(?, '')",
            params![source, justification, detail],
            |row| row.get(0),
        )
        .map_err(failed)?;

    Ok(SuppressionId(suppression_id))
}

/// The `bypass` row for one quarantine acknowledgement.
pub(super) fn bypass(
    conn: &Connection,
    source: &str,
    justification: Option<&str>,
    expires_ms: Option<i64>,
) -> Result<BypassId> {
    conn.execute(
        "INSERT OR IGNORE INTO bypass (source, justification, expires_ms) VALUES (?, ?, ?)",
        params![source, justification, expires_ms],
    )
    .map_err(failed)?;

    let bypass_id: i64 = conn
        .query_row(
            "SELECT bypass_id FROM bypass
             WHERE source = ?
               AND IFNULL(justification, '') = IFNULL(?, '')
               AND IFNULL(expires_ms, -1) = IFNULL(?, -1)",
            params![source, justification, expires_ms],
            |row| row.get(0),
        )
        .map_err(failed)?;

    Ok(BypassId(bypass_id))
}

pub(super) fn failed(source: rusqlite::Error) -> Error {
    Error::Report(format!("database: {source}"))
}
