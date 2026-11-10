//! Opening the report database, and the settings it is opened under.
//!
//! The schema itself is `schema/report-db.sql`, included here at compile
//! time rather than written out in Rust. One copy, which the published
//! documentation points at, so the file a user reads and the file the tool
//! applies cannot drift.
//!
//! # Two kinds of pragma
//!
//! Some settings live in the database and some live on the connection, and
//! confusing the two is how a report ends up with foreign keys silently
//! off. `page_size`, `auto_vacuum`, `application_id`, `user_version`, and
//! the journal mode are properties of the *file*; `foreign_keys`,
//! `busy_timeout`, and `synchronous` are properties of a *connection* and
//! must be set again every time one is opened. The schema file holds the
//! first kind and this module holds the second.
//!
//! # A read-only open does not write
//!
//! It opens read-only, applies no schema, and refuses a file that is not
//! already a report database. A reader that created tables would turn a
//! typo in a path into a new empty database that reports nothing found.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::core::error::{Error, Result};

/// The schema, applied on every read-write open.
///
/// Every statement in it is `IF NOT EXISTS` or `INSERT OR IGNORE`, so
/// applying it to a database that already has it is a no-op.
const SCHEMA: &str = include_str!("../../../schema/report-db.sql");

/// "AMPR", so `file(1)` and anything else can identify the file.
const APPLICATION_ID: i64 = 1_095_585_874;

/// Version 1 was the copy-only progress database and was never published,
/// so there is no upgrade path from it.
const SCHEMA_VERSION: i64 = 10;

/// How long a connection waits for another writer before giving up.
///
/// SQLite answers `SQLITE_BUSY` immediately without this, so a reader that
/// shares the file with a running copy would fail rather than wait.
const BUSY_TIMEOUT_MILLIS: u32 = 30_000;

/// What a connection intends to do with the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    /// Read the database, and create it when it is not there.
    ReadWrite,

    /// Read an existing database, changing nothing about it.
    ReadOnly,
}

/// Open one connection to a report database.
pub(super) fn open(path: &Path, access: Access) -> Result<Connection> {
    let connection = match access {
        Access::ReadWrite => Connection::open(path),

        Access::ReadOnly => Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ),
    }
    .map_err(|source| failed(path, source))?;

    // `busy_timeout` installs SQLite's own retry handler, so nothing here
    // registers one of its own -- whichever is set last wins, and a handler
    // that retried forever would hang a run rather than fail it.
    connection
        .execute_batch(&format!(
            "PRAGMA busy_timeout = {BUSY_TIMEOUT_MILLIS};
             PRAGMA foreign_keys = ON;"
        ))
        .map_err(|source| failed(path, source))?;

    refuse_another_application(path, &connection)?;

    if access == Access::ReadOnly {
        expect_version(path, &connection)?;

        return Ok(connection);
    }

    // The schema sets page_size and auto_vacuum, which only take effect
    // while the file is still empty, so it runs before anything else writes.
    connection
        .execute_batch(SCHEMA)
        .map_err(|source| failed(path, source))?;

    // After the tables, because switching the journal mode writes.
    //
    // NORMAL rather than FULL: a power cut may lose the last commits, whose
    // worst case is a forgotten problem record and some repeated copying.
    // Paying for a flush on every claim to avoid that is not worth it.
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )
        .map_err(|source| failed(path, source))?;

    expect_version(path, &connection)?;

    Ok(connection)
}

/// Milliseconds since the Unix epoch, which is how every time is stored.
pub(super) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Let the planner know what the data looks like, and give back any free
/// pages that pruning left behind.
pub(super) fn close(connection: Connection) -> Result<()> {
    // Best effort: these are housekeeping, and failing a run because the
    // statistics could not be refreshed would be the tool refusing work it
    // has already done.
    let _ = connection.execute_batch(
        "PRAGMA optimize;
         PRAGMA incremental_vacuum;",
    );

    connection
        .close()
        .map_err(|(_, source)| Error::Report(format!("the database would not close: {source}")))
}

/// Refuse a SQLite file that belongs to something else.
///
/// A zero application id is an ordinary empty database, or one written
/// before the tool set it, and is adopted rather than refused.
fn refuse_another_application(path: &Path, connection: &Connection) -> Result<()> {
    let found: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|source| failed(path, source))?;

    if found != 0 && found != APPLICATION_ID {
        return Err(Error::Config(format!(
            "{} is a SQLite database belonging to another application",
            path.display()
        )));
    }

    Ok(())
}

/// Refuse a report database this build does not understand.
fn expect_version(path: &Path, connection: &Connection) -> Result<()> {
    let found: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| failed(path, source))?;

    if found == SCHEMA_VERSION {
        return Ok(());
    }

    if found == 0 {
        return Err(Error::Config(format!(
            "{} holds no report database",
            path.display()
        )));
    }

    Err(Error::Config(format!(
        "{} holds report schema version {found}, and this build reads version {SCHEMA_VERSION}",
        path.display()
    )))
}

fn failed(path: &Path, source: rusqlite::Error) -> Error {
    Error::Report(format!("database {}: {source}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        (dir, path)
    }

    fn opened() -> (tempfile::TempDir, Connection) {
        let (dir, path) = fresh();
        let connection = open(&path, Access::ReadWrite).expect("opens");

        (dir, connection)
    }

    /// The schema has to apply cleanly, and applying it twice has to be a
    /// no-op. Every statement in the file is conditional for that reason,
    /// and one that is not would fail here rather than on a user's second
    /// run.
    #[test]
    fn schema_applies_and_reapplies() {
        let (_dir, path) = fresh();

        open(&path, Access::ReadWrite).expect("creates");
        open(&path, Access::ReadWrite).expect("reopens");
        open(&path, Access::ReadOnly).expect("reads");
    }

    /// Three settings that cannot be changed after the fact, so a mistake
    /// here is permanent for every database already written.
    #[test]
    fn durable_settings_take() {
        let (_dir, connection) = opened();

        let read = |pragma: &str| -> i64 {
            connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
                .expect(pragma)
        };

        assert_eq!(read("application_id"), APPLICATION_ID);
        assert_eq!(read("user_version"), SCHEMA_VERSION);

        // 2 is INCREMENTAL, which is what makes pruning able to return
        // space. It can only be set before the first table exists.
        assert_eq!(read("auto_vacuum"), 2);
    }

    #[test]
    fn connections_enforce_foreign_keys() {
        let (_dir, connection) = opened();

        let enabled: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("read");

        assert_eq!(enabled, 1);

        let orphan = connection.execute(
            "INSERT INTO artifact (package_id, purl) VALUES (404, 'pkg:npm/nope')",
            [],
        );

        assert!(orphan.is_err(), "an artifact without a package was taken");
    }

    /// Every table is `STRICT`, and the point of that is a column refusing
    /// a value of the wrong type instead of storing it.
    #[test]
    fn columns_refuse_wrong_type() {
        let (_dir, connection) = opened();

        let wrong = connection.execute(
            "INSERT INTO run (command, tool_version, started_ms)
             VALUES ('copy', '1.0', 'half past ten')",
            [],
        );

        assert!(wrong.is_err(), "a time column took a sentence");
    }

    /// A catalog that lists names only leaves the version null, and SQLite
    /// counts each null in a unique index as distinct -- so uniqueness has
    /// to rest on the rendered purl rather than on (package, version).
    #[test]
    fn package_keeps_one_name_only_row() {
        let (_dir, connection) = opened();

        connection
            .execute(
                "INSERT INTO package (package_id, purl, ecosystem, name)
                 VALUES (1, 'pkg:npm/tuna', 'npm', 'tuna')",
                [],
            )
            .expect("package");

        let name_only = "INSERT INTO artifact (package_id, purl) VALUES (1, 'pkg:npm/tuna')";

        connection.execute(name_only, []).expect("the first");

        assert!(
            connection.execute(name_only, []).is_err(),
            "a second name-only row was taken"
        );

        // Versions under the same package are still distinct rows.
        connection
            .execute(
                "INSERT INTO artifact (package_id, purl, version, release)
                 VALUES (1, 'pkg:npm/tuna@1.0.0', '1.0.0', 'general')",
                [],
            )
            .expect("a version");
    }

    /// A download names no destination, so a plain unique constraint would
    /// let one file be downloaded twice over. Two partial indexes are what
    /// hold each direction to one row.
    #[test]
    fn file_moves_once_per_destination() {
        let (_dir, connection) = opened();

        connection
            .execute_batch(
                "INSERT INTO repository (repository_id, role, name)
                     VALUES (1, 'source', 'origin'), (2, 'target', 'mirror'),
                            (3, 'target', 'spare');
                 INSERT INTO package (package_id, purl, ecosystem, name)
                     VALUES (1, 'pkg:npm/tuna', 'npm', 'tuna');
                 INSERT INTO artifact (artifact_id, package_id, purl, version, release)
                     VALUES (1, 1, 'pkg:npm/tuna@1.0.0', '1.0.0', 'general');
                 INSERT INTO repository_artifact
                     (repository_artifact_id, repository_id, artifact_id,
                      first_seen_ms, last_seen_ms)
                     VALUES (1, 1, 1, 0, 0);
                 INSERT INTO repository_file
                     (repository_file_id, repository_artifact_id, name, url, resolved_ms)
                     VALUES (1, 1, 'tuna.tgz', 'h://origin.test/tuna.tgz', 0);",
            )
            .expect("inventory");

        let download = "INSERT INTO file_transfer (repository_file_id, direction, state)
                        VALUES (1, 'download', 'pending')";

        connection
            .execute(download, [])
            .expect("the first download");

        assert!(
            connection.execute(download, []).is_err(),
            "one file was queued for download twice"
        );

        // An upload per destination, though, is two separate pieces of work.
        for destination in [2, 3] {
            connection
                .execute(
                    "INSERT INTO file_transfer
                         (repository_file_id, direction, destination_repository_id, state)
                     VALUES (1, 'upload', ?, 'pending')",
                    [destination],
                )
                .expect("an upload");
        }

        let twice = connection.execute(
            "INSERT INTO file_transfer
                 (repository_file_id, direction, destination_repository_id, state)
             VALUES (1, 'upload', 2, 'pending')",
            [],
        );

        assert!(twice.is_err(), "one file was queued twice for one target");
    }

    /// The resume query joins on `terminal` rather than repeating the list
    /// of finished states, so the flags have to be right here.
    #[test]
    fn transfer_finished_states_marked() {
        let (_dir, connection) = opened();

        let mut statement = connection
            .prepare("SELECT state FROM transfer_state WHERE terminal = 1 ORDER BY state")
            .expect("prepared");

        let terminal: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(
            terminal,
            vec![
                "already-present",
                "copied",
                "refused",
                "skipped",
                "unresolved"
            ]
        );
    }

    /// Times are integers, and the whole reason is that they survive a
    /// round trip and compare against each other. Text renderings of a
    /// `NaiveDateTime` and a `DateTime<Utc>` do neither.
    #[test]
    fn time_round_trips_as_integer() {
        let (_dir, connection) = opened();
        let started = now_ms();

        connection
            .execute(
                "INSERT INTO run (command, tool_version, started_ms) VALUES ('copy', '1.0', ?)",
                [started],
            )
            .expect("a run");

        let read: i64 = connection
            .query_row("SELECT started_ms FROM run", [], |row| row.get(0))
            .expect("read");

        assert_eq!(read, started);

        // Sanity, so a broken clock conversion cannot pass: some time after
        // 2020 and before 2100, in milliseconds.
        assert!(
            (1_577_836_800_000..4_102_444_800_000).contains(&started),
            "{started}"
        );
    }

    /// Closing runs `PRAGMA optimize` and an incremental vacuum in one
    /// batch. Both answer rows, and a batch that could not take that would
    /// fail every run's last act.
    #[test]
    fn close_runs_housekeeping() {
        let (_dir, path) = fresh();

        close(open(&path, Access::ReadWrite).expect("opens")).expect("closes");

        open(&path, Access::ReadWrite).expect("reopens");
    }

    /// A typo in a path must not read as an empty report. Creating the
    /// tables on a read would turn "nothing is there" into "nothing was
    /// found", which a caller cannot tell from a real answer.
    #[test]
    fn open_read_only_non_report_refused() {
        let (_dir, path) = fresh();

        open(&path, Access::ReadOnly).expect_err("a database that is not there");

        std::fs::write(&path, b"not a database").expect("written");

        open(&path, Access::ReadOnly).expect_err("a file that is not a database");
    }

    /// An unrelated SQLite database must be refused rather than grown a set
    /// of report tables.
    #[test]
    fn open_foreign_database_refused() {
        let (_dir, path) = fresh();

        let theirs = Connection::open(&path).expect("opens");
        theirs
            .execute_batch("PRAGMA application_id = 42; CREATE TABLE theirs (x);")
            .expect("written");
        theirs.close().expect("closed");

        let err = open(&path, Access::ReadWrite).expect_err("refused");

        assert!(err.to_string().contains("another application"), "{err}");
    }
}
