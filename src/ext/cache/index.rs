//! What each cached file is, and when it was fetched and last used.
//!
//! A cached file's path is a hash of its URL (see [`super::Cache::payload_path`]),
//! and a hash cannot be read backwards. So every file written is noted
//! here, in a SQLite file beside the shards it describes, with the times
//! its [`Lifetime`] is judged against:
//!
//! ```text
//!   <cache-dir>/<host>/
//!     index.sqlite                         path -> url, file name, times
//!     3f/a2/3fa2...e1/tuna-1.0.0.tgz       a payload
//!     documents/9c/04/9c04...7b/packument.json
//! ```
//!
//! On disk rather than in memory, because a repository of a million files
//! would otherwise be a million rows held for the whole run. The purl is not
//! here: join `url` to the report's `repository_file.url` for that.
//!
//! `size_bytes` keeps a running total possible without walking the disk,
//! and `evicted_ms` marks a file removed to keep a cache under its size: the
//! row stays as a tombstone, so a later run that finds the file gone knows
//! it was policy rather than somebody cleaning out the directory.
//!
//! `retain_until_ms` and `fresh_until_ms` are written from the lifetime in
//! force at the time, so a maintenance script can prune without reading the
//! configuration. A run judges against its own configuration instead, from
//! `fetched_ms` and `used_ms`, so a changed setting applies at once.
//!
//! Opened on first use, so a host that never caches a file gets no index.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};

use super::{CachePath, Lifetime};
use crate::core::error::{Error, Result};

/// How long a writer waits on another process holding the lock.
const BUSY_TIMEOUT_MILLIS: u32 = 5_000;

/// The shape of `entry`. An index of another version is dropped and built
/// again: the cache is disposable, and a file the index forgets is only
/// undated, which costs a download at most.
const INDEX_VERSION: i64 = 2;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS entry (
        relative_path   TEXT PRIMARY KEY,
        url             TEXT NOT NULL,
        file_name       TEXT NOT NULL,
        fetched_ms      INTEGER NOT NULL,
        used_ms         INTEGER NOT NULL,
        retain_until_ms INTEGER,
        fresh_until_ms  INTEGER,
        size_bytes      INTEGER,
        evicted_ms      INTEGER
    );
    CREATE INDEX IF NOT EXISTS entry_url ON entry (url);
    CREATE INDEX IF NOT EXISTS entry_retain ON entry (retain_until_ms);
    CREATE INDEX IF NOT EXISTS entry_used ON entry (used_ms) WHERE evicted_ms IS NULL;
";

/// Where one cached file came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub path: CachePath,
    pub url: String,

    /// The file's own name, which is also the path's last component.
    pub name: String,
}

/// What the index holds about one cached file's times, in milliseconds
/// since the Unix epoch. The two limits are `None` for forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kept {
    pub fetched_ms: i64,
    pub used_ms: i64,
    pub retain_until_ms: Option<i64>,
    pub fresh_until_ms: Option<i64>,
}

/// A cached file that could be evicted to make room, oldest use first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Candidate {
    pub(super) origin: Origin,
    pub(super) size_bytes: u64,
    pub(super) used_ms: i64,
}

#[derive(Debug)]
pub(super) struct Index {
    file: PathBuf,
    conn: Mutex<Option<Connection>>,
}

impl Index {
    pub(super) fn new(file: PathBuf) -> Self {
        Self {
            file,
            conn: Mutex::new(None),
        }
    }

    /// Note a fetched file of `size_bytes`, replacing whatever was noted for
    /// its path, a tombstone included.
    ///
    /// Answers how much the live total grew, which is less than the file's
    /// size when it replaced one.
    pub(super) fn record(
        &self,
        origin: &Origin,
        lifetime: &Lifetime,
        size_bytes: u64,
        now_ms: i64,
    ) -> Result<i64> {
        let replaced = self.live_size(&origin.path)?;

        self.with(|conn| {
            conn.execute(
                "INSERT INTO entry
                    (relative_path, url, file_name, fetched_ms, used_ms,
                     retain_until_ms, fresh_until_ms, size_bytes, evicted_ms)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                 ON CONFLICT (relative_path) DO UPDATE SET
                     url = excluded.url,
                     file_name = excluded.file_name,
                     fetched_ms = excluded.fetched_ms,
                     used_ms = excluded.used_ms,
                     retain_until_ms = excluded.retain_until_ms,
                     fresh_until_ms = excluded.fresh_until_ms,
                     size_bytes = excluded.size_bytes,
                     evicted_ms = NULL",
                params![
                    origin.path.as_str(),
                    origin.url,
                    origin.name,
                    now_ms,
                    now_ms,
                    until(now_ms, lifetime.retention),
                    until(now_ms, lifetime.freshness),
                    bytes(size_bytes),
                ],
            )
            .map(|_| ())
        })?;

        Ok(bytes(size_bytes) - bytes(replaced))
    }

    /// Note a use of a cached file, which restarts its retention.
    pub(super) fn touch(&self, path: &CachePath, lifetime: &Lifetime, now_ms: i64) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "UPDATE entry SET used_ms = ?, retain_until_ms = ? WHERE relative_path = ?",
                params![now_ms, until(now_ms, lifetime.retention), path.as_str()],
            )
            .map(|_| ())
        })
    }

    /// What was noted for a path. `None` for one never recorded, such as a
    /// file cached before the index existed.
    pub(super) fn find(&self, path: &CachePath) -> Result<Option<Origin>> {
        self.with(|conn| {
            conn.query_row(
                "SELECT url, file_name FROM entry WHERE relative_path = ?",
                params![path.as_str()],
                |row| {
                    Ok(Origin {
                        path: path.clone(),
                        url: row.get(0)?,
                        name: row.get(1)?,
                    })
                },
            )
            .optional()
        })
    }

    /// What was noted about a path's times, if it was recorded.
    pub(super) fn kept(&self, path: &CachePath) -> Result<Option<Kept>> {
        self.with(|conn| {
            conn.query_row(
                "SELECT fetched_ms, used_ms, retain_until_ms, fresh_until_ms
                 FROM entry WHERE relative_path = ?",
                params![path.as_str()],
                |row| {
                    Ok(Kept {
                        fetched_ms: row.get(0)?,
                        used_ms: row.get(1)?,
                        retain_until_ms: row.get(2)?,
                        fresh_until_ms: row.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Drop what was noted for a path, once its file is gone. Answers the
    /// size that leaves the live total.
    pub(super) fn forget(&self, path: &CachePath) -> Result<u64> {
        let size = self.live_size(path)?;

        self.with(|conn| {
            conn.execute(
                "DELETE FROM entry WHERE relative_path = ?",
                params![path.as_str()],
            )
            .map(|_| ())
        })?;

        Ok(size)
    }

    /// Mark a path's file removed to make room, keeping its row as a
    /// tombstone. Answers the size that leaves the live total.
    pub(super) fn tombstone(&self, path: &CachePath, now_ms: i64) -> Result<u64> {
        let size = self.live_size(path)?;

        self.with(|conn| {
            conn.execute(
                "UPDATE entry SET evicted_ms = ? WHERE relative_path = ? AND evicted_ms IS NULL",
                params![now_ms, path.as_str()],
            )
            .map(|_| ())
        })?;

        Ok(size)
    }

    /// Whether a path's file was removed to make room.
    pub(super) fn tombstoned(&self, path: &CachePath) -> Result<bool> {
        self.with(|conn| {
            conn.query_row(
                "SELECT 1 FROM entry WHERE relative_path = ? AND evicted_ms IS NOT NULL",
                params![path.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|found| found.is_some())
        })
    }

    /// The size of every file still here.
    pub(super) fn total(&self) -> Result<u64> {
        self.with(|conn| {
            conn.query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM entry WHERE evicted_ms IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(unsigned)
    }

    /// Up to `limit` files still here, least recently used first.
    pub(super) fn oldest(&self, limit: usize) -> Result<Vec<Candidate>> {
        self.with(|conn| {
            let mut statement = conn.prepare(
                "SELECT relative_path, url, file_name, COALESCE(size_bytes, 0), used_ms
                 FROM entry WHERE evicted_ms IS NULL
                 ORDER BY used_ms, relative_path LIMIT ?",
            )?;

            let rows = statement.query_map(params![bytes(limit as u64)], |row| {
                Ok(Candidate {
                    origin: Origin {
                        path: CachePath {
                            relative: PathBuf::from(row.get::<_, String>(0)?),
                        },
                        url: row.get(1)?,
                        name: row.get(2)?,
                    },
                    size_bytes: unsigned(row.get(3)?),
                    used_ms: row.get(4)?,
                })
            })?;

            rows.collect()
        })
    }

    /// A live file's recorded size; 0 for one unrecorded or tombstoned.
    fn live_size(&self, path: &CachePath) -> Result<u64> {
        self.with(|conn| {
            conn.query_row(
                "SELECT COALESCE(size_bytes, 0) FROM entry
                 WHERE relative_path = ? AND evicted_ms IS NULL",
                params![path.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
        })
        .map(|size| unsigned(size.unwrap_or_default()))
    }

    /// Let go of the file, so the directory holding it can be removed. On
    /// Windows an open database cannot be.
    pub(super) fn close(&self) {
        if let Ok(mut conn) = self.conn.lock() {
            *conn = None;
        }
    }

    /// Run `work` on the connection, opening it first if needed.
    fn with<T>(&self, work: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| Error::Config(format!("{}: lock poisoned", self.file.display())))?;

        let conn = match &mut *guard {
            Some(conn) => conn,
            empty => empty.insert(self.open().map_err(|source| self.failed(source))?),
        };

        work(conn).map_err(|source| self.failed(source))
    }

    fn open(&self) -> rusqlite::Result<Connection> {
        let conn = Connection::open(&self.file)?;

        // WAL lets two runs over one cache directory read while one writes.
        conn.execute_batch(&format!(
            "PRAGMA busy_timeout = {BUSY_TIMEOUT_MILLIS};
             PRAGMA journal_mode = WAL;"
        ))?;

        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        if version != INDEX_VERSION {
            conn.execute_batch("DROP TABLE IF EXISTS entry;")?;
        }

        conn.execute_batch(&format!("{SCHEMA} PRAGMA user_version = {INDEX_VERSION};"))?;

        Ok(conn)
    }

    fn failed(&self, source: rusqlite::Error) -> Error {
        Error::Config(format!("cache index {}: {source}", self.file.display()))
    }
}

/// A size as SQLite stores it.
fn bytes(size: u64) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}

/// A stored size, with a negative one read as none.
fn unsigned(size: i64) -> u64 {
    u64::try_from(size).unwrap_or_default()
}

/// `now_ms` plus `limit`, or `None` for forever.
fn until(now_ms: i64, limit: Option<Duration>) -> Option<i64> {
    limit.map(|limit| now_ms.saturating_add(i64::try_from(limit.as_millis()).unwrap_or(i64::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3_600);
    const HOUR_MS: i64 = 3_600_000;

    fn index() -> (tempfile::TempDir, Index) {
        let dir = tempfile::tempdir().expect("tempdir");
        let index = Index::new(dir.path().join("index.sqlite"));

        (dir, index)
    }

    fn origin() -> Origin {
        Origin {
            path: CachePath {
                relative: PathBuf::from("doc.json"),
            },
            url: "h://origin.test/doc".to_owned(),
            name: "doc.json".to_owned(),
        }
    }

    /// A use moves the retention clock and leaves the freshness clock
    /// where the fetch set it, so a file a migration keeps reusing is
    /// never aged out from under it.
    #[test]
    fn touch_moves_only_use() {
        let (_dir, index) = index();
        let origin = origin();
        let lifetime = Lifetime {
            retention: Some(HOUR),
            freshness: Some(HOUR),
        };

        index.record(&origin, &lifetime, 10, 0).expect("recorded");
        index
            .touch(&origin.path, &lifetime, HOUR_MS)
            .expect("touched");

        let kept = index.kept(&origin.path).expect("read").expect("found");

        assert_eq!(kept.fetched_ms, 0);
        assert_eq!(kept.used_ms, HOUR_MS);
        assert_eq!(kept.retain_until_ms, Some(HOUR_MS * 2));
        assert_eq!(kept.fresh_until_ms, Some(HOUR_MS));
    }

    /// The limits in force are written beside the times, so a maintenance
    /// script can prune without the configuration. Forever is null.
    #[test]
    fn until_columns_follow_lifetime() {
        assert_eq!(until(1_000, Some(HOUR)), Some(1_000 + HOUR_MS));
        assert_eq!(until(1_000, None), None);
    }

    #[test]
    fn forget_drops_entry() {
        let (_dir, index) = index();
        let origin = origin();

        index
            .record(&origin, &Lifetime::FOREVER, 10, 0)
            .expect("recorded");
        index.forget(&origin.path).expect("forgotten");

        assert_eq!(index.find(&origin.path).expect("read"), None);
    }
}
