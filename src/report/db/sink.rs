//! The database wearing [`ReportWriter`] and [`ReportReader`].
//!
//! # One connection, behind one lock
//!
//! SQLite allows one writer, and one handle cannot serve concurrent reads
//! either, so every operation takes the same mutex. That is not the
//! bottleneck it looks like: a record is a handful of small inserts beside
//! the network fetch that produced it, and the alternative -- a connection
//! per worker -- buys contention on the file instead of contention on a
//! mutex, with `SQLITE_BUSY` in place of a wait.
//!
//! The lock is never held across network work. A caller hands over a
//! finished record; nothing here calls out.
//!
//! # A run opens on the header
//!
//! A database needs a `run` row before it can attribute anything, and
//! everything it needs for one arrives on the header: the command, the tool
//! version, and what was screened. So the header opens the run, and a
//! record before it is refused rather than attributed to a run that does
//! not exist. Every command writes its header first, which is what makes
//! that safe rather than fragile.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::core::error::{Error, Result};
use crate::report::record::Record;
use crate::report::sink::{
    Binding, Claim, Claimed, Completion, Download, Enqueued, Enumeration, Marked, ReportQuery,
    ReportReader, ReportState, ReportWriter, Resume, Role, Transfer, Upload, WalkId, WalkState,
    WalkTask, Work,
};

use super::conn::{self, Access};
use super::enumeration;
use super::frontier;
use super::read;
use super::work;
use super::write::Writing;

/// Writes a report into a SQLite database.
pub(in crate::report) struct DbWriter {
    /// `None` once flushed, so a write after the run closed is an error
    /// rather than a silently dropped record.
    open: Mutex<Option<Open>>,

    /// Kept so a caller can be handed a read view of the same store rather
    /// than having to know where it is.
    path: PathBuf,

    artifact_count: AtomicU64,

    /// The temporary directory a run's own database lives in, when it has
    /// one. Last, so the connection closes before the directory goes.
    _scratch: Option<Arc<TempDir>>,
}

struct Open {
    conn: Connection,

    /// `None` until the header arrives, which is the one record that can
    /// open a run.
    writing: Option<Writing>,
}

impl DbWriter {
    /// Open a database and add a run to whatever it already holds.
    ///
    /// Eagerly, so a database that cannot be written fails before a walk
    /// starts rather than after the first artifact is fetched.
    pub(in crate::report) fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            open: Mutex::new(Some(Open {
                conn: conn::open(path, Access::ReadWrite)?,
                writing: None,
            })),
            path: path.to_path_buf(),
            artifact_count: AtomicU64::new(0),
            _scratch: None,
        })
    }

    /// Keep `scratch` until this writer is dropped.
    pub(in crate::report) fn keeping(mut self, scratch: Option<Arc<TempDir>>) -> Self {
        self._scratch = scratch;
        self
    }
}

impl ReportWriter for DbWriter {
    fn write(&self, record: &Record) -> Result<()> {
        if matches!(record, Record::Artifact(_)) {
            self.artifact_count.fetch_add(1, Ordering::Relaxed);
        }

        let mut guard = self.open.lock().map_err(poisoned)?;

        let Some(open) = guard.as_mut() else {
            return Err(Error::Report(
                "the report database is already closed".into(),
            ));
        };

        // A second header in one run is a report appended to another, which
        // the line formats allow; the first one opens the run.
        if let (Record::Header(header), None) = (record, &open.writing) {
            open.writing = Some(Writing::open(&mut open.conn, header)?);

            return Ok(());
        }

        let Some(writing) = open.writing.as_mut() else {
            return Err(Error::Report(
                "a report database record arrived before the header that opens its run".into(),
            ));
        };

        writing.write(&mut open.conn, record)
    }

    fn artifact_count(&self) -> u64 {
        self.artifact_count.load(Ordering::Relaxed)
    }

    /// Nothing is buffered, so this closes the run instead.
    ///
    /// A run with no finish time is how a later run recognizes a crash, so
    /// leaving one open is a claim about this run rather than an omission.
    /// Every command flushes its report after writing the summary.
    fn flush(&self) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;

        let Some(open) = guard.take() else {
            return Ok(());
        };

        if let Some(writing) = &open.writing {
            writing.finish(&open.conn)?;
        }

        conn::close(open.conn)
    }

    fn state(&self) -> Option<&dyn ReportState> {
        Some(self)
    }

    /// A second connection, read-only, over the same file.
    ///
    /// Safe alongside the writer because the database is in WAL mode: a
    /// reader sees a consistent snapshot while a writer is working, which
    /// is the whole reason WAL was chosen.
    fn query(&self) -> Result<Option<std::sync::Arc<dyn ReportQuery>>> {
        Ok(Some(std::sync::Arc::new(DbReader::open(&self.path)?)))
    }
}

impl ReportState for DbWriter {
    /// A binding needs the run it belongs to, so this refuses before the
    /// header rather than creating a repository with nothing to attach it
    /// to. Every command writes its header first.
    fn bind(&self, binding: &Binding<'_>) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "a repository was bound")?;

        writing.bind(conn, binding)
    }

    fn checkpoint(&self, at: &Enumeration<'_>) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "a walk was checkpointed")?;

        writing.checkpoint(conn, at)
    }

    fn claim(&self, claim: &Claim<'_>) -> Result<Option<Claimed>> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "work was claimed")?;

        writing.claim(conn, claim)
    }

    fn close(&self, claimed: Claimed, outcome: Transfer) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "a claim was closed")?;

        writing.close_claim(conn, claimed, outcome)
    }

    fn downloaded(&self, at: &Download<'_>) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "a payload was fetched")?;

        writing.downloaded(conn, at)
    }

    fn uploaded(&self, at: &Upload<'_>) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "a file was sent")?;

        writing.uploaded(conn, at)
    }

    fn present(&self, target: &str, purl: &str) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "a target's contents were recorded")?;

        super::cache::present(conn, target, purl)
    }

    fn complete(&self, how: Completion) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, _) = writing(&mut guard, "a run was completed")?;

        writing.complete(how);

        Ok(())
    }

    fn walks(&self) -> Option<&dyn WalkState> {
        Some(self)
    }
}

/// Each call is one short statement under the lock, like every other state
/// call; none of them waits on the network.
impl WalkState for DbWriter {
    fn start(
        &self,
        source: &str,
        spec: &str,
        targets: &str,
        resume: Option<WalkId>,
    ) -> Result<WalkId> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (writing, conn) = writing(&mut guard, "a dependency walk started")?;

        writing.start_walk(conn, source, spec, targets, resume)
    }

    fn push(&self, walk: WalkId, task: &WalkTask) -> Result<Enqueued> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "a dependency was queued")?;

        frontier::push(conn, walk, task)
    }

    fn pop(&self, walk: WalkId) -> Result<Option<(i64, WalkTask)>> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "a dependency was taken")?;

        let transaction = conn.transaction().map_err(super::ids::failed)?;
        let popped = frontier::pop(&transaction, walk)?;

        transaction.commit().map_err(super::ids::failed)?;

        Ok(popped)
    }

    fn done(&self, walk: WalkId, task: i64) -> Result<()> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "a dependency was finished")?;

        frontier::done(conn, walk, task)
    }

    fn pending(&self, walk: WalkId) -> Result<u64> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "a dependency walk was counted")?;

        frontier::pending(conn, walk)
    }

    fn mark(&self, walk: WalkId, purl: &str, task: i64) -> Result<Marked> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "an artifact was claimed")?;

        frontier::mark(conn, walk, purl, task)
    }

    fn marked(&self, walk: WalkId, purl: &str) -> Result<bool> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "a claim was checked")?;

        frontier::marked(conn, walk, purl)
    }

    fn marks(&self, walk: WalkId) -> Result<u64> {
        let mut guard = self.open.lock().map_err(poisoned)?;
        let (_, conn) = writing(&mut guard, "claims were counted")?;

        frontier::marks(conn, walk)
    }
}

/// The run a state call needs, or the reason there is not one.
///
/// Every one of these needs a run to attribute to, and the header is what
/// opens a run. Every command writes its header first, which is what makes
/// the refusal a guard rather than a hazard.
fn writing<'a>(
    guard: &'a mut Option<Open>,
    what: &str,
) -> Result<(&'a mut Writing, &'a mut Connection)> {
    let Some(open) = guard.as_mut() else {
        return Err(Error::Report(
            "the report database is already closed".into(),
        ));
    };

    let Some(writing) = open.writing.as_mut() else {
        return Err(Error::Report(format!(
            "{what} before the header that opens its run"
        )));
    };

    Ok((writing, &mut open.conn))
}

/// Reads a report out of a SQLite database.
pub(in crate::report) struct DbReader {
    path: PathBuf,
}

impl DbReader {
    /// Refuses anything that is not already a report database, so a typo in
    /// a path cannot read as a report with nothing in it.
    pub(in crate::report) fn open(path: &Path) -> Result<Self> {
        conn::close(conn::open(path, Access::ReadOnly)?)?;

        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl ReportReader for DbReader {
    /// Every record every run wrote, in the order they were written.
    ///
    /// Unlike a line report this may be read more than once, and each read
    /// gets its own connection. It is paged rather than collected: a
    /// database accumulates runs, so the whole stream would be the largest
    /// thing in the process.
    fn records(&self) -> Result<Box<dyn Iterator<Item = Result<Record>> + Send>> {
        Ok(Box::new(Paged {
            conn: conn::open(&self.path, Access::ReadOnly)?,
            after: 0,
            buffer: Vec::new().into_iter(),
            done: false,
        }))
    }

    fn query(&self) -> Option<&dyn ReportQuery> {
        Some(self)
    }
}

impl ReportQuery for DbReader {
    fn resume_enumeration(&self, role: Role, name: &str) -> Result<Option<Resume>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = enumeration::resume(&conn, role.as_str(), name)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn last_complete_enumeration(
        &self,
        role: Role,
        name: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = enumeration::last_complete(&conn, role.as_str(), name)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn outstanding(
        &self,
        source: &str,
        destinations: &[&str],
        after: i64,
        limit: u32,
    ) -> Result<Vec<Work>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = work::outstanding(&conn, source, destinations, after, limit)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn inventory(&self, source: &str, after: i64, limit: u32) -> Result<Vec<Work>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = work::inventory(&conn, source, after, limit)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn outstanding_count(&self, source: &str, destinations: &[&str]) -> Result<Option<u64>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let counted = work::outstanding_count(&conn, source, destinations)?;

        conn::close(conn)?;

        Ok(Some(counted))
    }

    fn inventory_count(&self, source: &str) -> Result<Option<u64>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let counted = work::inventory_count(&conn, source)?;

        conn::close(conn)?;

        Ok(Some(counted))
    }

    fn cached(
        &self,
        source: &str,
        purl: &str,
        file: &str,
    ) -> Result<Option<crate::report::CacheRecord>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = super::cache::recorded(&conn, source, purl, file)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn holds(&self, target: &str, purl: &str) -> Result<bool> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = super::cache::holds(&conn, target, purl)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn held(&self, source: &str, purl: &str) -> Result<Option<Work>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = work::held(&conn, source, purl)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn versions_held(&self, source: &str, package: &str) -> Result<Vec<(String, bool)>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = work::versions(&conn, source, package)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn source_listed(&self, source: &str) -> Result<bool> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = enumeration::source_listed(&conn, source)?;

        conn::close(conn)?;

        Ok(found)
    }

    fn resume_walk(&self, source: &str, spec: &str, targets: &str) -> Result<Option<WalkId>> {
        let conn = conn::open(&self.path, Access::ReadOnly)?;
        let found = frontier::resume(&conn, source, spec, targets)?;

        conn::close(conn)?;

        Ok(found)
    }
}

/// Walks the stream a page at a time, keyed on the last position seen.
///
/// Keyed rather than offset because a run reading a page may be the run
/// writing the next one, and `OFFSET` skips records as rows arrive.
struct Paged {
    conn: Connection,
    after: i64,
    buffer: std::vec::IntoIter<Record>,
    done: bool,
}

impl Iterator for Paged {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(record) = self.buffer.next() {
                return Some(Ok(record));
            }

            if self.done {
                return None;
            }

            match read::page(&self.conn, self.after) {
                Ok((records, reached)) => {
                    // A page that advanced nothing is the end. Checked on
                    // the position rather than on the records, because a
                    // page can legitimately yield none: a killed run leaves
                    // stream positions with no body under them.
                    self.done = reached <= self.after;
                    self.after = reached;
                    self.buffer = records.into_iter();
                }

                Err(err) => {
                    self.done = true;

                    return Some(Err(err));
                }
            }
        }
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> Error {
    Error::Report("the report database lock was poisoned".into())
}
