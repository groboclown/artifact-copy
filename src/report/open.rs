//! Turning the report options into somewhere to write a run.
//!
//! One place decides what a format means for a file, so a sub-command no
//! longer opens the file itself and no longer has to know that `json`
//! truncates while a database does not. Truncation is a property of the
//! format -- see [`ReportFormat::opening`] -- and this is where that
//! property turns into an open mode.
//!
//! ```text
//!   line only   LineWriter
//!   db only     Refreshing(DbWriter)
//!   both        Tee(LineWriter, Refreshing(DbWriter))
//! ```

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;

use crate::core::error::{Error, Result};

use super::db::DbWriter;
use super::format::{Opening, ReportFormat, ReportSpec};
use super::refresh::Refresh;
use super::refreshing::Refreshing;
use super::sink::ReportWriter;
use super::stream::LineWriter;
use super::tee::Tee;

/// Where a run's own temporary database is kept, under the cache root.
///
/// Parenthesized, which a host's cache folder never is, so no host's cache
/// shares it.
const SCRATCH_PREFIX: &str = "(run-db)";

/// The temporary database's file, inside its directory.
const SCRATCH_FILE: &str = "run.sqlite";

/// Where a report database is, and which of its parts a run refreshes.
#[derive(Debug, Clone)]
pub struct DbSpec {
    path: PathBuf,
    refresh: Refresh,

    /// The directory a temporary database lives in, removed with the
    /// writer that holds the last reference; see [`DbSpec::scratch`].
    scratch: Option<Arc<TempDir>>,
}

impl DbSpec {
    /// A database used as a cache for everything it holds.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            refresh: Refresh::default(),
            scratch: None,
        }
    }

    /// A database for one run alone, so a walk queues on disk rather than
    /// in memory without the user naming a file.
    ///
    /// Kept in a directory of its own under `root`, beside the run's other
    /// caches, because SQLite writes `-wal` and `-shm` files beside the
    /// database; removing the directory removes all three.
    ///
    /// ```text
    ///   {cache root}/(run-db)Xa81Qz/run.sqlite
    ///                              /run.sqlite-wal
    ///                              /run.sqlite-shm
    /// ```
    pub fn scratch(root: &Path) -> Result<Self> {
        let write_error = |source| Error::WriteFile {
            path: root.to_path_buf(),
            source,
        };

        std::fs::create_dir_all(root).map_err(write_error)?;

        let dir = tempfile::Builder::new()
            .prefix(SCRATCH_PREFIX)
            .tempdir_in(root)
            .map_err(write_error)?;

        Ok(Self {
            path: dir.path().join(SCRATCH_FILE),
            refresh: Refresh::default(),
            scratch: Some(Arc::new(dir)),
        })
    }

    /// The same database, asking the server for `refresh` instead.
    pub fn refreshing(mut self, refresh: Refresh) -> Self {
        self.refresh = refresh;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn refresh(&self) -> &Refresh {
        &self.refresh
    }
}

/// Open somewhere to write a run: a line report, a database, or both.
///
/// A `line` with no path is standard output.
pub async fn open(line: Option<&ReportSpec>, db: Option<&DbSpec>) -> Result<Box<dyn ReportWriter>> {
    match (line, db) {
        (Some(line), None) => open_line(line).await,
        (None, Some(db)) => open_db(db).await,
        (Some(line), Some(db)) => Ok(Box::new(Tee::new(
            open_line(line).await?,
            open_db(db).await?,
        ))),

        (None, None) => Err(Error::Config(
            "a run needs somewhere to write: --to-report, --db, or both".to_owned(),
        )),
    }
}

/// Open a line report.
async fn open_line(spec: &ReportSpec) -> Result<Box<dyn ReportWriter>> {
    let format = spec.format();

    let Some(path) = spec.path() else {
        return Ok(Box::new(LineWriter::new(std::io::stdout(), format)?));
    };

    crate::net::ensure_parent(path).await?;

    Ok(Box::new(LineWriter::new(line_file(format, path)?, format)?))
}

/// Open a report database, adding a run unless `all` is refreshed.
async fn open_db(spec: &DbSpec) -> Result<Box<dyn ReportWriter>> {
    let path = spec.path();

    crate::net::ensure_parent(path).await?;

    if spec.refresh().replaces() {
        replace(path)?;
    }

    let writer = DbWriter::open(path)?.keeping(spec.scratch.clone());

    Ok(Box::new(Refreshing::new(
        Box::new(writer),
        spec.refresh().clone(),
    )))
}

/// Remove a report database so the next open starts an empty one.
///
/// **A file that is not a report database is refused rather than removed.**
/// `--refresh=all` says "replace the database", and a user who spelled a path
/// wrong means something they can still open; deleting it to honor the
/// format would be the tool destroying what it was pointed at. An empty
/// file is the one exception, because `touch` is how people reserve a name.
fn replace(path: &Path) -> Result<()> {
    let Ok(found) = std::fs::metadata(path) else {
        return Ok(());
    };

    if found.len() > 0 {
        // Opening read-only proves it carries this tool's schema, and
        // changes nothing if it does not.
        super::db::DbReader::open(path)?;
    }

    std::fs::remove_file(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

/// Open a line report's file the way its format asks.
fn line_file(format: ReportFormat, path: &Path) -> Result<impl Write + Send + use<>> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);

    match format.opening() {
        Opening::Truncate => options.truncate(true),
        Opening::Append => options.append(true),
    };

    options.open(path).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Screening;
    use crate::report::refresh::Part;
    use crate::report::{Record, header};

    fn block<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(future)
    }

    fn wrote(line: Option<&ReportSpec>, db: Option<&DbSpec>, command: &str) {
        let writer = block(open(line, db)).expect("opens");

        writer
            .write(&Record::Header(header(command, &Screening::none())))
            .expect("written");
        writer.flush().expect("flushed");
    }

    fn json(format: &str, path: &Path) -> ReportSpec {
        ReportSpec::parse(&format!("{format},{}", path.display())).expect("parses")
    }

    #[test]
    fn json_replaces_earlier_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.jsonl");

        wrote(Some(&json("json", &path)), None, "inspect");
        wrote(Some(&json("json", &path)), None, "find");

        let text = std::fs::read_to_string(&path).expect("readable");

        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("find"), "{text}");
    }

    /// The point of the append spelling: a second run adds to the first
    /// rather than standing on it.
    #[test]
    fn json_append_keeps_earlier_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.jsonl");

        wrote(Some(&json("json", &path)), None, "inspect");
        wrote(Some(&json("json-append", &path)), None, "find");

        let text = std::fs::read_to_string(&path).expect("readable");

        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("inspect"), "{text}");
        assert!(text.contains("find"), "{text}");
    }

    /// Appended YAML has to stay one valid stream, and the separator is
    /// what makes the join legal.
    #[test]
    fn yaml_append_separates_documents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.yaml");

        wrote(Some(&json("yaml", &path)), None, "inspect");
        wrote(Some(&json("yaml-append", &path)), None, "find");

        let text = std::fs::read_to_string(&path).expect("readable");

        assert_eq!(text.matches("---").count(), 2, "{text}");
    }

    #[test]
    fn nowhere_to_write_refused() {
        let Err(err) = block(open(None, None)) else {
            panic!("a run opened with nowhere to write");
        };

        assert!(err.to_string().contains("--db"), "{err}");
    }

    /// A database accumulates runs, and only `--refresh=all` throws that
    /// away.
    #[test]
    fn db_adds_run_refresh_all_starts_over() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");

        let runs = |expected: i64| {
            let conn = rusqlite::Connection::open(&path).expect("opens");
            let found: i64 = conn
                .query_row("SELECT COUNT(*) FROM run", [], |row| row.get(0))
                .expect("counted");

            assert_eq!(found, expected);
        };

        let cached = DbSpec::new(&path);
        let targeted = DbSpec::new(&path).refreshing(Refresh::new([Part::Target]));
        let replaced = DbSpec::new(&path).refreshing(Refresh::new([Part::All]));

        wrote(None, Some(&cached), "inspect");
        runs(1);

        wrote(None, Some(&targeted), "find");
        runs(2);

        wrote(None, Some(&replaced), "copy");
        runs(1);
    }

    /// `--refresh=all` replaces a database. A user who spelled a path wrong
    /// means a file they can still open, so the tool refuses rather than
    /// deleting it to honor the flag.
    #[test]
    fn db_refresh_all_spares_other_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("notes.txt");

        std::fs::write(&path, b"do not delete me").expect("written");

        let spec = DbSpec::new(&path).refreshing(Refresh::new([Part::All]));
        let opened = block(open(None, Some(&spec)));

        assert!(opened.is_err(), "a text file was replaced");
        assert_eq!(std::fs::read(&path).expect("readable"), b"do not delete me");
    }

    /// Both at once: the line report and the database each hold the run.
    #[test]
    fn line_and_db_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let line = dir.path().join("run.jsonl");
        let db = dir.path().join("run.db");

        wrote(Some(&json("json", &line)), Some(&DbSpec::new(&db)), "find");

        assert!(
            std::fs::read_to_string(&line)
                .expect("readable")
                .contains("find")
        );
        assert!(db.exists());
    }
}
