//! One run, written to a line report and a database at once.
//!
//! The two serve different readers: a line report lets an outside tool
//! follow a run, and a database is this tool's cache and resume state. Every
//! record goes to both, and everything beyond the records comes from the
//! database, which is the only side that keeps any.
//!
//! ```text
//!   write, flush ----------> line + database
//!   state, query, count ---> database
//! ```

use std::sync::Arc;

use crate::core::error::Result;

use super::record::Record;
use super::sink::{ReportQuery, ReportState, ReportWriter};

/// Forwards records to both writers.
pub(super) struct Tee {
    line: Box<dyn ReportWriter>,
    db: Box<dyn ReportWriter>,
}

impl Tee {
    pub(super) fn new(line: Box<dyn ReportWriter>, db: Box<dyn ReportWriter>) -> Self {
        Self { line, db }
    }
}

impl ReportWriter for Tee {
    /// The database first, because it refuses what it cannot attribute and
    /// a line report that ran ahead of it would record what the database
    /// did not.
    fn write(&self, record: &Record) -> Result<()> {
        self.db.write(record)?;
        self.line.write(record)
    }

    fn artifact_count(&self) -> u64 {
        self.db.artifact_count()
    }

    /// Both, even when one fails: a database left open reads as a crashed
    /// run, and a line report left buffered loses its summary.
    fn flush(&self) -> Result<()> {
        let db = self.db.flush();
        let line = self.line.flush();

        db.and(line)
    }

    fn state(&self) -> Option<&dyn ReportState> {
        self.db.state()
    }

    fn query(&self) -> Result<Option<Arc<dyn ReportQuery>>> {
        self.db.query()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Screening;
    use crate::report::{ReportFormat, header};

    #[test]
    fn both_sides_take_each_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let line_path = dir.path().join("run.jsonl");
        let db_path = dir.path().join("run.db");

        let line = std::fs::File::create(&line_path).expect("created");
        let tee = Tee::new(
            Box::new(crate::report::LineWriter::new(line, ReportFormat::Json).expect("line")),
            Box::new(super::super::db::DbWriter::open(&db_path).expect("db")),
        );

        tee.write(&Record::Header(header("find", &Screening::none())))
            .expect("written");

        assert!(tee.state().is_some(), "state comes from the database");
        assert!(tee.query().expect("query").is_some());

        tee.flush().expect("flushed");

        let text = std::fs::read_to_string(&line_path).expect("readable");
        assert!(text.contains("find"), "{text}");

        let conn = rusqlite::Connection::open(&db_path).expect("opens");
        let runs: i64 = conn
            .query_row("SELECT COUNT(*) FROM run", [], |row| row.get(0))
            .expect("counted");

        assert_eq!(runs, 1);
    }
}
