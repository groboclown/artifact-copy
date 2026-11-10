//! Reports, as a stream of typed records.
//!
//! A report is JSON Lines -- one record per line -- rather than one document,
//! because an enumeration can name a million artifacts and neither writing nor
//! reading one may hold it whole.
//!
//! ```text
//!   {"record":"header",   ...}
//!   {"record":"artifact", ...}
//!   {"record":"problem",  ...}
//!   {"record":"artifact", ...}
//!   {"record":"summary",  ...}
//! ```
//!
//! Problems ride in the same stream as they occur, rather than accumulating
//! for the end.  That is what keeps [`crate::core::problem::ProblemSink`]
//! constant-memory by construction instead of by later repair.  The trailing
//! `summary` also means a killed run leaves a readable prefix, which a
//! half-written JSON array would not.
//!
//! ```text
//!   format      which spelling was asked for
//!   logged      a report that also logs what it is told
//!   open        the report options, turned into a writer
//!   record      what a line is
//!   refresh     which database parts a run asks the server for
//!   refreshing  a database with those parts blanked
//!   stream      reading and writing them
//!   tee         a line report and a database at once
//!   text        the human rendering
//! ```
//!
//! `record` and `stream` are apart because the record types are the
//! **published** shape -- someone's tooling parses them -- while the reader
//! and writer are an implementation of it. A change to one is a very
//! different kind of change from a change to the other.
//!
//! This module declares nothing of its own.

mod db;
mod format;
mod logged;
mod open;
mod record;
mod refresh;
mod refreshing;
mod sink;
mod stream;
mod tee;
mod text;

pub use format::{Opening, Rendering, ReportFormat, ReportSpec};
pub(crate) use logged::Logged;
pub use open::{DbSpec, open};
pub use record::{
    AdvisoryRecord, ArtifactRecord, BypassRecord, DestinationOutcome, FileOrigin, FileRecord,
    Header, LicenseRecord, Outcome, ProblemRecord, QuarantineRecord, Record, Summary,
    SuppressionRecord, Verification, header,
};
pub use refresh::{Part, Refresh};
pub use sink::{
    Binding, CacheRecord, Cached, Claim, Claimed, Completion, Download, Enqueued, Enumeration,
    Marked, Observing, ReportQuery, ReportReader, ReportState, ReportWriter, Resume, Role, Sent,
    Side, Stage, Transfer, Upload, WalkId, WalkState, WalkTask, Work, WorkFile,
};
pub use stream::LineWriter;
