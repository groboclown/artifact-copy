//! A report that also logs what it is told.
//!
//! The report and the log take the same observations for different readers:
//! the report keeps them for analysis and for later runs, the log tells the
//! person running the tool as they happen. This tee hands every call to the
//! report unchanged and logs a line for it, so neither can miss what the
//! other saw.
//!
//! ```text
//!   ProblemSink --saw--> Logged --write--> inner report (lines or database)
//!   walk -------write--> Logged --log----> core::log::Log
//! ```
//!
//! Levels, by what a line is about:
//!
//! ```text
//!   header, artifact outcome             info
//!   summary                              warn
//!   problem: ignore                      info
//!   problem: warn, stop-spider           warn
//!   problem: skip-artifact, abort        error
//!   state within an artifact             debug  (claims, downloads, holdings)
//! ```
//!
//! Lines render from each record's own fields and [`Message::render`], not
//! from the text report format: the two serve different readers, and
//! sharing the code would tie a change to one to the other.
//!
//! [`Message::render`]: crate::core::message::Message::render

use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::error::Result;
use crate::core::log::{Level, Log};
use crate::core::problem::{Action, Problem, Watch};

use super::record::{ArtifactRecord, Header, Outcome, ProblemRecord, Record, Summary};
use super::sink::{
    Binding, Claim, Claimed, Completion, Download, Enumeration, ReportQuery, ReportState,
    ReportWriter, Sent, Transfer, Upload,
};

/// Forwards to a report, and logs each call.
pub struct Logged {
    inner: Box<dyn ReportWriter>,
    log: Log,

    /// Problems seen with action `ignore`, which log below the default
    /// level. The summary names them apart, so its count matches the lines
    /// a reader saw: `12 problems (10 ignored)`.
    ignored: AtomicU64,
}

impl Logged {
    pub fn new(inner: Box<dyn ReportWriter>, log: Log) -> Self {
        Self {
            inner,
            log,
            ignored: AtomicU64::new(0),
        }
    }

    /// The inner report's state.
    ///
    /// Only reachable through [`ReportWriter::state`], which exposes this
    /// tee as state exactly when the inner report keeps some.
    fn inner_state(&self) -> &dyn ReportState {
        self.inner
            .state()
            .expect("state is exposed only when the inner report keeps it")
    }
}

impl ReportWriter for Logged {
    fn write(&self, record: &Record) -> Result<()> {
        let (level, line) = describe(record, self.ignored.load(Ordering::Relaxed));
        self.log.at(level, line);

        self.inner.write(record)
    }

    fn artifact_count(&self) -> u64 {
        self.inner.artifact_count()
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn state(&self) -> Option<&dyn ReportState> {
        self.inner.state().map(|_| self as &dyn ReportState)
    }

    fn query(&self) -> Result<Option<std::sync::Arc<dyn ReportQuery>>> {
        self.inner.query()
    }
}

impl ReportState for Logged {
    /// Not logged: one line per queued dependency would drown the log.
    fn walks(&self) -> Option<&dyn crate::report::WalkState> {
        self.inner_state().walks()
    }

    fn bind(&self, binding: &Binding<'_>) -> Result<()> {
        self.log.debug(format_args!(
            "using {} repository {:?}",
            binding.role.as_str(),
            binding.name
        ));

        self.inner_state().bind(binding)
    }

    fn checkpoint(&self, scan: &Enumeration<'_>) -> Result<()> {
        let end = match scan.reached_end {
            true => ", reached the end",
            false => "",
        };

        self.log.debug(format_args!(
            "scan of {:?}: {} pages, {} found{end}",
            scan.repository, scan.pages, scan.found
        ));

        self.inner_state().checkpoint(scan)
    }

    fn claim(&self, claim: &Claim<'_>) -> Result<Option<Claimed>> {
        let claimed = self.inner_state().claim(claim)?;

        match claimed {
            Some(_) => self.log.debug(format_args!(
                "claimed {} for {:?}",
                claim.purl, claim.destination
            )),

            None => self.log.debug(format_args!(
                "{} already done at {:?}",
                claim.purl, claim.destination
            )),
        }

        Ok(claimed)
    }

    fn close(&self, claimed: Claimed, outcome: Transfer) -> Result<()> {
        self.log
            .debug(format_args!("claim closed: {}", outcome.as_str()));

        self.inner_state().close(claimed, outcome)
    }

    fn present(&self, target: &str, purl: &str) -> Result<()> {
        self.log.debug(format_args!("{target:?} holds {purl}"));

        self.inner_state().present(target, purl)
    }

    fn downloaded(&self, at: &Download<'_>) -> Result<()> {
        match at.failure {
            Some((side, stage)) => self.log.debug(format_args!(
                "fetching {} of {} from {:?} failed: {} {}",
                at.file,
                at.purl,
                at.source,
                side.as_str(),
                stage.as_str()
            )),

            None => self.log.debug(format_args!(
                "fetched {} of {} from {:?}",
                at.file, at.purl, at.source
            )),
        }

        self.inner_state().downloaded(at)
    }

    fn uploaded(&self, at: &Upload<'_>) -> Result<()> {
        match at.sent {
            Sent::Failed(Some((side, stage))) => self.log.debug(format_args!(
                "sending {} of {} to {:?} failed: {} {}",
                at.file,
                at.purl,
                at.destination,
                side.as_str(),
                stage.as_str()
            )),

            sent => self.log.debug(format_args!(
                "sent {} of {} to {:?}: {}",
                at.file,
                at.purl,
                at.destination,
                sent.as_str()
            )),
        }

        self.inner_state().uploaded(at)
    }

    fn complete(&self, how: Completion) -> Result<()> {
        self.log.debug(format_args!("run {}", how.as_str()));

        self.inner_state().complete(how)
    }
}

/// Problems reach the report through the sink, not through the walk.
///
/// The walk only ever hands over artifacts, and most problems are not about
/// one: a page that would not parse, a depth limit, a source that could not
/// be reached. Watching the sink is what puts those in the report at all,
/// and it is also the only way a problem raised **after** an artifact's
/// record was written -- everything the dependency read finds -- reaches it,
/// since that record is long gone by then.
///
/// A write failure is logged rather than propagated. `ProblemSink::record`
/// answers with the action its caller must take, and that answer must not
/// depend on whether a report could be written; a report file that cannot
/// be written surfaces on the artifact records, which do propagate.
impl Watch for Logged {
    fn saw(&self, problem: &Problem) {
        let record = ProblemRecord::from(problem);

        if record.action == Action::Ignore {
            self.ignored.fetch_add(1, Ordering::Relaxed);
        }

        if let Err(err) = self.write(&Record::Problem(record)) {
            self.log.error(format_args!(
                "could not write a problem to the report: {err}"
            ));
        }
    }
}

/// The level and line a record logs as, with `ignored` problems seen so far
/// for the summary.
fn describe(record: &Record, ignored: u64) -> (Level, String) {
    match record {
        Record::Header(header) => (Level::Info, header_line(header)),
        Record::Artifact(artifact) => (Level::Info, artifact_line(artifact)),
        Record::Problem(problem) => (problem_level(problem.action), problem_line(problem)),
        Record::Summary(summary) => (Level::Warn, summary_line(summary, ignored)),
    }
}

fn header_line(header: &Header) -> String {
    format!(
        "{} started (artifact-copy {})",
        header.command, header.tool_version
    )
}

fn artifact_line(artifact: &ArtifactRecord) -> String {
    let purl = versioned(artifact);

    let Some(outcome) = &artifact.outcome else {
        return found_line(&purl, artifact.files.len());
    };

    // One line still, naming each target when a copy had several.
    match artifact.outcomes.as_slice() {
        [] => format!("{purl}: {}", taken(outcome)),
        several => {
            let each: Vec<String> = several
                .iter()
                .map(|at| format!("{}: {}", at.destination, taken(&at.outcome)))
                .collect();

            format!("{purl}: {} ({})", taken(outcome), each.join("; "))
        }
    }
}

/// What became of an artifact, as a log line says it.
fn taken(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Copied { .. } => "copied".to_owned(),
        Outcome::AlreadyPresent => "already present".to_owned(),
        Outcome::Refused { why } => format!("refused: {}", why.message),
        Outcome::Unresolved { why } => format!("unresolved: {}", why.message),
        Outcome::Failed { why } => format!("failed: {}", why.message),
    }
}

/// The record's purl with its version, so two versions of one package log
/// as two different lines.
///
/// A record keeps the version apart from the purl, and the version goes
/// before any qualifiers, so it cannot simply be appended.
fn versioned(artifact: &ArtifactRecord) -> String {
    let Some(version) = &artifact.version else {
        return artifact.purl.clone();
    };

    match crate::model::ArtifactId::parse(&artifact.purl) {
        Ok(parsed) => parsed.id.purl_at(version),
        Err(_) => format!("{}@{version}", artifact.purl),
    }
}

/// A record with no outcome, with how many files it carries.
///
/// The count is what tells apart the repeats an enumeration produces when a
/// directory's files straddle pages: each page's record carries that page's
/// files, e.g. `pkg:generic/a/b: 2 files` then `pkg:generic/a/b: 5 files`.
fn found_line(purl: &str, files: usize) -> String {
    match files {
        0 => purl.to_owned(),
        1 => format!("{purl}: 1 file"),
        _ => format!("{purl}: {files} files"),
    }
}

/// `ignore` is a policy saying the problem does not matter, so it shows only
/// with `--verbose`; what stops an artifact or the run is an error.
fn problem_level(action: Action) -> Level {
    match action {
        Action::Ignore => Level::Info,
        Action::Warn | Action::StopSpider => Level::Warn,
        Action::SkipArtifact | Action::Abort => Level::Error,
    }
}

fn problem_line(problem: &ProblemRecord) -> String {
    format!("{} ({}, {})", problem.message, problem.code, problem.action)
}

/// `finished: 3 artifacts, 12 problems (10 ignored), ...`; the split is left
/// out when nothing was ignored.
fn summary_line(summary: &Summary, ignored: u64) -> String {
    let problems: u64 = summary.counts.values().sum();
    let quarantined: u64 = summary.quarantined.values().sum();

    let ignored = match ignored {
        0 => String::new(),
        _ => format!(" ({ignored} ignored)"),
    };

    format!(
        "finished: {} artifacts, {problems} problems{ignored}, {quarantined} quarantined, \
         worst action {}",
        summary.artifacts, summary.worst_action
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::core::ctx::Ctx;
    use crate::core::log::Recorder;
    use crate::core::message::Message;
    use crate::core::problem::{Code, ProblemSink};
    use crate::model::Cause;
    use crate::report::{LineWriter, ReportFormat};

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("not poisoned").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("not poisoned").clone()).expect("utf-8")
        }
    }

    fn logged() -> (Shared, Arc<Recorder>, Arc<Logged>) {
        let out = Shared::default();
        let writer = LineWriter::new(out.clone(), ReportFormat::Json).expect("writer");
        let (log, recorder) = Log::recording();

        (out, recorder, Arc::new(Logged::new(Box::new(writer), log)))
    }

    fn watched(report: Arc<Logged>) -> Ctx {
        let sink = ProblemSink::new();
        sink.watched_by(report);

        Ctx::new(
            Cause::Requested { arg: "tuna".into() },
            sink,
            Arc::new(crate::core::progress::NullSink),
        )
    }

    #[test]
    fn problem_line_written_by_watched_sink() {
        let (out, _, report) = logged();
        let ctx = watched(report);

        ctx.report(Code::SignatureMissing, Message::new("unsigned"));

        let written = out.text();

        assert!(written.contains(r#""record":"problem""#), "{written}");
        assert!(
            written.contains(r#""code":"signature-missing""#),
            "{written}"
        );

        // The provenance is what makes a problem line worth more than the
        // summary's count: it says which request led here.
        assert!(written.contains("tuna"), "{written}");
    }

    /// The gap this exists to close.
    ///
    /// An artifact's record is written when the walk visits it, which is
    /// **before** its dependencies are read. Anything that read finds is
    /// therefore too late for the record, and before problem lines it
    /// reached the report nowhere at all.
    #[test]
    fn problem_late_still_reaches_report() {
        let (out, _, report) = logged();
        let ctx = watched(report.clone());

        // The order a walk produces: the artifact, then what reading its
        // dependencies turned up.
        report
            .write(&Record::Artifact(Box::new(ArtifactRecord::found(
                &crate::repo::enumerate::Found::new(crate::model::ArtifactId::new(
                    crate::model::EcosystemId::npm(),
                    None,
                    "tuna",
                )),
                Vec::new(),
            ))))
            .expect("written");

        ctx.report(Code::DependencyUnresolved, Message::new("no such version"));

        let written = out.text();
        let lines: Vec<&str> = written.lines().collect();

        let [artifact, problem] = lines.as_slice() else {
            panic!("expected two lines, got {lines:?}");
        };

        assert!(artifact.contains(r#""record":"artifact""#), "{artifact}");
        assert!(
            problem.contains(r#""code":"dependency-unresolved""#),
            "{problem}"
        );
    }

    /// The report is a side effect of recording, never a condition of it.
    /// A run's actions must not depend on whether anyone was watching.
    #[test]
    fn problem_action_kept_when_report_fails() {
        struct Broken;

        impl Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("no room"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let writer = LineWriter::new(Broken, ReportFormat::Json).expect("writer");
        let (log, recorder) = Log::recording();
        let ctx = watched(Arc::new(Logged::new(Box::new(writer), log)));

        assert_eq!(
            ctx.report(Code::ChecksumMismatch, Message::new("x")),
            Action::Abort
        );

        let failed = recorder
            .lines()
            .into_iter()
            .any(|(level, line)| level == Level::Error && line.contains("could not write"));

        assert!(failed, "{:?}", recorder.lines());
    }

    #[test]
    fn problem_logs_at_action_level() {
        let (_, recorder, report) = logged();
        let ctx = watched(report);

        ctx.report(Code::ChecksumMismatch, Message::new("x").text("bad digest"));

        let lines = recorder.lines();
        let (level, line) = lines.last().expect("logged");

        assert_eq!(*level, Level::Error);
        assert!(line.contains("bad digest"), "{line}");
        assert!(line.contains("checksum-mismatch"), "{line}");
    }

    #[test]
    fn problem_levels_follow_action() {
        let cases = [
            (Action::Ignore, Level::Info),
            (Action::Warn, Level::Warn),
            (Action::StopSpider, Level::Warn),
            (Action::SkipArtifact, Level::Error),
            (Action::Abort, Level::Error),
        ];

        for (action, level) in cases {
            assert_eq!(problem_level(action), level, "{action}");
        }
    }

    fn found(purl: &str, version: Option<&str>, files: &[&str]) -> ArtifactRecord {
        let id = crate::model::ArtifactId::parse(purl).expect("parses").id;

        let mut found = crate::repo::enumerate::Found::new(id);
        found.files = files
            .iter()
            .map(|name| crate::repo::enumerate::Listed {
                name: (*name).to_owned(),
                url: format!("h://repo.test/{name}"),
                size: None,
                digests: Vec::new(),
            })
            .collect();

        let mut record = ArtifactRecord::found(&found, Vec::new());
        record.version = version.map(str::to_owned);

        record
    }

    /// Two versions of one package are two lines, not one line twice.
    #[test]
    fn found_line_names_version() {
        let one = artifact_line(&found("pkg:npm/tuna", Some("1.0.0"), &[]));
        let two = artifact_line(&found("pkg:npm/tuna", Some("1.2.0"), &[]));

        assert_eq!(one, "pkg:npm/tuna@1.0.0");
        assert_eq!(two, "pkg:npm/tuna@1.2.0");
    }

    /// The version goes before the qualifiers, not after them.
    #[test]
    fn found_line_version_precedes_qualifiers() {
        let record = found("pkg:maven/g/a?type=pom", Some("1.0"), &[]);

        assert_eq!(artifact_line(&record), "pkg:maven/g/a@1.0?type=pom");
    }

    /// A directory straddling pages repeats, and the file count tells the
    /// repeats apart.
    #[test]
    fn found_line_counts_files() {
        let one = artifact_line(&found("pkg:npm/tuna", Some("1.0.0"), &["a.tgz"]));
        let two = artifact_line(&found("pkg:npm/tuna", Some("1.0.0"), &["a.tgz", "b.tgz"]));

        assert_eq!(one, "pkg:npm/tuna@1.0.0: 1 file");
        assert_eq!(two, "pkg:npm/tuna@1.0.0: 2 files");
    }

    #[test]
    fn summary_logs_at_warn() {
        let (out, recorder, report) = logged();

        report
            .write(&Record::Summary(Summary {
                artifacts: 3,
                counts: Default::default(),
                quarantined: Default::default(),
                worst_action: Action::Ignore,
                unmatched_suppressions: Vec::new(),
            }))
            .expect("written");

        let (level, line) = recorder.lines().pop().expect("logged");

        assert_eq!(level, Level::Warn);
        assert!(line.contains("3 artifacts"), "{line}");
        assert!(out.text().contains(r#""record":"summary""#));
    }

    /// Ignored problems log below the default level, so the summary names
    /// them apart; with none, it says nothing of them.
    #[test]
    fn summary_names_ignored_apart() {
        let summary = Summary {
            artifacts: 3,
            counts: [(Code::FileOmitted, 10), (Code::LicenseUnknown, 2)].into(),
            quarantined: Default::default(),
            worst_action: Action::Warn,
            unmatched_suppressions: Vec::new(),
        };

        assert!(summary_line(&summary, 10).contains("12 problems (10 ignored),"));
        assert!(summary_line(&summary, 0).contains("12 problems,"));
    }

    /// A line report keeps no state, and the tee must not pretend it does.
    #[test]
    fn state_none_for_line_report() {
        let (_, _, report) = logged();

        assert!(report.state().is_none());
    }

    /// A database keeps state; the tee forwards it and logs each call.
    #[tokio::test]
    async fn state_forwarded_and_logged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("report.sqlite");
        let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&path)))
            .await
            .expect("opens");
        let (log, recorder) = Log::recording();
        let report = Logged::new(writer, log);

        report
            .write(&Record::Header(crate::report::header(
                "inspect",
                &crate::advisory::Screening::none(),
            )))
            .expect("header");

        report
            .state()
            .expect("state")
            .bind(&Binding::new(crate::report::Role::Source, "upstream").observing())
            .expect("bound");

        let lines = recorder.lines();

        assert_eq!(lines[0].0, Level::Info);
        assert!(lines[0].1.contains("inspect started"), "{lines:?}");
        assert_eq!(lines[1].0, Level::Debug);
        assert!(lines[1].1.contains("upstream"), "{lines:?}");
    }
}
