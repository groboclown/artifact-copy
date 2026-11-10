//! What a report is written to, and read back from.
//!
//! Traits rather than structures, because a report is no longer only a
//! stream of lines. A line format appends and is read front to back; a
//! database accumulates an inventory over many runs and is queried. Both
//! carry the same [`Record`] values, so the record types stay the one
//! published shape and only the store behind them differs.
//!
//! Every method takes `&self`. A walk is concurrent, so whatever locking a
//! store needs belongs inside it: a line writer serializes on one mutex
//! because interleaved lines would not parse, and a database has its own
//! transaction rules. A caller should not have to know which.

use chrono::{DateTime, Utc};

use crate::core::error::Result;

use super::record::{Record, Verification};

/// What a run uses a repository for.
///
/// Part of a repository's identity in a report, not a passing detail: one
/// configured name may be both a source and a target, and the two must
/// never merge into one row. A source's inventory and a target's are
/// different claims about the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Source,
    Target,
    Enumerator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Source => "source",
            Role::Target => "target",
            Role::Enumerator => "enumerator",
        }
    }
}

/// Whether a run's artifact records describe this repository.
///
/// A run binds several repositories and observes at most one of them. A
/// `copy` binds a source and a target and describes the source; a
/// `find` pointed at a mirror binds an enumerator and describes **the
/// target that mirror is**, which the roles alone cannot say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observing {
    /// The repository this run's artifact records are about.
    Contents,

    /// A repository the run uses for something else: where it publishes,
    /// or the enumerator it walks to learn about another.
    Endpoint,
}

/// One repository a run uses.
///
/// Declared when the run opens rather than when the repository is first
/// touched, so that anything keyed on a repository can be built from a key
/// that already exists instead of creating one mid-walk.
#[derive(Debug, Clone)]
pub struct Binding<'a> {
    pub role: Role,
    pub name: &'a str,

    /// Recorded as last seen, and never checked. A user may repoint a
    /// configuration over time without rebuilding a report database; see
    /// `docs/contributors/report-as-database.md`.
    pub host: Option<&'a str>,
    pub base_url: Option<&'a str>,
    pub ecosystem: Option<&'a str>,

    /// Lower wins. Only meaningful for a source, where it decides which of
    /// several sources a copy takes an artifact from first.
    pub priority: i64,

    /// Whether this run's artifact records describe this repository.
    pub observing: Observing,
}

impl<'a> Binding<'a> {
    /// A binding with only what every caller knows.
    pub fn new(role: Role, name: &'a str) -> Self {
        Self {
            role,
            name,
            host: None,
            base_url: None,
            ecosystem: None,
            priority: 0,

            // An endpoint unless a caller says otherwise, so a binding
            // added without thought cannot silently claim that the run's
            // records are about it.
            observing: Observing::Endpoint,
        }
    }

    /// The repository this run's records are about.
    pub fn observing(mut self) -> Self {
        self.observing = Observing::Contents;
        self
    }
}

/// Where a catalog walk has got to.
///
/// Checkpointed per page, because a page is one request and that is the
/// granularity at which resuming is meaningful.
#[derive(Debug, Clone)]
pub struct Enumeration<'a> {
    /// The enumerator binding this walk is of.
    pub repository: &'a str,

    /// The enumerator kind, so a resumed walk can refuse a cursor issued by a
    /// different implementation.
    pub kind: &'a str,

    /// How far the enumerator's listing reaches, as it declared.
    pub depth: &'a str,

    /// What the walk was asked for, when it was asked for less than
    /// everything. A sampled walk is not an inventory however far it got.
    pub scope: Option<&'a str>,

    /// Where to resume. Opaque, and meaningful only to the enumerator that
    /// issued it.
    pub cursor: Option<&'a str>,

    pub pages: u64,
    pub found: u64,

    /// Whether the walk reached the end of the catalog.
    ///
    /// **Only this dates an inventory.** A walk that stopped at a sample
    /// size, or that was killed, saw part of a repository, and treating it
    /// as complete would let a later run skip what it never looked at.
    pub reached_end: bool,
}

/// Where an interrupted walk stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    pub kind: String,
    pub cursor: Option<String>,
    pub pages: u64,
    pub found: u64,

    /// What the walk was asked for, when it was less than everything:
    /// `sample=N`, or `since=DATE`.
    pub scope: Option<String>,
}

/// How a run ended.
///
/// Distinct from the summary's worst action: a run can stop on an error no
/// problem recorded, and one a person interrupted made no judgement at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// The command ran to its end.
    Finished,

    /// The command returned an error.
    Failed,

    /// A person or an `abort` problem stopped it.
    Cancelled,
}

impl Completion {
    pub fn as_str(self) -> &'static str {
        match self {
            Completion::Finished => "finished",
            Completion::Failed => "failed",
            Completion::Cancelled => "cancelled",
        }
    }
}

/// What became of one artifact at one destination.
///
/// The states a resumed copy reads. Five of the six are terminal: only
/// `Failed` is worth another attempt, because nothing decided against the
/// artifact and re-running may well take it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transfer {
    /// Fetched, checked, and written to the destination.
    Copied,

    /// The destination already held this exact version.
    AlreadyPresent,

    /// A rule decided against it. A policy decision, not a failure.
    Refused,

    /// The request matched no artifact, so there was nothing to copy.
    Unresolved,

    /// Permitted, and the transfer itself did not succeed.
    Failed,

    /// Set by a person, not by a run.
    Skipped,
}

impl Transfer {
    pub fn as_str(self) -> &'static str {
        match self {
            Transfer::Copied => "copied",
            Transfer::AlreadyPresent => "already-present",
            Transfer::Refused => "refused",
            Transfer::Unresolved => "unresolved",
            Transfer::Failed => "failed",
            Transfer::Skipped => "skipped",
        }
    }
}

/// Which end of a transfer a failure belongs to.
///
/// Not readable from an error alone: `Error::Transport` names a URL without
/// saying whose, and a write that fails while fetching *from* a source is
/// the local disk rather than the source. The caller knows which phase it
/// was in; the error knows what kind of failure it was; only the two
/// together answer this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Source,
    Target,

    /// This machine: its disk, its permissions, its cache.
    Local,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Source => "source",
            Side::Target => "target",
            Side::Local => "local",
        }
    }
}

/// How far a transfer got before it failed.
///
/// The second axis, and separate from [`Side`] because they answer
/// different questions: a target that ran out of disk and a source that
/// would not read differ by side, while a connection refused and a body
/// that would not verify differ by stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No connection was made.
    Connect,

    /// Connected, then the link failed part way through a body.
    Stream,

    /// Connected, and the request itself was refused or answered badly.
    Request,

    /// Reading.
    Read,

    /// Writing.
    Write,

    /// The bytes arrived and were not what was claimed.
    Verify,

    /// The target refused what it was given.
    Publish,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Connect => "connect",
            Stage::Stream => "stream",
            Stage::Request => "request",
            Stage::Read => "read",
            Stage::Write => "write",
            Stage::Verify => "verify",
            Stage::Publish => "publish",
        }
    }
}

/// Where a payload's bytes ended up.
#[derive(Debug, Clone)]
pub struct Cached<'a> {
    /// The cache folder it lives in. Two sources on one repository share a
    /// folder, which is why this and not the source.
    pub host: &'a str,

    /// The configured spelling, kept as written, so that moving or
    /// rebasing the cache directory is detectable rather than silent.
    pub cache_dir: &'a str,

    pub relative_path: &'a str,
    pub size: Option<u64>,
    pub verification: Verification,

    /// When the bytes were fetched and last used, in milliseconds since the
    /// Unix epoch; `None` where the cache recorded nothing, which the
    /// writer reads as now.
    pub fetched_ms: Option<i64>,
    pub used_ms: Option<i64>,

    /// Past these the cache would evict the file; `None` is forever.
    pub retain_until_ms: Option<i64>,
    pub fresh_until_ms: Option<i64>,
}

/// What the report says about a payload's cached bytes.
///
/// Owned rather than borrowed, because it crosses from a query into a
/// caller that keeps it for the length of an upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRecord {
    pub host: String,

    /// The cache directory as it was configured **when the bytes were
    /// fetched**. A run whose `cache-dir` has moved since compares this to
    /// its own and learns that the recorded path means nothing to it.
    pub cache_dir: String,

    pub relative_path: String,
    pub size: Option<u64>,
    pub verification: Verification,
}

/// One payload a run fetched, or tried to.
#[derive(Debug, Clone)]
pub struct Download<'a> {
    /// The repository that served it.
    pub source: &'a str,

    /// The exact purl of the artifact it belongs to.
    pub purl: &'a str,

    /// The file's name within that artifact.
    pub file: &'a str,

    pub url: &'a str,

    /// Where the bytes are, when they arrived.
    pub cached: Option<Cached<'a>>,

    /// Which end failed and how far it got, when it did.
    ///
    /// Both halves, because either alone answers half a question: a target
    /// that ran out of disk and a source that would not read differ by
    /// side, a connection refused and a body that would not verify differ
    /// by stage.
    pub failure: Option<(Side, Stage)>,
}

/// What became of one file sent to a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Uploaded,

    /// The target already held these bytes; nothing was written.
    AlreadyPresent,

    /// The target declined to send it, by its own rule.
    Skipped,

    /// Which end failed and how far it got, when the failure said.
    Failed(Option<(Side, Stage)>),
}

impl Sent {
    /// The `file_state` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Sent::Uploaded => "uploaded",
            Sent::AlreadyPresent => "already-present",
            Sent::Skipped => "skipped",
            Sent::Failed(..) => "failed",
        }
    }
}

/// One file a run sent to a target, or tried to.
#[derive(Debug, Clone)]
pub struct Upload<'a> {
    /// The repository the file was read from, whose inventory row it is.
    pub source: &'a str,

    /// The configured target it was sent to.
    pub destination: &'a str,

    /// The exact purl of the artifact it belongs to.
    pub purl: &'a str,

    /// The file's name within that artifact.
    pub file: &'a str,

    /// Where the source serves it.
    pub url: &'a str,

    pub sent: Sent,

    /// The artifact's claim, when the run took one, so the file's attempt
    /// is filed under the artifact's.
    pub claimed: Option<Claimed>,
}

/// Work a run is about to do on one artifact.
#[derive(Debug, Clone)]
pub struct Claim<'a> {
    /// The exact purl, version included.
    pub purl: &'a str,

    /// The source this attempt reads from, when one is known. An attribute
    /// of the attempt rather than part of its key: an artifact that reached
    /// a destination must stop a *different* source copying it again.
    pub source: Option<&'a str>,

    /// The configured target this is being copied into.
    pub destination: &'a str,
}

/// A handle to claimed work, handed back to close it.
///
/// Opaque: what is inside belongs to the store that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claimed {
    pub(crate) transfer: i64,
    pub(crate) attempt: i64,
}

/// One artifact a copy still has to move.
///
/// Everything needed to fetch and publish it, taken from the inventory
/// rather than from the source again. That is what lets a resumed
/// migration work through a catalog without re-resolving every coordinate
/// it already looked at.
#[derive(Debug, Clone)]
pub struct Work {
    /// Where this sits in the outstanding list. Passed back as `after` to
    /// get the next page, because a run reading a page is usually the run
    /// writing the next one and an offset would skip work.
    pub key: i64,

    /// The exact purl, version included.
    pub purl: String,

    /// Always present: a name-only inventory row is not copyable work, and
    /// the query leaves it out.
    pub version: Option<String>,

    /// Whether the version is a pre-release, as the run that recorded it
    /// classified it.
    pub pre_release: bool,

    pub declared_license: Option<String>,
    pub published: Option<DateTime<Utc>>,

    /// The run that last recorded this artifact at the source.
    pub run: Option<i64>,

    pub files: Vec<WorkFile>,
}

/// One file of an outstanding artifact.
#[derive(Debug, Clone)]
pub struct WorkFile {
    pub name: String,
    pub url: String,
    pub size: Option<u64>,

    /// Every digest recorded for this file, by an artifact enumeration or a
    /// resolution. A file that arrives without one is copied unverified
    /// rather than not at all, which is the same trade a live source gets.
    pub digests: Vec<crate::model::Digest>,

    /// A core-metadata document a resolution recorded beside the file, with
    /// its digests. As `FileRef.core_metadata`.
    pub core_metadata: Option<Vec<crate::model::Digest>>,

    /// The signatures a resolution recorded for the file.
    pub signatures: Vec<crate::model::SigRef>,

    /// Whether an artifact enumeration listed this file.
    pub listed: bool,

    /// Whether a resolution named this file.
    pub resolved: bool,
}

/// The half of a report that a stream of records cannot express.
///
/// A [`Record`] says what a run observed; this says what the run was
/// *doing* -- which repositories it bound, and later which work it claimed
/// and what reached a target. A line format answers [`ReportWriter::state`]
/// with `None`, so a command that needs this fails once, clearly, instead
/// of part way through a walk.
pub trait ReportState: Send + Sync {
    /// Record a repository this run uses.
    ///
    /// Calling it twice for one role and name is not an error: a repository
    /// is identity, and a run rebinding the same one is the ordinary case
    /// of a database that has seen it before.
    fn bind(&self, binding: &Binding<'_>) -> Result<()>;

    /// Record where a catalog walk has got to.
    ///
    /// Without this, resuming an interrupted walk of a large repository
    /// means paging from the beginning: a Nexus page takes about two
    /// seconds, so a million-artifact catalog costs hours before the walk
    /// reaches new ground. See `docs/contributors/write-path.md`.
    fn checkpoint(&self, scan: &Enumeration<'_>) -> Result<()>;

    /// Claim one artifact for copying into a destination.
    ///
    /// `None` means there is nothing to do: it already reached a terminal
    /// state at that destination, whichever source took it there. **That is
    /// what makes a copy resumable**, and what makes a lower-priority
    /// source skip what a higher-priority one already delivered.
    ///
    /// The claim is committed before any network work, so a killed run
    /// leaves an `in-progress` row rather than a lie in either direction.
    fn claim(&self, claim: &Claim<'_>) -> Result<Option<Claimed>>;

    /// Close a claim with what became of it.
    ///
    /// Committed after the network work, in one transaction with the
    /// summary row, so a resumed run never sees an attempt and a summary
    /// that disagree.
    fn close(&self, claimed: Claimed, outcome: Transfer) -> Result<()>;

    /// Record that a target holds an artifact.
    ///
    /// Written whenever a run learns it, however it learned it. A copy that
    /// asks a target a million times and writes none of the answers down
    /// asks again next time; writing them down turns the second migration
    /// into a query.
    ///
    /// Only what a target **does** hold. An inventory records contents, and
    /// "not there when we looked" is a fact about a moment rather than
    /// about the repository.
    fn present(&self, target: &str, purl: &str) -> Result<()>;

    /// Record a payload the run fetched, or tried to.
    ///
    /// Two things at once, because they are one event: where the bytes now
    /// live, so a later run can reuse them instead of fetching again, and
    /// what became of the attempt, so a person reading a stalled migration
    /// can tell a flaky source from a full disk without reading prose.
    fn downloaded(&self, at: &Download<'_>) -> Result<()>;

    /// Record a file the run sent to a target, or tried to.
    ///
    /// One row per file rather than per artifact, so a half-published
    /// artifact says which of its files the target already has.
    fn uploaded(&self, at: &Upload<'_>) -> Result<()>;

    /// Say how the run ended, before the flush that closes it.
    ///
    /// A run flushed without this reads as finished.
    fn complete(&self, how: Completion) -> Result<()>;

    /// Where a dependency walk keeps its frontier, when this store keeps one.
    ///
    /// `None` by default: a walk then queues in memory, bounded, and cannot
    /// resume.
    fn walks(&self) -> Option<&dyn WalkState> {
        None
    }
}

/// One dependency walk a report database keeps.
///
/// Opaque, as [`Claimed`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkId(pub(crate) i64);

/// A queued spider task, as text the walk wrote and reads back unread.
///
/// The report's vocabulary rather than the spider's: the store neither
/// parses a purl nor knows what a provenance chain is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkTask {
    /// What makes two tasks the same work; a second push of it is refused.
    pub key: String,
    pub purl: String,
    pub spec: String,
    pub provenance: String,
    pub depth: u32,
}

/// What became of a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    Added,

    /// The walk queued this key before, whether or not it has run.
    Duplicate,
}

/// What became of a claim on a resolved coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marked {
    /// This task is the first, and owns the work.
    First,
    Already,
}

/// A dependency walk's frontier and claims, kept in the report.
///
/// Kept so a killed walk resumes: a task popped and never finished is
/// handed out again, and the claim it made is withdrawn so it can make it
/// again. See `docs/contributors/report-as-database.md`.
pub trait WalkState: Send + Sync {
    /// Start a walk of `source` under `spec` for `targets`, or adopt
    /// `resume` into this run.
    ///
    /// `targets` are a copy's targets, sorted and comma-joined, and empty
    /// for a walk that copies nothing.
    fn start(
        &self,
        source: &str,
        spec: &str,
        targets: &str,
        resume: Option<WalkId>,
    ) -> Result<WalkId>;

    fn push(&self, walk: WalkId, task: &WalkTask) -> Result<Enqueued>;

    /// The shallowest pending task, marked in progress, with its id.
    fn pop(&self, walk: WalkId) -> Result<Option<(i64, WalkTask)>>;

    fn done(&self, walk: WalkId, task: i64) -> Result<()>;

    fn pending(&self, walk: WalkId) -> Result<u64>;

    /// Claim a resolved coordinate for `task`.
    fn mark(&self, walk: WalkId, purl: &str, task: i64) -> Result<Marked>;

    fn marked(&self, walk: WalkId, purl: &str) -> Result<bool>;

    fn marks(&self, walk: WalkId) -> Result<u64>;
}

/// What a report can be asked, beyond replaying its records.
///
/// A line report answers [`ReportReader::query`] with `None`: a stream can
/// be read front to back and nothing else. Everything here needs an index.
pub trait ReportQuery: Send + Sync {
    /// Where an interrupted walk of this repository stopped, if one did.
    ///
    /// `None` when every walk on record finished, which is the ordinary
    /// case and means a new walk starts from the beginning.
    fn resume_enumeration(&self, role: Role, name: &str) -> Result<Option<Resume>>;

    /// When the last walk that reached the end of this catalog *started*.
    ///
    /// The start rather than the finish, and the difference is the point: a
    /// push into the repository during the walk may have been missed, so
    /// only from the start time is "everything since" an honest claim.
    fn last_complete_enumeration(&self, role: Role, name: &str) -> Result<Option<DateTime<Utc>>>;

    /// Artifacts at `source` that have not reached every one of
    /// `destinations`.
    ///
    /// Paged on `after`, which is the `key` of the last [`Work`] a caller
    /// took; zero starts at the beginning. An empty page is the end.
    ///
    /// **Source priority is settled here and named nowhere.** The query
    /// asks whether an artifact reached the destination, not which source
    /// took it there, so a lower-priority source is handed only what a
    /// higher-priority one left behind.
    fn outstanding(
        &self,
        source: &str,
        destinations: &[&str],
        after: i64,
        limit: u32,
    ) -> Result<Vec<Work>>;

    /// What the report says about one file's cached bytes.
    ///
    /// `None` when nothing has been recorded, which is the ordinary case
    /// for a run that has not fetched this file before.
    fn cached(&self, source: &str, purl: &str, file: &str) -> Result<Option<CacheRecord>>;

    /// Whether a target is recorded as holding this exact artifact.
    ///
    /// `false` means only that nothing says so, which is why the caller
    /// still asks the repository. A report cannot prove an absence.
    fn holds(&self, target: &str, purl: &str) -> Result<bool>;

    /// Everything `source` is recorded as holding, a page at a time.
    ///
    /// Unlike [`ReportQuery::outstanding`] this names no destination: it
    /// answers what the repository has, not what is left to send anywhere.
    /// A name-only row is left out, because a coordinate with no version is
    /// not an artifact anybody can act on.
    fn inventory(&self, source: &str, after: i64, limit: u32) -> Result<Vec<Work>>;

    /// How many artifacts [`ReportQuery::outstanding`] would hand over, all
    /// pages together, so a copy's progress shows the whole list.
    ///
    /// `None` by default, for a store that cannot count cheaply.
    fn outstanding_count(&self, _source: &str, _destinations: &[&str]) -> Result<Option<u64>> {
        Ok(None)
    }

    /// How many artifacts [`ReportQuery::inventory`] would hand over, all
    /// pages together.
    ///
    /// `None` by default, as [`ReportQuery::outstanding_count`].
    fn inventory_count(&self, _source: &str) -> Result<Option<u64>> {
        Ok(None)
    }

    /// What `source` holds for one exact purl, if anything.
    ///
    /// Independent of any destination: this asks what the repository *has*,
    /// which is a different question from what is left to copy. Indexed, so
    /// a caller may ask it per artifact.
    fn held(&self, source: &str, purl: &str) -> Result<Option<Work>>;

    /// Every version of one package that `source` holds, with whether each
    /// is a pre-release.
    ///
    /// `package` is the name-level purl, everything up to the version.
    fn versions_held(&self, source: &str, package: &str) -> Result<Vec<(String, bool)>>;

    /// Whether a walk of `source`'s whole catalog reached its end: an
    /// artifact enumeration that recorded this source's contents, was not
    /// sampled, and listed versions.
    ///
    /// Only then is [`ReportQuery::versions_held`] the repository's list.
    /// Otherwise it is whatever resolutions happened to record, and a
    /// dependency walk that resolved `2.1.4` first would hold that version
    /// alone.
    fn source_listed(&self, source: &str) -> Result<bool>;

    /// The walk of `source` under `spec` for `targets` that a killed run
    /// left unfinished.
    ///
    /// `None` by default, for a store that keeps no walks.
    fn resume_walk(&self, _source: &str, _spec: &str, _targets: &str) -> Result<Option<WalkId>> {
        Ok(None)
    }
}

/// Somewhere to put a report.
pub trait ReportWriter: Send + Sync {
    /// Append one record.
    fn write(&self, record: &Record) -> Result<()>;

    /// How many artifact records this writer has taken.
    ///
    /// The run's own tally, not the store's: a database opened over an
    /// earlier run's records counts what this run wrote.
    fn artifact_count(&self) -> u64;

    /// Push anything buffered to the store behind this writer.
    fn flush(&self) -> Result<()>;

    /// The state this writer keeps beyond the records, when it keeps any.
    ///
    /// `None` for a stream of lines, which holds no state at all. A caller
    /// that needs an inventory or a resumable claim checks this once,
    /// before doing any work, rather than discovering it later.
    fn state(&self) -> Option<&dyn ReportState> {
        None
    }

    /// A read view of the same store, when there is one to read.
    ///
    /// A run writing a report often needs to ask what the report already
    /// says -- a copy asks what is left to do. Getting that view from the
    /// writer rather than opening the file again is what keeps the two from
    /// disagreeing about which store they mean.
    ///
    /// `None` for a stream of lines, which cannot be queried at all.
    fn query(&self) -> Result<Option<std::sync::Arc<dyn ReportQuery>>> {
        Ok(None)
    }
}

/// A shared writer is a writer, so one report can be handed to a walk and
/// also watch the problem sink.
impl<W: ReportWriter + ?Sized> ReportWriter for std::sync::Arc<W> {
    fn write(&self, record: &Record) -> Result<()> {
        (**self).write(record)
    }

    fn artifact_count(&self) -> u64 {
        (**self).artifact_count()
    }

    fn flush(&self) -> Result<()> {
        (**self).flush()
    }

    fn state(&self) -> Option<&dyn ReportState> {
        (**self).state()
    }

    fn query(&self) -> Result<Option<std::sync::Arc<dyn ReportQuery>>> {
        (**self).query()
    }
}

/// Somewhere to read a report from.
pub trait ReportReader: Send + Sync {
    /// Every record, in the order a run wrote them.
    ///
    /// A store that can only be walked once answers an error on the second
    /// call rather than silently yielding nothing.
    fn records(&self) -> Result<Box<dyn Iterator<Item = Result<Record>> + Send>>;

    /// What this report can be asked beyond its records, when it can be
    /// asked anything.
    fn query(&self) -> Option<&dyn ReportQuery> {
        None
    }
}
