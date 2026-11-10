//! The work a walk has discovered and not yet processed.
//!
//! The spider pulls from this rather than holding a level of the graph, so
//! what a walk keeps in memory is bounded by the frontier's own policy
//! rather than by the widest level of the graph.
//!
//! ```text
//!         +------- push(children) -------+
//!         v                              |
//!   [Frontier] --pop (lowest depth)--> [in flight <= N] --done(ticket)
//!         ^
//!    roots pushed at depth 0
//! ```
//!
//! Two decisions live here rather than in the spider, because they are
//! about storage: whether a request was already queued, and whether there
//! is room for another.
//!
//! **Lowest depth first.** The pop order keeps the walk close to
//! breadth-first, which is what makes the depth limit and `shallow` mean
//! what they say. It is not exact: under concurrency an artifact can be
//! claimed first through a deeper path while a shallower edge to it is
//! still resolving, and the shallower edge then finds it already seen.
//! The same race existed between root batches before this, and the cost is
//! confined to `shallow` walks and to the depth guard.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;

use super::visited::fingerprint;
use crate::core::error::{Error, Result};
use crate::model::{ArtifactId, ArtifactRequest, Provenance};
use crate::report::{Enqueued, ReportQuery, WalkId, WalkState, WalkTask};

/// How many tasks the in-memory frontier holds before it refuses more,
/// unless `setup.maximum-in-memory-queued-dependencies` says otherwise.
///
/// A queued task is a request and its provenance chain, a few hundred
/// bytes, so this caps the frontier in the tens of megabytes. It applies
/// only under `--db=-`: every other walk has a report database, named or
/// temporary, whose frontier is on disk.
pub const DEFAULT_QUEUE_LIMIT_TASKS: usize = 100_000;

/// One request waiting to be processed, and how far from a root it is.
///
/// Carries no context: a dependency's context is the run's with only the
/// provenance replaced, so the spider rebuilds it at pop. That is what
/// lets a task be stored outside the process.
#[derive(Debug, Clone)]
pub struct Pending {
    pub request: ArtifactRequest,
    pub depth: usize,
}

impl Pending {
    /// What makes two requests the same work.
    ///
    /// The coordinate and the version spec as asked, not the resolved
    /// version: that is not known until the request is resolved, and the
    /// claim on the resolved coordinate catches what this misses.
    pub fn key(&self) -> String {
        // JSON for the spec, so `Any` and an exact version "*" differ.
        let spec = serde_json::to_string(&self.request.spec).unwrap_or_default();

        format!("{} {spec}", self.request.id.purl())
    }
}

/// What became of a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// Queued, and will be popped.
    Queued,

    /// The same request was queued before, in this walk.
    Duplicate,

    /// No room. The task is dropped and the walk is incomplete.
    Full,
}

/// Names a popped task so its completion can be recorded.
///
/// Opaque to the spider. A store that remembers in-flight work uses it to
/// tell finished work from work a killed run left half-done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(i64);

impl Ticket {
    pub fn new(id: i64) -> Self {
        Self(id)
    }

    pub fn id(self) -> i64 {
        self.0
    }
}

/// Where a walk keeps its discovered work.
///
/// A trait for the reason [`super::Visited`] is one: an in-process queue is
/// right for most walks, and a walk large enough to need a database should
/// get one without the spider knowing the difference.
///
/// Implementations must tolerate concurrent calls.
#[async_trait]
pub trait Frontier: Send + Sync {
    /// Queue a task, unless it was queued before or there is no room.
    async fn push(&self, task: Pending) -> Result<Pushed>;

    /// The shallowest queued task, or `None` when nothing is queued.
    ///
    /// `None` is not the end of a walk: tasks in flight may still push.
    async fn pop(&self) -> Result<Option<(Ticket, Pending)>>;

    /// Record that a popped task finished.
    ///
    /// Not called for a task cut short by a stop, so a store that survives
    /// the process can hand it out again.
    async fn done(&self, ticket: Ticket) -> Result<()>;

    /// How many tasks are queued and not yet popped.
    async fn pending(&self) -> Result<u64>;
}

/// The in-process frontier, bounded.
///
/// At its limit a push answers [`Pushed::Full`] rather than waiting. A
/// waiting push could only be released by a pop, and pops and pushes come
/// from the same driver, so waiting would deadlock.
///
/// Pushed requests are remembered as fingerprints, as [`super::MemoryVisited`]
/// remembers claims.
#[derive(Debug)]
pub struct MemoryFrontier {
    limit_tasks: usize,
    queue: Mutex<Queue>,
}

#[derive(Debug, Default)]
struct Queue {
    by_depth: BTreeMap<usize, VecDeque<Pending>>,
    len: usize,
    pushed: HashSet<u128>,
}

impl MemoryFrontier {
    pub fn new(limit_tasks: usize) -> Self {
        Self {
            limit_tasks,
            queue: Mutex::new(Queue::default()),
        }
    }
}

impl Default for MemoryFrontier {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_LIMIT_TASKS)
    }
}

#[async_trait]
impl Frontier for MemoryFrontier {
    async fn push(&self, task: Pending) -> Result<Pushed> {
        let mut queue = self.queue.lock().expect("frontier poisoned");
        let key = fingerprint(&task.key());

        if queue.pushed.contains(&key) {
            return Ok(Pushed::Duplicate);
        }

        // Not remembered as pushed, so a later edge may queue it once
        // there is room.
        if queue.len >= self.limit_tasks {
            return Ok(Pushed::Full);
        }

        queue.pushed.insert(key);
        queue.len += 1;
        queue
            .by_depth
            .entry(task.depth)
            .or_default()
            .push_back(task);

        Ok(Pushed::Queued)
    }

    async fn pop(&self) -> Result<Option<(Ticket, Pending)>> {
        let mut queue = self.queue.lock().expect("frontier poisoned");

        let Some(mut shallowest) = queue.by_depth.first_entry() else {
            return Ok(None);
        };

        let task = shallowest.get_mut().pop_front();

        if shallowest.get().is_empty() {
            shallowest.remove();
        }

        let Some(task) = task else {
            return Ok(None);
        };

        queue.len -= 1;

        Ok(Some((Ticket::new(0), task)))
    }

    /// Nothing to record: a popped task is already gone from memory.
    async fn done(&self, _ticket: Ticket) -> Result<()> {
        Ok(())
    }

    async fn pending(&self) -> Result<u64> {
        Ok(self.queue.lock().expect("frontier poisoned").len as u64)
    }
}

/// The frontier of a walk kept in a report database.
///
/// Never full: it is on disk. Opening one adopts the walk a killed run left
/// for the same source and spec, so a rerun continues rather than restarts.
pub struct DbFrontier<'a> {
    walks: &'a dyn WalkState,
    walk: WalkId,
}

impl<'a> DbFrontier<'a> {
    /// Start a walk of `source` under `spec` for `targets`, resuming one
    /// `query` offers.
    ///
    /// `query` is asked rather than the state because a refreshed report
    /// answers it as though empty, which is how `--refresh=spider` works.
    pub fn open(
        walks: &'a dyn WalkState,
        query: Option<&dyn ReportQuery>,
        source: &str,
        spec: &str,
        targets: &str,
    ) -> Result<Self> {
        let resume = match query {
            Some(query) => query.resume_walk(source, spec, targets)?,
            None => None,
        };

        Ok(Self {
            walks,
            walk: walks.start(source, spec, targets, resume)?,
        })
    }

    /// The walk this frontier queues for, for the visited set beside it.
    pub fn walk(&self) -> WalkId {
        self.walk
    }
}

#[async_trait]
impl Frontier for DbFrontier<'_> {
    async fn push(&self, task: Pending) -> Result<Pushed> {
        let stored = WalkTask {
            key: task.key(),
            purl: task.request.id.purl(),
            spec: serde_json::to_string(&task.request.spec).map_err(unstored)?,
            provenance: task.request.prov.to_json(),
            depth: task.depth as u32,
        };

        Ok(match self.walks.push(self.walk, &stored)? {
            Enqueued::Added => Pushed::Queued,
            Enqueued::Duplicate => Pushed::Duplicate,
        })
    }

    async fn pop(&self) -> Result<Option<(Ticket, Pending)>> {
        let Some((id, stored)) = self.walks.pop(self.walk)? else {
            return Ok(None);
        };

        let request = ArtifactRequest {
            id: ArtifactId::parse(&stored.purl)?.id,
            spec: serde_json::from_str(&stored.spec).map_err(unstored)?,
            prov: Provenance::from_json(&stored.provenance).map_err(unstored)?,
        };

        let task = Pending {
            request,
            depth: stored.depth as usize,
        };

        Ok(Some((Ticket::new(id), task)))
    }

    async fn done(&self, ticket: Ticket) -> Result<()> {
        self.walks.done(self.walk, ticket.id())
    }

    async fn pending(&self) -> Result<u64> {
        self.walks.pending(self.walk)
    }
}

/// A task the report database holds but this build cannot read back.
fn unstored(err: impl std::fmt::Display) -> Error {
    Error::Report(format!("a queued dependency could not be read back: {err}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::commands::spider::{DbVisited, Visited};
    use crate::model::{Cause, EcosystemId, VersionSpec};
    use crate::report::{DbSpec, Part, Record, Refresh, ReportWriter, header};

    fn task(name: &str, depth: usize) -> Pending {
        Pending {
            request: ArtifactRequest {
                id: ArtifactId::new(EcosystemId::npm(), None, name),
                spec: VersionSpec::Any,
                prov: Arc::new(Provenance::root(Cause::Requested { arg: name.into() })),
            },
            depth,
        }
    }

    async fn popped(frontier: &dyn Frontier) -> Option<(String, usize)> {
        frontier
            .pop()
            .await
            .unwrap()
            .map(|(_, task)| (task.request.id.purl(), task.depth))
    }

    #[tokio::test]
    async fn pop_order_lowest_depth_first() {
        let frontier = MemoryFrontier::default();

        frontier.push(task("deep", 2)).await.unwrap();
        frontier.push(task("root", 0)).await.unwrap();
        frontier.push(task("mid", 1)).await.unwrap();
        frontier.push(task("root2", 0)).await.unwrap();

        assert_eq!(popped(&frontier).await, Some(("pkg:npm/root".into(), 0)));
        assert_eq!(popped(&frontier).await, Some(("pkg:npm/root2".into(), 0)));
        assert_eq!(popped(&frontier).await, Some(("pkg:npm/mid".into(), 1)));
        assert_eq!(popped(&frontier).await, Some(("pkg:npm/deep".into(), 2)));
        assert_eq!(popped(&frontier).await, None);
    }

    /// Already popped still counts: a request processed earlier in the
    /// walk is not work again.
    #[tokio::test]
    async fn push_dedup_after_pop() {
        let frontier = MemoryFrontier::default();

        assert_eq!(frontier.push(task("a", 0)).await.unwrap(), Pushed::Queued);
        frontier.pop().await.unwrap();

        assert_eq!(
            frontier.push(task("a", 3)).await.unwrap(),
            Pushed::Duplicate
        );
        assert_eq!(frontier.pending().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn push_dedup_keeps_specs_apart() {
        let frontier = MemoryFrontier::default();
        let mut exact = task("a", 0);
        exact.request.spec = VersionSpec::Exact("*".into());

        assert_eq!(frontier.push(task("a", 0)).await.unwrap(), Pushed::Queued);
        assert_eq!(frontier.push(exact).await.unwrap(), Pushed::Queued);
    }

    /// A report database open on a run, as a command holds one.
    async fn report(path: &std::path::Path, refresh: &[Part]) -> Box<dyn ReportWriter> {
        let spec = DbSpec::new(path).refreshing(Refresh::new(refresh.iter().copied()));
        let writer = crate::report::open(None, Some(&spec)).await.expect("opens");

        writer
            .write(&Record::Header(header(
                "inspect",
                &crate::advisory::Screening::none(),
            )))
            .expect("header");

        writer
    }

    /// A frontier on `writer` for source `s` under `spec`.
    fn opened<'a>(writer: &'a dyn ReportWriter, spec: &str) -> DbFrontier<'a> {
        let walks = writer
            .state()
            .and_then(|state| state.walks())
            .expect("walks");
        let query = writer.query().expect("a query");

        DbFrontier::open(walks, query.as_deref(), "s", spec, "").expect("opens")
    }

    /// The same contract the memory frontier keeps, on disk.
    #[tokio::test]
    async fn db_pop_order_and_dedup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = report(&dir.path().join("r.sqlite"), &[]).await;
        let frontier = opened(writer.as_ref(), "runtime");

        frontier.push(task("deep", 2)).await.unwrap();
        frontier.push(task("root", 0)).await.unwrap();
        frontier.push(task("mid", 1)).await.unwrap();

        assert_eq!(
            frontier.push(task("mid", 1)).await.unwrap(),
            Pushed::Duplicate
        );
        assert_eq!(frontier.pending().await.unwrap(), 3);

        assert_eq!(popped(&frontier).await, Some(("pkg:npm/root".into(), 0)));
        assert_eq!(popped(&frontier).await, Some(("pkg:npm/mid".into(), 1)));
        assert_eq!(popped(&frontier).await, Some(("pkg:npm/deep".into(), 2)));
        assert_eq!(popped(&frontier).await, None);
    }

    /// The request comes back as it went in, provenance included.
    #[tokio::test]
    async fn db_task_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = report(&dir.path().join("r.sqlite"), &[]).await;
        let frontier = opened(writer.as_ref(), "runtime");

        let mut sent = task("a", 1);
        sent.request.spec = VersionSpec::Range("^1.0.0".into());
        sent.request.prov = sent.request.prov.child(Cause::Dependency {
            of: ArtifactId::new(EcosystemId::npm(), Some("@scope"), "parent"),
            version: None,
            kind: crate::model::DepKind::Peer,
        });

        frontier.push(sent.clone()).await.unwrap();

        let (_, back) = frontier.pop().await.unwrap().expect("popped");

        assert_eq!(back.request.id, sent.request.id);
        assert_eq!(back.request.spec, sent.request.spec);
        assert_eq!(back.request.prov.render(), sent.request.prov.render());
        assert_eq!(back.depth, 1);
    }

    /// **A killed walk resumes.** The task in flight when the run died is
    /// handed out again, its claim withdrawn so it can claim again, and the
    /// finished task is not queued again.
    #[tokio::test]
    async fn walk_resumes_after_kill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("r.sqlite");

        {
            // Never flushed, so the run never closes: a kill.
            let writer = report(&path, &[]).await;
            let frontier = opened(writer.as_ref(), "runtime");
            let visited = DbVisited::new(
                writer
                    .state()
                    .and_then(|state| state.walks())
                    .expect("walks"),
                frontier.walk(),
            );

            frontier.push(task("finished", 0)).await.unwrap();
            frontier.push(task("in-flight", 0)).await.unwrap();
            frontier.push(task("queued", 1)).await.unwrap();

            let (done, _) = frontier.pop().await.unwrap().expect("popped");
            visited.mark("pkg:npm/finished@1", done).await.unwrap();
            frontier.done(done).await.unwrap();

            let (cut, _) = frontier.pop().await.unwrap().expect("popped");
            visited.mark("pkg:npm/in-flight@1", cut).await.unwrap();
        }

        let writer = report(&path, &[]).await;
        let frontier = opened(writer.as_ref(), "runtime");
        let visited = DbVisited::new(
            writer
                .state()
                .and_then(|state| state.walks())
                .expect("walks"),
            frontier.walk(),
        );

        assert_eq!(frontier.pending().await.unwrap(), 2);
        assert!(visited.contains("pkg:npm/finished@1").await.unwrap());
        assert!(!visited.contains("pkg:npm/in-flight@1").await.unwrap());

        assert_eq!(
            frontier.push(task("finished", 0)).await.unwrap(),
            Pushed::Duplicate
        );

        assert_eq!(
            popped(&frontier).await,
            Some(("pkg:npm/in-flight".into(), 0))
        );
        assert_eq!(popped(&frontier).await, Some(("pkg:npm/queued".into(), 1)));
    }

    /// A run that closed is not resumed, whatever it left.
    #[tokio::test]
    async fn walk_not_resumed_after_close() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("r.sqlite");

        {
            let writer = report(&path, &[]).await;
            let frontier = opened(writer.as_ref(), "runtime");

            frontier.push(task("a", 0)).await.unwrap();
            writer.flush().expect("closed");
        }

        let writer = report(&path, &[]).await;
        let frontier = opened(writer.as_ref(), "runtime");

        assert_eq!(frontier.pending().await.unwrap(), 0);
    }

    /// Another spec follows other edges, so its walk is not this one.
    #[tokio::test]
    async fn walk_not_resumed_for_other_spec() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("r.sqlite");

        {
            let writer = report(&path, &[]).await;
            opened(writer.as_ref(), "runtime")
                .push(task("a", 0))
                .await
                .unwrap();
        }

        let writer = report(&path, &[]).await;

        assert_eq!(opened(writer.as_ref(), "all").pending().await.unwrap(), 0);
    }

    /// Other targets have other work, so their walk is not this one; the
    /// same targets resume it.
    #[tokio::test]
    async fn walk_resumed_only_for_same_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("r.sqlite");

        let for_targets = |writer: &dyn ReportWriter, targets: &str| {
            let walks = writer
                .state()
                .and_then(|state| state.walks())
                .expect("walks");
            let query = writer.query().expect("a query");

            DbFrontier::open(walks, query.as_deref(), "s", "runtime", targets)
                .expect("opens")
                .walk()
        };

        let first = {
            let writer = report(&path, &[]).await;
            for_targets(writer.as_ref(), "backup,local")
        };

        let writer = report(&path, &[]).await;

        assert_ne!(for_targets(writer.as_ref(), "local"), first);
        assert_eq!(for_targets(writer.as_ref(), "backup,local"), first);
    }

    #[tokio::test]
    async fn walk_blanked_by_spider_refresh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("r.sqlite");

        {
            let writer = report(&path, &[]).await;
            opened(writer.as_ref(), "runtime")
                .push(task("a", 0))
                .await
                .unwrap();
        }

        let writer = report(&path, &[Part::Spider]).await;

        assert_eq!(
            opened(writer.as_ref(), "runtime").pending().await.unwrap(),
            0
        );
    }

    /// A refused task is not remembered, so it can be queued once room
    /// frees up.
    #[tokio::test]
    async fn push_full_forgets_task() {
        let frontier = MemoryFrontier::new(1);

        assert_eq!(frontier.push(task("a", 0)).await.unwrap(), Pushed::Queued);
        assert_eq!(frontier.push(task("b", 0)).await.unwrap(), Pushed::Full);

        frontier.pop().await.unwrap();

        assert_eq!(frontier.push(task("b", 0)).await.unwrap(), Pushed::Queued);
    }
}
