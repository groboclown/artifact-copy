//! Following dependencies.
//!
//! The first of the [operations](crate::commands) an embedder invokes: give
//! it a source, a visitor and a set of roots, and it walks the dependency
//! graph. It reads no arguments and writes no output, which is what lets a
//! command line and a host program drive the same walk.
//!
//! Dependency inspection walks a web, not a tree: one artifact is reached
//! again and again from different directions, and in npm a popular package
//! sits under thousands of others. Three things keep that from exploding,
//! and they sit at three different layers:
//!
//! - **[`Visited`]** decides who descends. Exactly one claimant per
//!   coordinate, so a subtree is walked once however many edges lead into
//!   it.
//! - **The source's own cache** (`cache::Coalesced`) absorbs
//!   duplicate *fetches*, including ones already in flight, so the workers
//!   that lose the race cost a cache hit rather than a request.
//! - **The [`Frontier`]** holds discovered work and refuses a request
//!   already queued, and the driver keeps at most `concurrency` tasks in
//!   flight.
//!
//! # Streaming, not accumulating
//!
//! Nothing here returns the artifacts it found. An inspection can reach
//! millions, and a `Vec<ResolvedArtifact>` would be the single largest thing
//! in the process. Artifacts go to a [`Visitor`] as they are inspected -- in
//! practice the report writer -- and [`Spider::run`] returns only counts.
//!
//! # Bounded frontier
//!
//! The work waiting to be processed grows with the width of the graph. The
//! in-memory [`MemoryFrontier`] caps it and prunes past the cap, saying so;
//! a walk with a report database keeps its frontier on disk instead, which
//! is also what lets a killed walk resume.
//!
//! Workers never push. They hand their children back to the one driver
//! loop, which pushes them, so a full frontier can never block a worker
//! that the driver is waiting on.

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::FuturesUnordered;

mod frontier;
mod limits;
mod spec;
mod summary;
mod visited;
#[cfg(test)]
mod visitors;
mod walk;

pub(crate) use frontier::{
    DEFAULT_QUEUE_LIMIT_TASKS, DbFrontier, Frontier, MemoryFrontier, Pending, Pushed, Ticket,
};
pub(crate) use spec::SpecOrigin;
pub use spec::{Depth, SpiderSetting, SpiderSpec};
pub use summary::Summary;
pub(crate) use visited::{DbVisited, MemoryVisited, Seen, Visited};
#[cfg(test)]
pub(crate) use visitors::{Collector, Discard};

use summary::Tally;

use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Problem;
use crate::core::progress::Node;
use crate::model::{ArtifactRequest, ResolvedArtifact};
use crate::repo::{Criteria, Source};

/// How many artifacts are resolved at once by default.
///
/// Per-host limits live in `net`, where they belong; this bounds how much
/// work the spider itself has in flight.
pub(crate) const DEFAULT_CONCURRENCY: usize = 16;

/// How deep the walk may go before it stops.
///
/// Real graphs are shallow -- npm's deepest chains run to a few dozen -- and
/// a cycle through a range specification that resolves differently each
/// time could otherwise descend forever. Reaching this is reported, never
/// silent.
pub(crate) const DEFAULT_MAX_DEPTH: usize = 64;

/// Receives artifacts as they are inspected.
///
/// A sink rather than a return value: see the module documentation.
///
/// Three methods rather than one taking a verdict, because they are three
/// different events and a caller that cares about only one should say so.
/// A single `visit` carrying "and by the way this one was refused" is a
/// method every implementor must remember to check, and one that forgets
/// records a refused artifact as taken -- the exact claim a report exists
/// to make honestly.
#[async_trait]
pub trait Visitor: Send + Sync {
    /// One artifact, exactly once per run.
    ///
    /// `source` is the one that described it, which is where its files are
    /// downloaded from.
    async fn visit(
        &self,
        artifact: &ResolvedArtifact,
        source: &dyn Source,
        ctx: &Ctx,
    ) -> Result<()>;

    /// An artifact a problem's disposition refuses to act on.
    ///
    /// Resolved, so it is a real artifact with a real version -- the walk
    /// simply may not take it. `why` is the finding that decided.
    async fn refused(&self, artifact: &ResolvedArtifact, why: &Problem, ctx: &Ctx) -> Result<()>;

    /// A request that never became an artifact.
    ///
    /// Reported rather than only counted so a run can be audited: a user
    /// asking why something is missing from a target needs the request and
    /// the reason together, and after the run the request is gone.
    async fn unresolved(&self, request: &ArtifactRequest, why: &Problem, ctx: &Ctx) -> Result<()>;

    /// The targets this visitor publishes to, for a walk that copies.
    ///
    /// Part of the walk's key, because a walk marks what it visited: a
    /// run with other targets has other work, and must not skip what this
    /// one marked. Empty for a walk that copies nothing.
    fn targets(&self) -> Vec<&str> {
        Vec::new()
    }
}

/// What a walk works with.
///
/// Grouped rather than passed one by one so that adding a collaborator does
/// not reshape every signature -- and so that progress cannot be forgotten,
/// which is the whole reason it is not an `Option`.
///
/// One lifetime, not four: the struct is covariant in it, so each reference
/// may come from a different scope and be shortened independently. Naming
/// four would add noise without admitting a single extra caller.
pub(crate) struct Walk<'a> {
    pub source: &'a dyn Source,

    /// Which coordinates have already been claimed.
    ///
    /// Borrowed so it carries across calls: a caller feeding enumerator pages
    /// hands the same set to every batch.
    pub visited: &'a dyn Visited,

    /// Where discovered work waits.
    ///
    /// Borrowed, like `visited`, so it carries across batches: a request
    /// queued for one page of roots is not queued again for the next.
    pub frontier: &'a dyn Frontier,

    /// Where inspected artifacts go.
    pub visitor: &'a dyn Visitor,

    /// The license policy resolved artifacts are judged under, when the
    /// configuration names one.
    ///
    /// Judged **here** rather than inside `Source::resolve`, which is where
    /// it first looks like it belongs. `resolve` is a trait method with a
    /// default body and `repo::github` already overrides it, so an
    /// evaluation placed there is one an adapter can silently skip -- which
    /// is the exact failure this wiring exists to end. The walk is the one
    /// point every resolved artifact passes through, whatever produced it.
    pub licenses: Option<&'a crate::policy::LicensePolicy>,

    /// The corpora resolved artifacts are screened against, beside the
    /// license policy and for the same reason. `None` screens nothing.
    pub screen: Option<crate::advisory::Screen<'a>>,

    /// The security policy screening answers to, with its path.
    pub security: crate::advisory::Policed<'a>,

    /// The node this walk reports into.
    ///
    /// **Owned by the caller**, which is what makes the display stack:
    /// `inspect` passes its top-level node and `find` passes the one
    /// beneath its enumerator, so the spider's counts land in the right place
    /// without it knowing anything about the surrounding work. It is also
    /// what lets a batched caller keep one total across every page.
    ///
    /// The spider raises the total by exactly what it queues and advances
    /// once per artifact, so the caller must not pre-count the roots
    /// itself -- unless it says so through [`Spider::promised_roots`].
    pub progress: &'a Node,
}

/// Whether a walk's roots are already in its progress total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootTotal {
    /// The spider counts each root as it queues it. The default: most
    /// callers learn their roots a batch at a time.
    Unpromised,

    /// The caller counted every root up front, such as a report's
    /// outstanding list, so queuing one adds nothing to the total.
    Promised,
}

/// Follows dependency edges.
pub(crate) struct Spider {
    spec: SpiderSpec,
    criteria: Criteria,
    max_depth: usize,
    concurrency: usize,
    roots: RootTotal,
}

impl Spider {
    pub fn new(spec: SpiderSpec, criteria: Criteria) -> Self {
        Self {
            spec,
            criteria,
            max_depth: DEFAULT_MAX_DEPTH,
            concurrency: DEFAULT_CONCURRENCY,
            roots: RootTotal::Unpromised,
        }
    }

    /// The caller put every root into the progress total before the walk.
    pub fn promised_roots(mut self) -> Self {
        self.roots = RootTotal::Promised;
        self
    }

    /// Test hook: a depth small enough to reach. Every real walk uses
    /// [`DEFAULT_MAX_DEPTH`].
    #[cfg(test)]
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Test hook: a worker count, to show the result does not depend on
    /// it. Every real walk uses [`DEFAULT_CONCURRENCY`].
    #[cfg(test)]
    pub fn concurrency(mut self, workers: usize) -> Self {
        self.concurrency = workers.max(1);
        self
    }

    /// Walk from a batch of roots.
    ///
    /// **Every root is taken**, whatever `--dependencies` says - the spider
    /// spec governs which *edges* are followed, not whether a requested
    /// artifact is wanted. That is what makes `--lock=FILE` behave as
    /// `README.md` describes: every artifact in the lock file is pulled,
    /// and the spec applies only to those artifacts' own dependencies.
    ///
    /// Takes a batch rather than a whole catalog so that a caller walking a
    /// enumerator can feed it one page at a time. `visited` is borrowed rather
    /// than owned precisely so it carries across those calls: an artifact
    /// claimed while processing page one is not walked again on page two.
    pub async fn run(
        &self,
        roots: &[ArtifactRequest],
        walk: &Walk<'_>,
        ctx: &Ctx,
    ) -> Result<Summary> {
        let tally = Tally::default();

        // Work a killed run left queued is this run's to finish, so it is
        // promised before any of it starts. Zero for a fresh frontier.
        walk.progress.grow_total(walk.frontier.pending().await?);

        // Each root reports under **its own** cause, not the run's. A
        // request arrives carrying the chain that explains it -- the
        // coordinate somebody typed, the lock file that named it -- and the
        // task's context is rebuilt from that chain when it is popped.
        let seeds = roots.iter().map(|request| Pending {
            request: request.clone(),
            depth: 0,
        });

        self.enqueue(seeds, walk, &tally).await?;

        let mut running = FuturesUnordered::new();
        let mut cut_short = 0u64;

        loop {
            // Checked before every pop so an interrupt, a deadline, a spent
            // budget or one task's fatal problem stops new work promptly.
            // Work already in flight races the same signal and drains.
            while ctx.stop_reason().is_none() && running.len() < self.concurrency {
                let Some((ticket, task)) = walk.frontier.pop().await? else {
                    break;
                };

                tally.depth.fetch_max(task.depth, Ordering::SeqCst);
                running.push(self.process(ticket, task, walk, ctx, &tally));
            }

            // Nothing in flight and nothing popped: the walk is done.
            let Some(finished) = running.next().await else {
                break;
            };

            let (ticket, children) = finished?;

            // Cut short by a stop, so not marked done: a frontier that
            // outlives the process hands it out again.
            let Some(children) = children else {
                cut_short += 1;
                continue;
            };

            self.enqueue(children.into_iter(), walk, &tally).await?;
            walk.frontier.done(ticket).await?;
        }

        // Empty by now; released so the tally it borrows can be read.
        drop(running);

        self.report_pruned(&tally, ctx);

        // Graceful rather than `check_abort`: the caller still has a report
        // to finish.
        let stopped = ctx.stop_reason();

        if let Some(reason) = stopped {
            let remaining = walk.frontier.pending().await? + cut_short;
            self.report_stopped(reason, remaining, ctx);
        }

        Ok(tally.into_summary(stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::cancel::Reason;
    use crate::core::ctx::Ctx;
    use crate::core::error::Result;
    use crate::core::problem::{Code, Problem};
    use crate::core::progress::Unit;
    use crate::model::{ArtifactRequest, Cause, ResolvedArtifact};
    use crate::repo::{Criteria, Source};

    use crate::ecosystem::{Ecosystem, Npm};
    use crate::ext::testing::Fixture;
    use crate::model::{ArtifactId, DepKind, EcosystemId, VersionSpec};
    use crate::net::{Canned, FixtureClient};
    use crate::repo::NpmSource;
    use crate::version::PreRelease;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const REGISTRY: &str = "h://registry.test";

    /// One package's packument.
    fn packument(name: &str, deps: &[(&str, DepKind)]) -> String {
        let mut runtime = BTreeMap::new();
        let mut dev = BTreeMap::new();
        let mut optional = BTreeMap::new();

        for (dep, kind) in deps {
            let group = match kind {
                DepKind::Dev => &mut dev,
                DepKind::Optional => &mut optional,
                _ => &mut runtime,
            };

            group.insert((*dep).to_owned(), "^1.0.0".to_owned());
        }

        serde_json::json!({
            "name": name,
            "license": "MIT",
            "time": {"1.0.0": "2024-01-01T00:00:00.000Z"},
            "versions": {
                "1.0.0": {
                    "license": "MIT",
                    "dist": {
                        "tarball": format!("{REGISTRY}/{name}/-/{name}-1.0.0.tgz"),
                        "shasum": "abcd"
                    },
                    "dependencies": runtime,
                    "devDependencies": dev,
                    "optionalDependencies": optional,
                }
            }
        })
        .to_string()
    }

    /// A registry whose packages depend on each other, built from a table
    /// so a test states only the graph it cares about.
    fn registry(packages: &[(&str, &[(&str, DepKind)])]) -> FixtureClient {
        let mut client = FixtureClient::new();

        for (name, deps) in packages {
            client = client.with_body(format!("{REGISTRY}/{name}"), packument(name, deps));
        }

        client
    }

    fn fixture(packages: &[(&str, &[(&str, DepKind)])]) -> Fixture<NpmSource> {
        Fixture::build(registry(packages), |host| NpmSource::new(REGISTRY, host))
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "root".into() })
    }

    fn root(name: &str, ctx: &Ctx) -> ArtifactRequest {
        ArtifactRequest {
            id: ArtifactId::new(EcosystemId::npm(), None, name),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        }
    }

    fn spec(text: &str) -> SpiderSpec {
        SpiderSpec::parse(text).expect("parses")
    }

    /// A progress node on the context's own sink.
    fn node(ctx: &Ctx) -> crate::core::progress::Node {
        ctx.progress("inspect", Unit::Items, None)
    }

    async fn walk(
        f: &Fixture<NpmSource>,
        ctx: &Ctx,
        roots: &[&str],
        spec: SpiderSpec,
    ) -> (Summary, Collector) {
        let requests: Vec<ArtifactRequest> = roots.iter().map(|name| root(name, ctx)).collect();

        walk_from(&f.subject, ctx, &requests, spec).await
    }

    /// Walk any source from prepared requests.
    async fn walk_from(
        source: &dyn Source,
        ctx: &Ctx,
        requests: &[ArtifactRequest],
        spec: SpiderSpec,
    ) -> (Summary, Collector) {
        let spider = Spider::new(spec, Criteria::new(PreRelease::Exclude));
        let visited = MemoryVisited::new();
        let frontier = MemoryFrontier::default();
        let collector = Collector::new();

        let progress = node(ctx);

        let walk = Walk {
            licenses: None,
            screen: None,
            security: None,
            source,
            visited: &visited,
            frontier: &frontier,
            visitor: &collector,
            progress: &progress,
        };

        let summary = spider.run(requests, &walk, ctx).await.expect("walked");

        (summary, collector)
    }

    /// Records the arithmetic, not the rendering.
    #[derive(Debug, Default)]
    struct ProgressLog {
        next: std::sync::Mutex<u64>,
        opened: std::sync::Mutex<Vec<(Option<u64>, String)>>,
        closed: AtomicU64,
        total: AtomicU64,
        advanced: AtomicU64,
    }

    impl crate::core::progress::ProgressSink for ProgressLog {
        fn open(
            &self,
            parent: Option<crate::core::progress::NodeId>,
            label: String,
            _unit: Unit,
            total: Option<u64>,
        ) -> crate::core::progress::NodeId {
            let mut next = self.next.lock().unwrap();
            *next += 1;

            self.total.fetch_add(total.unwrap_or(0), Ordering::SeqCst);
            self.opened
                .lock()
                .unwrap()
                .push((parent.map(|id| id.0), label));

            crate::core::progress::NodeId(*next)
        }

        fn advance(&self, _id: crate::core::progress::NodeId, amount: u64) {
            self.advanced.fetch_add(amount, Ordering::SeqCst);
        }

        fn grow_total(&self, _id: crate::core::progress::NodeId, additional: u64) {
            self.total.fetch_add(additional, Ordering::SeqCst);
        }

        fn close(&self, _id: crate::core::progress::NodeId) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A context reporting into a recording sink.
    fn watched() -> (Ctx, Arc<ProgressLog>) {
        let log = Arc::new(ProgressLog::default());

        let ctx = Ctx::new(
            Cause::Requested { arg: "root".into() },
            crate::core::problem::ProblemSink::new(),
            Arc::clone(&log) as Arc<dyn crate::core::progress::ProgressSink>,
        );

        (ctx, log)
    }

    /// Which dependency edges a walk follows, and how far.
    mod edges {
        use super::*;

        #[tokio::test]
        async fn follow_chain_to_end() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("c", DepKind::Runtime)]),
                ("c", &[]),
            ]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            let mut purls = found.purls();
            purls.sort();

            assert_eq!(
                purls,
                ["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"]
            );
            assert_eq!(summary.emitted, 3);
            assert_eq!(summary.depth_reached, 2);
        }

        #[tokio::test]
        async fn follow_only_requested_kinds() {
            let f = fixture(&[
                (
                    "a",
                    &[("runtime-dep", DepKind::Runtime), ("dev-dep", DepKind::Dev)],
                ),
                ("runtime-dep", &[]),
                ("dev-dep", &[]),
            ]);

            let ctx = ctx();
            let (_, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert!(
                found
                    .purls()
                    .contains(&"pkg:npm/runtime-dep@1.0.0".to_owned())
            );
            assert!(!found.purls().contains(&"pkg:npm/dev-dep@1.0.0".to_owned()));
        }

        /// `shallow` takes the roots' own dependencies and stops.
        #[tokio::test]
        async fn follow_shallow_one_level_only() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("c", DepKind::Runtime)]),
                ("c", &[]),
            ]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime+shallow")).await;

            assert_eq!(found.len(), 2);
            assert!(!found.purls().contains(&"pkg:npm/c@1.0.0".to_owned()));
            assert_eq!(summary.depth_reached, 1);
        }

        /// `none` still takes the roots. The spec governs which edges are
        /// followed, not whether a requested artifact is wanted -- which is what
        /// makes `--lock=FILE` pull every artifact in the file.
        #[tokio::test]
        async fn follow_none_still_takes_every_root() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a", "b"], spec("none")).await;

            assert_eq!(summary.emitted, 2);
            assert_eq!(found.len(), 2);
            assert_eq!(summary.depth_reached, 0);
        }
    }

    /// The claim set doing its job: one visit per coordinate, however many
    /// edges lead to it.
    mod dedup {
        use super::*;

        /// The diamond: two paths into one artifact. It is emitted once, and
        /// its subtree walked once.
        #[tokio::test]
        async fn shared_dependency_visited_once() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime), ("c", DepKind::Runtime)]),
                ("b", &[("shared", DepKind::Runtime)]),
                ("c", &[("shared", DepKind::Runtime)]),
                ("shared", &[("deep", DepKind::Runtime)]),
                ("deep", &[]),
            ]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(found.len(), 5);
            assert_eq!(summary.emitted, 5);

            // The second edge into `shared` was refused at the queue.
            assert_eq!(summary.already_seen, 1);

            // And `deep` was reached through the winner only.
            assert_eq!(
                found.purls().iter().filter(|p| p.contains("deep")).count(),
                1
            );
        }

        /// A cycle must terminate. Left unchecked this is an infinite walk, and
        /// published packages really do contain them.
        #[tokio::test]
        async fn cycle_terminates() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("c", DepKind::Runtime)]),
                ("c", &[("a", DepKind::Runtime)]),
            ]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(found.len(), 3);
            assert_eq!(summary.already_seen, 1);
        }

        #[tokio::test]
        async fn cycle_self_dependency_terminates() {
            let f = fixture(&[("a", &[("a", DepKind::Runtime)])]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(found.len(), 1);
            assert_eq!(summary.already_seen, 1);
        }

        /// The same artifact named twice among the roots is still one artifact.
        #[tokio::test]
        async fn root_duplicated_emitted_once() {
            let f = fixture(&[("a", &[])]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a", "a"], spec("runtime")).await;

            assert_eq!(found.len(), 1);
            assert_eq!(summary.already_seen, 1);
        }

        /// The visited set is borrowed so it carries across calls: a caller
        /// feeding enumerator pages must not re-walk what an earlier page claimed.
        #[tokio::test]
        async fn visited_set_carries_across_batches() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);

            let ctx = ctx();
            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();

            let progress = node(&ctx);
            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let first = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            let second = spider
                .run(&[root("b", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            assert_eq!(first.emitted, 2);

            // `b` was claimed while walking `a`, so the second batch adds
            // nothing rather than emitting it twice.
            assert_eq!(second.emitted, 0);
            assert_eq!(second.already_seen, 1);
            assert_eq!(collector.len(), 2);
        }

        /// Under concurrency the duplicate work is real rather than
        /// hypothetical: many workers reach the same package at once, and the
        /// fixture is slow so that they genuinely overlap.
        #[tokio::test]
        async fn shared_dependency_fetched_once_concurrently() {
            let mut packages: Vec<(String, Vec<(String, DepKind)>)> = Vec::new();
            let mut root_deps = Vec::new();

            for index in 0..30 {
                let name = format!("dep-{index}");
                root_deps.push((name.clone(), DepKind::Runtime));
                packages.push((name, vec![("shared".to_owned(), DepKind::Runtime)]));
            }

            packages.push(("root".to_owned(), root_deps));
            packages.push(("shared".to_owned(), Vec::new()));

            let borrowed: Vec<(&str, Vec<(&str, DepKind)>)> = packages
                .iter()
                .map(|(name, deps)| {
                    (
                        name.as_str(),
                        deps.iter().map(|(d, k)| (d.as_str(), *k)).collect(),
                    )
                })
                .collect();

            let table: Vec<(&str, &[(&str, DepKind)])> = borrowed
                .iter()
                .map(|(name, deps)| (*name, deps.as_slice()))
                .collect();

            // `shared` answers slowly on purpose. With an instant fixture the
            // thirty workers would finish one after another and a plain
            // check-then-fetch cache would look identical to a coalescing one;
            // the delay is what makes them genuinely overlap, so a single fetch
            // proves the in-flight deduplication rather than mere caching.
            let client = registry(&table).with(
                format!("{REGISTRY}/shared"),
                Canned::ok(packument("shared", &[])).slow(Duration::from_millis(25)),
            );

            let f = Fixture::build(client, |host| NpmSource::new(REGISTRY, host));

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["root"], spec("runtime")).await;

            // 1 root + 30 deps + 1 shared.
            assert_eq!(found.len(), 32);
            assert_eq!(summary.emitted, 32);

            // Thirty edges lead into `shared` with one spec; twenty-nine are
            // refused at the queue, and one request serves the walk.
            assert_eq!(summary.already_seen, 29);
            assert_eq!(f.host.hits(&format!("{REGISTRY}/shared")), 1);
        }
    }

    /// What a walk does when one artifact cannot be resolved -- which is
    /// never to abandon the rest of the graph.
    mod failure {
        use super::*;

        /// A dependency that does not exist is skipped, and its siblings and
        /// its parent survive.
        #[tokio::test]
        async fn dependency_missing_skips_only_itself() {
            let f = fixture(&[
                (
                    "a",
                    &[("present", DepKind::Runtime), ("ghost", DepKind::Runtime)],
                ),
                ("present", &[]),
            ]);

            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            let purls = found.purls();

            assert!(purls.contains(&"pkg:npm/a@1.0.0".to_owned()));
            assert!(purls.contains(&"pkg:npm/present@1.0.0".to_owned()));
            assert_eq!(summary.skipped, 1);
            assert_eq!(ctx.problems().counts()[&Code::ArtifactNotFound], 1);
        }

        /// Provenance is what answers "why is this artifact here?", and it has
        /// to survive a walk that migrates between threads.
        #[tokio::test]
        async fn failure_names_causing_chain() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("ghost", DepKind::Runtime)]),
            ]);

            let ctx = ctx();
            walk(&f, &ctx, &["a"], spec("runtime")).await;

            let problem = ctx.problems().tail().pop().expect("recorded");
            let rendered = problem.prov().render();

            assert!(
                rendered.contains("runtime dependency of pkg:npm/b"),
                "{rendered}"
            );
            assert!(
                rendered.contains("runtime dependency of pkg:npm/a"),
                "{rendered}"
            );
            assert!(rendered.contains(r#"requested: "root""#), "{rendered}");
        }

        /// The depth limit is a guard against a graph that resolves differently
        /// each time round a cycle. Reaching it is reported, never silent.
        #[tokio::test]
        async fn prune_at_depth_limit_reported() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("c", DepKind::Runtime)]),
                ("c", &[("d", DepKind::Runtime)]),
                ("d", &[]),
            ]);

            let ctx = ctx();
            let spider =
                Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude)).max_depth(2);
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();

            let progress = node(&ctx);
            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let summary = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            assert_eq!(collector.len(), 3);
            assert!(summary.pruned >= 1);
            assert!(ctx.problems().counts()[&Code::DependencyUnresolved] >= 1);
        }

        /// PyPI publishes no test dependencies. Asking for them must say so
        /// rather than returning nothing, which would read as "this package has
        /// no test dependencies".
        #[tokio::test]
        async fn follow_kind_ecosystem_lacks_reported() {
            let f = fixture(&[("a", &[])]);
            let ctx = ctx();

            // npm has no `test` kind.
            walk(&f, &ctx, &["a"], spec("test")).await;

            assert!(ctx.problems().counts()[&Code::ConfigInvalid] >= 1);
        }

        #[tokio::test]
        async fn walk_without_roots_does_nothing() {
            let f = fixture(&[("a", &[])]);
            let ctx = ctx();
            let (summary, found) = walk(&f, &ctx, &[], spec("runtime")).await;

            assert_eq!(summary, Summary::default());
            assert!(found.is_empty());
        }
    }

    /// The parts that are not about the graph: counts, provenance, worker
    /// count independence, and what a walk claims a version on.
    mod plumbing {
        use super::*;

        /// The count that shows what the visited set is worth. In npm it
        /// routinely exceeds the number emitted.
        #[tokio::test]
        async fn summary_counts_walk() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime), ("c", DepKind::Runtime)]),
                ("b", &[("shared", DepKind::Runtime)]),
                ("c", &[("shared", DepKind::Runtime)]),
                ("shared", &[]),
            ]);

            let ctx = ctx();
            let (summary, _) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(summary.emitted, 4);
            assert_eq!(summary.already_seen, 1);
            assert_eq!(summary.skipped, 0);
            assert_eq!(summary.depth_reached, 2);
        }

        /// The version really is resolved rather than taken from the request:
        /// `Any` has to become an exact coordinate before anything is claimed,
        /// or the visited set would key on a range.
        #[tokio::test]
        async fn claim_on_resolved_version() {
            let f = fixture(&[("a", &[])]);
            let ctx = ctx();

            let (_, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(found.purls(), ["pkg:npm/a@1.0.0"]);
        }

        /// A visitor that only counts is the shape a catalog walk uses; the
        /// collector exists for tests and small embedded uses.
        #[tokio::test]
        async fn walk_with_discarding_visitor() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);
            let ctx = ctx();

            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();

            let progress = node(&ctx);
            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &Discard,
                progress: &progress,
            };

            let summary = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            assert_eq!(summary.emitted, 2);
        }

        /// Concurrency is a knob, not a fixed cost: one worker must produce the
        /// same artifacts as sixteen.
        #[tokio::test]
        async fn walk_result_independent_of_worker_count() {
            let packages: &[(&str, &[(&str, DepKind)])] = &[
                ("a", &[("b", DepKind::Runtime), ("c", DepKind::Runtime)]),
                ("b", &[("d", DepKind::Runtime)]),
                ("c", &[("d", DepKind::Runtime)]),
                ("d", &[]),
            ];

            let mut results = Vec::new();

            for workers in [1, 4, 16] {
                let f = fixture(packages);
                let ctx = ctx();

                let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude))
                    .concurrency(workers);
                let visited = MemoryVisited::new();
                let frontier = MemoryFrontier::default();
                let collector = Collector::new();

                let progress = node(&ctx);
                let walk = Walk {
                    licenses: None,
                    screen: None,
                    security: None,
                    source: &f.subject,
                    visited: &visited,
                    frontier: &frontier,
                    visitor: &collector,
                    progress: &progress,
                };

                spider
                    .run(&[root("a", &ctx)], &walk, &ctx)
                    .await
                    .expect("walked");

                let mut purls = collector.purls();
                purls.sort();
                results.push(purls);
            }

            assert_eq!(results[0], results[1]);
            assert_eq!(results[1], results[2]);
            assert_eq!(results[0].len(), 4);
        }

        /// `Npm` is the ecosystem under test here; this pins that the spider
        /// asks the source rather than assuming a kind set.
        #[test]
        fn follow_kinds_from_ecosystem() {
            let supported = Npm.dep_kinds();

            assert_eq!(
                spec("all").resolve(supported),
                supported.iter().copied().collect()
            );
            assert!(spec("test").unsupported(supported).contains(&DepKind::Test));
        }

        /// A root reports under **its own** cause, not the run's.
        ///
        /// A request arrives carrying the chain that explains it, and an
        /// earlier version cloned the caller's context instead -- so a lock
        /// file of three hundred entries produced three hundred artifacts
        /// all filed under the command line, and `Cause::LockFile` could
        /// not appear in a report at all.
        #[tokio::test]
        async fn root_keeps_the_provenance_it_arrived_with() {
            let f = fixture(&[("a", &[])]);
            let ctx = ctx();

            let spider = Spider::new(spec("none"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();

            /// Records the provenance each artifact was visited under.
            #[derive(Default)]
            struct Chains(std::sync::Mutex<Vec<String>>);

            #[async_trait]
            impl Visitor for Chains {
                async fn visit(
                    &self,
                    _artifact: &ResolvedArtifact,
                    _source: &dyn Source,
                    ctx: &Ctx,
                ) -> Result<()> {
                    self.0
                        .lock()
                        .expect("not poisoned")
                        .push(ctx.prov().render());

                    Ok(())
                }

                async fn refused(
                    &self,
                    _artifact: &ResolvedArtifact,
                    _why: &Problem,
                    _ctx: &Ctx,
                ) -> Result<()> {
                    Ok(())
                }

                async fn unresolved(
                    &self,
                    _request: &ArtifactRequest,
                    _why: &Problem,
                    _ctx: &Ctx,
                ) -> Result<()> {
                    Ok(())
                }
            }

            let chains = Chains::default();

            let from_a_lock = ArtifactRequest {
                id: ArtifactId::new(EcosystemId::npm(), None, "a"),
                spec: VersionSpec::Any,
                prov: Arc::new(crate::model::Provenance::root(Cause::LockFile {
                    path: "somewhere/package-lock.json".into(),
                    entry: "pkg:npm/a".into(),
                })),
            };

            let progress = node(&ctx);
            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &chains,
                progress: &progress,
            };

            spider
                .run(&[from_a_lock], &walk, &ctx)
                .await
                .expect("walked");

            let seen = chains.0.lock().expect("not poisoned").clone();

            assert_eq!(seen.len(), 1);
            assert!(
                seen[0].contains("package-lock.json"),
                "reported under the run's cause instead: {}",
                seen[0]
            );
        }

        /// Past the frontier's limit a dependency is pruned and reported,
        /// never waited for: the walk ends, and says what it dropped.
        #[tokio::test]
        async fn prune_at_full_queue_reported() {
            let f = fixture(&[
                (
                    "a",
                    &[
                        ("b", DepKind::Runtime),
                        ("c", DepKind::Runtime),
                        ("d", DepKind::Runtime),
                    ],
                ),
                ("b", &[]),
                ("c", &[]),
                ("d", &[]),
            ]);

            let (ctx, log) = watched();
            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::new(1);
            let collector = Collector::new();
            let progress = node(&ctx);

            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let summary = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            // `a` is popped before its children arrive, so one of three fits.
            assert_eq!(summary.emitted, 2);
            assert_eq!(summary.overflowed, 2);
            assert_eq!(summary.pruned, 2);
            assert!(ctx.problems().counts()[&Code::DependencyUnresolved] >= 1);

            assert_eq!(
                log.total.load(Ordering::SeqCst),
                log.advanced.load(Ordering::SeqCst)
            );
        }

        /// Roots the caller counted up front add nothing to the total, a
        /// repeated root still advances, and dependencies still grow it.
        #[tokio::test]
        async fn promised_roots_counted_once() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);

            let (ctx, log) = watched();
            let spider =
                Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude)).promised_roots();
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();
            let progress = node(&ctx);

            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            // The caller's promise: two roots.
            progress.grow_total(2);

            spider
                .run(&[root("a", &ctx), root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            // Two promised roots and `b`, each advanced once.
            assert_eq!(log.total.load(Ordering::SeqCst), 3);
            assert_eq!(log.advanced.load(Ordering::SeqCst), 3);
        }

        /// A walk queued in a report database finds what one queued in
        /// memory finds, and its progress balances.
        #[tokio::test]
        async fn walk_with_db_frontier_alike() {
            use crate::report::{DbSpec, Record, header};

            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime), ("c", DepKind::Runtime)]),
                ("b", &[("shared", DepKind::Runtime)]),
                ("c", &[("shared", DepKind::Runtime)]),
                ("shared", &[]),
            ]);

            let dir = tempfile::tempdir().expect("tempdir");
            let writer = crate::report::open(None, Some(&DbSpec::new(dir.path().join("r.sqlite"))))
                .await
                .expect("opens");

            writer
                .write(&Record::Header(header(
                    "inspect",
                    &crate::advisory::Screening::none(),
                )))
                .expect("header");

            let walks = writer
                .state()
                .and_then(|state| state.walks())
                .expect("walks");
            let frontier = DbFrontier::open(walks, None, "npmjs", "runtime", "").expect("opens");
            let visited = DbVisited::new(walks, frontier.walk());

            let (ctx, log) = watched();
            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let collector = Collector::new();
            let progress = node(&ctx);

            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let summary = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            assert_eq!(summary.emitted, 4);
            assert_eq!(summary.already_seen, 1);
            assert_eq!(frontier.pending().await.unwrap(), 0);
            assert_eq!(
                log.total.load(Ordering::SeqCst),
                log.advanced.load(Ordering::SeqCst)
            );
        }

        /// A dependency edge that names a version the registry does not have is
        /// a skip, not a crash.
        #[tokio::test]
        async fn dependency_range_unsatisfiable_skipped() {
            let f = fixture(&[("a", &[]), ("b", &[])]);
            let ctx = ctx();

            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();

            let impossible = ArtifactRequest {
                id: ArtifactId::new(EcosystemId::npm(), None, "a"),
                spec: VersionSpec::Range("^9.0.0".into()),
                prov: ctx.prov().clone(),
            };

            let progress = node(&ctx);
            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let summary = spider
                .run(&[impossible], &walk, &ctx)
                .await
                .expect("walked");

            assert_eq!(summary.skipped, 1);
            assert!(collector.is_empty());

            // Once: `resolve` records the diagnosis, and `Spider::process`
            // acts on it without recording it again.
            assert_eq!(ctx.problems().counts()[&Code::VersionUnresolvable], 1);
        }

        /// A dependency carries the kind it was reached by, so the report can
        /// say an artifact is here only because of a dev dependency.
        #[tokio::test]
        async fn follow_edge_kind_reaches_provenance() {
            let f = fixture(&[
                ("a", &[("tool", DepKind::Dev)]),
                ("tool", &[("ghost", DepKind::Runtime)]),
            ]);

            let ctx = ctx();
            walk(&f, &ctx, &["a"], spec("runtime+dev")).await;

            let problem = ctx.problems().tail().pop().expect("recorded");
            let rendered = problem.prov().render();

            assert!(
                rendered.contains("dev dependency of pkg:npm/a"),
                "{rendered}"
            );
        }

        /// A caller walking enumerator pages across threads shares one visited
        /// set, so it has to be usable as a trait object behind an `Arc` --
        /// and both handles must see the same claims.
        #[tokio::test]
        async fn visited_set_can_be_shared() {
            let shared: Arc<dyn Visited> = Arc::new(MemoryVisited::new());
            let cloned = Arc::clone(&shared);

            let ticket = Ticket::new(0);

            assert_eq!(
                shared.mark("pkg:npm/a@1.0.0", ticket).await.unwrap(),
                Seen::First
            );
            assert_eq!(
                cloned.mark("pkg:npm/a@1.0.0", ticket).await.unwrap(),
                Seen::Already
            );

            assert_eq!(cloned.count().await.unwrap(), 1);
        }
    }

    /// What the walk reports while it runs.
    ///
    /// The load-bearing rule is that the total equals the work actually
    /// done: pruned work is never counted in, and every per-artifact node
    /// is closed.
    mod progress {
        use super::*;

        /// The property that makes a progress bar mean anything: what was
        /// promised and what was done have to come out equal. A bar that stops
        /// at 96% because skipped artifacts were counted into the total but
        /// never advanced is worse than no bar at all.
        #[tokio::test]
        async fn total_equals_work_done() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime), ("c", DepKind::Runtime)]),
                (
                    "b",
                    &[("shared", DepKind::Runtime), ("ghost", DepKind::Runtime)],
                ),
                ("c", &[("shared", DepKind::Runtime)]),
                ("shared", &[]),
            ]);

            let (ctx, log) = watched();
            let (summary, _) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            let total = log.total.load(Ordering::SeqCst);
            let advanced = log.advanced.load(Ordering::SeqCst);

            // Every kind of outcome is present here: emitted, already-seen from
            // the diamond, and skipped for the missing one.
            assert_eq!(summary.emitted, 4);
            assert_eq!(summary.already_seen, 1);
            assert_eq!(summary.skipped, 1);

            assert_eq!(
                total, advanced,
                "promised {total} artifacts and advanced {advanced}"
            );
            assert_eq!(
                advanced,
                summary.emitted + summary.already_seen + summary.skipped
            );
        }

        /// Work discarded at the depth limit must not be promised, or the bar
        /// can never reach its own end.
        #[tokio::test]
        async fn total_excludes_pruned_work() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("c", DepKind::Runtime)]),
                ("c", &[("d", DepKind::Runtime)]),
                ("d", &[]),
            ]);

            let (ctx, log) = watched();

            let spider =
                Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude)).max_depth(2);
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();
            let progress = node(&ctx);

            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let summary = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            assert!(summary.pruned >= 1);
            assert_eq!(
                log.total.load(Ordering::SeqCst),
                log.advanced.load(Ordering::SeqCst)
            );
        }

        /// A batched caller keeps one node across every page, so the totals
        /// accumulate rather than restarting -- and the spider counts the roots
        /// itself, so a caller must not.
        #[tokio::test]
        async fn total_accumulates_across_batches() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[]), ("c", &[])]);

            let (ctx, log) = watched();
            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();
            let progress = node(&ctx);

            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            spider
                .run(&[root("c", &ctx)], &walk, &ctx)
                .await
                .expect("walked");

            // a, b, then c.
            assert_eq!(log.advanced.load(Ordering::SeqCst), 3);
            assert_eq!(log.total.load(Ordering::SeqCst), 3);
        }

        /// The display stacks: the per-artifact lines hang beneath the node the
        /// caller supplied, so a `find` can nest a whole walk under its
        /// enumerator without the spider knowing anything about it.
        #[tokio::test]
        async fn node_per_artifact_nests_under_callers() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);

            let (ctx, log) = watched();
            walk(&f, &ctx, &["a"], spec("runtime")).await;

            let opened = log.opened.lock().unwrap().clone();

            // The caller's node is the root; everything else is its child.
            assert_eq!(opened[0], (None, "inspect".to_owned()));

            let children: Vec<&String> = opened[1..]
                .iter()
                .map(|(parent, label)| {
                    assert_eq!(
                        *parent,
                        Some(1),
                        "{label} should hang off the caller's node"
                    );
                    label
                })
                .collect();

            assert!(children.iter().any(|label| label.contains("pkg:npm/a")));
            assert!(children.iter().any(|label| label.contains("pkg:npm/b")));
        }

        /// An activity line has to end when its artifact does, or the display
        /// fills with stale rows over a long walk.
        #[tokio::test]
        async fn node_every_per_artifact_closed() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime), ("ghost", DepKind::Runtime)]),
                ("b", &[]),
            ]);

            let (ctx, log) = watched();
            walk(&f, &ctx, &["a"], spec("runtime")).await;

            // One per artifact processed, including the one that failed.
            let per_artifact = log.opened.lock().unwrap().len() - 1;

            assert_eq!(per_artifact, 3);
            assert!(log.closed.load(Ordering::SeqCst) as usize >= per_artifact);
        }
    }

    /// Cancellation, and why a stop is not an error: the artifacts already
    /// emitted are real, and the caller still has to write its summary.
    mod stopping {
        use super::*;

        /// A stop is not a failure. The artifacts already found are real and
        /// the caller still has a report to finish, so the walk unwinds
        /// cleanly and says why it ended.
        #[tokio::test]
        async fn stop_on_interrupt_without_failing() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime)]),
                ("b", &[("c", DepKind::Runtime)]),
                ("c", &[]),
            ]);

            let ctx = ctx();
            ctx.stop(Reason::Interrupted);

            let (summary, found) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(summary.stopped, Some(Reason::Interrupted));
            assert!(summary.was_stopped());
            assert!(found.is_empty());

            // And it says so, rather than leaving an unexplained short report.
            assert!(ctx.problems().counts()[&Code::Aborted] >= 1);
        }

        /// Stopping part-way keeps what was already found. A run interrupted
        /// after an hour must not throw away the hour.
        #[tokio::test]
        async fn stop_keeps_work_done() {
            // `a` resolves at once and `b` does not, so the stop lands while
            // the second level is genuinely in flight. With an instant fixture
            // the whole walk would finish first and the test would prove
            // nothing.
            let client = registry(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]).with(
                format!("{REGISTRY}/b"),
                Canned::ok(packument("b", &[])).slow(Duration::from_secs(30)),
            );

            let f = Fixture::build(client, |host| NpmSource::new(REGISTRY, host));

            let ctx = ctx();
            let spider = Spider::new(spec("runtime"), Criteria::new(PreRelease::Exclude));
            let visited = MemoryVisited::new();
            let frontier = MemoryFrontier::default();
            let collector = Collector::new();
            let progress = node(&ctx);

            let walk = Walk {
                licenses: None,
                screen: None,
                security: None,
                source: &f.subject,
                visited: &visited,
                frontier: &frontier,
                visitor: &collector,
                progress: &progress,
            };

            let stopper = {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    ctx.stop(Reason::Deadline);
                })
            };

            let summary = spider
                .run(&[root("a", &ctx)], &walk, &ctx)
                .await
                .expect("a stop is not an error");

            stopper.await.expect("joined");

            assert_eq!(summary.stopped, Some(Reason::Deadline));

            // The hour before the interrupt is not thrown away: `a` was found
            // and kept, even though `b` never finished.
            assert_eq!(summary.emitted, 1);
            assert_eq!(collector.purls(), ["pkg:npm/a@1.0.0"]);
        }

        /// The promptness that makes Ctrl-C feel like it worked: a task sitting
        /// in a slow fetch is dropped rather than waited out.
        #[tokio::test]
        async fn stop_does_not_wait_for_fetch_in_flight() {
            let client = registry(&[("a", &[])]).with(
                format!("{REGISTRY}/a"),
                Canned::ok(packument("a", &[])).slow(Duration::from_secs(30)),
            );

            let f = Fixture::build(client, |host| NpmSource::new(REGISTRY, host));

            let ctx = ctx();

            let stopper = {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    ctx.stop(Reason::Interrupted);
                })
            };

            let started = std::time::Instant::now();
            let (summary, _) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            stopper.await.expect("joined");

            // Seconds, not the fixture's thirty.
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "took {:?}",
                started.elapsed()
            );
            assert_eq!(summary.stopped, Some(Reason::Interrupted));
        }

        /// A download budget is one of the triggers, and it reaches the spider
        /// through the same signal as everything else.
        #[tokio::test]
        async fn stop_on_spent_budget() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);

            let ctx = ctx();
            let budget = ctx.cancel().budget(1024);

            budget.charge(2048);

            let (summary, _) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(summary.stopped, Some(Reason::Budget));
        }

        /// A fatal problem travels the same path, so one check covers both and
        /// an abort also cuts short work already in flight.
        #[tokio::test]
        async fn stop_on_fatal_problem_same_way() {
            let f = fixture(&[("a", &[])]);
            let ctx = ctx();

            // `checksum-mismatch` defaults to `abort`.
            ctx.report(
                Code::ChecksumMismatch,
                crate::core::message::Message::new("t").text("tampered"),
            );

            let (summary, _) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(summary.stopped, Some(Reason::Aborted));
        }

        /// A walk that runs to completion says so, rather than reporting a stop
        /// nobody asked for.
        #[tokio::test]
        async fn stop_absent_when_uninterrupted() {
            let f = fixture(&[("a", &[("b", DepKind::Runtime)]), ("b", &[])]);
            let ctx = ctx();

            let (summary, _) = walk(&f, &ctx, &["a"], spec("runtime")).await;

            assert_eq!(summary.stopped, None);
            assert!(!summary.was_stopped());
            assert_eq!(summary.processed(), 2);
        }

        /// The bar must not strand short of its own end at the exact moment a
        /// user is watching the run shut down.
        #[tokio::test]
        async fn stop_keeps_progress_balanced() {
            let f = fixture(&[
                ("a", &[("b", DepKind::Runtime), ("c", DepKind::Runtime)]),
                ("b", &[]),
                ("c", &[]),
            ]);

            let (ctx, log) = watched();

            let stopper = {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    ctx.stop(Reason::Interrupted);
                })
            };

            walk(&f, &ctx, &["a"], spec("runtime")).await;
            stopper.await.expect("joined");

            assert_eq!(
                log.total.load(Ordering::SeqCst),
                log.advanced.load(Ordering::SeqCst)
            );
        }

        #[tokio::test]
        async fn dependency_leaf_ends_cleanly() {
            let f = fixture(&[("a", &[("leaf", DepKind::Runtime)]), ("leaf", &[])]);
            let ctx = ctx();

            let (summary, _) = walk(&f, &ctx, &["a"], spec("all")).await;

            assert_eq!(summary.emitted, 2);
            assert_eq!(summary.skipped, 0);
        }
    }

    /// What an unsupported POM profile does to the walk.
    mod profiles {
        use super::*;
        use crate::repo::MavenSource;

        const REPO: &str = "h://repo.test/maven2";

        /// A POM whose `activeByDefault` profile adds a dependency, beside
        /// a plain one and a parent.
        const CHILD_POM: &str = r#"<project>
              <parent>
                <groupId>g</groupId><artifactId>parent</artifactId><version>1.0</version>
              </parent>
              <artifactId>child</artifactId>
              <packaging>pom</packaging>
              <dependencies><dependency>
                <groupId>g</groupId><artifactId>dep</artifactId><version>1.0</version>
              </dependency></dependencies>
              <profiles><profile>
                <id>extra</id>
                <activation><activeByDefault>true</activeByDefault></activation>
                <dependencies><dependency>
                  <groupId>g</groupId><artifactId>extra</artifactId><version>1.0</version>
                </dependency></dependencies>
              </profile></profiles>
            </project>"#;

        fn plain(name: &str) -> String {
            format!(
                "<project><groupId>g</groupId><artifactId>{name}</artifactId>\
                 <version>1.0</version><packaging>pom</packaging></project>"
            )
        }

        fn metadata(name: &str) -> String {
            format!(
                "<metadata><groupId>g</groupId><artifactId>{name}</artifactId>\
                 <versioning><versions><version>1.0</version></versions></versioning></metadata>"
            )
        }

        fn client() -> FixtureClient {
            let mut client = FixtureClient::new()
                .with_body(format!("{REPO}/g/child/1.0/child-1.0.pom"), CHILD_POM);

            for name in ["parent", "dep", "extra"] {
                client =
                    client.with_body(format!("{REPO}/g/{name}/1.0/{name}-1.0.pom"), plain(name));
            }

            for name in ["child", "parent", "dep", "extra"] {
                client = client.with_body(
                    format!("{REPO}/g/{name}/maven-metadata.xml"),
                    metadata(name),
                );
            }

            client
        }

        /// The dependency list is incomplete, so `dep` is not followed;
        /// the parent POM is, because no profile can change it.
        #[tokio::test]
        async fn stop_still_follows_parent() {
            let f = Fixture::build(client(), |host| MavenSource::new(REPO, host));
            let ctx = ctx();

            let request = ArtifactRequest {
                id: ArtifactId::new(EcosystemId::maven(), Some("g"), "child"),
                spec: VersionSpec::Exact("1.0".into()),
                prov: ctx.prov().clone(),
            };

            let (summary, found) = walk_from(&f.subject, &ctx, &[request], spec("runtime")).await;

            let mut purls = found.purls();
            purls.sort();

            assert_eq!(
                purls,
                ["pkg:maven/g/child@1.0", "pkg:maven/g/parent@1.0?type=pom"]
            );
            assert_eq!(summary.pruned, 1);
        }
    }
}
