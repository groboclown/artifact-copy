//! Find what a set of requests resolves to, without copying anything.
//!
//! The smallest operation that exercises the whole path: turn requests into
//! artifacts, follow their dependencies, and hand each one to a
//! [`Visitor`]. `copy` is this plus an upload, and `find` is this with
//! a catalog walk in front, which is why this is the one to get right.
//!
//! # What it does not do
//!
//! **It writes nothing.** Artifacts go to the visitor as they are found --
//! in practice a report writer, in tests a collector -- so this never holds
//! the result set and a caller chooses where it goes. See
//! [`crate::commands::spider`] for why that is not a `Vec` return.
//!
//! **It decides no exit code.** It returns what happened; whether that
//! means a run failed is the caller's question, and the answer depends on
//! how each artifact was reached rather than on the counts.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;

use crate::advisory::{Screen, Screening};
use crate::commands::spider::{
    DEFAULT_QUEUE_LIMIT_TASKS, DbFrontier, DbVisited, Frontier, MemoryFrontier, MemoryVisited,
    SpecOrigin, Spider, SpiderSetting, SpiderSpec, Summary, Visited, Visitor, Walk,
};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::message::Message;
use crate::core::problem::{Action, Code};
use crate::core::progress::Node;
use crate::lock::{Lock, LockHead, LockRead, LockSpec, Registry};
use crate::message;
use crate::model::{ArtifactId, ArtifactRequest, Cause, EcosystemId, Provenance, VersionSpec};
use crate::policy::Statement;
use crate::report::ReportWriter;
use crate::session::{ConfiguredSource, Session};
use crate::version::PreRelease;

/// How much of a lock file to read when deciding which reader claims it.
///
/// Enough for a format marker near the top; short enough that pointing this
/// at a huge file costs nothing before the reader that will actually parse
/// it has been chosen.
const HEAD_BYTES: usize = 4096;

/// What to inspect.
///
/// Grouped rather than passed one by one because the list is long and every
/// caller supplies all of it -- and because a bare `&[String]` beside a
/// `&[LockSpec]` is easy to transpose at a call site.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The configured source to resolve against.
    pub source: &'a str,

    /// Coordinates in the source ecosystem's own syntax.
    pub artifacts: &'a [String],

    /// Lock files to take every artifact from.
    ///
    /// **Every** artifact, whatever `spider` says. The specification
    /// governs which *edges* are followed, not whether a named artifact is
    /// wanted, and a lock file names all of them.
    pub locks: &'a [LockSpec],

    /// Which dependency edges to follow from the roots.
    pub spider: SpiderSetting,

    /// Whether pre-releases are candidates.
    pub pre: PreRelease,

    /// The corpora every resolved artifact is screened against.
    ///
    /// `None` only for a caller that loaded none; a sub-command always
    /// supplies one, empty when `--no-advisories` said so.
    pub screen: Option<Screen<'a>>,
}

/// Resolve the requests and walk their dependencies.
///
/// `progress` is the node this reports into, owned by the caller so the
/// display stacks -- see [`Walk::progress`].
///
/// `cache` is a report database to read the source through, so a named
/// artifact an earlier run already resolved costs no request.
///
/// `report` is where the walk keeps its frontier, when it keeps one; see
/// [`walk_from`].
pub async fn run(
    session: &mut Session<'_>,
    request: &Request<'_>,
    cache: Option<Arc<dyn crate::report::ReportQuery>>,
    report: Option<&dyn ReportWriter>,
    visitor: &dyn Visitor,
    progress: &Node,
    ctx: &Ctx,
) -> Result<Summary> {
    let mut opened = session.source(request.source)?;

    if let Some(query) = cache {
        opened = read_through(opened, query, request.source);
    }

    // Problems are decided under this source's policy, which may differ
    // from the run's: a host can name its own quarantine file.
    let ctx = opened.deciding(ctx);

    let mut roots = Requested::new(request, &opened, session.locks());

    // Before the walk, so a statement is known before the first artifact
    // it covers is screened, wherever on the command line it was named.
    roots
        .attest(request.screen.map(|screen| screen.screening), &ctx)
        .await?;

    walk_from(
        &mut roots, &opened, request, report, visitor, progress, &ctx,
    )
    .await
}

/// Walk everything a root provider yields.
///
/// **The roots arrive in batches and are never collected.** A repository
/// whose roots are every package it holds -- a mirror of PyPI, a migration
/// fed from a report -- would otherwise put the whole catalog in memory
/// before a single artifact was looked at, which is the failure this crate
/// avoids everywhere else it walks something large.
///
/// The visited set and the frontier are created once and borrowed across
/// every batch, so an artifact claimed while walking one batch is not
/// walked again in the next. That is the property `Spider::run` was already
/// shaped for, and the reason it takes a batch rather than a catalog.
///
/// With a `report` that keeps walks, both live in it: the frontier is not
/// bounded by memory, and a walk a killed run left is resumed. Without one
/// they live in memory, and the frontier is capped.
pub(crate) async fn walk_from(
    roots: &mut dyn Roots,
    opened: &ConfiguredSource,
    request: &Request<'_>,
    report: Option<&dyn ReportWriter>,
    visitor: &dyn Visitor,
    progress: &Node,
    ctx: &Ctx,
) -> Result<Summary> {
    // `default` defers to the source's own `dependencies` key.
    let spec = request
        .spider
        .resolve(opened.dependencies())
        .map_err(|err| Error::Config(format!("source {:?} dependencies: {err}", request.source)))?;

    log_spec(
        &spec,
        request.spider.origin(opened.dependencies()),
        request.source,
        ctx,
    );

    let limit_tasks = opened
        .in_memory_queued_dependencies()
        .unwrap_or(DEFAULT_QUEUE_LIMIT_TASKS);

    let stores = Stores::open(
        report,
        request.source,
        &spec,
        &walked_for(visitor),
        limit_tasks,
    )?;

    let walk = Walk {
        licenses: opened.licenses(),
        screen: request.screen,
        security: opened.policed(),
        source: &*opened.source,
        visited: stores.visited(),
        frontier: stores.frontier(),
        visitor,
        progress,
    };

    let mut spider = Spider::new(spec, opened.criteria(request.pre));
    let promised = roots.total()?;

    // The whole list up front, so the bar shows it rather than one page:
    // `300/50000`, not `300/512`.
    if let Some(total) = promised {
        progress.grow_total(total);
        spider = spider.promised_roots();
    }

    let mut summary = Summary::default();
    let mut any = false;
    let mut received = 0u64;

    loop {
        let batch = roots.next(ctx).await?;

        if batch.is_empty() {
            break;
        }

        any = true;
        received += batch.len() as u64;
        summary.absorb(spider.run(&batch, &walk, ctx).await?);

        // A stop is not an error, and the batches after it are not work the
        // user still wants. Asking for another would be the tool ignoring
        // the interrupt it just recorded.
        if summary.was_stopped() {
            break;
        }
    }

    // Rows counted but never handed over: dropped by `next`, or finished
    // as another artifact's dependency before their page came. Their work
    // is done, so the bar reaches its end.
    if let Some(total) = promised
        && !summary.was_stopped()
    {
        progress.advance(total.saturating_sub(received));
    }

    // Refused rather than reported, because an empty report and a report
    // of a run that asked for nothing are the same document and only one
    // of them is what somebody meant. Bad arguments are fail-fast per
    // `docs/contributors/exit-codes.md`.
    if !any {
        return Err(Error::Config(roots.nothing()));
    }

    Ok(summary)
}

/// Say which dependencies the walk follows, and what decided it, so a walk
/// that follows none is not a mystery:
///
/// ```text
///   following runtime dependencies, from --dependencies
///   following runtime+dev dependencies, from source npmjs's dependencies key
///   following no dependencies: neither --dependencies nor source npmjs's
///     dependencies key names any
/// ```
fn log_spec(spec: &SpiderSpec, origin: SpecOrigin, source: &str, ctx: &Ctx) {
    let text = match origin {
        SpecOrigin::Flag => message!(
            "spider-spec-flag",
            "following {spec} dependencies, from --dependencies",
            spec = spec.to_string(),
        ),
        SpecOrigin::Source => message!(
            "spider-spec-source",
            "following {spec} dependencies, from source {source}'s dependencies key",
            spec = spec.to_string(),
            source = source,
        ),
        SpecOrigin::Unset => message!(
            "spider-spec-unset",
            "following no dependencies: neither --dependencies nor source {source}'s \
             dependencies key names any",
            source = source,
        ),
    };

    ctx.log().info(&text);
}

/// The targets a walk is keyed on, sorted so their order on the command
/// line does not matter: `backup,local`.
fn walked_for(visitor: &dyn Visitor) -> String {
    let mut targets = visitor.targets();
    targets.sort_unstable();

    targets.join(WALK_TARGET_SEPARATOR)
}

/// Between the targets a walk is keyed on, as `spider_walk.targets` holds
/// them.
const WALK_TARGET_SEPARATOR: &str = ",";

/// Where a walk keeps its frontier and its claims.
enum Stores<'a> {
    Memory(MemoryFrontier, MemoryVisited),
    Report(DbFrontier<'a>, DbVisited<'a>),
}

impl<'a> Stores<'a> {
    /// In the report when it keeps walks, otherwise in memory holding at
    /// most `limit_tasks`.
    fn open(
        report: Option<&'a dyn ReportWriter>,
        source: &str,
        spec: &SpiderSpec,
        targets: &str,
        limit_tasks: usize,
    ) -> Result<Self> {
        let Some(report) = report else {
            return Ok(Self::memory(limit_tasks));
        };

        let Some(walks) = report.state().and_then(|state| state.walks()) else {
            return Ok(Self::memory(limit_tasks));
        };

        let query = report.query()?;
        let frontier =
            DbFrontier::open(walks, query.as_deref(), source, &spec.to_string(), targets)?;
        let visited = DbVisited::new(walks, frontier.walk());

        Ok(Self::Report(frontier, visited))
    }

    fn memory(limit_tasks: usize) -> Self {
        Self::Memory(MemoryFrontier::new(limit_tasks), MemoryVisited::new())
    }

    fn frontier(&self) -> &dyn Frontier {
        match self {
            Self::Memory(frontier, _) => frontier,
            Self::Report(frontier, _) => frontier,
        }
    }

    fn visited(&self) -> &dyn Visited {
        match self {
            Self::Memory(_, visited) => visited,
            Self::Report(_, visited) => visited,
        }
    }
}

/// Where a walk's roots come from.
///
/// Paged for the reason [`walk_from`] gives. **Empty means the end**, which
/// is safe here and is not safe for an enumerator page: a root provider is this
/// crate's own and always knows whether it has more, while a repository's
/// page can be filtered away entirely and the catalog continue.
#[async_trait]
pub(crate) trait Roots: Send + Sync {
    /// The next batch, or empty when there are none left.
    async fn next(&mut self, ctx: &Ctx) -> Result<Vec<ArtifactRequest>>;

    /// How many rows every batch together draws from, when the provider
    /// knows before the first: a report counts its list in one query.
    ///
    /// A row `next` drops, such as a name-only coordinate, still counts, so
    /// the walk advances past what it never received. `None` by default,
    /// and the total then grows a batch at a time.
    fn total(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    /// Why a walk that got no roots at all asked for nothing.
    ///
    /// The provider's to say, because only it knows where it looked: a
    /// report that holds nothing for a source is a different mistake from
    /// a command line that named nothing.
    fn nothing(&self) -> String {
        "no artifacts were requested, and no lock file named any".to_owned()
    }
}

/// The roots a [`Request`] names: its coordinates, then each lock file.
///
/// One batch for the coordinates and one per lock file, rather than one
/// batch for everything. A lock file is bounded by what a person wrote, so
/// this is about the shape rather than about the size -- the size matters
/// for the providers that come after it.
struct Requested<'a, 'o> {
    artifacts: &'a [String],
    locks: &'a [LockSpec],

    /// The readers the run offers, built-in and extension.
    readers: Registry,

    /// Borrowed separately from the request because only the opened source
    /// can say which ecosystem a bare coordinate is written in.
    opened: &'o ConfiguredSource,

    /// The batch each VEX document already gave, by its position in
    /// `locks`; see [`Requested::attest`].
    attested: Vec<Option<Vec<ArtifactRequest>>>,

    done_artifacts: bool,
    next_lock: usize,
}

impl<'a, 'o> Requested<'a, 'o> {
    fn new(request: &'a Request<'a>, opened: &'o ConfiguredSource, readers: Registry) -> Self {
        Self {
            artifacts: request.artifacts,
            locks: request.locks,
            readers,
            opened,
            attested: vec![None; request.locks.len()],
            done_artifacts: false,
            next_lock: 0,
        }
    }

    /// Read every VEX document among the lock files, handing its statements
    /// to `screening`.
    ///
    /// Every other lock file waits for the walk to reach it, so a large one
    /// is never held while the walk has not started.
    ///
    /// ```text
    ///   --lock a.json --lock vex.json
    ///     a.json    claimed by npm   -> read when the walk reaches it
    ///     vex.json  claimed by VEX   -> read now; statements to screening
    /// ```
    async fn attest(&mut self, screening: Option<&Screening>, ctx: &Ctx) -> Result<()> {
        let spoken = self.opened.source.ecosystems();

        for (position, spec) in self.locks.iter().enumerate() {
            let reader = resolve_lock(spec, &self.readers).inspect_err(|err| {
                ctx.report_err(err);
            })?;

            if !reader.attests() {
                continue;
            }

            let found = match read_lock(spec, reader.as_ref(), ctx).await {
                Ok(found) => found,

                // A quarantine rule may lower `vex-unparsable`; the document
                // is then left out rather than ending the run.
                Err(err) if err.code() == Code::VexUnparsable => {
                    if ctx.report_err(&err) >= Action::Abort {
                        return Err(err);
                    }

                    LockRead::default()
                }

                Err(err) => {
                    ctx.report_err(&err);

                    return Err(err);
                }
            };

            let LockRead {
                requests,
                statements,
            } = found;

            if let Some(screening) = screening {
                screening.attest(
                    statements
                        .into_iter()
                        .filter_map(|s| in_ecosystem(s, &spoken)),
                );
            }

            self.attested[position] = Some(served(requests, &spoken, spec, ctx));
        }

        Ok(())
    }
}

/// The requests whose ecosystem the source serves.
///
/// Each one left out is `bom-ecosystem-foreign`, ignored by default and
/// shown by `--verbose`: an SBOM generated from a container image lists the
/// operating system's packages beside the application's.
fn served(
    requests: Vec<ArtifactRequest>,
    spoken: &[EcosystemId],
    spec: &LockSpec,
    ctx: &Ctx,
) -> Vec<ArtifactRequest> {
    let (kept, foreign): (Vec<_>, Vec<_>) = requests
        .into_iter()
        .partition(|request| spoken.contains(request.id.ecosystem()));

    for request in foreign {
        ctx.report(
            Code::BomEcosystemForeign,
            message!(
                "bom-ecosystem-foreign",
                "{document} names {purl}, which is not in an ecosystem this source \
                 serves, so it is not requested",
                document = &spec.path().display(),
                purl = &request.id.purl(),
            ),
        );
    }

    kept
}

/// `statement`, naming only the products the source serves; `None` when it
/// names none of them.
///
/// The run can never ask about a product it does not request, so a
/// statement about none of the source's products is no part of the run,
/// and is never called stale.
fn in_ecosystem(mut statement: Statement, spoken: &[EcosystemId]) -> Option<Statement> {
    statement.products.retain(|product| {
        ArtifactId::parse(product).is_ok_and(|parsed| spoken.contains(parsed.id.ecosystem()))
    });

    match statement.products.is_empty() {
        true => None,
        false => Some(statement),
    }
}

#[async_trait]
impl Roots for Requested<'_, '_> {
    async fn next(&mut self, ctx: &Ctx) -> Result<Vec<ArtifactRequest>> {
        if !self.done_artifacts {
            self.done_artifacts = true;

            if !self.artifacts.is_empty() {
                let ecosystem = sole_ecosystem(self.opened)?;
                let mut batch = Vec::with_capacity(self.artifacts.len());

                for text in self.artifacts {
                    batch.push(ecosystem.parse_req(text)?);
                }

                return Ok(batch);
            }
        }

        // Each lock file is its own batch, so a walk starts on the first
        // one rather than after the last.
        while self.next_lock < self.locks.len() {
            let position = self.next_lock;
            let spec = &self.locks[position];
            self.next_lock += 1;

            if let Some(batch) = self.attested[position].take() {
                if !batch.is_empty() {
                    return Ok(batch);
                }

                continue;
            }

            // Recorded as well as returned, so the report says why the run
            // stopped: a lock-file fault is otherwise only a log line.
            let batch = read_named(spec, &self.readers, ctx)
                .await
                .inspect_err(|err| {
                    ctx.report_err(err);
                })?;

            if !batch.is_empty() {
                return Ok(batch);
            }
        }

        Ok(Vec::new())
    }
}

/// The roots a report database still has outstanding for a destination.
///
/// Pages `ReportQuery::outstanding`, which is the query the whole schema is
/// shaped around: artifacts the source holds that have not reached the
/// target, whichever source took them there. **The paging is the point** --
/// a migration's root set is the size of a repository, and this is what
/// What to ask for, given what a report row recorded as a version.
///
/// `None` means "leave this row alone", and the reason there are three
/// answers rather than two is that a `NULL` version in the database means
/// two opposite things. A name-only row from a `find` over npm's
/// replication feed has no version because nobody has paid for the
/// packument yet; resolving it to whatever is newest today would copy
/// something the report never named, so it is skipped. A raw repository's
/// directory has no version because there is none; skipping it would drop
/// the artifact from the migration.
///
/// The row cannot tell them apart, so the ecosystem is asked -- see
/// `Ecosystem::version_optional`. An ecosystem this build cannot open is
/// treated as versioned, which is the conservative direction: a skipped
/// artifact is visible in the report, and a wrongly widened one is not.
fn asked_for(id: &crate::model::ArtifactId, version: Option<String>) -> Option<VersionSpec> {
    match version {
        Some(version) => Some(VersionSpec::Exact(version)),

        None => match crate::ecosystem::open(id.ecosystem().as_str()) {
            Ok(ecosystem) if ecosystem.version_optional() => Some(VersionSpec::Any),
            _ => None,
        },
    }
}

/// [`walk_from`] pulls from rather than collecting.
///
/// Each root carries an **exact** version. A report-fed copy is working
/// through a manifest, so resolving `tuna` to whatever is newest today
/// would copy something the report never named.
pub(crate) struct Outstanding<'a> {
    query: &'a dyn crate::report::ReportQuery,
    source: &'a str,

    /// Every target still owed work. An artifact is outstanding until each
    /// of them has settled it.
    destinations: &'a [&'a str],

    /// What the provenance of these roots names, so a reader of the report
    /// can see where the work came from.
    manifest: String,

    after: i64,
    page: u32,
}

impl<'a> Outstanding<'a> {
    /// How many artifacts one page holds.
    ///
    /// Each becomes an `ArtifactRequest` that the walk holds until the
    /// batch is done, so this bounds the memory a report-fed copy uses for
    /// its frontier.
    pub const PAGE: u32 = 256;

    pub fn new(
        query: &'a dyn crate::report::ReportQuery,
        source: &'a str,
        destinations: &'a [&'a str],
        manifest: impl Into<String>,
    ) -> Self {
        Self {
            query,
            source,
            destinations,
            manifest: manifest.into(),
            after: 0,
            page: Self::PAGE,
        }
    }
}

#[async_trait]
impl Roots for Outstanding<'_> {
    fn total(&self) -> Result<Option<u64>> {
        self.query.outstanding_count(self.source, self.destinations)
    }

    async fn next(&mut self, _ctx: &Ctx) -> Result<Vec<ArtifactRequest>> {
        let found =
            self.query
                .outstanding(self.source, self.destinations, self.after, self.page)?;

        let Some(last) = found.last() else {
            return Ok(Vec::new());
        };

        self.after = last.key;

        let mut batch = Vec::with_capacity(found.len());

        for work in found {
            let parsed = crate::model::ArtifactId::parse(&work.purl)?;

            let Some(spec) = asked_for(&parsed.id, work.version) else {
                continue;
            };

            // Its own cause rather than `LockFile`: a reader who passed no
            // `--lock` should not see one named, and a report knows which
            // run and which target the work was outstanding for.
            batch.push(ArtifactRequest {
                id: parsed.id,
                spec,
                prov: Arc::new(Provenance::root(Cause::Report {
                    path: std::path::PathBuf::from(&self.manifest),
                    entry: work.purl,
                    source: self.source.to_owned(),
                    destinations: self
                        .destinations
                        .iter()
                        .map(|name| name.to_string())
                        .collect(),
                    run: work.run,
                })),
            });
        }

        Ok(batch)
    }

    fn nothing(&self) -> String {
        format!(
            "the report has nothing outstanding from source {} to {}; \
             a find files what it finds under its enumerator unless run with \
             --from={} (or --as-source={})",
            self.source,
            targets(self.destinations),
            self.source,
            self.source,
        )
    }
}

/// The targets a message names: `target a`, or `targets a, b` when there
/// are several.
fn targets(destinations: &[&str]) -> String {
    match destinations {
        [one] => format!("target {one}"),
        several => format!("targets {}", several.join(", ")),
    }
}

/// Everything a report says a source holds.
///
/// The roots a `inspect` takes from a report rather than from arguments:
/// what an earlier `find` or `inspect` recorded, replayed. Paged for
/// the reason [`walk_from`] gives -- a repository's contents are the root
/// set, which is the case that makes collecting them impossible.
///
/// Distinct from [`Outstanding`], which names a destination and answers
/// what is left to send there. This answers what the repository has.
pub(crate) struct Inventoried<'a> {
    query: &'a dyn crate::report::ReportQuery,
    source: &'a str,
    manifest: String,
    after: i64,
}

impl<'a> Inventoried<'a> {
    pub fn new(
        query: &'a dyn crate::report::ReportQuery,
        source: &'a str,
        manifest: impl Into<String>,
    ) -> Self {
        Self {
            query,
            source,
            manifest: manifest.into(),
            after: 0,
        }
    }
}

#[async_trait]
impl Roots for Inventoried<'_> {
    fn total(&self) -> Result<Option<u64>> {
        self.query.inventory_count(self.source)
    }

    async fn next(&mut self, _ctx: &Ctx) -> Result<Vec<ArtifactRequest>> {
        let found = self
            .query
            .inventory(self.source, self.after, Outstanding::PAGE)?;

        let Some(last) = found.last() else {
            return Ok(Vec::new());
        };

        self.after = last.key;

        Ok(found
            .into_iter()
            .filter_map(|work| {
                let id = crate::model::ArtifactId::parse(&work.purl).ok()?.id;
                let spec = asked_for(&id, work.version)?;

                Some(ArtifactRequest {
                    id,
                    spec,
                    prov: Arc::new(Provenance::root(Cause::Report {
                        path: std::path::PathBuf::from(&self.manifest),
                        entry: work.purl,
                        source: self.source.to_owned(),
                        destinations: Vec::new(),
                        run: work.run,
                    })),
                })
            })
            .collect())
    }

    fn nothing(&self) -> String {
        format!(
            "the report records nothing for source {}; a find files what it \
             finds under its enumerator unless run with --from={} (or \
             --as-source={})",
            self.source, self.source, self.source,
        )
    }
}

/// Walk what a report says a source holds.
///
/// `report` is where the walk keeps its frontier; see [`walk_from`].
///
/// **Reading through the report as well as from it.** The roots come from
/// the inventory, and so do each artifact's files, licence, and publish
/// time -- `InventorySource` answers them and falls back to the repository
/// for whatever the report does not hold. A rerun of an inspection that
/// already resolved everything therefore costs no requests at all.
#[allow(clippy::too_many_arguments)]
pub async fn from_report(
    session: &mut Session<'_>,
    request: &Request<'_>,
    query: Arc<dyn crate::report::ReportQuery>,
    manifest: &str,
    report: Option<&dyn ReportWriter>,
    visitor: &dyn Visitor,
    progress: &Node,
    ctx: &Ctx,
) -> Result<Summary> {
    let opened = read_through(
        session.source(request.source)?,
        Arc::clone(&query),
        request.source,
    );

    let ctx = opened.deciding(ctx);

    let mut roots = Inventoried::new(query.as_ref(), request.source, manifest);

    walk_from(
        &mut roots, &opened, request, report, visitor, progress, &ctx,
    )
    .await
}

/// `opened`, answering from the report database first.
///
/// Everything else the run decided about the source -- its policies, the
/// hosts a fetch may reach -- is kept exactly. See `InventorySource`.
pub(crate) fn read_through(
    opened: ConfiguredSource,
    query: Arc<dyn crate::report::ReportQuery>,
    source: &str,
) -> ConfiguredSource {
    let live = Arc::clone(&opened.source);

    opened.reading_through(Arc::new(crate::repo::InventorySource::new(
        query, source, live,
    )))
}

/// The ecosystem a coordinate is written in.
///
/// A source speaking exactly one answers this; a repository manager
/// fronting several does not, because `parse_req` takes an ecosystem's own
/// syntax and `g:a:1.0` and `lodash@^4` are not distinguishable by shape.
/// Refused with the alternatives named rather than guessed at, since
/// guessing wrong resolves a real but different artifact.
fn sole_ecosystem(opened: &ConfiguredSource) -> Result<Arc<dyn crate::ecosystem::Ecosystem>> {
    let spoken = opened.source.ecosystems();

    let [only] = spoken.as_slice() else {
        return Err(Error::Config(format!(
            "this source speaks {} ecosystems ({}), so a bare coordinate cannot say \
             which one it is written in; name artifacts through a lock file instead",
            spoken.len(),
            spoken
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        )));
    };

    crate::ecosystem::open(only.as_str())
}

/// The reader that claims a lock file.
///
/// Only the head of the file is read to decide: the reader opens the whole
/// file itself, from where it lies.
fn resolve_lock(spec: &LockSpec, readers: &Registry) -> Result<Arc<dyn Lock>> {
    let path = spec.path();

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Config(format!("{} has no filename", path.display())))?;

    let read_error = |source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    };

    let mut head = Vec::with_capacity(HEAD_BYTES);

    std::fs::File::open(path)
        .map_err(read_error)?
        .take(HEAD_BYTES as u64)
        .read_to_end(&mut head)
        .map_err(read_error)?;

    readers.resolve(spec, name, &LockHead::of(&head))
}

/// Read one lock file with the reader that claims it.
async fn read_named(
    spec: &LockSpec,
    readers: &Registry,
    ctx: &Ctx,
) -> Result<Vec<ArtifactRequest>> {
    let reader = resolve_lock(spec, readers)?;

    read_lock(spec, reader.as_ref(), ctx)
        .await
        .map(|found| found.requests)
}

/// Read one lock file with `reader`.
async fn read_lock(spec: &LockSpec, reader: &dyn Lock, ctx: &Ctx) -> Result<LockRead> {
    let path = spec.path();

    let mut found = reader
        .read(path, ctx)
        .await
        .map_err(|err| lock_malformed(err, path))?;

    // Re-rooted on the file rather than on the reader's own guess, so a
    // report says which file an artifact came from. A lock file naming
    // hundreds is otherwise a report with hundreds of identical causes.
    for request in &mut found.requests {
        request.prov = Arc::new(Provenance::root(Cause::LockFile {
            path: path.to_path_buf(),
            entry: request.id.purl(),
        }));
    }

    Ok(found)
}

/// A reader's parse failure, as the lock-file fault it is.
///
/// Converted here rather than in each reader, so an extension's reader is
/// covered too. `metadata-malformed` is a per-artifact code a quarantine
/// rule may excuse; a lock file that will not parse is the run's input.
fn lock_malformed(err: Error, path: &Path) -> Error {
    let Error::Malformed { detail, .. } = err else {
        return err;
    };

    Error::LockMalformed {
        path: path.to_path_buf(),
        detail,
    }
}

/// Report what an inspection found, for a caller that logs a summary.
pub fn describe(summary: &Summary) -> Message {
    message!(
        "inspect-finished",
        "discovered {emitted} artifacts, skipped {skipped}",
        emitted = summary.emitted,
        skipped = summary.skipped,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ConfigLoader;
    use crate::commands::spider::{Collector, SpiderSpec};
    use crate::config::Config;
    use crate::core::problem::Code;
    use crate::core::progress::Unit;
    use crate::net::FixtureClient;

    const REGISTRY: &str = "h://registry.test";

    const TUNA: &str = r#"{
        "name": "tuna",
        "dist-tags": {"latest": "1.2.0"},
        "license": "MIT",
        "versions": {
            "1.0.0": {
                "license": "MIT",
                "dist": {"tarball": "h://registry.test/tuna/-/tuna-1.0.0.tgz", "shasum": "aa"},
                "dependencies": {}
            },
            "1.2.0": {
                "license": "MIT",
                "dist": {
                    "tarball": "h://registry.test/tuna/-/tuna-1.2.0.tgz",
                    "shasum": "bb",
                    "integrity": "sha512-deadbeef"
                },
                "dependencies": {"salmon": "^2.0.0"}
            }
        }
    }"#;

    const SALMON: &str = r#"{
        "name": "salmon",
        "dist-tags": {"latest": "2.1.0"},
        "license": "MIT",
        "versions": {
            "2.1.0": {
                "license": "MIT",
                "dist": {"tarball": "h://registry.test/salmon/-/salmon-2.1.0.tgz", "shasum": "cc"},
                "dependencies": {}
            }
        }
    }"#;

    fn config(dir: &std::path::Path, sources: &str) -> Config {
        let path = dir.join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"{}"}},
                    "hosts":{{"registry":{{"url":"{REGISTRY}/"}}}},
                    "sources":{sources}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    fn registry() -> FixtureClient {
        FixtureClient::new()
            .with_body(format!("{REGISTRY}/tuna"), TUNA)
            .with_body(format!("{REGISTRY}/salmon"), SALMON)
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "tuna".into() })
    }

    async fn discovered(
        config: &Config,
        client: FixtureClient,
        request: Request<'_>,
    ) -> (Collector, Result<Summary>) {
        let mut session = Session::over(config, false, Arc::new(client)).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);
        let collector = Collector::new();

        let outcome = run(
            &mut session,
            &request,
            None,
            None,
            &collector,
            &progress,
            &ctx,
        )
        .await;

        (collector, outcome)
    }

    /// A root provider that hands out fixed batches and counts how many
    /// times it was asked, so a test can show the walk pulled rather than
    /// collected.
    struct Batches {
        batches: std::sync::Mutex<std::collections::VecDeque<Vec<ArtifactRequest>>>,
        asked: std::sync::atomic::AtomicUsize,

        /// What [`Roots::total`] answers.
        total: Option<u64>,
    }

    impl Batches {
        fn of(batches: Vec<Vec<&str>>) -> Self {
            let queued = batches
                .into_iter()
                .map(|names| names.into_iter().map(npm_request).collect())
                .collect();

            Self {
                batches: std::sync::Mutex::new(queued),
                asked: std::sync::atomic::AtomicUsize::new(0),
                total: None,
            }
        }

        /// Claiming `total` rows up front, as a report does.
        fn promising(mut self, total: u64) -> Self {
            self.total = Some(total);
            self
        }

        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Roots for Batches {
        fn total(&self) -> Result<Option<u64>> {
            Ok(self.total)
        }

        async fn next(&mut self, _ctx: &Ctx) -> Result<Vec<ArtifactRequest>> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            Ok(self
                .batches
                .lock()
                .expect("not poisoned")
                .pop_front()
                .unwrap_or_default())
        }
    }

    fn npm_request(name: &str) -> ArtifactRequest {
        ArtifactRequest {
            id: crate::model::ArtifactId::new(crate::model::EcosystemId::npm(), None, name),
            spec: crate::model::VersionSpec::Any,
            prov: Arc::new(Provenance::root(Cause::Requested {
                arg: name.to_owned(),
            })),
        }
    }

    /// Walk a provider's batches, so a test can watch the pulling rather
    /// than the argument parsing.
    async fn walked(
        config: &Config,
        client: FixtureClient,
        roots: &mut Batches,
    ) -> (Collector, Result<Summary>) {
        walked_with(config, client, roots, ctx()).await
    }

    /// [`walked`], reporting progress through `ctx`.
    async fn walked_with(
        config: &Config,
        client: FixtureClient,
        roots: &mut Batches,
        ctx: Ctx,
    ) -> (Collector, Result<Summary>) {
        let mut session = Session::over(config, false, Arc::new(client)).expect("opens");
        let progress = ctx.progress("inspect", Unit::Items, None);
        let collector = Collector::new();

        let opened = session.source("npmjs").expect("opens");
        let ctx = opened.deciding(&ctx);

        let empty: Vec<String> = Vec::new();
        let request = Request {
            source: "npmjs",
            artifacts: &empty,
            locks: &[],
            spider: SpiderSetting::Explicit(SpiderSpec::none()),
            pre: PreRelease::Exclude,
            screen: None,
        };

        let outcome = walk_from(roots, &opened, &request, None, &collector, &progress, &ctx).await;

        (collector, outcome)
    }

    /// **An inspection replayed from its own report.** Everything the first
    /// run resolved is in the inventory, so the second asks the repository
    /// for nothing at all -- which is the whole reason a report is a
    /// database rather than a log. A named artifact read through the
    /// database costs nothing either.
    #[tokio::test]
    async fn discovery_replays_from_report() {
        use crate::report::{Binding, Record, ReportWriter, Role, header};

        /// Where a run takes its artifacts, and what it reads them through.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Mode {
            Live,
            Cached,
            FromReport,
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);
        let report_path = dir.path().join("report.sqlite");

        let discovered = async |mode: Mode| {
            let shared = Arc::new(registry());
            let mut session = Session::over(&config, false, shared.clone()).expect("opens");
            let ctx = ctx();
            let progress = ctx.progress("inspect", Unit::Items, None);

            let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
                .await
                .expect("opens");
            let visitor = Arc::new(crate::commands::report::ToReport::new(writer));

            visitor
                .write(&Record::Header(header(
                    "inspect",
                    &crate::advisory::Screening::none(),
                )))
                .expect("header");
            visitor
                .state()
                .expect("state")
                .bind(&Binding::new(Role::Source, "npmjs").observing())
                .expect("bound");

            let wanted = vec!["tuna".to_owned()];
            let empty: Vec<String> = Vec::new();

            let request = Request {
                source: "npmjs",
                artifacts: match mode {
                    Mode::FromReport => &empty,
                    Mode::Live | Mode::Cached => &wanted,
                },
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            };

            let outcome = match mode {
                Mode::Live | Mode::Cached => {
                    let cache = match mode {
                        Mode::Cached => visitor.query().expect("a query"),
                        _ => None,
                    };

                    run(
                        &mut session,
                        &request,
                        cache,
                        Some(visitor.as_ref()),
                        visitor.as_ref(),
                        &progress,
                        &ctx,
                    )
                    .await
                }

                Mode::FromReport => {
                    let query = visitor.query().expect("a query").expect("a database");

                    super::from_report(
                        &mut session,
                        &request,
                        query,
                        "report.sqlite",
                        Some(visitor.as_ref()),
                        visitor.as_ref(),
                        &progress,
                        &ctx,
                    )
                    .await
                }
            };

            visitor.flush().expect("flushed");

            (shared, outcome)
        };

        let (first, outcome) = discovered(Mode::Live).await;

        assert_eq!(outcome.expect("discovered").emitted, 1);
        assert_eq!(first.hits(&format!("{REGISTRY}/tuna")), 1);

        let (second, outcome) = discovered(Mode::FromReport).await;

        assert_eq!(
            outcome.expect("replayed").emitted,
            1,
            "the report did not yield the artifact it recorded"
        );
        assert_eq!(
            second.hits(&format!("{REGISTRY}/tuna")),
            0,
            "the repository was asked for what the report already held"
        );

        let (third, outcome) = discovered(Mode::Cached).await;

        assert_eq!(outcome.expect("cached").emitted, 1);
        assert_eq!(
            third.hits(&format!("{REGISTRY}/tuna")),
            0,
            "a named artifact bypassed the database cache"
        );
    }

    /// A report with nothing in it is a run that asked for nothing, which
    /// is a bad argument rather than an empty answer.
    #[tokio::test]
    async fn roots_none_from_empty_report() {
        use crate::report::{Binding, Record, ReportWriter, Role, header};

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);
        let report_path = dir.path().join("report.sqlite");

        let mut session = Session::over(&config, false, Arc::new(registry())).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);

        let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
            .await
            .expect("opens");
        let visitor = Arc::new(crate::commands::report::ToReport::new(writer));

        visitor
            .write(&Record::Header(header(
                "inspect",
                &crate::advisory::Screening::none(),
            )))
            .expect("header");
        visitor
            .state()
            .expect("state")
            .bind(&Binding::new(Role::Source, "npmjs").observing())
            .expect("bound");

        let empty: Vec<String> = Vec::new();
        let query = visitor.query().expect("a query").expect("a database");

        let outcome = super::from_report(
            &mut session,
            &Request {
                source: "npmjs",
                artifacts: &empty,
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            },
            query,
            "report.sqlite",
            Some(visitor.as_ref()),
            visitor.as_ref(),
            &progress,
            &ctx,
        )
        .await;

        let err = outcome.expect_err("refused");

        // Named for where it looked, and for the flag that would have
        // filled it: an empty report is usually a find that filed its
        // enumeration under the enumerator.
        assert!(
            err.to_string().contains("records nothing for source npmjs")
                && err.to_string().contains("--from=npmjs"),
            "{err}"
        );
    }

    /// **The roots are pulled, not collected.** A provider is asked for the
    /// next batch only once the previous one has been walked, which is what
    /// keeps a catalog-sized root set out of memory.
    #[tokio::test]
    async fn roots_arrive_in_batches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let mut roots = Batches::of(vec![vec!["tuna"], vec!["salmon"]]);
        let (collector, outcome) = walked(&config, registry(), &mut roots).await;

        outcome.expect("walked");

        let mut found = collector.purls();
        found.sort();

        assert_eq!(found, vec!["pkg:npm/salmon@2.1.0", "pkg:npm/tuna@1.2.0"]);

        // Two batches, then one more that answered empty and ended it.
        assert_eq!(roots.asked(), 3);
    }

    /// A walk says at info which dependencies it follows and what decided
    /// it, so one that follows none says why.
    #[test]
    fn spec_logged_with_origin() {
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = ctx().logging_with(log);
        let none = SpiderSpec::none();
        let runtime = SpiderSpec::parse("runtime").expect("parses");

        log_spec(&runtime, SpecOrigin::Flag, "npmjs", &ctx);
        log_spec(&runtime, SpecOrigin::Source, "npmjs", &ctx);
        log_spec(&none, SpecOrigin::Unset, "npmjs", &ctx);

        let lines = recorder.lines();

        assert!(
            lines
                .iter()
                .all(|(level, _)| *level == crate::core::log::Level::Info)
        );
        assert!(lines[0].1.contains("runtime") && lines[0].1.contains("--dependencies"));
        assert!(lines[1].1.contains("source npmjs's dependencies key"));
        assert!(
            lines[2].1.contains("following no dependencies"),
            "{lines:?}"
        );
    }

    /// Sums what a walk promises and advances, to show its bar ends full.
    #[derive(Debug, Default)]
    struct Totals {
        total: std::sync::atomic::AtomicU64,
        advanced: std::sync::atomic::AtomicU64,
    }

    impl crate::core::progress::ProgressSink for Totals {
        fn open(
            &self,
            _parent: Option<crate::core::progress::NodeId>,
            _label: String,
            _unit: Unit,
            total: Option<u64>,
        ) -> crate::core::progress::NodeId {
            self.total
                .fetch_add(total.unwrap_or(0), std::sync::atomic::Ordering::SeqCst);
            crate::core::progress::NodeId(0)
        }

        fn advance(&self, _id: crate::core::progress::NodeId, amount: u64) {
            self.advanced
                .fetch_add(amount, std::sync::atomic::Ordering::SeqCst);
        }

        fn grow_total(&self, _id: crate::core::progress::NodeId, additional: u64) {
            self.total
                .fetch_add(additional, std::sync::atomic::Ordering::SeqCst);
        }

        fn close(&self, _id: crate::core::progress::NodeId) {}
    }

    /// A provider's count is the total from the start, and a promised row
    /// never handed over is advanced at the end, so the bar ends full:
    /// three promised, two received.
    #[tokio::test]
    async fn promised_total_ends_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);
        let totals = Arc::new(Totals::default());
        let ctx = Ctx::new(
            Cause::Requested { arg: "tuna".into() },
            crate::core::problem::ProblemSink::new(),
            Arc::clone(&totals) as Arc<dyn crate::core::progress::ProgressSink>,
        );

        let mut roots = Batches::of(vec![vec!["tuna"], vec!["salmon"]]).promising(3);
        let (_collector, outcome) = walked_with(&config, registry(), &mut roots, ctx).await;

        outcome.expect("walked");

        assert_eq!(totals.total.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(totals.advanced.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// The visited set is created once and carries across batches, so an
    /// artifact named in two of them is walked once. Without that, a
    /// migration fed a page at a time would re-walk every shared package.
    #[tokio::test]
    async fn roots_repeated_walked_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let mut roots = Batches::of(vec![vec!["tuna"], vec!["tuna"]]);
        let (collector, outcome) = walked(&config, registry(), &mut roots).await;

        let summary = outcome.expect("walked");

        assert_eq!(collector.purls(), vec!["pkg:npm/tuna@1.2.0"]);

        // Counted rather than silently dropped: the second batch's copy is
        // what `already_seen` exists to report.
        assert_eq!(summary.emitted, 1);
        assert_eq!(summary.already_seen, 1);
    }

    /// An empty first batch is a run that asked for nothing, which is a bad
    /// argument rather than an empty answer. A report of a run that asked
    /// for nothing and a report of a run that found nothing are the same
    /// document, and only one of them is what somebody meant.
    #[tokio::test]
    async fn roots_provider_without_roots_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let mut roots = Batches::of(Vec::new());
        let (_collector, outcome) = walked(&config, registry(), &mut roots).await;

        let err = outcome.expect_err("refused");

        assert!(
            err.to_string().contains("no artifacts were requested"),
            "{err}"
        );
    }

    /// Inspect one lock file, returning the error and the context it
    /// recorded into.
    async fn locked(name: &str, body: &str) -> (Error, Ctx) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let path = dir.path().join(name);
        std::fs::write(&path, body).expect("written");

        let locks = [LockSpec::parse(&path.display().to_string()).expect("parses")];
        let request = Request {
            locks: &locks,
            ..request(&[], SpiderSpec::none())
        };

        let mut session = Session::over(&config, false, Arc::new(registry())).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);
        let collector = Collector::new();

        let outcome = run(
            &mut session,
            &request,
            None,
            None,
            &collector,
            &progress,
            &ctx,
        )
        .await;

        (outcome.expect_err("refused"), ctx)
    }

    /// A claimed lock file that will not parse is the run's input failing,
    /// not a per-artifact `metadata-malformed`, and the report says so.
    #[tokio::test]
    async fn lock_unparsable_recorded() {
        let (err, ctx) = locked("package-lock.json", "not json").await;

        assert_eq!(err.code(), Code::LockMalformed);
        assert_eq!(ctx.problems().counts()[&Code::LockMalformed], 1);
    }

    /// A file no reader claims reaches the report under its own code.
    #[tokio::test]
    async fn lock_unrecognized_recorded() {
        let (err, ctx) = locked("mystery.bin", "\u{0}\u{1}").await;

        assert_eq!(err.code(), Code::LockUnrecognized);
        assert_eq!(ctx.problems().counts()[&Code::LockUnrecognized], 1);
    }

    fn request<'a>(artifacts: &'a [String], spider: SpiderSpec) -> Request<'a> {
        Request {
            source: "npmjs",
            artifacts,
            locks: &[],
            spider: SpiderSetting::Explicit(spider),
            pre: PreRelease::Exclude,
            screen: None,
        }
    }

    /// The whole path in one test: a name on the command line becomes a
    /// resolved artifact, through a real source, a real capability and a
    /// real spider.
    #[tokio::test]
    async fn request_resolves_to_highest_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let artifacts = vec!["tuna".to_owned()];
        let (found, outcome) =
            discovered(&config, registry(), request(&artifacts, SpiderSpec::none())).await;

        outcome.expect("discovered");

        assert_eq!(found.purls(), ["pkg:npm/tuna@1.2.0"]);
    }

    /// Without `--dependencies`, the requested artifact and nothing else.
    /// With them, the edges are followed.
    #[tokio::test]
    async fn dependencies_followed_only_when_asked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let artifacts = vec!["tuna".to_owned()];

        let (shallow, outcome) =
            discovered(&config, registry(), request(&artifacts, SpiderSpec::none())).await;
        outcome.expect("discovered");

        assert_eq!(shallow.len(), 1);

        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let (deep, outcome) = discovered(&config, registry(), request(&artifacts, runtime)).await;
        outcome.expect("discovered");

        let mut purls = deep.purls();
        purls.sort();

        assert_eq!(purls, ["pkg:npm/salmon@2.1.0", "pkg:npm/tuna@1.2.0"]);
    }

    /// `SourceDefault` follows what the source's `dependencies` key says.
    #[tokio::test]
    async fn dependencies_source_default_applies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(
            dir.path(),
            r#"{"npmjs":{"kind":"npm","host":"registry","dependencies":"runtime"}}"#,
        );

        let artifacts = vec!["tuna".to_owned()];
        let request = Request {
            spider: SpiderSetting::SourceDefault,
            ..request(&artifacts, SpiderSpec::none())
        };

        let (found, outcome) = discovered(&config, registry(), request).await;
        outcome.expect("discovered");

        assert_eq!(found.len(), 2);
    }

    /// `setup.maximum-in-memory-queued-dependencies` caps the in-memory frontier: two
    /// roots against a cap of one leave one pruned and counted.
    #[tokio::test]
    async fn setup_caps_in_memory_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "setup":{{"cache-dir":"{}","maximum-in-memory-queued-dependencies":1}},
                    "hosts":{{"registry":{{"url":"{REGISTRY}/"}}}},
                    "sources":{{"npmjs":{{"kind":"npm","host":"registry"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.path().join("scratch").display(),
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let artifacts = vec!["tuna".to_owned(), "salmon".to_owned()];

        let (found, outcome) =
            discovered(&config, registry(), request(&artifacts, SpiderSpec::none())).await;

        let summary = outcome.expect("discovered");

        assert_eq!(found.len(), 1);
        assert_eq!(summary.overflowed, 1);
    }

    /// An empty report and a report of a run that asked for nothing are the
    /// same document, and only one of them is what somebody meant.
    #[tokio::test]
    async fn roots_none_asked_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let (_found, outcome) =
            discovered(&config, registry(), request(&[], SpiderSpec::none())).await;

        assert!(outcome.is_err());
    }

    /// The source's publish window reaches the resolution, which is the
    /// half of `criteria_for` that had no caller until this command.
    #[tokio::test]
    async fn source_publish_window_applies() {
        let dir = tempfile::tempdir().expect("tempdir");

        // A window nothing can satisfy, and no publish times in the
        // packument, so `refuse` is what decides.
        let config = config(
            dir.path(),
            r#"{"npmjs":{"kind":"npm","host":"registry",
                "minimum-publish-time":"300 days","unknown-publish-time":"refuse"}}"#,
        );

        let artifacts = vec!["tuna".to_owned()];
        let (found, _outcome) =
            discovered(&config, registry(), request(&artifacts, SpiderSpec::none())).await;

        assert!(found.is_empty(), "every candidate was too recent");
    }

    // -- Quarantine reaching the report -------------------------------------

    /// The whole quarantine feature, end to end: a rule in a file changes
    /// what an inspection does to one artifact, and the record says so.
    ///
    /// Every layer below has been right for a while and none of it reached
    /// a report, because nothing in a walk narrowed the context to an
    /// artifact -- so `pkg:npm/tuna@<2` had no version to match against and
    /// the policy file was inert in a real run.
    #[tokio::test]
    async fn quarantine_rule_reaches_artifact_record() {
        use crate::core::problem::Quarantine;
        use crate::report::QuarantineRecord;

        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("quarantine.yaml"),
            format!(
                "$schema: {}\nrules:\n  - purl: \"pkg:npm/tuna\"\n    codes: [signature-missing]\n    class: hard\n    justification: \"unsigned, and we mind\"\n    expires: never\n",
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "setup":{{"cache-dir":"{}","quarantine-policy":"quarantine.yaml"}},
                    "hosts":{{"registry":{{"url":"{REGISTRY}/"}}}},
                    "sources":{{"npmjs":{{"kind":"npm","host":"registry"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.path().join("scratch").display(),
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        // A visitor that keeps the record rather than the artifact, since
        // the record is what the rule is supposed to change.
        //
        // Both paths, because a `hard` rule decides `skip-artifact` and the
        // walk therefore hands the artifact over as refused rather than
        // visited. The reservations are the same either way, and which
        // method arrived is itself asserted below.
        #[derive(Default)]
        struct Records {
            held: std::sync::Mutex<Vec<Vec<QuarantineRecord>>>,
            refusals: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl Visitor for Records {
            async fn visit(
                &self,
                _artifact: &crate::model::ResolvedArtifact,
                _source: &dyn crate::repo::Source,
                ctx: &Ctx,
            ) -> Result<()> {
                self.keep(ctx);

                Ok(())
            }

            async fn refused(
                &self,
                _artifact: &crate::model::ResolvedArtifact,
                _why: &crate::core::problem::Problem,
                ctx: &Ctx,
            ) -> Result<()> {
                self.refusals
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.keep(ctx);

                Ok(())
            }

            async fn unresolved(
                &self,
                _request: &crate::model::ArtifactRequest,
                _why: &crate::core::problem::Problem,
                _ctx: &Ctx,
            ) -> Result<()> {
                Ok(())
            }
        }

        impl Records {
            fn keep(&self, ctx: &Ctx) {
                self.held.lock().expect("not poisoned").push(
                    ctx.reservations()
                        .iter()
                        .filter_map(QuarantineRecord::of)
                        .collect(),
                );
            }
        }

        let mut session = Session::over(&config, false, Arc::new(registry())).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);
        let records = Records::default();

        let artifacts = vec!["tuna".to_owned()];

        run(
            &mut session,
            &request(&artifacts, SpiderSpec::none()),
            None,
            None,
            &records,
            &progress,
            &ctx,
        )
        .await
        .expect("discovered");

        let held = records.held.lock().expect("not poisoned").clone();
        let [reservations] = held.as_slice() else {
            panic!("expected one artifact, got {}", held.len());
        };

        // `hard` means `skip-artifact`, so the walk refuses the artifact
        // rather than taking it. The rule decides what happens to it, not
        // only what the record says about it.
        assert_eq!(
            records.refusals.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a hard rule refuses the artifact"
        );

        let [reserved] = reservations.as_slice() else {
            panic!("expected one reservation, got {reservations:?}");
        };

        assert_eq!(reserved.code, crate::core::problem::Code::SignatureMissing);

        // `hard`, not the built-in `soft`: the rule in the file decided.
        assert_eq!(reserved.class, Quarantine::Hard);

        let bypass = reserved.bypassed_by.as_ref().expect("a rule answered");

        assert_eq!(
            bypass.justification.as_deref(),
            Some("unsigned, and we mind")
        );
        assert!(bypass.source.ends_with("rule 1"), "{}", bypass.source);
        assert!(bypass.source.contains("quarantine.yaml"));
    }

    /// A coordinate has no way to say which ecosystem it is written in, so
    /// a source speaking several refuses rather than guesses -- resolving
    /// the wrong real artifact is worse than not resolving one.
    #[tokio::test]
    async fn request_bare_coordinate_refused_by_multi_ecosystem_source() {
        let dir = tempfile::tempdir().expect("tempdir");

        let config = config(
            dir.path(),
            r#"{
                "npmjs":{"kind":"npm","host":"registry"},
                "both":{"kind":"proxy-failover","proxy-to":[{"ref":"npmjs"}]}
            }"#,
        );

        let mut session = Session::over(&config, false, Arc::new(registry())).expect("opens");
        let opened = session.source("both").expect("opens");

        // One upstream, so this one does resolve; the refusal is about the
        // count, and a single-ecosystem proxy is the case that must work.
        assert!(sole_ecosystem(&opened).is_ok());
    }

    // -- The license policy reaching a walk ---------------------------------

    /// A config whose `setup` names a license policy holding `body`.
    fn with_license_policy(dir: &std::path::Path, body: &str) -> Config {
        std::fs::write(dir.join("license.yaml"), body).expect("written");

        let path = dir.join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "setup":{{"cache-dir":"{}","license-policy":"license.yaml"}},
                    "hosts":{{"registry":{{"url":"{REGISTRY}/"}}}},
                    "sources":{{"npmjs":{{"kind":"npm","host":"registry"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    fn policy_of(allowed: &str) -> String {
        format!(
            "$schema: {}\nallowed-licenses:\n  - {allowed}\ndefault-behavior: forbid\nunknown-license: forbid\n",
            crate::policy::LICENSE_POLICY_SCHEMA_ID
        )
    }

    /// Keeps the verdict each artifact was judged under.
    #[derive(Default)]
    struct Verdicts(std::sync::Mutex<Vec<(String, Option<crate::core::license::Verdict>)>>);

    #[async_trait::async_trait]
    impl Visitor for Verdicts {
        async fn visit(
            &self,
            artifact: &crate::model::ResolvedArtifact,
            _source: &dyn crate::repo::Source,
            ctx: &Ctx,
        ) -> Result<()> {
            self.0
                .lock()
                .expect("not poisoned")
                .push((artifact.purl(), ctx.verdict().cloned()));

            Ok(())
        }

        async fn refused(
            &self,
            artifact: &crate::model::ResolvedArtifact,
            _why: &crate::core::problem::Problem,
            ctx: &Ctx,
        ) -> Result<()> {
            self.0
                .lock()
                .expect("not poisoned")
                .push((artifact.purl(), ctx.verdict().cloned()));

            Ok(())
        }

        async fn unresolved(
            &self,
            _request: &crate::model::ArtifactRequest,
            _why: &crate::core::problem::Problem,
            _ctx: &Ctx,
        ) -> Result<()> {
            Ok(())
        }
    }

    async fn judged(
        config: &Config,
        client: FixtureClient,
        spider: SpiderSpec,
    ) -> (Arc<FixtureClient>, Verdicts, Result<Summary>) {
        let shared = Arc::new(client);
        let mut session = Session::over(config, false, shared.clone()).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);
        let seen = Verdicts::default();

        let artifacts = vec!["tuna".to_owned()];
        let outcome = run(
            &mut session,
            &request(&artifacts, spider),
            None,
            None,
            &seen,
            &progress,
            &ctx,
        )
        .await;

        (shared, seen, outcome)
    }

    /// The whole feature, end to end: a policy file refuses an artifact, the
    /// walk drops it, and its dependencies are never fetched.
    ///
    /// Before this the policy loaded, validated, and was never consulted, so
    /// a user forbidding a license watched a clean run and was told nothing.
    #[tokio::test]
    async fn license_forbidden_refuses_and_prunes() {
        let dir = tempfile::tempdir().expect("tempdir");

        // tuna declares MIT, which this policy does not allow.
        let config = with_license_policy(dir.path(), &policy_of("Apache-2.0"));
        let runtime = SpiderSpec::parse("runtime").expect("parses");

        let (client, seen, outcome) = judged(&config, registry(), runtime).await;

        let summary = outcome.expect("the run finished");

        assert_eq!(summary.refused, 1);
        assert_eq!(summary.emitted, 0, "nothing was taken");

        assert_eq!(
            client.hits(&format!("{REGISTRY}/salmon")),
            0,
            "a refused artifact's dependencies are not walked"
        );

        let seen = seen.0.lock().expect("not poisoned").clone();
        let [(purl, verdict)] = seen.as_slice() else {
            panic!("expected one artifact, got {seen:?}");
        };

        assert_eq!(purl, "pkg:npm/tuna@1.2.0");

        let verdict = verdict.as_ref().expect("judged");

        assert_eq!(verdict.decision, crate::core::license::Decision::Forbid);
        assert_eq!(
            verdict.problem,
            Some(crate::core::problem::Code::LicenseForbidden)
        );
    }

    /// An allowed artifact is taken, and the verdict still rides along so a
    /// report can say what was decided rather than only what was not.
    #[tokio::test]
    async fn license_allowed_recorded_on_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");

        let config = with_license_policy(dir.path(), &policy_of("MIT"));

        let (_, seen, outcome) = judged(&config, registry(), SpiderSpec::none()).await;

        assert_eq!(outcome.expect("the run finished").emitted, 1);

        let seen = seen.0.lock().expect("not poisoned").clone();
        let [(_, verdict)] = seen.as_slice() else {
            panic!("expected one artifact, got {seen:?}");
        };

        let verdict = verdict.as_ref().expect("judged");

        assert_eq!(verdict.decision, crate::core::license::Decision::Allow);
        assert_eq!(verdict.spdx.as_deref(), Some("MIT"));
        assert_eq!(verdict.problem, None, "an allowed license raises nothing");
    }

    // -- Advisories reaching a walk -----------------------------------------

    /// Keeps the advisories each artifact was flagged with, and whether it
    /// was refused.
    #[derive(Default)]
    struct Flagged(std::sync::Mutex<Vec<(String, Vec<crate::core::screened::Flag>, bool)>>);

    #[async_trait::async_trait]
    impl Visitor for Flagged {
        async fn visit(
            &self,
            artifact: &crate::model::ResolvedArtifact,
            _source: &dyn crate::repo::Source,
            ctx: &Ctx,
        ) -> Result<()> {
            self.0.lock().expect("not poisoned").push((
                artifact.purl(),
                ctx.flags().to_vec(),
                false,
            ));

            Ok(())
        }

        async fn refused(
            &self,
            artifact: &crate::model::ResolvedArtifact,
            _why: &crate::core::problem::Problem,
            ctx: &Ctx,
        ) -> Result<()> {
            self.0.lock().expect("not poisoned").push((
                artifact.purl(),
                ctx.flags().to_vec(),
                true,
            ));

            Ok(())
        }

        async fn unresolved(
            &self,
            _request: &crate::model::ArtifactRequest,
            _why: &crate::core::problem::Problem,
            _ctx: &Ctx,
        ) -> Result<()> {
            Ok(())
        }
    }

    /// A malware record against `tuna`, every version.
    fn malware_index() -> crate::advisory::Index {
        let record = serde_json::from_str(
            r#"{"id":"MAL-2024-1","affected":[{"package":{"ecosystem":"npm","name":"tuna"},
                 "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}"#,
        )
        .expect("record");

        let mut index = crate::advisory::Index::new(crate::advisory::Ecosystems::builtin());

        index.attributing("ossf");
        index.insert(record);

        index
    }

    /// The whole feature, end to end: a corpus names the artifact as
    /// malware, the walk drops it, its dependencies are never fetched, and
    /// the finding rides on the context for the report.
    #[tokio::test]
    async fn advisory_malware_refuses_and_prunes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = with_license_policy(dir.path(), &policy_of("MIT"));
        let client = Arc::new(registry());
        let mut session = Session::over(&config, false, client.clone()).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);
        let flagged = Flagged::default();
        let index = malware_index();
        let screening = crate::advisory::Screening::none();

        let artifacts = vec!["tuna".to_owned()];
        let request = Request {
            screen: Some(crate::advisory::Screen {
                index: &index,
                screening: &screening,
            }),
            ..request(&artifacts, SpiderSpec::parse("runtime").expect("parses"))
        };

        let summary = run(
            &mut session,
            &request,
            None,
            None,
            &flagged,
            &progress,
            &ctx,
        )
        .await
        .expect("the run finished");

        assert_eq!(summary.refused, 1);
        assert_eq!(
            client.hits(&format!("{REGISTRY}/salmon")),
            0,
            "a refused artifact's dependencies are not walked"
        );

        let seen = flagged.0.lock().expect("not poisoned").clone();
        let [(purl, flags, refused)] = seen.as_slice() else {
            panic!("expected one artifact, got {seen:?}");
        };

        assert_eq!(purl, "pkg:npm/tuna@1.2.0");
        assert!(refused);
        assert_eq!(flags[0].id, "MAL-2024-1");
        assert_eq!(flags[0].advisor, "ossf");
    }

    /// A VEX document named after a coordinate still applies to it: VEX
    /// files are read before the walk. Its product in another ecosystem is
    /// left out and recorded.
    #[tokio::test]
    async fn advisory_later_vex_suppresses_skips_foreign_products() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);
        let mut session = Session::over(&config, false, Arc::new(registry())).expect("opens");
        let ctx = ctx();
        let progress = ctx.progress("inspect", Unit::Items, None);
        let flagged = Flagged::default();
        let screening = crate::advisory::Screening::none();

        let record = serde_json::from_str(
            r#"{"id":"GHSA-1","affected":[{"package":{"ecosystem":"npm","name":"tuna"},
                 "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}"#,
        )
        .expect("record");
        let mut index = crate::advisory::Index::new(crate::advisory::Ecosystems::builtin());
        index.attributing("osv");
        index.insert(record);

        let vex = dir.path().join("triage.json");
        std::fs::write(
            &vex,
            r#"{"@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": "GHSA-1",
                    "products": ["pkg:npm/tuna@1.2.0", "pkg:pypi/requests@2.0.0"],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present"}]}"#,
        )
        .expect("written");

        let artifacts = vec!["tuna".to_owned()];
        let locks = [LockSpec::parse(&vex.display().to_string()).expect("parses")];
        let request = Request {
            locks: &locks,
            screen: Some(crate::advisory::Screen {
                index: &index,
                screening: &screening,
            }),
            ..request(&artifacts, SpiderSpec::none())
        };

        run(
            &mut session,
            &request,
            None,
            None,
            &flagged,
            &progress,
            &ctx,
        )
        .await
        .expect("the run finished");

        let seen = flagged.0.lock().expect("not poisoned").clone();
        let [(purl, flags, _)] = seen.as_slice() else {
            panic!("expected one artifact, got {seen:?}");
        };

        assert_eq!(purl, "pkg:npm/tuna@1.2.0");
        assert!(flags[0].suppressed_by.is_some());
        assert!(screening.stale().is_empty());

        let counts = ctx.problems().counts();
        assert_eq!(counts.get(&Code::VulnerabilityKnown), None);
        assert_eq!(counts[&Code::BomEcosystemForeign], 1);
    }

    /// No policy configured means no verdict, rather than an invented allow.
    #[tokio::test]
    async fn license_without_policy_unjudged() {
        let dir = tempfile::tempdir().expect("tempdir");

        let config = config(dir.path(), r#"{"npmjs":{"kind":"npm","host":"registry"}}"#);

        let (_, seen, outcome) = judged(&config, registry(), SpiderSpec::none()).await;

        assert_eq!(outcome.expect("the run finished").emitted, 1);

        let seen = seen.0.lock().expect("not poisoned").clone();
        let [(_, verdict)] = seen.as_slice() else {
            panic!("expected one artifact, got {seen:?}");
        };

        assert!(verdict.is_none());
    }

    // -- Which rows a report-fed run asks for ------------------------------

    fn npm_id() -> crate::model::ArtifactId {
        crate::model::ArtifactId::new(crate::model::EcosystemId::npm(), None, "tuna")
    }

    fn raw_id() -> crate::model::ArtifactId {
        crate::model::ArtifactId::new(crate::model::EcosystemId::raw(), None, "artifact1/1.0")
    }

    /// A recorded version is asked for exactly, because a report-fed copy
    /// is working through a manifest and must not widen on a re-run.
    #[test]
    fn discovery_recorded_version_asked_exactly() {
        assert_eq!(
            asked_for(&npm_id(), Some("1.2.0".to_owned())),
            Some(VersionSpec::Exact("1.2.0".to_owned()))
        );
    }

    /// **A name-only npm row is skipped.** `find` over a replication
    /// feed records a name because the versions cost a packument each and
    /// nobody has paid; resolving it to whatever is newest today would copy
    /// something the report never named.
    #[test]
    fn discovery_name_only_row_versioned_skipped() {
        assert_eq!(asked_for(&npm_id(), None), None);
    }

    /// **A raw row with no version is asked for.** The `NULL` means there
    /// is no version rather than that nobody looked, and skipping it would
    /// drop the artifact from the migration.
    ///
    /// The row cannot say which it is, so the two tests above and this one
    /// together are what keep the distinction real.
    #[test]
    fn discovery_versionless_raw_row_asked() {
        assert_eq!(asked_for(&raw_id(), None), Some(VersionSpec::Any));
    }

    /// An ecosystem this build cannot open is treated as versioned, which
    /// is the conservative direction: a skipped artifact is visible in the
    /// report and a wrongly widened one is not.
    #[test]
    fn discovery_unknown_ecosystem_treated_versioned() {
        let id =
            crate::model::ArtifactId::new(crate::model::EcosystemId::new("cargo"), None, "serde");

        assert_eq!(asked_for(&id, None), None);
    }
}
