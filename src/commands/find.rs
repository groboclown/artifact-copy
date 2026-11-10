//! Inventory everything a repository holds.
//!
//! Walks an enumerator's catalog page by page and hands each finding to a
//! [`Sink`]. What a repository *has*, not what each thing *is*.
//!
//! # Why it does not resolve
//!
//! A [`Found`] carries an id, sometimes a version, and when the repository
//! was last asked for it. The files, their digests, the license and the
//! publish time are a [`Source`](crate::repo::Source)'s answers, and each
//! costs a request -- so resolving a catalog would turn a walk of a million
//! artifacts into a million requests on top of the few hundred the walk
//! itself takes.
//!
//! That is the whole difference between this and `inspect`, and it is why
//! this command has no `--pre-release` and no `--dependencies`: neither
//! means anything without resolution. `copy --from-db` falls back to the
//! source for what an inventory lacks, so an inventory is enough to feed it.
//!
//! # Streaming, not accumulating
//!
//! Findings go to the sink as each page arrives. The whole point of this
//! command is the repository nobody can hold in memory.

use crate::advisory::{Policed, Screen};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::progress::Node;
use crate::model::{Cause, ListingDepth};
use crate::repo::enumerate::{Cursor, Enumerator, Found, Narrowing, SampleSize, page_of};
use crate::report::Resume;
use crate::session::Session;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};

/// How a walk narrowed to what changed since a date names itself in its
/// scope: `since=2026-10-09T14:03:11.204Z`.
const SINCE_SCOPE: &str = "since=";

/// The date a walk's scope narrowed it to, if it was narrowed by date.
pub fn narrowed_since(scope: Option<&str>) -> Option<DateTime<Utc>> {
    let date = scope?.strip_prefix(SINCE_SCOPE)?;

    DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn since_scope(since: DateTime<Utc>) -> String {
    format!(
        "{SINCE_SCOPE}{}",
        since.to_rfc3339_opts(SecondsFormat::Millis, true)
    )
}

/// Receives findings as the catalog is walked.
///
/// A sink rather than a return value, for the same reason
/// [`Visitor`](crate::commands::spider::Visitor) is one.
#[async_trait]
pub trait Sink: Send + Sync {
    /// One artifact the repository holds.
    async fn found(&self, found: &Found, ctx: &Ctx) -> Result<()>;

    /// The walk reached a page boundary.
    ///
    /// A no-op by default, because most sinks have nowhere to keep it. A
    /// report that does gets what an interrupted walk needs to resume
    /// without paging from the beginning again.
    async fn reached(&self, at: &Progress<'_>) -> Result<()> {
        let _ = at;

        Ok(())
    }
}

/// Where a walk has got to, handed to the sink at each page boundary.
///
/// The walk's own vocabulary rather than a report's: the enumerator's name and
/// kind, the cursor it issued, and what has been seen so far. A sink that
/// writes reports translates; one that does not never learns the word.
#[derive(Debug, Clone)]
pub struct Progress<'a> {
    /// The configured enumerator being walked.
    pub enumerator: &'a str,

    /// Its kind, because a cursor means nothing to a different
    /// implementation and some repositories reject an old one outright.
    pub kind: &'a str,

    /// How far the enumerator's listing reaches, as it declared.
    pub depth: ListingDepth,

    /// What the walk was asked for, when it was asked for less than
    /// everything.
    pub scope: Option<String>,

    /// Where to resume, or `None` at the end of the catalog.
    pub cursor: Option<&'a Cursor>,

    pub walked: Summary,

    /// Whether the walk reached the end of the catalog.
    ///
    /// **A sampled walk never sets this**, however far it got: seeing a
    /// tenth of a repository is not seeing a repository, and only a walk
    /// that reached the end can date an inventory.
    pub reached_end: bool,
}

/// How much of a catalog a walk covers: where it starts, and where it
/// stops short of the end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Span {
    /// Stop early. A percentage needs the enumerator to report a total and
    /// is refused when it cannot -- see [`SampleSize::resolve`].
    pub sample: Option<SampleSize>,

    /// Where an interrupted walk stopped, to continue from there.
    pub resume: Option<Resume>,

    /// Walk only what changed at or after this: the start of the last walk
    /// that reached the end. Ignored when resuming, since an interrupted
    /// walk keeps the narrowing it started with.
    pub since: Option<DateTime<Utc>>,
}

/// What happened during a walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Findings handed to the sink.
    pub found: u64,

    /// Pages fetched, which is what the walk actually cost.
    pub pages: u64,

    /// Whether the walk stopped at a sample size rather than at the end of
    /// the catalog.
    pub sampled: bool,

    /// The date the walk was narrowed to, when the enumerator could narrow
    /// it.
    pub since: Option<DateTime<Utc>>,
}

/// Screen one listed artifact, under a context narrowed to it.
///
/// `None` when there is nothing to screen: no corpora, or a listing with no
/// version, which a catalog of names only cannot supply. The version is
/// ordered by the ecosystem's own convention, since an enumerator has no source
/// to ask.
fn screened(
    found: &Found,
    screen: Option<Screen<'_>>,
    policed: Policed<'_>,
    ctx: &Ctx,
) -> Option<Ctx> {
    let (Some(screen), Some(version)) = (screen, found.version.as_ref()) else {
        return None;
    };

    let about = ctx.for_artifact(found.id.clone(), Some(version.clone()));

    let ecosystem = match crate::ecosystem::open(found.id.ecosystem().as_str()) {
        Ok(ecosystem) => ecosystem,

        // Reported rather than skipped, so an unscreened listing cannot
        // read as a clean one.
        Err(err) => {
            about.report_err(&err);
            return Some(about);
        }
    };

    let flags = screen.artifact(&found.id, version, ecosystem.as_ref(), policed, &about);

    Some(about.screened(flags))
}

/// Walk `enumerator`'s catalog, as much of it as `span` says.
pub async fn run(
    session: &mut Session<'_>,
    enumerator: &str,
    span: Span,
    sink: &dyn Sink,
    screen: Option<Screen<'_>>,
    progress: &Node,
    ctx: &Ctx,
) -> Result<Summary> {
    let opened = session.enumerator(enumerator)?;

    check_resume_kind(enumerator, &opened.kind, &span)?;

    // The walk's own cause, so every finding says which enumerator produced
    // it rather than inheriting whatever started the run.
    let ctx = ctx.rooted(std::sync::Arc::new(crate::model::Provenance::root(
        Cause::Enumerated {
            enumerator: enumerator.to_owned(),
        },
    )));

    let limit = sample_limit(opened.enumerator.as_ref(), span.sample, &ctx).await?;

    // Declared, not chosen: `find` records whatever the enumerator lists.
    let depth = opened.enumerator.depth();

    ctx.log().info(crate::message!(
        "find-depth",
        "enumerator {enumerator} lists {depth}",
        enumerator = enumerator,
        depth = depth,
    ));

    let since = narrowing(enumerator, opened.enumerator.narrowing(), &span, &ctx);

    // A total makes the bar a bar; without one it is an activity line,
    // which is the honest rendering of a catalog of unknown size.
    if let Some(total) = walk_total(opened.enumerator.as_ref(), limit, since, &ctx).await {
        progress.grow_total(total);
    }

    let walk = Walk {
        enumerator,

        // The configured kind rather than the configured name: a cursor
        // belongs to the implementation that issued it.
        kind: &opened.kind,
        depth,
        scope: walk_scope(limit, since),
        since,
        limit,
        lister: opened.enumerator.as_ref(),
        policed: opened.policed(),
        screen,
        sink,
        progress,
    };

    let summary = Summary {
        sampled: limit.is_some(),
        since,
        ..Summary::default()
    };

    let (cursor, summary) = resume_at(span.resume, summary, progress);

    walk.pages(cursor, summary, &ctx).await
}

/// Refuse to resume a walk another kind of enumerator started.
///
/// Before any request: a cursor belongs to the implementation that issued
/// it, and handing one to another kind means nothing.
fn check_resume_kind(enumerator: &str, kind: &str, span: &Span) -> Result<()> {
    let Some(resume) = &span.resume else {
        return Ok(());
    };

    if resume.kind == kind {
        return Ok(());
    }

    Err(Error::Config(format!(
        "enumerator {enumerator:?} is now {kind:?}, and its interrupted walk was {:?}; \
         pass --refresh=enumeration to walk it from the start",
        resume.kind
    )))
}

/// How many findings the walk stops at, when a sample was requested.
///
/// Asked once, before the walk, and only when a sample was requested -- a
/// total costs a request of its own and most enumerators cannot answer at
/// all.
async fn sample_limit(
    lister: &dyn Enumerator,
    sample: Option<SampleSize>,
    ctx: &Ctx,
) -> Result<Option<u64>> {
    let Some(sample) = sample else {
        return Ok(None);
    };

    let total = lister.count(ctx).await?;

    Ok(Some(sample.resolve(total).map_err(Error::Config)?))
}

/// How many artifacts the walk will find, when that is known before it
/// starts: the sample, or else the catalog's own count.
///
/// A walk narrowed by `since` lists part of the catalog, so the catalog's
/// count would leave the bar short of its end; it has none. A count that
/// fails costs only the bar, so it is logged rather than failing the run.
async fn walk_total(
    lister: &dyn Enumerator,
    limit: Option<u64>,
    since: Option<DateTime<Utc>>,
    ctx: &Ctx,
) -> Option<u64> {
    if limit.is_some() {
        return limit;
    }

    if since.is_some() {
        return None;
    }

    match lister.count(ctx).await {
        Ok(total) => total,
        Err(err) => {
            ctx.log().debug(format_args!(
                "the catalog could not be counted, so progress has no total: {err}"
            ));
            None
        }
    }
}

/// What the walk was asked for, when it was asked for less than everything.
fn walk_scope(limit: Option<u64>, since: Option<DateTime<Utc>>) -> Option<String> {
    match (limit, since) {
        (Some(limit), _) => Some(format!("sample={limit}")),
        (None, Some(since)) => Some(since_scope(since)),
        (None, None) => None,
    }
}

/// Where the walk starts, and what it has already counted.
///
/// An interrupted walk continues from its last page, and what it already
/// found counts toward a sample. Without a cursor it stopped before its
/// first page boundary, so it starts over and counts nothing.
fn resume_at(
    resume: Option<Resume>,
    mut summary: Summary,
    progress: &Node,
) -> (Option<Cursor>, Summary) {
    let Some(Resume {
        cursor: Some(at),
        pages,
        found,
        ..
    }) = resume
    else {
        return (None, summary);
    };

    summary.pages = pages;
    summary.found = found;
    progress.advance(found);

    (Some(Cursor::new(at)), summary)
}

/// One walk's fixed settings: what the page loop asks and what the sink
/// is told.
struct Walk<'a> {
    /// The configured enumerator's name.
    enumerator: &'a str,
    kind: &'a str,
    depth: ListingDepth,
    scope: Option<String>,
    since: Option<DateTime<Utc>>,

    /// The sample size, when the walk stops short of the end.
    limit: Option<u64>,
    lister: &'a dyn Enumerator,
    policed: Policed<'a>,
    screen: Option<Screen<'a>>,
    sink: &'a dyn Sink,
    progress: &'a Node,
}

impl<'a> Walk<'a> {
    /// Page through the catalog from `cursor` until it ends, the sample is
    /// reached, or the run is cancelled.
    async fn pages(
        &self,
        mut cursor: Option<Cursor>,
        mut summary: Summary,
        ctx: &Ctx,
    ) -> Result<Summary> {
        loop {
            // Checked per page rather than per finding: a page is one request,
            // and that is the granularity at which stopping is meaningful.
            if ctx.is_cancelled() {
                break;
            }

            let page = page_of(self.lister, self.since, cursor.as_ref(), ctx).await?;

            summary.pages += 1;

            for found in &page.found {
                if self.limit.is_some_and(|limit| summary.found >= limit) {
                    // Stopped at the sample, which is not the end of the
                    // catalog: the cursor is kept so the walk can be finished
                    // later, and `reached_end` stays false.
                    self.sink
                        .reached(&self.progress_at(cursor.as_ref(), summary, false))
                        .await?;

                    return Ok(summary);
                }

                match screened(found, self.screen, self.policed, ctx) {
                    Some(about) => self.sink.found(found, &about).await?,
                    None => self.sink.found(found, ctx).await?,
                }

                summary.found += 1;
                self.progress.advance(1);
            }

            // **An empty page is not the end.** A Nexus page can be filtered
            // away entirely and the catalog continue; only an absent cursor
            // ends a walk. Getting this wrong truncates a catalog silently,
            // which is the worst failure an enumerator has.
            match page.next {
                Some(next) => {
                    cursor = Some(next);

                    self.sink
                        .reached(&self.progress_at(cursor.as_ref(), summary, false))
                        .await?;
                }

                None => {
                    // The one place a walk earns `reached_end`, and the one
                    // thing that dates an inventory.
                    self.sink
                        .reached(&self.progress_at(None, summary, true))
                        .await?;

                    break;
                }
            }
        }

        Ok(summary)
    }

    /// Assemble what the sink is told at a page boundary.
    fn progress_at<'c>(
        &'c self,
        cursor: Option<&'c Cursor>,
        walked: Summary,
        reached_end: bool,
    ) -> Progress<'c> {
        Progress {
            enumerator: self.enumerator,
            kind: self.kind,
            depth: self.depth,
            scope: self.scope.clone(),
            cursor,
            walked,
            reached_end,
        }
    }
}

/// The date this walk is narrowed to, if any.
///
/// A resumed walk keeps the narrowing it started with, whatever this run
/// would have chosen: its cursor means nothing under another. A fresh walk
/// takes `span.since`, unless the enumerator cannot narrow, which is said
/// rather than left to look like a narrowed walk.
fn narrowing(
    enumerator: &str,
    narrowing: Narrowing,
    span: &Span,
    ctx: &Ctx,
) -> Option<DateTime<Utc>> {
    if let Some(resume) = &span.resume {
        return narrowed_since(resume.scope.as_deref());
    }

    let since = span.since?;

    if narrowing == Narrowing::Unsupported {
        ctx.log().info(crate::message!(
            "find-not-narrowed",
            "enumerator {enumerator} cannot list only what changed since {since}, \
             so it walks everything",
            enumerator = enumerator,
            since = since.to_rfc3339_opts(SecondsFormat::Millis, true),
        ));

        return None;
    }

    Some(since)
}

/// Report what a walk found, for a caller that logs a summary.
///
/// A walk narrowed by date says so, so the count reads as what changed
/// since then rather than as the repository's size.
pub fn describe(summary: &Summary) -> crate::core::message::Message {
    let Some(since) = summary.since else {
        return crate::message!(
            "find-finished",
            "found {found} artifacts over {pages} pages",
            found = summary.found,
            pages = summary.pages,
        );
    };

    crate::message!(
        "find-finished-since",
        "found {found} artifacts modified since {since}, over {pages} pages",
        found = summary.found,
        since = since.to_rfc3339_opts(SecondsFormat::Millis, true),
        pages = summary.pages,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ConfigLoader;
    use crate::config::Config;
    use crate::core::progress::Unit;
    use crate::net::{Canned, FixtureClient};
    use http::StatusCode;
    use std::sync::{Arc, Mutex};

    const NEXUS: &str = "h://nexus.test";

    /// Keeps what the walk found, which is small in a test and is the
    /// thing under test.
    #[derive(Default)]
    struct Kept(Mutex<Vec<String>>);

    #[async_trait]
    impl Sink for Kept {
        async fn found(&self, found: &Found, _ctx: &Ctx) -> Result<()> {
            self.0.lock().expect("not poisoned").push(found.id.purl());

            Ok(())
        }
    }

    fn config(dir: &std::path::Path) -> Config {
        let path = dir.join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"{}"}},
                    "hosts":{{"nexus":{{"url":"{NEXUS}/"}}}},
                    "enumerators":{{"all":{{"kind":"nexus","host":"nexus",
                      "options":{{"repository":"npm-group","ecosystem":"npm"}}}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    fn components(cursor: Option<&str>) -> String {
        match cursor {
            None => format!("{NEXUS}/service/rest/v1/components?repository=npm-group"),
            Some(token) => format!(
                "{NEXUS}/service/rest/v1/components?repository=npm-group&continuationToken={token}"
            ),
        }
    }

    fn page(names: &[&str], next: Option<&str>) -> String {
        let items: Vec<String> = names
            .iter()
            .map(|name| {
                format!(
                    r#"{{"group":null,"name":"{name}","version":"1.0.0","format":"npm","assets":[]}}"#
                )
            })
            .collect();

        let token = match next {
            Some(token) => format!("\"{token}\""),
            None => "null".to_owned(),
        };

        format!(
            r#"{{"items":[{}],"continuationToken":{token}}}"#,
            items.join(",")
        )
    }

    async fn walked(
        config: &Config,
        client: FixtureClient,
        sample: Option<SampleSize>,
    ) -> (Kept, Result<Summary>) {
        let mut session = Session::over(config, false, Arc::new(client)).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let progress = ctx.progress("find", Unit::Items, None);
        let kept = Kept::default();

        let span = Span {
            sample,
            ..Span::default()
        };

        let outcome = run(&mut session, "all", span, &kept, None, &progress, &ctx).await;

        (kept, outcome)
    }

    /// Keeps each listing's advisory ids.
    #[derive(Default)]
    struct Flagged(Mutex<Vec<(String, Vec<String>)>>);

    #[async_trait]
    impl Sink for Flagged {
        async fn found(&self, found: &Found, ctx: &Ctx) -> Result<()> {
            let ids = ctx.flags().iter().map(|flag| flag.id.clone()).collect();

            self.0
                .lock()
                .expect("not poisoned")
                .push((found.id.purl(), ids));

            Ok(())
        }
    }

    /// A listing with a version is screened by its ecosystem's own ordering,
    /// and the finding reaches the sink on a context narrowed to it.
    #[tokio::test]
    async fn listing_versioned_screened() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let client = FixtureClient::new().with_body(components(None), page(&["a", "b"], None));
        let mut session = Session::over(&config, false, Arc::new(client)).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let progress = ctx.progress("find", Unit::Items, None);
        let flagged = Flagged::default();

        let record = serde_json::from_str(
            r#"{"id":"MAL-2024-1","affected":[{"package":{"ecosystem":"npm","name":"a"},
                 "versions":["1.0.0"]}]}"#,
        )
        .expect("record");
        let mut index = crate::advisory::Index::new(crate::advisory::Ecosystems::builtin());

        index.insert(record);

        let screening = crate::advisory::Screening::none();
        let screen = Screen {
            index: &index,
            screening: &screening,
        };

        run(
            &mut session,
            "all",
            Span::default(),
            &flagged,
            Some(screen),
            &progress,
            &ctx,
        )
        .await
        .expect("walked");

        assert_eq!(
            flagged.0.lock().expect("not poisoned").clone(),
            [
                ("pkg:npm/a".to_owned(), vec!["MAL-2024-1".to_owned()]),
                ("pkg:npm/b".to_owned(), Vec::new()),
            ]
        );
        assert_eq!(
            ctx.problems()
                .counts()
                .get(&crate::core::problem::Code::MalwareKnown),
            Some(&1)
        );
    }

    /// A catalog arrives over several pages, and every page is walked.
    #[tokio::test]
    async fn walk_catalog_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new()
            .with_body(components(None), page(&["a", "b"], Some("t1")))
            .with_body(components(Some("t1")), page(&["c"], None));

        let (kept, outcome) = walked(&config, client, None).await;
        let summary = outcome.expect("walked");

        assert_eq!(
            kept.0.lock().expect("not poisoned").clone(),
            ["pkg:npm/a", "pkg:npm/b", "pkg:npm/c"]
        );
        assert_eq!(summary.found, 3);
        assert_eq!(summary.pages, 2);
        assert!(!summary.sampled);
    }

    /// Keeps the depth each page boundary reports.
    #[derive(Default)]
    struct Depths(Mutex<Vec<ListingDepth>>);

    #[async_trait]
    impl Sink for Depths {
        async fn found(&self, _found: &Found, _ctx: &Ctx) -> Result<()> {
            Ok(())
        }

        async fn reached(&self, at: &Progress<'_>) -> Result<()> {
            self.0.lock().expect("not poisoned").push(at.depth);

            Ok(())
        }
    }

    /// No depth option: the walk reports what the enumerator declares.
    #[tokio::test]
    async fn walk_reports_declared_depth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new()
            .with_body(components(None), page(&["a"], Some("t1")))
            .with_body(components(Some("t1")), page(&["b"], None));

        let mut session = Session::over(&config, false, Arc::new(client)).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let progress = ctx.progress("find", Unit::Items, None);
        let depths = Depths::default();

        run(
            &mut session,
            "all",
            Span::default(),
            &depths,
            None,
            &progress,
            &ctx,
        )
        .await
        .expect("walked");

        assert_eq!(
            depths.0.lock().expect("not poisoned").clone(),
            [ListingDepth::Files, ListingDepth::Files]
        );
    }

    /// **An empty page is not the end.** Nexus filters after paging, so a
    /// whole page can be filtered away while the catalog continues; only
    /// an absent cursor ends a walk. Getting this wrong truncates a
    /// catalog silently, which is the worst failure an enumerator has.
    #[tokio::test]
    async fn walk_empty_page_not_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new()
            .with_body(components(None), page(&[], Some("t1")))
            .with_body(components(Some("t1")), page(&["late"], None));

        let (kept, outcome) = walked(&config, client, None).await;
        let summary = outcome.expect("walked");

        assert_eq!(
            kept.0.lock().expect("not poisoned").clone(),
            ["pkg:npm/late"]
        );
        assert_eq!(summary.pages, 2, "the empty page was not taken as the end");
    }

    /// A count stops the walk mid-page rather than at a page boundary,
    /// because a sample of 35 means 35 and not "35 rounded up to whatever
    /// the page size happens to be".
    #[tokio::test]
    async fn walk_stopped_by_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new()
            .with_body(components(None), page(&["a", "b", "c"], Some("t1")))
            .with_body(components(Some("t1")), page(&["d"], None));

        let (kept, outcome) = walked(&config, client, Some(SampleSize::Count(2))).await;
        let summary = outcome.expect("walked");

        assert_eq!(
            kept.0.lock().expect("not poisoned").clone(),
            ["pkg:npm/a", "pkg:npm/b"]
        );
        assert_eq!(summary.found, 2);
        assert_eq!(summary.pages, 1, "the second page was never fetched");
        assert!(summary.sampled);
    }

    /// A percentage needs a total, and an enumerator that cannot report one
    /// says so rather than sampling some other amount.
    #[tokio::test]
    async fn walk_percentage_without_total_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new()
            .with_body(components(None), page(&["a"], None))
            .with(
                format!("{NEXUS}/service/rest/v1/status"),
                Canned::status(StatusCode::NOT_FOUND),
            );

        let (_kept, outcome) = walked(&config, client, Some(SampleSize::Percent(35))).await;

        let err = match outcome {
            Err(err) => err.to_string(),
            Ok(summary) => panic!("should have refused, walked {summary:?}"),
        };

        assert!(err.contains("percentage"), "{err}");
    }

    /// Every finding says which enumerator produced it, rather than
    /// inheriting whatever started the run.
    #[tokio::test]
    async fn finding_caused_by_enumerator() {
        struct Chains(Mutex<Vec<String>>);

        #[async_trait]
        impl Sink for Chains {
            async fn found(&self, _found: &Found, ctx: &Ctx) -> Result<()> {
                self.0
                    .lock()
                    .expect("not poisoned")
                    .push(ctx.prov().render());

                Ok(())
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new().with_body(components(None), page(&["a"], None));

        let mut session = Session::over(&config, false, Arc::new(client)).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let progress = ctx.progress("find", Unit::Items, None);
        let chains = Chains(Mutex::new(Vec::new()));

        run(
            &mut session,
            "all",
            Span::default(),
            &chains,
            None,
            &progress,
            &ctx,
        )
        .await
        .expect("walked");

        let seen = chains.0.lock().expect("not poisoned").clone();

        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("enumerator"), "{}", seen[0]);
        assert!(seen[0].contains("all"), "{}", seen[0]);
    }

    #[tokio::test]
    async fn enumerator_unknown_names_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let mut session =
            Session::over(&config, false, Arc::new(FixtureClient::new())).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let progress = ctx.progress("find", Unit::Items, None);

        let err = match run(
            &mut session,
            "nope",
            Span::default(),
            &Kept::default(),
            None,
            &progress,
            &ctx,
        )
        .await
        {
            Err(err) => err.to_string(),
            Ok(_) => panic!("should not have opened"),
        };

        assert!(err.contains("nope"), "{err}");
    }

    fn at(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(ms).expect("valid")
    }

    #[test]
    fn since_scope_round_trips() {
        let since = at(1_760_000_000_123);

        assert_eq!(narrowed_since(Some(&since_scope(since))), Some(since));
        assert_eq!(narrowed_since(Some("sample=10")), None);
        assert_eq!(narrowed_since(None), None);
    }

    /// A fresh walk narrows when the enumerator can, and walks everything
    /// when it cannot.
    #[test]
    fn narrowing_fresh_only_where_supported() {
        let ctx = Ctx::for_test(Cause::Requested { arg: "find".into() });
        let span = Span {
            since: Some(at(1_000)),
            ..Span::default()
        };

        assert_eq!(
            narrowing("e", Narrowing::Modified, &span, &ctx),
            Some(at(1_000))
        );
        assert_eq!(narrowing("e", Narrowing::Unsupported, &span, &ctx), None);
    }

    /// A resumed walk keeps the narrowing it started with, whatever this
    /// run would have chosen: its cursor means nothing under another.
    #[test]
    fn narrowing_resumed_kept() {
        let ctx = Ctx::for_test(Cause::Requested { arg: "find".into() });
        let mut narrowed = resumed("k", Some("c"));
        narrowed.resume.as_mut().expect("resumed").scope = Some(since_scope(at(5_000)));
        narrowed.since = Some(at(9_000));

        let mut full = resumed("k", Some("c"));
        full.since = Some(at(9_000));

        assert_eq!(
            narrowing("e", Narrowing::Modified, &narrowed, &ctx),
            Some(at(5_000))
        );
        assert_eq!(narrowing("e", Narrowing::Modified, &full, &ctx), None);
    }

    #[test]
    fn narrowing_summary_says_since_when() {
        let summary = Summary {
            found: 3,
            pages: 1,
            since: Some(at(0)),
            ..Summary::default()
        };

        let text = describe(&summary).render();

        assert!(
            text.contains("3 artifacts modified since 1970-01-01T00:00:00.000Z"),
            "{text}"
        );
    }

    fn resumed(kind: &str, cursor: Option<&str>) -> Span {
        Span {
            sample: None,
            resume: Some(Resume {
                kind: kind.to_owned(),
                cursor: cursor.map(str::to_owned),
                pages: 1,
                found: 2,
                scope: None,
            }),
            since: None,
        }
    }

    async fn walked_from(
        config: &Config,
        client: FixtureClient,
        span: Span,
    ) -> (Kept, Result<Summary>) {
        let mut session = Session::over(config, false, Arc::new(client)).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let progress = ctx.progress("find", Unit::Items, None);
        let kept = Kept::default();

        let outcome = run(&mut session, "all", span, &kept, None, &progress, &ctx).await;

        (kept, outcome)
    }

    /// An interrupted walk continues from its cursor, and never asks for
    /// the pages it already walked: the fixture has no first page to give.
    #[tokio::test]
    async fn cursor_resumes_walk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new().with_body(components(Some("t1")), page(&["c"], None));

        let (kept, outcome) = walked_from(&config, client, resumed("nexus", Some("t1"))).await;
        let summary = outcome.expect("walked");

        assert_eq!(kept.0.lock().expect("not poisoned").clone(), ["pkg:npm/c"]);
        assert_eq!(summary.found, 3);
        assert_eq!(summary.pages, 2);
    }

    /// Stopped before its first page boundary, so there is nothing to
    /// continue from and nothing already counted.
    #[tokio::test]
    async fn cursor_absent_starts_over() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = FixtureClient::new().with_body(components(None), page(&["a"], None));

        let (kept, outcome) = walked_from(&config, client, resumed("nexus", None)).await;

        assert_eq!(kept.0.lock().expect("not poisoned").clone(), ["pkg:npm/a"]);
        assert_eq!(outcome.expect("walked").found, 1);
    }

    #[tokio::test]
    async fn cursor_foreign_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let (kept, outcome) = walked_from(
            &config,
            FixtureClient::new(),
            resumed("artifactory", Some("t1")),
        )
        .await;

        let err = outcome.expect_err("refused").to_string();

        assert!(err.contains("--refresh=enumeration"), "{err}");
        assert!(kept.0.lock().expect("not poisoned").is_empty());
    }

    /// An enumerator that lists nothing and counts as told.
    struct Counted(Result<Option<u64>>);

    #[async_trait]
    impl Enumerator for Counted {
        fn ecosystems(&self) -> &[crate::model::EcosystemId] {
            &[]
        }

        async fn walk(
            &self,
            _cursor: Option<&Cursor>,
            _ctx: &Ctx,
        ) -> Result<crate::repo::enumerate::Page> {
            Ok(crate::repo::enumerate::Page::last(Vec::new()))
        }

        async fn count(&self, _ctx: &Ctx) -> Result<Option<u64>> {
            match &self.0 {
                Ok(total) => Ok(*total),
                Err(_) => Err(Error::Config("uncountable".to_owned())),
            }
        }
    }

    /// The catalog's count is the total of an unnarrowed walk; a sample is
    /// its own total, and a narrowed walk or a failed count has none.
    #[tokio::test]
    async fn walk_total_from_count() {
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });
        let counted = Counted(Ok(Some(3)));
        let failed = Counted(Err(Error::Config("uncountable".to_owned())));

        assert_eq!(walk_total(&counted, None, None, &ctx).await, Some(3));
        assert_eq!(walk_total(&counted, Some(2), None, &ctx).await, Some(2));
        assert_eq!(
            walk_total(&counted, None, Some(Utc::now()), &ctx).await,
            None
        );
        assert_eq!(walk_total(&failed, None, None, &ctx).await, None);
    }
}
