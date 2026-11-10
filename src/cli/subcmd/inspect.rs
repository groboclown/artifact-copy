//! `artifact-copy inspect`.
//!
//! Dispatch only: it turns parsed arguments into a
//! [`commands::inspect::Request`], opens somewhere to write, and lets
//! [`commands::inspect::run`] do the work. Deciding *what* to inspect is
//! not here, which is what lets an embedder run the same inspection without
//! an argument parser.
//!
//! # Where the report's frame comes from
//!
//! The artifacts are written by the visitor as they are found, and the
//! **header and summary** are written here. That split is deliberate: a
//! header states what produced the report and what it screened against,
//! and a summary states what the run as a whole did -- neither is something
//! a walk knows while it is walking.

use super::super::subcmd;
use crate::Ctx;
use crate::advisory::Screen;
use crate::cli::DiscoverArgs;
use crate::commands::inspect;
use crate::commands::report::ToReport;
use crate::core::error::{Error, Result};
use crate::core::problem::Action;
use crate::core::progress;
use crate::report::{Binding, Part, Record, ReportWriter, Role, Summary};
use crate::session::Session;
use crate::version::PreRelease;

/// Inspect what a report says the source holds.
///
/// Refuses rather than choosing when the user has also named artifacts:
/// two answers to "what should this run look at" is a question for the
/// person who typed them, and silently preferring one would produce a
/// report of work nobody asked for.
async fn from_report(
    session: &mut Session<'_>,
    request: &inspect::Request<'_>,
    visitor: &ToReport,
    progress: &crate::core::progress::Node,
    ctx: &Ctx,
    args: &DiscoverArgs,
) -> Result<crate::commands::spider::Summary> {
    if !args.artifacts.is_empty() || !args.resolution.locks.is_empty() {
        return Err(Error::Config(
            "--from-db takes the artifacts from the database, so naming artifacts \
             or a lock file as well says two different things"
                .to_owned(),
        ));
    }

    let Some(query) = visitor.query()? else {
        return Err(Error::Config(
            "--from-db needs a report database; use --db=FILE".to_owned(),
        ));
    };

    let manifest = subcmd::manifest(&args.report);

    inspect::from_report(
        session,
        request,
        query,
        &manifest,
        Some(visitor),
        visitor,
        progress,
        ctx,
    )
    .await
}

/// Run the sub-command.
pub async fn run(session: &mut Session<'_>, args: &DiscoverArgs, ctx: &Ctx) -> Result<()> {
    let writer = subcmd::store(
        &args.report,
        &[Part::Source, Part::Spider],
        subcmd::Scratch::Under(session.cache_root()),
    )
    .await?;
    let (visitor, logged) = subcmd::logged(writer, ctx);

    let (screening, index) = subcmd::opened(
        session,
        visitor.as_ref(),
        "inspect",
        &args.resolution.advisories,
        ctx,
    )
    .await?;

    // Declared before the walk, so anything the report keys on a repository
    // is keyed on a row that already exists.
    subcmd::bind(
        visitor.as_ref(),
        &[Binding::new(Role::Source, &args.from).observing()],
    )?;

    // After the header, so the first problem line cannot precede it, and
    // before the walk, so every problem the walk records is written where
    // it happened rather than summarised at the end.
    ctx.problems().watched_by(logged);

    // Before the walk rather than during it: a corpus is an index built
    // once, so whether screening *can* answer is known before the first
    // artifact rather than discovered part-way through one.
    subcmd::screening_ready(session, &screening, ctx);

    let progress = ctx.progress("inspect", progress::Unit::Items, None);

    let request = inspect::Request {
        source: &args.from,
        artifacts: &args.artifacts,
        locks: &args.resolution.locks,
        spider: args.resolution.dependencies.clone(),
        pre: match args.resolution.pre_release {
            true => PreRelease::Include,
            false => PreRelease::Exclude,
        },

        screen: Some(Screen {
            index: &index,
            screening: &screening,
        }),
    };

    let outcome = match args.from_db {
        false => {
            let cache = visitor.query()?;

            let report: &dyn ReportWriter = visitor.as_ref();

            inspect::run(
                session,
                &request,
                cache,
                Some(report),
                visitor.as_ref(),
                &progress,
                ctx,
            )
            .await
        }

        true => from_report(session, &request, &visitor, &progress, ctx, args).await,
    };

    progress.finish();

    let stale = subcmd::stale_suppressions(session, &screening, ctx);

    // The summary is written **whatever happened**, because a report
    // without one means "the run did not finish" and that is exactly what
    // a reader needs to be told when it did not. The error is returned
    // after, so the exit code still reflects it.
    visitor.write(&Record::Summary(Summary {
        artifacts: visitor.artifact_count(),
        counts: ctx.problems().counts(),
        quarantined: ctx.problems().quarantined(),
        worst_action: ctx.problems().worst().unwrap_or(Action::Ignore),
        unmatched_suppressions: stale,
    }))?;

    subcmd::closed(visitor.as_ref(), subcmd::completion(&outcome, ctx))?;

    outcome?;

    Ok(())
}
