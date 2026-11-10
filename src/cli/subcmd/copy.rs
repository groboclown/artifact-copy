//! `artifact-copy copy`.
//!
//! Dispatch only: names in, a [`commands::copy::Request`] out, the report
//! framed, and the result logged.
//!
//! The report is the same one `inspect` writes, in the same format, to the
//! same places -- and it lists **every** artifact the run reached, with what
//! became of each. A report of only what was copied would answer "what is
//! in the target", which the target answers better; what only the run can
//! say is why something it reached did not get there.

use super::super::subcmd;
use crate::Ctx;
use crate::advisory::Screen;
use crate::cli::CopyArgs;
use crate::commands::{copy, inspect};
use crate::core::error::{Error, Result};
use crate::core::problem::Action;
use crate::core::progress;
use crate::report::{Binding, Part, Record, ReportWriter, Role, Summary};
use crate::session::Session;
use crate::version::PreRelease;

/// Run the sub-command.
pub async fn run(session: &mut Session<'_>, args: &CopyArgs, ctx: &Ctx) -> Result<()> {
    let (source, targets) = ends(args)?;

    let writer = subcmd::store(
        &args.report,
        &[Part::Source, Part::Target, Part::Payloads, Part::Spider],
        subcmd::Scratch::Under(session.cache_root()),
    )
    .await?;

    let (report, logged) = subcmd::logged(writer, ctx);

    // How the work list names itself in provenance, so a reader of the
    // report can see which file the artifacts came from.
    let manifest = subcmd::manifest(&args.report);

    let (screening, index) = subcmd::opened(
        session,
        report.as_ref(),
        "copy",
        &args.resolution.advisories,
        ctx,
    )
    .await?;

    let bindings: Vec<Binding> = std::iter::once(Binding::new(Role::Source, source).observing())
        .chain(
            targets
                .iter()
                .map(|target| Binding::new(Role::Target, target)),
        )
        .collect();

    subcmd::bind(report.as_ref(), &bindings)?;

    // After the header, so the first problem line cannot precede it, and
    // before the walk, so every problem the walk records is written where
    // it happened rather than summarised at the end.
    ctx.problems().watched_by(logged);

    // Before the walk, for the reason `inspect` gives. It matters more
    // here: this is the command that publishes bytes, so a run that
    // screened nothing is the one worth refusing.
    subcmd::screening_ready(session, &screening, ctx);

    let progress = ctx.progress("copy", progress::Unit::Items, None);

    let request = copy::Request {
        what: inspect::Request {
            source,
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
        },
        targets,
        from: match args.from_db {
            true => copy::From::Report {
                manifest: &manifest,
            },
            false => copy::From::Requested,
        },
    };

    let outcome = copy::run(session, &request, report.as_ref(), &progress, ctx).await;

    progress.finish();

    let stale = subcmd::stale_suppressions(session, &screening, ctx);

    // Written **whatever happened**, for the reason `inspect` gives: a
    // report without a summary means the run did not finish, and that is
    // exactly what a reader needs to be told when it did not. The error is
    // returned after, so the exit code still reflects it.
    report.write(&Record::Summary(Summary {
        artifacts: report.artifact_count(),
        counts: ctx.problems().counts(),
        quarantined: ctx.problems().quarantined(),
        worst_action: ctx.problems().worst().unwrap_or(Action::Ignore),
        unmatched_suppressions: stale,
    }))?;

    subcmd::closed(report.as_ref(), subcmd::completion(&outcome, ctx))?;

    // One line per target, so a run with several says what each took.
    for line in copy::describe(&outcome?) {
        ctx.log().info(line);
    }

    Ok(())
}

/// The source and the targets a copy runs between.
fn ends(args: &CopyArgs) -> Result<(&str, &[String])> {
    // Caught here rather than by `clap`, which cannot express "both or
    // neither" without making the error worse than the explanation.
    let (Some(source), false) = (&args.from, args.to.is_empty()) else {
        return Err(Error::Config("copy needs both --from and --to".to_owned()));
    };

    // Refused rather than collapsed: a name given twice is a typo for
    // another target more often than a wish to publish twice.
    for (index, target) in args.to.iter().enumerate() {
        if args.to[..index].contains(target) {
            return Err(Error::Config(format!(
                "copy names target {target:?} more than once in --to"
            )));
        }
    }

    Ok((source, &args.to))
}
