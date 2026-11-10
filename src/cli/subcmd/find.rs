//! `artifact-copy find`.
//!
//! Dispatch only, and deliberately the same shape as
//! [`super::inspect`]: open somewhere to write, frame the report with a
//! header and a summary, and let [`commands::find::run`] do the walk.
//!
//! The two commands write **one** report format. That is the point of
//! sharing `ToReport` between them: a reader should not have to know which
//! sub-command produced a file.

use chrono::{DateTime, SecondsFormat, Utc};

use super::super::subcmd;
use crate::Ctx;
use crate::advisory::Screen;
use crate::cli::FindArgs;
use crate::commands::find::{self, Span};
use crate::commands::report::ToReport;
use crate::core::error::{Error, Result};
use crate::core::problem::Action;
use crate::core::progress;
use crate::report::{Binding, Part, Record, ReportWriter, Resume, Role, Summary};
use crate::session::Session;

/// Run the sub-command.
pub async fn run(session: &mut Session<'_>, args: &FindArgs, ctx: &Ctx) -> Result<()> {
    let writer = subcmd::store(&args.report, &[Part::Enumeration], subcmd::Scratch::Never).await?;
    let (visitor, logged) = subcmd::logged(writer, ctx);

    let (screening, index) =
        subcmd::opened(session, visitor.as_ref(), "find", &args.advisories, ctx).await?;

    // An artifact enumeration describes some repository. Usually that is the
    // enumerator itself; `--as-target` says it is the target the enumerator
    // points at, which is what lets a later copy ask the report what the
    // target holds instead of asking the target once per artifact.
    // `--as-source` says the same of a source, which is what a later
    // `--from-db` reads its work from.
    //
    // The equivalence is the user's assertion, made per run. The database
    // records what the enumeration saw and never that one repository *is*
    // another.
    // The two flags conflict, because two observed bindings attribute
    // nothing. `--from` names a repository, whose enumerator and source
    // share its name, so it implies `--as-source`.
    let (enumerator, as_source) = walked(args)?;
    let scanning = Binding::new(Role::Enumerator, enumerator);

    let bindings = match (&args.as_target, as_source) {
        (Some(target), _) => vec![scanning, Binding::new(Role::Target, target).observing()],

        (None, Some(source)) => vec![scanning, Binding::new(Role::Source, source).observing()],

        (None, None) => vec![scanning.observing()],
    };

    subcmd::bind(visitor.as_ref(), &bindings)?;

    // An interrupted walk continues where it stopped, unless
    // `--refresh=enumeration` blanked it. Asked before this run's own
    // checkpoints can replace it.
    let resume = match visitor.query()? {
        Some(query) => query.resume_enumeration(Role::Enumerator, enumerator)?,
        None => None,
    };

    let since = since(args, enumerator, visitor.as_ref(), resume.as_ref())?;

    // After the header, so the first problem line cannot precede it, and
    // before the walk, so every problem the walk records is written where
    // it happened rather than summarised at the end.
    ctx.problems().watched_by(logged);

    // Before the walk, for the reason `inspect` gives.
    subcmd::screening_ready(session, &screening, ctx);

    let progress = ctx.progress("find", progress::Unit::Items, None);

    let span = Span {
        sample: args.sample_size,
        resume,
        since,
    };

    let outcome = find::run(
        session,
        enumerator,
        span,
        visitor.as_ref(),
        Some(Screen {
            index: &index,
            screening: &screening,
        }),
        &progress,
        ctx,
    )
    .await;

    progress.finish();

    // The enumerator's security policy, which screened what it listed.
    let stale = subcmd::stale_suppressions(session, &screening, ctx);

    // Written whatever happened: a report without a summary means the run
    // did not finish, and that is what a reader needs told when it did not.
    visitor.write(&Record::Summary(Summary {
        artifacts: visitor.artifact_count(),
        counts: ctx.problems().counts(),
        quarantined: ctx.problems().quarantined(),
        worst_action: ctx.problems().worst().unwrap_or(Action::Ignore),
        unmatched_suppressions: stale,
    }))?;

    subcmd::closed(visitor.as_ref(), subcmd::completion(&outcome, ctx))?;

    // A walk narrowed by date says how much changed, which is what tells a
    // user whether another pass is needed.
    ctx.log().info(find::describe(&outcome?));

    Ok(())
}

/// The date this run's walk is narrowed to: the start of the last walk of
/// `enumerator` that reached the end.
///
/// None without a database, under `--rescan-all`, and for a sampled walk,
/// which asks for part of the catalog rather than for what changed. An
/// interrupted narrowed walk is refused beside `--rescan-all`, since the
/// two ask for different walks and resuming takes the cursor it left.
fn since(
    args: &FindArgs,
    enumerator: &str,
    visitor: &ToReport,
    resume: Option<&Resume>,
) -> Result<Option<DateTime<Utc>>> {
    let pending = resume.and_then(|resume| find::narrowed_since(resume.scope.as_deref()));

    if let (true, Some(pending)) = (args.rescan_all, pending) {
        return Err(Error::Config(format!(
            "enumerator {enumerator:?} has an interrupted walk of what changed since {}; \
             finish it, or pass --refresh=enumeration to drop it before --rescan-all",
            pending.to_rfc3339_opts(SecondsFormat::Millis, true)
        )));
    }

    if args.rescan_all || args.sample_size.is_some() {
        return Ok(None);
    }

    let Some(query) = visitor.query()? else {
        return Ok(None);
    };

    query.last_complete_enumeration(Role::Enumerator, enumerator)
}

/// The enumerator to walk, and the source it stands for.
///
/// `--from=X` walks enumerator `X` as source `X`: lowering names a
/// repository's enumerator and source alike.  `--enumerator` keeps the
/// explicit `--as-source`.
fn walked(args: &FindArgs) -> Result<(&str, Option<&str>)> {
    if let Some(from) = &args.from {
        return Ok((from, Some(from)));
    }

    // Unreachable through clap, whose group requires one of the two.
    let enumerator = args
        .enumerator
        .as_deref()
        .ok_or_else(|| Error::Config("find needs --from or --enumerator".to_owned()))?;

    Ok((enumerator, args.as_source.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn find(argv: &[&str]) -> FindArgs {
        let mut full = vec!["artifact-copy", "find"];
        full.extend_from_slice(argv);

        match crate::cli::Cli::try_parse_from(full)
            .expect("parses")
            .command
        {
            crate::cli::Command::Find(args) => args,
            _ => panic!("expected find"),
        }
    }

    #[test]
    fn from_walks_as_own_source() {
        let args = find(&["--from=nexus-npm"]);

        assert_eq!(
            walked(&args).expect("walks"),
            ("nexus-npm", Some("nexus-npm"))
        );
    }

    #[test]
    fn enumerator_keeps_explicit_binding() {
        let bare = find(&["--enumerator=e"]);
        let bound = find(&["--enumerator=e", "--as-source=s"]);

        assert_eq!(walked(&bare).expect("walks"), ("e", None));
        assert_eq!(walked(&bound).expect("walks"), ("e", Some("s")));
    }
}
