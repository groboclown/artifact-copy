//! The sub-commands of the one command a user runs.
//!
//! `artifact-copy` takes a verb -- `validate-config`, `inspect`,
//! `copy` -- and each is dispatched here: parsed arguments in, a
//! [`Session`] opened, the work handed to
//! [`crate::commands`], and an outcome the binary turns into an exit code.
//!
//! Each sub-command in `README.md` has a module here.

use std::path::Path;
use std::sync::Arc;

use super::{Cli, Command};
use crate::Ctx;
use crate::advisory::{self, Ecosystems, Freshness, Index, Screening};
use crate::cli::logging::Logging;
use crate::cli::{AdvisoryArgs, ConfigLoader, DbChoice, ReportArgs};
use crate::commands::report::ToReport;
use crate::config::Config;
use crate::core::error::{Error, Result};
use crate::core::log::Log;
use crate::core::problem::{Action, Code};
use crate::message;
use crate::report::{Completion, DbSpec, Logged, Part, Record, ReportWriter, Summary, header};
use crate::session::Session;

mod copy;
mod find;
mod inspect;
mod validate_config;

pub(crate) use validate_config::Findings;

/// Run the parsed command.
///
/// Returns the worst action taken, which the caller turns into an exit code.
pub async fn run(cli: Cli, ctx: &Ctx, logging: &Logging) -> Result<Action> {
    match &cli.command {
        // The one command that must **not** go through `working_ctx`: it
        // reports a broken configuration as a finding, so failing to load
        // one is its subject rather than an obstacle to it.
        Command::ValidateConfig(args) => {
            let probe = match args.probe_extensions {
                true => validate_config::Probe::Extensions,
                false => validate_config::Probe::NamesOnly,
            };

            let findings = validate_config::run(&cli.global.configs, probe, ctx)?;
            report_validation(&findings, ctx.log());
        }

        Command::Inspect(args) => {
            let config = configured(&cli, logging)?;
            let mut session = session(&cli, &config, ctx)?;

            inspect::run(&mut session, args, ctx).await?;
        }

        Command::Find(args) => {
            let config = configured(&cli, logging)?;
            let mut session = session(&cli, &config, ctx)?;

            find::run(&mut session, args, ctx).await?;
        }

        Command::Copy(args) => {
            let config = configured(&cli, logging)?;
            let mut session = session(&cli, &config, ctx)?;

            copy::run(&mut session, args, ctx).await?;
        }
    }

    Ok(ctx.problems().worst().unwrap_or(Action::Ignore))
}

/// Plan what this run screens against.
///
/// Every configured advisor starts out not consulted, because nothing
/// consults one yet -- see `TODO.md`'s *Advisories*. The point of building the
/// state anyway is that the report's header now says so, and a corpus that
/// starts answering fills the same structure without a call site changing.
///
/// Shared by the three report-writing sub-commands, which reach
/// `--no-advisories` through different argument groups but mean the same
/// thing by it.
/// The report a sub-command writes, logging each record as it goes.
///
/// The tee comes back too, for the problem sink to watch once the header
/// is written.
pub(super) fn logged(
    writer: Box<dyn crate::report::ReportWriter>,
    ctx: &Ctx,
) -> (Arc<ToReport>, Arc<Logged>) {
    let logged = Arc::new(Logged::new(writer, ctx.log().clone()));
    let report = Arc::new(ToReport::new(Box::new(Arc::clone(&logged))));

    (report, logged)
}

/// Tell a report which repositories this run uses.
///
/// A line report keeps no state, so it has nothing to be told and this is a
/// no-op rather than an error. Refusing every command that does not write a
/// database would make the database the only supported format.
///
/// The endpoint details are left out for now: a binding's identity is its
/// role and its name, and the host and base URL are recorded only as last
/// seen. They arrive when the session is asked to describe a repository.
pub(super) fn bind(
    report: &dyn crate::report::ReportWriter,
    bindings: &[crate::report::Binding<'_>],
) -> Result<()> {
    let Some(state) = report.state() else {
        return Ok(());
    };

    for binding in bindings {
        state.bind(binding)?;
    }

    Ok(())
}

/// Whether a sub-command without `--db` keeps a temporary database.
#[derive(Debug, Clone, Copy)]
pub(super) enum Scratch<'a> {
    /// Under this cache root, for a command that walks dependencies: its
    /// frontier and visited set then live on disk rather than in memory.
    Under(&'a Path),

    /// None, for a command that holds nothing that grows with a walk.
    Never,
}

/// Open where a sub-command writes its run: the line report, the database,
/// or both.
///
/// `accepts` is the `--refresh` parts this sub-command uses. Any other is
/// refused, because a part that changes nothing reads as though it did.
/// Example: `find --refresh=target` has no target to refresh.
///
/// Without `--db`, `scratch` decides whether the run keeps a temporary
/// database; `--db=-` keeps none.
pub(super) async fn store(
    args: &ReportArgs,
    accepts: &[Part],
    scratch: Scratch<'_>,
) -> Result<Box<dyn crate::report::ReportWriter>> {
    let choice = args.db_choice();

    if choice == DbChoice::Declined && !args.refresh.is_empty() {
        return Err(Error::Config(
            "--refresh needs a report database, and --db=- keeps none".to_owned(),
        ));
    }

    let unused: Vec<&str> = args
        .refresh
        .iter()
        .filter(|part| **part != Part::All && !accepts.contains(part))
        .map(|part| part.as_str())
        .collect();

    if !unused.is_empty() {
        let accepted: Vec<&str> = accepts.iter().map(|part| part.as_str()).collect();

        return Err(Error::Config(format!(
            "--refresh={} means nothing here; this command accepts {}, and all",
            unused.join(","),
            accepted.join(", ")
        )));
    }

    let database = match (args.database(), choice, scratch) {
        (Some(named), _, _) => Some(named),
        (None, DbChoice::Unsaid, Scratch::Under(root)) => Some(DbSpec::scratch(root)?),
        (None, _, _) => None,
    };

    crate::report::open(args.line().as_ref(), database.as_ref()).await
}

/// How a run reading its work from the database names it in provenance.
pub(super) fn manifest(args: &ReportArgs) -> String {
    args.db
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<db>".to_owned())
}

/// Plan the run's screening, and load every configured advisor into one
/// index unless `--no-advisories` said not to.
pub(super) async fn screening(
    session: &mut Session<'_>,
    args: &AdvisoryArgs,
    ctx: &Ctx,
) -> Result<(Screening, Index)> {
    let names: Vec<String> = session.advisors().map(str::to_owned).collect();
    let mut screening = Screening::plan(names.iter().cloned(), args.no_advisories);
    let mut index = Index::new(Ecosystems::builtin());

    if args.no_advisories {
        return Ok((screening, index));
    }

    let freshness = match args.refresh_advisories {
        true => Freshness::Refresh,
        false => Freshness::Cached,
    };

    // Under the run's dispositions, for the reason `screening_ready` gives.
    let deciding = session.deciding(ctx);

    // Built before anything loads, so a configuration fault stops the run
    // rather than reading as one corpus being down.
    let mut advisors = Vec::with_capacity(names.len());

    for name in names {
        let advisor = session.advisor(&name)?;
        advisors.push((name, advisor));
    }

    for (name, advisor) in &advisors {
        advisory::consult(
            name,
            advisor.as_ref(),
            &mut index,
            &mut screening,
            freshness,
            &deciding,
        )
        .await;
    }

    Ok((screening, index))
}

/// Screen, then open the run on its header.
///
/// The header says what was screened, so screening comes first. A screening
/// that fails still opens the run, under the plan it never got past, and
/// closes it: without a row, a run that died here is indistinguishable from
/// one that never started.
pub(super) async fn opened(
    session: &mut Session<'_>,
    report: &dyn ReportWriter,
    command: &str,
    args: &AdvisoryArgs,
    ctx: &Ctx,
) -> Result<(Screening, Index)> {
    let failed = match screening(session, args, ctx).await {
        Ok((screening, index)) => {
            report.write(&Record::Header(header(command, &screening)))?;

            return Ok((screening, index));
        }

        Err(err) => err,
    };

    let planned = Screening::plan(session.advisors().map(str::to_owned), args.no_advisories);

    report.write(&Record::Header(header(command, &planned)))?;
    report.write(&Record::Summary(Summary {
        artifacts: 0,
        counts: ctx.problems().counts(),
        quarantined: ctx.problems().quarantined(),
        worst_action: ctx.problems().worst().unwrap_or(Action::Ignore),
        unmatched_suppressions: Vec::new(),
    }))?;

    closed(report, completion(&Err::<(), _>(&failed), ctx))?;

    Err(failed)
}

/// How a command's outcome ends its run.
///
/// Cancelled wins over the outcome: an interrupted walk can end `Ok` with
/// what it got through, and that is still not a run that finished.
pub(super) fn completion<T, E>(outcome: &std::result::Result<T, E>, ctx: &Ctx) -> Completion {
    if ctx.is_cancelled() {
        return Completion::Cancelled;
    }

    match outcome {
        Ok(_) => Completion::Finished,
        Err(_) => Completion::Failed,
    }
}

/// Close the run, saying how it ended.
pub(super) fn closed(report: &dyn ReportWriter, how: Completion) -> Result<()> {
    if let Some(state) = report.state() {
        state.complete(how)?;
    }

    report.flush()
}

/// Say so when screening was asked for and did not happen.
///
/// `docs/contributors/exit-codes.md` treats an unavailable screening
/// resource more harshly than an unavailable *content* one, because "the
/// consequence isn't a missing artifact but a **wrong answer**: a run that
/// copies everything and reports nothing looks identical to a clean run".
/// `advisory-source-unavailable` aborts by default for that reason, and the
/// `problem-policy` table is how a user who accepts the risk says so as a
/// standing decision. `--no-advisories` is the same statement for one run,
/// and is already recorded in the header rather than raised here.
///
/// Reporting an `Abort` cancels the run through the context, so there is no
/// control flow to add at the call sites: the walk unwinds on its own and the
/// summary is still written, which is what a reader needs.
///
/// Reported through [`Session::deciding`] rather than the bare context. A root
/// `Ctx` decides under an **empty** `Policy`, so the `problem-policy` table
/// would be ignored here and the escape hatch this problem is worth having
/// would not work. The sub-commands get away with the bare context elsewhere
/// only because the walk derives its own further down.
pub(super) fn screening_ready(session: &Session<'_>, screening: &Screening, ctx: &Ctx) {
    if !screening.expected() || screening.ran() {
        return;
    }

    session.deciding(ctx).report(
        Code::AdvisorySourceUnavailable,
        message!(
            "advisory-source-unavailable",
            "screening was configured and no advisory corpus answered, \
             so a clean report would not mean anything",
        ),
    );
}

/// The suppressions this run showed to be dead policy, reported and returned.
///
/// Reported here rather than by the caller so the problems land **before**
/// the summary is built: `counts` is read when the `Summary` literal is
/// constructed, and a summary listing suppressions its own counts do not
/// mention would be two answers to one question.
///
/// `vex-unmatched` is a warning by default, so this never changes whether a
/// run succeeded unless a user asked it to -- only what it says about the
/// policy it ran under. Decided under the run's dispositions for the reason
/// [`screening_ready`] gives, so that asking is possible at all.
pub(super) fn stale_suppressions(
    session: &Session<'_>,
    screening: &Screening,
    ctx: &Ctx,
) -> Vec<String> {
    let stale = screening.stale();
    let deciding = session.deciding(ctx);

    for statement in &stale {
        deciding.report(
            Code::VexUnmatched,
            message!(
                "vex-unmatched",
                "the suppression {statement} was asked about and cleared nothing",
                statement = statement,
            ),
        );
    }

    stale
}

/// Load the configuration a command was pointed at.
fn load(cli: &Cli) -> Result<Config> {
    let mut loader = ConfigLoader::new();

    for path in &cli.global.configs {
        loader = loader.add_path(path);
    }

    loader.load()
}

/// Load the configuration, and apply its logging settings.
fn configured(cli: &Cli, logging: &Logging) -> Result<Config> {
    let config = load(cli)?;
    logging.configure(config.setup.log.as_ref())?;

    Ok(config)
}

/// The session an artifact-handling command runs under.
///
/// Errors rather than carrying on with defaults. An unreadable quarantine
/// policy would otherwise read as every exception in it having been
/// revoked, which is a silent tightening -- and the run would look like it
/// had honoured a file nobody could read.
///
/// Borrows the configuration, so a caller holds it for as long as the
/// session: see [`Session`].
fn session<'c>(cli: &Cli, config: &'c Config, ctx: &Ctx) -> Result<Session<'c>> {
    Ok(Session::open(config, cli.global.harden)?.logging_with(ctx.log().clone()))
}

fn report_validation(findings: &Findings, log: &Log) {
    if findings.is_ok() {
        log.info(format_args!(
            "configuration is valid: files={}, policies={}, secrets={}",
            findings.checked_files,
            findings.policies.len(),
            findings.resolved_secrets,
        ));

        return;
    }

    for complaint in &findings.complaints {
        log.error(complaint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stopped run is cancelled whatever the command returned; otherwise
    /// the outcome decides.
    #[test]
    fn completion_follows_outcome_and_stop() {
        let ctx = Ctx::anonymous_for_test();
        let ok: std::result::Result<(), ()> = Ok(());
        let err: std::result::Result<(), ()> = Err(());

        assert_eq!(completion(&ok, &ctx), Completion::Finished);
        assert_eq!(completion(&err, &ctx), Completion::Failed);

        ctx.stop(crate::core::cancel::Reason::Interrupted);

        assert_eq!(completion(&ok, &ctx), Completion::Cancelled);
        assert_eq!(completion(&err, &ctx), Completion::Cancelled);
    }

    fn report_args(argv: &[&str]) -> ReportArgs {
        let mut full = vec!["artifact-copy", "find", "--from=s"];
        full.extend_from_slice(argv);

        match Cli::try_parse_from(full).expect("parses").command {
            crate::cli::Command::Find(args) => args.report,
            _ => panic!("expected find"),
        }
    }

    #[tokio::test]
    async fn store_unused_part_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = format!("--db={}", dir.path().join("r.db").display());
        let args = report_args(&[&db, "--refresh=enumeration,target"]);

        let Err(err) = store(&args, &[Part::Enumeration], Scratch::Never).await else {
            panic!("an unused part was accepted");
        };

        let err = err.to_string();

        assert!(err.contains("--refresh=target"), "{err}");
        assert!(err.contains("enumeration"), "{err}");
    }

    #[tokio::test]
    async fn store_takes_all_anywhere() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = format!("--db={}", dir.path().join("r.db").display());
        let args = report_args(&[&db, "--refresh=all"]);

        store(&args, &[Part::Enumeration], Scratch::Never)
            .await
            .expect("opens");
    }

    /// The entries under a cache root that are run databases.
    fn scratch_dirs(root: &Path) -> usize {
        std::fs::read_dir(root)
            .expect("listed")
            .filter(|entry| {
                entry
                    .as_ref()
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("(run-db)")
            })
            .count()
    }

    /// Without `--db`, a walking command keeps a database for the run under
    /// the cache root, and removes it with the writer. The text report still
    /// goes to standard output.
    #[tokio::test]
    async fn store_without_db_keeps_scratch_for_run() {
        let root = tempfile::tempdir().expect("tempdir");
        let args = report_args(&[]);

        let writer = store(&args, &[], Scratch::Under(root.path()))
            .await
            .expect("opens");

        assert!(writer.query().expect("queries").is_some());
        assert_eq!(scratch_dirs(root.path()), 1);
        assert!(args.line().is_some());

        drop(writer);

        assert_eq!(scratch_dirs(root.path()), 0);
    }

    /// `--db=-` keeps no database at all, and the text report stays.
    #[tokio::test]
    async fn store_declined_db_keeps_none() {
        let root = tempfile::tempdir().expect("tempdir");
        let args = report_args(&["--db=-"]);

        let writer = store(&args, &[], Scratch::Under(root.path()))
            .await
            .expect("opens");

        assert!(writer.query().expect("queries").is_none());
        assert!(args.line().is_some());
        assert_eq!(scratch_dirs(root.path()), 0);
    }

    #[tokio::test]
    async fn store_declined_db_refresh_refused() {
        let args = report_args(&["--db=-", "--refresh=all"]);

        let Err(err) = store(&args, &[], Scratch::Never).await else {
            panic!("--refresh was accepted with no database");
        };

        assert!(err.to_string().contains("--db=-"), "{err}");
    }

    use crate::cli::Cli;
    use crate::core::message::Message;
    use crate::core::problem::{Code, Quarantine};
    use crate::model::{ArtifactId, Cause, EcosystemId, Release, Version};
    use clap::Parser;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("written");

        path
    }

    fn config(dir: &std::path::Path, setup: &str) -> std::path::PathBuf {
        write(
            dir,
            "config.json",
            &format!(
                r#"{{"$schema":"{}","setup":{setup}}}"#,
                crate::cli::config_schema_id()
            ),
        )
    }

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("artifact-copy").chain(args.iter().copied()))
            .expect("parses")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "x".into() })
    }

    /// Report `code` against one artifact through a context built from
    /// these arguments, and say what happened.
    ///
    /// Through `report` rather than by reading the context's decider,
    /// because that is the path a command actually takes: a decider wired
    /// to nothing would still answer correctly on its own.
    fn reported(args: &[&str], code: Code) -> (Action, Option<Quarantine>) {
        let parsed = cli(args);
        let config = load(&parsed).expect("loads");
        let built = session(&parsed, &config, &ctx())
            .expect("built")
            .deciding(&ctx());

        let at = built.for_artifact(
            ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            Some(Version::new("1.0.0", Release::General)),
        );

        let action = at.report(code, Message::new("x"));
        let recorded = at.problems().tail();

        (action, recorded.last().expect("recorded").quarantine())
    }

    /// The flag has to reach the thing that decides, or it is a switch
    /// wired to nothing -- which is exactly what a test of `Dispositions`
    /// alone would not catch.
    #[test]
    fn harden_flag_reaches_working_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = config(dir.path(), "{}");
        let path = path.to_str().expect("utf-8");

        let soft = Code::SignatureMissing;

        assert_eq!(reported(&["--config", path, "copy"], soft).0, Action::Warn);
        assert_eq!(
            reported(&["--config", path, "--harden", "copy"], soft).0,
            Action::SkipArtifact
        );
    }

    /// And the configuration can ask for it without the flag.
    #[test]
    fn harden_configured_without_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = config(dir.path(), r#"{"harden-quarantine":true}"#);

        let (action, class) = reported(
            &["--config", path.to_str().expect("utf-8"), "copy"],
            Code::SignatureMissing,
        );

        assert_eq!(action, Action::SkipArtifact);

        // Still the soft reservation it was: hardening changes what soft
        // does this run, not what the reservation is.
        assert_eq!(class, Some(Quarantine::Soft));
    }

    /// The quarantine policy file reaches the same place, so a per-artifact
    /// exception is in force for the whole command rather than for whoever
    /// remembered to load it.
    #[test]
    fn policy_quarantine_reaches_working_context() {
        let dir = tempfile::tempdir().expect("tempdir");

        write(
            dir.path(),
            "q.json",
            &format!(
                r#"{{"$schema":"{}","rules":[{{"purl":"pkg:npm/tuna","codes":["malware-known"],"class":"allowed","expires":"never"}}]}}"#,
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        );

        let path = config(dir.path(), r#"{"quarantine-policy":"q.json"}"#);

        let (action, class) = reported(
            &["--config", path.to_str().expect("utf-8"), "copy"],
            Code::MalwareKnown,
        );

        assert_eq!(action, Action::Warn, "the default would have skipped");
        assert_eq!(class, None);
    }

    /// A named policy file that will not load stops the command. Carrying
    /// on with defaults would read as every exception in it having been
    /// revoked, and the run would look like it had honoured a file nobody
    /// could read.
    #[tokio::test]
    async fn policy_quarantine_broken_stops_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = config(dir.path(), r#"{"quarantine-policy":"nowhere.json"}"#);

        let (_subscriber, logging) = crate::cli::logging::for_test();

        let err = run(
            cli(&["--config", path.to_str().expect("utf-8"), "copy"]),
            &ctx(),
            &logging,
        )
        .await
        .expect_err("refused");

        // Not `Unimplemented`: the policy is checked before the body runs.
        assert!(!matches!(err, Error::Unimplemented(_)), "{err}");
    }

    /// `validate-config` is the exception, and deliberately so: a broken
    /// configuration is its subject, so it reports rather than refuses.
    #[tokio::test]
    async fn policy_quarantine_broken_validate_reports() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = config(dir.path(), r#"{"quarantine-policy":"nowhere.json"}"#);

        let (_subscriber, logging) = crate::cli::logging::for_test();

        run(
            cli(&["--config", path.to_str().expect("utf-8"), "validate-config"]),
            &ctx(),
            &logging,
        )
        .await
        .expect("reports rather than refusing");
    }

    // -- Screening ---------------------------------------------------------

    /// A configuration naming one advisor, plus whatever else is given.
    ///
    /// Its corpus is a file that is not there, so loading it fails without
    /// a request.
    fn advisor_config(dir: &std::path::Path, extra: &str) -> std::path::PathBuf {
        write(
            dir,
            "config.json",
            &format!(
                r#"{{"$schema":"{}",
                    "hosts":{{"osv":{{"url":"https://osv.invalid/"}}}},
                    "advisors":{{"osv":{{"kind":"osv-offline","host":"osv",
                                         "path":{}}}}}{extra}}}"#,
                crate::cli::config_schema_id(),
                serde_json::json!(dir.join("nowhere.zip")),
            ),
        )
    }

    fn advisory_args(no_advisories: bool) -> AdvisoryArgs {
        AdvisoryArgs {
            no_advisories,
            refresh_advisories: false,
        }
    }

    async fn planned(built: &mut Session<'_>, no_advisories: bool, ctx: &Ctx) -> Screening {
        screening(built, &advisory_args(no_advisories), ctx)
            .await
            .expect("planned")
            .0
    }

    /// Screening that was asked for and did not happen aborts by default:
    /// `docs/contributors/exit-codes.md` would rather refuse to answer than
    /// answer "nothing found" when the truth is "nothing was asked".
    #[tokio::test]
    async fn screening_unavailable_aborts_by_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = advisor_config(dir.path(), "");
        let parsed = cli(&["--config", path.to_str().expect("utf-8"), "validate-config"]);
        let config = load(&parsed).expect("loads");
        let mut built = session(&parsed, &config, &ctx()).expect("built");
        let ctx = ctx();
        let planned = planned(&mut built, false, &ctx).await;

        screening_ready(&built, &planned, &ctx);

        assert_eq!(ctx.problems().worst(), Some(Action::Abort));
        assert_eq!(
            ctx.problems()
                .counts()
                .get(&Code::AdvisorySourceUnavailable),
            Some(&1)
        );
    }

    /// **The escape hatch, and the bug this pins.** Reported through the bare
    /// context, a root `Ctx` decides under an empty policy and the table is
    /// silently ignored -- so the one setting that lets somebody run
    /// unscreened as a standing decision would do nothing at all.
    #[tokio::test]
    async fn screening_unavailable_downgraded_by_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = advisor_config(
            dir.path(),
            r#","problem-policy":{"advisory-source-unavailable":"allowed"}"#,
        );
        let parsed = cli(&["--config", path.to_str().expect("utf-8"), "validate-config"]);
        let config = load(&parsed).expect("loads");
        let mut built = session(&parsed, &config, &ctx()).expect("built");
        let ctx = ctx();
        let planned = planned(&mut built, false, &ctx).await;

        screening_ready(&built, &planned, &ctx);

        assert_eq!(ctx.problems().worst(), Some(Action::Warn));
        assert!(!ctx.problems().is_aborted());
    }

    /// `--no-advisories` is somebody saying "not this run", so it is recorded
    /// in the header rather than raised. Raising it anyway would leave the
    /// flag useless without the table.
    #[tokio::test]
    async fn screening_declined_recorded_not_raised() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = advisor_config(dir.path(), "");
        let parsed = cli(&["--config", path.to_str().expect("utf-8"), "validate-config"]);
        let config = load(&parsed).expect("loads");
        let mut built = session(&parsed, &config, &ctx()).expect("built");
        let ctx = ctx();

        let planned = planned(&mut built, true, &ctx).await;

        screening_ready(&built, &planned, &ctx);

        assert_eq!(ctx.problems().worst(), None);
        assert_eq!(
            planned.ages()["osv"],
            crate::advisory::CorpusAge::SkippedByRequest
        );
    }

    /// A run configuring no advisors asked for nothing and is owed nothing.
    #[tokio::test]
    async fn screening_without_advisors_raises_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = config(dir.path(), "{}");
        let parsed = cli(&["--config", path.to_str().expect("utf-8"), "validate-config"]);
        let config = load(&parsed).expect("loads");
        let mut built = session(&parsed, &config, &ctx()).expect("built");
        let ctx = ctx();
        let planned = planned(&mut built, false, &ctx).await;

        screening_ready(&built, &planned, &ctx);

        assert_eq!(ctx.problems().worst(), None);
    }

    /// Nothing was exercised, so nothing is claimed -- and no `vex-unmatched`
    /// is reported for a policy the run never put a question to.
    #[tokio::test]
    async fn screening_none_reports_no_stale_suppressions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = advisor_config(dir.path(), "");
        let parsed = cli(&["--config", path.to_str().expect("utf-8"), "validate-config"]);
        let config = load(&parsed).expect("loads");
        let mut built = session(&parsed, &config, &ctx()).expect("built");
        let ctx = ctx();
        let planned = planned(&mut built, false, &ctx).await;

        let stale = stale_suppressions(&built, &planned, &ctx);

        assert!(stale.is_empty());
        assert_eq!(ctx.problems().counts().get(&Code::VexUnmatched), None);
    }
}
