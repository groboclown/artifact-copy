//! The command line: parsing it, and turning it into a run.
//!
//! Everything here is **outside an embedder's concern**. Someone driving a
//! copy from their own program builds a [`Config`](crate::config::Config)
//! and opens a [`Session`](crate::session::Session); they have no arguments
//! to parse and no files to find. So this module holds the three things
//! only a command line needs:
//!
//! - **Argument parsing**, below.
//! - [`subcmd`], the sub-commands each argument set reaches.
//! - [`ConfigLoader`], which finds configuration files, validates them
//!   against the schema and merges them into one `Config`.
//!
//! # Why the loader is here and the configuration is not
//!
//! They answer different questions. *What are the settings* is something
//! every layer below needs -- `net` reads a retry plan, `ext` reads
//! constraints, `repo` reads a publish window -- so the typed configuration
//! lives in [`crate::config`], where they can all reach it.
//!
//! *Where do the settings come from* is only ever a command line's
//! question. An embedder constructs a `Config` directly; nothing below
//! `cli` reads a file to get one. Putting the loader here is what keeps
//! `net` from depending on the command line, which the layering forbids.
//!
//! Every sub-command in `README.md` parses, including the ones whose bodies
//! are not written yet -- they reach their command module and fail there, so
//! the wiring is exercised now rather than at the moment someone implements
//! them.

mod config;
pub mod logging;
mod progress;
pub mod subcmd;

pub use config::{ConfigLoader, config_schema_id};

use std::path::{Path, PathBuf};

use clap::builder::PossibleValue;
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::lock::LockSpec;

use crate::commands::spider::SpiderSetting;
use crate::repo::enumerate::SampleSize;
use crate::report::{DbSpec, Part, Refresh, ReportSpec};

#[derive(Debug, Parser)]
#[command(
    name = "artifact-copy",
    version,
    about = "Copy artifacts from one repository to another",
    max_term_width = 100
)]
pub struct Cli {
    #[command(flatten)]
    pub(crate) global: Global,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Args)]
pub(crate) struct Global {
    /// Configuration file or directory.  May be repeated; EARLIER settings
    /// override later ones.
    #[arg(long = "config", value_name = "CONFIG", global = true)]
    pub configs: Vec<PathBuf>,

    /// Log each artifact as it is handled (level `info`).
    ///
    /// Of the level flags (--quiet, --verbose, --debug, --unsafe-debug,
    /// --tracing) the first one given wins.  Without one, the level comes
    /// from RUST_LOG, then `setup.log.level`, then `warn`.
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Log the actions taken within each artifact (level `debug`).
    #[arg(long, global = true)]
    pub debug: bool,

    /// Log errors only, and show no progress (level `error`).
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Log everything (level `trace`).  Secrets stay redacted unless
    /// --unsafe-debug is also given.
    #[arg(long, global = true)]
    pub tracing: bool,

    /// Where log lines go: a file to append to, or `-` for standard output.
    ///
    /// Defaults to `setup.log`'s file, then standard error.  Standard output
    /// is refused when the report also goes there.
    #[arg(long = "log-file", value_name = "FILE", global = true)]
    pub log_file: Option<PathBuf>,

    /// Make every soft quarantine stop its artifact rather than flag it.
    ///
    /// For a run that has to be strict -- a release pipeline -- without
    /// editing the `problem-policy` table that a development run shares.
    /// Sets `setup.harden-quarantine` for this run; it cannot turn the
    /// setting back off, because a configuration asking for strictness
    /// should not be silently relaxed from the command line.
    ///
    /// A per-artifact rule saying `allowed` still applies: hardening finds
    /// no quarantine there to harden.
    #[arg(long = "harden", global = true)]
    pub harden: bool,

    /// Debug *all* data, including secrets (level `debug`, or `trace` after
    /// --tracing).
    ///
    /// WARNING: this can print passwords and tokens.  Never use it anywhere
    /// the output could leak.
    #[arg(long = "unsafe-debug", global = true)]
    pub unsafe_debug: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Copy artifacts from a source repository to a target repository.
    Copy(CopyArgs),

    /// Report the artifacts matching a set of requests, without copying them.
    Inspect(DiscoverArgs),

    /// Report every artifact a repository holds.
    Find(FindArgs),

    /// Check the configuration, its policies, and its secrets.
    ValidateConfig(ValidateConfigArgs),
}

impl Command {
    /// Whether this writes its report to standard output.
    fn writes_stdout(&self) -> bool {
        match self {
            Command::Copy(args) => args.report.writes_stdout(),
            Command::Inspect(args) => args.report.writes_stdout(),
            Command::Find(args) => args.report.writes_stdout(),
            Command::ValidateConfig(_) => false,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ValidateConfigArgs {
    /// Also instantiate every configured extension and ask it to describe
    /// itself.
    ///
    /// Off by default because it runs user-configured programs as a side
    /// effect of validating a file, which is a surprising thing for a
    /// checking command to do unasked.
    #[arg(long = "probe-extensions")]
    pub probe_extensions: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CopyArgs {
    /// The repository to copy from, by its configured name.
    ///
    /// `--source` names a low-level source instead, for advanced use.
    #[arg(long, value_name = "REPOSITORY", visible_alias = "source")]
    pub from: Option<String>,

    /// A repository to copy to, by its configured name. Repeat it to copy
    /// to several; each artifact is fetched once and published to each, in
    /// the order given.
    ///
    /// `--target` names a low-level target instead, for advanced use.
    #[arg(long, value_name = "REPOSITORY", visible_alias = "target")]
    pub to: Vec<String>,

    #[command(flatten)]
    pub resolution: ResolutionArgs,

    /// Where the record of what this copy did goes.
    ///
    /// The same report `inspect` writes, listing every artifact reached
    /// and what became of it -- copied, already present, or the reason it
    /// was not taken.
    #[command(flatten)]
    pub report: ReportArgs,

    /// Copy what the `--db` database says is left, instead of named
    /// artifacts.
    ///
    /// The database is the manifest: a version the source gained since the
    /// artifact enumeration is not copied, so a migration split across
    /// several runs stays reproducible.
    #[arg(long = "from-db", requires = "db")]
    pub from_db: bool,

    /// Artifact requests, in the source ecosystem's coordinate syntax.
    #[arg(value_name = "ARTIFACT")]
    pub artifacts: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct DiscoverArgs {
    /// The repository to resolve against, by its configured name.
    ///
    /// Resolved through its **source**, not its enumerator: inspection
    /// resolves requests into full records -- files, digests, license,
    /// publish time -- and every one of those is something only a source can
    /// answer. `find` is the sub-command that walks a catalog.
    ///
    /// `--source` names a low-level source instead, for advanced use.
    #[arg(long, value_name = "REPOSITORY", visible_alias = "source")]
    pub from: String,

    #[command(flatten)]
    pub resolution: ResolutionArgs,

    #[command(flatten)]
    pub report: ReportArgs,

    /// Inspect what the `--db` database says the source holds, instead of
    /// named artifacts.
    ///
    /// Each artifact's files, licence and publish time come from the
    /// database where it has them, so a rerun of an inspection that already
    /// resolved everything costs no requests.
    #[arg(long = "from-db", requires = "db")]
    pub from_db: bool,

    #[arg(value_name = "ARTIFACT")]
    pub artifacts: Vec<String>,
}

/// Sub-commands that were renamed, as `(old, new)`.
const RENAMED_COMMANDS: [(&str, &str); 2] = [("find-all", "find"), ("discover", "inspect")];

/// The name a refused sub-command now goes by, when it was renamed.
///
/// clap suggests a near spelling, which finds `find` for `find-all` and
/// nothing for `discover`; this names the new one outright.
pub fn renamed_command(err: &clap::Error) -> Option<&'static str> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};

    if err.kind() != ErrorKind::InvalidSubcommand {
        return None;
    }

    let Some(ContextValue::String(given)) = err.get(ContextKind::InvalidSubcommand) else {
        return None;
    };

    RENAMED_COMMANDS
        .iter()
        .find(|(old, _)| old == given)
        .map(|(_, new)| *new)
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("walked").required(true).args(["from", "enumerator"])))]
pub(crate) struct FindArgs {
    /// The repository to walk, by its configured name.
    ///
    /// Walks the repository's enumerator and records what it finds as the
    /// contents of its source, so a later `inspect --from-db` or
    /// `copy --from-db` reads its work from the database.
    #[arg(
        long,
        value_name = "REPOSITORY",
        conflicts_with_all = ["as_source", "as_target"]
    )]
    pub from: Option<String>,

    /// A low-level enumerator to walk, by its configured name, for advanced
    /// use.
    ///
    /// What it finds is filed under the enumerator itself, unless
    /// `--as-source` or `--as-target` says otherwise.
    #[arg(long, value_name = "ENUMERATOR")]
    pub enumerator: Option<String>,

    #[command(flatten)]
    pub report: ReportArgs,

    /// Record what this artifact enumeration finds as the contents of a
    /// configured target.
    ///
    /// For an enumerator pointed at a repository that is also a publish target.
    /// A later `copy` then asks the database what the target holds instead of
    /// asking the target once per artifact.
    ///
    /// The equivalence is your assertion: the tool records what the
    /// enumeration saw, and never that one repository is another.
    #[arg(long = "as-target", value_name = "TARGET")]
    pub as_target: Option<String>,

    /// Record what this artifact enumeration finds as the contents of a
    /// configured source.
    ///
    /// For an enumerator pointed at a repository that is also a source. A later
    /// `inspect --from-db` or `copy --from-db` then reads its work
    /// from the database; without this, what the enumeration finds is filed
    /// under the enumerator and neither of them sees it.
    ///
    /// The equivalence is your assertion, as with `--as-target`.
    #[arg(
        long = "as-source",
        value_name = "SOURCE",
        conflicts_with = "as_target"
    )]
    pub as_source: Option<String>,

    /// Limit the walk: a count, or a percentage such as `35%`.
    ///
    /// A percentage requires an enumerator that can report a total.
    #[arg(long, value_name = "SIZE", value_parser = SampleSize::parse)]
    pub sample_size: Option<SampleSize>,

    /// Walk the whole catalog, even when the --db holds a finished walk.
    ///
    /// Without this, a walk after a finished one lists only what was
    /// modified since that walk started, where the enumerator can narrow
    /// by date.
    #[arg(long = "rescan-all")]
    pub rescan_all: bool,

    #[command(flatten)]
    pub advisories: AdvisoryArgs,
}

/// Options shared by every command that resolves artifact requests.
#[derive(Debug, Args)]
pub(crate) struct ResolutionArgs {
    /// Include alpha, beta, release-candidate and other non-GA versions.
    #[arg(long)]
    pub pre_release: bool,

    /// Which dependencies to follow: kinds joined with `+`, such as
    /// `runtime+dev`, or `all`, `none`, or `default`.
    ///
    /// Kinds: `runtime`, `dev`, `test`, `optional`, `peer`, `build`.  Add
    /// `shallow` to follow the first level only: `all+shallow`.
    ///
    /// `default` uses the source's `dependencies` setting, and `none` when
    /// it has none, so with neither set nothing is followed.
    ///
    /// Kinds differ by ecosystem: `test` is Maven-only, `peer` is npm-only,
    /// and PyPI publishes neither dev nor test dependencies.  Maven's
    /// `build` kind, a parent POM or an imported BOM, joins any walk.
    #[arg(long, value_name = "SPIDER", value_parser = SpiderSetting::parse, default_value = "default")]
    pub dependencies: SpiderSetting,

    /// Lock file to read artifacts from, as FILE or FORMAT,FILE.
    ///
    /// The format is detected from the filename and a peek at the content.
    /// State it explicitly when detection cannot work -- a lock file kept
    /// under another name, or one whose format is ambiguous -- and detection
    /// is then skipped entirely rather than second-guessed.
    ///
    /// Splitting on the first comma keeps even a comma-containing filename
    /// reachable: `--lock=npm,weird,name.lock`.
    ///
    /// Every artifact in the file is taken, regardless of --dependencies;
    /// that setting applies only to those artifacts' own dependencies.
    #[arg(long = "lock", value_name = "[FORMAT,]FILE", value_parser = LockSpec::parse)]
    pub locks: Vec<LockSpec>,

    #[command(flatten)]
    pub advisories: AdvisoryArgs,
}

#[derive(Debug, Args)]
pub(crate) struct ReportArgs {
    /// Where to write a line report, for tools following the run:
    /// `[TYPE,]FILE`.
    ///
    /// TYPE is one of json, json-append, yaml, yaml-append, text, or
    /// text-append, and defaults to text.  A FILE of `-` is standard output.
    /// Examples: `json,run.jsonl`, `yaml,-`.  Without this or --db, text
    /// goes to standard output.
    #[arg(long = "to-report", value_name = "[TYPE,]FILE", value_parser = ReportSpec::parse)]
    pub to_report: Option<ReportSpec>,

    /// A report database to add this run to, and to answer from.
    ///
    /// The database is a cache: what an earlier run learned about a source
    /// or a target, the bytes it fetched, and where an interrupted walk
    /// stopped are used rather than asked again.  --refresh asks again.
    /// Without it, copy and inspect keep a temporary database under the
    /// cache directory for the run, so a walk queues on disk; `-` keeps
    /// none, and the walk queues in memory.
    #[arg(long = "db", value_name = "FILE")]
    pub db: Option<PathBuf>,

    /// Parts of the --db cache to ask the server for instead: source,
    /// target, payloads, enumeration, spider, or all.
    ///
    /// Comma separated, and may be repeated.  What the server answers is
    /// still recorded.  `all` also replaces the database file.  Each command
    /// accepts only the parts it uses.
    #[arg(
        long = "refresh",
        value_name = "PART",
        value_delimiter = ',',
        requires = "db"
    )]
    pub refresh: Vec<Part>,
}

/// The `--db` value that keeps no database.
const NO_DATABASE: &str = "-";

/// What `--db` said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbChoice<'a> {
    /// `--db=FILE`.
    Named(&'a Path),

    /// `--db=-`: no database, not even a temporary one.
    Declined,

    /// No `--db`: a temporary database where the command walks.
    Unsaid,
}

impl ReportArgs {
    /// What `--db` said.
    pub fn db_choice(&self) -> DbChoice<'_> {
        match &self.db {
            Some(path) if path.as_os_str() == NO_DATABASE => DbChoice::Declined,
            Some(path) => DbChoice::Named(path),
            None => DbChoice::Unsaid,
        }
    }

    /// The line report: text on standard output when neither it nor a
    /// named database was asked for, and none when only a database was.
    ///
    /// A temporary database writes nothing anybody reads, so it leaves the
    /// default text in place.
    pub fn line(&self) -> Option<ReportSpec> {
        match (&self.to_report, self.db_choice()) {
            (Some(spec), _) => Some(spec.clone()),
            (None, DbChoice::Named(_)) => None,
            (None, DbChoice::Declined | DbChoice::Unsaid) => Some(ReportSpec::default()),
        }
    }

    /// The named database, and which of its parts this run refreshes.
    pub fn database(&self) -> Option<DbSpec> {
        let DbChoice::Named(path) = self.db_choice() else {
            return None;
        };

        let refresh = Refresh::new(self.refresh.iter().copied());

        Some(DbSpec::new(path).refreshing(refresh))
    }

    /// Whether the line report goes to standard output.
    fn writes_stdout(&self) -> bool {
        self.line().is_some_and(|spec| spec.path().is_none())
    }
}

#[derive(Debug, Args)]
pub(crate) struct AdvisoryArgs {
    /// Skip vulnerability and malware screening.
    #[arg(long = "no-advisories")]
    pub no_advisories: bool,

    /// Refresh the advisory corpus even if the cached copy is still fresh.
    #[arg(long = "refresh-advisories")]
    pub refresh_advisories: bool,
}

impl ValueEnum for Part {
    fn value_variants<'a>() -> &'a [Self] {
        Part::every()
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.as_str()))
    }
}

#[cfg(test)]
mod tests {
    /// Nothing below `cli` may reach into it.
    ///
    /// The whole point of grouping the command line here is that an
    /// embedder can ignore it, and that only holds while the dependency
    /// runs one way. A `use crate::cli::...` in `net` or `repo` would make
    /// the network layer need an argument parser, and would be invisible
    /// until somebody tried to use this crate as a library.
    ///
    /// Production code only. A test may build a `Config` with
    /// [`ConfigLoader`] because writing one out in JSON is the shortest way
    /// to say what a test is about, and a test dependency ships with
    /// nobody. Found by taking each file up to its first `#[cfg(test)]`,
    /// which is where every module in this crate puts its tests.
    #[test]
    fn nothing_below_cli_depends_on_cli() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("readable") {
                let path = entry.expect("entry").path();

                match path.is_dir() {
                    true => walk(&path, out),
                    false if path.extension().is_some_and(|ext| ext == "rs") => out.push(path),
                    false => {}
                }
            }
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();

        walk(&src, &mut files);
        assert!(files.len() > 50, "the walk found almost nothing");

        let mut offenders = Vec::new();

        for path in files {
            let relative = path.strip_prefix(&src).expect("under src");

            // `cli` itself, and the binary, are the two that may.
            if relative.starts_with("cli") || relative == std::path::Path::new("main.rs") {
                continue;
            }

            let text = std::fs::read_to_string(&path).expect("readable");
            let production = match text.find("#[cfg(test)]") {
                Some(at) => &text[..at],
                None => &text[..],
            };

            for (number, line) in production.lines().enumerate() {
                // A doc link is a reference, not a dependency.
                if line.trim_start().starts_with("//") {
                    continue;
                }

                if line.contains("crate::cli") {
                    offenders.push(format!("{}:{}", relative.display(), number + 1));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "these reach up into the command line: {offenders:?}"
        );
    }
    use super::*;
    use crate::report::ReportFormat;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parses")
    }

    /// A renamed sub-command is refused, and its new name offered.
    #[test]
    fn renamed_commands_name_new() {
        for (old, new) in RENAMED_COMMANDS {
            let err = Cli::try_parse_from(["artifact-copy", old]).expect_err("refused");

            assert_eq!(renamed_command(&err), Some(new), "{old}");
        }

        let err = Cli::try_parse_from(["artifact-copy", "nonsense"]).expect_err("refused");

        assert_eq!(renamed_command(&err), None);
    }

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// `--to-report` takes `[TYPE,]FILE`, so clap cannot list the TYPEs
    /// itself; the help prose does, and must name every format.
    #[test]
    fn report_help_names_every_format() {
        let command = Cli::command();
        let copy = command.find_subcommand("copy").expect("copy");
        let arg = copy
            .get_arguments()
            .find(|arg| arg.get_long() == Some("to-report"))
            .expect("--to-report");
        let help = arg
            .get_long_help()
            .or(arg.get_help())
            .expect("help")
            .to_string();

        for name in ReportFormat::names() {
            assert!(help.contains(name), "--to-report help omits {name}");
        }
    }

    #[test]
    fn flags_config_repeated_keep_order() {
        let cli = parse(&[
            "artifact-copy",
            "--config=a.yaml",
            "--config=b.yaml",
            "validate-config",
        ]);

        assert_eq!(
            cli.global.configs,
            vec![PathBuf::from("a.yaml"), PathBuf::from("b.yaml")]
        );
    }

    /// Global flags must work after the sub-command too; that is where users
    /// naturally type them.
    #[test]
    fn flags_global_work_on_either_side() {
        let cli = parse(&["artifact-copy", "validate-config", "--debug"]);

        assert!(cli.global.debug);
    }

    /// Level flags combine; the first one given decides the level.
    #[test]
    fn flags_level_combine() {
        let cli = parse(&["artifact-copy", "--quiet", "validate-config", "--verbose"]);

        assert!(cli.global.quiet);
        assert!(cli.global.verbose);
    }

    #[test]
    fn discover_parses_full_surface() {
        let cli = parse(&[
            "artifact-copy",
            "inspect",
            "--from=central",
            "--pre-release",
            "--dependencies=runtime+dev",
            "--lock=package-lock.json",
            "--to-report=json,out.jsonl",
            "org.example:thing:1.0",
        ]);

        let Command::Inspect(args) = cli.command else {
            panic!("expected inspect");
        };

        assert_eq!(args.from, "central");
        assert!(args.resolution.pre_release);
        assert_eq!(
            args.resolution.dependencies,
            SpiderSetting::parse("runtime+dev").expect("parses")
        );
        assert_eq!(args.resolution.locks.len(), 1);
        assert_eq!(
            args.report.line().expect("a line report").format(),
            ReportFormat::Json
        );
        assert_eq!(args.artifacts, vec!["org.example:thing:1.0"]);
    }

    /// A coordinate can start with `@`, which clap would otherwise try to
    /// read as an option.
    #[test]
    fn scoped_npm_coordinates_survive_separator() {
        let cli = parse(&[
            "artifact-copy",
            "copy",
            "--from=a",
            "--to=b",
            "--",
            "@angular/core@17.0.0",
        ]);

        let Command::Copy(args) = cli.command else {
            panic!("expected copy");
        };

        assert_eq!(args.artifacts, vec!["@angular/core@17.0.0"]);
    }

    #[test]
    fn copy_takes_report_options() {
        let cli = Cli::try_parse_from([
            "artifact-copy",
            "copy",
            "--from=s",
            "--to=t",
            "--to-report=json,out.jsonl",
            "tuna",
        ])
        .expect("parses");

        let Command::Copy(args) = &cli.command else {
            panic!("expected copy");
        };

        let line = args.report.line().expect("a line report");

        assert_eq!(line.format(), ReportFormat::Json);
        assert_eq!(line.path(), Some(std::path::Path::new("out.jsonl")));
    }

    #[test]
    fn find_parses_percentage_sample() {
        let cli = parse(&[
            "artifact-copy",
            "find",
            "--from=pypi-all",
            "--sample-size=35%",
        ]);

        let Command::Find(args) = cli.command else {
            panic!("expected find");
        };

        assert_eq!(args.sample_size, Some(SampleSize::Percent(35)));
    }

    #[test]
    fn dependencies_bad_kind_fails_at_parse() {
        assert!(
            Cli::try_parse_from([
                "artifact-copy",
                "inspect",
                "--from=s",
                "--dependencies=runtime+bogus",
            ])
            .is_err()
        );
    }

    #[test]
    fn dependencies_default_to_source() {
        for flags in [&[][..], &["--dependencies=default"][..]] {
            let mut argv = vec!["artifact-copy", "inspect", "--from=s"];
            argv.extend_from_slice(flags);

            let Command::Inspect(args) = parse(&argv).command else {
                panic!("expected inspect");
            };

            assert_eq!(args.resolution.dependencies, SpiderSetting::SourceDefault);
        }
    }

    #[test]
    fn dependencies_requires_value() {
        assert!(
            Cli::try_parse_from(["artifact-copy", "inspect", "--from=s", "--dependencies"])
                .is_err()
        );
    }

    /// A database is `--db` now, and the old TYPE says so.
    #[test]
    fn db_flag_named_by_sqlite_report_types() {
        for spelling in ["sqllite", "sqlite", "sqlite-new"] {
            let err = Cli::try_parse_from([
                "artifact-copy",
                "find",
                "--from=s",
                &format!("--to-report={spelling},r.db"),
            ])
            .expect_err(spelling)
            .to_string();

            assert!(err.contains("--db=FILE"), "{spelling}: {err}");
        }
    }

    #[test]
    fn every_subcommand_parses() {
        parse(&["artifact-copy", "validate-config"]);
        parse(&["artifact-copy", "copy", "--from=a", "--to=b"]);
        parse(&["artifact-copy", "inspect", "--from=s"]);
        parse(&["artifact-copy", "find", "--from=s"]);
    }

    /// `--to` repeats, and keeps the order given, which is the order each
    /// artifact is published in.
    #[test]
    fn copy_to_repeats_in_order() {
        let Command::Copy(copy) =
            parse(&["artifact-copy", "copy", "--from=a", "--to=c", "--target=b"]).command
        else {
            panic!("expected copy");
        };

        assert_eq!(copy.to, ["c", "b"]);
    }

    /// The low-level names stay, for advanced use, and mean the same
    /// fields.
    #[test]
    fn flags_low_level_still_parse() {
        let Command::Copy(copy) =
            parse(&["artifact-copy", "copy", "--source=a", "--target=b"]).command
        else {
            panic!("expected copy");
        };

        assert_eq!(copy.from.as_deref(), Some("a"));
        assert_eq!(copy.to, ["b"]);

        let Command::Inspect(inspect) = parse(&["artifact-copy", "inspect", "--source=s"]).command
        else {
            panic!("expected inspect");
        };

        assert_eq!(inspect.from, "s");

        let Command::Find(find) =
            parse(&["artifact-copy", "find", "--enumerator=e", "--as-source=s"]).command
        else {
            panic!("expected find");
        };

        assert_eq!(find.enumerator.as_deref(), Some("e"));
        assert_eq!(find.from, None);
    }

    /// `find` walks exactly one of a repository or a low-level enumerator.
    #[test]
    fn find_needs_one_walk() {
        let refused = |argv: &[&str]| Cli::try_parse_from(argv).is_err();

        assert!(refused(&["artifact-copy", "find"]));
        assert!(refused(&[
            "artifact-copy",
            "find",
            "--from=r",
            "--enumerator=e",
        ]));
    }

    /// `--from` already binds the source, so a second binding conflicts.
    #[test]
    fn find_from_refuses_other_bindings() {
        for binding in ["--as-source=s", "--as-target=t"] {
            assert!(
                Cli::try_parse_from(["artifact-copy", "find", "--from=r", binding]).is_err(),
                "{binding}"
            );
        }
    }

    /// No `--to-report` and no `--db` is text on standard output.
    #[test]
    fn report_defaults_to_text_on_stdout() {
        let Command::Find(args) = parse(&["artifact-copy", "find", "--from=s"]).command else {
            panic!("expected find");
        };

        let line = args.report.line().expect("a line report");

        assert_eq!(line.format(), ReportFormat::Text);
        assert_eq!(line.path(), None);
        assert!(args.report.database().is_none());
    }

    /// A database alone writes no line report; both together write both.
    #[test]
    fn db_alone_writes_no_line_report() {
        let find = |argv: &[&str]| {
            let mut full = vec!["artifact-copy", "find", "--from=s"];
            full.extend_from_slice(argv);

            let Command::Find(args) = parse(&full).command else {
                panic!("expected find");
            };

            args
        };

        let alone = find(&["--db=r.db"]);

        assert!(alone.report.line().is_none());
        assert_eq!(
            alone.report.database().expect("a database").path(),
            std::path::Path::new("r.db")
        );

        let both = find(&["--db=r.db", "--to-report=json,r.jsonl"]);

        assert!(both.report.line().is_some());
        assert!(both.report.database().is_some());
    }

    /// Bare `--from-db` takes no value, so a following artifact stays an
    /// artifact.
    #[test]
    fn from_db_leaves_artifacts() {
        let Command::Copy(args) = parse(&[
            "artifact-copy",
            "copy",
            "--from=a",
            "--to=b",
            "--db=r.db",
            "--from-db",
            "tuna",
        ])
        .command
        else {
            panic!("expected copy");
        };

        assert!(args.from_db);
        assert_eq!(args.artifacts, vec!["tuna"]);
    }

    /// `--from-db` and `--refresh` both describe a database, so neither
    /// means anything without one.
    #[test]
    fn db_options_need_db() {
        for flag in ["--from-db", "--refresh=target"] {
            assert!(
                Cli::try_parse_from(["artifact-copy", "copy", "--from=a", "--to=b", flag]).is_err(),
                "{flag}"
            );
        }
    }

    #[test]
    fn refresh_takes_a_list() {
        let Command::Copy(args) = parse(&[
            "artifact-copy",
            "copy",
            "--from=a",
            "--to=b",
            "--db=r.db",
            "--refresh=source,target",
            "--refresh=payloads",
        ])
        .command
        else {
            panic!("expected copy");
        };

        assert_eq!(
            args.report.refresh,
            vec![Part::Source, Part::Target, Part::Payloads]
        );
        assert!(
            Cli::try_parse_from([
                "artifact-copy",
                "find",
                "--from=s",
                "--db=r.db",
                "--refresh=bogus",
            ])
            .is_err()
        );
    }

    /// The old spellings are gone; nothing has been released.
    #[test]
    fn report_old_flags_refused() {
        for flag in [
            "--report-format=json",
            "--report-file=r.jsonl",
            "--from-report",
        ] {
            assert!(
                Cli::try_parse_from(["artifact-copy", "find", "--from=s", flag]).is_err(),
                "{flag}"
            );
        }
    }
}
