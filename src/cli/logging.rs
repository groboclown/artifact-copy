//! The process's log subscriber: where [`Log`](crate::core::log::Log) lines
//! end up.
//!
//! Logging has to start before the configuration is loaded, since loading
//! it can fail and that failure needs reporting. So it starts in two steps:
//!
//! ```text
//!   flags + RUST_LOG --install-->   subscriber (filter, output)
//!   setup.log        --configure--> reload whatever the flags left open
//! ```
//!
//! The level comes from the first level flag given, then `RUST_LOG`, then
//! `setup.log.level`, then `warn`. The destination comes from `--log-file`,
//! then `setup.log`'s file, then standard error.
//!
//! Progress bars follow the same settings: they draw for `ansi` output at
//! `warn` or more verbose, and terminal log lines clear them while printing.
//!
//! This is the one place that assembles a `tracing` subscriber. The library
//! never installs one; `main` calls [`install`].

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::layer::{Layer, Layered, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, reload};

use super::Cli;
use super::progress::{Bars, Display};
use crate::config::{LogLevel, Logging as Configured, OutputFormat};
use crate::core::error::{Error, Result};
pub use crate::core::log::Secrets;
use crate::core::progress::ProgressSink;

/// The level when nothing names one.
const DEFAULT_LEVEL: LogLevel = LogLevel::Warn;

/// The `--log-file` value that means standard output.
const STDOUT_PATH: &str = "-";

/// The target our own events carry, for the filter directive.
const CRATE_TARGET: &str = env!("CARGO_CRATE_NAME");

/// Ends the options on a command line; anything after is an argument.
const END_OF_OPTIONS: &str = "--";

/// The environment variable `tracing` reads directives from.
const RUST_LOG: &str = "RUST_LOG";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Destination {
    Stderr,
    Stdout,
    File(PathBuf),
}

/// A flag that sets the level.  Several may be given; the first one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LevelFlag {
    Quiet,
    Verbose,
    Debug,
    UnsafeDebug,
    Tracing,
}

impl LevelFlag {
    const ALL: [LevelFlag; 5] = [
        LevelFlag::Quiet,
        LevelFlag::Verbose,
        LevelFlag::Debug,
        LevelFlag::UnsafeDebug,
        LevelFlag::Tracing,
    ];

    fn spelling(self) -> &'static str {
        match self {
            LevelFlag::Quiet => "--quiet",
            LevelFlag::Verbose => "--verbose",
            LevelFlag::Debug => "--debug",
            LevelFlag::UnsafeDebug => "--unsafe-debug",
            LevelFlag::Tracing => "--tracing",
        }
    }

    fn level(self) -> LogLevel {
        match self {
            LevelFlag::Quiet => LogLevel::Error,
            LevelFlag::Verbose => LogLevel::Info,
            LevelFlag::Debug | LevelFlag::UnsafeDebug => LogLevel::Debug,
            LevelFlag::Tracing => LogLevel::Trace,
        }
    }
}

/// What decided the level, and so whether the configuration may change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LevelSource {
    CommandLine,
    Environment,
    Configuration,
}

/// What the command line decided about logging.
#[derive(Debug)]
pub struct Arguments {
    flag: Option<LevelFlag>,
    secrets: Secrets,
    destination: Option<Destination>,
}

impl Arguments {
    /// `args` is the raw command line, because clap reports that a flag was
    /// given but not where, and the first level flag wins.
    pub fn read(cli: &Cli, args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let destination = cli.global.log_file.as_deref().map(destination);

        // Log lines interleaved with a report would parse as neither.
        if destination == Some(Destination::Stdout) && cli.command.writes_stdout() {
            return Err(Error::Config(format!(
                "--log-file={STDOUT_PATH} needs the report written to a file"
            )));
        }

        let secrets = match cli.global.unsafe_debug {
            true => Secrets::Revealed,
            false => Secrets::Redacted,
        };

        Ok(Self {
            flag: first_flag(args),
            secrets,
            destination,
        })
    }
}

fn destination(path: &Path) -> Destination {
    if path.as_os_str() == STDOUT_PATH {
        return Destination::Stdout;
    }

    Destination::File(path.to_path_buf())
}

/// The first level flag on the command line, if any.
fn first_flag(args: impl IntoIterator<Item = OsString>) -> Option<LevelFlag> {
    for arg in args {
        if arg == END_OF_OPTIONS {
            return None;
        }

        let found = LevelFlag::ALL
            .into_iter()
            .find(|flag| arg == flag.spelling());

        if found.is_some() {
            return found;
        }
    }

    None
}

/// The whole subscriber: the filter, then the output.
type Assembled = Layered<reload::Layer<Output, Filtered>, Filtered>;

/// Filters every event before it reaches the output.
type Filtered = Layered<reload::Layer<EnvFilter, Registry>, Registry>;

/// Formats and writes an event.
type Output = Box<dyn Layer<Filtered> + Send + Sync>;

/// The installed subscriber, reconfigurable once the configuration loads.
pub struct Logging {
    arguments: Arguments,
    source: LevelSource,

    /// The most verbose level the initial filter lets through, which
    /// decides the bars when the configuration may not change the level.
    initial_hint: Option<LevelFilter>,

    filter: reload::Handle<EnvFilter, Registry>,
    output: reload::Handle<Output, Filtered>,
    bars: Arc<Bars>,
}

/// Install the process-wide subscriber from the command line and
/// `RUST_LOG`.
pub fn install(arguments: Arguments) -> Result<Logging> {
    let environment = std::env::var(RUST_LOG).ok();
    let (subscriber, logging) = build(arguments, environment.as_deref())?;

    subscriber
        .try_init()
        .map_err(|err| Error::Config(format!("cannot start logging: {err}")))?;

    Ok(logging)
}

/// The subscriber and its handle, without installing it.
fn build(arguments: Arguments, environment: Option<&str>) -> Result<(Assembled, Logging)> {
    let (filter, source) = initial_filter(arguments.flag, environment)?;
    let initial_hint = filter.max_level_hint();

    // Hidden until the configuration says the output is `ansi`.
    let bars = Arc::new(Bars::hidden());

    let destination = arguments.destination.clone().unwrap_or(Destination::Stderr);
    let output = output(&destination, OutputFormat::default(), &bars)?;

    let (filter_layer, filter) = reload::Layer::new(filter);
    let (output_layer, output) = reload::Layer::new(output);

    let subscriber = tracing_subscriber::registry()
        .with(filter_layer)
        .with(output_layer);

    let logging = Logging {
        arguments,
        source,
        initial_hint,
        filter,
        output,
        bars,
    };

    Ok((subscriber, logging))
}

/// A `Logging` for a test, writing to standard error at the default level.
///
/// The subscriber comes back beside it, uninstalled, and must outlive it:
/// reconfiguring reaches the subscriber through a weak handle.
#[cfg(test)]
pub(crate) fn for_test() -> (impl tracing::Subscriber, Logging) {
    let arguments = Arguments {
        flag: None,
        secrets: Secrets::Redacted,
        destination: None,
    };

    build(arguments, None).expect("builds")
}

impl Logging {
    pub fn secrets(&self) -> Secrets {
        self.arguments.secrets
    }

    /// Where progress goes.  Draws nothing until [`Logging::configure`]
    /// decides the bars show.
    pub fn progress(&self) -> Arc<dyn ProgressSink> {
        self.bars.clone()
    }

    /// Apply `setup.log` to whatever the command line left open.
    pub fn configure(&self, configured: Option<&Configured>) -> Result<()> {
        let level = configured.and_then(|log| log.level);
        let format = configured
            .and_then(|log| log.output_format)
            .unwrap_or_default();
        let file = configured.and_then(|log| log.file.clone());

        let mut hint = self.initial_hint;

        if self.source == LevelSource::Configuration {
            let filter = level_filter(level.unwrap_or(DEFAULT_LEVEL))?;
            hint = filter.max_level_hint();

            self.filter.reload(filter).map_err(reconfigure_error)?;
        }

        self.bars.display(bar_display(format, hint));

        let destination = self
            .arguments
            .destination
            .clone()
            .or(file.map(Destination::File))
            .unwrap_or(Destination::Stderr);

        self.output
            .reload(output(&destination, format, &self.bars)?)
            .map_err(reconfigure_error)
    }
}

/// Bars for `ansi` output at `warn` or more verbose, so `--quiet` hides
/// them.  A filter with no hint may let anything through, so it shows them.
fn bar_display(format: OutputFormat, hint: Option<LevelFilter>) -> Display {
    if format != OutputFormat::Ansi {
        return Display::Hidden;
    }

    match hint {
        Some(hint) if hint < LevelFilter::WARN => Display::Hidden,
        _ => Display::Shown,
    }
}

fn reconfigure_error(err: reload::Error) -> Error {
    Error::Config(format!("cannot reconfigure logging: {err}"))
}

/// The filter before the configuration loads, and what decided it.
///
/// An unparsable `RUST_LOG` is ignored rather than fatal, as it always has
/// been: it is an environment variable, often set for some other program.
fn initial_filter(
    flag: Option<LevelFlag>,
    environment: Option<&str>,
) -> Result<(EnvFilter, LevelSource)> {
    if let Some(flag) = flag {
        return Ok((level_filter(flag.level())?, LevelSource::CommandLine));
    }

    if let Some(filter) = environment.and_then(|text| EnvFilter::try_new(text).ok()) {
        return Ok((filter, LevelSource::Environment));
    }

    Ok((level_filter(DEFAULT_LEVEL)?, LevelSource::Configuration))
}

/// Our events at `level`; dependencies at `level` or `warn`, whichever is
/// quieter, so `--tracing` shows this tool's paths rather than every HTTP
/// frame.
fn level_filter(level: LogLevel) -> Result<EnvFilter> {
    let dependencies = match level {
        LogLevel::Error | LogLevel::Off => level,
        _ => LogLevel::Warn,
    };

    let directive = format!(
        "{CRATE_TARGET}={},{}",
        level_name(level),
        level_name(dependencies)
    );

    EnvFilter::try_new(&directive)
        .map_err(|err| Error::Config(format!("bad log filter {directive:?}: {err}")))
}

fn level_name(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
        LogLevel::Off => "off",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Color {
    On,
    Off,
}

impl Color {
    /// Color only on a terminal: escape codes in a file or a pipe are noise.
    fn for_terminal(is_terminal: bool) -> Self {
        match is_terminal {
            true => Color::On,
            false => Color::Off,
        }
    }
}

fn output(destination: &Destination, format: OutputFormat, bars: &Arc<Bars>) -> Result<Output> {
    match destination {
        Destination::Stderr => Ok(formatted(
            Terminal::new(Stream::Stderr, bars),
            format,
            Color::for_terminal(io::stderr().is_terminal()),
        )),

        Destination::Stdout => Ok(formatted(
            Terminal::new(Stream::Stdout, bars),
            format,
            Color::for_terminal(io::stdout().is_terminal()),
        )),

        Destination::File(path) => Ok(formatted(Arc::new(append(path)?), format, Color::Off)),
    }
}

fn formatted<W>(writer: W, format: OutputFormat, color: Color) -> Output
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer = fmt::layer()
        .with_writer(writer)
        .with_target(false)
        .without_time();

    match format {
        OutputFormat::JsonStream => layer.json().boxed(),
        OutputFormat::Plain => layer.with_ansi(false).boxed(),
        OutputFormat::Ansi => layer.with_ansi(color == Color::On).boxed(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stderr,
    Stdout,
}

/// Writes log lines to a terminal stream with the progress bars cleared,
/// so a line never tears through a bar.
struct Terminal {
    stream: Stream,
    bars: Arc<Bars>,
}

impl Terminal {
    fn new(stream: Stream, bars: &Arc<Bars>) -> Self {
        Self {
            stream,
            bars: Arc::clone(bars),
        }
    }
}

impl<'a> MakeWriter<'a> for Terminal {
    type Writer = TerminalWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        TerminalWriter { terminal: self }
    }
}

struct TerminalWriter<'a> {
    terminal: &'a Terminal,
}

impl Write for TerminalWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let stream = self.terminal.stream;

        self.terminal.bars.suspend(|| match stream {
            Stream::Stderr => io::stderr().write(buf),
            Stream::Stdout => io::stdout().write(buf),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.terminal.stream {
            Stream::Stderr => io::stderr().flush(),
            Stream::Stdout => io::stdout().flush(),
        }
    }
}

/// Open a log file for appending, creating it and its directory.
fn append(path: &Path) -> Result<File> {
    let failed = |source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    };

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(failed)?;
    }

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    use crate::core::log::Log;

    fn args(line: &[&str]) -> Vec<OsString> {
        line.iter().map(OsString::from).collect()
    }

    fn arguments(line: &[&str]) -> Result<Arguments> {
        let cli = Cli::try_parse_from(line).expect("parses");

        Arguments::read(&cli, args(line))
    }

    #[test]
    fn flags_first_level_wins() {
        let found = first_flag(args(&["am", "--debug", "validate-config", "--quiet"]));

        assert_eq!(found, Some(LevelFlag::Debug));
    }

    #[test]
    fn flags_after_end_of_options_are_arguments() {
        let found = first_flag(args(&["am", "copy", "--", "--quiet"]));

        assert_eq!(found, None);
    }

    #[test]
    fn flags_map_to_levels() {
        let cases = [
            (LevelFlag::Quiet, LogLevel::Error),
            (LevelFlag::Verbose, LogLevel::Info),
            (LevelFlag::Debug, LogLevel::Debug),
            (LevelFlag::UnsafeDebug, LogLevel::Debug),
            (LevelFlag::Tracing, LogLevel::Trace),
        ];

        for (flag, level) in cases {
            assert_eq!(flag.level(), level, "{flag:?}");
        }
    }

    /// `--unsafe-debug` reveals secrets wherever it appears, even when an
    /// earlier flag decided the level.
    #[test]
    fn secrets_revealed_by_later_unsafe_debug() {
        let read =
            arguments(&["am", "--tracing", "--unsafe-debug", "validate-config"]).expect("reads");

        assert_eq!(read.flag, Some(LevelFlag::Tracing));
        assert_eq!(read.secrets, Secrets::Revealed);
    }

    #[test]
    fn secrets_redacted_by_default() {
        let read = arguments(&["am", "--tracing", "validate-config"]).expect("reads");

        assert_eq!(read.secrets, Secrets::Redacted);
    }

    #[test]
    fn stdout_log_conflicts_with_stdout_report() {
        let refused = arguments(&["am", "--log-file=-", "find", "--from=s"]);

        assert!(refused.is_err());
    }

    #[test]
    fn stdout_log_with_report_file_allowed() {
        let read = arguments(&[
            "am",
            "--log-file=-",
            "find",
            "--from=s",
            "--to-report=r.jsonl",
        ])
        .expect("reads");

        assert_eq!(read.destination, Some(Destination::Stdout));
    }

    #[test]
    fn level_flag_beats_environment() {
        let (_, source) = initial_filter(Some(LevelFlag::Quiet), Some("trace")).expect("builds");

        assert_eq!(source, LevelSource::CommandLine);
    }

    #[test]
    fn level_environment_beats_configuration() {
        let (_, source) = initial_filter(None, Some("debug")).expect("builds");

        assert_eq!(source, LevelSource::Environment);
    }

    #[test]
    fn level_environment_unparsable_ignored() {
        let (_, source) = initial_filter(None, Some("=[")).expect("builds");

        assert_eq!(source, LevelSource::Configuration);
    }

    #[test]
    fn bars_show_for_ansi_at_warn() {
        assert_eq!(
            bar_display(OutputFormat::Ansi, Some(LevelFilter::WARN)),
            Display::Shown
        );
        assert_eq!(
            bar_display(OutputFormat::Ansi, Some(LevelFilter::TRACE)),
            Display::Shown
        );
    }

    #[test]
    fn bars_hidden_when_quiet() {
        assert_eq!(
            bar_display(OutputFormat::Ansi, Some(LevelFilter::ERROR)),
            Display::Hidden
        );
        assert_eq!(
            bar_display(OutputFormat::Ansi, Some(LevelFilter::OFF)),
            Display::Hidden
        );
    }

    #[test]
    fn bars_hidden_for_non_ansi() {
        for format in [OutputFormat::Plain, OutputFormat::JsonStream] {
            assert_eq!(
                bar_display(format, Some(LevelFilter::TRACE)),
                Display::Hidden
            );
        }
    }

    /// The quiet flag's filter must hint `error`, or `--quiet` would show bars.
    #[test]
    fn quiet_filter_hints_error() {
        let filter = level_filter(LevelFlag::Quiet.level()).expect("builds");

        assert_eq!(filter.max_level_hint(), Some(LevelFilter::ERROR));
    }

    fn configured(level: LogLevel, file: &Path) -> Configured {
        Configured {
            level: Some(level),
            file: Some(file.to_path_buf()),
            ..Configured::default()
        }
    }

    fn logged(file: &Path) -> String {
        std::fs::read_to_string(file).unwrap_or_default()
    }

    /// The configuration's file and level apply once it loads, when no flag
    /// or `RUST_LOG` decided them.
    #[test]
    fn configuration_applies_after_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("logs").join("run.log");
        let read = arguments(&["am", "validate-config"]).expect("reads");

        let (subscriber, logging) = build(read, None).expect("builds");

        tracing::subscriber::with_default(subscriber, || {
            logging
                .configure(Some(&configured(LogLevel::Info, &file)))
                .expect("configures");

            Log::default().info("configured");
            Log::default().debug("too detailed");
        });

        let text = logged(&file);

        assert!(text.contains("configured"), "{text}");
        assert!(!text.contains("too detailed"), "{text}");
    }

    #[test]
    fn level_flag_survives_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("run.log");
        let read = arguments(&["am", "--quiet", "validate-config"]).expect("reads");

        let (subscriber, logging) = build(read, None).expect("builds");

        tracing::subscriber::with_default(subscriber, || {
            logging
                .configure(Some(&configured(LogLevel::Trace, &file)))
                .expect("configures");

            Log::default().warn("a warning");
            Log::default().error("an error");
        });

        let text = logged(&file);

        assert!(!text.contains("a warning"), "{text}");
        assert!(text.contains("an error"), "{text}");
    }

    #[test]
    fn log_file_argument_beats_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let chosen = dir.path().join("chosen.log");
        let configured_file = dir.path().join("configured.log");
        let flag = format!("--log-file={}", chosen.display());
        let read = arguments(&["am", &flag, "validate-config"]).expect("reads");

        let (subscriber, logging) = build(read, None).expect("builds");

        tracing::subscriber::with_default(subscriber, || {
            logging
                .configure(Some(&configured(LogLevel::Warn, &configured_file)))
                .expect("configures");

            Log::default().warn("where does this go");
        });

        assert!(logged(&chosen).contains("where does this go"));
        assert!(!configured_file.exists());
    }

    #[test]
    fn json_stream_writes_json_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("run.log");
        let read = arguments(&["am", "validate-config"]).expect("reads");

        let (subscriber, logging) = build(read, None).expect("builds");

        tracing::subscriber::with_default(subscriber, || {
            let json = Configured {
                output_format: Some(OutputFormat::JsonStream),
                ..configured(LogLevel::Warn, &file)
            };

            logging.configure(Some(&json)).expect("configures");

            Log::default().warn("as json");
        });

        let line = logged(&file);
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).expect("json");

        assert_eq!(parsed["fields"]["message"], "as json");
    }
}
