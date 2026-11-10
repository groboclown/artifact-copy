//! Log lines, for whoever is running the tool.
//!
//! The report and the log answer different readers. The report records
//! observations for analysis and for later runs to consume; the log tells
//! the person at the terminal, and a developer reading along, what the run
//! is doing, what went wrong as it happened, and which paths it took.
//!
//! ```text
//!   ctx.log().warn(..) --> Log --> Emitter --> tracing subscriber (installed by main)
//!                                         \--> an embedder's own
//! ```
//!
//! [`Emitter`] is the driver seam. The default forwards to `tracing`, and
//! nothing else in the crate names `tracing` directly, so the backend can
//! change without touching a call site.
//!
//! Lines are plain U.S. English, not [`Message`](super::message::Message)s:
//! they are read next to the command that produced them, not exchanged as
//! data.

use std::fmt::{self, Display};
use std::sync::Arc;

/// How much a line matters.
///
/// Mirrors `tracing`'s levels one to one, so the command line, `RUST_LOG`,
/// and the configuration all speak the backend's vocabulary rather than a
/// second one that needs translating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Whether secret-bearing values print in full.
///
/// `Revealed` only by `--unsafe-debug`: a credential in a log line outlives
/// the run, in a file, a CI artifact, or a pasted bug report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secrets {
    Redacted,
    Revealed,
}

/// Where log lines go.
///
/// An embedder supplies one to receive lines without a `tracing` subscriber.
pub trait Emitter: fmt::Debug + Send + Sync {
    /// Whether a line at `level` would go anywhere.
    ///
    /// Asked before formatting, so a disabled debug line costs a check and
    /// nothing more.
    fn enabled(&self, level: Level) -> bool;

    fn emit(&self, level: Level, text: &dyn Display);
}

/// The handle every layer logs through.
///
/// Cheap to clone, and carried on [`Ctx`](super::ctx::Ctx) for the same
/// reason progress is: explicitly, rather than through a global.
#[derive(Debug, Clone)]
pub struct Log {
    emitter: Arc<dyn Emitter>,

    /// Whether a line may show a credential, such as a request's
    /// `authorization` header.
    secrets: Secrets,
}

impl Log {
    pub fn new(emitter: Arc<dyn Emitter>) -> Self {
        Self {
            emitter,
            secrets: Secrets::Redacted,
        }
    }

    /// Let lines show credentials, or not.
    pub fn with_secrets(mut self, secrets: Secrets) -> Self {
        self.secrets = secrets;
        self
    }

    pub fn secrets(&self) -> Secrets {
        self.secrets
    }

    pub fn error(&self, text: impl Display) {
        self.at(Level::Error, text);
    }

    pub fn warn(&self, text: impl Display) {
        self.at(Level::Warn, text);
    }

    pub fn info(&self, text: impl Display) {
        self.at(Level::Info, text);
    }

    pub fn debug(&self, text: impl Display) {
        self.at(Level::Debug, text);
    }

    pub fn trace(&self, text: impl Display) {
        self.at(Level::Trace, text);
    }

    /// Log at a level chosen at run time, such as by a problem's action.
    pub(crate) fn at(&self, level: Level, text: impl Display) {
        if !self.emitter.enabled(level) {
            return;
        }

        self.emitter.emit(level, &text);
    }
}

/// Forwards to `tracing`, which is what the binary installs a subscriber
/// for.  An embedder that installs none gets silence, as with any library
/// that logs through `tracing`.
impl Default for Log {
    fn default() -> Self {
        Self::new(Arc::new(Tracing))
    }
}

/// The `tracing` backend.
///
/// One arm per level because `tracing` fixes an event's level at its call
/// site; there is no way to pass one in.
#[derive(Debug)]
struct Tracing;

impl Emitter for Tracing {
    fn enabled(&self, level: Level) -> bool {
        match level {
            Level::Error => tracing::enabled!(tracing::Level::ERROR),
            Level::Warn => tracing::enabled!(tracing::Level::WARN),
            Level::Info => tracing::enabled!(tracing::Level::INFO),
            Level::Debug => tracing::enabled!(tracing::Level::DEBUG),
            Level::Trace => tracing::enabled!(tracing::Level::TRACE),
        }
    }

    fn emit(&self, level: Level, text: &dyn Display) {
        match level {
            Level::Error => tracing::error!("{text}"),
            Level::Warn => tracing::warn!("{text}"),
            Level::Info => tracing::info!("{text}"),
            Level::Debug => tracing::debug!("{text}"),
            Level::Trace => tracing::trace!("{text}"),
        }
    }
}

/// Keeps every line, so a test can assert on what was logged.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct Recorder {
    lines: std::sync::Mutex<Vec<(Level, String)>>,
}

#[cfg(test)]
impl Recorder {
    pub(crate) fn lines(&self) -> Vec<(Level, String)> {
        self.lines.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Emitter for Recorder {
    fn enabled(&self, _level: Level) -> bool {
        true
    }

    fn emit(&self, level: Level, text: &dyn Display) {
        self.lines.lock().unwrap().push((level, text.to_string()));
    }
}

#[cfg(test)]
impl Log {
    /// A log that records, and the recorder to read it back from.
    pub(crate) fn recording() -> (Self, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());

        (Self::new(recorder.clone()), recorder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn level_each_reaches_emitter() {
        let (log, recorder) = Log::recording();

        log.error("e");
        log.warn("w");
        log.info("i");
        log.debug("d");
        log.trace("t");

        let levels: Vec<Level> = recorder.lines().into_iter().map(|(l, _)| l).collect();

        assert_eq!(
            levels,
            [
                Level::Error,
                Level::Warn,
                Level::Info,
                Level::Debug,
                Level::Trace
            ]
        );
    }

    /// Only lets `Error` through, and notes whether anything was formatted.
    #[derive(Debug, Default)]
    struct ErrorsOnly {
        formatted: AtomicBool,
    }

    impl Emitter for ErrorsOnly {
        fn enabled(&self, level: Level) -> bool {
            level == Level::Error
        }

        fn emit(&self, _level: Level, text: &dyn Display) {
            let _ = text.to_string();
            self.formatted.store(true, Ordering::SeqCst);
        }
    }

    /// A disabled line must not be formatted: debug detail on a hot path
    /// would otherwise cost the same whether anyone reads it or not.
    #[test]
    fn level_disabled_not_emitted() {
        let emitter = Arc::new(ErrorsOnly::default());
        let log = Log::new(emitter.clone());

        log.debug(format_args!("{}", "expensive"));

        assert!(!emitter.formatted.load(Ordering::SeqCst));
    }

    #[test]
    fn clones_share_emitter() {
        let (log, recorder) = Log::recording();

        log.clone().info("from a clone");

        assert_eq!(recorder.lines(), [(Level::Info, "from a clone".to_owned())]);
    }
}
