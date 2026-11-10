//! The machinery every layer carries, and none of it does I/O.
//!
//! Six concerns that answer "what is happening, why, and should it still be
//! happening" -- the questions every other module asks and none of them owns:
//!
//! ```text
//!   Ctx -+- Provenance  why this work is happening
//!        +- ProblemSink what went wrong, and how badly
//!        +- ProgressSink how far along it is
//!        +- Log         what to tell the person running it
//!        `- Cancel      whether to stop
//! ```
//!
//! [`ctx::Ctx`] is the handle the rest of the crate actually holds; the
//! other five are reached through it. That is deliberate and it is why they
//! live here together rather than as five top-level peers -- `progress` and
//! `cancel` in particular have exactly two consumers each, and both of them
//! reach through a `Ctx`.
//!
//! Threading them explicitly rather than through globals is what keeps them
//! correct under `tokio`, where one task migrates between threads and one
//! thread interleaves many tasks, and testable, because a test builds a
//! `Ctx` with recording sinks and asserts what an adapter reported.
//!
//! This module declares nothing of its own. Each concern lives in its own
//! file and is re-exported here, so this page is the index.

pub mod cancel;
pub mod ctx;
pub mod error;
pub mod expiry;
pub mod license;
pub mod log;
pub mod message;
pub mod problem;
pub mod progress;
pub mod screened;

pub use cancel::{Budget, Cancel, Reason};
pub use ctx::Ctx;
pub use error::{Error, Result};
pub use log::{Emitter, Level, Log, Secrets};
pub use message::Message;
pub use problem::{Action, Class, Code, Problem, ProblemSink, Quarantine};
pub use progress::{Node, NullSink, ProgressSink, Unit};
