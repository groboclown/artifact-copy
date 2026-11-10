//! The operations this crate performs, as an embedder invokes them.
//!
//! One place to look for *what this tool can do*, separate from how a
//! command line asks for it. Each is driven by a [`Session`] and a
//! [`Ctx`], takes what it needs as arguments, and returns what it found --
//! none of them reads an argument, prints to a terminal, or decides an exit
//! code.
//!
//! ```text
//!   cli::subcmd  ->  commands  ->  session  ->  repo / ext / net
//! ```
//!
//! # Not the same as `cli::subcmd`
//!
//! [`cli::subcmd`] holds the sub-commands of the one command a user runs --
//! `validate-config`, `inspect`, `copy`. Each is *dispatch*: it reads
//! parsed arguments, resolves names against a configuration, reports
//! findings to a terminal and maps an outcome to an exit code. This module
//! is the work those sub-commands do, with none of that attached, which is
//! why an embedder can call it and a command line is only one of its
//! callers.
//!
//! The test is whether a host program would want it. Argument parsing is
//! something an embedder already has; a dependency walk is not.
//!
//! [`Session`]: crate::session::Session
//! [`Ctx`]: crate::core::ctx::Ctx
//! [`cli::subcmd`]: crate::cli::subcmd

pub mod copy;
pub mod find;
pub mod inspect;
pub mod report;
pub mod spider;
pub(crate) mod upload;
