//! Copy artifacts between package repositories.
//!
//! The binary is a thin shell over this library, which is also usable as a
//! dependency.  See `README.md` for the command-line interface.
//!
//! Layering, strictly observed -- each layer calls only the one below it,
//! per `AGENTS.md`:
//!
//! ```text
//!   cli::subcmd -> commands -> session -> repo -> ext -> net
//! ```
//!
//! [`core`] sits beside all of it: `Ctx` and the problem, progress,
//! cancellation and message machinery every layer carries. [`model`] is the
//! other true leaf -- the domain vocabulary, with no I/O and no dependencies
//! of its own, and [`version`] is behaviour over it: one trait, depending
//! on `model` alone.
//!
//! `config` and `policy` are *not* leaves, despite reading that way: both
//! depend on `core`, and `config`'s value types are consumed by `net`,
//! `ext` and `repo`. That is also why `config` is **not** under [`cli`]
//! even though a command line is what usually fills one in: the settings
//! are read everywhere, and only *reading a file to get them* is the
//! command line's job. [`cli::ConfigLoader`] is that half.
//!
//! [`session`] is where a configuration becomes the live objects a run
//! uses -- it is what hands a source the capability it fetches through.
//! Partly built: the host half is there and the rest is listed in
//! `TODO.md`. [`advisory`] is likewise partial: the record shape, the
//! matcher, the index, the corpora, the run's screening state, and screening
//! each artifact in the walk are there.
//!
//! # What is public, and why
//!
//! The modules are public **by decision**, and within them only what an
//! embedder uses ships. An embedder does one of two things:
//!
//! - **Drives a migration:** builds a [`config::Config`], opens a
//!   [`session::Session`], and calls a [`commands`] `run` with its
//!   `Request`, reading the [`report`] records it writes.
//! - **Adds an extension:** implements a trait (`repo::Source`,
//!   `repo::Target`, `repo::enumerate::Enumerator`, `advisory::Advisor`,
//!   `ecosystem::Ecosystem`, `version::VersionHandler`, `lock::Lock`)
//!   with the [`ext`], [`model`], and [`core`] types those traits name.
//!
//! So the traits, the types their signatures name, the `open_*` functions,
//! and the built-in implementations (`MavenSource`, `NpmTarget`,
//! `OsvOffline`, ...) are public, and an embedder may compose those. So are
//! the building blocks an adapter of the embedder's own needs to behave
//! like a built-in one: `repo::download` and `repo::stage`,
//! `repo::version_required` and `repo::sole_ecosystem`, `repo::PageCap`,
//! and `repo::OverwriteGuard`. What the crate uses only to check a
//! configuration or to run its own commands (kind lists, `validate-config`
//! checks, document caching, signature verification, walk internals) is
//! `pub(crate)`.
//!
//! The test for each item: could somebody outside this crate use it for
//! anything? The two crate-private modules at the end fail it whole: a
//! percent-encoder and an LRU of in-flight futures do not ship. Exposing an
//! item later is an additive change; narrowing one is a breaking one.
//!
//! [`commands`] is the opposite end of that: one place to look for *what
//! this tool can do*, with no argument parsing, no terminal output and no
//! exit codes attached. [`cli::subcmd`] is the dispatch that reads arguments
//! and calls into it.
//!
//! [`cli`] is public and is the one an embedder should expect **not** to
//! need. Argument parsing, the sub-commands and the configuration loader
//! are what a command line requires and a host program supplies for
//! itself -- it has arguments of its own and its own idea of where settings
//! come from. Grouped under one module so that boundary is visible rather
//! than inferred from which types happen to mention `clap`.

// A public signature naming a type an embedder cannot name is a broken
// API: the type is `pub` in a private module and has no re-export. Narrowing
// a module makes this easy to cause and impossible to see otherwise.
#![warn(unnameable_types)]
// Module docs explain internals to contributors, who build the docs with
// `--document-private-items`; there a link to a `pub(crate)` item resolves.
#![allow(rustdoc::private_intra_doc_links)]

pub mod advisory;
pub mod cli;
pub mod commands;
pub mod config;
pub mod core;
pub mod ecosystem;
pub mod ext;
pub mod lock;
pub mod model;
pub mod net;
pub mod policy;
pub mod repo;
pub mod report;
pub mod session;
pub mod version;

/// Adapter plumbing: a keyed cache that also collapses concurrent misses.
///
/// Crate-private by decision rather than by omission. Every holder is an
/// adapter or the spider, and an embedder supplying its own `Source` has no
/// use for ours.
pub(crate) mod cache;

/// Shared plumbing with no natural owner, and not part of the public API.
///
/// The bar is deliberately high: a URL helper belongs in `net` and a
/// version rule belongs in `ecosystem`. Only something a reader would not
/// think to look for anywhere more specific earns a place here.
pub(crate) mod internal;

pub use crate::core::ctx::Ctx;
pub use crate::core::error::{Error, Result};
