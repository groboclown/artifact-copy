//! A local directory as a generic repository.
//!
//! Read, written, and walked through the `ExtHost` like every other kind;
//! the directory itself is answered by `net::emulate`, which this module
//! never sees past. A file is a URL under the repository, and the listing
//! is the generic emulation:
//!
//! ```text
//!   GET  {base}/?api=generic-list&prefix={p}[&digests=sha256]
//!   GET  {base}/{path}
//!   PUT  {base}/{path}
//! ```
//!
//! # What an artifact is
//!
//! The same [`Mapping`] every raw repository reads, defaulting to
//! `directory`, so a copy between a directory and a repository manager
//! that both leave it unset puts every file back where it was.
//!
//! # Hashes
//!
//! A resolution asks the listing for SHA-256, which reads each file it
//! names: a copy states what it is about to send. A walk asks for none,
//! because hashing a whole backup to enumerate it would read it twice.
//! Nothing here ever writes to a directory it reads.

use std::sync::Arc;

use crate::core::error::Result;
use crate::ext::{ExtHost, Options};

mod enumerator;
mod repository;
mod source;
mod target;
#[cfg(test)]
pub(crate) mod testing;

pub use enumerator::LocalDirEnumerator;
pub use source::LocalDirSource;
pub use target::LocalDirTarget;

use repository::{Repository, file_url, prefix_of};

use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind, Versions};

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new(KIND, open_source).versions(Versions::DirectoryMapping)),
    target: Some(TargetKind {
        name: KIND,
        open: open_target,
    }),
    enumerators: &[EnumeratorKind::new(KIND, open_enumerator)],
};

/// The kind, as configuration names it for a source, target, and
/// enumerator alike.
pub const KIND: &str = "local-directory";

/// How the directory's paths become coordinates.
pub(super) const MAPPING: &str = "mapping";

/// Reading the directory at `base_url`.
fn open_source(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    _trust: super::Trust,
) -> Result<Arc<dyn super::Source>> {
    Ok(Arc::new(LocalDirSource::open(base_url, options, host)?))
}

/// Writing into the directory at `base_url`.
fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::Target>> {
    Ok(Arc::new(LocalDirTarget::open(base_url, options, host)?))
}

/// Walking the directory at `base_url`.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(LocalDirEnumerator::open(base_url, options, host)?))
}
