//! Lock-file inspection: the sixth extension point.
//!
//! Lock formats belong to *tools*, not to registries. `uv.lock`,
//! `poetry.lock` and `requirements.txt` all yield PyPI artifacts and share
//! nothing else, and an organization with an internal manifest format wants
//! to read it without reimplementing PyPI. Keeping this separate also leaves
//! [`crate::ecosystem::Ecosystem`] genuinely pure -- lock reading was the only
//! thing on it that touched a file.
//!
//! **Two different sizes of read, deliberately kept apart.** Deciding
//! *whether* a reader claims a file needs only its first bytes, so
//! [`LockHead`] carries at most [`LOCK_PEEK_BYTES`] and the type says so.
//! Actually reading the file needs all of it, so [`Lock::read`] takes a
//! path and opens it under a cap rather than receiving a `&[u8]`
//! somebody else had to hold in memory first. A `pnpm-lock.yaml` for a large
//! monorepo runs to tens of megabytes; nothing should pass one around by
//! accident.

use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::model::ArtifactRequest;
use crate::policy::Statement;

mod bom;
mod npm;
mod read;
mod registry;
mod spec;

pub use registry::Registry;
pub use spec::LockSpec;

use read::read_capped;

/// How much of a file a claim check may look at.
///
/// Enough to see a `lockfileVersion`, a `__metadata:` marker or a TOML
/// header, and small enough that probing a file costs nothing. A reader that
/// needs more than this to recognize its own format is doing it wrong.
pub const LOCK_PEEK_BYTES: usize = 64 * 1024;

/// The first bytes of a lock file.
///
/// A newtype rather than a bare `&[u8]` so the bound is in the signature: a
/// reader cannot mistake a peek for the whole file, and a caller cannot pass
/// a whole file where a peek was meant.
#[derive(Debug, Clone, Copy)]
pub struct LockHead<'a> {
    bytes: &'a [u8],
}

impl<'a> LockHead<'a> {
    /// Take at most [`LOCK_PEEK_BYTES`] from the front.
    pub fn of(body: &'a [u8]) -> Self {
        Self {
            bytes: &body[..body.len().min(LOCK_PEEK_BYTES)],
        }
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// The head as text, for the many formats that are recognizable by a
    /// marker string. Invalid UTF-8 is dropped rather than failing: a
    /// binary lock file simply will not match anything.
    pub fn text(&self) -> std::borrow::Cow<'a, str> {
        String::from_utf8_lossy(self.bytes)
    }
}

/// One lock format a `Lock` extension reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LockFormat {
    /// The name users type in `--lock=FORMAT,FILE`.  **User-facing API**:
    /// it lands in scripts, so renaming one is a breaking change.
    pub name: String,

    /// Filename globs this format answers to, for the cheap first pass.
    pub filenames: Vec<String>,
}

/// What one lock file names.
#[derive(Debug, Default)]
pub struct LockRead {
    /// Every artifact the file names.
    pub requests: Vec<ArtifactRequest>,

    /// The VEX statements the file makes about those artifacts. Empty for
    /// every format but a VEX or SBOM document.
    pub statements: Vec<Statement>,
}

impl From<Vec<ArtifactRequest>> for LockRead {
    fn from(requests: Vec<ArtifactRequest>) -> Self {
        Self {
            requests,
            statements: Vec::new(),
        }
    }
}

/// Reads one family of lock files.
#[async_trait]
pub trait Lock: Send + Sync {
    /// The formats this reader handles and the filenames they answer to.
    fn formats(&self) -> &[LockFormat];

    /// Whether this reader claims a file.
    ///
    /// Both arguments are needed and neither is sufficient on its own:
    /// `yarn.lock` v1 and Berry share a filename and are different formats,
    /// while a `pylock.toml` is routinely named `pylock.prod.toml`.
    fn claims<'n, 'h>(&self, name: &'n str, head: &LockHead<'h>) -> bool;

    /// Every artifact the file names, and any VEX statements it makes.
    ///
    /// The reader opens `file` itself, so a large lock file never travels
    /// through a call.
    async fn read(&self, file: &Path, ctx: &Ctx) -> Result<LockRead>;

    /// Whether the files this reader claims carry VEX statements.
    ///
    /// Such a file is read before the walk starts, since a statement has to
    /// be known before the first artifact it covers is screened. Every
    /// other lock file is read when the walk reaches it.
    fn attests(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound is in the type, so a reader cannot mistake a peek for the
    /// whole file.
    #[test]
    fn head_capped() {
        let big = vec![b'x'; LOCK_PEEK_BYTES * 3];
        let head = LockHead::of(&big);

        assert_eq!(head.bytes().len(), LOCK_PEEK_BYTES);
    }

    #[test]
    fn head_of_short_body_is_whole() {
        let head = LockHead::of(b"{}");

        assert_eq!(head.bytes(), b"{}");
        assert_eq!(head.text(), "{}");
    }

    #[test]
    fn head_binary_yields_lossy_text() {
        let head = LockHead::of(&[0xff, 0xfe, b'a']);

        assert!(head.text().contains('a'));
    }
}
