//! Versions, as text plus one computed flag.
//!
//! The raw text is kept verbatim and never re-rendered from a parsed form:
//! every ecosystem normalizes differently, and a round trip through a
//! structure would change what is asked of the registry. Ordering and
//! pre-release detection are the adapter's job, and [`Release`] is where
//! the adapter's answer is carried.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One resolved, exact version.
///
/// The text is kept verbatim because every ecosystem normalizes differently
/// and a round-trip through a parsed form would change what is requested from
/// the registry.  Ordering is the adapter's job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    text: String,
    release: Release,
}

/// Whether a version is generally available.
///
/// An enum rather than a `bool` so a call site reads as
/// `Release::PreRelease` instead of `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Release {
    /// A general-availability release.
    General,

    /// Alpha, beta, release candidate, snapshot, dev, or similar.
    PreRelease,
}

impl Version {
    pub fn new(text: impl Into<String>, release: Release) -> Self {
        Self {
            text: text.into(),
            release,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn release(&self) -> Release {
        self.release
    }

    pub fn is_pre_release(&self) -> bool {
        self.release == Release::PreRelease
    }
}

impl Release {
    /// The spelling a report and the report database store.
    pub fn as_str(self) -> &'static str {
        match self {
            Release::General => "general",
            Release::PreRelease => "pre-release",
        }
    }

    /// Read back what [`Release::as_str`] wrote.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "general" => Some(Release::General),
            "pre-release" => Some(Release::PreRelease),
            _ => None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// A requested version constraint, verbatim as the user wrote it.
///
/// Interpreting it is the adapter's job: `[1.0,2.0)` means something to Maven
/// and nothing to npm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionSpec {
    /// No constraint; take the newest.
    Any,

    /// An exact version.
    Exact(String),

    /// An ecosystem-specific range expression.
    Range(String),
}

impl fmt::Display for VersionSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionSpec::Any => f.write_str("*"),
            VersionSpec::Exact(text) | VersionSpec::Range(text) => f.write_str(text),
        }
    }
}
