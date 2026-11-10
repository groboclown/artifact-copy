//! Dependency edges, before resolution.
//!
//! [`DepKind`] is a closed set because these are the kinds this tool knows
//! how to be asked for on a command line. Not every ecosystem has every
//! one -- `test` is Maven's, `peer` is npm's -- which is why an adapter
//! declares its own set rather than being assumed to support all five.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{ArtifactId, VersionSpec};

/// A kind of dependency edge.
///
/// Not every ecosystem has every kind: `test` is Maven-only, `peer` is
/// npm-only, and PyPI publishes no dev/test distinction at all.  Adapters
/// declare their own set through `Repository::dep_kinds`, so asking for one
/// an ecosystem lacks is a loud error rather than a silent empty result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepKind {
    Runtime,
    Dev,
    Test,
    Optional,
    Peer,

    /// What reading or building against the artifact needs, rather than
    /// what it runs with: a Maven parent POM, or a BOM it imports.
    ///
    /// Followed whenever any dependency is, since none of the others can
    /// be resolved by a build without it.
    Build,
}

impl DepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DepKind::Runtime => "runtime",
            DepKind::Dev => "dev",
            DepKind::Test => "test",
            DepKind::Optional => "optional",
            DepKind::Peer => "peer",
            DepKind::Build => "build",
        }
    }

    /// Parse one `--dependencies` token.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "runtime" => Some(DepKind::Runtime),
            "dev" => Some(DepKind::Dev),
            "test" => Some(DepKind::Test),
            "optional" => Some(DepKind::Optional),
            "peer" => Some(DepKind::Peer),
            "build" => Some(DepKind::Build),
            _ => None,
        }
    }
}

impl fmt::Display for DepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One dependency edge, before resolution.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub id: ArtifactId,
    pub spec: VersionSpec,
    pub kind: DepKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_kind_round_trips() {
        for kind in [
            DepKind::Runtime,
            DepKind::Dev,
            DepKind::Test,
            DepKind::Optional,
            DepKind::Peer,
            DepKind::Build,
        ] {
            assert_eq!(DepKind::parse(kind.as_str()), Some(kind));
        }

        assert_eq!(DepKind::parse("provided"), None);
    }
}
