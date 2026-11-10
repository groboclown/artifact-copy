//! Which ecosystem something belongs to.
//!
//! **Open, not an enum**, because `ecosystem` is an extension point: a
//! third-party `cargo` or `nuget` has to be representable without a code
//! change in this crate.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A package ecosystem's identity.
///
/// **Open, not an enum.** `ecosystem` is an extension point, so a
/// third-party `cargo` or `nuget` extension has to be representable; a
/// closed enum would make "add an ecosystem" a code change in this crate.
/// The three built-in spellings are constants rather than variants.
///
/// The value is the purl type, which is the canonical lowercase name the
/// purl spec already defines -- so there is no separate mapping to keep in
/// step. The OSV name is *not* derivable (`Maven`, `PyPI`, `npm` are all
/// capitalized differently) and comes from the ecosystem's own description.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EcosystemId(String);

impl EcosystemId {
    pub const MAVEN: &'static str = "maven";
    pub const PYPI: &'static str = "pypi";
    pub const NPM: &'static str = "npm";

    /// A repository holding arbitrary files under a path.
    ///
    /// Not a registry and not a purl type anybody else publishes: the
    /// coordinate scheme is whatever the person who filled the repository
    /// decided, which is why a raw source takes a mapping.
    pub const RAW: &'static str = "raw";

    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn maven() -> Self {
        Self::new(Self::MAVEN)
    }

    pub fn pypi() -> Self {
        Self::new(Self::PYPI)
    }

    pub fn npm() -> Self {
        Self::new(Self::NPM)
    }

    pub fn raw() -> Self {
        Self::new(Self::RAW)
    }

    /// The `pkg:<type>` segment of a purl.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EcosystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id is the purl type verbatim, so there is no mapping to drift.
    #[test]
    fn ecosystem_id_is_purl_type() {
        assert_eq!(EcosystemId::pypi().as_str(), "pypi");
        assert_eq!(EcosystemId::npm().as_str(), "npm");
        assert_eq!(EcosystemId::maven().as_str(), "maven");
    }

    /// The point of an open id: an ecosystem this crate has never heard of.
    #[test]
    fn ecosystem_id_unknown_representable() {
        let cargo = EcosystemId::new("cargo");

        assert_eq!(cargo.as_str(), "cargo");
        assert_ne!(cargo, EcosystemId::npm());
    }
}
