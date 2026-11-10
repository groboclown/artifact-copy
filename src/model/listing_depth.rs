//! How far an enumerator's listing reaches.

use serde::{Deserialize, Serialize};

/// The most an enumerator's listing carries per item.
///
/// Declared by the enumerator rather than chosen by the user: a catalog of
/// names cannot be asked for versions, and one that lists files has nothing
/// to gain by withholding them. `find` records what it was given.
///
/// An item without a version under [`Versions`](Self::Versions) or
/// [`Files`](Self::Files) has a coordinate with no version -- a raw
/// `directory` or `as-is` mapping -- not a version a second pass would find.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ListingDepth {
    /// Names only, such as PyPI's simple index. The default, because it
    /// claims least.
    #[default]
    Names,

    /// Names and versions.
    Versions,

    /// Names, versions, and each version's files.
    Files,
}

impl ListingDepth {
    pub fn as_str(self) -> &'static str {
        match self {
            ListingDepth::Names => "names",
            ListingDepth::Versions => "versions",
            ListingDepth::Files => "files",
        }
    }
}

impl std::fmt::Display for ListingDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_is_default() {
        assert_eq!(ListingDepth::default(), ListingDepth::Names);
    }

    #[test]
    fn deeper_orders_after() {
        assert!(ListingDepth::Names < ListingDepth::Versions);
        assert!(ListingDepth::Versions < ListingDepth::Files);
    }

    #[test]
    fn serde_matches_as_str() {
        for depth in [
            ListingDepth::Names,
            ListingDepth::Versions,
            ListingDepth::Files,
        ] {
            let json = serde_json::to_string(&depth).expect("serialized");

            assert_eq!(json, format!("\"{}\"", depth.as_str()));
        }
    }
}
