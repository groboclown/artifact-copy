//! What one page of a walk contains.
//!
//! A page, not a stream: see the module documentation on [`super`] for why
//! the awkward shape is the only one that survives an out-of-process
//! enumerator.
//!
//! The rule a reader has to take from here is that **an empty page is not
//! the end of a catalog**. Only an absent [`Cursor`] ends a walk. A Nexus
//! page can be entirely filtered out and still have more behind it, and a
//! caller that stopped on emptiness would silently truncate.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::LastDownload;
use crate::model::{ArtifactId, Digest, Version};

/// One file an enumerator saw as part of an artifact.
///
/// What the catalog **says**, not what a source resolved: the report keeps
/// the two apart, and `repo::InventorySource` is the one place that
/// combines them. See `docs/contributors/sources-and-targets.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub url: String,
    pub size: Option<u64>,

    /// Every digest the catalog reported for this file.
    pub digests: Vec<Digest>,
}

/// One artifact an enumerator found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub id: ArtifactId,

    /// The version, when the enumerator enumerates them.
    ///
    /// Optional because some catalogs list names only: npm's replication
    /// feed yields package names, and the versions cost a packument each.
    /// An enumerator that cannot cheaply enumerate versions says so here rather
    /// than inventing one.
    pub version: Option<Version>,

    /// When the repository last served this artifact.
    pub last_download: LastDownload,

    /// The files the catalog holds for this artifact, when it lists them.
    ///
    /// Empty from an enumerator that lists names only. Never a claim that the
    /// list is complete: a directory can straddle pages, and a file the
    /// source names but no artifact enumeration saw is not a disagreement.
    pub files: Vec<Listed>,
}

impl Found {
    /// An artifact with no version and no usage data -- what most enumerators
    /// can honestly report.
    pub fn new(id: ArtifactId) -> Self {
        Self {
            id,
            version: None,
            last_download: LastDownload::Unknown,
            files: Vec::new(),
        }
    }

    pub fn files(mut self, files: Vec<Listed>) -> Self {
        self.files = files;
        self
    }

    pub fn version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    pub fn maybe_version(mut self, version: Option<Version>) -> Self {
        self.version = version;
        self
    }

    pub fn last_download(mut self, last: LastDownload) -> Self {
        self.last_download = last;
        self
    }
}

/// Where a walk resumes.
///
/// Opaque to the host and meaningful only to the enumerator that issued it: a
/// `startkey` for npm's feed, a continuation token for Nexus, a byte offset
/// into a cached index. A string rather than a structure so it survives
/// marshalling without the protocol needing to know what is inside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cursor(String);

impl Cursor {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One page of a walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub found: Vec<Found>,

    /// Where to resume, or `None` at the end of the catalog.
    ///
    /// An empty `found` with a cursor is legitimate -- a page of a Nexus
    /// catalog can be entirely filtered out -- so emptiness must not be
    /// taken as the end. Only the absent cursor ends a walk.
    pub next: Option<Cursor>,
}

impl Page {
    /// A page with more to come.
    pub fn more(found: Vec<Found>, next: Cursor) -> Self {
        Self {
            found,
            next: Some(next),
        }
    }

    /// The final page.
    pub fn last(found: Vec<Found>) -> Self {
        Self { found, next: None }
    }

    /// Whether the walk continues past this page.
    pub fn has_more(&self) -> bool {
        self.next.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EcosystemId;

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), name)
    }

    #[test]
    fn page_ends_walk_only_without_cursor() {
        assert!(Page::more(Vec::new(), Cursor::new("next")).has_more());
        assert!(!Page::last(vec![Found::new(id("lib"))]).has_more());

        // An empty page with a cursor is legitimate: a whole page of a
        // catalog can be filtered out. Treating emptiness as the end would
        // silently truncate the walk.
        let empty_but_more = Page::more(Vec::new(), Cursor::new("next"));

        assert!(empty_but_more.found.is_empty());
        assert!(empty_but_more.has_more());
    }

    #[test]
    fn cursor_survives_exchange_format() {
        let cursor = Cursor::new("startkey=%22lodash%22");

        let json = serde_json::to_string(&cursor).expect("serialized");
        let back: Cursor = serde_json::from_str(&json).expect("deserialized");

        assert_eq!(back, cursor);
        assert_eq!(back.as_str(), "startkey=%22lodash%22");
    }
}
