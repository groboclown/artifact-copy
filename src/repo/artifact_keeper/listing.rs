//! What the artifact listing and the stats endpoint return, and nothing else.
//!
//! An **item is a file**, not an artifact: recovering a coordinate from its
//! path stays with the enumerator.

use serde::Deserialize;

use crate::model::{Digest, DigestAlg, LastDownload};

/// One page of `GET {repository}/artifacts`.
#[derive(Debug, Deserialize)]
pub(super) struct Listing {
    #[serde(default)]
    pub(super) items: Vec<Item>,

    /// Absent, not false, on a remote repository's legacy listing, which
    /// pages by number only.  `None` is therefore not the end of a walk.
    #[serde(default)]
    pub(super) has_more: Option<bool>,

    /// The keyset cursor for the next page, when there is one.
    #[serde(default)]
    pub(super) next_cursor: Option<String>,

    #[serde(default)]
    pub(super) pagination: Option<Pagination>,
}

impl Listing {
    /// Whether the server says more pages follow, by whichever field it
    /// sent.  `None` when it sent neither, which no walk may read as the
    /// end.
    ///
    /// `has_more` first: the page totals were a lower bound as of 1.9.1,
    /// so they are read only where nothing better was sent.
    pub(super) fn more_after(&self, page: u64) -> Option<bool> {
        if let Some(more) = self.has_more {
            return Some(more);
        }

        self.pagination
            .as_ref()
            .and_then(|pagination| pagination.total_pages)
            .map(|total| page < total)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct Pagination {
    #[serde(default)]
    total_pages: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Item {
    /// The id the stats endpoint takes.
    #[serde(default)]
    pub(super) id: Option<String>,

    pub(super) path: String,

    #[serde(default)]
    size_bytes: Option<i64>,

    /// The only digest the listing carries.
    #[serde(default)]
    checksum_sha256: Option<String>,

    /// When the server stored the file.
    #[serde(default)]
    created_at: Option<String>,
}

impl Item {
    /// The file's name: the last segment of its path.
    pub(super) fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// A negative or zero size is no size.
    pub(super) fn size(&self) -> Option<u64> {
        self.size_bytes
            .filter(|&size| size > 0)
            .and_then(|size| u64::try_from(size).ok())
    }

    pub(super) fn published(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.created_at
            .as_deref()
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|stamp| stamp.with_timezone(&chrono::Utc))
    }

    pub(super) fn digests(&self) -> Vec<Digest> {
        self.checksum_sha256
            .as_deref()
            .map(str::trim)
            .filter(|hex| !hex.is_empty())
            .map(|hex| vec![Digest::new(DigestAlg::Sha256, hex)])
            .unwrap_or_default()
    }
}

/// `GET api/v1/artifacts/{id}/stats`.
#[derive(Debug, Deserialize)]
pub(super) struct Stats {
    #[serde(default)]
    last_downloaded: Option<String>,
}

impl Stats {
    /// The server records every download it serves, so no timestamp means
    /// none was recorded.  Events can be dropped under load, which makes
    /// `Never` approximate rather than wrong.
    /// A timestamp that does not parse says nothing either way.
    pub(super) fn last_download(&self) -> LastDownload {
        let Some(text) = self.last_downloaded.as_deref() else {
            return LastDownload::Never;
        };

        match chrono::DateTime::parse_from_rfc3339(text) {
            Ok(when) => LastDownload::At(when.with_timezone(&chrono::Utc)),
            Err(_) => LastDownload::Unknown,
        }
    }
}
