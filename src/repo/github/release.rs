//! What GitHub's releases endpoints return, and nothing else.
//!
//! One shape serves all three requests -- by tag, `/latest`, and a page of
//! them -- because GitHub returns the same document from each.
//!
//! [`ReleaseDoc::version`] is here rather than in the source because the
//! release status it reports is a property of the document: GitHub's own
//! `prerelease` flag, not a judgment made about the tag text.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::model::{Release, Version};

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ReleaseDoc {
    #[serde(default)]
    pub(super) tag_name: String,

    /// Unpublished: visible only to people who can write to the repository,
    /// and its assets are not downloadable. The source drops these rather
    /// than counting them as pre-releases.
    #[serde(default)]
    pub(super) draft: bool,

    #[serde(default)]
    pub(super) prerelease: bool,

    #[serde(default)]
    published_at: Option<String>,

    #[serde(default)]
    pub(super) assets: Vec<Asset>,
}

impl ReleaseDoc {
    /// `text`, the tag or what a name mapping made of it, carrying the
    /// release status the API reported.
    ///
    /// Taken from the `prerelease` flag rather than guessed from the tag
    /// text -- `v2.0.0-rc1` and `v2.0.0` are both just strings, and only the
    /// API knows which the project meant.
    pub(super) fn version_as(&self, text: &str) -> Version {
        Version::new(
            text,
            match self.prerelease {
                true => Release::PreRelease,
                false => Release::General,
            },
        )
    }

    pub(super) fn published(&self) -> Option<DateTime<Utc>> {
        self.published_at
            .as_deref()
            .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            .map(|stamp| stamp.with_timezone(&Utc))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Asset {
    #[serde(default)]
    pub(super) name: String,

    #[serde(default)]
    pub(super) browser_download_url: String,

    #[serde(default)]
    pub(super) size: Option<u64>,
}
