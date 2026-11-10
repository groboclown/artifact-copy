//! What an AQL search returns, and nothing else.
//!
//! A **row is a file**, not an artifact -- the distinction the enumerator
//! module is largely about -- so nothing here knows what a coordinate is.
//! These types answer only what one row said; folding rows into artifacts
//! and recovering coordinates from them stays with the enumerator.
//!
//! Keeping the shape apart means a change to what AQL returns is a change
//! to this file, and the fold above it does not have to be re-read to see
//! that a field was added.

use serde::Deserialize;

use crate::model::{Digest, DigestAlg, LastDownload};

#[derive(Debug, Deserialize)]
pub(super) struct Results {
    #[serde(default)]
    pub(super) results: Vec<Row>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Row {
    #[serde(default)]
    pub(super) path: String,

    #[serde(default)]
    pub(super) name: String,

    /// `stat.downloaded`, which AQL returns nested under `stats`.
    #[serde(default)]
    stats: Vec<Stat>,

    #[serde(default)]
    properties: Vec<Property>,

    /// Checksums Artifactory computed from the stored bytes. `actual_*`
    /// rather than `original_*`, which are whatever the uploader claimed.
    #[serde(default)]
    actual_sha1: Option<String>,

    #[serde(default)]
    actual_md5: Option<String>,

    #[serde(default)]
    sha256: Option<String>,

    #[serde(default)]
    pub(super) size: Option<u64>,
}

impl Row {
    pub(super) fn property(&self, key: &str) -> Option<String> {
        self.properties
            .iter()
            .find(|property| property.key == key)
            .and_then(|property| property.value.clone())
            .filter(|value| !value.is_empty())
    }

    /// Every checksum this row reported.
    pub(super) fn digests(&self) -> Vec<Digest> {
        [
            (DigestAlg::Sha1, &self.actual_sha1),
            (DigestAlg::Md5, &self.actual_md5),
            (DigestAlg::Sha256, &self.sha256),
        ]
        .into_iter()
        .filter_map(|(alg, hex)| {
            hex.as_deref()
                .filter(|hex| !hex.is_empty())
                .map(|hex| Digest::new(alg, hex))
        })
        .collect()
    }

    /// When this file was last served.
    ///
    /// A never-downloaded file still has its `stats` entry, with a zero count
    /// and no `downloaded` key: `"stats":[{"downloads":0,"remote_downloads":0}]`
    /// (measured on OSS 7.161.26). A row with no `stats` at all is one whose
    /// query did not ask for them, which would read the same, so this
    /// enumerator always asks for `stat.downloaded`; then no `downloaded` key,
    /// whether the entry is there or not, means the file has never been
    /// served.
    ///
    /// AQL's counts can trail a download by a few seconds, so a file fetched
    /// just before the walk may still read as never downloaded.
    pub(super) fn last_download(&self) -> LastDownload {
        let latest = self
            .stats
            .iter()
            .filter_map(|stat| stat.downloaded.as_deref())
            .filter_map(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|stamp| stamp.with_timezone(&chrono::Utc))
            .max();

        match latest {
            Some(when) => LastDownload::At(when),
            None => LastDownload::Never,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Stat {
    #[serde(default)]
    downloaded: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Property {
    #[serde(default)]
    key: String,

    #[serde(default)]
    value: Option<String>,
}
