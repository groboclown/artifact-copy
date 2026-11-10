//! What the Nexus asset search returns, and nothing else.
//!
//! Kept apart from the source for the same reason
//! `nexus::enumerator::component` is kept apart from its enumerator: a
//! change to the wire format -- Nexus adding a field, an older server
//! omitting one -- is a change to this file only, and reading the source
//! does not mean reading a hundred lines of field declarations first.
//!
//! # The doubled `lastDownloaded` cannot reach here
//!
//! A real Nexus 3 emits `lastDownloaded` **twice** on one asset, `null`
//! first and then the real timestamp, which a derived `Deserialize` refuses
//! outright with *duplicate field* -- failing the page and so the whole
//! request. The enumerator carries a hand-written visitor to fold the repeats.
//!
//! This one does not need it, and the reason is worth stating because it is
//! load-bearing rather than luck: **serde rejects a duplicate only of a
//! field the struct declares.** `lastDownloaded` is not declared here --
//! usage data is an enumerator's answer, not a source's -- so it goes to
//! `IgnoredAny` with no duplicate tracking at all.
//!
//! That makes the absence of the field a decision rather than an omission.
//! Adding it later would reintroduce the failure, and a test pins the
//! current behaviour against the real doubled page.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::model::{Digest, DigestAlg};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AssetPage {
    #[serde(default)]
    pub(super) items: Vec<Asset>,

    #[serde(default)]
    pub(super) continuation_token: Option<String>,
}

/// One page of `search`: components, each with its assets.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchPage {
    #[serde(default)]
    pub(super) items: Vec<Match>,

    #[serde(default)]
    pub(super) continuation_token: Option<String>,
}

/// One component a search matched.
#[derive(Debug, Deserialize)]
pub(super) struct Match {
    /// A Maven group, or an npm scope without its `@`.
    #[serde(default)]
    pub(super) group: Option<String>,

    #[serde(default)]
    pub(super) name: String,

    /// For Maven, the build: a snapshot's is timestamped.
    #[serde(default)]
    pub(super) version: Option<String>,

    #[serde(default)]
    pub(super) assets: Vec<Asset>,
}

/// A page that continues by token, whatever it holds.
pub(super) trait Paged {
    type Item;

    fn split(self) -> (Vec<Self::Item>, Option<String>);
}

impl Paged for AssetPage {
    type Item = Asset;

    fn split(self) -> (Vec<Asset>, Option<String>) {
        (self.items, self.continuation_token)
    }
}

impl Paged for SearchPage {
    type Item = Match;

    fn split(self) -> (Vec<Match>, Option<String>) {
        (self.items, self.continuation_token)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Asset {
    /// Where the file sits in the repository, which for a raw repository
    /// **is** the coordinate.
    #[serde(default)]
    pub(super) path: Option<String>,

    /// Where to fetch it.
    ///
    /// Taken as given rather than rebuilt from the base URL and the path:
    /// a Nexus behind a reverse proxy reports the outward URL, and
    /// constructing one from the API's own address would send every
    /// download to an address that may not be reachable.
    #[serde(default)]
    pub(super) download_url: Option<String>,

    /// An open map, because Nexus decides which algorithms it stores.
    ///
    /// All four of md5, sha1, sha256 and sha512 appeared in a captured
    /// repository. A `BTreeMap` rather than four fields so a fifth
    /// algorithm arrives as a dropped entry rather than a parse failure.
    #[serde(default)]
    checksum: BTreeMap<String, String>,

    #[serde(default)]
    pub(super) file_size: Option<u64>,

    /// When the stored blob was created.
    ///
    /// **The publish time**, and `lastModified` is not. In a captured
    /// repository 44 of 65 assets share one `lastModified` month while
    /// `blobCreated` spreads across three years -- `lastModified` reflects
    /// a server-side re-index, and taking it would put an entire
    /// repository inside any publish window.
    #[serde(default)]
    blob_created: Option<String>,
}

impl Asset {
    /// A file a browse page listed: no digests, and its modification time
    /// standing in for the blob's creation; see `browse`.
    pub(super) fn browsed(
        path: String,
        download_url: String,
        file_size: Option<u64>,
        modified: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            path: Some(path),
            download_url: Some(download_url),
            checksum: BTreeMap::new(),
            file_size,
            blob_created: modified.map(|stamp| stamp.to_rfc3339()),
        }
    }

    /// Every checksum Nexus declared, strongest last.
    ///
    /// An algorithm this build does not know is **dropped rather than
    /// guessed at**: a digest recorded under the wrong algorithm would fail
    /// every verification, which reads as corruption rather than as a
    /// checksum nobody can check.
    pub(super) fn digests(&self) -> Vec<Digest> {
        let mut out: Vec<Digest> = self
            .checksum
            .iter()
            .filter_map(|(algorithm, hex)| {
                DigestAlg::parse(algorithm).map(|alg| Digest::new(alg, hex))
            })
            .collect();

        out.sort_by_key(|digest| digest.alg);

        out
    }

    /// The file's own name: the last segment of its path.
    pub(super) fn file_name(&self) -> Option<&str> {
        self.path
            .as_deref()?
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
    }

    /// When this file was published, as far as the repository knows.
    pub(super) fn published(&self) -> Option<DateTime<Utc>> {
        self.blob_created
            .as_deref()
            .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            .map(|stamp| stamp.with_timezone(&Utc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed copy of a page the local Nexus served, keeping the shape
    /// that matters.
    const PAGE: &str = r#"{
      "items": [
        {
          "downloadUrl": "http://nexus.test/repository/raw-hosted/artifact1/1.0/a1.txt",
          "path": "/artifact1/1.0/a1.txt",
          "repository": "raw-hosted",
          "format": "raw",
          "checksum": {
            "md5": "dc32d9706b76667cfeee437e8d8955c0",
            "sha1": "9317c7beb2c7ac12f46d15348daf2307e8ffb785",
            "sha256": "15864e5fe90e1b96532857b4ef5a9cccef14307d22def8575507c0ff66eb060b",
            "sha512": "12ded3a3052db93ce82e7e1abaf1fdd752b307a6cdf4a9d895fe85e9d85074137b48cef74dbeba0d1ae7f7aef474aced01386ae0f2559310be2cf362fab5117a"
          },
          "contentType": "text/plain",
          "lastModified": "2026-09-22T23:33:08.066+00:00",
          "lastDownloaded": null,
          "fileSize": 15,
          "blobCreated": "2026-09-22T23:31:53.429+00:00",
          "raw": {}
        }
      ],
      "continuationToken": null
    }"#;

    fn parsed(text: &str) -> AssetPage {
        serde_json::from_str(text).expect("parses")
    }

    #[test]
    fn asset_carries_file_fields() {
        let page = parsed(PAGE);
        let [asset] = page.items.as_slice() else {
            panic!("expected one asset");
        };

        assert_eq!(asset.path.as_deref(), Some("/artifact1/1.0/a1.txt"));
        assert_eq!(asset.file_size, Some(15));
        assert!(asset.download_url.as_deref().unwrap().ends_with("a1.txt"));
    }

    /// Every algorithm Nexus declared, strongest last so `best_digest`
    /// finds the strongest.
    #[test]
    fn checksums_every_declared_become_digests() {
        let page = parsed(PAGE);
        let digests = page.items[0].digests();

        let algorithms: Vec<DigestAlg> = digests.iter().map(|digest| digest.alg).collect();

        assert_eq!(
            algorithms,
            [
                DigestAlg::Md5,
                DigestAlg::Sha1,
                DigestAlg::Sha256,
                DigestAlg::Sha512
            ]
        );
    }

    /// Dropped rather than guessed at: a digest recorded under the wrong
    /// algorithm fails every verification, which reads as corruption.
    #[test]
    fn checksums_unknown_algorithm_dropped() {
        let page = parsed(r#"{"items":[{"path":"a/b","checksum":{"blake3":"aa","sha256":"bb"}}]}"#);

        let digests = page.items[0].digests();

        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].alg, DigestAlg::Sha256);
    }

    /// **`blobCreated`, not `lastModified`.** In a captured repository 44
    /// of 65 assets share one `lastModified` month while `blobCreated`
    /// spreads across three years: `lastModified` is a re-index, and taking
    /// it would put an entire repository inside any publish window.
    #[test]
    fn publish_time_is_blob_creation() {
        let published = parsed(PAGE).items[0].published().expect("a time");

        assert_eq!(published.to_rfc3339(), "2026-09-22T23:31:53.429+00:00");
    }

    /// **The doubled `lastDownloaded` cannot fail this page**, because the
    /// field is not declared: serde tracks duplicates only of fields the
    /// struct names, so this one goes to `IgnoredAny`.
    ///
    /// The same shape fails a derived `Deserialize` in
    /// `nexus::enumerator::component`, which is why that one is hand-written.
    /// Declaring the field here would reintroduce the failure.
    #[test]
    fn last_downloaded_doubled_does_not_fail_page() {
        let doubled = r#"{"items":[{
            "path": "a/b/x.txt",
            "lastDownloaded": null,
            "fileSize": 12,
            "lastDownloaded": "2026-09-10T04:42:28.414+00:00"
        }]}"#;

        let page = parsed(doubled);

        assert_eq!(page.items[0].path.as_deref(), Some("a/b/x.txt"));
        assert_eq!(page.items[0].file_size, Some(12));
    }

    /// An asset with no checksums at all is a file that cannot be
    /// verified, not a parse failure.
    #[test]
    fn checksums_absent_read_as_none() {
        let page = parsed(r#"{"items":[{"path":"a/b"}]}"#);

        assert!(page.items[0].digests().is_empty());
        assert_eq!(page.items[0].published(), None);
    }
}
