//! Artifactory's storage API: what one path holds.
//!
//! ```text
//!   GET {base}/api/storage/{repo}/{path}   folder: children; file: checksums, size
//! ```
//!
//! The storage API rather than AQL, because AQL needs a login on every
//! edition and a source may read an anonymous repository.
//!
//! # Publish time
//!
//! The later of `created` and `lastModified`, because neither alone is safe
//! for a publish window, which asks whether anything is too new to trust:
//!
//! - A redeploy keeps `created` and moves `lastModified` (measured on OSS
//!   7.161.26), so `created` alone calls new bytes old.
//! - An uploader sets `lastModified` through `X-Artifactory-Last-Modified`
//!   or `Last-Modified` (see `server-behaviors.md`), so `lastModified` alone
//!   believes a backdated claim.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::Deserialize;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::ExtHost;
use crate::model::{Digest, DigestAlg, FileRef};
use crate::net::{ByteLimit, Req, encode_unreserved};

/// The storage API, relative to the Artifactory base URL.
const STORAGE: &str = "api/storage";

/// One folder's or one file's info.
const INFO_LIMIT: ByteLimit = ByteLimit::mib(1);

/// A folder's or a file's info; which one, `children` says.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    /// Sent for a folder, even an empty one, and never for a file.
    #[serde(default)]
    children: Option<Vec<Child>>,

    #[serde(flatten)]
    info: Info,
}

#[derive(Debug, Deserialize)]
struct Child {
    /// `/name`, relative to the folder.
    uri: String,

    #[serde(default)]
    folder: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Info {
    #[serde(default)]
    download_uri: Option<String>,

    /// A number, sent as a string.
    #[serde(default)]
    size: Option<String>,

    /// Computed from the stored bytes; `originalChecksums` are the
    /// uploader's claim.
    #[serde(default)]
    checksums: std::collections::BTreeMap<String, String>,

    #[serde(default)]
    created: Option<String>,

    #[serde(default)]
    last_modified: Option<String>,
}

impl Info {
    fn digests(&self) -> Vec<Digest> {
        self.checksums
            .iter()
            .filter_map(|(alg, hex)| Some(Digest::new(DigestAlg::parse(alg)?, hex.clone())))
            .collect()
    }

    /// The SHA-256 Artifactory computed from the stored bytes.
    pub(super) fn sha256(&self) -> Option<&str> {
        self.checksums.get("sha256").map(String::as_str)
    }

    /// The later of the two; see the module documentation.
    pub(super) fn published(&self) -> Option<DateTime<Utc>> {
        [&self.created, &self.last_modified]
            .into_iter()
            .filter_map(|text| DateTime::parse_from_rfc3339(text.as_deref()?).ok())
            .map(|stamp| stamp.with_timezone(&Utc))
            .max()
    }
}

/// What one path holds.
pub(super) enum Entry {
    /// Nothing is stored there.
    Missing,

    /// A folder's file names and sub-folder names, each relative to it.
    Folder {
        files: Vec<String>,
        folders: Vec<String>,
    },

    File(Info),
}

pub(super) struct Storage {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
}

impl Storage {
    pub(super) fn new(base_url: String, host: Arc<dyn ExtHost>, repository: String) -> Self {
        Self {
            base_url,
            host,
            repository,
        }
    }

    /// `path` with each segment encoded, for a path whose segments are
    /// text rather than already encoded.
    pub(super) fn encode(path: &str) -> String {
        path.split('/')
            .map(encode_unreserved)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// `path` is already encoded.
    fn url(&self, path: &str) -> String {
        format!(
            "{}/{STORAGE}/{}/{path}",
            self.base_url,
            encode_unreserved(&self.repository)
        )
    }

    /// Where the repository serves `path`, already encoded.
    pub(super) fn served(&self, path: &str) -> String {
        format!(
            "{}/{}/{path}",
            self.base_url,
            encode_unreserved(&self.repository)
        )
    }

    /// What `path`, already encoded, holds.
    pub(super) async fn entry(&self, path: &str, ctx: &Ctx) -> Result<Entry> {
        let fetched: Result<Item> = crate::ext::fetch_json(
            &*self.host,
            &Req::get(self.url(path)),
            INFO_LIMIT,
            "artifactory storage info",
            ctx,
        )
        .await;

        let item = match fetched {
            // HTTP 404: no such path.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                return Ok(Entry::Missing);
            }
            other => other?,
        };

        let Some(children) = item.children else {
            return Ok(Entry::File(item.info));
        };

        // Split by kind, dropping the empty name a stray `/` would leave.
        let mut files = Vec::new();
        let mut folders = Vec::new();

        for child in children {
            let name = child.uri.trim_start_matches('/').to_owned();

            if name.is_empty() {
                continue;
            }

            match child.folder {
                true => folders.push(name),
                false => files.push(name),
            }
        }

        Ok(Entry::Folder { files, folders })
    }

    /// One file's info; `path` is already encoded.
    pub(super) async fn info(&self, path: &str, ctx: &Ctx) -> Result<Info> {
        crate::ext::fetch_json(
            &*self.host,
            &Req::get(self.url(path)),
            INFO_LIMIT,
            "artifactory file info",
            ctx,
        )
        .await
    }

    /// The file at `path`, already encoded, published as `name`.
    ///
    /// Served where the storage API says, or where the repository serves
    /// the path when it says nothing.
    pub(super) fn file(&self, path: &str, name: &str, info: &Info) -> FileRef {
        let url = info
            .download_uri
            .clone()
            .unwrap_or_else(|| self.served(path));
        let mut file = FileRef::new(name, url);

        file.size = info.size.as_deref().and_then(|text| text.parse().ok());
        file.digests = info.digests();

        file
    }
}
