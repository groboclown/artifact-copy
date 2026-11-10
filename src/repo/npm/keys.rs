//! What `/-/npm/v1/keys` returns.
//!
//! A separate document from the packument, on a separate endpoint, and an
//! **optional** one: private registries and most proxies publish no keys at
//! all. That is why the source folds both a failed request and an
//! unreadable body into an empty key list rather than an error -- the
//! absence of this document is the normal case everywhere but
//! registry.npmjs.org.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct KeyList {
    #[serde(default)]
    pub(super) keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
pub(super) struct KeyEntry {
    pub(super) keyid: String,
    pub(super) key: String,
}
