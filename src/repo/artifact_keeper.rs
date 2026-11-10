//! Writing to an Artifact Keeper generic repository.
//!
//! A generic repository holds files under a path and asserts nothing else
//! about them, which makes it the raw repository of this product. Writing
//! one is therefore **copying files into their paths**: the source already
//! decided what an artifact is, and the only question here is where each
//! of its files lands.
//!
//! ```text
//!   PUT  {base}/api/v1/repositories/{repository}/artifacts/{path}
//!   GET  {base}/api/v1/repositories/{repository}/artifacts?path_prefix=...
//!   GET  {base}/api/v1/repositories/{repository}/artifacts/{path}
//! ```
//!
//! Like the `nexus` source, the configured entry names **no `host-path`**: the API
//! lives at the server root and the repository is an option.
//!
//! # Where a file lands
//!
//! [`Mapping::path`], the inverse of the reading a raw source applies. The
//! path is read back through the mapping before anything is sent, and a
//! path that does not read back as the artifact it came from is refused --
//! a copy that landed a file where the next artifact enumeration files it
//! under another artifact would be a migration that silently rearranged a
//! repository.
//!
//! # Every upload is verified by the server
//!
//! Each file is sent with `x-checksum-sha256` computed from the staged
//! bytes, which the server checks against what it received and refuses
//! with a 400 on a mismatch. The bytes were verified when they were
//! fetched; this is the other half, and it costs no request.
//!
//! # A path is written once
//!
//! Measured against a running 1.9 server: a second `PUT` to a path answers
//! **409 "already exists and is immutable" whether or not the bytes are
//! the same**. So re-sending is not idempotent, and a copy interrupted
//! half-way through a directory would fail on every file it had already
//! sent. A 409 is therefore answered by reading the stored checksum: the
//! same bytes are a file already delivered, and different bytes are a
//! conflict nothing here may resolve by overwriting.
//!
//! References: [Artifact Keeper OpenAPI](https://github.com/artifact-keeper/artifact-keeper-api).

use std::sync::Arc;

use super::Target;
use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind, Versions};
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;
use crate::net::{encode_unreserved, normalized_base};

mod api;
mod cache;
mod cache_source;
mod enumerator;
mod lister;
mod listing;
mod source;
mod target;

pub use enumerator::ArtifactKeeperEnumerator;
pub use target::ArtifactKeeperGenericTarget;

#[cfg(test)]
use api::API;
use api::{
    MAPPING, Mode, PAGE_LIMIT, PER_PAGE, download_url, encode_path, page_cap, prefix_of, prefixed,
    repository_url,
};

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new("artifact-keeper", open_source).versions(Versions::RawMapping)),
    target: Some(TargetKind {
        name: "artifact-keeper-generic",
        open: open_target,
    }),
    enumerators: &[EnumeratorKind::new("artifact-keeper", open_enumerator)],
};

/// An Artifact Keeper repository's source, by the format it holds.
///
/// A generic repository has no protocol, so its listing is the whole
/// source.  Every other format is read through its protocol at
/// `{format}/{name}` and told more by the listing; see
/// `repo::manager::source`.  Both reach the server root, which is why the
/// entry names no `host-path`.
///
/// A proxy repository's listing is its cache catalog (see `cache`):
/// `mode: proxy` lets it decide versions and files beside the protocol,
/// and `mode: proxy-cache` reads it alone.  A raw repository has no
/// protocol, so its source reads the listing whatever the mode.
fn open_source(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    trust: super::Trust,
) -> Result<Arc<dyn super::Source>> {
    let (repository, ecosystem) = super::manager::config(options, "artifact-keeper")?;

    // Refuses a `mapping` outside raw, as the enumerator does.
    super::manager::raw_mapping(options, &ecosystem)?;
    let mode = Mode::read(options, "artifact-keeper source")?;

    if ecosystem.as_str() == EcosystemId::RAW {
        return Ok(Arc::new(source::ArtifactKeeperRawSource::open(
            base_url, options, host,
        )?));
    }

    if mode == Mode::ProxyCache {
        return Ok(Arc::new(cache_source::ArtifactKeeperCacheSource::open(
            base_url, options, host, repository, ecosystem,
        )?));
    }

    // The server's format names are the purl types.
    let path = format!("{ecosystem}/{}", encode_unreserved(&repository));
    let protocol = super::under(base_url, Some(&path)).map_err(|detail| {
        Error::Config(format!(
            "artifact keeper repository {repository:?}: {detail}"
        ))
    })?;
    let inner = super::open_source(
        ecosystem.as_str(),
        &protocol,
        options,
        Arc::clone(&host),
        trust,
    )?;
    let lister = lister::ArtifactKeeperLister::new(
        normalized_base(base_url),
        host,
        repository,
        ecosystem,
        page_cap(options)?,
    )
    .with_mode(mode);

    Ok(Arc::new(super::manager::ManagedSource::new(inner, lister)))
}

/// The generic repository at `base_url` that `options` names, as a target.
fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Target>> {
    Ok(Arc::new(ArtifactKeeperGenericTarget::open(
        base_url, options, host,
    )?))
}

/// Walking the repository `options` names.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(ArtifactKeeperEnumerator::open(
        base_url, options, host,
    )?))
}
