//! Reading a Sonatype Nexus 3 raw repository.
//!
//! A raw repository holds files under a path and asserts nothing else about
//! them. There is no protocol to speak -- no packument, no `maven-metadata`,
//! no simple index -- so unlike every other source in this crate, this one
//! cannot be a plain HTTP client pointed at a repository root. It has to ask
//! the product what is in a directory, and that means the REST API.
//!
//! ```text
//!   GET {base}/service/rest/v1/search/assets?repository={name}&format=raw&group=/{dir}
//! ```
//!
//! Which is why the configured entry names **no `host-path`**, exactly as
//! the enumerator does not: the API lives at the server root, and the
//! repository is an option. A source confined to `repository/raw-hosted`
//! could never reach `/service/rest`.
//!
//! # Why `search/assets` rather than `components`
//!
//! `/v1/components` takes only `repository` and `continuationToken` -- no
//! filter at all -- so answering *what is in this one directory* through it
//! would mean walking the whole catalog per artifact. `/v1/search/assets`
//! takes `group`, and measurement settles the rest:
//!
//! | Filter | Answer |
//! | --- | --- |
//! | `group=/artifact1/1.0` | that directory's assets, exactly |
//! | `group=artifact1/1.0` | nothing -- **the leading `/` is required** |
//! | `group=/artifact1` | nothing -- an exact match, not a prefix |
//! | `group=/artifact1/*` | the sub-groups -- `*` is a glob that crosses `/` |
//!
//! The second row is the one that would silently break: a group built
//! without the leading separator returns an empty page, which reads as
//! "this artifact is not here" rather than as a malformed query.
//!
//! The third row is the happy one. `group` matching exactly, rather than by
//! prefix, is precisely [`Mapping::Directory`]'s rule -- a sub-directory is
//! a different artifact -- so one request answers one artifact.
//!
//! # Every returned asset is checked again
//!
//! `*` being a glob means a real path containing one would be read as a
//! pattern, so what comes back is re-read through the [`Mapping`] and kept
//! only where the coordinate matches what was asked for. That also gives
//! `Mapping::AsIs` and `Mapping::NameVersionFile` their filtering for free,
//! since neither's artifact is a whole `group`.
//!
//! # Versions
//!
//! Under the directory mapping there are none, and [`Source::versioned`]
//! says so -- resolution then skips selection entirely rather than hunting
//! through an empty candidate list. See `docs/contributors/versions.md`.
//!
//! References: [Nexus REST APIs](https://help.sonatype.com/en/rest-apis.html).

use std::sync::Arc;

use super::Source;
use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind, Versions};
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;
use crate::net::{encode_unreserved, normalized_base};

mod api;
mod asset;
mod browse;
mod enumerator;
mod lister;
mod source;
mod target;

pub use enumerator::NexusEnumerator;
pub use source::NexusRawSource;
pub use target::NexusRawTarget;

use api::{REPOSITORY_PATH, SEARCH, file_of, page_cap, paged};

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new("nexus", open_source).versions(Versions::RawMapping)),
    target: Some(TargetKind {
        name: "nexus-raw",
        open: open_target,
    }),
    enumerators: &[EnumeratorKind::new("nexus", open_enumerator)],
};

/// A Nexus repository's source, by the format it holds.
///
/// Raw has no protocol, so its API is the whole source.  Every other
/// format is read through its protocol at `repository/{name}` and told more
/// by the API; see `repo::manager::source`.  Both reach the server root,
/// which is why the entry names no `host-path`.
fn open_source(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    trust: super::Trust,
) -> Result<Arc<dyn Source>> {
    let (repository, ecosystem) = super::manager::config(options, "nexus")?;

    // Refuses a `mapping` outside raw, as the enumerator does.
    super::manager::raw_mapping(options, &ecosystem)?;

    if ecosystem.as_str() == EcosystemId::RAW {
        return Ok(Arc::new(NexusRawSource::open(base_url, options, host)?));
    }

    let path = format!("{REPOSITORY_PATH}/{}", encode_unreserved(&repository));
    let protocol = super::under(base_url, Some(&path))
        .map_err(|detail| Error::Config(format!("nexus repository {repository:?}: {detail}")))?;
    let inner = super::open_source(
        ecosystem.as_str(),
        &protocol,
        options,
        Arc::clone(&host),
        trust,
    )?;
    let lister = lister::NexusLister::new(
        normalized_base(base_url),
        host,
        repository,
        ecosystem,
        page_cap(options)?,
    );

    Ok(Arc::new(super::manager::ManagedSource::new(inner, lister)))
}

/// The raw repository `options` names, as a target.
fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::Target>> {
    Ok(Arc::new(NexusRawTarget::open(base_url, options, host)?))
}

/// Walking the repository `options` names.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(NexusEnumerator::open(base_url, options, host)?))
}
