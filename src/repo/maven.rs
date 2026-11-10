//! The Maven repository layout.
//!
//! Not a registry API -- a directory tree served over HTTP, which is why
//! this adapter is the only one that has to know where files *are* rather
//! than asking an endpoint:
//!
//! ```text
//!   {base}/org/apache/commons/commons-lang3/
//!     maven-metadata.xml          <- every published version
//!     3.14.0/
//!       commons-lang3-3.14.0.pom  <- license, dependencies, parent
//!       commons-lang3-3.14.0.jar  <- the payload
//!       commons-lang3-3.14.0.jar.sha1
//!       commons-lang3-3.14.0.jar.asc
//! ```
//!
//! # `maven-metadata.xml` is not part of an artifact
//!
//! It is an **inspection** document: an index of what a repository holds,
//! belonging to the repository rather than to any version in it. It is read
//! here to answer [`Source::versions`] and it never appears in a
//! [`ResolvedArtifact`]'s files.
//!
//! That is not an omission. The file is derived, it is rewritten every time
//! anything is published under the same coordinate, and a target repository
//! generates its own on upload from what it actually holds. Copying a
//! source's copy would overwrite the target's true index with a claim about
//! a *different* repository -- advertising versions the target does not
//! have. Publishing tools treat it as repository-managed state for exactly
//! this reason, and so does this one.
//!
//! # Checksums are not fetched during inspection
//!
//! Maven publishes digests as sidecar files, so learning one costs a
//! request per file per artifact. `inspect` is meant to be cheap over a
//! large catalog, so the sidecars are left to `copy`, which fetches them at
//! the moment it verifies. Files therefore appear here with no declared
//! digest -- unlike npm and PyPI, where digests arrive free in metadata that
//! was being fetched anyway.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

mod effective;
mod enumerator;
mod layout;
mod listing;
pub mod metadata;
pub mod pom;
pub mod sidecar;
mod signatures;
mod source;
mod target;
#[cfg(test)]
mod testing;
mod versions;
pub mod xml;

pub use enumerator::MavenIndexEnumerator;
pub(super) use layout::layout_of;
use source::FetchedPom;
pub use source::MavenSource;
pub use target::{MavenTarget, MetadataMode};

use std::sync::Arc;

use self::layout::{
    POM_PACKAGING, file_name, is_repository_managed, is_safe_segment, payload_shape,
};
use self::listing::FileListing;
use super::enumerate::Enumerator;
use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind};
use super::{Source, Target};
use crate::core::error::Result;
use crate::ecosystem::maven::METADATA_DOCUMENT as METADATA_FILE;
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;
use crate::net::normalized_base;

/// How many documents to keep, for each of the two caches.
///
/// One parent POM is shared by every module of a multi-module build, so
/// caching them turns a Spring Boot walk from thousands of fetches into
/// tens. Bounded, because enumeration walks millions of artifacts.
const DOCUMENT_CACHE: usize = 128;

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new("maven", open_source)),
    target: Some(TargetKind {
        name: "maven",
        open: open_target,
    }),
    enumerators: &[EnumeratorKind::new("maven-html-index", open_enumerator)
        .checked(check_enumerator)
        .native_for(EcosystemId::MAVEN)],
};

/// A Maven source, told the rest of each version's files by the directory
/// index when `file-listing: html-index` asks; see `listing`.
fn open_source(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    trust: super::Trust,
) -> Result<Arc<dyn Source>> {
    let file_listing = FileListing::read(options)?;
    let source: Arc<dyn Source> = Arc::new(
        MavenSource::open(base_url, options, Arc::clone(&host))?
            .with_keys(trust.keys)
            .with_keyservers(trust.keyservers)
            .with_signing(trust.signing),
    );

    match file_listing {
        FileListing::None => Ok(source),

        FileListing::HtmlIndex => {
            let lister = listing::IndexLister::new(normalized_base(base_url), host);

            Ok(Arc::new(super::manager::ManagedSource::new(source, lister)))
        }
    }
}

/// A Maven target.
fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Target>> {
    Ok(Arc::new(MavenTarget::open(base_url, options, host)?))
}

/// An enumerator walking a repository's HTML directory indexes.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Enumerator>> {
    Ok(Arc::new(MavenIndexEnumerator::open(
        base_url, options, host,
    )?))
}

/// Refuse an index enumerator's configuration that could never walk.
fn check_enumerator(base_url: &str, options: &Options) -> Result<()> {
    MavenIndexEnumerator::check(base_url, options).map(|_| ())
}
