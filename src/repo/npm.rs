//! The npm registry.
//!
//! One request answers everything: the full packument carries every version,
//! its license, its publish time, its dependencies, and its `dist` block
//! with the tarball, integrity hash and registry signatures.
//!
//! The abbreviated `application/vnd.npm.install-v1+json` form is smaller but
//! omits `time` and `license`, both of which this tool needs, so it is not
//! used.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::sync::Arc;

use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind};
use super::{Source, Target};
use crate::core::error::Result;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, EcosystemId};

mod enumerator;
mod keys;
mod manifest;
mod packument;
mod publish;
mod source;
mod target;

pub use enumerator::NpmReplicateEnumerator;
pub use source::NpmSource;
pub use target::{DistTags, NpmTarget};

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new("npm", open_source)),
    target: Some(TargetKind {
        name: "npm",
        open: open_target,
    }),
    enumerators: &[
        EnumeratorKind::new("npm-replicate", open_enumerator).native_for(EcosystemId::NPM)
    ],
};

/// The registry at `base_url`. Takes no options.
fn open_source(
    base_url: &str,
    _options: &Options,
    host: Arc<dyn ExtHost>,
    _trust: super::Trust,
) -> Result<Arc<dyn Source>> {
    Ok(Arc::new(NpmSource::new(base_url, host)))
}

/// Publishing to the registry at `base_url`.
fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Target>> {
    Ok(Arc::new(NpmTarget::open(base_url, options, host)?))
}

/// Walking the registry's replication feed.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(NpmReplicateEnumerator::open(
        base_url, options, host,
    )?))
}

/// A package's path under a registry: the name, after its scope.
///
/// A scope's `/` is percent-encoded: npm's own client does it, and while
/// registry.npmjs.org accepts either spelling, some proxies accept only
/// the encoded one.
fn package_path(id: &ArtifactId) -> String {
    match id.namespace() {
        Some(scope) => format!("{scope}%2f{}", id.name()),
        None => id.name().to_owned(),
    }
}

/// The file name npm gives a version's tarball.
fn tarball_name(id: &ArtifactId, version: &str) -> String {
    format!("{}-{version}.tgz", id.name())
}

/// `@scope/name`, as npm spells it.
fn package_name(id: &ArtifactId) -> String {
    match id.namespace() {
        Some(scope) => format!("{scope}/{}", id.name()),
        None => id.name().to_owned(),
    }
}
