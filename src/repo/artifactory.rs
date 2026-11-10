//! A JFrog Artifactory server: a source, a generic-repository target, and
//! two enumerators over AQL (`enumerator` and `oss`).
//!
//! References: [Artifactory repository management](https://docs.jfrog.com/artifactory/docs/repository-management-overview), [AQL](https://docs.jfrog.com/artifactory/docs/artifactory-query-language).

use std::sync::Arc;

use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;
use crate::net::{encode_unreserved, normalized_base};

mod aql;
mod enumerator;
mod fold;
mod lister;
mod oss;
mod raw;
mod row;
mod storage;
mod target;

pub use enumerator::ArtifactoryEnumerator;
pub use oss::ArtifactoryOssEnumerator;

use aql::{PAGE_LIMIT, PAGE_ROWS, SEARCH, aql_time, login};

use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind, Versions};

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new(KIND, open_source).versions(Versions::RawMapping)),
    target: Some(TargetKind {
        name: "artifactory-generic",
        open: open_target,
    }),
    enumerators: &[
        EnumeratorKind::new(KIND, open_enumerator).login(ArtifactoryEnumerator::login),
        EnumeratorKind::new("artifactory-oss", open_oss_enumerator)
            .login(ArtifactoryOssEnumerator::login),
    ],
};

/// The kind, as configuration names it.
const KIND: &str = "artifactory";

/// An Artifactory repository's source: its protocol at `{repository}`,
/// told more by the storage API; see `repo::manager::source`.  A generic
/// repository has no protocol, so the storage API alone reads it.
///
/// Both live under the server url, which is why the entry names no
/// `host-path`.  No `anonymous` option: the storage API answers an
/// anonymous caller wherever the repository does.
pub(super) fn open_source(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    trust: super::Trust,
) -> Result<Arc<dyn super::Source>> {
    let (repository, ecosystem) = crate::repo::manager::config(options, KIND)?;

    // Refuses a `mapping` outside raw, as the Nexus source does.
    let mapping = crate::repo::manager::raw_mapping(options, &ecosystem)?;

    // A generic repository has no protocol, so the storage API is the
    // whole source.
    if ecosystem.as_str() == EcosystemId::RAW {
        return Ok(Arc::new(raw::ArtifactoryRawSource::new(
            normalized_base(base_url),
            host,
            repository,
            mapping,
        )));
    }

    let protocol =
        super::under(base_url, Some(&encode_unreserved(&repository))).map_err(|detail| {
            Error::Config(format!("artifactory repository {repository:?}: {detail}"))
        })?;
    let inner = super::open_source(
        ecosystem.as_str(),
        &protocol,
        options,
        Arc::clone(&host),
        trust,
    )?;
    let lister =
        lister::ArtifactoryLister::new(normalized_base(base_url), host, repository, ecosystem);

    Ok(Arc::new(crate::repo::manager::ManagedSource::new(
        inner, lister,
    )))
}

/// An Artifactory generic repository's target; see `target`.
pub(super) fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::Target>> {
    Ok(Arc::new(target::ArtifactoryGenericTarget::open(
        base_url, options, host,
    )?))
}

/// Walking the repository `options` names, over AQL.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(ArtifactoryEnumerator::open(
        base_url, options, host,
    )?))
}

/// Walking the repository `options` names, over the OSS edition's AQL.
fn open_oss_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(ArtifactoryOssEnumerator::open(
        base_url, options, host,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{idle, options};

    const BASE: &str = "h://artifactory.test";
    const REPO: &str = "libs-release-local";

    fn source(ecosystem: &str, mapping: Option<&str>) -> Result<Arc<dyn crate::repo::Source>> {
        let mut config = serde_json::json!({"repository": REPO, "ecosystem": ecosystem});

        if let Some(mapping) = mapping {
            config["mapping"] = mapping.into();
        }

        open_source(
            BASE,
            &options(config),
            idle(),
            crate::repo::Trust::untrusting(),
        )
    }

    /// A generic repository opens whatever Artifactory calls its type.
    #[test]
    fn raw_source_opens() {
        let source = source("raw", Some("name-version-file")).expect("opens");

        assert_eq!(source.ecosystems(), [EcosystemId::raw()]);
    }

    /// A mapping on a registry format is a mistake, not a no-op.
    #[test]
    fn mapping_raw_only() {
        assert!(source("maven", Some("directory")).is_err());
        assert!(source("raw", Some("regex")).is_err());
    }
}
