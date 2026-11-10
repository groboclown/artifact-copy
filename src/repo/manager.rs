//! What the repository-manager enumerators share; their sources share
//! [`ManagedSource`], in `source`.
//!
//! Nexus and Artifactory are the same *kind* of thing -- a product hosting
//! registries rather than a registry -- and that shows up as two pieces of
//! identical code, both of which follow from that fact rather than from
//! coincidence:
//!
//! - Each is pointed at **one named repository holding one ecosystem**, so
//!   both read the same two options and reject the same omissions.
//! - Each therefore describes itself in terms of whichever ecosystem it was
//!   pointed at, rather than a fixed one, and each records a last-download
//!   time per asset.
//!
//! # What is deliberately *not* here
//!
//! [`Enumerator::walk`](crate::repo::enumerate::Enumerator::walk) -- and this is the important
//! part, because the two `walk` bodies look far more alike than they are.
//! Their **termination rules contradict each other**: Nexus filters after
//! paging, so an empty page is not the end of its catalog and only a
//! missing continuation token is; Artifactory stops on a short page of
//! rows. A shared walk would have to reconcile two incompatible stopping
//! conditions, and getting it wrong truncates a catalog silently, which is
//! the worst failure mode an enumerator has. They stay apart.
//!
//! Nor are the URL builders here. One is a query string against a REST
//! collection and the other is an AQL document posted to a search endpoint;
//! they share only that both start from a base URL.

use crate::core::error::{Error, Result};
use crate::ext::Options;
use crate::model::{EcosystemId, ListingDepth};
use crate::repo::Mapping;
use crate::repo::enumerate::Found;

mod source;

pub(super) use source::{Lister, Listing, ManagedSource};

/// Read the repository name and ecosystem a manager enumerator is pointed at.
///
/// Both are **required**. The ecosystem could in principle be inferred --
/// Nexus reports a format per component and Artifactory attaches indexing
/// properties -- but an enumerator has to describe itself before it walks
/// anything, and a description that could not be produced until after the
/// first page arrived would be no description at all. Auto-detection is a
/// later convenience; declaring it is the first cut.
///
/// `kind` names the enumerator in the error, so a user with several configured
/// learns which entry is wrong rather than only that one is.
pub(super) fn config(options: &Options, kind: &str) -> Result<(String, EcosystemId)> {
    let repository = options
        .require_string(crate::ext::options::REPOSITORY)?
        .to_owned();

    let ecosystem = options.ecosystem()?.ok_or_else(|| {
        Error::Config(format!(
            "{kind} needs an 'ecosystem' option naming what this \
             repository holds"
        ))
    })?;

    // Declaring an ecosystem this build cannot parse is caught here rather
    // than a page into the walk, where it would have already cost a
    // request and would surface as a parse failure instead of a
    // configuration one.
    if crate::ecosystem::open(ecosystem.as_str()).is_err() {
        return Err(Error::UnknownKind {
            collection: "ecosystem for this repository manager",
            kind: ecosystem.to_string(),
        });
    }

    Ok((repository, ecosystem))
}

/// Whether a manager enumerator reports last downloads: it does.
///
/// The claim that separates these two from every other enumerator, since both
/// products record a last-downloaded timestamp per asset and no registry
/// index carries usage data at all.
pub(super) const REPORTS_LAST_DOWNLOAD: bool = true;

/// How far a manager enumerator's listing reaches: every version, with its
/// files, since both products list assets rather than names.
pub(super) const LISTING_DEPTH: ListingDepth = ListingDepth::Files;

/// How a raw repository's paths become coordinates.
const MAPPING: &str = "mapping";

/// Read the `mapping` option, and refuse one where it means nothing.
///
/// Defaulting to [`Mapping::Directory`] is the reading that matches how a
/// raw repository is actually laid out: files in one directory are one
/// artifact's files.
///
/// Refused outside raw rather than ignored. A `mapping` on a Maven enumerator
/// is a mistake somebody made, and a setting that is silently ignored
/// leaves them believing it took effect -- which is the failure that only
/// shows up as a report that looks subtly wrong.
pub(super) fn raw_mapping(options: &Options, ecosystem: &EcosystemId) -> Result<Mapping> {
    let declared = options.string(MAPPING)?;

    if ecosystem.as_str() != EcosystemId::RAW {
        if let Some(mapping) = declared {
            return Err(Error::Config(format!(
                "the {MAPPING:?} option says how a raw repository's paths become \
                 coordinates, and this entry is configured for {ecosystem}; \
                 remove it or set 'ecosystem: raw' ({mapping:?} was given)"
            )));
        }

        return Ok(Mapping::default());
    }

    declared
        .map(Mapping::parse)
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Collapse one page's findings to one per artifact.
///
/// Under the directory mapping several raw components are one artifact --
/// two files in `a/b` are `a/b`'s files -- so a page can name the same
/// artifact repeatedly. Folding keeps first-seen order, so a walk still
/// reports the catalog in the order the server gave it.
///
/// **Within a page only.** Deduplicating across pages would need a set of
/// every artifact seen, which grows with the catalog and is exactly what
/// the memory discipline forbids; a directory's files really do straddle
/// pages -- a captured repository has 42 of 65 components in one group,
/// five pages of one artifact -- and the report database converges the
/// repeats through its upserts.
///
/// Usage folds with the coordinate: downloading any file is using the
/// artifact, so the most recent use wins. The same rule
/// `Component::last_download` already applies across one component's
/// assets, arriving here because the directory mapping makes several
/// components into one artifact.
pub(super) fn fold(found: impl Iterator<Item = Found>) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();

    for one in found {
        // Keyed on the version too: `id` names the package, and an npm
        // page of ten versions of one package is ten artifacts, not one
        // holding ten tarballs.
        match out
            .iter_mut()
            .find(|seen| seen.id == one.id && seen.version == one.version)
        {
            None => out.push(one),

            Some(seen) => {
                seen.last_download = seen.last_download.merged_with(one.last_download);

                // Each component brings its own files, and together they
                // are the directory. First wins on a repeated name, which
                // one page does not produce.
                for file in one.files {
                    if !seen.files.iter().any(|held| held.name == file.name) {
                        seen.files.push(file);
                    }
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::options;

    #[test]
    fn repository_and_ecosystem_required() {
        let (repository, ecosystem) = config(
            &options(serde_json::json!({"repository": "releases", "ecosystem": "maven"})),
            "nexus",
        )
        .expect("opens");

        assert_eq!(repository, "releases");
        assert_eq!(ecosystem, EcosystemId::maven());

        assert!(config(&options(serde_json::json!({"ecosystem": "maven"})), "nexus").is_err());
        assert!(config(&options(serde_json::json!({"repository": "r"})), "nexus").is_err());
    }

    /// A user with both enumerators configured has to learn *which* entry is
    /// missing the option.
    #[test]
    fn error_names_enumerator_missing_option() {
        for kind in ["nexus", "artifactory"] {
            let err = config(&options(serde_json::json!({"repository": "r"})), kind)
                .expect_err("no ecosystem");

            let text = err.to_string();

            assert!(text.contains(kind), "{text}");
            assert!(text.contains("ecosystem"), "{text}");
        }
    }

    /// Caught at open time, not a page into the walk.
    #[test]
    fn ecosystem_unknown_refused() {
        let err = config(
            &options(serde_json::json!({"repository": "r", "ecosystem": "cargo"})),
            "nexus",
        )
        .expect_err("unknown ecosystem");

        assert!(err.to_string().contains("cargo"), "{err}");
    }
}
