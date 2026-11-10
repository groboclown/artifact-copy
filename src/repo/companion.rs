//! Where a file's companion documents are, as a file advertises them.
//!
//! The default answer to [`Source::companion`](super::Source::companion):
//! PyPI's documents are named on the file itself, by the index that listed
//! it. A source that knows its own URLs -- npm's version document -- answers
//! for itself.

use std::path::{Path, PathBuf};

use crate::ecosystem::Companion;
use crate::model::{FileRef, SigScheme};
use crate::net::Expectation;

/// The suffix PEP 658 puts a file's core-metadata document under.
pub(crate) const CORE_METADATA_SUFFIX: &str = ".metadata";

/// The document of `kind` beside `file`, and what it must match, when the
/// source said one exists.
///
/// ```text
///   CoreMetadata  {url}.metadata, checked against the index's digests
///   Provenance    the URL the index named, unchecked
/// ```
pub(crate) fn advertised(file: &FileRef, kind: Companion) -> Option<(FileRef, Expectation)> {
    match kind {
        Companion::CoreMetadata => {
            let digests = file.core_metadata.as_ref()?;

            let mut document = FileRef::new(
                format!("{}{CORE_METADATA_SUFFIX}", file.name),
                format!("{}{CORE_METADATA_SUFFIX}", file.url),
            );
            document.digests = digests.clone();

            Some((document, Expectation::new().with_digests(digests.clone())))
        }

        // Not advertised on the file: only the source can name it.
        Companion::PackageManifest => None,

        Companion::Provenance => {
            let url = file
                .signatures
                .iter()
                .find(|signature| signature.scheme == SigScheme::PypiAttestation)?
                .url
                .as_ref()?;

            let document = FileRef::new(
                format!("{}{}", file.name, crate::ecosystem::pypi::PROVENANCE_SUFFIX),
                url,
            );

            Some((document, Expectation::new()))
        }
    }
}

/// Documents downloaded beside the payloads, for a target to publish with
/// them.
///
/// Keyed by the payload's file name and the kind of document, so a new
/// [`Companion`] kind needs no new field. A payload without an entry has
/// none of that kind to give, and the target falls back to what it can read
/// itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Companions {
    staged: std::collections::BTreeMap<(String, Companion), PathBuf>,
}

impl Companions {
    /// Record the document at `path` as `file`'s `kind`.
    pub fn insert(&mut self, file: &str, kind: Companion, path: PathBuf) {
        self.staged.insert((file.to_owned(), kind), path);
    }

    /// `file`'s document of `kind`, when one was downloaded.
    pub fn get(&self, file: &str, kind: Companion) -> Option<&Path> {
        self.staged
            .get(&(file.to_owned(), kind))
            .map(PathBuf::as_path)
    }

    /// Only the documents whose kind `keep` accepts, for a target that
    /// takes fewer kinds than were fetched.
    pub(crate) fn only(&self, keep: impl Fn(Companion) -> bool) -> Self {
        let staged = self
            .staged
            .iter()
            .filter(|((_, kind), _)| keep(*kind))
            .map(|(key, path)| (key.clone(), path.clone()))
            .collect();

        Self { staged }
    }
}
