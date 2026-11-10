//! What a PEP 691 simple index is.
//!
//! One document per project, listing every file of every version together --
//! which is why the source matches files to a version by filename rather
//! than by structure. There is no per-version grouping here to use.
//!
//! Three PEPs meet in this shape, and each is optional on an index that
//! predates it: PEP 691 is the JSON form itself, PEP 700 added `versions`,
//! PEP 658 added `core-metadata`, and PEP 740 added `provenance`.
//!
//! An index without PEP 691, such as Nexus 3, answers the PEP 503 HTML form
//! instead. [`SimpleIndex::parse`] reads either into the same shape; the
//! HTML carries no size or upload time, and its versions come from the
//! filenames.
//!
//! References: [PEP 503](https://peps.python.org/pep-0503/), [PEP 658](https://peps.python.org/pep-0658/), [PEP 691](https://peps.python.org/pep-0691/), [PEP 700](https://peps.python.org/pep-0700/), [PEP 740](https://peps.python.org/pep-0740/).

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{pep503, version_of};
use crate::model::{Digest, DigestAlg};

/// PEP 714 renamed PEP 658's attribute; an older index still sends the first.
const CORE_METADATA_ATTRIBUTES: [&str; 2] = ["data-core-metadata", "data-dist-info-metadata"];

/// PEP 740's attribute naming a file's provenance object.
const PROVENANCE_ATTRIBUTE: &str = "data-provenance";

#[derive(Debug, Deserialize)]
pub(super) struct SimpleIndex {
    /// PEP 700.  Absent on an index that predates it.
    #[serde(default)]
    pub(super) versions: Vec<String>,

    #[serde(default)]
    pub(super) files: Vec<SimpleFile>,
}

impl SimpleIndex {
    /// A project page in either form: PEP 691 JSON, or PEP 503 HTML.
    pub(super) fn parse(body: &[u8]) -> Result<Self, String> {
        if !pep503::is_html(body) {
            return serde_json::from_slice(body).map_err(|source| source.to_string());
        }

        let files: Vec<SimpleFile> = pep503::links(&String::from_utf8_lossy(body))?
            .into_iter()
            .map(SimpleFile::from_link)
            .collect();

        // A project page lists at least one file, or the server would have
        // answered 404. An HTML page with none is more likely a proxy's
        // error page than an empty project.
        if files.is_empty() {
            return Err("HTML page lists no distribution files".to_owned());
        }

        let mut versions: Vec<String> = Vec::new();

        for version in files.iter().filter_map(|file| version_of(&file.filename)) {
            if !versions.iter().any(|seen| seen == version) {
                versions.push(version.to_owned());
            }
        }

        Ok(Self { versions, files })
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SimpleFile {
    pub(super) filename: String,
    pub(super) url: String,

    #[serde(default)]
    pub(super) hashes: BTreeMap<String, String>,

    #[serde(default)]
    pub(super) size: Option<u64>,

    #[serde(rename = "upload-time", default)]
    pub(super) upload_time: Option<String>,

    /// PEP 658.  `true`, or the hash of the sidecar.
    #[serde(rename = "core-metadata", default)]
    pub(super) core_metadata: CoreMetadata,

    /// PEP 740.  The URL of the file's provenance object, which holds its
    /// attestations; `null` or absent when there is none.
    #[serde(default)]
    pub(super) provenance: Option<String>,
}

impl SimpleFile {
    /// One PEP 503 anchor: the hash rides in the URL fragment,
    /// `echo-1.0.tar.gz#sha256=1f1c`, and is split off it.
    fn from_link(link: pep503::Link) -> Self {
        let (url, fragment) = link.href.split_once('#').unwrap_or((&link.href, ""));
        let mut hashes = BTreeMap::new();

        if let Some((algorithm, hex)) = fragment.split_once('=')
            && !algorithm.is_empty()
            && !hex.is_empty()
        {
            hashes.insert(algorithm.to_owned(), hex.to_owned());
        }

        let core_metadata = CORE_METADATA_ATTRIBUTES
            .iter()
            .find_map(|name| link.attribute(name))
            .map_or(CoreMetadata::Absent, CoreMetadata::from_attribute);

        Self {
            filename: link.text.clone(),
            url: url.to_owned(),
            hashes,
            size: None,
            upload_time: None,
            core_metadata,
            provenance: link.attribute(PROVENANCE_ATTRIBUTE).map(str::to_owned),
        }
    }
}

/// Whether a `.metadata` sidecar exists beside a file.
///
/// The field is `false`, `true`, or a map of hashes, so it needs a shape of
/// its own rather than a `bool`.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub(super) enum CoreMetadata {
    #[default]
    Absent,
    Flag(bool),
    Hashes(BTreeMap<String, String>),
}

impl CoreMetadata {
    /// The HTML spelling: `true`, or `sha256=bb`.
    fn from_attribute(value: &str) -> Self {
        if value.eq_ignore_ascii_case("true") {
            return CoreMetadata::Flag(true);
        }

        match value.split_once('=') {
            Some((algorithm, hex)) => {
                CoreMetadata::Hashes(BTreeMap::from([(algorithm.to_owned(), hex.to_owned())]))
            }
            None => CoreMetadata::Absent,
        }
    }

    pub(super) fn is_present(&self) -> bool {
        match self {
            CoreMetadata::Absent => false,
            CoreMetadata::Flag(present) => *present,
            CoreMetadata::Hashes(hashes) => !hashes.is_empty(),
        }
    }

    /// The sidecar's digests, when one exists: `Some` with none for a bare
    /// `true`, and only the algorithms this build knows for a map -- one it
    /// does not know is dropped rather than guessed at.
    pub(super) fn digests(&self) -> Option<Vec<Digest>> {
        if !self.is_present() {
            return None;
        }

        let CoreMetadata::Hashes(hashes) = self else {
            return Some(Vec::new());
        };

        Some(
            hashes
                .iter()
                .filter_map(|(name, hex)| Some(Digest::new(DigestAlg::parse(name)?, hex.clone())))
                .collect(),
        )
    }
}
