//! Publishing to a PyPI index.
//!
//! One multipart `POST` per distribution, to the upload API twine speaks --
//! the "legacy" form every index that accepts twine accepts:
//!
//! ```text
//!   POST {base}/{upload-path}/
//!     :action=file_upload  protocol_version=1
//!     name  version  metadata_version  filetype  pyversion
//!     md5_digest  sha256_digest
//!     requires_python  summary  classifiers ...   <- the core metadata
//!     content=@{distribution}
//! ```
//!
//! # The metadata is the point
//!
//! An index serves `Requires-Python`, the summary, and the rest back to pip
//! from what the **upload** said, not from the distribution. A wheel
//! uploaded with only its name and version installs, but a pip on the wrong
//! interpreter will pick it. So each upload repeats the origin's core
//! metadata, taken from the first of:
//!
//! 1. The PEP 658 document beside the file on the source, which the caller
//!    fetched and checked -- see [`Question::CoreMetadata`].
//! 2. The distribution's own document: a wheel's `METADATA`, read with the
//!    caps in [`super::wheel`], or an sdist's `PKG-INFO`, with those in
//!    [`super::sdist`].
//! 3. Nothing: the fields a filename gives, and `upload-metadata-incomplete`
//!    to say so. This is where a `.tar.bz2` sdist without a sidecar lands.
//!
//! # Attestations are forwarded, not checked
//!
//! Under `attestations: forward`, the default, a file's PEP 740 provenance
//! object -- fetched by the caller, see [`Companion::Provenance`] -- is
//! flattened into the `attestations` field PyPI's upload API takes. Nexus
//! and Artifact Keeper accept the field and serve nothing back; pypi.org
//! refuses it unless the upload itself comes through Trusted Publishing,
//! which is when `drop` is the setting.
//!
//! # A file is written once
//!
//! PyPI and Nexus refuse a second upload of a filename with 400, and some
//! servers use 409. Either is answered by reading the target's own index:
//! the same sha256 is a file already delivered, a different one is a
//! conflict nothing here may resolve. A 400 for a file the index does not
//! list was not a conflict at all, and the server's refusal stands.
//!
//! References: [PEP 658](https://peps.python.org/pep-0658/), [PEP 740](https://peps.python.org/pep-0740/), [PyPI upload API](https://docs.pypi.org/api/upload/).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use serde::Deserialize;

use super::attestation::PROVENANCE_LIMIT;
use super::core_metadata::{self, Document};
use super::simple::SimpleIndex;
use super::{METADATA_LIMIT, fetch_simple, sdist, version_of, wheel};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::Companion;
use crate::ecosystem::pypi::normalize;
use crate::ecosystem::{Ecosystem, PyPi};
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{ArtifactId, DigestAlg, FileRef, ResolvedArtifact, Version};
use crate::net::{ByteLimit, FormPart, Req, normalized_base};
use crate::repo::{Companions, Delivered, Delivery, Target};

/// The statuses read as "this filename is already uploaded".
///
/// HTTP 400: PyPI and Nexus refusing a filename already uploaded.
/// HTTP 409: the same refusal, as some servers spell it.
const ALREADY_UPLOADED: [StatusCode; 2] = [StatusCode::BAD_REQUEST, StatusCode::CONFLICT];

/// What an upload response may hold. A page of prose, at most.
const RESPONSE_LIMIT: ByteLimit = ByteLimit::kib(64);

/// The option naming where uploads go, relative to the index root.
const UPLOAD_PATH_OPTION: &str = "upload-path";

/// The option deciding what happens to a legacy distribution.
const LEGACY_OPTION: &str = "legacy-dists";

/// The option deciding whether PEP 740 attestations are forwarded.
const ATTESTATIONS_OPTION: &str = "attestations";

/// The upload field PEP 740 attestations travel in.
const ATTESTATIONS_FIELD: &str = "attestations";

/// The metadata version claimed when there is no metadata to read one
/// from: the oldest, which asserts the least.
const MINIMAL_METADATA_VERSION: &str = "1.0";

/// What an sdist's `pyversion` is, per the upload API.
const SOURCE_PYVERSION: &str = "source";

/// What a legacy distribution's `pyversion` is when its filename says
/// nothing more specific.
const ANY_PYVERSION: &str = "any";

/// Extensions an sdist is published under. PEP 625 settles on `.tar.gz`;
/// the rest are what older indexes hold.
const SDIST_EXTENSIONS: [&str; 5] = [".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz"];

/// Files that travel with a distribution and are not one: a PEP 658
/// document, a detached signature.
const COMPANION_EXTENSIONS: [&str; 2] = [".metadata", ".asc"];

/// Core-metadata headers whose upload field is not simply the header in
/// snake case: the ones twine sends under a plural name.
const PLURAL_FIELDS: [(&str, &str); 3] = [
    ("classifier", "classifiers"),
    ("project-url", "project_urls"),
    ("license-file", "license_files"),
];

/// What to do with a distribution the upload API no longer takes.
///
/// `.egg`, `.exe`, `.msi` and their like cannot be uploaded to PyPI any
/// more, and are real on old mirrors -- and on old servers that still
/// accept them. So it is the user's call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyDists {
    /// Refuse the artifact before anything is sent, so a version is never
    /// half-copied. The default: an upload the tool had to guess at is a
    /// decision somebody should make on purpose.
    #[default]
    Error,

    /// Upload the wheels and sdists, and report each file left behind as
    /// `distribution-type-unsupported`.
    Skip,

    /// Upload it under the `filetype` its extension suggests, and let the
    /// server decide.
    Guess,
}

impl LegacyDists {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "error" => Some(LegacyDists::Error),
            "skip" => Some(LegacyDists::Skip),
            "guess" => Some(LegacyDists::Guess),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["error", "skip", "guess"]
    }

    fn from_options(options: &Options) -> Result<Self> {
        let Some(named) = options.string(LEGACY_OPTION)? else {
            return Ok(LegacyDists::default());
        };

        Self::parse(named).ok_or_else(|| {
            Error::Config(format!(
                "{LEGACY_OPTION} is {named:?}, which is not one of: {known}",
                known = Self::names().join(", "),
            ))
        })
    }
}

/// Whether PEP 740 attestations travel with an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Attestations {
    /// Send them. The default: a mirror that keeps them serves the
    /// origin's provenance, and the ones tried ignore what they do not keep.
    #[default]
    Forward,

    /// Send none, and fetch none. For an index that refuses them, such as
    /// pypi.org outside Trusted Publishing.
    Drop,
}

impl Attestations {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "forward" => Some(Attestations::Forward),
            "drop" => Some(Attestations::Drop),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    fn names() -> &'static [&'static str] {
        &["forward", "drop"]
    }

    fn from_options(options: &Options) -> Result<Self> {
        let Some(named) = options.string(ATTESTATIONS_OPTION)? else {
            return Ok(Attestations::default());
        };

        Self::parse(named).ok_or_else(|| {
            Error::Config(format!(
                "{ATTESTATIONS_OPTION} is {named:?}, which is not one of: {known}",
                known = Self::names().join(", "),
            ))
        })
    }
}

/// The parts of a PEP 740 provenance object an upload repeats.
#[derive(Debug, Deserialize)]
struct Provenance {
    attestation_bundles: Vec<AttestationBundle>,
}

/// One publisher's attestations. The publisher itself is the index's
/// business, derived from how the file was uploaded, so it is not sent.
#[derive(Debug, Deserialize)]
struct AttestationBundle {
    attestations: Vec<serde_json::Value>,
}

/// What one file of an artifact is, to the upload API.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Wheel {
        pyversion: String,
    },
    Sdist,

    /// Something the API once took. `filetype` is the guess.
    Legacy {
        filetype: &'static str,
        pyversion: String,
    },

    /// Travels with a distribution and is not uploaded as one.
    Companion,
}

pub struct PyPiTarget {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    upload_url: String,
    ecosystem: PyPi,
    legacy: LegacyDists,
    attestations: Attestations,
}

impl PyPiTarget {
    /// No HTTP client: every request goes through `host`.
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        let base_url = normalized_base(base_url);

        Self {
            upload_url: format!("{base_url}/"),
            base_url,
            host,
            ecosystem: PyPi,
            legacy: LegacyDists::default(),
            attestations: Attestations::default(),
        }
    }

    /// Build from configuration: `upload-path`, `legacy-dists`, and
    /// `attestations`.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let mut target = Self::new(base_url, host);

        target.legacy = LegacyDists::from_options(options)?;
        target.attestations = Attestations::from_options(options)?;

        if let Some(path) = options.string(UPLOAD_PATH_OPTION)? {
            target.upload_url = upload_url(&target.base_url, path)?;
        }

        Ok(target)
    }

    /// Treat legacy distributions this way.
    pub fn with_legacy(mut self, legacy: LegacyDists) -> Self {
        self.legacy = legacy;
        self
    }

    fn simple_url(&self, id: &ArtifactId) -> String {
        format!("{}/simple/{}/", self.base_url, normalize(id.name()))
    }

    /// The target's own index for a project, or `None` when it has none.
    async fn held(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Option<SimpleIndex>> {
        match fetch_simple(&*self.host, &self.simple_url(id), ctx).await {
            Ok(index) => Ok(Some(index)),
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Refuse the whole artifact when a legacy distribution is in it and
    /// the configuration says so, before anything is uploaded.
    fn refuse_legacy(&self, artifact: &ResolvedArtifact, kinds: &[Kind]) -> Result<()> {
        if self.legacy != LegacyDists::Error {
            return Ok(());
        }

        let Some((file, _)) = artifact
            .files
            .iter()
            .zip(kinds)
            .find(|(_, kind)| matches!(kind, Kind::Legacy { .. }))
        else {
            return Ok(());
        };

        Err(Error::BadRequest {
            ecosystem: "pypi",
            text: artifact.purl(),
            detail: format!(
                "{} is not a wheel or an sdist, and {LEGACY_OPTION} is error",
                file.name
            ),
        })
    }

    /// Whether a file is left out: a companion, which travels inside its
    /// distribution's upload, or a legacy distribution the configuration
    /// skips, which is reported.
    fn skips(&self, artifact: &ResolvedArtifact, file: &FileRef, kind: &Kind, ctx: &Ctx) -> bool {
        if *kind == Kind::Companion {
            return true;
        }

        if !matches!(kind, Kind::Legacy { .. }) || self.legacy != LegacyDists::Skip {
            return false;
        }

        ctx.report(
            Code::DistributionTypeUnsupported,
            message!(
                "pypi-legacy-distribution-skipped",
                "{file} of {purl} is not a wheel or an sdist and was not uploaded",
                file = &file.name,
                purl = artifact.purl(),
            ),
        );

        true
    }

    /// Upload one distribution as a form, and read a refusal that says the
    /// file is already there.
    async fn upload_one(
        &self,
        artifact: &ResolvedArtifact,
        version: &Version,
        dist: &Dist<'_>,
        companions: &Companions,
        ctx: &Ctx,
    ) -> Result<Delivered> {
        let document = self.metadata_for(artifact, dist, companions, ctx)?;

        let digests =
            crate::net::files::digests_of(dist.staged, &[DigestAlg::Md5, DigestAlg::Sha256])?;

        let mut text = fields(artifact, version, dist.kind, document.as_ref(), &digests);

        if let Some(attestations) = self.attestations(dist.file, companions)? {
            text.push((ATTESTATIONS_FIELD.to_owned(), attestations));
        }
        let mut form: Vec<FormPart<'_>> = text
            .iter()
            .map(|(name, value)| FormPart::text(name, value))
            .collect();

        form.push(FormPart::file("content", dist.staged).named(&dist.file.name));

        let sha256 = digests
            .iter()
            .find(|(alg, _)| *alg == DigestAlg::Sha256)
            .map(|(_, hex)| hex.clone())
            .unwrap_or_default();

        match self
            .host
            .send_form(
                &Req::post(&self.upload_url, String::new()),
                &form,
                RESPONSE_LIMIT,
                ctx,
            )
            .await
        {
            Ok(_) => Ok(Delivered::Uploaded),

            Err(err @ Error::HttpStatus { status, .. }) if ALREADY_UPLOADED.contains(&status) => {
                self.already_holds(artifact, dist.file, &sha256, err, ctx)
                    .await
            }

            Err(err) => Err(err),
        }
    }

    /// The core metadata to upload a distribution with, reporting when the
    /// filename is all there is.
    fn metadata_for(
        &self,
        artifact: &ResolvedArtifact,
        dist: &Dist<'_>,
        companions: &Companions,
        ctx: &Ctx,
    ) -> Result<Option<Document>> {
        let document = self.document(dist.file, dist.staged, dist.kind, companions)?;

        if document.is_none() {
            ctx.report(
                Code::UploadMetadataIncomplete,
                message!(
                    "pypi-upload-metadata-incomplete",
                    "{file} of {purl} was uploaded with only what its filename says; \
                     the origin's core metadata was not available",
                    file = &dist.file.name,
                    purl = artifact.purl(),
                ),
            );
        }

        Ok(document)
    }

    /// The core metadata to upload a file with, from the best source there
    /// is. `None` means the filename is all there is to go on.
    fn document(
        &self,
        file: &FileRef,
        staged: &Path,
        kind: &Kind,
        companions: &Companions,
    ) -> Result<Option<Document>> {
        if let Some(answered) = companions.get(&file.name, Companion::CoreMetadata) {
            let text = std::fs::read_to_string(answered).map_err(|source| Error::ReadFile {
                path: answered.to_path_buf(),
                source,
            })?;

            return Ok(Some(core_metadata::parse(&text)));
        }

        let text = match kind {
            Kind::Wheel { .. } => Some(wheel::metadata(staged, METADATA_LIMIT)?),
            Kind::Sdist => sdist::metadata(staged, &file.name, METADATA_LIMIT)?,
            Kind::Legacy { .. } | Kind::Companion => None,
        };

        Ok(text.map(|text| core_metadata::parse(&text)))
    }

    /// The `attestations` field for a file, as one JSON array: every
    /// attestation of every bundle in its provenance object. `None` when
    /// they are dropped, or when the file has none.
    fn attestations(&self, file: &FileRef, companions: &Companions) -> Result<Option<String>> {
        if self.attestations == Attestations::Drop {
            return Ok(None);
        }

        let Some(staged) = companions.get(&file.name, Companion::Provenance) else {
            return Ok(None);
        };

        let malformed = |detail: String| Error::Malformed {
            what: "PEP 740 provenance",
            url: staged.display().to_string(),
            detail,
        };

        let size = std::fs::metadata(staged)
            .map_err(|source| Error::ReadFile {
                path: staged.to_path_buf(),
                source,
            })?
            .len();

        if size > PROVENANCE_LIMIT.get() {
            return Err(malformed(format!(
                "it is {size} bytes, more than {}",
                PROVENANCE_LIMIT.get()
            )));
        }

        let bytes = std::fs::read(staged).map_err(|source| Error::ReadFile {
            path: staged.to_path_buf(),
            source,
        })?;

        let provenance: Provenance =
            serde_json::from_slice(&bytes).map_err(|err| malformed(err.to_string()))?;

        let attestations: Vec<serde_json::Value> = provenance
            .attestation_bundles
            .into_iter()
            .flat_map(|bundle| bundle.attestations)
            .collect();

        if attestations.is_empty() {
            return Ok(None);
        }

        serde_json::to_string(&attestations)
            .map(Some)
            .map_err(|err| malformed(err.to_string()))
    }

    /// Answer a refused upload: does the target hold this file already?
    ///
    /// `refused` is the server's own answer, returned unchanged when the
    /// index does not list the file -- then it was not a conflict, and the
    /// refusal is the real cause.
    async fn already_holds(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        sha256: &str,
        refused: Error,
        ctx: &Ctx,
    ) -> Result<Delivered> {
        let Some(index) = self.held(&artifact.id, ctx).await? else {
            return Err(refused);
        };

        let Some(listed) = index.files.iter().find(|held| held.filename == file.name) else {
            return Err(refused);
        };

        match listed.hashes.get(DigestAlg::Sha256.as_str()) {
            Some(held) if held.eq_ignore_ascii_case(sha256) => Ok(Delivered::AlreadyPresent),

            held => Err(Error::Integrity(format!(
                "{} is already uploaded to {} with sha256 {}, and an uploaded file is \
                 not replaced; the file being copied has sha256 {sha256}",
                file.name,
                self.base_url,
                held.map_or("unknown", String::as_str),
            ))),
        }
    }
}

/// `{base}/{path}/`, refusing a path that climbs out of it.
///
/// Always with a trailing `/`: Nexus answers 400 "Repository path must have
/// another '/' after initial '/'" without one, and PyPI's own endpoint is
/// `/legacy/`.
fn upload_url(base: &str, path: &str) -> Result<String> {
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();

    if segments.iter().any(|part| *part == "." || *part == "..") {
        return Err(Error::Config(format!(
            "{UPLOAD_PATH_OPTION} is {path:?}; '.' and '..' segments are refused"
        )));
    }

    match segments.is_empty() {
        true => Ok(format!("{base}/")),
        false => Ok(format!("{base}/{}/", segments.join("/"))),
    }
}

/// One downloaded file, as `publish` uploads it.
struct Dist<'a> {
    file: &'a FileRef,

    /// Where it was downloaded to.
    staged: &'a Path,
    kind: &'a Kind,
}

/// Refuse a mismatch between the files described and those downloaded,
/// which would pair each file with another's name.
fn check_file_count(artifact: &ResolvedArtifact, files: &[PathBuf]) -> Result<()> {
    if files.len() == artifact.files.len() {
        return Ok(());
    }

    Err(Error::BadRequest {
        ecosystem: "pypi",
        text: artifact.purl(),
        detail: format!(
            "{} files were described and {} were downloaded",
            artifact.files.len(),
            files.len()
        ),
    })
}

/// What a file is, from its name.
///
/// A wheel's `pyversion` is its python tag: the third field from the end
/// of `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`.
fn classify(name: &str) -> Kind {
    // A checksum sidecar travels with a file the same way; the listing
    // rule already says which names those are.
    if COMPANION_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
        || !crate::ecosystem::joins_listing(&crate::model::EcosystemId::pypi(), name)
    {
        return Kind::Companion;
    }

    if let Some(stem) = name.strip_suffix(".whl") {
        let fields: Vec<&str> = stem.split('-').collect();

        if fields.len() >= 5 {
            return Kind::Wheel {
                pyversion: fields[fields.len() - 3].to_owned(),
            };
        }
    }

    if SDIST_EXTENSIONS.iter().any(|ext| name.ends_with(ext)) {
        return Kind::Sdist;
    }

    let filetype = match name.rsplit_once('.').map(|(_, ext)| ext) {
        Some("egg") => "bdist_egg",
        Some("exe") => "bdist_wininst",
        Some("msi") => "bdist_msi",
        Some("rpm") => "bdist_rpm",
        Some("dmg") => "bdist_dmg",
        _ => "bdist_dumb",
    };

    // An egg names its interpreter: `pkg-1.0-py3.8.egg`.
    let pyversion = name
        .split('-')
        .find_map(|field| {
            let field = field.split('.').take(2).collect::<Vec<_>>().join(".");

            field.starts_with("py").then_some(field)
        })
        .unwrap_or_else(|| ANY_PYVERSION.to_owned());

    Kind::Legacy {
        filetype,
        pyversion,
    }
}

/// The upload field a core-metadata header travels under.
///
/// `Requires-Python` becomes `requires_python`; the few twine sends in the
/// plural are named in [`PLURAL_FIELDS`].
fn field_name(header: &str) -> String {
    let lower = header.to_ascii_lowercase();

    if let Some((_, plural)) = PLURAL_FIELDS.iter().find(|(name, _)| *name == lower) {
        return (*plural).to_owned();
    }

    lower.replace('-', "_")
}

/// Every text field of one upload, in the order they are sent.
fn fields(
    artifact: &ResolvedArtifact,
    version: &Version,
    kind: &Kind,
    document: Option<&Document>,
    digests: &[(DigestAlg, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![
        (":action".to_owned(), "file_upload".to_owned()),
        ("protocol_version".to_owned(), "1".to_owned()),
    ];

    if let Some(document) = document {
        out.extend(
            document
                .headers
                .iter()
                .map(|(header, value)| (field_name(header), value.clone())),
        );

        if let Some(body) = &document.body
            && document.first("description").is_none()
        {
            out.push(("description".to_owned(), body.clone()));
        }
    }

    let has = |out: &[(String, String)], name: &str| out.iter().any(|(field, _)| field == name);

    // Always present, whatever the document said or did not.
    for (name, fallback) in [
        ("name", artifact.id.name().to_owned()),
        ("version", version.text().to_owned()),
        ("metadata_version", MINIMAL_METADATA_VERSION.to_owned()),
    ] {
        if !has(&out, name) {
            out.push((name.to_owned(), fallback));
        }
    }

    let (filetype, pyversion) = match kind {
        Kind::Wheel { pyversion } => ("bdist_wheel", pyversion.as_str()),
        Kind::Sdist => ("sdist", SOURCE_PYVERSION),
        Kind::Legacy {
            filetype,
            pyversion,
        } => (*filetype, pyversion.as_str()),
        Kind::Companion => ("", ""),
    };

    out.push(("filetype".to_owned(), filetype.to_owned()));
    out.push(("pyversion".to_owned(), pyversion.to_owned()));

    for (alg, hex) in digests {
        out.push((format!("{}_digest", alg.as_str()), hex.clone()));
    }

    out
}

#[async_trait]
impl Target for PyPiTarget {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    /// Provenance is fetched only to be forwarded.
    fn declines(&self, companion: Companion) -> bool {
        companion == Companion::Provenance && self.attestations == Attestations::Drop
    }

    /// Whether the target's index lists this version.
    ///
    /// From PEP 700's `versions` where the index has it, and from the files
    /// where it predates that: an index listing a file of the version holds
    /// it.
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        let version = crate::repo::version_required(id, version)?;

        let Some(index) = self.held(id, ctx).await? else {
            return Ok(false);
        };

        if !index.versions.is_empty() {
            return Ok(index.versions.iter().any(|held| held == version.text()));
        }

        Ok(index
            .files
            .iter()
            .any(|file| version_of(&file.filename) == Some(version.text())))
    }

    /// Upload each distribution, with its core metadata.
    ///
    /// Every file is classified first, so a legacy distribution under
    /// `legacy-dists: error` refuses the artifact before anything is sent.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        let version = crate::repo::version_required(&artifact.id, artifact.version.as_ref())?;

        check_file_count(artifact, files)?;

        let kinds: Vec<Kind> = artifact
            .files
            .iter()
            .map(|file| classify(&file.name))
            .collect();

        self.refuse_legacy(artifact, &kinds)?;

        for ((file, staged), kind) in artifact.files.iter().zip(files).zip(&kinds) {
            if self.skips(artifact, file, kind, ctx) {
                delivery.finish(&file.name, Delivered::Skipped);
                continue;
            }

            delivery.start(&file.name);

            let dist = Dist { file, staged, kind };
            let delivered = self
                .upload_one(artifact, version, &dist, companions, ctx)
                .await?;

            delivery.finish(&file.name, delivered);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::Arc;

    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::ExtHost;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::{Cause, EcosystemId, Release};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://pypi.test/repository/pypi-hosted";
    const UPLOAD: &str = "h://pypi.test/repository/pypi-hosted/";

    const METADATA: &str = "\
Metadata-Version: 2.1
Name: echo
Version: 1.0
Requires-Python: >=3.9
Classifier: A
Classifier: B

Long description.
";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "echo".into() })
    }

    fn artifact(files: &[&str]) -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::pypi(), None, "echo"),
            version: Some(Version::new("1.0", Release::General)),
            files: files
                .iter()
                .map(|name| FileRef::new(*name, format!("h://origin.test/{name}")))
                .collect(),
            license: None,
            published: None,
        }
    }

    fn stage(host: &TestHost, name: &str, bytes: &[u8]) -> PathBuf {
        let staged = host.cache().path(name).expect("path");
        std::fs::write(host.cache().resolve(&staged), bytes).expect("staged");

        host.cache().resolve(&staged)
    }

    fn wheel_bytes(metadata: &str) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));

        writer
            .start_file(
                "echo-1.0.dist-info/METADATA",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("entry");
        writer.write_all(metadata.as_bytes()).expect("written");
        writer.finish().expect("finished");

        buffer
    }

    /// An sdist holding `echo-1.0/PKG-INFO`.
    fn sdist_bytes() -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();

        header.set_size(METADATA.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        builder
            .append_data(&mut header, "echo-1.0/PKG-INFO", METADATA.as_bytes())
            .expect("entry");

        builder
            .into_inner()
            .expect("tar finished")
            .finish()
            .expect("gzip finished")
    }

    fn sha256(bytes: &[u8]) -> String {
        use sha2::Digest as _;

        hex::encode(sha2::Sha256::digest(bytes))
    }

    /// Every form posted, as `(field, text)` pairs.
    fn posted(client: &FixtureClient) -> Vec<Vec<(String, String)>> {
        client
            .posted_to(UPLOAD)
            .into_iter()
            .map(|form| {
                form.into_iter()
                    .map(|(name, bytes)| (name, String::from_utf8_lossy(&bytes).into_owned()))
                    .collect()
            })
            .collect()
    }

    fn value<'f>(form: &'f [(String, String)], name: &str) -> Vec<&'f str> {
        form.iter()
            .filter(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    async fn publish(
        target: &PyPiTarget,
        described: &ResolvedArtifact,
        staged: &[PathBuf],
        companions: &Companions,
        ctx: &Ctx,
    ) -> Result<Delivery> {
        let mut delivery = Delivery::default();

        target
            .publish(described, staged, companions, &mut delivery, ctx)
            .await?;

        Ok(delivery)
    }

    // -- Configuration ----------------------------------------------------

    #[test]
    fn open_reads_options() {
        let target = PyPiTarget::open(
            BASE,
            &options(serde_json::json!({
                "upload-path": "/legacy/",
                "legacy-dists": "skip",
                "attestations": "drop",
            })),
            idle(),
        )
        .expect("opens");

        assert_eq!(target.upload_url, format!("{BASE}/legacy/"));
        assert_eq!(target.legacy, LegacyDists::Skip);
        assert_eq!(target.attestations, Attestations::Drop);
    }

    #[test]
    fn open_defaults_to_root() {
        let target = PyPiTarget::open(BASE, &Options::default(), idle()).expect("opens");

        assert_eq!(target.upload_url, UPLOAD);
        assert_eq!(target.legacy, LegacyDists::Error);
        assert_eq!(target.attestations, Attestations::Forward);
    }

    #[test]
    fn open_refuses_bad_options() {
        assert!(
            PyPiTarget::open(
                BASE,
                &options(serde_json::json!({"upload-path": "../other"})),
                idle()
            )
            .is_err()
        );
        assert!(
            PyPiTarget::open(
                BASE,
                &options(serde_json::json!({"legacy-dists": "maybe"})),
                idle()
            )
            .is_err()
        );
        assert!(
            PyPiTarget::open(
                BASE,
                &options(serde_json::json!({"attestations": "maybe"})),
                idle()
            )
            .is_err()
        );
    }

    // -- Classification -----------------------------------------------------

    #[test]
    fn classify_reads_filenames() {
        assert_eq!(
            classify("echo-1.0-py3-none-any.whl"),
            Kind::Wheel {
                pyversion: "py3".to_owned()
            }
        );
        assert_eq!(
            classify("echo-1.0-1build-cp311-cp311-linux_x86_64.whl"),
            Kind::Wheel {
                pyversion: "cp311".to_owned()
            }
        );
        assert_eq!(classify("echo-1.0.tar.gz"), Kind::Sdist);
        assert_eq!(classify("echo-1.0.zip"), Kind::Sdist);
        assert_eq!(
            classify("echo-1.0-py3.8.egg"),
            Kind::Legacy {
                filetype: "bdist_egg",
                pyversion: "py3.8".to_owned()
            }
        );
        assert_eq!(
            classify("echo-1.0-py3-none-any.whl.metadata"),
            Kind::Companion
        );
        assert_eq!(classify("echo-1.0.tar.gz.sha256"), Kind::Companion);
    }

    #[test]
    fn field_names_follow_twine() {
        assert_eq!(field_name("Requires-Python"), "requires_python");
        assert_eq!(field_name("Classifier"), "classifiers");
        assert_eq!(field_name("Project-URL"), "project_urls");
        assert_eq!(field_name("Requires-Dist"), "requires_dist");
    }

    // -- Existence --------------------------------------------------------

    async fn exists(client: FixtureClient, version: &str) -> bool {
        let host = Arc::new(TestHost::new(client));
        let ctx = ctx();

        PyPiTarget::new(BASE, host.clone())
            .exists(
                &ArtifactId::new(EcosystemId::pypi(), None, "Echo_Lib"),
                Some(&Version::new(version, Release::General)),
                &ctx,
            )
            .await
            .expect("asked")
    }

    /// PEP 700's list decides, under the PEP 503 normalized name.
    #[tokio::test]
    async fn exists_reads_versions() {
        let client = || {
            FixtureClient::new().with_body(
                format!("{BASE}/simple/echo-lib/"),
                r#"{"versions": ["1.0"], "files": []}"#,
            )
        };

        assert!(exists(client(), "1.0").await);
        assert!(!exists(client(), "2.0").await);
    }

    #[tokio::test]
    async fn exists_falls_back_to_files() {
        let client = FixtureClient::new().with_body(
            format!("{BASE}/simple/echo-lib/"),
            r#"{"files": [{"filename": "echo_lib-1.0.tar.gz", "url": "x"}]}"#,
        );

        assert!(exists(client, "1.0").await);
    }

    /// A PEP 503 index, such as Nexus 3, answers HTML to the JSON header.
    #[tokio::test]
    async fn exists_reads_html_index() {
        let client = || {
            FixtureClient::new().with_body(
                format!("{BASE}/simple/echo-lib/"),
                r#"<html><body><a href="../../packages/echo_lib-1.0.tar.gz#sha256=aa">echo_lib-1.0.tar.gz</a></body></html>"#,
            )
        };

        assert!(exists(client(), "1.0").await);
        assert!(!exists(client(), "2.0").await);
    }

    #[tokio::test]
    async fn exists_without_project_is_absent() {
        assert!(!exists(FixtureClient::new(), "1.0").await);
    }

    // -- Publishing -------------------------------------------------------

    /// The fetched PEP 658 document is what the upload repeats.
    #[tokio::test]
    async fn publish_uses_answered_metadata() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();

        let staged = [stage(&host, "echo-1.0-py3-none-any.whl", b"not read")];
        let document = stage(
            &host,
            "echo-1.0-py3-none-any.whl.metadata",
            METADATA.as_bytes(),
        );

        let mut known = Companions::default();
        known.insert(
            "echo-1.0-py3-none-any.whl",
            Companion::CoreMetadata,
            document,
        );

        publish(
            &PyPiTarget::new(BASE, host.clone()),
            &artifact(&["echo-1.0-py3-none-any.whl"]),
            &staged,
            &known,
            &ctx,
        )
        .await
        .expect("published");

        let forms = posted(&client);
        let [form] = forms.as_slice() else {
            panic!("expected one upload, got {}", forms.len());
        };

        assert_eq!(value(form, ":action"), ["file_upload"]);
        assert_eq!(value(form, "requires_python"), [">=3.9"]);
        assert_eq!(value(form, "classifiers"), ["A", "B"]);
        assert_eq!(value(form, "description"), ["Long description."]);
        assert_eq!(value(form, "metadata_version"), ["2.1"]);
        assert_eq!(value(form, "filetype"), ["bdist_wheel"]);
        assert_eq!(value(form, "pyversion"), ["py3"]);
        assert_eq!(value(form, "sha256_digest"), [sha256(b"not read")]);
        assert_eq!(value(form, "content"), ["not read"]);
        assert!(ctx.problems().counts().is_empty());
    }

    /// With no sidecar, a wheel's own `METADATA` is read.
    #[tokio::test]
    async fn publish_reads_wheel_metadata() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let staged = [stage(
            &host,
            "echo-1.0-py3-none-any.whl",
            &wheel_bytes(METADATA),
        )];

        publish(
            &PyPiTarget::new(BASE, host.clone()),
            &artifact(&["echo-1.0-py3-none-any.whl"]),
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
        .expect("published");

        assert_eq!(value(&posted(&client)[0], "requires_python"), [">=3.9"]);
    }

    /// With no sidecar, an sdist's own `PKG-INFO` is read.
    #[tokio::test]
    async fn publish_reads_sdist_metadata() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let staged = [stage(&host, "echo-1.0.tar.gz", &sdist_bytes())];

        publish(
            &PyPiTarget::new(BASE, host.clone()),
            &artifact(&["echo-1.0.tar.gz"]),
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
        .expect("published");

        let form = &posted(&client)[0];

        assert_eq!(value(form, "requires_python"), [">=3.9"]);
        assert_eq!(value(form, "filetype"), ["sdist"]);
        assert!(ctx.problems().counts().is_empty());
    }

    /// An sdist in a form not read, with no sidecar, is uploaded with what
    /// its name says, and the run says so.
    #[tokio::test]
    async fn publish_sdist_minimal_reports() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let staged = [stage(&host, "echo-1.0.tar.bz2", b"sdist")];

        publish(
            &PyPiTarget::new(BASE, host.clone()),
            &artifact(&["echo-1.0.tar.bz2"]),
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
        .expect("published");

        let form = &posted(&client)[0];

        assert_eq!(value(form, "name"), ["echo"]);
        assert_eq!(value(form, "version"), ["1.0"]);
        assert_eq!(value(form, "metadata_version"), ["1.0"]);
        assert_eq!(value(form, "filetype"), ["sdist"]);
        assert_eq!(value(form, "pyversion"), ["source"]);
        assert_eq!(ctx.problems().counts()[&Code::UploadMetadataIncomplete], 1);
    }

    /// A PEP 658 document or signature travels with a file and is not
    /// uploaded as a distribution.
    #[tokio::test]
    async fn publish_skips_companions() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let staged = [
            stage(&host, "echo-1.0.tar.gz", &sdist_bytes()),
            stage(&host, "echo-1.0.tar.gz.asc", b"sig"),
        ];

        let delivery = publish(
            &PyPiTarget::new(BASE, host.clone()),
            &artifact(&["echo-1.0.tar.gz", "echo-1.0.tar.gz.asc"]),
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
        .expect("published");

        assert_eq!(posted(&client).len(), 1);
        assert_eq!(
            delivery.files(),
            [
                ("echo-1.0.tar.gz".to_owned(), Delivered::Uploaded),
                ("echo-1.0.tar.gz.asc".to_owned(), Delivered::Skipped),
            ]
        );
    }

    // -- Attestations -----------------------------------------------------

    /// A provenance object with two bundles of one attestation each.
    const PROVENANCE: &str = r#"{"version": 1, "attestation_bundles": [
        {"publisher": {"kind": "GitHub"}, "attestations": [{"version": 1, "envelope": "a"}]},
        {"publisher": {"kind": "GitLab"}, "attestations": [{"version": 1, "envelope": "b"}]}
    ]}"#;

    /// Publish one sdist with `provenance` staged beside it, returning what
    /// the upload said and how it ended.
    async fn with_provenance(
        attestations: Attestations,
        provenance: &str,
    ) -> (Vec<Vec<(String, String)>>, Result<Delivery>) {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();

        let staged = [stage(&host, "echo-1.0.tar.gz", &sdist_bytes())];
        let document = stage(&host, "echo-1.0.tar.gz.provenance", provenance.as_bytes());

        let mut known = Companions::default();
        known.insert("echo-1.0.tar.gz", Companion::Provenance, document);

        let mut target = PyPiTarget::new(BASE, host.clone());
        target.attestations = attestations;

        let published = publish(
            &target,
            &artifact(&["echo-1.0.tar.gz"]),
            &staged,
            &known,
            &ctx,
        )
        .await;

        (posted(&client), published)
    }

    /// Every bundle's attestations travel as one JSON array.
    #[tokio::test]
    async fn publish_forwards_attestations() {
        let (forms, published) = with_provenance(Attestations::Forward, PROVENANCE).await;

        published.expect("published");

        let sent = value(&forms[0], ATTESTATIONS_FIELD);
        let [sent] = sent.as_slice() else {
            panic!("expected one attestations field, got {sent:?}");
        };

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(sent).expect("json"),
            serde_json::json!([
                {"version": 1, "envelope": "a"},
                {"version": 1, "envelope": "b"}
            ])
        );
    }

    #[tokio::test]
    async fn publish_drops_attestations() {
        let (forms, published) = with_provenance(Attestations::Drop, PROVENANCE).await;

        published.expect("published");

        assert!(value(&forms[0], ATTESTATIONS_FIELD).is_empty());
    }

    /// A provenance object with no attestations sends no field at all.
    #[tokio::test]
    async fn publish_empty_provenance_sends_none() {
        let (forms, published) =
            with_provenance(Attestations::Forward, r#"{"attestation_bundles": []}"#).await;

        published.expect("published");

        assert!(value(&forms[0], ATTESTATIONS_FIELD).is_empty());
    }

    #[tokio::test]
    async fn publish_malformed_provenance_refused() {
        let (forms, published) = with_provenance(Attestations::Forward, "not json").await;

        assert!(
            matches!(published, Err(Error::Malformed { .. })),
            "{published:?}"
        );
        assert!(forms.is_empty());
    }

    /// Under `drop` the provenance is not worth fetching.
    #[test]
    fn declines_provenance_only_when_dropped() {
        let mut target = PyPiTarget::new(BASE, idle());

        assert!(!target.declines(Companion::Provenance));

        target.attestations = Attestations::Drop;

        assert!(target.declines(Companion::Provenance));
        assert!(!target.declines(Companion::CoreMetadata));
    }

    fn with_egg(host: &TestHost) -> (ResolvedArtifact, [PathBuf; 2]) {
        (
            artifact(&["echo-1.0.tar.gz", "echo-1.0-py3.8.egg"]),
            [
                stage(host, "echo-1.0.tar.gz", &sdist_bytes()),
                stage(host, "echo-1.0-py3.8.egg", b"egg"),
            ],
        )
    }

    /// By default a legacy distribution refuses the artifact before any of
    /// it is sent.
    #[tokio::test]
    async fn publish_legacy_error_writes_nothing() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let (described, staged) = with_egg(&host);

        let published = publish(
            &PyPiTarget::new(BASE, host.clone()),
            &described,
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await;

        assert!(matches!(published, Err(Error::BadRequest { .. })));
        assert!(host.requested().is_empty(), "{:?}", host.requested());
    }

    #[tokio::test]
    async fn publish_legacy_skip_reports() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let (described, staged) = with_egg(&host);

        let delivery = publish(
            &PyPiTarget::new(BASE, host.clone()).with_legacy(LegacyDists::Skip),
            &described,
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
        .expect("published");

        assert_eq!(posted(&client).len(), 1);
        assert_eq!(
            delivery.files(),
            [
                ("echo-1.0.tar.gz".to_owned(), Delivered::Uploaded),
                ("echo-1.0-py3.8.egg".to_owned(), Delivered::Skipped),
            ]
        );
        assert_eq!(
            ctx.problems().counts()[&Code::DistributionTypeUnsupported],
            1
        );
    }

    #[tokio::test]
    async fn publish_legacy_guess_uploads() {
        let client = Arc::new(FixtureClient::new().with_body(UPLOAD, "ok"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let ctx = ctx();
        let (described, staged) = with_egg(&host);

        publish(
            &PyPiTarget::new(BASE, host.clone()).with_legacy(LegacyDists::Guess),
            &described,
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
        .expect("published");

        let forms = posted(&client);

        assert_eq!(forms.len(), 2);
        assert_eq!(value(&forms[1], "filetype"), ["bdist_egg"]);
        assert_eq!(value(&forms[1], "pyversion"), ["py3.8"]);
    }

    async fn refused_with(index: Option<String>) -> Result<Delivery> {
        let mut client = FixtureClient::new().with(UPLOAD, Canned::status(StatusCode::BAD_REQUEST));

        if let Some(index) = index {
            client = client.with_body(format!("{BASE}/simple/echo/"), index);
        }

        let host = Arc::new(TestHost::new(client));
        let ctx = ctx();
        let staged = [stage(&host, "echo-1.0.tar.gz", &sdist_bytes())];

        publish(
            &PyPiTarget::new(BASE, host.clone()),
            &artifact(&["echo-1.0.tar.gz"]),
            &staged,
            &Companions::default(),
            &ctx,
        )
        .await
    }

    fn listing(hex: &str) -> String {
        format!(
            r#"{{"versions": ["1.0"], "files": [
                {{"filename": "echo-1.0.tar.gz", "url": "x", "hashes": {{"sha256": "{hex}"}}}}]}}"#
        )
    }

    /// A refused filename holding the same bytes is a file already
    /// delivered.
    #[tokio::test]
    async fn publish_conflict_same_hash_passes() {
        let delivery = refused_with(Some(listing(&sha256(&sdist_bytes()).to_uppercase())))
            .await
            .expect("already there counts as published");

        assert_eq!(
            delivery.files(),
            [("echo-1.0.tar.gz".to_owned(), Delivered::AlreadyPresent)]
        );
    }

    #[tokio::test]
    async fn publish_conflict_different_hash_refused() {
        let refused = refused_with(Some(listing(&sha256(b"theirs")))).await;

        assert!(matches!(refused, Err(Error::Integrity(_))), "{refused:?}");
    }

    /// The HTML form carries the sha256 in the link's fragment.
    #[tokio::test]
    async fn publish_conflict_reads_html_hash() {
        let listing = format!(
            r#"<a href="x/echo-1.0.tar.gz#sha256={}">echo-1.0.tar.gz</a>"#,
            sha256(&sdist_bytes())
        );

        refused_with(Some(listing))
            .await
            .expect("already there counts as published");
    }

    /// A 400 for a file the index does not list was not a conflict, and
    /// the server's own refusal is the answer.
    #[tokio::test]
    async fn publish_refusal_without_listing_stands() {
        let refused = refused_with(None).await;

        assert!(
            matches!(
                refused,
                Err(Error::HttpStatus {
                    status: StatusCode::BAD_REQUEST,
                    ..
                })
            ),
            "{refused:?}"
        );
    }
}
