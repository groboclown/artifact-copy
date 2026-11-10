//! Writing to a Maven repository.
//!
//! The same directory tree [`MavenSource`] reads, written one file at a
//! time:
//!
//! ```text
//!   PUT {base}/org/example/lib/1.0/lib-1.0.pom
//!   PUT {base}/org/example/lib/1.0/lib-1.0.pom.sha1      <- per `checksums`
//!   PUT {base}/org/example/lib/1.0/lib-1.0.pom.asc       <- when the source had one
//!   PUT {base}/org/example/lib/1.0/lib-1.0.jar
//!   PUT {base}/org/example/lib/1.0/lib-1.0.jar.sha1
//!   PUT {base}/org/example/lib/maven-metadata.xml        <- `metadata: merge` only
//! ```
//!
//! # File names come from the source
//!
//! A snapshot's files carry its build's timestamp, and the source already
//! resolved which build that is. So every file lands under the name the
//! source gave it, in the directory of the version it belongs to, and the
//! target invents no name of its own.
//!
//! # `maven-metadata.xml` is the target's own, by default
//!
//! Nexus and Artifactory rebuild it on upload, and writing one would
//! overwrite what they computed from what they hold. `metadata: merge` is
//! for a repository that does not: the target's document is read, this
//! version added, and the result written back, under a per-coordinate lock
//! because that is a read-modify-write.
//!
//! # Checksums are computed, not copied
//!
//! Each sidecar is hashed from the staged bytes, which were verified on the
//! way in. A signature gets none: it is already the stronger claim, and a
//! checksum over it would only detect a corruption that failing to verify
//! detects anyway -- the argument [`super::sidecar`] makes for reading.
//!
//! # A written path may be refused
//!
//! A release repository commonly refuses to redeploy: Nexus answers 400,
//! Artifact Keeper 409. A copy interrupted part-way would then fail on
//! every file it had already sent, so a refusal is answered by comparing
//! what the target holds with what is staged. The same bytes are a file
//! already delivered; different bytes are a conflict nothing here may
//! resolve by overwriting.
//!
//! # Or it may not be
//!
//! Artifactory OSS, as admin, overwrites a path with different bytes and
//! answers 201, so the promise above holds only where the server refuses.
//! Under `overwrite-guard: check` the same comparison runs **before** any
//! file is sent: every file of the artifact is compared first, one request
//! each, and different bytes anywhere refuse the artifact with nothing
//! written. A file already holding the same bytes is not written again,
//! nor are its checksums.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;

use super::metadata::{self, Snapshot};
use super::sidecar::{self, SIGNATURE, parse_checksum};
use super::{
    METADATA_FILE, MavenSource, POM_PACKAGING, file_name, is_repository_managed, is_safe_segment,
    pom,
};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::Ecosystem;
use crate::ecosystem::maven::{CLASSIFIER_QUALIFIER, Maven, TYPE_QUALIFIER};
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{ArtifactId, DigestAlg, ResolvedArtifact, Version};
use crate::net::{ByteLimit, Req, normalized_base};
use crate::repo::{Companions, Delivered, Delivery, OverwriteGuard, Target};

/// The statuses read as "this path is already written".
///
/// HTTP 400: Nexus refusing to redeploy a release.
/// HTTP 409: a path already written, as Artifact Keeper answers it.
const ALREADY_WRITTEN: [StatusCode; 2] = [StatusCode::BAD_REQUEST, StatusCode::CONFLICT];

/// A file small enough to compare by its bytes rather than its checksum.
///
/// Covers a sidecar and an armored signature. Anything larger is compared
/// through the target's `.sha1`, rather than downloaded again whole.
const SMALL_FILE: ByteLimit = ByteLimit::kib(64);

/// The option that selects a [`MetadataMode`].
const METADATA_OPTION: &str = "metadata";

/// How many locks guard the metadata read-modify-write. See
/// [`crate::repo::NpmTarget`], which stripes for the same reason.
const PUBLISH_STRIPES: usize = 64;

/// Who keeps `maven-metadata.xml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetadataMode {
    /// The server, which rebuilds it on upload. Nothing is written.
    ///
    /// **The default**, because a repository manager computes its index
    /// from what it holds, and a document written here could only be a
    /// claim about something else.
    #[default]
    Server,

    /// This target: read, add the version, write back.
    ///
    /// For a repository served as plain files, where nothing else would.
    Merge,
}

impl MetadataMode {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "server" => Some(MetadataMode::Server),
            "merge" => Some(MetadataMode::Merge),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["server", "merge"]
    }

    fn from_options(options: &Options) -> Result<Self> {
        let Some(named) = options.string(METADATA_OPTION)? else {
            return Ok(MetadataMode::default());
        };

        Self::parse(named).ok_or_else(|| {
            Error::Config(format!(
                "{METADATA_OPTION} is {named:?}, which is not one of: {known}",
                known = Self::names().join(", "),
            ))
        })
    }
}

/// What the target holds at a path, against the file staged for it.
#[derive(Debug, PartialEq, Eq)]
enum Stored {
    /// Nothing, or nothing it will show to compare.
    Absent,

    Same,

    /// Something else, described for the refusal.
    Different(String),
}

pub struct MavenTarget {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    ecosystem: Maven,

    /// Which checksum sidecars to write beside each file, in order.
    checksums: Vec<DigestAlg>,

    metadata: MetadataMode,
    guard: OverwriteGuard,

    /// Serializes the metadata read-modify-write per coordinate.
    ///
    /// Held only under [`MetadataMode::Merge`]. State held across the read
    /// and the write, which an out-of-process target could not hold; the
    /// redesign in `TODO.md` moves it to the caller.
    publishing: [tokio::sync::Mutex<()>; PUBLISH_STRIPES],
}

impl MavenTarget {
    /// No HTTP client: every request goes through `host`.
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: normalized_base(base_url),
            host,
            ecosystem: Maven,
            checksums: sidecar::DEFAULT_CHECKSUMS.to_vec(),
            metadata: MetadataMode::default(),
            guard: OverwriteGuard::default(),
            publishing: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        }
    }

    /// Build from configuration: `checksums`, spelled as a source spells
    /// it, `metadata`, and `overwrite-guard`.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            checksums: sidecar::checksums_from(options)?,
            metadata: MetadataMode::from_options(options)?,
            guard: OverwriteGuard::from_options(options)?,
            ..Self::new(base_url, host)
        })
    }

    /// Keep `maven-metadata.xml` this way.
    pub fn with_metadata(mut self, metadata: MetadataMode) -> Self {
        self.metadata = metadata;
        self
    }

    /// Write these checksum sidecars instead of the defaults.
    pub fn with_checksums(mut self, checksums: Vec<DigestAlg>) -> Self {
        self.checksums = checksums;
        self
    }

    /// The directory holding every version of one artifact.
    fn artifact_dir(&self, group: &str, artifact: &str) -> String {
        format!(
            "{}/{}/{artifact}",
            self.base_url,
            MavenSource::group_path(group)
        )
    }

    fn version_dir(&self, group: &str, artifact: &str, version: &str) -> String {
        format!("{}/{version}", self.artifact_dir(group, artifact))
    }

    /// The lock covering one coordinate's metadata.
    fn stripe(&self, group: &str, artifact: &str) -> &tokio::sync::Mutex<()> {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (group, artifact).hash(&mut hasher);

        &self.publishing[hasher.finish() as usize % PUBLISH_STRIPES]
    }

    /// Why a file name cannot land in this artifact's directory, if it
    /// cannot.
    ///
    /// Checked for every file before any is written: a primary file failing
    /// it fails the artifact with nothing written, and a secondary one is
    /// reported and skipped; see [`Target::publish`].
    fn name_problem(artifact: &ResolvedArtifact, name: &str) -> Option<&'static str> {
        let prefix = format!("{}-", artifact.id.name());

        if !is_safe_segment(name) {
            return Some("is not a usable path segment");
        }

        if is_repository_managed(name) {
            return Some("belongs to the repository, not to an artifact");
        }

        if !name.starts_with(&prefix) {
            return Some("does not belong to this artifactId");
        }

        None
    }

    /// The target's own snapshot index for one version, or `None` when it
    /// holds none.
    async fn held_snapshot(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
        ctx: &Ctx,
    ) -> Result<Option<Snapshot>> {
        let url = format!(
            "{}/{METADATA_FILE}",
            self.version_dir(group, artifact, version)
        );

        let Some(body) = fetch_if_present(&*self.host, &url, ByteLimit::METADATA, ctx).await?
        else {
            return Ok(None);
        };

        metadata::parse_snapshot(&String::from_utf8_lossy(&body))
            .map(Some)
            .map_err(|detail| Error::Malformed {
                what: METADATA_FILE,
                url,
                detail,
            })
    }

    /// PUT one staged file, treating a refusal to rewrite as a question.
    async fn put(&self, url: &str, staged: &Path, ctx: &Ctx) -> Result<Delivered> {
        let req = Req::put(url).header("content-type", "application/octet-stream");

        match self
            .host
            .send_file(&req, staged, self.host.constraints().max_in_memory(), ctx)
            .await
        {
            Ok(_) => Ok(Delivered::Uploaded),

            Err(err @ Error::HttpStatus { status, .. }) if ALREADY_WRITTEN.contains(&status) => {
                self.already_holds(url, staged, err, ctx).await
            }

            Err(err) => Err(err),
        }
    }

    /// The artifact's own files: its POM, and the payload its packaging
    /// names. Every other file is secondary, as a directory listing adds.
    ///
    /// Named as the source names them ([`super::payload_shape`]), with the
    /// build read off the POM's file name so a timestamped snapshot's
    /// payload matches too. The packaging is the request's type, or the
    /// staged POM's.
    fn primary_files(artifact: &ResolvedArtifact, files: &[PathBuf]) -> Result<BTreeSet<String>> {
        let name = artifact.id.name();
        let prefix = format!("{name}-");
        let suffix = format!(".{POM_PACKAGING}");

        let Some((at, pom)) = artifact
            .files
            .iter()
            .enumerate()
            .find(|(_, file)| file.name.starts_with(&prefix) && file.name.ends_with(&suffix))
        else {
            return Ok(BTreeSet::new());
        };

        let mut primary = BTreeSet::from([pom.name.clone()]);

        let packaging = match artifact.id.qualifier(TYPE_QUALIFIER) {
            Some(packaging) => packaging.to_owned(),

            None => {
                let body = std::fs::read(&files[at]).map_err(|source| Error::ReadFile {
                    path: files[at].clone(),
                    source,
                })?;

                pom::parse(&String::from_utf8_lossy(&body))
                    .ok()
                    .and_then(|parsed| parsed.packaging)
                    .unwrap_or_else(|| pom::DEFAULT_PACKAGING.to_owned())
            }
        };

        if packaging == POM_PACKAGING && artifact.id.qualifier(CLASSIFIER_QUALIFIER).is_none() {
            return Ok(primary);
        }

        let build = &pom.name[prefix.len()..pom.name.len() - suffix.len()];
        let (classifier, extension) = super::payload_shape(&artifact.id, &packaging);

        primary.insert(file_name(name, build, classifier, extension));

        Ok(primary)
    }

    /// Answer a refused PUT: is what the target holds the file staged?
    ///
    /// 400 is both Nexus refusing a rewrite under `ALLOW_ONCE` and a path
    /// its Maven layout will not take, so what is stored decides. Nothing at
    /// the path is the second: `refusal` stands, as the target gave it.
    /// Something there with no checksum to compare is refused in turn rather
    /// than assumed to be a delivery.
    async fn already_holds(
        &self,
        url: &str,
        staged: &Path,
        refusal: Error,
        ctx: &Ctx,
    ) -> Result<Delivered> {
        match self.stored(url, staged, ctx).await? {
            Stored::Same => Ok(Delivered::AlreadyPresent),
            Stored::Different(held) => Err(refused(url, &held)),

            Stored::Absent => match self.host.head(&Req::head(url), ctx).await {
                Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                    Err(refusal)
                }
                _ => Err(refused(url, "a file it will not show to compare")),
            },
        }
    }

    /// Compare what the target holds at `url` with the staged file.
    ///
    /// A small file is compared by its bytes. A large one by the target's
    /// `.sha1`, which a repository manager computes on upload, rather than
    /// downloaded again whole; a large file with no readable `.sha1` reads
    /// as absent. Only a 404 is absence: a target that will not answer has
    /// not said the path is free.
    async fn stored(&self, url: &str, staged: &Path, ctx: &Ctx) -> Result<Stored> {
        let size = std::fs::metadata(staged)
            .map_err(|source| Error::ReadFile {
                path: staged.to_path_buf(),
                source,
            })?
            .len();

        if size <= SMALL_FILE.get() {
            let Some(held) = fetch_if_present(&*self.host, url, SMALL_FILE, ctx).await? else {
                return Ok(Stored::Absent);
            };

            let ours = std::fs::read(staged).map_err(|source| Error::ReadFile {
                path: staged.to_path_buf(),
                source,
            })?;

            return Ok(match held.as_ref() == ours.as_slice() {
                true => Stored::Same,
                false => Stored::Different("different bytes".to_owned()),
            });
        }

        let sidecar = format!("{url}.{}", DigestAlg::Sha1.as_str());

        let Some(held) = fetch_if_present(&*self.host, &sidecar, ByteLimit::SIDECAR, ctx)
            .await?
            .and_then(|bytes| parse_checksum(&bytes))
        else {
            return Ok(Stored::Absent);
        };

        let ours = crate::net::files::digests_of(staged, &[DigestAlg::Sha1])?;

        Ok(match ours.first() {
            Some((_, hex)) if *hex == held => Stored::Same,
            _ => Stored::Different(format!("different bytes (sha1 {held})")),
        })
    }

    /// Which files still need writing, under `overwrite-guard: check`:
    /// every file compared before any is sent, so different bytes anywhere
    /// refuse the artifact with nothing written.
    ///
    /// A file whose name is `unusable` is not asked about: it is skipped.
    async fn unwritten(
        &self,
        dir: &str,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        unusable: &[Option<&str>],
        ctx: &Ctx,
    ) -> Result<Vec<bool>> {
        let mut pending = Vec::with_capacity(files.len());

        for ((file, staged), problem) in artifact.files.iter().zip(files).zip(unusable) {
            if problem.is_some() {
                pending.push(false);
                continue;
            }

            let url = format!("{dir}/{}", file.name);

            match self.stored(&url, staged, ctx).await? {
                Stored::Absent => pending.push(true),
                Stored::Same => pending.push(false),
                Stored::Different(held) => return Err(refused(&url, &held)),
            }
        }

        Ok(pending)
    }

    /// Write each configured checksum of a file beside it.
    async fn put_checksums(&self, url: &str, staged: &Path, ctx: &Ctx) -> Result<()> {
        let computed = crate::net::files::digests_of(staged, &self.checksums)?;

        for (alg, hex) in computed {
            let sidecar = crate::net::files::temporary_with(hex.as_bytes())?;

            self.put(&format!("{url}.{}", alg.as_str()), sidecar.path(), ctx)
                .await?;
        }

        Ok(())
    }

    /// Write one metadata document and its checksums.
    ///
    /// A plain PUT: a document is rewritten by design, so a refusal here is
    /// a real failure rather than a delivery to confirm.
    async fn put_document(&self, dir: &str, document: &str, ctx: &Ctx) -> Result<()> {
        let staged = crate::net::files::temporary_with(document.as_bytes())?;
        let url = format!("{dir}/{METADATA_FILE}");
        let req = Req::put(&url).header("content-type", "application/xml");

        self.host
            .send_file(
                &req,
                staged.path(),
                self.host.constraints().max_in_memory(),
                ctx,
            )
            .await?;

        for (alg, hex) in crate::net::files::digests_of(staged.path(), &self.checksums)? {
            let sidecar = crate::net::files::temporary_with(hex.as_bytes())?;

            self.host
                .send_file(
                    &Req::put(format!("{url}.{}", alg.as_str())),
                    sidecar.path(),
                    self.host.constraints().max_in_memory(),
                    ctx,
                )
                .await?;
        }

        Ok(())
    }

    /// Add this version to the target's own index, and for a snapshot
    /// write its build's index too.
    async fn merge_metadata(
        &self,
        artifact: &ResolvedArtifact,
        group: &str,
        version: &Version,
        ctx: &Ctx,
    ) -> Result<()> {
        let artifact_id = artifact.id.name();
        let text = version.text();
        let now = Utc::now();

        // Held across the read and the write: a version merged in between
        // would be lost when this one writes back.
        let _publishing = self.stripe(group, artifact_id).lock().await;

        if metadata::is_snapshot(text) {
            let names: Vec<&str> = artifact
                .files
                .iter()
                .map(|file| file.name.as_str())
                .filter(|name| !is_signature(name))
                .collect();

            if let Some(document) = metadata::render_snapshot(group, artifact_id, text, &names, now)
            {
                self.put_document(&self.version_dir(group, artifact_id, text), &document, ctx)
                    .await?;
            }
        }

        let dir = self.artifact_dir(group, artifact_id);
        let url = format!("{dir}/{METADATA_FILE}");
        let existing = fetch_if_present(&*self.host, &url, ByteLimit::METADATA, ctx).await?;
        let existing = existing.as_ref().map(|body| String::from_utf8_lossy(body));

        let document = metadata::merge_versions(existing.as_deref(), group, artifact_id, text, now)
            .map_err(|detail| Error::Malformed {
                what: METADATA_FILE,
                url: url.clone(),
                detail,
            })?;

        self.put_document(&dir, &document, ctx).await
    }

    /// Each file's name problem, when it has one.
    ///
    /// Names the target cannot take. A primary one fails the artifact
    /// before anything is written; a secondary one is skipped, and never
    /// asked about.
    fn unusable_names(
        artifact: &ResolvedArtifact,
        primary: &BTreeSet<String>,
    ) -> Result<Vec<Option<&'static str>>> {
        let mut unusable = Vec::with_capacity(artifact.files.len());

        for file in &artifact.files {
            let problem = Self::name_problem(artifact, &file.name);

            if let Some(problem) = problem
                && primary.contains(&file.name)
            {
                return Err(Error::BadRequest {
                    ecosystem: "maven",
                    text: artifact.purl(),
                    detail: format!("the file {:?} {problem}", file.name),
                });
            }

            unusable.push(problem);
        }

        Ok(unusable)
    }

    /// Which files still need writing, by the overwrite guard.
    async fn pending_writes(
        &self,
        dir: &str,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        unusable: &[Option<&str>],
        ctx: &Ctx,
    ) -> Result<Vec<bool>> {
        match self.guard {
            OverwriteGuard::Server => Ok(vec![true; files.len()]),
            OverwriteGuard::Check => self.unwritten(dir, artifact, files, unusable, ctx).await,
        }
    }

    /// Put each file the plan still writes, skipping and reporting the
    /// rest.
    async fn put_files(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        plan: &Plan,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        for (((file, staged), write), problem) in artifact
            .files
            .iter()
            .zip(files)
            .zip(&plan.pending)
            .zip(&plan.unusable)
        {
            if let Some(problem) = problem {
                report_secondary(&file.name, None, &format!("its name {problem}"), ctx);
                delivery.finish(&file.name, Delivered::Skipped);

                continue;
            }

            // Already holding these bytes: delivered, checksums and all.
            if !write {
                delivery.finish(&file.name, Delivered::AlreadyPresent);
                continue;
            }

            let url = format!("{}/{}", plan.dir, file.name);

            delivery.start(&file.name);

            let delivered = match self.put(&url, staged, ctx).await {
                Ok(delivered) => delivered,

                Err(err)
                    if err.code() == Code::RequestRejected
                        && !plan.primary.contains(&file.name) =>
                {
                    let why = format!("the target rejected it ({})", err.reason());

                    report_secondary(&file.name, Some(&url), &why, ctx);
                    delivery.finish(&file.name, Delivered::Skipped);

                    continue;
                }

                Err(err) => return Err(err),
            };

            if !is_signature(&file.name) {
                self.put_checksums(&url, staged, ctx).await?;
            }

            delivery.finish(&file.name, delivered);
        }

        Ok(())
    }
}

/// What publishing one artifact does with each of its files, decided
/// before any is sent.
struct Plan {
    /// The version directory the files land in.
    dir: String,

    /// The POM and payload, which fail the artifact rather than being
    /// skipped.
    primary: BTreeSet<String>,

    /// Per file, why its name cannot land, when it cannot.
    unusable: Vec<Option<&'static str>>,

    /// Per file, whether it still needs writing.
    pending: Vec<bool>,
}

/// The artifact's group and version, refusing one that cannot name a
/// path.
fn check_coordinates(artifact: &ResolvedArtifact) -> Result<(&str, &Version)> {
    let version = crate::repo::version_required(&artifact.id, artifact.version.as_ref())?;
    let group = MavenSource::group_of(&artifact.id)?;

    MavenSource::safe(version.text(), "version", &artifact.id)?;

    Ok((group, version))
}

/// Refuse staged files that do not match the described ones one for one.
fn check_file_count(artifact: &ResolvedArtifact, files: &[PathBuf]) -> Result<()> {
    if files.len() == artifact.files.len() {
        return Ok(());
    }

    Err(Error::BadRequest {
        ecosystem: "maven",
        text: artifact.purl(),
        detail: format!(
            "{} files were described and {} were downloaded",
            artifact.files.len(),
            files.len()
        ),
    })
}

/// Whether a file is a detached signature.
fn is_signature(name: &str) -> bool {
    name.ends_with(&format!(".{SIGNATURE}"))
}

/// The refusal for a path already holding something else.
/// Say that the target rejected a secondary file and the rest went on.
/// Say that a secondary file was not published, and why, and that the
/// rest went on. `url` is where it would have gone, when it was tried.
fn report_secondary(name: &str, url: Option<&str>, why: &str, ctx: &Ctx) {
    let mut message = message!(
        "maven-secondary-file-rejected",
        "{file}: not published, because {reason}; the artifact's other files were \
         published",
        file = name,
        reason = why,
    );

    if let Some(url) = url {
        message = message.arg(crate::core::message::URL_ARG, url);
    }

    ctx.report(Code::SecondaryFileRejected, message);
}

fn refused(url: &str, held: &str) -> Error {
    Error::Integrity(format!(
        "{url} is already written and holds {held}; a written path is not replaced"
    ))
}

/// A body, or `None` for a 404. Any other failure is propagated: a target
/// that will not answer has not said the file is absent.
async fn fetch_if_present(
    host: &dyn ExtHost,
    url: &str,
    max: ByteLimit,
    ctx: &Ctx,
) -> Result<Option<bytes::Bytes>> {
    match host.fetch(&Req::get(url), max, ctx).await {
        Ok(body) => Ok(Some(body)),
        Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => Ok(None),
        Err(err) => Err(err),
    }
}

#[async_trait]
impl Target for MavenTarget {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    /// Whether the target holds this version's payload.
    ///
    /// The payload rather than the POM, because classifier artifacts share
    /// one POM: `lib-1.0-sources.jar` is not there because `lib-1.0.pom`
    /// is. The payload's extension follows from the POM's packaging, so the
    /// target's own POM is read first; a type qualifier on the request wins,
    /// as it does in [`MavenSource`]. A packaging is not an extension:
    /// `bundle` publishes a `.jar`; see `ecosystem::maven::published_as`.
    ///
    /// For a snapshot, the target's own index names the build, so a target
    /// holding an **older** build of this snapshot answers yes.
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        let version = crate::repo::version_required(id, version)?;
        let group = MavenSource::group_of(id)?;
        let artifact = id.name();
        let text = version.text();

        MavenSource::safe(text, "version", id)?;

        let build = match metadata::is_snapshot(text) {
            true => match self.held_snapshot(group, artifact, text, ctx).await? {
                Some(build) => build,
                None => return Ok(false),
            },
            false => Snapshot::default(),
        };

        let dir = self.version_dir(group, artifact, text);
        let pom_build = build.value_for(text, None, POM_PACKAGING);
        let pom_url = format!(
            "{dir}/{}",
            file_name(artifact, &pom_build, None, POM_PACKAGING)
        );

        let Some(body) = fetch_if_present(&*self.host, &pom_url, ByteLimit::METADATA, ctx).await?
        else {
            return Ok(false);
        };

        let packaging = match id.qualifier(TYPE_QUALIFIER) {
            Some(packaging) => packaging.to_owned(),

            None => pom::parse(&String::from_utf8_lossy(&body))
                .map_err(|detail| Error::Malformed {
                    what: "maven pom",
                    url: pom_url.clone(),
                    detail,
                })?
                .packaging
                .unwrap_or_else(|| pom::DEFAULT_PACKAGING.to_owned()),
        };

        let asked = id.qualifier(CLASSIFIER_QUALIFIER);

        if packaging == POM_PACKAGING && asked.is_none() {
            return Ok(true);
        }

        let (classifier, extension) = super::payload_shape(id, &packaging);
        let payload_build = build.value_for(text, classifier, extension);
        let payload = format!(
            "{dir}/{}",
            file_name(artifact, &payload_build, classifier, extension)
        );

        match self.host.head(&Req::head(&payload), ctx).await {
            Ok(_) => Ok(true),
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Put each file in its version directory, with its checksums, and
    /// then the index when this target keeps it.
    ///
    /// In the order the source listed them, so a signature follows the
    /// file it signs. A failure part-way leaves the earlier files written,
    /// which a rerun meets as refusals and confirms rather than failing on.
    ///
    /// A secondary file the target rejects -- one a directory listing
    /// added, not the POM or the payload -- is reported as
    /// `secondary-file-rejected` and the rest are still published; see
    /// [`MavenTarget::primary_files`].
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        // Nothing to decide from it: the index is read under the lock, not
        // answered ahead of it.
        let _ = companions;

        let (group, version) = check_coordinates(artifact)?;

        check_file_count(artifact, files)?;

        let dir = self.version_dir(group, artifact.id.name(), version.text());
        let primary = Self::primary_files(artifact, files)?;
        let unusable = Self::unusable_names(artifact, &primary)?;
        let pending = self
            .pending_writes(&dir, artifact, files, &unusable, ctx)
            .await?;

        let plan = Plan {
            dir,
            primary,
            unusable,
            pending,
        };

        self.put_files(artifact, files, &plan, delivery, ctx)
            .await?;

        if self.metadata == MetadataMode::Merge {
            self.merge_metadata(artifact, group, version, ctx).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::ExtHost;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::{Cause, EcosystemId, FileRef, Release};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://mirror.test/maven2";
    const DIR: &str = "h://mirror.test/maven2/org/example/lib";

    const POM: &str = "<project><artifactId>lib</artifactId></project>";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "org.example:lib:1.0".into(),
        })
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    fn artifact(version: &str, files: &[&str]) -> ResolvedArtifact {
        ResolvedArtifact {
            id: id(),
            version: Some(Version::new(version, Release::General)),
            files: files
                .iter()
                .map(|file| FileRef::new(*file, format!("h://origin.test/{file}")))
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

    fn sha1(bytes: &[u8]) -> String {
        use sha1::{Digest as _, Sha1};

        hex::encode(Sha1::digest(bytes))
    }

    /// A client accepting a PUT of each path, and of its default sidecars.
    fn accepting(paths: &[&str]) -> FixtureClient {
        paths.iter().fold(FixtureClient::new(), |client, path| {
            client
                .with_body(format!("{DIR}/{path}"), "")
                .with_body(format!("{DIR}/{path}.sha1"), "")
                .with_body(format!("{DIR}/{path}.md5"), "")
        })
    }

    /// Publish, answering what the target recorded per file.
    async fn publish(
        target: &MavenTarget,
        described: &ResolvedArtifact,
        staged: &[PathBuf],
    ) -> Result<Delivery> {
        let ctx = ctx();
        let mut delivery = Delivery::default();

        target
            .publish(
                described,
                staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await?;

        Ok(delivery)
    }

    #[test]
    fn open_refuses_unknown_metadata_mode() {
        let opened = MavenTarget::open(
            BASE,
            &options(serde_json::json!({"metadata": "always"})),
            idle(),
        );

        assert!(opened.is_err());
    }

    #[test]
    fn open_reads_options() {
        let target = MavenTarget::open(
            BASE,
            &options(serde_json::json!({"metadata": "merge", "checksums": ["sha256"]})),
            idle(),
        )
        .expect("opens");

        assert_eq!(target.metadata, MetadataMode::Merge);
        assert_eq!(target.checksums, [DigestAlg::Sha256]);
        assert_eq!(target.guard, OverwriteGuard::Server);
    }

    #[test]
    fn open_reads_overwrite_guard() {
        let target = MavenTarget::open(
            BASE,
            &options(serde_json::json!({"overwrite-guard": "check"})),
            idle(),
        )
        .expect("opens");

        assert_eq!(target.guard, OverwriteGuard::Check);
        assert!(
            MavenTarget::open(
                BASE,
                &options(serde_json::json!({"overwrite-guard": "maybe"})),
                idle()
            )
            .is_err()
        );
    }

    #[test]
    fn ecosystem_foreign_artifact_refused() {
        let npm = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert!(MavenTarget::new(BASE, idle()).ecosystem(&npm).is_err());
        assert!(MavenTarget::new(BASE, idle()).ecosystem(&id()).is_ok());
    }

    /// Each file lands in its version directory with a checksum per
    /// configured algorithm, computed from the staged bytes.
    #[tokio::test]
    async fn publish_puts_files_and_checksums() {
        let host = Arc::new(TestHost::new(
            accepting(&["1.0/lib-1.0.pom", "1.0/lib-1.0.jar"])
                .with_body(format!("{DIR}/1.0/lib-1.0.pom.asc"), ""),
        ));
        let staged = [
            stage(&host, "lib-1.0.pom", POM.as_bytes()),
            stage(&host, "lib-1.0.pom.asc", b"signature"),
            stage(&host, "lib-1.0.jar", b"payload"),
        ];
        let described = artifact("1.0", &["lib-1.0.pom", "lib-1.0.pom.asc", "lib-1.0.jar"]);

        let delivery = publish(&MavenTarget::new(BASE, host.clone()), &described, &staged)
            .await
            .expect("published");

        assert_eq!(
            delivery.files(),
            [
                ("lib-1.0.pom".to_owned(), Delivered::Uploaded),
                ("lib-1.0.pom.asc".to_owned(), Delivered::Uploaded),
                ("lib-1.0.jar".to_owned(), Delivered::Uploaded),
            ]
        );
        assert_eq!(
            host.sent_to(&format!("{DIR}/1.0/lib-1.0.jar")),
            vec![b"payload".to_vec()]
        );
        assert_eq!(
            host.sent_to(&format!("{DIR}/1.0/lib-1.0.jar.sha1")),
            vec![sha1(b"payload").into_bytes()]
        );
        assert_eq!(
            host.sent_to(&format!("{DIR}/1.0/lib-1.0.pom.asc")),
            vec![b"signature".to_vec()]
        );

        let asked = host.requested();

        // A signature gets no checksum, and the server keeps the index.
        assert!(!asked.iter().any(|url| url.contains(".asc.")), "{asked:?}");
        assert!(
            !asked.iter().any(|url| url.contains(METADATA_FILE)),
            "{asked:?}"
        );
    }

    /// An empty `checksums` list writes the files alone.
    #[tokio::test]
    async fn publish_without_checksums() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(format!("{DIR}/1.0/lib-1.0.pom"), ""),
        ));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];
        let target = MavenTarget::new(BASE, host.clone()).with_checksums(Vec::new());

        publish(&target, &artifact("1.0", &["lib-1.0.pom"]), &staged)
            .await
            .expect("published");

        assert_eq!(host.requested().len(), 1);
    }

    /// A secondary file whose name the target cannot take is skipped and
    /// reported, never sent, and the rest are published.
    #[tokio::test]
    async fn publish_foreign_secondary_name_skipped() {
        let host = Arc::new(TestHost::new(accepting(&["1.0/lib-1.0.pom"])));
        let staged = [
            stage(&host, "lib-1.0.pom", POM.as_bytes()),
            stage(&host, "other-1.0.jar", b"x"),
        ];
        let ctx = ctx();
        let mut delivery = Delivery::default();

        MavenTarget::new(BASE, host.clone())
            .publish(
                &artifact("1.0", &["lib-1.0.pom", "other-1.0.jar"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await
            .expect("the rest published");

        assert_eq!(
            delivery.files(),
            [
                ("lib-1.0.pom".to_owned(), Delivered::Uploaded),
                ("other-1.0.jar".to_owned(), Delivered::Skipped),
            ]
        );
        assert!(
            !host
                .requested()
                .iter()
                .any(|url| url.contains("other-1.0.jar")),
            "{:?}",
            host.requested()
        );
        assert_eq!(ctx.problems().counts()[&Code::SecondaryFileRejected], 1);
    }

    /// Staged files that do not match the described ones are refused
    /// before anything is sent.
    #[tokio::test]
    async fn publish_file_count_mismatch_refused() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];
        let described = artifact("1.0", &["lib-1.0.pom", "lib-1.0.jar"]);

        let err = publish(&MavenTarget::new(BASE, host.clone()), &described, &staged)
            .await
            .expect_err("refused");

        assert!(
            err.to_string()
                .contains("2 files were described and 1 were downloaded"),
            "{err}"
        );
        assert!(host.requested().is_empty(), "{:?}", host.requested());
    }

    /// A primary file whose name cannot land fails the artifact with
    /// nothing written.
    #[tokio::test]
    async fn publish_unusable_primary_name_refused() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];
        let described = artifact("1.0", &["lib-1.0/x.pom"]);

        let err = publish(&MavenTarget::new(BASE, host.clone()), &described, &staged)
            .await
            .expect_err("refused");

        assert!(
            err.to_string().contains("is not a usable path segment"),
            "{err}"
        );
        assert!(host.requested().is_empty(), "{:?}", host.requested());
    }

    /// The index is the repository's, even under a name the source sent:
    /// skipped and reported, never written.
    #[tokio::test]
    async fn publish_repository_file_skipped() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));
        let staged = [stage(&host, "maven-metadata.xml", b"<metadata/>")];
        let ctx = ctx();
        let mut delivery = Delivery::default();

        MavenTarget::new(BASE, host.clone())
            .publish(
                &artifact("1.0", &["maven-metadata.xml"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await
            .expect("nothing else to publish");

        assert!(host.requested().is_empty(), "{:?}", host.requested());
        assert_eq!(ctx.problems().counts()[&Code::SecondaryFileRejected], 1);
    }

    /// A refused rewrite of the same bytes is a file already delivered.
    #[tokio::test]
    async fn publish_conflict_same_bytes_passes() {
        let pom = format!("{DIR}/1.0/lib-1.0.pom");
        let host = Arc::new(TestHost::new(
            accepting(&["1.0/lib-1.0.pom"]).with_sequence(
                &pom,
                vec![Canned::status(StatusCode::BAD_REQUEST), Canned::ok(POM)],
            ),
        ));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];

        let delivery = publish(
            &MavenTarget::new(BASE, host.clone()),
            &artifact("1.0", &["lib-1.0.pom"]),
            &staged,
        )
        .await
        .expect("already there counts as published");

        assert_eq!(
            delivery.files(),
            [("lib-1.0.pom".to_owned(), Delivered::AlreadyPresent)]
        );
    }

    #[tokio::test]
    async fn publish_conflict_different_bytes_refused() {
        let pom = format!("{DIR}/1.0/lib-1.0.pom");
        let host = Arc::new(TestHost::new(FixtureClient::new().with_sequence(
            &pom,
            vec![Canned::status(StatusCode::CONFLICT), Canned::ok("theirs")],
        )));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];

        let published = publish(
            &MavenTarget::new(BASE, host.clone()),
            &artifact("1.0", &["lib-1.0.pom"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::Integrity(_))),
            "{published:?}"
        );
    }

    /// A large file is compared through the target's `.sha1` rather than
    /// downloaded again.
    #[tokio::test]
    async fn publish_conflict_large_file_uses_sha1() {
        let payload = vec![7u8; SMALL_FILE.get() as usize + 1];
        let jar = format!("{DIR}/1.0/lib-1.0.jar");
        let host = Arc::new(TestHost::new(
            accepting(&["1.0/lib-1.0.jar"])
                .with_sequence(&jar, vec![Canned::status(StatusCode::CONFLICT)])
                .with_body(
                    format!("{jar}.sha1"),
                    format!("{}  lib-1.0.jar\n", sha1(&payload)),
                ),
        ));
        let staged = [stage(&host, "lib-1.0.jar", &payload)];

        publish(
            &MavenTarget::new(BASE, host.clone()),
            &artifact("1.0", &["lib-1.0.jar"]),
            &staged,
        )
        .await
        .expect("confirmed by checksum");

        // The one request to the jar was the refused PUT.
        assert_eq!(host.hits(&jar), 1);
    }

    // -- overwrite-guard: check ----------------------------------------------

    fn guarded(host: Arc<TestHost>) -> MavenTarget {
        let mut target = MavenTarget::new(BASE, host);
        target.guard = OverwriteGuard::Check;

        target
    }

    /// A path answering 404 to the check, then accepting the PUT.
    fn free(client: FixtureClient, url: &str) -> FixtureClient {
        client.with_sequence(
            url,
            vec![Canned::status(StatusCode::NOT_FOUND), Canned::ok("")],
        )
    }

    /// Nothing stored: the check costs one request, and the file and its
    /// checksums are written as they would be without it.
    #[tokio::test]
    async fn guard_writes_absent_file() {
        let pom = format!("{DIR}/1.0/lib-1.0.pom");
        let client = Arc::new(
            free(FixtureClient::new(), &pom)
                .with_body(format!("{pom}.sha1"), "")
                .with_body(format!("{pom}.md5"), ""),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];

        publish(
            &guarded(host.clone()),
            &artifact("1.0", &["lib-1.0.pom"]),
            &staged,
        )
        .await
        .expect("published");

        assert_eq!(client.hits(&pom), 2);
        assert_eq!(client.sent_to(&pom), [POM.as_bytes().to_vec()]);
        assert_eq!(client.sent_to(&format!("{pom}.sha1")).len(), 1);
    }

    /// The same bytes stored: delivered already, so neither the file nor
    /// its checksums are written.
    #[tokio::test]
    async fn guard_skips_same_bytes() {
        let pom = format!("{DIR}/1.0/lib-1.0.pom");
        let client = Arc::new(FixtureClient::new().with_body(&pom, POM));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];

        let delivery = publish(
            &guarded(host.clone()),
            &artifact("1.0", &["lib-1.0.pom"]),
            &staged,
        )
        .await
        .expect("already delivered");

        assert_eq!(
            delivery.files(),
            [("lib-1.0.pom".to_owned(), Delivered::AlreadyPresent)]
        );
        assert!(client.sent_to(&pom).is_empty());
        assert!(client.sent_to(&format!("{pom}.sha1")).is_empty());
    }

    /// Different bytes under any file refuse the artifact before anything
    /// is written, including the files compared before it.
    #[tokio::test]
    async fn guard_refuses_before_writing() {
        let pom = format!("{DIR}/1.0/lib-1.0.pom");
        let jar = format!("{DIR}/1.0/lib-1.0.jar");
        let client = Arc::new(free(FixtureClient::new(), &pom).with_body(&jar, "theirs"));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [
            stage(&host, "lib-1.0.pom", POM.as_bytes()),
            stage(&host, "lib-1.0.jar", b"ours"),
        ];

        let published = publish(
            &guarded(host.clone()),
            &artifact("1.0", &["lib-1.0.pom", "lib-1.0.jar"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::Integrity(_))),
            "{published:?}"
        );
        assert!(client.sent_to(&pom).is_empty());
        assert!(client.sent_to(&jar).is_empty());
    }

    /// A large file is checked through the target's `.sha1`, not
    /// downloaded; a matching one is not written.
    #[tokio::test]
    async fn guard_large_file_uses_sha1() {
        let payload = vec![7u8; SMALL_FILE.get() as usize + 1];
        let jar = format!("{DIR}/1.0/lib-1.0.jar");
        let client = Arc::new(
            FixtureClient::new()
                .with_body(&jar, "")
                .with_body(format!("{jar}.sha1"), sha1(&payload)),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "lib-1.0.jar", &payload)];

        publish(
            &guarded(host.clone()),
            &artifact("1.0", &["lib-1.0.jar"]),
            &staged,
        )
        .await
        .expect("confirmed by checksum");

        assert_eq!(client.hits(&jar), 0);
    }

    /// A failure other than 404 is not read as a free path.
    #[tokio::test]
    async fn guard_propagates_other_failures() {
        let pom = format!("{DIR}/1.0/lib-1.0.pom");
        let client =
            Arc::new(FixtureClient::new().with(&pom, Canned::status(StatusCode::FORBIDDEN)));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];

        let published = publish(
            &guarded(host.clone()),
            &artifact("1.0", &["lib-1.0.pom"]),
            &staged,
        )
        .await;

        assert!(
            matches!(
                published,
                Err(Error::HttpStatus {
                    status: StatusCode::FORBIDDEN,
                    ..
                })
            ),
            "{published:?}"
        );
        assert!(client.sent_to(&pom).is_empty());
    }

    /// Any other failure is propagated, not read as success.
    #[tokio::test]
    async fn publish_forbidden_fails() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with(
            format!("{DIR}/1.0/lib-1.0.pom"),
            Canned::status(StatusCode::FORBIDDEN),
        )));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];

        let published = publish(
            &MavenTarget::new(BASE, host.clone()),
            &artifact("1.0", &["lib-1.0.pom"]),
            &staged,
        )
        .await;

        assert!(matches!(
            published,
            Err(Error::HttpStatus {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
    }

    /// A secondary file the target rejects, with nothing stored at its
    /// path, is reported as `secondary-file-rejected`; the POM and the
    /// payload are still published.
    #[tokio::test]
    async fn publish_rejected_secondary_file_reported() {
        // Named as Central's `groovy/2.4.0` holds `groovy-all-2.4.0-groovydoc.jar`.
        let extra = "lib-all-1.0-doc.jar";
        let host = Arc::new(TestHost::new(
            accepting(&["1.0/lib-1.0.pom", "1.0/lib-1.0.jar"])
                .with_sequence(
                    format!("{DIR}/1.0/{extra}"),
                    vec![
                        Canned::status(StatusCode::BAD_REQUEST),
                        Canned::status(StatusCode::NOT_FOUND),
                    ],
                )
                .with(
                    format!("{DIR}/1.0/{extra}.sha1"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        ));
        let payload = vec![7u8; SMALL_FILE.get() as usize + 1];
        let staged = [
            stage(&host, "lib-1.0.pom", POM.as_bytes()),
            stage(&host, "lib-1.0.jar", b"jar"),
            stage(&host, extra, &payload),
        ];
        let ctx = ctx();
        let mut delivery = Delivery::default();

        MavenTarget::new(BASE, host.clone())
            .publish(
                &artifact("1.0", &["lib-1.0.pom", "lib-1.0.jar", extra]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await
            .expect("the rest published");

        assert_eq!(
            delivery.files(),
            [
                ("lib-1.0.pom".to_owned(), Delivered::Uploaded),
                ("lib-1.0.jar".to_owned(), Delivered::Uploaded),
                (extra.to_owned(), Delivered::Skipped),
            ]
        );
        assert_eq!(ctx.problems().counts()[&Code::SecondaryFileRejected], 1);
        assert!(ctx.problems().worst().expect("reported").is_failure());
    }

    /// A rejected payload with nothing stored fails the artifact with the
    /// target's own answer, not as a file it will not show.
    #[tokio::test]
    async fn publish_rejected_payload_reports_refusal() {
        let host = Arc::new(TestHost::new(
            accepting(&["1.0/lib-1.0.pom"])
                .with_sequence(
                    format!("{DIR}/1.0/lib-1.0.jar"),
                    vec![
                        Canned::status(StatusCode::BAD_REQUEST),
                        Canned::status(StatusCode::NOT_FOUND),
                    ],
                )
                .with(
                    format!("{DIR}/1.0/lib-1.0.jar.sha1"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        ));
        let payload = vec![7u8; SMALL_FILE.get() as usize + 1];
        let staged = [
            stage(&host, "lib-1.0.pom", POM.as_bytes()),
            stage(&host, "lib-1.0.jar", &payload),
        ];

        let published = publish(
            &MavenTarget::new(BASE, host.clone()),
            &artifact("1.0", &["lib-1.0.pom", "lib-1.0.jar"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::HttpStatus { status, .. }) if status == StatusCode::BAD_REQUEST),
            "{published:?}"
        );
    }

    /// Under `merge` the target's index gains the version.
    #[tokio::test]
    async fn publish_merge_writes_index() {
        let index = format!("{DIR}/{METADATA_FILE}");
        let held = "<metadata><versioning><versions><version>0.9</version>\
                    </versions></versioning></metadata>";
        let host = Arc::new(TestHost::new(
            accepting(&["1.0/lib-1.0.pom", METADATA_FILE])
                .with_sequence(&index, vec![Canned::ok(held), Canned::ok("")]),
        ));
        let staged = [stage(&host, "lib-1.0.pom", POM.as_bytes())];
        let target = MavenTarget::new(BASE, host.clone()).with_metadata(MetadataMode::Merge);

        publish(&target, &artifact("1.0", &["lib-1.0.pom"]), &staged)
            .await
            .expect("published");

        let written = host.sent_to(&index);
        let [document] = written.as_slice() else {
            panic!("expected one index, got {}", written.len());
        };
        let document = String::from_utf8_lossy(document);

        assert!(document.contains("<version>0.9</version>"), "{document}");
        assert!(document.contains("<version>1.0</version>"), "{document}");
        assert_eq!(host.sent_to(&format!("{index}.sha1")).len(), 1);
    }

    /// A snapshot also gets its build's index, derived from its files.
    #[tokio::test]
    async fn publish_merge_writes_snapshot_index() {
        let pom = "2.0-SNAPSHOT/lib-2.0-20240101.123456-3.pom";
        let build_index = format!("{DIR}/2.0-SNAPSHOT/{METADATA_FILE}");
        let host = Arc::new(TestHost::new(
            accepting(&[pom, METADATA_FILE, &format!("2.0-SNAPSHOT/{METADATA_FILE}")])
                .with_sequence(
                    format!("{DIR}/{METADATA_FILE}"),
                    vec![Canned::status(StatusCode::NOT_FOUND), Canned::ok("")],
                ),
        ));
        let staged = [stage(
            &host,
            "lib-2.0-20240101.123456-3.pom",
            POM.as_bytes(),
        )];
        let target = MavenTarget::new(BASE, host.clone()).with_metadata(MetadataMode::Merge);

        publish(
            &target,
            &artifact("2.0-SNAPSHOT", &["lib-2.0-20240101.123456-3.pom"]),
            &staged,
        )
        .await
        .expect("published");

        let written = host.sent_to(&build_index);
        let document = String::from_utf8_lossy(&written[0]);

        assert!(
            document.contains("<value>2.0-20240101.123456-3</value>"),
            "{document}"
        );
    }

    async fn exists(target_id: &ArtifactId, version: &str, client: FixtureClient) -> bool {
        let host = Arc::new(TestHost::new(client));
        let ctx = ctx();

        MavenTarget::new(BASE, host.clone())
            .exists(
                target_id,
                Some(&Version::new(version, Release::General)),
                &ctx,
            )
            .await
            .expect("asked")
    }

    /// The payload's extension comes from the target's own POM.
    #[tokio::test]
    async fn exists_reads_packaging() {
        let war = "<project><artifactId>lib</artifactId><packaging>war</packaging></project>";
        let client = || {
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), war)
                .with_body(format!("{DIR}/1.0/lib-1.0.war"), "")
        };

        assert!(exists(&id(), "1.0", client()).await);

        // The POM alone is not the payload.
        let pom_only = FixtureClient::new().with_body(format!("{DIR}/1.0/lib-1.0.pom"), war);
        assert!(!exists(&id(), "1.0", pom_only).await);
    }

    /// A `bundle` project's payload is its `.jar`, not a `.bundle`.
    #[tokio::test]
    async fn exists_bundle_is_jar() {
        let bundle = "<project><artifactId>lib</artifactId><packaging>bundle</packaging></project>";
        let client = FixtureClient::new()
            .with_body(format!("{DIR}/1.0/lib-1.0.pom"), bundle)
            .with_body(format!("{DIR}/1.0/lib-1.0.jar"), "");

        assert!(exists(&id(), "1.0", client).await);
    }

    #[tokio::test]
    async fn exists_defaults_to_jar() {
        let client = FixtureClient::new()
            .with_body(format!("{DIR}/1.0/lib-1.0.pom"), POM)
            .with_body(format!("{DIR}/1.0/lib-1.0.jar"), "");

        assert!(exists(&id(), "1.0", client).await);
    }

    /// A `pom` project is its POM.
    #[tokio::test]
    async fn exists_pom_packaging() {
        let parent = "<project><packaging>pom</packaging></project>";
        let client = FixtureClient::new().with_body(format!("{DIR}/1.0/lib-1.0.pom"), parent);

        assert!(exists(&id(), "1.0", client).await);
    }

    /// Classifier artifacts share a POM, so the classified file decides.
    #[tokio::test]
    async fn exists_asks_classified_file() {
        let sources = id().with_qualifier(CLASSIFIER_QUALIFIER, "sources");
        let client = || FixtureClient::new().with_body(format!("{DIR}/1.0/lib-1.0.pom"), POM);

        assert!(!exists(&sources, "1.0", client()).await);
        assert!(
            exists(
                &sources,
                "1.0",
                client().with_body(format!("{DIR}/1.0/lib-1.0-sources.jar"), "")
            )
            .await
        );
    }

    #[tokio::test]
    async fn exists_without_pom_is_absent() {
        assert!(!exists(&id(), "1.0", FixtureClient::new()).await);
    }

    /// A snapshot is looked up by the build the target's own index names.
    #[tokio::test]
    async fn exists_snapshot_by_held_build() {
        let snapshot_dir = format!("{DIR}/2.0-SNAPSHOT");
        let index = "<metadata><versioning><snapshot><timestamp>20240101.123456</timestamp>\
                     <buildNumber>3</buildNumber></snapshot></versioning></metadata>";
        let client = FixtureClient::new()
            .with_body(format!("{snapshot_dir}/{METADATA_FILE}"), index)
            .with_body(format!("{snapshot_dir}/lib-2.0-20240101.123456-3.pom"), POM)
            .with_body(format!("{snapshot_dir}/lib-2.0-20240101.123456-3.jar"), "");

        assert!(exists(&id(), "2.0-SNAPSHOT", client).await);
        assert!(!exists(&id(), "2.0-SNAPSHOT", FixtureClient::new()).await);
    }

    /// A target that will not answer has not said the version is absent.
    #[tokio::test]
    async fn exists_propagates_failure() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with(
            format!("{DIR}/1.0/lib-1.0.pom"),
            Canned::status(StatusCode::INTERNAL_SERVER_ERROR),
        )));
        let ctx = ctx();

        let asked = MavenTarget::new(BASE, host.clone())
            .exists(&id(), Some(&Version::new("1.0", Release::General)), &ctx)
            .await;

        assert!(asked.is_err());
    }
}
