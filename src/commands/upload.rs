//! Moving one resolved artifact from a source into a target.
//!
//! The half of `copy` that does the work on a single artifact: fetch what
//! the source described, check it is what was claimed, and publish it. What
//! decides *which* artifacts -- a request, a lock file, a dependency walk --
//! is `copy`'s question and not this one's.
//!
//! # The source's cache, handed to the target
//!
//! Each file is downloaded by the **source**, through its own host, into
//! that host's cache. Fetching through the *target's* host instead would
//! need its constraints widened to cover the source's, which is the change
//! that would let one host's credentials reach another.
//!
//! A built-in target is then handed the cached file's path and reads it
//! where it lies: nothing is copied, and the cache keeps the one copy for
//! the next run. An out-of-process target is given its own scratch
//! directory by its gearing, which is where copying belongs.
//!
//! # What is verified, and when
//!
//! The digests the source declared are checked **in flight**, by
//! [`Source::download`], so corrupt bytes never reach the disk whole and
//! never reach the target at all. An artifact the source declared no digest
//! for is fetched anyway and reported as unverified: refusing it would make
//! this unusable against the registries that publish none, and saying
//! nothing would let a silent substitution through.
//!
//! What needs every file at once -- a payload's detached signature -- is
//! checked by [`Source::verify`] after the downloads and before the
//! publish.

use http::StatusCode;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::config::Payloads;
use crate::core::ctx::Ctx;
use crate::core::error::{Contact, Error};
use crate::core::problem::Code;
use crate::ecosystem::Companion;
use crate::ext::Hold;
use crate::message;
use crate::model::ResolvedArtifact;
use crate::net::Expectation;
use crate::repo::{Companions, Delivered, Delivery, Downloaded, Obtained, Source, writable};
use crate::report::{Side, Stage, Verification};
use crate::session::ConfiguredTarget;

/// Whether the staged files passed the checks that need them all at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checked {
    /// Ready for every target to publish.
    Passed,

    /// Fetched, and a check of the staged files refused it before it was
    /// published: a signature whose key may not vouch for it. The refusal
    /// is the context's, see [`Ctx::refusal`].
    Refused,
}

/// One payload, and where its bytes are.
#[derive(Debug, Clone)]
pub struct Payload {
    pub name: String,
    pub url: String,

    /// The cache folder it lives in, named for the host and path it came
    /// from.
    pub host: String,

    pub relative_path: String,
    pub size: Option<u64>,
    pub verification: Verification,

    /// Its times as the cache index holds them, for the report's
    /// `cache_entry`.
    pub kept: Option<crate::ext::Kept>,
}

/// One artifact, fetched and checked once, for every target to publish.
///
/// The source side of a copy: what is about the bytes rather than about a
/// destination. Holds each payload's cache hold, so a size cap cannot
/// remove a payload a target has yet to read; dropping this releases them.
pub struct Fetched {
    pub checked: Checked,

    /// Every payload this fetch put in the cache, or found there.
    ///
    /// Reported rather than recorded here, because `upload` holds no report
    /// and should not: what it does is move one artifact, and who writes
    /// that down is the caller's business.
    pub payloads: Vec<Payload>,

    /// Per file, the weakest verification any of them got.
    ///
    /// The weakest rather than the best, because a report saying an
    /// artifact was verified must mean **all** of it was.
    pub verification: Verification,

    paths: Vec<PathBuf>,
    holds: Vec<Option<Hold>>,

    /// Every companion any target wants; each target is handed its own.
    companions: Companions,
}

impl Fetched {
    /// Drop the published payloads from the cache, for `payloads: discard`.
    ///
    /// Only once the bytes are published everywhere. Until then they are
    /// work in progress, and a failed run should leave the cache holding
    /// what it held.
    ///
    /// Through each payload's hold, so a file another artifact shares and
    /// still needs stays; see `Hold::discard`.
    pub async fn discard(self, payloads: Payloads) {
        if payloads != Payloads::Discard {
            return;
        }

        for (path, hold) in self.paths.iter().zip(self.holds) {
            match hold {
                Some(hold) => hold.discard(path).await,
                None => discard(path),
            }
        }
    }
}

/// Download one artifact from `source`, and check it, for `intos`.
///
/// `source` is the one that described the artifact, so each file is fetched
/// through the host of the repository that listed it.
///
/// `intos` are the targets still to publish it. They choose which
/// companions are worth fetching, and nothing else.
pub async fn fetch(
    artifact: &ResolvedArtifact,
    source: &dyn Source,
    intos: &[&ConfiguredTarget],
    cache_dir: &str,
    recorded: &HashMap<String, crate::report::CacheRecord>,
    ctx: &Ctx,
) -> std::result::Result<Fetched, Failure> {
    refuse_empty(artifact)?;

    let mut paths = Vec::with_capacity(artifact.files.len());
    let mut holds = Vec::with_capacity(artifact.files.len());
    let mut payloads = Vec::with_capacity(artifact.files.len());
    let mut verification = Verification::Verified;

    for file in &artifact.files {
        let (payload, downloaded) = fetch_file(artifact, file, source, ctx).await?;
        let record = recorded.get(&file.name);

        warn_cache_moved(
            artifact,
            &file.name,
            record,
            cache_dir,
            downloaded.obtained,
            ctx,
        );

        verification = weakest(verification, payload.verification);
        payloads.push(payload);

        // Kept until the caller drops the fetch, after the last publish: a
        // size cap must not remove a payload a target has yet to read.
        holds.push(downloaded.hold);
        paths.push(downloaded.path);
    }

    let companions = companions(artifact, source, intos, ctx).await?;
    let checked = verify_all(artifact, source, &paths, &companions, ctx).await?;

    Ok(Fetched {
        checked,
        payloads,
        verification,
        paths,
        holds,
        companions,
    })
}

/// Refuse an artifact with no files before anything is fetched.
///
/// An artifact with no files is a source that answered oddly rather than
/// a package with no content, and publishing nothing under a real version
/// would put an empty release in the target that nobody could tell from a
/// real one.
fn refuse_empty(artifact: &ResolvedArtifact) -> std::result::Result<(), Failure> {
    if !artifact.files.is_empty() {
        return Ok(());
    }

    Err(Failure::from(Error::Malformed {
        what: "artifact files",
        url: artifact.id.purl(),
        detail: "the source described no files to copy".to_owned(),
    }))
}

/// Download one file through `source`, reporting one with no digest to
/// check it against.
async fn fetch_file(
    artifact: &ResolvedArtifact,
    file: &crate::model::FileRef,
    source: &dyn Source,
    ctx: &Ctx,
) -> std::result::Result<(Payload, Downloaded), Failure> {
    let expect = expectation(file);
    let checked = verified_as(file);

    if checked == Verification::NoDigestDeclared {
        ctx.report(
            Code::SignatureMissing,
            message!(
                "upload-unverifiable-file",
                "{purl} file {file} was copied with no digest to check it against",
                purl = artifact.purl(),
                file = &file.name,
            ),
        );
    }

    // Verified in flight: corrupt bytes never land whole and never
    // reach the target.
    let downloaded = source
        .download(file, &expect, ctx)
        .await
        .map_err(|err| Failure::at(Phase::Fetching, err).to(&file.name))?;

    let payload = Payload {
        name: file.name.clone(),
        url: file.url.clone(),
        host: downloaded.host.clone(),
        relative_path: downloaded.relative_path.clone(),
        size: std::fs::metadata(&downloaded.path)
            .ok()
            .map(|found| found.len()),
        verification: checked,
        kept: downloaded.kept,
    };

    Ok((payload, downloaded))
}

/// Warn when the report places a file's bytes where they are not.
///
/// What the report says about this file's bytes, against what was
/// actually on disk. The two disagree when a cache directory has moved or
/// been cleaned out, and that is worth a line: the run carries on, but a
/// migration that quietly re-downloads a repository somebody thought was
/// cached reads as merely slow.
fn warn_cache_moved(
    artifact: &ResolvedArtifact,
    file: &str,
    recorded: Option<&crate::report::CacheRecord>,
    cache_dir: &str,
    obtained: Obtained,
    ctx: &Ctx,
) {
    let Some(recorded) = recorded else {
        return;
    };

    let here = recorded.cache_dir == cache_dir;
    let present = obtained != Obtained::Fetched;

    if here && present {
        return;
    }

    ctx.report(
        Code::CacheFileMissing,
        message!(
            "cache-file-missing",
            "{purl} file {file} is recorded as cached at {at}, and is not there",
            purl = artifact.purl(),
            file = file,
            at = format!("{}/{}", recorded.cache_dir, recorded.relative_path),
        ),
    );
}

/// The checks that need every file at once, such as a payload's `.asc`,
/// given the companions so a check reads what is already staged.
///
/// Each verdict is reported; a signature that does not verify aborts the
/// run by default, and a key that may not vouch refuses the artifact.
/// Either way nothing is published.
async fn verify_all(
    artifact: &ResolvedArtifact,
    source: &dyn Source,
    paths: &[PathBuf],
    companions: &Companions,
    ctx: &Ctx,
) -> std::result::Result<Checked, Failure> {
    source
        .verify(artifact, paths, companions, ctx)
        .await
        .map_err(|err| Failure::at(Phase::Fetching, err))?;

    ctx.check_abort().map_err(Failure::from)?;

    Ok(match ctx.refusal() {
        Some(_) => Checked::Refused,
        None => Checked::Passed,
    })
}

/// Publish a fetched artifact to `into`, and say what it did with each
/// file.
///
/// `into` stays the target itself, because it publishes through a
/// **different** capability -- see this module's documentation.
pub async fn publish(
    artifact: &ResolvedArtifact,
    fetched: &Fetched,
    into: &ConfiguredTarget,
    ctx: &Ctx,
) -> std::result::Result<Vec<(String, Delivered)>, Failure> {
    // Only what this target takes. Another target may have wanted a
    // companion this one declines.
    let wanted = wanted(artifact, into)?;
    let companions = fetched.companions.only(|kind| wanted.contains(&kind));

    let mut delivery = Delivery::default();

    // What reached the target before a failure is kept on the failure, so
    // the report says which files a half-published artifact already has.
    if let Err(err) = into
        .target
        .publish(artifact, &fetched.paths, &companions, &mut delivery, ctx)
        .await
    {
        return Err(Failure::at(Phase::Publishing, err).after(delivery));
    }

    Ok(delivery.files().to_vec())
}

/// The companion kinds `into` takes for `artifact`: those its ecosystem
/// declares, less those it declines.
fn wanted(
    artifact: &ResolvedArtifact,
    into: &ConfiguredTarget,
) -> crate::core::error::Result<BTreeSet<Companion>> {
    let declared = into.target.ecosystem(&artifact.id)?.companions();

    Ok(declared
        .iter()
        .copied()
        .filter(|kind| !into.target.declines(*kind))
        .collect())
}

/// Stage the documents the artifact's ecosystem says travel beside its
/// files.
///
/// Fetched here because a target cannot: its host reaches only its own
/// repository, and the documents are on the source's. Each file whose
/// source said a PEP 658 document exists has it downloaded by the source,
/// checked against the digests the index published for it -- a mismatch
/// fails as `checksum-mismatch`, exactly as a payload would -- and handed
/// to the target by path. A PEP 740 provenance object is fetched the same
/// way, unchecked, since the index publishes no digest for it. A companion
/// every target declines is not fetched at all.
///
/// A 404 leaves that file without one, and the target falls back to what it
/// can read itself. Anything else is a failure: an index that advertised a
/// document and then would not serve it is not saying there is none.
async fn companions(
    artifact: &ResolvedArtifact,
    source: &dyn Source,
    intos: &[&ConfiguredTarget],
    ctx: &Ctx,
) -> std::result::Result<Companions, Failure> {
    let mut staged = Companions::default();

    // The union, so one fetch serves every target that wants a kind.
    let mut kinds = BTreeSet::new();

    for into in intos {
        kinds.extend(wanted(artifact, into)?);
    }

    for kind in kinds {
        for file in &artifact.files {
            let Some((document, expect)) = source.companion(artifact, file, kind) else {
                continue;
            };

            let downloaded = match source.download(&document, &expect, ctx).await {
                Ok(downloaded) => downloaded,
                // HTTP 404: the source publishes no such document.
                Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                    continue;
                }
                Err(err) => return Err(Failure::at(Phase::Fetching, err).to(&document.name)),
            };

            staged.insert(&file.name, kind, downloaded.path);
        }
    }

    Ok(staged)
}

/// An upload that did not finish, and where it stopped.
///
/// The error on its own is what the run acts on; the blame beside it is
/// what a report records, so that a person reading a failed migration can
/// tell "the target ran out of disk" from "the source would not answer"
/// without reading prose.
#[derive(Debug)]
pub struct Failure {
    pub err: Error,

    /// `None` when the failure says nothing about an end or a stage -- a
    /// configuration fault, a run already unwinding.
    pub blame: Option<(Side, Stage)>,

    /// The file being fetched when it happened, when one was.
    pub file: Option<String>,

    /// What the target finished, and was still sending, when a publish
    /// failed. Boxed, since most failures never reach a publish.
    pub delivery: Option<Box<Delivery>>,
}

impl Failure {
    /// Blame a failure on the phase it happened in.
    fn at(phase: Phase, err: Error) -> Self {
        Self {
            blame: phase.blame(&err),
            err,
            file: None,
            delivery: None,
        }
    }

    /// Name the file this happened to.
    fn to(mut self, file: &str) -> Self {
        self.file = Some(file.to_owned());
        self
    }

    /// Carry what a publish got through before it failed.
    fn after(mut self, delivery: Delivery) -> Self {
        self.delivery = Some(Box::new(delivery));
        self
    }
}

/// Anything that reaches `?` without a phase carries no blame, which is
/// the honest answer: nothing said which end it was about.
impl std::convert::From<Error> for Failure {
    fn from(err: Error) -> Self {
        Self {
            err,
            blame: None,
            file: None,
            delivery: None,
        }
    }
}

/// What a transfer was doing when something went wrong.
///
/// The half of the blame only the caller knows. An error says what kind of
/// failure it was; this says who the tool was talking to at the time, and
/// the two together name an end and a stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Pulling a payload out of the source.
    Fetching,

    /// Handing it to the target.
    Publishing,
}

impl Phase {
    /// Which end a failure belongs to, and how far it got.
    ///
    /// **A local fault outranks the phase.** A write that fails while
    /// fetching from a source is this machine's disk, not the source's, and
    /// filing it under the source would send somebody to check a
    /// repository that was answering perfectly. That is the same mistake
    /// `file-unreadable` used to make by covering writes as well as reads.
    ///
    /// `None` for anything that is not a transfer failure at all --
    /// configuration, an already-unwinding run. Recording no side rather
    /// than a guessed one keeps a count of source failures meaning what it
    /// says.
    pub fn blame(self, err: &Error) -> Option<(Side, Stage)> {
        // Whichever end the phase was talking to.
        let peer = match self {
            Phase::Fetching => Side::Source,
            Phase::Publishing => Side::Target,
        };

        Some(match err {
            // This machine, whatever the phase.
            Error::WriteFile { .. } => (Side::Local, Stage::Write),
            Error::ReadFile { .. } => (Side::Local, Stage::Read),

            Error::Transport { during, .. } => match during {
                Contact::Connect => (peer, Stage::Connect),
                Contact::Stream => (peer, Stage::Stream),
            },

            Error::HttpStatus { .. } | Error::Absent { .. } | Error::TooLarge { .. } => {
                (peer, Stage::Request)
            }

            // The bytes arrived and were not what was claimed. A source's
            // fault even when the run was publishing, because the payload
            // is what the source served.
            Error::Integrity(_) | Error::Malformed { .. } => (Side::Source, Stage::Verify),

            // The target looked at what it was given and refused it.
            Error::BadRequest { .. } => (Side::Target, Stage::Publish),

            // Not a transfer failure. A configuration fault, an unbuilt
            // feature, a run already unwinding: none of them says anything
            // about an end or a stage.
            _ => return None,
        })
    }
}

/// Drop a published payload from the cache, for `payloads: discard`.
///
/// Best effort: the bytes are published, and failing the upload over a
/// cache that could not be tidied would be the tool refusing work it has
/// already done. Writable first, because a cached payload is read-only and
/// on Windows a read-only file cannot be removed at all.
fn discard(path: &Path) {
    writable(path);

    let _ = std::fs::remove_file(path);
}

/// What the source claimed about one file.
fn expectation(file: &crate::model::FileRef) -> Expectation {
    let mut expect = Expectation::new().with_digests(file.digests.clone());

    if let Some(size) = file.size {
        expect = expect.with_size(size);
    }

    expect
}

/// How much one file's declared digests actually establish.
///
/// A **size alone is not verification**: it says nothing about the bytes,
/// and a substitution that preserved the length would pass it. Only a
/// digest counts, and only a collision-resistant one counts fully -- see
/// [`DigestAlg::is_collision_resistant`].
fn verified_as(file: &crate::model::FileRef) -> Verification {
    if file.digests.is_empty() {
        return Verification::NoDigestDeclared;
    }

    match file
        .digests
        .iter()
        .any(|digest| digest.alg.is_collision_resistant())
    {
        true => Verification::Verified,
        false => Verification::WeakDigestOnly,
    }
}

/// The lesser of two verifications.
///
/// Spelled out rather than derived from an ordering on [`Verification`],
/// because that type is a report vocabulary rather than a severity scale --
/// `NotAttempted` and `Failed` are not two ends of one axis, and an `Ord`
/// implying they were would be wrong the first time somebody used it.
pub fn weakest(left: Verification, right: Verification) -> Verification {
    let rank = |what| match what {
        Verification::Failed => 0,
        Verification::NoDigestDeclared => 1,
        Verification::NotAttempted => 2,
        Verification::WeakDigestOnly => 3,
        Verification::Verified => 4,
    };

    match rank(left) <= rank(right) {
        true => left,
        false => right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ConfigLoader;
    use crate::config::Config;
    use crate::core::ctx::Ctx;
    use crate::model::{
        ArtifactId, Cause, Digest, DigestAlg, EcosystemId, FileRef, Release, SigScheme, Version,
    };
    use crate::net::{Canned, FixtureClient};
    use crate::session::Session;
    use std::sync::Arc;

    const ORIGIN: &str = "h://origin.test";

    /// The source's cache folder, named for its configured host.
    const SOURCE_CACHE: &str = "origin";
    const MIRROR: &str = "h://mirror.test";

    const TARBALL: &[u8] = b"the payload bytes";

    /// sha256 of `TARBALL`, so the in-flight check actually passes.
    fn sha256_of(bytes: &[u8]) -> String {
        use sha2::Digest as _;

        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);

        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn config(dir: &std::path::Path) -> Config {
        let path = dir.join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"{}"}},
                    "hosts":{{
                      "origin":{{"url":"{ORIGIN}/"}},
                      "mirror":{{"url":"{MIRROR}/"}}
                    }},
                    "sources":{{"upstream":{{"kind":"npm","host":"origin"}}}},
                    "targets":{{"local":{{"kind":"npm","host":"mirror"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    fn artifact(digests: Vec<Digest>) -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            version: Some(Version::new("1.2.0", Release::General)),
            files: vec![FileRef {
                name: "tuna-1.2.0.tgz".into(),
                url: format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz"),
                size: Some(TARBALL.len() as u64),
                digests,
                signatures: Vec::new(),
                core_metadata: None,
            }],
            license: Some("MIT".into()),
            published: None,
        }
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "tuna".into() })
    }

    /// What one target's whole upload came to.
    #[derive(Debug)]
    struct Copied {
        checked: Checked,
        verification: Verification,
    }

    /// One target's whole upload, as `copy` drives it: fetch, publish when
    /// the checks passed, then discard.
    async fn run(
        artifact: &ResolvedArtifact,
        source: &dyn Source,
        into: &ConfiguredTarget,
        payloads: Payloads,
        cache_dir: &str,
        recorded: &HashMap<String, crate::report::CacheRecord>,
        ctx: &Ctx,
    ) -> std::result::Result<Copied, Failure> {
        let fetched = fetch(artifact, source, &[into], cache_dir, recorded, ctx).await?;

        let copied = Copied {
            checked: fetched.checked,
            verification: fetched.verification,
        };

        if fetched.checked == Checked::Refused {
            return Ok(copied);
        }

        publish(artifact, &fetched, into, ctx).await?;
        fetched.discard(payloads).await;

        Ok(copied)
    }

    /// A registry that serves the payload and accepts a publish, and whose
    /// version document is absent so the artifact looks new.
    fn both_ends() -> FixtureClient {
        FixtureClient::new()
            .with_body(format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz"), TARBALL)
            .with(
                format!("{MIRROR}/tuna/1.2.0"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#)
    }

    async fn uploaded(
        config: &Config,
        client: FixtureClient,
        artifact: &ResolvedArtifact,
    ) -> (
        Arc<FixtureClient>,
        Ctx,
        std::result::Result<Copied, Failure>,
    ) {
        let shared = Arc::new(client);
        let mut session = Session::over(config, false, shared.clone()).expect("opens");

        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        let outcome = run(
            artifact,
            &*from.source,
            &into,
            Payloads::Reuse,
            "",
            &Default::default(),
            &ctx,
        )
        .await;

        (shared, ctx, outcome)
    }

    /// Run an upload and hand back where the cache keeps its copy, so a
    /// test can say what became of it.
    async fn uploaded_with(
        config: &Config,
        client: FixtureClient,
        artifact: &ResolvedArtifact,
        payloads: Payloads,
    ) -> (std::result::Result<Copied, Failure>, std::path::PathBuf) {
        let shared = Arc::new(client);
        let mut session = Session::over(config, false, shared.clone()).expect("opens");

        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        // Named by the cache's own rule, which is a hash of the URL.
        let cache =
            crate::ext::Cache::open(std::path::Path::new(&session.cache_dir()).join(SOURCE_CACHE))
                .expect("opens");
        let file = &artifact.files[0];
        let cached = cache.resolve(&cache.payload_path(&file.url, &file.name).expect("path"));
        let outcome = run(
            artifact,
            &*from.source,
            &into,
            payloads,
            "",
            &Default::default(),
            &ctx,
        )
        .await;

        (outcome, cached)
    }

    // -- Core metadata ------------------------------------------------------

    const WHEEL: &str = "echo-1.0-py3-none-any.whl";
    const CORE_METADATA: &str =
        "Metadata-Version: 2.1\nName: echo\nVersion: 1.0\nRequires-Python: >=3.9\n";

    fn pypi_config(dir: &std::path::Path) -> Config {
        pypi_config_with(dir, "{}")
    }

    /// The PyPI configuration, with `options` given to the target.
    fn pypi_config_with(dir: &std::path::Path, options: &str) -> Config {
        let path = dir.join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"{}"}},
                    "hosts":{{
                      "origin":{{"url":"{ORIGIN}/"}},
                      "mirror":{{"url":"{MIRROR}/"}}
                    }},
                    "sources":{{"upstream":{{"kind":"pypi","host":"origin"}}}},
                    "targets":{{"local":{{"kind":"pypi","host":"mirror","options":{options}}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    fn wheel_artifact(core_metadata: Option<Vec<Digest>>) -> ResolvedArtifact {
        let mut file = FileRef::new(WHEEL, format!("{ORIGIN}/files/{WHEEL}"));
        file.core_metadata = core_metadata;

        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::pypi(), None, "echo"),
            version: Some(Version::new("1.0", Release::General)),
            files: vec![file],
            license: None,
            published: None,
        }
    }

    fn pypi_ends() -> FixtureClient {
        FixtureClient::new()
            .with_body(format!("{ORIGIN}/files/{WHEEL}"), TARBALL)
            .with_body(format!("{ORIGIN}/files/{WHEEL}.metadata"), CORE_METADATA)
            .with_body(format!("{MIRROR}/"), "ok")
    }

    fn uploaded_field(client: &FixtureClient, name: &str) -> Vec<String> {
        client
            .posted_to(&format!("{MIRROR}/"))
            .into_iter()
            .flatten()
            .filter(|(field, _)| field == name)
            .map(|(_, bytes)| String::from_utf8_lossy(&bytes).into_owned())
            .collect()
    }

    /// A target asking for core metadata gets the source's document,
    /// fetched through the source's call and checked against the digest
    /// the index published for it.
    #[tokio::test]
    async fn companion_core_metadata_fetched_checked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let digest = Digest::new(DigestAlg::Sha256, sha256_of(CORE_METADATA.as_bytes()));

        let (client, _, outcome) = uploaded(
            &pypi_config(dir.path()),
            pypi_ends(),
            &wheel_artifact(Some(vec![digest])),
        )
        .await;

        outcome.expect("published");

        assert_eq!(uploaded_field(&client, "requires_python"), [">=3.9"]);
    }

    /// A document that does not match its published digest is corrupt,
    /// and fails exactly as a payload would.
    #[tokio::test]
    async fn companion_core_metadata_mismatch_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wrong = Digest::new(DigestAlg::Sha256, "00".repeat(32));

        let (client, _, outcome) = uploaded(
            &pypi_config(dir.path()),
            pypi_ends(),
            &wheel_artifact(Some(vec![wrong])),
        )
        .await;

        let failure = outcome.expect_err("refused");

        assert!(
            matches!(failure.err, Error::Integrity(_)),
            "{:?}",
            failure.err
        );
        assert!(client.posted_to(&format!("{MIRROR}/")).is_empty());
    }

    /// A file the source advertised no document for costs no request.
    #[tokio::test]
    async fn companion_core_metadata_unadvertised_not_fetched() {
        let dir = tempfile::tempdir().expect("tempdir");

        let (client, _, _) =
            uploaded(&pypi_config(dir.path()), pypi_ends(), &wheel_artifact(None)).await;

        assert!(
            !client
                .requested()
                .iter()
                .any(|url| url.ends_with(".metadata")),
            "{:?}",
            client.requested()
        );
    }

    // -- Provenance ---------------------------------------------------------

    const PROVENANCE: &str = r#"{"attestation_bundles": [{"attestations": [{"envelope": "a"}]}]}"#;

    /// A wheel with a PEP 658 sidecar, so its fixture bytes need not be a
    /// zip, and provenance.
    fn attested_artifact() -> ResolvedArtifact {
        let digest = Digest::new(DigestAlg::Sha256, sha256_of(CORE_METADATA.as_bytes()));
        let mut artifact = wheel_artifact(Some(vec![digest]));

        artifact.files[0].signatures.push(crate::model::SigRef {
            scheme: SigScheme::PypiAttestation,
            key_id: None,
            value: None,
            url: Some(format!("{ORIGIN}/integrity/{WHEEL}/provenance")),
        });

        artifact
    }

    fn attested_ends() -> FixtureClient {
        pypi_ends().with_body(format!("{ORIGIN}/integrity/{WHEEL}/provenance"), PROVENANCE)
    }

    /// The provenance the index named is fetched through the source, once:
    /// the source's check and the forward share the one download.
    #[tokio::test]
    async fn companion_provenance_fetched_forwarded() {
        let dir = tempfile::tempdir().expect("tempdir");

        let (client, _, outcome) = uploaded(
            &pypi_config(dir.path()),
            attested_ends(),
            &attested_artifact(),
        )
        .await;

        outcome.expect("published");

        assert_eq!(
            uploaded_field(&client, "attestations"),
            [r#"[{"envelope":"a"}]"#]
        );
        assert_eq!(
            client.hits(&format!("{ORIGIN}/integrity/{WHEEL}/provenance")),
            1
        );
    }

    /// A target dropping attestations forwards none. The source still
    /// fetches the provenance once, to check it: checking is the source's
    /// business, forwarding the target's.
    #[tokio::test]
    async fn companion_provenance_declined_not_forwarded() {
        let dir = tempfile::tempdir().expect("tempdir");

        let (client, _, outcome) = uploaded(
            &pypi_config_with(dir.path(), r#"{"attestations":"drop"}"#),
            attested_ends(),
            &attested_artifact(),
        )
        .await;

        outcome.expect("published");

        assert_eq!(
            client.hits(&format!("{ORIGIN}/integrity/{WHEEL}/provenance")),
            1
        );
        assert!(uploaded_field(&client, "attestations").is_empty());
    }

    /// Which documents travel beside a file is the ecosystem's rule. npm
    /// declares none, so a file claiming one still costs no request.
    #[tokio::test]
    async fn companion_none_for_ecosystem_without() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut claiming = artifact(Vec::new());
        claiming.files[0].core_metadata = Some(Vec::new());

        let (client, _, outcome) = uploaded(&config(dir.path()), both_ends(), &claiming).await;

        outcome.expect("published");
        assert!(
            !client
                .requested()
                .iter()
                .any(|url| url.ends_with(crate::repo::CORE_METADATA_SUFFIX)),
            "{:?}",
            client.requested()
        );
    }

    /// **The cache keeps the single copy.** The target reads the cached
    /// file where it lies, so the cache still has it after the publish,
    /// ready for the next run.
    #[tokio::test]
    async fn cache_keeps_published_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let artifact = artifact(Vec::new());

        let (outcome, cached) =
            uploaded_with(&config, both_ends(), &artifact, Payloads::Reuse).await;

        outcome.expect("published");

        assert!(cached.exists(), "the cache lost its copy");
        assert_eq!(std::fs::read(&cached).expect("readable"), TARBALL);
    }

    /// `discard` is for the migration that would otherwise grow a second
    /// copy of the repository on local disk.
    #[tokio::test]
    async fn cache_discard_removes_payload_after_publish() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let artifact = artifact(Vec::new());

        let (outcome, cached) =
            uploaded_with(&config, both_ends(), &artifact, Payloads::Discard).await;

        outcome.expect("published");

        assert!(!cached.exists(), "the payload was kept");
    }

    /// A hard link shares an inode, so a target that wrote to a staged file
    /// would write into the cache. Read-only turns the ordinary accident
    /// into a loud failure instead of a silent corruption.
    ///
    /// A mitigation, not a guarantee: an extension that unlinks the file
    /// and creates a new one in its place defeats it.
    #[tokio::test]
    async fn cache_payload_read_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let artifact = artifact(Vec::new());

        let (outcome, cached) =
            uploaded_with(&config, both_ends(), &artifact, Payloads::Reuse).await;

        outcome.expect("published");

        let permissions = std::fs::metadata(&cached).expect("readable").permissions();

        assert!(permissions.readonly(), "a cached payload was writable");
    }

    /// A failed publish leaves the cache holding what it held. Until the
    /// bytes are published they are work in progress, and tidying the cache
    /// early would make a retry fetch them again.
    #[tokio::test]
    async fn cache_untouched_by_failed_publish() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let artifact = artifact(Vec::new());

        // The target refuses the publish.
        let client = FixtureClient::new()
            .with_body(format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz"), TARBALL)
            .with(
                format!("{MIRROR}/tuna/1.2.0"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with(
                format!("{MIRROR}/tuna"),
                Canned::status(StatusCode::INTERNAL_SERVER_ERROR),
            );

        let (outcome, cached) = uploaded_with(&config, client, &artifact, Payloads::Discard).await;

        assert!(outcome.is_err(), "the publish should have failed");
        assert!(
            cached.exists(),
            "a failed publish discarded the payload it may need to retry"
        );
    }

    /// **The point of keeping the payload.** A second run finds it already
    /// cached, proves it with the declared digest, and never goes to the
    /// network.
    #[tokio::test]
    async fn cache_payload_reused_not_refetched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let artifact = artifact(vec![Digest {
            alg: DigestAlg::Sha256,
            hex: sha256_of(TARBALL),
        }]);

        let (outcome, cached) =
            uploaded_with(&config, both_ends(), &artifact, Payloads::Reuse).await;

        outcome.expect("published");
        assert!(cached.exists());

        // The second run sees a target that still has nothing, so it
        // publishes again -- and fetches nothing.
        let shared = Arc::new(both_ends());
        let mut session = Session::over(&config, false, shared.clone()).expect("opens");
        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        run(
            &artifact,
            &*from.source,
            &into,
            Payloads::Reuse,
            "",
            &Default::default(),
            &ctx,
        )
        .await
        .expect("published");

        assert_eq!(
            shared.hits(&format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz")),
            0,
            "the payload was fetched again although the cache had it"
        );
    }

    /// A registry that republished a version under the same coordinate
    /// would otherwise be copied from a stale cache forever, and nobody
    /// would notice. The digest is what makes reuse provable.
    #[tokio::test]
    async fn cache_payload_mismatch_refetched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let artifact = artifact(vec![Digest {
            alg: DigestAlg::Sha256,
            hex: sha256_of(TARBALL),
        }]);

        let (outcome, cached) =
            uploaded_with(&config, both_ends(), &artifact, Payloads::Reuse).await;

        outcome.expect("published");

        // Something else is in the cache under that name.
        let mut writable = std::fs::metadata(&cached).expect("readable").permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        writable.set_readonly(false);
        std::fs::set_permissions(&cached, writable).expect("writable");
        std::fs::write(&cached, b"not the tarball").expect("written");

        let shared = Arc::new(both_ends());
        let mut session = Session::over(&config, false, shared.clone()).expect("opens");
        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        run(
            &artifact,
            &*from.source,
            &into,
            Payloads::Reuse,
            "",
            &Default::default(),
            &ctx,
        )
        .await
        .expect("published");

        assert_eq!(
            shared.hits(&format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz")),
            1,
            "a cached file that did not match was trusted"
        );
        assert_eq!(std::fs::read(&cached).expect("readable"), TARBALL);
    }

    /// Without a digest there is nothing to prove the cached bytes are
    /// current, so the fetch happens. Unverified either way; this costs a
    /// download rather than a wrong artifact.
    #[tokio::test]
    async fn cache_undigested_payload_never_reused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let artifact = artifact(Vec::new());

        let (outcome, cached) =
            uploaded_with(&config, both_ends(), &artifact, Payloads::Reuse).await;

        outcome.expect("published");
        assert!(cached.exists());

        let shared = Arc::new(both_ends());
        let mut session = Session::over(&config, false, shared.clone()).expect("opens");
        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        run(
            &artifact,
            &*from.source,
            &into,
            Payloads::Reuse,
            "",
            &Default::default(),
            &ctx,
        )
        .await
        .expect("published");

        assert_eq!(
            shared.hits(&format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz")),
            1,
            "a payload with nothing to check it against was reused"
        );
    }

    /// **The failure this step exists to make visible.** A report says a
    /// payload is cached under a directory the run is no longer using, so
    /// the bytes are not where the record says. The fetch happens anyway;
    /// what changes is that it is reported rather than silent.
    #[tokio::test]
    async fn cache_directory_moved_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let shared = Arc::new(both_ends());
        let mut session = Session::over(&config, false, shared.clone()).expect("opens");
        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        let recorded = std::collections::HashMap::from([(
            "tuna-1.2.0.tgz".to_owned(),
            crate::report::CacheRecord {
                host: "origin".to_owned(),
                cache_dir: "/somewhere/else".to_owned(),
                relative_path: "tuna-1.2.0.tgz".to_owned(),
                size: Some(13),
                verification: Verification::Verified,
            },
        )]);

        run(
            &artifact(Vec::new()),
            &*from.source,
            &into,
            Payloads::Reuse,
            "/the/configured/one",
            &recorded,
            &ctx,
        )
        .await
        .expect("published");

        let seen: Vec<String> = ctx
            .problems()
            .tail()
            .iter()
            .map(|problem| problem.code().to_string())
            .collect();

        assert!(
            seen.iter().any(|code| code == "cache-file-missing"),
            "a moved cache directory went unreported: {seen:?}"
        );

        // A warning, not a refusal: the payload is fetched and published.
        assert_eq!(shared.hits(&format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz")), 1);
    }

    /// Nothing recorded is the ordinary case for a file nobody has fetched
    /// before, and must not look like a moved cache.
    #[tokio::test]
    async fn cache_unrecorded_payload_not_reported_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let shared = Arc::new(both_ends());
        let mut session = Session::over(&config, false, shared.clone()).expect("opens");
        let from = session.source("upstream").expect("opens");
        let into = session.target("local").expect("opens");
        let ctx = ctx();

        run(
            &artifact(Vec::new()),
            &*from.source,
            &into,
            Payloads::Reuse,
            "/the/configured/one",
            &Default::default(),
            &ctx,
        )
        .await
        .expect("published");

        let seen: Vec<String> = ctx
            .problems()
            .tail()
            .iter()
            .map(|problem| problem.code().to_string())
            .collect();

        assert!(
            !seen.iter().any(|code| code == "cache-file-missing"),
            "a first fetch was reported as a moved cache: {seen:?}"
        );
    }

    /// The whole operation: the payload is fetched from one host and
    /// published to the other -- with the bytes intact.
    #[tokio::test]
    async fn artifact_crosses_from_source_to_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let artifact = artifact(vec![Digest {
            alg: DigestAlg::Sha256,
            hex: sha256_of(TARBALL),
        }]);

        let (client, _ctx, outcome) = uploaded(&config, both_ends(), &artifact).await;
        let outcome = outcome.expect("uploaded");

        assert_eq!(outcome.checked, Checked::Passed);
        assert_eq!(outcome.verification, Verification::Verified);

        // The document reached the target with the payload inside it,
        // which is the proof the file survived the trip.
        let sent = client.sent_to(&format!("{MIRROR}/tuna"));
        let [body] = sent.as_slice() else {
            panic!("expected one publish, got {}", sent.len());
        };

        let doc: serde_json::Value = serde_json::from_slice(body).expect("valid JSON");
        let data = doc["_attachments"]["tuna-1.2.0.tgz"]["data"]
            .as_str()
            .expect("base64");

        use base64::Engine as _;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .expect("decodes"),
            TARBALL
        );
    }

    /// Corrupt bytes never reach the target. The check is in flight, so a
    /// mismatch fails the fetch rather than being noticed afterwards.
    #[tokio::test]
    async fn digest_mismatch_stops_upload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let artifact = artifact(vec![Digest {
            alg: DigestAlg::Sha256,
            hex: sha256_of(b"something else entirely"),
        }]);

        let (client, _ctx, outcome) = uploaded(&config, both_ends(), &artifact).await;

        assert!(outcome.is_err(), "the wrong bytes were accepted");
        assert!(
            client.sent_to(&format!("{MIRROR}/tuna")).is_empty(),
            "corrupt bytes reached the target"
        );
    }

    /// A registry that publishes no digests is still usable -- refusing it
    /// would make this unusable against real ones -- but the run says so
    /// rather than implying the bytes were checked.
    #[tokio::test]
    async fn digest_undeclared_reported_copied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let (_client, ctx, outcome) = uploaded(&config, both_ends(), &artifact(Vec::new())).await;
        let outcome = outcome.expect("uploaded");

        assert_eq!(outcome.checked, Checked::Passed);
        assert_eq!(outcome.verification, Verification::NoDigestDeclared);
        assert!(
            ctx.problems()
                .counts()
                .contains_key(&Code::SignatureMissing)
        );
    }

    /// A broken digest is not verification. Both have practical collisions,
    /// so the bytes are *a* file somebody could have produced rather than
    /// the one that was published.
    #[tokio::test]
    async fn digest_weak_alone_not_verified() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let artifact = artifact(vec![Digest {
            alg: DigestAlg::Sha1,
            hex: {
                use sha1::Digest as _;
                let mut hasher = sha1::Sha1::new();
                hasher.update(TARBALL);
                hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            },
        }]);

        let (_client, _ctx, outcome) = uploaded(&config, both_ends(), &artifact).await;

        assert_eq!(
            outcome.expect("uploaded").verification,
            Verification::WeakDigestOnly
        );
    }

    /// An artifact with no files is a source that answered oddly, not a
    /// package with no content -- publishing nothing under a real version
    /// would leave an empty release nobody could tell from a real one.
    #[tokio::test]
    async fn artifact_without_files_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let mut empty = artifact(Vec::new());
        empty.files.clear();

        let (client, _ctx, outcome) = uploaded(&config, both_ends(), &empty).await;

        assert!(outcome.is_err());
        assert!(client.sent_to(&format!("{MIRROR}/tuna")).is_empty());
    }

    /// The weakest verification wins across files, because a report saying
    /// an artifact was verified must mean all of it was.
    #[test]
    fn verification_weakest_reported() {
        assert_eq!(
            weakest(Verification::Verified, Verification::WeakDigestOnly),
            Verification::WeakDigestOnly
        );
        assert_eq!(
            weakest(Verification::WeakDigestOnly, Verification::NoDigestDeclared),
            Verification::NoDigestDeclared
        );
        assert_eq!(
            weakest(Verification::NoDigestDeclared, Verification::Failed),
            Verification::Failed
        );
    }
}

#[cfg(test)]
mod blame_tests {
    use super::*;
    use crate::core::problem::Code;

    fn write_failure() -> Error {
        Error::WriteFile {
            path: "/full/disk/tuna.tgz".into(),
            source: std::io::Error::other("no space left on device"),
        }
    }

    /// **The case that motivated splitting `file-unreadable`.** A write
    /// that fails while fetching from a source is this machine's disk, not
    /// the source's. Blaming the phase would send somebody to check a
    /// repository that was answering perfectly.
    #[test]
    fn blame_local_fault_outranks_phase() {
        for phase in [Phase::Fetching, Phase::Publishing] {
            assert_eq!(
                phase.blame(&write_failure()),
                Some((Side::Local, Stage::Write)),
                "{phase:?} blamed a full disk on the far end"
            );
        }
    }

    /// The other half of the same split: a write failure is no longer
    /// reported as though the user's arguments were at fault.
    #[test]
    fn blame_write_failure_not_setup_fault() {
        use crate::core::problem::Concern;

        assert_eq!(write_failure().code(), Code::FileUnwritable);
        assert_eq!(Code::FileUnwritable.concerns(), Concern::Environment);

        // A file the user named and the tool cannot open still is one.
        let unreadable = Error::ReadFile {
            path: "/no/such/lock.json".into(),
            source: std::io::Error::other("not found"),
        };

        assert_eq!(unreadable.code(), Code::FileUnreadable);
        assert_eq!(Code::FileUnreadable.concerns(), Concern::Setup);
    }

    /// A transport failure belongs to whichever end the phase was talking
    /// to, which is the half only the caller knows: the error names a URL
    /// without saying whose it was.
    #[test]
    fn blame_transport_failure_follows_phase() {
        let refused = || Error::Transport {
            url: "h://either.test/x".to_owned(),
            during: Contact::Connect,
            source: Box::new(std::io::Error::other("connection refused")),
        };

        assert_eq!(
            Phase::Fetching.blame(&refused()),
            Some((Side::Source, Stage::Connect))
        );
        assert_eq!(
            Phase::Publishing.blame(&refused()),
            Some((Side::Target, Stage::Connect))
        );
    }

    /// A link lost part way is a different problem from one never made:
    /// retrying fixes the first, and only configuration fixes the second.
    #[test]
    fn blame_dropped_body_is_stream() {
        let dropped = Error::Transport {
            url: "h://either.test/x".to_owned(),
            during: Contact::Stream,
            source: Box::new(std::io::Error::other("connection reset")),
        };

        assert_eq!(
            Phase::Fetching.blame(&dropped),
            Some((Side::Source, Stage::Stream))
        );
        assert_eq!(
            Phase::Publishing.blame(&dropped),
            Some((Side::Target, Stage::Stream))
        );
    }

    /// Bytes that arrived and were not what was claimed are the source's
    /// fault whichever phase noticed, because the payload is what the
    /// source served.
    #[test]
    fn blame_bad_bytes_on_source() {
        let wrong = Error::Integrity("sha256 mismatch".to_owned());

        assert_eq!(
            Phase::Publishing.blame(&wrong),
            Some((Side::Source, Stage::Verify))
        );
    }

    /// A target that looked at what it was given and refused it.
    #[test]
    fn blame_refused_publish_on_target() {
        let refused = Error::BadRequest {
            ecosystem: "npm",
            text: "pkg:npm/tuna".to_owned(),
            detail: "version already exists".to_owned(),
        };

        assert_eq!(
            Phase::Publishing.blame(&refused),
            Some((Side::Target, Stage::Publish))
        );
    }

    /// Not every failure is a transfer failure. Recording no side rather
    /// than a guessed one keeps a count of source failures meaning what it
    /// says.
    #[test]
    fn blame_nobody_for_non_transfer_failure() {
        assert!(
            Phase::Fetching
                .blame(&Error::Config("bad argument".to_owned()))
                .is_none()
        );
        assert!(
            Phase::Publishing
                .blame(&Error::Aborted("stopping".to_owned()))
                .is_none()
        );
    }
}
