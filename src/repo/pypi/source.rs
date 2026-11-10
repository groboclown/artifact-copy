//! Reading a PyPI index as a source.
//!
//! References: [PEP 740](https://peps.python.org/pep-0740/).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use http::StatusCode;

use super::detail::Detail;
use super::metadata::{dependency, requires_dist};
use super::simple::{SimpleFile, SimpleIndex};
use crate::cache::Coalesced;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::pypi::PROVENANCE_SUFFIX;
use crate::ecosystem::{Companion, Ecosystem, PyPi};
use crate::ext::ExtHost;
use crate::message;
use crate::model::{
    ArtifactId, Dependency, Digest, DigestAlg, EcosystemId, FileRef, ResolvedArtifact, SigRef,
    SigScheme, Version,
};
use crate::net::sig::sigstore::{RootSource, SigstoreRoot};
use crate::net::{ByteLimit, Expectation, Req, normalized_base};
use crate::repo::{Downloaded, Source};
use crate::version::VersionHandler;

use super::{METADATA_LIMIT, SIMPLE_ACCEPT, SIMPLE_LIMIT, attestation, parse_simple, version_of};

/// The per-version JSON document, consulted for the license.
const DETAIL_LIMIT: ByteLimit = ByteLimit::mib(8);

/// How many simple-index documents to keep.
///
/// Bounded for the same reason the npm cache is: artifact enumeration
/// walks millions of projects, and a map keyed by name would grow with it.
const SIMPLE_CACHE: usize = 64;

pub struct PyPiSource {
    base_url: String,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    ecosystem: PyPi,

    /// Indexes already fetched, and those being fetched right now.  See
    /// [`Coalesced`]: concurrent workers reaching the same project share one
    /// request instead of each issuing their own.
    cache: Coalesced<SimpleIndex>,

    /// What PEP 740 attestations are checked against. Shared with every
    /// other source in the run, so the root loads at most once.
    sigstore: Arc<SigstoreRoot>,
}

impl PyPiSource {
    /// No HTTP client: every request goes through `host`, which is what
    /// confines this to the host it was configured for.
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: normalized_base(base_url),
            host,
            ecosystem: PyPi,
            cache: Coalesced::new(SIMPLE_CACHE),
            sigstore: Arc::new(SigstoreRoot::new(RootSource::Tuf(None))),
        }
    }

    /// Check attestations against this trust root.
    pub fn with_sigstore(mut self, sigstore: Arc<SigstoreRoot>) -> Self {
        self.sigstore = sigstore;
        self
    }

    /// Check one file's attestations, reporting what became of them.
    async fn attested(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        url: &str,
        staged: &std::path::Path,
        forwarded: Option<&std::path::Path>,
        ctx: &Ctx,
    ) -> Result<()> {
        let sha256 = sha256_of_file(file, staged)?;

        let fetched = self
            .fetch_provenance(artifact, file, url, forwarded, ctx)
            .await?;

        let Some(staged_provenance) = fetched else {
            return Ok(());
        };

        let provenance = read_bounded(&staged_provenance, attestation::PROVENANCE_LIMIT)?;
        let verdict = attestation::verify(&self.sigstore, &provenance, &file.name, &sha256).await;

        self.report_verdict(verdict, artifact, file, url, ctx);

        Ok(())
    }

    /// The staged provenance object of `file`, or `None` when the index
    /// advertised one it does not serve, which is reported here.
    ///
    /// Already staged when the target forwards the attestations, and
    /// fetched here only when it does not.
    async fn fetch_provenance(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        url: &str,
        forwarded: Option<&std::path::Path>,
        ctx: &Ctx,
    ) -> Result<Option<std::path::PathBuf>> {
        let document = FileRef::new(format!("{}{PROVENANCE_SUFFIX}", file.name), url);

        let fetched = match forwarded {
            Some(path) => Ok(path.to_path_buf()),
            None => self
                .download(&document, &Expectation::new(), ctx)
                .await
                .map(|downloaded| downloaded.path),
        };

        match fetched {
            Ok(path) => Ok(Some(path)),

            // HTTP 404: an advertised provenance object that is not there.
            // Advertised and then not served: there is nothing to check,
            // which is not the same as a check that failed.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                ctx.report(
                    Code::SignatureMissing,
                    message!(
                        "pypi-attestation-unavailable",
                        "{file} of {purl} advertises attestations at {url}, which is not found",
                        file = &file.name,
                        purl = artifact.purl(),
                        url = url,
                    ),
                );

                Ok(None)
            }

            Err(err) => Err(err),
        }
    }

    /// Report every verdict but a verified one.
    fn report_verdict(
        &self,
        verdict: attestation::Verdict,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        url: &str,
        ctx: &Ctx,
    ) {
        match verdict {
            attestation::Verdict::Verified => {}

            attestation::Verdict::Invalid(reason) => {
                ctx.report(
                    Code::SignatureInvalid,
                    message!(
                        "pypi-attestation-invalid",
                        "{file} of {purl} carries an attestation that does not hold: {reason}",
                        file = &file.name,
                        purl = artifact.purl(),
                        reason = &reason,
                    ),
                );
            }

            attestation::Verdict::UnknownPublisher(identity) => {
                ctx.report(
                    Code::SignatureMissing,
                    message!(
                        "pypi-attestation-publisher-unknown",
                        "{file} of {purl} is attested by {identity}, under a publisher kind \
                         whose identity this tool cannot match",
                        file = &file.name,
                        purl = artifact.purl(),
                        identity = &identity,
                    ),
                );
            }

            attestation::Verdict::Unchecked(reason) => {
                ctx.report(
                    Code::SignatureMissing,
                    message!(
                        "pypi-attestation-unchecked",
                        "{file} of {purl} was not checked against its attestations: the \
                         Sigstore trust root from {root} would not load: {reason}",
                        file = &file.name,
                        purl = artifact.purl(),
                        root = self.sigstore.describe(),
                        reason = &reason,
                    ),
                );
            }

            attestation::Verdict::Malformed(reason) => {
                ctx.report(
                    Code::MetadataMalformed,
                    message!(
                        "pypi-provenance-malformed",
                        "{url} is not a PEP 740 provenance object: {reason}",
                        url = url,
                        reason = &reason,
                    ),
                );
            }
        }
    }

    fn simple_url(&self, id: &ArtifactId) -> String {
        format!("{}/simple/{}/", self.base_url, id.name())
    }

    fn detail_url(&self, id: &ArtifactId, version: &Version) -> String {
        format!("{}/pypi/{}/{version}/json", self.base_url, id.name())
    }

    async fn simple(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Arc<SimpleIndex>> {
        let url = self.simple_url(id);

        // Through the document cache here and not in `fetch_simple`, which
        // the target shares: a target reading its own index must see it as
        // it is now.
        self.cache
            .get_or_try_init(&url, || async {
                let req = Req::get(&url).accept(SIMPLE_ACCEPT);
                let body = crate::ext::document(
                    &*self.host,
                    &req,
                    crate::ecosystem::pypi::SIMPLE_DOCUMENT,
                    SIMPLE_LIMIT,
                    ctx,
                )
                .await?;

                parse_simple(&body, &url)
            })
            .await
    }

    /// A file's URL, made absolute.
    ///
    /// PEP 691 lets an index give a file's `url` relative to the index page
    /// itself, and Nexus does: `../../packages/{name}/{version}/{file}`.
    /// Resolved against the page it came from, as a browser would; an
    /// absolute URL passes through unchanged. One that will not resolve is
    /// kept as written, and fails at the fetch with the URL in hand.
    fn file_url(&self, id: &ArtifactId, url: &str) -> String {
        url::Url::parse(&self.simple_url(id))
            .and_then(|page| page.join(url))
            .map(|joined| joined.to_string())
            .unwrap_or_else(|_| url.to_owned())
    }

    /// Files belonging to one version.
    ///
    /// The simple index lists every file of every version together, so they
    /// are matched by the version embedded in each filename.
    fn files_for<'i>(&self, index: &'i SimpleIndex, version: &Version) -> Vec<&'i SimpleFile> {
        index
            .files
            .iter()
            .filter(|file| version_of(&file.filename) == Some(version.text()))
            .collect()
    }

    /// Report each file whose name says no version, so it is not dropped
    /// from every version unseen: `pkg-1.0.dmg`.
    fn report_unparsed(&self, index: &SimpleIndex, ctx: &Ctx) {
        for file in &index.files {
            if version_of(&file.filename).is_some() {
                continue;
            }

            ctx.report(
                Code::DistributionTypeUnsupported,
                message!(
                    "pypi-filename-unparsed",
                    "{file} names no version this tool reads, so no version holds it",
                    file = &file.filename,
                ),
            );
        }
    }
}

/// The sha256 the file was checked against in flight, when the index
/// declared one; otherwise computed from the staged bytes.
fn sha256_of_file(file: &FileRef, staged: &std::path::Path) -> Result<String> {
    let declared = file
        .digests
        .iter()
        .find(|digest| digest.alg == DigestAlg::Sha256);

    if let Some(digest) = declared {
        return Ok(digest.hex.clone());
    }

    Ok(crate::net::files::digests_of(staged, &[DigestAlg::Sha256])?
        .into_iter()
        .map(|(_, hex)| hex)
        .next()
        .unwrap_or_default())
}

/// A staged file's bytes, refusing one larger than `limit` rather than
/// reading it.
fn read_bounded(path: &std::path::Path, limit: ByteLimit) -> Result<Vec<u8>> {
    let unreadable = |source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    };

    let size = std::fs::metadata(path).map_err(unreadable)?.len();

    if size > limit.get() {
        return Err(Error::TooLarge {
            url: path.display().to_string(),
            limit: limit.get(),
        });
    }

    std::fs::read(path).map_err(unreadable)
}

#[async_trait]
impl Source for PyPiSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![self.ecosystem.id()]
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let index = self.simple(id, ctx).await?;

        // PEP 700 does not promise an order, so the ecosystem sorts.  A
        // caller assuming index order would pick an arbitrary version.
        Ok(self.ecosystem.classify(&index.versions))
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let version = crate::repo::version_required(id, version)?;
        let index = self.simple(id, ctx).await?;
        let mut files = Vec::new();
        let mut published: Option<DateTime<Utc>> = None;

        self.report_unparsed(&index, ctx);

        for file in self.files_for(&index, version) {
            let mut entry = FileRef::new(&file.filename, self.file_url(id, &file.url));
            entry.size = file.size;
            entry.core_metadata = file.core_metadata.digests();

            // PEP 740: recorded so a target can forward the attestations,
            // not verified here.
            if let Some(provenance) = &file.provenance {
                entry.signatures.push(SigRef {
                    scheme: SigScheme::PypiAttestation,
                    key_id: None,
                    value: None,
                    url: Some(self.file_url(id, provenance)),
                });
            }

            for (algorithm, hex) in &file.hashes {
                if let Some(alg) = DigestAlg::parse(algorithm) {
                    entry.digests.push(Digest::new(alg, hex));
                }
            }

            // Modern uploads carry sha256; a 2012-era file may offer only
            // md5 and blake2b, which is verifiable but weak.
            if !entry.digests.is_empty() && !entry.has_strong_digest() {
                ctx.report(
                    Code::SignatureMissing,
                    message!(
                        "pypi-weak-digest-only",
                        "{file} offers no collision-resistant digest",
                        file = &file.filename,
                    ),
                );
            }

            if let Some(stamp) = file
                .upload_time
                .as_deref()
                .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            {
                let stamp = stamp.with_timezone(&Utc);

                // The earliest file of a version is when it was published.
                published = Some(published.map_or(stamp, |current| current.min(stamp)));
            }

            files.push(entry);
        }

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: Some(version.clone()),
            files,
            license: self.license(id, version, ctx).await,
            published,
        })
    }

    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        let index = self.simple(&artifact.id, ctx).await?;
        let version = crate::repo::version_required(&artifact.id, artifact.version.as_ref())?;

        // PEP 658: a file advertising `core-metadata` has its METADATA
        // beside it, so the dependency list costs one small request rather
        // than a wheel download.
        let sidecar = self
            .files_for(&index, version)
            .into_iter()
            .find(|file| file.core_metadata.is_present())
            .map(|file| format!("{}.metadata", self.file_url(&artifact.id, &file.url)));

        if let Some(url) = sidecar
            && let Ok(body) = crate::ext::document(
                &*self.host,
                &Req::get(&url),
                crate::ext::leaf(&url),
                METADATA_LIMIT,
                ctx,
            )
            .await
        {
            return Ok(requires_dist(&String::from_utf8_lossy(&body)));
        }

        // Fall back to the per-version JSON, which states the same list.
        let url = self.detail_url(&artifact.id, version);

        let Ok(body) = crate::ext::document(
            &*self.host,
            &Req::get(&url),
            crate::ecosystem::pypi::DETAIL_DOCUMENT,
            DETAIL_LIMIT,
            ctx,
        )
        .await
        else {
            return Ok(Vec::new());
        };

        let Ok(detail) = serde_json::from_slice::<Detail>(&body) else {
            return Ok(Vec::new());
        };

        // A package with only a dynamic `setup.py` publishes no static
        // metadata at all.  That is genuinely unresolvable without running
        // arbitrary code, so it is reported rather than guessed at.
        if detail.info.requires_dist.is_none() {
            ctx.report(
                Code::DependencyMetadataDynamic,
                message!(
                    "pypi-no-static-metadata",
                    "{purl} publishes no static dependency metadata",
                    purl = artifact.purl(),
                ),
            );

            return Ok(Vec::new());
        }

        Ok(detail
            .info
            .requires_dist
            .unwrap_or_default()
            .iter()
            .filter_map(|line| dependency(line))
            .collect())
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        crate::repo::download(&*self.host, file, expect, ctx).await
    }

    /// Each downloaded file's PEP 740 attestations, where the index named
    /// any. A file without them is not reported: most PyPI files have none.
    async fn verify(
        &self,
        artifact: &ResolvedArtifact,
        files: &[std::path::PathBuf],
        companions: &crate::repo::Companions,
        ctx: &Ctx,
    ) -> Result<()> {
        for (file, staged) in artifact.files.iter().zip(files) {
            let url = file
                .signatures
                .iter()
                .find(|signature| signature.scheme == SigScheme::PypiAttestation)
                .and_then(|signature| signature.url.as_deref());

            let Some(url) = url else {
                continue;
            };

            let forwarded = companions.get(&file.name, Companion::Provenance);

            self.attested(artifact, file, url, staged, forwarded, ctx)
                .await?;
        }

        Ok(())
    }

    fn serves(&self, url: &str) -> bool {
        self.host.permits(url)
    }
}

impl PyPiSource {
    /// The declared license, in the order PEP 639 establishes.
    ///
    /// `license_expression` is real SPDX but null for most projects even
    /// today; the trove classifiers are deprecated yet ubiquitous; the
    /// free-text `license` field is anything from `MIT` to an entire license
    /// body. Taking them in that order gets the most reliable answer
    /// available.
    async fn license(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Option<String> {
        let url = self.detail_url(id, version);
        let body = crate::ext::document(
            &*self.host,
            &Req::get(&url),
            crate::ecosystem::pypi::DETAIL_DOCUMENT,
            DETAIL_LIMIT,
            ctx,
        )
        .await
        .ok()?;
        let detail: Detail = serde_json::from_slice(&body).ok()?;

        if let Some(expression) = detail.info.license_expression.filter(|e| !e.is_empty()) {
            return Some(expression);
        }

        if let Some(classifier) = detail
            .info
            .classifiers
            .iter()
            .find_map(|c| c.strip_prefix("License :: OSI Approved :: "))
        {
            return Some(classifier.to_owned());
        }

        detail.info.license.filter(|text| !text.trim().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::testing::Fixture;
    use crate::model::{ArtifactRequest, Cause, DepKind, EcosystemId, VersionSpec};
    use crate::net::sig::sigstore;
    use crate::net::{Canned, FixtureClient};
    use crate::repo::Criteria;
    use crate::version::{PreRelease, VersionHandler};
    use std::time::Duration;

    const INDEX: &str = "h://pypi.test";

    const SIMPLE: &str = r#"{
        "meta": {"api-version": "1.4"},
        "name": "requests",
        "versions": ["2.31.0", "2.30.0", "3.0.0rc1"],
        "files": [
            {
                "filename": "requests-2.31.0-py3-none-any.whl",
                "url": "h://files.test/requests-2.31.0-py3-none-any.whl",
                "hashes": {"sha256": "aa"},
                "size": 62574,
                "upload-time": "2023-05-22T15:12:42.313790Z",
                "core-metadata": {"sha256": "bb"}
            },
            {
                "filename": "requests-2.31.0.tar.gz",
                "url": "h://files.test/requests-2.31.0.tar.gz",
                "hashes": {"sha256": "cc"},
                "upload-time": "2023-05-22T15:12:44.000000Z"
            },
            {
                "filename": "requests-2.30.0.tar.gz",
                "url": "h://files.test/requests-2.30.0.tar.gz",
                "hashes": {"md5": "dd"},
                "upload-time": "2023-05-03T00:00:00.000000Z"
            }
        ]
    }"#;

    const DETAIL: &str = r#"{
        "info": {
            "license_expression": null,
            "license": "Apache-2.0",
            "classifiers": ["License :: OSI Approved :: Apache Software License"],
            "requires_dist": [
                "charset-normalizer>=2,<4",
                "idna>=2.5,<4",
                "PySocks>=1.5.6; extra == \"socks\""
            ]
        }
    }"#;

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "requests".into(),
        })
    }

    fn fixture() -> Fixture<PyPiSource> {
        let client = FixtureClient::new()
            .with_body(format!("{INDEX}/simple/requests/"), SIMPLE)
            .with_body(format!("{INDEX}/pypi/requests/2.31.0/json"), DETAIL);

        Fixture::build(client, |host| PyPiSource::new(INDEX, host))
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::pypi(), None, name)
    }

    #[tokio::test]
    async fn versions_from_simple_index() {
        let f = fixture();
        let ctx = ctx();

        let versions = f
            .subject
            .versions(&id("requests"), &ctx)
            .await
            .expect("fetched");

        assert_eq!(versions.len(), 3);
        assert!(versions.iter().any(|v| v.text() == "2.31.0"));
    }

    /// The index is fetched with the PEP 691 header, or it answers HTML.
    #[tokio::test]
    async fn index_json_requested() {
        let f = fixture();
        let ctx = ctx();

        f.subject
            .versions(&id("requests"), &ctx)
            .await
            .expect("fetched");

        assert_eq!(f.host.hits(&format!("{INDEX}/simple/requests/")), 1);
    }

    /// A relative `url` is resolved against the index page, as Nexus
    /// serves it; an absolute one is untouched.
    #[tokio::test]
    async fn metadata_resolves_relative_urls() {
        let relative = r#"{"versions": ["1.0"], "files": [
            {"filename": "echo-1.0.tar.gz", "url": "../../packages/echo/1.0/echo-1.0.tar.gz"},
            {"filename": "echo-1.0-py3-none-any.whl", "url": "h://files.test/echo-1.0-py3-none-any.whl"}
        ]}"#;
        let f = Fixture::build(
            FixtureClient::new().with_body(format!("{INDEX}/simple/echo/"), relative),
            |host| PyPiSource::new(INDEX, host),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id("echo"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(
            artifact.files[0].url,
            format!("{INDEX}/packages/echo/1.0/echo-1.0.tar.gz")
        );
        assert_eq!(
            artifact.files[1].url,
            "h://files.test/echo-1.0-py3-none-any.whl"
        );
    }

    /// A file advertising PEP 658 metadata carries the sidecar's digests,
    /// so a target that needs the document can have it fetched and
    /// checked. A file advertising none carries nothing.
    #[tokio::test]
    async fn metadata_carries_core_metadata_digests() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.31.0");

        let artifact = f
            .subject
            .metadata(&id("requests"), Some(&version), &ctx)
            .await
            .expect("fetched");

        let wheel = &artifact.files[0];

        assert_eq!(
            wheel.core_metadata,
            Some(vec![Digest::new(DigestAlg::Sha256, "bb")])
        );
        assert_eq!(artifact.files[1].core_metadata, None);
    }

    #[tokio::test]
    async fn metadata_gathers_files_of_one_version() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.31.0");

        let artifact = f
            .subject
            .metadata(&id("requests"), Some(&version), &ctx)
            .await
            .expect("fetched");

        // Both the wheel and the sdist, and not the 2.30.0 file.
        assert_eq!(artifact.files.len(), 2);
        assert!(artifact.files.iter().all(|file| file.has_strong_digest()));
    }

    /// An old project's files: every kind of distribution, a wheel whose
    /// build tag reads as version `1`, and a name with no readable version.
    const LEGACY: &str = r#"{
        "meta": {"api-version": "1.4"},
        "name": "echo",
        "versions": ["1", "1.0"],
        "files": [
            {"filename": "echo-1.0.tar.bz2", "url": "h://files.test/echo-1.0.tar.bz2"},
            {"filename": "echo-1.0-py2.7.egg", "url": "h://files.test/echo-1.0-py2.7.egg"},
            {"filename": "echo-1.0.win32.exe", "url": "h://files.test/echo-1.0.win32.exe"},
            {"filename": "echo-1.0-1-py3-none-any.whl", "url": "h://files.test/echo-1.0-1-py3-none-any.whl"},
            {"filename": "echo-1.0.dmg", "url": "h://files.test/echo-1.0.dmg"}
        ]
    }"#;

    fn legacy_fixture() -> Fixture<PyPiSource> {
        let client = FixtureClient::new().with_body(format!("{INDEX}/simple/echo/"), LEGACY);

        Fixture::build(client, |host| PyPiSource::new(INDEX, host))
    }

    /// Names of the files `version` holds.
    async fn legacy_files(version: &str, ctx: &Ctx) -> Vec<String> {
        let f = legacy_fixture();
        let version = f.subject.ecosystem.version(version);

        let artifact = f
            .subject
            .metadata(&id("echo"), Some(&version), ctx)
            .await
            .expect("fetched");

        artifact.files.into_iter().map(|file| file.name).collect()
    }

    /// Every legacy kind reaches the target, which decides under
    /// `legacy-dists` what to do with it.
    #[tokio::test]
    async fn metadata_gathers_legacy_dists() {
        let files = legacy_files("1.0", &ctx()).await;

        assert_eq!(
            files,
            [
                "echo-1.0.tar.bz2",
                "echo-1.0-py2.7.egg",
                "echo-1.0.win32.exe",
                "echo-1.0-1-py3-none-any.whl",
            ]
        );
    }

    /// A wheel's build tag is not its version.
    #[tokio::test]
    async fn metadata_ignores_build_tag() {
        assert!(legacy_files("1", &ctx()).await.is_empty());
    }

    /// A file no version claims is reported, not dropped unseen.
    #[tokio::test]
    async fn metadata_reports_unparsed_name() {
        let ctx = ctx();

        legacy_files("1.0", &ctx).await;

        assert_eq!(
            ctx.problems().counts()[&Code::DistributionTypeUnsupported],
            1
        );
    }

    /// A version's publish time is its earliest file, not its last.
    #[tokio::test]
    async fn metadata_publish_time_earliest_upload() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.31.0");

        let artifact = f
            .subject
            .metadata(&id("requests"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(
            artifact.published.unwrap().to_rfc3339(),
            "2023-05-22T15:12:42.313790+00:00"
        );
    }

    /// The classifier is the fallback when PEP 639 is absent, which is still
    /// the common case.
    #[tokio::test]
    async fn license_falls_back_to_classifier() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.31.0");

        let artifact = f
            .subject
            .metadata(&id("requests"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.license.as_deref(), Some("Apache Software License"));
    }

    /// PEP 658 first: the sidecar avoids downloading a wheel.
    #[tokio::test]
    async fn dependencies_from_metadata_sidecar() {
        let sidecar = "Metadata-Version: 2.1\n\
                       Name: requests\n\
                       Requires-Dist: charset-normalizer>=2,<4\n\
                       Requires-Dist: PySocks>=1.5.6; extra == \"socks\"\n";

        let client = FixtureClient::new()
            .with_body(format!("{INDEX}/simple/requests/"), SIMPLE)
            .with_body(
                "h://files.test/requests-2.31.0-py3-none-any.whl.metadata",
                sidecar,
            );

        let f = Fixture::build(client, |host| PyPiSource::new(INDEX, host));
        let ctx = ctx();

        let artifact = ResolvedArtifact {
            id: id("requests"),
            version: Some(f.subject.ecosystem.version("2.31.0")),
            files: Vec::new(),
            license: None,
            published: None,
        };

        let deps = f.subject.deps(&artifact, &ctx).await.expect("read");

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].id.name(), "charset-normalizer");
        assert_eq!(deps[0].kind, DepKind::Runtime);

        // An `extra ==` marker makes it optional, which is the only
        // distinction PyPI publishes.
        assert_eq!(deps[1].id.name(), "pysocks");
        assert_eq!(deps[1].kind, DepKind::Optional);
    }

    /// Without a sidecar the per-version JSON says the same thing.
    #[tokio::test]
    async fn dependencies_fall_back_to_json_endpoint() {
        let f = fixture();
        let ctx = ctx();

        let artifact = ResolvedArtifact {
            id: id("requests"),
            version: Some(f.subject.ecosystem.version("2.31.0")),
            files: Vec::new(),
            license: None,
            published: None,
        };

        let deps = f.subject.deps(&artifact, &ctx).await.expect("read");

        assert_eq!(deps.len(), 3);
        assert_eq!(deps[2].kind, DepKind::Optional);
    }

    /// A dynamic `setup.py` publishes nothing static.  Unresolvable without
    /// running arbitrary code, so it is reported rather than guessed at.
    #[tokio::test]
    async fn dependencies_without_static_metadata_reported() {
        const NO_METADATA: &str = r#"{"info": {"license": "MIT"}}"#;

        let client = FixtureClient::new()
            .with_body(
                format!("{INDEX}/simple/legacy/"),
                r#"{"versions":["1.0"],"files":[]}"#,
            )
            .with_body(format!("{INDEX}/pypi/legacy/1.0/json"), NO_METADATA);

        let f = Fixture::build(client, |host| PyPiSource::new(INDEX, host));
        let ctx = ctx();

        let artifact = ResolvedArtifact {
            id: id("legacy"),
            version: Some(f.subject.ecosystem.version("1.0")),
            files: Vec::new(),
            license: None,
            published: None,
        };

        let deps = f.subject.deps(&artifact, &ctx).await.expect("read");

        assert!(deps.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::DependencyMetadataDynamic], 1);
    }

    /// A 2012-era upload may offer only md5, which is verifiable but weak.
    #[tokio::test]
    async fn metadata_weak_only_digest_reported() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.30.0");

        f.subject
            .metadata(&id("requests"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert!(
            ctx.problems()
                .counts()
                .contains_key(&Code::SignatureMissing)
        );
    }

    #[tokio::test]
    async fn resolution_takes_highest_match() {
        let f = fixture();
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("requests"),
            spec: VersionSpec::Range(">=2.0,<3".into()),
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("2.31.0"));
    }

    /// Trimmed from what Nexus 3.41 answers to the PEP 691 header.
    const SIMPLE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><title>Links for echo</title></head>
<body><h1>Links for echo</h1>
    <a href="../../packages/echo/1.0/echo-1.0.tar.gz#sha256=aa" rel="internal">echo-1.0.tar.gz</a><br/>
    <a href="../../packages/echo/1.1/echo-1.1-py3-none-any.whl#sha256=bb" rel="internal" data-core-metadata="sha256=cc" data-requires-python="&gt;=3.13" >echo-1.1-py3-none-any.whl</a><br/>
</body>
</html>"#;

    fn html_fixture(body: &'static str) -> Fixture<PyPiSource> {
        Fixture::build(
            FixtureClient::new().with_body(format!("{INDEX}/simple/echo/"), body),
            |host| PyPiSource::new(INDEX, host),
        )
    }

    /// Versions come from the filenames, since HTML has no PEP 700 list.
    #[tokio::test]
    async fn index_html_yields_versions() {
        let f = html_fixture(SIMPLE_HTML);
        let ctx = ctx();

        let versions = f
            .subject
            .versions(&id("echo"), &ctx)
            .await
            .expect("fetched");
        let mut texts: Vec<&str> = versions.iter().map(Version::text).collect();
        texts.sort();

        assert_eq!(texts, ["1.0", "1.1"]);
    }

    /// The hash rides in the URL fragment, which the file URL drops.
    #[tokio::test]
    async fn index_html_yields_files() {
        let f = html_fixture(SIMPLE_HTML);
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.1");

        let artifact = f
            .subject
            .metadata(&id("echo"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.files.len(), 1);

        let wheel = &artifact.files[0];

        assert_eq!(wheel.name, "echo-1.1-py3-none-any.whl");
        assert_eq!(
            wheel.url,
            format!("{INDEX}/packages/echo/1.1/echo-1.1-py3-none-any.whl")
        );
        assert_eq!(wheel.digests, [Digest::new(DigestAlg::Sha256, "bb")]);
        assert_eq!(
            wheel.core_metadata,
            Some(vec![Digest::new(DigestAlg::Sha256, "cc")])
        );
    }

    /// PEP 740's `provenance` is recorded as an attestation signature,
    /// resolved against the index page like a file's own URL; a file
    /// without one carries none.
    #[tokio::test]
    async fn metadata_records_provenance() {
        let index = r#"{"versions": ["1.0"], "files": [
            {"filename": "echo-1.0.tar.gz", "url": "h://files.test/echo-1.0.tar.gz",
             "provenance": "../../integrity/echo/1.0/echo-1.0.tar.gz/provenance"},
            {"filename": "echo-1.0-py3-none-any.whl", "url": "h://files.test/echo-1.0-py3-none-any.whl",
             "provenance": null}
        ]}"#;
        let f = Fixture::build(
            FixtureClient::new().with_body(format!("{INDEX}/simple/echo/"), index),
            |host| PyPiSource::new(INDEX, host),
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id("echo"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(
            artifact.files[0].signatures,
            [SigRef {
                scheme: SigScheme::PypiAttestation,
                key_id: None,
                value: None,
                url: Some(format!(
                    "{INDEX}/integrity/echo/1.0/echo-1.0.tar.gz/provenance"
                )),
            }]
        );
        assert!(artifact.files[1].signatures.is_empty());
    }

    // -- Verifying attestations ---------------------------------------------

    const WHEEL: &str = "sampleproject-4.0.0-py3-none-any.whl";
    const WHEEL_SHA256: &str = "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b";
    const PROVENANCE: &str = include_str!("testdata/sampleproject-4.0.0-provenance.json");

    /// Verify the captured `sampleproject` wheel's attestations, served as
    /// `provenance`, with the file claiming `sha256`.
    async fn verified_with(sha256: &str, provenance: Canned) -> Ctx {
        let url = format!("{INDEX}/integrity/{WHEEL}/provenance");
        let f = Fixture::build(FixtureClient::new().with(&url, provenance), |host| {
            PyPiSource::new(INDEX, host).with_sigstore(Arc::new(sigstore::embedded()))
        });
        let ctx = ctx();

        let mut file = FileRef::new(WHEEL, format!("{INDEX}/files/{WHEEL}"));
        file.digests = vec![Digest::new(DigestAlg::Sha256, sha256)];
        file.signatures = vec![SigRef {
            scheme: SigScheme::PypiAttestation,
            key_id: None,
            value: None,
            url: Some(url),
        }];

        let artifact = ResolvedArtifact {
            id: id("sampleproject"),
            version: Some(f.subject.ecosystem.version("4.0.0")),
            files: vec![file],
            license: None,
            published: None,
        };

        let staged = tempfile::NamedTempFile::new().expect("temp");

        f.subject
            .verify(
                &artifact,
                &[staged.path().to_path_buf()],
                &crate::repo::Companions::default(),
                &ctx,
            )
            .await
            .expect("checked");

        ctx
    }

    /// A real attestation, signed by the publisher it names, passes
    /// without a word.
    #[tokio::test]
    async fn verify_accepts_real_attestation() {
        let ctx = verified_with(WHEEL_SHA256, Canned::ok(PROVENANCE)).await;

        assert!(
            ctx.problems().counts().is_empty(),
            "{:?}",
            ctx.problems().counts()
        );
    }

    /// Bytes the attestation does not cover are `signature-invalid`.
    #[tokio::test]
    async fn verify_refuses_other_bytes() {
        let ctx = verified_with(&"00".repeat(32), Canned::ok(PROVENANCE)).await;

        assert_eq!(ctx.problems().counts()[&Code::SignatureInvalid], 1);
    }

    /// Advertised and not served: nothing to check, which is reported as
    /// such rather than as a failed check.
    #[tokio::test]
    async fn verify_missing_provenance_is_unchecked() {
        let ctx = verified_with(WHEEL_SHA256, Canned::status(StatusCode::NOT_FOUND)).await;

        assert_eq!(ctx.problems().counts()[&Code::SignatureMissing], 1);
    }

    /// A served document that is not a provenance object is malformed
    /// metadata, not a signature verdict.
    #[tokio::test]
    async fn verify_reports_malformed_provenance() {
        let ctx = verified_with(WHEEL_SHA256, Canned::ok("not json")).await;

        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// The HTML form carries it as `data-provenance`.
    #[tokio::test]
    async fn index_html_records_provenance() {
        let f = html_fixture(
            r#"<a href="h://files.test/echo-1.0.tar.gz" data-provenance="h://files.test/p">echo-1.0.tar.gz</a>"#,
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id("echo"), Some(&version), &ctx)
            .await
            .expect("fetched");

        let urls: Vec<_> = artifact.files[0]
            .signatures
            .iter()
            .map(|signature| signature.url.as_deref())
            .collect();

        assert_eq!(urls, [Some("h://files.test/p")]);
    }

    /// A proxy's error page is HTML too, and lists no files.
    #[tokio::test]
    async fn index_html_without_files_malformed() {
        let f = html_fixture("<html>502 Bad Gateway</html>");
        let ctx = ctx();

        let err = f.subject.versions(&id("echo"), &ctx).await.unwrap_err();

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    #[tokio::test]
    async fn index_missing_project_reported_not_found() {
        let f = fixture();
        let ctx = ctx();

        let err = f.subject.versions(&id("ghost"), &ctx).await.unwrap_err();

        assert_eq!(err.code(), Code::ArtifactNotFound);
    }

    /// The index is three trait calls against one document.
    #[tokio::test]
    async fn index_fetched_once() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("2.31.0");

        f.subject
            .versions(&id("requests"), &ctx)
            .await
            .expect("fetched");
        f.subject
            .metadata(&id("requests"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(f.host.hits(&format!("{INDEX}/simple/requests/")), 1);
    }

    /// The same property under concurrency, which is where a
    /// check-then-fetch cache quietly stops working: many workers miss
    /// together and each issues its own request. The fixture is slow on
    /// purpose, or the calls would run one after another and prove nothing.
    #[tokio::test]
    async fn index_fetch_shared_by_concurrent_callers() {
        let url = format!("{INDEX}/simple/requests/");

        let f = Fixture::build(
            FixtureClient::new().with(
                url.clone(),
                Canned::ok(SIMPLE).slow(Duration::from_millis(25)),
            ),
            |host| PyPiSource::new(INDEX, host),
        );

        let ctx = ctx();
        let requests = id("requests");

        let waiting = (0..40).map(|_| f.subject.versions(&requests, &ctx));
        let results = futures::future::join_all(waiting).await;

        assert!(results.iter().all(|result| result.is_ok()));
        assert_eq!(f.host.hits(&url), 1);
    }
}
