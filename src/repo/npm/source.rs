//! Reading the npm registry: one packument answers every question.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use tokio::sync::OnceCell;

use super::keys::KeyList;
use super::packument::{Dist, License, Packument};
use crate::cache::Coalesced;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::{Companion, Ecosystem, Npm};
use crate::ext::ExtHost;
use crate::message;
use crate::model::{
    ArtifactId, DepKind, Dependency, EcosystemId, FileRef, ResolvedArtifact, SigRef, SigScheme,
    Version, VersionSpec,
};
use crate::net::sig;
use crate::net::{ByteLimit, Expectation, Req, encode_unreserved, normalized_base};
use crate::repo::{Downloaded, Source};
use crate::version::VersionHandler;

use super::{package_name, package_path, tarball_name};
/// Where the registry publishes the keys it signs with.
const KEYS_PATH: &str = "-/npm/v1/keys";

/// How a registry without the version document route answers it, measured
/// on Nexus 3.41: 400 for a scoped name, 404 for an unscoped one.
const ROUTE_MISSING: [StatusCode; 2] = [StatusCode::BAD_REQUEST, StatusCode::NOT_FOUND];

/// How many packuments to keep.
///
/// `versions`, `metadata` and `deps` are three calls against one document,
/// so a cache turns an artifact into one request instead of three.  Bounded
/// deliberately: artifact enumeration walks millions of packages and an
/// unbounded map keyed by name would grow with it.
const PACKUMENT_CACHE: usize = 64;

/// What a staged version document is named after its tarball's stem.
const MANIFEST_SUFFIX: &str = ".manifest.json";

pub struct NpmSource {
    base_url: String,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    ecosystem: Npm,

    /// Packuments already fetched, and those being fetched right now.
    ///
    /// npm's dependency graph converges hard -- one popular package sits
    /// under thousands of others -- so under a worker pool many tasks reach
    /// the same package at the same moment.  [`Coalesced`] makes that one
    /// request rather than one per task.
    cache: Coalesced<Packument>,

    /// Registry signing keys, fetched once.
    ///
    /// A plain `OnceCell` rather than a `Coalesced`, because a failure here
    /// is deliberately absorbed into "this registry publishes no keys" and
    /// so is worth remembering; re-asking a registry that has no keys, once
    /// per version, would be a request per artifact for nothing.
    keys: OnceCell<Arc<Vec<sig::RegistryKey>>>,

    /// Keys the user pinned in configuration.
    ///
    /// When this is non-empty the key endpoint is **not** consulted at all.
    /// A user pins keys because that endpoint is gone, unreachable, or not
    /// to be trusted to vouch for the artifacts it is also serving; calling
    /// it anyway would reintroduce the very failure they configured their
    /// way out of.
    pinned: Vec<sig::RegistryKey>,

    /// Each version document URL [`Source::companion`] named, to the
    /// package and version it is for, so [`Source::download`] can cut the
    /// document from the packument when the registry has no route for it.
    manifests: Mutex<HashMap<String, (ArtifactId, String)>>,
}

impl NpmSource {
    /// No HTTP client: every request goes through `host`, which is what
    /// confines it to the host it was configured for.
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: normalized_base(base_url),
            host,
            ecosystem: Npm,
            cache: Coalesced::new(PACKUMENT_CACHE),
            keys: OnceCell::new(),
            pinned: Vec::new(),
            manifests: Mutex::new(HashMap::new()),
        }
    }

    /// Verify against these keys instead of the registry's own.
    pub fn with_pinned_keys(mut self, keys: Vec<sig::RegistryKey>) -> Self {
        self.pinned = keys;
        self
    }

    /// The registry URL for a package; see [`package_path`].
    fn package_url(&self, id: &ArtifactId) -> String {
        format!("{}/{}", self.base_url, package_path(id))
    }

    async fn packument(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Arc<Packument>> {
        let url = self.package_url(id);

        self.cache
            .get_or_try_init(&url, || async {
                crate::ext::document_json(
                    &*self.host,
                    &Req::get(&url),
                    crate::ecosystem::PACKUMENT_DOCUMENT,
                    ByteLimit::PACKUMENT,
                    "npm packument",
                    ctx,
                )
                .await
            })
            .await
    }

    /// `id`'s version document as its packument carries it, staged as
    /// `file`.
    ///
    /// The packument comes from the cache `packument` filled, so this costs
    /// no request.  A version the packument lacks is [`Error::Absent`],
    /// which leaves the target to build a minimal manifest.
    async fn cut_manifest(
        &self,
        id: &ArtifactId,
        version: &str,
        file: &FileRef,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        let url = self.package_url(id);
        let packument: serde_json::Value = crate::ext::document_json(
            &*self.host,
            &Req::get(&url),
            crate::ecosystem::PACKUMENT_DOCUMENT,
            ByteLimit::PACKUMENT,
            "npm packument",
            ctx,
        )
        .await?;

        let Some(entry) = packument.get("versions").and_then(|v| v.get(version)) else {
            return Err(Error::Absent {
                what: "version",
                url,
                name: version.to_owned(),
            });
        };

        let body = serde_json::to_vec(entry).map_err(|err| Error::Malformed {
            what: "npm packument",
            url: url.clone(),
            detail: err.to_string(),
        })?;

        crate::repo::stage(&*self.host, file, &body, ctx).await
    }

    /// The keys this source verifies against.
    ///
    /// Pinned keys win outright -- see [`NpmSource::pinned`]. Otherwise the
    /// registry's own endpoint is asked, at most once.
    ///
    /// A registry that publishes none is not an error: private registries
    /// and most proxies do not sign at all.
    async fn keys(&self, ctx: &Ctx) -> Arc<Vec<sig::RegistryKey>> {
        if !self.pinned.is_empty() {
            return Arc::new(self.pinned.clone());
        }

        let fetch = || async {
            let url = format!("{}/{KEYS_PATH}", self.base_url);

            let fetched = match self
                .host
                .fetch(&Req::get(&url), ByteLimit::kib(64), ctx)
                .await
            {
                Ok(body) => serde_json::from_slice::<KeyList>(&body)
                    .map(|list| list.keys)
                    .unwrap_or_default(),

                Err(_) => Vec::new(),
            };

            Arc::new(
                fetched
                    .into_iter()
                    .map(|key| sig::RegistryKey::published(key.keyid, key.key))
                    .collect::<Vec<_>>(),
            )
        };

        Arc::clone(self.keys.get_or_init(fetch).await)
    }

    /// Check a version's `dist.signatures`, recording what was found.
    ///
    /// Verifiable without the tarball, because the signature covers the
    /// integrity hash rather than the bytes.
    async fn check_signatures(
        &self,
        id: &ArtifactId,
        version: &str,
        dist: &Dist,
        ctx: &Ctx,
    ) -> Vec<SigRef> {
        let Some(integrity) = &dist.integrity else {
            return Vec::new();
        };

        if dist.signatures.is_empty() {
            report_unsigned(id, version, ctx);
            return Vec::new();
        }

        let keys = self.keys(ctx).await;
        let name = package_name(id);
        let mut out = Vec::new();

        for entry in &dist.signatures {
            let outcome =
                sig::verify_npm(&name, version, integrity, &entry.keyid, &entry.sig, &keys);

            report_outcome(id, version, &entry.keyid, outcome, ctx);

            out.push(SigRef {
                scheme: SigScheme::NpmEcdsa,
                key_id: Some(entry.keyid.clone()),
                value: Some(entry.sig.clone()),
                url: None,
            });
        }

        out
    }
}

/// Report a version with an integrity and no registry signature over it.
fn report_unsigned(id: &ArtifactId, version: &str, ctx: &Ctx) {
    ctx.report(
        Code::SignatureMissing,
        message!(
            "npm-unsigned-version",
            "{purl} carries no registry signature",
            purl = id.purl_at(version),
        ),
    );
}

/// Report every verdict on one signature but a valid one.
fn report_outcome(
    id: &ArtifactId,
    version: &str,
    key: &str,
    outcome: Result<sig::SigOutcome>,
    ctx: &Ctx,
) {
    match outcome {
        Ok(sig::SigOutcome::Valid) => {}

        Ok(sig::SigOutcome::UntrustedKey(reason)) => {
            ctx.report(
                sig::code_for(reason),
                message!(
                    "npm-untrusted-signing-key",
                    "{purl} is signed with key {key}, which is \
                     {reason} and may not vouch for it",
                    purl = id.purl_at(version),
                    key = key,
                    reason = reason.as_str(),
                ),
            );
        }

        Ok(sig::SigOutcome::UnknownKey) => {
            ctx.report(
                Code::SignatureMissing,
                message!(
                    "npm-unpublished-signing-key",
                    "{purl} is signed with key {key}, which this \
                     registry does not publish",
                    purl = id.purl_at(version),
                    key = key,
                ),
            );
        }

        Err(err) => {
            ctx.report(
                Code::SignatureInvalid,
                message!(
                    "npm-signature-invalid",
                    "{purl}: {reason}",
                    purl = id.purl_at(version),
                    reason = &err,
                ),
            );
        }
    }
}

#[async_trait]
impl Source for NpmSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![self.ecosystem.id()]
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let packument = self.packument(id, ctx).await?;

        Ok(packument
            .versions
            .keys()
            .map(|text| self.ecosystem.version(text))
            .collect())
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let version = crate::repo::version_required(id, version)?;
        let packument = self.packument(id, ctx).await?;

        let entry = packument
            .versions
            .get(version.text())
            .ok_or_else(|| Error::Absent {
                what: "version",
                url: self.package_url(id),
                name: version.text().to_owned(),
            })?;

        let mut files = Vec::new();

        if let Some(dist) = &entry.dist {
            let mut file = FileRef::new(
                tarball_name(id, version.text()),
                dist.tarball.clone().unwrap_or_default(),
            );

            file.digests = dist.digests();

            file.signatures = self.check_signatures(id, version.text(), dist, ctx).await;

            files.push(file);
        }

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: Some(version.clone()),
            files,
            license: entry
                .license
                .as_ref()
                .and_then(License::text)
                .or_else(|| entry.licenses.first().and_then(|l| l.type_name.clone()))
                .or_else(|| packument.license.as_ref().and_then(License::text)),
            published: packument
                .time
                .get(version.text())
                .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
                .map(|stamp| stamp.with_timezone(&Utc)),
        })
    }

    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        let packument = self.packument(&artifact.id, ctx).await?;

        // A packument is keyed by version, so an artifact without one has
        // no entry to read dependencies from. npm always has a version, so
        // this is the incoherent-request case rather than a real artifact.
        let Some(version) = &artifact.version else {
            return Ok(Vec::new());
        };

        let Some(entry) = packument.versions.get(version.text()) else {
            return Ok(Vec::new());
        };

        let mut out = Vec::new();

        let groups: [(&BTreeMap<String, String>, DepKind); 4] = [
            (&entry.dependencies, DepKind::Runtime),
            (&entry.dev_dependencies, DepKind::Dev),
            (&entry.optional_dependencies, DepKind::Optional),
            (&entry.peer_dependencies, DepKind::Peer),
        ];

        for (group, kind) in groups {
            for (name, range) in group {
                // A peer marked optional is optional first: it is the
                // weaker obligation, and treating it as a hard peer would
                // pull in packages npm itself would not install.
                let kind = match kind {
                    DepKind::Peer if entry.is_optional_peer(name) => DepKind::Optional,
                    other => other,
                };

                out.push(dependency(name, range, kind));
            }
        }

        Ok(out)
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        let fetched = crate::repo::download(&*self.host, file, expect, ctx).await;

        // A registry without the version document route: fall back to the
        // packument's entry, which is the same document.
        let Err(Error::HttpStatus { status, .. }) = &fetched else {
            return fetched;
        };

        if !ROUTE_MISSING.contains(status) {
            return fetched;
        }

        let named = self
            .manifests
            .lock()
            .ok()
            .and_then(|named| named.get(&file.url).cloned());

        let Some((id, version)) = named else {
            return fetched;
        };

        self.cut_manifest(&id, &version, file, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.host.permits(url)
    }

    /// The version document, `{registry}/{name}/{version}`, which no file
    /// advertises. Unchecked: a registry publishes no digest for it, and
    /// the target checks its `dist` against the tarball instead.
    ///
    /// The scope's `@` and `/` stay literal: Artifact Keeper answers 400 to
    /// `%2f` and 404 to `%40` on this route, and Nexus answers either
    /// spelling (measured).  Nexus 3.41 has no such route (400 scoped, 404
    /// unscoped); [`Source::download`] then cuts the document from the
    /// packument.
    fn companion(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        kind: Companion,
    ) -> Option<(FileRef, Expectation)> {
        if kind != Companion::PackageManifest {
            return crate::repo::companion::advertised(file, kind);
        }

        let version = artifact.version.as_ref()?.text();

        // `@scope/name/1.0.0`: the `@` and `/` literal, each part escaped.
        let scope = artifact
            .id
            .namespace()
            .map(|scope| format!("@{}/", encode_unreserved(scope.trim_start_matches('@'))))
            .unwrap_or_default();

        let document = FileRef::new(
            format!("{}-{version}{MANIFEST_SUFFIX}", artifact.id.name()),
            format!(
                "{}/{scope}{}/{}",
                self.base_url,
                encode_unreserved(artifact.id.name()),
                encode_unreserved(version)
            ),
        );

        if let Ok(mut named) = self.manifests.lock() {
            named.insert(
                document.url.clone(),
                (artifact.id.clone(), version.to_owned()),
            );
        }

        Some((document, Expectation::new()))
    }
}

fn dependency(name: &str, range: &str, kind: DepKind) -> Dependency {
    let (namespace, bare) = match name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((scope, bare)) => (Some(format!("@{scope}")), bare),
        None => (None, name),
    };

    Dependency {
        id: ArtifactId::new(EcosystemId::npm(), namespace.as_deref(), bare),
        spec: match range {
            "" | "*" | "latest" => VersionSpec::Any,
            other => VersionSpec::Range(other.to_owned()),
        },
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UnknownPublishTime;
    use crate::core::ctx::Ctx;
    use crate::core::problem::Quarantine;
    use crate::ext::testing::{Fixture, TestHost};
    use crate::model::{ArtifactRequest, Cause};
    use crate::net::{Canned, FixtureClient};
    use crate::repo::Criteria;
    use crate::version::{PreRelease, VersionHandler};
    use std::time::Duration;

    const REGISTRY: &str = "h://registry.test";

    /// The version document's URL keeps a scope's `@` and `/` literal,
    /// which Artifact Keeper needs and Nexus accepts.
    #[test]
    fn manifest_companion_url() {
        let source = NpmSource::new(REGISTRY, crate::ext::testing::idle());
        let at = |namespace: Option<&str>, name: &str| ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::npm(), namespace, name),
            version: Some(Version::new("1.0.0", crate::model::Release::General)),
            files: Vec::new(),
            license: None,
            published: None,
        };
        let tarball = FileRef::new("echo-1.0.0.tgz", "h://registry.test/echo-1.0.0.tgz");

        let url = |artifact: &ResolvedArtifact| {
            source
                .companion(artifact, &tarball, Companion::PackageManifest)
                .expect("named")
                .0
                .url
        };

        assert_eq!(
            url(&at(Some("@am-example"), "echo")),
            "h://registry.test/@am-example/echo/1.0.0"
        );
        assert_eq!(url(&at(None, "lodash")), "h://registry.test/lodash/1.0.0");

        // Not advertised on the tarball, so PyPI's kinds name nothing.
        assert!(
            source
                .companion(&at(None, "lodash"), &tarball, Companion::CoreMetadata)
                .is_none()
        );
    }

    /// A packument whose one version carries what only the version
    /// document would otherwise give: `engines`.
    const ECHO: &str = r#"{
        "name": "@am-example/echo",
        "versions": {"1.0.0": {"name": "@am-example/echo", "version": "1.0.0",
                               "engines": {"node": ">=18"}}}
    }"#;

    const ECHO_PACKUMENT: &str = "h://registry.test/@am-example%2fecho";
    const ECHO_MANIFEST: &str = "h://registry.test/@am-example/echo/1.0.0";

    fn echo(version: &str) -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::npm(), Some("@am-example"), "echo"),
            version: Some(Version::new(version, crate::model::Release::General)),
            files: Vec::new(),
            license: None,
            published: None,
        }
    }

    /// Fetch `artifact`'s version document from a registry answering its
    /// route with `status`.
    async fn manifest(
        artifact: &ResolvedArtifact,
        status: StatusCode,
    ) -> Result<serde_json::Value> {
        let f = repo(
            FixtureClient::new()
                .with_body(ECHO_PACKUMENT, ECHO)
                .with(ECHO_MANIFEST, Canned::status(status)),
        );
        let tarball = FileRef::new("echo-1.0.0.tgz", "h://registry.test/echo-1.0.0.tgz");
        let (document, expect) = f
            .subject
            .companion(artifact, &tarball, Companion::PackageManifest)
            .expect("named");

        let staged = f.subject.download(&document, &expect, &ctx()).await?;
        let body = std::fs::read(&staged.path).expect("staged");

        Ok(serde_json::from_slice(&body).expect("json"))
    }

    /// Nexus 3.41 answers a scoped version document with 400.
    #[tokio::test]
    async fn manifest_falls_back_on_400() {
        let document = manifest(&echo("1.0.0"), StatusCode::BAD_REQUEST)
            .await
            .expect("staged");

        assert_eq!(document["engines"]["node"], ">=18");
    }

    #[tokio::test]
    async fn manifest_falls_back_on_404() {
        let document = manifest(&echo("1.0.0"), StatusCode::NOT_FOUND)
            .await
            .expect("staged");

        assert_eq!(document["version"], "1.0.0");
    }

    /// Only a missing route falls back; a refusal stays a failure.
    #[tokio::test]
    async fn manifest_other_errors_propagate() {
        let err = manifest(&echo("1.0.0"), StatusCode::FORBIDDEN)
            .await
            .expect_err("refused");

        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::FORBIDDEN,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn manifest_missing_version_is_absent() {
        let err = manifest(&echo("2.0.0"), StatusCode::BAD_REQUEST)
            .await
            .expect_err("absent");

        assert_eq!(err.code(), Code::ArtifactNotFound);
    }

    /// A packument with the shapes that actually matter: a modern license, a
    /// legacy `licenses` array, a pre-release, and a signed `dist`.
    const LODASH: &str = r#"{
        "name": "lodash",
        "dist-tags": {"latest": "4.17.21"},
        "license": "MIT",
        "time": {
            "created": "2012-04-23T16:37:11.912Z",
            "modified": "2021-02-20T15:42:16.891Z",
            "4.17.20": "2020-08-13T16:53:54.008Z",
            "4.17.21": "2021-02-20T15:42:16.891Z",
            "5.0.0-rc.1": "2021-03-01T00:00:00.000Z"
        },
        "versions": {
            "4.17.20": {
                "license": "MIT",
                "dist": {
                    "tarball": "h://registry.test/lodash/-/lodash-4.17.20.tgz",
                    "shasum": "b4b1e4d7c1b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
                },
                "dependencies": {}
            },
            "4.17.21": {
                "license": "MIT",
                "dist": {
                    "tarball": "h://registry.test/lodash/-/lodash-4.17.21.tgz",
                    "shasum": "679591c564c3bffaae8454cf0b3df370c3d6911c",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
                    "signatures": [
                        {"keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
                         "sig": "MEUCIQDXjoxQ"}
                    ]
                },
                "dependencies": {"tiny": "^1.0.0"},
                "devDependencies": {"tester": "^2.0.0"},
                "peerDependencies": {"host": ">=3", "soft-host": "^1"},
                "peerDependenciesMeta": {"soft-host": {"optional": true}}
            },
            "5.0.0-rc.1": {
                "licenses": [{"type": "MIT", "url": "http://mths.be/mit"}],
                "dist": {
                    "tarball": "h://registry.test/lodash/-/lodash-5.0.0-rc.1.tgz",
                    "shasum": "aaaa"
                }
            }
        }
    }"#;

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "lodash".into(),
        })
    }

    /// A source plus the host it is confined to.  They travel together
    /// because a source is useless without one -- which is the design, not
    /// an inconvenience.
    fn repo(client: FixtureClient) -> Fixture<NpmSource> {
        Fixture::build(client, |host| NpmSource::new(REGISTRY, host))
    }

    fn lodash_repo() -> Fixture<NpmSource> {
        repo(FixtureClient::new().with_body(format!("{REGISTRY}/lodash"), LODASH))
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, name)
    }

    #[tokio::test]
    async fn versions_from_packument() {
        let f = lodash_repo();
        let ctx = ctx();
        let versions = f
            .subject
            .versions(&id("lodash"), &ctx)
            .await
            .expect("fetched");

        assert_eq!(versions.len(), 3);
        assert!(versions.iter().any(|v| v.text() == "4.17.21"));
    }

    /// A pre-release must be flagged, or `--pre-release` cannot filter it.
    #[tokio::test]
    async fn pre_releases_flagged() {
        let f = lodash_repo();
        let ctx = ctx();
        let versions = f
            .subject
            .versions(&id("lodash"), &ctx)
            .await
            .expect("fetched");

        let rc = versions
            .iter()
            .find(|v| v.text() == "5.0.0-rc.1")
            .expect("present");

        assert!(rc.is_pre_release());
    }

    #[tokio::test]
    async fn metadata_carries_license_time_and_digests() {
        let f = lodash_repo();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.license.as_deref(), Some("MIT"));
        assert_eq!(
            artifact.published.unwrap().to_rfc3339(),
            "2021-02-20T15:42:16.891+00:00"
        );

        let file = &artifact.files[0];
        assert_eq!(file.name, "lodash-4.17.21.tgz");
        assert!(file.has_strong_digest());
    }

    /// `lodash` only gained a singular `license` at 3.0.0; before that it
    /// carried a `licenses` array.
    #[tokio::test]
    async fn license_legacy_array_read() {
        let f = lodash_repo();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("5.0.0-rc.1");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.license.as_deref(), Some("MIT"));
    }

    /// A 2015-era version offers only sha1, which is verifiable but weak.
    #[tokio::test]
    async fn shasum_only_weakly_verified() {
        let f = lodash_repo();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.20");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert!(!artifact.files[0].has_strong_digest());
        assert!(artifact.files[0].best_digest().is_some());
    }

    #[tokio::test]
    async fn dependencies_tagged_by_kind() {
        let f = lodash_repo();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        let deps = f.subject.deps(&artifact, &ctx).await.expect("read");

        let by_name = |name: &str| {
            deps.iter()
                .find(|d| d.id.name() == name)
                .unwrap_or_else(|| panic!("{name} missing"))
                .kind
        };

        assert_eq!(by_name("tiny"), DepKind::Runtime);
        assert_eq!(by_name("tester"), DepKind::Dev);
        assert_eq!(by_name("host"), DepKind::Peer);

        // An optional peer is the weaker obligation; npm would not install
        // it, so neither should the spider treat it as a hard peer.
        assert_eq!(by_name("soft-host"), DepKind::Optional);
    }

    #[tokio::test]
    async fn resolution_takes_highest_match() {
        let f = lodash_repo();
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("lodash"),
            spec: VersionSpec::Range("^4.0.0".into()),
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("4.17.21"));
    }

    /// A package that has only ever published pre-releases.  Nothing at all
    /// resolves without `--pre-release`, which is precisely when suggesting
    /// it is useful.
    const ALPHA_ONLY: &str = r#"{
        "name": "alpha-only",
        "license": "MIT",
        "time": {"1.0.0-alpha.1": "2024-01-01T00:00:00.000Z"},
        "versions": {
            "1.0.0-alpha.1": {
                "license": "MIT",
                "dist": {
                    "tarball": "h://registry.test/alpha-only/-/alpha-only-1.0.0-alpha.1.tgz",
                    "shasum": "bbbb"
                }
            }
        }
    }"#;

    fn alpha_repo() -> Fixture<NpmSource> {
        repo(FixtureClient::new().with_body(format!("{REGISTRY}/alpha-only"), ALPHA_ONLY))
    }

    /// Where `--pre-release` genuinely would have helped, the failure says
    /// so rather than just reporting "not found".
    #[tokio::test]
    async fn resolution_unsatisfiable_suggests_pre_release() {
        let f = alpha_repo();
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("alpha-only"),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        };

        let err = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("--pre-release"));
        assert_eq!(ctx.problems().counts()[&Code::VersionUnresolvable], 1);
    }

    /// `^5.0.0` excludes `5.0.0-rc.1` on semver's own terms, not because
    /// pre-releases were filtered out.  Suggesting a flag that would change
    /// nothing sends the user down a blind alley.
    #[tokio::test]
    async fn resolution_range_excluding_on_own_terms_suggests_nothing() {
        let f = lodash_repo();
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("lodash"),
            spec: VersionSpec::Range("^5.0.0".into()),
            prov: ctx.prov().clone(),
        };

        let err = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .unwrap_err();

        assert!(!err.to_string().contains("--pre-release"));
    }

    #[tokio::test]
    async fn resolution_pre_release_finds_candidate() {
        let f = alpha_repo();
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("alpha-only"),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Include), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("1.0.0-alpha.1"));
    }

    /// Three trait calls against one document must cost one request.  The
    /// packument carries versions, metadata and dependencies alike, so
    /// fetching it three times would treble the cost of every artifact.
    #[tokio::test]
    async fn packument_fetched_once() {
        let f = lodash_repo();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        f.subject
            .versions(&id("lodash"), &ctx)
            .await
            .expect("fetched");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        f.subject.deps(&artifact, &ctx).await.expect("read");

        assert_eq!(f.host.hits(&format!("{REGISTRY}/lodash")), 1);
    }

    /// The property a sequential test cannot show.
    ///
    /// npm's graph converges hard: under a worker pool, many tasks reach the
    /// same package within milliseconds of each other. A check-then-fetch
    /// cache misses for all of them and issues a request each, so `lodash`
    /// would be fetched once per dependent rather than once. The fixture is
    /// deliberately slow, or the calls would simply run one after another
    /// and the test would pass without proving anything.
    #[tokio::test]
    async fn packument_fetch_shared_by_concurrent_callers() {
        let url = format!("{REGISTRY}/lodash");

        let f = repo(FixtureClient::new().with(
            url.clone(),
            Canned::ok(LODASH).slow(Duration::from_millis(25)),
        ));

        let ctx = ctx();

        let lodash = id("lodash");

        let waiting = (0..40).map(|_| f.subject.versions(&lodash, &ctx));
        let results = futures::future::join_all(waiting).await;

        assert!(results.iter().all(|result| result.is_ok()));

        // Forty dependents, one request.
        assert_eq!(f.host.hits(&url), 1);
    }

    /// A built-in source holds no HTTP client, so the only way out is its
    /// host -- and the host refuses a URL it was not configured for.
    /// This is what makes "even built-ins go through the host" a property
    /// rather than a promise.
    #[tokio::test]
    async fn source_cannot_reach_unconfigured_host() {
        let elsewhere = "h://evil.test/lodash";

        let host = Arc::new(TestHost::allowing(
            FixtureClient::new()
                .with_body(format!("{REGISTRY}/lodash"), LODASH)
                .with_body(elsewhere, LODASH),
            "h://other.test/",
        ));

        let source = NpmSource::new(REGISTRY, host.clone());
        let ctx = ctx();

        let err = source.versions(&id("lodash"), &ctx).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("outside what this extension may fetch")
        );
        assert_eq!(host.hits(&format!("{REGISTRY}/lodash")), 0);
    }

    // -- Versionless requests and the publish window -----------------------

    /// The quality-of-life case: a bare name with no version resolves to
    /// the newest acceptable version rather than being refused.
    #[tokio::test]
    async fn resolution_versionless_takes_newest() {
        let f = lodash_repo();
        let ctx = ctx();

        // Exactly what `parse_req("lodash")` produces.
        let request = Npm.parse_req("lodash").expect("parses");
        assert_eq!(request.spec, VersionSpec::Any);

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        // The newest GA, not the newest overall -- 5.0.0-rc.1 is excluded.
        assert_eq!(artifact.version_text(), Some("4.17.21"));
    }

    #[tokio::test]
    async fn resolution_versionless_honors_pre_release() {
        let f = lodash_repo();
        let ctx = ctx();
        let request = Npm.parse_req("lodash").expect("parses");

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Include), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("5.0.0-rc.1"));
    }

    /// The window cannot be applied during selection, because publish time
    /// is not in the version list. A too-recent version therefore steps
    /// down to the next newest instead of failing the request.
    #[tokio::test]
    async fn window_too_recent_steps_down_to_older() {
        let f = lodash_repo();
        let ctx = ctx();
        let request = Npm.parse_req("lodash").expect("parses");

        // 4.17.21 was published 2021-02-20 and 4.17.20 in 2020-08-13, so a
        // window anchored between them excludes exactly the newer one.
        let since_older = (Utc::now()
            - DateTime::parse_from_rfc3339("2020-12-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc))
        .to_std()
        .expect("positive");

        let artifact = f
            .subject
            .resolve(
                &request,
                Criteria::new(PreRelease::Exclude).minimum_age(since_older),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("4.17.20"));
        assert_eq!(ctx.problems().counts()[&Code::PublishTooRecent], 1);
    }

    /// An unknown publish time is the user's decision, and `refuse` is the
    /// default: the artifact cannot be *shown* to satisfy the window.
    #[tokio::test]
    async fn window_unknown_publish_time_refused_by_default() {
        const UNDATED: &str = r#"{
            "name": "undated",
            "license": "MIT",
            "versions": {
                "1.0.0": {
                    "license": "MIT",
                    "dist": {"tarball": "h://registry.test/x.tgz", "shasum": "aa"}
                }
            }
        }"#;

        let f = repo(FixtureClient::new().with_body(format!("{REGISTRY}/undated"), UNDATED));
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("undated"),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        };

        let err = f
            .subject
            .resolve(
                &request,
                Criteria::new(PreRelease::Exclude).minimum_age(Duration::from_secs(60)),
                &ctx,
            )
            .await
            .expect_err("nothing can satisfy the window");

        // Not `metadata-malformed`: nothing is wrong with the packument.
        // The repository answered clearly and no version it holds fits.
        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert!(ctx.problems().counts()[&Code::PublishTooRecent] >= 1);
    }

    /// The two window failures must stay **distinguishable**, which is the
    /// whole reason they are separate message ids rather than one.
    ///
    /// "This version is too new" and "this repository does not say when
    /// anything was published" call for completely different responses:
    /// wait, versus set `unknown-publish-time: allow`. A report that
    /// rendered both as `publish-too-recent` would send a user looking for
    /// a timestamp that was never there.
    ///
    /// They share a `Code`, because the *action* is the same -- skip the
    /// artifact -- and the code drives the action table. The id is what
    /// carries the diagnosis.
    #[tokio::test]
    async fn window_failures_carry_different_message_ids() {
        const UNDATED: &str = r#"{
            "name": "undated",
            "license": "MIT",
            "versions": {
                "1.0.0": {
                    "license": "MIT",
                    "dist": {"tarball": "h://registry.test/x.tgz", "shasum": "aa"}
                }
            }
        }"#;

        let window = Criteria::new(PreRelease::Exclude).minimum_age(Duration::from_secs(60));

        // A dated packument whose only version is far too recent.
        let dated = lodash_repo();
        let dated_ctx = ctx();

        let _ = dated
            .subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                Criteria::new(PreRelease::Exclude)
                    .minimum_age(Duration::from_secs(60 * 60 * 24 * 365 * 100)),
                &dated_ctx,
            )
            .await;

        // An undated one, where the window cannot be evaluated at all.
        let undated = repo(FixtureClient::new().with_body(format!("{REGISTRY}/undated"), UNDATED));
        let undated_ctx = ctx();

        let _ = undated
            .subject
            .resolve(
                &ArtifactRequest {
                    id: id("undated"),
                    spec: VersionSpec::Any,
                    prov: undated_ctx.prov().clone(),
                },
                window,
                &undated_ctx,
            )
            .await;

        let ids = |ctx: &Ctx| -> Vec<String> {
            ctx.problems()
                .tail()
                .iter()
                .map(|problem| problem.message().id.clone())
                .collect()
        };

        assert!(
            ids(&dated_ctx).contains(&"publish-too-recent".to_owned()),
            "{:?}",
            ids(&dated_ctx)
        );
        assert!(
            ids(&undated_ctx).contains(&"publish-time-unknown".to_owned()),
            "{:?}",
            ids(&undated_ctx)
        );

        // And neither reports the other's diagnosis.
        assert!(!ids(&dated_ctx).contains(&"publish-time-unknown".to_owned()));
        assert!(!ids(&undated_ctx).contains(&"publish-too-recent".to_owned()));
    }

    /// The other half of the same decision: a repository known not to
    /// report publish times can be told to allow them, so that a window
    /// meant for the sources that *do* report does not refuse everything
    /// from the ones that do not.
    #[tokio::test]
    async fn window_unknown_publish_time_allowed() {
        const UNDATED: &str = r#"{
            "name": "undated",
            "license": "MIT",
            "versions": {
                "1.0.0": {
                    "license": "MIT",
                    "dist": {"tarball": "h://registry.test/x.tgz", "shasum": "aa"}
                }
            }
        }"#;

        let f = repo(FixtureClient::new().with_body(format!("{REGISTRY}/undated"), UNDATED));
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("undated"),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(
                &request,
                Criteria::new(PreRelease::Exclude)
                    .minimum_age(Duration::from_secs(60))
                    .unknown_publish_time(UnknownPublishTime::Allow),
                &ctx,
            )
            .await
            .expect("allowed");

        assert_eq!(artifact.version_text(), Some("1.0.0"));
        assert!(
            !ctx.problems()
                .counts()
                .contains_key(&Code::PublishTooRecent)
        );
    }

    /// With no window configured, nothing steps down and no problem is
    /// raised -- the feature is opt-in.
    #[tokio::test]
    async fn window_absent_no_step_down() {
        let f = lodash_repo();
        let ctx = ctx();
        let request = Npm.parse_req("lodash").expect("parses");

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("4.17.21"));
        assert!(
            !ctx.problems()
                .counts()
                .contains_key(&Code::PublishTooRecent)
        );
    }

    // -- A quarantine rule may excuse the window ---------------------------

    /// A window nothing can satisfy, so every acceptance below is the rule's
    /// doing rather than the clock's.
    fn unsatisfiable_window() -> Criteria {
        Criteria::new(PreRelease::Exclude)
            .minimum_age(Duration::from_secs(60 * 60 * 24 * 365 * 100))
    }

    /// A context whose quarantine policy answers `class` for
    /// `publish-too-recent` on `purl`.
    ///
    /// `collecting` because that is what a real walk does before
    /// resolution (see `Ctx::collecting`), and without it a kept
    /// reservation has nowhere to go.
    fn excusing(purl: &str, class: &str) -> Ctx {
        let policy: crate::policy::QuarantinePolicy = serde_json::from_str(&format!(
            r#"{{"rules":[{{"purl":"{purl}","codes":["publish-too-recent"],
                 "class":"{class}","justification":"patch for a critical CVE",
                 "expires":"never"}}]}}"#
        ))
        .expect("parses");

        let dispositions = crate::policy::Dispositions::new(
            crate::core::problem::Policy::default(),
            [policy],
            crate::policy::Hardening::Off,
        );

        ctx()
            .deciding_with(std::sync::Arc::new(dispositions))
            .collecting()
    }

    /// **The case the excuse exists for.** Log4Shell is disclosed, a patch
    /// is published, and a team takes that one artifact before the window
    /// has run. See `repo::resolve` for why this reuses the quarantine file
    /// rather than growing a second mechanism.
    #[tokio::test]
    async fn window_excused_by_quarantine_rule() {
        let f = lodash_repo();
        let ctx = excusing("pkg:npm/lodash", "soft");

        let artifact = f
            .subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                unsatisfiable_window(),
                &ctx,
            )
            .await
            .expect("the rule excused the window");

        // The version the window refused, not an older one stepped down to.
        assert_eq!(artifact.version_text(), Some("4.17.21"));
    }

    /// Taking it silently would be worse than refusing it: the report has
    /// to say the window was broken and who said it could be.
    #[tokio::test]
    async fn window_excused_still_reported() {
        let f = lodash_repo();
        let ctx = excusing("pkg:npm/lodash", "soft");

        f.subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                unsatisfiable_window(),
                &ctx,
            )
            .await
            .expect("excused");

        assert_eq!(
            ctx.problems().counts()[&Code::PublishTooRecent],
            1,
            "reported once, for the version that was taken"
        );

        let problem = ctx
            .problems()
            .tail()
            .into_iter()
            .find(|problem| problem.code() == Code::PublishTooRecent)
            .expect("a problem line");

        let bypass = problem.bypass().expect("the rule that answered");

        assert_eq!(
            bypass.justification.as_deref(),
            Some("patch for a critical CVE")
        );

        // `soft` keeps it as a reservation, so it reaches
        // `ArtifactRecord.quarantine` and not only the problem line.
        assert_eq!(problem.quarantine(), Some(Quarantine::Soft));
    }

    /// `allowed` takes the artifact too, and is the stronger statement: it
    /// leaves no reservation, which is what makes it survive `--harden`.
    #[tokio::test]
    async fn window_excused_by_allowed_rule_without_reservation() {
        let f = lodash_repo();
        let ctx = excusing("pkg:npm/lodash", "allowed");

        let artifact = f
            .subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                unsatisfiable_window(),
                &ctx,
            )
            .await
            .expect("excused");

        assert_eq!(artifact.version_text(), Some("4.17.21"));

        let problem = ctx
            .problems()
            .tail()
            .into_iter()
            .find(|problem| problem.code() == Code::PublishTooRecent)
            .expect("still reported");

        assert_eq!(problem.quarantine(), None);
        assert!(problem.bypass().is_some(), "and still names the rule");
    }

    /// `soft` means *this run is not strict*, so a strict one refuses again.
    /// A team wanting the exception to hold under `--harden` writes
    /// `allowed`.
    #[tokio::test]
    async fn window_soft_excuse_taken_back_by_hardening() {
        let f = lodash_repo();

        let policy: crate::policy::QuarantinePolicy = serde_json::from_str(
            r#"{"rules":[{"purl":"pkg:npm/lodash","codes":["publish-too-recent"],
                 "class":"soft","expires":"never"}]}"#,
        )
        .expect("parses");

        let ctx = ctx()
            .deciding_with(std::sync::Arc::new(crate::policy::Dispositions::new(
                crate::core::problem::Policy::default(),
                [policy],
                crate::policy::Hardening::On,
            )))
            .collecting();

        let err = f
            .subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                unsatisfiable_window(),
                &ctx,
            )
            .await
            .expect_err("hardened back into a refusal");

        assert_eq!(err.code(), Code::VersionUnresolvable);
    }

    /// The excuse is per artifact, which is the whole point of the file: a
    /// rule about one package must not open the window for another.
    #[tokio::test]
    async fn window_not_excused_by_other_artifacts_rule() {
        let f = lodash_repo();
        let ctx = excusing("pkg:npm/salmon", "soft");

        let err = f
            .subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                unsatisfiable_window(),
                &ctx,
            )
            .await
            .expect_err("nothing excused lodash");

        assert_eq!(err.code(), Code::VersionUnresolvable);
    }

    /// Without a rule the window is unchanged: it steps down through the
    /// candidates and then gives up. The excuse must not have turned the
    /// window into a warning for everybody.
    #[tokio::test]
    async fn window_refuses_without_rule() {
        let f = lodash_repo();
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &Npm.parse_req("lodash").expect("parses"),
                unsatisfiable_window(),
                &ctx,
            )
            .await
            .expect_err("the window still applies");

        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert!(
            ctx.problems().counts()[&Code::PublishTooRecent] > 1,
            "and it stepped down rather than refusing the first candidate"
        );
    }

    // -- Pinned signing keys ----------------------------------------------

    /// The case the configuration exists for: the key endpoint is gone, so
    /// asking it would fail. A pinned key means verification still happens.
    #[tokio::test]
    async fn keys_pinned_replace_registry_endpoint() {
        // The endpoint is deliberately absent from the fixture -- a 404,
        // exactly as a retired PKI would answer.
        let f = Fixture::build(
            FixtureClient::new().with_body(format!("{REGISTRY}/lodash"), LODASH),
            |host| {
                NpmSource::new(REGISTRY, host).with_pinned_keys(vec![sig::RegistryKey::pinned(
                    "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
                )])
            },
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        f.subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        // The endpoint was never asked -- which is the point: a user pins
        // keys because that request cannot succeed.
        assert_eq!(f.host.hits(&format!("{REGISTRY}/{KEYS_PATH}")), 0);

        // And the key was recognized, so the failure is a bad signature
        // rather than an unpublished key.
        assert!(
            !ctx.problems()
                .counts()
                .contains_key(&Code::SignatureMissing),
            "the pinned key should have been found: {:?}",
            ctx.problems().counts()
        );
    }

    /// With nothing pinned, the registry's own endpoint is still consulted
    /// -- pinning is opt-in, not a change of default behavior.
    #[tokio::test]
    async fn keys_unpinned_consult_endpoint() {
        let f = repo(
            FixtureClient::new()
                .with_body(format!("{REGISTRY}/lodash"), LODASH)
                .with_body(format!("{REGISTRY}/{KEYS_PATH}"), r#"{"keys":[]}"#),
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        f.subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(f.host.hits(&format!("{REGISTRY}/{KEYS_PATH}")), 1);
    }

    /// A registry that rotates to a key outside the pinned set is reported,
    /// so the substitution is visible rather than silent.
    #[tokio::test]
    async fn keys_outside_pinned_set_reported() {
        let f = Fixture::build(
            FixtureClient::new().with_body(format!("{REGISTRY}/lodash"), LODASH),
            |host| {
                NpmSource::new(REGISTRY, host).with_pinned_keys(vec![sig::RegistryKey::pinned(
                    "SHA256:some-other-key",
                    "MFkw",
                )])
            },
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.files[0].signatures.len(), 1);
        assert!(ctx.problems().counts()[&Code::SignatureMissing] >= 1);
    }

    /// A scope's slash is encoded; some proxies accept nothing else.
    #[tokio::test]
    async fn scoped_package_url_encoded() {
        let scoped = ArtifactId::new(EcosystemId::npm(), Some("@angular"), "core");
        let f = lodash_repo();

        assert_eq!(
            f.subject.package_url(&scoped),
            "h://registry.test/@angular%2fcore"
        );
    }

    #[tokio::test]
    async fn packument_missing_reported_not_found() {
        let f = repo(FixtureClient::new());
        let ctx = ctx();

        let err = f.subject.versions(&id("ghost"), &ctx).await.unwrap_err();

        assert_eq!(err.code(), Code::ArtifactNotFound);
    }

    #[tokio::test]
    async fn packument_malformed_is_error() {
        let f = repo(FixtureClient::new().with_body(format!("{REGISTRY}/broken"), "{["));
        let ctx = ctx();

        let err = f.subject.versions(&id("broken"), &ctx).await.unwrap_err();

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    /// `underscore@1.1.7` publishes its empty dependency map as `[]`.
    const UNDERSCORE: &str = r#"{
        "name": "underscore",
        "time": {"1.1.7": "2011-07-13T00:00:00.000Z"},
        "versions": {
            "1.1.7": {
                "license": "MIT",
                "dist": {
                    "tarball": "h://registry.test/underscore/-/underscore-1.1.7.tgz",
                    "shasum": "40bab84bad19d230096e8d6ef628bff055d83db0"
                },
                "contributors": [],
                "dependencies": DEPS
            }
        }
    }"#;

    fn underscore_repo(deps: &str) -> Fixture<NpmSource> {
        let body = UNDERSCORE.replace("DEPS", deps);
        repo(FixtureClient::new().with_body(format!("{REGISTRY}/underscore"), body))
    }

    #[tokio::test]
    async fn dependencies_empty_array_read() {
        let f = underscore_repo("[]");
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.1.7");

        let versions = f
            .subject
            .versions(&id("underscore"), &ctx)
            .await
            .expect("listed");
        assert_eq!(versions.len(), 1);

        let artifact = f
            .subject
            .metadata(&id("underscore"), Some(&version), &ctx)
            .await
            .expect("fetched");

        let deps = f.subject.deps(&artifact, &ctx).await.expect("read");
        assert!(deps.is_empty());
    }

    #[tokio::test]
    async fn dependencies_nonempty_array_malformed() {
        let f = underscore_repo(r#"["x"]"#);
        let ctx = ctx();

        let err = f
            .subject
            .versions(&id("underscore"), &ctx)
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    /// A version with no integrity has nothing a signature could cover, so
    /// no signature verdict is reported.
    #[tokio::test]
    async fn signature_without_integrity_silent() {
        let f = lodash_repo();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.20");

        f.subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        // 4.17.20 has no integrity at all, so there is nothing to sign over
        // and nothing is reported.
        assert!(
            !ctx.problems()
                .counts()
                .contains_key(&Code::SignatureInvalid)
        );
    }

    /// An integrity with no signature over it is `signature-missing`, and
    /// records none.
    #[tokio::test]
    async fn signature_absent_with_integrity_warns() {
        let packument = r#"{
            "name": "bare",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "h://registry.test/bare/-/bare-1.0.0.tgz",
                        "integrity": "sha512-AAAA"
                    }
                }
            }
        }"#;
        let f = repo(FixtureClient::new().with_body(format!("{REGISTRY}/bare"), packument));
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0.0");

        let artifact = f
            .subject
            .metadata(&id("bare"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert!(artifact.files[0].signatures.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::SignatureMissing], 1);
    }

    /// A signature that does not verify under a known key is
    /// `signature-invalid`, and still recorded.
    #[tokio::test]
    async fn signature_bad_is_invalid() {
        let f = Fixture::build(
            FixtureClient::new().with_body(format!("{REGISTRY}/lodash"), LODASH),
            |host| {
                NpmSource::new(REGISTRY, host).with_pinned_keys(vec![sig::RegistryKey::pinned(
                    "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
                )])
            },
        );
        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.files[0].signatures.len(), 1);
        assert_eq!(ctx.problems().counts()[&Code::SignatureInvalid], 1);
    }

    /// A signature from a key the registry does not publish is recorded,
    /// not silently accepted.
    #[tokio::test]
    async fn signature_from_unpublished_key_reported() {
        let f = repo(
            FixtureClient::new()
                .with_body(format!("{REGISTRY}/lodash"), LODASH)
                .with_body(format!("{REGISTRY}/{KEYS_PATH}"), r#"{"keys":[]}"#),
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("4.17.21");

        let artifact = f
            .subject
            .metadata(&id("lodash"), Some(&version), &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.files[0].signatures.len(), 1);
        assert!(ctx.problems().counts()[&Code::SignatureMissing] >= 1);
    }
}
