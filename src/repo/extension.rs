//! A source an extension implements.
//!
//! The extension answers only what it alone knows: which versions exist,
//! and which files each one holds. Everything with an effect stays here --
//! downloads go through [`super::download`], so the cache, digests, and
//! read-only marking work exactly as for a built-in.
//!
//! ```text
//!   versions(id)          --invoke versions--> extension --fetch--> host
//!   metadata(id, version) --invoke metadata--> extension --fetch--> host
//!   download(file)        --> repo::download --> host        (never the extension)
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::gear::{Gear, PointKind};
use crate::ext::{ExtHost, Options};
use crate::model::{
    ArtifactId, Dependency, Digest, DigestAlg, EcosystemId, FileRef, ResolvedArtifact, Version,
};
use crate::net::Expectation;
use crate::version::VersionHandler;

use super::{Downloaded, Source};

const VERSIONS_OP: &str = "versions";
const METADATA_OP: &str = "metadata";

/// A [`Source`] whose listing an extension answers.
pub struct ExtensionSource {
    gear: Gear,
    base_url: String,
    options: Options,
    host: Arc<dyn ExtHost>,
    ecosystem: Arc<dyn Ecosystem>,

    /// The handler the extension's `version-scheme` names, if it named one.
    versions: Option<Arc<dyn VersionHandler>>,
}

#[derive(Deserialize)]
struct VersionsOutput {
    versions: Vec<Version>,
}

#[derive(Deserialize)]
struct MetadataOutput {
    files: Vec<ListedFile>,
    license: Option<String>,
    published: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
struct ListedFile {
    name: String,
    url: String,
    size: Option<u64>,

    #[serde(default)]
    digests: Vec<ListedDigest>,
}

#[derive(Deserialize)]
struct ListedDigest {
    algorithm: String,
    hex: String,
}

impl ExtensionSource {
    /// Wrap a launched extension that declared itself a source.
    ///
    /// It must speak exactly one built-in ecosystem: nothing builds an
    /// ecosystem from an extension's description yet.
    pub fn open(
        gear: Gear,
        base_url: &str,
        options: &Options,
        host: Arc<dyn ExtHost>,
    ) -> Result<Self> {
        let name = gear.name();
        let description = gear.description();

        if !description.provides(PointKind::Source) {
            return Err(Error::Config(format!(
                "extension {name:?} does not provide a source"
            )));
        }

        let ecosystem = description.sole_ecosystem().ok_or_else(|| {
            Error::Config(format!(
                "extension {name:?} must speak exactly one ecosystem to be a source"
            ))
        })?;
        let ecosystem = crate::ecosystem::open(&ecosystem.id)?;

        let versions = description
            .version_scheme
            .as_deref()
            .map(crate::version::open)
            .transpose()?;

        Ok(Self {
            gear,
            base_url: base_url.to_owned(),
            options: options.clone(),
            host,
            ecosystem,
            versions,
        })
    }

    /// The input every source op shares.
    fn input(&self, id: &ArtifactId) -> serde_json::Map<String, Value> {
        let mut artifact = serde_json::Map::new();

        if let Some(namespace) = id.namespace() {
            artifact.insert("namespace".into(), namespace.into());
        }
        artifact.insert("name".into(), id.name().into());

        let mut input = serde_json::Map::new();
        input.insert("artifact".into(), artifact.into());
        input.insert("base-url".into(), self.base_url.clone().into());
        input.insert("options".into(), self.options.as_map().clone().into());

        input
    }

    /// Invoke `op`, and check its output against `definition` before
    /// reading it.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        op: &str,
        input: serde_json::Map<String, Value>,
        definition: &'static str,
        ctx: &Ctx,
    ) -> Result<T> {
        let output = self
            .gear
            .invoke(PointKind::Source, op, input.into(), self.host.clone(), ctx)
            .await?;

        crate::ext::gear::check(definition, &output).map_err(|detail| self.broken(detail))?;

        serde_json::from_value(output).map_err(|err| self.broken(err.to_string()))
    }

    fn broken(&self, detail: String) -> Error {
        Error::Extension {
            extension: self.gear.name().to_owned(),
            code: crate::core::problem::Code::MetadataMalformed,
            detail,
        }
    }
}

impl ListedFile {
    fn into_file(self) -> FileRef {
        let mut file = FileRef::new(self.name, self.url);
        file.size = self.size;

        // The schema admits only algorithms `DigestAlg` knows.
        file.digests = self
            .digests
            .into_iter()
            .filter_map(|digest| {
                DigestAlg::parse(&digest.algorithm).map(|alg| Digest::new(alg, digest.hex))
            })
            .collect();

        file
    }
}

#[async_trait]
impl Source for ExtensionSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        super::sole_ecosystem(&*self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![self.ecosystem.id()]
    }

    /// The extension's declared scheme, else the ecosystem's.
    fn version_handler(&self, id: &ArtifactId) -> Result<&dyn VersionHandler> {
        match &self.versions {
            Some(handler) => Ok(&**handler),
            None => Ok(self.ecosystem(id)?),
        }
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let output: VersionsOutput = self
            .call(VERSIONS_OP, self.input(id), "SourceVersionsOutput", ctx)
            .await?;

        Ok(output.versions)
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let version = super::version_required(id, version)?;

        let mut input = self.input(id);
        input.insert("version".into(), version.text().into());

        let output: MetadataOutput = self
            .call(METADATA_OP, input, "SourceMetadataOutput", ctx)
            .await?;

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: Some(version.clone()),
            files: output
                .files
                .into_iter()
                .map(ListedFile::into_file)
                .collect(),
            license: output.license,
            published: output.published,
        })
    }

    /// A raw artifact declares no dependencies, and no extension source
    /// reports any yet.
    async fn deps(&self, _artifact: &ResolvedArtifact, _ctx: &Ctx) -> Result<Vec<Dependency>> {
        Ok(Vec::new())
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        super::download(&*self.host, file, expect, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.host.permits(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::problem::Code;
    use crate::ext::gear::testing::{DESCRIBE_RAW_SOURCE, launch_wat, router};
    use crate::ext::testing::{Fixture, options};
    use crate::model::{ArtifactRequest, Cause, Release, VersionSpec};
    use crate::net::FixtureClient;
    use crate::repo::Criteria;
    use crate::version::PreRelease;

    const BASE: &str = "h://dist.test/dist/";
    const SHA256: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    const VERSIONS: (&str, &str) = (
        r#""op":"versions""#,
        r#"","dir":"result","output":{"versions":[{"text":"24.1.0","release":"general"},{"text":"25.0.0-rc.1","release":"pre-release"}]}}"#,
    );

    fn metadata() -> (&'static str, String) {
        (
            r#""op":"metadata""#,
            format!(
                r#"","dir":"result","output":{{"files":[{{"name":"node.tar.gz","url":"h://dist.test/dist/v24.1.0/node.tar.gz","size":4,"digests":[{{"algorithm":"sha256","hex":"{SHA256}"}}]}}],"published":"2025-05-08T00:00:00Z"}}}}"#
            ),
        )
    }

    fn fixture(routes: &[(&str, &str)], client: FixtureClient) -> Fixture<ExtensionSource> {
        let mut all = vec![DESCRIBE_RAW_SOURCE];
        all.extend_from_slice(routes);

        let gear = launch_wat(&router(&all)).expect("launches");

        Fixture::build(client, |host| {
            ExtensionSource::open(gear, BASE, &options(serde_json::json!({})), host).expect("opens")
        })
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, "nodejs")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "nodejs".into(),
        })
    }

    #[tokio::test]
    async fn versions_from_extension() {
        let f = fixture(&[VERSIONS], FixtureClient::new());

        let versions = f.subject.versions(&id(), &ctx()).await.expect("listed");

        assert_eq!(
            versions,
            vec![
                Version::new("24.1.0", Release::General),
                Version::new("25.0.0-rc.1", Release::PreRelease),
            ]
        );
    }

    #[tokio::test]
    async fn metadata_carries_files_and_digests() {
        let (needle, rest) = metadata();
        let f = fixture(&[(needle, &rest)], FixtureClient::new());
        let version = Version::new("24.1.0", Release::General);

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx())
            .await
            .expect("resolved");

        let file = &artifact.files[0];
        assert_eq!(file.name, "node.tar.gz");
        assert_eq!(file.size, Some(4));
        assert_eq!(file.digests, vec![Digest::new(DigestAlg::Sha256, SHA256)]);
        assert!(artifact.published.is_some());
    }

    #[tokio::test]
    async fn request_exact_resolves() {
        let (needle, rest) = metadata();
        let f = fixture(&[VERSIONS, (needle, &rest)], FixtureClient::new());
        let ctx = ctx();
        let request = ArtifactRequest {
            id: id(),
            spec: VersionSpec::Exact("24.1.0".into()),
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("24.1.0"));
    }

    /// A proxy falls through on `artifact-not-found`, so the extension's
    /// code has to survive the trip.
    #[tokio::test]
    async fn error_not_found_keeps_code() {
        let gone = (
            r#""op":"versions""#,
            r#"","dir":"failed","code":"artifact-not-found","message":{"id":"no-such-artifact"}}"#,
        );
        let f = fixture(&[gone], FixtureClient::new());

        let err = f.subject.versions(&id(), &ctx()).await.expect_err("absent");

        assert_eq!(err.code(), Code::ArtifactNotFound);
    }

    #[tokio::test]
    async fn output_malformed_refused() {
        let bad = (
            r#""op":"versions""#,
            r#"","dir":"result","output":{"versions":[{"text":"1"}]}}"#,
        );
        let f = fixture(&[bad], FixtureClient::new());

        let err = f
            .subject
            .versions(&id(), &ctx())
            .await
            .expect_err("refused");

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    /// The bytes come through the host, never the extension.
    #[tokio::test]
    async fn download_through_host() {
        let url = "h://dist.test/dist/v24.1.0/node.tar.gz";
        let f = fixture(&[], FixtureClient::new().with_body(url, "test"));
        let file = FileRef::new("node.tar.gz", url);

        let downloaded = f
            .subject
            .download(&file, &Expectation::new(), &ctx())
            .await
            .expect("downloaded");

        assert_eq!(std::fs::read(&downloaded.path).expect("cached"), b"test");
        assert_eq!(f.requested(), vec![url.to_owned()]);
    }

    const DESCRIBE_SEMVER: (&str, &str) = (
        r#""dir":"describe""#,
        r#"","dir":"describe","output":{"protocol":1,"points":["source"],"ecosystems":[{"id":"raw","purl-type":"raw","osv-name":""}],"version-scheme":"semver"}}"#,
    );

    const RELEASES: (&str, &str) = (
        r#""op":"versions""#,
        r#"","dir":"result","output":{"versions":[{"text":"24.1.0","release":"general"},{"text":"24.2.0","release":"general"},{"text":"25.0.0","release":"general"},{"text":"25.1.0-rc.1","release":"pre-release"}]}}"#,
    );

    /// Any version's files; the answer names no version.
    const ANY_METADATA: (&str, &str) = (
        r#""op":"metadata""#,
        r#"","dir":"result","output":{"files":[]}}"#,
    );

    fn semver_fixture() -> Fixture<ExtensionSource> {
        let gear =
            launch_wat(&router(&[DESCRIBE_SEMVER, RELEASES, ANY_METADATA])).expect("launches");

        Fixture::build(FixtureClient::new(), |host| {
            ExtensionSource::open(gear, BASE, &options(serde_json::json!({})), host).expect("opens")
        })
    }

    /// Resolve `spec` against the semver fixture, to the chosen version.
    async fn chosen(spec: VersionSpec) -> String {
        let f = semver_fixture();
        let ctx = ctx();
        let request = ArtifactRequest {
            id: id(),
            spec,
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        artifact.version_text().expect("versioned").to_owned()
    }

    #[tokio::test]
    async fn request_major_picks_newest() {
        assert_eq!(chosen(VersionSpec::Exact("24".into())).await, "24.2.0");
    }

    #[tokio::test]
    async fn request_bare_picks_newest_ga() {
        assert_eq!(chosen(VersionSpec::Any).await, "25.0.0");
    }

    #[tokio::test]
    async fn request_full_version_stays_exact() {
        assert_eq!(chosen(VersionSpec::Exact("24.1.0".into())).await, "24.1.0");
    }

    #[test]
    fn handler_undeclared_keeps_ecosystem() {
        let f = fixture(&[], FixtureClient::new());

        let handler = f.subject.version_handler(&id()).expect("raw");

        assert_eq!(handler.version_spec("24"), VersionSpec::Exact("24".into()));
    }

    #[test]
    fn source_point_required() {
        let lock_only = (
            r#""dir":"describe""#,
            r#"","dir":"describe","output":{"protocol":1,"points":["lock"]}}"#,
        );
        let gear = launch_wat(&router(&[lock_only])).expect("launches");

        let err =
            ExtensionSource::open(gear, BASE, &Options::default(), crate::ext::testing::idle())
                .err()
                .expect("refused");

        assert_eq!(err.code(), Code::ConfigInvalid);
    }
}
