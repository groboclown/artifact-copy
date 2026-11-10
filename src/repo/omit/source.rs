//! A source without what its `omit` rules leave out.
//!
//! Wraps every source built, proxies included, so an omitted file is never
//! fetched and an omitted artifact never resolves. Everything else is
//! forwarded.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use super::Omit;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ecosystem::Ecosystem;
use crate::model::{
    ArtifactId, ArtifactRequest, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version,
};
use crate::net::Expectation;
use crate::repo::{Companions, Criteria, Downloaded, Source};
use crate::version::VersionHandler;

pub struct OmittingSource {
    inner: Arc<dyn Source>,
    omit: Omit,
}

impl OmittingSource {
    pub fn new(inner: Arc<dyn Source>, omit: Omit) -> Self {
        Self { inner, omit }
    }
}

#[async_trait]
impl Source for OmittingSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        self.inner.ecosystem(id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        self.inner.ecosystems()
    }

    fn version_handler(&self, id: &ArtifactId) -> Result<&dyn VersionHandler> {
        self.inner.version_handler(id)
    }

    fn versioned(&self, id: &ArtifactId) -> bool {
        self.inner.versioned(id)
    }

    /// Without the versions a whole-artifact rule leaves out, so a range
    /// never selects one.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        Ok(self
            .inner
            .versions(id, ctx)
            .await?
            .into_iter()
            .filter(|version| self.omit.artifact(id, Some(version)).is_none())
            .collect())
    }

    /// Forwarded unfiltered, as `unlisted` is: an omitted version is
    /// refused when it is offered, with the rule that omits it.
    async fn confirmed(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        self.inner.confirmed(id, text, ctx).await
    }

    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        self.inner.unlisted(id, text, ctx).await
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let artifact = self.inner.metadata(id, version, ctx).await?;

        self.offered(artifact, ctx).await
    }

    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        self.inner.deps(artifact, ctx).await
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        self.inner.download(file, expect, ctx).await
    }

    async fn verify(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        ctx: &Ctx,
    ) -> Result<()> {
        self.inner.verify(artifact, files, companions, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.inner.serves(url)
    }

    fn companion(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        kind: crate::ecosystem::Companion,
    ) -> Option<(FileRef, Expectation)> {
        self.inner.companion(artifact, file, kind)
    }

    /// The inner source's offer, less what these rules leave out.
    ///
    /// Idempotent: an artifact already offered has nothing left to omit,
    /// so asking again reports nothing twice.
    async fn offered(&self, artifact: ResolvedArtifact, ctx: &Ctx) -> Result<ResolvedArtifact> {
        let mut artifact = self.inner.offered(artifact, ctx).await?;
        let version = artifact.version.clone();

        if let Some(rule) = self.omit.artifact(&artifact.id, version.as_ref()) {
            return Err(self
                .omit
                .refusal(&artifact.id, version.as_ref(), &rule, ctx));
        }

        let files = std::mem::take(&mut artifact.files);
        artifact.files = self.omit.retain(
            &artifact.id,
            version.as_ref(),
            files,
            |file| file.name.as_str(),
            ctx,
        );

        Ok(artifact)
    }

    /// The inner source's resolution, then its offer.
    ///
    /// Forwarded rather than defaulted, so an inner override -- `github`'s,
    /// or `Bound`'s choice of loop -- still decides.
    async fn resolve(
        &self,
        request: &ArtifactRequest,
        criteria: Criteria,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let artifact = self.inner.resolve(request, criteria, ctx).await?;

        self.offered(artifact, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OmitRule;
    use crate::core::problem::Code;
    use crate::model::{Cause, Release};

    /// Holds `lib` at 1.0 and 1.1, each with a jar and a zip.
    struct Fixed;

    #[async_trait]
    impl Source for Fixed {
        fn ecosystem(&self, _id: &ArtifactId) -> Result<&dyn Ecosystem> {
            Ok(&crate::ecosystem::Maven)
        }

        fn ecosystems(&self) -> Vec<EcosystemId> {
            vec![EcosystemId::maven()]
        }

        async fn versions(&self, _id: &ArtifactId, _ctx: &Ctx) -> Result<Vec<Version>> {
            Ok(vec![at("1.0"), at("1.1")])
        }

        async fn metadata(
            &self,
            id: &ArtifactId,
            version: Option<&Version>,
            _ctx: &Ctx,
        ) -> Result<ResolvedArtifact> {
            Ok(ResolvedArtifact {
                id: id.clone(),
                version: version.cloned(),
                files: ["lib.jar", "lib.zip"]
                    .iter()
                    .map(|name| FileRef::new(*name, format!("h://source.test/{name}")))
                    .collect(),
                license: None,
                published: None,
            })
        }

        async fn deps(&self, _artifact: &ResolvedArtifact, _ctx: &Ctx) -> Result<Vec<Dependency>> {
            Ok(Vec::new())
        }

        async fn download(&self, _: &FileRef, _: &Expectation, _: &Ctx) -> Result<Downloaded> {
            unreachable!("not exercised")
        }

        fn serves(&self, _url: &str) -> bool {
            true
        }
    }

    fn at(text: &str) -> Version {
        Version::new(text, Release::General)
    }

    fn lib() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    fn omitting(rules: serde_json::Value) -> OmittingSource {
        let rules: Vec<OmitRule> = serde_json::from_value(rules).expect("rules");

        OmittingSource::new(Arc::new(Fixed), Omit::parse(&rules).expect("parses"))
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    #[tokio::test]
    async fn omitted_file_never_offered() {
        let source = omitting(serde_json::json!([{ "files": "*.zip" }]));
        let ctx = ctx();

        let artifact = source
            .metadata(&lib(), Some(&at("1.0")), &ctx)
            .await
            .expect("resolved");

        let names: Vec<&str> = artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["lib.jar"]);
        assert_eq!(ctx.problems().counts()[&Code::FileOmitted], 1);
    }

    /// A ranged rule hides its versions from resolution and refuses one
    /// asked for by name.
    #[tokio::test]
    async fn omitted_version_neither_listed_nor_offered() {
        let source = omitting(serde_json::json!([{ "purl": "pkg:maven/org.example/lib@1.1" }]));
        let ctx = ctx();

        let versions = source.versions(&lib(), &ctx).await.expect("listed");

        assert_eq!(versions, [at("1.0")]);

        source
            .metadata(&lib(), Some(&at("1.1")), &ctx)
            .await
            .expect_err("refused");

        assert_eq!(ctx.problems().counts()[&Code::ArtifactOmitted], 1);
    }

    /// Asked again of an artifact already offered, nothing is reported
    /// twice.
    #[tokio::test]
    async fn offering_idempotent() {
        let source = omitting(serde_json::json!([{ "files": "*.zip" }]));
        let ctx = ctx();

        let artifact = source
            .metadata(&lib(), Some(&at("1.0")), &ctx)
            .await
            .expect("resolved");
        let again = source
            .offered(artifact.clone(), &ctx)
            .await
            .expect("offered");

        assert_eq!(again.files.len(), artifact.files.len());
        assert_eq!(ctx.problems().counts()[&Code::FileOmitted], 1);
    }
}
