//! A source and what the configuration decided about it.
//!
//! The inner source is built from a kind and a url and knows nothing about
//! the file it was declared in, so the configured `version-handler` is
//! applied here, around it. Everything else is forwarded.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use super::{Criteria, Downloaded, Source};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ecosystem::Ecosystem;
use crate::model::{
    ArtifactId, ArtifactRequest, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version,
};
use crate::net::Expectation;
use crate::version::VersionHandler;

/// A source and what the configuration decided about it.
pub struct Bound {
    inner: Arc<dyn Source>,

    /// The handler `version-handler` named, if the source named one.
    versions: Option<Arc<dyn VersionHandler>>,
}

impl Bound {
    pub fn new(inner: Arc<dyn Source>) -> Self {
        Self {
            inner,
            versions: None,
        }
    }

    /// Read versions with this handler rather than the ecosystem's.
    pub fn reading_versions(mut self, versions: Option<Arc<dyn VersionHandler>>) -> Self {
        self.versions = versions;
        self
    }
}

#[async_trait]
impl Source for Bound {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        self.inner.ecosystem(id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        self.inner.ecosystems()
    }

    /// The configured handler when there is one, and the inner source's
    /// otherwise -- which is the ecosystem's, for every registry adapter.
    ///
    /// **This is where a configured `version-handler` reaches resolution.**
    /// Without it the key would validate, resolve to a handler, and change
    /// nothing, because `Source::resolve` asks the source how its versions
    /// order and the source only knows its ecosystem.
    fn version_handler(&self, id: &ArtifactId) -> Result<&dyn VersionHandler> {
        match &self.versions {
            Some(handler) => Ok(&**handler),
            None => self.inner.version_handler(id),
        }
    }

    /// Forwarded, never defaulted. Taking the default `true` would make a
    /// wrapped raw source look versioned, and resolution would then hunt
    /// for a candidate in a list the source correctly leaves empty.
    fn versioned(&self, id: &ArtifactId) -> bool {
        self.inner.versioned(id)
    }

    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        self.inner.versions(id, ctx).await
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
        self.inner.metadata(id, version, ctx).await
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
        companions: &crate::repo::Companions,
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

    async fn offered(&self, artifact: ResolvedArtifact, ctx: &Ctx) -> Result<ResolvedArtifact> {
        self.inner.offered(artifact, ctx).await
    }

    /// The inner source's own, unless a handler was configured.
    ///
    /// **With a handler, the default body runs against `self`.** It asks
    /// `self` how versions order, so delegating would let the *inner*
    /// source answer and a declared `version-handler` would be resolved,
    /// validated, and then ignored -- the bug an earlier version had.
    ///
    /// **Without one, the inner source decides.** For a source that does
    /// not override `resolve` the two are the same body against the same
    /// handler. For one that does, such as `github`, never forwarding meant
    /// its override never ran in a configured run.
    async fn resolve(
        &self,
        request: &ArtifactRequest,
        criteria: Criteria,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        if self.versions.is_none() {
            return self.inner.resolve(request, criteria, ctx).await;
        }

        super::resolve::resolve(self, request, criteria, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Cause;

    /// Speaks npm and answers nothing else.
    struct Npm;

    #[async_trait]
    impl Source for Npm {
        fn ecosystem(&self, _id: &ArtifactId) -> Result<&dyn Ecosystem> {
            Ok(&crate::ecosystem::Npm)
        }

        fn ecosystems(&self) -> Vec<EcosystemId> {
            vec![EcosystemId::npm()]
        }

        async fn versions(&self, _id: &ArtifactId, _ctx: &Ctx) -> Result<Vec<Version>> {
            unreachable!("not exercised")
        }

        async fn metadata(
            &self,
            _id: &ArtifactId,
            _version: Option<&Version>,
            _ctx: &Ctx,
        ) -> Result<ResolvedArtifact> {
            unreachable!("not exercised")
        }

        async fn deps(&self, _artifact: &ResolvedArtifact, _ctx: &Ctx) -> Result<Vec<Dependency>> {
            unreachable!("not exercised")
        }

        async fn download(
            &self,
            _file: &FileRef,
            _expect: &Expectation,
            _ctx: &Ctx,
        ) -> Result<Downloaded> {
            unreachable!("not exercised")
        }

        fn serves(&self, url: &str) -> bool {
            url.starts_with("h://mirror.test/")
        }
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "tuna")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "tuna".into() })
    }

    /// The wire that makes `version-handler` mean something. Resolution
    /// asks the source how its versions order, so a source that answers
    /// with the configured handler resolves ranges its ecosystem would
    /// refuse.
    #[tokio::test]
    async fn handler_configured_reaches_resolution() {
        use crate::ecosystem::Raw;
        use crate::model::{ArtifactRequest, Cause, Provenance, Release, VersionSpec};
        use crate::repo::Criteria;
        use crate::version::{Semver, VersionHandler};

        /// Answers a fixed version list and nothing else.
        struct Tagged;

        #[async_trait]
        impl Source for Tagged {
            fn ecosystem(&self, _id: &ArtifactId) -> Result<&dyn Ecosystem> {
                Ok(&Raw)
            }

            fn ecosystems(&self) -> Vec<EcosystemId> {
                vec![EcosystemId::raw()]
            }

            async fn versions(&self, _id: &ArtifactId, _ctx: &Ctx) -> Result<Vec<Version>> {
                Ok(vec![
                    Version::new("1.0.0", Release::General),
                    Version::new("1.9.0", Release::General),
                ])
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
                    files: Vec::new(),
                    license: None,
                    published: None,
                })
            }

            async fn deps(
                &self,
                _artifact: &ResolvedArtifact,
                _ctx: &Ctx,
            ) -> Result<Vec<Dependency>> {
                Ok(Vec::new())
            }

            async fn download(
                &self,
                _file: &FileRef,
                _expect: &Expectation,
                _ctx: &Ctx,
            ) -> Result<Downloaded> {
                unreachable!("not exercised")
            }

            fn serves(&self, _url: &str) -> bool {
                false
            }
        }

        let repo = ArtifactId::new(EcosystemId::raw(), None, "owner/repo");

        let request = ArtifactRequest {
            id: repo.clone(),
            spec: VersionSpec::Range("^1.0".into()),
            prov: Arc::new(Provenance::root(Cause::Requested {
                arg: "owner/repo".into(),
            })),
        };

        let ctx = ctx();

        // Tags have no order, so a range matches nothing at all.
        let plain = Bound::new(Arc::new(Tagged));

        assert!(
            plain
                .resolve(&request, Criteria::default(), &ctx)
                .await
                .is_err(),
            "the ecosystem refuses every range"
        );

        // Declaring semver makes the same range resolvable, and picks the
        // highest match rather than the first listed.
        let declared = Bound::new(Arc::new(Tagged)).reading_versions(Some(Arc::new(Semver)));

        let resolved = declared
            .resolve(&request, Criteria::default(), &ctx)
            .await
            .expect("semver resolves it");

        assert_eq!(resolved.version_text(), Some("1.9.0"));

        // Raw parses `owner/repo@1` as exact; under semver it is a range.
        let major = ArtifactRequest {
            spec: VersionSpec::Exact("1".into()),
            ..request.clone()
        };

        let resolved = declared
            .resolve(&major, Criteria::default(), &ctx)
            .await
            .expect("semver reads a major as a range");

        assert_eq!(resolved.version_text(), Some("1.9.0"));

        // And the accessor agrees with what resolution used, which is the
        // property that keeps the two from drifting.
        assert_eq!(
            declared
                .version_handler(&repo)
                .expect("declared")
                .version_spec("^1.0"),
            Semver.version_spec("^1.0")
        );
    }

    /// Identity questions are answered by the inner source unchanged.
    #[test]
    fn identity_passed_through() {
        let bound = Bound::new(Arc::new(Npm));

        assert_eq!(bound.ecosystems(), vec![EcosystemId::npm()]);
        assert!(bound.ecosystem(&id()).is_ok());
        assert!(bound.serves("h://mirror.test/tuna.tgz"));
        assert!(!bound.serves("h://elsewhere.test/tuna.tgz"));
    }
}
