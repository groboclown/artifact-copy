//! Try each upstream in order; take the first that answers.
//!
//! The simplest useful proxy, and the one that motivates the mechanism:
//! *read from the registry, and fall back to the mirror when it does not
//! have the artifact or cannot be reached.* It uses [`Upstreams`]' order
//! and ignores classifiers entirely.
//!
//! # What counts as "cannot answer"
//!
//! Falling through on the wrong failure is how a failover proxy turns a
//! problem into a silence, so the rule is a short explicit list rather
//! than "any error":
//!
//! | The upstream said | Fall through? | Why |
//! | --- | --- | --- |
//! | `artifact-not-found` | yes | It genuinely does not have it. |
//! | `host-unreachable` | yes | It cannot answer. The motivating case. |
//! | `metadata-malformed` | **no** | It is broken, and quietly preferring the mirror hides that. |
//! | `checksum-mismatch` | **no** | Something is wrong with the bytes; another copy is not the answer. |
//! | `aborted` | **no** | A stop is a stop. Trying the next upstream is exactly the work the user asked to stop. |
//! | anything else | **no** | A fault in the tool or its configuration, which the next upstream would hit identically. |
//!
//! # Answers are not bound to one upstream
//!
//! Each method falls through independently, so `versions` may be answered
//! by the registry and `metadata` for one of those versions by the mirror.
//! For a version that exists in both with *different content*, which answer
//! you get depends on the order.
//!
//! That is deliberate rather than unfinished. Binding an upstream per
//! artifact would mean remembering a decision per coordinate -- a map that
//! grows with the number of artifacts walked, which is precisely what the
//! memory discipline forbids. A proxy that has to guarantee one upstream
//! per artifact needs a different design, not a cache bolted onto this one.

use std::path::PathBuf;

use async_trait::async_trait;

use super::{SourceUpstreams, is_answerable_elsewhere};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};

use crate::ecosystem::Ecosystem;
use crate::ext::Options;
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::Expectation;
use crate::repo::{Downloaded, Source};

/// Reads from the first upstream that can answer.
pub struct Failover {
    upstreams: SourceUpstreams,

    /// Everything any upstream speaks, settled at construction so that a
    /// proxy can itself be an upstream without re-deriving this per call.
    ecosystems: Vec<EcosystemId>,
}

impl Failover {
    /// Two rules, both checked here rather than during a walk.
    ///
    /// **At least one upstream.** A failover over nothing answers nothing,
    /// and would report every artifact as missing rather than as
    /// misconfigured.
    ///
    /// **An ecosystem in common.** Upstreams here are meant to be
    /// alternative answers to the same question, and a fallback from an npm
    /// registry to a Maven mirror can only ever answer "not found" -- the
    /// two hold disjoint sets of artifacts. Catching it at startup beats
    /// finding it later as a catalog that silently resolves nothing.
    ///
    /// Note *in common*, not *identical*: a repository manager serves
    /// several ecosystems from one API, so a Maven registry falling back to
    /// a Nexus that also holds npm is ordinary and is allowed.
    pub fn open(upstreams: SourceUpstreams, options: &Options) -> Result<Self> {
        let _ = options;

        upstreams.require_at_least(1, "proxy-failover")?;
        upstreams.require_shared_ecosystem("proxy-failover")?;

        let ecosystems = upstreams.ecosystems();

        Ok(Self {
            upstreams,
            ecosystems,
        })
    }
}

/// Run `attempt` against each upstream in turn.
///
/// The **first** failure is the one returned when every upstream declines,
/// because the order is a precedence order: what the primary said is the
/// fact its operator needs, and a mirror's 404 afterwards adds nothing.
macro_rules! first_answer {
    ($self:expr, $what:expr, |$source:ident| $attempt:expr) => {{
        let mut first: Option<Error> = None;

        for upstream in $self.upstreams.iter() {
            let $source = upstream.item.as_ref();

            match $attempt.await {
                Ok(answer) => return Ok(answer),

                Err(err) if is_answerable_elsewhere(&err) => {
                    first.get_or_insert(err);
                }

                Err(err) => return Err(err),
            }
        }

        Err(first.unwrap_or_else(|| {
            Error::Config(format!(
                "a proxy-failover source with no upstreams cannot {}",
                $what
            ))
        }))
    }};
}

#[async_trait]
impl Source for Failover {
    /// The first upstream that claims the artifact.
    ///
    /// Not the first upstream outright. `open` requires only that the
    /// upstreams **share** an ecosystem, not that they speak identical
    /// sets -- a repository manager holds several -- so the first one may
    /// legitimately not speak this artifact's while a later one does.
    ///
    /// When none claims it, the first upstream's refusal is returned, so
    /// the message reads as it would without the proxy in the way.
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        let mut first: Option<Error> = None;

        for upstream in self.upstreams.iter() {
            match upstream.item.ecosystem(id) {
                Ok(ecosystem) => return Ok(ecosystem),
                Err(err) => {
                    first.get_or_insert(err);
                }
            }
        }

        Err(first.unwrap_or_else(|| Error::BadRequest {
            ecosystem: "proxy-failover",
            text: id.purl(),
            detail: "this proxy has no upstreams".to_owned(),
        }))
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        self.ecosystems.clone()
    }

    /// The version list of the first upstream that has any.
    ///
    /// An **empty list is not an answer**. A registry that has never heard
    /// of a package may say so with a 404 or with an empty list depending
    /// on how it is written, and a failover that accepted the empty list
    /// would stop at the first upstream and report the artifact missing
    /// while the mirror held it.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let mut first: Option<Error> = None;

        for upstream in self.upstreams.iter() {
            match upstream.item.versions(id, ctx).await {
                Ok(versions) if !versions.is_empty() => return Ok(versions),

                // Indistinguishable from a 404, and treated as one.
                Ok(_) => {}

                Err(err) if is_answerable_elsewhere(&err) => {
                    first.get_or_insert(err);
                }

                Err(err) => return Err(err),
            }
        }

        match first {
            Some(err) => Err(err),

            // Every upstream answered, and every one answered "nothing".
            None => Ok(Vec::new()),
        }
    }

    /// The first upstream that confirms the version directly. One that
    /// cannot says nothing, so the next is asked, and the list after all.
    async fn confirmed(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        for upstream in self.upstreams.iter() {
            match upstream.item.confirmed(id, text, ctx).await {
                Ok(Some(found)) => return Ok(Some(found)),
                Ok(None) => {}
                Err(err) if is_answerable_elsewhere(&err) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(None)
    }

    /// The first upstream that confirms the version, as `versions` takes
    /// the first that lists any.
    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        for upstream in self.upstreams.iter() {
            match upstream.item.unlisted(id, text, ctx).await {
                Ok(Some(found)) => return Ok(Some(found)),
                Ok(None) => {}
                Err(err) if is_answerable_elsewhere(&err) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(None)
    }

    /// Forwarded, never defaulted. Taking the default `true` would make a
    /// wrapped raw source look versioned, and resolution would then hunt
    /// for a candidate in a list the source correctly leaves empty.
    fn versioned(&self, id: &ArtifactId) -> bool {
        // The first upstream's answer, which is the same rule every
        // other question here follows.
        self.upstreams
            .iter()
            .next()
            .is_none_or(|upstream| upstream.item.versioned(id))
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        first_answer!(self, "describe an artifact", |source| source
            .metadata(id, version, ctx))
    }

    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        first_answer!(self, "read dependencies", |source| source
            .deps(artifact, ctx))
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        super::download_through(&self.upstreams, file, expect, ctx).await
    }

    async fn verify(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &crate::repo::Companions,
        ctx: &Ctx,
    ) -> Result<()> {
        super::verify_through(&self.upstreams, artifact, files, companions, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        super::serves_any(&self.upstreams, url)
    }

    fn companion(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        kind: crate::ecosystem::Companion,
    ) -> Option<(FileRef, Expectation)> {
        super::companion_through(&self.upstreams, artifact, file, kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::core::problem::Code;
    use crate::ext::ExtHost;
    use crate::ext::testing::{Fixture, idle};
    use crate::net::{Canned, FixtureClient};
    use crate::repo::NpmSource;
    use crate::repo::proxy::{SourceUpstreams, Upstream, Upstreams};
    use http::StatusCode;
    use std::sync::Arc;

    const PRIMARY: &str = "h://primary.test";
    const MIRROR: &str = "h://mirror.test";

    const LODASH: &str = r#"{
        "name": "lodash",
        "license": "MIT",
        "versions": {
            "4.17.21": {
                "license": "MIT",
                "dist": {"tarball": "h://mirror.test/lodash.tgz"}
            }
        },
        "time": {"4.17.21": "2021-02-20T00:00:00Z"}
    }"#;

    /// A packument naming a *different* version, so a test can tell which
    /// upstream answered.
    const LODASH_OLD: &str = r#"{
        "name": "lodash",
        "license": "MIT",
        "versions": {
            "4.17.20": {
                "license": "MIT",
                "dist": {"tarball": "h://primary.test/lodash.tgz"}
            }
        },
        "time": {"4.17.20": "2020-08-13T00:00:00Z"}
    }"#;

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "lodash")
    }

    /// A failover over one npm source per base URL, in the order given.
    fn failover(bases: &[&str], host: Arc<dyn ExtHost>) -> Failover {
        let upstreams: SourceUpstreams = Upstreams::new(
            bases
                .iter()
                .map(|base| {
                    Upstream::new(Arc::new(NpmSource::new(base, host.clone())) as Arc<dyn Source>)
                })
                .collect(),
        );

        Failover::open(upstreams, &Options::default()).expect("opens")
    }

    fn fixture(client: FixtureClient) -> Fixture<Failover> {
        Fixture::build(client, |host| failover(&[PRIMARY, MIRROR], host))
    }

    fn ctx() -> Ctx {
        Ctx::for_test(crate::model::Cause::Requested {
            arg: "lodash".into(),
        })
    }

    /// The ordinary case: the primary answers and the mirror is never asked.
    #[tokio::test]
    async fn upstream_first_answering_wins() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{PRIMARY}/lodash"), LODASH_OLD)
                .with_body(format!("{MIRROR}/lodash"), LODASH),
        );

        let ctx = ctx();
        let versions = f.subject.versions(&id(), &ctx).await.expect("resolved");

        assert_eq!(versions[0].text(), "4.17.20");
        assert_eq!(f.host.hits(&format!("{MIRROR}/lodash")), 0);
    }

    /// The motivating case: the primary does not have it, the mirror does.
    #[tokio::test]
    async fn fall_through_on_missing_artifact() {
        let f = fixture(
            FixtureClient::new()
                .with(
                    format!("{PRIMARY}/lodash"),
                    Canned::status(StatusCode::NOT_FOUND),
                )
                .with_body(format!("{MIRROR}/lodash"), LODASH),
        );

        let ctx = ctx();
        let versions = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect("the mirror has it");

        assert_eq!(versions[0].text(), "4.17.21");
    }

    /// The other fall-through case: the primary is down.
    #[tokio::test]
    async fn fall_through_on_unreachable_upstream() {
        let f = fixture(
            FixtureClient::new()
                .with(
                    format!("{PRIMARY}/lodash"),
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                )
                .with_body(format!("{MIRROR}/lodash"), LODASH),
        );

        let ctx = ctx();

        assert!(f.subject.versions(&id(), &ctx).await.is_ok());
    }

    /// A broken upstream is reported, not routed around. Preferring the
    /// mirror would hide that the primary is serving corruption.
    #[tokio::test]
    async fn answer_malformed_stops_walk() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{PRIMARY}/lodash"), "{[")
                .with_body(format!("{MIRROR}/lodash"), LODASH),
        );

        let ctx = ctx();
        let err = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect_err("corruption is not routed around");

        assert_eq!(err.code(), Code::MetadataMalformed);
        assert_eq!(f.host.hits(&format!("{MIRROR}/lodash")), 0);
    }

    /// An empty version list is how some registries say "no such package",
    /// and it must not stop the walk at the first upstream.
    #[tokio::test]
    async fn versions_empty_not_answer() {
        let f = fixture(
            FixtureClient::new()
                .with_body(
                    format!("{PRIMARY}/lodash"),
                    r#"{"name":"lodash","versions":{}}"#,
                )
                .with_body(format!("{MIRROR}/lodash"), LODASH),
        );

        let ctx = ctx();
        let versions = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect("the mirror has it");

        assert_eq!(versions[0].text(), "4.17.21");
    }

    /// Every upstream genuinely holding nothing is an empty list, not an
    /// error: the artifact does not exist anywhere this proxy can see.
    #[tokio::test]
    async fn versions_empty_when_every_upstream_empty() {
        let empty = r#"{"name":"lodash","versions":{}}"#;

        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{PRIMARY}/lodash"), empty)
                .with_body(format!("{MIRROR}/lodash"), empty),
        );

        let ctx = ctx();
        let versions = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect("no upstream failed");

        assert!(versions.is_empty());
    }

    /// Order is precedence, so the primary's complaint is the one worth
    /// reporting when nothing can answer.
    #[tokio::test]
    async fn failure_first_reported() {
        let f = fixture(
            FixtureClient::new()
                .with(
                    format!("{PRIMARY}/lodash"),
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                )
                .with(
                    format!("{MIRROR}/lodash"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        );

        let ctx = ctx();
        let err = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect_err("neither has it");

        assert_eq!(err.code(), Code::HostUnreachable);
    }

    /// Resolution is inherited, so a failover gets the step-down loop and
    /// every criterion for free.
    #[tokio::test]
    async fn resolve_works_through_proxy() {
        use crate::model::{ArtifactRequest, VersionSpec};
        use crate::repo::Criteria;
        use crate::version::PreRelease;

        let f = fixture(
            FixtureClient::new()
                .with(
                    format!("{PRIMARY}/lodash"),
                    Canned::status(StatusCode::NOT_FOUND),
                )
                .with_body(format!("{MIRROR}/lodash"), LODASH),
        );

        let ctx = ctx();
        let request = ArtifactRequest {
            id: id(),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved through the mirror");

        assert_eq!(artifact.version_text(), Some("4.17.21"));
    }

    /// A fallback in a different ecosystem can only ever answer "not
    /// found", so it is a configuration mistake and not a topology.
    ///
    /// `Failover` is not `Debug`, so `expect_err` is unavailable.
    #[test]
    fn upstreams_different_ecosystems_refused() {
        let mixed: SourceUpstreams = Upstreams::new(vec![
            Upstream::new(Arc::new(NpmSource::new(PRIMARY, idle())) as Arc<dyn Source>),
            Upstream::new(
                Arc::new(crate::repo::MavenSource::new(MIRROR, idle())) as Arc<dyn Source>
            ),
        ]);

        let err = match Failover::open(mixed, &Options::default()) {
            Err(err) => err,
            Ok(_) => panic!("npm and maven are not alternatives for each other"),
        };

        let text = err.to_string();

        assert_eq!(err.code(), Code::ConfigInvalid);
        assert!(text.contains("npm"), "{text}");
        assert!(text.contains("maven"), "{text}");
    }

    /// And the agreed ecosystem is what the proxy then reports as its own,
    /// so a proxy may be an upstream of another proxy.
    #[test]
    fn failover_speaks_agreed_ecosystem() {
        assert_eq!(
            failover(&[PRIMARY, MIRROR], idle()).ecosystems(),
            vec![EcosystemId::npm()]
        );
    }

    /// A failover over nothing would report every artifact as missing.
    /// Refusing at construction makes it a configuration error instead.
    ///
    /// `Failover` is not `Debug`, so `expect_err` is unavailable.
    #[test]
    fn failover_over_nothing_refused() {
        let err = match Failover::open(SourceUpstreams::default(), &Options::default()) {
            Err(err) => err,
            Ok(_) => panic!("a failover over nothing must not open"),
        };

        assert_eq!(err.code(), Code::ConfigInvalid);
        assert!(err.to_string().contains("proxy-failover"), "{err}");
    }
}
