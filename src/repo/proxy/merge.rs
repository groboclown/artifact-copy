//! Every upstream's versions of an artifact, as one list.
//!
//! The case [`super::Failover`] cannot serve: upstreams that hold
//! genuinely **different** things rather than copies of each other. A
//! release repository and a snapshot repository are the motivating pair --
//! neither is a subset of the other, and asking which versions of
//! `org.example:lib` exist has to consult both.
//!
//! Failover is right when the upstreams are a hot standby, or nested
//! subsets where the first holds everything the second does. It is wrong
//! here: it would report the release versions and silently omit every
//! snapshot.
//!
//! # Why merging is allowed here and not in a catalog walk
//!
//! This is the whole reason the merging proxy is a *source* and there is
//! no merging enumerator.
//!
//! Deduplicating **one artifact's versions** costs a list bounded by that
//! artifact's release history -- hundreds of entries for a long-lived
//! package, and it is already being held to be returned. Deduplicating a
//! **catalog** costs a claim set that grows with the catalog, which is
//! precisely what the memory discipline forbids.
//!
//! Same operation, two completely different costs, because one is bounded
//! by an artifact and the other by a repository.
//!
//! # An upstream that cannot answer is reported, not skipped
//!
//! The sharpest difference from failover. There, falling through is
//! ordinary operation: the whole point is that one upstream answers. Here,
//! every upstream is part of the answer, so one being unreachable makes
//! the result **incomplete** -- and an incomplete version list resolves to
//! an older version than it should, quietly.
//!
//! So a skipped upstream raises a problem against the run's context.
//! Whether that aborts is then the user's configured business, which is
//! what [`crate::core::problem`] is for; what this must not do is decide
//! silently.

use std::path::PathBuf;

use async_trait::async_trait;

use super::SourceUpstreams;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::Ecosystem;
use crate::ext::Options;
use crate::message;
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::Expectation;
use crate::repo::{Downloaded, Source};

/// Reads every upstream and combines what they hold.
pub struct Merge {
    upstreams: SourceUpstreams,

    /// Everything any upstream speaks, settled at construction.
    ecosystems: Vec<EcosystemId>,
}

impl Merge {
    /// **Two upstreams at least.** Merging one repository with nothing is
    /// the repository, and a user who wrote that meant something else --
    /// most likely they meant to list a second one and did not.
    ///
    /// An ecosystem in common, for the same reason failover needs one:
    /// upstreams holding disjoint ecosystems are not parts of one answer,
    /// they are unrelated repositories that happen to share a declaration.
    pub fn open(upstreams: SourceUpstreams, options: &Options) -> Result<Self> {
        let _ = options;

        upstreams.require_at_least(2, "proxy-merge")?;
        upstreams.require_shared_ecosystem("proxy-merge")?;

        let ecosystems = upstreams.ecosystems();

        Ok(Self {
            upstreams,
            ecosystems,
        })
    }

    /// Whether a failure means *this upstream has nothing to contribute*.
    ///
    /// The same allow-list both proxies use. It means something different
    /// here, though: for failover it means "ask the next one", and for a
    /// merge it means "this part of the answer is missing", which is why
    /// the caller of this reports rather than moves on quietly.
    fn is_absent(err: &Error) -> bool {
        matches!(err.code(), Code::ArtifactNotFound | Code::HostUnreachable)
    }

    /// Say that one upstream did not contribute.
    ///
    /// A `404` is the ordinary case -- not every upstream holds every
    /// artifact -- and is reported at a lower code than a host that could
    /// not be reached, because only the second makes the answer *less
    /// trustworthy* than it looks.
    fn report_absent(&self, id: &ArtifactId, at: usize, err: &Error, ctx: &Ctx) {
        if err.code() != Code::HostUnreachable {
            return;
        }

        ctx.report(
            Code::HostUnreachable,
            message!(
                "proxy-merge-upstream-unreachable",
                "{purl}: upstream {at} could not be reached, so the merged version \
                 list may be missing versions only it holds: {reason}",
                purl = id.purl(),
                at = at,
                reason = err,
            ),
        );
    }
}

#[async_trait]
impl Source for Merge {
    /// The first upstream that claims the artifact.
    ///
    /// `open` requires only that the upstreams **share** an ecosystem, not
    /// that they speak identical sets, so a later one may claim what the
    /// first does not.
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
            ecosystem: "proxy-merge",
            text: id.purl(),
            detail: "this proxy has no upstreams".to_owned(),
        }))
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        self.ecosystems.clone()
    }

    /// Every version any upstream holds, each once.
    ///
    /// Deduplicated **by version text alone**, not by the whole [`Version`].
    /// Two upstreams may disagree about whether `1.0-rc1` is a pre-release
    /// -- they are different repositories running different software -- and
    /// treating those as two versions would offer the same artifact twice
    /// and let the ecosystem's `select` pick between them arbitrarily. The
    /// first upstream to report a version decides how it is classified,
    /// which makes precedence order mean something here too.
    ///
    /// Left unsorted, as every other source leaves it: ordering is the
    /// ecosystem's job and callers must not assume otherwise.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let mut merged: Vec<Version> = Vec::new();
        let mut first: Option<Error> = None;
        let mut answered = false;

        for (at, upstream) in self.upstreams.iter().enumerate() {
            match upstream.item.versions(id, ctx).await {
                Ok(versions) => {
                    answered = true;

                    for version in versions {
                        if !merged.iter().any(|kept| kept.text() == version.text()) {
                            merged.push(version);
                        }
                    }
                }

                Err(err) if Self::is_absent(&err) => {
                    self.report_absent(id, at, &err, ctx);
                    first.get_or_insert(err);
                }

                // Corruption or a stop: reported as-is, exactly as the
                // failover proxy does. Half a merge is not an answer.
                Err(err) => return Err(err),
            }
        }

        match (answered, first) {
            // At least one upstream spoke, so there is an answer even if
            // it is empty.
            (true, _) => Ok(merged),

            // None did, so report what the first one said rather than an
            // empty list that would read as "this artifact does not
            // exist".
            (false, Some(err)) => Err(err),

            // Unreachable: `open` refuses fewer than two upstreams.
            (false, None) => Ok(merged),
        }
    }

    /// The first upstream that confirms the version, since any version
    /// one of them holds is in the union.
    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        for upstream in self.upstreams.iter() {
            match upstream.item.unlisted(id, text, ctx).await {
                Ok(Some(found)) => return Ok(Some(found)),
                Ok(None) => {}
                Err(err) if Self::is_absent(&err) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(None)
    }

    /// Forwarded, never defaulted. Taking the default `true` would make a
    /// wrapped raw source look versioned, and resolution would then hunt
    /// for a candidate in a list the source correctly leaves empty.
    fn versioned(&self, id: &ArtifactId) -> bool {
        // Any upstream saying its artifacts have no versions settles it
        // for the union: a merge cannot offer a version list that some of
        // its members deny having.
        self.upstreams
            .iter()
            .all(|upstream| upstream.item.versioned(id))
    }

    /// The first upstream holding this exact version.
    ///
    /// Order decides when several do, which is the same rule failover
    /// uses and the reason `proxy-to` is a list rather than a set: a
    /// release repository listed first wins over a snapshot repository
    /// that happens to hold the same version string.
    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let mut first: Option<Error> = None;

        for upstream in self.upstreams.iter() {
            match upstream.item.metadata(id, version, ctx).await {
                Ok(artifact) => return Ok(artifact),

                Err(err) if Self::is_absent(&err) => {
                    first.get_or_insert(err);
                }

                Err(err) => return Err(err),
            }
        }

        Err(first.unwrap_or_else(|| Error::BadRequest {
            ecosystem: "proxy-merge",
            text: id.purl(),
            detail: "this proxy has no upstreams".to_owned(),
        }))
    }

    /// The first upstream that can describe this artifact's dependencies.
    ///
    /// Not merged, and deliberately: a dependency list is a property of
    /// one published artifact, so two upstreams answering differently for
    /// the same coordinate means one of them is serving something else
    /// under that name. Unioning the two would hide that.
    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        let mut first: Option<Error> = None;

        for upstream in self.upstreams.iter() {
            match upstream.item.deps(artifact, ctx).await {
                Ok(deps) => return Ok(deps),

                Err(err) if Self::is_absent(&err) => {
                    first.get_or_insert(err);
                }

                Err(err) => return Err(err),
            }
        }

        Err(first.unwrap_or_else(|| Error::BadRequest {
            ecosystem: "proxy-merge",
            text: artifact.id.purl(),
            detail: "this proxy has no upstreams".to_owned(),
        }))
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
    use crate::ext::ExtHost;
    use crate::ext::testing::{Fixture, idle};
    use crate::net::{Canned, FixtureClient};
    use crate::repo::NpmSource;
    use crate::repo::upstream::{Upstream, Upstreams};
    use http::StatusCode;
    use std::sync::Arc;

    const RELEASES: &str = "h://releases.test";
    const SNAPSHOTS: &str = "h://snapshots.test";

    /// A packument holding exactly the versions named.
    fn packument(versions: &[&str]) -> String {
        let entries: Vec<String> = versions
            .iter()
            .map(|version| format!(r#""{version}":{{"license":"MIT","dist":{{}}}}"#))
            .collect();

        let times: Vec<String> = versions
            .iter()
            .map(|version| format!(r#""{version}":"2021-02-20T00:00:00Z""#))
            .collect();

        format!(
            r#"{{"name":"lib","license":"MIT","versions":{{{}}},"time":{{{}}}}}"#,
            entries.join(","),
            times.join(",")
        )
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "lib")
    }

    fn merge(bases: &[&str], host: Arc<dyn ExtHost>) -> Merge {
        let upstreams: SourceUpstreams = Upstreams::new(
            bases
                .iter()
                .map(|base| {
                    Upstream::new(Arc::new(NpmSource::new(base, host.clone())) as Arc<dyn Source>)
                })
                .collect(),
        );

        Merge::open(upstreams, &Options::default()).expect("opens")
    }

    fn fixture(client: FixtureClient) -> Fixture<Merge> {
        Fixture::build(client, |host| merge(&[RELEASES, SNAPSHOTS], host))
    }

    fn ctx() -> Ctx {
        Ctx::for_test(crate::model::Cause::Requested { arg: "lib".into() })
    }

    fn names(versions: &[Version]) -> Vec<&str> {
        versions.iter().map(Version::text).collect()
    }

    /// The motivating case: neither upstream is a subset of the other, so
    /// the answer is both.
    #[tokio::test]
    async fn versions_from_every_upstream() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0", "2.0.0"]))
                .with_body(format!("{SNAPSHOTS}/lib"), packument(&["2.1.0-snap"])),
        );

        let ctx = ctx();
        let mut found = f.subject.versions(&id(), &ctx).await.expect("merged");

        found.sort_by(|a, b| a.text().cmp(b.text()));

        assert_eq!(names(&found), ["1.0.0", "2.0.0", "2.1.0-snap"]);
    }

    /// A version in both upstreams is one version, not two. Two
    /// repositories running different software may disagree about whether
    /// it is a pre-release, and offering both would let `select` choose
    /// arbitrarily between them.
    #[tokio::test]
    async fn versions_shared_appear_once() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0", "2.0.0"]))
                .with_body(format!("{SNAPSHOTS}/lib"), packument(&["2.0.0", "3.0.0"])),
        );

        let ctx = ctx();
        let found = f.subject.versions(&id(), &ctx).await.expect("merged");

        assert_eq!(found.len(), 3, "{:?}", names(&found));
        assert_eq!(
            found.iter().filter(|v| v.text() == "2.0.0").count(),
            1,
            "2.0.0 must appear once"
        );
    }

    /// Precedence order decides the classification of a shared version,
    /// which is why `proxy-to` is a list.
    #[tokio::test]
    async fn versions_shared_classified_by_first_upstream() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["2.0.0"]))
                .with_body(format!("{SNAPSHOTS}/lib"), packument(&["2.0.0"])),
        );

        let ctx = ctx();
        let found = f.subject.versions(&id(), &ctx).await.expect("merged");

        let first = f
            .subject
            .upstreams
            .iter()
            .next()
            .expect("one")
            .item
            .versions(&id(), &ctx)
            .await
            .expect("releases answered");

        assert_eq!(found[0], first[0]);
    }

    /// Not every upstream holds every artifact; that is ordinary, and the
    /// rest of the answer stands.
    #[tokio::test]
    async fn upstream_without_artifact_contributes_nothing() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0"]))
                .with(
                    format!("{SNAPSHOTS}/lib"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        );

        let ctx = ctx();
        let found = f.subject.versions(&id(), &ctx).await.expect("merged");

        assert_eq!(names(&found), ["1.0.0"]);
    }

    /// The sharpest difference from failover. An unreachable upstream
    /// makes the answer incomplete, and an incomplete version list
    /// resolves to an older version than it should -- quietly, unless this
    /// says so.
    #[tokio::test]
    async fn upstream_unreachable_reported() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0"]))
                .with(
                    format!("{SNAPSHOTS}/lib"),
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                ),
        );

        let ctx = ctx();
        let found = f.subject.versions(&id(), &ctx).await.expect("merged");

        assert_eq!(names(&found), ["1.0.0"]);
        assert_eq!(ctx.problems().counts()[&Code::HostUnreachable], 1);
    }

    /// A 404 is not worth reporting: an upstream simply not holding an
    /// artifact is the normal case for a merge and says nothing about
    /// whether the answer is trustworthy.
    #[tokio::test]
    async fn upstream_missing_artifact_not_reported() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0"]))
                .with(
                    format!("{SNAPSHOTS}/lib"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        );

        let ctx = ctx();
        f.subject.versions(&id(), &ctx).await.expect("merged");

        assert!(ctx.problems().counts().is_empty(), "{:?}", ctx.problems());
    }

    /// No upstream holding it is "not found", not an empty list -- an empty
    /// list reads as "this artifact exists and has no versions".
    #[tokio::test]
    async fn upstream_none_holding_artifact_is_error() {
        let f = fixture(
            FixtureClient::new()
                .with(
                    format!("{RELEASES}/lib"),
                    Canned::status(StatusCode::NOT_FOUND),
                )
                .with(
                    format!("{SNAPSHOTS}/lib"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        );

        let ctx = ctx();
        let err = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect_err("nobody has it");

        assert_eq!(err.code(), Code::ArtifactNotFound);
    }

    /// Half a merge is not an answer: corruption stops, as it does
    /// everywhere else.
    #[tokio::test]
    async fn upstream_malformed_stops_merge() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), "{[")
                .with_body(format!("{SNAPSHOTS}/lib"), packument(&["1.0.0"])),
        );

        let ctx = ctx();
        let err = f
            .subject
            .versions(&id(), &ctx)
            .await
            .expect_err("corruption is not merged around");

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    /// Metadata is not merged: it comes from whichever upstream actually
    /// holds that version, first in order.
    #[tokio::test]
    async fn metadata_from_upstream_holding_version() {
        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0"]))
                .with_body(format!("{SNAPSHOTS}/lib"), packument(&["2.0.0-snap"])),
        );

        let ctx = ctx();
        let snapshot = Version::new("2.0.0-snap", crate::model::Release::PreRelease);

        let artifact = f
            .subject
            .metadata(&id(), Some(&snapshot), &ctx)
            .await
            .expect("the snapshot upstream has it");

        assert_eq!(artifact.version_text(), Some("2.0.0-snap"));
    }

    /// Resolution is inherited, so a merge gets the step-down loop and
    /// every criterion for free -- over the combined version list.
    #[tokio::test]
    async fn resolve_picks_highest_across_upstreams() {
        use crate::model::{ArtifactRequest, VersionSpec};
        use crate::repo::Criteria;
        use crate::version::PreRelease;

        let f = fixture(
            FixtureClient::new()
                .with_body(format!("{RELEASES}/lib"), packument(&["1.0.0"]))
                .with_body(format!("{SNAPSHOTS}/lib"), packument(&["3.0.0"])),
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
            .expect("resolved");

        assert_eq!(
            artifact.version_text(),
            Some("3.0.0"),
            "the highest version is in the second upstream"
        );
    }

    /// Merging one repository with nothing is the repository, and a user
    /// who wrote that meant to list a second one.
    ///
    /// `Merge` is not `Debug`, so `expect_err` is unavailable.
    #[test]
    fn merge_fewer_than_two_refused() {
        let one: SourceUpstreams =
            Upstreams::new(vec![Upstream::new(
                Arc::new(NpmSource::new(RELEASES, idle())) as Arc<dyn Source>,
            )]);

        let err = match Merge::open(one, &Options::default()) {
            Err(err) => err,
            Ok(_) => panic!("a merge of one must not open"),
        };

        assert_eq!(err.code(), Code::ConfigInvalid);
        assert!(err.to_string().contains("at least 2"), "{err}");
    }

    #[test]
    fn upstreams_disjoint_ecosystems_refused() {
        let mixed: SourceUpstreams = Upstreams::new(vec![
            Upstream::new(Arc::new(NpmSource::new(RELEASES, idle())) as Arc<dyn Source>),
            Upstream::new(
                Arc::new(crate::repo::MavenSource::new(SNAPSHOTS, idle())) as Arc<dyn Source>
            ),
        ]);

        let err = match Merge::open(mixed, &Options::default()) {
            Err(err) => err,
            Ok(_) => panic!("npm and maven are not parts of one answer"),
        };

        assert!(err.to_string().contains("disjoint"), "{err}");
    }
}
