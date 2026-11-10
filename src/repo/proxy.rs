//! Sources built from other sources.
//!
//! A *proxy* source is handed an ordered list of [`Upstream`]s and answers
//! by delegating to them, which is what lets "try the mirror if the
//! registry is missing it" be a configuration rather than a code change.
//!
//! # A proxy has no `host`, and that is a rule about the field
//!
//! A configured proxy carries **no `host` key**. Its I/O happens in its
//! upstreams, each of which names its own host, so a `host` beside
//! `proxy-to` would be a field nothing reads -- and a user who set one
//! would reasonably expect it to mean something.
//!
//! **The exception, and it is exceptional.** A proxy may genuinely need a
//! host of its own: one that consults an index to decide which upstream
//! should answer has somewhere to fetch that index from. Such a proxy takes
//! it from its `options`, **never** from the `host` field, because the
//! field means "the host this repository is" and that is not what the value
//! is for.
//!
//! A proxy in that position should name the option for the job it does --
//! `index-host`, say -- and not `host`. An option spelled `host` beside a
//! forbidden `host` field is the most confusing arrangement available, and
//! the point of forbidding the field is to have exactly one place a host
//! can come from and one reading of what it means.
//!
//! **No proxy target, deliberately.** The question a proxy answers --
//! *which of these places does this artifact come from* -- is a read-side
//! question. Writing to several targets at once is a different feature
//! with different failure modes (partial success, rollback) and should not
//! be smuggled in through this door.
//!
//! **A proxy enumerator is a different matter, and exists.** Asking *what
//! does this proxy hold* is a reasonable thing to want, and
//! [`crate::repo::proxy::enumerator`] answers it over the same [`Upstreams`] list with
//! `Enumerator`s in it instead of `Source`s.
//!
//! # The two things an upstream carries
//!
//! Order and an optional classifier, and a given proxy may use either,
//! neither, or both:
//!
//! - **Order** expresses precedence. [`Failover`] is nothing but an
//!   ordering, and [`Merge`] uses it to break ties.
//! - **Classifier** assigns a responsibility -- *this one is releases, that
//!   one is snapshots* -- for a proxy whose upstreams are not
//!   interchangeable. Classifiers are **not** unique unless a particular
//!   proxy says they must be.
//!
//! # Checked at construction
//!
//! A proxy states its own arity and classifier rules through the `require_`
//! methods on [`Upstreams`], and states them in `open`. A configuration
//! that cannot work is then a startup error naming what was wrong, rather
//! than a failure found partway through a walk over a million
//! artifacts.

use std::path::PathBuf;
use std::sync::Arc;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::Options;
use crate::model::{EcosystemId, FileRef, ResolvedArtifact};
use crate::net::Expectation;
use crate::repo::upstream::Proxied;

use super::{Downloaded, Source};

pub mod enumerator;
mod failover;
mod merge;

pub use crate::repo::upstream::{Upstream, Upstreams};
pub use failover::Failover;
pub use merge::Merge;

/// Proxying applied to sources.
///
/// `Source` answers ecosystems directly, so this is the whole of what a
/// proxy needs to know about one.
impl Proxied for dyn Source {
    fn ecosystems(&self) -> Vec<EcosystemId> {
        Source::ecosystems(self)
    }
}

/// The upstreams a source proxy stands in front of.
pub type SourceUpstreams = Upstreams<dyn Source>;

/// Build a proxy source over the upstreams it was configured with.
///
/// Separate from [`super::open_source`] because the two take different
/// things: an ordinary source is built from a base URL, and a proxy has no
/// host at all. Folding them together would mean every registry adapter's
/// constructor growing an argument it ignores.
///
/// `Upstreams` is taken by value: a proxy owns its list, and the sources
/// inside it are `Arc`s already.
pub fn open_proxy_source(
    kind: &str,
    upstreams: SourceUpstreams,
    options: &Options,
) -> Result<Arc<dyn Source>> {
    match kind {
        "proxy-failover" => Ok(Arc::new(Failover::open(upstreams, options)?)),
        "proxy-merge" => Ok(Arc::new(Merge::open(upstreams, options)?)),

        other => Err(Error::UnknownKind {
            collection: "proxy source",
            kind: other.to_owned(),
        }),
    }
}

/// Whether a failure means *ask the next upstream* or *stop here*.
///
/// Written as an allow-list so that a problem code added later does not
/// silently become a fall-through case.
fn is_answerable_elsewhere(err: &Error) -> bool {
    matches!(err.code(), Code::ArtifactNotFound | Code::HostUnreachable)
}

/// Download through the upstreams whose hosts serve the file's URL.
///
/// A file's URL names the repository that listed it, and only an upstream
/// whose host would send the request may fetch it -- which is what keeps
/// one upstream's credentials off another's files. Among those that serve
/// it, in precedence order, a file one does not have is asked of the next,
/// and the first failure is returned when all decline.
/// Where a file's companion is, asked of the first upstream that would
/// fetch the file itself: the one that listed it knows its URLs.
fn companion_through(
    upstreams: &SourceUpstreams,
    artifact: &ResolvedArtifact,
    file: &FileRef,
    kind: crate::ecosystem::Companion,
) -> Option<(FileRef, Expectation)> {
    upstreams
        .iter()
        .find(|upstream| upstream.item.serves(&file.url))?
        .item
        .companion(artifact, file, kind)
}

async fn download_through(
    upstreams: &SourceUpstreams,
    file: &FileRef,
    expect: &Expectation,
    ctx: &Ctx,
) -> Result<Downloaded> {
    let mut first: Option<Error> = None;

    for upstream in upstreams.iter() {
        if !upstream.item.serves(&file.url) {
            continue;
        }

        match upstream.item.download(file, expect, ctx).await {
            Ok(downloaded) => return Ok(downloaded),

            Err(err) if is_answerable_elsewhere(&err) => {
                first.get_or_insert(err);
            }

            Err(err) => return Err(err),
        }
    }

    Err(first.unwrap_or_else(|| {
        Error::Config(format!(
            "{} is outside what every upstream of this proxy may fetch",
            file.url
        ))
    }))
}

/// Verify through the upstream that serves the artifact's first file.
///
/// The files came from the upstream that described the artifact, and its
/// keys are the ones that apply. An artifact no upstream serves has
/// nothing to check here.
async fn verify_through(
    upstreams: &SourceUpstreams,
    artifact: &ResolvedArtifact,
    files: &[PathBuf],
    companions: &crate::repo::Companions,
    ctx: &Ctx,
) -> Result<()> {
    let Some(first) = artifact.files.first() else {
        return Ok(());
    };

    let Some(upstream) = upstreams
        .iter()
        .find(|upstream| upstream.item.serves(&first.url))
    else {
        return Ok(());
    };

    upstream.item.verify(artifact, files, companions, ctx).await
}

/// Whether any upstream serves `url`.
fn serves_any(upstreams: &SourceUpstreams, url: &str) -> bool {
    upstreams.iter().any(|upstream| upstream.item.serves(url))
}

/// Built-in proxy source kinds.
///
/// **Built-in only, and there is no extension fallback.** A configured
/// `kind` naming an entry in `extensions` is never a proxy. The loader has
/// to know whether a declaration's `proxy-to` is meaningful *before* it
/// builds anything, and asking an extension would mean running it to find
/// out. This restricts the configuration loader and nothing else: an
/// embedder composing sources in their own code may write whatever
/// proxies they like.
pub(crate) fn proxy_source_kinds() -> &'static [&'static str] {
    &["proxy-failover", "proxy-merge"]
}

/// Whether a configured kind names a proxy.
pub(crate) fn is_proxy_kind(kind: &str) -> bool {
    proxy_source_kinds().contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::idle;
    use crate::repo::NpmSource;
    use http::StatusCode;

    fn source() -> Arc<dyn Source> {
        Arc::new(NpmSource::new("h://registry.test", idle()))
    }

    fn upstreams(classifiers: &[Option<&str>]) -> SourceUpstreams {
        Upstreams::new(
            classifiers
                .iter()
                .map(|classifier| match classifier {
                    Some(text) => Upstream::classified(source(), *text),
                    None => Upstream::new(source()),
                })
                .collect(),
        )
    }

    /// Configuration order is the contract; nothing here reorders.
    #[test]
    fn upstreams_keep_given_order() {
        let list = upstreams(&[Some("c"), Some("a"), Some("b")]);

        let order: Vec<Option<&str>> = list
            .iter()
            .map(|entry| entry.classifier.as_deref())
            .collect();

        assert_eq!(order, [Some("c"), Some("a"), Some("b")]);
    }

    /// Classifiers are tags, not keys: several upstreams may share one.
    #[test]
    fn classifier_shared_by_several_upstreams() {
        let list = upstreams(&[Some("snapshot"), Some("release"), Some("snapshot")]);

        assert_eq!(list.with_classifier("snapshot").count(), 2);
        assert_eq!(list.with_classifier("release").count(), 1);
        assert_eq!(list.with_classifier("absent").count(), 0);
    }

    #[test]
    fn arity_checked_at_both_ends() {
        let two = upstreams(&[None, None]);

        assert!(two.require_at_least(1, "test").is_ok());
        assert!(two.require_at_least(2, "test").is_ok());
        assert!(two.require_at_least(3, "test").is_err());

        assert!(two.require_at_most(2, "test").is_ok());
        assert!(two.require_at_most(1, "test").is_err());
    }

    /// The count a user has to correct belongs in the message.
    #[test]
    fn arity_failure_names_configured_count() {
        let err = upstreams(&[None])
            .require_at_least(3, "failover")
            .expect_err("too few");

        let text = err.to_string();

        assert!(text.contains("failover"), "{text}");
        assert!(text.contains('3'), "{text}");
        assert!(text.contains('1'), "{text}");
    }

    #[test]
    fn classifier_duplicate_refused_when_asked() {
        let list = upstreams(&[Some("primary"), Some("primary")]);

        let err = list
            .require_unique_classifiers("test")
            .expect_err("duplicated");

        assert!(err.to_string().contains("primary"), "{err}");
    }

    /// Absent is not a value, so two unclassified upstreams do not collide.
    #[test]
    fn classifier_missing_never_collides() {
        assert!(
            upstreams(&[None, None, Some("primary")])
                .require_unique_classifiers("test")
                .is_ok()
        );
    }

    #[test]
    fn classifier_exactly_one_of_set_required() {
        let roles = ["primary", "canonical"];

        assert!(
            upstreams(&[Some("primary"), None])
                .require_exactly_one_of(&roles, "test")
                .is_ok()
        );

        assert!(
            upstreams(&[None, None])
                .require_exactly_one_of(&roles, "test")
                .is_err()
        );

        // Two *different* names from the set is still two.
        assert!(
            upstreams(&[Some("primary"), Some("canonical")])
                .require_exactly_one_of(&roles, "test")
                .is_err()
        );
    }

    /// A misspelled classifier is otherwise silent: the proxy never finds
    /// the upstream it wanted and the run quietly does less.
    #[test]
    fn classifier_unrecognized_can_be_refused() {
        let err = upstreams(&[Some("primry")])
            .require_known_classifiers(&["primary", "fallback"], "test")
            .expect_err("misspelled");

        let text = err.to_string();

        assert!(text.contains("primry"), "{text}");
        assert!(text.contains("primary"), "{text}");
    }

    #[test]
    fn classifier_absent_passes_known_check() {
        assert!(
            upstreams(&[None])
                .require_known_classifiers(&["primary"], "test")
                .is_ok()
        );
    }

    /// A source speaking several ecosystems, as a repository manager does.
    struct Manager(Vec<EcosystemId>);

    #[async_trait::async_trait]
    impl Source for Manager {
        fn ecosystem(
            &self,
            id: &crate::model::ArtifactId,
        ) -> Result<&dyn crate::ecosystem::Ecosystem> {
            Err(Error::UnknownKind {
                collection: "ecosystem for this source",
                kind: id.ecosystem().to_string(),
            })
        }

        fn ecosystems(&self) -> Vec<EcosystemId> {
            self.0.clone()
        }

        async fn versions(
            &self,
            _id: &crate::model::ArtifactId,
            _ctx: &Ctx,
        ) -> Result<Vec<crate::model::Version>> {
            Ok(Vec::new())
        }

        async fn metadata(
            &self,
            _id: &crate::model::ArtifactId,
            _version: Option<&crate::model::Version>,
            _ctx: &Ctx,
        ) -> Result<crate::model::ResolvedArtifact> {
            Err(Error::Unimplemented("a test source"))
        }

        async fn deps(
            &self,
            _artifact: &crate::model::ResolvedArtifact,
            _ctx: &Ctx,
        ) -> Result<Vec<crate::model::Dependency>> {
            Ok(Vec::new())
        }

        async fn download(
            &self,
            _file: &FileRef,
            _expect: &Expectation,
            _ctx: &Ctx,
        ) -> Result<Downloaded> {
            Err(Error::Unimplemented("a test source"))
        }

        fn serves(&self, _url: &str) -> bool {
            false
        }
    }

    fn speaking(ids: &[EcosystemId]) -> Arc<dyn Source> {
        Arc::new(Manager(ids.to_vec()))
    }

    /// The rule is *share one*, not *speak identical sets*. A repository
    /// manager holds several ecosystems behind one API -- which is why
    /// `Source::ecosystem` takes the artifact -- so a Maven registry falling
    /// back to a Nexus that also holds npm is ordinary configuration.
    #[test]
    fn ecosystem_upstream_may_speak_more() {
        let mixed: SourceUpstreams = Upstreams::new(vec![
            Upstream::new(speaking(&[EcosystemId::maven()])),
            Upstream::new(speaking(&[EcosystemId::maven(), EcosystemId::npm()])),
        ]);

        assert!(mixed.require_shared_ecosystem("test").is_ok());

        // And the proxy speaks the union, so it can answer for npm too.
        assert_eq!(
            mixed.ecosystems(),
            vec![EcosystemId::maven(), EcosystemId::npm()]
        );
    }

    /// Disjoint upstreams are not alternatives for anything: the fallback
    /// can only ever answer "not found".
    #[test]
    fn ecosystem_disjoint_upstreams_refused() {
        let disjoint: SourceUpstreams = Upstreams::new(vec![
            Upstream::new(speaking(&[EcosystemId::npm()])),
            Upstream::new(speaking(&[EcosystemId::maven()])),
        ]);

        let err = disjoint
            .require_shared_ecosystem("test")
            .expect_err("nothing in common");

        let text = err.to_string();

        assert!(text.contains("npm"), "{text}");
        assert!(text.contains("maven"), "{text}");
    }

    /// Three upstreams where each *pair* overlaps but all three do not.
    /// The invariant is that there is something they are *all* alternatives
    /// for, so this is refused.
    #[test]
    fn ecosystem_overlap_spans_every_upstream() {
        let chain: SourceUpstreams = Upstreams::new(vec![
            Upstream::new(speaking(&[EcosystemId::maven(), EcosystemId::npm()])),
            Upstream::new(speaking(&[EcosystemId::npm(), EcosystemId::pypi()])),
            Upstream::new(speaking(&[EcosystemId::pypi(), EcosystemId::maven()])),
        ]);

        assert!(chain.require_shared_ecosystem("test").is_err());
    }

    /// Two upstreams, because that satisfies every kind's arity rule:
    /// failover wants at least one and merge at least two.
    #[test]
    fn every_advertised_proxy_kind_opens() {
        for kind in proxy_source_kinds() {
            assert!(is_proxy_kind(kind), "{kind} is not reported as a proxy");

            open_proxy_source(kind, upstreams(&[None, None]), &Options::default())
                .unwrap_or_else(|_| panic!("{kind} is advertised and must open"));
        }
    }

    #[test]
    fn kind_ordinary_source_not_proxy() {
        for kind in crate::repo::source_kinds() {
            assert!(!is_proxy_kind(kind), "{kind} must not be a proxy kind");
        }
    }

    #[test]
    fn kind_unknown_proxy_reported() {
        let err = match open_proxy_source(
            "proxy-nonsense",
            SourceUpstreams::default(),
            &Options::default(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("an unknown proxy kind must not open"),
        };

        assert!(err.to_string().contains("proxy-nonsense"), "{err}");
    }

    // -- Downloading through the upstream that serves the file -------------

    /// Serves one URL prefix, and answers a download with its own name so a
    /// test can see which upstream fetched.
    struct Served {
        prefix: &'static str,
        name: &'static str,
        missing: bool,
    }

    #[async_trait::async_trait]
    impl Source for Served {
        fn ecosystem(
            &self,
            _id: &crate::model::ArtifactId,
        ) -> Result<&dyn crate::ecosystem::Ecosystem> {
            Ok(&crate::ecosystem::Npm)
        }

        fn ecosystems(&self) -> Vec<EcosystemId> {
            vec![EcosystemId::npm()]
        }

        async fn versions(
            &self,
            _id: &crate::model::ArtifactId,
            _ctx: &Ctx,
        ) -> Result<Vec<crate::model::Version>> {
            Ok(Vec::new())
        }

        async fn metadata(
            &self,
            _id: &crate::model::ArtifactId,
            _version: Option<&crate::model::Version>,
            _ctx: &Ctx,
        ) -> Result<crate::model::ResolvedArtifact> {
            Err(Error::Unimplemented("a test source"))
        }

        async fn deps(
            &self,
            _artifact: &crate::model::ResolvedArtifact,
            _ctx: &Ctx,
        ) -> Result<Vec<crate::model::Dependency>> {
            Ok(Vec::new())
        }

        async fn download(
            &self,
            file: &FileRef,
            _expect: &Expectation,
            _ctx: &Ctx,
        ) -> Result<Downloaded> {
            if self.missing {
                return Err(Error::HttpStatus {
                    url: file.url.clone(),
                    status: StatusCode::NOT_FOUND,
                    retry_at: None,
                    detail: None,
                });
            }

            Ok(Downloaded {
                path: std::path::PathBuf::from(&file.name),
                relative_path: file.name.clone(),
                host: self.name.to_owned(),
                obtained: crate::repo::Obtained::Fetched,
                kept: None,
                hold: None,
            })
        }

        fn serves(&self, url: &str) -> bool {
            url.starts_with(self.prefix)
        }
    }

    fn served(prefix: &'static str, name: &'static str, missing: bool) -> Arc<dyn Source> {
        Arc::new(Served {
            prefix,
            name,
            missing,
        })
    }

    fn file(url: &str) -> FileRef {
        FileRef::new("tuna-1.0.0.tgz", url)
    }

    async fn downloaded(upstreams: &SourceUpstreams, url: &str) -> Result<Downloaded> {
        let ctx = Ctx::anonymous_for_test();

        download_through(upstreams, &file(url), &Expectation::new(), &ctx).await
    }

    /// A file belongs to the repository that listed it, so it is fetched
    /// through that upstream's host even when it is not first.
    #[tokio::test]
    async fn download_through_upstream_serving_url() {
        let upstreams = Upstreams::new(vec![
            Upstream::new(served("h://primary.test/", "primary", false)),
            Upstream::new(served("h://mirror.test/", "mirror", false)),
        ]);

        let got = downloaded(&upstreams, "h://mirror.test/tuna.tgz")
            .await
            .expect("downloaded");

        assert_eq!(got.host, "mirror");
        assert!(serves_any(&upstreams, "h://mirror.test/tuna.tgz"));
    }

    /// Among upstreams that serve the URL, one without the file hands it to
    /// the next.
    #[tokio::test]
    async fn download_missing_file_falls_to_next_upstream() {
        let upstreams = Upstreams::new(vec![
            Upstream::new(served("h://shared.test/", "first", true)),
            Upstream::new(served("h://shared.test/", "second", false)),
        ]);

        let got = downloaded(&upstreams, "h://shared.test/tuna.tgz")
            .await
            .expect("downloaded");

        assert_eq!(got.host, "second");
    }

    /// A URL no upstream may fetch is refused rather than sent anywhere.
    #[tokio::test]
    async fn download_url_unserved_refused() {
        let upstreams = Upstreams::new(vec![Upstream::new(served(
            "h://primary.test/",
            "primary",
            false,
        ))]);

        let err = downloaded(&upstreams, "h://elsewhere.test/tuna.tgz")
            .await
            .expect_err("refused");

        assert!(
            err.to_string().contains("h://elsewhere.test/tuna.tgz"),
            "{err}"
        );
        assert!(!serves_any(&upstreams, "h://elsewhere.test/tuna.tgz"));
    }
}
