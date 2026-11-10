//! Repository enumeration: the enumerator extension point.
//!
//! Enumeration is a different capability from resolution, which is why a
//! enumerator has its own `kind` and its own trait. Maven Central speaks the
//! Maven protocol perfectly well and cannot be enumerated over it at all;
//! conversely a Nexus instance enumerates every ecosystem it hosts through
//! one API.
//!
//! # Pages, not a stream
//!
//! [`Enumerator::walk`] returns one [`Page`] and a [`Cursor`], rather than a
//! stream. That is deliberately awkward in process and is the only shape
//! that survives being out of process: a `BoxStream` has no JSON
//! representation, so an executable or WASM enumerator could not implement
//! one. The host reassembles the pages.
//!
//! It is also what keeps enumeration within the memory discipline. A page
//! is bounded by the enumerator; the catalog behind it is not. Nothing here
//! names a collection that grows with the size of the repository.
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use std::sync::{Arc, LazyLock};

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::{EcosystemId, ListingDepth};

mod enumerators;
mod page;
mod sample;

pub use super::artifact_keeper::ArtifactKeeperEnumerator;
pub use super::artifactory::{ArtifactoryEnumerator, ArtifactoryOssEnumerator};
pub use super::local_dir::LocalDirEnumerator;
pub use super::maven::MavenIndexEnumerator;
pub use super::nexus::NexusEnumerator;
pub use super::npm::NpmReplicateEnumerator;
pub use super::proxy::enumerator::{
    EnumeratorUpstreams, Failover as FailoverEnumerator, open_proxy_enumerator,
};
pub(crate) use super::proxy::enumerator::{is_proxy_enumerator_kind, proxy_enumerator_kinds};
pub use super::pypi::PyPiEnumerator;
pub use enumerators::Enumerators;
pub use page::{Cursor, Found, Listed, Page};
pub use sample::SampleSize;

/// The OSV spelling of an ecosystem, which is capitalized differently from
/// the purl type.
///
/// Every enumerator has to declare it. The repository-manager enumerators do so
/// for whichever ecosystem they were pointed at rather than for a fixed
/// one, which is why this takes an argument at all.
///
/// TODO Remove dead_code on this once the OSV enumerator use of it is implemented.
#[allow(dead_code)]
pub(crate) fn osv_name_of(ecosystem: &crate::model::EcosystemId) -> String {
    match ecosystem.as_str() {
        crate::model::EcosystemId::MAVEN => "Maven".to_owned(),
        crate::model::EcosystemId::PYPI => "PyPI".to_owned(),

        // There is no OSV ecosystem for arbitrary files, and saying so is
        // the truth rather than a gap: advisories are published against
        // registries and a file in a raw repository is not in one. The
        // fallback would have answered `"raw"`, which names nothing, and a
        // screen would then look up an ecosystem that does not exist --
        // reported as a failed lookup rather than as "nothing screens
        // this". `ecosystem::raw` already declares the empty name; this is
        // the same claim from the enumerator side, and the two must agree.
        crate::model::EcosystemId::RAW => String::new(),

        other => other.to_owned(),
    }
}

/// Whether an enumerator can walk only what changed since a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Narrowing {
    /// It walks everything, whatever it is asked.
    Unsupported,

    /// The server lists only files modified since the time: Artifactory's
    /// `modified`, which a redeploy moves where `created` stays.
    Modified,
}

/// Enumerates what a repository holds.
#[async_trait]
pub trait Enumerator: Send + Sync {
    /// Which ecosystems this enumerator enumerates, and therefore how to
    /// parse what it returns.
    fn ecosystems(&self) -> &[EcosystemId];

    /// Whether this enumerator can report when an artifact was last
    /// downloaded.
    ///
    /// Declared rather than discovered, so a command that depends on usage
    /// data can **refuse before it starts** instead of walking a catalog
    /// and finding every answer is
    /// [`Unknown`](crate::model::LastDownload::Unknown). Over a repository
    /// of millions that is the difference between an immediate error and a
    /// long walk that produces nothing usable.
    ///
    /// `false` by default, which is the honest default: almost nothing can
    /// report this. A Maven directory index, npm's replication feed and
    /// PyPI's simple index carry no usage data at all. Repository managers
    /// do, which is why `nexus` and `artifactory` say so.
    fn reports_last_download(&self) -> bool {
        false
    }

    /// How far this enumerator's listing reaches.
    ///
    /// `find` has no depth option of its own: it records whatever the
    /// enumerator lists, and this says what that is. `Names` by default,
    /// which claims least.
    fn depth(&self) -> ListingDepth {
        ListingDepth::Names
    }

    /// One page of the catalog.
    ///
    /// `cursor` is `None` for the first page and otherwise the value the
    /// previous page returned.
    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page>;

    /// Whether [`Enumerator::walk_since`] narrows the walk.
    ///
    /// Declared, like [`Enumerator::depth`], so `find` can say before the
    /// walk whether it re-reads the whole catalog. `Unsupported` by default.
    fn narrowing(&self) -> Narrowing {
        Narrowing::Unsupported
    }

    /// One page of what changed at or after `since`.
    ///
    /// A cursor this issued carries the narrowing with it. By default the
    /// whole catalog, which is a superset of the answer and so never loses
    /// an artifact.
    async fn walk_since(
        &self,
        since: DateTime<Utc>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        let _ = since;

        self.walk(cursor, ctx).await
    }

    /// How many artifacts the catalog holds, if that is knowable cheaply.
    ///
    /// `None` is the honest answer for an enumerator that would have to walk
    /// the whole catalog to count it, and it makes `--sample-size=N%` a
    /// clear error rather than a guess against an invented total. Defaults
    /// to `None`, so an enumerator claims a count only when it has one.
    async fn count(&self, ctx: &Ctx) -> Result<Option<u64>> {
        let _ = ctx;

        Ok(None)
    }
}

/// One page of `enumerator`'s catalog, narrowed to what changed at or after
/// `since` when one is given.
pub async fn page_of(
    enumerator: &dyn Enumerator,
    since: Option<DateTime<Utc>>,
    cursor: Option<&Cursor>,
    ctx: &Ctx,
) -> Result<Page> {
    match since {
        Some(since) => enumerator.walk_since(since, cursor, ctx).await,
        None => enumerator.walk(cursor, ctx).await,
    }
}

/// Build an enumerator for a configured entry.
///
/// Takes no HTTP client, for the same reason a source does not: the host it
/// may reach is decided by the `Constraints` on the `host` it is built
/// with, not by anything it holds.
pub fn open_enumerator(
    kind: &str,
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Enumerator>> {
    // Named so a configuration written for it learns why, rather than
    // reading as a typo.
    if kind == REMOVED_MAVEN_CENTRAL {
        return Err(Error::Config(
            "the maven-central-index enumerator was removed: Maven Central's terms forbid \
             enumerating its catalog, and this tool is not for mirroring public registries. \
             To inspect known artifacts with every published file, use a source of kind \
             'maven' with 'file-listing: html-index'"
                .to_owned(),
        ));
    }

    let Some(found) = enumerator_kind(kind) else {
        return Err(Error::UnknownKind {
            collection: "enumerator",
            kind: kind.to_owned(),
        });
    };

    (found.open)(base_url, options, host)
}

/// The enumerator kind that once walked Maven Central's index.
const REMOVED_MAVEN_CENTRAL: &str = "maven-central-index";

/// Every server's enumerator kinds.
fn enumerator_descriptors() -> impl Iterator<Item = &'static super::kind::EnumeratorKind> {
    super::SERVERS.iter().flat_map(|server| server.enumerators)
}

/// The enumerator kind named `kind`, if a server offers it.
fn enumerator_kind(kind: &str) -> Option<&'static super::kind::EnumeratorKind> {
    enumerator_descriptors().find(|found| found.name == kind)
}

/// Refuse a built-in enumerator kind's configuration that could never
/// walk, without building it, for `validate-config`.
pub(crate) fn check_enumerator(kind: &str, base_url: &str, options: &Options) -> Result<()> {
    let Some(found) = enumerator_kind(kind) else {
        return Ok(());
    };

    (found.check)(base_url, options)
}

/// Whether an enumerator kind can walk without credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Login {
    /// Anonymous walks work wherever the repository allows anonymous reads.
    Optional,

    /// The server refuses the walk to an anonymous caller, whatever the
    /// repository allows; its host must carry `authentication`.
    Required,
}

/// Whether `kind`, configured with `options`, needs its host to log in.
///
/// Declared rather than discovered, so `validate-config` and the start of a
/// walk can refuse an anonymous host before any request instead of failing
/// on the first page.
pub(crate) fn login(kind: &str, options: &Options) -> Result<Login> {
    let Some(found) = enumerator_kind(kind) else {
        return Ok(Login::Optional);
    };

    (found.login)(options)
}

/// The enumerator that walks an ecosystem's own protocol rather than a
/// server's API, for a repository whose server API needs a login.
fn native_kind(ecosystem: &EcosystemId) -> Option<&'static str> {
    enumerator_descriptors()
        .find(|found| found.native_for == Some(ecosystem.as_str()))
        .map(|found| found.name)
}

/// Why an enumerator needing a login was refused on an anonymous `host`,
/// and what to do instead.
///
/// One text for `validate-config` and for the walk, which refuse the same
/// thing at different times.
pub(crate) fn login_advice(kind: &str, host: &str, options: &Options) -> String {
    let native = options
        .ecosystem()
        .ok()
        .flatten()
        .and_then(|ecosystem| native_kind(&ecosystem));

    let instead = match native {
        Some(native) => format!("the repository kind's native enumerator, {native:?}"),
        None => "the repository kind's native enumerator".to_owned(),
    };

    format!(
        "kind {kind} needs a login with read permission, even on an anonymously readable \
         repository, and host {host:?} has no 'authentication'. Add it; or, if the server \
         allows anonymous queries, set the option 'anonymous: attempt'; or, if no login \
         can be used, switch to {instead}"
    )
}

/// Built-in enumerator kinds, for an error that names the alternatives.
pub(crate) fn enumerator_kinds() -> &'static [&'static str] {
    static ENUMERATOR_KINDS: LazyLock<Vec<&'static str>> =
        LazyLock::new(|| super::sorted(enumerator_descriptors().map(|found| found.name)));

    &ENUMERATOR_KINDS
}

/// Every spelling an enumerator's `kind` may take, proxies included.
pub(crate) fn all_enumerator_kinds() -> &'static [&'static str] {
    static ALL_ENUMERATOR_KINDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        super::sorted(
            enumerator_kinds()
                .iter()
                .chain(proxy_enumerator_kinds())
                .copied(),
        )
    });

    &ALL_ENUMERATOR_KINDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::testing::idle;
    use crate::model::LastDownload;
    use crate::model::{ArtifactId, Cause, Release, Version};
    use chrono::{DateTime, Utc};
    use std::sync::LazyLock;

    fn when(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("a valid timestamp")
            .with_timezone(&Utc)
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), name)
    }

    // -- Declaring what an enumerator can answer -------------------------------

    /// Both AQL kinds need a login; nothing else does.
    #[test]
    fn login_needed_only_by_aql_kinds() {
        let options = crate::ext::testing::options(serde_json::json!({}));

        for kind in enumerator_kinds() {
            let expected = match *kind {
                "artifactory" | "artifactory-oss" => Login::Required,
                _ => Login::Optional,
            };

            assert_eq!(login(kind, &options).expect("reads"), expected, "{kind}");
        }
    }

    #[test]
    fn login_advice_names_native_kind() {
        let advice = |ecosystem: &str| {
            login_advice(
                "artifactory",
                "h",
                &crate::ext::testing::options(serde_json::json!({"ecosystem": ecosystem})),
            )
        };

        assert!(advice("npm").contains("npm-replicate"));
        assert!(advice("pypi").contains("pypi-simple"));
        assert!(advice("raw").contains("native enumerator"));
    }

    #[test]
    fn depth_declared_by_enumerators() {
        let config = |ecosystem: &str| {
            crate::ext::testing::options(serde_json::json!({
                "repository": "r",
                "ecosystem": ecosystem,
            }))
        };

        // Repository managers list every version with its files.
        assert_eq!(
            NexusEnumerator::open("h://nexus.test", &config("maven"), idle())
                .expect("opens")
                .depth(),
            ListingDepth::Files
        );
        assert_eq!(
            ArtifactoryEnumerator::open("h://artifactory.test", &config("maven"), idle())
                .expect("opens")
                .depth(),
            ListingDepth::Files
        );
        assert_eq!(
            ArtifactKeeperEnumerator::open("h://keeper.test", &config("maven"), idle())
                .expect("opens")
                .depth(),
            ListingDepth::Files
        );

        // A registry index lists names.
        assert_eq!(
            PyPiEnumerator::new("h://pypi.test", idle()).depth(),
            ListingDepth::Names
        );
    }

    #[test]
    fn depth_names_by_default() {
        assert_eq!(PlainEnumerator.depth(), ListingDepth::Names);
    }

    /// The Pull Updates command depends on usage data, so it must be able
    /// to refuse before it starts rather than walk a catalog of millions
    /// and find every answer is `Unknown`.
    #[test]
    fn usage_reporting_declared_by_enumerators() {
        let config = |ecosystem: &str| {
            crate::ext::testing::options(serde_json::json!({
                "repository": "r",
                "ecosystem": ecosystem,
            }))
        };

        // Repository managers record a last-downloaded time per asset.
        assert!(
            NexusEnumerator::open("h://nexus.test", &config("maven"), idle())
                .expect("opens")
                .reports_last_download()
        );
        assert!(
            ArtifactoryEnumerator::open("h://artifactory.test", &config("maven"), idle())
                .expect("opens")
                .reports_last_download()
        );

        // Artifact Keeper only when asked to spend a request per file.
        assert!(
            !ArtifactKeeperEnumerator::open("h://keeper.test", &config("maven"), idle())
                .expect("opens")
                .reports_last_download()
        );

        // A registry index carries no usage data at all.
        assert!(!PyPiEnumerator::new("h://pypi.test", idle()).reports_last_download());
    }

    /// False is the default, which is the honest one: almost nothing can
    /// report this, so an enumerator that says nothing must not be taken to.
    #[test]
    fn usage_not_reported_by_default() {
        assert!(!PlainEnumerator.reports_last_download());
    }

    // -- The trait --------------------------------------------------------

    static MAVEN: LazyLock<[EcosystemId; 1]> = LazyLock::new(|| [EcosystemId::maven()]);

    /// An enumerator that reports usage data, as a repository manager would.
    struct TrackingEnumerator;

    #[async_trait]
    impl Enumerator for TrackingEnumerator {
        fn ecosystems(&self) -> &[EcosystemId] {
            &*MAVEN
        }

        async fn walk(&self, cursor: Option<&Cursor>, _ctx: &Ctx) -> Result<Page> {
            match cursor.map(Cursor::as_str) {
                None => Ok(Page::more(
                    vec![
                        Found::new(id("busy"))
                            .version(Version::new("1.0", Release::General))
                            .last_download(LastDownload::At(when("2024-06-01T00:00:00Z"))),
                        Found::new(id("idle"))
                            .version(Version::new("1.0", Release::General))
                            .last_download(LastDownload::Never),
                    ],
                    Cursor::new("page-2"),
                )),

                Some("page-2") => Ok(Page::last(vec![Found::new(id("last"))])),

                Some(other) => panic!("unexpected cursor {other}"),
            }
        }

        async fn count(&self, _ctx: &Ctx) -> Result<Option<u64>> {
            Ok(Some(3))
        }
    }

    /// An enumerator over a catalog with no usage data -- the common case.
    struct PlainEnumerator;

    #[async_trait]
    impl Enumerator for PlainEnumerator {
        fn ecosystems(&self) -> &[EcosystemId] {
            &*MAVEN
        }

        async fn walk(&self, _cursor: Option<&Cursor>, _ctx: &Ctx) -> Result<Page> {
            Ok(Page::last(vec![Found::new(id("lib"))]))
        }
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Enumerated {
            enumerator: "test".into(),
        })
    }

    #[tokio::test]
    async fn walk_follows_cursors_to_end() {
        let ctx = ctx();

        let enumerator = TrackingEnumerator;
        let mut names = Vec::new();
        let mut cursor = None;

        loop {
            let page = enumerator
                .walk(cursor.as_ref(), &ctx)
                .await
                .expect("walked");

            names.extend(page.found.iter().map(|found| found.id.name().to_owned()));

            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        assert_eq!(names, ["busy", "idle", "last"]);
    }

    /// The point of the whole exercise: an enumerator that knows can say so,
    /// per artifact, and two artifacts in one page can differ.
    #[tokio::test]
    async fn usage_reported_per_artifact() {
        let ctx = ctx();

        let page = TrackingEnumerator.walk(None, &ctx).await.expect("walked");
        let cutoff = when("2025-01-01T00:00:00Z");

        let busy = &page.found[0];
        let idle = &page.found[1];

        assert_eq!(
            busy.last_download,
            LastDownload::At(when("2024-06-01T00:00:00Z"))
        );
        assert!(busy.last_download.known_unused_since(cutoff));
        assert_eq!(idle.last_download, LastDownload::Never);
    }

    /// An enumerator over a catalog with no statistics reports `Unknown`, and
    /// nothing downstream may read that as disuse.
    #[tokio::test]
    async fn usage_none_claimed_without_statistics() {
        let ctx = ctx();

        let page = PlainEnumerator.walk(None, &ctx).await.expect("walked");
        let found = &page.found[0];

        assert_eq!(found.last_download, LastDownload::Unknown);
        assert!(
            !found
                .last_download
                .known_unused_since(when("2099-01-01T00:00:00Z"))
        );
    }

    /// `--sample-size=N%` needs a total, and an enumerator that would have to
    /// walk the catalog to produce one says `None` rather than guessing.
    #[tokio::test]
    async fn count_optional() {
        let ctx = ctx();

        assert_eq!(
            TrackingEnumerator.count(&ctx).await.expect("counted"),
            Some(3)
        );
        assert_eq!(PlainEnumerator.count(&ctx).await.expect("counted"), None);
    }

    /// A version is optional: npm's feed yields names, and the versions
    /// cost a packument each.
    #[tokio::test]
    async fn names_without_versions_allowed() {
        let ctx = ctx();

        let page = PlainEnumerator.walk(None, &ctx).await.expect("walked");

        assert_eq!(page.found[0].version, None);
    }

    #[test]
    fn ecosystems_declared_by_enumerator() {
        assert_eq!(TrackingEnumerator.ecosystems(), [EcosystemId::maven()]);
    }
}
