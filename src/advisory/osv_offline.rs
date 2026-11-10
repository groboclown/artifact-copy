//! The OSV bucket's per-ecosystem `all.zip`.
//!
//! OSV publishes every record it holds as a flat archive per ecosystem, in a
//! public bucket with no authentication and no rate limit worth planning
//! around. One request per ecosystem gets the whole corpus, which is the
//! only shape that works here: the alternative is OSV's query API, and a
//! walk of a million artifacts cannot be a million queries -- nor should a
//! mirroring tool tell a public service everything its organization
//! depends on.
//!
//! ```text
//!   {base}/{OSV name}/all.zip   ->   <ID>.json, one record each
//! ```
//!
//! # The ecosystems fetched are the ecosystems keyable
//!
//! Which corpora to download is read from the index's own
//! [`Ecosystems`](super::Ecosystems) table rather than from a list of this
//! module's own. That is not tidiness: an advisor that downloaded an
//! ecosystem the index cannot translate would file every record it read
//! under [`Index::untranslated`] and screen those artifacts against nothing,
//! reporting a clean run. Reading both from one table makes the two lists
//! the same list.
//!
//! The OSV name is also what the URL needs, and it is **not** derivable from
//! the purl type -- `PyPI`, `Maven`, `crates.io` -- so a bucket path built
//! by lower-casing would 404. [`Ecosystems::osv_name`](super::Ecosystems::osv_name)
//! is the published spelling, which is why the table keeps it beside the
//! lower-cased lookup key.
//!
//! # An ecosystem with no corpus
//!
//! Not every ecosystem has one: OSV has no GitHub-releases feed, and a
//! third-party ecosystem may have no OSV presence at all. A 404 for one
//! ecosystem is **not** a failed corpus -- it is a corpus that does not
//! exist, which is a different claim from one that could not be reached --
//! so it is skipped and the others still load. A run whose *every* configured
//! ecosystem answered nothing gets no records, and that is what
//! `advisory-source-unavailable` is for.
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::ExtHost;
use crate::model::EcosystemId;
use crate::net::Req;

use super::archive::{self, Freshness, Origin, Tally};
use super::index::Index;
use super::{Advisor, Loaded, Settings};

/// Where OSV publishes the corpora.
///
/// A Google Cloud Storage bucket served over plain HTTPS. Named here rather
/// than required in configuration because it is the published location of a
/// public corpus, and a user who has to look it up to turn screening on will
/// not turn screening on.
pub const OSV_BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// This advisor's configured `kind`.
pub const KIND: &str = "osv-offline";

/// This corpus's kind, for [`super::open`].
pub(super) const ADVISOR: super::AdvisorKind = super::AdvisorKind {
    name: KIND,
    open: |base_url, settings, _, host| Ok(Box::new(configured(base_url, settings, host))),
};

/// The corpus at `base_url`, as `settings` configure it.
fn configured(base_url: &str, settings: &Settings, host: Arc<dyn ExtHost>) -> OsvOffline {
    let mut advisor = OsvOffline::at(base_url, host).for_ecosystems(settings.ecosystems.clone());

    if let Some(ttl) = settings.ttl {
        advisor = advisor.with_ttl(ttl);
    }

    if let Some(path) = &settings.path {
        advisor = advisor.from_file(path);
    }

    advisor
}

/// What a user-supplied archive is called inside the cache.
///
/// One name whatever the file was called outside, so a second run with a
/// differently named copy of the same corpus does not leave the first
/// behind in the cache directory.
const LOCAL_FILE: &str = "osv-supplied.zip";

/// The OSV bucket, read per ecosystem.
pub struct OsvOffline {
    base_url: String,

    /// Where every request goes, and whose directory caches the corpus.
    host: Arc<dyn ExtHost>,

    /// Which ecosystems to fetch, or empty for every one the run speaks.
    ///
    /// A narrowing rather than a declaration: an ecosystem named here that
    /// the index cannot key is still not fetched, because the URL needs an
    /// OSV name and only the table has one.
    only: Vec<EcosystemId>,

    /// How long a cached corpus stays usable. `advisors.*.ttl`.
    ttl: Duration,

    /// An archive on disk to read instead of fetching anything.
    ///
    /// For an air-gapped run, or one whose corpora are mirrored by
    /// something other than this tool. One file rather than one per
    /// ecosystem, because that is what the bucket's own combined `all.zip`
    /// is -- and the index keys whatever ecosystems it finds inside, so
    /// nothing here has to be told which they are.
    local: Option<PathBuf>,
}

impl OsvOffline {
    /// Every ecosystem the run speaks, from the published bucket.
    pub fn new(host: Arc<dyn ExtHost>) -> Self {
        Self::at(OSV_BUCKET, host)
    }

    /// From somewhere else, which is how this is tested and how a mirror of
    /// the bucket is used.
    pub fn at(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: crate::net::normalized_base(base_url),
            host,
            only: Vec::new(),
            ttl: archive::DEFAULT_TTL,
            local: None,
        }
    }

    /// Read `path` instead of fetching, and make no request at all.
    ///
    /// `advisors.*.path`. The file is an OSV archive somebody else
    /// downloaded -- the bucket's combined `all.zip`, or one ecosystem's --
    /// and it is read under exactly the rules a fetched one is.
    pub fn from_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.local = Some(path.into());

        self
    }

    /// How long a cached corpus stays usable before a refresh is attempted.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;

        self
    }

    /// Fetch only these ecosystems.
    ///
    /// `advisors.*.ecosystems` in the configuration, whose documented
    /// meaning is that empty is all of them.
    pub fn for_ecosystems(mut self, only: Vec<EcosystemId>) -> Self {
        self.only = only;

        self
    }

    /// `{base}/{OSV name}/all.zip`.
    ///
    /// The name is percent-encoded because an ecosystem's OSV name is not
    /// guaranteed to be URL-safe -- OSV suffixes a distribution release onto
    /// one, as in `Alpine:v3.16` -- and a raw colon in a path segment is
    /// not something to hand to a URL parser and hope.
    fn corpus_url(&self, osv_name: &str) -> String {
        format!(
            "{}/{}/all.zip",
            self.base_url,
            crate::net::encode_unreserved(osv_name)
        )
    }

    /// The ecosystems to fetch, each with the OSV name its URL needs.
    ///
    /// An ecosystem asked for that the table does not know is refused rather
    /// than skipped: the user named it, and silently not screening something
    /// somebody asked to have screened is the failure this whole module is
    /// built to avoid.
    fn planned(&self, index: &Index) -> Result<Vec<(EcosystemId, String)>> {
        if self.only.is_empty() {
            return Ok(index
                .ecosystems()
                .all()
                .map(|(id, osv_name)| (id.clone(), osv_name.to_owned()))
                .collect());
        }

        self.only
            .iter()
            .map(|id| match index.ecosystems().osv_name(id) {
                Some(osv_name) => Ok((id.clone(), osv_name.to_owned())),

                None => Err(Error::Config(format!(
                    "the {KIND} advisor was asked for the {id} ecosystem, \
                     which declares no OSV name to fetch a corpus under"
                ))),
            })
            .collect()
    }
}

impl OsvOffline {
    /// Read the archive the user named, and ask for nothing.
    async fn read_local(&self, path: &Path, index: &mut Index) -> Result<Loaded> {
        let acquired = archive::local(&*self.host, path, LOCAL_FILE).await?;
        let named = path.display().to_string();

        // Narrowed as it is read: a supplied file may be the bucket's
        // combined archive, which holds every ecosystem.
        let read = archive::read_zip_from_host(
            &acquired.file,
            &named,
            |_| true,
            &self.only,
            index,
            &*self.host,
        )
        .await?;

        Ok(Loaded {
            modified: read.modified,
            tally: read,
            origin: acquired.origin,
        })
    }
}

#[async_trait]
impl Advisor for OsvOffline {
    async fn load(&self, index: &mut Index, freshness: Freshness, ctx: &Ctx) -> Result<Loaded> {
        // A file somebody supplied replaces the whole plan rather than
        // narrowing it: they said which archive to read, and asking the
        // bucket for the rest would be a request they did not ask for.
        if let Some(path) = &self.local {
            return self.read_local(path, index).await;
        }

        let mut tally = Tally::default();
        let mut origin = None;

        for (id, osv_name) in self.planned(index)? {
            let url = self.corpus_url(&osv_name);
            let name = format!("osv-{}-all.zip", id.as_str());

            let acquired = match archive::acquire(
                &*self.host,
                &Req::get(&url),
                &name,
                self.ttl,
                freshness,
                ctx,
            )
            .await
            {
                Ok(acquired) => acquired,

                // No corpus for this ecosystem. Distinct from one that
                // could not be reached, and the module documentation
                // says why the difference matters. Reachable only when
                // nothing was cached, since `acquire` prefers a stale
                // copy to an error -- and nothing is ever cached for an
                // ecosystem the bucket does not publish.
                Err(err) if is_absent(&err) => continue,

                Err(err) => return Err(err),
            };

            // Every entry in this archive is a record: OSV publishes nothing
            // else in it.
            let read = archive::read_zip_from_host(
                &acquired.file,
                &url,
                |_| true,
                &self.only,
                index,
                &*self.host,
            )
            .await?;

            tally.add(read);

            origin = Some(match origin {
                Some(worst) => Origin::worst(worst, acquired.origin),
                None => acquired.origin,
            });
        }

        Ok(Loaded {
            modified: tally.modified,
            tally,
            origin: origin.unwrap_or_default(),
        })
    }
}

/// Whether a failure means *there is no such corpus* rather than *the corpus
/// could not be read*.
///
/// Only a 404 counts. A 403, a timeout or a connection refusal is a corpus
/// this run failed to consult, and treating one as an absence is how an
/// unscreened run comes to look like a clean one.
fn is_absent(err: &Error) -> bool {
    matches!(
        err,
        Error::HttpStatus {
            status: StatusCode::NOT_FOUND,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use crate::advisory::archive::Origin;
    use crate::advisory::index::Ecosystems;
    use crate::core::ctx::Ctx;
    use crate::ext::testing::{Fixture, idle};
    use crate::model::{ArtifactId, Cause};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://osv.test";

    fn zipped(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buffer = Vec::new();

        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));

            for (name, body) in entries {
                writer
                    .start_file(*name, zip::write::SimpleFileOptions::default())
                    .expect("entry");
                writer.write_all(body).expect("written");
            }

            writer.finish().expect("finished");
        }

        buffer
    }

    fn record(id: &str, ecosystem: &str, name: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"{id}","modified":"2024-06-01T00:00:00Z",
                "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{name}"}},
                              "versions":["1.0.0"]}}]}}"#
        )
        .into_bytes()
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "advisories".to_owned(),
        })
    }

    fn corpus(ecosystem: &str) -> String {
        format!("{BASE}/{ecosystem}/all.zip")
    }

    /// Every built-in ecosystem answers, so a default run fetches all of
    /// them.
    fn serving_all() -> FixtureClient {
        FixtureClient::new()
            .with_body(
                corpus("npm"),
                zipped(&[("GHSA-n.json", &record("GHSA-n", "npm", "tuna"))]),
            )
            .with_body(
                corpus("PyPI"),
                zipped(&[("GHSA-p.json", &record("GHSA-p", "PyPI", "requests"))]),
            )
            .with_body(
                corpus("Maven"),
                zipped(&[("GHSA-m.json", &record("GHSA-m", "Maven", "g:a"))]),
            )
    }

    async fn load(
        client: FixtureClient,
        build: impl FnOnce(Arc<dyn ExtHost>) -> OsvOffline,
    ) -> (Result<Loaded>, Index, Fixture<()>) {
        let f = Fixture::new((), client);
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());
        let loaded = build(f.shared())
            .load(&mut index, Freshness::Cached, &ctx)
            .await;

        (loaded, index, f)
    }

    // -- The URL -----------------------------------------------------------

    /// A bucket path is case-sensitive, so the published spelling is the
    /// only one that works.
    #[test]
    fn corpus_url_uses_osv_spelling() {
        let advisor = OsvOffline::at(BASE, idle());

        assert_eq!(advisor.corpus_url("PyPI"), format!("{BASE}/PyPI/all.zip"));
        assert_eq!(
            advisor.corpus_url("crates.io"),
            format!("{BASE}/crates.io/all.zip")
        );
    }

    /// OSV suffixes a distribution release onto an ecosystem name, and a
    /// raw colon is not something to hand to a URL parser and hope.
    #[test]
    fn ecosystem_name_encoded_for_path() {
        assert_eq!(
            OsvOffline::at(BASE, idle()).corpus_url("Alpine:v3.16"),
            format!("{BASE}/Alpine%3Av3.16/all.zip")
        );
    }

    // -- What gets fetched -------------------------------------------------

    #[tokio::test]
    async fn ecosystem_every_spoken_fetched() {
        let (loaded, index, f) = load(serving_all(), |host| OsvOffline::at(BASE, host)).await;

        assert_eq!(loaded.expect("loaded").tally.parsed, 3);
        assert_eq!(index.records(), 3);

        assert_eq!(f.host.hits(&corpus("npm")), 1);
        assert_eq!(f.host.hits(&corpus("PyPI")), 1);
        assert_eq!(f.host.hits(&corpus("Maven")), 1);
    }

    /// `github` declares no OSV name, so there is no corpus to ask for.
    /// Asking would be a request to a URL that cannot exist.
    #[tokio::test]
    async fn ecosystem_without_osv_name_never_requested() {
        let (_, _, f) = load(serving_all(), |host| OsvOffline::at(BASE, host)).await;

        assert!(
            !f.host.requested().iter().any(|url| url.contains("github")),
            "{:?}",
            f.host.requested()
        );
    }

    /// `advisors.*.ecosystems`, whose documented meaning is that empty is
    /// all of them.
    #[tokio::test]
    async fn ecosystem_narrowed_fetches_only_named() {
        let (loaded, index, f) = load(serving_all(), |host| {
            OsvOffline::at(BASE, host).for_ecosystems(vec![EcosystemId::npm()])
        })
        .await;

        assert_eq!(loaded.expect("loaded").tally.parsed, 1);
        assert_eq!(index.records(), 1);
        assert_eq!(f.host.requested(), vec![corpus("npm")]);
    }

    /// The user named it, and silently not screening something somebody
    /// asked to have screened is the failure this module exists to avoid.
    #[tokio::test]
    async fn ecosystem_without_corpus_refused_when_named() {
        let (loaded, _, _) = load(serving_all(), |host| {
            OsvOffline::at(BASE, host).for_ecosystems(vec![EcosystemId::raw()])
        })
        .await;

        let message = loaded.expect_err("refused").to_string();

        assert!(message.contains("raw"), "{message}");
        assert!(message.contains("no OSV name"), "{message}");
    }

    // -- What the records become -------------------------------------------

    /// The point of all of it: a record from the corpus answers about an
    /// artifact, keyed the way the walk will ask.
    #[tokio::test]
    async fn load_record_answers_for_package() {
        let (_, index, _) = load(serving_all(), |host| OsvOffline::at(BASE, host)).await;

        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");
        let maven = ArtifactId::new(EcosystemId::maven(), Some("g"), "a");

        assert_eq!(index.advisories(&tuna)[0].advisory().id, "GHSA-n");
        assert_eq!(index.advisories(&maven)[0].advisory().id, "GHSA-m");
    }

    #[tokio::test]
    async fn load_returns_corpus_age() {
        let (loaded, _, _) = load(serving_all(), |host| OsvOffline::at(BASE, host)).await;

        assert_eq!(
            loaded
                .expect("loaded")
                .modified
                .expect("dated")
                .to_rfc3339(),
            "2024-06-01T00:00:00+00:00"
        );
    }

    // -- Absent versus unreachable -----------------------------------------

    /// A 404 is a corpus that does not exist, which is a different claim
    /// from one that could not be reached.
    #[tokio::test]
    async fn ecosystem_unpublished_skipped() {
        let client = serving_all().with(corpus("PyPI"), Canned::status(StatusCode::NOT_FOUND));

        let (loaded, index, _) = load(client, |host| OsvOffline::at(BASE, host)).await;

        assert_eq!(loaded.expect("loaded").tally.parsed, 2);
        assert_eq!(index.records(), 2);
    }

    /// **The distinction that decides whether an unscreened run reads as
    /// clean.** A 403 or a timeout is a corpus this run failed to consult,
    /// and carrying on would report every artifact in that ecosystem as
    /// screened and clean.
    #[tokio::test]
    async fn ecosystem_unreachable_fails_load() {
        let client = serving_all().with(corpus("PyPI"), Canned::status(StatusCode::FORBIDDEN));

        let (loaded, _, _) = load(client, |host| OsvOffline::at(BASE, host)).await;

        assert!(loaded.is_err(), "403 is not an absence");
    }

    #[tokio::test]
    async fn corpus_not_zip_fails_load() {
        let client = serving_all().with_body(corpus("npm"), b"<html>no</html>".to_vec());

        let (loaded, _, _) = load(client, |host| OsvOffline::at(BASE, host)).await;

        assert!(loaded.is_err());
    }

    // -- Two corpora into one index ----------------------------------------

    /// `load` fills the caller's index, which is what lets a second advisor
    /// add to the same one -- and what makes the de-duplication possible.
    #[tokio::test]
    async fn load_second_adds_to_same_index() {
        let f = Fixture::new((), serving_all());
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        OsvOffline::at(BASE, f.shared())
            .for_ecosystems(vec![EcosystemId::npm()])
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("first");

        OsvOffline::at(BASE, f.shared())
            .for_ecosystems(vec![EcosystemId::maven()])
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("second");

        assert_eq!(index.records(), 2);
        assert_eq!(index.packages(), 2);
    }

    // -- Caching, and a file the user supplied -----------------------------

    /// A second run inside the TTL asks for nothing. The whole reason the
    /// corpus is cached at all.
    #[tokio::test]
    async fn cache_corpus_read_by_second_run() {
        let f = Fixture::new((), serving_all());
        let ctx = ctx();

        let advisor = OsvOffline::at(BASE, f.shared()).for_ecosystems(vec![EcosystemId::npm()]);

        let mut first = Index::new(Ecosystems::builtin());
        let loaded = advisor
            .load(&mut first, Freshness::Cached, &ctx)
            .await
            .expect("first run");

        assert_eq!(loaded.origin, Origin::Downloaded);

        // A fresh index, as a second run would have, over the same host
        // directory.
        let mut second = Index::new(Ecosystems::builtin());
        let loaded = advisor
            .load(&mut second, Freshness::Cached, &ctx)
            .await
            .expect("second run");

        assert_eq!(loaded.origin, Origin::Cached);
        assert_eq!(second.records(), 1, "and it still screens");
        assert_eq!(f.host.hits(&corpus("npm")), 1);
    }

    /// `--refresh-advisories`, which must beat a copy still inside its TTL
    /// or the flag does nothing.
    #[tokio::test]
    async fn cache_refresh_asks_again() {
        let f = Fixture::new((), serving_all());
        let ctx = ctx();

        let advisor = OsvOffline::at(BASE, f.shared()).for_ecosystems(vec![EcosystemId::npm()]);

        let mut index = Index::new(Ecosystems::builtin());
        advisor
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("first");

        let mut again = Index::new(Ecosystems::builtin());
        advisor
            .load(&mut again, Freshness::Refresh, &ctx)
            .await
            .expect("second");

        assert_eq!(f.host.hits(&corpus("npm")), 2);
    }

    /// An ecosystem the bucket does not publish is still skipped rather
    /// than falling back to a stale copy, because there is never a copy:
    /// nothing was downloaded for it in the first place.
    #[tokio::test]
    async fn cache_unpublished_ecosystem_still_skipped() {
        let client = serving_all().with(corpus("PyPI"), Canned::status(StatusCode::NOT_FOUND));

        let f = Fixture::new((), client);
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        let loaded = OsvOffline::at(BASE, f.shared())
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("the others loaded");

        assert_eq!(loaded.tally.parsed, 2);
    }

    /// An air-gapped run, or one whose corpora are mirrored by something
    /// other than this tool. The file is the bucket's own archive, so the
    /// index keys whatever ecosystems it finds inside.
    #[tokio::test]
    async fn supplied_file_read_instead_of_bucket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("all.zip");

        std::fs::write(
            &path,
            zipped(&[
                ("GHSA-n.json", &record("GHSA-n", "npm", "tuna")),
                ("GHSA-m.json", &record("GHSA-m", "Maven", "g:a")),
            ]),
        )
        .expect("written");

        let f = Fixture::new((), serving_all());
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        let loaded = OsvOffline::at(BASE, f.shared())
            .from_file(&path)
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("read from disk");

        assert_eq!(loaded.origin, Origin::Local);
        assert_eq!(loaded.tally.parsed, 2);

        assert!(
            f.host.requested().is_empty(),
            "nothing was asked for: {:?}",
            f.host.requested()
        );

        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");
        let maven = ArtifactId::new(EcosystemId::maven(), Some("g"), "a");

        assert_eq!(index.advisories(&tuna).len(), 1);
        assert_eq!(index.advisories(&maven).len(), 1);
    }

    /// A supplied file replaces the whole plan rather than narrowing it:
    /// the user said which archive to read, so asking the bucket for the
    /// rest would be a request they did not ask for.
    #[tokio::test]
    async fn supplied_file_suppresses_every_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("all.zip");

        std::fs::write(
            &path,
            zipped(&[("GHSA-n.json", &record("GHSA-n", "npm", "tuna"))]),
        )
        .expect("written");

        let f = Fixture::new((), serving_all());
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        OsvOffline::at(BASE, f.shared())
            .from_file(&path)
            .for_ecosystems(vec![EcosystemId::npm(), EcosystemId::maven()])
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("read from disk");

        assert!(f.host.requested().is_empty());
    }

    /// A file that is not there is the user's mistake and is reported as
    /// one, rather than quietly falling back to the network.
    #[tokio::test]
    async fn supplied_file_missing_fails_not_fetches() {
        let f = Fixture::new((), serving_all());
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        let outcome = OsvOffline::at(BASE, f.shared())
            .from_file("/nonexistent/all.zip")
            .load(&mut index, Freshness::Cached, &ctx)
            .await;

        assert!(outcome.is_err());
        assert!(f.host.requested().is_empty());
    }
}
