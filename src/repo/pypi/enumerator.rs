//! Enumerating PyPI, or any PEP 503 index.
//!
//! ```text
//!   GET {base}/simple/    Accept: application/vnd.pypi.simple.v1+json
//! ```
//!
//! One request returns every project name the index holds -- about 650,000
//! for PyPI proper, in a document of some tens of megabytes. That shape is
//! unlike every other enumerator here: there is no pagination to follow,
//! because the index is not paginated. It is one document, and the paging
//! is this enumerator's own.
//!
//! # The index goes to disk, not into a response buffer
//!
//! The document is far too large to be a capped in-memory fetch, so it is
//! streamed into the host's cache and read from there, and reused while it
//! is within its freshness: `simple-index.json` in `cache-freshness`, a day
//! by default. See [`crate::ext::Cache`].
//!
//! # Known ceiling
//!
//! The parsed **names** are held in memory for the walk: roughly 15 MB for
//! PyPI. That is bounded by the size of the registry's catalog rather than
//! by anything the run does, in the same way the advisory index is, and it
//! is paid once rather than per page.
//!
//! It is still a real ceiling and worth naming. The fix, if a registry ever
//! outgrows it, is to index byte offsets into the staged file and read each
//! page back from disk; that is an implementation change behind
//! [`Enumerator::walk`], which already declines to return more than a page.
//!
//! # What this enumerator cannot tell you
//!
//! Names only. A PEP 503 index lists projects, not versions, and it carries
//! no usage data at all -- so every artifact comes back with no version and
//! [`LastDownload::Unknown`]. Resolving versions costs one request per
//! project, which is the spider's job and not an enumerator's.
//!
//! References: [PEP 503](https://peps.python.org/pep-0503/), [PEP 691](https://peps.python.org/pep-0691/).

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
// What the index is called inside the cache, and the name a freshness
// rule matches.
use crate::ecosystem::pypi::INDEX_DOCUMENT as INDEX_FILE;
use crate::ext::{
    CachePath, Expiry, ExtHost, Hold, Judged, Options, gone, report_expired, report_stale, settle,
};
use crate::model::{ArtifactId, EcosystemId};
use crate::net::{ByteLimit, Expectation, Req, normalized_base};
use crate::repo::enumerate::{Cursor, Enumerator, Found, Page};
use crate::repo::pep503;

/// The PEP 691 content negotiation header.
///
/// Without it the index answers HTML, and parsing anchors for data the JSON
/// form states outright is a worse job done less reliably.
const ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// A ceiling on the index document.
///
/// PyPI's is around 25 MB today and grows with the registry. Generous
/// enough to outlast that growth for years, and bounded so a hostile or
/// broken index cannot fill the disk.
const INDEX_LIMIT: ByteLimit = ByteLimit::mib(512);

/// How many names to return per page.
///
/// A page is what the caller holds at once, so it is kept small enough to
/// be unremarkable while large enough that 650,000 names do not become
/// 650,000 round trips through the walk loop.
const PAGE_SIZE: usize = 1_000;

/// The option `cache-freshness` replaced, refused so a configuration still
/// naming it says so rather than having it quietly ignored.
const RETIRED_INDEX_TTL_OPTION: &str = "index-ttl";

pub struct PyPiEnumerator {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,

    /// The project names, read once, on the first walk or count.
    names: OnceCell<Vec<String>>,
}

impl PyPiEnumerator {
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: normalized_base(base_url),
            host,
            names: OnceCell::new(),
        }
    }

    /// Build from configuration.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        if options.keys().contains(&RETIRED_INDEX_TTL_OPTION) {
            return Err(Error::Config(format!(
                "the pypi-simple option '{RETIRED_INDEX_TTL_OPTION}' was replaced by \
                 'cache-freshness' on the enumerator, with a rule for '{INDEX_FILE}'"
            )));
        }

        Ok(Self::new(base_url, host))
    }

    fn index_url(&self) -> String {
        format!("{}/simple/", self.base_url)
    }

    /// Every project name the index lists, read at most once per run.
    async fn names(&self, ctx: &Ctx) -> Result<&Vec<String>> {
        self.names
            .get_or_try_init(|| async {
                let url = self.index_url();
                // Held through the read, so no size cap removes it first.
                let (staged, _hold) = self.index(&url, ctx).await?;

                let body = self.host.cache().read(&staged, INDEX_LIMIT).await?;

                let names = parse_names(&body).map_err(|detail| Error::Malformed {
                    what: "pypi simple index",
                    url: url.clone(),
                    detail,
                })?;

                Ok(names
                    .into_iter()
                    .filter(|name| !name.trim().is_empty())
                    .collect())
            })
            .await
    }

    /// The cached index while it is within its lifetime, and a fresh
    /// download otherwise -- or, when that download fails, the copy past
    /// its freshness, with a warning, as any cached document would be.
    ///
    /// Streamed to disk rather than held in memory: the document is tens of
    /// megabytes, and a capped in-memory fetch large enough to hold it would
    /// defeat the point of the cap.
    async fn index(&self, url: &str, ctx: &Ctx) -> Result<(CachePath, Hold)> {
        let cache = self.host.cache();
        let path = cache.path(INDEX_FILE)?;
        let lifetime = self.host.cache_policy().lifetime(INDEX_FILE);

        let expired = match cache.judge(&path, &lifetime) {
            Judged::Usable => {
                let _ = cache.touch(&path, &lifetime);
                let hold = cache.hold(&path);

                return Ok((path, hold));
            }

            Judged::Expired(expiry) => {
                report_expired(ctx, url, INDEX_FILE, expiry);

                Some(expiry)
            }

            Judged::Absent | Judged::Undated => None,
        };

        if expired == Some(Expiry::Retention) {
            cache.evict(&path);
        }

        let fetched = self
            .host
            .fetch_to_cache(
                &Req::get(url).accept(ACCEPT),
                INDEX_FILE,
                &Expectation::new(),
                ctx,
            )
            .await;

        match fetched {
            Ok(fetched) => {
                let hold = cache.hold(&fetched);
                settle(&*self.host, &fetched, url, INDEX_FILE, &lifetime, ctx)?;

                Ok((fetched, hold))
            }

            Err(err) if expired == Some(Expiry::Freshness) && !gone(&err) => {
                report_stale(ctx, url, INDEX_FILE, &err);
                let hold = cache.hold(&path);

                Ok((path, hold))
            }

            Err(err) => Err(err),
        }
    }
}

/// Built once, because [`Enumerator::ecosystems`] lends it out.
static PYPI_ECOSYSTEMS: LazyLock<[EcosystemId; 1]> = LazyLock::new(|| [EcosystemId::pypi()]);

#[async_trait]
impl Enumerator for PyPiEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        &*PYPI_ECOSYSTEMS
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        let names = self.names(ctx).await?;

        let start: usize = cursor
            .map(Cursor::as_str)
            .and_then(|text| text.parse().ok())
            .unwrap_or(0)
            .min(names.len());

        let end = (start + PAGE_SIZE).min(names.len());

        let found = names[start..end]
            .iter()
            .map(|name| {
                // Normalized per PEP 503, because `Foo_Bar`, `foo-bar` and
                // `foo.bar` are one project and three purls would be three
                // entries in a report for one package.
                let normalized = crate::ecosystem::pypi::normalize(name);

                // No version and no usage data: the index carries neither.
                // Claiming either would be an invention.
                Found::new(ArtifactId::new(EcosystemId::pypi(), None, &normalized))
            })
            .collect();

        match end < names.len() {
            true => Ok(Page::more(found, Cursor::new(end.to_string()))),
            false => Ok(Page::last(found)),
        }
    }

    /// Exact, and cheap after the first page.
    ///
    /// The index is one document, so counting it is counting a list already
    /// in hand. This is the enumerator that makes `--sample-size=N%` mean
    /// something -- everything else here has to answer `None`.
    async fn count(&self, ctx: &Ctx) -> Result<Option<u64>> {
        Ok(Some(self.names(ctx).await?.len() as u64))
    }
}

/// Project names from the root page, in either form.
///
/// PEP 503 HTML is what an index without PEP 691 answers, such as Nexus 3:
/// one `<a href="echo/">echo</a>` per project, the text being the name.
fn parse_names(body: &[u8]) -> std::result::Result<Vec<String>, String> {
    if pep503::is_html(body) {
        let links = pep503::links(&String::from_utf8_lossy(body))?;

        return Ok(links.into_iter().map(|link| link.text).collect());
    }

    let index: SimpleIndex = serde_json::from_slice(body).map_err(|source| source.to_string())?;

    Ok(index
        .projects
        .into_iter()
        .map(|project| project.name)
        .collect())
}

#[derive(Debug, Deserialize)]
struct SimpleIndex {
    #[serde(default)]
    projects: Vec<Project>,
}

#[derive(Debug, Deserialize)]
struct Project {
    #[serde(default)]
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::core::problem::Code;
    use crate::ext::testing::{Fixture, idle};
    use crate::ext::{CachePolicy, FreshnessRule, Policed};
    use crate::model::Cause;
    use crate::net::FixtureClient;
    use std::time::Duration;

    const INDEX: &str = "h://pypi.test";

    fn index_url() -> String {
        format!("{INDEX}/simple/")
    }

    fn body(names: &[&str]) -> String {
        serde_json::json!({
            "meta": {"api-version": "1.0"},
            "projects": names.iter().map(|n| serde_json::json!({"name": n})).collect::<Vec<_>>(),
        })
        .to_string()
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Enumerated {
            enumerator: "pypi-simple".into(),
        })
    }

    fn fixture(names: &[&str]) -> Fixture<PyPiEnumerator> {
        Fixture::build(
            FixtureClient::new().with_body(index_url(), body(names)),
            |host| PyPiEnumerator::new(INDEX, host),
        )
    }

    /// Walk to the end, collecting every name.
    async fn walk_all(f: &Fixture<PyPiEnumerator>, ctx: &Ctx) -> Vec<String> {
        let mut names = Vec::new();
        let mut cursor = None;

        loop {
            let page = f.subject.walk(cursor.as_ref(), ctx).await.expect("walked");

            names.extend(page.found.iter().map(|found| found.id.name().to_owned()));

            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        names
    }

    // -- Walking ----------------------------------------------------------

    #[tokio::test]
    async fn names_every_project_found() {
        let f = fixture(&["requests", "flask", "django"]);
        let ctx = ctx();

        let mut names = walk_all(&f, &ctx).await;
        names.sort();

        assert_eq!(names, ["django", "flask", "requests"]);
    }

    /// `Foo_Bar`, `foo-bar` and `foo.bar` are one project. Three purls
    /// would be three entries in a report for one package.
    #[tokio::test]
    async fn names_normalized_per_pep_503() {
        let f = fixture(&["Zope.Interface", "Flask_SQLAlchemy", "ruamel.yaml"]);
        let ctx = ctx();

        let mut names = walk_all(&f, &ctx).await;
        names.sort();

        assert_eq!(names, ["flask-sqlalchemy", "ruamel-yaml", "zope-interface"]);
    }

    /// The index is one document with no pagination of its own, so the
    /// paging here is this enumerator's -- and it still has to be complete.
    #[tokio::test]
    async fn page_walks_large_catalog() {
        let names: Vec<String> = (0..PAGE_SIZE * 2 + 7)
            .map(|index| format!("project-{index}"))
            .collect();

        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        let f = fixture(&borrowed);
        let ctx = ctx();

        let first = f.subject.walk(None, &ctx).await.expect("walked");

        assert_eq!(first.found.len(), PAGE_SIZE);
        assert!(first.has_more());

        assert_eq!(walk_all(&f, &ctx).await.len(), names.len());
    }

    /// A PEP 503 index, such as Nexus 3, answers HTML to the JSON header.
    #[tokio::test]
    async fn index_html_walked() {
        let html = r#"<!DOCTYPE html>
<html><head><title>Simple index</title></head>
<body>
  <a href="Echo_Lib/">Echo_Lib</a><br/>
  <a href="scenario/">scenario</a><br/>
</body></html>"#;
        let f = Fixture::build(FixtureClient::new().with_body(index_url(), html), |host| {
            PyPiEnumerator::new(INDEX, host)
        });
        let ctx = ctx();

        let mut names = walk_all(&f, &ctx).await;
        names.sort();

        assert_eq!(names, ["echo-lib", "scenario"]);
    }

    #[tokio::test]
    async fn page_last_ends_walk() {
        let f = fixture(&["only"]);
        let ctx = ctx();

        let page = f.subject.walk(None, &ctx).await.expect("walked");

        assert_eq!(page.found.len(), 1);
        assert!(!page.has_more());
    }

    #[tokio::test]
    async fn index_empty_walks_to_nothing() {
        let f = fixture(&[]);
        let ctx = ctx();

        let page = f.subject.walk(None, &ctx).await.expect("walked");

        assert!(page.found.is_empty());
        assert!(!page.has_more());
    }

    /// The document is tens of megabytes; fetching it once per page would
    /// turn a 650,000-name catalog into 650 downloads of the same file.
    #[tokio::test]
    async fn index_fetched_once_per_walk() {
        let names: Vec<String> = (0..PAGE_SIZE * 3)
            .map(|index| format!("project-{index}"))
            .collect();

        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        let f = fixture(&borrowed);
        let ctx = ctx();

        walk_all(&f, &ctx).await;

        assert_eq!(f.host.hits(&index_url()), 1);
    }

    /// The document lands in the cache rather than in a response buffer.
    #[tokio::test]
    async fn index_kept_in_cache() {
        let f = fixture(&["requests"]);
        let ctx = ctx();

        f.subject.walk(None, &ctx).await.expect("walked");

        assert!(
            f.host.cache().root().join(INDEX_FILE).exists(),
            "the index should have been streamed to disk"
        );
    }

    // -- Reusing the cached index -------------------------------------------

    /// A later run inside the index's freshness reads the cached index and
    /// asks for nothing. Tens of megabytes per run is the cost this avoids.
    #[tokio::test]
    async fn index_fresh_reused_next_run() {
        let f = fixture(&["requests"]);
        let ctx = ctx();

        f.subject.walk(None, &ctx).await.expect("walked");

        let next_run = PyPiEnumerator::new(INDEX, f.shared());
        let page = next_run.walk(None, &ctx).await.expect("walked");

        assert_eq!(page.found.len(), 1);
        assert_eq!(f.host.hits(&index_url()), 1);
    }

    /// Past its freshness the index is fetched again, and the eviction is
    /// recorded.
    #[tokio::test]
    async fn index_expired_fetched_again() {
        let f = fixture(&["requests"]);
        let ctx = ctx();
        let policy = CachePolicy::new(
            None,
            vec![FreshnessRule::new(INDEX_FILE, Some(Duration::ZERO))],
        );

        f.subject.walk(None, &ctx).await.expect("walked");

        let next_run = PyPiEnumerator::new(INDEX, Arc::new(Policed::new(f.shared(), policy)));
        next_run.walk(None, &ctx).await.expect("walked");

        assert_eq!(f.host.hits(&index_url()), 2);
        assert_eq!(
            ctx.problems().counts().get(&Code::CacheEntryExpired),
            Some(&1)
        );
    }

    /// The option `cache-freshness` replaced says so, rather than being
    /// ignored and leaving somebody wondering why their setting does
    /// nothing.
    #[test]
    fn index_ttl_retired_refused() {
        let retired = crate::ext::testing::options(serde_json::json!({"index-ttl": "1 hour"}));

        let err = PyPiEnumerator::open(INDEX, &retired, idle())
            .err()
            .expect("refused");

        assert!(err.to_string().contains("cache-freshness"), "{err}");
    }

    // -- What it cannot say -----------------------------------------------

    /// A PEP 503 index lists projects, not versions. Inventing one would be
    /// worse than admitting there is none; resolving versions is one
    /// request per project, which is the spider's job.
    #[tokio::test]
    async fn versions_none_claimed() {
        let f = fixture(&["requests"]);
        let ctx = ctx();

        let page = f.subject.walk(None, &ctx).await.expect("walked");

        assert_eq!(page.found[0].version, None);
    }

    /// The index carries no usage data whatever, so `Unknown` is the only
    /// honest answer -- and must never be read as "never downloaded".
    #[tokio::test]
    async fn usage_unknown_not_never() {
        use crate::model::LastDownload;

        let f = fixture(&["requests"]);
        let ctx = ctx();

        let page = f.subject.walk(None, &ctx).await.expect("walked");

        assert_eq!(page.found[0].last_download, LastDownload::Unknown);
        assert!(
            !page.found[0]
                .last_download
                .known_unused_since(chrono::Utc::now())
        );
    }

    // -- Counting ---------------------------------------------------------

    /// The enumerator that makes `--sample-size=N%` mean something. Everything
    /// else here has to answer `None`, because counting would mean walking.
    #[tokio::test]
    async fn count_exact() {
        let f = fixture(&["a", "b", "c"]);
        let ctx = ctx();

        assert_eq!(f.subject.count(&ctx).await.expect("counted"), Some(3));
    }

    #[tokio::test]
    async fn index_fetch_shared_by_count_and_walk() {
        let f = fixture(&["a", "b"]);
        let ctx = ctx();

        f.subject.count(&ctx).await.expect("counted");
        walk_all(&f, &ctx).await;

        assert_eq!(f.host.hits(&index_url()), 1);
    }

    // -- Edges ------------------------------------------------------------

    #[tokio::test]
    async fn index_malformed_is_error() {
        let f = Fixture::build(FixtureClient::new().with_body(index_url(), "{["), |host| {
            PyPiEnumerator::new(INDEX, host)
        });

        let ctx = ctx();
        let err = f.subject.walk(None, &ctx).await.unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::MetadataMalformed);
    }

    /// An entry with no name is not a project, and an empty purl would be
    /// worse than a shorter catalog.
    #[tokio::test]
    async fn names_missing_dropped() {
        let f = Fixture::build(
            FixtureClient::new().with_body(
                index_url(),
                r#"{"projects": [{"name": "real"}, {"name": ""}, {}]}"#,
            ),
            |host| PyPiEnumerator::new(INDEX, host),
        );

        let ctx = ctx();
        let page = f.subject.walk(None, &ctx).await.expect("walked");

        assert_eq!(page.found.len(), 1);
        assert_eq!(page.found[0].id.name(), "real");
    }

    /// A cursor this enumerator did not issue must not crash the walk, and one
    /// past the end must not panic on the slice.
    #[tokio::test]
    async fn page_cursor_out_of_range_survivable() {
        let f = fixture(&["a", "b"]);
        let ctx = ctx();

        for cursor in ["not-a-number", "999999"] {
            let page = f
                .subject
                .walk(Some(&Cursor::new(cursor)), &ctx)
                .await
                .expect("walked");

            assert!(!page.has_more(), "{cursor}");
        }
    }

    #[tokio::test]
    async fn index_json_requested_not_html() {
        let f = fixture(&["a"]);
        let ctx = ctx();

        f.subject.walk(None, &ctx).await.expect("walked");

        // The fixture records URLs rather than headers, so this asserts the
        // endpoint; the `Accept` is set on the request beside it.
        assert_eq!(f.host.requested(), [index_url()]);
    }

    #[test]
    fn ecosystem_is_pypi() {
        let enumerator = PyPiEnumerator::new(INDEX, idle());

        assert_eq!(enumerator.ecosystems(), [EcosystemId::pypi()]);
        assert!(!enumerator.reports_last_download());
    }
}
