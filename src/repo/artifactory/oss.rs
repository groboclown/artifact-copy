//! Enumerating an Artifactory OSS repository, over windowed AQL.
//!
//! OSS refuses any AQL `sort` ("Sorting is not supported by AQL in the open
//! source version", measured on 7.161.26), and an offset into an unsorted
//! result is not a position.  So this walk pages by **modification time**
//! instead: each page is the files `modified` in one half-open window.
//! `modified` rather than `created`, because a redeploy moves the first and
//! keeps the second, and a walk since a date has to see redeployed bytes.
//!
//! ```text
//!   POST {base}/api/search/aql
//!   items.find({"repo":"NAME","type":"file",
//!               "$and":[{"modified":{"$gte":FROM}},{"modified":{"$lt":TO}}]})
//!        .include(...).limit(500)
//! ```
//!
//! # Sizing a window
//!
//! A window that fills the limit lost rows nobody can name, since the
//! result is unsorted.  It is halved and asked again until it fits; a
//! window of one millisecond that still fills it is fetched without a
//! limit, bounded only by the response size.  A window that came back
//! sparse doubles for the next page, so an empty decade costs a handful of
//! requests rather than one per window.
//!
//! The first window spans from the epoch to the start of the walk, which
//! answers a small repository in one request.  A walk since a date starts
//! its first window there instead.
//!
//! ```text
//!   [epoch ........................ until)   full: halve
//!   [epoch ........ mid)                     full: halve
//!   [epoch .. q)                             fits: page 1
//!              [q ......... q+2w)            sparse: page 2, double
//! ```
//!
//! Half-open, so a file modified on a boundary is listed exactly once.
//! `until` is fixed when the walk starts: a file modified after that is the
//! next walk's.
//!
//! # A login is required
//!
//! OSS refuses AQL to an anonymous caller (403, measured on 7.161.26) even
//! on a repository that allows anonymous reads, so a host without
//! `authentication` is refused before the walk starts.  `anonymous:
//! attempt` lifts that check, for a release that someday allows it.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;

use super::fold::{Folder, INCLUDE};
use super::row::{Results, Row};
use super::{PAGE_LIMIT, PAGE_ROWS, SEARCH, aql_time};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::{EcosystemId, ListingDepth};
use crate::net::{Req, normalized_base};
use crate::repo::enumerate::{Cursor, Enumerator, Login, Narrowing, Page};

/// The kind, as configuration names it.
const KIND: &str = "artifactory-oss";

/// The narrowest window: one millisecond, AQL's timestamp resolution.
const MIN_SPAN_MS: i64 = 1;

/// A window returning fewer rows than this share of the limit doubles.
const SPARSE_DIVISOR: usize = 4;

/// Where the walk is: the next window's start and width, and the fixed end.
///
/// Spelled `{from_ms}:{span_ms}:{until_ms}` in the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    from_ms: i64,
    span_ms: i64,
    until_ms: i64,
}

impl Window {
    /// The first window: everything from `since`, or from the epoch, up to
    /// now.
    fn first(now: DateTime<Utc>, since: Option<DateTime<Utc>>) -> Self {
        // One past now, so a file modified this millisecond is inside.
        let until_ms = now.timestamp_millis() + 1;
        let from_ms = since.map_or(0, |since| since.timestamp_millis());

        Self {
            from_ms,
            span_ms: (until_ms - from_ms).max(MIN_SPAN_MS),
            until_ms,
        }
    }

    fn read(cursor: &Cursor) -> Result<Self> {
        let parsed: Option<Vec<i64>> = cursor
            .as_str()
            .split(':')
            .map(|part| part.parse().ok())
            .collect();

        match parsed.as_deref() {
            Some(&[from_ms, span_ms, until_ms]) if span_ms >= MIN_SPAN_MS => Ok(Self {
                from_ms,
                span_ms,
                until_ms,
            }),

            // Refused rather than restarted: a restart re-walks the whole
            // repository without a word.
            _ => Err(Error::Config(format!(
                "the {KIND} enumerator cannot resume from cursor {:?}, which it did not issue",
                cursor.as_str()
            ))),
        }
    }

    fn cursor(&self) -> Cursor {
        Cursor::new(format!(
            "{}:{}:{}",
            self.from_ms, self.span_ms, self.until_ms
        ))
    }

    /// The window's end, never past the walk's.
    fn end_ms(&self) -> i64 {
        (self.from_ms + self.span_ms).min(self.until_ms)
    }
}

/// Whether a window's rows are all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Limit {
    /// At most [`PAGE_ROWS`]; a full answer may have lost rows.
    Rows,

    /// Every row, for a one-millisecond window nothing can narrow.
    None,
}

pub struct ArtifactoryOssEnumerator {
    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    folder: Folder,
}

impl ArtifactoryOssEnumerator {
    /// Build from configuration: `repository` and `ecosystem`, as for the
    /// `artifactory` enumerator.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let (repository, ecosystem) = crate::repo::manager::config(options, KIND)?;
        let mapping = crate::repo::manager::raw_mapping(options, &ecosystem)?;

        // Read for its refusal of a misspelling; `login` acts on it.
        super::login(options, KIND)?;

        Ok(Self {
            host,
            folder: Folder::new(normalized_base(base_url), repository, ecosystem, mapping),
        })
    }

    /// A login unless the `anonymous` option says to try without one.
    pub(crate) fn login(options: &Options) -> Result<Login> {
        super::login(options, KIND)
    }

    fn search_url(&self) -> String {
        format!("{}/{SEARCH}", self.folder.base_url())
    }

    /// The AQL query for the files modified in `[from_ms, to_ms)`.
    fn query(&self, from_ms: i64, to_ms: i64, limit: Limit) -> String {
        let mut query = format!(
            r#"items.find({{"repo":"{repo}","type":"file","$and":[{{"modified":{{"$gte":"{from}"}}}},{{"modified":{{"$lt":"{to}"}}}}]}}){INCLUDE}"#,
            repo = self.folder.repository().replace('"', ""),
            from = aql_time(from_ms),
            to = aql_time(to_ms),
        );

        if limit == Limit::Rows {
            query.push_str(&format!(".limit({PAGE_ROWS})"));
        }

        query
    }

    async fn rows(&self, from_ms: i64, to_ms: i64, limit: Limit, ctx: &Ctx) -> Result<Vec<Row>> {
        let url = self.search_url();
        let fetched: Result<Results> = crate::ext::fetch_json(
            &*self.host,
            &Req::post(&url, self.query(from_ms, to_ms, limit)),
            PAGE_LIMIT,
            "artifactory aql results",
            ctx,
        )
        .await;

        match fetched {
            Ok(results) => Ok(results.results),

            // HTTP 401 and 403: AQL refused to an anonymous caller.
            Err(Error::HttpStatus { status, .. })
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN =>
            {
                Err(Error::Config(format!(
                    "the {KIND} enumerator for {} was refused AQL ({status}); AQL needs \
                     a login with read permission on the repository",
                    self.folder.repository()
                )))
            }

            Err(err) => Err(err),
        }
    }

    /// The rows of the widest window from `window.from_ms` that fits the
    /// limit, and the width that fit.
    async fn fitted(&self, window: Window, ctx: &Ctx) -> Result<(Vec<Row>, i64)> {
        let mut span_ms = window.end_ms() - window.from_ms;

        loop {
            let to_ms = window.from_ms + span_ms;
            let rows = self.rows(window.from_ms, to_ms, Limit::Rows, ctx).await?;

            if rows.len() < PAGE_ROWS {
                return Ok((rows, span_ms));
            }

            if span_ms <= MIN_SPAN_MS {
                let every = self.rows(window.from_ms, to_ms, Limit::None, ctx).await?;

                return Ok((every, span_ms));
            }

            span_ms /= 2;
        }
    }
}

#[async_trait]
impl Enumerator for ArtifactoryOssEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        std::slice::from_ref(self.folder.ecosystem())
    }

    fn reports_last_download(&self) -> bool {
        crate::repo::manager::REPORTS_LAST_DOWNLOAD
    }

    fn depth(&self) -> ListingDepth {
        crate::repo::manager::LISTING_DEPTH
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        self.page(None, cursor, ctx).await
    }

    fn narrowing(&self) -> Narrowing {
        Narrowing::Modified
    }

    /// The same windowed walk, its first window starting at `since`; a
    /// cursor already carries where the walk is.
    async fn walk_since(
        &self,
        since: DateTime<Utc>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        self.page(Some(since), cursor, ctx).await
    }
}

impl ArtifactoryOssEnumerator {
    /// One window's page; a walk with no cursor starts at `since`, or at
    /// the epoch.
    async fn page(
        &self,
        since: Option<DateTime<Utc>>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        let window = match cursor {
            Some(cursor) => Window::read(cursor)?,
            None => Window::first(Utc::now(), since),
        };

        if window.from_ms >= window.until_ms {
            return Ok(Page::last(Vec::new()));
        }

        let (rows, span_ms) = self.fitted(window, ctx).await?;
        let found = self.folder.fold(&rows, ctx);
        let from_ms = window.from_ms + span_ms;

        if from_ms >= window.until_ms {
            return Ok(Page::last(found));
        }

        // An empty page is not the end: the next window may hold plenty.
        let span_ms = match rows.len() < PAGE_ROWS / SPARSE_DIVISOR {
            true => span_ms.saturating_mul(2),
            false => span_ms,
        };

        let next = Window {
            from_ms,
            span_ms,
            until_ms: window.until_ms,
        };

        Ok(Page::more(found, next.cursor()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::Cause;
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://artifactory.test";
    const REPO: &str = "maven-a";

    fn search() -> String {
        format!("{BASE}/{SEARCH}")
    }

    fn enumerator(host: Arc<dyn ExtHost>) -> ArtifactoryOssEnumerator {
        ArtifactoryOssEnumerator::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "ecosystem": "maven"})),
            host,
        )
        .expect("opens")
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Enumerated {
            enumerator: KIND.into(),
        })
    }

    /// `n` rows of distinct Maven artifacts.
    fn rows(n: usize) -> String {
        let rows: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"path": "org/example/lib{i}/1.0", "name": "lib{i}-1.0.jar"}}"#))
            .collect();

        format!(r#"{{"results": [{}]}}"#, rows.join(","))
    }

    // -- The query --------------------------------------------------------

    /// A walk since a date starts its first window there; a full walk
    /// starts at the epoch.
    #[test]
    fn window_first_starts_at_since() {
        let now = DateTime::<Utc>::from_timestamp_millis(10_000).expect("valid");
        let since = DateTime::<Utc>::from_timestamp_millis(4_000).expect("valid");

        let narrowed = Window::first(now, Some(since));
        let full = Window::first(now, None);

        assert_eq!((narrowed.from_ms, narrowed.span_ms), (4_000, 6_001));
        assert_eq!((full.from_ms, full.span_ms), (0, 10_001));
    }

    /// OSS refuses any sort, and spells a range as two clauses under
    /// `$and` (a single `{"$gte":..,"$lt":..}` is a syntax error there).
    #[test]
    fn query_unsorted_half_open_window() {
        let query = enumerator(idle()).query(0, 1_000, Limit::Rows);

        assert!(!query.contains(".sort("), "{query}");
        assert!(
            query.contains(
                r#""$and":[{"modified":{"$gte":"1970-01-01T00:00:00.000Z"}},{"modified":{"$lt":"1970-01-01T00:00:01.000Z"}}]"#
            ),
            "{query}"
        );
        assert!(query.contains("stat.downloaded"), "{query}");
        assert!(query.ends_with(&format!(".limit({PAGE_ROWS})")), "{query}");
        assert!(
            !enumerator(idle())
                .query(0, 1, Limit::None)
                .contains(".limit(")
        );
    }

    // -- Cursors ----------------------------------------------------------

    #[test]
    fn cursor_round_trips() {
        let window = Window {
            from_ms: 10,
            span_ms: 20,
            until_ms: 30,
        };

        assert_eq!(Window::read(&window.cursor()).expect("reads"), window);
    }

    #[test]
    fn cursor_foreign_refused() {
        for text in ["500", "1:0:3", "a:b:c"] {
            assert!(Window::read(&Cursor::new(text)).is_err(), "{text}");
        }
    }

    // -- Walking ----------------------------------------------------------

    /// A small repository is one request.
    #[tokio::test]
    async fn window_first_spans_everything() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), rows(2)),
        ));

        let page = enumerator(host.clone())
            .walk(None, &ctx())
            .await
            .expect("walked");

        assert_eq!(page.found.len(), 2);
        assert!(!page.has_more());
        assert_eq!(host.hits(&search()), 1);
    }

    /// A full window lost rows nobody can name, so it is asked again at
    /// half the width, and the walk resumes where the narrower one ended.
    #[tokio::test]
    async fn window_full_halves() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with_sequence(
            search(),
            vec![Canned::ok(rows(PAGE_ROWS)), Canned::ok(rows(PAGE_ROWS / 2))],
        )));

        let page = enumerator(host.clone())
            .walk(Some(&Cursor::new("0:1000:1000")), &ctx())
            .await
            .expect("walked");

        assert_eq!(host.hits(&search()), 2);
        assert_eq!(page.found.len(), PAGE_ROWS / 2);

        // Resumes at the narrower window's end; not sparse, so the width
        // that fit carries on.
        assert_eq!(page.next, Some(Cursor::new("500:500:1000")));
    }

    #[tokio::test]
    async fn window_sparse_doubles() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), rows(0)),
        ));

        let page = enumerator(host)
            .walk(Some(&Cursor::new("0:100:1000")), &ctx())
            .await
            .expect("walked");

        // Empty, and still not the end.
        assert!(page.found.is_empty());
        assert_eq!(page.next, Some(Cursor::new("100:200:1000")));
    }

    #[tokio::test]
    async fn window_never_passes_end() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(search(), rows(1)),
        ));

        let page = enumerator(host.clone())
            .walk(Some(&Cursor::new("900:400:1000")), &ctx())
            .await
            .expect("walked");

        // Clamped to the end, so this window was the last.
        assert!(!page.has_more());
    }

    /// One millisecond cannot be narrowed, so it is fetched whole.
    #[tokio::test]
    async fn window_full_millisecond_drops_limit() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with_sequence(
            search(),
            vec![Canned::ok(rows(PAGE_ROWS)), Canned::ok(rows(PAGE_ROWS + 1))],
        )));

        let page = enumerator(host.clone())
            .walk(Some(&Cursor::new("0:1:1000")), &ctx())
            .await
            .expect("walked");

        assert_eq!(host.hits(&search()), 2);
        assert_eq!(page.found.len(), PAGE_ROWS + 1);
        assert_eq!(page.next, Some(Cursor::new("1:1:1000")));
    }

    #[tokio::test]
    async fn login_anonymous_refusal_says_why() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with(search(), Canned::status(StatusCode::FORBIDDEN)),
        ));

        let err = enumerator(host)
            .walk(None, &ctx())
            .await
            .expect_err("refused");

        assert!(err.to_string().contains("login"), "{err}");
    }

    #[test]
    fn login_required_unless_attempted() {
        let with = |anonymous: serde_json::Value| {
            options(
                serde_json::json!({"repository": REPO, "ecosystem": "maven", "anonymous": anonymous}),
            )
        };

        assert_eq!(
            ArtifactoryOssEnumerator::login(&with(serde_json::Value::Null)).expect("reads"),
            Login::Required
        );
        assert_eq!(
            ArtifactoryOssEnumerator::login(&with("attempt".into())).expect("reads"),
            Login::Optional
        );
        assert!(ArtifactoryOssEnumerator::open(BASE, &with("sometimes".into()), idle()).is_err());
    }

    #[test]
    fn declares_what_it_answers() {
        let enumerator = enumerator(idle());

        assert!(enumerator.reports_last_download());
        assert_eq!(enumerator.depth(), ListingDepth::Files);
        assert_eq!(enumerator.ecosystems(), &[EcosystemId::maven()]);
    }

    /// The mapping is read as the `artifactory` enumerator reads it.
    #[test]
    fn mapping_raw_only() {
        let open = |ecosystem: &str| {
            ArtifactoryOssEnumerator::open(
                BASE,
                &options(serde_json::json!(
                    {"repository": REPO, "ecosystem": ecosystem, "mapping": "as-is"}
                )),
                idle(),
            )
        };

        assert!(open("raw").is_ok());
        assert!(open("maven").is_err());
    }
}
