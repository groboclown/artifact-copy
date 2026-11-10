//! Inventory documents, kept in the cache under their binding's freshness.
//!
//! A `maven-metadata.xml`, a packument, a simple page: what a source reads
//! to learn what a repository holds, as opposed to the payloads it then
//! copies. Each call site names its document (`maven-metadata.xml`,
//! `packument.json`), and that name is what a `cache-freshness` rule
//! matches.
//!
//! ```text
//!   judge --usable--> read, touch ------------------------------> bytes
//!     |
//!     +--expired (retention)--> evict --+
//!     +--expired (freshness)------------+--> fetch --ok--> replace, record --> bytes
//!     +--absent / undated---------------+       |
//!                                               +--failed, freshness only--> stale copy, warn
//! ```
//!
//! Only a source's own reads come through here. A target reading its own
//! state must see it as it is now, so it fetches directly.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md), [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use bytes::Bytes;
use http::StatusCode;

use super::ExtHost;
use super::cache::{Bound, CachePath, Expiry, Judged, Lifetime, Origin};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::message;
use crate::net::{ByteLimit, Req};

/// The header a document is negotiated by, and so part of its cache key.
const ACCEPT_HEADER: &str = "accept";

/// HTTP statuses that answer the question rather than fail to: the
/// document is gone, so a stale copy of it would be wrong rather than old.
const GONE_STATUSES: [StatusCode; 2] = [StatusCode::NOT_FOUND, StatusCode::GONE];

/// Fetch `req` as the document `name`, through the cache.
///
/// A copy within its freshness is used without a request. A copy past its
/// freshness is fetched again, and used anyway, with a warning, when that
/// fetch fails for any reason but the document being gone. A copy past its
/// retention is removed first and never used.
pub async fn document(
    host: &dyn ExtHost,
    req: &Req,
    name: &str,
    max: ByteLimit,
    ctx: &Ctx,
) -> Result<Bytes> {
    let cache = host.cache();
    let accept = req
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(ACCEPT_HEADER))
        .map(|(_, value)| value.as_str());
    let path = cache.document_path(&req.url, accept, name)?;
    let lifetime = host.cache_policy().lifetime(name);

    let expired = match cache.judge(&path, &lifetime) {
        Judged::Usable => {
            // A copy that cannot be read, or has grown past the cap, is
            // fetched again rather than failing the run.
            if let Ok(body) = cache.read(&path, max).await {
                let _ = cache.touch(&path, &lifetime);

                return Ok(Bytes::from(body));
            }

            None
        }

        Judged::Expired(expiry) => {
            report_expired(ctx, &req.url, name, expiry);

            Some(expiry)
        }

        Judged::Absent | Judged::Undated => None,
    };

    // Past retention, the copy should not be here at all, so it is no
    // fallback either.
    if expired == Some(Expiry::Retention) {
        cache.evict(&path);
    }

    let body = match host.fetch(req, max, ctx).await {
        Ok(body) => body,

        Err(err) if expired == Some(Expiry::Freshness) && !gone(&err) => {
            let Ok(stale) = cache.read(&path, max).await else {
                return Err(err);
            };

            report_stale(ctx, &req.url, name, &err);

            return Ok(Bytes::from(stale));
        }

        Err(err) => return Err(err),
    };

    cache.replace(&path, &body).await?;
    settle(host, &path, &req.url, name, &lifetime, ctx)?;

    Ok(body)
}

/// Record a file just fetched into `host`'s cache, then keep the caches
/// under their size caps, reporting whatever that removed.
///
/// The binding's own cap first, over its repository's folder, then
/// `setup.cache-size` over the whole cache directory. A held file is never
/// removed, so a caller still needing the file it just fetched holds it
/// before calling this.
pub fn settle(
    host: &dyn ExtHost,
    path: &CachePath,
    url: &str,
    name: &str,
    lifetime: &Lifetime,
    ctx: &Ctx,
) -> Result<()> {
    let cache = host.cache();
    cache.record(path, url, name, lifetime)?;

    // The file just written is held for the length of the trims, so making
    // room never removes what made room necessary.
    let _just_fetched = cache.hold(path);

    if let Some(cap) = host.cache_policy().size_cap_bytes() {
        for origin in cache.trim(cap)? {
            report_evicted(ctx, &origin, Bound::Repository);
        }
    }

    for (_, origin) in cache.trim_shared()? {
        report_evicted(ctx, &origin, Bound::CacheDir);
    }

    Ok(())
}

/// [`document`], parsed as JSON.
pub async fn document_json<T: serde::de::DeserializeOwned>(
    host: &dyn ExtHost,
    req: &Req,
    name: &str,
    max: ByteLimit,
    what: &'static str,
    ctx: &Ctx,
) -> Result<T> {
    let body = document(host, req, name, max, ctx).await?;

    serde_json::from_slice(&body).map_err(|err| Error::Malformed {
        what,
        url: req.url.clone(),
        detail: err.to_string(),
    })
}

/// Record and log a cached file evicted by its lifetime.
///
/// Recorded as `ignore`, since expiry is configuration doing its job. The
/// report's log shows an `ignore` problem at info, so whoever runs the tool
/// still sees the cache working, once.
pub fn report_expired(ctx: &Ctx, url: &str, file: &str, expiry: Expiry) {
    let text = message!(
        "cache-entry-expired",
        "cached {file} from {url} passed its {reason}, so it is fetched again",
        file = file,
        url = url,
        reason = expiry.as_str(),
    );

    ctx.report(Code::CacheEntryExpired, text);
}

/// Record and log a cached file removed to keep a cache under `bound`.
///
/// Recorded as `ignore`, and so shown at info, as an expiry is.
pub fn report_evicted(ctx: &Ctx, origin: &Origin, bound: Bound) {
    let text = message!(
        "cache-entry-evicted",
        "cached {file} from {url} was removed to keep the cache under its {reason} size",
        file = &origin.name,
        url = &origin.url,
        reason = bound.as_str(),
    );

    ctx.report(Code::CacheEntryEvicted, text);
}

/// Record a cached file used past its freshness because the fetch that
/// would have replaced it failed with `err`.
pub fn report_stale(ctx: &Ctx, url: &str, file: &str, err: &Error) {
    ctx.report(
        Code::CacheEntryStale,
        message!(
            "cache-entry-stale",
            "{url} could not be fetched again ({error}), so the cached {file} past its freshness was used",
            url = url,
            error = err,
            file = file,
        ),
    );
}

/// The last segment of `url`, which names a document that is a file of
/// the repository: `.../1.0/core-1.0.pom` is `core-1.0.pom`.
pub fn leaf(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

/// Whether `err` says the document no longer exists, so a stale copy of
/// it would be wrong rather than old.
pub fn gone(err: &Error) -> bool {
    matches!(err, Error::HttpStatus { status, .. } if GONE_STATUSES.contains(status))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::ext::testing::TestHost;
    use crate::ext::{CachePolicy, FreshnessRule, Policed};
    use crate::net::{Canned, FixtureClient};

    const URL: &str = "h://origin.test/pkg/maven-metadata.xml";
    const NAME: &str = "maven-metadata.xml";
    const BODY: &[u8] = b"<metadata/>";

    /// `client` behind a binding whose files have `retention` and whose
    /// `NAME` has `freshness`. The test host is returned too, for its hit
    /// counts.
    fn bound(
        client: FixtureClient,
        retention: Option<Duration>,
        freshness: Option<Duration>,
    ) -> (Arc<TestHost>, Policed) {
        let host = Arc::new(TestHost::new(client));
        let policy = CachePolicy::new(retention, vec![FreshnessRule::new(NAME, freshness)]);

        (Arc::clone(&host), Policed::new(host, policy))
    }

    async fn get(host: &Policed, ctx: &Ctx) -> Result<Bytes> {
        document(host, &Req::get(URL), NAME, ByteLimit::kib(64), ctx).await
    }

    fn count(ctx: &Ctx, code: Code) -> u64 {
        ctx.problems()
            .counts()
            .get(&code)
            .copied()
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn copy_reused_within_freshness() {
        let (test, host) = bound(FixtureClient::new().with_body(URL, BODY), None, None);
        let ctx = Ctx::anonymous_for_test();

        get(&host, &ctx).await.expect("first");
        let again = get(&host, &ctx).await.expect("second");

        assert_eq!(&again[..], BODY);
        assert_eq!(test.hits(URL), 1);
    }

    #[tokio::test]
    async fn copy_refetched_past_freshness() {
        let (test, host) = bound(
            FixtureClient::new().with_body(URL, BODY),
            None,
            Some(Duration::ZERO),
        );
        let ctx = Ctx::anonymous_for_test();

        get(&host, &ctx).await.expect("first");
        get(&host, &ctx).await.expect("second");

        assert_eq!(test.hits(URL), 2);
        assert_eq!(count(&ctx, Code::CacheEntryExpired), 1);
    }

    /// An older answer beats none, with a warning, when the document could
    /// not be fetched again.
    #[tokio::test]
    async fn copy_stale_used_when_refetch_fails() {
        let client = FixtureClient::new().with_sequence(
            URL,
            vec![
                Canned::ok(BODY),
                Canned::status(StatusCode::SERVICE_UNAVAILABLE),
            ],
        );
        let (_test, host) = bound(client, None, Some(Duration::ZERO));
        let ctx = Ctx::anonymous_for_test();

        get(&host, &ctx).await.expect("first");
        let stale = get(&host, &ctx).await.expect("served stale");

        assert_eq!(&stale[..], BODY);
        assert_eq!(count(&ctx, Code::CacheEntryStale), 1);
    }

    /// A 404 answers the question: the document is gone, so a copy of it
    /// would be wrong rather than old.
    #[tokio::test]
    async fn copy_stale_not_served_when_gone() {
        let client = FixtureClient::new().with_sequence(
            URL,
            vec![Canned::ok(BODY), Canned::status(StatusCode::NOT_FOUND)],
        );
        let (_test, host) = bound(client, None, Some(Duration::ZERO));
        let ctx = Ctx::anonymous_for_test();

        get(&host, &ctx).await.expect("first");

        assert!(get(&host, &ctx).await.is_err());
        assert_eq!(count(&ctx, Code::CacheEntryStale), 0);
    }

    /// Past retention the copy is removed before the fetch, so it is never
    /// a fallback.
    #[tokio::test]
    async fn copy_past_retention_never_served() {
        let client = FixtureClient::new().with_sequence(
            URL,
            vec![
                Canned::ok(BODY),
                Canned::status(StatusCode::SERVICE_UNAVAILABLE),
            ],
        );
        let (_test, host) = bound(client, Some(Duration::ZERO), None);
        let ctx = Ctx::anonymous_for_test();

        get(&host, &ctx).await.expect("first");

        assert!(get(&host, &ctx).await.is_err());
        assert_eq!(count(&ctx, Code::CacheEntryExpired), 1);
    }

    /// One URL negotiated two ways is two documents.
    #[tokio::test]
    async fn accept_keys_separately() {
        let (test, host) = bound(FixtureClient::new().with_body(URL, BODY), None, None);
        let ctx = Ctx::anonymous_for_test();
        let max = ByteLimit::kib(64);

        document(&host, &Req::get(URL).accept("text/html"), NAME, max, &ctx)
            .await
            .expect("html");
        document(
            &host,
            &Req::get(URL).accept("application/json"),
            NAME,
            max,
            &ctx,
        )
        .await
        .expect("json");

        assert_eq!(test.hits(URL), 2);
    }

    /// Errors are not cached: the next call asks again.
    #[tokio::test]
    async fn failure_not_cached() {
        let client = FixtureClient::new().with_sequence(
            URL,
            vec![
                Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                Canned::ok(BODY),
            ],
        );
        let (test, host) = bound(client, None, None);
        let ctx = Ctx::anonymous_for_test();

        assert!(get(&host, &ctx).await.is_err());
        assert_eq!(&get(&host, &ctx).await.expect("second")[..], BODY);
        assert_eq!(test.hits(URL), 2);
    }

    /// A binding's `cache-size` removes its least recently used documents
    /// once a fetch passes it, and says so.
    #[tokio::test]
    async fn binding_cap_evicts_and_reports() {
        const OTHER: &str = "h://origin.test/other/maven-metadata.xml";

        let client = FixtureClient::new()
            .with_body(URL, BODY)
            .with_body(OTHER, BODY);
        let test = Arc::new(TestHost::new(client));
        let cap = BODY.len() as u64;
        let host = Policed::new(
            test.clone(),
            CachePolicy::default().with_size_cap(Some(cap)),
        );
        let ctx = Ctx::anonymous_for_test();
        let max = ByteLimit::kib(64);

        document(&host, &Req::get(URL), NAME, max, &ctx)
            .await
            .expect("first");
        std::thread::sleep(Duration::from_millis(3));
        document(&host, &Req::get(OTHER), NAME, max, &ctx)
            .await
            .expect("second");
        document(&host, &Req::get(URL), NAME, max, &ctx)
            .await
            .expect("again");

        assert_eq!(test.hits(URL), 2, "the first document was evicted");
        assert!(count(&ctx, Code::CacheEntryEvicted) >= 1);
    }
}
