//! Test support for extension implementations.
//!
//! [`TestHost`] ships, and deliberately so: an embedder writing an
//! extension against this crate needs the same host its built-ins are
//! tested against, and a half-working copy written by each of them is worse
//! than this one.
//!
//! The rest -- `Fixture` and `options`, which do not appear here because
//! they are `#[cfg(test)]` -- is convenience over `TestHost` rather than
//! capability. An embedder who wants a two-field struct around a host can
//! write one; what they cannot write is a host that enforces this crate's
//! own constraints.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use super::cache::{Cache, CachePath};
use super::constraints::Constraints;
use super::host::ExtHost;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::net::{ByteLimit, Expectation, FixtureClient, FormPart, Head, HttpClient, Req};

/// Reached only by the `#[cfg(test)]` half of this module.
#[cfg(test)]
use super::options::Options;

/// Makes each host's directory unique within a process.
static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);

/// A host backed by recorded responses and a throwaway cache.
///
/// Permits every URL by default, because most adapter tests are about the
/// adapter rather than about the constraints. Use [`TestHost::allowing`]
/// or [`TestHost::with_constraints`] when the constraints are the point.
///
/// The directory is made under the system temp directory and removed on
/// drop, which keeps `tempfile` a dev-dependency even though this module
/// ships in the library.
#[derive(Debug)]
pub struct TestHost {
    /// Held concretely rather than as `Arc<dyn HttpClient>` so a test can
    /// ask what was actually requested -- which is how a caching claim gets
    /// proved, and how "a refused URL was never requested" gets proved.
    http: Arc<FixtureClient>,

    constraints: Constraints,
    cache: Cache,

    /// Whether the constraints are enforced at all.
    limited: Limited,
}

/// Whether a test host checks URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Limited {
    /// Any URL is permitted; the fixture decides what exists.
    No,

    /// The constraints are enforced, which is the point of the test.
    Yes,
}

impl TestHost {
    /// A host serving `client` and permitting any URL.
    pub fn new(client: FixtureClient) -> Self {
        Self::build(client, Constraints::new(), Limited::No)
    }

    /// A host over a fixture somebody else also holds.
    ///
    /// For a test where two hosts must share one request log -- proving
    /// that concurrent work against one registry did not interleave needs
    /// a single ordered record of what reached it.
    pub fn sharing(client: Arc<FixtureClient>) -> Self {
        let unique = NEXT_SANDBOX.fetch_add(1, Ordering::SeqCst);

        let root = std::env::temp_dir().join(format!(
            "artifact-copy-test-{}-{unique}",
            std::process::id()
        ));

        Self {
            http: client,
            constraints: Constraints::new(),
            cache: Cache::open(root).expect("cache"),
            limited: Limited::No,
        }
    }

    /// A host permitting only URLs under `prefix`.
    pub fn allowing(client: FixtureClient, prefix: &str) -> Self {
        let constraints = Constraints::new()
            .allow(prefix)
            .expect("the test prefix must be a URL");

        Self::with_constraints(client, constraints)
    }

    /// A host enforcing exactly these constraints.
    pub fn with_constraints(client: FixtureClient, constraints: Constraints) -> Self {
        Self::build(client, constraints, Limited::Yes)
    }

    fn build(client: FixtureClient, constraints: Constraints, limited: Limited) -> Self {
        let unique = NEXT_SANDBOX.fetch_add(1, Ordering::SeqCst);

        let root = std::env::temp_dir().join(format!(
            "artifact-copy-test-{}-{unique}",
            std::process::id()
        ));

        let cache = Cache::open(root).expect("cache");

        Self {
            http: Arc::new(client),
            constraints,
            cache,
            limited,
        }
    }

    /// What was uploaded to `url`, in order.
    ///
    /// A publish is only testable by what it sent: a target that built the
    /// wrong document would otherwise pass every test that only checked it
    /// did not error.
    pub fn sent_to(&self, url: &str) -> Vec<Vec<u8>> {
        self.http.sent_to(url)
    }

    /// The headers of each request to `url`, in order.
    pub fn headers_to(&self, url: &str) -> Vec<crate::net::Headers> {
        self.http.headers_to(url)
    }

    /// How many times one URL was requested.
    pub fn hits(&self, url: &str) -> usize {
        self.http.hits(url)
    }

    /// Every URL requested, in order.
    pub fn requested(&self) -> Vec<String> {
        self.http.requested()
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.cache.discard();
    }
}

#[async_trait]
impl ExtHost for TestHost {
    async fn head(&self, req: &Req, ctx: &Ctx) -> Result<Head> {
        if !self.permits(&req.url) {
            return Err(refused(&req.url));
        }

        self.http.head(req, ctx).await
    }

    async fn fetch(&self, req: &Req, max: ByteLimit, ctx: &Ctx) -> Result<Bytes> {
        if !self.permits(&req.url) {
            return Err(refused(&req.url));
        }

        self.http
            .fetch_bounded(req, self.constraints.cap(max), ctx)
            .await
    }

    async fn send_file(
        &self,
        req: &Req,
        body: &std::path::Path,
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes> {
        if !self.permits(&req.url) {
            return Err(refused(&req.url));
        }

        self.http.send_file(req, body, max, ctx).await
    }

    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes> {
        if !self.permits(&req.url) {
            return Err(refused(&req.url));
        }

        self.http.send_form(req, parts, max, ctx).await
    }

    async fn fetch_to_cache(
        &self,
        req: &Req,
        name: &str,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<CachePath> {
        if !self.permits(&req.url) {
            return Err(refused(&req.url));
        }

        let target = self.cache.path(name)?;
        let full = self.cache.resolve(&target);

        self.http.fetch_to_file(req, &full, expect, ctx).await?;

        Ok(target)
    }

    /// `TestHost::new` permits everything; a configured prefix narrows it.
    fn permits(&self, url: &str) -> bool {
        self.limited == Limited::No || self.constraints.allows(url)
    }

    fn cache(&self) -> &Cache {
        &self.cache
    }

    fn constraints(&self) -> &Constraints {
        &self.constraints
    }
}

fn refused(url: &str) -> crate::core::error::Error {
    crate::core::error::Error::Config(format!("{url} is outside what this extension may fetch"))
}

/// An extension under test, with the host it talks to.
///
/// Every adapter test needs exactly this pair and nothing else: the thing
/// being tested, built around a shared [`TestHost`] so the test can see
/// what it asked for. Six modules had written the same two-field struct.
///
/// `subject` rather than `source` or `enumerator` because it holds both, and
/// a name that claimed one would be wrong half the time.
///
/// Unlike [`TestHost`], this does **not** ship: it is convenience over the
/// host rather than capability, and an embedder can write the two-field
/// struct it wants in three lines.
#[cfg(test)]
pub struct Fixture<T> {
    pub subject: T,
    pub host: Arc<TestHost>,
}

#[cfg(test)]
impl<T> Fixture<T> {
    pub fn new(subject: T, client: FixtureClient) -> Self {
        Self {
            subject,
            host: Arc::new(TestHost::new(client)),
        }
    }

    /// A subject built around the host, which is how an extension holding
    /// its own host is tested.
    pub fn build(client: FixtureClient, make: impl FnOnce(Arc<dyn ExtHost>) -> T) -> Self {
        let host = Arc::new(TestHost::new(client));

        Self {
            subject: make(host.clone()),
            host,
        }
    }

    /// The host, shared, for a subject built to hold it.
    pub fn shared(&self) -> Arc<dyn ExtHost> {
        self.host.clone()
    }

    /// What was actually requested, in order.
    ///
    /// The way a caching claim gets proved, and the way "a refused URL was
    /// never requested" gets proved.
    pub fn requested(&self) -> Vec<String> {
        self.host.requested()
    }
}

/// A host for a subject whose requests the test does not inspect.
#[cfg(test)]
pub fn idle() -> Arc<dyn ExtHost> {
    Arc::new(TestHost::new(FixtureClient::new()))
}

/// Extension options from a JSON literal.
///
/// Configuration reaches an extension as a JSON object, so a test that
/// builds [`Options`] any other way is testing a shape the tool never
/// produces. Panics on anything but an object, because a test that passed
/// an array here is a broken test and not a case worth handling.
///
/// Test-only for the same reason as [`Fixture`]: [`Options::from`] is the
/// shipped route, and this is two lines of `panic!` on top of it.
#[cfg(test)]
pub fn options(value: serde_json::Value) -> Options {
    match value {
        serde_json::Value::Object(map) => Options::from(map),
        other => panic!("extension options must be a JSON object, not {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "h://registry.test/thing";

    #[tokio::test]
    async fn host_default_permits_any_fetch() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, "body"));

        let body = host
            .fetch(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        assert_eq!(&body[..], b"body");
    }

    #[tokio::test]
    async fn host_narrowed_refuses_outside_prefix() {
        let host = TestHost::allowing(
            FixtureClient::new().with_body("h://evil.test/x", "loot"),
            "h://registry.test/",
        );

        assert!(
            host.fetch(
                &Req::get("h://evil.test/x"),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn cache_usable() {
        let host = TestHost::new(FixtureClient::new());

        let path = host.cache().write("x.json", b"{}").await.expect("wrote");

        assert_eq!(path.as_str(), "x.json");
    }
}
