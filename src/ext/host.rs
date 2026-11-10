//! The capability an extension is handed.
//!
//! Every network request an extension makes goes through here, where it is
//! checked against the instance's [`Constraints`], given its credentials,
//! and capped. The extension asks for a URL and receives bytes; it never
//! sees a token, so it cannot leak one.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;

use super::cache::{Cache, CachePath, CachePolicy, wildcard};
use super::constraints::Constraints;
use super::gate::Gates;
use crate::config::{Authentication, SecretValue};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::net::{ByteLimit, Expectation, FormPart, Head, HttpClient, Req};

/// What a binding given no policy of its own answers.
static FOREVER_POLICY: CachePolicy = CachePolicy::FOREVER;

/// What an extension may do.
#[async_trait]
pub trait ExtHost: std::fmt::Debug + Send + Sync {
    /// Response metadata only, with no body.
    ///
    /// Its own capability rather than a zero-capped `fetch`, because the
    /// answer is the headers: a Maven publish time is the `Last-Modified`
    /// of an artifact that may be a hundred megabytes, and downloading it
    /// to learn its date would be absurd.
    async fn head(&self, req: &Req, ctx: &Ctx) -> Result<Head>;

    /// Whether a file is there, by a `HEAD` a mirror may answer.
    ///
    /// For a check that needs presence and nothing else, such as whether a
    /// jar has an `.asc` beside it. [`ExtHost::head`] stays with the owner
    /// because its headers describe the owner's copy -- a mirror's
    /// `Last-Modified` is when it copied the file -- but a mirror's "it is
    /// here" is as good as the owner's.
    ///
    /// `Ok(false)` for a missing file; any other failure is an error. By
    /// default, the owner's answer through `head`.
    async fn exists(&self, req: &Req, ctx: &Ctx) -> Result<bool> {
        present(self.head(req, ctx).await)
    }

    /// Fetch into memory, capped.
    async fn fetch(&self, req: &Req, max: ByteLimit, ctx: &Ctx) -> Result<Bytes>;

    /// Fetch into this host's cache under `name`, verified in flight; the
    /// extension then opens it through [`ExtHost::cache`].
    async fn fetch_to_cache(
        &self,
        req: &Req,
        name: &str,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<CachePath>;

    /// Send a file as a request body.
    ///
    /// The one capability that **writes**, and the mirror of
    /// [`ExtHost::fetch_to_cache`]. The body is a file for the same reason a
    /// download is: a publish can be the size of the artifact, and npm's is
    /// a third larger again because it wraps the tarball in base64. Neither
    /// may pass through a call as a `String`.
    ///
    /// Constrained and credentialed exactly as a fetch is -- an extension
    /// can no more publish to an unconfigured host than read from one.
    async fn send_file(&self, req: &Req, body: &Path, max: ByteLimit, ctx: &Ctx) -> Result<Bytes>;

    /// Send a `multipart/form-data` request, `curl -F` style.
    ///
    /// The shape most registry upload endpoints take. Here rather than in
    /// each adapter because the framing is identical everywhere and three
    /// hand-rolled copies would be three chances to get one subtly wrong --
    /// and because an extension that built its own body would still have to
    /// hand it here to be sent, so it would gain nothing but the bugs.
    ///
    /// File fields name a path and are streamed from it, so an upload of
    /// any size costs no memory.
    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes>;

    /// Whether a read of `url` would be sent anywhere.
    ///
    /// The same check a fetch makes before it attaches credentials, asked
    /// without fetching, so a proxy can choose the upstream a file belongs
    /// to rather than trying each in turn.
    fn permits(&self, url: &str) -> bool;

    /// Where this host keeps what it downloaded, across runs.
    fn cache(&self) -> &Cache;

    fn constraints(&self) -> &Constraints;

    /// How long the files this binding caches may be used and kept.
    ///
    /// Forever, unless the binding was given its own through
    /// [`Policed`](super::Policed): a capability is shared by every source
    /// reading one repository, so the policy belongs to the binding rather
    /// than to the capability.
    fn cache_policy(&self) -> &CachePolicy {
        &FOREVER_POLICY
    }
}

/// A second host this capability may **read** from, and how.
///
/// An additional host: an index on one host listing files on another, as
/// pypi.org does with `files.pythonhosted.org`, or a host redirecting to
/// another, as github.com does to `codeload.github.com`. Its own client and
/// its own credentials, never the capability's unless configuration says
/// so, because a credential attaches to whatever a prefix permits -- see
/// `docs/contributors/wiring.md`.
#[derive(Debug)]
pub struct Route {
    constraints: Constraints,
    http: std::sync::Arc<dyn HttpClient>,
    auth: Option<Authentication>,

    /// The additional host's own caps; none unless it is a configured host.
    gates: Gates,
}

impl Route {
    /// `constraints` say what the route reaches; `auth` is sent there and
    /// nowhere else. `None` for a host reached without credentials.
    pub fn new(
        constraints: Constraints,
        http: std::sync::Arc<dyn HttpClient>,
        auth: Option<Authentication>,
    ) -> Self {
        Self {
            constraints,
            http,
            auth,
            gates: Gates::default(),
        }
    }

    /// Count this route's requests against `gates`.
    pub(crate) fn with_gates(mut self, gates: Gates) -> Self {
        self.gates = gates;
        self
    }
}

/// A copy of the host, asked first for each read under the host's url.
///
/// ```text
///   https://repo1.maven.org/maven2/a/b/1/b-1.jar
///   https://maven-central.storage-download.googleapis.com/maven2/a/b/1/b-1.jar
/// ```
///
/// Anonymous and never redirected: a mirror is a public copy, so the
/// owner's credentials stay off it, and a redirect hands the read back.
#[derive(Debug)]
pub struct Mirror {
    /// The owner's url, ending in `/`; what a mirrored url starts with.
    from: String,

    /// The mirror's url, ending in `/`; what replaces `from`.
    to: String,

    http: Arc<dyn HttpClient>,

    /// Paths below `from` this mirror is never asked for.
    skip: Vec<String>,
}

impl Mirror {
    pub fn new(from: &str, to: &str, http: Arc<dyn HttpClient>, skip: Vec<String>) -> Self {
        Self {
            from: format!("{}/", crate::net::normalized_base(from)),
            to: format!("{}/", crate::net::normalized_base(to)),
            http,
            skip,
        }
    }

    /// `url` on this mirror, or `None` when it is not this mirror's to
    /// answer: outside the owner's url, or skipped (`*/` for an index).
    fn rewrite(&self, url: &str) -> Option<String> {
        let path = url.strip_prefix(&self.from)?;

        if self
            .skip
            .iter()
            .any(|pattern| wildcard(pattern.as_bytes(), path.as_bytes()))
        {
            return None;
        }

        Some(format!("{}{path}", self.to))
    }
}

/// Send one hop inside a slot of the server it goes to.
///
/// Per hop, so a redirect to an additional host counts against that host,
/// and held across the client's retries, so a throttled server sees fewer
/// requests rather than the same number later.
async fn gated<'h, T>(
    hop: Hop<'h>,
    gates: &Gates,
    access: Access,
    send: &impl Fn(Hop<'h>) -> futures::future::BoxFuture<'h, Result<T>>,
) -> Result<T> {
    let gate = match access {
        Access::Read => gates.downloads(),
        Access::Write => gates.uploads(),
    };

    let _slot = gate.enter().await;

    send(hop).await
}

/// A `HEAD`'s answer as presence: a 404 is absence, not a failure.
fn present(answer: Result<Head>) -> Result<bool> {
    match answer {
        Ok(_) => Ok(true),
        Err(err) if err.code() == Code::ArtifactNotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Whether a mirror's failure hands the read to the next: it lacks the
/// file, is down, or redirects. Anything else, such as a digest mismatch,
/// is the answer.
fn is_passed_over(err: &Error) -> bool {
    matches!(err, Error::Redirected { .. })
        || matches!(err.code(), Code::ArtifactNotFound | Code::HostUnreachable)
}

/// The live host: a real HTTP client behind a real set of constraints.
#[derive(Debug)]
pub struct HostedExt {
    http: std::sync::Arc<dyn HttpClient>,
    constraints: Constraints,

    /// Shared with every capability on the same host folder.
    cache: Arc<Cache>,

    /// Attached to outgoing requests by this type and never exposed.
    auth: Option<Authentication>,

    /// Other hosts a read may reach, each with its own client and
    /// credentials. Tried only when [`HostedExt::constraints`] refuses.
    routes: Vec<Route>,

    /// Copies asked first for a `GET`, or an `exists`, under the host's
    /// url, in order.
    mirrors: Vec<Mirror>,

    /// Where a read may be **redirected** with this capability's own client
    /// and credentials: the whole host, not only `constraints`' prefix.
    ///
    /// A repository manager redirecting `/repository/a` to `/repository/b`
    /// is the case. A first request stays inside `constraints`.
    site: Constraints,

    /// The configured host's caps, shared with every capability built from
    /// the same entry. A mirror is never capped.
    gates: Gates,
}

/// Whether a request reads or writes, which decides where it may be
/// redirected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Anywhere under the host's own url, or on an additional host.
    Read,

    /// Only inside the capability's own prefix, and only by a redirect that
    /// keeps the method and the body.
    Write,
}

/// How many redirects one request may follow. reqwest's own default.
const MAX_REDIRECTS: usize = 10;

/// A request ready to send, and the client to send it with.
type Hop<'h> = (Req, &'h Arc<dyn HttpClient>);

/// Where a request goes: its client, credentials, and caps.
type Server<'h> = (
    &'h Arc<dyn HttpClient>,
    Option<&'h Authentication>,
    &'h Gates,
);

impl HostedExt {
    pub fn new(
        http: std::sync::Arc<dyn HttpClient>,
        constraints: Constraints,
        cache: Arc<Cache>,
    ) -> Self {
        Self {
            http,
            site: constraints.clone(),
            constraints,
            cache,
            auth: None,
            routes: Vec::new(),
            mirrors: Vec::new(),
            gates: Gates::default(),
        }
    }

    /// Where a read may be redirected with this capability's credentials.
    /// Defaults to `constraints`; a host's whole url in practice.
    pub fn with_site(mut self, site: Constraints) -> Self {
        self.site = site;
        self
    }

    /// Also read from these hosts. Writes never route.
    pub fn with_routes(mut self, routes: Vec<Route>) -> Self {
        self.routes = routes;
        self
    }

    /// Read from these copies first. Writes and `head` never mirror;
    /// `exists` does.
    pub fn with_mirrors(mut self, mirrors: Vec<Mirror>) -> Self {
        self.mirrors = mirrors;
        self
    }

    /// Count this capability's requests against `gates`.
    pub(crate) fn with_gates(mut self, gates: Gates) -> Self {
        self.gates = gates;
        self
    }

    /// Attach credentials to every request this host issues.
    pub fn with_auth(mut self, auth: Option<Authentication>) -> Self {
        self.auth = auth;
        self
    }

    /// Check the URL, then add credentials.
    ///
    /// Order matters: a refused URL must never have a credential attached,
    /// or a misconfigured allow-list would leak a token to whatever host the
    /// extension named.
    ///
    /// For a **write**, which never leaves the capability's own prefix.
    fn prepare(&self, req: &Req) -> Result<Req> {
        if !self.constraints.allows(&req.url) {
            return Err(self.refused(req, &[]));
        }

        credentialed(req, self.auth.as_ref())
    }

    /// Choose where a **read** goes, then add that host's credentials.
    ///
    /// The capability's own prefix first, with its own credentials; then
    /// each additional host, with **its** credentials. The URL is matched
    /// before anything is attached, so a credential only ever reaches the
    /// host it was configured for.
    fn route(&self, req: &Req) -> Result<(Hop<'_>, &Gates)> {
        let Some((http, auth, gates)) = self.select(&req.url, &self.constraints) else {
            return Err(self.refused(req, &self.routes));
        };

        Ok(((credentialed(req, auth)?, http), gates))
    }

    /// The client and credentials serving `url`: `own`'s with this
    /// capability's, then the first additional host permitting it.
    fn select(&self, url: &str, own: &Constraints) -> Option<Server<'_>> {
        if own.allows(url) {
            return Some((&self.http, self.auth.as_ref(), &self.gates));
        }

        self.routes
            .iter()
            .find(|route| route.constraints.allows(url))
            .map(|route| (&route.http, route.auth.as_ref(), &route.gates))
    }

    /// The first hop of a request.
    fn first(&self, req: &Req, access: Access) -> Result<(Hop<'_>, &Gates)> {
        match access {
            Access::Read => self.route(req),
            Access::Write => Ok(((self.prepare(req)?, &self.http), &self.gates)),
        }
    }

    /// The request a redirect asks for, and where it goes.
    ///
    /// `Err(redirect)` when it may not be followed, so the refusal names
    /// both ends of the hop.
    fn next(&self, from: &Req, access: Access, redirect: Error) -> Result<(Req, Hop<'_>, &Gates)> {
        let Error::Redirected {
            status, location, ..
        } = &redirect
        else {
            return Err(redirect);
        };

        let next = Req {
            url: crate::net::redirect::target(&from.url, location)?,
            ..from.clone()
        };

        let selected = match access {
            Access::Read => self.select(&next.url, &self.site),

            // Re-sent with its body, so only by a redirect that promises to
            // keep the method, and only where a first write could go.
            Access::Write => match crate::net::redirect::keeps_method(*status)
                && self.constraints.allows(&next.url)
            {
                true => Some((&self.http, self.auth.as_ref(), &self.gates)),
                false => None,
            },
        };

        let Some((http, auth, gates)) = selected else {
            return Err(redirect);
        };

        let prepared = credentialed(&next, auth)?;

        Ok((next, (prepared, http), gates))
    }

    /// Send `req`, following each redirect that may be followed.
    ///
    /// Every hop is checked as a first request is, and carries the
    /// credentials of wherever it lands -- never the previous hop's.
    async fn follow<'h, T>(
        &'h self,
        req: &Req,
        access: Access,
        send: impl Fn(Hop<'h>) -> futures::future::BoxFuture<'h, Result<T>>,
    ) -> Result<T> {
        let mut current = req.clone();
        let (mut hop, mut gates) = self.first(&current, access)?;

        for _ in 0..MAX_REDIRECTS {
            let redirect = match gated(hop, gates, access, &send).await {
                Err(redirect @ Error::Redirected { .. }) => redirect,
                other => return other,
            };

            (current, hop, gates) = self.next(&current, access, redirect)?;
        }

        gated(hop, gates, access, &send).await
    }

    /// Send a read to each mirror, then to the host.
    ///
    /// `head` does not come here: a mirror's `Last-Modified` is when it
    /// copied the file, and Maven reads a publish time from it. `exists`
    /// does, since presence is all it asks.
    async fn read<'h, T>(
        &'h self,
        req: &Req,
        ctx: &Ctx,
        send: impl Fn(Hop<'h>) -> futures::future::BoxFuture<'h, Result<T>>,
    ) -> Result<T> {
        // Only what the host itself would send, so a mirror widens nothing.
        if self.constraints.allows(&req.url) {
            for mirror in &self.mirrors {
                let Some(url) = mirror.rewrite(&req.url) else {
                    continue;
                };

                let copy = Req {
                    url: url.clone(),
                    ..req.clone()
                };

                match send((copy, &mirror.http)).await {
                    Err(err) if is_passed_over(&err) => continue,

                    // Named, because every message names the owner's url:
                    // a log is the one place to see a mirror answered.
                    Ok(answer) => {
                        ctx.log()
                            .debug(format_args!("{} answered from mirror {url}", req.url));

                        return Ok(answer);
                    }

                    other => return other,
                }
            }
        }

        self.follow(req, Access::Read, send).await
    }

    /// The refusal for a URL nothing permits, naming everything that is.
    fn refused(&self, req: &Req, routes: &[Route]) -> Error {
        let allowed: Vec<String> = self
            .constraints
            .allowed()
            .into_iter()
            .chain(routes.iter().flat_map(|route| route.constraints.allowed()))
            .collect();

        Error::Config(format!(
            "{} is outside what this extension may fetch ({})",
            req.url,
            match allowed.as_slice() {
                [] => "it is permitted no network access".to_owned(),
                allowed => allowed.join(", "),
            }
        ))
    }
}

/// A copy of the request carrying `auth`, when there is one.
fn credentialed(req: &Req, auth: Option<&Authentication>) -> Result<Req> {
    let mut prepared = req.clone();

    if let Some(auth) = auth {
        attach(&mut prepared, auth)?;
    }

    Ok(prepared)
}

/// Add the configured credential as a header.
fn attach(req: &mut Req, auth: &Authentication) -> Result<()> {
    match auth {
        Authentication::Basic { username, password } => {
            let user = resolve(username)?;
            let pass = resolve(password)?;

            let encoded = BASE64.encode(format!("{user}:{pass}"));
            req.headers
                .push(("authorization".into(), format!("Basic {encoded}")));
        }

        Authentication::Bearer {
            token,
            header,
            prefix,
        } => {
            let value = resolve(token)?;

            req.headers
                .push((header.to_ascii_lowercase(), format!("{prefix}{value}")));
        }
    }

    Ok(())
}

fn resolve(value: &Option<SecretValue>) -> Result<String> {
    match value {
        Some(secret) => Ok(secret.resolve()?.expose().to_owned()),
        None => Ok(String::new()),
    }
}

#[async_trait]
impl ExtHost for HostedExt {
    async fn head(&self, req: &Req, ctx: &Ctx) -> Result<Head> {
        self.follow(req, Access::Read, |(prepared, http)| {
            Box::pin(async move { http.head(&prepared, ctx).await })
        })
        .await
    }

    async fn exists(&self, req: &Req, ctx: &Ctx) -> Result<bool> {
        let answer = self
            .read(req, ctx, |(prepared, http)| {
                Box::pin(async move { http.head(&prepared, ctx).await })
            })
            .await;

        present(answer)
    }

    async fn fetch(&self, req: &Req, max: ByteLimit, ctx: &Ctx) -> Result<Bytes> {
        let max = self.constraints.cap(max);

        self.read(req, ctx, |(prepared, http)| {
            Box::pin(async move { http.fetch_bounded(&prepared, max, ctx).await })
        })
        .await
    }

    async fn send_file(&self, req: &Req, body: &Path, max: ByteLimit, ctx: &Ctx) -> Result<Bytes> {
        self.follow(req, Access::Write, |(prepared, http)| {
            Box::pin(async move { http.send_file(&prepared, body, max, ctx).await })
        })
        .await
    }

    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes> {
        self.follow(req, Access::Write, |(prepared, http)| {
            Box::pin(async move { http.send_form(&prepared, parts, max, ctx).await })
        })
        .await
    }

    async fn fetch_to_cache(
        &self,
        req: &Req,
        name: &str,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<CachePath> {
        // Whichever host serves it, the file lands in this capability's
        // own cache: that is where the caller will look for it.
        let target = self.cache.path(name)?;
        let full = self.cache.resolve(&target);

        self.read(req, ctx, |(prepared, http)| {
            let full = &full;

            Box::pin(async move { http.fetch_to_file(&prepared, full, expect, ctx).await })
        })
        .await?;

        Ok(target)
    }

    fn permits(&self, url: &str) -> bool {
        self.constraints.allows(url)
            || self
                .routes
                .iter()
                .any(|route| route.constraints.allows(url))
    }

    fn cache(&self) -> &Cache {
        &self.cache
    }

    fn constraints(&self) -> &Constraints {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::FixtureClient;
    use http::StatusCode;
    use std::sync::Arc;

    const ALLOWED: &str = "h://registry.test/pkg";
    const FORBIDDEN: &str = "h://evil.test/pkg";

    fn hosted(client: FixtureClient) -> (tempfile::TempDir, HostedExt) {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new()
            .allow("h://registry.test/")
            .expect("valid");

        (
            dir,
            HostedExt::new(Arc::new(client), constraints, Arc::new(sandbox)),
        )
    }

    #[tokio::test]
    async fn url_allowed_fetched() {
        let (_dir, host) = hosted(FixtureClient::new().with_body(ALLOWED, "body"));

        let body = host
            .fetch(
                &Req::get(ALLOWED),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        assert_eq!(&body[..], b"body");
    }

    /// The load-bearing test for the whole inversion.  A built-in source is
    /// ordinary Rust in this process; what stops it reaching an arbitrary
    /// host is that its only way out is this check.
    #[tokio::test]
    async fn url_outside_constraints_refused() {
        let (_dir, host) = hosted(FixtureClient::new().with_body(FORBIDDEN, "loot"));

        let err = host
            .fetch(
                &Req::get(FORBIDDEN),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("outside what this extension may fetch")
        );
        assert!(err.to_string().contains("h://registry.test/"));
    }

    /// Refusing must happen before the request exists, not after it returns.
    #[tokio::test]
    async fn url_refused_never_requested() {
        let client = FixtureClient::new().with_body(FORBIDDEN, "loot");
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new().allow("h://registry.test/").unwrap();
        let shared = Arc::new(client);
        let host = HostedExt::new(shared.clone(), constraints, Arc::new(sandbox));

        let _ = host
            .fetch(
                &Req::get(FORBIDDEN),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await;

        assert_eq!(shared.hits(FORBIDDEN), 0);
    }

    #[tokio::test]
    async fn fetch_to_cache_lands_in_the_cache() {
        let (_dir, host) = hosted(FixtureClient::new().with_body(ALLOWED, "payload"));

        let path = host
            .fetch_to_cache(
                &Req::get(ALLOWED),
                "index.json",
                &Expectation::new(),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        assert_eq!(path.as_str(), "index.json");
        assert_eq!(
            tokio::fs::read(host.cache().resolve(&path)).await.unwrap(),
            b"payload"
        );
    }

    #[tokio::test]
    async fn fetch_to_cache_refuses_escape() {
        let (_dir, host) = hosted(FixtureClient::new().with_body(ALLOWED, "payload"));

        let err = host
            .fetch_to_cache(
                &Req::get(ALLOWED),
                "../escape.json",
                &Expectation::new(),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("leaves the cache"));
    }

    /// A call site may ask for less than the configured ceiling; it cannot
    /// talk its way past it.
    #[tokio::test]
    async fn ceiling_configured_wins_over_larger_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new()
            .allow("h://registry.test/")
            .unwrap()
            .with_max_in_memory(ByteLimit::bytes(4));

        let client = FixtureClient::new().with_body(ALLOWED, "0123456789");
        let host = HostedExt::new(Arc::new(client), constraints, Arc::new(sandbox));

        let err = host
            .fetch(
                &Req::get(ALLOWED),
                ByteLimit::mib(64),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::DownloadTooLarge);
    }

    /// `curl -F name=value -F name=@file`: values go as written, and a
    /// file field sends the file's **contents**, not its path.
    #[tokio::test]
    async fn form_sends_values_and_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new().allow("h://registry.test/").unwrap();
        let client = Arc::new(FixtureClient::new().with_body(ALLOWED, "ok"));

        let staged = dir.path().join("dist.tgz");
        std::fs::write(&staged, b"payload bytes").expect("written");

        let host = HostedExt::new(client.clone(), constraints, Arc::new(sandbox));

        host.send_form(
            &Req::post(ALLOWED, String::new()),
            &[
                FormPart::text(":action", "file_upload"),
                FormPart::text("name", "tuna"),
                FormPart::file("content", &staged).named("tuna-1.2.0.tgz"),
            ],
            ByteLimit::mib(1),
            &Ctx::for_test(crate::model::Cause::Requested { arg: "x".into() }),
        )
        .await
        .expect("sent");

        let posted = client.posted_to(ALLOWED);
        let [fields] = posted.as_slice() else {
            panic!("expected one form, got {}", posted.len());
        };

        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();

        assert_eq!(names, [":action", "name", "content"], "order is preserved");
        assert_eq!(fields[0].1, b"file_upload");
        assert_eq!(
            fields[2].1, b"payload bytes",
            "the file's contents, not its path"
        );
    }

    /// A form goes through the same allow-list as a fetch. An extension
    /// able to post anywhere would be a way around the constraint that
    /// makes every other request safe -- and an upload is the request where
    /// it would matter most.
    #[tokio::test]
    async fn form_cannot_reach_outside_allow_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new().allow("h://registry.test/").unwrap();
        let client = FixtureClient::new().with_body(FORBIDDEN, "ok");

        let host = HostedExt::new(Arc::new(client), constraints, Arc::new(sandbox));

        let refused = host
            .send_form(
                &Req::post(FORBIDDEN, String::new()),
                &[FormPart::text("a", "b")],
                ByteLimit::mib(1),
                &Ctx::for_test(crate::model::Cause::Requested { arg: "x".into() }),
            )
            .await;

        assert!(refused.is_err());
    }

    /// The extension asks for a URL and gets bytes; the host adds the
    /// credential, so there is nothing for the extension to leak.
    #[tokio::test]
    async fn credential_attached_by_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new().allow("h://registry.test/").unwrap();
        let client = FixtureClient::new().with_body(ALLOWED, "body");

        let host = HostedExt::new(Arc::new(client), constraints, Arc::new(sandbox)).with_auth(
            Some(Authentication::Bearer {
                token: Some(SecretValue::Text {
                    value: "s3cret".into(),
                }),
                header: "Authorization".into(),
                prefix: "Bearer ".into(),
            }),
        );

        let prepared = host.prepare(&Req::get(ALLOWED)).expect("prepared");

        assert_eq!(
            prepared.headers,
            vec![("authorization".to_string(), "Bearer s3cret".to_string())]
        );
    }

    /// A credential must never be attached to a request that was going to be
    /// refused anyway -- that would hand a token to whatever host the
    /// extension named.
    #[tokio::test]
    async fn url_refused_gets_no_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let constraints = Constraints::new().allow("h://registry.test/").unwrap();

        let host = HostedExt::new(
            Arc::new(FixtureClient::new()),
            constraints,
            Arc::new(sandbox),
        )
        .with_auth(Some(Authentication::Bearer {
            token: Some(SecretValue::Text {
                value: "s3cret".into(),
            }),
            header: "Authorization".into(),
            prefix: "Bearer ".into(),
        }));

        let err = host.prepare(&Req::get(FORBIDDEN)).unwrap_err();

        assert!(!err.to_string().contains("s3cret"));
    }

    #[tokio::test]
    async fn credential_basic_auth_encoded() {
        let mut req = Req::get(ALLOWED);

        attach(
            &mut req,
            &Authentication::Basic {
                username: Some(SecretValue::Text { value: "u".into() }),
                password: Some(SecretValue::Text { value: "p".into() }),
            },
        )
        .expect("attached");

        // base64("u:p")
        assert_eq!(req.headers[0].1, "Basic dTpw");
    }
    // -- File hosts ---------------------------------------------------------

    const INDEX: &str = "h://index.test/simple/pkg/";
    const FILE: &str = "h://files.test/packages/pkg-1.0.tar.gz";
    const ANONYMOUS: &str = "https://cdn.test/packages/pkg-1.0.tar.gz";

    fn bearer(token: &str) -> Option<Authentication> {
        Some(Authentication::Bearer {
            token: Some(SecretValue::Text {
                value: token.into(),
            }),
            header: "Authorization".into(),
            prefix: "Bearer ".into(),
        })
    }

    /// An index with its own credential, a file host with another, and an
    /// anonymous CDN, each served by its own fixture so a test can see
    /// which client carried a request.
    struct Routed {
        _dir: tempfile::TempDir,
        host: HostedExt,
        index: Arc<FixtureClient>,
        files: Arc<FixtureClient>,
        cdn: Arc<FixtureClient>,
    }

    fn routed() -> Routed {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let index = Arc::new(FixtureClient::new().with_body(INDEX, "index"));
        let files = Arc::new(FixtureClient::new().with_body(FILE, "file"));
        let cdn = Arc::new(FixtureClient::new().with_body(ANONYMOUS, "cdn"));

        let host = HostedExt::new(
            index.clone(),
            Constraints::new().allow("h://index.test/").unwrap(),
            Arc::new(sandbox),
        )
        .with_auth(bearer("index-token"))
        .with_routes(vec![
            Route::new(
                Constraints::new().allow("h://files.test/").unwrap(),
                files.clone(),
                bearer("files-token"),
            ),
            Route::new(
                Constraints::new().allow("https://cdn.test/").unwrap(),
                cdn.clone(),
                None,
            ),
        ]);

        Routed {
            _dir: dir,
            host,
            index,
            files,
            cdn,
        }
    }

    fn authorization(client: &FixtureClient, url: &str) -> Vec<String> {
        client
            .headers_to(url)
            .into_iter()
            .flatten()
            .filter(|(name, _)| name == "authorization")
            .map(|(_, value)| value)
            .collect()
    }

    async fn fetched(routed: &Routed, url: &str) -> Result<Bytes> {
        routed
            .host
            .fetch(
                &Req::get(url),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
    }

    /// The host's own prefix keeps its own client and credential.
    #[tokio::test]
    async fn route_own_base_uses_own_credential() {
        let routed = routed();

        assert_eq!(
            &fetched(&routed, INDEX).await.expect("fetched")[..],
            b"index"
        );
        assert_eq!(authorization(&routed.index, INDEX), ["Bearer index-token"]);
    }

    /// A file host gets its own credential, and never the index's.
    #[tokio::test]
    async fn route_file_host_uses_its_credential() {
        let routed = routed();

        assert_eq!(&fetched(&routed, FILE).await.expect("fetched")[..], b"file");
        assert_eq!(authorization(&routed.files, FILE), ["Bearer files-token"]);
        assert!(routed.index.requested().is_empty());
    }

    /// Permission is asked the way a read is routed: the own prefix, then
    /// each file host, and nothing else.
    #[test]
    fn permits_own_base_and_file_hosts() {
        let routed = routed();

        assert!(routed.host.permits(INDEX));
        assert!(routed.host.permits(FILE));
        assert!(routed.host.permits(ANONYMOUS));
        assert!(!routed.host.permits("h://elsewhere.test/x"));
    }

    #[tokio::test]
    async fn route_anonymous_sends_no_credential() {
        let routed = routed();

        assert_eq!(
            &fetched(&routed, ANONYMOUS).await.expect("fetched")[..],
            b"cdn"
        );
        assert!(authorization(&routed.cdn, ANONYMOUS).is_empty());
    }

    /// An anonymous file host is https only, so the same name over http is
    /// refused.
    #[tokio::test]
    async fn route_anonymous_refuses_http() {
        let routed = routed();

        assert!(
            fetched(&routed, "http://cdn.test/packages/pkg-1.0.tar.gz")
                .await
                .is_err()
        );
    }

    /// Nothing permits it, so nothing is sent, and the refusal names every
    /// prefix that is permitted.
    #[tokio::test]
    async fn route_unlisted_is_refused() {
        let routed = routed();

        let err = fetched(&routed, FORBIDDEN).await.unwrap_err();

        assert!(err.to_string().contains("h://files.test/"), "{err}");
        assert!(routed.index.requested().is_empty());
        assert!(routed.files.requested().is_empty());
        assert!(routed.cdn.requested().is_empty());
    }

    /// Routes are for reads. A write to a file host is refused.
    #[tokio::test]
    async fn route_never_carries_writes() {
        let routed = routed();
        let staged = routed._dir.path().join("body");
        std::fs::write(&staged, b"x").expect("written");

        let sent = routed
            .host
            .send_file(
                &Req::put(FILE),
                &staged,
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await;

        assert!(sent.is_err());

        let posted = routed
            .host
            .send_form(
                &Req::post(FILE, String::new()),
                &[FormPart::text("a", "b")],
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await;

        assert!(posted.is_err());
        assert!(routed.files.requested().is_empty());
    }

    /// Whichever host serves a file, it lands in this capability's own
    /// cache, where the caller looks for it.
    #[tokio::test]
    async fn route_fetch_lands_in_own_cache() {
        let routed = routed();

        let staged = routed
            .host
            .fetch_to_cache(
                &Req::get(FILE),
                "pkg-1.0.tar.gz",
                &Expectation::new(),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        let path = routed.host.cache().resolve(&staged);

        assert_eq!(std::fs::read(path).expect("read"), b"file");
    }

    // -- Redirects ----------------------------------------------------------

    const MANAGER: &str = "h://mgr.test/";
    const REPO_A: &str = "h://mgr.test/repository/a/x.jar";
    const REPO_B: &str = "h://mgr.test/repository/b/x.jar";

    fn moved(status: StatusCode, location: &str) -> crate::net::Canned {
        crate::net::Canned::status(status).header("location", location)
    }

    /// Confined to `repository/a`, redirectable anywhere on the manager.
    fn manager(client: Arc<FixtureClient>) -> (tempfile::TempDir, HostedExt) {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");

        let host = HostedExt::new(
            client,
            Constraints::new()
                .allow("h://mgr.test/repository/a/")
                .unwrap(),
            Arc::new(sandbox),
        )
        .with_site(Constraints::new().allow(MANAGER).unwrap())
        .with_auth(bearer("mgr-token"));

        (dir, host)
    }

    async fn read(host: &HostedExt, url: &str) -> Result<Bytes> {
        host.fetch(
            &Req::get(url),
            ByteLimit::kib(1),
            &Ctx::anonymous_for_test(),
        )
        .await
    }

    /// A manager moving `/repository/a` to `/repository/b` is followed, with
    /// the manager's own credential.
    #[tokio::test]
    async fn redirect_within_site_keeps_credential() {
        let client = Arc::new(
            FixtureClient::new()
                .with(REPO_A, moved(StatusCode::FOUND, "/repository/b/x.jar"))
                .with_body(REPO_B, "moved"),
        );
        let (_dir, host) = manager(client.clone());

        assert_eq!(&read(&host, REPO_A).await.expect("followed")[..], b"moved");
        assert_eq!(authorization(&client, REPO_B), ["Bearer mgr-token"]);
    }

    /// Landing on an additional host carries **its** credential, never the
    /// one the first hop was sent with.
    #[tokio::test]
    async fn redirect_to_additional_host_uses_its_credential() {
        let routed = routed();
        let redirecting =
            Arc::new(FixtureClient::new().with(INDEX, moved(StatusCode::FOUND, FILE)));
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");
        let host = HostedExt::new(
            redirecting,
            Constraints::new().allow("h://index.test/").unwrap(),
            Arc::new(sandbox),
        )
        .with_auth(bearer("index-token"))
        .with_routes(vec![Route::new(
            Constraints::new().allow("h://files.test/").unwrap(),
            routed.files.clone(),
            bearer("files-token"),
        )]);

        assert_eq!(&read(&host, INDEX).await.expect("followed")[..], b"file");
        assert_eq!(authorization(&routed.files, FILE), ["Bearer files-token"]);
    }

    #[tokio::test]
    async fn redirect_elsewhere_is_refused() {
        let client =
            Arc::new(FixtureClient::new().with(REPO_A, moved(StatusCode::FOUND, FORBIDDEN)));
        let (_dir, host) = manager(client.clone());

        let err = read(&host, REPO_A).await.expect_err("refused");

        assert!(matches!(err, Error::Redirected { .. }), "{err}");
        assert!(client.headers_to(FORBIDDEN).is_empty());
    }

    #[tokio::test]
    async fn redirect_chain_is_capped() {
        let client = Arc::new(FixtureClient::new().with(REPO_A, moved(StatusCode::FOUND, REPO_A)));
        let (_dir, host) = manager(client.clone());

        let err = read(&host, REPO_A).await.expect_err("capped");

        assert!(matches!(err, Error::Redirected { .. }), "{err}");
        assert_eq!(client.hits(REPO_A), MAX_REDIRECTS + 1);
    }

    async fn upload(host: &HostedExt, url: &str) -> Result<Bytes> {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = dir.path().join("body");

        std::fs::write(&body, "payload").expect("written");

        host.send_file(
            &Req::put(url),
            &body,
            ByteLimit::kib(1),
            &Ctx::anonymous_for_test(),
        )
        .await
    }

    /// 307 promises the same method and body, and the target is where a
    /// first write could go.
    #[tokio::test]
    async fn write_follows_307_within_prefix() {
        const MOVED: &str = "h://mgr.test/repository/a/y.jar";

        let client = Arc::new(
            FixtureClient::new()
                .with(REPO_A, moved(StatusCode::TEMPORARY_REDIRECT, MOVED))
                .with_body(MOVED, "stored"),
        );
        let (_dir, host) = manager(client.clone());

        assert_eq!(
            &upload(&host, REPO_A).await.expect("followed")[..],
            b"stored"
        );
        assert_eq!(client.sent_to(MOVED), [b"payload".to_vec()]);
    }

    /// A write never leaves its prefix, even for the rest of the site.
    #[tokio::test]
    async fn write_redirect_outside_prefix_is_refused() {
        let client = Arc::new(
            FixtureClient::new().with(REPO_A, moved(StatusCode::TEMPORARY_REDIRECT, REPO_B)),
        );
        let (_dir, host) = manager(client.clone());

        let err = upload(&host, REPO_A).await.expect_err("refused");

        assert!(matches!(err, Error::Redirected { .. }), "{err}");
        assert!(client.sent_to(REPO_B).is_empty());
    }

    /// 302 lets a client switch to `GET`, which would drop the upload.
    #[tokio::test]
    async fn write_redirect_changing_method_is_refused() {
        const MOVED: &str = "h://mgr.test/repository/a/y.jar";

        let client = Arc::new(FixtureClient::new().with(REPO_A, moved(StatusCode::FOUND, MOVED)));
        let (_dir, host) = manager(client.clone());

        let err = upload(&host, REPO_A).await.expect_err("refused");

        assert!(matches!(err, Error::Redirected { .. }), "{err}");
        assert!(client.sent_to(MOVED).is_empty());
    }

    const ORIGIN: &str = "h://central.test/maven2/";
    const ORIGIN_JAR: &str = "h://central.test/maven2/a/b/1/b-1.jar";
    const ORIGIN_INDEX: &str = "h://central.test/maven2/a/b/1/";
    const COPY_JAR: &str = "h://copy.test/maven2/a/b/1/b-1.jar";
    const COPY_INDEX: &str = "h://copy.test/maven2/a/b/1/";
    const SECOND_JAR: &str = "h://second.test/m2/a/b/1/b-1.jar";
    const INDEX_SKIP: &str = "*/";

    /// A host on `ORIGIN`, sending its token, mirrored by `copies` in order.
    fn mirrored(
        client: Arc<FixtureClient>,
        copies: &[(&str, &[&str])],
    ) -> (tempfile::TempDir, HostedExt) {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");
        let constraints = Constraints::new().allow(ORIGIN).expect("valid");

        let mirrors = copies
            .iter()
            .map(|(url, skip)| {
                let skip = skip.iter().map(|pattern| (*pattern).to_owned()).collect();

                Mirror::new(ORIGIN, url, client.clone(), skip)
            })
            .collect();

        let host = HostedExt::new(client, constraints, Arc::new(sandbox))
            .with_mirrors(mirrors)
            .with_auth(Some(Authentication::Bearer {
                token: Some(SecretValue::Text {
                    value: "s3cret".into(),
                }),
                header: "Authorization".into(),
                prefix: "Bearer ".into(),
            }));

        (dir, host)
    }

    async fn get(host: &HostedExt, url: &str) -> Result<Bytes> {
        host.fetch(
            &Req::get(url),
            ByteLimit::kib(1),
            &Ctx::anonymous_for_test(),
        )
        .await
    }

    #[tokio::test]
    async fn mirror_answers_first() {
        let client = Arc::new(
            FixtureClient::new()
                .with_body(COPY_JAR, "copy")
                .with_body(ORIGIN_JAR, "origin"),
        );
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2", &[])]);

        assert_eq!(&get(&host, ORIGIN_JAR).await.expect("fetched")[..], b"copy");
        assert_eq!(client.hits(ORIGIN_JAR), 0);
    }

    /// Every message names the owner's url, so the log says a mirror
    /// answered.
    #[tokio::test]
    async fn mirror_answer_is_logged() {
        let client = Arc::new(FixtureClient::new().with_body(COPY_JAR, "copy"));
        let (_dir, host) = mirrored(client, &[("h://copy.test/maven2", &[])]);
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = Ctx::anonymous_for_test().logging_with(log);

        host.fetch(&Req::get(ORIGIN_JAR), ByteLimit::kib(1), &ctx)
            .await
            .expect("fetched");

        let lines: Vec<String> = recorder.lines().into_iter().map(|(_, text)| text).collect();

        assert_eq!(
            lines,
            [format!("{ORIGIN_JAR} answered from mirror {COPY_JAR}")]
        );
    }

    /// Each mirror lacking the file hands the read on, the owner last.
    #[tokio::test]
    async fn mirror_missing_file_falls_through() {
        let client = Arc::new(FixtureClient::new().with_body(ORIGIN_JAR, "origin"));
        let (_dir, host) = mirrored(
            client.clone(),
            &[("h://copy.test/maven2/", &[]), ("h://second.test/m2/", &[])],
        );

        assert_eq!(
            &get(&host, ORIGIN_JAR).await.expect("fetched")[..],
            b"origin"
        );
        assert_eq!(client.hits(COPY_JAR), 1);
        assert_eq!(client.hits(SECOND_JAR), 1);
    }

    /// `*/` keeps a directory index off a mirror that has none.
    #[tokio::test]
    async fn mirror_skipped_path_goes_to_owner() {
        let client = Arc::new(FixtureClient::new().with_body(ORIGIN_INDEX, "index"));
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2/", &[INDEX_SKIP])]);

        assert_eq!(
            &get(&host, ORIGIN_INDEX).await.expect("fetched")[..],
            b"index"
        );
        assert_eq!(client.hits(COPY_INDEX), 0);
    }

    #[tokio::test]
    async fn mirror_gets_no_credential() {
        let client = Arc::new(FixtureClient::new().with_body(COPY_JAR, "copy"));
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2/", &[])]);

        get(&host, ORIGIN_JAR).await.expect("fetched");

        let sent = client.headers_to(COPY_JAR);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].iter().all(|(name, _)| name != "authorization"));
    }

    /// A mirror's `Last-Modified` is when it copied the file.
    #[tokio::test]
    async fn mirror_skipped_by_head() {
        let client = Arc::new(
            FixtureClient::new()
                .with_body(COPY_JAR, "copy")
                .with_body(ORIGIN_JAR, "origin"),
        );
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2/", &[])]);

        host.head(&Req::head(ORIGIN_JAR), &Ctx::anonymous_for_test())
            .await
            .expect("answered");

        assert_eq!(client.hits(COPY_JAR), 0);
        assert_eq!(client.hits(ORIGIN_JAR), 1);
    }

    /// Presence is all `exists` asks, so a mirror answers it.
    #[tokio::test]
    async fn exists_asks_mirrors() {
        let client = Arc::new(FixtureClient::new().with_body(COPY_JAR, "copy"));
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2/", &[])]);

        let found = host
            .exists(&Req::head(ORIGIN_JAR), &Ctx::anonymous_for_test())
            .await
            .expect("answered");

        assert!(found);
        assert_eq!(client.hits(COPY_JAR), 1);
        assert_eq!(client.hits(ORIGIN_JAR), 0);
    }

    /// Missing everywhere is an answer, not an error.
    #[tokio::test]
    async fn exists_answers_absence() {
        let client = Arc::new(FixtureClient::new());
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2/", &[])]);

        let found = host
            .exists(&Req::head(ORIGIN_JAR), &Ctx::anonymous_for_test())
            .await
            .expect("answered");

        assert!(!found);
        assert_eq!(client.hits(ORIGIN_JAR), 1);
    }

    /// A mirror that answers wrongly is the answer, not a reason to ask
    /// the owner: the same rule a proxy follows.
    #[tokio::test]
    async fn mirror_failure_stops() {
        let client = Arc::new(
            FixtureClient::new()
                .with_body(COPY_JAR, "0123456789".repeat(200))
                .with_body(ORIGIN_JAR, "origin"),
        );
        let (_dir, host) = mirrored(client.clone(), &[("h://copy.test/maven2/", &[])]);

        let err = get(&host, ORIGIN_JAR).await.expect_err("too large");

        assert_eq!(err.code(), crate::core::problem::Code::DownloadTooLarge);
        assert_eq!(client.hits(ORIGIN_JAR), 0);
    }

    #[tokio::test]
    async fn mirror_fills_cache() {
        let client = Arc::new(FixtureClient::new().with_body(COPY_JAR, "copy"));
        let (_dir, host) = mirrored(client, &[("h://copy.test/maven2/", &[])]);

        let path = host
            .fetch_to_cache(
                &Req::get(ORIGIN_JAR),
                "b-1.jar",
                &Expectation::new(),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        assert_eq!(
            tokio::fs::read(host.cache().resolve(&path)).await.unwrap(),
            b"copy"
        );
    }

    /// Only the owner's own urls: an additional host's files stay there.
    #[test]
    fn mirror_rewrite_stays_in_owner() {
        let mirror = Mirror::new(
            ORIGIN,
            "h://copy.test/maven2",
            Arc::new(FixtureClient::new()),
            vec![],
        );

        assert_eq!(mirror.rewrite(ORIGIN_JAR).as_deref(), Some(COPY_JAR));
        assert_eq!(mirror.rewrite(FILE), None);
    }

    // -- Concurrency caps ---------------------------------------------------

    /// Long enough for a request that is free to go to finish; a request
    /// still waiting for a slot after this is held.
    const SETTLE: std::time::Duration = std::time::Duration::from_millis(50);

    /// One download and one upload slot.
    fn single() -> Gates {
        let one = std::num::NonZeroUsize::new(1).expect("nonzero");

        Gates::new(
            crate::ext::Gate::limited(one),
            crate::ext::Gate::limited(one),
        )
    }

    /// Whether `request` finishes within [`SETTLE`].
    async fn finishes<T>(request: impl std::future::Future<Output = T>) -> bool {
        tokio::time::timeout(SETTLE, request).await.is_ok()
    }

    /// A read waits while every download slot is taken, and goes once one
    /// frees.
    #[tokio::test]
    async fn gate_full_holds_read() {
        let gates = single();
        let (_dir, host) = hosted(FixtureClient::new().with_body(ALLOWED, "body"));
        let host = host.with_gates(gates.clone());

        let held = gates.downloads().enter().await;

        assert!(
            !finishes(get(&host, ALLOWED)).await,
            "a read passed a full gate"
        );

        drop(held);

        assert!(
            finishes(get(&host, ALLOWED)).await,
            "the freed slot was not used"
        );
    }

    /// An upload takes an upload slot, not a download one.
    #[tokio::test]
    async fn gate_uploads_apart_from_downloads() {
        let gates = single();
        let (dir, host) = hosted(FixtureClient::new().with_body(ALLOWED, ""));
        let host = host.with_gates(gates.clone());
        let staged = dir.path().join("staged");

        std::fs::write(&staged, b"payload").expect("staged");

        let _reading = gates.downloads().enter().await;
        let ctx = Ctx::anonymous_for_test();
        let put = Req::put(ALLOWED);
        let upload = host.send_file(&put, &staged, ByteLimit::kib(1), &ctx);

        assert!(finishes(upload).await, "an upload waited behind a download");
    }

    /// A read routed to an additional host counts against that host's caps,
    /// and leaves the owner's alone.
    #[tokio::test]
    async fn gate_route_counts_against_its_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sandbox = Cache::open(dir.path().join("work")).expect("opened");
        let client = Arc::new(
            FixtureClient::new()
                .with_body(INDEX, "index")
                .with_body(FILE, "file"),
        );
        let files = single();

        let host = HostedExt::new(
            client.clone(),
            Constraints::new().allow("h://index.test/").unwrap(),
            Arc::new(sandbox),
        )
        .with_routes(vec![
            Route::new(
                Constraints::new().allow("h://files.test/").unwrap(),
                client,
                None,
            )
            .with_gates(files.clone()),
        ]);

        let _held = files.downloads().enter().await;

        assert!(
            !finishes(get(&host, FILE)).await,
            "a routed read passed its full gate"
        );
        assert!(
            finishes(get(&host, INDEX)).await,
            "the owner's read waited on a route"
        );
    }

    /// A mirror is never capped: it answers while the owner's slots are full.
    #[tokio::test]
    async fn gate_mirror_uncapped() {
        let gates = single();
        let client = Arc::new(FixtureClient::new().with_body(COPY_JAR, "copy"));
        let (_dir, host) = mirrored(client, &[("h://copy.test/maven2", &[])]);
        let host = host.with_gates(gates.clone());

        let _held = gates.downloads().enter().await;

        assert!(
            finishes(get(&host, ORIGIN_JAR)).await,
            "a mirror read waited"
        );
    }
}
