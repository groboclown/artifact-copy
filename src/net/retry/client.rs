//! Carrying out what a [`Plan`] decided.
//!
//! A decorator over any [`HttpClient`] rather than logic inside the live
//! one, which is the whole reason the retry loop can be tested at all: a
//! recorded fixture that fails twice and then recovers proves a working
//! loop, and a real flaky server proves nothing repeatable.

use std::fmt::{self, Display};
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use http::StatusCode;

use super::plan::{Decision, Outcome, Plan};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::log::{Level, Secrets};
use crate::net::excerpt::loggable;
use crate::net::{ByteLimit, Expectation, FormPart, Head, HttpClient, Method, Req};

/// What a request carried as its body, for the log.
#[derive(Debug, Clone, Copy)]
enum Payload<'b> {
    /// [`Req::body`], which may be none.
    Inline,

    File(&'b Path),

    Form(&'b [FormPart<'b>]),
}

/// A request the server refused for good, and its answer, as `--verbose`
/// shows it:
///
/// ```text
///   PUT https://nx.test/repository/m2/a/1/a-1.jar responded 503 Service Unavailable after 4 attempts
///     request header authorization: <redacted>      (shown under --unsafe-debug)
///     request body: 1024 bytes from /cache/a-1.jar
///     response retry at: 2026-11-04 12:00:00 UTC
///     response body: {"error":"read only"}
/// ```
///
/// Response headers are not here: the error that reaches this layer does
/// not carry them.  Formatted only when the line is enabled, so a quiet run
/// pays nothing, not even the file size lookup.
struct Refusal<'r> {
    req: &'r Req,
    payload: Payload<'r>,
    status: StatusCode,
    retry_at: Option<chrono::DateTime<chrono::Utc>>,
    detail: Option<&'r str>,
    attempts: u32,

    /// Whether request headers show their credentials.
    secrets: Secrets,
}

impl Display for Refusal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} responded {}",
            verb(self.req.method),
            self.req.url,
            self.status
        )?;

        if self.attempts > 1 {
            write!(f, " after {} attempts", self.attempts)?;
        }

        for (name, value) in &self.req.headers {
            write!(
                f,
                "\n  request header {name}: {}",
                loggable(name, value, self.secrets)
            )?;
        }

        if let Some(body) = self.body() {
            write!(f, "\n  request body: {body}")?;
        }

        if let Some(at) = self.retry_at {
            write!(f, "\n  response retry at: {at}")?;
        }

        if let Some(detail) = self.detail {
            write!(f, "\n  response body: {detail}")?;
        }

        Ok(())
    }
}

impl Refusal<'_> {
    /// The body's size and source, never its bytes: an upload may be large
    /// or binary.  Example: `1024 bytes from /cache/a-1.jar`.
    fn body(&self) -> Option<String> {
        match self.payload {
            Payload::Inline => self
                .req
                .body
                .as_ref()
                .map(|body| format!("{} bytes", body.len())),

            Payload::File(path) => Some(match std::fs::metadata(path) {
                Ok(meta) => format!("{} bytes from {}", meta.len(), path.display()),
                Err(_) => format!("from {}", path.display()),
            }),

            Payload::Form(parts) => Some(format!("form of {} parts", parts.len())),
        }
    }
}

fn verb(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
    }
}

/// Retries a wrapped client according to a [`Plan`].
///
/// A decorator rather than logic inside the live client, so the retrying can
/// be tested against recorded responses instead of a real flaky server.
#[derive(Debug)]
pub struct RetryingClient {
    inner: std::sync::Arc<dyn HttpClient>,
    plan: Plan,
}

impl RetryingClient {
    pub fn new(inner: std::sync::Arc<dyn HttpClient>, plan: Plan) -> Self {
        Self { inner, plan }
    }

    /// Run one operation, retrying per the plan.
    async fn attempt<T, F, Fut>(
        &self,
        req: &Req,
        payload: Payload<'_>,
        ctx: &Ctx,
        mut once: F,
    ) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        let mut elapsed = Duration::ZERO;

        loop {
            let error = match once().await {
                Ok(value) => return Ok(value),
                Err(err) => err,
            };

            let (outcome, retry_after) = match &error {
                Error::HttpStatus {
                    status, retry_at, ..
                } => (
                    Outcome::Status(*status),
                    // A time already past is no wait, not an error.
                    retry_at.map(|at| (at - chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO)),
                ),

                Error::Transport { .. } => (Outcome::Transport, None),

                // A body that exceeded its cap, a malformed document: the
                // server answered and the answer was the problem.  Trying
                // again produces the same answer.
                _ => return Err(error),
            };

            let Decision::Wait(delay) = self.plan.decide(outcome, attempt, elapsed, retry_after)
            else {
                refused(req, payload, &error, attempt + 1, ctx);
                return Err(error);
            };

            ctx.log().debug(format_args!(
                "retrying after {error}: url={}, attempt={}, delay_ms={}",
                req.url,
                attempt + 1,
                delay.as_millis(),
            ));

            tokio::time::sleep(delay).await;

            attempt += 1;
            elapsed += delay;
        }
    }
}

/// Log the last answer to a request the server refused.
///
/// 404 and 410 are routine (a probe, a mirror without the file, a missing
/// checksum sidecar), so they wait for `--debug`; any other refusal shows
/// at `--verbose`.  A transport failure had no answer and is not logged.
fn refused(req: &Req, payload: Payload<'_>, error: &Error, attempts: u32, ctx: &Ctx) {
    let Error::HttpStatus {
        status,
        retry_at,
        detail,
        ..
    } = error
    else {
        return;
    };

    let level = match *status {
        StatusCode::NOT_FOUND | StatusCode::GONE => Level::Debug,
        _ => Level::Info,
    };

    ctx.log().at(
        level,
        Refusal {
            req,
            payload,
            status: *status,
            retry_at: *retry_at,
            detail: detail.as_deref(),
            attempts,
            secrets: ctx.log().secrets(),
        },
    );
}

#[async_trait]
impl HttpClient for RetryingClient {
    async fn head(&self, req: &Req, ctx: &Ctx) -> Result<Head> {
        self.attempt(req, Payload::Inline, ctx, || self.inner.head(req, ctx))
            .await
    }

    async fn fetch_bounded(&self, req: &Req, max: ByteLimit, ctx: &Ctx) -> Result<Bytes> {
        self.attempt(req, Payload::Inline, ctx, || {
            self.inner.fetch_bounded(req, max, ctx)
        })
        .await
    }

    async fn fetch_to_file(
        &self,
        req: &Req,
        dest: &std::path::Path,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<std::path::PathBuf> {
        self.attempt(req, Payload::Inline, ctx, || {
            self.inner.fetch_to_file(req, dest, expect, ctx)
        })
        .await
    }

    /// Retried like any other request.
    ///
    /// Safe to retry because the body is a **file**, re-read from the start
    /// each attempt -- unlike a stream, which has already yielded bytes by
    /// the time it fails. Whether the *server* is happy to see a publish
    /// twice is the retry plan's business: a `PUT` is idempotent by
    /// definition and a registry that disagrees answers with a status the
    /// plan can be told not to retry.
    async fn send_file(
        &self,
        req: &Req,
        body: &std::path::Path,
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes> {
        self.attempt(req, Payload::File(body), ctx, || {
            self.inner.send_file(req, body, max, ctx)
        })
        .await
    }

    /// Retried like any other request, on the same terms as
    /// [`RetryingClient::send_file`]: every file part is re-read from the
    /// start, so an attempt that failed halfway leaves nothing behind.
    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes> {
        self.attempt(req, Payload::Form(parts), ctx, || {
            self.inner.send_form(req, parts, max, ctx)
        })
        .await
    }

    fn fetch_stream<'a>(&'a self, req: &'a Req, ctx: &'a Ctx) -> BoxStream<'a, Result<Bytes>> {
        // A stream may already have yielded bytes when it fails, so
        // re-issuing it would duplicate them.  Streaming callers handle
        // their own recovery.
        self.inner.fetch_stream(req, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigDuration;
    use crate::net::FixtureClient;
    use crate::net::fixture::Canned;
    use http::StatusCode;
    use std::sync::Arc;

    const URL: &str = "h://registry.test/thing";

    /// Delays small enough that the tests stay fast, with the curve intact.
    fn brisk(extra: &str) -> Plan {
        let json = format!(
            r#"{{"initial-delay": "1 ms", "maximum-delay": "5 ms",
                 "maximum-total-retry-seconds": "1 hr"{extra}}}"#
        );

        Plan::from_config(Some(&serde_json::from_str(&json).expect("parses"))).expect("valid")
    }

    fn retrying(client: FixtureClient, plan: Plan) -> (Arc<FixtureClient>, RetryingClient) {
        let shared = Arc::new(client);

        (shared.clone(), RetryingClient::new(shared.clone(), plan))
    }

    /// A server that fails and then recovers.  A fixture that always fails
    /// could not tell a working retry loop from a broken one.
    #[tokio::test]
    async fn failure_transient_retried_until_success() {
        let (fixture, client) = retrying(
            FixtureClient::new().with_sequence(
                URL,
                vec![
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                    Canned::ok("recovered"),
                ],
            ),
            brisk(""),
        );

        let body = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("recovered");

        assert_eq!(&body[..], b"recovered");
        assert_eq!(fixture.hits(URL), 3);
    }

    /// A permanent failure must cost exactly one request.  Retrying a 404
    /// only delays the moment the user learns the artifact is not there.
    #[tokio::test]
    async fn failure_permanent_never_retries() {
        let (fixture, client) = retrying(
            FixtureClient::new().with(URL, Canned::status(StatusCode::NOT_FOUND)),
            brisk(""),
        );

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::ArtifactNotFound);
        assert_eq!(fixture.hits(URL), 1);
    }

    /// Giving up returns the failure rather than swallowing it.
    #[tokio::test]
    async fn attempts_exhausted_surface_last_error() {
        let (fixture, client) = retrying(
            FixtureClient::new().with(URL, Canned::status(StatusCode::SERVICE_UNAVAILABLE)),
            brisk(r#", "max-retries": 2"#),
        );

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::HostUnreachable);

        // One attempt plus exactly two retries: the `Retry-After` comes off
        // the failed response, so nothing probes for it separately.
        assert_eq!(fixture.hits(URL), 3);
    }

    /// GitHub's exhausted limit is a 403 with the reset in epoch seconds.
    /// A host whose plan retries 403 waits until then; one with a budget
    /// shorter than the wait gives up and says when to come back.
    #[tokio::test]
    async fn rate_limit_exhausted_waits_for_reset() {
        let soon = (chrono::Utc::now() + chrono::Duration::seconds(1)).timestamp();
        let limited = || {
            Canned::status(StatusCode::FORBIDDEN)
                .header("x-ratelimit-remaining", "0")
                .header("x-ratelimit-reset", &soon.to_string())
        };

        let (fixture, client) = retrying(
            FixtureClient::new().with_sequence(URL, vec![limited(), Canned::ok("reset")]),
            brisk(r#", "on-status": {"403": {"retry": true}}"#),
        );

        let body = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("waited for the reset");

        assert_eq!(&body[..], b"reset");
        assert_eq!(fixture.hits(URL), 2);

        let later = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp();
        let (fixture, client) = retrying(
            FixtureClient::new().with(
                URL,
                Canned::status(StatusCode::FORBIDDEN)
                    .header("x-ratelimit-remaining", "0")
                    .header("x-ratelimit-reset", &later.to_string()),
            ),
            Plan::from_config(Some(
                &serde_json::from_str(r#"{"on-status": {"403": {"retry": true}}}"#)
                    .expect("parses"),
            ))
            .expect("valid"),
        );

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("retry after"), "{err}");
        assert_eq!(fixture.hits(URL), 1);
    }

    /// A status the user switched off stops immediately, even though the
    /// default set would have retried it.
    #[tokio::test]
    async fn status_disabled_not_retried() {
        let (fixture, client) = retrying(
            FixtureClient::new().with(URL, Canned::status(StatusCode::INTERNAL_SERVER_ERROR)),
            brisk(r#", "on-status": {"500": {"retry": false}}"#),
        );

        assert!(
            client
                .fetch_bounded(
                    &Req::get(URL),
                    ByteLimit::kib(1),
                    &Ctx::anonymous_for_test()
                )
                .await
                .is_err()
        );

        assert_eq!(fixture.hits(URL), 1);
    }

    /// An oversized body is the server answering, and the answer was the
    /// problem.  Asking again produces the same answer.
    #[tokio::test]
    async fn failure_not_server_fault_not_retried() {
        let (fixture, client) = retrying(
            FixtureClient::new().with(URL, Canned::ok("0123456789")),
            brisk(""),
        );

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::bytes(4),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::DownloadTooLarge);
        assert_eq!(fixture.hits(URL), 1);
    }

    /// A duration parses the same here as anywhere else in the config.
    #[test]
    fn durations_from_config_parser() {
        let parsed: ConfigDuration = serde_json::from_str(r#""90 sec""#).expect("parses");

        assert_eq!(parsed.get(), Duration::from_secs(90));
    }

    /// The lines a request logged that name its final answer.
    fn refusals(recorder: &crate::core::log::Recorder) -> Vec<(Level, String)> {
        recorder
            .lines()
            .into_iter()
            .filter(|(_, text)| !text.starts_with("retrying") && text.contains(" responded "))
            .collect()
    }

    fn authorized(url: &str) -> Req {
        Req {
            headers: vec![
                ("accept".into(), "application/json".into()),
                ("authorization".into(), "Bearer s3cret".into()),
            ],
            ..Req::get(url)
        }
    }

    /// Only the last attempt is logged, with credentials hidden and the
    /// server's explanation shown.
    #[tokio::test]
    async fn log_final_refusal_verbose() {
        let refused = Canned {
            body: Bytes::from_static(b"down for maintenance"),
            ..Canned::status(StatusCode::SERVICE_UNAVAILABLE)
        };
        let (_fixture, client) = retrying(
            FixtureClient::new().with(URL, refused),
            brisk(r#", "max-retries": 2"#),
        );
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = Ctx::anonymous_for_test().logging_with(log);

        client
            .fetch_bounded(&authorized(URL), ByteLimit::kib(1), &ctx)
            .await
            .expect_err("refused");

        let lines = refusals(&recorder);
        assert_eq!(lines.len(), 1, "{lines:?}");

        let (level, text) = &lines[0];
        assert_eq!(*level, Level::Info);
        assert!(
            text.starts_with(&format!("GET {URL} responded 503")),
            "{text}"
        );
        assert!(text.contains("after 3 attempts"), "{text}");
        assert!(
            text.contains("request header accept: application/json"),
            "{text}"
        );
        assert!(
            text.contains("request header authorization: <redacted>"),
            "{text}"
        );
        assert!(!text.contains("s3cret"), "{text}");
        assert!(
            text.contains("response body: down for maintenance"),
            "{text}"
        );
    }

    /// `--unsafe-debug` shows the credential a refused request sent.
    #[tokio::test]
    async fn log_unsafe_debug_reveals_header() {
        let (_fixture, client) = retrying(
            FixtureClient::new().with(URL, Canned::status(StatusCode::FORBIDDEN)),
            brisk(""),
        );
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = Ctx::anonymous_for_test().logging_with(log.with_secrets(Secrets::Revealed));

        client
            .fetch_bounded(&authorized(URL), ByteLimit::kib(1), &ctx)
            .await
            .expect_err("refused");

        let lines = refusals(&recorder);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0]
                .1
                .contains("request header authorization: Bearer s3cret"),
            "{lines:?}"
        );
    }

    /// A missing file is routine; it waits for `--debug`.
    #[tokio::test]
    async fn log_not_found_at_debug() {
        let (_fixture, client) = retrying(FixtureClient::new(), brisk(""));
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = Ctx::anonymous_for_test().logging_with(log);

        client
            .fetch_bounded(&Req::get(URL), ByteLimit::kib(1), &ctx)
            .await
            .expect_err("missing");

        let lines = refusals(&recorder);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0].0, Level::Debug);
        assert!(!lines[0].1.contains("attempts"), "{lines:?}");
    }

    /// A request that recovered was not refused.
    #[tokio::test]
    async fn log_recovery_no_refusal() {
        let (_fixture, client) = retrying(
            FixtureClient::new().with_sequence(
                URL,
                vec![
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                    Canned::ok("recovered"),
                ],
            ),
            brisk(""),
        );
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = Ctx::anonymous_for_test().logging_with(log);

        client
            .fetch_bounded(&Req::get(URL), ByteLimit::kib(1), &ctx)
            .await
            .expect("recovered");

        assert!(refusals(&recorder).is_empty());
    }

    /// An upload's size and source, never its bytes.
    #[tokio::test]
    async fn log_upload_body_summarized() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("a-1.jar");
        std::fs::write(&file, b"0123456789").expect("written");

        let (_fixture, client) = retrying(
            FixtureClient::new().with(URL, Canned::status(StatusCode::FORBIDDEN)),
            brisk(""),
        );
        let (log, recorder) = crate::core::log::Log::recording();
        let ctx = Ctx::anonymous_for_test().logging_with(log);

        client
            .send_file(&Req::put(URL), &file, ByteLimit::kib(1), &ctx)
            .await
            .expect_err("refused");

        let lines = refusals(&recorder);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].1.starts_with(&format!("PUT {URL} responded 403")),
            "{lines:?}"
        );
        assert!(
            lines[0]
                .1
                .contains(&format!("request body: 10 bytes from {}", file.display())),
            "{lines:?}"
        );
    }
}
