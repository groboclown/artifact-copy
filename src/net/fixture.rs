//! A client backed by recorded responses.
//!
//! Every test in this crate fetches through one of these, which is what keeps
//! `cargo test` offline and deterministic.  It also records the requests it
//! served, so a test can assert that an adapter fetched a packument once
//! rather than once per version.
//!
//! # Test URLs use an invalid scheme
//!
//! Fixture URLs are spelled `h://host.test/...`, not `https://`.  A reserved
//! `.test` name merely fails to resolve, which leaves a test that escapes its
//! fixture depending on DNS behaving as expected.  An invalid *scheme* cannot
//! be attempted at all: [`crate::net::ReqwestClient`] rejects it before a
//! socket exists, so the failure is a loud library error rather than a real
//! request.
//!
//! The exception is a test whose subject *is* URL semantics -- default ports,
//! scheme comparison -- where a real scheme is the faithful thing to use.
//! `h://` has no default port, so `https://x` and `https://x:443` being the
//! same host is not a property it can express.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{self, BoxStream, StreamExt};
use http::StatusCode;
use tokio::io::AsyncWriteExt;

use super::excerpt;
use super::{ByteLimit, Expectation, FormPart, Head, HttpClient, Req};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};

/// One recorded response.
#[derive(Debug, Clone)]
pub struct Canned {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,

    /// Bytes per chunk when streaming, so a test can exercise chunk-boundary
    /// behavior.  `None` delivers the body in one piece.
    pub chunk_size: Option<usize>,

    /// How long the response takes to arrive.
    ///
    /// A fixture that answers instantly cannot show a concurrency property:
    /// tasks that never overlap look identical to tasks that coalesce.  A
    /// delay here is what makes the overlap real.
    pub delay: Option<std::time::Duration>,
}

impl Canned {
    /// A 200 whose `Content-Length` matches the body.
    pub fn ok(body: impl Into<Bytes>) -> Self {
        let body = body.into();

        Self {
            status: StatusCode::OK,
            headers: vec![("content-length".into(), body.len().to_string())],
            body,
            chunk_size: None,
            delay: None,
        }
    }

    pub fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            chunk_size: None,
            delay: None,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Claim a `Content-Length` that is not the real body length.
    ///
    /// Exists to prove the size cap is enforced mid-stream: a client that
    /// trusts this header lets an oversized body straight through.
    pub fn lying_length(mut self, claimed: u64) -> Self {
        self.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        self.headers
            .push(("content-length".into(), claimed.to_string()));
        self
    }

    pub fn chunked(mut self, chunk_size: usize) -> Self {
        self.chunk_size = Some(chunk_size);
        self
    }

    /// Take `delay` to answer, so concurrent requests genuinely overlap.
    pub fn slow(mut self, delay: std::time::Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Wait out this response's delay, if it has one.
    async fn pause(&self) {
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
    }

    fn chunks(&self) -> Vec<Bytes> {
        let size = self.chunk_size.unwrap_or(self.body.len().max(1));

        self.body
            .chunks(size.max(1))
            .map(Bytes::copy_from_slice)
            .collect()
    }
}

/// Serves [`Canned`] responses by URL.
#[derive(Debug, Default)]
pub struct FixtureClient {
    responses: Mutex<HashMap<String, Canned>>,

    /// Responses served in order, for a URL that answers differently on
    /// successive requests.  A retry test needs a server that fails and then
    /// recovers; one that always fails cannot tell a working retry loop from
    /// a broken one.
    sequences: Mutex<HashMap<String, Vec<Canned>>>,

    requested: Mutex<Vec<String>>,

    /// Bodies uploaded through `send_file`, by URL.
    ///
    /// A publish is only testable by what it sent: a target that built the
    /// wrong document would otherwise pass every test that only checked it
    /// did not error.
    sent: Mutex<Vec<(String, Vec<u8>)>>,

    /// Form fields sent through `send_form`, by URL.
    ///
    /// In the order they were given -- a form's order matters to some
    /// servers, and a test that could not see it could not catch that.
    posted: Mutex<Vec<(String, Fields)>>,

    /// The headers each request carried, by URL.
    ///
    /// For a target that asks the server to verify what it sent: a
    /// checksum header nobody could see would pass every test whether it
    /// was sent or not.
    headers: Mutex<Vec<(String, Headers)>>,
}

/// One form's fields: a name and its bytes, in the order sent.
///
/// A file field records its **contents** rather than its path, because
/// what was uploaded is the thing a test is asking about.
pub type Fields = Vec<(String, Vec<u8>)>;

/// One request's headers, as sent.
pub type Headers = Vec<(String, String)>;

/// HTTP 400 and above.
const FIRST_ERROR_STATUS: StatusCode = StatusCode::BAD_REQUEST;

impl FixtureClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a response.  Chainable, so a test reads as a table.
    pub fn with(self, url: impl Into<String>, canned: Canned) -> Self {
        self.responses
            .lock()
            .expect("fixture poisoned")
            .insert(url.into(), canned);

        self
    }

    /// Register a 200 carrying `body`.
    pub fn with_body(self, url: impl Into<String>, body: impl Into<Bytes>) -> Self {
        self.with(url, Canned::ok(body))
    }

    /// Register responses served in order.
    ///
    /// The last one repeats once the sequence runs out, so a test states
    /// only the interesting prefix.
    pub fn with_sequence(self, url: impl Into<String>, responses: Vec<Canned>) -> Self {
        self.sequences
            .lock()
            .expect("fixture poisoned")
            .insert(url.into(), responses);

        self
    }

    /// URLs requested so far, in order.
    pub fn requested(&self) -> Vec<String> {
        self.requested.lock().expect("fixture poisoned").clone()
    }

    /// How many times one URL was requested.
    /// The form fields posted to `url`, in the order they were sent.
    pub fn posted_to(&self, url: &str) -> Vec<Fields> {
        self.posted
            .lock()
            .expect("fixture poisoned")
            .iter()
            .filter(|(to, _)| to == url)
            .map(|(_, fields)| fields.clone())
            .collect()
    }

    /// What was uploaded to `url`, in order.
    pub fn sent_to(&self, url: &str) -> Vec<Vec<u8>> {
        self.sent
            .lock()
            .expect("fixture poisoned")
            .iter()
            .filter(|(to, _)| to == url)
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// The headers of each request to `url`, in order.
    pub fn headers_to(&self, url: &str) -> Vec<Headers> {
        self.headers
            .lock()
            .expect("fixture poisoned")
            .iter()
            .filter(|(to, _)| to == url)
            .map(|(_, headers)| headers.clone())
            .collect()
    }

    pub fn hits(&self, url: &str) -> usize {
        self.requested()
            .iter()
            .filter(|seen| seen.as_str() == url)
            .count()
    }

    fn lookup(&self, req: &Req) -> Result<Canned> {
        self.requested
            .lock()
            .expect("fixture poisoned")
            .push(req.url.clone());

        self.headers
            .lock()
            .expect("fixture poisoned")
            .push((req.url.clone(), req.headers.clone()));

        let canned = self
            .next_in_sequence(&req.url)
            .or_else(|| {
                self.responses
                    .lock()
                    .expect("fixture poisoned")
                    .get(&req.url)
                    .cloned()
            })
            // An unregistered URL is a 404 rather than a panic: adapters
            // legitimately probe for optional files such as `.sha256`.
            .unwrap_or_else(|| Canned::status(StatusCode::NOT_FOUND));

        let location = canned
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.as_str());

        if let Some(redirect) = crate::net::redirect::redirected(&req.url, canned.status, location)
        {
            return Err(redirect);
        }

        if canned.status >= FIRST_ERROR_STATUS {
            let header = |wanted: &str| {
                canned
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
                    .map(|(_, value)| value.as_str())
            };

            // Capped as the live client caps it, so a test sees what a
            // report would.
            let limit = excerpt::ERROR_BODY_LIMIT.get() as usize;

            let (body, read) = match canned.body.len() > limit {
                true => (&canned.body[..limit], excerpt::Read::Truncated),
                false => (&canned.body[..], excerpt::Read::Whole),
            };

            return Err(Error::HttpStatus {
                url: req.url.clone(),
                status: canned.status,
                retry_at: crate::net::retry::retry_at(header, chrono::Utc::now()),
                detail: excerpt::detail(body, read, header("content-type"), &req.headers),
            });
        }

        Ok(canned)
    }
}

impl FixtureClient {
    /// Take the next response of a sequence, holding the last one once the
    /// sequence is spent.
    fn next_in_sequence(&self, url: &str) -> Option<Canned> {
        let mut sequences = self.sequences.lock().expect("fixture poisoned");
        let queued = sequences.get_mut(url)?;

        match queued.len() {
            0 => None,
            1 => queued.first().cloned(),
            _ => Some(queued.remove(0)),
        }
    }
}

#[async_trait]
impl HttpClient for FixtureClient {
    async fn head(&self, req: &Req, _ctx: &Ctx) -> Result<Head> {
        let canned = self.lookup(req)?;
        canned.pause().await;

        Ok(Head {
            status: canned.status,
            headers: canned.headers,
        })
    }

    async fn fetch_bounded(&self, req: &Req, max: ByteLimit, _ctx: &Ctx) -> Result<Bytes> {
        let canned = self.lookup(req)?;
        canned.pause().await;

        let mut seen = 0u64;

        // Accumulated chunk by chunk, exactly as the live client does, so the
        // cap is exercised the same way here.
        for chunk in canned.chunks() {
            seen += chunk.len() as u64;

            if seen > max.get() {
                return Err(Error::TooLarge {
                    url: req.url.clone(),
                    limit: max.get(),
                });
            }
        }

        Ok(canned.body)
    }

    /// Records what was sent, so a test can assert on a publish body.
    ///
    /// The file is read whole -- a fixture is small by construction, and a
    /// test that wants to know what was uploaded needs all of it.
    async fn send_file(
        &self,
        req: &Req,
        body: &Path,
        _max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        let sent = tokio::fs::read(body)
            .await
            .map_err(|source| Error::ReadFile {
                path: body.to_path_buf(),
                source,
            })?;

        self.sent
            .lock()
            .expect("fixture poisoned")
            .push((req.url.clone(), sent));

        let canned = self.lookup(req)?;
        canned.pause().await;

        Ok(canned.body.clone())
    }

    /// Records the form as `curl -F` would have been written, so a test
    /// can assert on what a publish actually sent.
    ///
    /// File parts record their **contents**, not their path: a fixture is
    /// small by construction, and what was uploaded is the thing under
    /// test.
    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        _max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        let mut fields = Vec::new();

        for part in parts {
            match part {
                FormPart::Text { name, value } => {
                    fields.push(((*name).to_owned(), value.as_bytes().to_vec()));
                }

                FormPart::File { name, path, .. } => {
                    let bytes = tokio::fs::read(path)
                        .await
                        .map_err(|source| Error::ReadFile {
                            path: path.to_path_buf(),
                            source,
                        })?;

                    fields.push(((*name).to_owned(), bytes));
                }
            }
        }

        self.posted
            .lock()
            .expect("fixture poisoned")
            .push((req.url.clone(), fields));

        let canned = self.lookup(req)?;
        canned.pause().await;

        Ok(canned.body.clone())
    }

    async fn fetch_to_file(
        &self,
        req: &Req,
        dest: &Path,
        expect: &Expectation,
        _ctx: &Ctx,
    ) -> Result<PathBuf> {
        let canned = self.lookup(req)?;
        canned.pause().await;

        // Through `Pending`, as the live client writes, so a test sees the
        // same partial-file behavior: two writers of one destination.
        let pending = super::files::Pending::begin(dest).await?;
        let mut verifier = expect.verifier();
        let mut file = pending.writer()?;

        for chunk in canned.chunks() {
            verifier.update(&chunk);

            file.write_all(&chunk)
                .await
                .map_err(|source| Error::WriteFile {
                    path: pending.path().to_path_buf(),
                    source,
                })?;
        }

        file.flush().await.map_err(|source| Error::WriteFile {
            path: pending.path().to_path_buf(),
            source,
        })?;
        drop(file);

        verifier.finish()?;
        pending.commit()?;

        Ok(dest.to_path_buf())
    }

    fn fetch_stream<'a>(&'a self, req: &'a Req, _ctx: &'a Ctx) -> BoxStream<'a, Result<Bytes>> {
        match self.lookup(req) {
            Ok(canned) => Box::pin(
                stream::once(async move {
                    canned.pause().await;
                    canned
                })
                .flat_map(|canned| stream::iter(canned.chunks().into_iter().map(Ok))),
            ),
            Err(err) => Box::pin(stream::once(async move { Err(err) })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Digest, DigestAlg};
    use futures::StreamExt;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    const URL: &str = "h://example.test/thing";

    #[tokio::test]
    async fn fetch_bounded_returns_body() {
        let client = FixtureClient::new().with_body(URL, "abc");

        let body = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        assert_eq!(&body[..], b"abc");
        assert_eq!(client.hits(URL), 1);
    }

    #[tokio::test]
    async fn fetch_oversized_body_rejected() {
        let client = FixtureClient::new().with_body(URL, "0123456789");

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::bytes(4),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::DownloadTooLarge);
    }

    /// The load-bearing test for the whole bounded-fetch design.  A client
    /// that sizes its buffer from `Content-Length` would accept this body.
    #[tokio::test]
    async fn fetch_understated_length_does_not_bypass_cap() {
        let client = FixtureClient::new().with(
            URL,
            Canned::ok("0123456789ABCDEF0123456789ABCDEF")
                .lying_length(4)
                .chunked(8),
        );

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::bytes(16),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::DownloadTooLarge);
    }

    /// A body that fits must still be served when the header lies low.
    #[tokio::test]
    async fn fetch_understated_length_within_cap_still_succeeds() {
        let client = FixtureClient::new().with(URL, Canned::ok("abcdefgh").lying_length(1));

        let body = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("fetched");

        assert_eq!(body.len(), 8);
    }

    #[tokio::test]
    async fn fetch_unregistered_url_not_found() {
        let client = FixtureClient::new();

        let err = client
            .fetch_bounded(
                &Req::get(URL),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::ArtifactNotFound);
    }

    /// The reason a server gives reaches the error, minus the credential
    /// it echoed.
    #[tokio::test]
    async fn error_body_becomes_detail() {
        let mut canned = Canned::status(StatusCode::CONFLICT).header("content-type", "text/plain");
        canned.body = Bytes::from("key\nt0ken-value is owned by another repository");

        let client = FixtureClient::new().with(URL, canned);
        let req = Req::get(URL).header("authorization", "Bearer t0ken-value");

        let err = client
            .fetch_bounded(&req, ByteLimit::kib(1), &Ctx::anonymous_for_test())
            .await
            .unwrap_err();

        let Error::HttpStatus { detail, .. } = err else {
            panic!("expected a status error: {err}");
        };

        assert_eq!(
            detail.as_deref(),
            Some("key <redacted> is owned by another repository")
        );
    }

    #[tokio::test]
    async fn fetch_to_file_verifies_before_publishing_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let client = FixtureClient::new().with_body(URL, "abc");
        let wrong = Expectation::new().with_digest(Digest::new(DigestAlg::Sha256, "00"));

        let err = client
            .fetch_to_file(&Req::get(URL), &dest, &wrong, &Ctx::anonymous_for_test())
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::ChecksumMismatch);
        assert!(
            !dest.exists(),
            "a failed download must leave nothing behind"
        );
    }

    #[tokio::test]
    async fn fetch_to_file_writes_verified_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("nested").join("out.bin");

        let client = FixtureClient::new().with(URL, Canned::ok("abc").chunked(1));
        let expect = Expectation::new()
            .with_size(3)
            .with_digest(Digest::new(DigestAlg::Sha256, ABC_SHA256));

        client
            .fetch_to_file(&Req::get(URL), &dest, &expect, &Ctx::anonymous_for_test())
            .await
            .expect("fetched");

        assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn stream_yields_configured_chunks() {
        let client = FixtureClient::new().with(URL, Canned::ok("abcdef").chunked(2));
        let ctx = Ctx::anonymous_for_test();
        let req = Req::get(URL);

        let chunks: Vec<_> = client.fetch_stream(&req, &ctx).collect().await;

        assert_eq!(chunks.len(), 3);
        assert_eq!(&chunks[0].as_ref().unwrap()[..], b"ab");
    }
}
