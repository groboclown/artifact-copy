//! HTTP access, and the only place in the tool that touches the network.
//!
//! There is deliberately **no** `fetch(url) -> Bytes`.  Every call site must
//! choose between holding a capped body in memory, streaming to a file, or
//! consuming incrementally -- which forces it to state, in code, how large it
//! expects the response to be.  A million-artifact enumeration has no room
//! for a call that quietly reads whatever arrives.

use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use http::StatusCode;

use crate::core::ctx::Ctx;
use crate::core::error::Result;

pub mod emulate;
/// Not public API: plumbing `net` shares with the cache and the targets.
mod excerpt;
pub(crate) mod files;
pub mod fixture;
mod limit;
/// Not public API: the capability follows redirects, and the clients only
/// recognize them.
pub(crate) mod redirect;
mod request;
mod reqwest_client;
pub mod retry;
pub mod sig;
/// Not public API: plumbing the adapters share.
pub(crate) mod url;
pub mod verify;

pub(crate) use files::ensure_parent;
pub use fixture::{Canned, Fields, FixtureClient, Headers};
pub use limit::ByteLimit;
pub use request::{FormPart, Method, Req};
pub use reqwest_client::ReqwestClient;
pub use retry::{Plan as RetryPlan, RetryingClient};
pub(crate) use url::{encode_path, encode_unreserved, normalized_base};
pub use verify::{Expectation, Verifier};

/// Response metadata, without a body.
#[derive(Debug, Clone, Default)]
pub struct Head {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One capped fetch, without knowing who is permitting it.
///
/// This exists to keep the dependency between `net` and `ext` pointing one
/// way. `ext` is built on `net` -- an `ExtHost` wraps an [`HttpClient`] --
/// so anything in `net` that reached back up for a host would close a
/// cycle between the two modules.
///
/// Some things in `net` genuinely do need to fetch through the host rather
/// than through a raw client, because the host is what applies the URL
/// constraints and attaches credentials. A keyserver lookup is the case:
/// it belongs beside the key handling in [`sig`], and it must still go out
/// through the host like everything else.
///
/// So the dependency is inverted. `net` declares what it needs, and `ext`
/// says that a [`crate::ext::HostFetch`] provides it.
#[async_trait]
pub trait Fetch: Send + Sync {
    /// Body held in memory, hard-capped, subject to whatever the
    /// implementation permits.
    async fn fetch(&self, req: &Req, max: ByteLimit) -> Result<Bytes>;
}

/// Fetches bytes.  Implemented by the real client, by the fixture client the
/// tests use, and by an embedder that wants to supply its own.
#[async_trait]
pub trait HttpClient: fmt::Debug + Send + Sync {
    /// Response metadata only.
    async fn head(&self, req: &Req, ctx: &Ctx) -> Result<Head>;

    /// Body held in memory, hard-capped.
    ///
    /// The cap is enforced **while streaming**, never from `Content-Length`:
    /// a hostile or broken server can understate that header, and trusting it
    /// is precisely how the cap gets bypassed.
    async fn fetch_bounded(&self, req: &Req, max: ByteLimit, ctx: &Ctx) -> Result<Bytes>;

    /// Body streamed straight to `dest`, never held whole in memory.
    /// Verified in flight against `expect`.
    async fn fetch_to_file(
        &self,
        req: &Req,
        dest: &Path,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<PathBuf>;

    /// Chunks as they arrive, for callers that parse incrementally.
    fn fetch_stream<'a>(&'a self, req: &'a Req, ctx: &'a Ctx) -> BoxStream<'a, Result<Bytes>>;

    /// Send `body` as the request body, streamed from disk.
    ///
    /// The mirror of [`HttpClient::fetch_to_file`], and it exists for the
    /// same reason: an artifact can be gigabytes, and a publish body can be
    /// larger still -- npm's wraps the tarball in base64, which is a third
    /// bigger again. Neither may be held whole in memory, so neither
    /// travels as a `String`.
    ///
    /// The **response** is capped and returned, because a refused publish
    /// explains itself in the body: *you cannot publish over an existing
    /// version* is the difference between a bug and a no-op.
    async fn send_file(&self, req: &Req, body: &Path, max: ByteLimit, ctx: &Ctx) -> Result<Bytes>;

    /// Send `parts` as a `multipart/form-data` body.
    ///
    /// The shape most registry upload endpoints take -- PyPI's is a handful
    /// of metadata fields beside the distribution file -- and the reason it
    /// is here rather than in each adapter: the framing, the boundary and
    /// the escaping are the same everywhere, and one implementation per
    /// adapter would be one chance each to get it subtly wrong.
    ///
    /// File parts are **streamed**, so a multi-gigabyte upload never lands
    /// in memory. The response is capped and returned, for the same reason
    /// [`HttpClient::send_file`] returns one.
    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_ignores_case() {
        let head = Head {
            status: StatusCode::OK,
            headers: vec![("Content-Length".into(), "42".into())],
        };

        assert_eq!(head.header("content-length"), Some("42"));
        assert_eq!(head.header("CONTENT-LENGTH"), Some("42"));
        assert_eq!(head.header("etag"), None);
    }
}
