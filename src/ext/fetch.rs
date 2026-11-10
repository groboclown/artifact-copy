//! Fetching through a host: a JSON document, or a `net::Fetch` for `net`.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use bytes::Bytes;

use super::ExtHost;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::net::{ByteLimit, Fetch, Req};

/// Fetch a JSON document through `host` and read it.
///
/// Six adapters wrote the same three steps -- fetch, `from_slice`, wrap the
/// parse failure with the URL -- and the wrapping is the part worth
/// centralizing: a `serde_json` message alone ("expected value at line 1
/// column 1") names neither what was being read nor where it came from.
///
/// `what` names the *document*, not the operation -- "npm packument", not
/// "fetching the packument" -- because it is read as a noun in
/// `Error::Malformed`'s rendering. The URL is taken from the request, so it
/// cannot disagree with the one actually fetched.
///
/// Only for documents small enough to hold in memory, which `max`
/// enforces; anything artifact-sized goes to [`ExtHost::fetch_to_cache`].
pub async fn fetch_json<T: serde::de::DeserializeOwned>(
    host: &dyn ExtHost,
    req: &Req,
    max: ByteLimit,
    what: &'static str,
    ctx: &Ctx,
) -> Result<T> {
    let body = host.fetch(req, max, ctx).await?;

    serde_json::from_slice(&body).map_err(|source| crate::core::error::Error::Malformed {
        what,
        url: req.url.clone(),
        detail: source.to_string(),
    })
}

/// A host and a context, as the [`Fetch`] anything in `net` reads through.
///
/// Declared here rather than in `net` so the dependency runs one way:
/// `ext` is built on `net`, and `net` never names `ext`. The two lifetimes
/// are separate because the host lives for the run and the context for one
/// artifact.
pub struct HostFetch<'h, 'c> {
    host: &'h dyn ExtHost,
    ctx: &'c Ctx,
}

impl<'h, 'c> HostFetch<'h, 'c> {
    pub fn new(host: &'h dyn ExtHost, ctx: &'c Ctx) -> Self {
        Self { host, ctx }
    }
}

#[async_trait::async_trait]
impl Fetch for HostFetch<'_, '_> {
    async fn fetch(&self, req: &Req, max: ByteLimit) -> Result<Bytes> {
        self.host.fetch(req, max, self.ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the shared helper is for: a parse failure that names the
    /// document and the URL.
    ///
    /// The failing body here is what a misconfigured proxy actually
    /// returns -- an HTML error page with a 200 -- and `serde_json`'s own
    /// message for it ("expected value at line 1 column 1") identifies
    /// neither the registry nor the request.
    #[tokio::test]
    async fn document_malformed_reported_with_name_and_url() {
        use crate::ext::testing::TestHost;
        use crate::model::Cause;
        use crate::net::FixtureClient;

        const URL: &str = "https://registry.test/thing";

        let host = TestHost::new(
            FixtureClient::new().with_body(URL, "<html>502 Bad Gateway</html>".as_bytes()),
        );
        let ctx = Ctx::for_test(Cause::Requested { arg: "app".into() });

        let err = fetch_json::<serde_json::Value>(
            &host,
            &Req::get(URL),
            ByteLimit::METADATA,
            "widget index",
            &ctx,
        )
        .await
        .expect_err("HTML is not JSON");

        let rendered = err.to_string();

        assert!(rendered.contains("widget index"), "{rendered}");
        assert!(rendered.contains(URL), "{rendered}");
        assert_eq!(err.code(), crate::core::problem::Code::MetadataMalformed);
    }

    /// The URL comes from the request, so the two cannot disagree -- the
    /// reason the helper does not take one.
    #[tokio::test]
    async fn document_well_formed_reads_without_caller_url() {
        use crate::ext::testing::TestHost;
        use crate::model::Cause;
        use crate::net::FixtureClient;

        const URL: &str = "https://registry.test/good";

        let host = TestHost::new(FixtureClient::new().with_body(URL, r#"{"n":1}"#.as_bytes()));
        let ctx = Ctx::for_test(Cause::Requested { arg: "app".into() });

        let doc: serde_json::Value = fetch_json(
            &host,
            &Req::get(URL),
            ByteLimit::METADATA,
            "widget index",
            &ctx,
        )
        .await
        .expect("valid JSON");

        assert_eq!(doc["n"], 1);
        assert_eq!(host.requested(), vec![URL.to_owned()]);
    }
}
