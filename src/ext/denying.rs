//! A host that permits nothing.

use async_trait::async_trait;
use bytes::Bytes;

use super::cache::{Cache, CachePath};
use super::constraints::Constraints;
use super::host::ExtHost;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::net::{ByteLimit, Expectation, FormPart, Head, Req};

/// A host with no HTTP client, for building extensions that will not fetch.
///
/// `validate-config` builds every configured extension to prove it can,
/// and starting an HTTP client per host to answer that would be a side
/// effect of checking a file. Every request is refused.
///
/// The cache is a temporary directory, removed when this is dropped.
#[derive(Debug)]
pub struct DenyingHost {
    // Declared before `_dir`, so the cache goes before its directory.
    cache: Cache,
    constraints: Constraints,

    /// Held only so the directory lives as long as the host.
    _dir: tempfile::TempDir,
}

impl DenyingHost {
    pub fn new() -> Result<Self> {
        let dir = tempfile::tempdir().map_err(|source| Error::WriteFile {
            path: std::env::temp_dir(),
            source,
        })?;

        Ok(Self {
            cache: Cache::open(dir.path())?,
            constraints: Constraints::new(),
            _dir: dir,
        })
    }

    fn refused(req: &Req) -> Error {
        Error::Config(format!(
            "{} is outside what this extension may fetch (it is permitted no network access)",
            req.url
        ))
    }
}

#[async_trait]
impl ExtHost for DenyingHost {
    async fn head(&self, req: &Req, _ctx: &Ctx) -> Result<Head> {
        Err(Self::refused(req))
    }

    async fn fetch(&self, req: &Req, _max: ByteLimit, _ctx: &Ctx) -> Result<Bytes> {
        Err(Self::refused(req))
    }

    async fn fetch_to_cache(
        &self,
        req: &Req,
        _name: &str,
        _expect: &Expectation,
        _ctx: &Ctx,
    ) -> Result<CachePath> {
        Err(Self::refused(req))
    }

    async fn send_file(
        &self,
        req: &Req,
        _body: &std::path::Path,
        _max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        Err(Self::refused(req))
    }

    async fn send_form(
        &self,
        req: &Req,
        _parts: &[FormPart<'_>],
        _max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        Err(Self::refused(req))
    }

    fn permits(&self, _url: &str) -> bool {
        false
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
    use crate::model::Cause;

    #[tokio::test]
    async fn every_request_refused() {
        let host = DenyingHost::new().expect("built");
        let ctx = Ctx::for_test(Cause::Requested { arg: "app".into() });
        let req = Req::get("https://registry.test/thing");

        assert!(host.head(&req, &ctx).await.is_err());
        assert!(host.fetch(&req, ByteLimit::METADATA, &ctx).await.is_err());
        assert!(!host.permits(&req.url));
    }

    #[test]
    fn cache_goes_with_host() {
        let host = DenyingHost::new().expect("built");
        let root = host.cache().root().to_path_buf();

        assert!(root.exists());

        drop(host);

        assert!(!root.exists());
    }
}
