//! A capability with one binding's cache policy.
//!
//! Two sources reading one repository share one capability, and with it
//! one cache, but each was configured with its own `cache-retention` and
//! `cache-freshness`. So the policy is put on the binding's handle rather
//! than on the capability: everything else is passed straight through.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use super::cache::{Cache, CachePath, CachePolicy};
use super::constraints::Constraints;
use super::host::ExtHost;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::net::{ByteLimit, Expectation, FormPart, Head, Req};

/// `inner`, answering [`ExtHost::cache_policy`] with `policy`.
#[derive(Debug)]
pub struct Policed {
    inner: Arc<dyn ExtHost>,
    policy: CachePolicy,
}

impl Policed {
    pub fn new(inner: Arc<dyn ExtHost>, policy: CachePolicy) -> Self {
        Self { inner, policy }
    }
}

#[async_trait]
impl ExtHost for Policed {
    async fn head(&self, req: &Req, ctx: &Ctx) -> Result<Head> {
        self.inner.head(req, ctx).await
    }

    async fn exists(&self, req: &Req, ctx: &Ctx) -> Result<bool> {
        self.inner.exists(req, ctx).await
    }

    async fn fetch(&self, req: &Req, max: ByteLimit, ctx: &Ctx) -> Result<Bytes> {
        self.inner.fetch(req, max, ctx).await
    }

    async fn fetch_to_cache(
        &self,
        req: &Req,
        name: &str,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<CachePath> {
        self.inner.fetch_to_cache(req, name, expect, ctx).await
    }

    async fn send_file(&self, req: &Req, body: &Path, max: ByteLimit, ctx: &Ctx) -> Result<Bytes> {
        self.inner.send_file(req, body, max, ctx).await
    }

    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        ctx: &Ctx,
    ) -> Result<Bytes> {
        self.inner.send_form(req, parts, max, ctx).await
    }

    fn permits(&self, url: &str) -> bool {
        self.inner.permits(url)
    }

    fn cache(&self) -> &Cache {
        self.inner.cache()
    }

    fn constraints(&self) -> &Constraints {
        self.inner.constraints()
    }

    fn cache_policy(&self) -> &CachePolicy {
        &self.policy
    }
}
