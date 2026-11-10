//! The two visitors that ship.
//!
//! Neither is what a real walk uses -- a report writer streams to disk -- and
//! both exist because a walk has to be runnable without one.
//!
//! [`Collector`] holds every artifact it is given, which is precisely what
//! [`Visitor`] exists to avoid. It is fine for a test and for a small
//! embedded use, and wrong for a catalog walk; its own documentation says
//! so, because the type's name does not.

use async_trait::async_trait;

use super::Visitor;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Problem;
use crate::model::{ArtifactRequest, ResolvedArtifact};
use crate::repo::Source;

/// Collects what a walk found, for tests.
///
/// **Not for a catalog walk**: it holds every artifact, which is exactly
/// what [`Visitor`] exists to avoid. A report writer streams instead.
#[derive(Debug, Default)]
pub struct Collector {
    seen: std::sync::Mutex<Vec<ResolvedArtifact>>,
}

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    /// The purls collected, in inspection order.
    pub fn purls(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("collector poisoned")
            .iter()
            .map(ResolvedArtifact::purl)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.seen.lock().expect("collector poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl Visitor for Collector {
    async fn visit(
        &self,
        artifact: &ResolvedArtifact,
        _source: &dyn Source,
        _ctx: &Ctx,
    ) -> Result<()> {
        self.seen
            .lock()
            .expect("collector poisoned")
            .push(artifact.clone());

        Ok(())
    }

    /// Not collected. This holds what a walk **took**, and a caller asking
    /// for that list would otherwise act on an artifact the run refused.
    async fn refused(
        &self,
        _artifact: &ResolvedArtifact,
        _why: &Problem,
        _ctx: &Ctx,
    ) -> Result<()> {
        Ok(())
    }

    async fn unresolved(
        &self,
        _request: &ArtifactRequest,
        _why: &Problem,
        _ctx: &Ctx,
    ) -> Result<()> {
        Ok(())
    }
}

/// A visitor that does nothing, for a walk run only for its problems.
pub struct Discard;

#[async_trait]
impl Visitor for Discard {
    async fn visit(
        &self,
        _artifact: &ResolvedArtifact,
        _source: &dyn Source,
        _ctx: &Ctx,
    ) -> Result<()> {
        Ok(())
    }

    async fn refused(
        &self,
        _artifact: &ResolvedArtifact,
        _why: &Problem,
        _ctx: &Ctx,
    ) -> Result<()> {
        Ok(())
    }

    async fn unresolved(
        &self,
        _request: &ArtifactRequest,
        _why: &Problem,
        _ctx: &Ctx,
    ) -> Result<()> {
        Ok(())
    }
}
