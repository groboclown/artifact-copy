//! An enumerator without what its `omit` rules leave out.
//!
//! Wraps every enumerator built, proxies and extensions included, so no
//! enumerator applies the built-in omissions itself.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::Omit;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::model::{EcosystemId, ListingDepth};
use crate::repo::enumerate::{Cursor, Enumerator, Found, Narrowing, Page, page_of};

pub struct OmittingEnumerator {
    inner: Arc<dyn Enumerator>,
    omit: Omit,
}

impl OmittingEnumerator {
    pub fn new(inner: Arc<dyn Enumerator>, omit: Omit) -> Self {
        Self { inner, omit }
    }

    /// `found`, or `None` when a whole-artifact rule leaves it out.
    fn kept(&self, mut found: Found, ctx: &Ctx) -> Option<Found> {
        if let Some(rule) = self.omit.artifact(&found.id, found.version.as_ref()) {
            // Reported, not returned: one artifact, not the walk.
            self.omit
                .omitted(&found.id, found.version.as_ref(), &rule, ctx);

            return None;
        }

        let files = std::mem::take(&mut found.files);
        found.files = self.omit.retain(
            &found.id,
            found.version.as_ref(),
            files,
            |file| file.name.as_str(),
            ctx,
        );

        Some(found)
    }
}

#[async_trait]
impl Enumerator for OmittingEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        self.inner.ecosystems()
    }

    fn reports_last_download(&self) -> bool {
        self.inner.reports_last_download()
    }

    fn depth(&self) -> ListingDepth {
        self.inner.depth()
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        self.page(None, cursor, ctx).await
    }

    fn narrowing(&self) -> Narrowing {
        self.inner.narrowing()
    }

    async fn walk_since(
        &self,
        since: DateTime<Utc>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        self.page(Some(since), cursor, ctx).await
    }

    /// The inner count, which still includes what is left out: counting
    /// that would mean walking the catalog.
    async fn count(&self, ctx: &Ctx) -> Result<Option<u64>> {
        self.inner.count(ctx).await
    }
}

impl OmittingEnumerator {
    /// The inner page, filtered. Its cursor is kept as it came: an empty
    /// page with a cursor still has more behind it.
    async fn page(
        &self,
        since: Option<DateTime<Utc>>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        let page = page_of(self.inner.as_ref(), since, cursor, ctx).await?;

        Ok(Page {
            found: page
                .found
                .into_iter()
                .filter_map(|found| self.kept(found, ctx))
                .collect(),
            next: page.next,
        })
    }
}
