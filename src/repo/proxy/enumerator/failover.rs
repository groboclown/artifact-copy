//! Enumerate the first upstream that can start.
//!
//! The enumeration companion to [`crate::repo::proxy::Failover`], and it
//! reads the same way: the upstreams are alternatives holding the same
//! content, so one of them answering is enough.
//!
//! # Falling over is only possible before the first page
//!
//! This is the rule the whole design turns on, and it is not the source
//! proxy's rule.
//!
//! A source proxy may fall through per artifact, because each artifact is
//! an independent question. A catalog is not: walking it is one long
//! conversation, and abandoning it halfway to start another upstream would
//! re-report everything already emitted. A caller counting artifacts, or
//! sampling a percentage of them, would be quietly wrong.
//!
//! So an upstream is chosen once:
//!
//! | When it fails | What happens |
//! | --- | --- |
//! | before its first page | the next upstream is tried |
//! | after its first page | the failure is returned |
//!
//! The consequence worth stating plainly: **a failover enumerator reports
//! one upstream's catalog, not the union of all of them.** If the mirror
//! holds something the registry does not, this does not list it.
//!
//! That is the correct reading when the upstreams are a hot standby of
//! each other, or nested subsets of each other, which is what
//! `proxy-failover` means. It is *not* correct for upstreams that hold
//! genuinely different things -- a release repository and a snapshot one,
//! say -- and the answer there is not a merging enumerator. It is to merge on
//! the **source** side, where the question is the version list of one
//! artifact and the answer is bounded; see [`crate::repo::proxy::Merge`].
//!
//! # Counting
//!
//! [`Enumerator::count`] answers from the first upstream that can answer, and
//! `None` -- *do not guess* -- as soon as one cannot. A total that came from
//! a different upstream than the walk would make `--sample-size=N%` a
//! percentage of the wrong number.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{EnumeratorUpstreams, Position};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::Options;
use crate::model::{EcosystemId, ListingDepth};
use crate::repo::enumerate::{Cursor, Enumerator, Narrowing, Page, page_of};

/// Enumerates the first upstream that can start.
pub struct Failover {
    upstreams: EnumeratorUpstreams,
}

impl Failover {
    /// At least one upstream, and an ecosystem in common -- the same two
    /// rules the source proxy applies, for the same reasons. A failover
    /// over nothing enumerates nothing, and upstreams holding disjoint
    /// ecosystems are not alternatives for each other.
    pub fn open(upstreams: EnumeratorUpstreams, options: &Options) -> Result<Self> {
        let _ = options;

        upstreams.require_at_least(1, "proxy-failover")?;
        upstreams.require_shared_ecosystem("proxy-failover")?;

        Ok(Self { upstreams })
    }

    /// Whether a failure means *try the next upstream* or *stop*.
    ///
    /// The same allow-list the source proxy uses: this upstream does not
    /// have it, or cannot answer. Corruption and cancellation stop.
    fn can_try_another(err: &Error) -> bool {
        matches!(err.code(), Code::ArtifactNotFound | Code::HostUnreachable)
    }

    /// The first upstream, whose identity this proxy inherits.
    fn first(&self) -> &dyn Enumerator {
        self.at(0).expect("open refused an empty failover")
    }

    fn at(&self, at: usize) -> Option<&dyn Enumerator> {
        self.upstreams
            .iter()
            .nth(at)
            .map(|upstream| upstream.item.as_ref())
    }

    /// Re-address a page's cursor into this proxy's own numbering, or move
    /// to the next upstream when this one has finished.
    fn forward(&self, at: usize, page: Page) -> Page {
        // `None` stays `None`: a failover reports one upstream's catalog,
        // so finishing the chosen upstream finishes the walk.
        let next = page.next.map(|inner| {
            Position {
                at,
                inner: Some(inner),
            }
            .to_cursor()
        });

        Page {
            found: page.found,
            next,
        }
    }
}

#[async_trait]
impl Enumerator for Failover {
    /// The first upstream's ecosystems, which is sound because `open`
    /// required them to share one.
    fn ecosystems(&self) -> &[EcosystemId] {
        self.first().ecosystems()
    }

    /// **Inherited rather than assumed**: a proxy in front of a Nexus can
    /// answer the usage question, and one in front of a registry index
    /// cannot, and claiming otherwise is how a retention tool deletes
    /// things people are using.
    fn reports_last_download(&self) -> bool {
        self.first().reports_last_download()
    }

    /// Inherited from the first upstream, as `reports_last_download` is.
    fn depth(&self) -> ListingDepth {
        self.first().depth()
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        self.page(None, cursor, ctx).await
    }

    /// Inherited from the first upstream, as `depth` is. A later upstream
    /// that cannot narrow walks everything, which is a superset and loses
    /// nothing.
    fn narrowing(&self) -> Narrowing {
        self.first().narrowing()
    }

    async fn walk_since(
        &self,
        since: DateTime<Utc>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        self.page(Some(since), cursor, ctx).await
    }

    /// The first upstream that can answer, and `None` the moment one
    /// cannot.
    ///
    /// Not "the first upstream that has a count": a total taken from a
    /// different upstream than the one the walk will use would make
    /// `--sample-size=N%` a percentage of the wrong number. `None` is
    /// always a safe answer here and a wrong total never is.
    async fn count(&self, ctx: &Ctx) -> Result<Option<u64>> {
        for upstream in self.upstreams.iter() {
            match upstream.item.count(ctx).await {
                Ok(Some(total)) => return Ok(Some(total)),

                // This upstream will not say. Another one's number would
                // describe a catalog this walk is not going to read.
                Ok(None) => return Ok(None),

                Err(err) if Self::can_try_another(&err) => continue,

                Err(err) => return Err(err),
            }
        }

        Ok(None)
    }
}

impl Failover {
    /// One page from the chosen upstream, narrowed to `since` when one is
    /// given.
    async fn page(
        &self,
        since: Option<DateTime<Utc>>,
        cursor: Option<&Cursor>,
        ctx: &Ctx,
    ) -> Result<Page> {
        let position = match cursor {
            Some(cursor) => Position::parse(cursor)?,
            None => Position::start(),
        };

        // Resuming: the upstream was already chosen, and its own rule
        // decides what happens next. Falling over now would re-report
        // everything already emitted.
        if position.inner.is_some() {
            let Some(enumerator) = self.at(position.at) else {
                return Err(out_of_range(position.at, self.upstreams.len()));
            };

            let page = page_of(enumerator, since, position.inner.as_ref(), ctx).await?;

            return Ok(self.forward(position.at, page));
        }

        // Starting, either at the first upstream or at a later one because
        // an earlier one could not begin.
        let mut first: Option<Error> = None;

        for at in position.at..self.upstreams.len() {
            let enumerator = self.at(at).expect("in range");

            match page_of(enumerator, since, None, ctx).await {
                Ok(page) => return Ok(self.forward(at, page)),

                Err(err) if Self::can_try_another(&err) => {
                    first.get_or_insert(err);
                }

                Err(err) => return Err(err),
            }
        }

        match first {
            Some(err) => Err(err),

            // Reached only when the list is empty, which `open` refuses.
            None => Ok(Page::last(Vec::new())),
        }
    }
}

/// A cursor naming an upstream that is not there.
///
/// Reachable by handing back a cursor issued against a differently
/// configured proxy -- after an entry was removed from `proxy-to`, say.
fn out_of_range(at: usize, len: usize) -> Error {
    Error::Malformed {
        what: "proxy enumerator cursor",
        url: String::new(),
        detail: format!(
            "names upstream {at}, but this proxy has {len}; the cursor was issued \
             against a different configuration"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::model::ArtifactId;
    use crate::repo::enumerate::Found;
    use crate::repo::upstream::{Upstream, Upstreams};
    use http::StatusCode;
    use std::sync::Arc;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NPM: LazyLock<[EcosystemId; 1]> = LazyLock::new(|| [EcosystemId::npm()]);
    static MAVEN: LazyLock<[EcosystemId; 1]> = LazyLock::new(|| [EcosystemId::maven()]);

    /// An enumerator over a fixed catalog, which can be told to fail at a
    /// chosen page.
    struct Fake {
        name: &'static str,

        /// One entry per page; each is the artifact names that page holds.
        pages: Vec<Vec<&'static str>>,

        /// Fail when asked for this page index, whatever it holds.
        fails_at: Option<usize>,

        /// What that failure is.
        code: Code,

        /// What `count` answers.
        total: Option<u64>,

        asked: AtomicUsize,
    }

    impl Fake {
        fn new(name: &'static str, pages: &[&[&'static str]]) -> Self {
            Self {
                name,
                pages: pages.iter().map(|page| page.to_vec()).collect(),
                fails_at: None,
                code: Code::HostUnreachable,
                total: None,
                asked: AtomicUsize::new(0),
            }
        }

        fn failing_at(mut self, page: usize) -> Self {
            self.fails_at = Some(page);
            self
        }

        fn with_code(mut self, code: Code) -> Self {
            self.code = code;
            self
        }

        fn counting(mut self, total: Option<u64>) -> Self {
            self.total = total;
            self
        }
    }

    #[async_trait]
    impl Enumerator for Fake {
        fn ecosystems(&self) -> &[EcosystemId] {
            &*NPM
        }

        fn reports_last_download(&self) -> bool {
            true
        }

        fn depth(&self) -> ListingDepth {
            ListingDepth::Versions
        }

        async fn walk(&self, cursor: Option<&Cursor>, _ctx: &Ctx) -> Result<Page> {
            self.asked.fetch_add(1, Ordering::SeqCst);

            let page: usize = match cursor {
                Some(cursor) => cursor.as_str().parse().expect("our own cursor"),
                None => 0,
            };

            if self.fails_at == Some(page) {
                return Err(match self.code {
                    Code::ArtifactNotFound => Error::HttpStatus {
                        url: self.name.to_owned(),
                        status: StatusCode::NOT_FOUND,
                        retry_at: None,
                        detail: None,
                    },

                    Code::MetadataMalformed => Error::Malformed {
                        what: "catalog",
                        url: self.name.to_owned(),
                        detail: "corrupt".to_owned(),
                    },

                    _ => Error::HttpStatus {
                        url: self.name.to_owned(),
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        retry_at: None,
                        detail: None,
                    },
                });
            }

            let found: Vec<Found> = self.pages[page]
                .iter()
                .map(|name| Found::new(ArtifactId::new(EcosystemId::npm(), None, name)))
                .collect();

            Ok(match page + 1 < self.pages.len() {
                true => Page::more(found, Cursor::new((page + 1).to_string())),
                false => Page::last(found),
            })
        }

        async fn count(&self, _ctx: &Ctx) -> Result<Option<u64>> {
            Ok(self.total)
        }
    }

    fn failover(enumerators: Vec<Fake>) -> Failover {
        let upstreams: EnumeratorUpstreams = Upstreams::new(
            enumerators
                .into_iter()
                .map(|enumerator| Upstream::new(Arc::new(enumerator) as Arc<dyn Enumerator>))
                .collect(),
        );

        Failover::open(upstreams, &Options::default()).expect("opens")
    }

    /// Walk to the end, collecting every name in order.
    async fn walk_all(enumerator: &Failover) -> Result<Vec<String>> {
        let ctx = Ctx::anonymous_for_test();

        let mut names = Vec::new();
        let mut cursor: Option<Cursor> = None;

        loop {
            let page = enumerator.walk(cursor.as_ref(), &ctx).await?;

            names.extend(page.found.iter().map(|found| found.id.name().to_owned()));

            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(names),
            }
        }
    }

    #[tokio::test]
    async fn upstream_first_walked_to_end() {
        let enumerator = failover(vec![
            Fake::new("primary", &[&["a", "b"], &["c"]]),
            Fake::new("mirror", &[&["x"]]),
        ]);

        let names = walk_all(&enumerator).await.expect("walked");

        assert_eq!(names, ["a", "b", "c"]);
    }

    /// The consequence of failover-not-merge, stated as a test so nobody
    /// "fixes" it by accident: the mirror's extra artifact is not listed.
    #[tokio::test]
    async fn failover_reports_one_catalog_not_union() {
        let enumerator = failover(vec![
            Fake::new("primary", &[&["a"]]),
            Fake::new("mirror", &[&["a", "only-here"]]),
        ]);

        let names = walk_all(&enumerator).await.expect("walked");

        assert_eq!(names, ["a"]);
    }

    /// The motivating case: the primary cannot begin, so the mirror is
    /// walked instead -- from its own beginning, in full.
    #[tokio::test]
    async fn upstream_unable_to_begin_skipped() {
        let enumerator = failover(vec![
            Fake::new("primary", &[&["a"]]).failing_at(0),
            Fake::new("mirror", &[&["x", "y"], &["z"]]),
        ]);

        let names = walk_all(&enumerator).await.expect("walked");

        assert_eq!(names, ["x", "y", "z"]);
    }

    /// The rule the design turns on. Restarting on the mirror here would
    /// re-report "a" and "b", and every count downstream would be wrong.
    #[tokio::test]
    async fn failure_after_first_page_not_fallen_over() {
        let enumerator = failover(vec![
            Fake::new("primary", &[&["a", "b"], &["c"]]).failing_at(1),
            Fake::new("mirror", &[&["x"]]),
        ]);

        let err = walk_all(&enumerator)
            .await
            .expect_err("a part-walked catalog cannot be restarted elsewhere");

        assert_eq!(err.code(), Code::HostUnreachable);
    }

    /// Corruption is reported, not routed around -- the same rule the
    /// source proxy applies, for the same reason.
    #[tokio::test]
    async fn failure_malformed_catalog_not_fallen_over() {
        let enumerator = failover(vec![
            Fake::new("primary", &[&["a"]])
                .failing_at(0)
                .with_code(Code::MetadataMalformed),
            Fake::new("mirror", &[&["x"]]),
        ]);

        let err = walk_all(&enumerator).await.expect_err("corruption stops");

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    /// Every upstream refusing to begin returns the first refusal, because
    /// order is precedence order.
    #[tokio::test]
    async fn failure_first_refusal_reported_when_none_begin() {
        let enumerator = failover(vec![
            Fake::new("primary", &[&["a"]])
                .failing_at(0)
                .with_code(Code::HostUnreachable),
            Fake::new("mirror", &[&["x"]])
                .failing_at(0)
                .with_code(Code::ArtifactNotFound),
        ]);

        let err = walk_all(&enumerator).await.expect_err("neither can begin");

        assert_eq!(err.code(), Code::HostUnreachable);
    }

    /// A total from a different upstream than the walk would make
    /// `--sample-size=N%` a percentage of the wrong number.
    #[tokio::test]
    async fn count_unknown_not_borrowed_from_next_upstream() {
        let ctx = Ctx::anonymous_for_test();

        let silent = failover(vec![
            Fake::new("primary", &[&["a"]]).counting(None),
            Fake::new("mirror", &[&["x"]]).counting(Some(99)),
        ]);

        assert_eq!(silent.count(&ctx).await.expect("counted"), None);

        let answering = failover(vec![
            Fake::new("primary", &[&["a"]]).counting(Some(7)),
            Fake::new("mirror", &[&["x"]]).counting(Some(99)),
        ]);

        assert_eq!(answering.count(&ctx).await.expect("counted"), Some(7));
    }

    /// A proxy in front of a Nexus can answer the usage question and one
    /// in front of a registry index cannot. Claiming otherwise is how a
    /// retention tool deletes things people are using.
    #[test]
    fn identity_inherited_not_invented() {
        let enumerator = failover(vec![Fake::new("primary", &[&["a"]])]);

        assert!(enumerator.reports_last_download());
        assert_eq!(enumerator.depth(), ListingDepth::Versions);
        assert_eq!(enumerator.ecosystems(), [EcosystemId::npm()]);
    }

    /// A cursor issued against a differently configured proxy names an
    /// upstream that is no longer there.
    #[tokio::test]
    async fn cursor_naming_missing_upstream_refused() {
        let ctx = Ctx::anonymous_for_test();

        let enumerator = failover(vec![Fake::new("primary", &[&["a"], &["b"]])]);

        let err = enumerator
            .walk(Some(&Cursor::new("4:0")), &ctx)
            .await
            .expect_err("no such upstream");

        assert!(err.to_string().contains("this proxy has 1"), "{err}");
    }

    /// The claim set exists so a walk is not repeated; a proxy that
    /// re-issued an upstream's cursor unchanged would send the caller back
    /// to the wrong enumerator on resume.
    #[tokio::test]
    async fn cursor_resumed_returns_to_same_upstream() {
        let ctx = Ctx::anonymous_for_test();

        let enumerator = failover(vec![
            Fake::new("primary", &[&["a"]]).failing_at(0),
            Fake::new("mirror", &[&["x"], &["y"]]),
        ]);

        let first = enumerator.walk(None, &ctx).await.expect("walked");
        let next = first.next.expect("more to come");

        // The mirror answered, so the cursor must point back at it and not
        // at the primary that could not begin.
        assert!(next.as_str().starts_with("1:"), "{next}");

        let second = enumerator.walk(Some(&next), &ctx).await.expect("resumed");

        assert_eq!(second.found[0].id.name(), "y");
        assert!(!second.has_more());
    }

    #[test]
    fn failover_over_nothing_refused() {
        let err = match Failover::open(EnumeratorUpstreams::default(), &Options::default()) {
            Err(err) => err,
            Ok(_) => panic!("a failover over nothing must not open"),
        };

        assert_eq!(err.code(), Code::ConfigInvalid);
    }

    #[test]
    fn upstreams_disjoint_ecosystems_refused() {
        struct Maven;

        #[async_trait]
        impl Enumerator for Maven {
            fn ecosystems(&self) -> &[EcosystemId] {
                &*MAVEN
            }

            async fn walk(&self, _cursor: Option<&Cursor>, _ctx: &Ctx) -> Result<Page> {
                Ok(Page::last(Vec::new()))
            }
        }

        let mixed: EnumeratorUpstreams = Upstreams::new(vec![
            Upstream::new(Arc::new(Fake::new("npm", &[&["a"]])) as Arc<dyn Enumerator>),
            Upstream::new(Arc::new(Maven) as Arc<dyn Enumerator>),
        ]);

        let err = match Failover::open(mixed, &Options::default()) {
            Err(err) => err,
            Ok(_) => panic!("npm and maven catalogs are not alternatives"),
        };

        assert!(err.to_string().contains("disjoint"), "{err}");
    }
}
