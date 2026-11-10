//! A report database whose refreshed parts answer as though empty.
//!
//! Every cache lookup already asks the database first and falls back to the
//! server, so refreshing a part is only a matter of the database having no
//! answer for it. The writes are untouched: what the server says is still
//! recorded, so the next run can use it.
//!
//! ```text
//!   part          blanked                  fallback
//!   source        held, versions_held      the live source
//!   target        holds                    Target::exists
//!   payloads      cached                   a fresh download
//!   enumeration   resume_enumeration       a walk from the start
//!   spider        resume_walk              a dependency walk from the roots
//! ```
//!
//! The work list (`outstanding`, `inventory`) and the history
//! (`last_complete_enumeration`) are never blanked: they are what a run was
//! asked to do and what earlier runs did, not cached answers.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::core::error::Result;

use super::record::Record;
use super::refresh::{Part, Refresh};
use super::sink::{
    CacheRecord, ReportQuery, ReportState, ReportWriter, Resume, Role, WalkId, Work,
};

/// Forwards to a report, filtering what its read view answers.
pub(super) struct Refreshing {
    inner: Box<dyn ReportWriter>,
    refresh: Refresh,
}

impl Refreshing {
    pub(super) fn new(inner: Box<dyn ReportWriter>, refresh: Refresh) -> Self {
        Self { inner, refresh }
    }
}

impl ReportWriter for Refreshing {
    fn write(&self, record: &Record) -> Result<()> {
        self.inner.write(record)
    }

    fn artifact_count(&self) -> u64 {
        self.inner.artifact_count()
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn state(&self) -> Option<&dyn ReportState> {
        self.inner.state()
    }

    fn query(&self) -> Result<Option<Arc<dyn ReportQuery>>> {
        let Some(inner) = self.inner.query()? else {
            return Ok(None);
        };

        // Nothing refreshed, nothing to filter.
        if self.refresh.parts().is_empty() {
            return Ok(Some(inner));
        }

        Ok(Some(Arc::new(Filtered {
            inner,
            refresh: self.refresh.clone(),
        })))
    }
}

/// A read view with the refreshed parts blanked.
struct Filtered {
    inner: Arc<dyn ReportQuery>,
    refresh: Refresh,
}

impl ReportQuery for Filtered {
    fn resume_enumeration(&self, role: Role, name: &str) -> Result<Option<Resume>> {
        if self.refresh.covers(Part::Enumeration) {
            return Ok(None);
        }

        self.inner.resume_enumeration(role, name)
    }

    fn last_complete_enumeration(&self, role: Role, name: &str) -> Result<Option<DateTime<Utc>>> {
        self.inner.last_complete_enumeration(role, name)
    }

    fn outstanding(
        &self,
        source: &str,
        destinations: &[&str],
        after: i64,
        limit: u32,
    ) -> Result<Vec<Work>> {
        self.inner.outstanding(source, destinations, after, limit)
    }

    fn cached(&self, source: &str, purl: &str, file: &str) -> Result<Option<CacheRecord>> {
        if self.refresh.covers(Part::Payloads) {
            return Ok(None);
        }

        self.inner.cached(source, purl, file)
    }

    fn holds(&self, target: &str, purl: &str) -> Result<bool> {
        if self.refresh.covers(Part::Target) {
            return Ok(false);
        }

        self.inner.holds(target, purl)
    }

    fn inventory(&self, source: &str, after: i64, limit: u32) -> Result<Vec<Work>> {
        self.inner.inventory(source, after, limit)
    }

    fn outstanding_count(&self, source: &str, destinations: &[&str]) -> Result<Option<u64>> {
        self.inner.outstanding_count(source, destinations)
    }

    fn inventory_count(&self, source: &str) -> Result<Option<u64>> {
        self.inner.inventory_count(source)
    }

    fn held(&self, source: &str, purl: &str) -> Result<Option<Work>> {
        if self.refresh.covers(Part::Source) {
            return Ok(None);
        }

        self.inner.held(source, purl)
    }

    fn versions_held(&self, source: &str, package: &str) -> Result<Vec<(String, bool)>> {
        if self.refresh.covers(Part::Source) {
            return Ok(Vec::new());
        }

        self.inner.versions_held(source, package)
    }

    /// Not while the source is refreshed, whose versions are blanked too.
    fn source_listed(&self, source: &str) -> Result<bool> {
        if self.refresh.covers(Part::Source) {
            return Ok(false);
        }

        self.inner.source_listed(source)
    }

    fn resume_walk(&self, source: &str, spec: &str, targets: &str) -> Result<Option<WalkId>> {
        if self.refresh.covers(Part::Spider) {
            return Ok(None);
        }

        self.inner.resume_walk(source, spec, targets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers every question with something, so a blank is visible.
    struct Full;

    impl ReportQuery for Full {
        fn resume_enumeration(&self, _role: Role, _name: &str) -> Result<Option<Resume>> {
            Ok(Some(Resume {
                kind: "k".into(),
                cursor: None,
                pages: 1,
                found: 1,
                scope: None,
            }))
        }

        fn last_complete_enumeration(
            &self,
            _role: Role,
            _name: &str,
        ) -> Result<Option<DateTime<Utc>>> {
            Ok(Some(DateTime::UNIX_EPOCH))
        }

        fn outstanding(
            &self,
            _s: &str,
            _d: &[&str],
            _after: i64,
            _limit: u32,
        ) -> Result<Vec<Work>> {
            Ok(vec![work()])
        }

        fn cached(&self, _s: &str, _p: &str, _f: &str) -> Result<Option<CacheRecord>> {
            Ok(Some(CacheRecord {
                host: "h".into(),
                cache_dir: "c".into(),
                relative_path: "r".into(),
                size: None,
                verification: crate::report::Verification::Verified,
            }))
        }

        fn holds(&self, _t: &str, _p: &str) -> Result<bool> {
            Ok(true)
        }

        fn inventory(&self, _s: &str, _after: i64, _limit: u32) -> Result<Vec<Work>> {
            Ok(vec![work()])
        }

        fn held(&self, _s: &str, _p: &str) -> Result<Option<Work>> {
            Ok(Some(work()))
        }

        fn versions_held(&self, _s: &str, _p: &str) -> Result<Vec<(String, bool)>> {
            Ok(vec![("1.0.0".into(), false)])
        }

        fn source_listed(&self, _s: &str) -> Result<bool> {
            Ok(true)
        }
    }

    fn work() -> Work {
        Work {
            key: 1,
            purl: "pkg:npm/tuna@1.0.0".into(),
            version: Some("1.0.0".into()),
            pre_release: false,
            declared_license: None,
            published: None,
            run: None,
            files: Vec::new(),
        }
    }

    fn filtered(parts: &[Part]) -> Filtered {
        Filtered {
            inner: Arc::new(Full),
            refresh: Refresh::new(parts.iter().copied()),
        }
    }

    /// What each part blanks, as `(source, target, payloads, enumeration)`.
    fn blanked(query: &Filtered) -> (bool, bool, bool, bool) {
        (
            query.held("s", "p").expect("held").is_none()
                && query.versions_held("s", "p").expect("versions").is_empty()
                && !query.source_listed("s").expect("listed"),
            !query.holds("t", "p").expect("holds"),
            query.cached("s", "p", "f").expect("cached").is_none(),
            query
                .resume_enumeration(Role::Enumerator, "e")
                .expect("resume")
                .is_none(),
        )
    }

    #[test]
    fn blanks_each_part_only_own() {
        assert_eq!(blanked(&filtered(&[])), (false, false, false, false));
        assert_eq!(
            blanked(&filtered(&[Part::Source])),
            (true, false, false, false)
        );
        assert_eq!(
            blanked(&filtered(&[Part::Target])),
            (false, true, false, false)
        );
        assert_eq!(
            blanked(&filtered(&[Part::Payloads])),
            (false, false, true, false)
        );
        assert_eq!(
            blanked(&filtered(&[Part::Enumeration])),
            (false, false, false, true)
        );
        assert_eq!(blanked(&filtered(&[Part::All])), (true, true, true, true));
    }

    /// The work list and the history are what a run was asked to do, so
    /// refreshing everything still leaves them.
    #[test]
    fn blanks_never_work_or_history() {
        let query = filtered(&[Part::All]);

        assert_eq!(
            query
                .outstanding("s", &["d"], 0, 1)
                .expect("outstanding")
                .len(),
            1
        );
        assert_eq!(query.inventory("s", 0, 1).expect("inventory").len(), 1);
        assert!(
            query
                .last_complete_enumeration(Role::Enumerator, "e")
                .expect("history")
                .is_some()
        );
    }
}
