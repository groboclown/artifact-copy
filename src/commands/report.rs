//! Writing inspected artifacts to a report as they are found.
//!
//! The [`Visitor`] every inspection hands its artifacts to. Streaming rather
//! than collecting, for the reason [`crate::commands::spider`] gives: a
//! inspection can reach millions, and the result set would be the largest
//! thing in the process.
//!
//! # One writer, many workers
//!
//! The spider visits concurrently, and a [`ReportWriter`] takes records
//! from every worker. Whatever locking that needs lives inside the writer,
//! so this is a plain adapter: it turns the walk's vocabulary -- visited,
//! refused, and unresolved -- into records, and hands them over. Problems
//! reach the report through [`crate::report::Logged`], which watches the
//! sink.

use async_trait::async_trait;

use super::spider::Visitor;

use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Problem;
use crate::internal::provenance::provenance_chain;
use crate::model::{ArtifactRequest, ResolvedArtifact};
use crate::repo::Source;
use crate::repo::enumerate::Found;
use crate::report::{
    AdvisoryRecord, ArtifactRecord, Enumeration, LicenseRecord, Outcome, ProblemRecord,
    QuarantineRecord, Record, ReportWriter,
};

/// Appends each artifact to a report.
pub struct ToReport {
    writer: Box<dyn ReportWriter>,
}

impl ToReport {
    pub fn new(writer: Box<dyn ReportWriter>) -> Self {
        Self { writer }
    }
}

/// An adapter is also a writer, so a command that only appends records --
/// the header that opens the stream, the summary that closes it, a copy's
/// outcomes -- takes this rather than reaching past it for the writer.
impl ReportWriter for ToReport {
    fn write(&self, record: &Record) -> Result<()> {
        self.writer.write(record)
    }

    fn artifact_count(&self) -> u64 {
        self.writer.artifact_count()
    }

    fn flush(&self) -> Result<()> {
        self.writer.flush()
    }

    /// Forwarded, not defaulted.
    ///
    /// Inheriting the `None` default would make every command that writes
    /// through this adapter -- which is all of them -- silently claim
    /// nothing, bind nothing, and checkpoint nothing, while still writing a
    /// perfectly good record stream. Nothing would fail; the database would
    /// just be missing the half that makes it more than a log.
    fn state(&self) -> Option<&dyn crate::report::ReportState> {
        self.writer.state()
    }

    fn query(&self) -> Result<Option<std::sync::Arc<dyn crate::report::ReportQuery>>> {
        self.writer.query()
    }
}

/// The same writer serves an inventory walk, so `inspect` and `find`
/// produce one report format rather than two that drift.
#[async_trait]
impl crate::commands::find::Sink for ToReport {
    /// A record of what the repository **holds**, with no files, license or
    /// publish time -- an enumerator knows none of those. See
    /// [`crate::commands::find`] for why it does not go and ask.
    async fn found(&self, found: &Found, ctx: &Ctx) -> Result<()> {
        let mut record = ArtifactRecord::found(found, provenance_chain(ctx));

        record.quarantine = held(ctx);
        record.advisories = flagged(ctx);

        self.write(&Record::Artifact(Box::new(record)))
    }

    /// Translate the walk's vocabulary into the report's.
    ///
    /// A line report keeps no state and drops this, which is the honest
    /// answer: a JSONL file has nowhere to put a cursor, so a walk written
    /// to one cannot be resumed and should not appear to be.
    async fn reached(&self, at: &crate::commands::find::Progress<'_>) -> Result<()> {
        let Some(state) = self.writer.state() else {
            return Ok(());
        };

        state.checkpoint(&Enumeration {
            repository: at.enumerator,
            kind: at.kind,
            depth: at.depth.as_str(),
            scope: at.scope.as_deref(),
            cursor: at.cursor.map(|cursor| cursor.as_str()),
            pages: at.walked.pages,
            found: at.walked.found,
            reached_end: at.reached_end,
        })
    }
}

#[async_trait]
impl Visitor for ToReport {
    /// Both halves of a record come from the context, and that is
    /// the whole reason the walk narrows it to one artifact before
    /// visiting: the **provenance** says why this artifact was looked at,
    /// and the **reservations** are what rules had to say about it.
    ///
    /// Read here rather than looked up afterwards because the context is
    /// the only thing that knows both, and it is already in hand.
    async fn visit(
        &self,
        artifact: &ResolvedArtifact,
        _source: &dyn Source,
        ctx: &Ctx,
    ) -> Result<()> {
        let mut record = ArtifactRecord::new(artifact, provenance_chain(ctx));

        record.quarantine = held(ctx);
        record.license = judged(ctx);
        record.advisories = flagged(ctx);

        self.write(&Record::Artifact(Box::new(record)))
    }

    /// The same record a taken artifact gets, plus why it was not taken.
    /// Everything else about it is still true and still worth reporting:
    /// a reader deciding whether to override the refusal needs the
    /// license and the files, not only the verdict.
    async fn refused(&self, artifact: &ResolvedArtifact, why: &Problem, ctx: &Ctx) -> Result<()> {
        let mut record = ArtifactRecord::new(artifact, provenance_chain(ctx));

        record.quarantine = held(ctx);
        record.license = judged(ctx);
        record.advisories = flagged(ctx);
        record.outcome = Some(Outcome::Refused {
            why: Box::new(ProblemRecord::from(why)),
        });

        self.write(&Record::Artifact(Box::new(record)))
    }

    async fn unresolved(&self, request: &ArtifactRequest, why: &Problem, ctx: &Ctx) -> Result<()> {
        self.write(&Record::Artifact(Box::new(ArtifactRecord::unresolved(
            request,
            why,
            provenance_chain(ctx),
        ))))
    }
}

/// What the license policy decided about the artifact this context is
/// narrowed to, when a policy decided anything.
fn judged(ctx: &Ctx) -> Option<LicenseRecord> {
    ctx.verdict().map(LicenseRecord::from)
}

/// The advisories that named the artifact this context is narrowed to.
fn flagged(ctx: &Ctx) -> Vec<AdvisoryRecord> {
    ctx.flags().iter().map(AdvisoryRecord::from).collect()
}

/// The reservations held against the artifact this context is narrowed to.
fn held(ctx: &Ctx) -> Vec<QuarantineRecord> {
    ctx.reservations()
        .iter()
        .filter_map(QuarantineRecord::of)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::commands::find::Sink;
    use crate::core::problem::{Code, Quarantine};
    use crate::model::{ArtifactId, EcosystemId, Release, Version};

    /// Keeps every record, shared with the test so it can look after the
    /// adapter has taken ownership of the writer.
    #[derive(Clone, Default)]
    struct Kept(Arc<Mutex<Vec<Record>>>);

    impl ReportWriter for Kept {
        fn write(&self, record: &Record) -> Result<()> {
            self.0.lock().expect("not poisoned").push(record.clone());
            Ok(())
        }

        fn artifact_count(&self) -> u64 {
            0
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }
    }

    /// A listing held back by a quarantine carries it on its record, so
    /// the database files it in `observation_quarantine`.
    #[tokio::test]
    async fn found_carries_quarantine() {
        let kept = Kept::default();
        let report = ToReport::new(Box::new(kept.clone()));

        let id = ArtifactId::new(EcosystemId::npm(), None, "fs");
        let version = Version::new("0.0.1-security", Release::General);
        let ctx = Ctx::anonymous_for_test().for_artifact(id.clone(), Some(version.clone()));

        ctx.report(Code::MalwareKnown, crate::message!("advisory-affected"));
        report
            .found(&Found::new(id).version(version), &ctx)
            .await
            .expect("written");

        let records = kept.0.lock().expect("not poisoned");
        let [Record::Artifact(record)] = records.as_slice() else {
            panic!("one artifact record, found {records:?}");
        };

        assert_eq!(record.quarantine.len(), 1);
        assert_eq!(record.quarantine[0].class, Quarantine::Hard);
    }
}
