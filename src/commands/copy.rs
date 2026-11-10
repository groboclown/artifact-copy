//! Copying artifacts from a source into a target.
//!
//! Exactly [`inspect`] with somewhere to put
//! the answer: the same requests, the same lock files, the same dependency
//! walk, and an [`upload`] for each artifact
//! reached instead of a report line.
//!
//! That sameness is the point rather than a convenience. `README.md` says
//! `inspect` "uses the same rules as the `copy` sub-command", and the only
//! way to keep that true is for one of them to *be* the other -- a second
//! implementation of root-building and spidering would drift, and the drift
//! would show up as a `inspect` that promised artifacts `copy` then did
//! not take.
//!
//! # Where the copying happens
//!
//! In the visitor. The spider hands each resolved artifact to a
//! [`Visitor`], and this one uploads it rather than writing it down, so
//! nothing accumulates and a million-artifact copy costs no more memory
//! than a walk.
//!
//! # Several versions of one package
//!
//! An ordinary case, not an edge one. A lock file names several versions of
//! a package, a user names them (`abc@1.0 abc@2.0`), and two ranges that
//! look different -- `abc@>6` and `abc@>2` -- may resolve to the same version
//! or to different ones. The spider claims each **resolved** coordinate
//! once, so two requests landing on one version are walked once and two
//! landing on different versions are both copied.
//!
//! The order they finish in is arbitrary, because the walk is concurrent.
//! That matters for anything a registry keeps *per package* rather than per
//! version -- npm's `latest` tag is the one that exists today, and it is
//! handled where it belongs: `NpmTarget` asks the target what its `latest`
//! already is and publishes the higher of that and the version in hand, so
//! the answer does not depend on which upload finished first. Nothing here
//! needs to order anything, which is what keeps the walk streaming.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::commands::spider::{Summary as Walked, Visitor};
use crate::commands::{inspect, upload};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::{Action, Problem};
use crate::core::progress::Node;
use crate::model::{ArtifactRequest, Cause, ResolvedArtifact};
use crate::repo::{Delivered, Source};
use crate::report::{
    ArtifactRecord, Cached, Claim, Claimed, DestinationOutcome, Download, Outcome, ProblemRecord,
    QuarantineRecord, Record, ReportWriter, Sent, Transfer, Upload, Verification,
};
use crate::session::Holding;
use crate::session::{ConfiguredTarget, Session};

/// What to copy, and where to.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// What to copy -- the same request `inspect` takes.
    pub what: inspect::Request<'a>,

    /// The configured targets to publish into, in the order each artifact
    /// is published to them.
    pub targets: &'a [String],

    /// Where the work comes from.
    pub from: From<'a>,
}

/// Where a copy gets its work.
#[derive(Debug, Clone)]
pub enum From<'a> {
    /// The coordinates and lock files the user named, resolved against the
    /// source. What `copy` has always done.
    Requested,

    /// A report database: everything the source holds that has not reached
    /// every target, with each artifact's files taken from the inventory
    /// rather than asked of the source again.
    ///
    /// The report is the manifest. A version the repository gained since
    /// the artifact enumeration is not in it, so re-running copies what the
    /// report says rather than quietly widening -- which is what makes a
    /// migration split across days reproducible.
    Report {
        /// How the report names itself in provenance, so a reader can see
        /// which file the work came from.
        manifest: &'a str,
    },
}

/// What a copy did.
#[derive(Debug, Clone)]
pub struct Summary {
    /// How the walk went: what was reached, skipped, pruned.
    pub walked: Walked,

    /// What each target took, in `--to` order.
    pub destinations: Vec<Tally>,

    /// The weakest verification any copied file got.
    pub verification: Verification,
}

/// What one target took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    /// The configured target's name.
    pub destination: String,

    /// Artifacts published.
    pub published: u64,

    /// Artifacts the target already had.
    ///
    /// Counted apart from `published` because re-running a migration over a
    /// mostly-copied repository is the ordinary case, and a run that says
    /// only "0 published" cannot be told from one that did nothing.
    pub already_present: u64,

    /// Artifacts a rule refused to copy.
    pub refused: u64,

    /// Artifacts that were permitted, and whose copy failed anyway.
    pub failed: u64,
}

/// Whether an artifact is this run's work for one target.
enum Claiming {
    /// Claimed. `None` when the report keeps no state to claim against.
    Go(Option<Claimed>),

    /// Already at the target, whichever run put it there.
    Skip,
}

/// Copy everything the request reaches.
pub async fn run(
    session: &mut Session<'_>,
    request: &Request<'_>,
    report: &dyn ReportWriter,
    progress: &Node,
    ctx: &Ctx,
) -> Result<Summary> {
    // Opened before the walk, so a misconfigured target fails immediately
    // rather than after the first artifact has been fetched.
    let intos = request
        .targets
        .iter()
        .map(|name| session.target(name))
        .collect::<Result<Vec<_>>>()?;

    let destinations = request
        .targets
        .iter()
        .zip(&intos)
        .map(|(name, into)| Destination::new(name, into))
        .collect();

    let copying = Copying::new(
        destinations,
        report,
        request.what.source,
        session.payloads(),
        session.cache_dir(),
    );

    let walked = match request.from {
        From::Requested => {
            let cache = copying.query.clone();

            inspect::run(
                session,
                &request.what,
                cache,
                Some(report),
                &copying,
                progress,
                ctx,
            )
            .await?
        }

        From::Report { manifest } => {
            from_report(session, request, manifest, &copying, progress, ctx).await?
        }
    };

    Ok(copying.summary(walked))
}

/// Copy what a report database says is left to do.
///
/// Two substitutions, and nothing else changes. The **roots** come from the
/// outstanding list rather than from arguments, a page at a time. And the
/// **source** is wrapped so that an artifact somebody already resolved
/// costs no request: `InventorySource` answers `versions` and `metadata`
/// out of the inventory and falls back to the repository for anything the
/// report does not hold.
///
/// Everything else -- the quarantine policy, the licence policy, the
/// publish window, the host a fetch may reach -- is what the run decided
/// about that repository, and is kept exactly.
async fn from_report(
    session: &mut Session<'_>,
    request: &Request<'_>,
    manifest: &str,
    copying: &Copying<'_, '_, '_>,
    progress: &Node,
    ctx: &Ctx,
) -> Result<Walked> {
    let Some(query) = copying.report.query()? else {
        return Err(Error::Config(
            "copying from a report database needs one; use --db=FILE".to_owned(),
        ));
    };

    let opened = inspect::read_through(
        session.source(request.what.source)?,
        std::sync::Arc::clone(&query),
        request.what.source,
    );

    let ctx = opened.deciding(ctx);

    let destinations: Vec<&str> = request.targets.iter().map(String::as_str).collect();

    let mut roots =
        inspect::Outstanding::new(query.as_ref(), request.what.source, &destinations, manifest);

    inspect::walk_from(
        &mut roots,
        &opened,
        &request.what,
        Some(copying.report),
        copying,
        progress,
        &ctx,
    )
    .await
}

/// One target a copy publishes into, and what it took.
struct Destination<'t, 'n> {
    /// The configured name this target's claims are keyed on.
    name: &'n str,

    into: &'t ConfiguredTarget,

    published: AtomicU64,
    already_present: AtomicU64,
    refused: AtomicU64,
    failed: AtomicU64,
}

impl<'t, 'n> Destination<'t, 'n> {
    fn new(name: &'n str, into: &'t ConfiguredTarget) -> Self {
        Self {
            name,
            into,
            published: AtomicU64::new(0),
            already_present: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    fn tally(&self) -> Tally {
        Tally {
            destination: self.name.to_owned(),
            published: self.published.load(Ordering::SeqCst),
            already_present: self.already_present.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
            failed: self.failed.load(Ordering::SeqCst),
        }
    }
}

/// One destination still owed an artifact, and the claim it holds on it.
struct Leg<'d, 't, 'n> {
    at: &'d Destination<'t, 'n>,
    claimed: Option<Claimed>,
}

/// What became of one artifact at each destination, in `--to` order.
type Settled<'d> = Vec<(&'d str, Outcome)>;

/// Uploads each artifact the spider reaches to every target, and records
/// what it did.
///
/// The source side -- download, verification, refusal -- happens once per
/// artifact; the target side -- claim, presence, publish -- once per
/// destination:
///
/// ```text
///   for each target: claim, holds --> skip the held and the terminal
///                         |
///   fetch + verify once  (a refusal or failure applies to all)
///                         |
///   for each remaining target, in order: publish, close
///                         |
///   discard only if every target took it
/// ```
///
/// Two lifetimes because the targets and the report are chosen in different
/// places and neither should shorten the other.
struct Copying<'t, 'r, 'n> {
    /// In `--to` order, which is the order each artifact is published in.
    destinations: Vec<Destination<'t, 'n>>,

    /// The configured source name this run's claims are keyed on.
    ///
    /// Carried because a report keys copy work on the repositories rather
    /// than on the opened handles, and only the request knows what the user
    /// called them.
    source: &'n str,

    /// Written **after** the upload, never before. The record carries what
    /// the upload decided and anything the upload itself reported, and a
    /// line written first could say neither.
    report: &'r dyn ReportWriter,

    /// Guarded rather than atomic because it is not a counter: combining
    /// two verifications is a `min` over a vocabulary, not an add.
    verification: Mutex<Verification>,

    /// What becomes of a payload once it has been published.
    payloads: crate::config::Payloads,

    /// The configured cache directory, kept as written so that moving or
    /// rebasing it is detectable rather than silent.
    cache_dir: String,

    /// A read view of the report, when the report can be asked anything.
    query: Option<std::sync::Arc<dyn crate::report::ReportQuery>>,
}

impl<'t, 'r, 'n> Copying<'t, 'r, 'n> {
    fn new(
        destinations: Vec<Destination<'t, 'n>>,
        report: &'r dyn ReportWriter,
        source: &'n str,
        payloads: crate::config::Payloads,
        cache_dir: String,
    ) -> Self {
        Self {
            destinations,
            source,
            report,

            // Nothing copied yet, so nothing is unverified yet. The first
            // artifact lowers this if it deserves to.
            verification: Mutex::new(Verification::Verified),

            payloads,
            cache_dir,

            // Asked for once. Opening a read view per artifact would be a
            // connection per artifact, which is the cost this exists to
            // avoid.
            query: report.query().unwrap_or_default(),
        }
    }

    fn summary(&self, walked: Walked) -> Summary {
        Summary {
            walked,
            destinations: self.destinations.iter().map(Destination::tally).collect(),
            verification: *self.verification.lock().expect("copy summary poisoned"),
        }
    }

    /// Claim this artifact at one destination, or learn there is nothing
    /// to do there.
    ///
    /// A report that keeps no state claims nothing and every artifact is
    /// work, which is exactly how a copy behaved before a database existed.
    fn claim(&self, at: &Destination, artifact: &ResolvedArtifact) -> Result<Claiming> {
        let Some(state) = self.report.state() else {
            return Ok(Claiming::Go(None));
        };

        let claimed = state.claim(&Claim {
            purl: &artifact.purl(),
            source: Some(self.source),
            destination: at.name,
        })?;

        match claimed {
            Some(claimed) => Ok(Claiming::Go(Some(claimed))),

            // Already at the target. Counted as already present, because
            // that is what it is from this run's point of view, and a run
            // that reported nothing for it would look like it had skipped
            // work it was asked to do.
            None => {
                at.already_present.fetch_add(1, Ordering::SeqCst);

                Ok(Claiming::Skip)
            }
        }
    }

    /// Close a claim, when one was taken.
    fn close(&self, claimed: Option<Claimed>, outcome: Transfer) -> Result<()> {
        let (Some(state), Some(claimed)) = (self.report.state(), claimed) else {
            return Ok(());
        };

        state.close(claimed, outcome)
    }

    /// Close every claim still open as `failed`, for a run that is
    /// unwinding.
    ///
    /// So the run leaves no claim open behind it. The abort is the answer
    /// either way: a claim that will not close is reported beneath it, not
    /// over it.
    fn abandon(&self, legs: &[Leg], ctx: &Ctx) {
        for leg in legs {
            if let Err(unclosed) = self.close(leg.claimed, Transfer::Failed) {
                ctx.reported_err(&unclosed);
            }
        }
    }

    /// What the report says about this artifact's cached payloads.
    ///
    /// Asked once per artifact rather than once per file, because the
    /// report is one store and a round trip per file would undo what
    /// caching bought.
    fn recorded(
        &self,
        artifact: &ResolvedArtifact,
    ) -> Result<std::collections::HashMap<String, crate::report::CacheRecord>> {
        let mut found = std::collections::HashMap::new();

        let Some(query) = self.query.as_ref() else {
            return Ok(found);
        };

        let purl = artifact.purl();

        for file in &artifact.files {
            if let Some(record) = query.cached(self.source, &purl, &file.name)? {
                found.insert(file.name.clone(), record);
            }
        }

        Ok(found)
    }

    /// Write down where each payload's bytes are, and what a failure cost.
    ///
    /// A report that keeps no state has nowhere to put this, which is the
    /// honest answer: a JSONL file cannot be asked what is cached, so a run
    /// against one fetches everything every time.
    fn fetched(
        &self,
        artifact: &ResolvedArtifact,
        payloads: &[upload::Payload],
        failed: Option<&upload::Failure>,
    ) -> Result<()> {
        let Some(state) = self.report.state() else {
            return Ok(());
        };

        let purl = artifact.purl();

        for payload in payloads {
            state.downloaded(&Download {
                source: self.source,
                purl: &purl,
                file: &payload.name,
                url: &payload.url,
                cached: Some(Cached {
                    host: &payload.host,
                    cache_dir: &self.cache_dir,
                    relative_path: &payload.relative_path,
                    size: payload.size,
                    verification: payload.verification,
                    fetched_ms: payload.kept.map(|kept| kept.fetched_ms),
                    used_ms: payload.kept.map(|kept| kept.used_ms),
                    retain_until_ms: payload.kept.and_then(|kept| kept.retain_until_ms),
                    fresh_until_ms: payload.kept.and_then(|kept| kept.fresh_until_ms),
                }),
                failure: None,
            })?;
        }

        // A failure that named no file was not about a payload at all --
        // the target refused the artifact, the run is unwinding -- and
        // filing it under one would invent a fault in a file that is fine.
        let Some(failed) = failed else {
            return Ok(());
        };

        let Some(file) = &failed.file else {
            return Ok(());
        };

        state.downloaded(&Download {
            source: self.source,
            purl: &purl,
            file,
            url: "",
            cached: None,
            failure: failed.blame,
        })
    }

    /// Write down what one target did with each file, and which files a
    /// failed publish was sending.
    ///
    /// A failure that names no side or stage is still a failed file, with
    /// no blame: the target was sending it, and recording nothing would
    /// read as never tried.
    fn delivered(
        &self,
        artifact: &ResolvedArtifact,
        leg: &Leg,
        delivered: &[(String, Delivered)],
        failed: Option<&upload::Failure>,
    ) -> Result<()> {
        let Some(state) = self.report.state() else {
            return Ok(());
        };

        let purl = artifact.purl();

        // The source's URL for a file, which keys its inventory row.
        let url_of = |name: &str| {
            artifact
                .files
                .iter()
                .find(|file| file.name == name)
                .map_or("", |file| file.url.as_str())
        };

        let undelivered = failed
            .and_then(|failed| failed.delivery.as_ref())
            .map_or(&[][..], |at| at.pending());
        let blame = failed.and_then(|failed| failed.blame);

        let finished = delivered.iter().map(|(name, how)| {
            let sent = match how {
                Delivered::Uploaded => Sent::Uploaded,
                Delivered::AlreadyPresent => Sent::AlreadyPresent,
                Delivered::Skipped => Sent::Skipped,
            };

            (name.as_str(), sent)
        });
        let pending = undelivered
            .iter()
            .map(|name| (name.as_str(), Sent::Failed(blame)));

        for (file, sent) in finished.chain(pending) {
            state.uploaded(&Upload {
                source: self.source,
                destination: leg.at.name,
                purl: &purl,
                file,
                url: url_of(file),
                sent,
                claimed: leg.claimed,
            })?;
        }

        Ok(())
    }

    /// Claim the artifact at each destination, and keep those still owed
    /// it.
    ///
    /// A destination whose claim is terminal is done for this artifact and
    /// says nothing: another run settled it. One whose target already holds
    /// the artifact is done too, and lands in `settled`.
    async fn owed<'d>(
        &'d self,
        artifact: &ResolvedArtifact,
        settled: &mut Settled<'d>,
        ctx: &Ctx,
    ) -> Result<Vec<Leg<'d, 't, 'n>>> {
        let mut legs = Vec::with_capacity(self.destinations.len());

        for at in &self.destinations {
            // Committed before a byte moves. A run killed after this leaves
            // an `in-progress` claim, which is true, and which a later run
            // can reclaim. `Skip` means the artifact already reached this
            // target, whichever source took it there.
            let claimed = match self.claim(at, artifact) {
                Ok(Claiming::Go(claimed)) => claimed,
                Ok(Claiming::Skip) => continue,
                Err(err) => {
                    self.abandon(&legs, ctx);
                    return Err(err);
                }
            };

            // A rule on this target leaves the artifact out: a decision, not
            // a failure, and settled before anything is fetched for it.
            if let Some(rule) = at.into.target.omitted(artifact) {
                let problem = ctx.reported(
                    crate::core::problem::Code::ArtifactOmitted,
                    crate::message!(
                        "artifact-omitted",
                        "{purl} is left out by the omit rule {rule} on target {target}",
                        purl = &artifact.purl(),
                        rule = &rule,
                        target = at.name,
                    ),
                );

                self.close(claimed, Transfer::Refused)?;

                let why = Box::new(ProblemRecord::from(&problem));
                settled.push((at.name, Outcome::Refused { why }));
                continue;
            }

            let leg = Leg { at, claimed };

            let holding = at
                .into
                .holds(artifact, self.report, self.query.as_deref(), at.name, ctx)
                .await;

            let holding = match holding {
                Ok(holding) => holding,
                Err(err) => {
                    legs.push(leg);
                    self.abandon(&legs, ctx);
                    return Err(err);
                }
            };

            if holding == Holding::Held {
                at.already_present.fetch_add(1, Ordering::SeqCst);
                self.close(leg.claimed, Transfer::AlreadyPresent)?;
                settled.push((at.name, Outcome::AlreadyPresent));
                continue;
            }

            legs.push(leg);
        }

        Ok(legs)
    }

    /// Grade a failed upload, and say whether it ends the run.
    ///
    /// Graded rather than propagated. One artifact a target refused must
    /// not discard the run's remaining work and the report along with it --
    /// the walk continues and the failure becomes this artifact's line. An
    /// `abort` still unwinds: a checksum mismatch or an unwritable cache is
    /// a statement about the run, not about this artifact.
    fn graded(&self, failed: &upload::Failure, ctx: &Ctx) -> Problem {
        match &failed.file {
            Some(file) => ctx.reported_file_err(&failed.err, file),
            None => ctx.reported_err(&failed.err),
        }
    }

    /// Record one artifact, with what became of it at each destination.
    ///
    /// Nothing is written when no destination settled anything: an
    /// artifact every target had already claimed was another run's work.
    fn wrote(&self, artifact: &ResolvedArtifact, settled: Settled, ctx: &Ctx) -> Result<()> {
        let Some(outcome) = worst(&settled) else {
            return Ok(());
        };

        let provenance = ctx.prov().chain().map(Cause::message).collect();

        let mut record = ArtifactRecord::new(artifact, provenance);

        record.quarantine = ctx
            .reservations()
            .iter()
            .filter_map(QuarantineRecord::of)
            .collect();

        record.outcome = Some(outcome);

        // Per target only when there are several to tell apart, so a
        // one-target report reads as it always has.
        if self.destinations.len() > 1 {
            record.outcomes = settled
                .into_iter()
                .map(|(destination, outcome)| DestinationOutcome {
                    destination: destination.to_owned(),
                    outcome,
                })
                .collect();
        }

        self.report.write(&Record::Artifact(Box::new(record)))
    }

    /// Settle a failed fetch as every destination's failure, or unwind
    /// when it aborts the run.
    fn fail_fetch<'d>(
        &'d self,
        artifact: &ResolvedArtifact,
        legs: &[Leg<'d, 't, 'n>],
        failed: upload::Failure,
        mut settled: Settled<'d>,
        ctx: &Ctx,
    ) -> Result<()> {
        let problem = self.graded(&failed, ctx);

        if problem.action() == Action::Abort {
            self.abandon(legs, ctx);
            return Err(failed.err);
        }

        self.fetched(artifact, &[], Some(&failed))?;

        for leg in legs {
            leg.at.failed.fetch_add(1, Ordering::SeqCst);
            self.close(leg.claimed, Transfer::Failed)?;

            let why = Box::new(ProblemRecord::from(&problem));
            settled.push((leg.at.name, Outcome::Failed { why }));
        }

        self.wrote(artifact, settled, ctx)
    }

    /// Settle an artifact refused after the fetch, by a check of the staged
    /// files; the refusal is the context's, and about the bytes, so every
    /// destination's.
    fn refuse_all<'d>(
        &'d self,
        artifact: &ResolvedArtifact,
        legs: &[Leg<'d, 't, 'n>],
        mut settled: Settled<'d>,
        ctx: &Ctx,
    ) -> Result<()> {
        for leg in legs {
            self.close(leg.claimed, Transfer::Refused)?;
        }

        let Some(why) = ctx.refusal() else {
            return Ok(());
        };

        for leg in legs {
            leg.at.refused.fetch_add(1, Ordering::SeqCst);

            let why = Box::new(ProblemRecord::from(&why));
            settled.push((leg.at.name, Outcome::Refused { why }));
        }

        self.wrote(artifact, settled, ctx)
    }

    /// Publish to each leg, in `--to` order. One target's failure leaves the
    /// others to publish; an abort unwinds every leg not yet closed.
    async fn publish_legs<'d>(
        &'d self,
        artifact: &ResolvedArtifact,
        fetched: &upload::Fetched,
        legs: &[Leg<'d, 't, 'n>],
        settled: &mut Settled<'d>,
        ctx: &Ctx,
    ) -> Result<Taken> {
        let mut taken = Taken::ByEvery;

        for (index, leg) in legs.iter().enumerate() {
            let failed = match upload::publish(artifact, fetched, leg.at.into, ctx).await {
                Ok(delivered) => {
                    self.delivered(artifact, leg, &delivered, None)?;
                    leg.at.published.fetch_add(1, Ordering::SeqCst);
                    self.close(leg.claimed, Transfer::Copied)?;

                    let copied = Outcome::Copied {
                        verification: fetched.verification,
                    };
                    settled.push((leg.at.name, copied));
                    continue;
                }
                Err(failed) => failed,
            };

            let problem = self.graded(&failed, ctx);

            // This leg and every one after it still holds its claim.
            if problem.action() == Action::Abort {
                self.abandon(&legs[index..], ctx);
                return Err(failed.err);
            }

            taken = Taken::NotByEvery;
            leg.at.failed.fetch_add(1, Ordering::SeqCst);

            let delivered = failed.delivery.as_ref().map_or(&[][..], |at| at.files());
            self.delivered(artifact, leg, delivered, Some(&failed))?;
            self.close(leg.claimed, Transfer::Failed)?;

            let why = Box::new(ProblemRecord::from(&problem));
            settled.push((leg.at.name, Outcome::Failed { why }));
        }

        Ok(taken)
    }

    /// Lower the run's verification to this artifact's, when it was copied.
    ///
    /// Only a copy says anything about verification. An artifact already
    /// present was not fetched, and letting its `NotAttempted` drag the
    /// run's answer down would report a re-run as less verified than the
    /// run that did the work.
    fn note_verification(&self, settled: &Settled, verification: Verification) {
        let copied = settled
            .iter()
            .any(|(_, outcome)| matches!(outcome, Outcome::Copied { .. }));

        if !copied {
            return;
        }

        let mut weakest = self.verification.lock().expect("copy summary poisoned");

        *weakest = upload::weakest(*weakest, verification);
    }
}

/// Whether every destination still owed an artifact took it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Taken {
    ByEvery,
    NotByEvery,
}

/// The outcome a reader of one line should see: the worst any destination
/// got, and of equals, the first in `--to` order.
///
/// ```text
///   failed > refused > copied > already-present
/// ```
fn worst(settled: &Settled) -> Option<Outcome> {
    let rank = |outcome: &Outcome| match outcome {
        Outcome::AlreadyPresent => 0,
        Outcome::Copied { .. } => 1,
        Outcome::Refused { .. } => 2,
        Outcome::Unresolved { .. } => 3,
        Outcome::Failed { .. } => 4,
    };

    let mut found: Option<&Outcome> = None;

    for (_, outcome) in settled {
        if found.is_none_or(|best| rank(outcome) > rank(best)) {
            found = Some(outcome);
        }
    }

    found.cloned()
}

#[async_trait]
impl Visitor for Copying<'_, '_, '_> {
    /// The context is already narrowed to this artifact, so a problem
    /// reported while copying is filed against it and judged under whatever
    /// rule covers it.
    async fn visit(
        &self,
        artifact: &ResolvedArtifact,
        source: &dyn Source,
        ctx: &Ctx,
    ) -> Result<()> {
        let mut settled = Settled::new();

        let legs = self.owed(artifact, &mut settled, ctx).await?;

        // Every target already has it: nothing is fetched.
        if legs.is_empty() {
            return self.wrote(artifact, settled, ctx);
        }

        let recorded = match self.recorded(artifact) {
            Ok(recorded) => recorded,
            Err(err) => {
                self.abandon(&legs, ctx);
                return Err(err);
            }
        };

        let intos: Vec<&ConfiguredTarget> = legs.iter().map(|leg| leg.at.into).collect();

        // The source side, once for every target: a failure here is about
        // the bytes, so it is every destination's failure.
        let fetched =
            match upload::fetch(artifact, source, &intos, &self.cache_dir, &recorded, ctx).await {
                Ok(fetched) => fetched,
                Err(failed) => return self.fail_fetch(artifact, &legs, failed, settled, ctx),
            };

        self.fetched(artifact, &fetched.payloads, None)?;

        if fetched.checked == upload::Checked::Refused {
            return self.refuse_all(artifact, &legs, settled, ctx);
        }

        let taken = self
            .publish_legs(artifact, &fetched, &legs, &mut settled, ctx)
            .await?;

        self.note_verification(&settled, fetched.verification);

        // A destination that did not take it keeps the payload cached, so a
        // retry does not fetch it again.
        if taken == Taken::ByEvery {
            fetched.discard(self.payloads).await;
        }

        self.wrote(artifact, settled, ctx)
    }

    /// Refused before anything was fetched, by a rule about the artifact
    /// itself, so refused for every destination.
    async fn refused(&self, artifact: &ResolvedArtifact, why: &Problem, ctx: &Ctx) -> Result<()> {
        let mut settled = Settled::new();

        for at in &self.destinations {
            at.refused.fetch_add(1, Ordering::SeqCst);

            let why = Box::new(ProblemRecord::from(why));
            settled.push((at.name, Outcome::Refused { why }));
        }

        self.wrote(artifact, settled, ctx)
    }

    async fn unresolved(&self, request: &ArtifactRequest, why: &Problem, ctx: &Ctx) -> Result<()> {
        let provenance = ctx.prov().chain().map(Cause::message).collect();

        self.report
            .write(&Record::Artifact(Box::new(ArtifactRecord::unresolved(
                request, why, provenance,
            ))))
    }

    fn targets(&self) -> Vec<&str> {
        self.destinations.iter().map(|at| at.name).collect()
    }
}

/// Report what a copy did, one message per target, for a caller that logs
/// a summary.
///
/// A run with one target says which only when it has several to tell
/// apart.
pub fn describe(summary: &Summary) -> Vec<crate::core::message::Message> {
    let several = summary.destinations.len() > 1;

    summary
        .destinations
        .iter()
        .map(|tally| match several {
            false => crate::message!(
                "copy-finished",
                "published {published} artifacts, {present} already present, \
                 {refused} refused, {failed} failed, {skipped} unresolved ({verification})",
                published = tally.published,
                present = tally.already_present,
                refused = tally.refused,
                failed = tally.failed,
                skipped = summary.walked.skipped,
                verification = &format!("{:?}", summary.verification),
            ),
            true => crate::message!(
                "copy-finished-at",
                "{target}: published {published} artifacts, {present} already present, \
                 {refused} refused, {failed} failed, {skipped} unresolved ({verification})",
                target = &tally.destination,
                published = tally.published,
                present = tally.already_present,
                refused = tally.refused,
                failed = tally.failed,
                skipped = summary.walked.skipped,
                verification = &format!("{:?}", summary.verification),
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ConfigLoader;
    use crate::commands::spider::{SpiderSetting, SpiderSpec};
    use crate::config::Config;
    use crate::core::progress::Unit;
    use crate::model::Cause;
    use crate::net::{Canned, FixtureClient};
    use crate::report::{Outcome, Record};
    use crate::version::PreRelease;
    use http::StatusCode;
    use std::sync::Arc;

    const ORIGIN: &str = "h://origin.test";
    const MIRROR: &str = "h://mirror.test";

    /// The one target most tests copy into.
    static LOCAL: std::sync::LazyLock<[String; 1]> =
        std::sync::LazyLock::new(|| ["local".to_owned()]);

    /// Keeps every record a copy writes, so a test can assert on the
    /// outcomes rather than only on the counts.
    #[derive(Default)]
    struct Recorded {
        records: Mutex<Vec<Record>>,
    }

    impl ReportWriter for Recorded {
        fn write(&self, record: &Record) -> Result<()> {
            self.records
                .lock()
                .expect("recorded poisoned")
                .push(record.clone());

            Ok(())
        }

        fn artifact_count(&self) -> u64 {
            self.records
                .lock()
                .expect("recorded poisoned")
                .iter()
                .filter(|record| matches!(record, Record::Artifact(_)))
                .count() as u64
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }
    }

    impl Recorded {
        /// Every artifact record, as (purl, outcome).
        fn outcomes(&self) -> Vec<(String, Option<Outcome>)> {
            self.records
                .lock()
                .expect("recorded poisoned")
                .iter()
                .filter_map(|record| match record {
                    Record::Artifact(artifact) => {
                        Some((artifact.purl.clone(), artifact.outcome.clone()))
                    }
                    _ => None,
                })
                .collect()
        }
    }

    const TUNA_TGZ: &[u8] = b"tuna payload";
    const SALMON_TGZ: &[u8] = b"salmon payload";

    /// The sha1 npm publishes as `shasum`, which the copy checks in
    /// flight -- so a fixture has to carry the real one.
    fn sha1_of(bytes: &[u8]) -> String {
        use sha1::Digest as _;

        let mut hasher = sha1::Sha1::new();
        hasher.update(bytes);

        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// npm's `integrity`, which is what makes the source look for a
    /// signature -- without it `check_signatures` returns before reporting
    /// anything, so a rule keyed on `signature-missing` never fires.
    fn integrity_of(bytes: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::Digest as _;

        let mut hasher = sha2::Sha512::new();
        hasher.update(bytes);

        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        )
    }

    /// The same packument, declaring an integrity and no signature.
    fn unsigned(name: &str, payload: &[u8]) -> String {
        format!(
            r#"{{
              "name": "{name}",
              "dist-tags": {{"latest": "1.0.0"}},
              "license": "MIT",
              "versions": {{
                "1.0.0": {{
                  "license": "MIT",
                  "dist": {{
                    "tarball": "{ORIGIN}/{name}/-/{name}-1.0.0.tgz",
                    "shasum": "{shasum}",
                    "integrity": "{integrity}"
                  }},
                  "dependencies": {{}}
                }}
              }}
            }}"#,
            name = name,
            shasum = sha1_of(payload),
            integrity = integrity_of(payload),
        )
    }

    fn packument(name: &str, deps: &str, payload: &[u8]) -> String {
        format!(
            r#"{{
              "name": "{name}",
              "dist-tags": {{"latest": "1.0.0"}},
              "license": "MIT",
              "versions": {{
                "1.0.0": {{
                  "license": "MIT",
                  "dist": {{
                    "tarball": "{ORIGIN}/{name}/-/{name}-1.0.0.tgz",
                    "shasum": "{shasum}"
                  }},
                  "dependencies": {deps}
                }}
              }}
            }}"#,
            name = name,
            deps = deps,
            shasum = sha1_of(payload),
        )
    }

    /// A packument whose tarball declares no digest at all.
    fn undigested(name: &str) -> String {
        format!(
            r#"{{
              "name": "{name}",
              "dist-tags": {{"latest": "1.0.0"}},
              "license": "MIT",
              "versions": {{
                "1.0.0": {{
                  "license": "MIT",
                  "dist": {{"tarball": "{ORIGIN}/{name}/-/{name}-1.0.0.tgz"}},
                  "dependencies": {{}}
                }}
              }}
            }}"#
        )
    }

    fn config(dir: &std::path::Path) -> Config {
        let path = dir.join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"{}"}},
                    "hosts":{{
                      "origin":{{"url":"{ORIGIN}/"}},
                      "mirror":{{"url":"{MIRROR}/"}}
                    }},
                    "sources":{{"upstream":{{"kind":"npm","host":"origin"}}}},
                    "targets":{{"local":{{"kind":"npm","host":"mirror"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    /// A registry holding tuna, which depends on salmon, and a mirror that
    /// holds neither and accepts both.
    fn both_ends() -> FixtureClient {
        FixtureClient::new()
            .with_body(
                format!("{ORIGIN}/tuna"),
                packument("tuna", r#"{"salmon": "^1.0.0"}"#, TUNA_TGZ),
            )
            .with_body(
                format!("{ORIGIN}/salmon"),
                packument("salmon", "{}", SALMON_TGZ),
            )
            .with_body(format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz"), TUNA_TGZ)
            .with_body(format!("{ORIGIN}/salmon/-/salmon-1.0.0.tgz"), SALMON_TGZ)
            .with(
                format!("{MIRROR}/tuna/1.0.0"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with(
                format!("{MIRROR}/salmon/1.0.0"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#)
            .with_body(format!("{MIRROR}/salmon"), r#"{"ok":true}"#)
    }

    async fn copied(
        config: &Config,
        client: FixtureClient,
        artifacts: &[String],
        spider: SpiderSpec,
    ) -> (Arc<FixtureClient>, Result<Summary>) {
        let (shared, summary, _) = recording(config, client, artifacts, spider).await;

        (shared, summary)
    }

    /// The same, keeping the report the copy wrote.
    async fn recording(
        config: &Config,
        client: FixtureClient,
        artifacts: &[String],
        spider: SpiderSpec,
    ) -> (Arc<FixtureClient>, Result<Summary>, Recorded) {
        let shared = Arc::new(client);
        let mut session = Session::over(config, false, shared.clone()).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
        let progress = ctx.progress("copy", Unit::Items, None);

        let request = Request {
            what: inspect::Request {
                source: "upstream",
                artifacts,
                locks: &[],
                spider: SpiderSetting::Explicit(spider),
                pre: PreRelease::Exclude,
                screen: None,
            },
            targets: &LOCAL[..],
            from: From::Requested,
        };

        let report = Recorded::default();
        let summary = run(&mut session, &request, &report, &progress, &ctx).await;

        (shared, summary, report)
    }

    /// The whole command in one test: a named artifact is resolved from the
    /// source, its payload fetched, and published to the target.
    #[tokio::test]
    async fn requested_artifact_copied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let wanted = vec!["tuna".to_owned()];
        let (client, summary) = copied(&config, both_ends(), &wanted, SpiderSpec::none()).await;

        let summary = summary.expect("copied");

        assert_eq!(summary.destinations[0].published, 1);
        assert_eq!(summary.destinations[0].already_present, 0);

        let sent = client.sent_to(&format!("{MIRROR}/tuna"));
        assert_eq!(sent.len(), 1, "expected exactly one publish");

        // Nothing was published to the dependency, which was not asked for.
        assert!(client.sent_to(&format!("{MIRROR}/salmon")).is_empty());
    }

    /// `--dependencies` reaches the copy the same way it reaches a
    /// inspection, because the two share the walk rather than repeating it.
    /// The origin's version document is what the target is sent, so the
    /// mirror serves tuna's dependencies; the origin's `_npmUser` is not.
    #[tokio::test]
    async fn origin_manifest_published() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let version = serde_json::json!({
            "name": "tuna",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": { "salmon": "^1.0.0" },
            "engines": { "node": ">=18" },
            "_npmUser": { "name": "origin" },
            "dist": {
                "tarball": format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz"),
                "shasum": sha1_of(TUNA_TGZ),
            },
        });
        let client = both_ends().with_body(format!("{ORIGIN}/tuna/1.0.0"), version.to_string());

        let wanted = vec!["tuna".to_owned()];
        let (client, summary) = copied(&config, client, &wanted, SpiderSpec::none()).await;

        summary.expect("copied");

        let sent = client.sent_to(&format!("{MIRROR}/tuna"));
        let document: serde_json::Value =
            serde_json::from_slice(&sent[0]).expect("a JSON publish document");
        let published = &document["versions"]["1.0.0"];

        assert_eq!(published["dependencies"]["salmon"], "^1.0.0");
        assert_eq!(published["engines"]["node"], ">=18");
        assert!(published.get("_npmUser").is_none());
        assert_eq!(
            published["dist"]["tarball"],
            format!("{MIRROR}/tuna/-/tuna-1.0.0.tgz")
        );
    }

    #[tokio::test]
    async fn dependencies_copied_when_asked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let wanted = vec!["tuna".to_owned()];
        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let (client, summary) = copied(&config, both_ends(), &wanted, runtime).await;

        assert_eq!(summary.expect("copied").destinations[0].published, 2);
        assert_eq!(client.sent_to(&format!("{MIRROR}/salmon")).len(), 1);
    }

    /// An upload that aborts the run closes its claim first, as `failed`,
    /// so the next run over the same report does not meet it still open.
    #[tokio::test]
    async fn abort_closes_claim() {
        use crate::report::{Binding, ReportWriter, Role, header};

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let report_path = dir.path().join("report.sqlite");

        // Bytes that do not match the published shasum: a checksum
        // mismatch, which aborts.
        let client =
            Arc::new(both_ends().with_body(format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz"), "corrupt"));

        let mut session = Session::over(&config, false, client.clone()).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
        let progress = ctx.progress("copy", Unit::Items, None);

        let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
            .await
            .expect("opens");
        let report = Arc::new(crate::commands::report::ToReport::new(writer));

        report
            .write(&Record::Header(header(
                "copy",
                &crate::advisory::Screening::none(),
            )))
            .expect("header");

        let state = report.state().expect("state");
        state
            .bind(&Binding::new(Role::Source, "upstream"))
            .expect("bound");
        state
            .bind(&Binding::new(Role::Target, "local"))
            .expect("bound");

        let wanted = vec!["tuna".to_owned()];
        let request = Request {
            what: inspect::Request {
                source: "upstream",
                artifacts: &wanted,
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            },
            targets: &LOCAL[..],
            from: From::Requested,
        };

        let summary = run(&mut session, &request, report.as_ref(), &progress, &ctx).await;

        report.flush().expect("flushed");

        assert!(summary.is_err(), "a checksum mismatch aborts the run");

        let conn = rusqlite::Connection::open(&report_path).expect("opens");
        let states: Vec<String> = conn
            .prepare("SELECT state FROM artifact_transfer_attempt")
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        assert_eq!(states, ["failed"]);
    }

    /// A version the target already holds is counted apart from one copied,
    /// because a re-run over a mostly-copied repository is the ordinary
    /// case and "0 published" alone cannot be told from doing nothing.
    #[tokio::test]
    async fn already_present_counted_separately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = both_ends().with_body(
            format!("{MIRROR}/tuna/1.0.0"),
            r#"{"name":"tuna","version":"1.0.0"}"#,
        );

        let wanted = vec!["tuna".to_owned()];
        let (client, summary) = copied(&config, client, &wanted, SpiderSpec::none()).await;
        let summary = summary.expect("copied");

        assert_eq!(summary.destinations[0].published, 0);
        assert_eq!(summary.destinations[0].already_present, 1);
        assert!(client.sent_to(&format!("{MIRROR}/tuna")).is_empty());
    }

    /// **The migration this whole format exists for**: `inspect` into a
    /// database, then copy what it says is left, in separate runs.
    ///
    /// The second run never asks the source for metadata -- the inventory
    /// already holds the files -- and a third run finds nothing to do.
    #[tokio::test]
    async fn record_through_report_database() {
        use crate::commands::inspect as inspection;
        use crate::report::{Binding, ReportWriter, Role, header};

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let report_path = dir.path().join("report.sqlite");

        // An inspection run, filling the inventory.
        {
            let shared = Arc::new(both_ends());
            let mut session = Session::over(&config, false, shared.clone()).expect("opens");
            let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
            let progress = ctx.progress("inspect", Unit::Items, None);

            let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
                .await
                .expect("opens");
            let visitor = Arc::new(crate::commands::report::ToReport::new(writer));

            visitor
                .write(&Record::Header(header(
                    "inspect",
                    &crate::advisory::Screening::none(),
                )))
                .expect("header");
            visitor
                .state()
                .expect("state")
                .bind(&Binding::new(Role::Source, "upstream").observing())
                .expect("bound");

            let wanted = vec!["tuna".to_owned()];

            inspection::run(
                &mut session,
                &inspection::Request {
                    source: "upstream",
                    artifacts: &wanted,
                    locks: &[],
                    spider: SpiderSetting::Explicit(SpiderSpec::none()),
                    pre: PreRelease::Exclude,
                    screen: None,
                },
                None,
                None,
                visitor.as_ref(),
                &progress,
                &ctx,
            )
            .await
            .expect("discovered");

            visitor.flush().expect("flushed");
        }

        // The copy, driven by the report rather than by an argument.
        let from_report = async |config: &crate::config::Config| {
            let shared = Arc::new(both_ends());
            let mut session = Session::over(config, false, shared.clone()).expect("opens");
            let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
            let progress = ctx.progress("copy", Unit::Items, None);

            let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
                .await
                .expect("opens");
            let report = Arc::new(crate::commands::report::ToReport::new(writer));

            report
                .write(&Record::Header(header(
                    "copy",
                    &crate::advisory::Screening::none(),
                )))
                .expect("header");
            report
                .state()
                .expect("state")
                .bind(&Binding::new(Role::Target, "local"))
                .expect("bound");

            let manifest = report_path.display().to_string();
            let no_artifacts: Vec<String> = Vec::new();

            let summary = run(
                &mut session,
                &Request {
                    what: inspect::Request {
                        source: "upstream",
                        artifacts: &no_artifacts,
                        locks: &[],
                        spider: SpiderSetting::Explicit(SpiderSpec::none()),
                        pre: PreRelease::Exclude,
                        screen: None,
                    },
                    targets: &LOCAL[..],
                    from: From::Report {
                        manifest: &manifest,
                    },
                },
                report.as_ref(),
                &progress,
                &ctx,
            )
            .await;

            report.flush().expect("flushed");

            (shared, summary)
        };

        let (shared, summary) = from_report(&config).await;
        let summary = summary.expect("copied");

        assert_eq!(summary.destinations[0].published, 1);

        // The inventory held the files, so the packument was never fetched
        // again. That is the whole reason the source is wrapped.
        assert_eq!(
            shared.hits(&format!("{ORIGIN}/tuna")),
            0,
            "the source was asked for metadata the report already held"
        );

        // A second copy has nothing left: the transfer is terminal.
        let (_shared, summary) = from_report(&config).await;

        assert!(
            summary.is_err(),
            "a copy with nothing outstanding should refuse rather than report an empty run"
        );
    }

    /// Copy `tuna` from `upstream` into `local` over `client`, recording
    /// into a report database, and open that database.
    async fn copied_into_db(client: FixtureClient) -> (tempfile::TempDir, rusqlite::Connection) {
        use crate::report::{Binding, ReportWriter, Role, header};

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let report_path = dir.path().join("report.sqlite");

        {
            let mut session = Session::over(&config, false, Arc::new(client)).expect("opens");
            let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
            let progress = ctx.progress("copy", Unit::Items, None);

            let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
                .await
                .expect("opens");
            let report = Arc::new(crate::commands::report::ToReport::new(writer));

            report
                .write(&Record::Header(header(
                    "copy",
                    &crate::advisory::Screening::none(),
                )))
                .expect("header");

            for binding in [
                Binding::new(Role::Source, "upstream").observing(),
                Binding::new(Role::Target, "local"),
            ] {
                report
                    .state()
                    .expect("state")
                    .bind(&binding)
                    .expect("bound");
            }

            let wanted = vec!["tuna".to_owned()];

            run(
                &mut session,
                &Request {
                    what: inspect::Request {
                        source: "upstream",
                        artifacts: &wanted,
                        locks: &[],
                        spider: SpiderSetting::Explicit(SpiderSpec::none()),
                        pre: PreRelease::Exclude,
                        screen: None,
                    },
                    targets: &LOCAL[..],
                    from: From::Requested,
                },
                report.as_ref(),
                &progress,
                &ctx,
            )
            .await
            .expect("ran");

            report.flush().expect("flushed");
        }

        let conn = rusqlite::Connection::open(&report_path).expect("opens");

        (dir, conn)
    }

    /// A copy writes down where each payload's bytes are, so a later run
    /// can reuse the download instead of fetching it again.
    #[tokio::test]
    async fn record_payload_cache_location() {
        let (_dir, conn) = copied_into_db(both_ends()).await;

        let (host, relative, verification): (String, String, String) = conn
            .query_row(
                "SELECT host, relative_path, verification FROM cache_entry",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("a cache entry");

        assert!(!host.is_empty(), "the cache entry named no host");
        assert!(relative.ends_with(".tgz"), "{relative}");
        // The npm fixture declares a sha1, which is a check but not a
        // collision-resistant one -- and the report says so rather than
        // rounding it up.
        assert_eq!(verification, "weak-digest-only");

        // The file points at the entry, so a later run finds the bytes from
        // the inventory rather than by guessing a path.
        let linked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM repository_file WHERE cache_entry_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .expect("counted");

        assert_eq!(linked, 1);

        // The cache's own times travel with the entry. Nothing configured a
        // limit here, so both stay forever.
        let (downloaded, used, retain, fresh): (i64, i64, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT downloaded_ms, used_ms, retain_until_ms, fresh_until_ms FROM cache_entry",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("times");

        assert!(downloaded > 0 && used >= downloaded, "{downloaded} {used}");
        assert_eq!((retain, fresh), (None, None));

        // And the fetch itself is recorded as finished work.
        let state: String = conn
            .query_row(
                "SELECT state FROM file_transfer WHERE direction = 'download'",
                [],
                |row| row.get(0),
            )
            .expect("a transfer");

        assert_eq!(state, "downloaded");

        let (side, stage): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT a.error_side, a.error_stage
                 FROM file_transfer_attempt a
                 JOIN file_transfer t ON t.file_transfer_id = a.file_transfer_id
                 WHERE t.direction = 'download'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("an attempt");

        assert!(side.is_none(), "a successful fetch blamed somebody");
        assert!(stage.is_none());

        // The publish is recorded per file, at the target, and filed under
        // the artifact's own attempt.
        let (state, destination, linked): (String, String, Option<i64>) = conn
            .query_row(
                "SELECT t.state, r.name, a.artifact_transfer_attempt_id
                 FROM file_transfer t
                 JOIN repository r ON r.repository_id = t.destination_repository_id
                 JOIN file_transfer_attempt a ON a.file_transfer_id = t.file_transfer_id
                 WHERE t.direction = 'upload'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("an upload");

        assert_eq!(state, "uploaded");
        assert_eq!(destination, "local");
        assert!(
            linked.is_some(),
            "the upload was not filed under its artifact"
        );
    }

    /// A target refusing the publish records the file it was sending as a
    /// failed upload, blamed on the target.
    #[tokio::test]
    async fn record_refused_publish_as_failed_upload() {
        let client = both_ends().with(
            format!("{MIRROR}/tuna"),
            Canned::status(StatusCode::INTERNAL_SERVER_ERROR),
        );
        let (_dir, conn) = copied_into_db(client).await;

        let (state, side, stage): (String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT t.state, a.error_side, a.error_stage
                 FROM file_transfer t
                 JOIN file_transfer_attempt a ON a.file_transfer_id = t.file_transfer_id
                 WHERE t.direction = 'upload'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("an upload");

        assert_eq!(state, "failed");
        assert_eq!(side.as_deref(), Some("target"));
        assert_eq!(stage.as_deref(), Some("request"));
    }

    /// **What asking rather than looking buys.** A target that already
    /// holds a version is asked once; the answer is written down, and the
    /// next run reads it instead of spending a request per artifact.
    #[tokio::test]
    async fn record_target_contents_reused() {
        use crate::report::{Binding, ReportWriter, Role, header};

        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let report_path = dir.path().join("report.sqlite");

        // The target already holds it, so the copy has nothing to send.
        //
        // Built rather than derived from `both_ends`, which registers a 404
        // for this version and would win over a body added after it.
        let present = || {
            FixtureClient::new()
                .with_body(
                    format!("{ORIGIN}/tuna"),
                    packument("tuna", r#"{"salmon": "^1.0.0"}"#, TUNA_TGZ),
                )
                .with_body(format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz"), TUNA_TGZ)
                .with_body(
                    format!("{MIRROR}/tuna/1.0.0"),
                    r#"{"name":"tuna","version":"1.0.0"}"#,
                )
                .with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#)
        };

        let copied_once = async |config: &crate::config::Config| {
            let shared = Arc::new(present());
            let mut session = Session::over(config, false, shared.clone()).expect("opens");
            let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
            let progress = ctx.progress("copy", Unit::Items, None);

            let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
                .await
                .expect("opens");
            let report = Arc::new(crate::commands::report::ToReport::new(writer));

            report
                .write(&Record::Header(header(
                    "copy",
                    &crate::advisory::Screening::none(),
                )))
                .expect("header");

            for binding in [
                Binding::new(Role::Source, "upstream").observing(),
                Binding::new(Role::Target, "local"),
            ] {
                report
                    .state()
                    .expect("state")
                    .bind(&binding)
                    .expect("bound");
            }

            let wanted = vec!["tuna".to_owned()];

            let summary = run(
                &mut session,
                &Request {
                    what: inspect::Request {
                        source: "upstream",
                        artifacts: &wanted,
                        locks: &[],
                        spider: SpiderSetting::Explicit(SpiderSpec::none()),
                        pre: PreRelease::Exclude,
                        screen: None,
                    },
                    targets: &LOCAL[..],
                    from: From::Requested,
                },
                report.as_ref(),
                &progress,
                &ctx,
            )
            .await;

            report.flush().expect("flushed");

            (shared, summary)
        };

        let (first, summary) = copied_once(&config).await;

        assert_eq!(summary.expect("copied").destinations[0].already_present, 1);

        // The first run had to ask the repository.
        assert_eq!(first.hits(&format!("{MIRROR}/tuna/1.0.0")), 1);

        // And wrote the answer down as the target's contents.
        let conn = rusqlite::Connection::open(&report_path).expect("opens");
        let held: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM repository_artifact ra
                 JOIN repository r ON r.repository_id = ra.repository_id
                 WHERE r.role = 'target' AND r.name = 'local'",
                [],
                |row| row.get(0),
            )
            .expect("counted");

        assert_eq!(held, 1, "the target's contents were not recorded");
        drop(conn);

        let (second, summary) = copied_once(&config).await;

        // The artifact reached the target in the first run, so this one is
        // stopped by the claim before it asks anything at all.
        summary.expect("copied");
        assert_eq!(
            second.hits(&format!("{MIRROR}/tuna/1.0.0")),
            0,
            "the target was asked again for what the report already said"
        );
    }

    /// A report that cannot be queried cannot say what is left, and saying
    /// so once beats failing part way through a walk.
    #[tokio::test]
    async fn from_line_report_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let mut session = Session::over(&config, false, Arc::new(both_ends())).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
        let progress = ctx.progress("copy", Unit::Items, None);

        let no_artifacts: Vec<String> = Vec::new();
        let request = Request {
            what: inspect::Request {
                source: "upstream",
                artifacts: &no_artifacts,
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            },
            targets: &LOCAL[..],
            from: From::Report {
                manifest: "report.jsonl",
            },
        };

        let report = Recorded::default();
        let err = run(&mut session, &request, &report, &progress, &ctx)
            .await
            .expect_err("refused");

        assert!(err.to_string().contains("--db=FILE"), "{err}");
    }

    /// A misconfigured target fails before anything is fetched, rather than
    /// after the first artifact has been pulled across the network.
    #[tokio::test]
    async fn failure_unknown_target_before_fetch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let shared = Arc::new(both_ends());
        let mut session = Session::over(&config, false, shared.clone()).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
        let progress = ctx.progress("copy", Unit::Items, None);

        let wanted = vec!["tuna".to_owned()];
        let request = Request {
            what: inspect::Request {
                source: "upstream",
                artifacts: &wanted,
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            },
            targets: &["nope".to_owned()],
            from: From::Requested,
        };

        let report = Recorded::default();

        assert!(
            run(&mut session, &request, &report, &progress, &ctx)
                .await
                .is_err()
        );
        assert_eq!(
            shared.hits(&format!("{ORIGIN}/tuna")),
            0,
            "the source was consulted before the target was checked"
        );
    }

    /// An artifact already present was never fetched, so it says nothing
    /// about verification -- letting its `NotAttempted` count would report a
    /// re-run as less verified than the run that did the work.
    #[tokio::test]
    async fn already_present_keeps_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = both_ends().with_body(
            format!("{MIRROR}/salmon/1.0.0"),
            r#"{"name":"salmon","version":"1.0.0"}"#,
        );

        let wanted = vec!["tuna".to_owned()];
        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let (_client, summary) = copied(&config, client, &wanted, runtime).await;
        let summary = summary.expect("copied");

        assert_eq!(summary.destinations[0].published, 1);
        assert_eq!(summary.destinations[0].already_present, 1);

        // npm declares a sha1 `shasum`, which is a weak digest -- not
        // `NotAttempted`, which is what the skipped one would have given.
        assert_ne!(summary.verification, Verification::NotAttempted);
    }

    // -- The report a copy writes ------------------------------------------

    /// The point of the report: one line per artifact reached, each saying
    /// what became of it. A reader auditing the run should not have to
    /// infer anything from counts.
    #[tokio::test]
    async fn every_artifact_reached_gets_a_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let wanted = vec!["tuna".to_owned()];

        let (_, summary, report) = recording(&config, both_ends(), &wanted, runtime).await;

        summary.expect("copied");

        let mut outcomes = report.outcomes();
        outcomes.sort_by(|left, right| left.0.cmp(&right.0));

        let [salmon, tuna] = outcomes.as_slice() else {
            panic!("expected two artifacts, got {outcomes:?}");
        };

        assert_eq!(salmon.0, "pkg:npm/salmon");
        assert_eq!(tuna.0, "pkg:npm/tuna");

        for (purl, outcome) in [salmon, tuna] {
            assert!(
                matches!(outcome, Some(Outcome::Copied { .. })),
                "{purl}: {outcome:?}"
            );
        }
    }

    /// Distinguished from "copied", because a re-run over a mostly-copied
    /// repository is the ordinary case and the two answers mean different
    /// things to somebody reading the report.
    #[tokio::test]
    async fn already_present_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = both_ends().with_body(
            format!("{MIRROR}/tuna/1.0.0"),
            r#"{"name":"tuna","version":"1.0.0"}"#,
        );

        let wanted = vec!["tuna".to_owned()];
        let (_, summary, report) = recording(&config, client, &wanted, SpiderSpec::none()).await;

        assert_eq!(summary.expect("ran").destinations[0].already_present, 1);

        let outcomes = report.outcomes();
        let [(purl, outcome)] = outcomes.as_slice() else {
            panic!("expected one artifact, got {outcomes:?}");
        };

        assert_eq!(purl, "pkg:npm/tuna");
        assert!(
            matches!(outcome, Some(Outcome::AlreadyPresent)),
            "{outcome:?}"
        );
    }

    /// A request that matched nothing still gets a line. It is the case a
    /// user most often goes to the report to explain, and after the run the
    /// request itself is gone.
    #[tokio::test]
    async fn request_resolving_to_nothing_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        let client = both_ends().with(
            format!("{ORIGIN}/herring"),
            Canned::status(StatusCode::NOT_FOUND),
        );

        let wanted = vec!["herring".to_owned()];
        let (_, summary, report) = recording(&config, client, &wanted, SpiderSpec::none()).await;

        assert_eq!(summary.expect("ran").destinations[0].published, 0);

        let outcomes = report.outcomes();
        let [(purl, outcome)] = outcomes.as_slice() else {
            panic!("expected one artifact, got {outcomes:?}");
        };

        assert_eq!(purl, "pkg:npm/herring");
        assert!(
            matches!(outcome, Some(Outcome::Unresolved { .. })),
            "{outcome:?}"
        );
    }

    /// One target refusing a publish must not discard the run and the
    /// report with it. The failure becomes that artifact's line and the
    /// walk carries on.
    #[tokio::test]
    async fn failure_upload_does_not_end_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());

        // The mirror accepts salmon and rejects tuna.
        let client = both_ends().with(
            format!("{MIRROR}/tuna"),
            Canned::status(StatusCode::INTERNAL_SERVER_ERROR),
        );

        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let wanted = vec!["tuna".to_owned()];

        let (_, summary, report) = recording(&config, client, &wanted, runtime).await;

        let summary = summary.expect("the run still finished");

        assert_eq!(summary.destinations[0].published, 1, "salmon still went");
        assert_eq!(summary.destinations[0].failed, 1, "tuna did not");

        let mut outcomes = report.outcomes();
        outcomes.sort_by(|left, right| left.0.cmp(&right.0));

        let [salmon, tuna] = outcomes.as_slice() else {
            panic!("expected two artifacts, got {outcomes:?}");
        };

        assert!(
            matches!(salmon.1, Some(Outcome::Copied { .. })),
            "{salmon:?}"
        );
        assert!(matches!(tuna.1, Some(Outcome::Failed { .. })), "{tuna:?}");
    }

    /// A file the source will not serve is named in the problem's text,
    /// and its URL kept in the arguments for whoever investigates.
    #[tokio::test]
    async fn failure_missing_file_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let tarball = format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz");
        let client = both_ends().with(&tarball, Canned::status(StatusCode::NOT_FOUND));

        let wanted = vec!["tuna".to_owned()];
        let (_, _, report) = recording(&config, client, &wanted, SpiderSpec::none()).await;

        let outcomes = report.outcomes();
        let [(_, Some(Outcome::Failed { why }))] = outcomes.as_slice() else {
            panic!("expected one failed artifact, got {outcomes:?}");
        };

        let message = &why.message;

        assert_eq!(why.code, crate::core::problem::Code::ArtifactNotFound);
        assert_eq!(
            message.args.get("file").map(String::as_str),
            Some("tuna-1.0.0.tgz")
        );
        assert_eq!(message.args.get("url"), Some(&tarball));
        assert_eq!(
            message.text.as_deref(),
            Some("tuna-1.0.0.tgz: responded 404")
        );
    }

    /// A rule that refuses an artifact must actually stop the upload, not
    /// merely annotate it -- and the report has to say which artifact was
    /// refused and why, so the refusal can be reviewed or overridden.
    #[tokio::test]
    async fn refusal_before_fetch_reported_not_uploaded() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("quarantine.yaml"),
            format!(
                "$schema: {}\nrules:\n  - purl: \"pkg:npm/tuna\"\n    \
                 codes: [signature-missing]\n    class: hard\n    \
                 justification: \"unsigned, and we mind\"\n    expires: never\n",
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "setup":{{"cache-dir":"{}","quarantine-policy":"quarantine.yaml"}},
                    "hosts":{{
                      "origin":{{"url":"{ORIGIN}/"}},
                      "mirror":{{"url":"{MIRROR}/"}}
                    }},
                    "sources":{{"upstream":{{"kind":"npm","host":"origin"}}}},
                    "targets":{{"local":{{"kind":"npm","host":"mirror"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.path().join("scratch").display(),
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        // Unsigned, so the source reports `signature-missing` while
        // resolving -- which is the code the rule above refuses on.
        let client = both_ends().with_body(format!("{ORIGIN}/tuna"), unsigned("tuna", TUNA_TGZ));

        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let wanted = vec!["tuna".to_owned()];

        let (client, summary, report) = recording(&config, client, &wanted, runtime).await;

        let summary = summary.expect("the run still finished");

        assert_eq!(summary.destinations[0].refused, 1);
        assert_eq!(
            summary.destinations[0].published, 0,
            "and the refusal pruned its subtree"
        );

        assert_eq!(
            client.hits(&format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz")),
            0,
            "a refused artifact is not even fetched"
        );

        let outcomes = report.outcomes();
        let [(purl, outcome)] = outcomes.as_slice() else {
            panic!("expected one artifact, got {outcomes:?}");
        };

        assert_eq!(purl, "pkg:npm/tuna");

        let Some(Outcome::Refused { why }) = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };

        assert_eq!(why.code, crate::core::problem::Code::SignatureMissing);
    }

    /// A refusal raised by checking the staged files is fetched, refused at
    /// every target, and not published.
    #[tokio::test]
    async fn refusal_after_fetch_not_published() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("quarantine.yaml"),
            format!(
                "$schema: {}\nrules:\n  - purl: \"pkg:npm/tuna\"\n    \
                 codes: [signature-missing]\n    class: hard\n    \
                 justification: \"undigested, and we mind\"\n    expires: never\n",
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "setup":{{"cache-dir":"{}","quarantine-policy":"quarantine.yaml"}},
                    "hosts":{{
                      "origin":{{"url":"{ORIGIN}/"}},
                      "mirror":{{"url":"{MIRROR}/"}}
                    }},
                    "sources":{{"upstream":{{"kind":"npm","host":"origin"}}}},
                    "targets":{{"local":{{"kind":"npm","host":"mirror"}}}}}}"#,
                crate::cli::config_schema_id(),
                dir.path().join("scratch").display(),
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let client = both_ends().with_body(format!("{ORIGIN}/tuna"), undigested("tuna"));

        let runtime = SpiderSpec::parse("runtime").expect("parses");
        let wanted = vec!["tuna".to_owned()];

        let (client, summary, report) = recording(&config, client, &wanted, runtime).await;

        let summary = summary.expect("the run still finished");

        assert_eq!(summary.destinations[0].refused, 1);
        assert_eq!(summary.destinations[0].published, 0);
        assert_eq!(
            client.hits(&format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz")),
            1,
            "refused after the fetch"
        );
        assert_eq!(
            client.hits(&format!("{MIRROR}/tuna")),
            0,
            "and not published"
        );

        let outcomes = report.outcomes();
        let [(_, Some(Outcome::Refused { why }))] = outcomes.as_slice() else {
            panic!("expected one refusal, got {outcomes:?}");
        };

        assert_eq!(why.code, crate::core::problem::Code::SignatureMissing);
    }

    // -- Several targets ----------------------------------------------------

    const SPARE: &str = "h://spare.test";

    /// Two targets, in the order each artifact is published to them.
    static BOTH: std::sync::LazyLock<[String; 2]> =
        std::sync::LazyLock::new(|| ["local".to_owned(), "backup".to_owned()]);

    /// `config`, with a second target on its own host.
    fn two_config(dir: &std::path::Path, payloads: crate::config::Payloads) -> Config {
        let path = dir.join("config.json");
        let payloads = serde_json::to_string(&payloads).expect("serializes");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"{}","cache-payloads":{payloads}}},
                    "hosts":{{
                      "origin":{{"url":"{ORIGIN}/"}},
                      "mirror":{{"url":"{MIRROR}/"}},
                      "spare":{{"url":"{SPARE}/"}}
                    }},
                    "sources":{{"upstream":{{"kind":"npm","host":"origin"}}}},
                    "targets":{{
                      "local":{{"kind":"npm","host":"mirror"}},
                      "backup":{{"kind":"npm","host":"spare"}}
                    }}}}"#,
                crate::cli::config_schema_id(),
                dir.join("scratch").display(),
            ),
        )
        .expect("written");

        ConfigLoader::new().add_path(&path).load().expect("loads")
    }

    /// `both_ends`, with a second mirror that holds nothing and accepts
    /// tuna.
    fn three_ends() -> FixtureClient {
        both_ends()
            .with(
                format!("{SPARE}/tuna/1.0.0"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with_body(format!("{SPARE}/tuna"), r#"{"ok":true}"#)
    }

    /// Where the cache keeps tuna's payload under `dir`.
    fn tuna_cached(dir: &std::path::Path) -> std::path::PathBuf {
        let cache = crate::ext::Cache::open(dir.join("scratch").join("origin")).expect("opens");
        let url = format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz");

        cache.resolve(&cache.payload_path(&url, "tuna-1.0.0.tgz").expect("path"))
    }

    /// Copy tuna to both targets, keeping the records.
    async fn fanned(
        config: &Config,
        client: FixtureClient,
    ) -> (Arc<FixtureClient>, Result<Summary>, Recorded) {
        let shared = Arc::new(client);
        let mut session = Session::over(config, false, shared.clone()).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
        let progress = ctx.progress("copy", Unit::Items, None);

        let wanted = vec!["tuna".to_owned()];
        let request = Request {
            what: inspect::Request {
                source: "upstream",
                artifacts: &wanted,
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            },
            targets: &BOTH[..],
            from: From::Requested,
        };

        let report = Recorded::default();
        let summary = run(&mut session, &request, &report, &progress, &ctx).await;

        (shared, summary, report)
    }

    /// Copy tuna to both targets, recording into a report database, and
    /// read back each claim's state, in `--to` order.
    async fn fanned_states(
        config: &Config,
        client: FixtureClient,
    ) -> (Result<Summary>, Vec<String>) {
        use crate::report::{Binding, ReportWriter, Role, header};

        let dir = tempfile::tempdir().expect("tempdir");
        let report_path = dir.path().join("report.sqlite");

        let mut session = Session::over(config, false, Arc::new(client)).expect("opens");
        let ctx = Ctx::for_test(Cause::Requested { arg: "tuna".into() });
        let progress = ctx.progress("copy", Unit::Items, None);

        let writer = crate::report::open(None, Some(&crate::report::DbSpec::new(&report_path)))
            .await
            .expect("opens");
        let report = Arc::new(crate::commands::report::ToReport::new(writer));

        report
            .write(&Record::Header(header(
                "copy",
                &crate::advisory::Screening::none(),
            )))
            .expect("header");

        let state = report.state().expect("state");
        state
            .bind(&Binding::new(Role::Source, "upstream").observing())
            .expect("bound");

        for target in BOTH.iter() {
            state
                .bind(&Binding::new(Role::Target, target))
                .expect("bound");
        }

        let wanted = vec!["tuna".to_owned()];
        let request = Request {
            what: inspect::Request {
                source: "upstream",
                artifacts: &wanted,
                locks: &[],
                spider: SpiderSetting::Explicit(SpiderSpec::none()),
                pre: PreRelease::Exclude,
                screen: None,
            },
            targets: &BOTH[..],
            from: From::Requested,
        };

        let summary = run(&mut session, &request, report.as_ref(), &progress, &ctx).await;

        report.flush().expect("flushed");

        let conn = rusqlite::Connection::open(&report_path).expect("opens");
        let states: Vec<String> = conn
            .prepare(
                "SELECT t.state FROM artifact_transfer t
                 JOIN repository r ON r.repository_id = t.destination_repository_id
                 ORDER BY r.name DESC",
            )
            .expect("prepared")
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<std::result::Result<_, _>>()
            .expect("read");

        (summary, states)
    }

    /// Each target gets the artifact, and the source is asked for it once.
    #[tokio::test]
    async fn two_targets_both_copied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Reuse);

        let (client, summary, report) = fanned(&config, three_ends()).await;
        let summary = summary.expect("copied");

        let published: Vec<u64> = summary.destinations.iter().map(|at| at.published).collect();
        assert_eq!(published, [1, 1]);

        assert_eq!(client.sent_to(&format!("{MIRROR}/tuna")).len(), 1);
        assert_eq!(client.sent_to(&format!("{SPARE}/tuna")).len(), 1);
        assert_eq!(client.hits(&format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz")), 1);

        let outcomes = report.outcomes();
        assert!(
            matches!(outcomes.as_slice(), [(_, Some(Outcome::Copied { .. }))]),
            "{outcomes:?}"
        );
    }

    /// A target whose `omit` leaves the artifact out refuses it before
    /// anything is sent, as a decision rather than a failure; the other
    /// target still gets it.
    #[tokio::test]
    async fn two_targets_one_omits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = two_config(dir.path(), crate::config::Payloads::Reuse);

        config.targets.get_mut("backup").expect("backup").omit = vec![crate::config::OmitRule {
            purl: Some("pkg:npm/tuna*".to_owned()),
            files: None,
        }];

        let (client, summary, _) = fanned(&config, three_ends()).await;
        let summary = summary.expect("copied");

        assert_eq!(summary.destinations[0].published, 1);
        assert_eq!(summary.destinations[1].published, 0);
        assert_eq!(summary.destinations[1].failed, 0);
        assert!(client.sent_to(&format!("{SPARE}/tuna")).is_empty());

        let (_, states) = fanned_states(&config, three_ends()).await;

        assert_eq!(states, ["copied", "refused"]);
    }

    /// A target that already holds the artifact is skipped; the other still
    /// gets it.
    #[tokio::test]
    async fn two_targets_one_already_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Reuse);

        let client = three_ends().with_body(
            format!("{SPARE}/tuna/1.0.0"),
            r#"{"name":"tuna","version":"1.0.0"}"#,
        );

        let (client, summary, _) = fanned(&config, client).await;
        let summary = summary.expect("copied");

        assert_eq!(summary.destinations[0].published, 1);
        assert_eq!(summary.destinations[1].already_present, 1);
        assert!(client.sent_to(&format!("{SPARE}/tuna")).is_empty());
    }

    /// One target failing leaves the other to publish, and the artifact's
    /// line says the worst of the two.
    #[tokio::test]
    async fn two_targets_one_failing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Reuse);

        let client = three_ends().with(
            format!("{MIRROR}/tuna"),
            Canned::status(StatusCode::INTERNAL_SERVER_ERROR),
        );

        let (client, summary, report) = fanned(&config, client).await;
        let summary = summary.expect("the run still finished");

        assert_eq!(summary.destinations[0].failed, 1);
        assert_eq!(summary.destinations[1].published, 1);
        assert_eq!(client.sent_to(&format!("{SPARE}/tuna")).len(), 1);

        let outcomes = report.outcomes();
        assert!(
            matches!(outcomes.as_slice(), [(_, Some(Outcome::Failed { .. }))]),
            "{outcomes:?}"
        );
    }

    /// A target refusing the publish closes only its own claim.
    #[tokio::test]
    async fn two_targets_one_refusing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Reuse);

        let client = three_ends().with(
            format!("{SPARE}/tuna"),
            Canned::status(StatusCode::BAD_REQUEST),
        );

        let (summary, states) = fanned_states(&config, client).await;
        let summary = summary.expect("the run still finished");

        assert_eq!(summary.destinations[0].published, 1);
        assert_eq!(summary.destinations[1].failed, 1);
        assert_eq!(states, ["copied", "failed"]);
    }

    /// An abort closes every claim the artifact holds, not only the first.
    #[tokio::test]
    async fn two_targets_abort_closes_both() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Reuse);

        // Bytes that do not match the published shasum, which aborts.
        let client = three_ends().with_body(format!("{ORIGIN}/tuna/-/tuna-1.0.0.tgz"), "corrupt");

        let (summary, states) = fanned_states(&config, client).await;

        assert!(summary.is_err(), "a checksum mismatch aborts the run");
        assert_eq!(states, ["failed", "failed"]);
    }

    /// Under `discard`, a payload one target did not take stays cached, so
    /// a retry does not fetch it again.
    #[tokio::test]
    async fn two_targets_keep_payload_when_one_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Discard);

        let client = three_ends().with(
            format!("{SPARE}/tuna"),
            Canned::status(StatusCode::INTERNAL_SERVER_ERROR),
        );

        let (_, summary, _) = fanned(&config, client).await;
        summary.expect("the run still finished");

        assert!(
            tuna_cached(dir.path()).exists(),
            "the payload was discarded"
        );
    }

    /// Under `discard`, a payload every target took is removed.
    #[tokio::test]
    async fn two_targets_discard_after_both() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = two_config(dir.path(), crate::config::Payloads::Discard);

        let (_, summary, _) = fanned(&config, three_ends()).await;
        summary.expect("copied");

        assert!(!tuna_cached(dir.path()).exists(), "the payload was kept");
    }

    /// One target's summary line reads as it always has; several name
    /// their target.
    #[test]
    fn describe_names_target_when_several() {
        let tally = |destination: &str| Tally {
            destination: destination.to_owned(),
            published: 1,
            already_present: 0,
            refused: 0,
            failed: 0,
        };
        let summary = |destinations: Vec<Tally>| Summary {
            walked: Walked::default(),
            destinations,
            verification: Verification::Verified,
        };

        let one = describe(&summary(vec![tally("local")]));
        assert!(
            one[0].render().starts_with("published 1 artifacts"),
            "{one:?}"
        );

        let two = describe(&summary(vec![tally("local"), tally("backup")]));
        assert!(two[0].render().starts_with("local: published 1"), "{two:?}");
        assert!(
            two[1].render().starts_with("backup: published 1"),
            "{two:?}"
        );
    }
}
