//! The context every operation carries.
//!
//! `Ctx` threads the cross-cutting machinery -- why this work is happening,
//! where failures go, where progress goes -- explicitly rather than through
//! globals.  That is what keeps the design correct under `tokio`, where one
//! task migrates between threads, and testable, because a test builds a
//! `Ctx` with recording sinks and asserts exactly what an adapter reported.

use std::sync::{Arc, Mutex};

use super::cancel::{Cancel, Reason};
use super::error::{Error, Result};
use super::license::Verdict;
use super::log::Log;
use super::message::{FILE_ARG, HTTP_DETAIL_ARG, Message, PURL_ARG, URL_ARG};
use super::problem::{Action, Code, Decide, Policy, Problem, ProblemSink, Subject};
use super::progress::{self, Node, ProgressSink, Unit};
use super::screened::Flag;
use crate::model::{ArtifactId, Cause, Provenance, Version};

/// Only [`Ctx::for_test`] discards progress, and it is test-only.
#[cfg(test)]
use super::progress::NullSink;

#[derive(Debug, Clone)]
pub struct Ctx {
    prov: Arc<Provenance>,
    problems: ProblemSink,
    progress: Arc<dyn ProgressSink>,

    /// Where log lines go.  Shared by every context in a run, like progress.
    log: Log,

    /// Shared by every context in a run, including children, so that one
    /// task's stop is every task's stop.  Carried here rather than passed
    /// separately because every layer already takes a `Ctx` -- which is what
    /// lets an interrupt reach an in-flight download and not merely the
    /// loop around it.
    cancel: Cancel,

    /// How a problem's disposition is decided.
    ///
    /// Here rather than at each call site for the same reason `cancel` is:
    /// every layer already takes a `Ctx`, so consulting it once on the way
    /// into the sink means no reporter has to remember a policy exists.
    /// An empty [`Policy`] by default, which is exactly the built-in
    /// behaviour.
    decide: Arc<dyn Decide>,

    /// The artifact being worked on, when one is.
    ///
    /// Separate from `prov`, which says *why* work is happening: a
    /// dependency's provenance names its parent, so what is being worked
    /// on is nowhere in that chain. Per-artifact overrides need it, and
    /// nothing else does -- which is why it is an `Option` rather than
    /// something every context must invent.
    subject: Option<Arc<Subject>>,

    /// Findings worth keeping against an artifact, as they are reported.
    ///
    /// The report needs them *per artifact*, and the shared sink cannot
    /// answer: it keeps counts and a bounded tail, both run-wide, because
    /// indexing every problem by artifact is the kind of collection the
    /// memory discipline forbids. This holds only the findings a record or
    /// a refusal needs, for only the artifact in hand, so it is bounded by
    /// how many such call sites run per artifact -- eight publish-window
    /// step-downs, one per file for a missing signature -- rather than by
    /// anything a run finds.
    ///
    /// `Some` exactly when `subject` is: an artifact to hold findings
    /// against is what makes holding them mean anything.
    reserved: Option<Arc<Mutex<Vec<Held>>>>,

    /// What the license policy decided about this artifact.
    ///
    /// Beside the reservations because it is the same kind of thing -- a
    /// finding about the artifact in hand, needed by whoever writes the
    /// record. It is not on [`ResolvedArtifact`] because that lives in
    /// `model`, which depends on nothing, and a verdict names a `Message`
    /// and a `Code`.
    ///
    /// Set once, by the walk, after the artifact is resolved. `None` means
    /// nothing evaluated it: no policy is configured, or this context is
    /// not about an artifact at all.
    verdict: Option<Arc<Verdict>>,

    /// What advisory screening found about this artifact.
    ///
    /// Carried as the verdict is, and for the same reason. Empty means
    /// nothing named it, or nothing screened it.
    flags: Arc<[Flag]>,
}

/// One kept finding, and the artifact it was decided under.
///
/// The subject is stored rather than inferred because one list outlives
/// several subjects. [`Ctx::for_artifact`] inherits the list so that
/// resolving a version and reading its dependencies land in one record,
/// and `resolve` narrows once per candidate it tries -- so a finding about
/// a version that was *rejected* shares the list with the version that
/// won. Provenance cannot tell them apart: it is identical across
/// candidates. Without this, a `publish-too-recent` about the candidate
/// that lost would be read as a refusal of the one that won.
#[derive(Debug, Clone)]
struct Held {
    subject: Option<Arc<Subject>>,
    problem: Problem,
}

impl Ctx {
    /// Build a root context for one run.
    pub fn new(cause: Cause, problems: ProblemSink, progress: Arc<dyn ProgressSink>) -> Self {
        Self {
            prov: Arc::new(Provenance::root(cause)),
            problems,
            progress,
            log: Log::default(),
            cancel: Cancel::new(),
            decide: Arc::new(Policy::default()),
            subject: None,
            reserved: None,
            verdict: None,
            flags: Arc::from([]),
        }
    }

    /// Decide dispositions with this, for everything reported through this
    /// context and its children.
    pub fn deciding_with(mut self, decide: Arc<dyn Decide>) -> Self {
        self.decide = decide;
        self
    }

    /// Log through this, for everything done under this context and its
    /// children.
    pub fn logging_with(mut self, log: Log) -> Self {
        self.log = log;
        self
    }

    /// Derive a context for work on one artifact.
    ///
    /// Only per-artifact overrides need this, so a caller that has no
    /// artifact -- loading configuration, opening a source -- simply does not
    /// call it, and its problems are decided per code.
    ///
    /// Not a `Cause`: provenance says why this work is happening and this
    /// says what it is happening to, and a dependency's provenance names
    /// its parent rather than itself.
    pub fn for_artifact(&self, id: ArtifactId, version: Option<Version>) -> Self {
        Self {
            subject: Some(Arc::new(Subject::new(id, version))),

            // The list already in force when there is one, so that findings
            // from resolving a version and findings from reading its
            // dependencies end up in the same record. Resolution narrows to
            // a candidate before this caller knows which version won, so
            // without inheriting there would be two lists and the earlier
            // one would be thrown away with the context that held it.
            reserved: self
                .reserved
                .clone()
                .or_else(|| Some(Arc::new(Mutex::new(Vec::new())))),
            ..self.clone()
        }
    }

    /// Start collecting reservations, before the artifact is known.
    ///
    /// The other half of [`Ctx::for_artifact`]'s inheritance. A walk opens
    /// one of these per artifact it is about to work on, and everything
    /// under it -- resolving a version, reading its dependencies -- files
    /// into the same list however many times the subject is narrowed on
    /// the way.
    pub fn collecting(&self) -> Self {
        Self {
            reserved: Some(Arc::new(Mutex::new(Vec::new()))),
            ..self.clone()
        }
    }

    /// Carry a license verdict for this context's artifact.
    ///
    /// A builder rather than a setter, so the verdict is fixed when the
    /// context is derived and cannot be swapped underneath work already
    /// using it. The walk evaluates once, against the narrowed context, and
    /// hands the result down with everything else.
    pub fn judged(mut self, verdict: Verdict) -> Self {
        self.verdict = Some(Arc::new(verdict));
        self
    }

    /// What the license policy decided about this context's artifact.
    ///
    /// `None` when nothing evaluated it -- no policy is configured, or this
    /// context is not about an artifact -- which is why a report's `license`
    /// field is absent rather than claiming an allow nobody decided.
    pub fn verdict(&self) -> Option<&Verdict> {
        self.verdict.as_deref()
    }

    /// Carry what screening found for this context's artifact.
    ///
    /// A builder, as [`Ctx::judged`] is.
    pub fn screened(mut self, flags: Vec<Flag>) -> Self {
        self.flags = Arc::from(flags);
        self
    }

    /// The advisories that named this context's artifact.
    pub fn flags(&self) -> &[Flag] {
        &self.flags
    }

    /// Quarantine findings reported against this context's artifact.
    ///
    /// Empty for a context that is not about one artifact, and for one
    /// nothing was reserved about -- a report then carries no quarantine
    /// list, which is the ordinary case and reads as such.
    pub fn reservations(&self) -> Vec<Problem> {
        self.kept(|problem| problem.quarantine().is_some())
    }

    /// The finding that refuses this artifact, if one does.
    ///
    /// The worst kept action, reported as a refusal only when it reaches
    /// `skip-artifact`. `abort` is deliberately not a refusal: it unwinds
    /// the run by tripping the stop signal, and labelling the artifact
    /// refused would describe a run that stopped as a run that made a
    /// judgement.
    pub fn refusal(&self) -> Option<Problem> {
        self.kept(|problem| problem.action() == Action::SkipArtifact)
            .into_iter()
            .max_by_key(Problem::action)
    }

    /// Whether a finding says to stop descending from this artifact.
    ///
    /// Asked *after* the dependency read rather than before the visit,
    /// because the only code that answers yes is reported while reading
    /// dependencies -- see [`Spider::children`](crate::commands::spider).
    pub fn stops_spider(&self) -> bool {
        !self
            .kept(|problem| problem.action() == Action::StopSpider)
            .is_empty()
    }

    /// The kept findings about this context's artifact that `want` accepts.
    fn kept(&self, want: impl Fn(&Problem) -> bool) -> Vec<Problem> {
        let Some(held) = &self.reserved else {
            return Vec::new();
        };

        held.lock()
            .expect("reservations poisoned")
            .iter()
            .filter(|held| held.subject.as_deref() == self.subject())
            .map(|held| held.problem.clone())
            .filter(|problem| want(problem))
            .collect()
    }

    /// Keep a problem against the artifact, when it is one worth reviewing.
    ///
    /// Quarantines, because a record carries them, and anything severe
    /// enough to change what the walk does with the artifact, because the
    /// walk has to be able to ask. Everything else is in the sink already,
    /// and copying it here would be the unbounded per-artifact collection
    /// this deliberately is not.
    fn reserve(&self, problem: &Problem) {
        if problem.quarantine().is_none() && problem.action() < Action::StopSpider {
            return;
        }

        if let Some(held) = &self.reserved {
            held.lock().expect("reservations poisoned").push(Held {
                subject: self.subject.clone(),
                problem: problem.clone(),
            });
        }
    }

    /// Take this provenance instead of the one carried.
    ///
    /// For work whose cause the *caller* already knows: a request parsed
    /// from a coordinate, or read out of a lock file, arrives carrying the
    /// chain that explains it, and a context built by cloning would report
    /// that artifact under whatever caused the surrounding run instead.
    ///
    /// Not a [`Ctx::child`]: this replaces the chain rather than extending
    /// it, because the request's chain already **is** a root.
    pub fn rooted(&self, prov: Arc<Provenance>) -> Self {
        Self {
            prov,

            // Same reasoning as `child`: a different artifact's work, so
            // it must not inherit an identity that would judge it by
            // another artifact's overrides.
            subject: None,
            ..self.clone()
        }
    }

    /// The artifact being worked on, when one is.
    pub fn subject(&self) -> Option<&Subject> {
        self.subject.as_deref()
    }

    /// Use a caller's stop signal instead of a fresh one.
    ///
    /// An embedder that already has one -- wired to its own shutdown, or
    /// shared with other work -- passes it here rather than racing two.
    pub fn with_cancel(mut self, cancel: Cancel) -> Self {
        self.cancel = cancel;
        self
    }

    /// A context that records problems but renders no progress.
    ///
    /// Test-only by construction: an embedder builds a `Ctx` with its own
    /// sinks through [`Ctx::new`], and a constructor that silently discards
    /// progress is a trap outside a test.
    #[cfg(test)]
    pub fn for_test(cause: Cause) -> Self {
        Self::new(cause, ProblemSink::new(), Arc::new(NullSink))
    }

    /// A context for a test that is not about provenance.
    ///
    /// Most tests need *a* context and never look at its [`Cause`], and
    /// inventing one per module produced seven different pieces of filler.
    /// This names the filler once, so a `Cause` written out at a call site
    /// now means the test cares what it says.
    #[cfg(test)]
    pub fn anonymous_for_test() -> Self {
        Self::for_test(Cause::Requested {
            arg: "a test".to_owned(),
        })
    }

    /// Derive a context for work caused by this one.
    ///
    /// The policy carries down with everything else: a run has one, and a
    /// dependency reached three levels in is judged by the same table as
    /// the artifact that was asked for.
    pub fn child(&self, cause: Cause) -> Self {
        Self {
            prov: self.prov.child(cause),
            problems: self.problems.clone(),
            progress: Arc::clone(&self.progress),
            log: self.log.clone(),
            cancel: self.cancel.clone(),
            decide: Arc::clone(&self.decide),

            // Deliberately not carried: a child context is a *different*
            // artifact's work, and inheriting the parent's identity would
            // judge a dependency by its parent's overrides -- and would
            // file its reservations in the parent's record.
            subject: None,
            reserved: None,
            verdict: None,
            flags: Arc::from([]),
        }
    }

    /// This run's stop signal.
    pub fn cancel(&self) -> &Cancel {
        &self.cancel
    }

    /// Whether the run is stopping, for any reason.
    ///
    /// Covers an external stop and a recorded `abort` alike, so a caller
    /// needs one check rather than one per cause.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled() || self.problems.is_aborted()
    }

    /// Why the run is stopping, if it is.
    pub fn stop_reason(&self) -> Option<Reason> {
        self.cancel
            .reason()
            .or_else(|| match self.problems.is_aborted() {
                true => Some(Reason::Aborted),
                false => None,
            })
    }

    /// Resolves once the run is stopping.
    ///
    /// Compose with `tokio::select!` so that work in flight is dropped
    /// rather than waited out -- for an HTTP request that closes the
    /// connection instead of draining the body.
    pub async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }

    /// Ask for the run to stop.
    pub fn stop(&self, reason: Reason) {
        self.cancel.cancel(reason);
    }

    pub fn prov(&self) -> &Arc<Provenance> {
        &self.prov
    }

    pub fn problems(&self) -> &ProblemSink {
        &self.problems
    }

    pub fn log(&self) -> &Log {
        &self.log
    }

    /// Open a root progress node.
    pub fn progress(&self, label: impl Into<String>, unit: Unit, total: Option<u64>) -> Node {
        progress::root(Arc::clone(&self.progress), label, unit, total)
    }

    /// Record a problem against this context's provenance and return the
    /// action the caller must take.
    pub fn report(&self, code: Code, message: Message) -> Action {
        self.reported(code, message).action()
    }

    /// Record a problem, and hand back the problem that was recorded.
    ///
    /// The same thing [`Ctx::report`] does, for a caller that passes the
    /// finding on in an error, so whoever receives the error need not
    /// record it a second time.
    pub fn reported(&self, code: Code, message: Message) -> Problem {
        let problem = Problem::ruled(
            code,
            self.decide.decide(code, self.subject()),
            Arc::clone(&self.prov),
            self.about(message),
        );

        self.sink(problem.clone());

        problem
    }

    /// The message, naming this context's artifact as its `purl` when it
    /// names none itself.
    ///
    /// What links a problem to its artifact in the report database, for a
    /// finding that has no purl of its own to give, such as a wrapped error
    /// or a license verdict. A message's own `purl` wins: it may name the
    /// artifact more exactly than the subject does.
    fn about(&self, message: Message) -> Message {
        let Some(subject) = self.subject() else {
            return message;
        };

        if message.args.contains_key(PURL_ARG) {
            return message;
        }

        let purl = match &subject.version {
            Some(version) => subject.id.purl_at(version.text()),
            None => subject.id.purl(),
        };

        message.arg(PURL_ARG, purl)
    }

    /// Record one problem, keeping it against the artifact when it is a
    /// reservation, and act on what it decided.
    fn sink(&self, problem: Problem) -> Action {
        self.reserve(&problem);

        self.acted(self.problems.record(problem))
    }

    /// Trip the stop signal when a problem's action is `abort`.
    ///
    /// This is what makes a fatal problem and an interrupt the same event
    /// downstream: both stop in-flight work through `cancelled`, rather
    /// than a fatal problem only being noticed at the next loop check.
    fn acted(&self, action: Action) -> Action {
        if action == Action::Abort {
            self.cancel.cancel(Reason::Aborted);
        }

        action
    }

    /// Record a problem with an action the caller has decided, overriding the
    /// code's default.  Used where context changes severity: an oversized
    /// body is fatal while loading config, survivable mid-enumeration.
    /// The quarantine class still comes from the policy: a call site
    /// saying "this one is fatal here" is speaking about severity, not
    /// about whether the problem is reviewable, and dropping the class
    /// would quietly remove an artifact from the quarantine list.
    pub fn report_as(&self, code: Code, action: Action, message: Message) -> Action {
        self.sink(
            Problem::ruled(
                code,
                self.decide.decide(code, self.subject()),
                Arc::clone(&self.prov),
                self.about(message),
            )
            .with_action(action),
        )
    }

    /// Record a problem whose action is at least `floor`, unless a
    /// per-artifact rule decided it.
    ///
    /// For a policy stance that raises severity: `vulnerabilities: forbid`
    /// holds back every vulnerability whatever the `problem-policy` table
    /// says, but a quarantine rule naming this one artifact is the more
    /// specific statement, and it answers.
    pub fn report_at_least(&self, code: Code, floor: Action, message: Message) -> Action {
        let ruling = self.decide.decide(code, self.subject());
        let raised = ruling.bypass.is_none() && ruling.disposition.action < floor;
        let problem = Problem::ruled(code, ruling, Arc::clone(&self.prov), self.about(message));

        match raised {
            true => self.sink(problem.with_action(floor)),
            false => self.sink(problem),
        }
    }

    /// Record an error under the code it maps to.
    ///
    /// An `Error` carries only a formatted string, so the problem code
    /// stands in as the message id and the rendered error becomes the
    /// fallback.  Call sites with something more specific to say should
    /// build a [`Message`] instead.
    pub fn report_err(&self, err: &Error) -> Action {
        self.reported_err(err).action()
    }

    /// Record an error, and hand back the problem that was recorded.
    ///
    /// The same thing [`Ctx::report_err`] does, for a caller that has to
    /// pass the finding on rather than only act on it: a walk reporting a
    /// request it could not resolve owes the report the reason, and the
    /// reason is the problem the policy decided, not the bare error.
    pub fn reported_err(&self, err: &Error) -> Problem {
        let message = Message::new(err.code().as_str()).text(err.to_string());

        self.recorded_err(err, message)
    }

    /// Record an error that happened to one file of the subject.
    ///
    /// The text names the file and leaves out the URL, which a person
    /// reading a report recognizes less readily; the URL stays in the
    /// arguments for whoever investigates.
    ///
    /// ```text
    ///   text: lib-1.0.jar: responded 404
    ///   args: file=lib-1.0.jar, url=h://host/repo/lib-1.0.jar, purl=...
    /// ```
    pub fn reported_file_err(&self, err: &Error, file: &str) -> Problem {
        let message = Message::new(err.code().as_str())
            .text(format!("{file}: {}", err.reason()))
            .arg(FILE_ARG, file);

        self.recorded_err(err, message)
    }

    /// Record `message` for `err`, with the arguments every error carries.
    fn recorded_err(&self, err: &Error, mut message: Message) -> Problem {
        let code = err.code();

        // Where it happened, for investigation, whatever the text says.
        if let Some(url) = err.url() {
            message = message.arg(URL_ARG, url);
        }

        // The server's own reason, also in the text, kept apart for a
        // consumer that queries it.
        if let Error::HttpStatus {
            detail: Some(detail),
            ..
        } = err
        {
            message = message.arg(HTTP_DETAIL_ARG, detail);
        }

        let problem = Problem::ruled(
            code,
            self.decide.decide(code, self.subject()),
            Arc::clone(&self.prov),
            self.about(message),
        );

        self.sink(problem.clone());

        problem
    }

    /// Whether an `Abort` has been recorded anywhere in this run.
    ///
    /// Long loops check this so one task's fatal problem stops the others
    /// promptly instead of at the end.
    pub fn is_aborted(&self) -> bool {
        self.problems.is_aborted()
    }

    /// Fail if the run is stopping.  Call at the top of each iteration of a
    /// long loop.
    ///
    /// For a loop that should end *gracefully* -- finishing its report
    /// rather than unwinding -- test [`Ctx::is_cancelled`] instead. A
    /// truncated report that cannot say how far it got is worse than a
    /// complete one that says it stopped early.
    pub fn check_abort(&self) -> Result<()> {
        match self.stop_reason() {
            Some(reason) => Err(Error::Aborted(reason.describe().to_owned())),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactId, DepKind, EcosystemId};
    use http::StatusCode;

    fn root_ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "lodash@4".into(),
        })
    }

    #[test]
    fn child_shares_problem_sink() {
        let parent = root_ctx();

        let child = parent.child(Cause::Dependency {
            of: ArtifactId::new(EcosystemId::npm(), None, "lodash"),
            version: None,
            kind: DepKind::Runtime,
        });

        child.report(
            Code::LicenseUnmatched,
            Message::new("t").text("odd license text"),
        );

        assert_eq!(parent.problems().counts()[&Code::LicenseUnmatched], 1);
    }

    /// The whole point of provenance: a problem knows it came from spidering
    /// rather than from something the user typed.
    #[test]
    fn finding_spidered_names_cause() {
        let ctx = root_ctx().child(Cause::Dependency {
            of: ArtifactId::new(EcosystemId::npm(), None, "lodash"),
            version: None,
            kind: DepKind::Runtime,
        });

        ctx.report(Code::ArtifactNotFound, Message::new("t").text("404"));

        let problem = ctx.problems().tail().pop().expect("recorded");
        let rendered = problem.prov().render();

        assert!(rendered.starts_with("runtime dependency of pkg:npm/lodash"));
        assert!(rendered.contains(r#"requested: "lodash@4""#));
    }

    #[test]
    fn abort_propagates_to_siblings() {
        let parent = root_ctx();
        let a = parent.child(Cause::Enumerated {
            enumerator: "s".into(),
        });
        let b = parent.child(Cause::Enumerated {
            enumerator: "s".into(),
        });

        a.report(Code::ChecksumMismatch, Message::new("t").text("tampered"));

        assert!(b.is_aborted());
        assert!(b.check_abort().is_err());
    }

    #[test]
    fn report_as_overrides_default_action() {
        let ctx = root_ctx();

        let action = ctx.report_as(Code::DownloadTooLarge, Action::Abort, Message::new("t"));

        assert_eq!(action, Action::Abort);
        assert!(ctx.is_aborted());
    }

    #[test]
    fn report_at_least_raises_lower_action() {
        let ctx = root_ctx();

        let action = ctx.report_at_least(
            Code::VulnerabilityKnown,
            Action::SkipArtifact,
            Message::new("t"),
        );

        assert_eq!(action, Action::SkipArtifact);
    }

    #[test]
    fn report_at_least_keeps_higher_action() {
        let ctx = root_ctx();

        let action = ctx.report_at_least(Code::MalwareKnown, Action::Warn, Message::new("t"));

        assert_eq!(action, Action::SkipArtifact);
    }

    /// Answers every code as a per-artifact rule allowing it.
    #[derive(Debug)]
    struct Excused;

    impl Decide for Excused {
        fn decide(&self, _code: Code, _at: Option<&Subject>) -> crate::core::problem::Ruling {
            crate::core::problem::Ruling {
                disposition: crate::core::problem::Disposition {
                    action: Action::Warn,
                    quarantine: None,
                },
                bypass: Some(crate::core::problem::Bypass {
                    justification: Some("reviewed".into()),
                    source: "quarantine.yaml#0".into(),
                    expires: None,
                }),
                hardened: false,
            }
        }
    }

    /// A rule about this one artifact is the more specific statement, so a
    /// stance's floor yields to it.
    #[test]
    fn report_at_least_yields_to_artifact_rule() {
        let ctx = Ctx::anonymous_for_test().deciding_with(std::sync::Arc::new(Excused));

        let action = ctx.report_at_least(
            Code::VulnerabilityKnown,
            Action::SkipArtifact,
            Message::new("t"),
        );

        assert_eq!(action, Action::Warn);
    }

    #[test]
    fn error_maps_to_code() {
        let ctx = root_ctx();

        ctx.report_err(&Error::HttpStatus {
            url: "h://example.test/x".into(),
            status: StatusCode::NOT_FOUND,
            retry_at: None,
            detail: None,
        });

        assert_eq!(ctx.problems().counts()[&Code::ArtifactNotFound], 1);
    }

    #[test]
    fn error_http_detail_becomes_arg() {
        let ctx = root_ctx();

        let problem = ctx.reported_err(&Error::HttpStatus {
            url: "h://example.test/x".into(),
            status: StatusCode::CONFLICT,
            retry_at: None,
            detail: Some("already owned".into()),
        });

        assert_eq!(
            problem
                .message()
                .args
                .get(HTTP_DETAIL_ARG)
                .map(String::as_str),
            Some("already owned")
        );
    }

    /// The URL is an argument whatever the text says.
    #[test]
    fn error_url_becomes_arg() {
        let problem = root_ctx().reported_err(&Error::HttpStatus {
            url: "h://example.test/x".into(),
            status: StatusCode::NOT_FOUND,
            retry_at: None,
            detail: None,
        });

        assert_eq!(
            problem.message().args.get(URL_ARG).map(String::as_str),
            Some("h://example.test/x")
        );
    }

    /// A file's failure names the file in its text, and keeps the URL in
    /// the arguments.
    #[test]
    fn error_file_names_file() {
        let problem = root_ctx().reported_file_err(
            &Error::HttpStatus {
                url: "h://example.test/repo/lib-1.0.jar".into(),
                status: StatusCode::NOT_FOUND,
                retry_at: None,
                detail: None,
            },
            "lib-1.0.jar",
        );

        let message = problem.message();

        assert_eq!(message.text.as_deref(), Some("lib-1.0.jar: responded 404"));
        assert_eq!(
            message.args.get(FILE_ARG).map(String::as_str),
            Some("lib-1.0.jar")
        );
        assert_eq!(
            message.args.get(URL_ARG).map(String::as_str),
            Some("h://example.test/repo/lib-1.0.jar")
        );
    }

    // -- The problem policy ------------------------------------------------

    use crate::core::problem::{Class, Policy, Quarantine};

    fn under(policy: Policy) -> Ctx {
        Ctx::anonymous_for_test().deciding_with(std::sync::Arc::new(policy))
    }

    /// The policy has to reach a reported problem, which is the part that
    /// could silently not work: every table above it can be right while
    /// nothing consults it.
    #[test]
    fn class_configured_reaches_recorded_problem() {
        let ctx = under(Policy::new().set(Code::SignatureMissing, Class::Hard));

        let action = ctx.report(Code::SignatureMissing, Message::new("x"));

        assert_eq!(action, Action::SkipArtifact, "the default is warn");

        let recorded = ctx.problems().tail();
        let problem = recorded.last().expect("recorded");

        assert_eq!(problem.quarantine(), Some(Quarantine::Hard));
        assert_eq!(problem.action(), Action::SkipArtifact);
    }

    /// And an unconfigured code is untouched by a policy that mentions
    /// other ones.
    #[test]
    fn policy_unmentioned_code_keeps_default() {
        let ctx = under(Policy::new().set(Code::SignatureMissing, Class::Hard));

        ctx.report(Code::MalwareKnown, Message::new("x"));

        let recorded = ctx.problems().tail();
        let problem = recorded.last().expect("recorded");

        assert_eq!(problem.quarantine(), Code::MalwareKnown.quarantine());
        assert_eq!(problem.action(), Code::MalwareKnown.action());
    }

    /// A run has one policy, and a dependency reached three levels in is
    /// judged by the same table as the artifact that was asked for.
    #[test]
    fn child_inherits_policy() {
        let root = under(Policy::new().set(Code::SignatureMissing, Class::Hard));

        let child = root
            .child(Cause::Dependency {
                of: ArtifactId::new(EcosystemId::npm(), None, "a"),
                version: None,
                kind: DepKind::Runtime,
            })
            .child(Cause::Dependency {
                of: ArtifactId::new(EcosystemId::npm(), None, "b"),
                version: None,
                kind: DepKind::Runtime,
            });

        child.report(Code::SignatureMissing, Message::new("x"));

        let recorded = child.problems().tail();
        let problem = recorded.last().expect("recorded");

        assert_eq!(problem.quarantine(), Some(Quarantine::Hard));
    }

    /// Turning a code into an abort through the policy must still trip the
    /// stop signal, or a configured failure would be recorded and ignored.
    #[test]
    fn policy_fatal_code_stops_run() {
        let ctx = under(Policy::new().set(Code::ChecksumMismatch, Class::Failure));

        // `failure` never weakens, so this stays an abort.
        assert_eq!(
            ctx.report(Code::ChecksumMismatch, Message::new("x")),
            Action::Abort
        );
        assert!(ctx.is_cancelled());
    }

    /// `report_as` overrides severity for one call site. It must not
    /// thereby drop the quarantine class, which would quietly remove the
    /// artifact from the quarantine list.
    #[test]
    fn class_kept_by_action_override() {
        let ctx = under(Policy::new().set(Code::SignatureMissing, Class::Soft));

        ctx.report_as(Code::SignatureMissing, Action::Abort, Message::new("x"));

        let recorded = ctx.problems().tail();
        let problem = recorded.last().expect("recorded");

        assert_eq!(problem.action(), Action::Abort, "the call site decided");
        assert_eq!(
            problem.quarantine(),
            Some(Quarantine::Soft),
            "and the policy still decided reviewability"
        );
    }

    // -- The artifact a problem happened to --------------------------------

    /// A context with no artifact reports per code, which is what loading
    /// configuration or opening a source does.
    #[test]
    fn subject_absent_without_artifact() {
        assert!(Ctx::anonymous_for_test().subject().is_none());
    }

    #[test]
    fn subject_set_by_for_artifact() {
        let ctx = Ctx::anonymous_for_test().for_artifact(
            ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            Some(crate::model::Version::new(
                "1.0.0",
                crate::model::Release::General,
            )),
        );

        let subject = ctx.subject().expect("set");

        assert_eq!(subject.id.name(), "tuna");
        assert_eq!(subject.version.as_ref().map(|v| v.text()), Some("1.0.0"));
    }

    /// A problem raised about an artifact names it as its `purl`, unless
    /// the message already names one.
    #[test]
    fn subject_fills_missing_purl() {
        let ctx = Ctx::anonymous_for_test().for_artifact(
            ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            Some(crate::model::Version::new(
                "1.0.0",
                crate::model::Release::General,
            )),
        );

        ctx.report(Code::MetadataMalformed, Message::new("filled"));
        ctx.report(
            Code::MetadataMalformed,
            Message::new("kept").arg(PURL_ARG, "pkg:npm/other@2"),
        );

        let purls: Vec<String> = ctx
            .problems()
            .tail()
            .iter()
            .map(|problem| problem.message().args[PURL_ARG].clone())
            .collect();

        assert_eq!(purls, ["pkg:npm/tuna@1.0.0", "pkg:npm/other@2"]);
    }

    /// The subject does **not** carry down to a child, because a child is a
    /// different artifact's work. Inheriting it would judge a dependency by
    /// its parent's per-artifact overrides, which is the wrong artifact
    /// entirely and would be invisible when it happened.
    #[test]
    fn child_does_not_inherit_subject() {
        let parent = Ctx::anonymous_for_test().for_artifact(
            ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            Some(crate::model::Version::new(
                "1.0.0",
                crate::model::Release::General,
            )),
        );

        let child = parent.child(Cause::Dependency {
            of: ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            version: None,
            kind: DepKind::Runtime,
        });

        assert!(child.subject().is_none());
    }

    /// Everything else does carry down, so a run still has one policy.
    #[test]
    fn child_keeps_decisions() {
        let root = under(Policy::new().set(Code::SignatureMissing, Class::Hard));

        let child = root.child(Cause::Dependency {
            of: ArtifactId::new(EcosystemId::npm(), None, "a"),
            version: None,
            kind: DepKind::Runtime,
        });

        child.report(Code::SignatureMissing, Message::new("x"));

        let recorded = child.problems().tail();

        assert_eq!(
            recorded.last().expect("recorded").quarantine(),
            Some(Quarantine::Hard)
        );
    }

    // -- What is kept against the artifact ---------------------------------

    fn version(text: &str) -> crate::model::Version {
        crate::model::Version::new(text, crate::model::Release::General)
    }

    fn tuna() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "tuna")
    }

    /// The case `resolve`'s publish-window loop actually produces: a
    /// candidate is tried, found too recent, and an older one wins. Both
    /// narrow from the same collecting context, so the finding about the
    /// version that lost shares a list with the version that won -- and must
    /// not be read as a finding about it.
    #[test]
    fn finding_of_rejected_candidate_not_on_chosen() {
        let collecting = under(Policy::new().set(Code::PublishTooRecent, Class::Hard)).collecting();

        let rejected = collecting.for_artifact(tuna(), Some(version("1.2.0")));
        rejected.report(Code::PublishTooRecent, Message::new("too new"));

        let chosen = collecting.for_artifact(tuna(), Some(version("1.0.0")));

        assert!(
            chosen.reservations().is_empty(),
            "the finding was about 1.2.0"
        );
        assert!(chosen.refusal().is_none(), "so 1.0.0 is not refused");

        assert_eq!(
            rejected.reservations().len(),
            1,
            "and 1.2.0 still carries it"
        );
    }

    /// The inheritance the list exists for: resolution and the dependency
    /// read narrow to the same artifact and land in one record.
    #[test]
    fn finding_about_artifact_kept() {
        let collecting = under(Policy::new().set(Code::SignatureMissing, Class::Soft)).collecting();

        let about = collecting.for_artifact(tuna(), Some(version("1.0.0")));
        about.report(Code::SignatureMissing, Message::new("x"));

        let again = collecting.for_artifact(tuna(), Some(version("1.0.0")));

        assert_eq!(again.reservations().len(), 1);
    }

    #[test]
    fn finding_skip_artifact_refuses() {
        let collecting = under(Policy::new().set(Code::SignatureMissing, Class::Hard)).collecting();

        let about = collecting.for_artifact(tuna(), Some(version("1.0.0")));
        about.report(Code::SignatureMissing, Message::new("x"));

        let refusal = about.refusal().expect("refused");

        assert_eq!(refusal.code(), Code::SignatureMissing);
        assert_eq!(refusal.action(), Action::SkipArtifact);
    }

    /// An aborting run is not a judgement about the artifact, so it is not
    /// reported as one.  The abort stops the run by its own path.
    #[test]
    fn abort_not_refusal() {
        let collecting = Ctx::anonymous_for_test().collecting();

        let about = collecting.for_artifact(tuna(), Some(version("1.0.0")));

        assert_eq!(
            about.report(Code::ChecksumMismatch, Message::new("x")),
            Action::Abort
        );
        assert!(about.refusal().is_none());
    }

    /// `stop-spider` keeps the artifact and prunes below it, so it must be
    /// visible without being a refusal.
    #[test]
    fn finding_stop_spider_prunes_without_refusing() {
        let collecting = Ctx::anonymous_for_test().collecting();

        let about = collecting.for_artifact(tuna(), Some(version("1.0.0")));
        about.report(Code::PomProfileUnsupported, Message::new("x"));

        assert!(about.stops_spider());
        assert!(about.refusal().is_none(), "the artifact itself stands");
    }

    /// Nothing is kept where there is nothing to keep it against, which is
    /// what loading configuration does.
    #[test]
    fn collect_off_keeps_nothing() {
        let ctx = under(Policy::new().set(Code::SignatureMissing, Class::Hard));

        ctx.report(Code::SignatureMissing, Message::new("x"));

        assert!(ctx.reservations().is_empty());
        assert!(ctx.refusal().is_none());
    }
}
