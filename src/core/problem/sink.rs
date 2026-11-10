//! Collecting a run's problems, and telling a watcher about each.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use super::{Action, Code, Problem, Quarantine};

/// Told about each problem as it is recorded.
///
/// The inversion that lets a problem reach a report without `core` knowing
/// what a report is -- the same shape as [`Decide`](super::Decide) and `net::Fetch`, and
/// for the same reason. A report writer implements this; `core` only knows
/// that something might be listening.
///
/// **Called outside the sink's lock**, so an implementation may take its
/// own, and may even record a problem of its own without deadlocking.
///
/// It returns nothing on purpose. [`ProblemSink::record`] answers with the
/// action a caller must take, and a report that could not be written must
/// not change that answer: the run's behaviour cannot depend on whether
/// anyone was watching. An implementation that fails logs and carries on.
pub trait Watch: Send + Sync {
    /// One problem, as it is recorded.
    fn saw(&self, problem: &Problem);
}

/// How many recent problems the sink keeps.
///
/// Problems are written into the report stream as they occur -- see
/// [`Watch`] -- and the closing summary carries counts, so the tail is
/// needed by neither. What it is for is a caller holding a sink without a
/// report: the tests, and an embedder that wants to look at what happened
/// without writing a file. Bounded because that caller must not be able to
/// turn a million-artifact enumeration into a million retained problems.
const TAIL_CAPACITY: usize = 64;

/// Cloneable handle over one shared collector.
///
/// Every concurrent task records through its own clone; they share one inner
/// state.  Nothing here grows with artifact count.
#[derive(Debug, Clone, Default)]
pub struct ProblemSink {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    aborted: AtomicBool,

    /// Set once, by whoever is writing the run's report.
    ///
    /// A `OnceLock` rather than a `Mutex` because the read happens on every
    /// recorded problem and the write happens once, before the work starts:
    /// the sink is built with the run's context, and the report writer is
    /// built later by the sub-command that owns the output.
    watcher: OnceLock<Arc<dyn Watch>>,
}

/// Hand-written because a watcher is not `Debug`: a report writer wraps a
/// `dyn Write`, which is not, and requiring it would rule out the only
/// implementation this has.
impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("state", &self.state)
            .field("aborted", &self.aborted)
            .field("watched", &self.watcher.get().is_some())
            .finish()
    }
}

#[derive(Debug, Default)]
struct State {
    counts: BTreeMap<Code, u64>,

    /// Problems by quarantine class, not artifacts.
    ///
    /// Counted the same way `counts` is, because this sink sees problems
    /// and nothing else: one artifact with two soft reservations adds two.
    /// The per-artifact view lives in the report's artifact records, where
    /// an artifact is a thing that exists.
    quarantined: BTreeMap<Quarantine, u64>,

    worst: Option<Action>,
    tail: Vec<Problem>,
}

impl ProblemSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Watch every problem from here on.
    ///
    /// The first watcher wins and later calls do nothing: a run writes one
    /// report. Attach it **after** the report's header, since a problem
    /// recorded before this call is not seen and one recorded after is
    /// written where it happened.
    pub fn watched_by(&self, watcher: Arc<dyn Watch>) {
        let _ = self.inner.watcher.set(watcher);
    }

    /// Record a problem and return the action the caller must now take.
    pub fn record(&self, problem: Problem) -> Action {
        let action = problem.action();

        if action == Action::Abort {
            self.inner.aborted.store(true, Ordering::SeqCst);
        }

        {
            let mut state = self.inner.state.lock().expect("problem sink poisoned");

            *state.counts.entry(problem.code()).or_default() += 1;

            if let Some(class) = problem.quarantine() {
                *state.quarantined.entry(class).or_default() += 1;
            }

            state.worst = Some(state.worst.map_or(action, |w| w.max(action)));

            if state.tail.len() == TAIL_CAPACITY {
                state.tail.remove(0);
            }
            state.tail.push(problem.clone());
        }

        // Told **after** the lock is released, which is what lets a watcher
        // take a lock of its own -- a report writer does -- without ordering
        // against this one, and lets it record a problem of its own without
        // deadlocking on the borrow it is already inside.
        if let Some(watcher) = self.inner.watcher.get() {
            watcher.saw(&problem);
        }

        action
    }

    /// Whether an `Abort` has been recorded.  Long loops check this so a
    /// fatal problem in one task stops the others promptly.
    pub fn is_aborted(&self) -> bool {
        self.inner.aborted.load(Ordering::SeqCst)
    }

    /// Worst action recorded so far; `None` when nothing went wrong.
    pub fn worst(&self) -> Option<Action> {
        self.inner
            .state
            .lock()
            .expect("problem sink poisoned")
            .worst
    }

    /// Occurrence count per code, for the report's closing summary.
    /// Problems by quarantine class.
    ///
    /// Empty when nothing was held or flagged, which is the ordinary case
    /// and reads as such in a report.
    pub fn quarantined(&self) -> BTreeMap<Quarantine, u64> {
        self.inner
            .state
            .lock()
            .expect("problem sink poisoned")
            .quarantined
            .clone()
    }

    pub fn counts(&self) -> BTreeMap<Code, u64> {
        self.inner
            .state
            .lock()
            .expect("problem sink poisoned")
            .counts
            .clone()
    }

    /// The most recent problems, oldest first.  Bounded, so this stays
    /// constant-memory however many a run records.
    pub fn tail(&self) -> Vec<Problem> {
        self.inner
            .state
            .lock()
            .expect("problem sink poisoned")
            .tail
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::message::Message;
    use crate::model::{Cause, Provenance};

    fn prov() -> Arc<Provenance> {
        Arc::new(Provenance::root(Cause::Requested { arg: "test".into() }))
    }

    #[test]
    fn action_worst_is_maximum() {
        let sink = ProblemSink::new();

        sink.record(Problem::new(
            Code::LicenseUnmatched,
            prov(),
            Message::new("test"),
        ));
        sink.record(Problem::new(
            Code::ArtifactNotFound,
            prov(),
            Message::new("test"),
        ));
        sink.record(Problem::new(
            Code::LicenseUnmatched,
            prov(),
            Message::new("test"),
        ));

        assert_eq!(sink.worst(), Some(Action::SkipArtifact));
        assert!(sink.worst().unwrap().is_failure());
        assert!(!sink.worst().unwrap().is_fatal());
    }

    #[test]
    fn warnings_alone_not_failure() {
        let sink = ProblemSink::new();
        sink.record(Problem::new(
            Code::LicenseUnmatched,
            prov(),
            Message::new("test"),
        ));

        assert!(!sink.worst().unwrap().is_failure());
        assert!(!sink.is_aborted());
    }

    #[test]
    fn abort_visible_to_other_tasks() {
        let sink = ProblemSink::new();
        let other = sink.clone();

        sink.record(Problem::new(
            Code::ChecksumMismatch,
            prov(),
            Message::new("test"),
        ));

        assert!(other.is_aborted());
    }

    #[test]
    fn tail_stays_bounded() {
        let sink = ProblemSink::new();

        for _ in 0..(TAIL_CAPACITY * 3) {
            sink.record(Problem::new(
                Code::LicenseUnmatched,
                prov(),
                Message::new("test"),
            ));
        }

        assert_eq!(sink.tail().len(), TAIL_CAPACITY);
        assert_eq!(sink.counts()[&Code::LicenseUnmatched], 192);
    }

    #[test]
    fn action_override_survives_recording() {
        let sink = ProblemSink::new();

        let problem = Problem::new(Code::DownloadTooLarge, prov(), Message::new("test"))
            .with_action(Action::Abort);

        assert_eq!(sink.record(problem), Action::Abort);
        assert!(sink.is_aborted());
    }

    // -- Quarantine counting -----------------------------------------------

    /// The ordinary case, and what a report should read as: nothing held,
    /// nothing flagged, no quarantine section at all.
    #[test]
    fn reservations_absent_counts_none() {
        let sink = ProblemSink::new();
        let prov = Arc::new(Provenance::root(Cause::Requested { arg: "x".into() }));

        sink.record(Problem::new(
            Code::HostUnreachable,
            Arc::clone(&prov),
            Message::new("x"),
        ));

        assert!(sink.quarantined().is_empty());
        assert_eq!(sink.counts()[&Code::HostUnreachable], 1);
    }

    #[test]
    fn reservations_counted_by_class() {
        let sink = ProblemSink::new();
        let prov = Arc::new(Provenance::root(Cause::Requested { arg: "x".into() }));

        // Two soft, one hard.
        for code in [
            Code::SignatureMissing,
            Code::SignatureKeyExpired,
            Code::MalwareKnown,
        ] {
            sink.record(Problem::new(code, Arc::clone(&prov), Message::new("x")));
        }

        let counted = sink.quarantined();

        assert_eq!(counted[&Quarantine::Soft], 2);
        assert_eq!(counted[&Quarantine::Hard], 1);
    }

    /// Problems, not artifacts -- stated as a test because the difference is
    /// easy to misread and the summary says so in prose.
    #[test]
    fn count_problems_not_artifacts() {
        let sink = ProblemSink::new();
        let prov = Arc::new(Provenance::root(Cause::Requested { arg: "x".into() }));

        // One artifact's worth of provenance, two reservations.
        sink.record(Problem::new(
            Code::SignatureMissing,
            Arc::clone(&prov),
            Message::new("x"),
        ));
        sink.record(Problem::new(
            Code::SignatureKeyExpired,
            Arc::clone(&prov),
            Message::new("x"),
        ));

        assert_eq!(sink.quarantined()[&Quarantine::Soft], 2);
    }

    // -- Watching ----------------------------------------------------------

    #[derive(Default)]
    struct Seen(Mutex<Vec<Code>>);

    impl Watch for Seen {
        fn saw(&self, problem: &Problem) {
            self.0.lock().expect("not poisoned").push(problem.code());
        }
    }

    fn problem_of(code: Code) -> Problem {
        Problem::new(
            code,
            Arc::new(Provenance::root(Cause::Requested { arg: "x".into() })),
            Message::new("x"),
        )
    }

    #[test]
    fn watcher_told_every_problem() {
        let sink = ProblemSink::new();
        let seen = Arc::new(Seen::default());

        sink.watched_by(seen.clone());

        sink.record(problem_of(Code::SignatureMissing));
        sink.record(problem_of(Code::ArtifactNotFound));

        assert_eq!(
            *seen.0.lock().expect("not poisoned"),
            vec![Code::SignatureMissing, Code::ArtifactNotFound]
        );
    }

    /// Only from the point it is attached. A sub-command attaches its
    /// watcher after writing the report's header, so a problem recorded
    /// before that must not be written above it.
    #[test]
    fn watcher_sees_nothing_before_attach() {
        let sink = ProblemSink::new();
        let seen = Arc::new(Seen::default());

        sink.record(problem_of(Code::SignatureMissing));
        sink.watched_by(seen.clone());
        sink.record(problem_of(Code::ArtifactNotFound));

        assert_eq!(
            *seen.0.lock().expect("not poisoned"),
            vec![Code::ArtifactNotFound]
        );
    }

    /// A run writes one report, so a second attach is ignored rather than
    /// replacing the first and silently splitting the stream.
    #[test]
    fn watcher_first_wins() {
        let sink = ProblemSink::new();
        let first = Arc::new(Seen::default());
        let second = Arc::new(Seen::default());

        sink.watched_by(first.clone());
        sink.watched_by(second.clone());

        sink.record(problem_of(Code::SignatureMissing));

        assert_eq!(first.0.lock().expect("not poisoned").len(), 1);
        assert!(second.0.lock().expect("not poisoned").is_empty());
    }

    /// The property that makes this safe to hand a report writer.
    ///
    /// A watcher takes its own lock, and the real one records problems of
    /// its own when a write fails. Notifying inside the sink's lock would
    /// deadlock on the re-entrant `record`; this pins that it does not.
    #[test]
    fn watcher_may_record_a_problem_of_its_own() {
        struct Reentrant(ProblemSink);

        impl Watch for Reentrant {
            fn saw(&self, problem: &Problem) {
                // Only for the first, or this never terminates.
                if problem.code() == Code::SignatureMissing {
                    self.0.record(problem_of(Code::ArtifactNotFound));
                }
            }
        }

        let sink = ProblemSink::new();

        sink.watched_by(Arc::new(Reentrant(sink.clone())));

        sink.record(problem_of(Code::SignatureMissing));

        assert_eq!(sink.counts()[&Code::SignatureMissing], 1);
        assert_eq!(sink.counts()[&Code::ArtifactNotFound], 1);
    }

    /// The sink still answers its caller the same way, whoever is watching.
    #[test]
    fn watcher_does_not_change_action() {
        let sink = ProblemSink::new();

        let unwatched = sink.record(problem_of(Code::ChecksumMismatch));

        let watched_sink = ProblemSink::new();
        watched_sink.watched_by(Arc::new(Seen::default()));

        assert_eq!(
            watched_sink.record(problem_of(Code::ChecksumMismatch)),
            unwatched
        );
    }
}
