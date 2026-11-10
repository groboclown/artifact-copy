//! Stopping a run before it finishes.
//!
//! A migration is long-running and concurrent, so it needs a way to be told
//! to stop that is neither a panic nor a process kill. At least three
//! things ask for that, and they are the same mechanism with different
//! triggers:
//!
//! - the user pressing Ctrl-C,
//! - a time limit on the run,
//! - a cap on how much is downloaded.
//!
//! A fourth is internal: a problem whose action is
//! [`Action::Abort`](super::problem::Action::Abort) stops the run too, and
//! it travels the same path so that one check covers every reason.
//!
//! # Stopping is not failing
//!
//! A cancelled run **unwinds cleanly and finishes its bookkeeping**. The
//! report is a stream with a trailing summary record, and a run that
//! returned an error the moment it was interrupted would leave that record
//! unwritten -- turning "the user pressed Ctrl-C" into "the report is
//! truncated and you cannot tell how far it got". So cancellation is
//! reported as a [`Reason`] alongside partial results, not as an `Err`, and
//! the caller decides the exit code.
//!
//! # Promptness
//!
//! A token that is only checked between units of work is not much use when
//! a unit is a multi-megabyte download. [`Cancel::cancelled`] is an
//! awaitable that composes with `tokio::select!`, so a caller can drop
//! whatever is in flight -- which for an HTTP request means the connection
//! is closed rather than drained.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;

/// Why a run stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The user interrupted it -- Ctrl-C, or a `SIGTERM`.
    Interrupted,

    /// A configured time limit elapsed.
    Deadline,

    /// A configured download budget was spent.
    Budget,

    /// A problem was recorded whose action is `abort`.
    Aborted,

    /// An embedder asked for it.
    Requested,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Interrupted => "interrupted",
            Reason::Deadline => "deadline",
            Reason::Budget => "budget",
            Reason::Aborted => "aborted",
            Reason::Requested => "requested",
        }
    }

    /// What to tell the user, in U.S. English.
    pub fn describe(self) -> &'static str {
        match self {
            Reason::Interrupted => "interrupted",
            Reason::Deadline => "the time limit elapsed",
            Reason::Budget => "the download budget was spent",
            Reason::Aborted => "a fatal problem was recorded",
            Reason::Requested => "stopping was requested",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A shared "stop now" signal.
///
/// Cloning shares one signal, so every task in a run observes the same
/// decision. The **first** reason wins: a run interrupted while it was
/// already stopping for a deadline still reports the deadline, because that
/// is what actually ended it.
#[derive(Debug, Clone)]
pub struct Cancel {
    /// A watch channel rather than a `Notify`: it is level-triggered, so a
    /// task that starts waiting *after* the signal fires still sees it.
    /// With edge-triggered notification that task would wait forever, and
    /// it is exactly the task spawned last -- during shutdown -- that would
    /// hang.
    tx: Arc<watch::Sender<Option<Reason>>>,
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

impl Cancel {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(None);

        Self { tx: Arc::new(tx) }
    }

    /// Stop the run. The first call decides the reason.
    pub fn cancel(&self, reason: Reason) {
        self.tx.send_if_modified(|current| match current {
            Some(_) => false,
            None => {
                *current = Some(reason);
                true
            }
        });
    }

    /// Why the run is stopping, if it is.
    pub fn reason(&self) -> Option<Reason> {
        *self.tx.borrow()
    }

    pub fn is_cancelled(&self) -> bool {
        self.reason().is_some()
    }

    /// Resolves once the run is stopping.
    ///
    /// Cancel-safe, so it composes with `tokio::select!`:
    ///
    /// ```ignore
    /// tokio::select! {
    ///     result = work => result,
    ///     () = cancel.cancelled() => Err(Error::Aborted("stopped".into())),
    /// }
    /// ```
    ///
    /// Returns immediately when the signal has already fired.
    pub async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();

        loop {
            if rx.borrow_and_update().is_some() {
                return;
            }

            // The sender is held by this `Arc`, so it outlives the wait and
            // `changed` cannot fail here.
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Stop the run once `limit` has elapsed.
    ///
    /// The timer runs as its own task and holds a clone, so it does not
    /// depend on anyone awaiting it.
    pub fn cancel_after(&self, limit: Duration) {
        let cancel = self.clone();

        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(limit) => cancel.cancel(Reason::Deadline),

                // Nothing to do if the run ended first; this arm exists so
                // the timer task does not outlive it.
                () = cancel.cancelled() => {}
            }
        });
    }

    /// Stop the run on Ctrl-C.
    ///
    /// **One interrupt only.** A second Ctrl-C should kill the process
    /// immediately, because a user pressing it twice has stopped asking
    /// politely -- but exiting is a decision for the binary, not for a
    /// library that may be embedded in a larger program. `main` installs
    /// that; this installs the graceful half.
    pub fn cancel_on_interrupt(&self) {
        let cancel = self.clone();

        tokio::spawn(async move {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if result.is_ok() {
                        cancel.cancel(Reason::Interrupted);
                    }
                }

                () = cancel.cancelled() => {}
            }
        });
    }

    /// A download budget that stops the run when it is spent.
    pub fn budget(&self, limit: u64) -> Budget {
        Budget {
            cancel: self.clone(),
            limit,
            spent: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// A cap on how much a run may download.
///
/// Charged as bytes arrive rather than from a `Content-Length`, for the
/// same reason [`crate::net::ByteLimit`] is enforced while streaming: a
/// server that understates the header would otherwise walk straight past
/// the cap.
#[derive(Debug, Clone)]
pub struct Budget {
    cancel: Cancel,
    limit: u64,
    spent: Arc<AtomicU64>,
}

impl Budget {
    /// Record bytes downloaded, stopping the run if that spends the budget.
    ///
    /// Returns whether there is budget left. Charging past the limit is
    /// not an error -- the bytes have already arrived, and the honest thing
    /// is to count them and stop asking for more.
    pub fn charge(&self, bytes: u64) -> bool {
        let spent = self.spent.fetch_add(bytes, Ordering::SeqCst) + bytes;

        if spent >= self.limit {
            self.cancel.cancel(Reason::Budget);

            return false;
        }

        true
    }

    pub fn spent(&self) -> u64 {
        self.spent.load(Ordering::SeqCst)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// What is left, saturating at zero.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.spent())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn signal_fresh_not_cancelled() {
        let cancel = Cancel::new();

        assert!(!cancel.is_cancelled());
        assert_eq!(cancel.reason(), None);
    }

    #[test]
    fn signal_cancel_visible_through_every_clone() {
        let cancel = Cancel::new();
        let worker = cancel.clone();

        cancel.cancel(Reason::Interrupted);

        assert!(worker.is_cancelled());
        assert_eq!(worker.reason(), Some(Reason::Interrupted));
    }

    /// The reason has to be the one that actually ended the run. A deadline
    /// that fires while the user is pressing Ctrl-C still reports the
    /// deadline, or the report would explain the stop wrongly.
    #[test]
    fn signal_first_reason_wins() {
        let cancel = Cancel::new();

        cancel.cancel(Reason::Deadline);
        cancel.cancel(Reason::Interrupted);
        cancel.cancel(Reason::Aborted);

        assert_eq!(cancel.reason(), Some(Reason::Deadline));
    }

    #[tokio::test]
    async fn wait_resolves_when_signal_fires() {
        let cancel = Cancel::new();
        let waiter = cancel.clone();

        let waiting = tokio::spawn(async move {
            waiter.cancelled().await;
            waiter.reason()
        });

        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel.cancel(Reason::Requested);

        assert_eq!(waiting.await.expect("joined"), Some(Reason::Requested));
    }

    /// The failure a `Notify` would have: a task that starts waiting after
    /// the signal fired must not hang. During shutdown that is every task
    /// spawned last.
    #[tokio::test]
    async fn wait_after_signal_returns_at_once() {
        let cancel = Cancel::new();
        cancel.cancel(Reason::Interrupted);

        let started = Instant::now();

        // Would hang forever if the signal were edge-triggered.
        tokio::time::timeout(Duration::from_millis(100), cancel.cancelled())
            .await
            .expect("must not hang");

        assert!(started.elapsed() < Duration::from_millis(100));
    }

    /// Many waiters, one signal. All of them have to wake, not just the
    /// first.
    #[tokio::test]
    async fn wait_every_waiter_wakes() {
        let cancel = Cancel::new();

        let waiters: Vec<_> = (0..32)
            .map(|_| {
                let cancel = cancel.clone();
                tokio::spawn(async move { cancel.cancelled().await })
            })
            .collect();

        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel.cancel(Reason::Requested);

        for waiter in waiters {
            tokio::time::timeout(Duration::from_millis(500), waiter)
                .await
                .expect("a waiter hung")
                .expect("joined");
        }
    }

    /// Cancel-safety: composing with `select!` must not lose the signal.
    #[tokio::test]
    async fn wait_composes_with_select() {
        let cancel = Cancel::new();
        let worker = cancel.clone();

        let work = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(30)) => "finished",
                () = worker.cancelled() => "stopped",
            }
        });

        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel.cancel(Reason::Interrupted);

        assert_eq!(work.await.expect("joined"), "stopped");
    }

    // -- Deadline ---------------------------------------------------------

    #[tokio::test]
    async fn deadline_stops_run() {
        let cancel = Cancel::new();
        cancel.cancel_after(Duration::from_millis(20));

        tokio::time::timeout(Duration::from_secs(2), cancel.cancelled())
            .await
            .expect("the deadline should have fired");

        assert_eq!(cancel.reason(), Some(Reason::Deadline));
    }

    /// A run that finishes first must not be stopped retroactively by its
    /// own timer.
    #[tokio::test]
    async fn deadline_unelapsed_changes_nothing() {
        let cancel = Cancel::new();
        cancel.cancel_after(Duration::from_secs(30));

        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(!cancel.is_cancelled());
    }

    // -- Budget -----------------------------------------------------------

    #[test]
    fn budget_spent_stops_run() {
        let cancel = Cancel::new();
        let budget = cancel.budget(1000);

        assert!(budget.charge(400));
        assert!(!cancel.is_cancelled());

        assert!(budget.charge(400));
        assert_eq!(budget.remaining(), 200);

        // The charge that reaches the limit stops the run.
        assert!(!budget.charge(200));
        assert!(cancel.is_cancelled());
        assert_eq!(cancel.reason(), Some(Reason::Budget));
    }

    /// The bytes have already arrived by the time they are charged, so
    /// overshooting is counted honestly rather than clamped or refused.
    #[test]
    fn budget_overspend_counted_not_refused() {
        let cancel = Cancel::new();
        let budget = cancel.budget(100);

        assert!(!budget.charge(250));

        assert_eq!(budget.spent(), 250);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(cancel.reason(), Some(Reason::Budget));
    }

    /// Concurrent downloads charge the same budget, so the count has to be
    /// atomic rather than merely shared.
    #[tokio::test]
    async fn budget_charged_correctly_by_concurrent_tasks() {
        let cancel = Cancel::new();
        let budget = cancel.budget(u64::MAX);

        let charging: Vec<_> = (0..64)
            .map(|_| {
                let budget = budget.clone();
                tokio::spawn(async move {
                    for _ in 0..100 {
                        budget.charge(1);
                    }
                })
            })
            .collect();

        for task in charging {
            task.await.expect("joined");
        }

        assert_eq!(budget.spent(), 6400);
    }

    #[test]
    fn budget_shares_one_count_across_clones() {
        let cancel = Cancel::new();
        let budget = cancel.budget(1000);
        let other = budget.clone();

        budget.charge(600);
        other.charge(300);

        assert_eq!(budget.spent(), 900);
        assert_eq!(other.spent(), 900);
    }

    #[test]
    fn reason_each_renders_for_report() {
        for reason in [
            Reason::Interrupted,
            Reason::Deadline,
            Reason::Budget,
            Reason::Aborted,
            Reason::Requested,
        ] {
            assert!(!reason.as_str().is_empty());
            assert!(!reason.describe().is_empty());
            assert_eq!(reason.to_string(), reason.as_str());
        }
    }
}
