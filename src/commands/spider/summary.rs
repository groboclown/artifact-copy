//! What a walk did, and how the workers add it up.
//!
//! **Counts only.** An inspection can reach millions of artifacts, so nothing a
//! walk returns may grow with the size of the graph -- which is why
//! [`Summary`] holds only numbers and no collection, and why the artifacts
//! themselves go to a [`Visitor`](super::Visitor) as they are found.
//!
//! [`Tally`] is the same numbers as atomics, because the workers of
//! one walk share them. It exists separately so that `Summary` stays a plain
//! value a caller can copy, compare and serialize.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::core::cancel::Reason;

/// What a walk did.
///
/// Counts only. Nothing here grows with the size of the graph.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Artifacts handed to the visitor.
    pub emitted: u64,

    /// Artifacts another edge had already claimed.
    ///
    /// The measure of how much the visited set saved: in npm this routinely
    /// exceeds `emitted` several times over.
    pub already_seen: u64,

    /// Artifacts dropped because resolving them failed.
    pub skipped: u64,

    /// Artifacts resolved, then refused by a problem's disposition.
    ///
    /// Apart from `skipped` because the two are different answers to a
    /// user asking why something is missing: one could not be found, the
    /// other was found and deliberately not taken.
    pub refused: u64,

    /// Subtrees abandoned, by `stop-spider`, by the depth limit, or by a
    /// full frontier.
    pub pruned: u64,

    /// Tasks dropped because the frontier was full.
    ///
    /// Also counted in `pruned`. Apart because the remedy differs: a full
    /// in-memory frontier asks for a report database, not a smaller graph.
    pub overflowed: u64,

    /// How deep the walk actually went.
    pub depth_reached: usize,

    /// Why the walk ended early, if it did.
    ///
    /// A stop is **not** an error: the artifacts already emitted are real,
    /// and the caller still has to write its report's trailing summary.
    /// Returning `Err` the moment an interrupt arrived would turn "the user
    /// pressed Ctrl-C" into "the report is truncated and you cannot tell
    /// how far it got".
    pub stopped: Option<Reason>,
}

impl Summary {
    /// Everything the walk actually looked at.
    pub fn processed(&self) -> u64 {
        self.emitted + self.already_seen + self.skipped + self.refused
    }

    pub fn was_stopped(&self) -> bool {
        self.stopped.is_some()
    }

    /// Fold another batch's walk into this one.
    ///
    /// A root set too large to hold is walked a batch at a time, and a
    /// caller wants one answer for the run rather than one per batch. The
    /// counts add; the depth is the deepest any batch reached, not their
    /// sum; and the **first** stop wins, because a later batch stopping for
    /// the same reason says nothing the first did not.
    pub fn absorb(&mut self, other: Summary) {
        self.emitted += other.emitted;
        self.already_seen += other.already_seen;
        self.skipped += other.skipped;
        self.refused += other.refused;
        self.pruned += other.pruned;
        self.overflowed += other.overflowed;
        self.depth_reached = self.depth_reached.max(other.depth_reached);
        self.stopped = self.stopped.or(other.stopped);
    }
}

/// Counters shared by the workers of one walk.
#[derive(Debug, Default)]
pub(super) struct Tally {
    pub(super) emitted: AtomicU64,
    pub(super) already_seen: AtomicU64,
    pub(super) skipped: AtomicU64,
    pub(super) refused: AtomicU64,
    pub(super) pruned: AtomicU64,
    pub(super) overflowed: AtomicU64,

    /// Tasks pruned at the depth limit, reported once at the end.
    pub(super) beyond_depth: AtomicU64,

    pub(super) depth: AtomicUsize,
}

impl Tally {
    pub(super) fn into_summary(self, stopped: Option<Reason>) -> Summary {
        Summary {
            emitted: self.emitted.load(Ordering::SeqCst),
            already_seen: self.already_seen.load(Ordering::SeqCst),
            skipped: self.skipped.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
            pruned: self.pruned.load(Ordering::SeqCst),
            overflowed: self.overflowed.load(Ordering::SeqCst),
            depth_reached: self.depth.load(Ordering::SeqCst),
            stopped,
        }
    }
}
