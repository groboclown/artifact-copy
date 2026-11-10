//! Where a walk was cut short, reported so a reader knows what it missed.

use std::sync::atomic::Ordering;

use super::summary::Tally;

use crate::core::cancel::Reason;
use crate::core::ctx::Ctx;
use crate::core::problem::Code;
use crate::message;

use super::Spider;

impl Spider {
    /// Say why the walk stopped, and how much was left.
    ///
    /// Reported at the code's own severity rather than forced: an
    /// interrupt is not a new failure, and the run's exit code already
    /// reflects whatever stopped it.
    pub(super) fn report_stopped(&self, reason: Reason, remaining: u64, ctx: &Ctx) {
        ctx.report(
            Code::Aborted,
            message!(
                "spider-stopped",
                "stopped after {reason}, leaving {remaining} artifacts unexplored",
                reason = reason.describe(),
                remaining = remaining,
            ),
        );
    }

    /// Say what the depth limit and a full frontier dropped.
    ///
    /// Once per walk rather than once per task: a wide level past the
    /// limit would otherwise bury the report in identical lines.
    pub(super) fn report_pruned(&self, tally: &Tally, ctx: &Ctx) {
        let beyond = tally.beyond_depth.load(Ordering::SeqCst);

        if beyond > 0 {
            self.report_depth_limit(beyond, ctx);
        }

        let overflowed = tally.overflowed.load(Ordering::SeqCst);

        if overflowed > 0 {
            report_queue_full(overflowed, ctx);
        }
    }

    pub(super) fn report_depth_limit(&self, pruned: u64, ctx: &Ctx) {
        ctx.report(
            Code::DependencyUnresolved,
            message!(
                "spider-depth-limit",
                "stopped at {depth} levels of dependencies, leaving {pruned} \
                 unexplored; a graph this deep usually means a cycle",
                depth = self.max_depth,
                pruned = pruned,
            ),
        );
    }
}

/// Say that the frontier ran out of room.
///
/// Under the code the depth limit uses, because the consequence is the
/// same: dependencies that were never looked at.
pub(super) fn report_queue_full(dropped: u64, ctx: &Ctx) {
    ctx.report(
        Code::DependencyUnresolved,
        message!(
            "spider-queue-full",
            "the work queue was full, leaving {dropped} dependencies \
             unexplored; raise setup.maximum-in-memory-queued-dependencies or run \
             without --db=- to queue on disk",
            dropped = dropped,
        ),
    );
}
