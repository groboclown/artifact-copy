//! Retrying a request, and deciding whether to.
//!
//! Two halves that meet at one type. A [`Plan`] is a pure function from a
//! failed attempt to a [`Decision`] -- wait this long, or stop -- and a
//! [`RetryingClient`] is the loop that acts on it. Splitting them is what
//! lets the interesting half be tested as arithmetic, with no clock and no
//! server, and the loop be tested against recorded responses rather than a
//! real flaky one.
//!
//! `net` already re-exports the two separately (`RetryPlan` and
//! `RetryingClient`), so nothing outside this module can tell the
//! difference.
//!
//! This module declares nothing of its own.

mod client;
mod plan;

pub use client::RetryingClient;
pub(crate) use plan::retry_at;
pub use plan::{Decision, Outcome, Plan};
