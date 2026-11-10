//! How many requests may reach one server at once.
//!
//! One [`Gates`] per configured host, cloned into every capability built
//! from that entry, so a repository manager serving ten repositories still
//! sees at most its configured number of requests:
//!
//! ```text
//!   hosts.nexus (downloads: 4)
//!     |-- capability for /repository/maven-public --+
//!     |-- capability for /repository/npm-proxy -----+-- one counter of 4
//!     '-- additional host {host: nexus} -------------+
//! ```

use std::num::NonZeroUsize;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A cap on simultaneous requests, or none.
///
/// Cloned to share: every clone counts against the same slots.
#[derive(Debug, Clone, Default)]
pub(crate) struct Gate(Option<Arc<Semaphore>>);

impl Gate {
    /// At most `limit` requests at once.
    pub(crate) fn limited(limit: NonZeroUsize) -> Self {
        Self(Some(Arc::new(Semaphore::new(limit.get()))))
    }

    /// Wait for a slot, held until the returned value drops; `None` when
    /// there is no cap.
    pub(crate) async fn enter(&self) -> Option<OwnedSemaphorePermit> {
        let slots = self.0.as_ref()?;

        // The semaphore is never closed, so acquiring cannot fail.
        Arc::clone(slots).acquire_owned().await.ok()
    }
}

/// One server's download and upload caps.
///
/// Counted apart, so an upload never queues behind a walk's reads.
#[derive(Debug, Clone, Default)]
pub(crate) struct Gates {
    downloads: Gate,
    uploads: Gate,
}

impl Gates {
    pub(crate) fn new(downloads: Gate, uploads: Gate) -> Self {
        Self { downloads, uploads }
    }

    /// The cap every read takes: `GET`, `HEAD`, and `exists` alike.
    pub(crate) fn downloads(&self) -> &Gate {
        &self.downloads
    }

    /// The cap every write takes.
    pub(crate) fn uploads(&self) -> &Gate {
        &self.uploads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    const WAIT: Duration = Duration::from_millis(50);

    fn one() -> NonZeroUsize {
        NonZeroUsize::new(1).expect("nonzero")
    }

    #[tokio::test]
    async fn gate_unlimited_never_waits() {
        let gate = Gate::default();

        let first = gate.enter().await;
        let second = tokio::time::timeout(WAIT, gate.enter()).await;

        assert!(first.is_none());
        assert!(second.is_ok(), "an uncapped gate waited");
    }

    #[tokio::test]
    async fn gate_limited_waits_for_release() {
        let gate = Gate::limited(one());

        let held = gate.enter().await;
        let blocked = tokio::time::timeout(WAIT, gate.enter()).await;

        assert!(blocked.is_err(), "a second request passed a full gate");

        drop(held);

        let freed = tokio::time::timeout(WAIT, gate.enter()).await;

        assert!(freed.is_ok(), "the released slot was not reused");
    }

    #[tokio::test]
    async fn gate_clones_share_slots() {
        let gate = Gate::limited(one());
        let clone = gate.clone();

        let _held = gate.enter().await;
        let blocked = tokio::time::timeout(WAIT, clone.enter()).await;

        assert!(blocked.is_err(), "a clone counted apart");
    }

    #[tokio::test]
    async fn gates_count_downloads_and_uploads_apart() {
        let gates = Gates::new(Gate::limited(one()), Gate::limited(one()));

        let _reading = gates.downloads().enter().await;
        let writing = tokio::time::timeout(WAIT, gates.uploads().enter()).await;

        assert!(writing.is_ok(), "an upload waited behind a download");
    }
}
