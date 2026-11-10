//! Which coordinates the walk has already claimed.
//!
//! A *different* kind of cache from `cache::Coalesced`,
//! which is why it lives here rather than beside it. That one remembers
//! **documents**, keyed by URL, so a second fetch is free; this one
//! remembers **decisions**, keyed by coordinate, so a second claim does not
//! happen at all. They share no code, and this one has exactly one
//! consumer -- the spider.
//!
//! The distinction matters for a practical reason: a document cache may
//! evict whatever it likes, because a miss costs a re-fetch. This may not.
//! Forgetting a claim would walk a subtree twice.

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;

use async_trait::async_trait;

use super::Ticket;
use crate::core::error::Result;
use crate::report::{Marked, WalkId, WalkState};

/// Whether a key had been seen before.
///
/// An enum rather than a `bool` so a call site reads as `Seen::Already`
/// instead of `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// This caller is the first, and owns the work.
    First,

    /// Someone got here already.
    Already,
}
/// The set of coordinates the spider has already dealt with.
///
/// A trait rather than a struct because this is the one collection that
/// genuinely scales with the run: an inspection of a large internal
/// repository can reach tens of millions of coordinates, and at some point
/// an in-process set stops being the right answer. A user in that position
/// needs to point the spider at something else -- a key-value store, a
/// database table, a file-backed set -- without the spider knowing the
/// difference.
///
/// [`MemoryVisited`] serves a walk without a report database, and
/// [`DbVisited`] one with: the alternative is a new implementation rather
/// than a reshaping of the spider.
///
/// Asynchronous for the same reason: an in-memory set has no need of it,
/// but a store that answers over a socket does, and retrofitting `async`
/// through the spider later would touch every call site.
///
/// Implementations must tolerate concurrent calls: the whole point is to be
/// consulted from a pool of workers.
#[async_trait]
pub trait Visited: Send + Sync {
    /// Claim a coordinate for the task holding `ticket`.
    ///
    /// Must return [`Seen::First`] to exactly one caller, however many ask
    /// at once -- the spider uses the answer to decide who descends, so a
    /// store that answered `First` twice would spider a subtree twice.
    ///
    /// The ticket lets a store that survives the process withdraw a claim
    /// made by a task that never finished.
    async fn mark(&self, key: &str, ticket: Ticket) -> Result<Seen>;

    /// Whether a coordinate has been claimed, without claiming it.
    #[cfg(test)]
    async fn contains(&self, key: &str) -> Result<bool>;

    /// How many coordinates have been claimed, for tests to check a
    /// store's bookkeeping.
    #[cfg(test)]
    async fn count(&self) -> Result<u64>;
}

/// The in-process visited set.
///
/// Stores a 128-bit fingerprint rather than the coordinate, so a million
/// artifacts cost around 20 MB instead of 150 MB of strings. Collision
/// probability at that scale is negligible, and the consequence of one
/// would be skipping a single artifact rather than anything unsafe.
///
/// A store with room to spare should keep the coordinate itself instead --
/// the fingerprinting here is a concession to memory, not a property of the
/// interface, which is why [`Visited`] passes the coordinate through.
#[derive(Debug, Default)]
pub struct MemoryVisited {
    seen: Mutex<HashSet<u128>>,
}

impl MemoryVisited {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Visited for MemoryVisited {
    async fn mark(&self, key: &str, _ticket: Ticket) -> Result<Seen> {
        let mut seen = self.seen.lock().expect("visited set poisoned");

        Ok(match seen.insert(fingerprint(key)) {
            true => Seen::First,
            false => Seen::Already,
        })
    }

    #[cfg(test)]
    async fn contains(&self, key: &str) -> Result<bool> {
        Ok(self
            .seen
            .lock()
            .expect("visited set poisoned")
            .contains(&fingerprint(key)))
    }

    #[cfg(test)]
    async fn count(&self) -> Result<u64> {
        Ok(self.seen.lock().expect("visited set poisoned").len() as u64)
    }
}

/// The visited set of a walk kept in a report database.
///
/// Keeps the coordinate itself rather than a fingerprint: it is on disk,
/// where the strings cost nothing that matters.
pub struct DbVisited<'a> {
    walks: &'a dyn WalkState,
    walk: WalkId,
}

impl<'a> DbVisited<'a> {
    pub fn new(walks: &'a dyn WalkState, walk: WalkId) -> Self {
        Self { walks, walk }
    }
}

#[async_trait]
impl Visited for DbVisited<'_> {
    async fn mark(&self, key: &str, ticket: Ticket) -> Result<Seen> {
        Ok(match self.walks.mark(self.walk, key, ticket.id())? {
            Marked::First => Seen::First,
            Marked::Already => Seen::Already,
        })
    }

    #[cfg(test)]
    async fn contains(&self, key: &str) -> Result<bool> {
        self.walks.marked(self.walk, key)
    }

    #[cfg(test)]
    async fn count(&self) -> Result<u64> {
        self.walks.marks(self.walk)
    }
}

/// A 128-bit fingerprint, built from two independently salted 64-bit hashes.
pub(super) fn fingerprint(key: &str) -> u128 {
    let half = |salt: u64| {
        let mut hasher = DefaultHasher::new();
        salt.hash(&mut hasher);
        key.hash(&mut hasher);

        hasher.finish()
    };

    (u128::from(half(0)) << 64) | u128::from(half(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::spider::Ticket;
    use std::sync::Arc;

    #[tokio::test]
    async fn claim_exactly_once() {
        let visited = MemoryVisited::new();

        assert_eq!(
            visited
                .mark("pkg:npm/lodash@4.17.21", Ticket::new(0))
                .await
                .unwrap(),
            Seen::First
        );
        assert_eq!(
            visited
                .mark("pkg:npm/lodash@4.17.21", Ticket::new(0))
                .await
                .unwrap(),
            Seen::Already
        );
        assert_eq!(
            visited
                .mark("pkg:npm/lodash@4.17.20", Ticket::new(0))
                .await
                .unwrap(),
            Seen::First
        );

        assert_eq!(visited.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn claim_not_made_by_contains() {
        let visited = MemoryVisited::new();

        assert!(!visited.contains("a").await.unwrap());
        assert_eq!(visited.count().await.unwrap(), 0);

        visited.mark("a", Ticket::new(0)).await.unwrap();
        assert!(visited.contains("a").await.unwrap());
    }

    /// Distinct coordinates must not collide into one, or the spider would
    /// silently skip an artifact.
    #[tokio::test]
    async fn similar_coordinates_stay_distinct() {
        let visited = MemoryVisited::new();

        for key in [
            "pkg:npm/a@1.0.0",
            "pkg:npm/a@1.0.1",
            "pkg:npm/ab@1.0.0",
            "pkg:npm/%40scope/a@1.0.0",
            "pkg:maven/a/b@1.0.0",
        ] {
            assert_eq!(
                visited.mark(key, Ticket::new(0)).await.unwrap(),
                Seen::First,
                "{key}"
            );
        }

        assert_eq!(visited.count().await.unwrap(), 5);
    }

    /// The contract every implementation owes, stated as a test so a later
    /// db-backed store can be run against it: however many workers claim a
    /// coordinate at once, exactly one is told it got there first. A store
    /// that answered `First` twice would spider one subtree twice.
    #[tokio::test]
    async fn claim_concurrent_exactly_one_wins() {
        let visited: Arc<dyn Visited> = Arc::new(MemoryVisited::new());

        let claiming = (0..64).map(|_| {
            let visited = Arc::clone(&visited);
            async move {
                visited
                    .mark("pkg:npm/lodash@4.17.21", Ticket::new(0))
                    .await
                    .unwrap()
            }
        });

        let firsts = futures::future::join_all(claiming)
            .await
            .into_iter()
            .filter(|seen| *seen == Seen::First)
            .count();

        assert_eq!(firsts, 1);
        assert_eq!(visited.count().await.unwrap(), 1);
    }

    /// A spider holds this behind a trait object, so it has to be one.
    #[tokio::test]
    async fn memory_set_usable_as_trait_object() {
        let visited: Box<dyn Visited> = Box::new(MemoryVisited::new());

        assert_eq!(
            visited.mark("a", Ticket::new(0)).await.unwrap(),
            Seen::First
        );
        assert_eq!(
            visited.mark("a", Ticket::new(0)).await.unwrap(),
            Seen::Already
        );
    }

    /// The fingerprint is what bounds the memory, so it has to be stable
    /// and use its whole width.
    #[test]
    fn fingerprint_deterministic_and_wide() {
        assert_eq!(fingerprint("x"), fingerprint("x"));
        assert_ne!(fingerprint("x"), fingerprint("y"));

        // Both halves contribute: a fingerprint whose top half were always
        // zero would be a 64-bit hash wearing a 128-bit coat.
        assert_ne!(fingerprint("x") >> 64, 0);
        assert_ne!(fingerprint("x") & u128::from(u64::MAX), 0);
    }
}
