//! Not fetching the same document twice.
//!
//! Dependency inspection converges hard. In npm especially one package sits
//! under thousands of others, and because this tool resolves the *highest*
//! matching version rather than the most compatible one, the same document
//! is reached again and again from different directions.
//!
//! Two distinct problems, and an ordinary cache solves only one:
//!
//! - **Work already finished.** [`Coalesced`] remembers the result, so the
//!   second request for a packument is free.
//! - **Work already underway.** With a pool of workers a plain cache is
//!   check-then-fetch: a hundred tasks miss together and a hundred requests
//!   go out for one document. [`Coalesced`] makes the first caller fetch
//!   and the rest *wait on that same fetch*.
//!
//! The second is what bites under concurrency, and it is invisible in a
//! single-threaded test -- which is why the tests here deliberately delay
//! the fixture so the overlap is real.
//!
//! Every holder keys this by URL. Remembering which *coordinates* a walk
//! has claimed is a different job with different rules, and lives in
//! [`crate::commands::spider::visited`]: a document cache may evict whatever it
//! likes, because a miss costs a re-fetch, and a claim set may not.

use std::sync::{Arc, Mutex};

use tokio::sync::OnceCell;

use crate::core::error::Result;

/// How many completed results to keep.
///
/// Bounded deliberately: an inspection walks millions of artifacts, and a
/// map keyed by coordinate would grow with the inspection. In-flight entries
/// are not counted against this, because their number is bounded by the
/// worker pool anyway.
const DEFAULT_CAPACITY: usize = 256;

/// A keyed cache that also collapses concurrent misses.
///
/// Nothing partial is ever kept. A fetch that fails, or that is dropped
/// part-way because the run is stopping, leaves the slot empty rather than
/// caching half an answer -- so a later attempt re-fetches and can end with
/// a good cached copy. The empty slot itself is reclaimed on the next
/// eviction, which is what keeps a long run of failures from growing this
/// list.
///
/// Errors are **not** cached, and are **not** shared. A transient failure
/// must not poison a coordinate for the rest of the run, nor fail every
/// task that happened to be waiting on it -- so a failed attempt hands the
/// work to the next waiter, which tries again. Attempts are serialized, so
/// a struggling host still sees one request at a time rather than one per
/// waiter. Success is shared; failure is not.
pub struct Coalesced<V> {
    slots: Mutex<Slots<V>>,
    capacity: usize,
}

/// Keyed cells, most recently used last.
///
/// A cell rather than a value, because a slot is claimed before the work
/// finishes -- that is what lets a second caller find and wait on a fetch
/// that is still in flight.
type Slots<V> = Vec<(String, Arc<OnceCell<Arc<V>>>)>;

impl<V> std::fmt::Debug for Coalesced<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coalesced")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<V> Default for Coalesced<V> {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl<V> Coalesced<V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            capacity: capacity.max(1),
        }
    }

    /// Fetch once, however many callers ask at once.
    ///
    /// The first caller for a key runs `init`; everyone else awaits its
    /// result. If `init` fails, the slot is left empty so a later caller
    /// retries rather than inheriting the failure.
    pub async fn get_or_try_init<F, Fut>(&self, key: &str, init: F) -> Result<Arc<V>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<V>>,
    {
        let cell = self.slot(key);

        // Awaited outside the lock: holding a std mutex across an await
        // would serialize every key against every other, which is the
        // opposite of the point.
        let value = cell
            .get_or_try_init(|| async { init().await.map(Arc::new) })
            .await?;

        Ok(Arc::clone(value))
    }

    /// The value for a key, if it is already known.
    ///
    /// Only tests ask this. Production code calls `get_or_try_init`, which
    /// is the whole point of the type -- asking whether something is cached
    /// and then fetching it is the race this collapses.
    #[cfg(test)]
    pub fn peek(&self, key: &str) -> Option<Arc<V>> {
        let slots = self.slots.lock().expect("cache poisoned");

        slots
            .iter()
            .find(|(candidate, _)| candidate == key)
            .and_then(|(_, cell)| cell.get())
            .map(Arc::clone)
    }

    /// Find or create the slot for a key.
    fn slot(&self, key: &str) -> Arc<OnceCell<Arc<V>>> {
        let mut slots = self.slots.lock().expect("cache poisoned");

        if let Some(index) = slots.iter().position(|(candidate, _)| candidate == key) {
            // Most recently used goes last, so eviction takes from the front.
            let entry = slots.remove(index);
            let cell = Arc::clone(&entry.1);
            slots.push(entry);

            return cell;
        }

        self.evict(&mut slots);

        let cell = Arc::new(OnceCell::new());
        slots.push((key.to_owned(), Arc::clone(&cell)));

        cell
    }

    /// Make room, without ever discarding work in progress.
    ///
    /// Three kinds of slot live here and they are not interchangeable:
    ///
    /// - **Abandoned** -- nothing filled it and nobody is waiting on it. The
    ///   residue of a fetch that failed or was interrupted. Reclaimed
    ///   first, because it is pure waste; leaving it would let an
    ///   inspection that meets a million 404s grow this list by a million
    ///   entries, which is precisely the unbounded growth the memory
    ///   discipline forbids.
    /// - **Completed** -- a cached value. Reclaimed next, oldest first.
    /// - **In flight** -- someone is awaiting it. Never reclaimed: dropping
    ///   one would send its waiters off to fetch the same thing again,
    ///   which is the duplication this type exists to prevent. If every
    ///   slot is in flight the cache runs briefly over capacity, bounded by
    ///   the worker pool.
    ///
    /// The three are told apart by reference count: a slot nobody holds but
    /// this list is one nobody is waiting on. The count is read under the
    /// same lock that hands slots out, so there is no window in which an
    /// in-flight slot looks abandoned.
    fn evict(&self, slots: &mut Slots<V>) {
        if slots.len() < self.capacity {
            return;
        }

        let abandoned = slots
            .iter()
            .position(|(_, cell)| !cell.initialized() && Arc::strong_count(cell) == 1);

        if let Some(index) =
            abandoned.or_else(|| slots.iter().position(|(_, cell)| cell.initialized()))
        {
            slots.remove(index);
        }
    }

    /// How many slots are held.
    ///
    /// Only tests ask this, and what they are really asking is whether
    /// eviction kept the bound.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.lock().expect("cache poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::core::error::Error;

    /// Counts how many times the work actually ran.
    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Counter {
        fn bump(&self) -> usize {
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        }

        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn request_second_reuses_first_result() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        for _ in 0..3 {
            let value = cache
                .get_or_try_init("k", || async {
                    runs.bump();
                    Ok("value".to_owned())
                })
                .await
                .expect("initialized");

            assert_eq!(*value, "value");
        }

        assert_eq!(runs.count(), 1);
    }

    /// The property that matters under a worker pool, and the one a
    /// single-threaded test cannot show: the work is *delayed*, so the
    /// callers genuinely overlap rather than arriving one after another.
    #[tokio::test]
    async fn fetch_shared_by_concurrent_callers() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        let waiting = (0..50).map(|_| {
            cache.get_or_try_init("lodash", || async {
                runs.bump();
                tokio::time::sleep(Duration::from_millis(20)).await;

                Ok("packument".to_owned())
            })
        });

        let results = futures::future::join_all(waiting).await;

        assert_eq!(results.len(), 50);
        assert!(results.iter().all(|result| result.is_ok()));

        // Fifty callers, one request.
        assert_eq!(runs.count(), 1);
    }

    /// A transient failure must not poison a coordinate for the rest of the
    /// run: caching the error would turn one blip into a permanent gap.
    #[tokio::test]
    async fn failure_not_remembered() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        let attempt = || async {
            cache
                .get_or_try_init("k", || async {
                    match runs.bump() {
                        1 => Err(Error::Config("a blip".into())),
                        _ => Ok("recovered".to_owned()),
                    }
                })
                .await
        };

        assert!(attempt().await.is_err());

        let value = attempt().await.expect("the retry succeeds");
        assert_eq!(*value, "recovered");
        assert_eq!(runs.count(), 2);
    }

    /// A failure does not become everyone's failure.
    ///
    /// Waiters are handed the work one at a time rather than all being
    /// failed together, so a blip that hits the first caller costs one
    /// retry and not a whole subtree of the dependency graph. The host
    /// still sees one request at a time -- serialized, never a herd.
    #[tokio::test]
    async fn failure_retried_by_next_waiter_not_shared() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        let waiting = (0..10).map(|_| {
            cache.get_or_try_init("k", || async {
                let attempt = runs.bump();
                tokio::time::sleep(Duration::from_millis(5)).await;

                match attempt {
                    1 => Err(Error::Config("a blip".into())),
                    _ => Ok("recovered".to_owned()),
                }
            })
        });

        let results = futures::future::join_all(waiting).await;
        let recovered = results.iter().filter(|result| result.is_ok()).count();

        // One caller wore the failure; the other nine got the value, and
        // only two requests were made for the ten of them.
        assert_eq!(recovered, 9);
        assert_eq!(runs.count(), 2);
    }

    /// The flip side of retrying: a key that is failing persistently must
    /// not be attempted once per waiter *concurrently*. Attempts are
    /// serialized, so a struggling host sees one request at a time.
    #[tokio::test]
    async fn failure_persistent_attempted_serially() {
        let cache: Coalesced<String> = Coalesced::default();
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let waiting = (0..10).map(|_| {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);

            cache.get_or_try_init("k", move || async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);

                tokio::time::sleep(Duration::from_millis(2)).await;
                live.fetch_sub(1, Ordering::SeqCst);

                Err(Error::Config("down".into()))
            })
        });

        let results = futures::future::join_all(waiting).await;

        assert!(results.iter().all(|result| result.is_err()));
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keys_distinct_do_not_block_each_other() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        let waiting = ["a", "b", "c"].map(|key| {
            cache.get_or_try_init(key, || async {
                runs.bump();
                tokio::time::sleep(Duration::from_millis(20)).await;

                Ok(key.to_owned())
            })
        });

        let started = std::time::Instant::now();
        futures::future::join_all(waiting).await;

        assert_eq!(runs.count(), 3);

        // Concurrent, not serial: three 20 ms fetches in well under 60 ms.
        assert!(started.elapsed() < Duration::from_millis(55));
    }

    /// An inspection walks millions of coordinates, so the cache must not
    /// grow with it.
    #[tokio::test]
    async fn eviction_completed_entries_once_full() {
        let cache: Coalesced<usize> = Coalesced::new(4);

        for index in 0..20 {
            cache
                .get_or_try_init(&index.to_string(), || async move { Ok(index) })
                .await
                .expect("initialized");
        }

        assert_eq!(cache.slots.lock().unwrap().len(), 4);

        // The oldest are gone; the most recent are kept.
        assert!(cache.peek("0").is_none());
        assert!(cache.peek("19").is_some());
    }

    /// Evicting an in-flight slot would send its waiters off to fetch the
    /// same thing again -- the exact duplication this type prevents.
    #[tokio::test]
    async fn eviction_never_in_flight_entry() {
        let cache: Arc<Coalesced<String>> = Arc::new(Coalesced::new(2));
        let runs = Arc::new(Counter::default());

        let slow = {
            let cache = Arc::clone(&cache);
            let runs = Arc::clone(&runs);

            async move {
                cache
                    .get_or_try_init("slow", || async {
                        runs.bump();
                        tokio::time::sleep(Duration::from_millis(40)).await;

                        Ok("done".to_owned())
                    })
                    .await
            }
        };

        // While `slow` is in flight, churn enough other keys to overrun the
        // capacity several times.
        let churn = {
            let cache = Arc::clone(&cache);

            async move {
                tokio::time::sleep(Duration::from_millis(5)).await;

                for index in 0..10 {
                    let _ = cache
                        .get_or_try_init(&format!("other-{index}"), || async move {
                            Ok(index.to_string())
                        })
                        .await;
                }

                // Now join the slow fetch that has been running throughout.
                cache
                    .get_or_try_init("slow", || async {
                        panic!("the in-flight fetch was evicted and re-run");
                    })
                    .await
            }
        };

        let (first, second) = futures::future::join(slow, churn).await;

        assert_eq!(*first.expect("completed"), "done");
        assert_eq!(*second.expect("joined"), "done");
        assert_eq!(runs.count(), 1);
    }

    /// The bug this guards: an abandoned slot that `evict` could never
    /// reclaim. An inspection meeting a million 404s would have grown the
    /// list by a million entries -- unbounded growth keyed by artifact count.
    #[tokio::test]
    async fn failure_does_not_grow_cache() {
        let cache: Coalesced<String> = Coalesced::new(4);

        for index in 0..500 {
            let _ = cache
                .get_or_try_init(&format!("missing-{index}"), || async {
                    Err(Error::Config("404".into()))
                })
                .await;
        }

        assert!(cache.len() <= 4, "grew to {}", cache.len());
    }

    /// Nothing partial is kept, so a later attempt can still end with a
    /// good cached copy -- which is the whole point of not caching the
    /// failure.
    #[tokio::test]
    async fn failure_later_attempt_still_caches_good_copy() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        let attempt = || async {
            cache
                .get_or_try_init("k", || async {
                    match runs.bump() {
                        1 => Err(Error::Config("the pipe closed early".into())),
                        _ => Ok("complete".to_owned()),
                    }
                })
                .await
        };

        assert!(attempt().await.is_err());
        assert!(
            cache.peek("k").is_none(),
            "a failure must leave nothing behind"
        );

        assert_eq!(*attempt().await.expect("recovered"), "complete");
        assert_eq!(*cache.peek("k").expect("now cached"), "complete");

        // And the good copy really is cached, rather than re-fetched.
        attempt().await.expect("cached");
        assert_eq!(runs.count(), 2);
    }

    /// An interrupted fetch is dropped where it stands -- no `?` runs, no
    /// error is returned. The slot must still come out empty, or the
    /// coordinate would be poisoned for the rest of the run.
    #[tokio::test]
    async fn fetch_interrupted_caches_nothing() {
        let cache: Coalesced<String> = Coalesced::default();
        let runs = Counter::default();

        // Dropped part-way, exactly as `select!` drops a losing branch.
        {
            let fetching = cache.get_or_try_init("k", || async {
                runs.bump();
                tokio::time::sleep(Duration::from_secs(30)).await;

                Ok("never finishes".to_owned())
            });

            assert!(
                tokio::time::timeout(Duration::from_millis(20), fetching)
                    .await
                    .is_err(),
                "the fetch should still have been running"
            );
        }

        assert!(cache.peek("k").is_none());

        // And the coordinate is still usable afterwards: the slot was left
        // empty rather than claimed, so this closure actually runs.
        let value = cache
            .get_or_try_init("k", || async {
                runs.bump();
                Ok("complete".to_owned())
            })
            .await
            .expect("initialized");

        assert_eq!(*value, "complete");
        assert_eq!(runs.count(), 2, "the second attempt should have run");
    }

    /// Reclaiming must never take a slot somebody is waiting on, however
    /// much pressure the cache is under.
    #[tokio::test]
    async fn eviction_never_in_flight_slot_under_pressure() {
        let cache: Arc<Coalesced<String>> = Arc::new(Coalesced::new(2));
        let runs = Arc::new(Counter::default());

        let slow = {
            let cache = Arc::clone(&cache);
            let runs = Arc::clone(&runs);

            async move {
                cache
                    .get_or_try_init("slow", || async {
                        runs.bump();
                        tokio::time::sleep(Duration::from_millis(40)).await;

                        Ok("done".to_owned())
                    })
                    .await
            }
        };

        // Churn failures -- the very entries eviction now prefers -- while
        // the slow fetch is in flight.
        let churn = {
            let cache = Arc::clone(&cache);

            async move {
                tokio::time::sleep(Duration::from_millis(5)).await;

                for index in 0..50 {
                    let _ = cache
                        .get_or_try_init(&format!("dead-{index}"), || async {
                            Err(Error::Config("gone".into()))
                        })
                        .await;
                }

                cache
                    .get_or_try_init("slow", || async {
                        panic!("the in-flight fetch was evicted and re-run")
                    })
                    .await
            }
        };

        let (first, second) = futures::future::join(slow, churn).await;

        assert_eq!(*first.expect("completed"), "done");
        assert_eq!(*second.expect("joined"), "done");
        assert_eq!(runs.count(), 1);
    }
}
