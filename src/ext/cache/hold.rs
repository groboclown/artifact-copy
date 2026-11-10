//! Keeping a cached file from eviction, and one writer per path.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::{Cache, CachePath, writable};

/// How many holds each path has, shared by a cache and its [`Hold`]s.
pub(super) type Holds = Arc<Mutex<BTreeMap<CachePath, usize>>>;

/// One lock per path in use, shared by a cache and its [`Hold`]s.
pub(super) type Locks = Arc<Mutex<BTreeMap<CachePath, Arc<tokio::sync::Mutex<()>>>>>;

/// A cached file kept from size eviction while this lives.
///
/// Taken by whatever still needs a file it fetched: a payload until it is
/// published, a corpus until it is read. Released on drop.
#[derive(Debug)]
pub struct Hold {
    holds: Holds,
    locks: Locks,
    path: CachePath,
}

impl Clone for Hold {
    fn clone(&self) -> Self {
        add_hold(&self.holds, &self.path);

        Self {
            holds: Arc::clone(&self.holds),
            locks: Arc::clone(&self.locks),
            path: self.path.clone(),
        }
    }
}

impl Hold {
    /// Release this hold, and remove the file at `full` -- this hold's
    /// path, resolved -- when nothing else holds it.
    ///
    /// Under the path's lock, so a task about to reuse the file for the
    /// same URL either sees it held or finds it gone, never removed under
    /// it. A file another task still holds stays: two artifacts may share
    /// one payload, such as a POM that is a jar's and a parent's.
    pub async fn discard(self, full: &Path) {
        let _locked = lock_path(&self.locks, &self.path).await;

        let alone = self
            .holds
            .lock()
            .map(|holds| holds.get(&self.path).copied().unwrap_or_default() <= 1)
            .unwrap_or(false);

        if alone {
            writable(full);

            let _ = std::fs::remove_file(full);
        }
    }
}

/// Exclusive use of one cached path while this lives: a writer checking,
/// replacing, or removing the file there. See [`Cache::lock`].
pub struct PathLock {
    locks: Locks,
    path: CachePath,
    mutex: Arc<tokio::sync::Mutex<()>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for PathLock {
    /// Released, and forgotten once no other task waits on it, so the map
    /// holds only paths in use rather than every path a run touched.
    fn drop(&mut self) {
        self.guard.take();

        let Ok(mut locks) = self.locks.lock() else {
            return;
        };

        // The map's reference and this one: nobody else waits.
        if Arc::strong_count(&self.mutex) == 2 {
            locks.remove(&self.path);
        }
    }
}

/// Wait for, and take, `path`'s lock.
pub(super) async fn lock_path(locks: &Locks, path: &CachePath) -> PathLock {
    let mutex = match locks.lock() {
        Ok(mut map) => Arc::clone(map.entry(path.clone()).or_default()),

        // A poisoned map still serializes nothing worse than before: this
        // task proceeds on a lock of its own.
        Err(_) => Arc::default(),
    };

    let guard = Arc::clone(&mutex).lock_owned().await;

    PathLock {
        locks: Arc::clone(locks),
        path: path.clone(),
        mutex,
        guard: Some(guard),
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let Ok(mut holds) = self.holds.lock() else {
            return;
        };

        let Some(count) = holds.get_mut(&self.path) else {
            return;
        };

        *count -= 1;

        if *count == 0 {
            holds.remove(&self.path);
        }
    }
}

pub(super) fn add_hold(holds: &Holds, path: &CachePath) {
    if let Ok(mut holds) = holds.lock() {
        *holds.entry(path.clone()).or_default() += 1;
    }
}

impl Cache {
    /// Keep `path` from size eviction until the hold is dropped.
    pub fn hold(&self, path: &CachePath) -> Hold {
        add_hold(&self.holds, path);

        Hold {
            holds: Arc::clone(&self.holds),
            locks: Arc::clone(&self.locks),
            path: path.clone(),
        }
    }

    /// Whether a task of this run still needs `path`'s file.
    pub fn is_held(&self, path: &CachePath) -> bool {
        self.holds
            .lock()
            .map(|holds| holds.contains_key(path))
            .unwrap_or(false)
    }

    /// Exclusive use of `path` until the returned lock drops.
    ///
    /// For whatever checks a file and then replaces or removes it: two
    /// tasks fetching one URL would otherwise each evict and rewrite the
    /// other's copy. The second waits, and then finds the first's.
    pub(crate) async fn lock(&self, path: &CachePath) -> PathLock {
        lock_path(&self.locks, path).await
    }
}

#[cfg(test)]
mod tests {

    use crate::ext::cache::testing::*;

    /// A discarded payload another task still holds stays; the last
    /// holder's discard removes it.
    #[tokio::test]
    async fn discard_spares_shared_file() {
        let (_dir, cache) = cache();
        let path = cache.write("shared.pom", b"pom").await.expect("written");
        let full = cache.resolve(&path);

        let first = cache.hold(&path);
        let second = cache.hold(&path);

        first.discard(&full).await;
        assert!(full.exists(), "the other holder still needs it");

        second.discard(&full).await;
        assert!(!full.exists());
        assert!(!cache.is_held(&path));
    }
}
