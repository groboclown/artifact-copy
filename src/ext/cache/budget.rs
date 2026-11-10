//! One size cap over every cache under a cache directory.
//!
//! Each host folder keeps its own index, so the total is the sum of theirs,
//! measured once and then kept up to date as files are recorded and
//! removed, rather than summed again on every fetch:
//!
//! ```text
//!   <cache-dir>/
//!     central/index.sqlite     12 GiB  \
//!     npmjs/index.sqlite        3 GiB   } total, against setup.cache-size
//!     pypi/index.sqlite         1 GiB  /
//! ```
//!
//! Over the cap, the least recently used files go first, across every
//! folder, including ones no binding of this run opened. A file a cache of
//! this run is holding -- a payload not yet published -- never goes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use super::index::{Candidate, Index};
use super::{Cache, CachePath, INDEX_FILE, Origin, now_ms};
use crate::core::error::{Error, Result};

/// Candidates read from each folder at a time while making room.
pub(super) const CANDIDATE_BATCH: usize = 256;

/// The shared cap, and the caches of this run that may be holding files.
#[derive(Debug)]
pub struct Budget {
    root: PathBuf,
    limit_bytes: u64,

    /// The live total, measured on first use. `None` until then.
    total: Mutex<Option<u64>>,

    /// Caches opened this run, so their holds are respected.
    caches: Mutex<Vec<Weak<Cache>>>,
}

/// One folder under the root, as eviction sees it.
enum Folder {
    /// Opened by this run: its own index, and its holds.
    Live(Arc<Cache>),

    /// Not opened by this run, so nothing in it is held.
    Idle { dir: PathBuf, index: Index },
}

impl Budget {
    pub fn new(root: impl Into<PathBuf>, limit_bytes: u64) -> Self {
        Self {
            root: root.into(),
            limit_bytes,
            total: Mutex::new(None),
            caches: Mutex::new(Vec::new()),
        }
    }

    /// Count `cache`'s holds when making room.
    pub(super) fn register(&self, cache: &Arc<Cache>) {
        if let Ok(mut caches) = self.caches.lock() {
            caches.push(Arc::downgrade(cache));
        }
    }

    /// Move the running total by `delta` bytes, when it has been measured.
    pub(super) fn adjust(&self, delta: i64) {
        let Ok(mut total) = self.total.lock() else {
            return;
        };

        if let Some(bytes) = total.as_mut() {
            *bytes = bytes.saturating_add_signed(delta);
        }
    }

    /// Remove the least recently used files until the total fits, and
    /// answer what went, each with the folder it was in.
    pub(super) fn trim(&self) -> Result<Vec<(String, Origin)>> {
        let mut total = self.measured()?;

        if total <= self.limit_bytes {
            return Ok(Vec::new());
        }

        let folders = self.folders();
        let mut evicted = Vec::new();

        // A pass that frees nothing means everything left is held.
        while total > self.limit_bytes {
            let freed_before = evicted.len();

            for (at, candidate) in oldest(&folders)? {
                if total <= self.limit_bytes {
                    break;
                }

                let Some(size) = remove(&folders[at], &candidate)? else {
                    continue;
                };

                total = total.saturating_sub(size);
                evicted.push((folder_name(&folders[at]), candidate.origin));
            }

            if evicted.len() == freed_before {
                break;
            }
        }

        if let Ok(mut kept) = self.total.lock() {
            *kept = Some(total);
        }

        Ok(evicted)
    }

    /// The live total, summing every folder's index the first time.
    fn measured(&self) -> Result<u64> {
        let mut total = self
            .total
            .lock()
            .map_err(|_| Error::Config("cache budget: lock poisoned".to_owned()))?;

        if let Some(bytes) = *total {
            return Ok(bytes);
        }

        let mut sum = 0u64;

        for folder in self.folders() {
            sum = sum.saturating_add(match &folder {
                Folder::Live(cache) => cache.index.total()?,
                Folder::Idle { index, .. } => index.total()?,
            });
        }

        *total = Some(sum);

        Ok(sum)
    }

    /// Every folder under the root that keeps an index.
    fn folders(&self) -> Vec<Folder> {
        let live: Vec<Arc<Cache>> = self
            .caches
            .lock()
            .map(|caches| caches.iter().filter_map(Weak::upgrade).collect())
            .unwrap_or_default();

        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };

        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|dir| dir.join(INDEX_FILE).is_file())
            .map(|dir| {
                let real = dir.canonicalize().unwrap_or_else(|_| dir.clone());

                match live.iter().find(|cache| cache.root() == real) {
                    Some(cache) => Folder::Live(Arc::clone(cache)),
                    None => Folder::Idle {
                        index: Index::new(dir.join(INDEX_FILE)),
                        dir,
                    },
                }
            })
            .collect()
    }
}

/// The next candidates across every folder, least recently used first, as
/// (folder position, candidate).
fn oldest(folders: &[Folder]) -> Result<Vec<(usize, Candidate)>> {
    let mut all = Vec::new();

    for (at, folder) in folders.iter().enumerate() {
        let candidates = match folder {
            Folder::Live(cache) => cache.index.oldest(CANDIDATE_BATCH)?,
            Folder::Idle { index, .. } => index.oldest(CANDIDATE_BATCH)?,
        };

        all.extend(candidates.into_iter().map(|candidate| (at, candidate)));
    }

    all.sort_by(|(_, left), (_, right)| {
        (left.used_ms, left.origin.path.as_str()).cmp(&(right.used_ms, right.origin.path.as_str()))
    });

    Ok(all)
}

/// Remove one candidate, answering the size freed; `None` for a file its
/// cache is holding.
fn remove(folder: &Folder, candidate: &Candidate) -> Result<Option<u64>> {
    match folder {
        Folder::Live(cache) => cache.make_room(&candidate.origin.path),
        Folder::Idle { dir, index } => {
            delete(&dir.join(candidate.origin.path.as_path()));

            index.tombstone(&candidate.origin.path, now_ms()).map(Some)
        }
    }
}

/// Remove a file, writable first, since a payload is read-only.
pub(super) fn delete(full: &Path) {
    super::writable(full);

    let _ = std::fs::remove_file(full);
}

fn folder_name(folder: &Folder) -> String {
    let dir = match folder {
        Folder::Live(cache) => cache.root(),
        Folder::Idle { dir, .. } => dir.as_path(),
    };

    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl Cache {
    /// Whether `path`'s file was removed to keep a cache under its size,
    /// rather than lost some other way.
    pub fn tombstoned(&self, path: &CachePath) -> bool {
        self.index.tombstoned(path).unwrap_or(false)
    }

    /// Remove the least recently used files of this folder, none of them
    /// held, until it holds `cap_bytes` or less. Answers what went.
    pub fn trim(&self, cap_bytes: u64) -> Result<Vec<Origin>> {
        let mut total = self.index.total()?;
        let mut evicted = Vec::new();

        while total > cap_bytes {
            let freed_before = evicted.len();

            for candidate in self.index.oldest(CANDIDATE_BATCH)? {
                if total <= cap_bytes {
                    break;
                }

                let Some(size) = self.make_room(&candidate.origin.path)? else {
                    continue;
                };

                total = total.saturating_sub(size);
                evicted.push(candidate.origin);
            }

            // Everything left is held.
            if evicted.len() == freed_before {
                break;
            }
        }

        Ok(evicted)
    }

    /// Remove files across the whole cache directory until it fits
    /// `setup.cache-size`, when one is set. Answers what went, each with
    /// the folder it was in.
    pub fn trim_shared(&self) -> Result<Vec<(String, Origin)>> {
        match &self.budget {
            Some(budget) => budget.trim(),
            None => Ok(Vec::new()),
        }
    }

    /// Remove one file to make room, unless it is held, leaving a
    /// tombstone. Answers the size freed.
    pub(super) fn make_room(&self, path: &CachePath) -> Result<Option<u64>> {
        let held = self
            .holds
            .lock()
            .map(|holds| holds.contains_key(path))
            .unwrap_or(true);

        if held {
            return Ok(None);
        }

        delete(&self.resolve(path));

        let size = self.index.tombstone(path, now_ms())?;
        self.adjust(-i64::try_from(size).unwrap_or(i64::MAX));

        Ok(Some(size))
    }

    /// Move the shared total, when there is one.
    pub(super) fn adjust(&self, delta: i64) {
        if let Some(budget) = &self.budget {
            budget.adjust(delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::cache::testing::*;
    use crate::ext::cache::{Cache, CachePath, Judged, Lifetime};

    use std::sync::Arc;

    /// Write and record `name` with `size` bytes, a few milliseconds after
    /// the last, so least-recently-used order is the order written.
    async fn sized(cache: &Cache, name: &str, size: usize) -> CachePath {
        std::thread::sleep(std::time::Duration::from_millis(3));

        let path = cache.write(name, &vec![0u8; size]).await.expect("written");
        cache
            .record(
                &path,
                &format!("h://origin.test/{name}"),
                name,
                &Lifetime::FOREVER,
            )
            .expect("recorded");

        path
    }

    #[tokio::test]
    async fn trim_removes_least_recent_first() {
        let (_dir, cache) = cache();
        let old = sized(&cache, "old.jar", 100).await;
        let mid = sized(&cache, "mid.jar", 100).await;
        let new = sized(&cache, "new.jar", 100).await;

        let evicted = cache.trim(200).expect("trimmed");

        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].path, old);
        assert_eq!(cache.judge(&old, &Lifetime::FOREVER), Judged::Absent);
        assert_eq!(cache.judge(&mid, &Lifetime::FOREVER), Judged::Usable);
        assert_eq!(cache.judge(&new, &Lifetime::FOREVER), Judged::Usable);
    }

    /// A file this run still needs is never removed, however old.
    #[tokio::test]
    async fn trim_skips_held_files() {
        let (_dir, cache) = cache();
        let old = sized(&cache, "old.jar", 100).await;
        let new = sized(&cache, "new.jar", 100).await;
        let _hold = cache.hold(&old);

        let evicted = cache.trim(100).expect("trimmed");

        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].path, new);
        assert_eq!(cache.judge(&old, &Lifetime::FOREVER), Judged::Usable);
    }

    /// Dropping the hold releases it.
    #[tokio::test]
    async fn hold_dropped_releases() {
        let (_dir, cache) = cache();
        let old = sized(&cache, "old.jar", 100).await;

        drop(cache.hold(&old));

        assert_eq!(cache.trim(0).expect("trimmed").len(), 1);
    }

    /// A file removed for size leaves a tombstone, so a later run knows its
    /// absence was policy; fetching it again clears the tombstone.
    #[tokio::test]
    async fn trim_leaves_tombstone() {
        let (_dir, cache) = cache();
        let old = sized(&cache, "old.jar", 100).await;

        cache.trim(0).expect("trimmed");

        assert!(cache.tombstoned(&old));

        sized(&cache, "old.jar", 100).await;

        assert!(!cache.tombstoned(&old));
    }

    /// `setup.cache-size` spans every folder under the cache directory,
    /// including one no binding of this run opened.
    #[tokio::test]
    async fn budget_spans_folders() {
        let dir = tempfile::tempdir().expect("tempdir");

        // A folder from an earlier run, holding the oldest file.
        let earlier = Cache::open(dir.path().join("earlier")).expect("opened");
        let stale = sized(&earlier, "stale.jar", 100).await;
        drop(earlier);

        let budget = Arc::new(Budget::new(dir.path(), 250));
        let central =
            Cache::open_within(dir.path().join("central"), Arc::clone(&budget)).expect("opened");
        let npm = Cache::open_within(dir.path().join("npm"), Arc::clone(&budget)).expect("opened");

        let held = sized(&central, "held.jar", 100).await;
        let _hold = central.hold(&held);
        let newest = sized(&npm, "newest.tgz", 100).await;

        let evicted = npm.trim_shared().expect("trimmed");
        let names: Vec<&str> = evicted
            .iter()
            .map(|(_, origin)| origin.name.as_str())
            .collect();

        assert_eq!(names, ["stale.jar"]);
        assert_eq!(evicted[0].0, "earlier");
        assert!(!dir.path().join("earlier").join(stale.as_path()).exists());
        assert_eq!(central.judge(&held, &Lifetime::FOREVER), Judged::Usable);
        assert_eq!(npm.judge(&newest, &Lifetime::FOREVER), Judged::Usable);
    }

    /// The running total follows records and evictions, so a second trim
    /// needs no scan to know it fits.
    #[tokio::test]
    async fn budget_total_follows_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let budget = Arc::new(Budget::new(dir.path(), 150));
        let cache =
            Cache::open_within(dir.path().join("central"), Arc::clone(&budget)).expect("opened");

        sized(&cache, "a.jar", 100).await;
        assert!(cache.trim_shared().expect("trimmed").is_empty());

        sized(&cache, "b.jar", 100).await;
        assert_eq!(cache.trim_shared().expect("trimmed").len(), 1);
        assert!(cache.trim_shared().expect("trimmed").is_empty());
    }
}
