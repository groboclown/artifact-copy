//! Whether a cached file may still be used, by its recorded times.

use super::{Cache, CachePath, Expiry, Kept, Lifetime, Origin};
use crate::core::error::Result;

/// What a cached file's [`Lifetime`] allows, judged by [`Cache::judge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judged {
    /// Nothing is cached under the name.
    Absent,

    /// Cached with no recorded times, such as a file kept before the index
    /// existed. A caller with its own proof, such as a digest, may use it.
    Undated,

    /// Cached and within both limits.
    Usable,

    /// Cached and past one limit.
    Expired(Expiry),
}

/// Milliseconds since the Unix epoch.
pub(super) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Whether `limit` has passed since `since_ms`. Never, for a limit of
/// forever; always, for a limit of zero, which is how a binding says
/// "fetch every time".
pub(super) fn passed(now_ms: i64, since_ms: i64, limit: Option<std::time::Duration>) -> bool {
    let Some(limit) = limit else {
        return false;
    };

    let limit_ms = i64::try_from(limit.as_millis()).unwrap_or(i64::MAX);

    now_ms.saturating_sub(since_ms) >= limit_ms
}

impl Cache {
    /// Note a use of a cached file, restarting its retention.
    pub fn touch(&self, path: &CachePath, lifetime: &Lifetime) -> Result<()> {
        self.index.touch(path, lifetime, now_ms())
    }

    /// What the index holds about a cached file's times, when it was
    /// recorded and the index can be read.
    pub fn kept(&self, path: &CachePath) -> Option<Kept> {
        self.index.kept(path).ok().flatten()
    }

    /// Where a cached file came from, when it was recorded.
    pub fn origin(&self, path: &CachePath) -> Result<Option<Origin>> {
        self.index.find(path)
    }

    /// Whether the file at `path` may be used under `lifetime`.
    ///
    /// Judged from the recorded times against the lifetime given now, not
    /// against what was recorded with the file, so a changed setting takes
    /// effect on the next run. Retention is checked first: a file past it
    /// should not be here at all.
    pub fn judge(&self, path: &CachePath, lifetime: &Lifetime) -> Judged {
        if self.resolve_existing(path).is_err() {
            return Judged::Absent;
        }

        // An index that cannot be read cannot date the file.
        let Some(times) = self.kept(path) else {
            return Judged::Undated;
        };

        let now = now_ms();

        if passed(now, times.used_ms, lifetime.retention) {
            return Judged::Expired(Expiry::Retention);
        }

        if passed(now, times.fetched_ms, lifetime.freshness) {
            return Judged::Expired(Expiry::Freshness);
        }

        Judged::Usable
    }

    /// Remove a cached file and what the index says about it.
    ///
    /// Writable first: a payload is read-only, and Windows will not remove
    /// a read-only file. Best effort, like every cleanup here; a file that
    /// stays is replaced or reported by whatever writes it next.
    pub fn evict(&self, path: &CachePath) {
        super::budget::delete(&self.resolve(path));

        if let Ok(size) = self.index.forget(path) {
            self.adjust(-i64::try_from(size).unwrap_or(i64::MAX));
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::ext::cache::INDEX_FILE;
    use crate::ext::cache::testing::*;
    use crate::ext::cache::{Cache, CachePath, Expiry, Judged, Lifetime};

    /// A file written and recorded now, under `lifetime`.
    async fn recorded(cache: &Cache, lifetime: &Lifetime) -> CachePath {
        let path = cache.write("doc.json", b"{}").await.expect("written");
        cache
            .record(&path, "h://origin.test/doc", "doc.json", lifetime)
            .expect("recorded");

        path
    }

    #[tokio::test]
    async fn judge_usable_inside_both_limits() {
        let (_dir, cache) = cache();
        let lifetime = Lifetime {
            retention: Some(HOUR),
            freshness: Some(HOUR),
        };
        let path = recorded(&cache, &lifetime).await;

        assert_eq!(cache.judge(&path, &lifetime), Judged::Usable);
    }

    /// A freshness of zero is how a binding says "fetch every time".
    #[tokio::test]
    async fn judge_zero_freshness_expires_at_once() {
        let (_dir, cache) = cache();
        let lifetime = Lifetime {
            retention: None,
            freshness: Some(std::time::Duration::ZERO),
        };
        let path = recorded(&cache, &lifetime).await;

        assert_eq!(
            cache.judge(&path, &lifetime),
            Judged::Expired(Expiry::Freshness)
        );
    }

    /// Retention is checked first: a file past it should not be here at
    /// all, whatever its freshness says.
    #[tokio::test]
    async fn judge_retention_outranks_freshness() {
        let (_dir, cache) = cache();
        let lifetime = Lifetime {
            retention: Some(std::time::Duration::ZERO),
            freshness: Some(std::time::Duration::ZERO),
        };
        let path = recorded(&cache, &lifetime).await;

        assert_eq!(
            cache.judge(&path, &lifetime),
            Judged::Expired(Expiry::Retention)
        );
    }

    /// Judged against the lifetime given now, so a setting changed since
    /// the file was recorded applies at once.
    #[tokio::test]
    async fn judge_uses_current_setting() {
        let (_dir, cache) = cache();
        let path = recorded(&cache, &Lifetime::FOREVER).await;
        let now = Lifetime {
            retention: None,
            freshness: Some(std::time::Duration::ZERO),
        };

        assert_eq!(cache.judge(&path, &now), Judged::Expired(Expiry::Freshness));
    }

    /// **A copy that cannot be dated is not usable as current.** Reading it
    /// as current would pin a stale cache in place; a caller with its own
    /// proof, such as a digest, may still use it.
    #[tokio::test]
    async fn judge_unrecorded_file_undated() {
        let (_dir, cache) = cache();
        let path = cache.write("doc.json", b"{}").await.expect("written");

        assert_eq!(cache.judge(&path, &Lifetime::FOREVER), Judged::Undated);
    }

    #[test]
    fn judge_missing_file_absent() {
        let (_dir, cache) = cache();
        let path = cache.path("doc.json").expect("named");

        assert_eq!(cache.judge(&path, &Lifetime::FOREVER), Judged::Absent);
    }

    /// Eviction removes the file and the index's note of it, read-only or
    /// not.
    #[tokio::test]
    async fn evict_removes_file_and_entry() {
        let (_dir, cache) = cache();
        let path = recorded(&cache, &Lifetime::FOREVER).await;
        read_only(&cache.resolve(&path));

        cache.evict(&path);

        assert_eq!(cache.judge(&path, &Lifetime::FOREVER), Judged::Absent);
        assert_eq!(cache.origin(&path).expect("read"), None);
    }

    #[tokio::test]
    async fn origin_round_trips() {
        let (_dir, cache) = cache();
        let path = cache.payload_path(MAVEN_A, "core-1.0.jar").expect("path");

        assert_eq!(cache.origin(&path).expect("read"), None);

        cache
            .record(&path, MAVEN_A, "core-1.0.jar", &Lifetime::FOREVER)
            .expect("recorded");

        let origin = cache.origin(&path).expect("read").expect("found");

        assert_eq!(origin.url, MAVEN_A);
        assert_eq!(origin.name, "core-1.0.jar");
        assert!(cache.root().join(INDEX_FILE).exists());
    }

    /// The index outlives the process that wrote it.
    #[test]
    fn origin_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("host.example");

        let first = Cache::open(&root).expect("opened");
        let path = first.payload_path(MAVEN_A, "core-1.0.jar").expect("path");
        first
            .record(&path, MAVEN_A, "core-1.0.jar", &Lifetime::FOREVER)
            .expect("recorded");
        drop(first);

        let again = Cache::open(&root).expect("reopened");

        assert!(again.origin(&path).expect("read").is_some());
    }
}
