//! What a host downloaded, kept between runs.
//!
//! A cache sits at `<setup.cache-dir>/<host>`, and the name is derived from
//! the host and its path alone -- no run id, no process id -- so the
//! directory and everything in it **survives between runs**. That is what
//! makes it the place a large, slowly-changing download belongs: an OSV
//! corpus is a few hundred megabytes, and fetching it once per invocation
//! is the difference between a tool somebody uses and one they do not.
//!
//! Nothing may **rely** on anything being here: a cold cache, a cleared
//! `cache-dir`, and a first run all look the same, so a missing file must
//! always be answerable by fetching. What a caller *may* do is **use** what
//! it finds, which is what [`Cache::staged`] is for.
//!
//! Keyed per host because that is what a cache of somebody else's content
//! has to be keyed by: two sources on one registry are fetching from one
//! place, and a file under one host's directory says nothing about another
//! host that happens to serve the same path.
//!
//! # Payloads
//!
//! An artifact's file is kept under a hash of its URL, not under its name:
//! two artifacts on one host may share a file name (`core-1.0.jar` from two
//! Maven groups), and a URL is unique within a host. Two levels of shards
//! keep any one directory small; a million payloads is about fifteen per
//! leaf directory. The file keeps its own name, for anything that reads it.
//!
//! ```text
//!   sha256(url) = 3fa2...e1
//!   3f/a2/3fa2...e1/tuna-1.0.0.tgz
//! ```
//!
//! Each file's URL, and when it was fetched and last used, is noted in a
//! SQLite index beside the shards; see [`index`]. What those times allow is
//! a [`Lifetime`], judged by [`Cache::judge`].
//!
//! # Documents
//!
//! An inventory document -- a `maven-metadata.xml`, a packument, a simple
//! page -- is kept under `documents/`, hashed by its URL and the media type
//! it was asked for, so the same URL asked for as HTML and as JSON keeps two
//! copies, and a document can never land on a payload of the same URL.
//!
//! Names go through [`Cache::path`], which refuses anything that leaves the
//! directory. Built-ins are Rust code in this process and could write
//! anywhere; this makes the safe thing the easy thing rather than
//! pretending it is a jail. Confining an out-of-process extension to its
//! own scratch directory is the gearing's job, not this one's.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::error::{Error, Result};

mod budget;
mod fs;
mod hold;
mod index;
mod judge;
mod lifetime;
mod paths;
#[cfg(test)]
mod testing;

pub use budget::Budget;
pub(crate) use fs::writable;
pub use hold::Hold;
pub use index::{Kept, Origin};
pub use judge::Judged;
pub(super) use lifetime::wildcard;
pub use lifetime::{CachePolicy, Expiry, FreshnessRule, Lifetime};
pub use paths::CachePath;

use fs::writable_tree;
use hold::{Holds, Locks};
use judge::now_ms;

/// The cache index, at the cache root. Never a cached file's own path,
/// since every one sits under a shard directory.
const INDEX_FILE: &str = "index.sqlite";

/// A file found in a cache.
///
/// Whether it may be used instead of fetching is a separate question,
/// answered by [`Cache::judge`].
#[derive(Debug, Clone)]
pub struct Staged {
    path: CachePath,
}

impl Staged {
    pub fn path(&self) -> &CachePath {
        &self.path
    }

    pub fn into_path(self) -> CachePath {
        self.path
    }
}

/// Which size cap a file was removed to keep a cache under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// The binding's own `cache-size`, over its repository's folder.
    Repository,

    /// `setup.cache-size`, over the whole cache directory.
    CacheDir,
}

impl Bound {
    /// The spelling a report records as the `reason` argument.
    pub fn as_str(self) -> &'static str {
        match self {
            Bound::Repository => "repository",
            Bound::CacheDir => "cache-dir",
        }
    }
}

/// One invocation's working directory.
#[derive(Debug)]
pub struct Cache {
    root: PathBuf,
    index: index::Index,

    /// Files this run still needs, which size eviction leaves alone.
    holds: Holds,

    /// Paths a task is checking, writing, or removing; see [`Cache::lock`].
    locks: Locks,

    /// The cap over the whole cache directory, when one is configured.
    budget: Option<Arc<Budget>>,
}

impl Cache {
    /// Open a cache at `root`, creating it if needed.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();

        std::fs::create_dir_all(&root).map_err(|source| Error::WriteFile {
            path: root.clone(),
            source,
        })?;

        // Canonicalized once, so the containment check below compares
        // against a path with no symlinks of its own left in it.
        let root = root
            .canonicalize()
            .map_err(|source| Error::ReadFile { path: root, source })?;

        let index = index::Index::new(root.join(INDEX_FILE));

        Ok(Self {
            root,
            index,
            holds: Arc::default(),
            locks: Arc::default(),
            budget: None,
        })
    }

    /// Open a cache at `root` that counts against `budget`.
    pub fn open_within(root: impl Into<PathBuf>, budget: Arc<Budget>) -> Result<Arc<Self>> {
        let mut cache = Self::open(root)?;
        cache.budget = Some(Arc::clone(&budget));

        let cache = Arc::new(cache);
        budget.register(&cache);

        Ok(cache)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Note a file just fetched into the cache, starting both clocks and
    /// counting its size.
    pub fn record(
        &self,
        path: &CachePath,
        url: &str,
        name: &str,
        lifetime: &Lifetime,
    ) -> Result<()> {
        let origin = Origin {
            path: path.clone(),
            url: url.to_owned(),
            name: name.to_owned(),
        };
        let size_bytes = std::fs::metadata(self.resolve(path))
            .map(|found| found.len())
            .unwrap_or_default();

        let grew = self.index.record(&origin, lifetime, size_bytes, now_ms())?;
        self.adjust(grew);

        Ok(())
    }

    /// Write a cached file whole or not at all.
    ///
    /// Written beside its name and renamed into place, so a run killed part
    /// way never leaves a file that looks complete -- which a later run
    /// would otherwise judge by the times of the copy it replaced.
    ///
    /// **Each writer has its own partial file.** Two tasks fetching one URL
    /// at once both replace it, and a shared partial name let the first
    /// rename take the second's file away:
    ///
    /// ```text
    ///   A: write x.partial   B: write x.partial   A: rename -> x   B: rename: ENOENT
    /// ```
    ///
    /// With a name each, both renames succeed and the last one stands; the
    /// bodies are the same document either way.
    pub async fn replace(&self, path: &CachePath, body: &[u8]) -> Result<()> {
        let full = self.resolve(path);

        let pending = crate::net::files::Pending::begin(&full).await?;

        pending.write_all(body).await?;

        writable(&full);

        pending.commit()
    }

    /// Copy a file the caller supplied into the cache.
    ///
    /// How a user-supplied advisory corpus is read under the same rules a
    /// downloaded one is.
    pub async fn stage(&self, source: &Path, name: &str) -> Result<CachePath> {
        // Future note: may consider on some operating systems using a hard-link
        // to the file to avoid the copy cost.  This requires the extension execution
        // system to guarantee that the caller cannot modify the file, which requires
        // extra work that most systems would find difficult to implement right.
        let target = self.path(name)?;
        let full = self.resolve(&target);

        crate::net::ensure_parent(&full).await?;

        // A copy takes its source's permissions, so a read-only file the
        // user supplied lands read-only -- and the next run's copy over it
        // is refused. Writable before and after, so only a payload is ever
        // read-only here.
        writable(&full);

        tokio::fs::copy(source, &full)
            .await
            .map_err(|err| Error::ReadFile {
                path: source.to_path_buf(),
                source: err,
            })?;

        writable(&full);

        Ok(target)
    }

    /// Read a cached file, capped.
    pub async fn read(&self, path: &CachePath, max: crate::net::ByteLimit) -> Result<Vec<u8>> {
        let full = self.resolve_existing(path)?;

        let size = tokio::fs::metadata(&full)
            .await
            .map_err(|source| Error::ReadFile {
                path: full.clone(),
                source,
            })?
            .len();

        if size > max.get() {
            return Err(Error::TooLarge {
                url: path.as_str(),
                limit: max.get(),
            });
        }

        tokio::fs::read(&full)
            .await
            .map_err(|source| Error::ReadFile { path: full, source })
    }

    /// A file already here, and how long ago it was written.
    ///
    /// The read side of the host cache: `None` when nothing is there, which
    /// is a cold cache rather than a fault and is what every first run
    /// sees. A caller that gets `None` fetches.
    ///
    /// Deliberately **not** `Result`. Anything that stops this answering --
    /// an absent file, an unreadable directory, a name that resolves out of
    /// the cache -- means the same thing to a caller: there is no cached
    /// copy to use, so fetch. Returning an error would make every call site
    /// write the same `unwrap_or(None)`.
    pub fn staged(&self, name: &str) -> Option<Staged> {
        let path = self.path(name).ok()?;
        self.resolve_existing(&path).ok()?;

        Some(Staged { path })
    }

    /// Write a cached file, whole or not at all; see [`Cache::replace`].
    pub async fn write(&self, name: &str, body: &[u8]) -> Result<CachePath> {
        let target = self.path(name)?;

        self.replace(&target, body).await?;

        Ok(target)
    }

    /// Remove the directory and everything in it.
    ///
    /// The caller keeps it on failure when `--debug` is set: a malformed
    /// response is far easier to diagnose from the actual bytes.
    pub fn discard(&self) {
        self.index.close();

        if std::fs::remove_dir_all(&self.root).is_ok() {
            return;
        }

        // A cached payload is read-only, and Windows will not remove a
        // read-only file. Cleared only after a failure, because walking a
        // million payloads to clear a flag Unix ignores is not free.
        writable_tree(&self.root);

        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::cache::testing::*;
    use crate::net::ByteLimit;

    /// Two writers of one path both succeed, and leave no partial file:
    /// a shared partial name let the first rename take the second's file.
    #[tokio::test]
    async fn replace_concurrent_both_succeed() {
        let (_dir, cache) = cache();
        let path = cache
            .document_path("h://repo.test/a/", None, "index.html")
            .expect("path");

        let writes: Vec<_> = (0..8u8)
            .map(|round| {
                let cache = &cache;
                let path = &path;

                async move { cache.replace(path, &[round; 64]).await }
            })
            .collect();

        for written in futures::future::join_all(writes).await {
            written.expect("written");
        }

        let full = cache.resolve(&path);
        let leftovers: Vec<_> = std::fs::read_dir(full.parent().expect("parent"))
            .expect("listed")
            .flatten()
            .filter(|entry| entry.path() != full)
            .collect();

        assert_eq!(std::fs::read(&full).expect("read").len(), 64);
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[tokio::test]
    async fn write_then_read_round_trips() {
        let (_dir, cache) = cache();

        let path = cache.write("out/data.bin", b"hello").await.expect("wrote");
        let body = cache.read(&path, ByteLimit::kib(1)).await.expect("read");

        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn read_past_cap_refused() {
        let (_dir, cache) = cache();

        let path = cache.write("big.bin", &[0u8; 512]).await.expect("wrote");

        let err = cache.read(&path, ByteLimit::bytes(16)).await.unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::DownloadTooLarge);
    }

    /// `--lock=FILE` reaches a reader this way, and the reader never learns
    /// where the file came from.
    #[tokio::test]
    async fn stage_copies_caller_file_in() {
        let (dir, cache) = cache();

        let outside = dir.path().join("package-lock.json");
        std::fs::write(&outside, b"{}").expect("written");

        let staged = cache
            .stage(&outside, "package-lock.json")
            .await
            .expect("staged");

        assert_eq!(cache.read(&staged, ByteLimit::kib(1)).await.unwrap(), b"{}");
    }

    /// A copy takes its source's permissions, so a read-only corpus used to
    /// land read-only and the next run's copy over it was refused.
    #[tokio::test]
    async fn stage_read_only_source_twice() {
        let (dir, cache) = cache();

        let outside = dir.path().join("corpus.zip");
        std::fs::write(&outside, b"PK").expect("written");
        read_only(&outside);

        cache
            .stage(&outside, "corpus.zip")
            .await
            .expect("first run");
        let staged = cache
            .stage(&outside, "corpus.zip")
            .await
            .expect("second run");

        assert!(!is_read_only(&cache.resolve(&staged)));
    }

    #[test]
    fn discard_removes_everything() {
        let (_dir, cache) = cache();
        let root = cache.root().to_path_buf();

        std::fs::write(root.join("x"), b"x").expect("written");
        cache.discard();

        assert!(!root.exists());
    }

    /// **On Windows, the retry path.** A read-only file there refuses
    /// removal, so the first `remove_dir_all` fails and only clearing the
    /// flags lets the second succeed. Unix removes it on the first try,
    /// so there this passes either way.
    #[test]
    fn discard_removes_read_only_payloads() {
        let (_dir, cache) = cache();
        let root = cache.root().to_path_buf();
        let payload = root.join("3f/a2/3fa2/tuna-1.0.0.tgz");

        std::fs::create_dir_all(payload.parent().expect("parent")).expect("made");
        std::fs::write(&payload, b"x").expect("written");
        read_only(&payload);

        cache.discard();

        assert!(!root.exists(), "a read-only payload kept the cache alive");
    }

    /// A cold cache, a cleared `cache-dir`, and a first run all look like
    /// this, and all mean the same thing to a caller: fetch.
    #[tokio::test]
    async fn staged_nothing_answers_none() {
        let (_dir, cache) = cache();

        assert!(cache.staged("corpus.zip").is_none());
    }

    #[tokio::test]
    async fn staged_file_comes_back() {
        let (_dir, cache) = cache();

        cache
            .write("corpus.zip", b"payload")
            .await
            .expect("written");

        let staged = cache.staged("corpus.zip").expect("it is there");

        assert_eq!(staged.path().as_str(), "corpus.zip");
    }

    /// A name that leaves the cache is answered the same way an absent
    /// file is, because it means the same thing: there is nothing here to
    /// use.
    #[test]
    fn staged_name_outside_cache_answers_none() {
        let (_dir, cache) = cache();

        assert!(cache.staged("../escape.zip").is_none());
        assert!(cache.staged("/etc/passwd").is_none());
    }

    #[test]
    fn discard_removes_open_index() {
        let (_dir, cache) = cache();
        let path = cache.payload_path(MAVEN_A, "core-1.0.jar").expect("path");

        cache
            .record(&path, MAVEN_A, "core-1.0.jar", &Lifetime::FOREVER)
            .expect("recorded");
        cache.discard();

        assert!(!cache.root().exists());
    }

    /// The directory survives a run, which is what makes it a cache: a
    /// second `Cache` over the same root finds what the first wrote.
    #[tokio::test]
    async fn reopen_finds_earlier_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("host.example");

        let first = Cache::open(&root).expect("opened");
        first
            .write("corpus.zip", b"payload")
            .await
            .expect("written");

        let again = Cache::open(&root).expect("reopened");

        assert!(again.staged("corpus.zip").is_some());
    }
}
