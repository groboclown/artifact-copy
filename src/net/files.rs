//! Writing downloaded bytes to disk, and hashing staged ones.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};
use crate::model::DigestAlg;

/// The read buffer for hashing a file.
const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Create a file's parent directory if it is not there already.
///
/// Every place that streams a response to disk needs this first, and all of
/// them want the same error: one naming the *directory* that could not be
/// made, rather than the file that was never reached.
pub(crate) async fn ensure_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|source| Error::WriteFile {
            path: parent.to_path_buf(),
            source,
        })
}

/// Prefix of a file being written, so a partial one sorts apart from its
/// name and is never taken for it.
const PARTIAL_PREFIX: &str = ".";

/// Suffix of a file being written, renamed into place once whole.
const PARTIAL_SUFFIX: &str = ".partial";

/// A file written beside its destination and moved into place only when
/// whole.
///
/// Every write the cache keeps goes through this: a download streamed to
/// disk, a document replaced, a file written. An interrupted write never
/// leaves a file that looks complete, and two writers of one destination
/// never touch each other's partial file:
///
/// ```text
///   begin(dest)    .lib-1.0.pom.k3Xq9z.partial    unique per writer
///   write          bytes into the partial file
///   commit         rename over dest               the last commit stands
///   drop           partial file removed           error, or run stopping
/// ```
///
/// A shared partial name is what failed twice: the first rename took the
/// second writer's file away, and its rename found nothing. Removal on
/// drop also covers a future dropped mid-write when a run stops, where no
/// `?` ever runs.
pub(crate) struct Pending {
    partial: tempfile::NamedTempFile,
    dest: PathBuf,
}

impl Pending {
    /// Start a write to `dest`, creating its directory if needed.
    pub(crate) async fn begin(dest: &Path) -> Result<Self> {
        ensure_parent(dest).await?;

        let directory = dest.parent().unwrap_or(Path::new("."));
        let name = dest.file_name().unwrap_or_default().to_string_lossy();

        let partial = tempfile::Builder::new()
            .prefix(&format!("{PARTIAL_PREFIX}{name}."))
            .suffix(PARTIAL_SUFFIX)
            .tempfile_in(directory)
            .map_err(|source| Error::WriteFile {
                path: directory.to_path_buf(),
                source,
            })?;

        Ok(Self {
            partial,
            dest: dest.to_path_buf(),
        })
    }

    /// Where the bytes go until [`Pending::commit`].
    pub(crate) fn path(&self) -> &Path {
        self.partial.path()
    }

    /// A handle to stream the bytes through.
    pub(crate) fn writer(&self) -> Result<tokio::fs::File> {
        let reopened = self.partial.reopen().map_err(|source| Error::WriteFile {
            path: self.path().to_path_buf(),
            source,
        })?;

        Ok(tokio::fs::File::from_std(reopened))
    }

    /// Write `body` whole.
    pub(crate) async fn write_all(&self, body: &[u8]) -> Result<()> {
        tokio::fs::write(self.path(), body)
            .await
            .map_err(|source| Error::WriteFile {
                path: self.path().to_path_buf(),
                source,
            })
    }

    /// Move the finished file into place, replacing what is there.
    pub(crate) fn commit(self) -> Result<()> {
        let dest = self.dest;

        self.partial
            .persist(&dest)
            .map(|_| ())
            .map_err(|failed| Error::WriteFile {
                path: dest,
                source: failed.error,
            })
    }

    /// Move the finished file into place only where nothing is.
    ///
    /// For a store where a path is written once: a writer that lost a race
    /// learns so here, and its partial file is removed on drop.
    pub(crate) fn commit_new(self) -> Result<Placed> {
        let dest = self.dest;

        match self.partial.persist_noclobber(&dest) {
            Ok(_) => Ok(Placed::Created),

            Err(failed) if failed.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(Placed::Occupied)
            }

            Err(failed) => Err(Error::WriteFile {
                path: dest,
                source: failed.error,
            }),
        }
    }
}

/// What [`Pending::commit_new`] found at its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placed {
    /// Nothing; the file is there now.
    Created,

    /// Something already; it was left alone.
    Occupied,
}

/// Whether a file name is a [`Pending`] write still in progress, which a
/// listing of the directory must not report as a file.
pub(crate) fn is_partial(name: &str) -> bool {
    name.starts_with(PARTIAL_PREFIX) && name.ends_with(PARTIAL_SUFFIX)
}

/// How a relative name would leave the directory it is joined to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Escape {
    Empty,
    Absolute,
    Parent,
    Rooted,
}

/// How `name` would leave the directory it is joined to, or `None` when it
/// stays inside.
///
/// Syntactic, so it works for a file that does not exist yet. A symlink
/// is the caller's to check once the file does: see [`canonical_within`].
pub(crate) fn escape_of(name: &Path) -> Option<Escape> {
    if name.as_os_str().is_empty() {
        return Some(Escape::Empty);
    }

    if name.is_absolute() {
        return Some(Escape::Absolute);
    }

    for part in name.components() {
        match part {
            std::path::Component::Normal(_) | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return Some(Escape::Parent),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Some(Escape::Rooted);
            }
        }
    }

    None
}

/// The real path of an existing `full`, or `None` when it resolves outside
/// `root`, which must itself be canonical.
pub(crate) fn canonical_within(root: &Path, full: &Path) -> std::io::Result<Option<PathBuf>> {
    let real = full.canonicalize()?;

    Ok(real.starts_with(root).then_some(real))
}

#[cfg(test)]
mod pending_tests {
    use super::*;

    /// Writers of one destination each commit, and leave no partial file.
    #[tokio::test]
    async fn commit_concurrent_both_succeed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("sub").join("lib-1.0.pom");

        let writes: Vec<_> = (0..8u8)
            .map(|round| {
                let dest = &dest;

                async move {
                    let pending = Pending::begin(dest).await?;
                    pending.write_all(&[round; 32]).await?;
                    pending.commit()
                }
            })
            .collect();

        for written in futures::future::join_all(writes).await {
            written.expect("committed");
        }

        let entries: Vec<_> = std::fs::read_dir(dest.parent().expect("parent"))
            .expect("listed")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();

        assert_eq!(entries, [std::ffi::OsString::from("lib-1.0.pom")]);
        assert_eq!(std::fs::read(&dest).expect("read").len(), 32);
    }

    /// An abandoned write removes its partial file and leaves the
    /// destination as it was.
    #[tokio::test]
    async fn write_dropped_leaves_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("lib-1.0.pom");

        let pending = Pending::begin(&dest).await.expect("begun");
        pending.write_all(b"half").await.expect("written");
        let partial = pending.path().to_path_buf();
        drop(pending);

        assert!(!partial.exists());
        assert!(!dest.exists());
    }
}

/// A temporary file, removed when dropped.
///
/// For a built-in that must hand a body to `ExtHost::send_file` and has no
/// scratch directory of its own: an npm publish document, a Maven checksum
/// sidecar. Under the system temp directory rather than the cache, because
/// nothing written here is worth keeping.
pub(crate) fn temporary() -> Result<tempfile::NamedTempFile> {
    tempfile::NamedTempFile::new().map_err(|source| Error::WriteFile {
        path: std::env::temp_dir(),
        source,
    })
}

/// A temporary file holding `contents`.
pub(crate) fn temporary_with(contents: &[u8]) -> Result<tempfile::NamedTempFile> {
    let mut file = temporary()?;

    std::io::Write::write_all(&mut file, contents).map_err(|source| Error::WriteFile {
        path: file.path().to_path_buf(),
        source,
    })?;

    Ok(file)
}

/// Hex digests of one file, streamed once for every algorithm asked.
pub(crate) fn digests_of(path: &Path, algs: &[DigestAlg]) -> Result<Vec<(DigestAlg, String)>> {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256, Sha512};

    let read_error = |source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    };

    let wants = |alg: DigestAlg| algs.contains(&alg);
    let mut md5 = wants(DigestAlg::Md5).then(Md5::new);
    let mut sha1 = wants(DigestAlg::Sha1).then(Sha1::new);
    let mut sha256 = wants(DigestAlg::Sha256).then(Sha256::new);
    let mut sha512 = wants(DigestAlg::Sha512).then(Sha512::new);

    let mut file = std::fs::File::open(path).map_err(read_error)?;
    let mut buffer = vec![0; HASH_BUFFER_BYTES];

    loop {
        let read = file.read(&mut buffer).map_err(read_error)?;

        if read == 0 {
            break;
        }

        let chunk = &buffer[..read];

        if let Some(hasher) = &mut md5 {
            hasher.update(chunk);
        }
        if let Some(hasher) = &mut sha1 {
            hasher.update(chunk);
        }
        if let Some(hasher) = &mut sha256 {
            hasher.update(chunk);
        }
        if let Some(hasher) = &mut sha512 {
            hasher.update(chunk);
        }
    }

    let md5 = md5.map(|hasher| hex::encode(hasher.finalize()));
    let sha1 = sha1.map(|hasher| hex::encode(hasher.finalize()));
    let sha256 = sha256.map(|hasher| hex::encode(hasher.finalize()));
    let sha512 = sha512.map(|hasher| hex::encode(hasher.finalize()));

    // In the order asked, which is the order the sidecars are written.
    Ok(algs
        .iter()
        .filter_map(|alg| {
            let hex = match alg {
                DigestAlg::Md5 => &md5,
                DigestAlg::Sha1 => &sha1,
                DigestAlg::Sha256 => &sha256,
                DigestAlg::Sha512 => &sha512,
            };

            hex.clone().map(|hex| (*alg, hex))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "artifact-copy-files-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));

        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn parent_missing_created() {
        let dir = temp();
        let file = dir.join("deep").join("nested").join("f.txt");

        ensure_parent(&file).await.expect("created");

        assert!(file.parent().expect("has a parent").is_dir());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Called before every write, so it must not object to finding the
    /// directory already there.
    #[tokio::test]
    async fn parent_existing_accepted() {
        let dir = temp();
        let file = dir.join("f.txt");

        ensure_parent(&file).await.expect("created");
        ensure_parent(&file).await.expect("still fine");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn parent_none_accepted() {
        ensure_parent(Path::new("f.txt")).await.expect("no parent");
    }
}
