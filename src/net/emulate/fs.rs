//! The directory itself: the one place the emulation touches `std::fs`.
//!
//! Every path arrives relative to the root and leaves as a real path only
//! once it is known to stay inside, under the host's [`Symlinks`] mode:
//!
//! ```text
//!   mode          a link in a listing          a link named by a request
//!   as-file       a file holding the link text  the link text
//!   follow        followed anywhere             followed anywhere
//!   skip          reported as skipped           refused
//!   within-root   followed while inside         refused when outside
//! ```
//!
//! Synchronous throughout; the client runs it off the async runtime.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};

use super::Symlinks;
use crate::net::files::{canonical_within, escape_of, is_partial};

/// The configured directory, and how its links are treated.
#[derive(Debug)]
pub(super) struct Root {
    path: PathBuf,
    symlinks: Symlinks,
}

/// What a request names.
#[derive(Debug)]
pub(super) enum Opened {
    File(PathBuf),

    /// A link under [`Symlinks::AsFile`]: its text is its content.
    Link(Vec<u8>),

    Directory(PathBuf),
}

/// One file of a listing.
#[derive(Debug)]
pub(super) struct Entry {
    /// Relative to the listed directory, `/`-separated.
    pub(super) path: String,
    pub(super) size: u64,
    pub(super) modified: Option<DateTime<Utc>>,
    pub(super) content: Content,
}

/// Where an entry's bytes are, for hashing it.
#[derive(Debug)]
pub(super) enum Content {
    File(PathBuf),
    Link(Vec<u8>),
}

/// A name a listing passed over, and why.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Passed {
    pub(super) path: String,
    pub(super) reason: String,
}

/// Every file under one directory, and every name passed over.
#[derive(Debug, Default)]
pub(super) struct Walked {
    pub(super) entries: Vec<Entry>,
    pub(super) passed: Vec<Passed>,
}

/// Why a request could not be answered.
#[derive(Debug)]
pub(super) enum Refusal {
    Missing,

    /// Named, but not reachable under this host's rules.
    Forbidden(String),

    /// A write to a path that is already there.
    Occupied,

    Failed {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl Refusal {
    fn of(path: &Path, source: std::io::Error) -> Self {
        match source.kind() {
            std::io::ErrorKind::NotFound => Self::Missing,
            _ => Self::Failed {
                path: path.to_path_buf(),
                source,
            },
        }
    }
}

impl Root {
    pub(super) fn new(path: PathBuf, symlinks: Symlinks) -> Self {
        Self { path, symlinks }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// The file or directory `relative` names. Empty names the root.
    pub(super) fn open(&self, relative: &Path) -> Result<Opened, Refusal> {
        let parts = parts_of(relative)?;
        let mut current = self.path.clone();

        for (index, part) in parts.iter().enumerate() {
            current.push(part);

            let found =
                std::fs::symlink_metadata(&current).map_err(|err| Refusal::of(&current, err))?;

            if !found.file_type().is_symlink() {
                continue;
            }

            let last = index + 1 == parts.len();

            match self.symlinks {
                Symlinks::Follow => {}
                Symlinks::WithinRoot => self.inside(&current)?,
                Symlinks::AsFile if last => return Ok(Opened::Link(link_text(&current)?)),

                Symlinks::AsFile => {
                    return Err(Refusal::Forbidden(format!(
                        "{} passes through a symbolic link, which this host reads as a file",
                        relative.display()
                    )));
                }

                Symlinks::Skip => {
                    return Err(Refusal::Forbidden(format!(
                        "{} passes through a symbolic link, which this host skips",
                        relative.display()
                    )));
                }
            }
        }

        let found = std::fs::metadata(&current).map_err(|err| Refusal::of(&current, err))?;

        match found.is_dir() {
            true => Ok(Opened::Directory(current)),
            false => Ok(Opened::File(current)),
        }
    }

    /// Every file under `within`, a directory inside `base`, sorted by
    /// path relative to `base`: walking `a` in `repo` reports `a/b/c.txt`.
    ///
    /// A name the walk cannot report -- one that is not UTF-8, a link this
    /// host skips, a directory it cannot read -- is passed over and said
    /// so, rather than failing the whole listing.
    pub(super) fn walk(&self, base: &Path, within: &Path) -> Result<Walked, Refusal> {
        let mut walked = Walked::default();

        let Opened::Directory(start) = self.open(&base.join(within))? else {
            return Ok(walked);
        };

        // Only a followed link can loop, so only followed directories are
        // remembered.
        let mut visited = HashSet::new();

        if let Ok(real) = start.canonicalize() {
            visited.insert(real);
        }

        let root = self.path.canonicalize().ok();
        let shown = slashed(within);

        self.descend(&start, &shown, root.as_deref(), &mut visited, &mut walked);

        walked.entries.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(walked)
    }

    /// Where a new file at `relative` goes, once nothing in its way says
    /// otherwise.
    pub(super) fn writable(&self, relative: &Path) -> Result<PathBuf, Refusal> {
        if escape_of(relative).is_some() {
            return Err(Refusal::Forbidden(format!(
                "{} does not name a file inside this directory",
                relative.display()
            )));
        }

        let parts = parts_of(relative)?;
        let Some((_, parents)) = parts.split_last() else {
            return Err(Refusal::Forbidden(
                "the directory itself is not a file".into(),
            ));
        };

        let mut current = self.path.clone();

        for part in parents {
            current.push(part);

            let found = match std::fs::symlink_metadata(&current) {
                Ok(found) => found,

                // Created by the write, with everything below it.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                Err(err) => return Err(Refusal::of(&current, err)),
            };

            if found.file_type().is_symlink() {
                match self.symlinks {
                    Symlinks::Follow => {}
                    Symlinks::WithinRoot => self.inside(&current)?,

                    Symlinks::AsFile | Symlinks::Skip => {
                        return Err(Refusal::Forbidden(format!(
                            "{} passes through a symbolic link, which this host does not follow",
                            relative.display()
                        )));
                    }
                }
            }

            if !current.is_dir() {
                return Err(Refusal::Forbidden(format!(
                    "{} needs a directory where a file is",
                    relative.display()
                )));
            }
        }

        let dest = self.path.join(relative);

        match std::fs::symlink_metadata(&dest) {
            Ok(_) => Err(Refusal::Occupied),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(dest),
            Err(err) => Err(Refusal::of(&dest, err)),
        }
    }

    /// Refuse a path that resolves outside the root.
    fn inside(&self, path: &Path) -> Result<(), Refusal> {
        let root = self
            .path
            .canonicalize()
            .map_err(|err| Refusal::of(&self.path, err))?;

        match canonical_within(&root, path) {
            Ok(Some(_)) => Ok(()),

            Ok(None) => Err(Refusal::Forbidden(format!(
                "{} resolves outside this host's directory",
                path.display()
            ))),

            Err(err) => Err(Refusal::of(path, err)),
        }
    }

    fn descend(
        &self,
        directory: &Path,
        shown: &str,
        root: Option<&Path>,
        visited: &mut HashSet<PathBuf>,
        walked: &mut Walked,
    ) {
        let listed = match std::fs::read_dir(directory) {
            Ok(listed) => listed,
            Err(err) => {
                walked.passed.push(Passed {
                    path: shown.to_owned(),
                    reason: format!("the directory cannot be read: {err}"),
                });
                return;
            }
        };

        for entry in listed {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    walked.passed.push(Passed {
                        path: shown.to_owned(),
                        reason: format!("the directory cannot be read: {err}"),
                    });
                    continue;
                }
            };

            let raw = entry.file_name();

            let Some(name) = raw.to_str() else {
                walked.passed.push(Passed {
                    path: joined(shown, &raw.to_string_lossy()),
                    reason: "its name is not UTF-8".into(),
                });
                continue;
            };

            // A write in progress, by this tool or another run of it.
            if is_partial(name) {
                continue;
            }

            let path = joined(shown, name);
            let full = entry.path();

            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(err) => {
                    walked.passed.push(Passed {
                        path,
                        reason: format!("it cannot be read: {err}"),
                    });
                    continue;
                }
            };

            if kind.is_symlink() {
                self.link(&full, path, root, visited, walked);
                continue;
            }

            self.found(&full, path, root, visited, walked);
        }
    }

    /// A link met while walking, under this host's mode.
    fn link(
        &self,
        full: &Path,
        path: String,
        root: Option<&Path>,
        visited: &mut HashSet<PathBuf>,
        walked: &mut Walked,
    ) {
        match self.symlinks {
            Symlinks::Skip => walked.passed.push(Passed {
                path,
                reason: "it is a symbolic link, which this host skips".into(),
            }),

            Symlinks::AsFile => match link_text(full) {
                Ok(text) => walked.entries.push(Entry {
                    path,
                    size: text.len() as u64,
                    modified: std::fs::symlink_metadata(full).ok().and_then(modified_of),
                    content: Content::Link(text),
                }),

                Err(_) => walked.passed.push(Passed {
                    path,
                    reason: "its link text cannot be read".into(),
                }),
            },

            Symlinks::WithinRoot => {
                let inside = root.and_then(|root| canonical_within(root, full).ok().flatten());

                match inside {
                    Some(_) => self.found(full, path, root, visited, walked),
                    None => walked.passed.push(Passed {
                        path,
                        reason: "it is a symbolic link resolving outside this host's directory"
                            .into(),
                    }),
                }
            }

            Symlinks::Follow => self.found(full, path, root, visited, walked),
        }
    }

    /// A file or directory, reached directly or through a followed link.
    fn found(
        &self,
        full: &Path,
        path: String,
        root: Option<&Path>,
        visited: &mut HashSet<PathBuf>,
        walked: &mut Walked,
    ) {
        let meta = match std::fs::metadata(full) {
            Ok(meta) => meta,
            Err(err) => {
                walked.passed.push(Passed {
                    path,
                    reason: format!("it cannot be read: {err}"),
                });
                return;
            }
        };

        if meta.is_dir() {
            // Real path, so a link back up the tree is seen as a loop.
            let real = full.canonicalize().unwrap_or_else(|_| full.to_path_buf());

            if !visited.insert(real) {
                walked.passed.push(Passed {
                    path,
                    reason: "it leads back to a directory already walked".into(),
                });
                return;
            }

            self.descend(full, &path, root, visited, walked);
            return;
        }

        if !meta.is_file() {
            walked.passed.push(Passed {
                path,
                reason: "it is not a regular file".into(),
            });
            return;
        }

        walked.entries.push(Entry {
            path,
            size: meta.len(),
            modified: modified_of(meta),
            content: Content::File(full.to_path_buf()),
        });
    }
}

/// The normal components of a relative path, refusing one that leaves.
///
/// Empty is allowed and names the root.
fn parts_of(relative: &Path) -> Result<Vec<&std::ffi::OsStr>, Refusal> {
    let mut parts = Vec::new();

    for part in relative.components() {
        match part {
            Component::Normal(name) => parts.push(name),
            Component::CurDir => {}

            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Refusal::Forbidden(format!(
                    "{} does not name a file inside this directory",
                    relative.display()
                )));
            }
        }
    }

    Ok(parts)
}

/// A link's target, exactly as stored.
fn link_text(path: &Path) -> Result<Vec<u8>, Refusal> {
    let target = std::fs::read_link(path).map_err(|err| Refusal::of(path, err))?;

    #[cfg(unix)]
    let text = std::os::unix::ffi::OsStrExt::as_bytes(target.as_os_str()).to_vec();

    #[cfg(not(unix))]
    let text = target.to_string_lossy().into_owned().into_bytes();

    Ok(text)
}

fn modified_of(meta: std::fs::Metadata) -> Option<DateTime<Utc>> {
    meta.modified().ok().map(DateTime::<Utc>::from)
}

/// `relative` written with `/`, as a listing reports it.
fn slashed(relative: &Path) -> String {
    relative
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn joined(parent: &str, name: &str) -> String {
    match parent.is_empty() {
        true => name.to_owned(),
        false => format!("{parent}/{name}"),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::create_dir_all(dir.path().join("root/a/b")).expect("dirs");
        std::fs::write(dir.path().join("root/a/one.txt"), b"one").expect("file");
        std::fs::write(dir.path().join("root/a/b/two.txt"), b"two").expect("file");
        std::fs::write(dir.path().join("outside.txt"), b"secret").expect("file");

        dir
    }

    fn root(dir: &tempfile::TempDir, symlinks: Symlinks) -> Root {
        Root::new(dir.path().join("root"), symlinks)
    }

    fn link(dir: &tempfile::TempDir, target: &str, at: &str) {
        std::os::unix::fs::symlink(target, dir.path().join("root").join(at)).expect("linked");
    }

    fn paths(walked: &Walked) -> Vec<&str> {
        walked
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect()
    }

    #[test]
    fn walk_lists_every_file_sorted() {
        let dir = tree();
        let walked = root(&dir, Symlinks::AsFile)
            .walk(Path::new(""), Path::new(""))
            .expect("walked");

        assert_eq!(paths(&walked), ["a/b/two.txt", "a/one.txt"]);
        assert_eq!(walked.entries[1].size, 3);
        assert!(walked.entries[1].modified.is_some());
    }

    #[test]
    fn walk_keeps_subdir_prefix() {
        let dir = tree();
        let walked = root(&dir, Symlinks::AsFile)
            .walk(Path::new(""), Path::new("a/b"))
            .expect("walked");

        assert_eq!(paths(&walked), ["a/b/two.txt"]);
    }

    #[test]
    fn walk_paths_relative_to_base() {
        let dir = tree();
        let walked = root(&dir, Symlinks::AsFile)
            .walk(Path::new("a"), Path::new("b"))
            .expect("walked");

        assert_eq!(paths(&walked), ["b/two.txt"]);
    }

    #[test]
    fn walk_missing_dir_is_missing() {
        let dir = tree();

        assert!(matches!(
            root(&dir, Symlinks::AsFile).walk(Path::new(""), Path::new("nope")),
            Err(Refusal::Missing)
        ));
    }

    #[test]
    fn walk_ignores_partial_writes() {
        let dir = tree();
        std::fs::write(dir.path().join("root/a/.x.txt.k3Xq9z.partial"), b"half").expect("file");

        let walked = root(&dir, Symlinks::AsFile)
            .walk(Path::new(""), Path::new(""))
            .expect("walked");

        assert_eq!(paths(&walked), ["a/b/two.txt", "a/one.txt"]);
    }

    #[test]
    fn path_parent_segments_refused() {
        let dir = tree();
        let root = root(&dir, Symlinks::Follow);

        assert!(matches!(
            root.open(Path::new("../outside.txt")),
            Err(Refusal::Forbidden(_))
        ));
        assert!(matches!(
            root.writable(Path::new("a/../../escape.txt")),
            Err(Refusal::Forbidden(_))
        ));
        assert!(matches!(
            root.open(Path::new("/etc/passwd")),
            Err(Refusal::Forbidden(_))
        ));
    }

    #[test]
    fn symlinks_as_file_reads_link_text() {
        let dir = tree();
        link(&dir, "../outside.txt", "escape");

        let root = root(&dir, Symlinks::AsFile);

        let Opened::Link(text) = root.open(Path::new("escape")).expect("opened") else {
            panic!("expected the link text");
        };
        assert_eq!(text, b"../outside.txt");

        let walked = root.walk(Path::new(""), Path::new("")).expect("walked");
        let entry = walked
            .entries
            .iter()
            .find(|entry| entry.path == "escape")
            .expect("listed");

        assert_eq!(entry.size, "../outside.txt".len() as u64);
        assert!(matches!(entry.content, Content::Link(_)));
    }

    #[test]
    fn symlinks_skip_passes_every_link() {
        let dir = tree();
        link(&dir, "a/one.txt", "inner");

        let root = root(&dir, Symlinks::Skip);
        let walked = root.walk(Path::new(""), Path::new("")).expect("walked");

        assert_eq!(paths(&walked), ["a/b/two.txt", "a/one.txt"]);
        assert_eq!(walked.passed.len(), 1);
        assert!(matches!(
            root.open(Path::new("inner")),
            Err(Refusal::Forbidden(_))
        ));
    }

    #[test]
    fn symlinks_within_root_stays_inside() {
        let dir = tree();
        link(&dir, "a/one.txt", "inner");
        link(&dir, "../outside.txt", "escape");

        let root = root(&dir, Symlinks::WithinRoot);
        let walked = root.walk(Path::new(""), Path::new("")).expect("walked");

        assert_eq!(paths(&walked), ["a/b/two.txt", "a/one.txt", "inner"]);
        assert_eq!(walked.passed[0].path, "escape");
        assert!(matches!(root.open(Path::new("inner")), Ok(Opened::File(_))));
        assert!(matches!(
            root.open(Path::new("escape")),
            Err(Refusal::Forbidden(_))
        ));
    }

    #[test]
    fn symlinks_follow_reaches_outside() {
        let dir = tree();
        link(&dir, "../outside.txt", "escape");

        let root = root(&dir, Symlinks::Follow);

        assert!(matches!(
            root.open(Path::new("escape")),
            Ok(Opened::File(_))
        ));
    }

    #[test]
    fn symlinks_follow_does_not_loop() {
        let dir = tree();
        link(&dir, "..", "a/b/up");

        let walked = root(&dir, Symlinks::Follow)
            .walk(Path::new(""), Path::new(""))
            .expect("walked");

        assert_eq!(paths(&walked), ["a/b/two.txt", "a/one.txt"]);
        assert_eq!(walked.passed.len(), 1);
    }

    #[test]
    fn write_existing_file_occupied() {
        let dir = tree();
        let root = root(&dir, Symlinks::AsFile);

        assert!(matches!(
            root.writable(Path::new("a/one.txt")),
            Err(Refusal::Occupied)
        ));
        assert_eq!(
            root.writable(Path::new("new/dir/file.txt")).expect("free"),
            dir.path().join("root/new/dir/file.txt")
        );
    }

    #[test]
    fn write_file_blocking_dir_refused() {
        let dir = tree();

        assert!(matches!(
            root(&dir, Symlinks::AsFile).writable(Path::new("a/one.txt/inner.txt")),
            Err(Refusal::Forbidden(_))
        ));
    }

    #[test]
    fn write_via_link_follows_mode() {
        let dir = tree();
        link(&dir, "a", "alias");

        assert!(matches!(
            root(&dir, Symlinks::AsFile).writable(Path::new("alias/new.txt")),
            Err(Refusal::Forbidden(_))
        ));
        assert!(
            root(&dir, Symlinks::WithinRoot)
                .writable(Path::new("alias/new.txt"))
                .is_ok()
        );
    }
}
