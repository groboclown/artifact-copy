//! Naming a file in the cache, and finding it on disk.

use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};
use sha2::Digest as _;

use super::Cache;
use crate::net::files::Escape;

/// The directory documents are kept under, apart from payloads.
const DOCUMENTS_DIR: &str = "documents";

/// Hex characters per shard directory: 256 directories at each level.
const SHARD_HEX_CHARS: usize = 2;

/// The leaf name of a payload whose own name cannot be one.
const UNNAMED_PAYLOAD: &str = "payload";

/// A path inside a cache.
///
/// Always relative, and validated on the way in, so holding one is proof it
/// stays within the directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CachePath {
    pub(super) relative: PathBuf,
}

impl CachePath {
    /// The cache-relative path, which is what a report records.
    pub fn as_str(&self) -> String {
        self.relative.to_string_lossy().into_owned()
    }

    pub fn as_path(&self) -> &Path {
        &self.relative
    }
}

impl std::fmt::Display for CachePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// `3f/a2/3fa2...e1/{name}`, from a hash of `key`.
fn sharded(key: &str, name: &str) -> String {
    let key = hex::encode(sha2::Sha256::digest(key.as_bytes()));
    let first = &key[..SHARD_HEX_CHARS];
    let second = &key[SHARD_HEX_CHARS..SHARD_HEX_CHARS * 2];

    format!("{first}/{second}/{key}/{}", leaf_name(name))
}

/// A name's last path component, or a fixed one when it has none usable.
fn leaf_name(name: &str) -> &str {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or_default();

    match leaf {
        "" | "." | ".." => UNNAMED_PAYLOAD,
        _ => leaf,
    }
}

impl Cache {
    /// Name a file inside the cache.
    ///
    /// Refuses an absolute path and any `..` component. The check is
    /// syntactic, so it works for a file that does not exist yet -- which is
    /// the common case, since most calls are about to create it.
    pub fn path(&self, name: &str) -> Result<CachePath> {
        let candidate = Path::new(name);

        if let Some(escape) = crate::net::files::escape_of(candidate) {
            let why = match escape {
                Escape::Empty => "the name is empty",
                Escape::Absolute => "an absolute path leaves the cache",
                Escape::Parent => "`..` leaves the cache",
                Escape::Rooted => "a rooted path leaves the cache",
            };

            return Err(self.refuse(name, why));
        }

        Ok(CachePath {
            relative: candidate.to_path_buf(),
        })
    }

    /// Where the payload at `url` is kept: `3f/a2/3fa2...e1/{name}`.
    ///
    /// Keyed by URL, which is unique within a host; see the module notes.
    /// Only the last component of `name` is kept, so a name cannot pick its
    /// own directory.
    pub fn payload_path(&self, url: &str, name: &str) -> Result<CachePath> {
        self.path(&sharded(url, name))
    }

    /// Where the document at `url`, asked for as `accept`, is kept:
    /// `documents/9c/04/9c04...7b/{name}`.
    pub fn document_path(&self, url: &str, accept: Option<&str>, name: &str) -> Result<CachePath> {
        let key = format!("{url}\n{}", accept.unwrap_or_default());

        self.path(&format!("{DOCUMENTS_DIR}/{}", sharded(&key, name)))
    }

    /// The real path of a cached file, for opening it.
    pub fn resolve(&self, path: &CachePath) -> PathBuf {
        self.root.join(&path.relative)
    }

    /// The real path of a file that must already exist, checked for
    /// containment.
    ///
    /// [`Cache::path`] cannot see a symlink that did not exist when the
    /// name was validated, so anything being *read* is confirmed here.
    pub fn resolve_existing(&self, path: &CachePath) -> Result<PathBuf> {
        let full = self.resolve(path);

        let real = crate::net::files::canonical_within(&self.root, &full).map_err(|source| {
            Error::ReadFile {
                path: full.clone(),
                source,
            }
        })?;

        real.ok_or_else(|| {
            self.refuse(
                &path.as_str(),
                "it resolves outside the cache, probably through a symlink",
            )
        })
    }

    pub(super) fn refuse(&self, name: &str, why: &str) -> Error {
        Error::Config(format!("{name:?} is not a usable cache path: {why}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::cache::testing::*;

    use crate::net::ByteLimit;

    #[test]
    fn path_plain_name_accepted() {
        let (_dir, cache) = cache();

        let path = cache.path("index.json").expect("accepted");

        assert_eq!(path.as_str(), "index.json");
        assert_eq!(cache.resolve(&path), cache.root().join("index.json"));
    }

    #[test]
    fn path_nested_name_accepted() {
        let (_dir, cache) = cache();

        assert!(cache.path("parts/0001.json").is_ok());
    }

    /// The whole point of the type.
    #[test]
    fn path_traversal_refused() {
        let (_dir, cache) = cache();

        for bad in [
            "../escape",
            "a/../../escape",
            "..",
            "a/..",
            "/etc/passwd",
            "",
        ] {
            assert!(cache.path(bad).is_err(), "{bad:?} should have been refused");
        }
    }

    /// `./x` is harmless and some callers produce it.
    #[test]
    fn path_current_directory_component_accepted() {
        let (_dir, cache) = cache();

        assert!(cache.path("./index.json").is_ok());
    }

    /// A name validated before the file existed cannot see a symlink planted
    /// afterwards, so reads re-check containment.
    #[cfg(unix)]
    #[tokio::test]
    async fn path_symlink_outside_cache_refused_on_read() {
        let (dir, cache) = cache();

        let outside = dir.path().join("secret");
        std::fs::write(&outside, b"secret").expect("written");

        let link = cache.root().join("innocent.json");
        std::os::unix::fs::symlink(&outside, &link).expect("linked");

        let path = cache.path("innocent.json").expect("syntactically fine");
        let err = cache.read(&path, ByteLimit::kib(1)).await.unwrap_err();

        assert!(err.to_string().contains("outside the cache"));
    }

    /// Two sharding levels, then the full hash, then the file's own name.
    #[test]
    fn payload_path_sharded() {
        let (_dir, cache) = cache();

        let path = cache.payload_path(MAVEN_A, "core-1.0.jar").expect("path");
        let parts: Vec<String> = path
            .as_path()
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();

        assert_eq!(parts.len(), 4, "{path}");
        assert_eq!(parts[0].len(), SHARD_HEX_CHARS);
        assert!(parts[2].starts_with(&format!("{}{}", parts[0], parts[1])));
        assert_eq!(parts[3], "core-1.0.jar");
    }

    /// The bug the layout exists for: one name, two artifacts.
    #[test]
    fn payload_same_name_different_url_do_not_collide() {
        let (_dir, cache) = cache();

        let a = cache.payload_path(MAVEN_A, "core-1.0.jar").expect("path");
        let b = cache.payload_path(MAVEN_B, "core-1.0.jar").expect("path");

        assert_ne!(a, b);
    }

    /// A name cannot choose its own directory.
    #[test]
    fn payload_name_keeps_only_leaf() {
        let (_dir, cache) = cache();

        for (name, leaf) in [
            ("../../escape.jar", "escape.jar"),
            ("dir\\win.jar", "win.jar"),
            ("..", UNNAMED_PAYLOAD),
            ("", UNNAMED_PAYLOAD),
        ] {
            let path = cache.payload_path(MAVEN_A, name).expect("path");

            assert_eq!(path.as_path().file_name().unwrap(), leaf, "{name:?}");
        }
    }
}
