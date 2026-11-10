//! A real directory behind a real capability, for the tests of all
//! three.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ext::{Cache, Constraints, ExtHost, HostedExt};
use crate::net::emulate::{LocalClient, Settings};

pub(crate) struct Directory {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) host: Arc<dyn ExtHost>,
    pub(crate) base: String,
}

impl Directory {
    /// An empty repository at `{tmp}/root/repo`, its host at `root`.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("root/repo")).expect("dirs");

        let root = url::Url::from_directory_path(dir.path().join("root"))
            .expect("a url")
            .to_string();
        let base = format!("{root}repo");

        let client = LocalClient::new(&root, Settings::default()).expect("built");
        let cache = Arc::new(Cache::open(dir.path().join("cache")).expect("cache"));
        let constraints = Constraints::new().allow(&base).expect("allowed");

        let host: Arc<dyn ExtHost> = Arc::new(HostedExt::new(Arc::new(client), constraints, cache));

        Self { dir, host, base }
    }

    /// Where `path` lands inside the repository.
    pub(crate) fn at(&self, path: &str) -> PathBuf {
        self.dir.path().join("root/repo").join(path)
    }

    pub(crate) fn write(&self, path: &str, bytes: &[u8]) {
        let at = self.at(path);
        std::fs::create_dir_all(at.parent().expect("a parent")).expect("dirs");
        std::fs::write(at, bytes).expect("written");
    }

    /// A file outside the repository, as a staged payload is.
    pub(crate) fn staged(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let at = self.dir.path().join("staged").join(name);
        std::fs::create_dir_all(at.parent().expect("a parent")).expect("dirs");
        std::fs::write(&at, bytes).expect("staged");
        at
    }

    pub(crate) fn exists(&self, path: &str) -> bool {
        Path::new(&self.at(path)).exists()
    }
}
