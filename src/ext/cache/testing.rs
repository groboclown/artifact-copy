//! Fixtures shared by the cache's tests.

use std::path::Path;

use super::Cache;

pub(super) fn cache() -> (tempfile::TempDir, Cache) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = Cache::open(dir.path().join("work")).expect("opened");

    (dir, cache)
}

/// Mark `path` read-only, as a package manager or a read-only mount
/// would leave a file the user points at.
pub(super) fn read_only(path: &Path) {
    let mut permissions = std::fs::metadata(path).expect("exists").permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions).expect("read-only");
}

pub(super) fn is_read_only(path: &Path) -> bool {
    std::fs::metadata(path)
        .expect("exists")
        .permissions()
        .readonly()
}

/// A freshness or retention long enough not to pass during a test.
pub(super) const HOUR: std::time::Duration = std::time::Duration::from_secs(3_600);

/// Two payload URLs ending in the same file name.
pub(super) const MAVEN_A: &str = "h://repo.test/org/a/core/1.0/core-1.0.jar";
pub(super) const MAVEN_B: &str = "h://repo.test/org/b/core/1.0/core-1.0.jar";
