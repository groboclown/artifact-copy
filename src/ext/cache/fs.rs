//! File permissions in the cache.

use std::path::Path;

/// Clear a file's read-only flag, so it can be replaced or removed.
///
/// Best effort: a file that is gone or cannot be changed is left for the
/// write or remove that follows to report.
pub(crate) fn writable(path: &Path) {
    let Ok(found) = std::fs::metadata(path) else {
        return;
    };

    let mut permissions = found.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);

    let _ = std::fs::set_permissions(path, permissions);
}

/// [`writable`] for every file under `dir`. Symlinks are not followed, so
/// nothing outside the cache is changed.
pub(super) fn writable_tree(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };

        if kind.is_dir() {
            writable_tree(&entry.path());
            continue;
        }

        if kind.is_file() {
            writable(&entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::cache::testing::*;

    /// What `discard` falls back to where a read-only payload blocks the
    /// removal. Unix removes one regardless, so the walk is tested alone.
    #[test]
    fn writable_tree_clears_nested_files() {
        let (_dir, cache) = cache();
        let nested = cache.root().join("3f/a2/3fa2/tuna-1.0.0.tgz");
        let top = cache.root().join("corpus.zip");

        std::fs::create_dir_all(nested.parent().expect("parent")).expect("made");
        for file in [&nested, &top] {
            std::fs::write(file, b"x").expect("written");
            read_only(file);
        }

        writable_tree(cache.root());

        assert!(!is_read_only(&nested));
        assert!(!is_read_only(&top));
    }
}
