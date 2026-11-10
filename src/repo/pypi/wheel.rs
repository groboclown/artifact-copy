//! Reading the core metadata out of a staged wheel.
//!
//! The fallback when the source advertised no PEP 658 document: a wheel is
//! a zip, and its `{name}-{version}.dist-info/METADATA` is the same
//! document. Opening one is opening untrusted input, so every limit is
//! checked before anything is decompressed or while it is:
//!
//! - **How many entries** the central directory lists, before any is
//!   looked at. An archive of empty files costs time without costing bytes.
//! - **Exactly one** top-level `*.dist-info/METADATA`. Two would be a
//!   wheel claiming to be two distributions, and picking one would be a
//!   guess about which the upload describes.
//! - **Its declared size**, before decompressing.
//! - **The bytes actually read**, because the declared size is the
//!   archive's own claim and a crafted one lies. The read stops one byte
//!   past the limit, so a lie is caught rather than trusted.
//!
//! Reaching any of them is an error, not a truncated document: metadata
//! cut short would upload a description of a different package.

use std::io::Read as _;
use std::path::Path;

use crate::core::error::{Error, Result};
use crate::net::ByteLimit;
use crate::repo::archive::Wanted;

/// How many entries a wheel may list.
///
/// Far past any real wheel -- large ones hold a few thousand files -- and
/// small enough that walking the names costs nothing.
const MAX_ENTRIES: usize = 100_000;

/// The directory suffix naming a wheel's metadata.
const DIST_INFO: &str = ".dist-info/METADATA";

/// The one place a wheel's `METADATA` may be.
const WHEEL_WANTED: [Wanted; 1] = [Wanted {
    label: "top-level *.dist-info/METADATA",
    matches: is_top_level_metadata,
}];

/// Read one wheel's `METADATA`, no larger than `limit`.
pub(super) fn metadata(path: &Path, limit: ByteLimit) -> Result<String> {
    zip_entry(path, "wheel", &WHEEL_WANTED, limit)
}

/// Read the one entry of the zip at `path` from the first place in `wanted`
/// that holds any, under the caps above.  `what` names the archive in
/// errors.
///
/// Shared with the sdist reader, whose `.zip` form holds `PKG-INFO` the
/// way a wheel holds `METADATA`.
pub(super) fn zip_entry(
    path: &Path,
    what: &'static str,
    wanted: &[Wanted],
    limit: ByteLimit,
) -> Result<String> {
    let malformed = |detail: String| Error::Malformed {
        what,
        url: path.display().to_string(),
        detail,
    };

    let file = std::fs::File::open(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|err| malformed(format!("not a readable zip: {err}")))?;

    if archive.len() > MAX_ENTRIES {
        return Err(malformed(format!(
            "it lists {} entries, more than {MAX_ENTRIES}",
            archive.len()
        )));
    }

    // Earlier places win: `echo-1.0/PKG-INFO` over its egg-info copy.
    let found = wanted.iter().find_map(|place| {
        let names: Vec<String> = archive
            .file_names()
            .filter(|name| (place.matches)(name))
            .map(str::to_owned)
            .collect();

        (!names.is_empty()).then_some((place.label, names))
    });

    let Some((label, candidates)) = found else {
        let labels: Vec<&str> = wanted.iter().map(|place| place.label).collect();

        return Err(malformed(format!(
            "it holds no {} entry",
            labels.join(" or ")
        )));
    };

    let [name] = candidates.as_slice() else {
        return Err(malformed(format!(
            "it holds {} {label} entries, not one",
            candidates.len()
        )));
    };

    let entry = archive
        .by_name(name)
        .map_err(|err| malformed(format!("{name}: {err}")))?;

    if entry.size() > limit.get() {
        return Err(malformed(format!(
            "{name} declares {} bytes, more than {}",
            entry.size(),
            limit.get()
        )));
    }

    // One byte past the limit, so an entry that lied about its size shows
    // as too long rather than as a document that happens to end there.
    let mut bytes = Vec::new();

    entry
        .take(limit.get() + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| malformed(format!("{name}: {err}")))?;

    if bytes.len() as u64 > limit.get() {
        return Err(malformed(format!(
            "{name} decompresses past {} bytes",
            limit.get()
        )));
    }

    String::from_utf8(bytes).map_err(|_| malformed(format!("{name} is not UTF-8")))
}

/// `pkg-1.0.dist-info/METADATA`, and not `pkg/vendored-1.0.dist-info/METADATA`.
fn is_top_level_metadata(name: &str) -> bool {
    name.strip_suffix(DIST_INFO)
        .is_some_and(|directory| !directory.is_empty() && !directory.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const LIMIT: ByteLimit = ByteLimit::kib(4);

    fn wheel(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp");
        let mut writer = zip::ZipWriter::new(file.reopen().expect("reopen"));

        for (name, body) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("entry");
            writer.write_all(body).expect("written");
        }

        writer.finish().expect("finished");

        file
    }

    #[test]
    fn metadata_read() {
        let file = wheel(&[
            ("echo/__init__.py", b""),
            ("echo-1.0.dist-info/METADATA", b"Name: echo\nVersion: 1.0\n"),
        ]);

        assert_eq!(
            metadata(file.path(), LIMIT).expect("read"),
            "Name: echo\nVersion: 1.0\n"
        );
    }

    /// A vendored package's own dist-info is not this wheel's metadata.
    #[test]
    fn metadata_ignores_nested_dist_info() {
        let file = wheel(&[
            ("echo/_vendor/dep-2.0.dist-info/METADATA", b"Name: dep\n"),
            ("echo-1.0.dist-info/METADATA", b"Name: echo\n"),
        ]);

        assert_eq!(metadata(file.path(), LIMIT).expect("read"), "Name: echo\n");
    }

    #[test]
    fn metadata_refuses_two_dist_infos() {
        let file = wheel(&[
            ("a-1.0.dist-info/METADATA", b"Name: a\n"),
            ("b-1.0.dist-info/METADATA", b"Name: b\n"),
        ]);

        assert!(matches!(
            metadata(file.path(), LIMIT),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn metadata_refuses_missing() {
        let file = wheel(&[("echo/__init__.py", b"")]);

        assert!(metadata(file.path(), LIMIT).is_err());
    }

    /// Compressible to almost nothing and far past the limit once
    /// inflated: the shape of a bomb, refused on its declared size.
    #[test]
    fn metadata_refuses_oversized() {
        let huge = vec![b'x'; LIMIT.get() as usize * 64];
        let file = wheel(&[("echo-1.0.dist-info/METADATA", &huge)]);

        let refused = metadata(file.path(), LIMIT).expect_err("too large");

        assert!(refused.to_string().contains("declares"), "{refused}");
    }

    #[test]
    fn metadata_refuses_non_zip() {
        let mut file = tempfile::NamedTempFile::new().expect("temp");
        file.write_all(b"not a zip").expect("written");

        assert!(metadata(file.path(), LIMIT).is_err());
    }
}
