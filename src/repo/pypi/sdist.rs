//! Reading the core metadata out of a staged sdist.
//!
//! The fallback when the source advertised no PEP 658 document: an sdist
//! carries the same document as `{name}-{version}/PKG-INFO`. Two forms are
//! read -- `.tar.gz` (PEP 625's) and `.zip` -- and any other is left to
//! what its filename says.
//!
//! A `.zip` goes through [`super::wheel::zip_entry`] and a `.tar.gz`
//! through [`crate::repo::archive::tar_gz`], each with its caps. What is
//! wanted is exactly one top-level `*/PKG-INFO`: the nested
//! `src/pkg.egg-info/PKG-INFO` setuptools writes is not this sdist's.
//! Lacking one, exactly one `*/*.egg-info/PKG-INFO` directly under the top
//! directory stands in: `mysql-connector-python` 8.3.0 ships only that.
//!
//! References: [PEP 625](https://peps.python.org/pep-0625/).

use std::path::Path;

use super::wheel;
use crate::core::error::Result;
use crate::net::ByteLimit;
use crate::repo::archive::{self, MAX_INFLATED, Wanted};

/// What an sdist is called in errors.
const WHAT: &str = "sdist";

/// The document inside an sdist's top-level directory.
const PKG_INFO: &str = "/PKG-INFO";

/// The directory suffix of setuptools' metadata copy.
const EGG_INFO: &str = ".egg-info";

/// Where an sdist's `PKG-INFO` may be, most authoritative first.
const SDIST_WANTED: [Wanted; 2] = [
    Wanted {
        label: "top-level */PKG-INFO",
        matches: is_top_level_pkg_info,
    },
    Wanted {
        label: "*/*.egg-info/PKG-INFO",
        matches: is_egg_info_pkg_info,
    },
];

/// Extensions read as a gzipped tar.
const TAR_GZ_EXTENSIONS: [&str; 2] = [".tar.gz", ".tgz"];

/// The extension read as a zip.
const ZIP_EXTENSION: &str = ".zip";

/// Read one sdist's `PKG-INFO`, no larger than `limit`.
///
/// `None` for a form this does not read, such as `.tar.bz2`.
pub(super) fn metadata(path: &Path, name: &str, limit: ByteLimit) -> Result<Option<String>> {
    if name.ends_with(ZIP_EXTENSION) {
        return wheel::zip_entry(path, WHAT, &SDIST_WANTED, limit).map(Some);
    }

    if !TAR_GZ_EXTENSIONS.iter().any(|ext| name.ends_with(ext)) {
        return Ok(None);
    }

    archive::tar_gz(path, WHAT, &SDIST_WANTED, limit, MAX_INFLATED).map(Some)
}

/// `echo-1.0/PKG-INFO`, and not `echo-1.0/src/echo.egg-info/PKG-INFO`.
///
/// A leading `./` is how some tar tools write every name.
fn is_top_level_pkg_info(name: &str) -> bool {
    name.trim_start_matches("./")
        .strip_suffix(PKG_INFO)
        .is_some_and(|directory| !directory.is_empty() && !directory.contains('/'))
}

/// `echo-1.0/echo.egg-info/PKG-INFO`, and not
/// `echo-1.0/src/echo.egg-info/PKG-INFO`.
fn is_egg_info_pkg_info(name: &str) -> bool {
    let Some(path) = name.trim_start_matches("./").strip_suffix(PKG_INFO) else {
        return false;
    };

    let Some((top, directory)) = path.split_once('/') else {
        return false;
    };

    !top.is_empty()
        && !directory.contains('/')
        && directory
            .strip_suffix(EGG_INFO)
            .is_some_and(|stem| !stem.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::Error;
    use std::io::Write as _;

    const LIMIT: ByteLimit = ByteLimit::kib(4);

    const DOCUMENT: &[u8] = b"Name: echo\nVersion: 1.0\n";

    fn tar_gz_file(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp");
        let encoder = flate2::write::GzEncoder::new(
            file.reopen().expect("reopen"),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);

        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            builder
                .append_data(&mut header, name, *body)
                .expect("entry");
        }

        builder
            .into_inner()
            .expect("tar finished")
            .finish()
            .expect("gzip finished");

        file
    }

    fn read(entries: &[(&str, &[u8])]) -> Result<String> {
        let file = tar_gz_file(entries);

        archive::tar_gz(file.path(), WHAT, &SDIST_WANTED, LIMIT, MAX_INFLATED)
    }

    #[test]
    fn metadata_read() {
        let read = read(&[("echo-1.0/setup.py", b""), ("echo-1.0/PKG-INFO", DOCUMENT)]);

        assert_eq!(read.expect("read").as_bytes(), DOCUMENT);
    }

    #[test]
    fn metadata_accepts_dot_prefix() {
        let read = read(&[("./echo-1.0/PKG-INFO", DOCUMENT)]);

        assert_eq!(read.expect("read").as_bytes(), DOCUMENT);
    }

    /// setuptools' own copy under `egg-info` is not the sdist's document.
    #[test]
    fn metadata_ignores_nested_pkg_info() {
        let read = read(&[
            ("echo-1.0/src/echo.egg-info/PKG-INFO", b"Name: other\n"),
            ("echo-1.0/PKG-INFO", DOCUMENT),
        ]);

        assert_eq!(read.expect("read").as_bytes(), DOCUMENT);
    }

    /// The `mysql-connector-python` 8.3.0 shape: no top-level `PKG-INFO`.
    #[test]
    fn metadata_falls_back_to_egg_info() {
        let read = read(&[
            ("echo-1.0/setup.py", b""),
            ("echo-1.0/echo-1.0-py3.8.egg-info/PKG-INFO", DOCUMENT),
        ]);

        assert_eq!(read.expect("read").as_bytes(), DOCUMENT);
    }

    /// The top-level document wins even when the egg-info copy comes first.
    #[test]
    fn metadata_prefers_top_level() {
        let read = read(&[
            ("echo-1.0/echo.egg-info/PKG-INFO", b"Name: other\n"),
            ("echo-1.0/PKG-INFO", DOCUMENT),
        ]);

        assert_eq!(read.expect("read").as_bytes(), DOCUMENT);
    }

    #[test]
    fn metadata_ignores_deep_egg_info() {
        let read = read(&[("echo-1.0/src/echo.egg-info/PKG-INFO", DOCUMENT)]);

        assert!(matches!(read, Err(Error::Malformed { .. })), "{read:?}");
    }

    #[test]
    fn metadata_refuses_two_egg_infos() {
        let read = read(&[
            ("echo-1.0/a.egg-info/PKG-INFO", DOCUMENT),
            ("echo-1.0/b.egg-info/PKG-INFO", DOCUMENT),
        ]);

        let refused = read.expect_err("two");
        assert!(refused.to_string().contains("egg-info"), "{refused}");
    }

    #[test]
    fn egg_info_pattern() {
        assert!(is_egg_info_pkg_info("echo-1.0/echo.egg-info/PKG-INFO"));
        assert!(is_egg_info_pkg_info("./echo-1.0/echo.egg-info/PKG-INFO"));
        assert!(!is_egg_info_pkg_info("echo-1.0/PKG-INFO"));
        assert!(!is_egg_info_pkg_info("echo-1.0/.egg-info/PKG-INFO"));
        assert!(!is_egg_info_pkg_info("echo-1.0/src/echo.egg-info/PKG-INFO"));
        assert!(!is_egg_info_pkg_info("echo.egg-info/PKG-INFO"));
        assert!(!is_egg_info_pkg_info("/echo.egg-info/PKG-INFO"));
    }

    #[test]
    fn metadata_refuses_two_pkg_infos() {
        let read = read(&[("a-1.0/PKG-INFO", DOCUMENT), ("b-1.0/PKG-INFO", DOCUMENT)]);

        assert!(matches!(read, Err(Error::Malformed { .. })), "{read:?}");
    }

    #[test]
    fn metadata_refuses_missing() {
        let read = read(&[("echo-1.0/setup.py", b"")]);

        assert!(matches!(read, Err(Error::Malformed { .. })), "{read:?}");
    }

    #[test]
    fn metadata_refuses_oversized() {
        let huge = vec![b'x'; LIMIT.get() as usize + 1];
        let refused = read(&[("echo-1.0/PKG-INFO", &huge)]).expect_err("too large");

        assert!(refused.to_string().contains("declares"), "{refused}");
    }

    /// Compressible to almost nothing, and walked past on the way to the
    /// document: the shape of a bomb, stopped by the inflated cap.
    #[test]
    fn metadata_refuses_inflated_past_cap() {
        let filler = vec![0u8; ByteLimit::kib(64).get() as usize];
        let file = tar_gz_file(&[
            ("echo-1.0/filler", &filler),
            ("echo-1.0/PKG-INFO", DOCUMENT),
        ]);

        let refused = archive::tar_gz(file.path(), WHAT, &SDIST_WANTED, LIMIT, ByteLimit::kib(16))
            .expect_err("capped");

        assert!(
            refused.to_string().contains("decompresses past"),
            "{refused}"
        );
    }

    #[test]
    fn metadata_refuses_non_archive() {
        let mut file = tempfile::NamedTempFile::new().expect("temp");
        file.write_all(b"not a tar.gz").expect("written");

        assert!(archive::tar_gz(file.path(), WHAT, &SDIST_WANTED, LIMIT, MAX_INFLATED).is_err());
    }

    #[test]
    fn metadata_zip_read() {
        let file = tempfile::NamedTempFile::new().expect("temp");
        let mut writer = zip::ZipWriter::new(file.reopen().expect("reopen"));

        writer
            .start_file(
                "echo-1.0/PKG-INFO",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("entry");
        writer.write_all(DOCUMENT).expect("written");
        writer.finish().expect("finished");

        let read = metadata(file.path(), "echo-1.0.zip", LIMIT).expect("read");

        assert_eq!(read.as_deref().map(str::as_bytes), Some(DOCUMENT));
    }

    fn zip_file(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
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
    fn metadata_zip_falls_back_to_egg_info() {
        let file = zip_file(&[("echo-1.0/echo.egg-info/PKG-INFO", DOCUMENT)]);

        let read = metadata(file.path(), "echo-1.0.zip", LIMIT).expect("read");

        assert_eq!(read.as_deref().map(str::as_bytes), Some(DOCUMENT));
    }

    #[test]
    fn metadata_zip_prefers_top_level() {
        let file = zip_file(&[
            ("echo-1.0/echo.egg-info/PKG-INFO", b"Name: other\n"),
            ("echo-1.0/PKG-INFO", DOCUMENT),
        ]);

        let read = metadata(file.path(), "echo-1.0.zip", LIMIT).expect("read");

        assert_eq!(read.as_deref().map(str::as_bytes), Some(DOCUMENT));
    }

    #[test]
    fn metadata_zip_refuses_missing() {
        let file = zip_file(&[("echo-1.0/setup.py", b"")]);

        let refused = metadata(file.path(), "echo-1.0.zip", LIMIT).expect_err("missing");

        assert!(refused.to_string().contains("holds no"), "{refused}");
    }

    #[test]
    fn metadata_skips_other_forms() {
        let file = tempfile::NamedTempFile::new().expect("temp");

        assert_eq!(
            metadata(file.path(), "echo-1.0.tar.bz2", LIMIT).expect("skipped"),
            None
        );
    }
}
