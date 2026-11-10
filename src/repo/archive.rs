//! Reading one document out of an untrusted archive.
//!
//! A package format often carries its own description inside the payload:
//! an sdist's `PKG-INFO`, a wheel's `METADATA`, an npm tarball's
//! `package.json`. Opening one is opening untrusted input, so each reader
//! bounds the work before it is done.
//!
//! A tar has no central directory, so finding the one entry wanted means
//! inflating the whole stream, and the caps follow from that:
//!
//! - **How many entries** are walked.
//! - **How many bytes** are inflated in all, entries skipped included. A
//!   gzip bomb costs time rather than memory, and this bounds the time.
//! - **Exactly one** entry in a wanted place, a regular file.
//! - **Its declared size**, before reading it.
//!
//! Reaching any of them is an error, not a truncated document: a document
//! cut short would describe a different package.

use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;

use crate::core::error::{Error, Result};
use crate::net::ByteLimit;

/// How many entries a tar may hold.
///
/// Far past any real package, and small enough that walking the headers
/// costs nothing.
const MAX_ENTRIES: usize = 100_000;

/// How many bytes a tar may inflate to, in all.
///
/// Well past the largest sdists PyPI holds, which run to a few hundred
/// megabytes, and a bound on how long a bomb can keep the walk busy.
pub(super) const MAX_INFLATED: ByteLimit = ByteLimit::mib(1024);

/// One place an archive's metadata document may be.
pub(super) struct Wanted {
    /// The place, as errors name it: `top-level */PKG-INFO`.
    pub(super) label: &'static str,

    pub(super) matches: fn(&str) -> bool,
}

/// The one entry of the gzipped tar at `path` from the first place in
/// `wanted` that holds any, no larger than `limit`, inflating no more than
/// `inflated` in all. `what` names the archive in errors: `sdist`.
pub(super) fn tar_gz(
    path: &Path,
    what: &'static str,
    wanted: &[Wanted],
    limit: ByteLimit,
    inflated: ByteLimit,
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

    let mut counted = Counted::new(GzDecoder::new(std::io::BufReader::new(file)), inflated);
    let walked = walk(tar::Archive::new(&mut counted), wanted, limit);

    // Checked first: tar reports the cap as whatever read it interrupted,
    // which would name the wrong cause.
    if counted.past {
        return Err(malformed(format!(
            "it decompresses past {} bytes",
            inflated.get()
        )));
    }

    walked.map_err(malformed)
}

/// Every entry of `archive`, keeping the one entry from the first place in
/// `wanted` that holds any.
fn walk<R: Read>(
    mut archive: tar::Archive<R>,
    wanted: &[Wanted],
    limit: ByteLimit,
) -> std::result::Result<String, String> {
    let unreadable = |err: std::io::Error| format!("not a readable tar.gz: {err}");

    // One slot per place: a tar has no directory, so a later entry may
    // still be the better one.
    let mut found: Vec<Option<(String, Vec<u8>)>> = vec![None; wanted.len()];

    for (seen, entry) in archive.entries().map_err(unreadable)?.enumerate() {
        if seen >= MAX_ENTRIES {
            return Err(format!("it lists more than {MAX_ENTRIES} entries"));
        }

        let mut entry = entry.map_err(unreadable)?;
        let name = entry
            .path()
            .map_err(unreadable)?
            .to_string_lossy()
            .into_owned();

        let Some(place) = wanted.iter().position(|place| (place.matches)(&name)) else {
            continue;
        };

        if !entry.header().entry_type().is_file() {
            return Err(format!("{name} is not a regular file"));
        }

        if found[place].is_some() {
            return Err(format!(
                "it holds more than one {} entry",
                wanted[place].label
            ));
        }

        if entry.size() > limit.get() {
            return Err(format!(
                "{name} declares {} bytes, more than {}",
                entry.size(),
                limit.get()
            ));
        }

        // The header's size bounds the entry's stream, so unlike a zip's
        // declared size it cannot lie about how much is read here.
        let mut bytes = Vec::new();

        entry
            .read_to_end(&mut bytes)
            .map_err(|err| format!("{name}: {err}"))?;

        found[place] = Some((name, bytes));
    }

    let Some((name, bytes)) = found.into_iter().flatten().next() else {
        let labels: Vec<&str> = wanted.iter().map(|place| place.label).collect();

        return Err(format!("it holds no {} entry", labels.join(" or ")));
    };

    String::from_utf8(bytes).map_err(|_| format!("{name} is not UTF-8"))
}

/// A reader that fails once more than `cap` bytes have passed through it,
/// and remembers that it did.
struct Counted<R> {
    inner: R,
    read_bytes: u64,
    cap: ByteLimit,
    past: bool,
}

impl<R> Counted<R> {
    fn new(inner: R, cap: ByteLimit) -> Self {
        Self {
            inner,
            read_bytes: 0,
            cap,
            past: false,
        }
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read_bytes += read as u64;

        if self.read_bytes > self.cap.get() {
            self.past = true;

            return Err(std::io::Error::other("inflated past the cap"));
        }

        Ok(read)
    }
}
