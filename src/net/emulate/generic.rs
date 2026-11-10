//! The generic emulation: a directory listed as a raw repository.
//!
//! ```text
//!   GET {repository}/?api=generic-list&prefix={p}[&digests=sha256]
//! ```
//!
//! Every file under the repository whose path starts with `prefix`, a
//! literal match as a repository manager's prefix search is: `a/b` reaches
//! `a/b/c.txt` and `a/bc.txt`. Paths are relative to the repository and
//! sorted. A reader re-reads each through its mapping rather than trusting
//! the prefix.
//!
//! `digests=sha256` hashes every file listed, which reads each one whole.
//! A resolution asks for it, to state what it is about to copy; a walk of
//! the whole repository does not.
//!
//! The wire types live here so the emulation and its reader agree on them
//! by construction.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::fs::{Content, Refusal, Root};
use crate::model::DigestAlg;
use crate::net::{encode_unreserved, normalized_base};

/// The query key naming an emulation.
pub(super) const API: &str = "api";

/// This emulation's name.
pub(super) const LIST: &str = "generic-list";

const PREFIX: &str = "prefix";
const DIGESTS: &str = "digests";
const SHA256: &str = "sha256";

/// One listing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub items: Vec<Item>,

    /// Names the walk passed over, and why; see [`Skipped`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<Skipped>,
}

/// One listed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Relative to the repository, `/`-separated.
    pub path: String,
    pub size: u64,

    /// When the file was last modified, which stands in for when it was
    /// published: a directory records nothing closer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,

    /// Hex, when the listing was asked for digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// A name under the prefix that is not listed: a link the host skips, a
/// name that is not UTF-8, a directory that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

/// Whether a listing hashes what it lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digests {
    Omitted,
    Sha256,
}

/// The listing of `repository` under `prefix`.
pub fn listing_url(repository: &str, prefix: &str, digests: Digests) -> String {
    let hashed = match digests {
        Digests::Omitted => String::new(),
        Digests::Sha256 => format!("&{DIGESTS}={SHA256}"),
    };

    format!(
        "{}/?{API}={LIST}&{PREFIX}={}{hashed}",
        normalized_base(repository),
        encode_unreserved(prefix),
    )
}

/// Answer one listing of the directory `repository`, relative to `root`.
///
/// The query has already been read past `api`.
///
/// Not paged, as a directory listing is not: the whole answer is built in
/// memory, and a repository of a great many files is a large response.
/// Worth revisiting for very large directories, with a cursor carrying the
/// last path returned.
pub(super) fn answer(
    root: &Root,
    repository: &Path,
    query: &[(String, String)],
) -> Result<Listing, Refusal> {
    let mut prefix = "";
    let mut digests = Digests::Omitted;

    for (key, value) in query {
        match (key.as_str(), value.as_str()) {
            (PREFIX, given) => prefix = given,
            (DIGESTS, SHA256) => digests = Digests::Sha256,

            _ => {
                return Err(Refusal::Forbidden(format!(
                    "{LIST} takes {PREFIX:?} and {DIGESTS}={SHA256}, not {key}={value}"
                )));
            }
        }
    }

    let prefix = prefix.trim_start_matches('/');

    // Walk only the directory the prefix is inside of; the rest of the
    // prefix is matched against each path.
    let within = prefix
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);

    let walked = match root.walk(repository, Path::new(within)) {
        Ok(walked) => walked,

        // A prefix reaching nothing lists nothing; only a missing
        // repository is missing.
        Err(Refusal::Missing) if !within.is_empty() => return Ok(Listing::default()),
        Err(refusal) => return Err(refusal),
    };

    let mut items = Vec::new();

    for entry in walked.entries {
        if !entry.path.starts_with(prefix) {
            continue;
        }

        let sha256 = match digests {
            Digests::Omitted => None,
            Digests::Sha256 => Some(sha256_of(&entry.content)?),
        };

        items.push(Item {
            path: entry.path,
            size: entry.size,
            modified: entry.modified,
            sha256,
        });
    }

    let skipped = walked
        .passed
        .into_iter()
        .filter(|passed| passed.path.starts_with(prefix))
        .map(|passed| Skipped {
            path: passed.path,
            reason: passed.reason,
        })
        .collect();

    Ok(Listing { items, skipped })
}

fn sha256_of(content: &Content) -> Result<String, Refusal> {
    match content {
        Content::Link(text) => {
            use sha2::Digest as _;

            Ok(hex::encode(sha2::Sha256::digest(text)))
        }

        Content::File(path) => {
            let found =
                crate::net::files::digests_of(path, &[DigestAlg::Sha256]).map_err(|err| {
                    Refusal::Failed {
                        path: path.clone(),
                        source: std::io::Error::other(err.to_string()),
                    }
                })?;

            found
                .into_iter()
                .next()
                .map(|(_, hex)| hex)
                .ok_or_else(|| Refusal::Failed {
                    path: path.clone(),
                    source: std::io::Error::other("no digest computed"),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::emulate::Symlinks;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::create_dir_all(dir.path().join("repo/a/b")).expect("dirs");
        std::fs::create_dir_all(dir.path().join("repo/ab")).expect("dirs");
        std::fs::write(dir.path().join("repo/a/one.txt"), b"one").expect("file");
        std::fs::write(dir.path().join("repo/a/b/two.txt"), b"two").expect("file");
        std::fs::write(dir.path().join("repo/ab/three.txt"), b"three").expect("file");

        dir
    }

    fn query(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn paths(listing: &Listing) -> Vec<&str> {
        listing
            .items
            .iter()
            .map(|item| item.path.as_str())
            .collect()
    }

    fn list(dir: &tempfile::TempDir, pairs: &[(&str, &str)]) -> Listing {
        let root = Root::new(dir.path().to_path_buf(), Symlinks::AsFile);

        answer(&root, Path::new("repo"), &query(pairs)).expect("listed")
    }

    #[test]
    fn url_names_route() {
        assert_eq!(
            listing_url("file:///srv/backup/", "a b/c", Digests::Omitted),
            "file:///srv/backup/?api=generic-list&prefix=a%20b%2Fc"
        );
        assert_eq!(
            listing_url("file:///srv/backup", "", Digests::Sha256),
            "file:///srv/backup/?api=generic-list&prefix=&digests=sha256"
        );
    }

    #[test]
    fn prefix_literal_match() {
        let dir = tree();

        assert_eq!(
            paths(&list(&dir, &[("prefix", "a")])),
            ["a/b/two.txt", "a/one.txt", "ab/three.txt"]
        );
        assert_eq!(
            paths(&list(&dir, &[("prefix", "a/")])),
            ["a/b/two.txt", "a/one.txt"]
        );
        assert_eq!(paths(&list(&dir, &[("prefix", "a/o")])), ["a/one.txt"]);
    }

    #[test]
    fn digests_only_when_asked() {
        let dir = tree();

        let plain = list(&dir, &[("prefix", "a/one")]);
        let hashed = list(&dir, &[("prefix", "a/one"), ("digests", "sha256")]);

        assert_eq!(plain.items[0].sha256, None);
        assert_eq!(
            hashed.items[0].sha256.as_deref(),
            Some("7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed")
        );
    }

    #[test]
    fn prefix_unmatched_lists_nothing() {
        let dir = tree();

        assert!(list(&dir, &[("prefix", "nope/x")]).items.is_empty());
    }

    #[test]
    fn missing_repository_is_missing() {
        let dir = tree();
        let root = Root::new(dir.path().to_path_buf(), Symlinks::AsFile);

        assert!(matches!(
            answer(&root, Path::new("gone"), &[]),
            Err(Refusal::Missing)
        ));
    }

    #[test]
    fn parameter_unknown_refused() {
        let dir = tree();
        let root = Root::new(dir.path().to_path_buf(), Symlinks::AsFile);

        assert!(matches!(
            answer(&root, Path::new("repo"), &query(&[("page", "2")])),
            Err(Refusal::Forbidden(_))
        ));
    }
}
