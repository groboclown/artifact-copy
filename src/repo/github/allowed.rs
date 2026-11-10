//! Which GitHub repositories a source may read.
//!
//! Adding GitHub as a source does not make all of GitHub fair game, so a
//! `github` source names the repositories it serves, and it is required:
//!
//! ```text
//!   repositories: ["gitleaks/*", "artifactory/web-*", "rust-lang/rust"]
//! ```
//!
//! The owner is literal and the repository name may hold `*`, which
//! matches any run of characters: trust is granted to an owner, never
//! across owners, so `*/gitleaks` and `git*/x` are refused. Both compare
//! ignoring case, as GitHub resolves names.

use crate::core::error::{Error, Result};
use crate::ext::Options;

/// The option naming the repositories.
pub(super) const REPOSITORIES: &str = "repositories";

/// What matches any run of characters in a repository name.
const WILDCARD: char = '*';

/// One `owner/pattern` entry, lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    owner: String,
    repo: String,
}

/// The repositories one source may read.
#[derive(Debug, Clone)]
pub(super) struct Allowed {
    entries: Vec<Entry>,
}

impl Allowed {
    /// Read and check the `repositories` option.
    pub(super) fn read(options: &Options) -> Result<Self> {
        let listed = options.string_list(REPOSITORIES)?.unwrap_or_default();

        if listed.is_empty() {
            return Err(Error::Config(format!(
                "a github source needs a non-empty {REPOSITORIES:?} option naming the \
                 repositories it may read, such as [\"gitleaks/*\"]"
            )));
        }

        let entries = listed.into_iter().map(entry).collect::<Result<Vec<_>>>()?;

        Ok(Self { entries })
    }

    /// Whether `owner/repo` is listed.
    pub(super) fn permits(&self, owner: &str, repo: &str) -> bool {
        let owner = owner.to_lowercase();
        let repo = repo.to_lowercase();

        self.entries
            .iter()
            .any(|entry| entry.owner == owner && matches(&entry.repo, &repo))
    }

    /// The entries as configured, for a refusal that names them.
    pub(super) fn describe(&self) -> String {
        self.entries
            .iter()
            .map(|entry| format!("{}/{}", entry.owner, entry.repo))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// One `owner/pattern`, refused where the owner holds a wildcard or either
/// half is missing.
fn entry(text: &str) -> Result<Entry> {
    let refused = |why: &str| {
        Err(Error::Config(format!(
            "{REPOSITORIES:?} entry {text:?} {why}; write owner/repo or owner/pattern, \
             such as gitleaks/* or artifactory/web-*"
        )))
    };

    let Some((owner, repo)) = text.trim().split_once('/') else {
        return refused("has no owner");
    };

    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return refused("is not owner/repo");
    }

    if owner.contains(WILDCARD) {
        return refused("puts a wildcard in the owner, which would trust every owner it matches");
    }

    Ok(Entry {
        owner: owner.to_lowercase(),
        repo: repo.to_lowercase(),
    })
}

/// Whether `name` matches `pattern`, where `*` is any run of characters.
///
/// ```text
///   web-*   matches  web-ui, web-       not  api-web
///   *-cli   matches  fmt-cli            not  fmt-cli-x
/// ```
fn matches(pattern: &str, name: &str) -> bool {
    // No wildcard: the whole name.
    if !pattern.contains(WILDCARD) {
        return name == pattern;
    }

    let mut parts = pattern.split(WILDCARD);
    let first = parts.next().unwrap_or_default();

    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };

    let parts: Vec<&str> = parts.collect();

    // Every middle part in order, as early as it appears; the last anchors
    // the end.
    let Some((last, middle)) = parts.split_last() else {
        return true;
    };

    for part in middle {
        let Some(at) = rest.find(part) else {
            return false;
        };

        rest = &rest[at + part.len()..];
    }

    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::options;

    fn allowed(entries: &[&str]) -> Result<Allowed> {
        Allowed::read(&options(serde_json::json!({ REPOSITORIES: entries })))
    }

    #[test]
    fn list_required() {
        assert!(Allowed::read(&Options::default()).is_err());
        assert!(allowed(&[]).is_err());
    }

    /// Trust is granted to an owner, never across owners.
    #[test]
    fn wildcard_owner_refused() {
        for text in ["*/gitleaks", "git*/x", "*/*"] {
            let err = allowed(&[text]).expect_err(text).to_string();

            assert!(err.contains("owner"), "{text}: {err}");
        }
    }

    #[test]
    fn entry_malformed_refused() {
        for text in ["gitleaks", "gitleaks/", "/gitleaks", "a/b/c"] {
            assert!(allowed(&[text]).is_err(), "{text}");
        }
    }

    #[test]
    fn wildcard_repo_matches() {
        let list = allowed(&["gitleaks/*", "artifactory/web-*", "rust-lang/rust"]).expect("reads");

        assert!(list.permits("gitleaks", "gitleaks"));
        assert!(list.permits("artifactory", "web-ui"));
        assert!(list.permits("rust-lang", "rust"));

        assert!(!list.permits("artifactory", "api-web"));
        assert!(!list.permits("rust-lang", "cargo"));
        assert!(!list.permits("other", "gitleaks"));
    }

    /// GitHub resolves names without regard to case.
    #[test]
    fn case_ignored() {
        let list = allowed(&["GitLeaks/Web-*"]).expect("reads");

        assert!(list.permits("gitleaks", "WEB-UI"));
    }

    #[test]
    fn pattern_matching() {
        assert!(matches("web-*", "web-"));
        assert!(matches("*-cli", "fmt-cli"));
        assert!(!matches("*-cli", "fmt-cli-x"));
        assert!(matches("a*b*c", "aXbYc"));
        assert!(!matches("a*b*c", "aXcYb"));
        assert!(matches("*", "anything"));
        assert!(!matches("exact", "exactly"));
    }
}
