//! Wildcard matching, shared by the two places that need it.
//!
//! Lives here because its consumers sit in unrelated subtrees --
//! [`crate::lock`] matches filenames against format patterns, and
//! [`crate::policy`] matches purls against policy rules -- with no common
//! parent below the crate root. Two copies of a backtracking matcher is a
//! correctness liability: a fix or a subtle bug lands in one and nobody
//! editing it has reason to look at the other.
//!
//! # `*` crosses `/`, deliberately
//!
//! Filename globbing conventionally stops `*` at a path separator, so that
//! `*.json` does not match `a/b.json`. **This does not**, and the two
//! callers are why:
//!
//! - A purl is full of separators -- `pkg:npm/@scope/name@1.0` -- and a
//!   policy rule like `pkg:maven/org.example/*` is meant to reach all of
//!   them.
//! - The lock patterns are bare filenames (`package-lock.json`,
//!   `pylock*.toml`) with no separator to stop at, so the rule costs
//!   nothing there today.
//!
//! Each kind of text has its own function, so a call site says what it
//! matches: [`matches_purl`] and [`matches_file_name`]. Both share one
//! matcher today. If file names ever need the conventional rule, only
//! [`matches_file_name`] changes, rather than a flag on a shared function
//! putting the decision at the call sites, where it would get copied
//! wrongly.

/// Whether `purl` matches the purl glob `pattern`.
///
/// `*` crosses `/`, so `pkg:maven/org.example/*` reaches every artifact in
/// the group.
pub(crate) fn matches_purl(pattern: &str, purl: &str) -> bool {
    wildcard(pattern, purl)
}

/// Whether the file name `name` matches the file glob `pattern`, such as
/// `pylock*.toml`.
///
/// `*` also crosses `/` here, which costs nothing while the names matched
/// hold no separator.
pub(crate) fn matches_file_name(pattern: &str, name: &str) -> bool {
    wildcard(pattern, name)
}

/// Whether `text` matches `pattern`, where `*` is any run of characters
/// (including none, and including `/`) and `?` is exactly one.
///
/// Iterative with backtracking, so a pattern full of `*` cannot go
/// exponential.
fn wildcard(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();

    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut retry = 0usize;

    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some(p);
                retry = t;
                p += 1;
            }

            Some('?') => {
                p += 1;
                t += 1;
            }

            Some(ch) if *ch == text[t] => {
                p += 1;
                t += 1;
            }

            _ => match star {
                Some(index) => {
                    p = index + 1;
                    retry += 1;
                    t = retry;
                }
                None => return false,
            },
        }
    }

    pattern[p..].iter().all(|ch| *ch == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_literal_matches_only_itself() {
        assert!(wildcard("package-lock.json", "package-lock.json"));
        assert!(!wildcard("package-lock.json", "package-lock.jsonx"));
        assert!(!wildcard("package-lock.json", "npm-shrinkwrap.json"));
    }

    #[test]
    fn star_matches_any_run_including_none() {
        assert!(wildcard("pylock*.toml", "pylock.toml"));
        assert!(wildcard("pylock*.toml", "pylock.prod.toml"));
        assert!(!wildcard("pylock*.toml", "poetry.lock"));
    }

    #[test]
    fn question_mark_matches_exactly_one() {
        assert!(wildcard("a?c", "abc"));
        assert!(!wildcard("a?c", "ac"));
        assert!(!wildcard("a?c", "abbc"));
    }

    /// The property purl rules depend on, and the one a conventional
    /// filename globber would get the other way round.
    #[test]
    fn star_crosses_path_separator() {
        assert!(matches_purl(
            "pkg:maven/org.example/*",
            "pkg:maven/org.example/lib"
        ));
        assert!(matches_purl("pkg:npm/*", "pkg:npm/%40scope/name"));
        assert!(wildcard("a/*", "a/b/c/d"));
    }

    /// Trailing `*`s must not require anything left to consume, or
    /// `pkg:npm/lodash*` would fail against `pkg:npm/lodash`.
    #[test]
    fn star_trailing_matches_exhausted_input() {
        assert!(wildcard("abc*", "abc"));
        assert!(wildcard("abc***", "abc"));
        assert!(wildcard("*", ""));
        assert!(wildcard("***", ""));
    }

    #[test]
    fn pattern_empty_matches_only_empty_text() {
        assert!(wildcard("", ""));
        assert!(!wildcard("", "a"));
    }

    /// Backtracking, not recursion: a pathological pattern must return
    /// rather than run for the age of the universe.
    #[test]
    fn pattern_all_stars_not_exponential() {
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(200);

        let started = std::time::Instant::now();

        assert!(!wildcard(pattern, &text));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "took {:?}",
            started.elapsed()
        );
    }

    /// Patterns and text are compared by character, not by byte, so a
    /// multi-byte name cannot be split mid-character.
    #[test]
    fn match_by_character_not_byte() {
        assert!(wildcard("caf?", "caf\u{e9}"));
        assert!(wildcard("*\u{e9}", "caf\u{e9}"));
    }
}
