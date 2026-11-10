//! `*` and `?` file name patterns, without a regex engine in the module.

/// Marks a pattern that drops what it matches: `!*-alpine-*`.
const EXCLUDE_PREFIX: char = '!';

/// Whether a `files` list keeps `name`.
///
/// Patterns apply in order and the last one matching decides, as in
/// `.gitignore`. A name no pattern matches is kept only when the list has
/// no include patterns, so an exclusion-only list drops just what it names.
///
/// ```text
///   ["*.tar.gz", "!*-alpine-*"]   a.tar.gz kept, a-alpine-x.tar.gz dropped, a.zip dropped
///   ["!*.sig"]                    a.zip kept, a.zip.sig dropped
///   ["!*-alpine-*", "*"]          everything kept: the later "*" wins
/// ```
pub fn keeps(patterns: &[String], name: &str) -> bool {
    let includes = patterns
        .iter()
        .any(|pattern| !pattern.starts_with(EXCLUDE_PREFIX));

    let mut kept = !includes;

    for pattern in patterns {
        let (exclude, glob) = match pattern.strip_prefix(EXCLUDE_PREFIX) {
            Some(glob) => (true, glob),
            None => (false, pattern.as_str()),
        };

        if matches(glob, name) {
            kept = !exclude;
        }
    }

    kept
}

/// Whether `name` matches `pattern`: `*` is any run of characters, `?` is
/// exactly one, and everything else matches itself.
///
/// ```text
///   node-v*-linux-x64.tar.gz   matches   node-v24.1.0-linux-x64.tar.gz
/// ```
pub fn matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();

    let (mut p, mut n) = (0, 0);

    // Where the last `*` was, and the name position it is currently
    // standing in for; a mismatch retries with the star taking one more.
    let mut star: Option<(usize, usize)> = None;

    while n < name.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, n));
                p += 1;
                continue;
            }

            Some('?') => {
                p += 1;
                n += 1;
                continue;
            }

            Some(&c) if c == name[n] => {
                p += 1;
                n += 1;
                continue;
            }

            _ => {}
        }

        let Some((star_p, star_n)) = star else {
            return false;
        };

        star = Some((star_p, star_n + 1));
        p = star_p + 1;
        n = star_n + 1;
    }

    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::{keeps, matches};

    fn list(patterns: &[&str]) -> Vec<String> {
        patterns.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn include_then_exclude() {
        let patterns = list(&["*.tar.gz", "!*-alpine-*"]);

        assert!(keeps(&patterns, "a-linux.tar.gz"));
        assert!(!keeps(&patterns, "a-alpine-linux.tar.gz"));
        assert!(!keeps(&patterns, "a.zip"));
    }

    #[test]
    fn exclude_only() {
        let patterns = list(&["!*.sig"]);

        assert!(keeps(&patterns, "a.zip"));
        assert!(!keeps(&patterns, "a.zip.sig"));
    }

    #[test]
    fn last_match_wins() {
        let patterns = list(&["!*-alpine-*", "*"]);

        assert!(keeps(&patterns, "a-alpine-x.tar.gz"));
    }

    #[test]
    fn empty_list_keeps() {
        assert!(keeps(&[], "a"));
    }

    #[test]
    fn literal() {
        assert!(matches("a.txt", "a.txt"));
        assert!(!matches("a.txt", "b.txt"));
    }

    #[test]
    fn star() {
        assert!(matches(
            "node-v*-linux-x64.tar.gz",
            "node-v24.1.0-linux-x64.tar.gz"
        ));
        assert!(!matches(
            "node-v*-linux-x64.tar.gz",
            "node-v24.1.0-linux-x64.tar.xz"
        ));
        assert!(matches("*", ""));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
    }

    #[test]
    fn question() {
        assert!(matches("v?", "v1"));
        assert!(!matches("v?", "v12"));
    }
}
