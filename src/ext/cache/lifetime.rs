//! How long a cached file may be used, and how long it may stay.
//!
//! Two clocks, because they answer two different questions:
//!
//! ```text
//!   fetched ----- used ----- used ---------------> now
//!      |<-- freshness -->|                         may it still be used?
//!                        |<---- retention ---->|   may it still be kept?
//! ```
//!
//! **Freshness** runs from the fetch. It depends on what the file is: a
//! `maven-metadata.xml` changes whenever a version is published, while a
//! released jar never does. **Retention** runs from the last use, so a file
//! a migration keeps reusing stays and one nobody asks for ages out.
//!
//! `None` means forever for either.

use std::time::Duration;

/// The two limits for one cached file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Lifetime {
    /// How long after its last use the file may be kept.
    pub retention: Option<Duration>,

    /// How long after its fetch the file may be used.
    pub freshness: Option<Duration>,
}

impl Lifetime {
    /// Kept and used forever.
    pub const FOREVER: Lifetime = Lifetime {
        retention: None,
        freshness: None,
    };
}

/// Which limit a cached file passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Retention,
    Freshness,
}

impl Expiry {
    /// The spelling a report records as the `reason` argument.
    pub fn as_str(self) -> &'static str {
        match self {
            Expiry::Retention => "retention",
            Expiry::Freshness => "freshness",
        }
    }
}

/// One `cache-freshness` entry: files whose name matches `pattern` are
/// fresh for `fresh_for`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessRule {
    pattern: String,
    fresh_for: Option<Duration>,
}

impl FreshnessRule {
    /// `pattern` matches a whole file name, with `*` for any run of
    /// characters and `?` for one. `fresh_for` of `None` is forever.
    pub fn new(pattern: impl Into<String>, fresh_for: Option<Duration>) -> Self {
        Self {
            pattern: pattern.into(),
            fresh_for,
        }
    }

    fn matches(&self, name: &str) -> bool {
        wildcard(self.pattern.as_bytes(), name.as_bytes())
    }
}

/// What one source, enumerator, or advisor allows its cached files.
///
/// The rules are already in precedence order -- the binding's own, then
/// `setup`'s, then the built-in ones -- and the first match wins. A file no
/// rule names is fresh forever.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachePolicy {
    retention: Option<Duration>,
    rules: Vec<FreshnessRule>,

    /// The most the binding's repository folder may hold. `None` is no cap.
    size_cap_bytes: Option<u64>,
}

impl CachePolicy {
    /// Every file kept and used forever.
    pub const FOREVER: CachePolicy = CachePolicy {
        retention: None,
        rules: Vec::new(),
        size_cap_bytes: None,
    };

    pub fn new(retention: Option<Duration>, rules: Vec<FreshnessRule>) -> Self {
        Self {
            retention,
            rules,
            size_cap_bytes: None,
        }
    }

    /// Cap the binding's repository folder at `cap_bytes`, when given.
    pub fn with_size_cap(mut self, cap_bytes: Option<u64>) -> Self {
        self.size_cap_bytes = cap_bytes;
        self
    }

    pub fn size_cap_bytes(&self) -> Option<u64> {
        self.size_cap_bytes
    }

    /// The limits for a file named `name`.
    pub fn lifetime(&self, name: &str) -> Lifetime {
        let freshness = self
            .rules
            .iter()
            .find(|rule| rule.matches(name))
            .and_then(|rule| rule.fresh_for);

        Lifetime {
            retention: self.retention,
            freshness,
        }
    }
}

/// Whether `name` matches `pattern`, with `*` and `?` as the only
/// wildcards. Linear in the two lengths: a `*` remembers where it was
/// tried, and a mismatch retries one character further on.
pub(in crate::ext) fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;

    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
            continue;
        }

        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, n));
            p += 1;
            continue;
        }

        let Some((star_p, star_n)) = star else {
            return false;
        };

        p = star_p + 1;
        n = star_n + 1;
        star = Some((star_p, n));
    }

    pattern[p..].iter().all(|&byte| byte == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3_600);

    #[test]
    fn wildcard_matches() {
        assert!(wildcard(b"maven-metadata.xml*", b"maven-metadata.xml"));
        assert!(wildcard(b"maven-metadata.xml*", b"maven-metadata.xml.sha1"));
        assert!(wildcard(b"*.jar", b"core-1.0.jar"));
        assert!(wildcard(b"core-?.0.jar", b"core-1.0.jar"));
        assert!(wildcard(b"*", b""));
        assert!(wildcard(b"a*b*c", b"aXbYbZc"));
    }

    #[test]
    fn wildcard_refuses() {
        assert!(!wildcard(b"*.jar", b"core-1.0.pom"));
        assert!(!wildcard(b"core-?.0.jar", b"core-10.0.jar"));
        assert!(!wildcard(b"index.html", b"index.htm"));
        assert!(!wildcard(b"a*b*c", b"aXbY"));
    }

    /// The binding's own rules come first, so a source can shorten what a
    /// built-in rule allows.
    #[test]
    fn lifetime_first_rule_wins() {
        let policy = CachePolicy::new(
            Some(HOUR),
            vec![
                FreshnessRule::new("maven-metadata.xml", Some(Duration::from_secs(60))),
                FreshnessRule::new("maven-metadata.xml*", Some(HOUR)),
            ],
        );

        let lifetime = policy.lifetime("maven-metadata.xml");

        assert_eq!(lifetime.freshness, Some(Duration::from_secs(60)));
        assert_eq!(lifetime.retention, Some(HOUR));
    }

    /// A rule of forever stops the search, rather than falling through to a
    /// shorter built-in rule further down.
    #[test]
    fn lifetime_forever_rule_stops_search() {
        let policy = CachePolicy::new(
            None,
            vec![
                FreshnessRule::new("packument.json", None),
                FreshnessRule::new("*", Some(HOUR)),
            ],
        );

        assert_eq!(policy.lifetime("packument.json").freshness, None);
        assert_eq!(policy.lifetime("other").freshness, Some(HOUR));
    }

    #[test]
    fn lifetime_unmatched_forever() {
        assert_eq!(CachePolicy::default().lifetime("x.jar"), Lifetime::FOREVER);
    }
}
