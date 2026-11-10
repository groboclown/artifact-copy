//! What an extension instance is allowed to do.
//!
//! Bound to the instance when it is resolved from config, and checked on
//! every call -- by the host, not by the extension. A built-in npm source
//! configured for `registry.npmjs.org` cannot fetch from anywhere else, and
//! that is true because it has no HTTP client of its own to try with, not
//! because it promises not to.

use url::Url;

use crate::config::TlsVerify;
use crate::net::ByteLimit;

/// The default ceiling on a response held in memory, when `setup` names
/// none.
const DEFAULT_MAX_IN_MEMORY: ByteLimit = ByteLimit::mib(64);

/// Default cap on files an extension may leave in its sandbox.
const DEFAULT_MAX_FILES: usize = 4_096;

/// Default cap on the total bytes in a sandbox.
const DEFAULT_MAX_SANDBOX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Constraints {
    /// URL prefixes this extension may fetch, from its configured host(s).
    /// Empty means it may fetch nothing at all.
    allowed: Vec<Url>,

    max_in_memory: ByteLimit,
    max_files: usize,
    max_sandbox_bytes: u64,
    tls: TlsVerify,
}

impl Default for Constraints {
    /// Permits no network access.  An extension that was never given a host
    /// should not reach one.
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            max_in_memory: DEFAULT_MAX_IN_MEMORY,
            max_files: DEFAULT_MAX_FILES,
            max_sandbox_bytes: DEFAULT_MAX_SANDBOX_BYTES,
            tls: TlsVerify::Enabled,
        }
    }
}

impl Constraints {
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit fetches at or below this URL.
    pub fn allow(mut self, prefix: &str) -> Result<Self, String> {
        let parsed =
            Url::parse(prefix).map_err(|source| format!("{prefix:?} is not a URL: {source}"))?;

        self.allowed.push(parsed);

        Ok(self)
    }

    pub fn with_max_in_memory(mut self, max: ByteLimit) -> Self {
        self.max_in_memory = max;
        self
    }

    pub fn with_tls(mut self, tls: TlsVerify) -> Self {
        self.tls = tls;
        self
    }

    pub fn max_in_memory(&self) -> ByteLimit {
        self.max_in_memory
    }

    pub fn max_files(&self) -> usize {
        self.max_files
    }

    pub fn max_sandbox_bytes(&self) -> u64 {
        self.max_sandbox_bytes
    }

    pub fn tls(&self) -> TlsVerify {
        self.tls
    }

    /// The prefixes this extension may fetch, for an error message.
    pub fn allowed(&self) -> Vec<String> {
        self.allowed.iter().map(Url::to_string).collect()
    }

    /// Whether a URL is within any allowed prefix.
    ///
    /// Compared by parsed parts rather than by string prefix, because
    /// `https://example.com` is a string prefix of
    /// `https://example.com.evil.test` and emphatically does not authorize
    /// it.
    pub fn allows(&self, url: &str) -> bool {
        let Ok(candidate) = Url::parse(url) else {
            return false;
        };

        self.allowed.iter().any(|prefix| covers(prefix, &candidate))
    }

    /// Narrow to the smaller of the two caps.
    ///
    /// A call site may ask for less than the configured ceiling -- a Maven
    /// checksum sidecar asks for 1 KiB -- but never for more.
    pub fn cap(&self, requested: ByteLimit) -> ByteLimit {
        requested.min(self.max_in_memory)
    }
}

/// Whether `prefix` authorizes `candidate`.
fn covers(prefix: &Url, candidate: &Url) -> bool {
    if prefix.scheme() != candidate.scheme() {
        return false;
    }

    if prefix.host_str() != candidate.host_str() {
        return false;
    }

    // `port_or_known_default` so `https://x` and `https://x:443` agree.
    if prefix.port_or_known_default() != candidate.port_or_known_default() {
        return false;
    }

    // The prefix path must end at a segment boundary, or `/maven2` would
    // authorize `/maven2-staging`.
    let base = prefix.path();
    let path = candidate.path();

    if base == "/" || base.is_empty() {
        return true;
    }

    let base = base.strip_suffix('/').unwrap_or(base);

    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn central() -> Constraints {
        Constraints::new()
            .allow("https://repo1.maven.org/maven2/")
            .expect("valid")
    }

    #[test]
    fn url_under_prefix_allowed() {
        let rules = central();

        assert!(rules.allows("https://repo1.maven.org/maven2/org/apache/x.pom"));
        assert!(rules.allows("https://repo1.maven.org/maven2/"));
    }

    /// The reason this compares parsed parts rather than strings.
    #[test]
    fn url_lookalike_host_refused() {
        let rules = central();

        assert!(!rules.allows("https://repo1.maven.org.evil.test/maven2/x"));
        assert!(!rules.allows("https://evil.test/maven2/x"));
    }

    /// And the reason the path must end at a segment boundary.
    #[test]
    fn url_sibling_path_refused() {
        let rules = central();

        assert!(!rules.allows("https://repo1.maven.org/maven2-staging/x"));
    }

    #[test]
    fn url_different_scheme_refused() {
        let rules = central();

        assert!(!rules.allows("http://repo1.maven.org/maven2/x"));
    }

    #[test]
    fn url_different_port_refused() {
        let rules = Constraints::new()
            .allow("https://internal.test:8443/repo/")
            .expect("valid");

        assert!(rules.allows("https://internal.test:8443/repo/x"));
        assert!(!rules.allows("https://internal.test:9443/repo/x"));
    }

    /// The default port is the same port.
    #[test]
    fn url_explicit_default_port_matches() {
        let rules = Constraints::new()
            .allow("https://example.test/")
            .expect("valid");

        assert!(rules.allows("https://example.test:443/x"));
    }

    /// An extension that was given no host reaches nothing.  This is the
    /// safe direction to fail in.
    #[test]
    fn url_none_allowed_by_default() {
        let rules = Constraints::new();

        assert!(!rules.allows("https://example.test/"));
        assert!(rules.allowed().is_empty());
    }

    #[test]
    fn url_under_any_prefix_allowed() {
        let rules = Constraints::new()
            .allow("https://a.test/")
            .unwrap()
            .allow("https://b.test/")
            .unwrap();

        assert!(rules.allows("https://a.test/x"));
        assert!(rules.allows("https://b.test/y"));
        assert!(!rules.allows("https://c.test/z"));
    }

    #[test]
    fn url_nonsense_refused_without_panic() {
        assert!(!central().allows("not a url"));
    }

    /// A call site may ask for less than the ceiling, never for more.
    #[test]
    fn caps_narrow_but_never_widen() {
        let rules = central().with_max_in_memory(ByteLimit::mib(8));

        assert_eq!(rules.cap(ByteLimit::kib(1)), ByteLimit::kib(1));
        assert_eq!(rules.cap(ByteLimit::mib(64)), ByteLimit::mib(8));
    }
}
