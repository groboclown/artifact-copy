//! How many bytes a response may occupy in memory.

use std::fmt;

/// A cap on how many bytes a response may occupy in memory.
///
/// A newtype rather than a bare `u64` so a call site cannot pass a timeout,
/// a retry count, or a size in kilobytes by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteLimit(u64);

impl ByteLimit {
    pub const fn bytes(n: u64) -> Self {
        Self(n)
    }

    pub const fn kib(n: u64) -> Self {
        Self(n * 1024)
    }

    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }

    pub fn get(self) -> u64 {
        self.0
    }

    /// A Maven checksum sidecar: 40 hex characters and maybe a filename.
    pub const SIDECAR: ByteLimit = ByteLimit::kib(1);

    /// A POM or `maven-metadata.xml`.
    pub const METADATA: ByteLimit = ByteLimit::mib(8);

    /// An npm packument.  Popular packages run to several megabytes.
    pub const PACKUMENT: ByteLimit = ByteLimit::mib(96);
}

impl fmt::Display for ByteLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_limit_units_convert() {
        assert_eq!(ByteLimit::kib(1).get(), 1024);
        assert_eq!(ByteLimit::mib(1).get(), 1024 * 1024);
        assert_eq!(ByteLimit::SIDECAR.get(), 1024);
    }
}
