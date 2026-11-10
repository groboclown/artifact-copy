//! What both AQL enumerators share: the endpoint, paging, time format,
//! and the login rule.

use chrono::{DateTime, Utc};

use crate::core::error::{Error, Result};
use crate::ext::Options;
use crate::net::ByteLimit;
use crate::repo::enumerate::Login;

/// The AQL endpoint, relative to the Artifactory base URL.
pub(super) const SEARCH: &str = "api/search/aql";

/// How many **files** to ask for at a time.
///
/// Files, not artifacts: see the `enumerator` module documentation. A
/// Maven artifact is six or more rows, so this is a smaller page of results
/// than it looks.
pub(super) const PAGE_ROWS: usize = 500;

/// A page of rows with their properties.
pub(super) const PAGE_LIMIT: ByteLimit = ByteLimit::mib(16);

/// Whether to walk on a host with no credentials.
const ANONYMOUS: &str = "anonymous";

/// The `anonymous` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anonymous {
    /// Refuse a host with no credentials before the walk: AQL needs a login.
    Refuse,

    /// Send the queries anyway, for a release that allows anonymous AQL.
    Attempt,
}

impl Anonymous {
    fn read(options: &Options, kind: &str) -> Result<Self> {
        match options.string(ANONYMOUS)? {
            None | Some("refuse") => Ok(Self::Refuse),
            Some("attempt") => Ok(Self::Attempt),

            Some(other) => Err(Error::Config(format!(
                "the {kind} enumerator's {ANONYMOUS:?} option is \"refuse\" or \"attempt\", \
                 not {other:?}"
            ))),
        }
    }
}

/// A login unless the `anonymous` option says to try without one.
///
/// Every edition refuses AQL to an anonymous caller (403 on OSS 7.161.26
/// and on 6.9.1), even on a repository that allows anonymous reads.
pub(super) fn login(options: &Options, kind: &str) -> Result<Login> {
    match Anonymous::read(options, kind)? {
        Anonymous::Refuse => Ok(Login::Required),
        Anonymous::Attempt => Ok(Login::Optional),
    }
}

/// AQL's spelling of a moment: `2026-09-29T15:42:48.678Z`.
pub(super) fn aql_time(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}
