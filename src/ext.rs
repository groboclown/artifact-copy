//! What an extension point is given to do its work.
//!
//! Five things are extension points -- **source, target, enumerator, advisory,
//! lock** -- and an ecosystem is extensible without being one; see
//! [`gear`].
//!
//! The rule that shapes everything here:
//!
//! > **No extension point holds an HTTP client. Not even a built-in one.**
//!
//! A built-in npm source is built with an [`ExtHost`] and asks it for a URL;
//! the host decides whether that fetch is permitted, how large the answer
//! may be, which credentials it carries, and whether the certificate is
//! checked. That buys three things. Constraints are enforced in one place
//! instead of being trusted to every implementation. Credentials never leave
//! the host. And caching, retry and per-host concurrency become properties
//! of the tool rather than something each adapter reimplements slightly
//! differently.
//!
//! Downloads land in the host's [`Cache`], which persists between runs and
//! is the channel for anything too large to hold in memory. A built-in reads
//! and writes ordinary files directly; it has no scratch directory.
//!
//! An out-of-process extension is held to more: no network I/O at all, a
//! stateless protocol, and files only inside a scratch directory of its
//! own. Those rules are the gearing's to enforce, in [`gear`].

use std::sync::Arc;

use crate::core::error::Result;

mod cache;
mod constraints;
mod denying;
mod document;
mod fetch;
mod gate;
pub mod gear;
mod host;
pub mod options;
mod policed;
pub mod testing;
mod unbound;

pub(crate) use cache::writable;
pub use cache::{
    Bound, Budget, Cache, CachePath, CachePolicy, Expiry, FreshnessRule, Hold, Judged, Kept,
    Lifetime, Origin, Staged,
};
pub use constraints::Constraints;
pub use denying::DenyingHost;
pub(crate) use document::{
    document, document_json, gone, leaf, report_expired, report_stale, settle,
};
pub use fetch::{HostFetch, fetch_json};
pub(crate) use gate::{Gate, Gates};
pub use host::{ExtHost, HostedExt, Mirror, Route};
pub use options::Options;
pub use policed::Policed;
pub use unbound::Unbound;

/// Where a source or an enumerator gets the capability it fetches through.
///
/// Implemented by `session::Hosts`; supplied as a parameter rather than
/// built where it is used, because `repo` and `enumerate` read a configuration
/// and do no I/O, while opening a capability starts an HTTP client and a
/// cache.
///
/// **A repository is given its host as it is built**, not afterwards: a
/// proxy's upstreams are built inside that recursion and never handed out
/// individually, so a caller has nothing to give them a host through. Each
/// upstream gets its own, which is what keeps one upstream's credentials
/// off another's requests.
pub trait Capabilities {
    /// The capability for the host configured under `name`, confined to
    /// `base`.
    ///
    /// `base` is the URL root the source will actually read from -- the
    /// host's url with the source's `path` joined on -- and **not** the
    /// host's url. That is what keeps one repository's source off another
    /// repository on the same server, which is the whole reason a manager
    /// can be configured as one host rather than several.
    ///
    /// A caller checking that a configuration *builds* is handed a host
    /// that refuses everything -- see [`Unbound`].
    ///
    /// The host's additional hosts come with it, from its own entry.
    fn host(&mut self, name: &str, base: &str) -> Result<Arc<dyn ExtHost>>;

    /// A capability for key lookups, permitting exactly these keyserver
    /// URLs: no credentials, default TLS and retry.
    ///
    /// Apart from any host's, so a keyserver is reached only by a key
    /// lookup, and a source's own capability is not widened to reach it.
    fn keyservers(&mut self, urls: &[String]) -> Result<Arc<dyn ExtHost>>;
}
