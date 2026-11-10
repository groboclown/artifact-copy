//! Enumerators built from other enumerators.
//!
//! The enumeration half of [`crate::repo::proxy`]: a configured proxy
//! source is asked *what do you hold*, and the answer comes from its
//! upstreams' catalogs.
//!
//! # Termination is never reimplemented here
//!
//! The single most dangerous thing a proxy enumerator could do is decide for
//! itself when an upstream's catalog has ended, because **the built-in
//! enumerators disagree about that and are each right**. Nexus filters after
//! paging, so an empty page is *not* the end of its catalog and only a
//! missing continuation token is; Artifactory and the PyPI index stop on a
//! short page. A proxy that applied either rule to the other would
//! silently truncate a catalog, which is the worst failure an enumerator has.
//!
//! So a proxy here asks *one* upstream for *one* page and believes
//! whatever that upstream says about whether there is more. It moves on
//! only when an upstream returns no cursor. Each upstream's own rule
//! applies to itself, unchanged and unexamined.
//!
//! # Cursors
//!
//! A [`Cursor`] is opaque to the host and meaningful only to the enumerator
//! that issued it, which is exactly the licence a proxy needs: it issues
//! `"<index>:<whatever the upstream said>"`, and takes the index back off
//! before handing the rest down. An index with no colon means *start this
//! upstream from the beginning*.
//!
//! Split on the **first** colon only, since an upstream's own cursor may
//! contain any number of them.

use std::sync::Arc;

use crate::core::error::{Error, Result};
use crate::ext::Options;
use crate::model::EcosystemId;
use crate::repo::upstream::{Proxied, Upstreams};

use crate::repo::enumerate::{Cursor, Enumerator};

mod failover;

pub use crate::repo::upstream::{Upstream, Upstreams as ProxyUpstreams};
pub use failover::Failover;

/// Proxying applied to enumerators.
impl Proxied for dyn Enumerator {
    fn ecosystems(&self) -> Vec<EcosystemId> {
        Enumerator::ecosystems(self).to_vec()
    }
}

/// The upstreams an enumerator proxy stands in front of.
pub type EnumeratorUpstreams = Upstreams<dyn Enumerator>;

/// Where a proxy's walk currently is: which upstream, and where inside it.
///
/// A parsed [`Cursor`], and the only place its spelling is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Position {
    /// Index into the upstream list.
    pub(crate) at: usize,

    /// The upstream's own cursor, or `None` to start it from the
    /// beginning.
    pub(crate) inner: Option<Cursor>,
}

impl Position {
    /// The first page of the first upstream.
    pub(crate) fn start() -> Self {
        Self { at: 0, inner: None }
    }

    /// Read a cursor this proxy issued.
    ///
    /// A cursor that does not parse is a caller handing back something
    /// another enumerator issued, which is a bug worth naming rather than a
    /// walk to restart from the beginning -- restarting would re-report
    /// everything already seen.
    pub(crate) fn parse(cursor: &Cursor) -> Result<Self> {
        let text = cursor.as_str();

        // Split on the first colon only: an upstream's own cursor may
        // contain any number of them.
        let (index, rest) = match text.split_once(':') {
            Some((index, rest)) => (index, Some(Cursor::new(rest))),
            None => (text, None),
        };

        let at = index.parse::<usize>().map_err(|_| Error::Malformed {
            what: "proxy enumerator cursor",
            url: String::new(),
            detail: format!(
                "{text:?} does not begin with an upstream index; it was issued by \
                 some other enumerator"
            ),
        })?;

        Ok(Self { at, inner: rest })
    }

    /// The cursor to hand back for this position.
    pub(crate) fn to_cursor(&self) -> Cursor {
        match &self.inner {
            Some(inner) => Cursor::new(format!("{}:{}", self.at, inner.as_str())),
            None => Cursor::new(self.at.to_string()),
        }
    }
}

/// Build a proxy enumerator over the upstreams it was configured with.
///
/// Separate from [`crate::repo::enumerate::open_enumerator`] for the same reason the source
/// registries are separate: an ordinary enumerator is built from a base URL
/// and a proxy has no host at all.
pub fn open_proxy_enumerator(
    kind: &str,
    upstreams: EnumeratorUpstreams,
    options: &Options,
) -> Result<Arc<dyn Enumerator>> {
    match kind {
        "proxy-failover" => Ok(Arc::new(Failover::open(upstreams, options)?)),

        other => Err(Error::UnknownKind {
            collection: "proxy enumerator",
            kind: other.to_owned(),
        }),
    }
}

/// Built-in proxy enumerator kinds.
///
/// Built-in only, for the reason [`crate::repo::proxy_source_kinds`] gives:
/// the loader has to know whether a declaration's `proxy-to` is meaningful
/// before it builds anything.
///
/// One entry, and **failover is the only pattern a catalog walk may
/// follow**. Merging belongs on the source side, where the question is a
/// version list for one artifact and the answer is bounded by that
/// artifact's release history. A catalog is not bounded by anything, so a
/// merging walk would need a claim set growing with it. See
/// [`crate::repo::proxy`] and `docs/contributors/sources-and-targets.md`.
///
/// A future merging *source* proxy therefore does not get a matching
/// enumerator. Its catalog walk is either this failover -- which under-reports
/// when the upstreams hold different things, which is the whole point of
/// merging them -- or refused outright. Refusing is the honest answer and
/// is the likely shape.
pub(crate) fn proxy_enumerator_kinds() -> &'static [&'static str] {
    &["proxy-failover"]
}

/// Whether a configured enumerator kind names a proxy.
pub(crate) fn is_proxy_enumerator_kind(kind: &str) -> bool {
    proxy_enumerator_kinds().contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(text: &str) -> Cursor {
        Cursor::new(text)
    }

    #[test]
    fn cursor_position_round_trips() {
        for position in [
            Position::start(),
            Position { at: 0, inner: None },
            Position {
                at: 3,
                inner: Some(cursor("abc")),
            },
        ] {
            let read = Position::parse(&position.to_cursor()).expect("parses");

            assert_eq!(read, position);
        }
    }

    /// An upstream's own cursor is opaque and may hold anything, colons
    /// included -- a Nexus continuation token or a URL, say.
    #[test]
    fn cursor_inner_may_contain_colons() {
        let position = Position {
            at: 2,
            inner: Some(cursor("h://registry.test/page?after=x:y:z")),
        };

        let read = Position::parse(&position.to_cursor()).expect("parses");

        assert_eq!(read, position);
        assert_eq!(
            read.inner.expect("inner").as_str(),
            "h://registry.test/page?after=x:y:z"
        );
    }

    /// An index alone means "start this upstream", which is how the proxy
    /// moves from one to the next.
    #[test]
    fn cursor_index_alone_starts_upstream() {
        let read = Position::parse(&cursor("1")).expect("parses");

        assert_eq!(read.at, 1);
        assert!(read.inner.is_none());
    }

    /// An empty inner cursor is not the same as no inner cursor: an
    /// upstream is entitled to issue one.
    #[test]
    fn cursor_inner_empty_survives() {
        let read = Position::parse(&cursor("0:")).expect("parses");

        assert_eq!(read.inner.expect("inner").as_str(), "");
    }

    /// Handing back a cursor some other enumerator issued is a bug, and
    /// restarting from the beginning would re-report the whole catalog.
    #[test]
    fn cursor_foreign_refused() {
        let err = Position::parse(&cursor("startkey=%22lodash%22")).expect_err("not ours");

        assert_eq!(err.code(), crate::core::problem::Code::MetadataMalformed);
        assert!(err.to_string().contains("upstream index"), "{err}");
    }

    #[test]
    fn kind_unknown_proxy_reported() {
        let err = match open_proxy_enumerator(
            "proxy-nonsense",
            EnumeratorUpstreams::default(),
            &Options::default(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("an unknown proxy enumerator kind must not open"),
        };

        assert!(err.to_string().contains("proxy-nonsense"), "{err}");
    }

    /// The two proxy kind lists are independent registries and may drift
    /// apart; today they happen to agree, and an enumerator kind is never
    /// resolved against the source list or the other way round.
    #[test]
    fn kind_ordinary_enumerator_not_proxy() {
        for kind in crate::repo::enumerate::enumerator_kinds() {
            assert!(
                !is_proxy_enumerator_kind(kind),
                "{kind} must not be a proxy kind"
            );
        }
    }
}
