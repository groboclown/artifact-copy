//! How Artifact Keeper's REST API is addressed and paged, shared by the
//! source, target, lister, and enumerator.

use super::listing::Listing;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::Version;
use crate::net::{ByteLimit, Req, encode_unreserved};
use crate::repo::{Mapping, PageCap};

/// The repository API, relative to the server root.
pub(super) const API: &str = "api/v1/repositories";

/// One listing page, or one artifact's metadata. Both are small.
pub(super) const PAGE_LIMIT: ByteLimit = ByteLimit::mib(8);

/// Listing rows per page.
pub(super) const PER_PAGE: u32 = 100;

/// How many listing rows one prefix match may take, unless
/// `max-listing-rows` says otherwise.
///
/// A prefix match reaches an artifact's sub-directories and siblings as
/// well as the artifact, so this bounds the work of a very deep tree
/// rather than a single directory. Twenty thousand rows is far past any
/// directory anybody lays out by hand.
pub(super) const DEFAULT_MAX_ROWS: u32 = 20_000;

/// How a raw repository's paths become coordinates.
pub(super) const MAPPING: &str = "mapping";

/// What kind of repository a source or enumerator reads, and so which
/// layout its listing holds.
pub(super) const MODE: &str = "mode";

/// The `mode` option.
///
/// A Remote (proxy) repository lists what it has cached, from the server's
/// `proxy_cache_artifacts` catalog, under the paths a client fetched rather
/// than the hosted storage layout.  Its protocol route passes through to the
/// upstream, so it answers with the upstream's versions and files, not the
/// cached ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// A hosted repository: the protocol answers, the listing adds.
    Hosted,

    /// A Remote: the protocol answers metadata and dependencies, and the
    /// cache catalog decides which versions and files exist.
    Proxy,

    /// A Remote read from its cache catalog alone, with no protocol
    /// request: no dependencies, no license.
    ProxyCache,
}

impl Mode {
    /// Absent is `hosted`, which is what every configuration written
    /// before this option existed means.
    pub(super) fn read(options: &Options, kind: &str) -> Result<Self> {
        match options.string(MODE)? {
            None | Some("hosted") => Ok(Self::Hosted),
            Some("proxy") => Ok(Self::Proxy),
            Some("proxy-cache") => Ok(Self::ProxyCache),

            Some(other) => Err(Error::Config(format!(
                "the {kind} {MODE:?} option is \"hosted\", \"proxy\", or \"proxy-cache\", \
                 not {other:?}"
            ))),
        }
    }

    /// Whether the listing is a Remote's cache catalog.
    pub(super) fn cached(self) -> bool {
        self != Self::Hosted
    }
}

/// `{base}/api/v1/repositories/{repository}`.
pub(super) fn repository_url(base_url: &str, repository: &str) -> String {
    format!("{base_url}/{API}/{}", encode_unreserved(repository))
}

/// The generic download route, which serves every format by its stored or
/// its URL-shaped path.
pub(super) fn download_url(base_url: &str, repository: &str, path: &str) -> String {
    format!(
        "{}/download/{}",
        repository_url(base_url, repository),
        encode_path(path.trim_start_matches('/'))
    )
}

/// The listing prefix that reaches every file of one raw artifact.
///
/// Wider than the artifact, deliberately: the server matches a literal
/// prefix, so `a/b` reaches `a/b/c/...` and `a/bc` too. What comes back
/// is re-read through the mapping rather than trusted.
///
/// No trailing separator under `directory`, because a file at the root
/// is its own artifact and `readme.txt/` would miss it.
pub(super) fn prefix_of(mapping: Mapping, name: &str, version: Option<&Version>) -> String {
    match (mapping, version) {
        (Mapping::NameVersionFile, Some(version)) => format!("{name}/{}/", version.text()),
        _ => name.to_owned(),
    }
}

/// Every listed file whose stored path starts with `prefix`, following the
/// keyset cursor.
///
/// A listing that says more follows and gives no cursor is an error: the
/// prefix listing of a hosted repository always sends one, and reading its
/// absence as the end would drop files without a word.
pub(super) async fn prefixed(
    host: &dyn ExtHost,
    base_url: &str,
    repository: &str,
    prefix: &str,
    cap: PageCap,
    ctx: &Ctx,
) -> Result<Vec<super::listing::Item>> {
    let first = format!(
        "{}/artifacts?path_prefix={}&per_page={PER_PAGE}",
        repository_url(base_url, repository),
        encode_unreserved(prefix),
    );
    let mut items = Vec::new();
    let mut url = first.clone();

    for _ in 0..cap.pages() {
        let page: Listing = crate::ext::fetch_json(
            host,
            &Req::get(&url),
            PAGE_LIMIT,
            "artifact keeper listing",
            ctx,
        )
        .await?;
        let more = page.has_more.unwrap_or(false);
        let cursor = page.next_cursor.filter(|token| !token.is_empty());

        items.extend(page.items);

        match (more, cursor) {
            (false, _) => return Ok(items),
            (true, Some(token)) => url = format!("{first}&cursor={}", encode_unreserved(&token)),

            (true, None) => {
                return Err(Error::Malformed {
                    what: "artifact keeper listing",
                    url,
                    detail: "it says more pages follow but gives no cursor to reach them".into(),
                });
            }
        }
    }

    Err(Error::Malformed {
        what: "artifact keeper listing",
        url: first,
        detail: cap.exhausted(),
    })
}

/// The page cap `options` configures, at this listing's page size.
pub(super) fn page_cap(options: &Options) -> Result<PageCap> {
    PageCap::from_options(options, PER_PAGE, DEFAULT_MAX_ROWS)
}

/// Percent-encode each segment of a path, keeping its separators.
pub(super) fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_unreserved)
        .collect::<Vec<_>>()
        .join("/")
}
