//! How Nexus's REST API is addressed and paged, and an asset as a file,
//! shared by the source, lister, target, and enumerator.

use super::asset::{Asset, Paged};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::FileRef;
use crate::net::{ByteLimit, Req};
use crate::repo::{Coordinate, PageCap};

/// The asset search endpoint, relative to the Nexus base URL.
pub(super) const SEARCH: &str = "service/rest/v1/search/assets";

/// One page of assets. Nexus pages these at fifty; a page of them is small.
pub(super) const PAGE_LIMIT: ByteLimit = ByteLimit::mib(8);

/// Assets per page, which Nexus fixes.
pub(super) const PER_PAGE: u32 = 50;

/// How many assets one directory may list before the walk gives up, unless
/// `max-listing-rows` says otherwise.
///
/// A bound rather than a limit anybody should reach: a thousand files in
/// one directory is well inside it. It is here because Nexus has been
/// observed handing back a continuation token equal to the previous one,
/// and a loop that believed it would never end.
pub(super) const DEFAULT_MAX_ROWS: u32 = 10_000;

/// Where a repository's protocol is served, under the server root.
pub(super) const REPOSITORY_PATH: &str = "repository";

/// Every item of a paged search, following continuation tokens.
///
/// Three stop conditions and all three matter: an absent token, a token
/// equal to the one that produced the page, and a page cap. The middle
/// is not defensive programming -- Nexus has been observed repeating a
/// token forever, and the working Python reader carries the same guard.
pub(super) async fn paged<P: Paged + serde::de::DeserializeOwned>(
    host: &dyn ExtHost,
    url_at: impl Fn(Option<&str>) -> String,
    what: &'static str,
    cap: PageCap,
    ctx: &Ctx,
) -> Result<Vec<P::Item>> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;

    for _ in 0..cap.pages() {
        let url = url_at(cursor.as_deref());
        let page: P = crate::ext::fetch_json(host, &Req::get(&url), PAGE_LIMIT, what, ctx).await?;
        let (items, next) = page.split();

        out.extend(items);

        match next.filter(|token| !token.is_empty()) {
            None => return Ok(out),

            // The same token again: the server is not advancing, and
            // believing it would loop until the process was killed.
            Some(token) if Some(&token) == cursor.as_ref() => return Ok(out),

            Some(token) => cursor = Some(token),
        }
    }

    Err(Error::Malformed {
        what,
        url: url_at(None),
        detail: cap.exhausted(),
    })
}

/// The page cap `options` configures, at Nexus's page size.
pub(super) fn page_cap(options: &Options) -> Result<PageCap> {
    PageCap::from_options(options, PER_PAGE, DEFAULT_MAX_ROWS)
}

/// One asset as a file of its artifact.
pub(super) fn file_of(asset: &Asset, at: &Coordinate) -> FileRef {
    let url = asset.download_url.clone().unwrap_or_default();
    let mut file = FileRef::new(&at.file, &url);

    // Nexus search reports 0 when its index lacks the size, as for every
    // asset on one captured server. Undeclared rather than trusted, so a
    // listed size survives; the digests still cover a genuinely empty file.
    file.size = asset.file_size.filter(|&size| size > 0);
    file.digests = asset.digests();

    file
}
