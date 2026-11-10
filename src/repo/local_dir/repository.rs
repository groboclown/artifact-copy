//! What the source, target, and enumerator share: where the repository
//! is, how its paths read, and its listing.

use std::sync::Arc;

use http::StatusCode;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::Version;
use crate::net::emulate::generic::{Digests, Listing, listing_url};
use crate::net::{ByteLimit, Req, encode_path, normalized_base};
use crate::repo::Mapping;

/// The most one listing may hold in memory, before the host's own cap.
///
/// Generous because the listing is not paged; see
/// `net::emulate::generic`.
const LISTING_LIMIT: ByteLimit = ByteLimit::mib(256);

/// What the generic listing is, for an error that cannot parse one.
const LISTING: &str = "local directory listing";

/// The mapping configured, or the default.
fn mapping_of(options: &Options) -> Result<Mapping> {
    Ok(options
        .string(super::MAPPING)?
        .map(Mapping::parse)
        .transpose()?
        .unwrap_or_default())
}

/// The URL of one file of the repository at `base`.
pub(super) fn file_url(base: &str, path: &str) -> String {
    format!("{base}/{}", encode_path(path.trim_start_matches('/')))
}

/// The listing prefix that reaches every file of one artifact.
///
/// Wider than the artifact, as a literal prefix is: `a/b` reaches
/// `a/b/c/...` and `a/bc` too, so what comes back is re-read through the
/// mapping. No trailing separator under `directory`, because a file at
/// the root is its own artifact.
pub(super) fn prefix_of(mapping: Mapping, name: &str, version: Option<&Version>) -> String {
    match (mapping, version) {
        (Mapping::NameVersionFile, Some(version)) => format!("{name}/{}/", version.text()),
        _ => name.to_owned(),
    }
}

/// The files of the repository at `base` under `prefix`.
///
/// A missing repository directory is an error rather than an empty
/// listing: read as empty, it would republish everything into nowhere.
async fn listed(
    host: &dyn ExtHost,
    base: &str,
    prefix: &str,
    digests: Digests,
    ctx: &Ctx,
) -> Result<Listing> {
    let url = listing_url(base, prefix, digests);

    match crate::ext::fetch_json(host, &Req::get(&url), LISTING_LIMIT, LISTING, ctx).await {
        // HTTP 404: the repository's directory is not there.
        Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
            Err(Error::Absent {
                what: "local directory",
                url,
                name: base.to_owned(),
            })
        }

        other => other,
    }
}

/// What the three share: where the repository is, and how it is read.
pub(super) struct Repository {
    pub(super) base: String,
    pub(super) host: Arc<dyn ExtHost>,
    pub(super) mapping: Mapping,
}

impl Repository {
    pub(super) fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            base: normalized_base(base_url),
            host,
            mapping: mapping_of(options)?,
        })
    }

    pub(super) async fn listed(
        &self,
        prefix: &str,
        digests: Digests,
        ctx: &Ctx,
    ) -> Result<Listing> {
        listed(&*self.host, &self.base, prefix, digests, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_url_escapes_each_segment() {
        assert_eq!(
            file_url("file:///srv/repo", "my tools/read me.txt"),
            "file:///srv/repo/my%20tools/read%20me.txt"
        );
    }

    #[test]
    fn prefix_narrows_to_version() {
        let version = Version::new("1.0", crate::model::Release::General);

        assert_eq!(prefix_of(Mapping::Directory, "a/b", None), "a/b");
        assert_eq!(
            prefix_of(Mapping::NameVersionFile, "a/b", Some(&version)),
            "a/b/1.0/"
        );
    }
}
