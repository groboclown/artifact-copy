//! Enumerating an npm registry through a CouchDB changes feed.
//!
//! ```text
//!   GET {base}/                              doc_count, for the total
//!   GET {base}/_changes?since={seq}&limit=N  package names, a page at a time
//!   GET {registry}/{name}                    each name's packument
//! ```
//!
//! # Names from the feed, versions from the registry
//!
//! The feed lists names and revisions only: npm's refuses `include_docs`
//! (measured; see `server-behaviors.md`). So each name's packument is
//! fetched from `registry`, which defaults to the feed's own host. They are
//! separate because npm serves them from separate hosts --
//! `replicate.npmjs.com` and `registry.npmjs.org` -- while a CouchDB-backed
//! registry serves both from one. The host reaches a separate `registry`
//! through its `additional-hosts`.
//!
//! The packument step speaks only the npm registry protocol, so any server
//! that answers it can supply the versions behind any feed.
//!
//! # Cursors
//!
//! The cursor is the feed's `last_seq`, opaque text a later `since` takes
//! back. A package updated during a walk appears again further on; the
//! report records an artifact once however often it is listed.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use http::StatusCode;
use serde::Deserialize;

use super::packument::Packument;
use super::{package_path, tarball_name};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::{Ecosystem, Npm};
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{ArtifactId, EcosystemId, ListingDepth};
use crate::net::{ByteLimit, Req, encode_unreserved, normalized_base};
use crate::repo::enumerate::{Cursor, Enumerator, Found, Listed, Page};
use crate::version::VersionHandler;

/// The option naming where packuments come from.
const REGISTRY: &str = "registry";

/// The option bounding how many names one page holds.
const PAGE_SIZE: &str = "page-size";

/// Names per page when `page-size` is absent. Each costs a packument.
const DEFAULT_PAGE_SIZE: usize = 100;

/// Packuments fetched at once. The host's own connection limit still
/// applies beneath this.
const CONCURRENT_PACKUMENTS: usize = 8;

/// One page of the feed: an id, a sequence, and a revision per change.
const FEED_LIMIT: ByteLimit = ByteLimit::mib(4);

/// The database's own description.
const INFO_LIMIT: ByteLimit = ByteLimit::kib(64);

/// CouchDB's prefix for design documents, which are not packages.
const DESIGN_PREFIX: &str = "_design/";

pub struct NpmReplicateEnumerator {
    /// The changes feed's database root.
    base_url: String,

    /// Where packuments are read.
    registry: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,

    page_size: usize,

    ecosystems: [EcosystemId; 1],
}

#[derive(Debug, Deserialize)]
struct Changes {
    #[serde(default)]
    results: Vec<Change>,

    /// A number on CouchDB 1, a string from 2 on.
    #[serde(default)]
    last_seq: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct Change {
    id: String,

    #[serde(default)]
    deleted: bool,
}

#[derive(Debug, Deserialize)]
struct Info {
    #[serde(default)]
    doc_count: Option<u64>,
}

impl NpmReplicateEnumerator {
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let base_url = normalized_base(base_url);

        let registry = options
            .string(REGISTRY)?
            .map_or_else(|| base_url.clone(), normalized_base);

        let page_size = match options.integer(PAGE_SIZE)? {
            None => DEFAULT_PAGE_SIZE,
            Some(size) => usize::try_from(size)
                .ok()
                .filter(|size| *size > 0)
                .ok_or_else(|| {
                    Error::Config(format!("{PAGE_SIZE:?} must be at least 1, not {size}"))
                })?,
        };

        Ok(Self {
            base_url,
            registry,
            host,
            page_size,
            ecosystems: [EcosystemId::npm()],
        })
    }

    fn feed_url(&self, cursor: Option<&Cursor>) -> String {
        let mut url = format!("{}/_changes?limit={}", self.base_url, self.page_size);

        if let Some(cursor) = cursor {
            url.push_str("&since=");
            url.push_str(&encode_unreserved(cursor.as_str()));
        }

        url
    }

    /// The artifact a feed id names, or `None` with the reason reported
    /// when it names none.
    fn package(&self, change: &Change, ctx: &Ctx) -> Option<ArtifactId> {
        if change.deleted || change.id.starts_with(DESIGN_PREFIX) {
            return None;
        }

        match Npm.parse_req(&change.id) {
            Ok(request) => Some(request.id),

            Err(err) => {
                ctx.report(
                    Code::MetadataMalformed,
                    message!(
                        "npm-feed-id-unreadable",
                        "the changes feed at {url} lists {id}, which is not a package \
                         name ({reason}); it is skipped",
                        url = &self.base_url,
                        id = &change.id,
                        reason = &err,
                    ),
                );

                None
            }
        }
    }

    /// Every version of one package, each with its tarball.
    async fn versions(&self, id: ArtifactId, ctx: &Ctx) -> Result<Vec<Found>> {
        let url = format!("{}/{}", self.registry, package_path(&id));

        let packument: Packument = match crate::ext::document_json(
            &*self.host,
            &Req::get(&url),
            crate::ecosystem::PACKUMENT_DOCUMENT,
            ByteLimit::PACKUMENT,
            "npm packument",
            ctx,
        )
        .await
        {
            Ok(packument) => packument,

            // Listed by the feed and gone from the registry: removed since,
            // or the two hosts disagree. One package, not the walk.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                ctx.report(
                    Code::ArtifactNotFound,
                    message!(
                        "npm-feed-package-missing",
                        "the changes feed lists {purl}, which {url} does not hold; \
                         it is skipped",
                        purl = id.purl(),
                        url = &url,
                    ),
                );

                return Ok(Vec::new());
            }

            Err(err) => return Err(err),
        };

        Ok(packument
            .versions
            .iter()
            .filter_map(|(version, entry)| {
                let dist = entry.dist.as_ref()?;
                let tarball = dist.tarball.clone()?;

                let file = Listed {
                    name: tarball_name(&id, version),
                    url: tarball,
                    size: None,
                    digests: dist.digests(),
                };

                Some(
                    Found::new(id.clone())
                        .version(Npm.version(version))
                        .files(vec![file]),
                )
            })
            .collect())
    }
}

#[async_trait]
impl Enumerator for NpmReplicateEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        &self.ecosystems
    }

    fn depth(&self) -> ListingDepth {
        ListingDepth::Files
    }

    /// One page of the feed, each name's versions read from its packument.
    ///
    /// A short page is the end: a normal CouchDB feed returns fewer than
    /// `limit` changes only when it has none left.
    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        let changes: Changes = crate::ext::fetch_json(
            &*self.host,
            &Req::get(self.feed_url(cursor)),
            FEED_LIMIT,
            "npm changes feed",
            ctx,
        )
        .await?;

        let ids: Vec<ArtifactId> = changes
            .results
            .iter()
            .filter_map(|change| self.package(change, ctx))
            .collect();

        let mut found = Vec::new();
        let mut fetched = futures::stream::iter(ids)
            .map(|id| self.versions(id, ctx))
            .buffered(CONCURRENT_PACKUMENTS);

        while let Some(versions) = fetched.next().await {
            found.extend(versions?);
        }

        let next = match &changes.last_seq {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        };

        match next {
            Some(next) if changes.results.len() >= self.page_size => {
                Ok(Page::more(found, Cursor::new(next)))
            }

            _ => Ok(Page::last(found)),
        }
    }

    /// The database's `doc_count`, which counts design documents too, so
    /// the total is a few high on a registry that has any.
    async fn count(&self, ctx: &Ctx) -> Result<Option<u64>> {
        let info: Info = crate::ext::fetch_json(
            &*self.host,
            &Req::get(format!("{}/", self.base_url)),
            INFO_LIMIT,
            "npm changes feed database",
            ctx,
        )
        .await?;

        Ok(info.doc_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{TestHost, options};
    use crate::model::Cause;
    use crate::net::FixtureClient;

    const FEED: &str = "h://replicate.test";
    const REGISTRY_URL: &str = "h://registry.test";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "walk".into() })
    }

    fn packument(name: &str, versions: &[&str]) -> String {
        let versions: serde_json::Map<String, serde_json::Value> = versions
            .iter()
            .map(|version| {
                (
                    (*version).to_owned(),
                    serde_json::json!({
                        "dist": {
                            "tarball": format!("{REGISTRY_URL}/{name}/-/{name}-{version}.tgz"),
                            "shasum": "0123456789abcdef0123456789abcdef01234567",
                        }
                    }),
                )
            })
            .collect();

        serde_json::json!({ "name": name, "versions": versions }).to_string()
    }

    /// Two pages of two: a package, a deleted one, a design document, and
    /// a scoped package, then one past the end.
    fn feed() -> FixtureClient {
        FixtureClient::new()
            .with_body(
                format!("{FEED}/_changes?limit=2"),
                serde_json::json!({
                    "results": [
                        {"seq": 1, "id": "tuna"},
                        {"seq": 2, "id": "gone", "deleted": true},
                    ],
                    "last_seq": 2,
                })
                .to_string(),
            )
            .with_body(
                format!("{FEED}/_changes?limit=2&since=2"),
                serde_json::json!({
                    "results": [
                        {"seq": 3, "id": "_design/app"},
                        {"seq": 4, "id": "@fish/salmon"},
                    ],
                    "last_seq": "4-abc",
                })
                .to_string(),
            )
            .with_body(
                format!("{FEED}/_changes?limit=2&since=4-abc"),
                serde_json::json!({"results": [], "last_seq": "4-abc"}).to_string(),
            )
            .with_body(
                format!("{REGISTRY_URL}/tuna"),
                packument("tuna", &["1.0.0", "1.1.0"]),
            )
            .with_body(
                format!("{REGISTRY_URL}/@fish%2fsalmon"),
                packument("salmon", &["2.0.0"]),
            )
            .with_body(
                format!("{FEED}/"),
                r#"{"db_name":"registry","doc_count":3}"#,
            )
    }

    fn enumerator(client: FixtureClient) -> NpmReplicateEnumerator {
        let host = Arc::new(TestHost::new(client));

        NpmReplicateEnumerator::open(
            FEED,
            &options(serde_json::json!({ REGISTRY: REGISTRY_URL, PAGE_SIZE: 2 })),
            host,
        )
        .expect("opens")
    }

    fn purls(found: &[Found]) -> Vec<String> {
        found
            .iter()
            .map(|one| {
                one.id
                    .purl_at(one.version.as_ref().expect("versioned").text())
            })
            .collect()
    }

    #[tokio::test]
    async fn feed_names_become_versions() {
        let subject = enumerator(feed());
        let ctx = ctx();
        let mut cursor = None;
        let mut all = Vec::new();

        loop {
            let page = subject.walk(cursor.as_ref(), &ctx).await.expect("walked");
            all.extend(purls(&page.found));

            let Some(next) = page.next else {
                break;
            };

            cursor = Some(next);
        }

        assert_eq!(
            all,
            [
                "pkg:npm/tuna@1.0.0",
                "pkg:npm/tuna@1.1.0",
                "pkg:npm/%40fish/salmon@2.0.0",
            ]
        );
    }

    #[tokio::test]
    async fn tarball_carries_digest() {
        let subject = enumerator(feed());
        let page = subject.walk(None, &ctx()).await.expect("walked");
        let file = &page.found[0].files[0];

        assert_eq!(file.name, "tuna-1.0.0.tgz");
        assert_eq!(file.url, format!("{REGISTRY_URL}/tuna/-/tuna-1.0.0.tgz"));
        assert_eq!(file.digests.len(), 1);
    }

    /// Gone from the registry since the feed listed it: one package, not
    /// the walk.
    #[tokio::test]
    async fn packument_missing_skipped() {
        let client = FixtureClient::new().with_body(
            format!("{FEED}/_changes?limit=2"),
            serde_json::json!({"results": [{"seq": 1, "id": "vanished"}], "last_seq": 1})
                .to_string(),
        );

        let subject = enumerator(client);
        let ctx = ctx();
        let page = subject.walk(None, &ctx).await.expect("walked");

        assert!(page.found.is_empty());
        assert!(!page.has_more());
        assert_eq!(ctx.problems().counts()[&Code::ArtifactNotFound], 1);
    }

    #[tokio::test]
    async fn count_is_document_count() {
        let subject = enumerator(feed());

        assert_eq!(subject.count(&ctx()).await.expect("counted"), Some(3));
    }

    /// Without `registry`, the feed's own host serves the packuments.
    #[test]
    fn registry_defaults_to_feed() {
        let subject =
            NpmReplicateEnumerator::open(FEED, &Options::default(), crate::ext::testing::idle())
                .expect("opens");

        assert_eq!(subject.registry, FEED);
        assert!(
            NpmReplicateEnumerator::open(
                FEED,
                &options(serde_json::json!({ PAGE_SIZE: 0 })),
                crate::ext::testing::idle(),
            )
            .is_err()
        );
    }
}
