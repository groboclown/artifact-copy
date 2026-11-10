//! Walking a local directory.
//!
//! One listing of the whole repository, without hashes, read through the
//! [`Mapping`]. Pages end only between artifacts, so no artifact is split
//! across two:
//!
//! ```text
//!   sorted by (directory, file)    a/x.txt  a/y.txt | b/z.txt ...
//!   page ends once it holds        PAGE_FILES, at the next new artifact
//!   cursor                         the last path the page consumed
//! ```
//!
//! Sorting by directory first is what keeps an artifact's files together:
//! by whole path, `a/b.txt` and `a/d.txt` would have `a/c/q.txt` between
//! them.
//!
//! The listing is not paged, so every page lists the whole repository
//! again and skips past the cursor. Worth revisiting with the listing:
//! see `net::emulate::generic`.

use std::sync::Arc;

use async_trait::async_trait;

use super::{Repository, file_url};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Code;
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{ArtifactId, EcosystemId, ListingDepth};
use crate::net::emulate::generic::{Digests, Item, Skipped};
use crate::repo::Coordinate;
use crate::repo::enumerate::{Cursor, Enumerator, Found, Listed, Page};
use crate::version::VersionHandler;

/// How many files a page holds before it ends at the next artifact.
const PAGE_FILES: usize = 500;

pub struct LocalDirEnumerator {
    repository: Repository,
    ecosystems: [EcosystemId; 1],
}

/// Which artifact a coordinate belongs to: its name and version, not its
/// file.
fn artifact_of(at: &Coordinate) -> (&str, Option<&str>) {
    (&at.name, at.version.as_deref())
}

/// Where a path sorts: its directory, then its name.
fn order_of(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

impl LocalDirEnumerator {
    /// `mapping` defaults to `directory`.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            repository: Repository::open(base_url, options, host)?,
            ecosystems: [EcosystemId::raw()],
        })
    }

    fn found(&self, at: &Coordinate) -> Found {
        let version = at
            .version
            .as_deref()
            .map(|text| crate::ecosystem::Raw.version(text));

        Found::new(ArtifactId::new(EcosystemId::raw(), None, &at.name)).maybe_version(version)
    }

    fn listed(&self, item: &Item, at: &Coordinate) -> Listed {
        Listed {
            name: at.file.clone(),
            url: file_url(&self.repository.base, &item.path),
            size: Some(item.size),
            digests: Vec::new(),
        }
    }

    fn unmapped(&self, path: &str, ctx: &Ctx) {
        ctx.report(
            Code::MetadataMalformed,
            message!(
                "local-directory-unreadable-path",
                "{path} in {repository} does not fit the {mapping} mapping, so no \
                 coordinate can be read from it; it is skipped",
                path = path,
                repository = &self.repository.base,
                mapping = self.repository.mapping.as_str(),
            ),
        );
    }

    fn skipped(&self, skipped: &Skipped, ctx: &Ctx) {
        ctx.report(
            Code::MetadataMalformed,
            message!(
                "local-directory-skipped-path",
                "{path} in {repository} is not listed: {reason}",
                path = &skipped.path,
                repository = &self.repository.base,
                reason = &skipped.reason,
            ),
        );
    }
}

#[async_trait]
impl Enumerator for LocalDirEnumerator {
    fn ecosystems(&self) -> &[EcosystemId] {
        &self.ecosystems
    }

    fn depth(&self) -> ListingDepth {
        ListingDepth::Files
    }

    async fn walk(&self, cursor: Option<&Cursor>, ctx: &Ctx) -> Result<Page> {
        let listing = self.repository.listed("", Digests::Omitted, ctx).await?;
        let after = cursor.map(|cursor| order_of(cursor.as_str()));

        let mut items: Vec<&Item> = listing
            .items
            .iter()
            .filter(|item| after.is_none_or(|after| order_of(&item.path) > after))
            .collect();

        items.sort_by(|a, b| order_of(&a.path).cmp(&order_of(&b.path)));

        let mut found: Vec<Found> = Vec::new();
        let mut current: Option<Coordinate> = None;
        let same = |at: Option<&Coordinate>, current: Option<&Coordinate>| {
            at.map(artifact_of) == current.map(artifact_of)
        };
        let mut files = 0;
        let mut last: Option<&str> = None;
        let mut next: Option<Cursor> = None;

        for item in items {
            let at = self.repository.mapping.read(&item.path);

            // Only between artifacts, so one is never split.
            if files >= PAGE_FILES && !same(at.as_ref(), current.as_ref()) {
                next = last.map(Cursor::new);
                break;
            }

            last = Some(&item.path);

            let Some(at) = at else {
                self.unmapped(&item.path, ctx);
                current = None;
                continue;
            };

            if current.is_none() || !same(Some(&at), current.as_ref()) {
                found.push(self.found(&at));
            }

            let listed = self.listed(item, &at);
            found
                .last_mut()
                .expect("pushed above for a new artifact")
                .files
                .push(listed);

            files += 1;
            current = Some(at);
        }

        // Each name passed over once: the one page whose range holds it.
        let through = next.as_ref().map(|cursor| order_of(cursor.as_str()));

        for skipped in &listing.skipped {
            let at = order_of(&skipped.path);

            let mine = after.is_none_or(|after| at > after) && through.is_none_or(|end| at <= end);

            if mine {
                self.skipped(skipped, ctx);
            }
        }

        match next {
            Some(next) => Ok(Page::more(found, next)),
            None => Ok(Page::last(found)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::Error;
    use crate::ext::testing::options;
    use crate::model::{Cause, LastDownload, Version};
    use crate::repo::local_dir::testing::Directory;

    fn text(version: &Option<Version>) -> Option<&str> {
        version.as_ref().map(Version::text)
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Enumerated {
            enumerator: crate::repo::local_dir::KIND.into(),
        })
    }

    fn enumerator(directory: &Directory, mapping: &str) -> LocalDirEnumerator {
        LocalDirEnumerator::open(
            &directory.base,
            &options(serde_json::json!({ "mapping": mapping })),
            Arc::clone(&directory.host),
        )
        .expect("opens")
    }

    /// Every page of a walk, in order.
    async fn every_page(enumerator: &LocalDirEnumerator, ctx: &Ctx) -> Vec<Page> {
        let mut pages = Vec::new();
        let mut cursor = None;

        loop {
            let page = enumerator.walk(cursor.as_ref(), ctx).await.expect("walked");
            cursor = page.next.clone();
            pages.push(page);

            if cursor.is_none() {
                return pages;
            }
        }
    }

    #[test]
    fn enumerator_declares_capabilities() {
        let directory = Directory::new();
        let enumerator = enumerator(&directory, "directory");

        assert!(!enumerator.reports_last_download());
        assert_eq!(enumerator.depth(), ListingDepth::Files);
        assert_eq!(enumerator.ecosystems(), [EcosystemId::raw()]);
    }

    /// Sorted by whole path, `a/c/q.txt` falls between `a/b.txt` and
    /// `a/d.txt`; the artifact `a` must still come out as one.
    #[tokio::test]
    async fn directory_files_stay_together() {
        let directory = Directory::new();
        directory.write("a/b.txt", b"b");
        directory.write("a/c/q.txt", b"q");
        directory.write("a/d.txt", b"d");

        let ctx = ctx();
        let page = enumerator(&directory, "directory")
            .walk(None, &ctx)
            .await
            .expect("walked");

        let names: Vec<&str> = page.found.iter().map(|found| found.id.name()).collect();

        assert_eq!(names, ["a", "a/c"]);
        assert_eq!(page.found[0].files.len(), 2);
        assert_eq!(page.found[0].files[0].size, Some(1));
        assert!(page.found[0].files[0].digests.is_empty());
        assert_eq!(page.found[0].last_download, LastDownload::Unknown);
        assert!(!page.has_more());
    }

    #[tokio::test]
    async fn versions_from_paths() {
        let directory = Directory::new();
        directory.write("tools/fmt/2.0/fmt.zip", b"z");

        let ctx = ctx();
        let page = enumerator(&directory, "name-version-file")
            .walk(None, &ctx)
            .await
            .expect("walked");

        assert_eq!(page.found[0].id.name(), "tools/fmt");
        assert_eq!(text(&page.found[0].version), Some("2.0"));
    }

    #[tokio::test]
    async fn path_unmapped_reported() {
        let directory = Directory::new();
        directory.write("stray.txt", b"s");
        directory.write("tools/fmt/2.0/fmt.zip", b"z");

        let ctx = ctx();
        let page = enumerator(&directory, "name-version-file")
            .walk(None, &ctx)
            .await
            .expect("walked");

        assert_eq!(page.found.len(), 1);
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// Pages end between artifacts, the cursor resumes after the last,
    /// and every file is seen exactly once.
    #[tokio::test]
    async fn pages_never_split_artifact() {
        let directory = Directory::new();

        for artifact in 0..3 {
            for file in 0..300 {
                directory.write(&format!("art{artifact}/f{file:03}.txt"), b"x");
            }
        }

        let ctx = ctx();
        let pages = every_page(&enumerator(&directory, "directory"), &ctx).await;

        assert_eq!(pages.len(), 2);

        let found: Vec<&Found> = pages.iter().flat_map(|page| &page.found).collect();
        let names: Vec<&str> = found.iter().map(|found| found.id.name()).collect();

        assert_eq!(names, ["art0", "art1", "art2"]);
        assert!(found.iter().all(|found| found.files.len() == 300));
    }

    #[tokio::test]
    async fn repository_missing_is_error() {
        let directory = Directory::new();
        std::fs::remove_dir(directory.at("")).expect("removed");

        let err = enumerator(&directory, "directory")
            .walk(None, &ctx())
            .await
            .expect_err("missing");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn link_skipped_reported_once() {
        use crate::ext::{Cache, Constraints, HostedExt};
        use crate::net::emulate::{LocalClient, Settings, Symlinks};

        let directory = Directory::new();
        directory.write("a/b.txt", b"b");
        std::os::unix::fs::symlink("b.txt", directory.at("a/link")).expect("linked");

        // The same directory, behind a host that skips links.
        let root = url::Url::from_directory_path(directory.dir.path().join("root"))
            .expect("a url")
            .to_string();
        let client = LocalClient::new(
            &root,
            Settings {
                symlinks: Symlinks::Skip,
            },
        )
        .expect("built");
        let cache = Arc::new(Cache::open(directory.dir.path().join("cache")).expect("cache"));
        let host: Arc<dyn ExtHost> = Arc::new(HostedExt::new(
            Arc::new(client),
            Constraints::new().allow(&directory.base).expect("allowed"),
            cache,
        ));

        let enumerator =
            LocalDirEnumerator::open(&directory.base, &Options::default(), host).expect("opens");

        let ctx = ctx();
        let pages = every_page(&enumerator, &ctx).await;

        assert_eq!(pages[0].found[0].files.len(), 1);
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }
}
