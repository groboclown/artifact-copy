//! Fetching one file a source described into that source's cache.
//!
//! Every leaf source downloads the same way, through its own host, so the
//! steps live here once: reuse a cached copy that proves current, otherwise
//! fetch it verified in flight, and leave it read-only.

use std::path::{Path, PathBuf};

use crate::core::ctx::Ctx;
use crate::core::error::Result;
pub(crate) use crate::ext::writable;
use crate::ext::{CachePath, ExtHost, Hold, Judged, Kept, report_expired, settle};
use crate::model::FileRef;
use crate::net::{Expectation, Req};

/// Bytes read at a time when re-checking a cached file.
const VERIFY_CHUNK_BYTES: usize = 64 * 1024;

/// How a download was satisfied.
///
/// Three answers rather than two, because a report tells "the cache did not
/// have it" apart from "the cache had something else": only the first
/// means a recorded cache entry has gone missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Obtained {
    /// The cached copy matched the declared digests. Nothing was fetched.
    Reused,

    /// A copy was cached and could not be shown current, so it was fetched
    /// again over it.
    Replaced,

    /// Nothing was cached. The file was fetched.
    Fetched,
}

/// A file a source fetched, and where its bytes now are.
#[derive(Debug, Clone)]
pub struct Downloaded {
    /// The file on disk, read-only while it stays cached.
    pub path: PathBuf,

    /// Where it sits under its cache folder, as a report records it.
    pub relative_path: String,

    /// The cache folder, named for the host and path it came from. Two
    /// repositories on one host share it.
    pub host: String,

    pub obtained: Obtained,

    /// When the cached copy was fetched and last used, and the limits in
    /// force, as the cache index holds them. `None` where nothing was
    /// recorded.
    pub kept: Option<Kept>,

    /// Keeps the file from size eviction while the caller still needs it:
    /// until a payload is published. Drop it once done.
    pub hold: Option<Hold>,
}

/// Download `file` through `host` into its cache.
///
/// The declared digests are checked **in flight**, so corrupt bytes never
/// land whole. A failure is returned as the host reported it, so a caller
/// can tell a missing file from an unreachable host and fall back.
pub async fn download(
    host: &dyn ExtHost,
    file: &FileRef,
    expect: &Expectation,
    ctx: &Ctx,
) -> Result<Downloaded> {
    let cache = host.cache();

    // Under its URL, not its name: two artifacts may share a file name.
    let path = cache.payload_path(&file.url, &file.name)?;
    let lifetime = host.cache_policy().lifetime(&file.name);

    // One task at a time per path, from the check through the record: two
    // artifacts may share one payload (a POM that is a jar's and, as a
    // `build` dependency, an artifact of its own), and each would otherwise
    // evict and rewrite the other's copy mid-use. The second waits.
    let _locked = cache.lock(&path).await;

    // Another task of this run fetched it and still needs it: the same URL,
    // moments ago, so it is reused whatever its digests -- evicting it
    // would pull the file out from under that task.
    if cache.is_held(&path) && cache.resolve_existing(&path).is_ok() {
        let hold = cache.hold(&path);

        return Ok(downloaded(host, &path, Obtained::Reused, hold));
    }

    let judged = cache.judge(&path, &lifetime);

    // A copy a size cap removed was cached, and its absence is policy, so
    // the download replaces it rather than finding a recorded file lost.
    let present = judged != Judged::Absent || cache.tombstoned(&path);

    if let Judged::Expired(expiry) = judged {
        report_expired(ctx, &file.url, &file.name, expiry);
    }

    // Inside its lifetime, a copy is still reused only on a digest's proof.
    // An undated one, kept before its times were recorded, is adopted.
    let reusable = matches!(judged, Judged::Usable | Judged::Undated);
    let reused = reusable
        .then(|| cached(host, &path, file, expect))
        .flatten();

    if let Some(reused) = reused {
        let hold = cache.hold(&reused);

        if judged == Judged::Undated {
            settle(host, &reused, &file.url, &file.name, &lifetime, ctx)?;
        } else {
            let _ = cache.touch(&reused, &lifetime);
        }

        return Ok(downloaded(host, &reused, Obtained::Reused, hold));
    }

    // A cached payload is read-only, so whatever is under that name has to
    // go before anything can be written there. Not an optimization: a
    // replace-in-place would fail outright on Windows and depends on
    // directory permissions on Unix.
    cache.evict(&path);

    let fetched = host
        .fetch_to_cache(&Req::get(&file.url), &path.as_str(), expect, ctx)
        .await?;

    // The download is the cache's copy from here on, so nothing else may
    // write through it.
    read_only(&cache.resolve(&fetched));

    // Held before it is recorded, so keeping the cache under its size never
    // removes the payload about to be published.
    let hold = cache.hold(&fetched);

    // The path is a hash, so the index is how anyone learns what it holds,
    // and when it was fetched is what its lifetime is judged from.
    settle(host, &fetched, &file.url, &file.name, &lifetime, ctx)?;

    let obtained = match present {
        true => Obtained::Replaced,
        false => Obtained::Fetched,
    };

    Ok(downloaded(host, &fetched, obtained, hold))
}

/// Keep `body` in `host`'s cache as the copy of `file`, for a document a
/// source built rather than fetched: npm's version document, cut from the
/// packument when a registry has no route for it.
pub async fn stage(
    host: &dyn ExtHost,
    file: &FileRef,
    body: &[u8],
    ctx: &Ctx,
) -> Result<Downloaded> {
    let cache = host.cache();
    let path = cache.payload_path(&file.url, &file.name)?;
    let lifetime = host.cache_policy().lifetime(&file.name);

    // Same lock and ordering as `download`: nothing else writes the path
    // meanwhile, and the copy is held before the trims can see it.
    let _locked = cache.lock(&path).await;

    cache.evict(&path);
    cache.replace(&path, body).await?;
    read_only(&cache.resolve(&path));

    let hold = cache.hold(&path);
    settle(host, &path, &file.url, &file.name, &lifetime, ctx)?;

    Ok(downloaded(host, &path, Obtained::Fetched, hold))
}

fn downloaded(host: &dyn ExtHost, path: &CachePath, obtained: Obtained, hold: Hold) -> Downloaded {
    let cache = host.cache();

    Downloaded {
        path: cache.resolve(path),
        relative_path: path.as_str(),
        host: cache
            .root()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        obtained,
        kept: cache.kept(path),
        hold: Some(hold),
    }
}

/// A file already in the cache, when it is provably the right one.
///
/// **Only a digest makes a cached file reusable.** The bytes on disk are
/// complete -- a download is written beside its destination and renamed, so
/// an interrupted one never leaves a file that looks finished -- but
/// complete is not the same as current. A registry that republished a
/// version under the same coordinate would otherwise be copied from a stale
/// cache forever, and that is the failure nobody would notice.
///
/// So a file with no declared digest is fetched again. That is the same
/// answer a fresh fetch gives such a file -- unverified either way -- and
/// it costs a download rather than a wrong artifact. A weak digest is
/// enough here: it is what the fetch itself would have checked against, and
/// catching a cache that has gone stale is not the threat model a
/// collision-resistant hash exists for.
fn cached(
    host: &dyn ExtHost,
    path: &CachePath,
    file: &FileRef,
    expect: &Expectation,
) -> Option<CachePath> {
    // A **digest**, not merely an expectation. A size alone says nothing
    // about the bytes -- a substitution that preserved the length would
    // pass it.
    if file.digests.is_empty() {
        return None;
    }

    let full = host.cache().resolve_existing(path).ok()?;

    let opened = std::fs::File::open(&full).ok()?;
    let mut reader = std::io::BufReader::new(opened);
    let mut verifier = expect.verifier();
    let mut chunk = vec![0u8; VERIFY_CHUNK_BYTES];

    loop {
        let read = std::io::Read::read(&mut reader, &mut chunk).ok()?;

        if read == 0 {
            break;
        }

        verifier.update(&chunk[..read]);
    }

    // A mismatch is not an error: it means the cache holds something else,
    // which the fetch replaces. Warning about it would be noise on the
    // ordinary path of a registry that moved on.
    verifier.finish().ok()?;

    Some(path.clone())
}

/// Mark a cached payload read-only.
///
/// A target is handed the cached file itself, so one that wrote to it
/// would write into the cache. No built-in target does, and an
/// out-of-process one is given a copy by its gearing.
///
/// A mitigation rather than a guarantee: an extension that unlinks the file
/// and creates a new one in its place defeats it. Copying every payload is
/// the only complete answer and costs the bytes of every artifact of every
/// migration; see `docs/contributors/report-as-database.md`.
fn read_only(path: &Path) {
    let Ok(found) = std::fs::metadata(path) else {
        return;
    };

    let mut permissions = found.permissions();
    permissions.set_readonly(true);

    let _ = std::fs::set_permissions(path, permissions);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::TestHost;
    use crate::model::{Digest, DigestAlg};
    use crate::net::FixtureClient;

    const URL: &str = "h://origin.test/tuna-1.0.0.tgz";
    const BYTES: &[u8] = b"the payload";

    fn sha256(bytes: &[u8]) -> String {
        use sha2::Digest as _;

        hex::encode(sha2::Sha256::digest(bytes))
    }

    fn file(digested: bool) -> FileRef {
        let mut file = FileRef::new("tuna-1.0.0.tgz", URL);

        if digested {
            file.digests = vec![Digest::new(DigestAlg::Sha256, sha256(BYTES))];
        }

        file
    }

    async fn fetched(host: &TestHost, file: &FileRef) -> Downloaded {
        let expect = Expectation::new().with_digests(file.digests.clone());

        download(host, file, &expect, &Ctx::anonymous_for_test())
            .await
            .expect("downloaded")
    }

    #[tokio::test]
    async fn cache_empty_fetches() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, BYTES));

        let got = fetched(&host, &file(true)).await;

        assert_eq!(got.obtained, Obtained::Fetched);
        assert_eq!(std::fs::read(&got.path).expect("readable"), BYTES);
        assert!(
            std::fs::metadata(&got.path)
                .expect("there")
                .permissions()
                .readonly()
        );
    }

    /// Two artifacts sharing one payload, fetched at once: one request, and
    /// both get the file -- even with no digest, which would otherwise
    /// evict and fetch again under the first.
    #[tokio::test]
    async fn payload_fetch_shared_by_concurrent_downloads() {
        let host = TestHost::new(FixtureClient::new().with(
            URL,
            crate::net::Canned::ok(BYTES).slow(std::time::Duration::from_millis(50)),
        ));
        let undigested = file(false);

        let (first, second) =
            tokio::join!(fetched(&host, &undigested), fetched(&host, &undigested));

        assert_eq!(host.hits(URL), 1);
        assert_eq!(std::fs::read(&first.path).expect("readable"), BYTES);
        assert_eq!(std::fs::read(&second.path).expect("readable"), BYTES);
        assert_eq!(second.obtained, Obtained::Reused);
    }

    #[tokio::test]
    async fn copy_proven_reused() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, BYTES));

        fetched(&host, &file(true)).await;
        let again = fetched(&host, &file(true)).await;

        assert_eq!(again.obtained, Obtained::Reused);
        assert_eq!(host.hits(URL), 1);
    }

    /// A copy cached before its times were recorded is adopted on its
    /// digest's proof, and recorded from then on.
    #[tokio::test]
    async fn copy_undated_adopted() {
        let host = TestHost::new(FixtureClient::new());
        let path = host
            .cache()
            .payload_path(URL, "tuna-1.0.0.tgz")
            .expect("path");
        let full = host.cache().resolve(&path);

        std::fs::create_dir_all(full.parent().expect("parent")).expect("dir");
        std::fs::write(&full, BYTES).expect("written");

        let got = fetched(&host, &file(true)).await;

        assert_eq!(got.obtained, Obtained::Reused);
        assert_eq!(host.hits(URL), 0);
        assert!(host.cache().origin(&path).expect("read").is_some());
    }

    /// Two artifacts sharing a file name keep separate copies.
    #[tokio::test]
    async fn copy_same_name_two_urls_kept_apart() {
        const OTHER_URL: &str = "h://origin.test/other/tuna-1.0.0.tgz";
        const OTHER_BYTES: &[u8] = b"another payload";

        let host = TestHost::new(
            FixtureClient::new()
                .with_body(URL, BYTES)
                .with_body(OTHER_URL, OTHER_BYTES),
        );

        let first = fetched(&host, &file(false)).await;
        let second = fetched(&host, &FileRef::new("tuna-1.0.0.tgz", OTHER_URL)).await;

        assert_ne!(first.path, second.path);
        assert_eq!(std::fs::read(&first.path).expect("readable"), BYTES);
        assert_eq!(std::fs::read(&second.path).expect("readable"), OTHER_BYTES);
    }

    /// The hashed path is traced back through the payload index.
    #[tokio::test]
    async fn download_indexed() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, BYTES));

        let got = fetched(&host, &file(true)).await;
        let path = host
            .cache()
            .payload_path(URL, "tuna-1.0.0.tgz")
            .expect("path");
        let origin = host.cache().origin(&path).expect("read").expect("indexed");

        assert_eq!(got.relative_path, path.as_str());
        assert_eq!(origin.url, URL);
        assert_eq!(origin.name, "tuna-1.0.0.tgz");
    }

    /// Present but unprovable is not missing: the report must not call it
    /// a lost cache entry.
    #[tokio::test]
    async fn copy_unprovable_replaced() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, BYTES));

        fetched(&host, &file(false)).await;
        let again = fetched(&host, &file(false)).await;

        assert_eq!(again.obtained, Obtained::Replaced);
        assert_eq!(host.hits(URL), 2);
    }

    /// Past its lifetime, even a copy its digest proves is fetched again,
    /// and the eviction is recorded. Both limits behave alike here.
    #[tokio::test]
    async fn payload_expired_replaced() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::core::problem::Code;
        use crate::ext::{CachePolicy, FreshnessRule, Policed};

        let limits = [
            CachePolicy::new(Some(Duration::ZERO), Vec::new()),
            CachePolicy::new(
                None,
                vec![FreshnessRule::new("*.tgz", Some(Duration::ZERO))],
            ),
        ];

        for policy in limits {
            let test = Arc::new(TestHost::new(FixtureClient::new().with_body(URL, BYTES)));
            let host = Policed::new(Arc::clone(&test) as Arc<dyn ExtHost>, policy);
            let file = file(true);
            let expect = Expectation::new().with_digests(file.digests.clone());
            let ctx = Ctx::anonymous_for_test();

            download(&host, &file, &expect, &ctx).await.expect("first");
            let again = download(&host, &file, &expect, &ctx).await.expect("second");

            assert_eq!(again.obtained, Obtained::Replaced);
            assert_eq!(test.hits(URL), 2);
            assert_eq!(
                ctx.problems().counts().get(&Code::CacheEntryExpired),
                Some(&1)
            );
        }
    }

    /// A payload a size cap removed was cached on purpose, so fetching it
    /// again is a replacement, not a recorded file gone missing.
    #[tokio::test]
    async fn payload_evicted_replaced() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, BYTES));

        let first = fetched(&host, &file(true)).await;
        drop(first);
        host.cache().trim(0).expect("trimmed");
        let again = fetched(&host, &file(true)).await;

        assert_eq!(again.obtained, Obtained::Replaced);
        assert_eq!(host.hits(URL), 2);
    }

    /// The payload is held until the caller drops it, so a size cap
    /// cannot remove it before it is published.
    #[tokio::test]
    async fn payload_downloaded_held() {
        let host = TestHost::new(FixtureClient::new().with_body(URL, BYTES));

        let got = fetched(&host, &file(true)).await;

        assert!(host.cache().trim(0).expect("trimmed").is_empty());

        drop(got);

        assert_eq!(host.cache().trim(0).expect("trimmed").len(), 1);
    }
}
