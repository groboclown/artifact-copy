//! The client a `file://` host sends its requests through.
//!
//! ```text
//!   GET  {path}                     the file's bytes
//!   HEAD {path}                     its size and modification time
//!   PUT  {path}                     create it; 409 when something is there
//!   GET  {dir}/?api={emulation}...  an emulation's answer; see the module above
//! ```
//!
//! Failures answer as a server's would, so a repository kind needs no
//! second path for a directory: 404 for nothing there, 403 for a path this
//! host may not reach, 405 for a method a directory cannot take.
//!
//! Only the generic emulation answers `?api=` today. A repository type
//! that needs responses a directory does not hold as files -- an npm
//! packument, a PyPI simple index -- would add its own, enabled through
//! this host's `options` when it is implemented.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use http::StatusCode;
use tokio::io::AsyncWriteExt;
use url::Url;

use super::fs::{Opened, Refusal, Root};
use super::{FILE_SCHEME, Settings, generic};
use crate::core::ctx::Ctx;
use crate::core::error::{Contact, Error, Result};
use crate::net::files::{Pending, Placed};
use crate::net::{ByteLimit, Expectation, FormPart, Head, HttpClient, Method, Req};

/// The read buffer for streaming a file.
const CHUNK_BYTES: usize = 64 * 1024;

/// The `Last-Modified` format, RFC 9110's IMF-fixdate, always in GMT.
const HTTP_DATE: &str = "%a, %d %b %Y %H:%M:%S GMT";

/// Answers requests from one directory.
#[derive(Debug, Clone)]
pub struct LocalClient {
    root: Arc<Root>,
}

/// Where a request points.
struct Located {
    /// Relative to the root; empty for the root itself.
    relative: PathBuf,

    /// The emulation a query names, if any.
    api: Option<String>,

    /// The rest of the query.
    query: Vec<(String, String)>,
}

impl LocalClient {
    /// A client for the directory `url` names.
    ///
    /// Touches nothing: the directory is first read by the first request,
    /// so a configuration can be checked where the directory is absent.
    /// The message is the caller's to frame with the host's name.
    pub fn new(url: &str, settings: Settings) -> std::result::Result<Self, String> {
        let parsed = Url::parse(url).map_err(|err| format!("{url:?} is not a URL: {err}"))?;

        if parsed.scheme() != FILE_SCHEME {
            return Err(format!("{url:?} is not a {FILE_SCHEME}:// URL"));
        }

        let path = parsed
            .to_file_path()
            .map_err(|()| format!("{url:?} does not name a directory on this machine"))?;

        Ok(Self {
            root: Arc::new(Root::new(path, settings.symlinks)),
        })
    }

    fn locate(&self, req: &Req) -> Result<Located> {
        let url = &req.url;

        let parsed = Url::parse(url)
            .map_err(|err| status(url, StatusCode::BAD_REQUEST, format!("not a URL: {err}")))?;

        if parsed.scheme() != FILE_SCHEME {
            return Err(status(
                url,
                StatusCode::BAD_REQUEST,
                format!("not a {FILE_SCHEME}:// URL"),
            ));
        }

        let path = parsed.to_file_path().map_err(|()| {
            status(
                url,
                StatusCode::BAD_REQUEST,
                "does not name a path on this machine".into(),
            )
        })?;

        let relative = path
            .strip_prefix(self.root.path())
            .map_err(|_| {
                status(
                    url,
                    StatusCode::FORBIDDEN,
                    "outside this host's directory".into(),
                )
            })?
            .to_path_buf();

        let mut api = None;
        let mut query = Vec::new();

        for (key, value) in parsed.query_pairs() {
            if key == generic::API && api.is_none() {
                api = Some(value.into_owned());
                continue;
            }

            query.push((key.into_owned(), value.into_owned()));
        }

        Ok(Located {
            relative,
            api,
            query,
        })
    }

    /// Run filesystem work off the async runtime.
    async fn blocking<T: Send + 'static>(
        &self,
        url: &str,
        work: impl FnOnce(&Root) -> std::result::Result<T, Refusal> + Send + 'static,
    ) -> Result<T> {
        let root = Arc::clone(&self.root);

        let done = tokio::task::spawn_blocking(move || work(&root))
            .await
            .map_err(|source| Error::Transport {
                url: url.to_owned(),
                during: Contact::Stream,
                source: Box::new(source),
            })?;

        done.map_err(|refusal| refused(url, refusal))
    }

    /// The file a read names, refusing anything else.
    async fn readable(&self, req: &Req) -> Result<Opened> {
        let located = self.locate(req)?;

        if located.api.is_some() {
            return Err(status(
                &req.url,
                StatusCode::METHOD_NOT_ALLOWED,
                "an emulated route answers GET only".into(),
            ));
        }

        let relative = located.relative;
        let opened = self
            .blocking(&req.url, move |root| root.open(&relative))
            .await?;

        if let Opened::Directory(_) = opened {
            return Err(status(
                &req.url,
                StatusCode::FORBIDDEN,
                "a directory, not a file".into(),
            ));
        }

        Ok(opened)
    }

    /// An emulation's answer.
    async fn emulated(&self, req: &Req, located: Located) -> Result<Vec<u8>> {
        let Some(api) = located.api else {
            unreachable!("only called for a query naming an emulation");
        };

        if api != generic::LIST {
            return Err(status(
                &req.url,
                StatusCode::NOT_FOUND,
                format!("this host has no emulation named {api:?}"),
            ));
        }

        let (relative, query) = (located.relative, located.query);
        let listing = self
            .blocking(&req.url, move |root| {
                generic::answer(root, &relative, &query)
            })
            .await?;

        serde_json::to_vec(&listing).map_err(|err| Error::Malformed {
            what: "generic listing",
            url: req.url.clone(),
            detail: err.to_string(),
        })
    }
}

/// An error status, as a server would answer.
fn status(url: &str, code: StatusCode, detail: String) -> Error {
    Error::HttpStatus {
        url: url.to_owned(),
        status: code,
        retry_at: None,
        detail: Some(detail),
    }
}

fn refused(url: &str, refusal: Refusal) -> Error {
    match refusal {
        Refusal::Missing => status(url, StatusCode::NOT_FOUND, "nothing is at this path".into()),
        Refusal::Forbidden(why) => status(url, StatusCode::FORBIDDEN, why),

        Refusal::Occupied => status(
            url,
            StatusCode::CONFLICT,
            "a file is already at this path, and a written path is not replaced".into(),
        ),

        Refusal::Failed { path, source } => Error::ReadFile { path, source },
    }
}

/// Refuse a method this route cannot take.
fn require(req: &Req, allowed: &[Method]) -> Result<()> {
    if allowed.contains(&req.method) {
        return Ok(());
    }

    Err(status(
        &req.url,
        StatusCode::METHOD_NOT_ALLOWED,
        format!("a directory does not answer {:?} here", req.method),
    ))
}

fn read_error(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    }
}

#[async_trait]
impl HttpClient for LocalClient {
    async fn head(&self, req: &Req, _ctx: &Ctx) -> Result<Head> {
        require(req, &[Method::Head, Method::Get])?;

        let opened = self.readable(req).await?;

        let (size, modified) = match opened {
            Opened::Link(text) => (text.len() as u64, None),

            Opened::File(path) => {
                let meta = tokio::fs::metadata(&path)
                    .await
                    .map_err(read_error(&path))?;
                let modified = meta
                    .modified()
                    .ok()
                    .map(chrono::DateTime::<chrono::Utc>::from);

                (meta.len(), modified)
            }

            Opened::Directory(_) => unreachable!("refused by readable"),
        };

        let mut headers = vec![("content-length".to_owned(), size.to_string())];

        if let Some(modified) = modified {
            headers.push((
                "last-modified".to_owned(),
                modified.format(HTTP_DATE).to_string(),
            ));
        }

        Ok(Head {
            status: StatusCode::OK,
            headers,
        })
    }

    async fn fetch_bounded(&self, req: &Req, max: ByteLimit, _ctx: &Ctx) -> Result<Bytes> {
        require(req, &[Method::Get])?;

        let located = self.locate(req)?;

        let body = match located.api {
            Some(_) => self.emulated(req, located).await?,

            None => match self.readable(req).await? {
                Opened::Link(text) => text,

                Opened::File(path) => {
                    let size = tokio::fs::metadata(&path)
                        .await
                        .map_err(read_error(&path))?
                        .len();

                    // Checked again on the bytes read: the file may grow.
                    if size > max.get() {
                        return Err(too_large(req, max));
                    }

                    tokio::fs::read(&path).await.map_err(read_error(&path))?
                }

                Opened::Directory(_) => unreachable!("refused by readable"),
            },
        };

        if body.len() as u64 > max.get() {
            return Err(too_large(req, max));
        }

        Ok(Bytes::from(body))
    }

    async fn fetch_to_file(
        &self,
        req: &Req,
        dest: &Path,
        expect: &Expectation,
        _ctx: &Ctx,
    ) -> Result<PathBuf> {
        require(req, &[Method::Get])?;

        let opened = self.readable(req).await?;

        // Written beside the destination and committed only once verified,
        // as a download is; see `Pending`.
        let pending = Pending::begin(dest).await?;
        let mut file = pending.writer()?;
        let mut verifier = expect.verifier();

        let write_error = |source| Error::WriteFile {
            path: pending.path().to_path_buf(),
            source,
        };

        match opened {
            Opened::Link(text) => {
                verifier.update(&text);
                file.write_all(&text).await.map_err(write_error)?;
            }

            Opened::File(path) => {
                let mut source = tokio::fs::File::open(&path)
                    .await
                    .map_err(read_error(&path))?;
                let mut buffer = vec![0; CHUNK_BYTES];

                loop {
                    let read = tokio::io::AsyncReadExt::read(&mut source, &mut buffer)
                        .await
                        .map_err(read_error(&path))?;

                    if read == 0 {
                        break;
                    }

                    verifier.update(&buffer[..read]);
                    file.write_all(&buffer[..read]).await.map_err(write_error)?;
                }
            }

            Opened::Directory(_) => unreachable!("refused by readable"),
        }

        file.flush().await.map_err(write_error)?;
        drop(file);

        verifier.finish()?;
        pending.commit()?;

        Ok(dest.to_path_buf())
    }

    fn fetch_stream<'a>(&'a self, req: &'a Req, _ctx: &'a Ctx) -> BoxStream<'a, Result<Bytes>> {
        let stream = async_stream::try_stream! {
            require(req, &[Method::Get])?;

            match self.readable(req).await? {
                Opened::Link(text) => yield Bytes::from(text),

                Opened::File(path) => {
                    let source = tokio::fs::File::open(&path)
                        .await
                        .map_err(read_error(&path))?;
                    let mut chunks = tokio_util::io::ReaderStream::with_capacity(source, CHUNK_BYTES);

                    while let Some(chunk) = chunks.next().await {
                        yield chunk.map_err(read_error(&path))?;
                    }
                }

                Opened::Directory(_) => unreachable!("refused by readable"),
            }
        };

        Box::pin(stream)
    }

    /// Create the file a `PUT` names, once.
    async fn send_file(
        &self,
        req: &Req,
        body: &Path,
        _max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        require(req, &[Method::Put])?;

        let located = self.locate(req)?;

        if located.api.is_some() {
            return Err(status(
                &req.url,
                StatusCode::METHOD_NOT_ALLOWED,
                "an emulated route answers GET only".into(),
            ));
        }

        let relative = located.relative;
        let dest = self
            .blocking(&req.url, move |root| root.writable(&relative))
            .await?;

        let pending = Pending::begin(&dest).await?;
        let mut file = pending.writer()?;

        let write_error = |source| Error::WriteFile {
            path: pending.path().to_path_buf(),
            source,
        };

        let mut source = tokio::fs::File::open(body)
            .await
            .map_err(read_error(body))?;

        tokio::io::copy(&mut source, &mut file)
            .await
            .map_err(write_error)?;
        file.flush().await.map_err(write_error)?;
        drop(file);

        match pending.commit_new()? {
            Placed::Created => Ok(Bytes::new()),

            // Another writer got there between the check and the commit.
            Placed::Occupied => Err(refused(&req.url, Refusal::Occupied)),
        }
    }

    async fn send_form(
        &self,
        req: &Req,
        _parts: &[FormPart<'_>],
        _max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        Err(status(
            &req.url,
            StatusCode::METHOD_NOT_ALLOWED,
            "a directory does not take a form upload".into(),
        ))
    }
}

fn too_large(req: &Req, max: ByteLimit) -> Error {
    Error::TooLarge {
        url: req.url.clone(),
        limit: max.get(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::model::{Cause, Digest, DigestAlg};
    use crate::net::emulate::Symlinks;
    use crate::net::emulate::generic::{Digests, Listing, listing_url};

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "local".into(),
        })
    }

    struct Fixture {
        dir: tempfile::TempDir,
        client: LocalClient,
    }

    impl Fixture {
        fn new(symlinks: Symlinks) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");

            std::fs::create_dir_all(dir.path().join("root/repo/a")).expect("dirs");
            std::fs::write(dir.path().join("root/repo/a/one.txt"), b"one").expect("file");
            std::fs::write(dir.path().join("outside.txt"), b"secret").expect("file");

            let url = Url::from_directory_path(dir.path().join("root"))
                .expect("a url")
                .to_string();
            let client = LocalClient::new(&url, Settings { symlinks }).expect("built");

            Self { dir, client }
        }

        fn url(&self, relative: &str) -> String {
            let base = Url::from_directory_path(self.dir.path().join("root")).expect("a url");

            format!("{base}{relative}")
        }

        fn staged(&self, bytes: &[u8]) -> PathBuf {
            let path = self.dir.path().join("staged.bin");
            std::fs::write(&path, bytes).expect("staged");
            path
        }
    }

    fn code(err: &Error) -> Option<StatusCode> {
        match err {
            Error::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    #[test]
    fn only_file_url_builds() {
        assert!(LocalClient::new("https://repo.test/", Settings::default()).is_err());
        assert!(LocalClient::new("file:///srv/backup/", Settings::default()).is_ok());
    }

    #[tokio::test]
    async fn get_reads_file() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let body = fixture
            .client
            .fetch_bounded(
                &Req::get(fixture.url("repo/a/one.txt")),
                ByteLimit::kib(1),
                &ctx(),
            )
            .await
            .expect("read");

        assert_eq!(body.as_ref(), b"one");
    }

    #[tokio::test]
    async fn get_cap_enforced() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let err = fixture
            .client
            .fetch_bounded(
                &Req::get(fixture.url("repo/a/one.txt")),
                ByteLimit::bytes(2),
                &ctx(),
            )
            .await
            .expect_err("too large");

        assert!(matches!(err, Error::TooLarge { .. }), "{err}");
    }

    #[tokio::test]
    async fn head_describes_file() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let head = fixture
            .client
            .head(&Req::head(fixture.url("repo/a/one.txt")), &ctx())
            .await
            .expect("described");

        assert_eq!(head.header("content-length"), Some("3"));
        assert!(
            head.header("last-modified")
                .is_some_and(|date| date.ends_with("GMT"))
        );
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let err = fixture
            .client
            .fetch_bounded(
                &Req::get(fixture.url("repo/nope.txt")),
                ByteLimit::kib(1),
                &ctx(),
            )
            .await
            .expect_err("missing");

        assert_eq!(code(&err), Some(StatusCode::NOT_FOUND), "{err}");
    }

    #[tokio::test]
    async fn get_outside_root_is_403() {
        let fixture = Fixture::new(Symlinks::Follow);
        let url = Url::from_file_path(fixture.dir.path().join("outside.txt"))
            .expect("a url")
            .to_string();

        let err = fixture
            .client
            .fetch_bounded(&Req::get(url), ByteLimit::kib(1), &ctx())
            .await
            .expect_err("refused");

        assert_eq!(code(&err), Some(StatusCode::FORBIDDEN), "{err}");
    }

    #[tokio::test]
    async fn get_directory_is_403() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let err = fixture
            .client
            .fetch_bounded(&Req::get(fixture.url("repo/a/")), ByteLimit::kib(1), &ctx())
            .await
            .expect_err("refused");

        assert_eq!(code(&err), Some(StatusCode::FORBIDDEN), "{err}");
    }

    #[tokio::test]
    async fn put_creates_once() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let ctx = ctx();
        let staged = fixture.staged(b"new");
        let put = Req::put(fixture.url("repo/b/new.txt"));

        fixture
            .client
            .send_file(&put, &staged, ByteLimit::kib(1), &ctx)
            .await
            .expect("created");

        assert_eq!(
            std::fs::read(fixture.dir.path().join("root/repo/b/new.txt")).expect("written"),
            b"new"
        );

        let other = fixture.staged(b"other");
        let err = fixture
            .client
            .send_file(&put, &other, ByteLimit::kib(1), &ctx)
            .await
            .expect_err("occupied");

        assert_eq!(code(&err), Some(StatusCode::CONFLICT), "{err}");
        assert_eq!(
            std::fs::read(fixture.dir.path().join("root/repo/b/new.txt")).expect("kept"),
            b"new"
        );
    }

    #[tokio::test]
    async fn put_needs_put() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let staged = fixture.staged(b"x");

        let err = fixture
            .client
            .send_file(
                &Req::get(fixture.url("repo/x.txt")),
                &staged,
                ByteLimit::kib(1),
                &ctx(),
            )
            .await
            .expect_err("refused");

        assert_eq!(code(&err), Some(StatusCode::METHOD_NOT_ALLOWED), "{err}");
    }

    #[tokio::test]
    async fn fetch_verifies_in_flight() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let dest = fixture.dir.path().join("cache/one.txt");
        let wrong = Expectation::new().with_digest(Digest::new(DigestAlg::Sha256, "00".repeat(32)));

        let err = fixture
            .client
            .fetch_to_file(
                &Req::get(fixture.url("repo/a/one.txt")),
                &dest,
                &wrong,
                &ctx(),
            )
            .await
            .expect_err("mismatch");

        assert!(!dest.exists(), "{err}");

        fixture
            .client
            .fetch_to_file(
                &Req::get(fixture.url("repo/a/one.txt")),
                &dest,
                &Expectation::new(),
                &ctx(),
            )
            .await
            .expect("fetched");

        assert_eq!(std::fs::read(&dest).expect("read"), b"one");
    }

    #[tokio::test]
    async fn generic_listing_answers() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let url = listing_url(&fixture.url("repo"), "a/", Digests::Sha256);

        let body = fixture
            .client
            .fetch_bounded(&Req::get(url), ByteLimit::kib(64), &ctx())
            .await
            .expect("listed");
        let listing: Listing = serde_json::from_slice(&body).expect("json");

        assert_eq!(listing.items.len(), 1);
        assert_eq!(listing.items[0].path, "a/one.txt");
        assert!(listing.items[0].sha256.is_some());
    }

    #[tokio::test]
    async fn emulation_unknown_is_404() {
        let fixture = Fixture::new(Symlinks::AsFile);
        let err = fixture
            .client
            .fetch_bounded(
                &Req::get(format!("{}?api=npm-packument", fixture.url("repo/"))),
                ByteLimit::kib(64),
                &ctx(),
            )
            .await
            .expect_err("unknown");

        assert_eq!(code(&err), Some(StatusCode::NOT_FOUND), "{err}");
    }

    #[tokio::test]
    async fn link_streams_text() {
        let fixture = Fixture::new(Symlinks::AsFile);
        std::os::unix::fs::symlink("../outside.txt", fixture.dir.path().join("root/repo/link"))
            .expect("linked");

        let chunks: Vec<Bytes> = fixture
            .client
            .fetch_stream(&Req::get(fixture.url("repo/link")), &ctx())
            .map(|chunk| chunk.expect("chunk"))
            .collect()
            .await;

        assert_eq!(chunks.concat(), b"../outside.txt");
    }
}
