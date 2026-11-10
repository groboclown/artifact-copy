//! The live HTTP client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::stream::{BoxStream, StreamExt};
use http::StatusCode;
use tokio::io::AsyncWriteExt;

use super::excerpt::{self, ERROR_BODY_LIMIT, Read};
use super::{ByteLimit, Expectation, FormPart, Head, HttpClient, Method, Req};
use crate::config::TlsVerify;
use crate::core::ctx::Ctx;
use crate::core::error::{Contact, Error, Result};
use crate::core::log::Log;

/// Identifies this tool to registries, with a contact point.
///
/// Not decoration: Maven Central fingerprints clients and returns 403 to
/// anonymous ones, and PyPI's API docs ask consumers to identify themselves
/// so they can be contacted before being blocked.
const USER_AGENT: &str = concat!(
    "artifact-copy/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/groboclown/artifact-copy)"
);

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// One file field of a form, streamed rather than read.
///
/// `stream_with_length` rather than `stream`: without a length the part is
/// sent chunked, and registries behind a proxy routinely refuse a chunked
/// upload.
async fn file_part(
    path: &Path,
    filename: Option<&str>,
    content_type: Option<&str>,
) -> Result<reqwest::multipart::Part> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;

    let length = file
        .metadata()
        .await
        .map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?
        .len();

    let mut part = reqwest::multipart::Part::stream_with_length(
        reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file)),
        length,
    );

    // Defaulted to the name on disk, because a server that is told nothing
    // has no way to name what it received.
    let named = filename.map(str::to_owned).or_else(|| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });

    if let Some(named) = named {
        part = part.file_name(named);
    }

    if let Some(mime) = content_type {
        part = part.mime_str(mime).map_err(|source| {
            Error::Config(format!("{mime:?} is not a usable content type: {source}"))
        })?;
    }

    Ok(part)
}

/// Read a response into memory, capped.
///
/// Enforced **per chunk** rather than from `Content-Length`, which a server
/// is free to understate or omit -- trusting it is precisely how the cap
/// gets bypassed.
async fn bounded(mut response: reqwest::Response, url: &str, max: ByteLimit) -> Result<Bytes> {
    let mut body = BytesMut::new();

    while let Some(chunk) = response.chunk().await.map_err(|source| Error::Transport {
        url: url.to_owned(),
        during: Contact::Stream,
        source: Box::new(source),
    })? {
        if body.len() as u64 + chunk.len() as u64 > max.get() {
            return Err(Error::TooLarge {
                url: url.to_owned(),
                limit: max.get(),
            });
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

/// Read an error body up to [`ERROR_BODY_LIMIT`], giving up quietly.
///
/// The status is the error and the body only explains it, so a failure
/// here keeps what arrived instead of replacing the error.  Bounded in time
/// as well as size: this runs on the failure path of every call, and a
/// server that is failing may also be slow to say why.
async fn error_body(mut response: reqwest::Response) -> (BytesMut, Read) {
    let mut body = BytesMut::new();
    let limit = ERROR_BODY_LIMIT.get() as usize;

    let reading = async {
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return Read::Whole,
                Err(_) => return Read::Truncated,
            };

            let room = limit - body.len();

            if chunk.len() > room {
                body.extend_from_slice(&chunk[..room]);
                return Read::Truncated;
            }

            body.extend_from_slice(&chunk);
        }
    };

    let read = tokio::time::timeout(ERROR_BODY_TIMEOUT, reading)
        .await
        .unwrap_or(Read::Truncated);

    (body, read)
}

/// How long an error body may take to arrive.
const ERROR_BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP 400 and above.
const FIRST_ERROR_STATUS: StatusCode = StatusCode::BAD_REQUEST;

#[derive(Debug, Clone)]
pub struct ReqwestClient {
    inner: reqwest::Client,
}

impl ReqwestClient {
    pub fn new() -> Result<Self> {
        Self::with_tls(TlsVerify::Enabled, &Log::default())
    }

    /// Build a client, optionally accepting any certificate.
    ///
    /// Disabling verification is a per-host decision the user has to make
    /// explicitly, and it is logged every time: without it, nothing
    /// distinguishes the real host from an interceptor, so every checksum
    /// and signature fetched over that connection could come from one.
    pub fn with_tls(tls: TlsVerify, log: &Log) -> Result<Self> {
        if tls == TlsVerify::Disabled {
            log.warn(
                "TLS certificate verification is disabled for this host; \
                 checksums and signatures fetched over it cannot be trusted",
            );
        }

        let inner = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(tls == TlsVerify::Disabled)
            // Followed by the capability, which checks each hop. Followed
            // here, a redirect would carry this request's credentials past
            // the host's constraints.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|source| Error::Transport {
                url: "<client>".into(),
                during: Contact::Connect,
                source: Box::new(source),
            })?;

        Ok(Self { inner })
    }

    /// Issue the request and reject error statuses, so every caller below
    /// sees only a response it can read.
    async fn send(&self, req: &Req) -> Result<reqwest::Response> {
        let mut builder = self.request(req);

        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }

        self.dispatch(builder, req).await
    }

    /// The request, without a body.
    fn request(&self, req: &Req) -> reqwest::RequestBuilder {
        let mut builder = match req.method {
            Method::Get => self.inner.get(&req.url),
            Method::Head => self.inner.head(&req.url),
            Method::Post => self.inner.post(&req.url),
            Method::Put => self.inner.put(&req.url),
        };

        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }

        builder
    }

    /// Send a built request and refuse an error status.
    ///
    /// `req` is the request `builder` was made from; its headers name the
    /// credentials an error body must not repeat.
    async fn dispatch(
        &self,
        builder: reqwest::RequestBuilder,
        req: &Req,
    ) -> Result<reqwest::Response> {
        let url = req.url.as_str();

        // reqwest says whether it ever connected; a request it could not
        // build never tried. Anything after that -- a request body cut off,
        // a response that never came -- is the link, not the address.
        let response = builder.send().await.map_err(|source| Error::Transport {
            url: url.to_owned(),
            during: if source.is_connect() || source.is_builder() {
                Contact::Connect
            } else {
                Contact::Stream
            },
            source: Box::new(source),
        })?;

        let status = response.status();

        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok());

        if let Some(redirect) = crate::net::redirect::redirected(url, status, location) {
            return Err(redirect);
        }

        if status >= FIRST_ERROR_STATUS {
            let header = |name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };

            let retry_at = crate::net::retry::retry_at(
                |name| {
                    response
                        .headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                },
                chrono::Utc::now(),
            );
            let content_type = header(reqwest::header::CONTENT_TYPE);
            let (body, read) = error_body(response).await;

            return Err(Error::HttpStatus {
                url: url.to_owned(),
                status,
                retry_at,
                detail: excerpt::detail(&body, read, content_type.as_deref(), &req.headers),
            });
        }

        Ok(response)
    }
}

fn collect_head(response: &reqwest::Response) -> Head {
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect();

    Head {
        status: response.status(),
        headers,
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn head(&self, req: &Req, _ctx: &Ctx) -> Result<Head> {
        let response = self.send(req).await?;

        Ok(collect_head(&response))
    }

    async fn fetch_bounded(&self, req: &Req, max: ByteLimit, _ctx: &Ctx) -> Result<Bytes> {
        bounded(self.send(req).await?, &req.url, max).await
    }

    async fn fetch_to_file(
        &self,
        req: &Req,
        dest: &Path,
        expect: &Expectation,
        _ctx: &Ctx,
    ) -> Result<PathBuf> {
        let mut response = self.send(req).await?;

        // Written beside the destination, then committed, so an interrupted
        // download never leaves a partial file that looks complete to the
        // cache on the next run; see `Pending`.
        let pending = super::files::Pending::begin(dest).await?;
        let mut file = pending.writer()?;

        let mut verifier = expect.verifier();

        while let Some(chunk) = response.chunk().await.map_err(|source| Error::Transport {
            url: req.url.clone(),
            during: Contact::Stream,
            source: Box::new(source),
        })? {
            verifier.update(&chunk);

            file.write_all(&chunk)
                .await
                .map_err(|source| Error::WriteFile {
                    path: pending.path().to_path_buf(),
                    source,
                })?;
        }

        file.flush().await.map_err(|source| Error::WriteFile {
            path: pending.path().to_path_buf(),
            source,
        })?;
        drop(file);

        // Verify before publishing the name: a failed check must not leave a
        // usable file behind.
        verifier.finish()?;

        pending.commit()?;

        Ok(dest.to_path_buf())
    }

    async fn send_file(&self, req: &Req, body: &Path, max: ByteLimit, _ctx: &Ctx) -> Result<Bytes> {
        let file = tokio::fs::File::open(body)
            .await
            .map_err(|source| Error::ReadFile {
                path: body.to_path_buf(),
                source,
            })?;

        let length = file
            .metadata()
            .await
            .map_err(|source| Error::ReadFile {
                path: body.to_path_buf(),
                source,
            })?
            .len();

        let mut builder = self.request(req).body(reqwest::Body::wrap_stream(
            tokio_util::io::ReaderStream::new(file),
        ));

        // Sent explicitly because a streamed body would otherwise go out
        // chunked, and registries behind a proxy routinely refuse that for
        // an upload.
        builder = builder.header(reqwest::header::CONTENT_LENGTH, length);

        let response = self.dispatch(builder, req).await?;

        bounded(response, &req.url, max).await
    }

    async fn send_form(
        &self,
        req: &Req,
        parts: &[FormPart<'_>],
        max: ByteLimit,
        _ctx: &Ctx,
    ) -> Result<Bytes> {
        let mut form = reqwest::multipart::Form::new();

        for part in parts {
            form = match part {
                FormPart::Text { name, value } => form.text(name.to_string(), value.to_string()),

                FormPart::File {
                    name,
                    path,
                    filename,
                    content_type,
                } => form.part(
                    name.to_string(),
                    file_part(path, *filename, *content_type).await?,
                ),
            };
        }

        // `multipart` sets its own content type, boundary included, so a
        // caller's would be wrong rather than merely redundant.
        let response = self
            .dispatch(self.request(req).multipart(form), req)
            .await?;

        bounded(response, &req.url, max).await
    }

    fn fetch_stream<'a>(&'a self, req: &'a Req, _ctx: &'a Ctx) -> BoxStream<'a, Result<Bytes>> {
        let url = req.url.clone();

        let stream = async_stream::try_stream! {
            let response = self.send(req).await?;
            let mut bytes = response.bytes_stream();

            while let Some(chunk) = bytes.next().await {
                let chunk = chunk.map_err(|source| Error::Transport {
                    url: url.clone(),
                    during: Contact::Stream,
                    source: Box::new(source),
                })?;

                yield chunk;
            }
        };

        Box::pin(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the `h://` test-URL convention relies on.
    ///
    /// If a test ever escapes its fixture and reaches the real client, the
    /// request must fail here -- in the library, before any socket -- rather
    /// than becoming a live request that happens to fail at DNS.
    #[tokio::test]
    async fn scheme_invalid_never_becomes_request() {
        let client = ReqwestClient::new().expect("built");
        let ctx = Ctx::anonymous_for_test();

        let err = client
            .fetch_bounded(&Req::get("h://registry.test/pkg"), ByteLimit::kib(1), &ctx)
            .await
            .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::HostUnreachable);
        assert!(matches!(
            err,
            Error::Transport {
                during: Contact::Connect,
                ..
            }
        ));
    }

    /// The contact a transport failure against `server` reports.
    ///
    /// `server` gets the accepted socket; `None` refuses the connection.
    async fn contact(server: Option<fn(std::net::TcpStream)>) -> Contact {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bound");
        let url = format!("http://{}/pkg", listener.local_addr().expect("addr"));

        match server {
            Some(serve) => {
                std::thread::spawn(move || {
                    let (socket, _) = listener.accept().expect("accepted");
                    serve(socket);
                });
            }

            None => drop(listener),
        }

        let client = ReqwestClient::new().expect("built");
        let err = client
            .fetch_bounded(
                &Req::get(&url),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .unwrap_err();

        let Error::Transport { during, .. } = err else {
            panic!("expected a transport failure, got {err:?}");
        };

        during
    }

    /// Read the request, so closing does not reset it unread.
    fn drain(socket: &mut std::net::TcpStream) {
        use std::io::Read;

        let mut request = [0u8; 1024];
        let _ = socket.read(&mut request);
    }

    #[tokio::test]
    async fn contact_refused_connection_is_connect() {
        assert_eq!(contact(None).await, Contact::Connect);
    }

    #[tokio::test]
    async fn contact_closed_before_response_is_stream() {
        let close = |mut socket: std::net::TcpStream| drain(&mut socket);

        assert_eq!(contact(Some(close)).await, Contact::Stream);
    }

    #[tokio::test]
    async fn contact_short_body_is_stream() {
        let short = |mut socket: std::net::TcpStream| {
            use std::io::Write;

            drain(&mut socket);
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nten bytes!");
        };

        assert_eq!(contact(Some(short)).await, Contact::Stream);
    }
}
