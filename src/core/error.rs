//! Error type for every fallible operation in the library.
//!
//! An `Error` is a Rust failure return; a [`super::problem::Problem`] is a
//! graded, recorded event.  They meet at [`Error::code`], which lets a caller
//! turn any failure into a problem without a match arm per variant.

use std::path::PathBuf;

use http::StatusCode;
use thiserror::Error;

use super::problem::{Code, Problem};

pub type Result<T> = std::result::Result<T, Error>;

/// How far a request got before its transport failed.
///
/// Two different problems for whoever runs a migration: a connection never
/// made is configuration or a firewall, and one lost part way is a flaky
/// link that retrying fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contact {
    /// No connection was made.
    Connect,

    /// Connected, then lost, timed out, or cut off while either end was
    /// sending a body.
    Stream,
}

#[derive(Debug, Error)]
pub enum Error {
    /// A sub-command or option that parses but has no implementation yet.
    #[error("{0} is not implemented")]
    Unimplemented(&'static str),

    #[error("cannot read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid configuration: {0}")]
    Config(String),

    /// The report store failed. Not [`Error::Config`]: nothing the user
    /// configured is at fault.
    #[error("report: {0}")]
    Report(String),

    /// Config names a source/target/enumerator/advisor that is not defined.
    #[error("no {collection} named {name:?} is configured")]
    UnknownName {
        collection: &'static str,
        name: String,
    },

    #[error("unsupported {collection} kind {kind:?}")]
    UnknownKind {
        collection: &'static str,
        kind: String,
    },

    #[error("{url} responded {}{}{}", .status.as_u16(), retry_suffix(.retry_at), detail_suffix(.detail))]
    HttpStatus {
        url: String,
        status: StatusCode,

        /// When the server said to try again, from `Retry-After`,
        /// `RateLimit-Reset`, or an exhausted `X-RateLimit-Reset`; see
        /// `net::retry::plan::retry_at`.
        ///
        /// Carried on the error because it belongs to *this* response.
        /// Fetching it separately would cost an extra request against a
        /// server that is already struggling, and could read a different
        /// answer than the one that failed. Shown in the message, so a run
        /// that gave up on a long wait says when the server will answer.
        retry_at: Option<chrono::DateTime<chrono::Utc>>,

        /// What the response body said, where the server explains *why*.
        ///
        /// Not the body itself: capped, cleaned of control characters and
        /// echoed credentials, and replaced outright for a large HTML page.
        /// A JSON body is kept as sent.
        detail: Option<String>,
    },

    /// A redirect that was not followed: the next hop is somewhere the
    /// capability may not reach, or the chain ran too long. Raised by a
    /// client for every redirect, and followed by the capability when it
    /// may be.
    #[error("{url} redirected ({}) to {location}, which was not followed", .status.as_u16())]
    Redirected {
        url: String,
        status: StatusCode,
        location: String,
    },

    #[error("{url}: {source}")]
    Transport {
        url: String,

        /// Whether a connection was ever made.
        during: Contact,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A body exceeded the cap its call site declared.  Enforced while
    /// streaming, so `actual` is "at least this much", never a header value.
    #[error("{url} exceeded the {limit} byte limit")]
    TooLarge { url: String, limit: u64 },

    #[error("cannot parse {what} from {url}: {detail}")]
    Malformed {
        what: &'static str,
        url: String,
        detail: String,
    },

    /// Nothing the repository holds satisfies the request.
    ///
    /// **Distinct from [`Error::Malformed`]**, which was doing this job
    /// and should not have been. The two channels disagreed: resolution
    /// reported `version-unresolvable` or `publish-too-recent` to the
    /// problem sink and then returned a `Malformed`, whose code is
    /// `metadata-malformed`. A caller reading the returned error therefore
    /// classified the same event differently from one reading the sink,
    /// and the action table could have sent them in different directions.
    ///
    /// Nothing is wrong with the metadata here. The repository answered
    /// clearly, and the answer was "no version of this fits what you
    /// asked for".
    ///
    /// `problem` is the diagnosis, **already recorded** by whoever raised
    /// this. A caller acts on it and must not record the error again.
    #[error("no version of {artifact} can be resolved: {detail}")]
    Unresolvable {
        artifact: String,
        detail: String,
        problem: Box<Problem>,
    },

    /// The repository answered, and does not hold what was asked for.
    ///
    /// **Distinct from [`Error::Malformed`]**, which was doing this job and
    /// should not have been: a packument that parses cleanly and simply
    /// lists no version `2.0` is not a corrupt document. The two mean
    /// opposite things to anything composing repositories -- a proxy asking
    /// several upstreams treats *absent* as "ask the next one" and
    /// *malformed* as "stop, this one is broken" -- so collapsing them made
    /// a proxy either route around corruption or refuse to look past a
    /// version one upstream happens to lack.
    ///
    /// Reports as [`Code::ArtifactNotFound`], which is what it has always
    /// meant.
    #[error("{url} holds no {what} {name:?}")]
    Absent {
        what: &'static str,
        url: String,
        name: String,
    },

    /// Coordinate text that does not match the ecosystem's syntax.
    #[error("{text:?} is not a valid {ecosystem} artifact request: {detail}")]
    BadRequest {
        ecosystem: &'static str,
        text: String,
        detail: String,
    },

    /// `--lock=FORMAT,FILE` named a format no reader provides.
    #[error("no lock format named {format:?}; registered formats are {known}")]
    LockFormatUnknown { format: String, known: String },

    /// No reader claimed a lock file whose format was not stated.
    #[error(
        "no reader recognized {name:?}; tried {tried}.  \
         State the format with --lock=FORMAT,FILE if it is one of these."
    )]
    LockUnrecognized { name: String, tried: String },

    /// A reader claimed a lock file and could not parse it.
    ///
    /// **Distinct from [`Error::Malformed`]**, whose code a quarantine rule
    /// may excuse per artifact. A lock file names the artifacts, so one that
    /// will not parse is a fault in the run's input, and fail-fast.
    #[error("cannot parse lock file {}: {detail}", .path.display())]
    LockMalformed { path: PathBuf, detail: String },

    /// A VEX document that will not parse, or states what its format
    /// forbids. Apart from [`Error::LockMalformed`] because a quarantine
    /// rule may excuse it; see `Code::VexUnparsable`.
    #[error("cannot use VEX document {source_name}: {detail}")]
    VexUnparsable { source_name: String, detail: String },

    #[error("integrity check failed: {0}")]
    Integrity(String),

    /// An extension failed, or answered outside the protocol.
    ///
    /// `code` is the extension's own classification where it gave a known
    /// one, so a proxy still falls through on its `artifact-not-found`;
    /// otherwise `metadata-malformed`.
    #[error("extension {extension:?}: {detail}")]
    Extension {
        extension: String,
        code: Code,
        detail: String,
    },

    /// Raised by an `Action::Abort` problem, unwinding the whole run.
    #[error("aborted: {0}")]
    Aborted(String),
}

impl Error {
    /// The URL this error happened at, where it names one.
    pub fn url(&self) -> Option<&str> {
        match self {
            Error::HttpStatus { url, .. }
            | Error::Redirected { url, .. }
            | Error::Transport { url, .. }
            | Error::TooLarge { url, .. }
            | Error::Malformed { url, .. }
            | Error::Absent { url, .. } => Some(url),

            _ => None,
        }
    }

    /// What went wrong, without the URL it went wrong at, for a message
    /// that names the file instead.
    ///
    /// ```text
    ///   h://host/repo/lib-1.0.jar responded 404    ->   responded 404
    /// ```
    pub fn reason(&self) -> String {
        match self {
            Error::HttpStatus {
                status,
                retry_at,
                detail,
                ..
            } => format!(
                "responded {}{}{}",
                status.as_u16(),
                retry_suffix(retry_at),
                detail_suffix(detail)
            ),

            Error::Redirected { status, .. } => {
                format!("redirected ({}), which was not followed", status.as_u16())
            }

            Error::Transport { source, .. } => source.to_string(),
            Error::TooLarge { limit, .. } => format!("exceeded the {limit} byte limit"),
            Error::Malformed { what, detail, .. } => format!("cannot parse {what}: {detail}"),
            Error::Absent { what, name, .. } => format!("holds no {what} {name:?}"),

            other => other.to_string(),
        }
    }

    /// The problem code this failure reports as.  Callers use it to consult
    /// the action table rather than re-deciding severity at each call site.
    pub fn code(&self) -> Code {
        match self {
            Error::Unimplemented(_) => Code::Unimplemented,

            Error::ReadFile { .. } => Code::FileUnreadable,

            // Apart, because they are different tiers: a file the user
            // named and the tool cannot open is a fault in the input, and a
            // file the tool cannot write is the environment failing while
            // the run works.
            Error::WriteFile { .. } => Code::FileUnwritable,

            Error::Config(_) | Error::UnknownName { .. } | Error::UnknownKind { .. } => {
                Code::ConfigInvalid
            }

            Error::Report(_) => Code::ReportUnusable,

            Error::LockFormatUnknown { .. } => Code::LockFormatUnknown,

            Error::LockUnrecognized { .. } => Code::LockUnrecognized,

            Error::LockMalformed { .. } => Code::LockMalformed,

            Error::VexUnparsable { .. } => Code::VexUnparsable,

            Error::Absent { .. } => Code::ArtifactNotFound,

            Error::Unresolvable { .. } => Code::VersionUnresolvable,

            // HTTP 404; the one status that means "no such artifact" rather than
            // "this host is having trouble".  A 404 carrying a retry time is a
            // throttle in disguise (Maven Central's CDN does this), so it falls
            // through to unreachable.
            Error::HttpStatus {
                status,
                retry_at: None,
                ..
            } if *status == StatusCode::NOT_FOUND => Code::ArtifactNotFound,

            // The host answered and said no. 408 and 429 are the host
            // struggling rather than refusing, so they stay unreachable.
            Error::HttpStatus { status, .. } if rejected(*status) => Code::RequestRejected,

            Error::HttpStatus { .. } | Error::Transport { .. } => Code::HostUnreachable,

            // The host answered with somewhere else to go, and going there
            // was refused.
            Error::Redirected { .. } => Code::RequestRejected,

            Error::TooLarge { .. } => Code::DownloadTooLarge,

            Error::Malformed { .. } | Error::BadRequest { .. } => Code::MetadataMalformed,

            Error::Integrity(_) => Code::ChecksumMismatch,

            Error::Extension { code, .. } => *code,

            Error::Aborted(_) => Code::Aborted,
        }
    }
}

/// `": {detail}"`, or nothing when the response said nothing.
fn retry_suffix(retry_at: &Option<chrono::DateTime<chrono::Utc>>) -> String {
    match retry_at {
        Some(at) => format!(
            " (retry after {})",
            at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
        None => String::new(),
    }
}

fn detail_suffix(detail: &Option<String>) -> String {
    match detail {
        Some(detail) => format!(": {detail}"),
        None => String::new(),
    }
}

/// Whether a status is the host refusing the request, as opposed to the
/// artifact being absent or the host being unable to answer.
///
/// Examples: 401, 403, and 409 are rejections; 404, 408, 429, and 503 are not.
fn rejected(status: StatusCode) -> bool {
    status.is_client_error()
        && status != StatusCode::NOT_FOUND
        && status != StatusCode::REQUEST_TIMEOUT
        && status != StatusCode::TOO_MANY_REQUESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(status: StatusCode) -> Error {
        Error::HttpStatus {
            url: "h://host.test/x".to_owned(),
            status,
            retry_at: None,
            detail: None,
        }
    }

    /// A refusal is the host answering, not the host being unreachable.
    #[test]
    fn status_client_error_rejected() {
        for code in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::CONFLICT,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert_eq!(status(code).code(), Code::RequestRejected, "{code}");
        }
    }

    #[test]
    fn display_detail_follows_status() {
        let err = Error::HttpStatus {
            url: "h://host.test/x".to_owned(),
            status: StatusCode::CONFLICT,
            retry_at: None,
            detail: Some("already owned".to_owned()),
        };

        assert_eq!(
            err.to_string(),
            "h://host.test/x responded 409: already owned"
        );
        assert_eq!(
            status(StatusCode::CONFLICT).to_string(),
            "h://host.test/x responded 409"
        );
    }

    /// The reason leaves out the URL, which a file name replaces.
    #[test]
    fn reason_omits_url() {
        let absent = Error::Absent {
            what: "artifact",
            url: "h://host.test/x".to_owned(),
            name: "lib".to_owned(),
        };

        assert_eq!(status(StatusCode::NOT_FOUND).reason(), "responded 404");
        assert_eq!(absent.reason(), "holds no artifact \"lib\"");
        assert_eq!(absent.url(), Some("h://host.test/x"));
    }

    /// A run that gave up on a long wait says when the server will answer.
    #[test]
    fn display_retry_time_follows_status() {
        let err = Error::HttpStatus {
            url: "h://host.test/x".to_owned(),
            status: StatusCode::FORBIDDEN,
            retry_at: chrono::DateTime::from_timestamp(1_791_936_000, 0),
            detail: Some("API rate limit exceeded".to_owned()),
        };

        assert_eq!(
            err.to_string(),
            "h://host.test/x responded 403 (retry after 2026-10-14T00:00:00Z): \
             API rate limit exceeded"
        );
    }

    /// Absence and transient trouble keep their own codes.
    #[test]
    fn status_other_keeps_code() {
        assert_eq!(status(StatusCode::NOT_FOUND).code(), Code::ArtifactNotFound);

        for code in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(status(code).code(), Code::HostUnreachable, "{code}");
        }
    }

    /// A 404 that says when to come back is a throttle, not an absence.
    #[test]
    fn status_404_throttled_unreachable() {
        let err = Error::HttpStatus {
            url: "h://host.test/x".to_owned(),
            status: StatusCode::NOT_FOUND,
            retry_at: chrono::DateTime::from_timestamp(1_791_936_000, 0),
            detail: None,
        };

        assert_eq!(err.code(), Code::HostUnreachable);
    }
}
