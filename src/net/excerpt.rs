//! The part of an error response body worth keeping.
//!
//! A server says *why* it refused in the body, so the body travels on
//! [`Error::HttpStatus`](crate::core::error::Error::HttpStatus) as its
//! `detail`.  It is untrusted text headed for a report and a terminal:
//!
//! ```text
//!   JSON        kept as sent                    machine-readable already
//!   HTML  < 2K  cleaned                         a sentence wrapped in tags
//!   HTML >= 2K  "HTML response"                 an error page; misconfiguration
//!   other       cleaned
//!
//!   cleaned = control characters to spaces, whitespace collapsed,
//!             request credential values replaced by "<redacted>"
//! ```

use super::ByteLimit;
use crate::core::log::Secrets;

/// The most of an error body read into memory.
pub(super) const ERROR_BODY_LIMIT: ByteLimit = ByteLimit::kib(4);

/// HTML shorter than this is most likely readable text in simple markup.
const HTML_KEPT_BYTES: usize = 2 * 1024;

/// Stands in for an HTML page too large to be a message.
const HTML_SUBSTITUTE: &str = "HTML response";

const REDACTED: &str = "<redacted>";

/// Appended when the body ran past [`ERROR_BODY_LIMIT`].
const TRUNCATED_MARK: &str = "...";

/// Header values shorter than this are never treated as credentials, so a
/// stray `1` does not blank every digit in the body.
const MIN_SECRET_CHARS: usize = 4;

/// Request headers known to carry no credential.  Every other header value
/// is scrubbed: the credential header's name is configurable, so naming
/// the safe ones is the only list that cannot miss one.
const PUBLIC_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "content-length",
    "content-type",
    "if-modified-since",
    "if-none-match",
    "user-agent",
    "x-checksum-sha256",
];

/// Whether the read stopped at the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Read {
    Whole,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Json,
    Html,
    Text,
}

/// The `detail` for an error body, or `None` when it says nothing.
///
/// `headers` are the *request's*, whose credential values a server may
/// echo back.
pub(super) fn detail(
    body: &[u8],
    read: Read,
    content_type: Option<&str>,
    headers: &[(String, String)],
) -> Option<String> {
    let text = String::from_utf8_lossy(body);

    if text.trim().is_empty() {
        return None;
    }

    let kind = kind(content_type);

    if kind == Kind::Json {
        return Some(marked(text.into_owned(), read));
    }

    if kind == Kind::Html && (read == Read::Truncated || body.len() >= HTML_KEPT_BYTES) {
        return Some(HTML_SUBSTITUTE.to_owned());
    }

    let cleaned = scrub(&clean(&text), headers);

    if cleaned.is_empty() {
        return None;
    }

    Some(marked(cleaned, read))
}

/// The body's kind, from its media type alone; nothing is parsed.
///
/// Example: `application/problem+json; charset=utf-8` is JSON.
fn kind(content_type: Option<&str>) -> Kind {
    let Some(content_type) = content_type else {
        return Kind::Text;
    };

    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    if essence == "application/json" || essence.ends_with("+json") {
        return Kind::Json;
    }

    if essence == "text/html" || essence == "application/xhtml+xml" {
        return Kind::Html;
    }

    Kind::Text
}

/// Control characters to spaces, then runs of whitespace to one space.
fn clean(text: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|ch| match ch.is_control() {
            true => ' ',
            false => ch,
        })
        .collect();

    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Replace every credential the request carried.
///
/// Both the whole header value and its last word, since a server may echo
/// `Bearer abc` or only `abc`.  Longest first, so the whole value is not
/// left half-replaced by its own token.
fn scrub(text: &str, headers: &[(String, String)]) -> String {
    let mut secrets: Vec<&str> = Vec::new();

    for (name, value) in headers {
        if is_public(name) {
            continue;
        }

        let value = value.trim();
        secrets.push(value);

        if let Some(last) = value.split_whitespace().last() {
            secrets.push(last);
        }
    }

    secrets.retain(|secret| secret.chars().count() >= MIN_SECRET_CHARS);
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));

    let mut scrubbed = text.to_owned();

    for secret in secrets {
        scrubbed = scrubbed.replace(secret, REDACTED);
    }

    scrubbed
}

/// Whether a request header is known to carry no credential.
fn is_public(name: &str) -> bool {
    PUBLIC_HEADERS
        .iter()
        .any(|safe| name.eq_ignore_ascii_case(safe))
}

/// A request header's value as a log may show it: `<redacted>` unless the
/// header is known to carry no credential, or `--unsafe-debug` reveals it.
pub(super) fn loggable<'v>(name: &str, value: &'v str, secrets: Secrets) -> &'v str {
    if secrets == Secrets::Revealed || is_public(name) {
        return value;
    }

    REDACTED
}

fn marked(mut text: String, read: Read) -> String {
    if read == Read::Truncated {
        text.push_str(TRUNCATED_MARK);
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: Option<&str> = Some("application/json");
    const HTML: Option<&str> = Some("text/html; charset=utf-8");

    fn plain(body: &str) -> Option<String> {
        detail(body.as_bytes(), Read::Whole, Some("text/plain"), &[])
    }

    fn bearer(token: &str) -> Vec<(String, String)> {
        vec![("authorization".into(), format!("Bearer {token}"))]
    }

    #[test]
    fn empty_body_is_none() {
        assert_eq!(plain(""), None);
        assert_eq!(plain(" \n\t "), None);
    }

    #[test]
    fn control_characters_become_spaces() {
        assert_eq!(
            plain("line one\r\nline\u{1b}[31m two\u{7}\u{0}"),
            Some("line one line [31m two".to_owned())
        );
    }

    #[test]
    fn json_kept_as_sent() {
        let body = "{\n  \"error\": \"owned by another repository\"\n}";

        assert_eq!(
            detail(body.as_bytes(), Read::Whole, JSON, &bearer("abc123")),
            Some(body.to_owned())
        );
    }

    #[test]
    fn json_suffix_media_type_read_as_json() {
        assert_eq!(
            kind(Some("application/problem+json; charset=utf-8")),
            Kind::Json
        );
    }

    #[test]
    fn html_small_cleaned() {
        let body = "<html><body>\n<h1>409 Conflict</h1>\n</body></html>";

        assert_eq!(
            detail(body.as_bytes(), Read::Whole, HTML, &[]),
            Some("<html><body> <h1>409 Conflict</h1> </body></html>".to_owned())
        );
    }

    #[test]
    fn html_large_substituted() {
        let body = "x".repeat(HTML_KEPT_BYTES);

        assert_eq!(
            detail(body.as_bytes(), Read::Whole, HTML, &[]),
            Some(HTML_SUBSTITUTE.to_owned())
        );
    }

    #[test]
    fn html_truncated_substituted() {
        assert_eq!(
            detail(b"<p>cut", Read::Truncated, HTML, &[]),
            Some(HTML_SUBSTITUTE.to_owned())
        );
    }

    #[test]
    fn text_truncated_marked() {
        assert_eq!(
            detail(b"partial", Read::Truncated, None, &[]),
            Some(format!("partial{TRUNCATED_MARK}"))
        );
    }

    #[test]
    fn redact_echoed_credential() {
        let body = "token Bearer s3cr3t-token rejected; s3cr3t-token expired";

        assert_eq!(
            detail(body.as_bytes(), Read::Whole, None, &bearer("s3cr3t-token")),
            Some("token <redacted> rejected; <redacted> expired".to_owned())
        );
    }

    #[test]
    fn redact_custom_credential_header() {
        let headers = vec![("x-api-key".to_owned(), "k-0123456789".to_owned())];

        assert_eq!(
            detail(b"bad key k-0123456789", Read::Whole, None, &headers),
            Some("bad key <redacted>".to_owned())
        );
    }

    #[test]
    fn redact_skips_public_header() {
        let headers = vec![("content-type".to_owned(), "application/xml".to_owned())];

        assert_eq!(
            detail(b"expected application/xml", Read::Whole, None, &headers),
            Some("expected application/xml".to_owned())
        );
    }

    #[test]
    fn redact_skips_short_header_value() {
        let headers = vec![("x-depth".to_owned(), "1".to_owned())];

        assert_eq!(
            detail(b"page 1 of 1", Read::Whole, None, &headers),
            Some("page 1 of 1".to_owned())
        );
    }
}
