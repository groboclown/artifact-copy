//! PEP 503: the HTML form of a simple index.
//!
//! What an index answers when it ignores the PEP 691 `Accept` header, as
//! Nexus 3 does. Both pages are a list of anchors and nothing else of use:
//!
//! ```text
//!   /simple/        <a href="echo/">echo</a>
//!   /simple/echo/   <a href="../../packages/echo/1.0/echo-1.0.tar.gz#sha256=1f1c"
//!                      data-core-metadata="sha256=bb">echo-1.0.tar.gz</a>
//! ```
//!
//! So this reads anchors, not HTML: every `<a ...>text</a>`, its attributes
//! and its text, with entities decoded. Everything outside an anchor is
//! skipped. That is the whole of what PEP 503 promises, and it keeps an
//! HTML parser out of the dependency tree.
//!
//! References: [PEP 503](https://peps.python.org/pep-0503/), [PEP 691](https://peps.python.org/pep-0691/).

const ANCHOR_OPEN: &str = "<a";
const ANCHOR_CLOSE: &str = "</a>";

/// One `<a>` element.
#[derive(Debug)]
pub(crate) struct Link {
    /// The anchor's text: a project name on the root page, a filename on a
    /// project page.
    pub(crate) text: String,
    pub(crate) href: String,

    /// Names lowercased, values decoded.
    attributes: Vec<(String, String)>,
}

impl Link {
    pub(crate) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Whether a simple-index body is the HTML form rather than PEP 691 JSON.
///
/// Sniffed from the body, because that is what the fetch hands back: JSON
/// opens with `{`, HTML with `<`.
pub(crate) fn is_html(body: &[u8]) -> bool {
    body.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'<')
}

/// Every anchor with an `href`, in page order.
pub(crate) fn links(html: &str) -> Result<Vec<Link>, String> {
    // Tags are case-insensitive. ASCII lowercasing keeps every byte offset,
    // so positions found in `lower` slice `html` directly.
    let lower = html.to_ascii_lowercase();
    let mut links = Vec::new();
    let mut at = 0;

    while let Some(start) = next_anchor(&lower, at) {
        let tag_start = start + ANCHOR_OPEN.len();
        let (attributes, tag_len) = attributes(&html[tag_start..]);
        let text_start = tag_start + tag_len;

        let Some(text_len) = lower[text_start..].find(ANCHOR_CLOSE) else {
            return Err(format!("unterminated anchor at byte {start}"));
        };

        at = text_start + text_len + ANCHOR_CLOSE.len();

        let mut link = Link {
            text: unescape(html[text_start..text_start + text_len].trim()),
            href: String::new(),
            attributes,
        };

        // An anchor without a target names nothing to fetch.
        let Some(href) = link.attribute("href") else {
            continue;
        };

        link.href = href.to_owned();
        links.push(link);
    }

    Ok(links)
}

/// Where the next `<a` tag starts, skipping `<abbr>` and the like.
fn next_anchor(lower: &str, from: usize) -> Option<usize> {
    let mut at = from;

    while let Some(found) = lower[at..].find(ANCHOR_OPEN) {
        let start = at + found;
        let after = lower.as_bytes().get(start + ANCHOR_OPEN.len());

        if after.is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>') {
            return Some(start);
        }

        at = start + ANCHOR_OPEN.len();
    }

    None
}

/// A tag's attributes, and how many bytes up to and including its `>`.
///
/// Walked rather than cut at the first `>`, because a quoted value may hold
/// one. Values may be double-quoted, single-quoted, or bare.
fn attributes(tag: &str) -> (Vec<(String, String)>, usize) {
    let bytes = tag.as_bytes();
    let mut attributes = Vec::new();
    let mut at = 0;

    loop {
        while at < bytes.len() && (bytes[at].is_ascii_whitespace() || bytes[at] == b'/') {
            at += 1;
        }

        if at >= bytes.len() {
            return (attributes, at);
        }

        if bytes[at] == b'>' {
            return (attributes, at + 1);
        }

        let name_start = at;

        while at < bytes.len() && !is_name_end(bytes[at]) {
            at += 1;
        }

        let name = tag[name_start..at].to_ascii_lowercase();

        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }

        // A bare attribute, such as `download`, has no value.
        if bytes.get(at) != Some(&b'=') {
            attributes.push((name, String::new()));
            continue;
        }

        at += 1;

        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }

        let (value, len) = value(&tag[at..]);

        attributes.push((name, unescape(value)));
        at += len;
    }
}

fn is_name_end(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'=' | b'>' | b'/')
}

/// An attribute value, and how many bytes it spans including its quotes.
fn value(text: &str) -> (&str, usize) {
    let quote = text.as_bytes().first().copied();

    if let Some(quote @ (b'"' | b'\'')) = quote {
        let body = &text[1..];

        return match body.find(quote as char) {
            Some(end) => (&body[..end], end + 2),
            None => (body, text.len()),
        };
    }

    let end = text
        .find(|c: char| c.is_ascii_whitespace() || c == '>')
        .unwrap_or(text.len());

    (&text[..end], end)
}

/// Decode character references: `&gt;=3.8` is `>=3.8`.
///
/// Only the named ones an index has reason to use, and numeric ones. An
/// unknown reference is kept as written.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];

        let decoded = rest
            .find(';')
            .and_then(|end| Some((reference(&rest[1..end])?, end)));

        let Some((c, end)) = decoded else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };

        out.push(c);
        rest = &rest[end + 1..];
    }

    out.push_str(rest);
    out
}

fn reference(name: &str) -> Option<char> {
    match name {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        _ => {}
    }

    let number = name.strip_prefix('#')?;

    let code = match number.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => number.parse().ok()?,
    };

    char::from_u32(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from what Nexus 3.41 serves for a project page.
    const NEXUS: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><title>Links for echo</title>
  <meta name="api-version" value="2"/>
</head>
<body><h1>Links for echo</h1>
    <a href="../../packages/echo/1.0/echo-1.0.tar.gz#sha256=aa" rel="internal">echo-1.0.tar.gz</a><br/>
    <a href="../../packages/echo/1.1/echo-1.1-py3-none-any.whl#sha256=bb" rel="internal"       data-requires-python="&gt;=3.13,&lt;3.14" >echo-1.1-py3-none-any.whl</a><br/>
</body>
</html>"#;

    #[test]
    fn nexus_page_yields_each_anchor() {
        let links = links(NEXUS).expect("parsed");

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].text, "echo-1.0.tar.gz");
        assert_eq!(
            links[0].href,
            "../../packages/echo/1.0/echo-1.0.tar.gz#sha256=aa"
        );
        assert_eq!(links[0].attribute("rel"), Some("internal"));
        assert_eq!(
            links[1].attribute("data-requires-python"),
            Some(">=3.13,<3.14")
        );
    }

    /// Tags and attribute names are case-insensitive; values keep their
    /// case. Single quotes and bare values are legal HTML.
    #[test]
    fn html_spelling_variants_read() {
        let html = "<A HREF='Echo/' Data-X=bare>Echo</A><abbr>no</abbr>";
        let links = links(html).expect("parsed");

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href, "Echo/");
        assert_eq!(links[0].text, "Echo");
        assert_eq!(links[0].attribute("data-x"), Some("bare"));
    }

    /// A `>` inside a quoted value does not end the tag.
    #[test]
    fn quoted_angle_bracket_stays_in_value() {
        let links = links(r#"<a href="x" data-requires-python=">=3.8">x</a>"#).expect("parsed");

        assert_eq!(links[0].attribute("data-requires-python"), Some(">=3.8"));
        assert_eq!(links[0].text, "x");
    }

    #[test]
    fn anchor_without_href_skipped() {
        let links = links(r#"<a name="top">top</a><a href="e/">e</a>"#).expect("parsed");

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].text, "e");
    }

    #[test]
    fn anchor_unterminated_is_error() {
        assert!(links(r#"<a href="e/">e"#).is_err());
    }

    #[test]
    fn references_decoded() {
        assert_eq!(unescape("a&amp;b&#62;&#x3c;&bogus;&"), "a&b><&bogus;&");
    }

    #[test]
    fn html_told_from_json() {
        assert!(is_html(b"  \n<!DOCTYPE html>"));
        assert!(!is_html(br#"{"files": []}"#));
        assert!(!is_html(b""));
    }
}
