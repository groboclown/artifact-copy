//! Read the links out of a directory index page.
//!
//! Not an HTML parser: nodejs.org serves a plain `<pre>` list of
//! `<a href="...">name</a>` lines, and this reads exactly that.
//!
//! ```text
//!   <a href="/dist/v24.1.0/SHASUMS256.txt">SHASUMS256.txt</a>
//!   -> Link { href: "/dist/v24.1.0/SHASUMS256.txt", text: "SHASUMS256.txt" }
//! ```

/// One `<a>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub href: String,
    pub text: String,
}

const OPEN_TAG: &str = "<a";
const CLOSE_TAG: &str = "</a>";

/// Every link with an `href`, in page order.
pub fn parse(page: &str) -> Vec<Link> {
    let page = remove_sections(page, "<![CDATA[", "]]>");
    let page = remove_sections(&page, "<!--", "-->");

    let mut links = Vec::new();
    let mut start = 0;

    while let Some((link, end)) = next_link(&page, start) {
        links.push(link);
        start = end;
    }

    links
}

/// Remove every `start`..`end` section; an unterminated one runs to the end.
fn remove_sections(page: &str, start: &str, end: &str) -> String {
    let mut kept = String::with_capacity(page.len());
    let mut rest = page;

    while let Some(at) = rest.find(start) {
        kept.push_str(&rest[..at]);

        let Some(close) = rest[at..].find(end) else {
            return kept;
        };

        rest = &rest[at + close + end.len()..];
    }

    kept.push_str(rest);
    kept
}

/// The next link at or after `start`, and where it ends.
fn next_link(page: &str, mut start: usize) -> Option<(Link, usize)> {
    loop {
        let open = start + page.get(start..)?.find(OPEN_TAG)?;
        let after_name = open + OPEN_TAG.len();

        // `<abbr>` and friends are not links.
        if !page[after_name..].starts_with(|c: char| c.is_ascii_whitespace()) {
            start = after_name;
            continue;
        }

        let tag_end = after_name + page[after_name..].find('>')?;
        let close = tag_end + 1 + page[tag_end + 1..].find(CLOSE_TAG)?;
        let end = close + CLOSE_TAG.len();

        if let Some(href) = attribute(&page[after_name..tag_end], "href") {
            let text = page[tag_end + 1..close].to_owned();

            return Some((Link { href, text }, end));
        }

        start = end;
    }
}

/// The value of one attribute inside a tag, quoted or bare.
fn attribute(mut tag: &str, wanted: &str) -> Option<String> {
    loop {
        tag = tag.trim_start();

        let name_len = tag
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '-')))
            .unwrap_or(tag.len());

        if name_len == 0 {
            return None;
        }

        let name = &tag[..name_len];
        tag = tag[name_len..].trim_start();

        let Some(after_equals) = tag.strip_prefix('=') else {
            // An attribute with no value, such as `download`.
            continue;
        };

        let (value, rest) = value(after_equals.trim_start())?;

        if name.eq_ignore_ascii_case(wanted) {
            return Some(value.to_owned());
        }

        tag = rest;
    }
}

/// Split one attribute value from what follows it.
fn value(text: &str) -> Option<(&str, &str)> {
    for quote in ['"', '\''] {
        if let Some(inner) = text.strip_prefix(quote) {
            let end = inner.find(quote)?;

            return Some((&inner[..end], &inner[end + 1..]));
        }
    }

    let end = text
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(text.len());

    Some((&text[..end], &text[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(href: &str, text: &str) -> Link {
        Link {
            href: href.into(),
            text: text.into(),
        }
    }

    #[test]
    fn quoted_and_bare_values() {
        let page = r#"<a href="one">1</a> <a href='two'>2</a> <a class=x href=three>3</a>"#;

        assert_eq!(
            parse(page),
            vec![link("one", "1"), link("two", "2"), link("three", "3")]
        );
    }

    #[test]
    fn comments_and_cdata_hide_links() {
        let page = r#"<!-- <a href="hidden">h</a> --><![CDATA[<a href="raw">r</a>]]><a href="shown">s</a>"#;

        assert_eq!(parse(page), vec![link("shown", "s")]);
    }

    #[test]
    fn unterminated_comment_hides_the_rest() {
        assert!(parse(r#"<!-- <a href="x">x</a>"#).is_empty());
    }

    #[test]
    fn non_link_tags_are_skipped() {
        let page = r#"<abbr title="t">a</abbr><a href="real">r</a>"#;

        assert_eq!(parse(page), vec![link("real", "r")]);
    }

    #[test]
    fn valueless_attribute_is_skipped() {
        assert_eq!(parse(r#"<a download href="f">f</a>"#), vec![link("f", "f")]);
    }

    #[test]
    fn anchor_without_href_is_skipped() {
        assert_eq!(
            parse(r#"<a name="top">t</a><a href="x">x</a>"#),
            vec![link("x", "x")]
        );
    }

    #[test]
    fn version_page_fixture() {
        let links = parse(include_str!("../fixtures/node-v24.1.0.html"));

        assert_eq!(links[0], link("../", "../"));
        assert!(links.contains(&link("/dist/v24.1.0/SHASUMS256.txt", "SHASUMS256.txt")));
    }
}
