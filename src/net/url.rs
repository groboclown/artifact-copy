//! Building URLs out of values that were not written for URLs.
//!
//! Repository names, continuation tokens, git tags and account names all
//! reach this tool as text a person or a server chose, and all of them end
//! up inside a URL. These are the two things every adapter was doing by
//! hand.
//!
//! References: [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).

/// Percent-encode everything outside RFC 3986's *unreserved* set.
///
/// Named for the character set rather than for a URL component, because the
/// callers use it for different ones -- a Nexus query value, a GitHub path
/// segment -- and a name like `encode_query` would quietly claim a component
/// rule this does not implement. The unreserved set is safe in both today.
///
/// Should a component ever need its own rule (a query value wanting `+` for
/// space, say), it wants its own function rather than a parameter here.
///
/// Not to be confused with [`crate::model`]'s purl-segment encoder, which
/// escapes a *different* set -- the characters purl reserves -- for a
/// different purpose.
pub(crate) fn encode_unreserved(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }

    out
}

/// Percent-encode each segment of a path, keeping its separators:
/// `my tools/read me.txt` becomes `my%20tools/read%20me.txt`.
pub(crate) fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_unreserved)
        .collect::<Vec<_>>()
        .join("/")
}

/// A base URL stored without its trailing slash.
///
/// The convention every source and enumerator follows, written down once: a
/// base is held bare so that call sites can join with a leading `/` and not
/// have to wonder whether they will produce `//`.
pub(crate) fn normalized_base(url: &str) -> String {
    url.trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_unreserved_pass_through() {
        assert_eq!(encode_unreserved("maven-releases"), "maven-releases");
        assert_eq!(encode_unreserved("a.b_c~d-9"), "a.b_c~d-9");
    }

    #[test]
    fn encode_everything_else_escaped() {
        assert_eq!(encode_unreserved("a/b=c&d"), "a%2Fb%3Dc%26d");
        assert_eq!(encode_unreserved("sp ace"), "sp%20ace");
        assert_eq!(encode_unreserved("@scope"), "%40scope");
    }

    /// A multi-byte character is escaped byte by byte, which is what a URL
    /// wants -- not one escape for the character.
    #[test]
    fn encode_multi_byte_escapes_per_byte() {
        assert_eq!(encode_unreserved("\u{e9}"), "%C3%A9");
    }

    #[test]
    fn encode_empty_value_to_nothing() {
        assert_eq!(encode_unreserved(""), "");
    }

    #[test]
    fn base_loses_trailing_slash() {
        assert_eq!(normalized_base("https://e.test/"), "https://e.test");
        assert_eq!(normalized_base("https://e.test"), "https://e.test");
        assert_eq!(
            normalized_base("https://e.test/api/v3//"),
            "https://e.test/api/v3"
        );
    }
}
