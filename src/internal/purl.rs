//! Rendering and reading a package URL.
//!
//! String mechanics only: nothing here knows what an artifact is. The
//! pieces go in and a purl comes out, or a purl goes in and the pieces come
//! out. [`crate::model::ArtifactId`] owns what those pieces *mean* and
//! delegates the spelling to this module, so the encoding rules sit in one
//! place rather than beside the type that happens to need them first.
//!
//! # The shape
//!
//! ```text
//!   scheme:type/namespace/name@version?qualifiers#subpath
//! ```
//!
//! Seven components, of which this handles six. A **subpath is refused**
//! rather than dropped: it names a location inside a package, so two purls
//! differing only by subpath are two different things, and a caller with
//! nowhere to keep it would silently conflate them.
//!
//! # Three encodings, not one
//!
//! Which characters are escaped depends on where a string sits, and the
//! differences are load-bearing rather than pedantic:
//!
//! | Position | `/` | `&` and `=` |
//! | --- | --- | --- |
//! | namespace | kept -- it separates the segments | ordinary |
//! | name | escaped -- one segment, and parsing needs the boundary | ordinary |
//! | qualifier value | escaped -- it is a character in somebody's URL | escaped |
//!
//! The specification's own examples are the authority for the first and the
//! third: `pkg:golang/google.golang.org/genproto` keeps its namespace
//! separator, and `?repository_url=repo.spring.io%2Frelease` escapes a
//! slash in a value.
//!
//! References: [Package URL](https://github.com/package-url/purl-spec).

use crate::core::error::{Error, Result};

pub(crate) mod pattern;

/// A purl read back into its pieces.
///
/// The version comes back beside the rest rather than inside it, because a
/// purl spells the version in the *middle* -- after the name and before the
/// qualifiers -- so a caller cannot take it off either end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parts {
    pub(crate) ecosystem: String,
    pub(crate) namespace: Option<String>,
    pub(crate) name: String,

    /// In the order the purl carried them, which a caller is free to sort.
    pub(crate) qualifiers: Vec<(String, String)>,

    pub(crate) version: Option<String>,
}

/// Render a purl.
///
/// `version` is `None` for the name-level form, which is what a catalog
/// listing names only honestly produces.
pub(crate) fn render(
    ecosystem: &str,
    namespace: Option<&str>,
    name: &str,
    qualifiers: &[(String, String)],
    version: Option<&str>,
) -> String {
    let mut out = format!("pkg:{ecosystem}/");

    if let Some(namespace) = namespace {
        out.push_str(&encode_namespace(namespace));
        out.push('/');
    }

    out.push_str(&encode_segment(name));

    if let Some(version) = version {
        out.push('@');
        out.push_str(&encode_segment(version));
    }

    for (index, (key, value)) in qualifiers.iter().enumerate() {
        out.push(if index == 0 { '?' } else { '&' });
        out.push_str(key);
        out.push('=');
        out.push_str(&encode_value(value));
    }

    out
}

/// Read a purl back into its pieces.
pub(crate) fn parse(purl: &str) -> Result<Parts> {
    let malformed = |detail: &str| Error::Malformed {
        what: "purl",
        url: purl.to_owned(),
        detail: detail.to_owned(),
    };

    let body = purl
        .strip_prefix("pkg:")
        .ok_or_else(|| malformed("it does not start with \"pkg:\""))?;

    // Split in the order the specification composes them. A reserved
    // character inside a segment is escaped, so the first literal `#` can
    // only begin the subpath and the first literal `?` can only begin the
    // qualifiers.
    if let Some((_, subpath)) = body.split_once('#') {
        return Err(malformed(&format!(
            "it carries the subpath {subpath:?}, which this tool cannot represent"
        )));
    }

    let (path, qualifiers) = match body.split_once('?') {
        Some((path, qualifiers)) => (path, Some(qualifiers)),
        None => (body, None),
    };

    let (ecosystem, rest) = path
        .split_once('/')
        .ok_or_else(|| malformed("it names no artifact after the type"))?;

    if ecosystem.is_empty() {
        return Err(malformed("it names no ecosystem"));
    }

    // Splitting on the last separator is what makes a namespace of several
    // segments read as one namespace: everything before the final `/`.
    let (namespace, last) = match rest.rsplit_once('/') {
        Some((namespace, last)) => (Some(namespace), last),
        None => (None, rest),
    };

    // `@` is escaped within a segment, so the one here separates the
    // version. Split from the right, so a name that somehow carries an
    // unescaped `@` keeps it.
    let (name, version) = match last.rsplit_once('@') {
        Some((name, version)) => (name, Some(version)),
        None => (last, None),
    };

    if name.is_empty() {
        return Err(malformed("it names no artifact"));
    }

    let mut pairs = Vec::new();

    for pair in qualifiers.unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }

        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| malformed("a qualifier has no value"))?;

        pairs.push((key.to_owned(), decode_segment(value)));
    }

    Ok(Parts {
        ecosystem: decode_segment(ecosystem),
        namespace: namespace.map(decode_namespace),
        name: decode_segment(name),
        qualifiers: pairs,
        version: version.map(decode_segment).filter(|text| !text.is_empty()),
    })
}

/// Percent-encode a namespace, whose `/` separate its segments.
///
/// A purl namespace is a **path**, not one word: the specification joins
/// its segments with `/` and encodes each one, so those separators are
/// structure and must stay literal. Maven and npm never exercise it -- a
/// groupId uses dots and an npm scope is a single segment -- but a raw
/// repository's namespace comes from a directory path, and
/// `pkg:raw/a%2Fb/c` would claim one segment where the source has two.
fn encode_namespace(text: &str) -> String {
    let segments: Vec<String> = text.split('/').map(encode_segment).collect();

    segments.join("/")
}

/// Read a namespace back, one segment at a time.
///
/// Decoding the whole string at once would turn an escaped `/` inside a
/// segment into a separator, silently adding a segment.
///
/// A namespace segment that genuinely contains a `/` is not representable,
/// because the namespace is held as one string: it comes back as two
/// segments. No ecosystem produces one.
fn decode_namespace(text: &str) -> String {
    let segments: Vec<String> = text.split('/').map(decode_segment).collect();

    segments.join("/")
}

/// Percent-encode one purl segment: a name, a version, or one segment of a
/// namespace.
///
/// `@`, `#`, `?`, and `/` are the reserved ones. Escaping `@` is what
/// leaves it free to mean "the version starts here" -- an npm scope reaches
/// us with its `@` intact, so `pkg:npm/%40angular/core@17.0.0` has exactly
/// one literal `@` and it is the separator.
///
/// `%` is escaped for a harder reason: **without it this is not
/// reversible.** A name holding the text `%40` would render unchanged and
/// read back as `@`, so two different artifacts would render to one purl --
/// and a rendered purl is a unique key in the report database. No registry
/// adapter can produce such a name today; a raw repository, whose artifact
/// names come from arbitrary file paths, could.
fn encode_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for ch in text.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '@' => out.push_str("%40"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            '/' => out.push_str("%2F"),
            _ => out.push(ch),
        }
    }

    out
}

/// Percent-encode a qualifier value.
///
/// A segment's escapes plus `&` and `=`, which separate one qualifier from
/// the next and a value from its key: a value carrying either would render
/// a purl that cannot be read back at all.
///
/// **A `/` is escaped here, unlike in a namespace**, and the specification's
/// canonical example is the reason --
/// `?repository_url=repo.spring.io%2Frelease`. The difference is not
/// arbitrary: a `/` in a namespace *is* the separator between its segments,
/// and a `/` in a value is a character in somebody's URL.
fn encode_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for ch in text.chars() {
        match ch {
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            other => out.push_str(&encode_segment(&other.to_string())),
        }
    }

    out
}

/// Percent-decode the characters [`encode_segment`] escapes.
///
/// Byte oriented, so a multi-byte character written as several escapes --
/// `%C3%A9` for an accented e -- is reassembled rather than turned into two
/// broken ones.
///
/// Tolerant of a stray `%`, which is left as written. This reads back what
/// this crate rendered, and failing a whole report over one odd percent
/// sign would punish the reader for the writer's mistake.
fn decode_segment(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        let escape = (bytes[index] == b'%' && index + 3 <= bytes.len())
            .then(|| &bytes[index + 1..index + 3])
            .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());

        match escape {
            Some(byte) => {
                out.push(byte);
                index += 3;
            }

            None => {
                out.push(bytes[index]);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render what a parse produced, which is the round trip every other
    /// test here rests on.
    fn rerender(parts: &Parts) -> String {
        render(
            &parts.ecosystem,
            parts.namespace.as_deref(),
            &parts.name,
            &parts.qualifiers,
            parts.version.as_deref(),
        )
    }

    /// Every example the specification publishes, re-rendered to the byte.
    /// A parser that handles this crate's own output and nothing else is
    /// one that will surprise somebody, and each of these carries a case: a
    /// version holding a colon, a namespace holding dots, a scope holding
    /// an escaped `@`, and a version ending in a period.
    #[test]
    fn spec_examples_round_trip() {
        let examples = [
            "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
            "pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c",
            "pkg:gem/jruby-launcher@1.1.2?platform=java",
            "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io%2Frelease&packaging=sources",
            "pkg:npm/%40angular/animation@12.3.1",
            "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
            "pkg:pypi/django@1.11.1",
            "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
            "pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed",
        ];

        for text in examples {
            let parts = parse(text).unwrap_or_else(|err| panic!("{text}: {err}"));

            assert_eq!(rerender(&parts), text);
        }
    }

    /// The `@` that starts an npm scope and the `@` that starts a version
    /// are the same character, which is why the scope's is escaped. This is
    /// the case a naive split gets wrong.
    #[test]
    fn scope_not_mistaken_for_version() {
        let parts = parse("pkg:npm/%40angular/animation@12.3.1").expect("parsed");

        assert_eq!(parts.ecosystem, "npm");
        assert_eq!(parts.namespace.as_deref(), Some("@angular"));
        assert_eq!(parts.name, "animation");
        assert_eq!(parts.version.as_deref(), Some("12.3.1"));
        assert!(parts.qualifiers.is_empty());
    }

    /// A `/` inside a namespace is structure, not a character to escape.
    #[test]
    fn namespace_keeps_separators() {
        let text = "pkg:golang/google.golang.org/genproto";
        let parts = parse(text).expect("parsed");

        assert_eq!(parts.namespace.as_deref(), Some("google.golang.org"));
        assert_eq!(parts.name, "genproto");
        assert_eq!(rerender(&parts), text);
    }

    /// The seventh component, which this tool has nowhere to keep. Two
    /// purls differing only by subpath are two different things, so
    /// dropping it would merge them under one key.
    #[test]
    fn subpath_refused_not_dropped() {
        let err = parse("pkg:golang/google.golang.org/genproto#googleapis/api/annotations")
            .expect_err("refused");

        assert!(err.to_string().contains("subpath"), "{err}");
    }

    /// A qualifier value escapes its `/`, which a namespace does not, and
    /// escapes `&` and `=` for a harder reason: a value carrying either
    /// would render a purl nothing could read back.
    #[test]
    fn qualifier_value_escapes_separators() {
        let qualifiers = vec![
            ("note".to_owned(), "a=b&c".to_owned()),
            ("repository_url".to_owned(), "repo.test/release".to_owned()),
        ];

        let rendered = render(
            "maven",
            Some("org.example"),
            "lib",
            &qualifiers,
            Some("1.0"),
        );

        assert_eq!(
            rendered,
            "pkg:maven/org.example/lib@1.0?note=a%3Db%26c&repository_url=repo.test%2Frelease"
        );

        assert_eq!(parse(&rendered).expect("parsed").qualifiers, qualifiers);
    }

    /// Two artifacts must never render to one purl, because the rendering
    /// is a unique key in the report database. A name holding the text
    /// `%40` is the case that breaks if `%` is not escaped.
    #[test]
    fn percent_literal_escape_not_scope() {
        let escaped = render("raw", None, "%40angular", &[], None);

        assert_eq!(escaped, "pkg:raw/%2540angular");
        assert_eq!(parse(&escaped).expect("parsed").name, "%40angular");
        assert_eq!(
            parse("pkg:raw/%40angular").expect("parsed").name,
            "@angular"
        );
    }

    /// A stray percent sign is the writer's problem, not the reader's:
    /// failing a whole report over one would lose every good record with it.
    #[test]
    fn percent_stray_survives() {
        assert_eq!(decode_segment("100%"), "100%");
        assert_eq!(decode_segment("%zz"), "%zz");
        assert_eq!(decode_segment("%4"), "%4");

        // A multi-byte character arrives as several escapes and has to be
        // reassembled rather than broken into replacement characters.
        assert_eq!(decode_segment("caf%C3%A9"), "caf\u{e9}");
    }

    /// A catalog that lists names only has no version, and inventing one
    /// would be worse than saying so.
    #[test]
    fn name_only_has_no_version() {
        assert!(parse("pkg:npm/lodash").expect("parsed").version.is_none());
    }

    #[test]
    fn nonsense_refused() {
        for text in [
            "",
            "npm/lodash",
            "pkg:",
            "pkg:npm",
            "pkg:npm/",
            "pkg:/lodash",
        ] {
            assert!(parse(text).is_err(), "{text:?} was accepted");
        }
    }
}
