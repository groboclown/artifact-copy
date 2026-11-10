//! Reading a core-metadata document whole.
//!
//! The same RFC 822 document [`super::metadata`] reads dependencies out
//! of, taken apart completely here because an upload repeats all of it: a
//! PyPI index serves `Requires-Python`, `Summary` and the rest back to pip
//! from what the upload said, not from the distribution.
//!
//! ```text
//!   Metadata-Version: 2.1        -> ("Metadata-Version", "2.1")
//!   Classifier: A                -> ("Classifier", "A")
//!   Classifier: B                -> ("Classifier", "B")      repeats kept, in order
//!   Description: first           -> ("Description", "first\nsecond")
//!           second                  continuation lines join the header above
//!                                -- a blank line ends the headers --
//!   The long description.        -> body
//! ```
//!
//! References: [Core metadata](https://packaging.python.org/en/latest/specifications/core-metadata/), [RFC 822](https://www.rfc-editor.org/rfc/rfc822).

/// One parsed document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Document {
    /// Every header, in document order, repeats included.
    pub headers: Vec<(String, String)>,

    /// Everything after the first blank line, when anything is.
    ///
    /// Metadata 2.1 moved the long description here; older documents put
    /// it in a `Description` header instead.
    pub body: Option<String>,
}

impl Document {
    /// The first value of a header, compared case-insensitively.
    ///
    /// Case-insensitive here, unlike [`super::metadata`]'s strict match:
    /// that one decides what an artifact depends on, and this one only
    /// relays what the origin said.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Parse a core-metadata document.
///
/// Lenient, because an upload relays rather than judges: a line that is
/// neither a header nor a continuation is dropped, and the rest survive.
pub(super) fn parse(text: &str) -> Document {
    let mut document = Document::default();
    let mut lines = text.lines();

    for line in lines.by_ref() {
        if line.trim().is_empty() {
            break;
        }

        // A continuation belongs to the header above it.
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = document.headers.last_mut() {
                value.push('\n');
                value.push_str(line.trim());
            }

            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        document
            .headers
            .push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let body = lines.collect::<Vec<_>>().join("\n");

    if !body.trim().is_empty() {
        document.body = Some(body);
    }

    document
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Metadata-Version: 2.1
Name: am-python-echo
Version: 1.0
Summary: Minimal package
Requires-Python: >=3.9
Classifier: License :: OSI Approved :: MIT License
Classifier: Programming Language :: Python :: 3
Description: first line
        second line

# The long description

More text.
";

    #[test]
    fn parse_keeps_repeats_in_order() {
        let document = parse(SAMPLE);
        let classifiers: Vec<&str> = document
            .headers
            .iter()
            .filter(|(name, _)| name == "Classifier")
            .map(|(_, value)| value.as_str())
            .collect();

        assert_eq!(
            classifiers,
            [
                "License :: OSI Approved :: MIT License",
                "Programming Language :: Python :: 3"
            ]
        );
    }

    #[test]
    fn parse_joins_continuations() {
        assert_eq!(
            parse(SAMPLE).first("description"),
            Some("first line\nsecond line")
        );
    }

    #[test]
    fn parse_reads_the_body() {
        let body = parse(SAMPLE).body.expect("a body");

        assert!(body.starts_with("# The long description"), "{body}");
    }

    #[test]
    fn first_ignores_case() {
        assert_eq!(parse(SAMPLE).first("requires-python"), Some(">=3.9"));
    }

    /// A value may itself hold a colon; only the first one separates.
    #[test]
    fn parse_splits_on_first_colon() {
        let document = parse("Project-URL: Home, https://example.test/\n");

        assert_eq!(
            document.first("Project-URL"),
            Some("Home, https://example.test/")
        );
    }
}
