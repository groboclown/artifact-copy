//! Corretto release tags.
//!
//! ```text
//!   25.0.5.0.10          major.minor.patch.build.revision
//!   8.452.09.2           8.update.build.revision
//!   8.242.08.1-1         a respin of 8.242.08.1, ordered after it
//!   preview-11.0.15.2.1  a preview, never carried from or into
//! ```
//!
//! The dotted fields before the last two name the OpenJDK update: `25.0.1`
//! of `25.0.1.9.1`, and `8.402` of `8.402.07.1`. A respin suffix is not a
//! dotted field.

use std::cmp::Ordering;

const PREVIEW_PREFIX: &str = "preview-";

/// Separates a respin from the build it respins: `8.242.08.1-1`.
const RESPIN_SEPARATOR: char = '-';

/// Trailing dotted fields that vary within one OpenJDK update: the build
/// and its revision.
const BUILD_FIELDS: usize = 2;

/// A tag read as numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// The dotted fields, then any respin numbers.
    numbers: Vec<u64>,

    /// How many of `numbers` are dotted fields.
    dotted: usize,

    preview: bool,
}

impl Tag {
    /// `None` for anything but dot- or dash-separated numbers, optionally
    /// after `preview-`.
    pub fn parse(text: &str) -> Option<Self> {
        let (preview, digits) = match text.strip_prefix(PREVIEW_PREFIX) {
            Some(rest) => (true, rest),
            None => (false, text),
        };

        let (dotted, respin) = match digits.split_once(RESPIN_SEPARATOR) {
            Some((dotted, respin)) => (dotted, Some(respin)),
            None => (digits, None),
        };

        let mut numbers = numbers(dotted.split('.'))?;
        let dotted = numbers.len();

        if let Some(respin) = respin {
            numbers.extend(self::numbers(respin.split(RESPIN_SEPARATOR))?);
        }

        Some(Self {
            numbers,
            dotted,
            preview,
        })
    }

    pub fn major(&self) -> u64 {
        self.numbers[0]
    }

    pub fn is_preview(&self) -> bool {
        self.preview
    }

    /// The OpenJDK update this build belongs to: every dotted field but
    /// the last two. `None` when too short to say.
    pub fn update(&self) -> Option<&[u64]> {
        let fields = self.dotted.checked_sub(BUILD_FIELDS).filter(|&n| n > 0)?;

        self.numbers.get(..fields)
    }

    /// Whether `self` and `other` are builds of one OpenJDK update.
    pub fn same_update(&self, other: &Tag) -> bool {
        self.update().is_some() && self.update() == other.update()
    }
}

/// Every part as a number, or `None`.
fn numbers<'a>(parts: impl Iterator<Item = &'a str>) -> Option<Vec<u64>> {
    parts.map(|part| part.parse::<u64>().ok()).collect()
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.numbers.cmp(&other.numbers)
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(text: &str) -> Tag {
        Tag::parse(text).expect("a tag")
    }

    #[test]
    fn shapes() {
        assert_eq!(tag("25.0.5.0.10").major(), 25);
        assert!(tag("preview-11.0.15.2.1").is_preview());
        assert_eq!(Tag::parse("v25"), None);
        assert_eq!(Tag::parse("25..1"), None);
    }

    #[test]
    fn respin_orders_after() {
        assert!(tag("8.242.08.1-1") > tag("8.242.08.1"));
        assert!(tag("25.0.1.9.1") > tag("25.0.1.8.1"));
        assert!(tag("25.0.10.1.1") > tag("25.0.9.1.1"));
    }

    #[test]
    fn update_grouping() {
        assert!(tag("25.0.1.9.1").same_update(&tag("25.0.1.8.1")));
        assert!(!tag("25.0.2.10.1").same_update(&tag("25.0.1.9.1")));
        assert!(tag("8.402.07.1").same_update(&tag("8.402.06.1")));
        assert!(!tag("8.412.08.1").same_update(&tag("8.402.07.1")));
        assert!(tag("22.0.0.37.1").same_update(&tag("22.0.0.36.2")));
    }

    #[test]
    fn respin_same_update() {
        assert!(tag("8.242.08.1-1").same_update(&tag("8.242.08.1")));
        assert!(tag("11.0.6.10.1-1").same_update(&tag("11.0.6.10.1")));
        assert_eq!(Tag::parse("8.242.08.1-x"), None);
        assert_eq!(tag("25.0").update(), None);
    }
}
