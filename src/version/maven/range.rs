//! Maven version ranges.
//!
//! The bracket syntax, ported from `VersionRange.createFromVersionSpec`:
//!
//! | Spec | Meaning |
//! | --- | --- |
//! | `1.0` | a **soft** requirement -- see below |
//! | `[1.0]` | exactly `1.0` |
//! | `(,1.0]` | at most `1.0` |
//! | `[1.2,1.3]` | between, inclusive |
//! | `[1.0,2.0)` | at least `1.0`, below `2.0` |
//! | `[1.5,)` | at least `1.5` |
//! | `(,1.0],[1.2,)` | either -- a union, here excluding `1.1` |
//!
//! # Soft requirements
//!
//! A bare `1.0` means something weaker in Maven than `[1.0]`: it is the
//! *recommended* version, and the resolver may return a different one when
//! another part of the graph asks for something else. This tool honors it
//! as the version it names.
//!
//! That is a deliberate narrowing. A migrator is asked to copy what a
//! project declared, and silently substituting a neighbouring version would
//! produce a repository that does not match the build it was taken from --
//! a failure that shows up much later, in someone else's build. Resolving
//! the whole graph the way Maven's resolver does is a different and much
//! larger job; until it exists, taking the declared version literally is
//! the honest reading, and an absent version is reported rather than
//! quietly replaced.

use std::cmp::Ordering;

use super::parsed::compare;
use crate::core::error::{Error, Result};

/// One interval.
///
/// Both bounds optional: `(,1.0]` has no lower bound and `[1.5,)` no upper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Restriction {
    lower: Option<String>,
    lower_inclusive: bool,
    upper: Option<String>,
    upper_inclusive: bool,
}

impl Restriction {
    fn exactly(version: &str) -> Self {
        Self {
            lower: Some(version.to_owned()),
            lower_inclusive: true,
            upper: Some(version.to_owned()),
            upper_inclusive: true,
        }
    }

    pub fn contains(&self, version: &str) -> bool {
        if let Some(lower) = &self.lower {
            match compare(version, lower) {
                Ordering::Less => return false,
                Ordering::Equal if !self.lower_inclusive => return false,
                _ => {}
            }
        }

        if let Some(upper) = &self.upper {
            match compare(version, upper) {
                Ordering::Greater => return false,
                Ordering::Equal if !self.upper_inclusive => return false,
                _ => {}
            }
        }

        true
    }
}

/// A parsed range: a union of intervals.
///
/// A soft requirement and its bracketed equivalent produce the same range,
/// because they resolve the same way here. Which of the two was *written*
/// is carried by [`crate::model::VersionSpec`] -- `Exact` against `Range` --
/// so this type has no need to remember it too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    restrictions: Vec<Restriction>,
}

impl Range {
    /// Parse a Maven version specification.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut restrictions = Vec::new();
        let mut rest = spec.trim();

        while rest.starts_with('[') || rest.starts_with('(') {
            let end = closing_bracket(rest)
                .ok_or_else(|| bad(spec, "the range is missing its closing bracket"))?;

            restrictions.push(parse_restriction(&rest[..=end], spec)?);

            rest = rest[end + 1..].trim_start();

            if let Some(after_comma) = rest.strip_prefix(',') {
                rest = after_comma.trim_start();
            }
        }

        let rest = rest.trim();

        if rest.is_empty() {
            if restrictions.is_empty() {
                return Err(bad(spec, "the version specification is empty"));
            }

            return Ok(Self { restrictions });
        }

        // Text after a bracketed set is a malformed union, not a second
        // kind of requirement: `[1.0],2.0` cannot be honored either way
        // round, so it is refused rather than half-read.
        if !restrictions.is_empty() {
            return Err(bad(
                spec,
                "a union must be made of bracketed ranges only, with nothing loose between them",
            ));
        }

        Ok(Self {
            restrictions: vec![Restriction::exactly(rest)],
        })
    }

    /// Whether a version satisfies any interval.
    pub fn contains(&self, version: &str) -> bool {
        self.restrictions
            .iter()
            .any(|restriction| restriction.contains(version))
    }
}

/// The index of the bracket that closes the set starting at 0.
///
/// Whichever of `)` and `]` comes first, matching upstream: brackets do not
/// nest in this grammar, so the first closer is the right one.
fn closing_bracket(text: &str) -> Option<usize> {
    text.char_indices()
        .find(|(_, ch)| *ch == ')' || *ch == ']')
        .map(|(index, _)| index)
}

fn parse_restriction(text: &str, spec: &str) -> Result<Restriction> {
    let lower_inclusive = text.starts_with('[');
    let upper_inclusive = text.ends_with(']');

    let inner = text[1..text.len() - 1].trim();

    let Some(comma) = inner.find(',') else {
        // `(1.0)` is not "a version, exclusively" -- it is meaningless, and
        // reading it as `[1.0]` would silently widen what was asked for.
        if !lower_inclusive || !upper_inclusive {
            return Err(bad(
                spec,
                "a single version must be written [1.0], with square brackets",
            ));
        }

        if inner.is_empty() {
            return Err(bad(spec, "[] names no version"));
        }

        return Ok(Restriction::exactly(inner));
    };

    let lower = non_empty(inner[..comma].trim());
    let upper = non_empty(inner[comma + 1..].trim());

    if let (Some(low), Some(high)) = (&lower, &upper) {
        match compare(high, low) {
            Ordering::Less => {
                return Err(bad(spec, "the upper bound is below the lower bound"));
            }

            // `[1.0,1.0]` is a legitimate way to write one version;
            // `(1.0,1.0]` and friends can contain nothing at all, so they
            // are a mistake worth naming rather than an empty result.
            Ordering::Equal if !lower_inclusive || !upper_inclusive => {
                return Err(bad(
                    spec,
                    "the bounds are the same version but exclude it, so nothing can match",
                ));
            }

            _ => {}
        }
    }

    Ok(Restriction {
        lower,
        lower_inclusive,
        upper,
        upper_inclusive,
    })
}

fn non_empty(text: &str) -> Option<String> {
    match text.is_empty() {
        true => None,
        false => Some(text.to_owned()),
    }
}

fn bad(spec: &str, detail: &str) -> Error {
    Error::BadRequest {
        ecosystem: "maven",
        text: spec.to_owned(),
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(spec: &str) -> Range {
        Range::parse(spec).unwrap_or_else(|err| panic!("{spec:?} should parse: {err}"))
    }

    fn refused(spec: &str) -> String {
        Range::parse(spec)
            .err()
            .unwrap_or_else(|| panic!("{spec:?} should have been refused"))
            .to_string()
    }

    #[test]
    fn range_exact_admits_only_that_version() {
        let exact = range("[1.0]");

        assert!(exact.contains("1.0"));
        assert!(!exact.contains("1.1"));
        assert!(!exact.contains("0.9"));

        // Maven's own equality: `1.0`, `1` and `1.0.0` are one version, so
        // a registry listing any spelling satisfies the range.
        assert!(exact.contains("1"));
        assert!(exact.contains("1.0.0"));
    }

    #[test]
    fn range_half_open_excludes_upper_bound() {
        let spec = range("[1.0,2.0)");

        assert!(spec.contains("1.0"));
        assert!(spec.contains("1.9.9"));
        assert!(!spec.contains("2.0"));
        assert!(!spec.contains("0.9"));
    }

    #[test]
    fn range_unbounded_upper_accepts_all_above() {
        let spec = range("[1.5,)");

        assert!(spec.contains("1.5"));
        assert!(spec.contains("99.0"));
        assert!(!spec.contains("1.4"));
    }

    #[test]
    fn range_unbounded_lower_accepts_all_below() {
        let spec = range("(,1.0]");

        assert!(spec.contains("1.0"));
        assert!(spec.contains("0.1"));
        assert!(!spec.contains("1.0.1"));
    }

    /// The documented way to say "anything but 1.1".
    #[test]
    fn range_union_excludes_gap() {
        let spec = range("(,1.0],[1.2,)");

        assert!(spec.contains("1.0"));
        assert!(spec.contains("1.2"));
        assert!(spec.contains("5.0"));
        assert!(!spec.contains("1.1"));
    }

    #[test]
    fn range_whitespace_around_parts_ignored() {
        let spec = range(" [ 1.0 , 2.0 ) , [ 3.0 ] ");

        assert!(spec.contains("1.5"));
        assert!(spec.contains("3.0"));
        assert!(!spec.contains("2.5"));
    }

    /// A bare version is a soft requirement, and this tool honors it as
    /// the version it names rather than as "anything".
    #[test]
    fn range_bare_version_honored_as_written() {
        let spec = range("1.0");

        assert!(spec.contains("1.0"));
        assert!(!spec.contains("1.1"));

        // Identical to the bracketed spelling, which is the point: the two
        // resolve the same way, and which was written is recorded by the
        // `VersionSpec` rather than duplicated here.
        assert_eq!(spec, range("[1.0]"));
    }

    /// Ordering inside a range is Maven's, not a lexical or semver one.
    /// `1.10` above `1.9` is the vector that catches a string comparison.
    #[test]
    fn range_bounds_use_maven_ordering() {
        let spec = range("[1.9,1.11]");

        assert!(spec.contains("1.10"));
        assert!(spec.contains("1.11"));
        assert!(!spec.contains("1.8"));
    }

    /// A pre-release sorts below its release, so `[1.0,2.0)` admits
    /// `2.0-rc1` -- it really is below `2.0`. Filtering pre-releases is the
    /// caller's job, not the range's.
    #[test]
    fn range_admits_pre_release_below_upper_bound() {
        assert!(range("[1.0,2.0)").contains("2.0-rc1"));
        assert!(!range("[1.0,2.0)").contains("2.0"));
    }

    // -- Refusals ---------------------------------------------------------

    #[test]
    fn range_unclosed_refused() {
        assert!(refused("[1.0,2.0").contains("closing bracket"));
    }

    /// `(1.0)` cannot mean anything; reading it as `[1.0]` would widen the
    /// request without saying so.
    #[test]
    fn range_single_version_in_parens_refused() {
        assert!(refused("(1.0)").contains("square brackets"));
        assert!(refused("[1.0)").contains("square brackets"));
    }

    #[test]
    fn range_inverted_refused() {
        assert!(refused("[2.0,1.0]").contains("below the lower bound"));
    }

    #[test]
    fn range_unsatisfiable_refused() {
        assert!(refused("(1.0,1.0)").contains("nothing can match"));
        assert!(refused("(1.0,1.0]").contains("nothing can match"));
    }

    #[test]
    fn range_loose_version_beside_bracket_refused() {
        assert!(refused("[1.0],2.0").contains("bracketed ranges only"));
    }

    #[test]
    fn range_empty_spec_refused() {
        assert!(refused("").contains("empty"));
        assert!(refused("   ").contains("empty"));
        assert!(refused("[]").contains("no version"));
    }

    /// Every refusal names the ecosystem and echoes what was written, so
    /// the message is actionable without the surrounding context.
    #[test]
    fn range_refusal_quotes_spec() {
        let message = refused("[2.0,1.0]");

        assert!(message.contains("maven"));
        assert!(message.contains("[2.0,1.0]"));
    }
}
