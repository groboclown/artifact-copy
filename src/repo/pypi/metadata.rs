//! Reading a PyPI `METADATA` document.
//!
//! The RFC 822 core-metadata file PEP 658 puts beside a distribution, so a
//! dependency list costs one small request rather than a wheel download.
//!
//! A format reader beside the source that fetches it, in the same shape as
//! [`crate::repo::maven::pom`]. What it reads is a *document*; what a
//! `Requires-Dist` line means is PEP 508 and belongs to the ecosystem, so
//! each line is handed to [`PyPi::parse_req`] rather than parsed here.
//!
//! References: [Core metadata](https://packaging.python.org/en/latest/specifications/core-metadata/), [PEP 508](https://peps.python.org/pep-0508/).

use crate::ecosystem::{Ecosystem, PyPi};
use crate::model::{DepKind, Dependency};

/// The header naming a dependency.
///
/// Matched case-sensitively, as PEP 566 spells it. Core metadata is
/// machine-generated, and accepting other spellings would mean guessing at
/// a file that is not supposed to vary.
const REQUIRES_DIST: &str = "Requires-Dist:";

/// Parse a `Requires-Dist` value into a dependency.
///
/// An `extra == "..."` marker means the dependency is optional: it applies
/// only when that extra is requested.
///
/// A line that does not parse yields `None` rather than a guess -- see
/// [`requires_dist`].
pub(super) fn dependency(line: &str) -> Option<Dependency> {
    let kind = match line.contains("extra ==") {
        true => DepKind::Optional,
        false => DepKind::Runtime,
    };

    let request = PyPi.parse_req(line).ok()?;

    Some(Dependency {
        id: request.id,
        spec: request.spec,
        kind,
    })
}

/// Pull every `Requires-Dist` out of a `METADATA` document.
///
/// Unparseable lines are dropped rather than failing the document. A
/// `METADATA` file carries a great deal besides dependencies, and refusing
/// the whole of it over one malformed requirement would lose the rest --
/// which is the more useful part.
pub(super) fn requires_dist(text: &str) -> Vec<Dependency> {
    text.lines()
        .filter_map(|line| line.strip_prefix(REQUIRES_DIST))
        .filter_map(|value| dependency(value.trim()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Metadata-Version: 2.1
Name: example
Version: 1.0.0
Requires-Dist: requests>=2.31
Requires-Dist: urllib3
Requires-Dist: pytest>=7 ; extra == 'test'
Summary: Requires-Dist: not a header, it is prose
";

    fn names(deps: &[Dependency]) -> Vec<&str> {
        deps.iter().map(|dep| dep.id.name()).collect()
    }

    #[test]
    fn requires_dist_every_becomes_dependency() {
        let deps = requires_dist(SAMPLE);

        assert_eq!(names(&deps), ["requests", "urllib3", "pytest"]);
    }

    /// An `extra ==` marker means the dependency applies only when that
    /// extra is requested, which is what `optional` means here.
    #[test]
    fn extra_marker_makes_optional() {
        let deps = requires_dist(SAMPLE);

        assert_eq!(deps[0].kind, DepKind::Runtime);
        assert_eq!(deps[1].kind, DepKind::Runtime);
        assert_eq!(deps[2].kind, DepKind::Optional);
    }

    /// Only a line that *starts* with the header is one. The sample's
    /// `Summary:` mentions the text and must not be mistaken for a
    /// requirement.
    #[test]
    fn header_matched_at_line_start() {
        assert_eq!(requires_dist(SAMPLE).len(), 3);
    }

    /// Core metadata is machine-generated and spells the header one way;
    /// accepting others would be guessing at a file that does not vary.
    #[test]
    fn header_case_sensitive() {
        assert!(requires_dist("requires-dist: requests").is_empty());
        assert!(requires_dist("REQUIRES-DIST: requests").is_empty());
    }

    /// A `METADATA` file carries far more than dependencies. Refusing all
    /// of it over one malformed requirement would lose the useful part.
    #[test]
    fn line_unparseable_keeps_others() {
        let deps = requires_dist(
            "Requires-Dist: requests>=2.31\n\
             Requires-Dist: \n\
             Requires-Dist: urllib3\n",
        );

        assert_eq!(names(&deps), ["requests", "urllib3"]);
    }

    /// PEP 503 normalization, so `Flask_SQLAlchemy` and `flask-sqlalchemy`
    /// are one artifact rather than two entries in a report.
    #[test]
    fn names_normalized() {
        let deps = requires_dist("Requires-Dist: Flask_SQLAlchemy>=3\n");

        assert_eq!(names(&deps), ["flask-sqlalchemy"]);
    }

    #[test]
    fn document_without_requirements_yields_none() {
        assert!(requires_dist("Name: example\nVersion: 1.0\n").is_empty());
        assert!(requires_dist("").is_empty());
    }
}
