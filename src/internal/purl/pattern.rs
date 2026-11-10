//! Taking a purl apart, for the rules that match against one.
//!
//! Shared because several rule sets need the same split, for different
//! reasons: the license policy globs what it finds, the quarantine and
//! signing policies and a configured `omit` read the version half as an
//! **ecosystem range**. The split itself is the same either way, and the
//! one subtlety in it is worth having in exactly one place.
//!
//! `model::ArtifactId::purl` is what produces these.

/// The version portion of a purl, or `None` when it names no version.
///
/// The separator is the `@` after the final `/`: a purl encodes an npm
/// scope's own `@` as `%40`, but a hand-written rule may not, and the
/// version never contains a slash.
pub fn version_of(purl: &str) -> Option<&str> {
    let last_slash = purl.rfind('/').map(|i| i + 1).unwrap_or(0);
    let at = purl[last_slash..].find('@')? + last_slash;

    let rest = &purl[at + 1..];
    let end = rest.find('?').unwrap_or(rest.len());

    Some(&rest[..end])
}

/// A purl with its version and qualifiers removed.
pub(crate) fn name_of(purl: &str) -> &str {
    let last_slash = purl.rfind('/').map(|i| i + 1).unwrap_or(0);

    let end = purl[last_slash..]
        .find(['@', '?'])
        .map(|i| i + last_slash)
        .unwrap_or(purl.len());

    &purl[..end]
}

/// Whether a rule's purl pattern covers an artifact: the name half is a
/// glob, and the version half, when there is one, an ecosystem range.
///
/// A pattern naming no version covers every version, and the artifact that
/// has none. A range asks a question an artifact without a version cannot
/// answer, so it covers no such artifact; nor anything in an ecosystem this
/// build cannot parse (`None`), which is unanswerable rather than answered
/// wrongly.
pub(crate) fn covers(
    pattern: &str,
    id: &crate::model::ArtifactId,
    version: Option<&crate::model::Version>,
    ecosystem: Option<&dyn crate::ecosystem::Ecosystem>,
) -> bool {
    if !crate::internal::glob::matches_purl(name_of(pattern), &id.purl()) {
        return false;
    }

    let Some(range) = version_of(pattern) else {
        return true;
    };

    let (Some(version), Some(ecosystem)) = (version, ecosystem) else {
        return false;
    };

    ecosystem
        .select(
            &ecosystem.version_spec(range),
            std::slice::from_ref(version),
            crate::version::PreRelease::Include,
        )
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subtlety the split exists for: an npm scope's `@` is encoded in
    /// a purl, but a hand-written rule may leave it bare, and neither
    /// spelling may be mistaken for the version separator.
    #[test]
    fn scope_not_version_separator() {
        assert_eq!(version_of("pkg:npm/%40angular/core"), None);
        assert_eq!(version_of("pkg:npm/@angular/core"), None);
        assert_eq!(version_of("pkg:npm/@angular/core@17.0.0"), Some("17.0.0"));

        assert_eq!(
            name_of("pkg:npm/@angular/core@17.0.0"),
            "pkg:npm/@angular/core"
        );
    }

    /// Purl puts the version before the qualifiers, so the version half
    /// stops at the first `?`.
    #[test]
    fn qualifiers_not_part_of_version() {
        assert_eq!(
            version_of("pkg:maven/g/a@1.0.0?classifier=sources"),
            Some("1.0.0")
        );

        assert_eq!(
            name_of("pkg:maven/g/a@1.0.0?classifier=sources"),
            "pkg:maven/g/a"
        );
    }

    #[test]
    fn purl_without_version_has_none() {
        assert_eq!(version_of("pkg:npm/lodash"), None);
        assert_eq!(name_of("pkg:npm/lodash"), "pkg:npm/lodash");
    }
}
