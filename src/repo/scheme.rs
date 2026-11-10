//! Whether a source kind's version scheme is its own or the user's.

use std::sync::LazyLock;

use crate::ext::Options;

/// Whether a source kind's version scheme is its own or the user's to say.
///
/// The two are genuinely different claims and only one of them is a
/// setting. A Maven repository orders versions the way Maven orders
/// versions -- that is not a preference, it is what the repository *is*, and
/// a user who set it to something else would get a plausible-looking wrong
/// answer rather than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionScheme {
    /// Decided by the kind. `version-handler` is refused.
    Fixed,

    /// Whatever the repository's publisher happened to use, which this tool
    /// cannot know. `version-handler` says which.
    Declared,
}

/// Which of the two a kind is.
///
/// **Fixed is the answer for every registry adapter.** npm is semver, Maven
/// is `ComparableVersion`, PyPI is PEP 440 -- each is defined by the
/// ecosystem the adapter speaks, and letting a configuration disagree would
/// be letting it be wrong. The scheme is still reachable on its own through
/// [`crate::version::open`], which is what a repository with no ecosystem
/// uses; what is refused is *overriding* one that has an answer already.
///
/// **Declared is for repositories whose contents decide.** GitHub tags are
/// text a publisher chose, and `v2.1.0`, `nightly` and `2024-06-01` are all
/// real; the default refuses to order them, and a repository that does
/// follow a scheme says which. A raw repository is the same case and more
/// so -- it has no ecosystem at all, and a path segment its mapping calls a
/// version might be `1.2.0`, `latest`, or `build-77`.
///
/// A repository manager is either, by the `ecosystem` it is configured
/// with: raw under `mapping: name-version-file` is declared, and every
/// registry format is fixed. Raw under `directory` or `as-is` is fixed too:
/// those mappings read no version at all, so a handler would order nothing.
///
/// An unknown kind answers `Fixed`, so an extension's source cannot be
/// handed a handler this tool would then not apply. That is the
/// conservative direction: a setting that is refused is visible, and one
/// that is silently ignored is not.
pub(crate) fn version_scheme(kind: &str, options: &Options) -> VersionScheme {
    let Some(found) = super::source_kind(kind) else {
        return VersionScheme::Fixed;
    };

    found.versions.scheme(options)
}

/// The sources that accept a `version-handler`, and when, for a message
/// that names them.
pub(crate) fn declared_version_kinds() -> &'static [String] {
    static DECLARED: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut kinds: Vec<String> = super::source_descriptors()
            .filter_map(|found| found.versions.describe(found.name))
            .collect();

        kinds.sort_unstable();
        kinds
    });

    &DECLARED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw repository has no ecosystem to fix its ordering, so what its
    /// path segments mean is the user's to declare -- unlike npm, which
    /// *is* semver whatever a configuration says.
    #[test]
    fn raw_source_declares_version_scheme() {
        let raw = |mapping: &str| {
            crate::ext::testing::options(
                serde_json::json!({"ecosystem": "raw", "mapping": mapping}),
            )
        };
        let unmapped = crate::ext::testing::options(serde_json::json!({"ecosystem": "raw"}));
        let maven = crate::ext::testing::options(serde_json::json!({"ecosystem": "maven"}));

        for kind in ["nexus", "artifactory", "artifact-keeper"] {
            assert_eq!(
                version_scheme(kind, &raw("name-version-file")),
                VersionScheme::Declared,
                "{kind}"
            );
            assert_eq!(version_scheme(kind, &maven), VersionScheme::Fixed, "{kind}");
        }

        // No version to order under these.
        assert_eq!(version_scheme("nexus", &unmapped), VersionScheme::Fixed);
        assert_eq!(
            version_scheme("nexus", &raw("directory")),
            VersionScheme::Fixed
        );
        assert_eq!(version_scheme("nexus", &raw("as-is")), VersionScheme::Fixed);
        assert_eq!(version_scheme("nexus", &raw("regex")), VersionScheme::Fixed);
        assert!(
            declared_version_kinds()
                .iter()
                .any(|kind| kind.starts_with("nexus"))
        );
    }
}
