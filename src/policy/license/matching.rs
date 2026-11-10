//! Deciding whether a policy entry names a given artifact or license.
//!
//! Pure string work: nothing here knows what a [`Decision`] is, which is
//! why it is apart from the policy that acts on the answers. Every function
//! takes two strings and returns a boolean or a slice of one of them.
//!
//! Both rules are deliberately forgiving in one direction and strict in the
//! other, and both reasons are about the data these actually meet -- a
//! hand-written policy file on one side, and whatever a POM or a registry
//! said on the other.
//!
//! [`Decision`]: super::Decision

use crate::internal::glob;
use crate::internal::purl::pattern::{name_of, version_of};

/// Compare a policy URL against a declared one, ignoring the scheme and a
/// trailing slash.
///
/// Policies say `https://www.apache.org/licenses/LICENSE-2.0` and POMs say
/// `http://www.apache.org/licenses/LICENSE-2.0.txt`; treating those as
/// different would make the alias table useless.
pub(super) fn url_matches(policy: &str, declared: &str) -> bool {
    normalize_url(policy) == normalize_url(declared)
}

fn normalize_url(url: &str) -> String {
    let without_scheme = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    without_scheme
        .trim_end_matches('/')
        .trim_end_matches(".txt")
        .trim_end_matches(".html")
        .to_ascii_lowercase()
}

/// Match a policy purl against an artifact's.
///
/// The rule is a glob: `*` matches any run of characters and `?` matches one.
/// A rule naming no version applies to every version, which is what keeps a
/// policy file maintainable.
///
/// The version qualifier exists because licenses change mid-life.
/// Elasticsearch went Apache-2.0 to SSPL at 7.11; Terraform went MPL to BUSL
/// at 1.6.  Forbidding those means naming versions, not packages:
///
/// ```text
///   pkg:npm/foo            every version of foo
///   pkg:npm/foo@2.*        the 2.x line
///   pkg:npm/foo@*-beta*    every beta
///   pkg:npm/foo@*          every version, said explicitly
/// ```
///
/// A glob is textual, so it cannot say "7.11 and later".  Covering a license
/// change means listing the lines above it -- `@7.11.*`, `@7.12.*`, `@8.*` --
/// and a new major release needs a new entry.  That is the cost of the simple
/// matcher; a range comparator using each ecosystem's own version ordering is
/// the natural successor.
pub(super) fn purl_matches(rule: &str, artifact: &str) -> bool {
    // A rule with no version covers every version, so anchor it at the
    // version separator rather than letting a prefix match `specialist`
    // when the rule said `special`.
    if version_of(rule).is_none() {
        let name = name_of(artifact);

        return glob::matches_purl(rule, name);
    }

    glob::matches_purl(rule, artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_versionless_rule_covers_every_version() {
        assert!(purl_matches("pkg:npm/special", "pkg:npm/special@9.9.9"));
        assert!(purl_matches(
            "pkg:npm/special",
            "pkg:npm/special@1.0.0-rc.1"
        ));

        // And must not reach a longer name.
        assert!(!purl_matches("pkg:npm/special", "pkg:npm/specialist@1.0.0"));
    }

    #[test]
    fn match_exact_version_only_itself() {
        assert!(purl_matches("pkg:npm/a@1.0.0", "pkg:npm/a@1.0.0"));
        assert!(!purl_matches("pkg:npm/a@1.0.0", "pkg:npm/a@1.0.1"));
    }

    #[test]
    fn match_glob_in_version() {
        assert!(purl_matches("pkg:npm/a@*", "pkg:npm/a@1.0.0"));
        assert!(purl_matches("pkg:npm/a@1.?.0", "pkg:npm/a@1.4.0"));
        assert!(!purl_matches("pkg:npm/a@1.?.0", "pkg:npm/a@1.44.0"));

        // Every pre-release of any version.
        assert!(purl_matches("pkg:npm/a@*-beta*", "pkg:npm/a@2.0.0-beta.3"));
        assert!(!purl_matches("pkg:npm/a@*-beta*", "pkg:npm/a@2.0.0"));
    }

    /// A glob may name packages too, but only when one is written: a plain
    /// name stays an exact match.
    #[test]
    fn match_glob_spans_package_name() {
        assert!(purl_matches(
            "pkg:npm/%40acme/*",
            "pkg:npm/%40acme/tool@1.0.0"
        ));
        assert!(!purl_matches(
            "pkg:npm/%40acme/*",
            "pkg:npm/%40other/tool@1.0.0"
        ));
    }

    /// Purl puts the version before the qualifiers, so a rule written that
    /// way has to match what the tool produces.
    #[test]
    fn match_qualifiers_follow_version() {
        let artifact = "pkg:maven/g/a@1.0.0?classifier=sources";

        assert!(purl_matches("pkg:maven/g/a", artifact));
        assert!(purl_matches(
            "pkg:maven/g/a@1.0.0?classifier=sources",
            artifact
        ));
        assert!(purl_matches("pkg:maven/g/a@*?classifier=sources", artifact));
        assert!(!purl_matches(
            "pkg:maven/g/a@*?classifier=javadoc",
            artifact
        ));
    }

    /// An npm scope's `@` is encoded in a purl, but a hand-written rule may
    /// keep it; neither spelling may be mistaken for the version separator.
    #[test]
    fn match_scope_not_version_separator() {
        assert_eq!(version_of("pkg:npm/%40angular/core"), None);
        assert_eq!(version_of("pkg:npm/@angular/core"), None);
        assert_eq!(version_of("pkg:npm/@angular/core@17.0.0"), Some("17.0.0"));
        assert_eq!(
            name_of("pkg:npm/@angular/core@17.0.0"),
            "pkg:npm/@angular/core"
        );
    }
}
