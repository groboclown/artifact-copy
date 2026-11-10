//! The PyPI ecosystem.
//!
//! Coordinates are PEP 508 requirement strings -- what a Python developer
//! already types -- and versions order by PEP 440, which is neither semver
//! nor Maven's scheme and disagrees with both.
//!
//! Two asymmetries worth knowing before reading further. PyPI publishes
//! **one** dependency list, so there is no dev or test kind to report: those
//! live in `pyproject.toml` and are never published. And a name is
//! normalized before use, because `Foo_Bar`, `foo-bar` and `foo.bar` are the
//! same project.
//!
//! References: [PEP 440](https://peps.python.org/pep-0440/), [PEP 508](https://peps.python.org/pep-0508/), [PEP 740](https://peps.python.org/pep-0740/).

use std::sync::Arc;
use std::time::Duration;

use super::{Companion, Ecosystem};
use crate::core::error::{Error, Result};
use crate::model::{
    ArtifactId, ArtifactRequest, Cause, DepKind, EcosystemId, Provenance, Version, VersionSpec,
};
use crate::version::{Pep440Versions, PreRelease, Ranking, VersionHandler};

/// PyPI publishes exactly these.
///
/// `dev` and `test` are absent because core metadata has no such concept:
/// PEP 735 dependency groups live in `pyproject.toml` and never reach the
/// index. `--dependencies=test` against PyPI is therefore an error rather
/// than an empty result that would read as "this package has no test
/// dependencies".
const DEP_KINDS: [DepKind; 2] = [DepKind::Runtime, DepKind::Optional];

/// The OSV spelling, which is neither the purl type nor the display name.
const OSV_NAME: &str = "PyPI";

/// The document name a PyPI source caches a project's simple page under.
pub const SIMPLE_DOCUMENT: &str = "simple.html";

/// The document name a PyPI source caches a release's JSON detail under.
pub const DETAIL_DOCUMENT: &str = "detail.json";

/// The document name the `pypi-simple` enumerator caches the whole index
/// under.
pub const INDEX_DOCUMENT: &str = "simple-index.json";

/// A project's pages change with every upload. The whole index is a
/// large download, so it is kept a day, as `index-ttl` used to default to.
const FRESHNESS: [(&str, Duration); 3] = [
    (SIMPLE_DOCUMENT, Duration::from_secs(3_600)),
    (DETAIL_DOCUMENT, Duration::from_secs(3_600)),
    (INDEX_DOCUMENT, Duration::from_secs(86_400)),
];

/// The name a file's PEP 740 provenance object is cached under, beside the
/// file. PEP 740 fixes no URL for it, so this names the cached copy only,
/// and one name lets the check and the forward share one download.
pub const PROVENANCE_SUFFIX: &str = ".provenance";

/// The PEP 658 document beside each file, which an upload repeats so the
/// target index serves what the origin did, and the PEP 740 provenance,
/// whose attestations an upload forwards.
const COMPANIONS: [Companion; 2] = [Companion::CoreMetadata, Companion::Provenance];

pub struct PyPi;

impl Ecosystem for PyPi {
    fn id(&self) -> EcosystemId {
        EcosystemId::new(EcosystemId::PYPI)
    }

    fn purl_type(&self) -> &str {
        EcosystemId::PYPI
    }

    fn osv_name(&self) -> &str {
        OSV_NAME
    }

    fn dep_kinds(&self) -> &[DepKind] {
        &DEP_KINDS
    }

    fn freshness(&self) -> &[(&'static str, Duration)] {
        &FRESHNESS
    }

    fn companions(&self) -> &[Companion] {
        &COMPANIONS
    }

    fn parse_req(&self, text: &str) -> Result<ArtifactRequest> {
        let (name, spec) = split_requirement(text)?;

        Ok(ArtifactRequest {
            id: ArtifactId::new(EcosystemId::pypi(), None, &normalize(&name)),
            spec,
            prov: Arc::new(Provenance::root(Cause::Requested {
                arg: text.to_owned(),
            })),
        })
    }
}

/// Versions are PEP 440's, which orders `1.0.post1` above `1.0` and counts
/// a `.devN` segment as a pre-release.
///
/// Delegated rather than implemented, because the convention is not the
/// ecosystem's property: a repository publishing PEP 440 versions without
/// being a Python index configures [`Pep440Versions`] directly.
impl VersionHandler for PyPi {
    fn version_spec(&self, text: &str) -> VersionSpec {
        Pep440Versions.version_spec(text)
    }

    fn classify(&self, texts: &[String]) -> Vec<Version> {
        Pep440Versions.classify(texts)
    }

    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
        Pep440Versions.select(spec, of, pre)
    }

    fn compare(&self, a: &Version, b: &Version) -> Ranking {
        Pep440Versions.compare(a, b)
    }

    fn sort(&self, versions: &mut [Version]) {
        Pep440Versions.sort(versions)
    }
}

/// PEP 503 normalization: runs of `-`, `_` and `.` collapse to one `-`, and
/// the whole thing lowercases.
///
/// `Foo_Bar`, `foo-bar` and `foo.bar` are one project, and a purl that did
/// not say so would produce three entries in a report for one package.
pub fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_separator = false;

    for ch in name.trim().chars() {
        if matches!(ch, '-' | '_' | '.') {
            last_was_separator = true;
            continue;
        }

        if last_was_separator && !out.is_empty() {
            out.push('-');
        }

        last_was_separator = false;
        out.push(ch.to_ascii_lowercase());
    }

    out
}

/// Split a PEP 508 requirement into its name and its version constraint.
///
/// Extras are dropped from the identity: `requests[socks]` and `requests`
/// are the same artifact, and an extra selects which of its dependencies
/// apply rather than naming a different package.
fn split_requirement(text: &str) -> Result<(String, VersionSpec)> {
    let trimmed = text.trim();

    if trimmed.is_empty() {
        return Err(bad_request(text, "the requirement is empty"));
    }

    // A marker applies to whether the dependency is needed at all, not to
    // which version; the resolver handles it elsewhere.
    let without_marker = trimmed.split(';').next().unwrap_or(trimmed).trim();

    let name_end = without_marker
        .find(|c: char| c == '[' || c == '(' || is_operator_start(c))
        .unwrap_or(without_marker.len());

    let name = without_marker[..name_end].trim().to_owned();

    if name.is_empty() {
        return Err(bad_request(text, "the requirement names no package"));
    }

    let rest = without_marker[name_end..].trim();

    // Skip the extras group, which is part of the name syntax rather than
    // the version.
    let rest = match rest.strip_prefix('[') {
        Some(after) => match after.split_once(']') {
            Some((_, tail)) => tail.trim(),
            None => return Err(bad_request(text, "the extras group is not closed")),
        },
        None => rest,
    };

    let spec = rest.trim_start_matches('(').trim_end_matches(')').trim();

    Ok((name, Pep440Versions.version_spec(spec)))
}

fn is_operator_start(c: char) -> bool {
    matches!(c, '=' | '<' | '>' | '!' | '~')
}

fn bad_request(text: &str, detail: &str) -> Error {
    Error::BadRequest {
        ecosystem: "pypi",
        text: text.to_owned(),
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str) -> ArtifactRequest {
        PyPi.parse_req(text).expect("parses")
    }

    #[test]
    fn requirement_bare_name_takes_any_version() {
        let request = req("requests");

        assert_eq!(request.id.purl(), "pkg:pypi/requests");
        assert_eq!(request.spec, VersionSpec::Any);
    }

    #[test]
    fn requirement_double_equals_is_exact() {
        assert_eq!(
            req("requests==2.31.0").spec,
            VersionSpec::Exact("2.31.0".into())
        );
    }

    #[test]
    fn requirement_comparison_is_range() {
        assert_eq!(
            req("requests>=2.31,<3").spec,
            VersionSpec::Range(">=2.31,<3".into())
        );
        assert_eq!(
            req("requests~=2.31.0").spec,
            VersionSpec::Range("~=2.31.0".into())
        );
    }

    /// A prefix wildcard is a range, not a pin, however much it looks like
    /// one.
    #[test]
    fn requirement_wildcard_pin_is_range() {
        assert_eq!(
            req("requests==2.31.*").spec,
            VersionSpec::Range("==2.31.*".into())
        );
    }

    /// Extras select which dependencies apply; they do not name a different
    /// package, so they are not part of the identity.
    #[test]
    fn requirement_extras_keep_artifact() {
        let request = req("requests[socks,security]>=2.31");

        assert_eq!(request.id.purl(), "pkg:pypi/requests");
        assert_eq!(request.spec, VersionSpec::Range(">=2.31".into()));
    }

    /// Three spellings of one project must not become three report entries.
    #[test]
    fn requirement_name_normalized_per_pep_503() {
        for spelling in ["Foo_Bar", "foo-bar", "foo.bar", "FOO--BAR"] {
            assert_eq!(normalize(spelling), "foo-bar", "{spelling}");
        }

        assert_eq!(req("Zope.Interface").id.name(), "zope-interface");
    }

    #[test]
    fn requirement_marker_not_in_version() {
        let request = req("requests>=2.31; python_version < \"3.11\"");

        assert_eq!(request.id.name(), "requests");
        assert_eq!(request.spec, VersionSpec::Range(">=2.31".into()));
    }

    #[test]
    fn requirement_empty_rejected() {
        assert!(PyPi.parse_req("   ").is_err());
        assert!(PyPi.parse_req(">=1.0").is_err());
    }

    /// PEP 440 orders by release tuple, so 1.10 beats 1.9 -- the opposite of
    /// a lexical sort.
    #[test]
    fn pypi_publishes_no_dev_or_test_dependencies() {
        let kinds = PyPi.dep_kinds();

        assert!(kinds.contains(&DepKind::Runtime));
        assert!(kinds.contains(&DepKind::Optional));
        assert!(!kinds.contains(&DepKind::Dev));
        assert!(!kinds.contains(&DepKind::Test));
    }

    /// The OSV name is not derivable from the id, which is why it is
    /// declared rather than computed.
    #[test]
    fn pypi_states_osv_name() {
        assert_eq!(PyPi.id(), EcosystemId::pypi());
        assert_eq!(PyPi.purl_type(), "pypi");
        assert_eq!(PyPi.osv_name(), "PyPI");
    }
}
