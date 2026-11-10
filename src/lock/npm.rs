//! npm lock formats.
//!
//! `package-lock.json` is the one to reach for first: its `packages` map
//! already carries a `resolved` URL and an `integrity` hash, which is
//! everything needed to fetch and verify without asking the registry
//! anything.
//!
//! References: [package-lock.json](https://docs.npmjs.com/cli/configuring-npm/package-lock-json), [yarn.lock](https://classic.yarnpkg.com/lang/en/docs/yarn-lock/).

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use serde::Deserialize;

use super::{Lock, LockFormat, LockHead, LockRead, read_capped};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::model::{ArtifactId, ArtifactRequest, Cause, EcosystemId, Provenance, VersionSpec};

/// The readers this crate ships for npm.
pub(super) fn readers() -> Vec<Arc<dyn Lock>> {
    vec![Arc::new(PackageLock), Arc::new(YarnLock)]
}

/// `@scope/name` split into its parts.
///
/// Duplicated from the ecosystem rather than shared: a lock reader is its
/// own extension point and must not need an ecosystem resolved first.
fn split_scope(name: &str) -> (Option<String>, &str) {
    if !name.starts_with('@') {
        return (None, name);
    }

    match name.split_once('/') {
        Some((scope, bare)) => (Some(scope.to_owned()), bare),
        None => (None, name),
    }
}

/// One format, for the registry.
fn format(name: &str, filenames: &[&str]) -> LockFormat {
    LockFormat {
        name: name.to_owned(),
        filenames: filenames.iter().map(|f| (*f).to_owned()).collect(),
    }
}

/// Built once, because [`Lock::formats`] lends them out.
static PACKAGE_LOCK_FORMATS: LazyLock<[LockFormat; 1]> =
    LazyLock::new(|| [format("package-lock", &PACKAGE_LOCK_NAMES)]);

static YARN_LOCK_FORMATS: LazyLock<[LockFormat; 1]> =
    LazyLock::new(|| [format("yarn", &[YARN_LOCK_NAME])]);

/// Lock files name exact versions, so every entry is an exact request.
fn request(name: &str, version: &str, file: &str) -> ArtifactRequest {
    let (namespace, bare) = split_scope(name);

    ArtifactRequest {
        id: ArtifactId::new(EcosystemId::npm(), namespace.as_deref(), bare),
        spec: VersionSpec::Exact(version.to_owned()),
        prov: Arc::new(Provenance::root(Cause::LockFile {
            path: PathBuf::from(file),
            entry: format!("{name}@{version}"),
        })),
    }
}

// -- package-lock.json ---------------------------------------------------

/// `package-lock.json` and `npm-shrinkwrap.json`.
struct PackageLock;

const PACKAGE_LOCK_NAMES: [&str; 2] = ["package-lock.json", "npm-shrinkwrap.json"];

/// The `node_modules/` prefix on every key in the v2/v3 `packages` map.
const NODE_MODULES: &str = "node_modules/";

#[derive(Deserialize)]
struct PackageLockFile {
    #[serde(rename = "lockfileVersion", default)]
    lockfile_version: u32,

    /// v2 and v3.  Keyed by install path; `""` is the project itself.
    #[serde(default)]
    packages: std::collections::BTreeMap<String, PackageEntry>,

    /// v1 only.  npm 7+ ignores this whenever `packages` is present.
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, LegacyEntry>,
}

#[derive(Deserialize)]
struct PackageEntry {
    #[serde(default)]
    version: Option<String>,

    /// A workspace symlink, not a registry artifact.
    #[serde(default)]
    link: bool,

    /// Present for a registry package; absent for a local or git one.
    #[serde(default)]
    resolved: Option<String>,

    /// Explicit name, for a path that does not encode it.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct LegacyEntry {
    #[serde(default)]
    version: Option<String>,

    #[serde(default)]
    resolved: Option<String>,

    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, LegacyEntry>,
}

#[async_trait]
impl Lock for PackageLock {
    fn formats(&self) -> &[LockFormat] {
        &*PACKAGE_LOCK_FORMATS
    }

    fn claims<'n, 'h>(&self, name: &'n str, head: &LockHead<'h>) -> bool {
        PACKAGE_LOCK_NAMES.contains(&name)
            || (name.ends_with(".json") && head.text().contains("lockfileVersion"))
    }

    async fn read(&self, file: &Path, _ctx: &Ctx) -> Result<LockRead> {
        let body = read_capped(file).await?;

        self.parse(&body).map(LockRead::from)
    }
}

impl PackageLock {
    fn parse(&self, body: &[u8]) -> Result<Vec<ArtifactRequest>> {
        let file: PackageLockFile =
            serde_json::from_slice(body).map_err(|source| Error::Malformed {
                what: "package-lock.json",
                url: String::new(),
                detail: source.to_string(),
            })?;

        // v1's tree is ignored whenever the flat map exists, exactly as
        // npm 7+ does.
        if !file.packages.is_empty() {
            return Ok(read_packages(&file.packages));
        }

        let mut out = Vec::new();
        read_legacy(&file.dependencies, &mut out);

        if out.is_empty() && file.lockfile_version == 0 {
            return Err(Error::Malformed {
                what: "package-lock.json",
                url: String::new(),
                detail: "no lockfileVersion, packages, or dependencies".into(),
            });
        }

        Ok(out)
    }
}

fn read_packages(
    packages: &std::collections::BTreeMap<String, PackageEntry>,
) -> Vec<ArtifactRequest> {
    let mut out = Vec::new();

    for (path, entry) in packages {
        // The root project is not an artifact to migrate.
        if path.is_empty() {
            continue;
        }

        // A workspace link resolves to a sibling directory, and a package
        // with no `resolved` came from git or a file path.  Neither exists
        // in a registry, so neither can be copied from one.
        if entry.link || entry.resolved.is_none() {
            continue;
        }

        let Some(version) = &entry.version else {
            continue;
        };

        let name = entry
            .name
            .clone()
            .or_else(|| name_from_path(path))
            .unwrap_or_else(|| path.clone());

        out.push(request(&name, version, "package-lock.json"));
    }

    out
}

/// Take the package name from an install path.
///
/// Nested paths carry the whole chain -- `node_modules/a/node_modules/b` --
/// and only the last segment names the package.
fn name_from_path(path: &str) -> Option<String> {
    let last = path.rfind(NODE_MODULES)? + NODE_MODULES.len();

    Some(path[last..].to_owned())
}

fn read_legacy(
    entries: &std::collections::BTreeMap<String, LegacyEntry>,
    out: &mut Vec<ArtifactRequest>,
) {
    for (name, entry) in entries {
        if let Some(version) = &entry.version
            && entry.resolved.is_some()
        {
            out.push(request(name, version, "package-lock.json"));
        }

        read_legacy(&entry.dependencies, out);
    }
}

// -- yarn.lock -----------------------------------------------------------

/// `yarn.lock`, both v1 and Berry.
///
/// v1 is a custom near-YAML text format that is *not* valid YAML, so it gets
/// a hand-written reader rather than a YAML parser that would appear to work
/// and then mangle entries.
struct YarnLock;

const YARN_LOCK_NAME: &str = "yarn.lock";

/// Berry marks itself; v1 does not.
const BERRY_MARKER: &str = "__metadata:";

#[async_trait]
impl Lock for YarnLock {
    fn formats(&self) -> &[LockFormat] {
        &*YARN_LOCK_FORMATS
    }

    fn claims<'n, 'h>(&self, name: &'n str, _head: &LockHead<'h>) -> bool {
        name == YARN_LOCK_NAME
    }

    async fn read(&self, file: &Path, _ctx: &Ctx) -> Result<LockRead> {
        let body = read_capped(file).await?;

        self.parse(&body).map(LockRead::from)
    }
}

impl YarnLock {
    fn parse(&self, body: &[u8]) -> Result<Vec<ArtifactRequest>> {
        let text = std::str::from_utf8(body).map_err(|source| Error::Malformed {
            what: "yarn.lock",
            url: String::new(),
            detail: source.to_string(),
        })?;

        Ok(read_yarn(text, text.contains(BERRY_MARKER)))
    }
}

/// Read the entry headers and their `version:` lines.
///
/// Both dialects share this shape: an unindented header naming one or more
/// descriptors, then indented fields.  Berry quotes and uses `npm:` protocol
/// prefixes; v1 does not.
fn read_yarn(text: &str, berry: bool) -> Vec<ArtifactRequest> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;

    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }

        // An unindented line opens a new entry.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            pending = first_descriptor(line.trim_end_matches(':').trim(), berry);
            continue;
        }

        let trimmed = line.trim();

        let Some(rest) = trimmed.strip_prefix("version") else {
            continue;
        };

        let version = rest.trim_start_matches([':', ' ']).trim().trim_matches('"');

        if let Some(name) = pending.take()
            && !version.is_empty()
        {
            out.push(request(&name, version, YARN_LOCK_NAME));
        }
    }

    out
}

/// Take the package name from an entry header.
///
/// A header may list several descriptors -- `lodash@^4.0.0, lodash@^4.17.0` --
/// which all name the same package.
fn first_descriptor(header: &str, berry: bool) -> Option<String> {
    let first = header.split(',').next()?.trim().trim_matches('"');

    if first.starts_with(BERRY_MARKER.trim_end_matches(':')) {
        return None;
    }

    // Same problem as a coordinate: the scope's leading `@` is not the
    // separator.
    let search_from = usize::from(first.starts_with('@'));
    let at = first[search_from..].find('@').map(|i| i + search_from)?;

    let name = first[..at].to_owned();

    if berry && name.is_empty() {
        return None;
    }

    (!name.is_empty()).then_some(name)
}

/// Test support, public within the crate so the registry's own tests can
/// register a competing reader.
#[cfg(test)]
pub(super) mod testing {
    use super::*;

    /// Claims everything, to prove a declared reader outranks a built-in.
    pub struct AlwaysClaims;

    static ALWAYS_CLAIMS_FORMATS: LazyLock<[LockFormat; 1]> =
        LazyLock::new(|| [format("always-claims", &["*"])]);

    #[async_trait]
    impl Lock for AlwaysClaims {
        fn formats(&self) -> &[LockFormat] {
            &*ALWAYS_CLAIMS_FORMATS
        }

        fn claims<'n, 'h>(&self, _name: &'n str, _head: &LockHead<'h>) -> bool {
            true
        }

        async fn read(&self, _file: &Path, _ctx: &Ctx) -> Result<LockRead> {
            Ok(LockRead::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{LockHead, LockSpec, Registry};

    use crate::model::Cause;

    /// The whole path a real `--lock=FILE` takes: write the file, resolve a
    /// reader for it, and let the reader open it itself.
    async fn read_lock(file_name: &str, body: &[u8]) -> Vec<ArtifactRequest> {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join(file_name);
        let ctx = Ctx::for_test(Cause::Requested {
            arg: file_name.to_owned(),
        });

        std::fs::write(&file, body).expect("written");

        let reader = Registry::builtin()
            .resolve(
                &LockSpec::parse(file_name).expect("parses"),
                file_name,
                &LockHead::of(body),
            )
            .expect("a reader claims it");

        reader.read(&file, &ctx).await.expect("reads").requests
    }

    const V3: &str = r#"{
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-abc"
            },
            "node_modules/@angular/core": {
                "version": "17.0.0",
                "resolved": "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz"
            },
            "node_modules/a/node_modules/nested": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/nested/-/nested-2.0.0.tgz"
            },
            "packages/workspace-thing": {"resolved": "packages/workspace-thing", "link": true},
            "node_modules/from-git": {"version": "1.0.0"}
        }
    }"#;

    #[tokio::test]
    async fn lock_v3_yields_registry_packages() {
        let requests = read_lock("package-lock.json", V3.as_bytes()).await;

        let purls: Vec<String> = requests.iter().map(|r| r.id.purl()).collect();

        assert!(purls.contains(&"pkg:npm/lodash".to_string()));
        assert!(purls.contains(&"pkg:npm/%40angular/core".to_string()));

        // Only the last path segment names the package.
        assert!(purls.contains(&"pkg:npm/nested".to_string()));

        // The root project, a workspace link, and a git dependency are not
        // registry artifacts.
        assert_eq!(requests.len(), 3);
    }

    #[tokio::test]
    async fn lock_entries_exact_requests() {
        let requests = read_lock("package-lock.json", V3.as_bytes()).await;

        let lodash = requests
            .iter()
            .find(|r| r.id.name() == "lodash")
            .expect("present");

        assert_eq!(lodash.spec, VersionSpec::Exact("4.17.21".into()));
    }

    /// Provenance must say the artifact came from a lock file, not from a
    /// command line.
    #[tokio::test]
    async fn lock_entries_carry_origin() {
        let requests = read_lock("package-lock.json", V3.as_bytes()).await;

        let rendered = requests[0].prov.render();

        assert!(rendered.contains("lock file"));
        assert!(rendered.contains("package-lock.json"));
    }

    /// npm 7+ ignores the v1 tree whenever `packages` exists; so must this.
    #[tokio::test]
    async fn lock_flat_map_wins_over_legacy_tree() {
        const BOTH: &str = r#"{
            "lockfileVersion": 2,
            "packages": {
                "node_modules/from-packages": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"
                }
            },
            "dependencies": {
                "from-dependencies": {
                    "version": "9.9.9",
                    "resolved": "https://registry.npmjs.org/y/-/y-9.9.9.tgz"
                }
            }
        }"#;

        let requests = read_lock("package-lock.json", BOTH.as_bytes()).await;

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id.name(), "from-packages");
    }

    #[tokio::test]
    async fn lock_v1_walks_nested_tree() {
        const V1: &str = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "top": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/top/-/top-1.0.0.tgz",
                    "dependencies": {
                        "deep": {
                            "version": "2.0.0",
                            "resolved": "https://registry.npmjs.org/deep/-/deep-2.0.0.tgz"
                        }
                    }
                }
            }
        }"#;

        let requests = read_lock("package-lock.json", V1.as_bytes()).await;

        assert_eq!(requests.len(), 2);
    }

    /// Same format under a second name, so it must reach the same reader.
    #[test]
    fn lock_shrinkwrap_same_format() {
        let reader = Registry::builtin()
            .resolve(
                &LockSpec::parse("npm-shrinkwrap.json").expect("parses"),
                "npm-shrinkwrap.json",
                &LockHead::of(V3.as_bytes()),
            )
            .expect("a reader claims it");

        assert_eq!(reader.formats()[0].name, "package-lock");
    }

    /// v1 yarn.lock is not valid YAML, which is why it gets its own reader.
    #[tokio::test]
    async fn yarn_v1_lock_read() {
        const YARN_V1: &str = r#"# THIS IS AN AUTOGENERATED FILE
# yarn lockfile v1

lodash@^4.17.0, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-abc

"@angular/core@^17.0.0":
  version "17.0.1"
  resolved "https://registry.yarnpkg.com/@angular/core/-/core-17.0.1.tgz"
"#;

        let requests = read_lock("yarn.lock", YARN_V1.as_bytes()).await;

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].id.name(), "lodash");
        assert_eq!(requests[0].spec, VersionSpec::Exact("4.17.21".into()));
        assert_eq!(requests[1].id.namespace(), Some("@angular"));
    }

    #[tokio::test]
    async fn yarn_berry_lock_read() {
        const BERRY: &str = r#"# This file is generated by running "yarn install"
__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: abc
"#;

        let requests = read_lock("yarn.lock", BERRY.as_bytes()).await;

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id.name(), "lodash");
        assert_eq!(requests[0].spec, VersionSpec::Exact("4.17.21".into()));
    }

    #[test]
    fn file_unknown_claimed_by_nobody() {
        assert!(
            Registry::builtin()
                .resolve(
                    &LockSpec::parse("Cargo.lock").expect("parses"),
                    "Cargo.lock",
                    &LockHead::of(b"[[package]]"),
                )
                .is_err()
        );
    }

    #[test]
    fn lock_malformed_json_is_error() {
        assert!(PackageLock.parse(b"not json").is_err());
    }
}
