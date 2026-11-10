//! The layout of a Remote repository's cache catalog, shared by the lister,
//! the catalog source, and the enumerator.
//!
//! A Remote (proxy) repository answers its artifact listing from the
//! server's `proxy_cache_artifacts` catalog.  Each row is a file the server
//! cached, under the path a client fetched it by, which is not the layout a
//! hosted repository stores:
//!
//! | Ecosystem | Cached path |
//! | --- | --- |
//! | maven | `org/example/lib/1.0/lib-1.0.jar`, as hosted |
//! | npm | `@scope/name/-/name-1.0.0.tgz` |
//! | pypi | `simple/{normalized}/{file}` |
//! | raw | the upstream's path, read through the `mapping` |
//!
//! The server leaves index pages and npm packuments out of the listing, so
//! every row is a file of some version.
//!
//! # Files are fetched through the format route
//!
//! `{base}/{format}/{repository}/{path}` serves a cached path for every
//! format, and passes it through the repository's scan gate.  The generic
//! `/download/` route refuses a Remote miss on a repository that scans on
//! proxy (Artifact Keeper #4442), so it is used only for raw files.

use super::api::{download_url, encode_path, prefix_of};
use crate::model::{ArtifactId, EcosystemId, Version};
use crate::net::encode_unreserved;
use crate::repo::Mapping;

/// The directory npm's tarball URLs put between a name and its file.
pub(super) const NPM_TARBALLS: &str = "-";

/// PyPI's cached simple index sits under this directory.
const PYPI_SIMPLE: &str = "simple";

/// A PEP 658 core-metadata file, which the server caches beside the
/// distribution it describes.  Not a distribution, and not malformed.
const PYPI_CORE_METADATA: &str = ".metadata";

/// What one cached path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Cached {
    /// Maven's group, or npm's `@scope`.
    pub(super) namespace: Option<String>,
    pub(super) name: String,

    /// `None` only for a raw mapping that reads no version.
    pub(super) version: Option<String>,
}

impl Cached {
    /// Whether this path belongs to `id`.
    pub(super) fn is(&self, id: &ArtifactId) -> bool {
        match id.ecosystem().as_str() {
            EcosystemId::PYPI => {
                crate::ecosystem::pypi::normalize(&self.name)
                    == crate::ecosystem::pypi::normalize(id.name())
            }
            EcosystemId::RAW => self.name == id.name().trim_matches('/'),
            _ => self.namespace.as_deref() == id.namespace() && self.name == id.name(),
        }
    }
}

/// Whether a cached file is one to pass over without a word: it is about a
/// file rather than one, and is no layout error.
pub(super) fn skipped(ecosystem: &EcosystemId, name: &str) -> bool {
    ecosystem.as_str() == EcosystemId::PYPI && name.ends_with(PYPI_CORE_METADATA)
}

/// The coordinate a cached path names, or `None` where the path is not
/// that ecosystem's cache layout.
pub(super) fn coordinate(ecosystem: &EcosystemId, mapping: Mapping, path: &str) -> Option<Cached> {
    let path = path.trim_matches('/');

    match ecosystem.as_str() {
        EcosystemId::MAVEN => {
            let (directory, _) = path.rsplit_once('/')?;
            let (group, artifact, version) = crate::repo::maven::layout_of(directory)?;

            Some(Cached {
                namespace: Some(group),
                name: artifact.to_owned(),
                version: Some(version.to_owned()),
            })
        }

        EcosystemId::NPM => {
            let (scope, name, version) = npm_coordinate(path)?;

            // A cache holds only tarballs, under `-`; the stored layout's
            // version directory is a hosted repository's.
            if !path.contains(&format!("/{NPM_TARBALLS}/")) {
                return None;
            }

            Some(Cached {
                namespace: scope.map(str::to_owned),
                name: name.to_owned(),
                version: Some(version.to_owned()),
            })
        }

        EcosystemId::PYPI => {
            let (project, version) = pypi_coordinate(path)?;

            Some(Cached {
                namespace: None,
                name: project.to_owned(),
                version: Some(version.to_owned()),
            })
        }

        // Raw: what the mapping reads.
        _ => {
            let at = mapping.read(path)?;

            Some(Cached {
                namespace: None,
                name: at.name,
                version: at.version,
            })
        }
    }
}

/// `@scope/name/-/name-1.0.0.tgz` or `name/-/name-1.0.0.tgz`, the shape the
/// listing reports; also the stored `name/1.0.0/name-1.0.0.tgz`, which the
/// listing of a hosted repository leaves alone when it cannot rewrite it.
///
/// The version is read from the file name, which is the only place the
/// URL shape carries it.
pub(super) fn npm_coordinate(path: &str) -> Option<(Option<&str>, &str, &str)> {
    let segments: Vec<&str> = path.split('/').collect();

    let (scope, rest) = match segments.split_first() {
        Some((scope, rest)) if scope.starts_with('@') => (Some(*scope), rest),
        _ => (None, segments.as_slice()),
    };

    let [name, middle, file] = rest else {
        return None;
    };

    let version = file
        .strip_prefix(*name)?
        .strip_prefix('-')?
        .strip_suffix(".tgz")?;

    if version.is_empty() || (*middle != NPM_TARBALLS && *middle != version) {
        return None;
    }

    Some((scope, name, version))
}

/// `simple/{project}/{file}`, with the version read from the file name.
///
/// The file's own name must start with the project's, so a file cached
/// under the wrong project is not read as that project's.
fn pypi_coordinate(path: &str) -> Option<(&str, &str)> {
    let segments: Vec<&str> = path.split('/').collect();

    let [PYPI_SIMPLE, project, file] = segments.as_slice() else {
        return None;
    };

    let project_prefix = format!("{}-", crate::ecosystem::pypi::normalize(project));

    if project.is_empty() || !crate::ecosystem::pypi::normalize(file).starts_with(&project_prefix) {
        return None;
    }

    Some((project, crate::repo::pypi::version_of(file)?))
}

/// The listing prefix that reaches every cached version of `id`.
pub(super) fn name_prefix(id: &ArtifactId, mapping: Mapping) -> String {
    match id.ecosystem().as_str() {
        EcosystemId::MAVEN => format!("{}/", maven_directory(id)),
        EcosystemId::NPM => format!("{}/{NPM_TARBALLS}/", npm_name(id)),
        EcosystemId::PYPI => pypi_directory(id),
        _ => prefix_of(mapping, id.name().trim_matches('/'), None),
    }
}

/// The listing prefix that reaches every cached file of one version.
///
/// Wider than the version, as every literal prefix is: `1.0` reaches
/// `1.0.1`, and PyPI caches every version in one directory.  Callers keep
/// only what [`coordinate`] reads as this version.
pub(super) fn version_prefix(id: &ArtifactId, version: &Version, mapping: Mapping) -> String {
    match id.ecosystem().as_str() {
        EcosystemId::MAVEN => format!("{}/{}/", maven_directory(id), version.text()),
        EcosystemId::NPM => format!(
            "{}/{NPM_TARBALLS}/{}-{}",
            npm_name(id),
            id.name(),
            version.text()
        ),
        EcosystemId::PYPI => pypi_directory(id),
        _ => prefix_of(mapping, id.name().trim_matches('/'), Some(version)),
    }
}

/// Where a cached file is fetched; see the module documentation.
pub(super) fn file_url(
    base_url: &str,
    ecosystem: &EcosystemId,
    repository: &str,
    path: &str,
) -> String {
    let path = path.trim_start_matches('/');

    let encoded = match ecosystem.as_str() {
        EcosystemId::RAW => return download_url(base_url, repository, path),

        // The npm routes match a literal `@` on the scope, and answer no
        // `%40` spelling of it.
        EcosystemId::NPM => path
            .split('/')
            .map(|segment| match segment.strip_prefix('@') {
                Some(scope) => format!("@{}", encode_unreserved(scope)),
                None => encode_unreserved(segment),
            })
            .collect::<Vec<_>>()
            .join("/"),

        _ => encode_path(path),
    };

    format!(
        "{base_url}/{ecosystem}/{}/{encoded}",
        encode_unreserved(repository)
    )
}

/// `org/example/lib`.
fn maven_directory(id: &ArtifactId) -> String {
    format!(
        "{}/{}",
        id.namespace().unwrap_or_default().replace('.', "/"),
        id.name()
    )
}

/// `@scope/name` or `name`.
fn npm_name(id: &ArtifactId) -> String {
    match id.namespace() {
        Some(scope) => format!("{scope}/{}", id.name()),
        None => id.name().to_owned(),
    }
}

/// `simple/{normalized}/`.
fn pypi_directory(id: &ArtifactId) -> String {
    format!(
        "{PYPI_SIMPLE}/{}/",
        crate::ecosystem::pypi::normalize(id.name())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Release;

    fn read(ecosystem: EcosystemId, path: &str) -> Option<Cached> {
        coordinate(&ecosystem, Mapping::default(), path)
    }

    fn version(text: &str) -> Version {
        Version::new(text, Release::General)
    }

    #[test]
    fn coordinate_pypi_from_simple_path() {
        let cached = read(
            EcosystemId::pypi(),
            "simple/my-pkg/my_pkg-1.0-py3-none-any.whl",
        )
        .expect("reads");

        assert_eq!(cached.name, "my-pkg");
        assert_eq!(cached.version.as_deref(), Some("1.0"));
        assert!(cached.is(&ArtifactId::new(EcosystemId::pypi(), None, "My_Pkg")));

        assert_eq!(
            read(
                EcosystemId::pypi(),
                "simple/requests/requests-2.31.0.tar.gz"
            )
            .and_then(|c| c.version),
            Some("2.31.0".to_owned())
        );
    }

    #[test]
    fn coordinate_pypi_refuses_other_shapes() {
        // A hosted repository's stored layout.
        assert_eq!(
            read(EcosystemId::pypi(), "my-pkg/1.0/my_pkg-1.0.tar.gz"),
            None
        );

        // Another project's file.
        assert_eq!(
            read(EcosystemId::pypi(), "simple/requests/urllib3-2.0.tar.gz"),
            None
        );
    }

    #[test]
    fn coordinate_npm_tarballs_only() {
        let cached = read(EcosystemId::npm(), "@acme/widget/-/widget-2.0.0.tgz").expect("reads");

        assert_eq!(cached.namespace.as_deref(), Some("@acme"));
        assert_eq!(cached.name, "widget");
        assert_eq!(cached.version.as_deref(), Some("2.0.0"));

        // The hosted stored layout is not a cache path.
        assert_eq!(
            read(EcosystemId::npm(), "left-pad/1.3.0/left-pad-1.3.0.tgz"),
            None
        );
    }

    #[test]
    fn coordinate_maven_as_hosted() {
        let cached = read(EcosystemId::maven(), "org/example/lib/1.0/lib-1.0.jar").expect("reads");

        assert!(cached.is(&ArtifactId::new(
            EcosystemId::maven(),
            Some("org.example"),
            "lib"
        )));
        assert_eq!(cached.version.as_deref(), Some("1.0"));
    }

    #[test]
    fn skipped_pypi_core_metadata() {
        assert!(skipped(
            &EcosystemId::pypi(),
            "pkg-1.0-py3-none-any.whl.metadata"
        ));
        assert!(!skipped(&EcosystemId::pypi(), "pkg-1.0.tar.gz"));
        assert!(!skipped(&EcosystemId::maven(), "lib-1.0.metadata"));
    }

    #[test]
    fn prefixes_follow_cache_layout() {
        let maven = ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib");
        let npm = ArtifactId::new(EcosystemId::npm(), Some("@acme"), "widget");
        let pypi = ArtifactId::new(EcosystemId::pypi(), None, "My_Pkg");
        let mapping = Mapping::default();

        assert_eq!(name_prefix(&maven, mapping), "org/example/lib/");
        assert_eq!(
            version_prefix(&maven, &version("1.0"), mapping),
            "org/example/lib/1.0/"
        );
        assert_eq!(name_prefix(&npm, mapping), "@acme/widget/-/");
        assert_eq!(
            version_prefix(&npm, &version("2.0.0"), mapping),
            "@acme/widget/-/widget-2.0.0"
        );
        assert_eq!(name_prefix(&pypi, mapping), "simple/my-pkg/");
        assert_eq!(
            version_prefix(&pypi, &version("1.0"), mapping),
            "simple/my-pkg/"
        );
    }

    #[test]
    fn file_url_uses_format_route() {
        const BASE: &str = "h://keeper.test";

        assert_eq!(
            file_url(
                BASE,
                &EcosystemId::pypi(),
                "pypi-remote",
                "simple/requests/requests-2.31.0.tar.gz"
            ),
            "h://keeper.test/pypi/pypi-remote/simple/requests/requests-2.31.0.tar.gz"
        );
        assert_eq!(
            file_url(
                BASE,
                &EcosystemId::npm(),
                "npm-remote",
                "@acme/widget/-/widget-2.0.0.tgz"
            ),
            "h://keeper.test/npm/npm-remote/@acme/widget/-/widget-2.0.0.tgz"
        );
        assert_eq!(
            file_url(BASE, &EcosystemId::raw(), "files", "tools/fmt.zip"),
            "h://keeper.test/api/v1/repositories/files/download/tools/fmt.zip"
        );
    }
}
