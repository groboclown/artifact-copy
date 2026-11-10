//! Folding AQL file rows into artifacts, shared by every Artifactory
//! enumerator.
//!
//! The walks differ (a sorted offset on Pro, a `created` window on OSS)
//! but a row means the same thing to both, so recovering a coordinate and
//! grouping files under it lives here once.

use std::collections::BTreeMap;

use super::row::Row;
use crate::core::ctx::Ctx;
use crate::core::problem::Code;
use crate::message;
use crate::model::LastDownload;
use crate::model::{ArtifactId, EcosystemId, Release, Version};
use crate::repo::Mapping;
use crate::repo::enumerate::{Found, Listed};

/// What an AQL query asks of each row.
pub(super) const INCLUDE: &str = r#".include("repo","path","name","size","actual_sha1","actual_md5","sha256","stat.downloaded","property.*")"#;

/// Files that belong to the repository rather than to an artifact.
///
/// Checksums and signatures are *about* an artifact and are never one, so
/// folding them in would be right and emitting them would not. Maven
/// metadata is the repository's own index -- the same rule `repo::maven`
/// applies, for the same reason.
fn is_not_an_artifact(name: &str) -> bool {
    // Kept apart from `ecosystem::joins_listing`: this decides whether a
    // row can name an artifact, which a signature never does, and that
    // decides whether a row is one of an artifact's files.
    const SIDECARS: [&str; 5] = [".sha1", ".sha256", ".sha512", ".md5", ".asc"];

    if name.starts_with("maven-metadata") || name == "_remote.repositories" {
        return true;
    }

    SIDECARS.iter().any(|suffix| name.ends_with(suffix))
}

/// Whether a row is a detached signature.
fn is_signature(name: &str) -> bool {
    name.ends_with(".asc")
}

/// One repository's rows, read as one ecosystem's artifacts.
pub(super) struct Folder {
    base_url: String,
    repository: String,
    ecosystem: EcosystemId,

    /// How a raw repository's paths become coordinates; unread for every
    /// other ecosystem.
    mapping: Mapping,
}

impl Folder {
    pub(super) fn new(
        base_url: String,
        repository: String,
        ecosystem: EcosystemId,
        mapping: Mapping,
    ) -> Self {
        Self {
            base_url,
            repository,
            ecosystem,
            mapping,
        }
    }

    pub(super) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(super) fn repository(&self) -> &str {
        &self.repository
    }

    pub(super) fn ecosystem(&self) -> &EcosystemId {
        &self.ecosystem
    }

    /// Fold a page of files into the artifacts they belong to.
    ///
    /// Keyed by coordinate, so the jar and the POM of one version become
    /// one entry, and its last download is the most recent across them --
    /// fetching any file of an artifact is using it. Each row that belongs
    /// to its artifact is listed as one of its files.
    ///
    /// A Maven `.asc` joins the artifact of the file it signs, read from
    /// the same layout path, but never makes one: a signature with nothing
    /// beside it on this page is not evidence of an artifact.
    pub(super) fn fold(&self, rows: &[Row], ctx: &Ctx) -> Vec<Found> {
        let mut artifacts: BTreeMap<(String, Option<String>), Found> = BTreeMap::new();

        for row in rows.iter().filter(|row| self.can_name(&row.name)) {
            let Some((id, version)) = self.coordinate(row, ctx) else {
                continue;
            };

            let key = (id.purl(), version.as_ref().map(|v| v.text().to_owned()));
            let downloaded = row.last_download();
            let found = artifacts.entry(key).or_insert_with(|| {
                Found::new(id)
                    .last_download(LastDownload::Unknown)
                    .maybe_version(version)
            });

            found.last_download = later_of(found.last_download, downloaded);
            self.list(found, row);
        }

        if self.ecosystem.as_str() == EcosystemId::MAVEN {
            for row in rows.iter().filter(|row| is_signature(&row.name)) {
                let Some((id, version)) = self.coordinate(row, ctx) else {
                    continue;
                };

                let key = (id.purl(), version.as_ref().map(|v| v.text().to_owned()));

                if let Some(found) = artifacts.get_mut(&key) {
                    self.list(found, row);
                }
            }
        }

        artifacts.into_values().collect()
    }

    /// Whether a row can name an artifact on its own.
    ///
    /// Every raw file can: a raw repository's `fmt.zip.sha256` is a file
    /// somebody published, with no convention saying what it is about.
    /// The directory mapping still folds it beside `fmt.zip`.
    fn can_name(&self, name: &str) -> bool {
        if self.ecosystem.as_str() == EcosystemId::RAW {
            return true;
        }

        !is_signature(name) && !is_not_an_artifact(name)
    }

    /// Add one row to its artifact's files, when it belongs there.
    fn list(&self, found: &mut Found, row: &Row) {
        if !crate::ecosystem::joins_listing(&self.ecosystem, &row.name) {
            return;
        }

        if found.files.iter().any(|file| file.name == row.name) {
            return;
        }

        found.files.push(Listed {
            name: row.name.clone(),
            url: self.file_url(row),
            size: row.size,
            digests: row.digests(),
        });
    }

    /// Where one row's file is served: `{base}/{repository}/{path}/{name}`.
    ///
    /// AQL spells a file at the repository root with the path `.`.
    fn file_url(&self, row: &Row) -> String {
        format!(
            "{}/{}/{}",
            self.base_url,
            self.repository,
            Self::stored_path(row)
        )
    }

    /// One row's path in the repository: `{path}/{name}`.
    ///
    /// AQL spells a file at the repository root with the path `.`.
    fn stored_path(row: &Row) -> String {
        match row.path.trim_matches('/') {
            "" | "." => row.name.clone(),
            path => format!("{path}/{}", row.name),
        }
    }

    /// Recover an artifact's coordinate from one file row.
    fn coordinate(&self, row: &Row, ctx: &Ctx) -> Option<(ArtifactId, Option<Version>)> {
        match self.ecosystem.as_str() {
            EcosystemId::MAVEN => self.coordinate_from_layout(row, ctx),
            EcosystemId::RAW => self.coordinate_from_mapping(row, ctx),
            _ => self.coordinate_from_properties(row, ctx),
        }
    }

    /// The coordinate the `mapping` reads from a raw row's path.
    ///
    /// A path the mapping does not fit is a finding rather than a failure:
    /// one stray file must not fail a walk of a million laid out correctly.
    fn coordinate_from_mapping(
        &self,
        row: &Row,
        ctx: &Ctx,
    ) -> Option<(ArtifactId, Option<Version>)> {
        let path = Self::stored_path(row);

        let Some(at) = self.mapping.read(&path) else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "artifactory-raw-path-unmapped",
                    "{path} in {repository} does not fit the {mapping} mapping; \
                     it is skipped",
                    path = &path,
                    repository = &self.repository,
                    mapping = self.mapping.as_str(),
                ),
            );

            return None;
        };

        Some((
            ArtifactId::new(self.ecosystem.clone(), None, &at.name),
            at.version.map(|text| self.classify(&text)),
        ))
    }

    /// Maven's repository layout, which is a published specification; see
    /// [`crate::repo::maven::layout_of`].
    fn coordinate_from_layout(
        &self,
        row: &Row,
        ctx: &Ctx,
    ) -> Option<(ArtifactId, Option<Version>)> {
        let Some((group, artifact, version)) = crate::repo::maven::layout_of(&row.path) else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "artifactory-unreadable-layout",
                    "{path} is not a Maven layout path, so no coordinate can be read \
                     from it; it is skipped",
                    path = &row.path,
                ),
            );

            return None;
        };

        Some((
            ArtifactId::new(self.ecosystem.clone(), Some(&group), artifact),
            Some(self.classify(version)),
        ))
    }

    /// The properties Artifactory attaches when it indexes a package.
    fn coordinate_from_properties(
        &self,
        row: &Row,
        ctx: &Ctx,
    ) -> Option<(ArtifactId, Option<Version>)> {
        let prefix = self.ecosystem.as_str();

        let Some(name) = row.property(&format!("{prefix}.name")) else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "artifactory-missing-package-properties",
                    "{path}/{file} carries no {prefix}.name property, so no coordinate \
                     can be read from it; it is skipped",
                    path = &row.path,
                    file = &row.name,
                    prefix = prefix,
                ),
            );

            return None;
        };

        let version = row
            .property(&format!("{prefix}.version"))
            .map(|text| self.classify(&text));

        // An npm scope arrives inside the name, as `@scope/name`.
        let (namespace, bare) = match self.ecosystem.as_str() {
            EcosystemId::NPM => match name.strip_prefix('@').and_then(|r| r.split_once('/')) {
                Some((scope, bare)) => (Some(format!("@{scope}")), bare.to_owned()),
                None => (None, name),
            },
            _ => (None, name),
        };

        Some((
            ArtifactId::new(self.ecosystem.clone(), namespace.as_deref(), &bare),
            version,
        ))
    }

    fn classify(&self, version: &str) -> Version {
        match crate::ecosystem::open(self.ecosystem.as_str()) {
            Ok(ecosystem) => ecosystem.version(version),
            Err(_) => Version::new(version, Release::PreRelease),
        }
    }
}

/// The later of two download times, preferring evidence over its absence.
///
/// `Unknown` loses to anything: one file of an artifact reporting a
/// download is evidence about the artifact, whatever the others say.
/// `Never` loses to a real timestamp for the same reason.
fn later_of(left: LastDownload, right: LastDownload) -> LastDownload {
    match (left, right) {
        (LastDownload::At(a), LastDownload::At(b)) => LastDownload::At(a.max(b)),

        (LastDownload::At(when), _) | (_, LastDownload::At(when)) => LastDownload::At(when),

        (LastDownload::Never, _) | (_, LastDownload::Never) => LastDownload::Never,

        _ => LastDownload::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_artifact_files_recognized() {
        for name in [
            "a-1.0.jar.sha1",
            "a-1.0.jar.sha256",
            "a-1.0.jar.sha512",
            "a-1.0.jar.md5",
            "a-1.0.jar.asc",
            "maven-metadata.xml",
            "maven-metadata-central.xml",
            "_remote.repositories",
        ] {
            assert!(is_not_an_artifact(name), "{name}");
        }

        for name in ["a-1.0.jar", "a-1.0.pom", "a-1.0-sources.jar", "a-1.0.tgz"] {
            assert!(!is_not_an_artifact(name), "{name}");
        }
    }

    /// Evidence beats its absence: one file reporting a download says
    /// something about the artifact whatever the others say.
    #[test]
    fn last_download_real_beats_never_and_unknown() {
        let when = chrono::Utc::now();

        assert_eq!(
            later_of(LastDownload::Never, LastDownload::At(when)),
            LastDownload::At(when)
        );
        assert_eq!(
            later_of(LastDownload::Unknown, LastDownload::At(when)),
            LastDownload::At(when)
        );
        assert_eq!(
            later_of(LastDownload::Unknown, LastDownload::Never),
            LastDownload::Never
        );
        assert_eq!(
            later_of(LastDownload::Unknown, LastDownload::Unknown),
            LastDownload::Unknown
        );
    }
}
