//! Reading an Artifactory generic repository.
//!
//! A generic repository has no protocol, so the storage API is the whole
//! source, as the artifact listing is for an Artifact Keeper generic one:
//!
//! ```text
//!   GET {base}/api/storage/{repo}/{name}             directory, as-is
//!   GET {base}/api/storage/{repo}/{name}/{version}   name-version-file
//!   GET {base}/api/storage/{repo}/{path}/{file}      each file a folder holds
//! ```
//!
//! Every path is read again through the [`Mapping`] and kept only where it
//! names the artifact asked for, before its file is asked about: a folder
//! that `as-is` names is not an artifact, and a sub-folder is never part
//! of its parent's.
//!
//! **The repository's package type is never checked.** Older repositories
//! typed "Ivy" hold the same kind of content, so the type is not evidence
//! of the layout, and refusing one would leave its files unmigratable.

use std::sync::Arc;

use async_trait::async_trait;

use super::storage::{Entry, Info, Storage};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::ExtHost;
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::Expectation;
use crate::repo::{Downloaded, Mapping, Source};
use crate::version::VersionHandler;

/// One stored file of an artifact.
pub(super) struct Held {
    /// Its path in the repository, already encoded.
    path: String,

    /// Its name in the artifact.
    file: String,

    /// Its info, where finding it already fetched it.
    info: Option<Info>,
}

pub(super) struct ArtifactoryRawSource {
    storage: Storage,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    mapping: Mapping,
    ecosystem: crate::ecosystem::Raw,
}

impl ArtifactoryRawSource {
    pub(super) fn new(
        base_url: String,
        host: Arc<dyn ExtHost>,
        repository: String,
        mapping: Mapping,
    ) -> Self {
        Self {
            storage: Storage::new(base_url, Arc::clone(&host), repository),
            host,
            mapping,
            ecosystem: crate::ecosystem::Raw,
        }
    }

    /// The path that holds the artifact: a folder of its files, or the
    /// file itself.
    fn holder(&self, name: &str, version: Option<&Version>) -> String {
        match (self.mapping, version) {
            (Mapping::NameVersionFile, Some(version)) => format!("{name}/{}", version.text()),
            _ => name.to_owned(),
        }
    }

    /// The file name, where the mapping reads `path` as the artifact asked
    /// for.
    fn file_of(&self, path: &str, name: &str, version: Option<&str>) -> Option<String> {
        let at = self.mapping.read(path)?;

        (at.name == name && at.version.as_deref() == version).then_some(at.file)
    }

    /// The artifact's stored files.
    ///
    /// A folder's files are read back through the mapping by name, so
    /// their info is not fetched here; a file the holder path names
    /// arrives with its info.
    pub(super) async fn held(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<Vec<Held>> {
        let name = id.name().trim_matches('/');
        let wanted = version.map(Version::text);
        let holder = self.holder(name, version);
        let encoded = Storage::encode(&holder);
        let mut held = Vec::new();

        match self.storage.entry(&encoded, ctx).await? {
            Entry::Missing => {}

            Entry::File(info) => {
                if let Some(file) = self.file_of(&holder, name, wanted) {
                    held.push(Held {
                        path: encoded,
                        file,
                        info: Some(info),
                    });
                }
            }

            Entry::Folder { files, .. } => {
                for child in files {
                    let path = format!("{holder}/{child}");

                    let Some(file) = self.file_of(&path, name, wanted) else {
                        continue;
                    };

                    held.push(Held {
                        path: Storage::encode(&path),
                        file,
                        info: None,
                    });
                }
            }
        }

        Ok(held)
    }

    /// Whether a folder holds files of its own.
    async fn holds_files(&self, path: &str, ctx: &Ctx) -> Result<bool> {
        match self.storage.entry(&Storage::encode(path), ctx).await? {
            Entry::Folder { files, .. } => Ok(!files.is_empty()),
            Entry::Missing | Entry::File(_) => Ok(false),
        }
    }
}

#[async_trait]
impl Source for ArtifactoryRawSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![EcosystemId::raw()]
    }

    /// Only where the mapping declares a segment is a version.
    fn versioned(&self, _: &ArtifactId) -> bool {
        self.mapping == Mapping::NameVersionFile
    }

    /// The sub-folders of `name` that hold files of their own.
    ///
    /// A request per sub-folder, because a sub-folder holding only folders
    /// is a deeper name rather than a version: `tools/fmt/cli/2.0/cli.zip`
    /// is `tools/fmt/cli` at `2.0`, not `tools/fmt` at `cli`.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        if !self.versioned(id) {
            return Ok(Vec::new());
        }

        let name = id.name().trim_matches('/');
        let Entry::Folder { folders, .. } = self.storage.entry(&Storage::encode(name), ctx).await?
        else {
            return Ok(Vec::new());
        };

        let mut found = Vec::new();

        for folder in folders {
            if self.holds_files(&format!("{name}/{folder}"), ctx).await? {
                found.push(folder);
            }
        }

        // Sorted by text rather than kept in listing order: a listing order
        // is not a version order.
        found.sort();

        Ok(self.ecosystem.classify(&found))
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let held = self.held(id, version, ctx).await?;

        if held.is_empty() {
            let holder = self.holder(id.name().trim_matches('/'), version);

            // `Absent`, so a proxy asks its next upstream.
            return Err(Error::Absent {
                what: "artifact",
                url: self.storage.served(&Storage::encode(&holder)),
                name: id.purl(),
            });
        }

        // Each (encoded path, published name, info) the artifact holds.
        let mut mine: Vec<(String, String, Info)> = Vec::new();

        for Held { path, file, info } in held {
            let info = match info {
                Some(info) => info,
                None => self.storage.info(&path, ctx).await?,
            };

            mine.push((path, file, info));
        }

        let files: Vec<FileRef> = mine
            .iter()
            .map(|(path, file, info)| self.storage.file(path, file, info))
            .collect();

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: version.cloned(),
            files,

            // A generic repository declares none.
            license: None,

            // The newest: a publish window asks whether anything here is
            // too new to trust yet.
            published: mine
                .iter()
                .filter_map(|(_, _, info)| info.published())
                .max(),
        })
    }

    /// None: a generic repository publishes no dependency information.
    async fn deps(&self, _: &ResolvedArtifact, _: &Ctx) -> Result<Vec<Dependency>> {
        Ok(Vec::new())
    }

    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        crate::repo::download(&*self.host, file, expect, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.host.permits(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::TestHost;
    use crate::model::Cause;
    use crate::net::{Canned, FixtureClient};
    use http::StatusCode;

    const BASE: &str = "h://artifactory.test";
    const REPO: &str = "generic-a";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "raw".into() })
    }

    fn storage(path: &str) -> String {
        format!("{BASE}/api/storage/{REPO}/{path}")
    }

    fn source(mapping: Mapping, client: FixtureClient) -> ArtifactoryRawSource {
        ArtifactoryRawSource::new(
            BASE.into(),
            Arc::new(TestHost::new(client)),
            REPO.into(),
            mapping,
        )
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, name)
    }

    fn file_info(path: &str) -> String {
        format!(
            r#"{{"downloadUri": "{BASE}/{REPO}/{path}", "size": "7",
                "checksums": {{"sha256": "aa"}},
                "created": "2026-09-29T15:42:48.678Z",
                "lastModified": "2026-10-05T16:15:05.407Z"}}"#
        )
    }

    fn names(artifact: &ResolvedArtifact) -> Vec<&str> {
        artifact.files.iter().map(|f| f.name.as_str()).collect()
    }

    /// A sub-folder is a different artifact, so only the folder's own
    /// files are asked about.
    #[tokio::test]
    async fn directory_keeps_only_own_files() {
        let client = FixtureClient::new()
            .with_body(
                storage("tools/fmt"),
                r#"{"children": [
                    {"uri": "/fmt.zip", "folder": false},
                    {"uri": "/sub", "folder": true}
                ]}"#,
            )
            .with_body(storage("tools/fmt/fmt.zip"), file_info("tools/fmt/fmt.zip"));

        let artifact = source(Mapping::Directory, client)
            .metadata(&id("tools/fmt"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["fmt.zip"]);
        assert_eq!(artifact.files[0].size, Some(7));
        assert_eq!(
            artifact.files[0].url,
            format!("{BASE}/{REPO}/tools/fmt/fmt.zip")
        );
        assert!(artifact.published.is_some());
    }

    /// A file at the root has no folder to share and is its own artifact.
    #[tokio::test]
    async fn directory_root_file_own_artifact() {
        let client = FixtureClient::new().with_body(storage("notes.txt"), file_info("notes.txt"));

        let artifact = source(Mapping::Directory, client)
            .metadata(&id("notes.txt"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["notes.txt"]);
    }

    /// Under the directory mapping, `tools/fmt.zip` is a file of `tools`.
    #[tokio::test]
    async fn directory_nested_file_absent() {
        let client =
            FixtureClient::new().with_body(storage("tools/fmt.zip"), file_info("tools/fmt.zip"));

        let err = source(Mapping::Directory, client)
            .metadata(&id("tools/fmt.zip"), None, &ctx())
            .await
            .expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    #[tokio::test]
    async fn as_is_file_own_artifact() {
        let client =
            FixtureClient::new().with_body(storage("tools/fmt.zip"), file_info("tools/fmt.zip"));

        let artifact = source(Mapping::AsIs, client)
            .metadata(&id("tools/fmt.zip"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["fmt.zip"]);
    }

    /// A folder is no artifact under `as-is`, and its files are never
    /// asked about.
    #[tokio::test]
    async fn as_is_folder_absent() {
        let client = FixtureClient::new().with_body(
            storage("tools"),
            r#"{"children": [{"uri": "/fmt.zip", "folder": false}]}"#,
        );

        let err = source(Mapping::AsIs, client)
            .metadata(&id("tools"), None, &ctx())
            .await
            .expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    #[tokio::test]
    async fn metadata_missing_is_absent() {
        let client =
            FixtureClient::new().with(storage("nope"), Canned::status(StatusCode::NOT_FOUND));

        let err = source(Mapping::Directory, client)
            .metadata(&id("nope"), None, &ctx())
            .await
            .expect_err("absent");

        assert!(matches!(err, Error::Absent { .. }), "{err}");
    }

    #[tokio::test]
    async fn name_version_file_reads_version_folder() {
        let client = FixtureClient::new()
            .with_body(
                storage("tools/fmt/2.0"),
                r#"{"children": [
                    {"uri": "/fmt.zip", "folder": false},
                    {"uri": "/fmt.sig", "folder": false}
                ]}"#,
            )
            .with_body(
                storage("tools/fmt/2.0/fmt.zip"),
                file_info("tools/fmt/2.0/fmt.zip"),
            )
            .with_body(
                storage("tools/fmt/2.0/fmt.sig"),
                file_info("tools/fmt/2.0/fmt.sig"),
            );
        let version = Version::new("2.0", crate::model::Release::General);

        let artifact = source(Mapping::NameVersionFile, client)
            .metadata(&id("tools/fmt"), Some(&version), &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["fmt.zip", "fmt.sig"]);
        assert_eq!(artifact.version, Some(version));
    }

    /// A sub-folder holding only folders is a deeper name, not a version.
    #[tokio::test]
    async fn versions_folders_holding_files() {
        let client = FixtureClient::new()
            .with_body(
                storage("tools/fmt"),
                r#"{"children": [
                    {"uri": "/2.1", "folder": true},
                    {"uri": "/2.0", "folder": true},
                    {"uri": "/cli", "folder": true},
                    {"uri": "/README", "folder": false}
                ]}"#,
            )
            .with_body(
                storage("tools/fmt/2.1"),
                r#"{"children": [{"uri": "/fmt.zip", "folder": false}]}"#,
            )
            .with_body(
                storage("tools/fmt/2.0"),
                r#"{"children": [{"uri": "/fmt.zip", "folder": false}]}"#,
            )
            .with_body(
                storage("tools/fmt/cli"),
                r#"{"children": [{"uri": "/2.0", "folder": true}]}"#,
            );

        let versions = source(Mapping::NameVersionFile, client)
            .versions(&id("tools/fmt"), &ctx())
            .await
            .expect("lists");
        let mut texts: Vec<&str> = versions.iter().map(Version::text).collect();

        texts.sort();

        assert_eq!(texts, ["2.0", "2.1"]);
    }

    #[tokio::test]
    async fn directory_mapping_has_no_versions() {
        let source = source(Mapping::Directory, FixtureClient::new());

        assert!(!source.versioned(&id("tools/fmt")));
        assert!(
            source
                .versions(&id("tools/fmt"), &ctx())
                .await
                .expect("lists")
                .is_empty()
        );
    }

    /// Each segment is encoded on its own, so the separators survive.
    #[tokio::test]
    async fn segments_encoded_separately() {
        let client = FixtureClient::new()
            .with_body(
                storage("my%20tools"),
                r#"{"children": [{"uri": "/a b.zip", "folder": false}]}"#,
            )
            .with_body(storage("my%20tools/a%20b.zip"), r#"{"size": "1"}"#);

        let artifact = source(Mapping::Directory, client)
            .metadata(&id("my tools"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(names(&artifact), ["a b.zip"]);
        assert_eq!(
            artifact.files[0].url,
            format!("{BASE}/{REPO}/my%20tools/a%20b.zip")
        );
    }
}
