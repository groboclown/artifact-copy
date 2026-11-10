//! Writing to an Artifactory generic repository.
//!
//! A generic repository holds files under a path, so writing one is copying
//! each file to the path the mapping gives it -- the rule the Nexus and
//! Artifact Keeper raw targets follow. One deploy per file:
//!
//! ```text
//!   GET  {base}/api/storage/{repo}/{path}   what is there, before writing
//!   PUT  {base}/{repo}/{path}               X-Checksum-Sha256, -Sha1, -Md5
//! ```
//!
//! # A written path is replaced unless something guards it
//!
//! Artifactory OSS as admin overwrites a path with different bytes and
//! answers 201 (see `write-path.md`), so `overwrite-guard` defaults to
//! **`check`** here, unlike the other targets: every file is looked up
//! before any is sent. The same bytes are not sent again; different bytes
//! refuse the artifact with nothing written.
//!
//! `server` skips the lookups, for an account without overwrite
//! permission. A refusal, 403, is then answered by the same comparison.
//!
//! # Every upload carries its checksums
//!
//! `X-Checksum-Sha256` from the staged bytes, and SHA-1 and MD5 where the
//! source declared them, so the stored file serves every sidecar a client
//! may ask for; Artifactory serves only the ones it was given.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;

use super::raw::ArtifactoryRawSource;
use super::storage::{Entry, Storage};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, DigestAlg, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::{Req, normalized_base};
use crate::repo::{Companions, Coordinate, Delivered, Delivery, Mapping, OverwriteGuard, Target};

/// What the repository holds at a path, against the staged file.
#[derive(Debug, PartialEq, Eq)]
enum Stored {
    Absent,
    Same,

    /// Something else, or something with no checksum to compare; described
    /// for the refusal.
    Different(String),
}

/// One file of the artifact, and where it lands.
struct Placed<'a> {
    file: &'a FileRef,
    staged: &'a Path,

    /// Already encoded.
    path: String,
    sha256: String,
}

pub(super) struct ArtifactoryGenericTarget {
    storage: Storage,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    mapping: Mapping,
    guard: OverwriteGuard,

    /// The same repository read as a source, which already knows how to
    /// find what it holds.
    reader: ArtifactoryRawSource,
    ecosystem: crate::ecosystem::Raw,
}

impl ArtifactoryGenericTarget {
    /// Build from configuration.
    ///
    /// The repository is required, since one server holds many. The
    /// mapping defaults to [`Mapping::Directory`], as the source's does, so
    /// a copy between two repositories that both leave it unset puts every
    /// file back where it was.
    pub(super) fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let repository = options
            .require_string(crate::ext::options::REPOSITORY)?
            .to_owned();
        let mapping = crate::repo::manager::raw_mapping(options, &EcosystemId::raw())?;
        let guard = OverwriteGuard::from_options_or(options, OverwriteGuard::Check)?;
        let base_url = normalized_base(base_url);

        Ok(Self {
            storage: Storage::new(base_url.clone(), Arc::clone(&host), repository.clone()),
            reader: ArtifactoryRawSource::new(base_url, Arc::clone(&host), repository, mapping),
            host,
            mapping,
            guard,
            ecosystem: crate::ecosystem::Raw,
        })
    }

    /// Where one file of an artifact lands, encoded.
    ///
    /// Refused rather than written when the path would not read back as
    /// this artifact, as the Artifact Keeper target refuses it.
    fn path_for(&self, artifact: &ResolvedArtifact, file: &str) -> Result<String> {
        let at = Coordinate {
            name: artifact.id.name().trim_matches('/').to_owned(),
            version: artifact.version.as_ref().map(|v| v.text().to_owned()),
            file: file.to_owned(),
        };

        let path = self.mapping.path(&at);

        if at.name.is_empty() || file.is_empty() || self.mapping.read(&path).as_ref() != Some(&at) {
            return Err(Error::BadRequest {
                ecosystem: "raw",
                text: artifact.purl(),
                detail: format!(
                    "file {file:?} would be written to {path:?}, which the {} mapping \
                     does not read back as this artifact",
                    self.mapping.as_str()
                ),
            });
        }

        Ok(Storage::encode(&path))
    }

    /// What the repository holds where `placed` lands.
    async fn stored(&self, placed: &Placed<'_>, ctx: &Ctx) -> Result<Stored> {
        let info = match self.storage.entry(&placed.path, ctx).await? {
            Entry::Missing => return Ok(Stored::Absent),
            Entry::Folder { .. } => return Ok(Stored::Different("a folder".to_owned())),
            Entry::File(info) => info,
        };

        Ok(match info.sha256() {
            Some(held) if held.eq_ignore_ascii_case(&placed.sha256) => Stored::Same,
            Some(held) => Stored::Different(format!("sha256 {held}")),
            None => Stored::Different("no sha256 to compare".to_owned()),
        })
    }

    /// The refusal for a path holding something else.
    fn conflict(&self, placed: &Placed<'_>, held: &str) -> Error {
        Error::Integrity(format!(
            "{} already holds a different file ({held}), and a written path is not \
             replaced; the file being copied has sha256 {}",
            self.storage.served(&placed.path),
            placed.sha256
        ))
    }

    /// Deploy one file, with every checksum it has.
    async fn put(&self, placed: &Placed<'_>, ctx: &Ctx) -> Result<()> {
        let mut req = Req::put(self.storage.served(&placed.path))
            .header("content-type", "application/octet-stream")
            .header("x-checksum-sha256", &placed.sha256);

        // The weaker digests too, where the source declared them; SHA-256
        // above is the one computed here.
        for digest in &placed.file.digests {
            let name = match digest.alg {
                DigestAlg::Sha1 => "x-checksum-sha1",
                DigestAlg::Md5 => "x-checksum-md5",
                DigestAlg::Sha256 | DigestAlg::Sha512 => continue,
            };

            req = req.header(name, &digest.hex);
        }

        self.host
            .send_file(
                &req,
                placed.staged,
                self.host.constraints().max_in_memory(),
                ctx,
            )
            .await?;

        Ok(())
    }

    /// Send one file; under `server`, answer a refusal by comparing.
    async fn send(&self, placed: &Placed<'_>, ctx: &Ctx) -> Result<Delivered> {
        let refused = match self.put(placed, ctx).await {
            Ok(()) => return Ok(Delivered::Uploaded),
            // HTTP 403: an account without overwrite permission refusing a rewrite.
            Err(err @ Error::HttpStatus { status, .. }) if status == StatusCode::FORBIDDEN => err,
            Err(err) => return Err(err),
        };

        // A 403 is also an account that may not deploy at all, which the
        // path being absent tells apart.
        match self.stored(placed, ctx).await? {
            Stored::Same => Ok(Delivered::AlreadyPresent),
            Stored::Different(held) => Err(self.conflict(placed, &held)),
            Stored::Absent => Err(refused),
        }
    }
}

#[async_trait]
impl Target for ArtifactoryGenericTarget {
    /// Raw artifacts only, for the reason the Artifact Keeper target gives.
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    /// Whether any file of this artifact is already there.
    ///
    /// **Any**, not all, as the Artifact Keeper target answers: this target
    /// cannot be asked which files a version should have.
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        if self.mapping == Mapping::NameVersionFile {
            crate::repo::version_required(id, version)?;
        }

        Ok(!self.reader.held(id, version, ctx).await?.is_empty())
    }

    /// Put each file at its path.
    ///
    /// Under `check`, every file is compared before any is sent, so a
    /// conflict writes nothing. A failure part-way leaves the earlier files
    /// written, which a rerun finds the same and does not send again.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        // Nothing to decide from it: a generic repository has no index to
        // merge and no tag to move.
        let _ = companions;

        if files.len() != artifact.files.len() {
            return Err(Error::BadRequest {
                ecosystem: "raw",
                text: artifact.purl(),
                detail: format!(
                    "{} files were described and {} were staged",
                    artifact.files.len(),
                    files.len()
                ),
            });
        }

        // Every path first, so an artifact that cannot be laid out is
        // refused before any of it is written.
        let mut placed = Vec::with_capacity(files.len());

        for (file, staged) in artifact.files.iter().zip(files) {
            let digests = crate::net::files::digests_of(staged, &[DigestAlg::Sha256])?;
            let sha256 = digests
                .into_iter()
                .next()
                .map(|(_, hex)| hex)
                .unwrap_or_default();

            placed.push(Placed {
                file,
                staged,
                path: self.path_for(artifact, &file.name)?,
                sha256,
            });
        }

        // Under `check`, which files already hold the same bytes; any
        // holding other bytes refuses the artifact here.
        let mut present = vec![false; placed.len()];

        if self.guard == OverwriteGuard::Check {
            for (index, file) in placed.iter().enumerate() {
                match self.stored(file, ctx).await? {
                    Stored::Absent => {}
                    Stored::Same => present[index] = true,
                    Stored::Different(held) => return Err(self.conflict(file, &held)),
                }
            }
        }

        for (file, present) in placed.iter().zip(present) {
            if present {
                delivery.finish(&file.file.name, Delivered::AlreadyPresent);
                continue;
            }

            delivery.start(&file.file.name);

            let delivered = self.send(file, ctx).await?;

            delivery.finish(&file.file.name, delivered);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::{Cause, Digest, Release};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://artifactory.test";
    const REPO: &str = "generic-local";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "raw".into() })
    }

    fn put(path: &str) -> String {
        format!("{BASE}/{REPO}/{path}")
    }

    fn storage(path: &str) -> String {
        format!("{BASE}/api/storage/{REPO}/{path}")
    }

    fn target(extra: serde_json::Value, host: Arc<dyn ExtHost>) -> ArtifactoryGenericTarget {
        let mut config = serde_json::json!({"repository": REPO});

        for (key, value) in extra.as_object().expect("an object") {
            config[key] = value.clone();
        }

        ArtifactoryGenericTarget::open(BASE, &options(config), host).expect("opens")
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, name)
    }

    fn artifact(name: &str, version: Option<&str>, files: &[&str]) -> ResolvedArtifact {
        ResolvedArtifact {
            id: id(name),
            version: version.map(|text| Version::new(text, Release::General)),
            files: files
                .iter()
                .map(|file| FileRef::new(*file, format!("h://origin.test/{file}")))
                .collect(),
            license: None,
            published: None,
        }
    }

    fn stage(host: &TestHost, name: &str, bytes: &[u8]) -> PathBuf {
        let staged = host.cache().path(name).expect("path");
        std::fs::write(host.cache().resolve(&staged), bytes).expect("staged");

        host.cache().resolve(&staged)
    }

    fn sha256(bytes: &[u8]) -> String {
        use sha2::Digest as _;

        hex::encode(sha2::Sha256::digest(bytes))
    }

    fn file_info(sha256: &str) -> String {
        format!(r#"{{"checksums": {{"sha256": "{sha256}"}}}}"#)
    }

    fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    async fn publish(
        target: &ArtifactoryGenericTarget,
        artifact: &ResolvedArtifact,
        staged: &[PathBuf],
    ) -> Result<Delivery> {
        let mut delivery = Delivery::default();

        target
            .publish(
                artifact,
                staged,
                &Companions::default(),
                &mut delivery,
                &ctx(),
            )
            .await?;

        Ok(delivery)
    }

    #[test]
    fn repository_required() {
        assert!(ArtifactoryGenericTarget::open(BASE, &Options::default(), idle()).is_err());
    }

    /// Artifactory as admin replaces silently, so checking is the default.
    #[test]
    fn guard_defaults_to_check() {
        assert_eq!(
            target(serde_json::json!({}), idle()).guard,
            OverwriteGuard::Check
        );
        assert_eq!(
            target(serde_json::json!({"overwrite-guard": "server"}), idle()).guard,
            OverwriteGuard::Server
        );
    }

    #[test]
    fn ecosystem_foreign_artifact_refused() {
        let npm = ArtifactId::new(EcosystemId::npm(), None, "tuna");
        let target = target(serde_json::json!({}), idle());

        assert!(target.ecosystem(&npm).is_err());
        assert!(target.ecosystem(&id("tools/cli")).is_ok());
    }

    /// Each absent file is checked, then put at its path with its checksums.
    #[tokio::test]
    async fn check_puts_absent_files() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with(
                    storage("tools/fmt/a.txt"),
                    Canned::status(StatusCode::NOT_FOUND),
                )
                .with_body(put("tools/fmt/a.txt"), "{}"),
        ));
        let staged = [stage(&host, "a.txt", b"first")];
        let mut described = artifact("tools/fmt", None, &["a.txt"]);

        described.files[0].digests = vec![Digest::new(DigestAlg::Sha1, "ab".repeat(20))];

        let delivery = publish(
            &target(serde_json::json!({}), host.clone()),
            &described,
            &staged,
        )
        .await
        .expect("published");

        assert_eq!(
            delivery.files(),
            [("a.txt".to_owned(), Delivered::Uploaded)]
        );
        assert_eq!(
            host.sent_to(&put("tools/fmt/a.txt")),
            vec![b"first".to_vec()]
        );

        let headers = host.headers_to(&put("tools/fmt/a.txt"));
        let [first] = headers.as_slice() else {
            panic!("expected one request, got {}", headers.len());
        };

        assert_eq!(
            header(first, "x-checksum-sha256"),
            Some(sha256(b"first").as_str())
        );
        assert_eq!(
            header(first, "x-checksum-sha1"),
            Some("ab".repeat(20).as_str())
        );
    }

    /// The same bytes are not sent again.
    #[tokio::test]
    async fn check_skips_same_bytes() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(storage("tools/fmt/a.txt"), file_info(&sha256(b"first"))),
        ));
        let staged = [stage(&host, "a.txt", b"first")];

        let delivery = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("tools/fmt", None, &["a.txt"]),
            &staged,
        )
        .await
        .expect("published");

        assert_eq!(
            delivery.files(),
            [("a.txt".to_owned(), Delivered::AlreadyPresent)]
        );
        assert_eq!(host.hits(&put("tools/fmt/a.txt")), 0);
    }

    /// Different bytes anywhere refuse the artifact with nothing written.
    #[tokio::test]
    async fn check_conflict_writes_nothing() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with(
                    storage("tools/fmt/a.txt"),
                    Canned::status(StatusCode::NOT_FOUND),
                )
                .with_body(storage("tools/fmt/b.txt"), file_info("00")),
        ));
        let staged = [
            stage(&host, "a.txt", b"first"),
            stage(&host, "b.txt", b"second"),
        ];

        let err = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("tools/fmt", None, &["a.txt", "b.txt"]),
            &staged,
        )
        .await
        .expect_err("refused");

        assert!(matches!(err, Error::Integrity(_)), "{err}");
        assert_eq!(host.hits(&put("tools/fmt/a.txt")), 0);
    }

    /// Under `server` nothing is looked up before the deploy.
    #[tokio::test]
    async fn server_puts_without_checking() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(put("tools/fmt/2.0/fmt.zip"), "{}"),
        ));
        let staged = [stage(&host, "fmt.zip", b"zip")];

        publish(
            &target(
                serde_json::json!({"overwrite-guard": "server", "mapping": "name-version-file"}),
                host.clone(),
            ),
            &artifact("tools/fmt", Some("2.0"), &["fmt.zip"]),
            &staged,
        )
        .await
        .expect("published");

        assert_eq!(host.hits(&storage("tools/fmt/2.0/fmt.zip")), 0);
        assert_eq!(host.hits(&put("tools/fmt/2.0/fmt.zip")), 1);
    }

    /// A 403 over the same bytes is a delivery that already happened.
    #[tokio::test]
    async fn server_refusal_same_bytes_present() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with(
                    put("tools/fmt/a.txt"),
                    Canned::status(StatusCode::FORBIDDEN),
                )
                .with_body(storage("tools/fmt/a.txt"), file_info(&sha256(b"first"))),
        ));
        let staged = [stage(&host, "a.txt", b"first")];

        let delivery = publish(
            &target(
                serde_json::json!({"overwrite-guard": "server"}),
                host.clone(),
            ),
            &artifact("tools/fmt", None, &["a.txt"]),
            &staged,
        )
        .await
        .expect("published");

        assert_eq!(
            delivery.files(),
            [("a.txt".to_owned(), Delivered::AlreadyPresent)]
        );
    }

    /// A 403 over an absent path is no permission to deploy at all.
    #[tokio::test]
    async fn server_refusal_absent_path_fails() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with(
                    put("tools/fmt/a.txt"),
                    Canned::status(StatusCode::FORBIDDEN),
                )
                .with(
                    storage("tools/fmt/a.txt"),
                    Canned::status(StatusCode::NOT_FOUND),
                ),
        ));
        let staged = [stage(&host, "a.txt", b"first")];

        let err = publish(
            &target(
                serde_json::json!({"overwrite-guard": "server"}),
                host.clone(),
            ),
            &artifact("tools/fmt", None, &["a.txt"]),
            &staged,
        )
        .await
        .expect_err("refused");

        assert!(
            matches!(err, Error::HttpStatus { status, .. } if status == StatusCode::FORBIDDEN),
            "{err}"
        );
    }

    /// Two `as-is` files cannot land on one path.
    #[tokio::test]
    async fn publish_unplaceable_artifact_writes_nothing() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));
        let staged = [stage(&host, "a.txt", b"a"), stage(&host, "b.txt", b"b")];

        let err = publish(
            &target(serde_json::json!({"mapping": "as-is"}), host.clone()),
            &artifact("tools/a.txt", None, &["a.txt", "b.txt"]),
            &staged,
        )
        .await
        .expect_err("refused");

        assert!(matches!(err, Error::BadRequest { .. }), "{err}");
        assert!(host.requested().is_empty());
    }

    #[tokio::test]
    async fn exists_reads_back_through_mapping() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            storage("tools/fmt"),
            r#"{"children": [
                {"uri": "/fmt.zip", "folder": false},
                {"uri": "/sub", "folder": true}
            ]}"#,
        )));
        let target = target(serde_json::json!({}), host);

        assert!(
            target
                .exists(&id("tools/fmt"), None, &ctx())
                .await
                .expect("asked")
        );
    }

    #[tokio::test]
    async fn exists_needs_version_under_name_version_file() {
        let target = target(serde_json::json!({"mapping": "name-version-file"}), idle());

        assert!(target.exists(&id("tools/fmt"), None, &ctx()).await.is_err());
    }
}
