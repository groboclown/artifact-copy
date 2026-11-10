//! Writing a local directory.
//!
//! Copying files into their paths: the source already decided what an
//! artifact is, and the only question here is where each file lands. The
//! path comes from [`Mapping::path`] and is read back through the mapping
//! before anything is written.
//!
//! # A path is written once
//!
//! The emulation creates a file only where nothing is, and answers 409
//! otherwise. The same bytes there are a file already delivered, as a
//! resumed copy finds; different bytes are a conflict nothing here
//! resolves by overwriting.
//!
//! `overwrite-guard` defaults to `check`: every file is compared before
//! any is written, so a conflict leaves the directory as it was rather
//! than holding half an artifact.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;

use super::{Repository, file_url, prefix_of};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, DigestAlg, ResolvedArtifact, Version};
use crate::net::Req;
use crate::net::emulate::generic::Digests;
use crate::repo::{Companions, Coordinate, Delivered, Delivery, Mapping, OverwriteGuard, Target};

pub struct LocalDirTarget {
    repository: Repository,
    guard: OverwriteGuard,
    ecosystem: crate::ecosystem::Raw,
}

impl LocalDirTarget {
    /// `mapping` defaults to `directory`; `overwrite-guard` to `check`.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            repository: Repository::open(base_url, options, host)?,
            guard: OverwriteGuard::from_options_or(options, OverwriteGuard::Check)?,
            ecosystem: crate::ecosystem::Raw,
        })
    }

    fn mapping(&self) -> Mapping {
        self.repository.mapping
    }

    /// Where one file of an artifact lands.
    ///
    /// Refused when the path would not read back as this artifact, which
    /// catches a file name carrying a separator, a `name-version-file`
    /// artifact with no version, and several files of an `as-is` artifact
    /// on one path; and when a segment is empty or a dot, which would
    /// name somewhere else on disk than it reads as.
    fn path_for(&self, id: &ArtifactId, version: Option<&Version>, file: &str) -> Result<String> {
        let at = Coordinate {
            name: id.name().trim_matches('/').to_owned(),
            version: version.map(|version| version.text().to_owned()),
            file: file.to_owned(),
        };

        let path = self.mapping().path(&at);

        let dotted = path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..");

        if at.name.is_empty() || dotted || self.mapping().read(&path).as_ref() != Some(&at) {
            return Err(Error::BadRequest {
                ecosystem: "raw",
                text: id.purl(),
                detail: format!(
                    "file {file:?} would be written to {path:?}, which the {} mapping \
                     does not read back as this artifact",
                    self.mapping().as_str()
                ),
            });
        }

        Ok(path)
    }

    /// The SHA-256 of every file under `prefix`, by path.
    async fn stored(&self, prefix: &str, ctx: &Ctx) -> Result<HashMap<String, Option<String>>> {
        let listing = self.repository.listed(prefix, Digests::Sha256, ctx).await?;

        Ok(listing
            .items
            .into_iter()
            .map(|item| (item.path, item.sha256))
            .collect())
    }

    /// Whether what is at `path` is the file being copied.
    fn compare(&self, path: &str, held: Option<&str>, sha256: &str) -> Result<Delivered> {
        match held {
            Some(held) if held.eq_ignore_ascii_case(sha256) => Ok(Delivered::AlreadyPresent),

            held => Err(Error::Integrity(format!(
                "{} already holds a different file (sha256 {}), and a written path is \
                 not replaced; the file being copied has sha256 {sha256}",
                file_url(&self.repository.base, path),
                held.unwrap_or("unknown"),
            ))),
        }
    }

    /// Answer a 409: is what was written there first this file?
    async fn already_holds(&self, path: &str, sha256: &str, ctx: &Ctx) -> Result<Delivered> {
        let stored = self.stored(path, ctx).await?;

        self.compare(path, stored.get(path).cloned().flatten().as_deref(), sha256)
    }
}

/// The SHA-256 of a staged file.
fn sha256_of(staged: &std::path::Path) -> Result<String> {
    crate::net::files::digests_of(staged, &[DigestAlg::Sha256])?
        .into_iter()
        .next()
        .map(|(_, hex)| hex)
        .ok_or_else(|| Error::Integrity(format!("{} could not be hashed", staged.display())))
}

#[async_trait]
impl Target for LocalDirTarget {
    /// Raw artifacts only: only a raw source says what path each file
    /// belongs at.
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    /// Whether any file of this artifact is already there.
    ///
    /// **Any**, not all, as for every raw target: a directory left
    /// half-written reads as present, and the report's transfer claims are
    /// what resume it.
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        if self.mapping() == Mapping::NameVersionFile {
            crate::repo::version_required(id, version)?;
        }

        let name = id.name().trim_matches('/');
        let wanted = version.map(Version::text);
        let prefix = prefix_of(self.mapping(), name, version);

        let listing = match self.repository.listed(&prefix, Digests::Omitted, ctx).await {
            Ok(listing) => listing,

            // An empty repository directory not made yet holds nothing.
            Err(Error::Absent { .. }) => return Ok(false),
            Err(err) => return Err(err),
        };

        Ok(listing.items.iter().any(|item| {
            self.mapping()
                .read(&item.path)
                .is_some_and(|at| at.name == name && at.version.as_deref() == wanted)
        }))
    }

    /// Put each file at its path, in the order the source listed them.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        // Nothing to decide from it: a directory has no index to merge.
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
        let paths = artifact
            .files
            .iter()
            .map(|file| self.path_for(&artifact.id, artifact.version.as_ref(), &file.name))
            .collect::<Result<Vec<_>>>()?;

        let hashes = files
            .iter()
            .map(|staged| sha256_of(staged))
            .collect::<Result<Vec<_>>>()?;

        // Under `check`, every conflict is found before anything is
        // written. A repository directory not made yet holds nothing.
        let mut present = vec![false; paths.len()];

        if self.guard == OverwriteGuard::Check {
            let prefix = prefix_of(
                self.mapping(),
                artifact.id.name().trim_matches('/'),
                artifact.version.as_ref(),
            );

            let stored = match self.stored(&prefix, ctx).await {
                Ok(stored) => stored,
                Err(Error::Absent { .. }) => HashMap::new(),
                Err(err) => return Err(err),
            };

            for (index, (path, sha256)) in paths.iter().zip(&hashes).enumerate() {
                let Some(held) = stored.get(path) else {
                    continue;
                };

                self.compare(path, held.as_deref(), sha256)?;
                present[index] = true;
            }
        }

        for (index, file) in artifact.files.iter().enumerate() {
            let (path, sha256, staged) = (&paths[index], &hashes[index], &files[index]);

            if present[index] {
                delivery.finish(&file.name, Delivered::AlreadyPresent);
                continue;
            }

            let req = Req::put(file_url(&self.repository.base, path));

            delivery.start(&file.name);

            let delivered = match self
                .repository
                .host
                .send_file(
                    &req,
                    staged,
                    self.repository.host.constraints().max_in_memory(),
                    ctx,
                )
                .await
            {
                Ok(_) => Delivered::Uploaded,

                // HTTP 409: the path is already written.
                Err(Error::HttpStatus { status, .. }) if status == StatusCode::CONFLICT => {
                    self.already_holds(path, sha256, ctx).await?
                }

                Err(err) => return Err(err),
            };

            delivery.finish(&file.name, delivered);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::options;
    use crate::model::{Cause, EcosystemId, FileRef, Release};
    use crate::repo::local_dir::testing::Directory;

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "raw".into() })
    }

    fn target(directory: &Directory, extra: serde_json::Value) -> LocalDirTarget {
        LocalDirTarget::open(
            &directory.base,
            &options(extra),
            Arc::clone(&directory.host),
        )
        .expect("opens")
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

    async fn publish(
        target: &LocalDirTarget,
        artifact: &ResolvedArtifact,
        staged: &[PathBuf],
    ) -> (Result<()>, Delivery) {
        let mut delivery = Delivery::default();
        let published = target
            .publish(
                artifact,
                staged,
                &Companions::default(),
                &mut delivery,
                &ctx(),
            )
            .await;

        (published, delivery)
    }

    #[test]
    fn guard_misspelled_refused() {
        let directory = Directory::new();

        assert!(
            LocalDirTarget::open(
                &directory.base,
                &options(serde_json::json!({ "overwrite-guard": "never" })),
                Arc::clone(&directory.host),
            )
            .is_err()
        );
    }

    #[test]
    fn ecosystem_foreign_artifact_refused() {
        let directory = Directory::new();
        let npm = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert!(
            target(&directory, serde_json::json!({}))
                .ecosystem(&npm)
                .is_err()
        );
    }

    #[tokio::test]
    async fn path_each_file_lands_at_own() {
        let directory = Directory::new();
        let staged = [
            directory.staged("a1.txt", b"first"),
            directory.staged("a2.txt", b"second"),
        ];

        let (published, delivery) = publish(
            &target(&directory, serde_json::json!({})),
            &artifact("tools/one", None, &["a1.txt", "a2.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(
            delivery.files(),
            [
                ("a1.txt".to_owned(), Delivered::Uploaded),
                ("a2.txt".to_owned(), Delivered::Uploaded),
            ]
        );
        assert_eq!(
            std::fs::read(directory.at("tools/one/a1.txt")).expect("written"),
            b"first"
        );
    }

    #[tokio::test]
    async fn path_version_is_segment() {
        let directory = Directory::new();
        let staged = [directory.staged("cli.tar.gz", b"cli")];

        let (published, _) = publish(
            &target(
                &directory,
                serde_json::json!({ "mapping": "name-version-file" }),
            ),
            &artifact("tools/cli", Some("1.2.0"), &["cli.tar.gz"]),
            &staged,
        )
        .await;

        published.expect("published");
        assert!(directory.exists("tools/cli/1.2.0/cli.tar.gz"));
    }

    #[tokio::test]
    async fn same_bytes_already_present() {
        let directory = Directory::new();
        directory.write("tools/one/a1.txt", b"same");
        let staged = [directory.staged("a1.txt", b"same")];

        for guard in ["check", "server"] {
            let (published, delivery) = publish(
                &target(&directory, serde_json::json!({ "overwrite-guard": guard })),
                &artifact("tools/one", None, &["a1.txt"]),
                &staged,
            )
            .await;

            published.expect("already there counts as published");
            assert_eq!(
                delivery.files(),
                [("a1.txt".to_owned(), Delivered::AlreadyPresent)],
                "{guard}"
            );
        }
    }

    /// Under `check`, a conflict on the second file stops the first from
    /// being written at all.
    #[tokio::test]
    async fn check_writes_nothing() {
        let directory = Directory::new();
        directory.write("tools/one/a2.txt", b"theirs");
        let staged = [
            directory.staged("a1.txt", b"first"),
            directory.staged("a2.txt", b"ours"),
        ];

        let (published, _) = publish(
            &target(&directory, serde_json::json!({})),
            &artifact("tools/one", None, &["a1.txt", "a2.txt"]),
            &staged,
        )
        .await;

        assert!(matches!(published, Err(Error::Integrity(_))));
        assert!(!directory.exists("tools/one/a1.txt"));
        assert_eq!(
            std::fs::read(directory.at("tools/one/a2.txt")).expect("kept"),
            b"theirs"
        );
    }

    /// Under `server`, the refusal is met file by file.
    #[tokio::test]
    async fn server_refuses_other_bytes() {
        let directory = Directory::new();
        directory.write("tools/one/a1.txt", b"theirs");
        let staged = [directory.staged("a1.txt", b"ours")];

        let (published, delivery) = publish(
            &target(
                &directory,
                serde_json::json!({ "overwrite-guard": "server" }),
            ),
            &artifact("tools/one", None, &["a1.txt"]),
            &staged,
        )
        .await;

        assert!(matches!(published, Err(Error::Integrity(_))));
        assert_eq!(delivery.pending(), ["a1.txt"]);
    }

    #[tokio::test]
    async fn publish_unplaceable_artifact_writes_nothing() {
        let directory = Directory::new();
        let staged = [
            directory.staged("x.txt", b"x"),
            directory.staged("y.txt", b"y"),
        ];

        let (published, _) = publish(
            &target(&directory, serde_json::json!({ "mapping": "as-is" })),
            &artifact("a/x.txt", None, &["x.txt", "y.txt"]),
            &staged,
        )
        .await;

        assert!(matches!(published, Err(Error::BadRequest { .. })));
        assert!(!directory.exists("a"));
    }

    #[test]
    fn path_dot_segment_refused() {
        let directory = Directory::new();
        let target = target(&directory, serde_json::json!({}));

        assert!(target.path_for(&id("a/./b"), None, "c.txt").is_err());
        assert!(target.path_for(&id("a/../b"), None, "c.txt").is_err());
        assert_eq!(
            target
                .path_for(&id("a/b"), None, "c.txt")
                .expect("laid out"),
            "a/b/c.txt"
        );
    }

    #[tokio::test]
    async fn present_only_own_files() {
        let directory = Directory::new();
        directory.write("a/b/c/deeper.txt", b"x");
        directory.write("a/bc/sibling.txt", b"x");

        let target = target(&directory, serde_json::json!({}));

        assert!(
            !target
                .exists(&id("a/b"), None, &ctx())
                .await
                .expect("asked")
        );

        directory.write("a/b/mine.txt", b"x");

        assert!(
            target
                .exists(&id("a/b"), None, &ctx())
                .await
                .expect("asked")
        );
    }

    #[tokio::test]
    async fn present_none_in_absent_repository() {
        let directory = Directory::new();
        std::fs::remove_dir(directory.at("")).expect("removed");

        let target = target(&directory, serde_json::json!({}));

        assert!(
            !target
                .exists(&id("a/b"), None, &ctx())
                .await
                .expect("asked")
        );

        let staged = [directory.staged("c.txt", b"c")];
        let (published, _) = publish(&target, &artifact("a/b", None, &["c.txt"]), &staged).await;

        published.expect("published");
        assert!(directory.exists("a/b/c.txt"));
    }
}
