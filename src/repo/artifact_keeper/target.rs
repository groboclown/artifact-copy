//! Publishing to an Artifact Keeper generic repository.
//!
//! # A written path is replaced only on a versioned repository
//!
//! A repository without `versioning_enabled` answers 409 to any rewrite,
//! even of identical bytes, and the stored checksum then decides. One with
//! it answers 201 and appends a revision, keeping the old bytes: how a raw
//! repository holds "the latest X". `overwrite-guard` picks who guards it:
//!
//! - `server`, the default: trust the server. A versioned repository takes
//!   the new bytes as its head.
//! - `check`: compare what is stored before writing anything, so a path is
//!   never replaced.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use serde::Deserialize;

use super::listing::Listing;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, DigestAlg, ResolvedArtifact, Version};
use crate::net::{Req, encode_unreserved, normalized_base};
use crate::repo::{
    Companions, Coordinate, Delivered, Delivery, Mapping, OverwriteGuard, PageCap, Target,
};

use super::{MAPPING, PAGE_LIMIT, PER_PAGE, encode_path, page_cap, prefix_of, repository_url};

/// The revision label a versioned repository records; ignored by one
/// without versioning.
const VERSION_HEADER: &str = "x-artifact-version";

pub struct ArtifactKeeperGenericTarget {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
    mapping: Mapping,
    ecosystem: crate::ecosystem::Raw,
    page_cap: PageCap,
    guard: OverwriteGuard,
}

/// What a path holds, against the file about to go there.
enum Stored {
    Absent,
    Same,

    /// Something else, described for the error.
    Different(String),
}

/// One file of an artifact, with where it goes and what it is.
struct Placed<'a> {
    file: &'a crate::model::FileRef,
    staged: &'a PathBuf,
    path: String,
    sha256: String,
}

impl ArtifactKeeperGenericTarget {
    /// Build from configuration.
    ///
    /// The repository is required, since one server holds many. The
    /// mapping defaults to [`Mapping::Directory`], which is the source
    /// side's default too: a copy between two repositories that both leave
    /// it unset puts every file back where it was.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let repository = options
            .require_string(crate::ext::options::REPOSITORY)?
            .to_owned();

        let mapping = options
            .string(MAPPING)?
            .map(Mapping::parse)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            repository,
            mapping,
            ecosystem: crate::ecosystem::Raw,
            page_cap: page_cap(options)?,
            guard: OverwriteGuard::from_options(options)?,
        })
    }

    fn repository_url(&self) -> String {
        repository_url(&self.base_url, &self.repository)
    }

    fn artifact_url(&self, path: &str) -> String {
        format!("{}/artifacts/{}", self.repository_url(), encode_path(path))
    }

    fn listing_url(&self, prefix: &str, page: u32) -> String {
        format!(
            "{}/artifacts?path_prefix={}&page={page}&per_page={PER_PAGE}",
            self.repository_url(),
            encode_unreserved(prefix),
        )
    }

    /// Where one file of an artifact lands.
    ///
    /// Refused rather than written when the path would not read back as
    /// this artifact. That catches a file name carrying a separator, a
    /// `name-version-file` artifact with no version, and several files of
    /// an `as-is` artifact that would all land on one path.
    fn path_for(&self, id: &ArtifactId, version: Option<&Version>, file: &str) -> Result<String> {
        let at = Coordinate {
            name: id.name().trim_matches('/').to_owned(),
            version: version.map(|version| version.text().to_owned()),
            file: file.to_owned(),
        };

        let path = self.mapping.path(&at);

        if at.name.is_empty() || file.is_empty() || self.mapping.read(&path).as_ref() != Some(&at) {
            return Err(Error::BadRequest {
                ecosystem: "raw",
                text: id.purl(),
                detail: format!(
                    "file {file:?} would be written to {path:?}, which the {} mapping \
                     does not read back as this artifact",
                    self.mapping.as_str()
                ),
            });
        }

        Ok(path)
    }

    /// What the server holds at a file's path.
    async fn stored(&self, placed: &Placed<'_>, ctx: &Ctx) -> Result<Stored> {
        let fetched: Result<StoredFile> = crate::ext::fetch_json(
            &*self.host,
            &Req::get(self.artifact_url(&placed.path)),
            PAGE_LIMIT,
            "artifact keeper artifact",
            ctx,
        )
        .await;

        let stored = match fetched {
            Ok(stored) => stored,
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                return Ok(Stored::Absent);
            }
            Err(err) => return Err(err),
        };

        Ok(match stored.checksum_sha256.as_deref().map(str::trim) {
            Some(held) if held.eq_ignore_ascii_case(&placed.sha256) => Stored::Same,
            Some(held) => Stored::Different(format!("sha256 {held}")),
            None => Stored::Different("no sha256 to compare".to_owned()),
        })
    }

    /// The refusal for a path holding something else.
    ///
    /// Refused rather than overwritten: a copy that deleted a written path
    /// to make room would be destroying the target's own history.
    fn conflict(&self, placed: &Placed<'_>, held: &str) -> Error {
        Error::Integrity(format!(
            "{} already holds a different file ({held}), and a written path is not \
             replaced; the file being copied has sha256 {}",
            self.artifact_url(&placed.path),
            placed.sha256
        ))
    }

    /// Put one file, with every checksum it has and the version it is.
    async fn put(&self, placed: &Placed<'_>, version: Option<&Version>, ctx: &Ctx) -> Result<()> {
        let mut req = Req::put(self.artifact_url(&placed.path))
            .header("content-type", "application/octet-stream")
            .header("x-checksum-sha256", &placed.sha256);

        // The weaker digests too, where the source declared them. The
        // server checks every one it is given, and SHA-256 above is
        // the one that matters.
        for digest in &placed.file.digests {
            let name = match digest.alg {
                DigestAlg::Sha1 => "x-checksum-sha1",
                DigestAlg::Md5 => "x-checksum-md5",
                DigestAlg::Sha256 | DigestAlg::Sha512 => continue,
            };

            req = req.header(name, &digest.hex);
        }

        // Labels the revision on a versioned repository, rather than
        // leaving the server to guess one from the path.
        if let Some(version) = version {
            req = req.header(VERSION_HEADER, version.text());
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

    /// Send one file, answering a 409 by comparing.
    ///
    /// **A written path answers 409 even for identical bytes** on a
    /// repository without versioning, measured, so the stored checksum
    /// decides between a file already delivered and a conflict.
    async fn send(
        &self,
        placed: &Placed<'_>,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<Delivered> {
        let refused = match self.put(placed, version, ctx).await {
            Ok(()) => return Ok(Delivered::Uploaded),
            Err(err @ Error::HttpStatus { status, .. }) if status == StatusCode::CONFLICT => err,
            Err(err) => return Err(err),
        };

        match self.stored(placed, ctx).await? {
            Stored::Same => Ok(Delivered::AlreadyPresent),
            Stored::Different(held) => Err(self.conflict(placed, &held)),
            Stored::Absent => Err(refused),
        }
    }

    /// Every path first, so an artifact that cannot be laid out is
    /// refused before any of it is written.
    fn place<'a>(
        &self,
        artifact: &'a ResolvedArtifact,
        files: &'a [PathBuf],
    ) -> Result<Vec<Placed<'a>>> {
        artifact
            .files
            .iter()
            .zip(files)
            .map(|(file, staged)| {
                Ok(Placed {
                    file,
                    staged,
                    path: self.path_for(&artifact.id, artifact.version.as_ref(), &file.name)?,
                    sha256: sha256_of(staged)?,
                })
            })
            .collect()
    }

    /// Under `check`, which files already hold the same bytes; any holding
    /// other bytes refuses the artifact here. Under `server`, none.
    async fn present(&self, placed: &[Placed<'_>], ctx: &Ctx) -> Result<Vec<bool>> {
        let mut present = vec![false; placed.len()];

        if self.guard != OverwriteGuard::Check {
            return Ok(present);
        }

        for (index, file) in placed.iter().enumerate() {
            match self.stored(file, ctx).await? {
                Stored::Absent => {}
                Stored::Same => present[index] = true,
                Stored::Different(held) => return Err(self.conflict(file, &held)),
            }
        }

        Ok(present)
    }
}

/// The SHA-256 of a staged file, streamed rather than read whole.
fn sha256_of(path: &std::path::Path) -> Result<String> {
    use sha2::Digest as _;

    let read_error = |source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    };

    let mut file = std::fs::File::open(path).map_err(read_error)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0; 64 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(read_error)?;

        if read == 0 {
            return Ok(hex::encode(hasher.finalize()));
        }

        hasher.update(&buffer[..read]);
    }
}

/// What the server stored at one path.
#[derive(Debug, Deserialize)]
struct StoredFile {
    checksum_sha256: Option<String>,
}

#[async_trait]
impl Target for ArtifactKeeperGenericTarget {
    /// Raw artifacts only.
    ///
    /// Any source could in principle be copied into a generic repository,
    /// but only a raw one says what path each file belongs at. Inventing a
    /// layout for a Maven or npm artifact is a decision about the target's
    /// shape, and it belongs to whoever configures one rather than to a
    /// default nobody chose.
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    /// Whether any file of this artifact is already there.
    ///
    /// **Any**, not all: the question is whether this version was
    /// delivered, and this target cannot be asked which files a version
    /// *should* have. A directory left half-written by an interrupted copy
    /// reads as present here; the report's transfer claims are what
    /// resume that copy, and a republish would meet the 409 handling in
    /// [`Target::publish`] file by file.
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        if self.mapping == Mapping::NameVersionFile {
            crate::repo::version_required(id, version)?;
        }

        let name = id.name().trim_matches('/');
        let wanted = version.map(Version::text);
        let prefix = prefix_of(self.mapping, name, version);

        for page in 1..=self.page_cap.pages() {
            let listing: Listing = crate::ext::fetch_json(
                &*self.host,
                &Req::get(self.listing_url(&prefix, page)),
                PAGE_LIMIT,
                "artifact keeper listing",
                ctx,
            )
            .await?;

            let found = listing.items.iter().any(|item| {
                self.mapping
                    .read(&item.path)
                    .is_some_and(|at| at.name == name && at.version.as_deref() == wanted)
            });

            if found {
                return Ok(true);
            }

            if !listing.has_more.unwrap_or(false) {
                return Ok(false);
            }
        }

        Err(Error::Malformed {
            what: "artifact keeper listing",
            url: self.listing_url(&prefix, 1),
            detail: self.page_cap.exhausted(),
        })
    }

    /// Put each file at its path.
    ///
    /// One request per file, in the order the source listed them. Under
    /// `check`, every file is compared before any is sent, so a conflict
    /// writes nothing. A failure part-way leaves the earlier files
    /// written, which a rerun finds the same and does not count again.
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

        let placed = self.place(artifact, files)?;
        let present = self.present(&placed, ctx).await?;

        for (file, present) in placed.iter().zip(present) {
            if present {
                delivery.finish(&file.file.name, Delivered::AlreadyPresent);
                continue;
            }

            delivery.start(&file.file.name);

            let delivered = self.send(file, artifact.version.as_ref(), ctx).await?;

            delivery.finish(&file.file.name, delivered);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::API;
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::ExtHost;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::{Cause, Digest, EcosystemId, FileRef, Release};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://keeper.test";
    const REPO: &str = "generic-local";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "raw".to_owned(),
        })
    }

    fn target(mapping: &str, host: Arc<dyn ExtHost>) -> ArtifactKeeperGenericTarget {
        ArtifactKeeperGenericTarget::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "mapping": mapping})),
            host,
        )
        .expect("opens")
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, name)
    }

    fn put(path: &str) -> String {
        format!("{BASE}/{API}/{REPO}/artifacts/{path}")
    }

    fn listing(prefix: &str, page: u32) -> String {
        format!(
            "{BASE}/{API}/{REPO}/artifacts?path_prefix={}&page={page}&per_page={PER_PAGE}",
            encode_unreserved(prefix)
        )
    }

    fn page(paths: &[&str], has_more: bool) -> String {
        let items: Vec<String> = paths
            .iter()
            .map(|path| format!(r#"{{"path": "{path}", "checksum_sha256": "00"}}"#))
            .collect();

        format!(
            r#"{{"items": [{}], "has_more": {has_more},
                 "pagination": {{"page": 1, "per_page": 1, "total": 999}}}}"#,
            items.join(",")
        )
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

    fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn repository_required() {
        assert!(ArtifactKeeperGenericTarget::open(BASE, &Options::default(), idle()).is_err());
    }

    #[test]
    fn mapping_misspelled_refused() {
        let opened = ArtifactKeeperGenericTarget::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "mapping": "regex"})),
            idle(),
        );

        assert!(opened.is_err());
    }

    /// Only a raw artifact says where its files go.
    #[test]
    fn ecosystem_foreign_artifact_refused() {
        let npm = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert!(target("directory", idle()).ecosystem(&npm).is_err());
        assert!(
            target("directory", idle())
                .ecosystem(&id("tools/cli"))
                .is_ok()
        );
    }

    /// The whole publish path: each staged file is PUT at the path the
    /// mapping gives it, carrying its bytes and a checksum the server
    /// verifies.
    #[tokio::test]
    async fn publish_puts_each_file_with_checksum() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(put("artifact1/1.0/a1.txt"), "{}")
                .with_body(put("artifact1/1.0/a2.txt"), "{}"),
        ));

        let staged = [
            stage(&host, "a1.txt", b"first"),
            stage(&host, "a2.txt", b"second"),
        ];

        let mut described = artifact("artifact1/1.0", None, &["a1.txt", "a2.txt"]);
        described.files[0].digests = vec![Digest::new(DigestAlg::Sha1, "ab".repeat(20))];

        let ctx = ctx();
        let mut delivery = Delivery::default();

        target("directory", host.clone())
            .publish(
                &described,
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await
            .expect("published");

        assert_eq!(
            delivery.files(),
            [
                ("a1.txt".to_owned(), Delivered::Uploaded),
                ("a2.txt".to_owned(), Delivered::Uploaded),
            ]
        );

        assert_eq!(
            host.sent_to(&put("artifact1/1.0/a1.txt")),
            vec![b"first".to_vec()]
        );
        assert_eq!(
            host.sent_to(&put("artifact1/1.0/a2.txt")),
            vec![b"second".to_vec()]
        );

        let headers = host.headers_to(&put("artifact1/1.0/a1.txt"));
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

    /// Under `name-version-file` the version is a path segment.
    #[tokio::test]
    async fn path_version_segment_under_name_version_file() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(put("tools/cli/1.2.0/cli.tar.gz"), "{}"),
        ));
        let staged = [stage(&host, "cli.tar.gz", b"cli")];
        let ctx = ctx();

        target("name-version-file", host.clone())
            .publish(
                &artifact("tools/cli", Some("1.2.0"), &["cli.tar.gz"]),
                &staged,
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect("published");

        assert_eq!(host.sent_to(&put("tools/cli/1.2.0/cli.tar.gz")).len(), 1);
    }

    /// A segment that needs escaping is escaped, and the separators are
    /// kept.
    #[tokio::test]
    async fn path_segments_escaped_separators_kept() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(put("my%20tools/read%20me.txt"), "{}"),
        ));
        let staged = [stage(&host, "read me.txt", b"x")];
        let ctx = ctx();

        target("directory", host.clone())
            .publish(
                &artifact("my tools", None, &["read me.txt"]),
                &staged,
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect("published");

        assert_eq!(host.sent_to(&put("my%20tools/read%20me.txt")).len(), 1);
    }

    /// **A written path answers 409 even for identical bytes**, measured.
    /// The stored checksum decides whether that is a file already
    /// delivered -- a resumed copy -- or a conflict.
    #[tokio::test]
    async fn conflict_same_bytes_already_delivered() {
        let path = put("artifact3/versionless.txt");
        let stored = format!(
            r#"{{"path": "artifact3/versionless.txt",
                                   "checksum_sha256": "{}"}}"#,
            sha256(b"same").to_uppercase()
        );

        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                // The PUT and the metadata GET share a URL; the fixture
                // answers them in order.
                .with_sequence(
                    &path,
                    vec![Canned::status(StatusCode::CONFLICT), Canned::ok(stored)],
                ),
        ));
        let staged = [stage(&host, "versionless.txt", b"same")];
        let ctx = ctx();
        let mut delivery = Delivery::default();

        target("directory", host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await
            .expect("already there counts as published");

        assert_eq!(
            delivery.files(),
            [("versionless.txt".to_owned(), Delivered::AlreadyPresent)]
        );
    }

    /// Different bytes at a written path are refused, not overwritten.
    #[tokio::test]
    async fn conflict_different_bytes_refused() {
        let path = put("artifact3/versionless.txt");
        let stored = format!(r#"{{"checksum_sha256": "{}"}}"#, sha256(b"theirs"));

        let host = Arc::new(TestHost::new(FixtureClient::new().with_sequence(
            &path,
            vec![Canned::status(StatusCode::CONFLICT), Canned::ok(stored)],
        )));
        let staged = [stage(&host, "versionless.txt", b"ours")];
        let ctx = ctx();

        let err = target("directory", host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect_err("refused");

        assert!(matches!(err, Error::Integrity(_)), "{err}");
    }

    /// Under `overwrite-guard: check`.
    fn guarded(host: Arc<dyn ExtHost>) -> ArtifactKeeperGenericTarget {
        ArtifactKeeperGenericTarget::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "overwrite-guard": "check"})),
            host,
        )
        .expect("opens")
    }

    #[test]
    fn guard_defaults_to_server() {
        assert_eq!(target("directory", idle()).guard, OverwriteGuard::Server);
        assert_eq!(guarded(idle()).guard, OverwriteGuard::Check);
    }

    /// A versioned repository answers 201 to a rewrite and keeps the old
    /// bytes as a revision. Under `server` that is the server's call.
    #[tokio::test]
    async fn versioned_rewrite_uploaded() {
        let path = put("artifact3/versionless.txt");
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(&path, "{}")));
        let staged = [stage(&host, "versionless.txt", b"newer")];
        let mut delivery = Delivery::default();

        target("directory", host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx(),
            )
            .await
            .expect("published");

        assert_eq!(
            delivery.files(),
            [("versionless.txt".to_owned(), Delivered::Uploaded)]
        );
        assert_eq!(host.sent_to(&path), vec![b"newer".to_vec()]);
    }

    /// Under `check`, a path holding other bytes refuses the artifact
    /// before anything is sent, versioned repository or not.
    #[tokio::test]
    async fn check_different_bytes_sends_nothing() {
        let path = put("artifact3/versionless.txt");
        let stored = format!(r#"{{"checksum_sha256": "{}"}}"#, sha256(b"theirs"));
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(&path, stored)));
        let staged = [stage(&host, "versionless.txt", b"ours")];

        let err = guarded(host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut Delivery::default(),
                &ctx(),
            )
            .await
            .expect_err("refused");

        assert!(matches!(err, Error::Integrity(_)), "{err}");
        assert_eq!(host.hits(&path), 1);
    }

    /// Under `check`, a path holding the same bytes is not sent again,
    /// so a versioned repository records no revision for it.
    #[tokio::test]
    async fn check_same_bytes_already_present() {
        let path = put("artifact3/versionless.txt");
        let stored = format!(r#"{{"checksum_sha256": "{}"}}"#, sha256(b"same"));
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(&path, stored)));
        let staged = [stage(&host, "versionless.txt", b"same")];
        let mut delivery = Delivery::default();

        guarded(host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx(),
            )
            .await
            .expect("already there counts as published");

        assert_eq!(
            delivery.files(),
            [("versionless.txt".to_owned(), Delivered::AlreadyPresent)]
        );
        assert_eq!(host.hits(&path), 1);
    }

    /// Under `check`, an absent path is written.
    #[tokio::test]
    async fn check_absent_path_uploaded() {
        let path = put("artifact3/versionless.txt");
        let host = Arc::new(TestHost::new(FixtureClient::new().with_sequence(
            &path,
            vec![Canned::status(StatusCode::NOT_FOUND), Canned::ok("{}")],
        )));
        let staged = [stage(&host, "versionless.txt", b"new")];
        let mut delivery = Delivery::default();

        guarded(host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx(),
            )
            .await
            .expect("published");

        assert_eq!(
            delivery.files(),
            [("versionless.txt".to_owned(), Delivered::Uploaded)]
        );
    }

    /// The artifact's version labels the revision a versioned repository
    /// records; a versionless artifact sends no label.
    #[tokio::test]
    async fn version_header_sent_when_known() {
        let versioned = put("tools/cli/1.2.0/cli.tar.gz");
        let versionless = put("artifact3/versionless.txt");
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(&versioned, "{}")
                .with_body(&versionless, "{}"),
        ));
        let subject = target("name-version-file", host.clone());

        subject
            .publish(
                &artifact("tools/cli", Some("1.2.0"), &["cli.tar.gz"]),
                &[stage(&host, "cli.tar.gz", b"cli")],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx(),
            )
            .await
            .expect("published");

        target("directory", host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &[stage(&host, "versionless.txt", b"text")],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx(),
            )
            .await
            .expect("published");

        let sent = host.headers_to(&versioned);
        assert_eq!(header(&sent[0], VERSION_HEADER), Some("1.2.0"));

        let sent = host.headers_to(&versionless);
        assert_eq!(header(&sent[0], VERSION_HEADER), None);
    }

    /// Any other failure is propagated, not read as success.
    #[tokio::test]
    async fn publish_refused_upload_fails() {
        let host = Arc::new(TestHost::new(FixtureClient::new().with(
            put("artifact3/versionless.txt"),
            Canned::status(StatusCode::FORBIDDEN),
        )));
        let staged = [stage(&host, "versionless.txt", b"x")];
        let ctx = ctx();
        let mut delivery = Delivery::default();

        let published = target("directory", host.clone())
            .publish(
                &artifact("artifact3", None, &["versionless.txt"]),
                &staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await;

        assert!(matches!(
            published,
            Err(Error::HttpStatus {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        assert_eq!(delivery.pending(), ["versionless.txt"]);
    }

    /// A path that would not read back as the artifact is refused before
    /// anything is written: here, two files of one `as-is` artifact would
    /// both land on its one path.
    #[tokio::test]
    async fn publish_unplaceable_artifact_writes_nothing() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));
        let staged = [stage(&host, "x.txt", b"x"), stage(&host, "y.txt", b"y")];
        let ctx = ctx();

        let published = target("as-is", host.clone())
            .publish(
                &artifact("a/x.txt", None, &["x.txt", "y.txt"]),
                &staged,
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await;

        assert!(matches!(published, Err(Error::BadRequest { .. })));
        assert!(host.requested().is_empty(), "{:?}", host.requested());
    }

    #[test]
    fn path_must_read_back_as_artifact() {
        let directory = target("directory", idle());

        assert_eq!(
            directory
                .path_for(&id("artifact1/1.0"), None, "a1.txt")
                .expect("laid out"),
            "artifact1/1.0/a1.txt"
        );

        // A file at the root is its own artifact.
        assert_eq!(
            directory
                .path_for(&id("readme.txt"), None, "readme.txt")
                .expect("laid out"),
            "readme.txt"
        );

        // A separator in a file name would put it in another directory.
        assert!(directory.path_for(&id("a"), None, "b/c.txt").is_err());

        // `name-version-file` has nowhere to put a versionless file.
        assert!(
            target("name-version-file", idle())
                .path_for(&id("tools/cli"), None, "cli.tar.gz")
                .is_err()
        );
    }

    /// The listing matches a literal prefix, so what comes back includes
    /// sub-directories and siblings. Only a path the mapping reads as this
    /// artifact counts.
    #[tokio::test]
    async fn exists_only_own_files_count() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            listing("a/b", 1),
            page(&["a/b/c/deeper.txt", "a/bc/sibling.txt"], false),
        )));

        let present = target("directory", host.clone())
            .exists(&id("a/b"), None, &ctx)
            .await
            .expect("asked");

        assert!(!present);

        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            listing("a/b", 1),
            page(&["a/b/c/deeper.txt", "a/b/mine.txt"], false),
        )));

        let present = target("directory", host.clone())
            .exists(&id("a/b"), None, &ctx)
            .await
            .expect("asked");

        assert!(present);
    }

    /// `has_more` is followed; the pagination totals are not trusted.
    #[tokio::test]
    async fn exists_listing_followed_while_more() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(listing("a/b", 1), page(&["a/b/c/one.txt"], true))
                .with_body(listing("a/b", 2), page(&["a/b/two.txt"], false)),
        ));

        let present = target("directory", host.clone())
            .exists(&id("a/b"), None, &ctx)
            .await
            .expect("asked");

        assert!(present);
        assert_eq!(host.hits(&listing("a/b", 2)), 1);
    }

    /// A version narrows the prefix to its own directory.
    #[tokio::test]
    async fn exists_version_asked_by_directory() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(FixtureClient::new().with_body(
            listing("tools/cli/1.2.0/", 1),
            page(&["tools/cli/1.2.0/cli.tar.gz"], false),
        )));

        let present = target("name-version-file", host.clone())
            .exists(
                &id("tools/cli"),
                Some(&Version::new("1.2.0", Release::General)),
                &ctx,
            )
            .await
            .expect("asked");

        assert!(present);
    }

    /// A repository that is not there is not an absent artifact: treating
    /// it as one would republish everything into nowhere.
    #[tokio::test]
    async fn exists_missing_repository_is_error() {
        let ctx = ctx();
        let host = Arc::new(TestHost::new(FixtureClient::new()));

        assert!(
            target("directory", host.clone())
                .exists(&id("a/b"), None, &ctx)
                .await
                .is_err()
        );
    }
}
