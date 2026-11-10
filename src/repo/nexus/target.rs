//! Writing to a Sonatype Nexus 3 raw repository.
//!
//! A raw repository holds files under a path, so writing one is copying
//! each file to the path the mapping gives it -- the same rule
//! [`super::super::ArtifactKeeperGenericTarget`] follows. The files go up
//! through the components API, several to a request:
//!
//! ```text
//!   POST {base}/service/rest/v1/components?repository={name}
//!        raw.directory=/{dir}
//!        raw.asset1=@file  raw.asset1.filename={name}
//!        ...
//!        raw.assetN=@file  raw.assetN.filename={name}
//! ```
//!
//! # Groups are capped
//!
//! One request carries one directory, and at most `upload-group-size` of
//! it. Files are taken in the order the source listed them, and a group
//! closes when the next file would push it past the cap. No packing: a
//! file larger than the cap goes up alone.
//!
//! ```text
//!   cap 50 MiB:   [10 MiB, 30 MiB] [40 MiB] [90 MiB] [5 MiB]
//! ```
//!
//! # A written path may be refused, or replaced
//!
//! A repository with `writePolicy: ALLOW_ONCE` refuses a rewrite with 400,
//! and one with `ALLOW` replaces it and says nothing. `overwrite-guard`
//! picks who guards it, as it does for the Maven target:
//!
//! - `server`, the default: send, and answer a refusal by listing the
//!   directory. A file holding the same bytes is already delivered;
//!   different bytes are refused; a file still absent is sent again, once,
//!   since the request does not say which of its files was refused.
//! - `check`: list each directory first. The same bytes are not sent, and
//!   different bytes refuse the artifact with nothing written.
//!
//! # A repository of another format takes one `PUT` per file
//!
//! The components API takes only the repository format's own fields, and
//! with them Nexus places the file itself, so a path from the mapping is
//! not one it would keep. A non-raw repository is written instead with
//!
//! ```text
//!   PUT {base}/repository/{name}/{path}
//! ```
//!
//! which measured 201 on Maven for a Maven-layout path and 400 for any
//! other, 400 on npm and cargo, and 404 on PyPI (3.96.3). A refusal is the
//! repository's own rule, and stands. The format is asked once:
//!
//! ```text
//!   GET {base}/service/rest/v1/repositories/{name}   "format": "maven2"
//! ```
//!
//! A stored file is found through the browse pages, which list no digest,
//! so one the same size is downloaded and hashed to compare.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use serde::Deserialize;
use tokio::sync::OnceCell;

use super::asset::Asset;
use super::{NexusRawSource, REPOSITORY_PATH, browse};
use crate::config::ByteSize;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, DigestAlg, FileRef, ResolvedArtifact, Version};
use crate::net::{ByteLimit, Expectation, FormPart, Req, encode_unreserved, normalized_base};
use crate::repo::{Companions, Coordinate, Delivered, Delivery, Mapping, OverwriteGuard, Target};

/// The components endpoint, relative to the Nexus base URL.
const COMPONENTS: &str = "service/rest/v1/components";

/// One repository's description, relative to the Nexus base URL.
const REPOSITORIES: &str = "service/rest/v1/repositories";

/// The format whose repositories take the components API's raw fields.
const RAW_FORMAT: &str = "raw";

/// One repository's description: a few fields.
const DESCRIPTION_LIMIT: ByteLimit = ByteLimit::kib(64);

/// What `GET {REPOSITORIES}/{name}` says, of what this target reads.
#[derive(Debug, Deserialize)]
struct Description {
    format: String,
}

/// The option that caps one request's files.
const UPLOAD_GROUP_OPTION: &str = "upload-group-size";

/// How much one request carries by default.
const DEFAULT_UPLOAD_GROUP: ByteSize = ByteSize::mib(50);

/// What an upload answers with. Nexus sends 204 and no body.
const RESPONSE_LIMIT: ByteLimit = ByteLimit::kib(64);

/// The form field naming the directory a request's files land in.
const DIRECTORY_FIELD: &str = "raw.directory";

pub struct NexusRawTarget {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
    mapping: Mapping,
    guard: OverwriteGuard,
    group_bytes: u64,

    /// The same repository read as a source, which already knows how to
    /// find what it holds.
    reader: NexusRawSource,
    ecosystem: crate::ecosystem::Raw,

    /// The repository's format, asked before the first upload.
    format: OnceCell<String>,
}

/// One file of the artifact, and where it lands.
#[derive(Debug)]
struct Placed<'a> {
    /// The file's name in the artifact, which the delivery is keyed on.
    name: &'a str,
    staged: &'a Path,

    /// The full path in the repository: `dir/leaf`.
    path: String,
    directory: String,
    leaf: String,
    size: u64,
}

/// What the repository holds at a path, against the staged file.
#[derive(Debug, PartialEq, Eq)]
enum Stored {
    Absent,
    Same,

    /// Something else, or something with no checksum to compare; described
    /// for the refusal.
    Different(String),
}

impl NexusRawTarget {
    /// Build from configuration.
    ///
    /// The repository is required, since one server holds many. The mapping
    /// defaults to [`Mapping::Directory`], as the source's does, so a copy
    /// between two repositories that both leave it unset puts every file
    /// back where it was.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        let reader = NexusRawSource::open(base_url, options, Arc::clone(&host))?;

        let group_bytes = options
            .size(UPLOAD_GROUP_OPTION)?
            .unwrap_or(DEFAULT_UPLOAD_GROUP.get());

        if group_bytes == 0 {
            return Err(Error::Config(format!(
                "{UPLOAD_GROUP_OPTION} is 0, and a request must carry something"
            )));
        }

        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            repository: reader.repository.clone(),
            mapping: reader.mapping,
            guard: OverwriteGuard::from_options(options)?,
            group_bytes,
            reader,
            ecosystem: crate::ecosystem::Raw,
            format: OnceCell::new(),
        })
    }

    /// The repository's format, asked once.
    async fn format(&self, ctx: &Ctx) -> Result<&str> {
        let url = format!(
            "{}/{REPOSITORIES}/{}",
            self.base_url,
            encode_unreserved(&self.repository)
        );

        let format = self
            .format
            .get_or_try_init(|| async {
                let described: Description = crate::ext::fetch_json(
                    &*self.host,
                    &Req::get(&url),
                    DESCRIPTION_LIMIT,
                    "nexus repository",
                    ctx,
                )
                .await?;

                Ok::<_, Error>(described.format)
            })
            .await?;

        Ok(format)
    }

    /// Where the repository serves `path`.
    fn served(&self, path: &str) -> String {
        let encoded: Vec<String> = path.split('/').map(encode_unreserved).collect();

        format!(
            "{}/{REPOSITORY_PATH}/{}/{}",
            self.base_url,
            encode_unreserved(&self.repository),
            encoded.join("/")
        )
    }

    /// Put each file with its own request, for a repository of another
    /// format; see the module documentation.
    async fn publish_each(
        &self,
        placed: &[Placed<'_>],
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        // Compared before anything is sent, as for raw.
        let mut held = vec![false; placed.len()];

        if self.guard == OverwriteGuard::Check {
            for (index, file) in placed.iter().enumerate() {
                match self.stored_at(file, ctx).await? {
                    Stored::Absent => {}
                    Stored::Same => held[index] = true,
                    Stored::Different(found) => {
                        return Err(conflict(&self.base_url, file, &found));
                    }
                }
            }
        }

        for (file, held) in placed.iter().zip(held) {
            if held {
                delivery.finish(file.name, Delivered::AlreadyPresent);
                continue;
            }

            delivery.start(file.name);

            let delivered = self.put(file, ctx).await?;

            delivery.finish(file.name, delivered);
        }

        Ok(())
    }

    /// One `PUT`; a refusal over the same bytes is a delivery.
    async fn put(&self, file: &Placed<'_>, ctx: &Ctx) -> Result<Delivered> {
        let req =
            Req::put(self.served(&file.path)).header("content-type", "application/octet-stream");

        let refused = match self
            .host
            .send_file(
                &req,
                file.staged,
                self.host.constraints().max_in_memory(),
                ctx,
            )
            .await
        {
            Ok(_) => return Ok(Delivered::Uploaded),
            // HTTP 400: Nexus refusing to rewrite a path under `ALLOW_ONCE`.
            Err(err @ Error::HttpStatus { status, .. }) if status == StatusCode::BAD_REQUEST => err,
            Err(err) => return Err(err),
        };

        // 400 is both `ALLOW_ONCE` refusing a rewrite and a path the
        // format will not take; what is stored tells them apart.
        match self.stored_at(file, ctx).await? {
            Stored::Same => Ok(Delivered::AlreadyPresent),
            Stored::Different(held) => Err(conflict(&self.base_url, file, &held)),
            Stored::Absent => Err(refused),
        }
    }

    /// What a non-raw repository holds at a file's path.
    ///
    /// The browse page has the name and size; a file of the same size is
    /// downloaded and hashed, since no digest is listed.
    async fn stored_at(&self, file: &Placed<'_>, ctx: &Ctx) -> Result<Stored> {
        let entries = self
            .reader
            .browse(&file.directory, ctx)
            .await?
            .unwrap_or_default();

        let found = entries.into_iter().find_map(|entry| match entry {
            browse::Entry::File {
                name, url, size, ..
            } if name == file.leaf => Some((url, size)),
            _ => None,
        });

        let Some((url, size)) = found else {
            return Ok(Stored::Absent);
        };

        if let Some(size) = size.filter(|&size| size != file.size) {
            return Ok(Stored::Different(format!("{size} bytes")));
        }

        let downloaded = crate::repo::download(
            &*self.host,
            &FileRef::new(&file.leaf, &url),
            &Expectation::new(),
            ctx,
        )
        .await?;

        let held = crate::net::files::digests_of(&downloaded.path, &[DigestAlg::Sha256])?;
        let ours = crate::net::files::digests_of(file.staged, &[DigestAlg::Sha256])?;

        Ok(match held == ours {
            true => Stored::Same,
            false => Stored::Different(format!(
                "sha256 {}",
                held.first().map_or("unknown", |(_, hex)| hex.as_str())
            )),
        })
    }

    fn components_url(&self) -> String {
        format!(
            "{}/{COMPONENTS}?repository={}",
            self.base_url,
            encode_unreserved(&self.repository)
        )
    }

    /// Where one file of an artifact lands.
    ///
    /// Refused rather than written when the path would not read back as
    /// this artifact, as the Artifact Keeper target refuses it.
    fn place<'a>(
        &self,
        artifact: &ResolvedArtifact,
        name: &'a str,
        staged: &'a Path,
    ) -> Result<Placed<'a>> {
        let at = Coordinate {
            name: artifact.id.name().trim_matches('/').to_owned(),
            version: artifact.version.as_ref().map(|v| v.text().to_owned()),
            file: name.to_owned(),
        };

        let path = self.mapping.path(&at);

        if at.name.is_empty() || name.is_empty() || self.mapping.read(&path).as_ref() != Some(&at) {
            return Err(Error::BadRequest {
                ecosystem: "raw",
                text: artifact.purl(),
                detail: format!(
                    "file {name:?} would be written to {path:?}, which the {} mapping \
                     does not read back as this artifact",
                    self.mapping.as_str()
                ),
            });
        }

        let (directory, leaf) = match path.rsplit_once('/') {
            Some((directory, leaf)) => (directory.to_owned(), leaf.to_owned()),
            None => (String::new(), path.clone()),
        };

        let size = std::fs::metadata(staged)
            .map_err(|source| Error::ReadFile {
                path: staged.to_path_buf(),
                source,
            })?
            .len();

        Ok(Placed {
            name,
            staged,
            path,
            directory,
            leaf,
            size,
        })
    }

    /// What the repository holds under each directory, listed once each.
    async fn listed(
        &self,
        placed: &[&Placed<'_>],
        ctx: &Ctx,
    ) -> Result<BTreeMap<String, Vec<Asset>>> {
        let mut found = BTreeMap::new();

        for file in placed {
            if found.contains_key(&file.directory) {
                continue;
            }

            let assets = self.reader.searched(&group(&file.directory), ctx).await?;

            found.insert(file.directory.clone(), assets);
        }

        Ok(found)
    }

    /// Send one group, and on a refusal, sort out which of it was there.
    async fn send(&self, group: &[&Placed<'_>], delivery: &mut Delivery, ctx: &Ctx) -> Result<()> {
        for file in group {
            delivery.start(file.name);
        }

        let refused = match self.post(group, ctx).await {
            Ok(()) => {
                finish_all(group, delivery, Delivered::Uploaded);
                return Ok(());
            }

            // HTTP 400: Nexus refusing to rewrite a path under `ALLOW_ONCE`.
            Err(err @ Error::HttpStatus { status, .. }) if status == StatusCode::BAD_REQUEST => err,
            Err(err) => return Err(err),
        };

        // The request does not say which file was refused, so ask what is
        // there. A file the same is delivered; a file still absent goes
        // again, alone in its own group, once.
        let listed = self.listed(group, ctx).await?;
        let mut absent = Vec::new();

        for file in group {
            match stored(&listed, file)? {
                Stored::Same => delivery.finish(file.name, Delivered::AlreadyPresent),
                Stored::Different(held) => return Err(conflict(&self.base_url, file, &held)),
                Stored::Absent => absent.push(*file),
            }
        }

        if absent.is_empty() {
            return Ok(());
        }

        // Nothing there and still refused: the server's reason stands.
        if absent.len() == group.len() {
            return Err(refused);
        }

        self.post(&absent, ctx).await?;
        finish_all(&absent, delivery, Delivered::Uploaded);

        Ok(())
    }

    /// One components request.
    async fn post(&self, group: &[&Placed<'_>], ctx: &Ctx) -> Result<()> {
        // A group is one directory; see `groups`.
        let directory = format!("/{}", group[0].directory);

        let names: Vec<(String, String)> = (1..=group.len())
            .map(|index| {
                (
                    format!("raw.asset{index}"),
                    format!("raw.asset{index}.filename"),
                )
            })
            .collect();

        let mut form = vec![FormPart::text(DIRECTORY_FIELD, &directory)];

        for (file, (asset, filename)) in group.iter().zip(&names) {
            form.push(FormPart::file(asset, file.staged).named(&file.leaf));
            form.push(FormPart::text(filename, &file.leaf));
        }

        self.host
            .send_form(
                &Req::post(self.components_url(), String::new()),
                &form,
                RESPONSE_LIMIT,
                ctx,
            )
            .await?;

        Ok(())
    }
}

/// The search `group` naming one directory, with the leading `/` Nexus
/// requires.
fn group(directory: &str) -> String {
    format!("/{directory}")
}

fn finish_all(group: &[&Placed<'_>], delivery: &mut Delivery, how: Delivered) {
    for file in group {
        delivery.finish(file.name, how);
    }
}

/// Split files into requests: one directory each, in order, closing a group
/// when the next file would push it past `cap`. A file larger than `cap`
/// goes alone.
///
/// ```text
///   cap 50:  a/10 a/30 a/40 a/90 b/5   ->   [a/10 a/30] [a/40] [a/90] [b/5]
/// ```
fn groups<'p, 'a>(files: &[&'p Placed<'a>], cap: u64) -> Vec<Vec<&'p Placed<'a>>> {
    let mut out: Vec<Vec<&Placed<'_>>> = Vec::new();
    let mut total = 0;

    for file in files {
        let fits = out
            .last()
            .is_some_and(|open| open[0].directory == file.directory && total + file.size <= cap);

        if fits {
            total += file.size;
            out.last_mut().expect("an open group").push(file);
            continue;
        }

        total = file.size;
        out.push(vec![file]);
    }

    out
}

/// Compare what is listed at a file's path with the staged bytes.
///
/// By SHA-256 where Nexus lists one, and SHA-1 otherwise; Nexus has listed
/// SHA-1 for every asset measured. A listed file with neither cannot be
/// confirmed, and is refused rather than assumed to be a delivery.
fn stored(listed: &BTreeMap<String, Vec<Asset>>, file: &Placed<'_>) -> Result<Stored> {
    let Some(asset) = listed.get(&file.directory).and_then(|assets| {
        assets.iter().find(|asset| {
            asset
                .path
                .as_deref()
                .is_some_and(|path| path.trim_start_matches('/') == file.path)
        })
    }) else {
        return Ok(Stored::Absent);
    };

    let declared = asset.digests();

    for alg in [DigestAlg::Sha256, DigestAlg::Sha1] {
        let Some(held) = declared.iter().find(|digest| digest.alg == alg) else {
            continue;
        };

        let staged = crate::net::files::digests_of(file.staged, &[alg])?;
        let same = staged
            .first()
            .is_some_and(|(_, hex)| hex.eq_ignore_ascii_case(&held.hex));

        return Ok(match same {
            true => Stored::Same,
            false => Stored::Different(format!("{} {}", alg.as_str(), held.hex)),
        });
    }

    Ok(Stored::Different(
        "a file with no checksum to compare".to_owned(),
    ))
}

fn conflict(base_url: &str, file: &Placed<'_>, held: &str) -> Error {
    Error::Integrity(format!(
        "{base_url} already holds a different file at {} ({held}), and a written path \
         is not replaced",
        file.path
    ))
}

#[async_trait]
impl Target for NexusRawTarget {
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

        let assets = self
            .reader
            .assets(&self.reader.group_of(id, version), ctx)
            .await?;

        Ok(!self.reader.files_for(&assets, id, version).is_empty())
    }

    /// Put each file at its path, a capped group of one directory at a time.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        // Nothing to decide from it: a raw repository has no index to merge
        // and no tag to move.
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
        let placed = artifact
            .files
            .iter()
            .zip(files)
            .map(|(file, staged)| self.place(artifact, &file.name, staged))
            .collect::<Result<Vec<_>>>()?;

        if self.format(ctx).await? != RAW_FORMAT {
            return self.publish_each(&placed, delivery, ctx).await;
        }

        let mut pending: Vec<&Placed<'_>> = placed.iter().collect();

        // Compared before anything is sent, so a conflict anywhere refuses
        // the artifact with nothing written.
        if self.guard == OverwriteGuard::Check {
            let listed = self.listed(&pending, ctx).await?;
            let mut held = Vec::new();

            for file in &pending {
                match stored(&listed, file)? {
                    Stored::Absent => {}
                    Stored::Same => held.push(file.name),
                    Stored::Different(found) => {
                        return Err(conflict(&self.base_url, file, &found));
                    }
                }
            }

            for name in &held {
                delivery.finish(name, Delivered::AlreadyPresent);
            }

            pending.retain(|file| !held.contains(&file.name));
        }

        for group in groups(&pending, self.group_bytes) {
            self.send(&group, delivery, ctx).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::{TestHost, idle, options};
    use crate::model::{Cause, EcosystemId, FileRef};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://nexus.test";
    const REPO: &str = "raw-b";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "raw".to_owned(),
        })
    }

    /// A client whose repository describes itself as `format`.
    fn described(format: &str) -> FixtureClient {
        FixtureClient::new().with_body(
            format!("{BASE}/{REPOSITORIES}/{REPO}"),
            format!(r#"{{"format": "{format}"}}"#),
        )
    }

    fn post_url() -> String {
        format!("{BASE}/{COMPONENTS}?repository={REPO}")
    }

    fn search_url(directory: &str) -> String {
        format!(
            "{BASE}/{}?repository={REPO}&group={}",
            super::super::SEARCH,
            encode_unreserved(&group(directory))
        )
    }

    fn sha256(bytes: &[u8]) -> String {
        use sha2::Digest as _;

        hex::encode(sha2::Sha256::digest(bytes))
    }

    /// One listed asset holding `bytes`.
    fn page(path: &str, bytes: &[u8]) -> String {
        format!(
            r#"{{"items": [{{"path": "/{path}", "downloadUrl": "{BASE}/repository/{REPO}/{path}",
                "checksum": {{"sha256": "{}"}}}}], "continuationToken": null}}"#,
            sha256(bytes)
        )
    }

    fn empty() -> String {
        r#"{"items": [], "continuationToken": null}"#.to_owned()
    }

    fn target(extra: serde_json::Value, host: Arc<dyn ExtHost>) -> NexusRawTarget {
        let mut config = serde_json::json!({"repository": REPO});
        config
            .as_object_mut()
            .expect("an object")
            .extend(extra.as_object().expect("an object").clone());

        NexusRawTarget::open(BASE, &options(config), host).expect("opens")
    }

    fn artifact(name: &str, files: &[&str]) -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::raw(), None, name),
            version: None,
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

    async fn publish(
        target: &NexusRawTarget,
        described: &ResolvedArtifact,
        staged: &[PathBuf],
    ) -> (Result<()>, Delivery) {
        let ctx = ctx();
        let mut delivery = Delivery::default();

        let published = target
            .publish(
                described,
                staged,
                &Companions::default(),
                &mut delivery,
                &ctx,
            )
            .await;

        (published, delivery)
    }

    /// The `raw.assetN.filename` values of each posted form.
    fn posted(client: &FixtureClient) -> Vec<Vec<String>> {
        client
            .posted_to(&post_url())
            .into_iter()
            .map(|form| {
                form.into_iter()
                    .filter(|(field, _)| field.ends_with(".filename"))
                    .map(|(_, value)| String::from_utf8_lossy(&value).into_owned())
                    .collect()
            })
            .collect()
    }

    fn placed<'a>(directory: &str, name: &'a str, size: u64) -> Placed<'a> {
        Placed {
            name,
            staged: Path::new(name),
            path: format!("{directory}/{name}"),
            directory: directory.to_owned(),
            leaf: name.to_owned(),
            size,
        }
    }

    // -- Configuration -----------------------------------------------------

    #[test]
    fn open_reads_options() {
        let opened = target(
            serde_json::json!({"overwrite-guard": "check", "upload-group-size": "2 MiB"}),
            idle(),
        );

        assert_eq!(opened.guard, OverwriteGuard::Check);
        assert_eq!(opened.group_bytes, 2 * 1_048_576);
        assert_eq!(opened.mapping, Mapping::Directory);
    }

    #[test]
    fn open_defaults_group_size() {
        let opened = target(serde_json::json!({}), idle());

        assert_eq!(opened.group_bytes, DEFAULT_UPLOAD_GROUP.get());
        assert_eq!(opened.guard, OverwriteGuard::Server);
    }

    #[test]
    fn open_refuses_zero_group_size() {
        let opened = NexusRawTarget::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "upload-group-size": 0})),
            idle(),
        );

        assert!(opened.is_err());
    }

    // -- Grouping ----------------------------------------------------------

    /// One pass, in order: a group closes when the next file would pass
    /// the cap or changes directory, and an oversized file goes alone.
    #[test]
    fn groups_split_at_cap_and_directory() {
        let files = [
            placed("a", "f10", 10),
            placed("a", "f30", 30),
            placed("a", "f40", 40),
            placed("a", "f90", 90),
            placed("b", "f5", 5),
        ];
        let refs: Vec<&Placed<'_>> = files.iter().collect();

        let split: Vec<Vec<&str>> = groups(&refs, 50)
            .iter()
            .map(|group| group.iter().map(|file| file.name).collect())
            .collect();

        assert_eq!(
            split,
            [vec!["f10", "f30"], vec!["f40"], vec!["f90"], vec!["f5"]]
        );
    }

    // -- Publishing --------------------------------------------------------

    #[tokio::test]
    async fn publish_posts_one_group() {
        let client = Arc::new(described(RAW_FORMAT).with_body(post_url(), ""));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [
            stage(&host, "a1.txt", b"one"),
            stage(&host, "a2.txt", b"two"),
        ];

        let (published, delivery) = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("artifact1/1.0", &["a1.txt", "a2.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(posted(&client), [vec!["a1.txt", "a2.txt"]]);

        let form = &client.posted_to(&post_url())[0];
        let directory = form
            .iter()
            .find(|(field, _)| field == DIRECTORY_FIELD)
            .map(|(_, value)| value.clone());

        assert_eq!(directory, Some(b"/artifact1/1.0".to_vec()));
        assert_eq!(
            delivery.files(),
            [
                ("a1.txt".to_owned(), Delivered::Uploaded),
                ("a2.txt".to_owned(), Delivered::Uploaded),
            ]
        );
    }

    /// A cap smaller than the files sends each alone.
    #[tokio::test]
    async fn publish_splits_past_cap() {
        let client = Arc::new(described(RAW_FORMAT).with_body(post_url(), ""));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [
            stage(&host, "a1.txt", b"one"),
            stage(&host, "a2.txt", b"two"),
        ];

        let (published, _) = publish(
            &target(serde_json::json!({"upload-group-size": 4}), host.clone()),
            &artifact("artifact1/1.0", &["a1.txt", "a2.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(posted(&client), [vec!["a1.txt"], vec!["a2.txt"]]);
    }

    /// A refused group is sorted out by listing: the file already there is
    /// delivered, and the one still absent goes again alone.
    #[tokio::test]
    async fn refusal_resends_absent_files() {
        let client = Arc::new(
            described(RAW_FORMAT)
                .with_sequence(
                    post_url(),
                    vec![Canned::status(StatusCode::BAD_REQUEST), Canned::ok("")],
                )
                .with_body(search_url("dir"), page("dir/held.txt", b"held")),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [
            stage(&host, "held.txt", b"held"),
            stage(&host, "new.txt", b"new"),
        ];

        let (published, delivery) = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("dir", &["held.txt", "new.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(
            posted(&client),
            [vec!["held.txt", "new.txt"], vec!["new.txt"]]
        );
        assert_eq!(
            delivery.files(),
            [
                ("held.txt".to_owned(), Delivered::AlreadyPresent),
                ("new.txt".to_owned(), Delivered::Uploaded),
            ]
        );
    }

    /// A refusal with nothing there is the server's own, and stands.
    #[tokio::test]
    async fn refusal_with_nothing_held_fails() {
        let client = Arc::new(
            described(RAW_FORMAT)
                .with(post_url(), Canned::status(StatusCode::BAD_REQUEST))
                .with_body(search_url("dir"), empty()),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "x.txt", b"x")];

        let (published, delivery) = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("dir", &["x.txt"]),
            &staged,
        )
        .await;

        assert!(matches!(
            published,
            Err(Error::HttpStatus {
                status: StatusCode::BAD_REQUEST,
                ..
            })
        ));
        assert_eq!(delivery.pending(), ["x.txt"]);
    }

    /// Different bytes at a refused path are a conflict, not overwritten.
    #[tokio::test]
    async fn refusal_holding_different_bytes_refused() {
        let client = Arc::new(
            described(RAW_FORMAT)
                .with(post_url(), Canned::status(StatusCode::BAD_REQUEST))
                .with_body(search_url("dir"), page("dir/x.txt", b"theirs")),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "x.txt", b"ours")];

        let (published, _) = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("dir", &["x.txt"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::Integrity(_))),
            "{published:?}"
        );
    }

    /// Under `check`, the same bytes are not sent at all.
    #[tokio::test]
    async fn check_skips_same_bytes() {
        let client = Arc::new(
            described(RAW_FORMAT)
                .with_body(post_url(), "")
                .with_body(search_url("dir"), page("dir/held.txt", b"held")),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [
            stage(&host, "held.txt", b"held"),
            stage(&host, "new.txt", b"new"),
        ];

        let (published, delivery) = publish(
            &target(
                serde_json::json!({"overwrite-guard": "check"}),
                host.clone(),
            ),
            &artifact("dir", &["held.txt", "new.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(posted(&client), [vec!["new.txt"]]);
        assert_eq!(
            delivery.files(),
            [
                ("held.txt".to_owned(), Delivered::AlreadyPresent),
                ("new.txt".to_owned(), Delivered::Uploaded),
            ]
        );
    }

    /// Under `check`, different bytes anywhere refuse the artifact with
    /// nothing sent.
    #[tokio::test]
    async fn check_refuses_different_bytes() {
        let client = Arc::new(
            described(RAW_FORMAT)
                .with_body(post_url(), "")
                .with_body(search_url("dir"), page("dir/x.txt", b"theirs")),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [
            stage(&host, "new.txt", b"new"),
            stage(&host, "x.txt", b"ours"),
        ];

        let (published, delivery) = publish(
            &target(
                serde_json::json!({"overwrite-guard": "check"}),
                host.clone(),
            ),
            &artifact("dir", &["new.txt", "x.txt"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::Integrity(_))),
            "{published:?}"
        );
        assert!(posted(&client).is_empty());
        assert!(delivery.files().is_empty());
    }

    /// A path that would not read back as the artifact is refused before
    /// anything is asked: two files of one `as-is` artifact.
    #[tokio::test]
    async fn publish_unplaceable_artifact_writes_nothing() {
        let host = Arc::new(TestHost::new(described(RAW_FORMAT)));
        let staged = [stage(&host, "x.txt", b"x"), stage(&host, "y.txt", b"y")];

        let (published, _) = publish(
            &target(serde_json::json!({"mapping": "as-is"}), host.clone()),
            &artifact("a/x.txt", &["x.txt", "y.txt"]),
            &staged,
        )
        .await;

        assert!(matches!(published, Err(Error::BadRequest { .. })));
        assert!(host.requested().is_empty(), "{:?}", host.requested());
    }

    // -- Existence ---------------------------------------------------------

    #[tokio::test]
    async fn exists_finds_any_file() {
        let host = Arc::new(TestHost::new(
            described(RAW_FORMAT).with_body(search_url("dir"), page("dir/x.txt", b"x")),
        ));
        let ctx = ctx();
        let id = ArtifactId::new(EcosystemId::raw(), None, "dir");

        let held = target(serde_json::json!({}), host)
            .exists(&id, None, &ctx)
            .await
            .expect("asked");

        assert!(held);
    }

    #[tokio::test]
    async fn exists_answers_absent() {
        let host = Arc::new(TestHost::new(
            described(RAW_FORMAT).with_body(search_url("dir"), empty()),
        ));
        let ctx = ctx();
        let id = ArtifactId::new(EcosystemId::raw(), None, "dir");

        let held = target(serde_json::json!({}), host)
            .exists(&id, None, &ctx)
            .await
            .expect("asked");

        assert!(!held);
    }

    #[test]
    fn ecosystem_foreign_artifact_refused() {
        let npm = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert!(
            target(serde_json::json!({}), idle())
                .ecosystem(&npm)
                .is_err()
        );
    }

    // -- A repository of another format ------------------------------------

    fn put_url(path: &str) -> String {
        format!("{BASE}/{REPOSITORY_PATH}/{REPO}/{path}")
    }

    fn browse_url(folder: &str) -> String {
        format!("{BASE}/service/rest/repository/browse/{REPO}/{folder}/")
    }

    /// A browse page listing one file of `size` bytes, served at its path.
    fn browse_page(path: &str, size: usize) -> String {
        let name = path.rsplit('/').next().expect("a name");

        format!(
            r#"<table><tr><td><a href="../">Parent Directory</a></td></tr>
            <tr><td><a href="{url}">{name}</a></td><td>Mon Oct 05 16:14:59 Z 2026</td>
            <td align="right">{size}</td><td></td></tr></table>"#,
            url = put_url(path),
        )
    }

    /// One request per file, at the path the mapping gives it.
    #[tokio::test]
    async fn other_format_puts_each_file() {
        let client = Arc::new(described("maven2").with_body(put_url("dir/a.txt"), ""));
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "a.txt", b"one")];

        let (published, delivery) = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("dir", &["a.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(
            delivery.files(),
            [("a.txt".to_owned(), Delivered::Uploaded)]
        );
        assert_eq!(client.sent_to(&put_url("dir/a.txt")), vec![b"one".to_vec()]);
        assert!(client.posted_to(&post_url()).is_empty());
    }

    /// A 400 with nothing stored is the format refusing the path.
    #[tokio::test]
    async fn other_format_refusal_stands() {
        let client = described("npm")
            .with(
                put_url("dir/a.txt"),
                Canned::status(StatusCode::BAD_REQUEST),
            )
            .with(browse_url("dir"), Canned::status(StatusCode::NOT_FOUND));
        let host = Arc::new(TestHost::new(client));
        let staged = [stage(&host, "a.txt", b"one")];

        let (published, _) = publish(
            &target(serde_json::json!({}), host.clone()),
            &artifact("dir", &["a.txt"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::HttpStatus { status, .. }) if status == StatusCode::BAD_REQUEST),
            "{published:?}"
        );
    }

    /// Listed with the same size, then downloaded and found the same.
    #[tokio::test]
    async fn other_format_check_skips_same_bytes() {
        let client = Arc::new(
            described("maven2")
                .with_body(browse_url("dir"), browse_page("dir/a.txt", 3))
                .with_body(put_url("dir/a.txt"), "one"),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "a.txt", b"one")];

        let (published, delivery) = publish(
            &target(
                serde_json::json!({"overwrite-guard": "check"}),
                host.clone(),
            ),
            &artifact("dir", &["a.txt"]),
            &staged,
        )
        .await;

        published.expect("published");

        assert_eq!(
            delivery.files(),
            [("a.txt".to_owned(), Delivered::AlreadyPresent)]
        );
        assert!(client.sent_to(&put_url("dir/a.txt")).is_empty());
    }

    /// Another size is another file, refused with nothing written.
    #[tokio::test]
    async fn other_format_check_refuses_other_size() {
        let client = Arc::new(
            described("maven2").with_body(browse_url("dir"), browse_page("dir/a.txt", 99)),
        );
        let host = Arc::new(TestHost::sharing(client.clone()));
        let staged = [stage(&host, "a.txt", b"one")];

        let (published, _) = publish(
            &target(
                serde_json::json!({"overwrite-guard": "check"}),
                host.clone(),
            ),
            &artifact("dir", &["a.txt"]),
            &staged,
        )
        .await;

        assert!(
            matches!(published, Err(Error::Integrity(_))),
            "{published:?}"
        );
        assert!(client.sent_to(&put_url("dir/a.txt")).is_empty());
    }
}
