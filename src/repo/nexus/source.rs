//! Reading a Nexus raw repository as a source.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::asset::{Asset, AssetPage};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version};
use crate::net::{Expectation, encode_unreserved, normalized_base};
use crate::repo::{Coordinate, Downloaded, Mapping, PageCap, Source};
use crate::version::VersionHandler;

use super::{SEARCH, browse, file_of, page_cap, paged};

/// How a raw repository's paths become coordinates.
const MAPPING: &str = "mapping";

pub struct NexusRawSource {
    base_url: String,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    pub(super) repository: String,
    pub(super) mapping: Mapping,
    ecosystem: crate::ecosystem::Raw,
    page_cap: PageCap,
}

impl NexusRawSource {
    /// Build from configuration.
    ///
    /// The repository name is required -- one Nexus serves many, and there
    /// is no sensible default. The mapping defaults to
    /// [`Mapping::Directory`], the reading that matches how a raw
    /// repository is actually laid out.
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
        })
    }

    /// The `group` filter that finds one artifact's files.
    ///
    /// **With a leading `/`, which the server requires**: without one it
    /// answers an empty page, and an empty page reads as "not here" rather
    /// than as a malformed query. Measured against a running Nexus, and
    /// the production capture agrees -- `group` carries the separator on
    /// both servers even where `path` and `name` disagree about it.
    ///
    /// The mapping decides what a group *is*. `Directory` names the
    /// artifact's own path; the other two name a directory an artifact's
    /// files sit under, and their extra segments are filtered afterwards.
    pub(super) fn group_of(&self, id: &ArtifactId, version: Option<&Version>) -> String {
        let name = id.name().trim_matches('/');

        match (self.mapping, version) {
            // `.../name/version/file`: the files live under the version.
            (Mapping::NameVersionFile, Some(version)) => format!("/{name}/{}", version.text()),

            // Every version of one name, for `versions`. A glob, which
            // crosses `/` -- what comes back is re-read through the mapping
            // rather than trusted.
            //
            // The `*` is percent-encoded on the way out, like everything
            // else in the query. Standard decoding puts it back before the
            // server reads the parameter, and the glob was measured
            // unencoded; that the encoded spelling reaches the matcher
            // intact is the one step in this not confirmed against a
            // running Nexus. It is listed in `TODO.md`.
            (Mapping::NameVersionFile, None) => format!("/{name}/*"),

            // `AsIs` names a file, so its directory is what holds it. A
            // file at the root has none, which `Directory` handles by
            // naming the file itself.
            (Mapping::AsIs, _) => match name.rsplit_once('/') {
                Some((directory, _)) => format!("/{directory}"),
                None => "/".to_owned(),
            },

            (Mapping::Directory, _) => format!("/{name}"),
        }
    }

    fn search_url(&self, group: &str, cursor: Option<&str>) -> String {
        // No `format=raw`. The endpoint accepts one, and a repository holds
        // exactly one format, so it could only restate what `repository`
        // already says -- and every parameter sent is one more thing that
        // can be wrong against a server nobody has tried yet. The probes
        // that settled the `group` rules were run without it.
        let mut url = format!(
            "{}/{SEARCH}?repository={}&group={}",
            self.base_url,
            encode_unreserved(&self.repository),
            encode_unreserved(group),
        );

        if let Some(cursor) = cursor {
            url.push_str("&continuationToken=");
            url.push_str(&encode_unreserved(cursor));
        }

        url
    }

    /// Every asset under one group, from the browse pages where the search
    /// finds nothing.
    ///
    /// Outside a raw repository `group` never names a folder, so the
    /// search always answers empty there; see `browse`. In a raw one an
    /// empty search is an absent artifact, and the browse confirms it.
    pub(super) async fn assets(&self, group: &str, ctx: &Ctx) -> Result<Vec<Asset>> {
        let found = self.searched(group, ctx).await?;

        if !found.is_empty() {
            return Ok(found);
        }

        self.browsed(group, ctx).await
    }

    /// Every file the browse pages show under one group.
    ///
    /// `/{folder}` is that folder's files, and `/{folder}/*` those of each
    /// sub-folder too, one level down: a `name-version-file` version is a
    /// sub-folder, and a deeper file is another name's. A missing
    /// top-level folder may be a file at the root, which the root's page
    /// shows.
    async fn browsed(&self, group: &str, ctx: &Ctx) -> Result<Vec<Asset>> {
        let (folder, deep) = match group.strip_suffix("/*") {
            Some(folder) => (folder.trim_matches('/'), true),
            None => (group.trim_matches('/'), false),
        };

        let entries = match self.browse(folder, ctx).await? {
            Some(entries) => entries,
            None if !deep && !folder.contains('/') => {
                return Ok(files_in(
                    "",
                    self.browse("", ctx).await?.unwrap_or_default(),
                ));
            }
            None => return Ok(Vec::new()),
        };

        let mut assets = Vec::new();

        for entry in entries {
            match entry {
                browse::Entry::Folder(sub) if deep => {
                    let inner = format!("{folder}/{sub}");
                    let found = self.browse(&inner, ctx).await?.unwrap_or_default();

                    assets.extend(files_in(&inner, found));
                }

                browse::Entry::Folder(_) => {}
                file => assets.extend(files_in(folder, vec![file])),
            }
        }

        Ok(assets)
    }

    pub(super) async fn browse(
        &self,
        folder: &str,
        ctx: &Ctx,
    ) -> Result<Option<Vec<browse::Entry>>> {
        browse::folder(&*self.host, &self.base_url, &self.repository, folder, ctx).await
    }

    /// Every asset the search finds under one group.
    pub(super) async fn searched(&self, group: &str, ctx: &Ctx) -> Result<Vec<Asset>> {
        paged::<AssetPage>(
            &*self.host,
            |cursor| self.search_url(group, cursor),
            "nexus asset page",
            self.page_cap,
            ctx,
        )
        .await
    }

    /// The files whose coordinate is exactly the one asked for.
    ///
    /// The client-side half of the search, and it is not belt and braces.
    /// `group` accepts `*` as a glob that crosses `/`, so a real path
    /// containing one would match a subtree; and `AsIs` and
    /// `NameVersionFile` both ask for a directory wider than the artifact.
    /// Re-reading each path through the mapping is the one check that
    /// answers all three.
    pub(super) fn files_for<'a>(
        &self,
        assets: &'a [Asset],
        id: &ArtifactId,
        version: Option<&Version>,
    ) -> Vec<(&'a Asset, Coordinate)> {
        let name = id.name().trim_matches('/');
        let wanted = version.map(Version::text);

        assets
            .iter()
            .filter_map(|asset| {
                let at = self.mapping.read(asset.path.as_deref()?)?;

                (at.name == name && at.version.as_deref() == wanted).then_some((asset, at))
            })
            .collect()
    }

    /// Every version the mapping reads out of one name's paths.
    async fn versions_under(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let name = id.name().trim_matches('/');
        let assets = self.assets(&self.group_of(id, None), ctx).await?;

        // Sorted and deduplicated by text rather than kept in arrival
        // order: a repository's own listing order is not a version order,
        // and the handler refuses to impose one. See `version::Tags`.
        let found: BTreeSet<String> = assets
            .iter()
            .filter_map(|asset| self.mapping.read(asset.path.as_deref()?))
            .filter(|at| at.name == name)
            .filter_map(|at| at.version)
            .collect();

        Ok(self
            .ecosystem
            .classify(&found.into_iter().collect::<Vec<_>>()))
    }
}

/// The files among one folder's browse rows, as assets at their paths.
fn files_in(folder: &str, entries: Vec<browse::Entry>) -> Vec<Asset> {
    entries
        .into_iter()
        .filter_map(|entry| match entry {
            browse::Entry::File {
                name,
                url,
                size,
                modified,
            } => {
                let path = match folder {
                    "" => format!("/{name}"),
                    _ => format!("/{folder}/{name}"),
                };

                Some(Asset::browsed(path, url, size, modified))
            }

            browse::Entry::Folder(_) => None,
        })
        .collect()
}

#[async_trait]
impl Source for NexusRawSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![EcosystemId::raw()]
    }

    /// Only where the mapping declares a segment is a version.
    ///
    /// `Directory` and `AsIs` both say there are none, and saying so is
    /// what lets `resolve` skip selection rather than fail on an empty
    /// candidate list.
    fn versioned(&self, _: &ArtifactId) -> bool {
        self.mapping == Mapping::NameVersionFile
    }

    /// Empty under a mapping with no versions, and **no request**.
    ///
    /// The mapping declares there is exactly one thing; a request could
    /// only confirm it, and whether the artifact is there at all is a
    /// question `metadata` answers where the files are.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        match self.versioned(id) {
            false => Ok(Vec::new()),
            true => self.versions_under(id, ctx).await,
        }
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let group = self.group_of(id, version);
        let assets = self.assets(&group, ctx).await?;
        let mine = self.files_for(&assets, id, version);

        if mine.is_empty() {
            // `Absent` rather than `Malformed`: a proxy asks the next
            // upstream about something absent and gives up on something
            // malformed, and a directory this repository does not hold is
            // the first of those.
            return Err(Error::Absent {
                what: "artifact",
                url: self.search_url(&group, None),
                name: id.purl(),
            });
        }

        // The **newest** of this artifact's own files, because a publish
        // window asks whether anything here is too new to trust yet. The
        // oldest would let a file added this morning through on the
        // strength of one added three years ago.
        let published = mine.iter().filter_map(|(asset, _)| asset.published()).max();

        Ok(ResolvedArtifact {
            id: id.clone(),
            version: version.cloned(),
            files: mine.iter().map(|(asset, at)| file_of(asset, at)).collect(),

            // A raw repository declares none, and there is nowhere it
            // could. An invented one would read as a licence somebody
            // published.
            license: None,
            published,
        })
    }

    /// None, ever, and no request to find that out.
    ///
    /// A raw repository publishes no dependency information of any kind --
    /// see `ecosystem::raw`, whose `dep_kinds` is empty for the same
    /// reason.
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
    use crate::core::ctx::Ctx;
    use crate::ext::testing::{Fixture, idle, options};
    use crate::model::{ArtifactRequest, Cause, Digest, DigestAlg};
    use crate::net::FixtureClient;
    use crate::repo::Criteria;
    use crate::version::PreRelease;
    use http::StatusCode;

    const BASE: &str = "h://nexus.test";
    const REPO: &str = "raw-hosted";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "raw".to_owned(),
        })
    }

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, name)
    }

    /// The URL one group search produces, spelled out so a test asserting
    /// it fails loudly if the shape drifts.
    fn url(group: &str) -> String {
        format!("{BASE}/{SEARCH}?repository={REPO}&group={group}")
    }

    /// One asset, in the shape the live server answers with.
    fn asset(path: &str) -> String {
        format!(
            r#"{{"path": "{path}",
                "downloadUrl": "{BASE}/repository/{REPO}{path}",
                "checksum": {{"sha256": "abc", "md5": "def"}},
                "fileSize": 15,
                "blobCreated": "2026-09-22T23:31:53.429+00:00"}}"#
        )
    }

    fn page(paths: &[&str]) -> String {
        let items: Vec<String> = paths.iter().map(|path| asset(path)).collect();

        format!(
            r#"{{"items": [{}], "continuationToken": null}}"#,
            items.join(",")
        )
    }

    fn source(mapping: &str, host: Arc<dyn ExtHost>) -> NexusRawSource {
        NexusRawSource::open(
            BASE,
            &options(serde_json::json!({"repository": REPO, "mapping": mapping})),
            host,
        )
        .expect("opens")
    }

    fn fixture(mapping: &str, group: &str, body: String) -> Fixture<NexusRawSource> {
        Fixture::build(FixtureClient::new().with_body(url(group), body), |host| {
            source(mapping, host)
        })
    }

    // -- Another format, read through the browse pages ---------------------

    fn browse_url(folder: &str) -> String {
        format!("{BASE}/service/rest/repository/browse/{REPO}/{folder}")
    }

    /// A browse page: `(name, size)` files, and `name/` folders.
    fn browse_page(folder: &str, rows: &[(&str, Option<u64>)]) -> String {
        let rows: Vec<String> = rows
            .iter()
            .map(|(name, size)| match size {
                None => format!(r#"<tr><td><a href="{name}/">{name}</a></td></tr>"#),
                Some(size) => format!(
                    r#"<tr><td><a href="{BASE}/repository/{REPO}/{folder}{name}">{name}</a></td>
                    <td>Mon Oct 05 16:14:59 Z 2026</td><td>{size}</td><td></td></tr>"#
                ),
            })
            .collect();

        format!("<table>{}</table>", rows.join(""))
    }

    fn empty_search() -> String {
        r#"{"items": [], "continuationToken": null}"#.to_owned()
    }

    /// `group` never names a folder outside raw, so an empty search is
    /// asked again of the browse page.
    #[tokio::test]
    async fn other_format_reads_browse_page() {
        let client = FixtureClient::new()
            .with_body(url("%2Fexample%2Flib%2F1.0"), empty_search())
            .with_body(
                browse_url("example/lib/1.0/"),
                browse_page(
                    "example/lib/1.0/",
                    &[("lib-1.0.jar", Some(884)), ("sub", None)],
                ),
            );
        let f = Fixture::build(client, |host| source("directory", host));

        let artifact = f
            .subject
            .metadata(&id("example/lib/1.0"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(artifact.files.len(), 1);
        assert_eq!(artifact.files[0].name, "lib-1.0.jar");
        assert_eq!(artifact.files[0].size, Some(884));
        assert!(artifact.files[0].digests.is_empty());
        assert!(artifact.published.is_some());
    }

    /// A version is a sub-folder holding files; a deeper one is another
    /// name's.
    #[tokio::test]
    async fn other_format_versions_are_sub_folders() {
        let client = FixtureClient::new()
            .with_body(url("%2Ftools%2Ffmt%2F%2A"), empty_search())
            .with_body(
                browse_url("tools/fmt/"),
                browse_page("tools/fmt/", &[("2.0", None), ("cli", None)]),
            )
            .with_body(
                browse_url("tools/fmt/2.0/"),
                browse_page("tools/fmt/2.0/", &[("fmt.zip", Some(3))]),
            )
            .with_body(
                browse_url("tools/fmt/cli/"),
                browse_page("tools/fmt/cli/", &[("2.0", None)]),
            );
        let f = Fixture::build(client, |host| source("name-version-file", host));

        let versions = f
            .subject
            .versions(&id("tools/fmt"), &ctx())
            .await
            .expect("lists");
        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(texts, ["2.0"]);
    }

    /// A file at the root has no folder of its own; the root's page shows it.
    #[tokio::test]
    async fn other_format_root_file_is_found() {
        let client = FixtureClient::new()
            .with_body(url("%2Fnotes.txt"), empty_search())
            .with(
                browse_url("notes.txt/"),
                crate::net::Canned::status(StatusCode::NOT_FOUND),
            )
            .with_body(browse_url(""), browse_page("", &[("notes.txt", Some(5))]));
        let f = Fixture::build(client, |host| source("directory", host));

        let artifact = f
            .subject
            .metadata(&id("notes.txt"), None, &ctx())
            .await
            .expect("resolves");

        assert_eq!(artifact.files[0].name, "notes.txt");
    }

    // -- Configuration -----------------------------------------------------

    /// One Nexus serves many repositories and there is no sensible
    /// default, so the name is required rather than guessed.
    #[test]
    fn repository_required() {
        assert!(NexusRawSource::open(BASE, &Options::default(), idle()).is_err());
    }

    /// The reading that matches how a raw repository is actually laid out.
    #[test]
    fn mapping_defaults_to_directory() {
        let opened = NexusRawSource::open(
            BASE,
            &options(serde_json::json!({"repository": REPO})),
            idle(),
        )
        .expect("opens");

        assert_eq!(opened.mapping, Mapping::Directory);
    }

    #[test]
    fn mapping_unknown_refused() {
        let bogus = options(serde_json::json!({"repository": REPO, "mapping": "regex"}));

        assert!(NexusRawSource::open(BASE, &bogus, idle()).is_err());
    }

    /// A raw source speaks `raw` and nothing else, so a Maven purl handed
    /// to it is a bug worth saying out loud.
    #[test]
    fn ecosystem_foreign_refused() {
        let opened = source("directory", idle());

        assert!(opened.ecosystem(&id("a/b")).is_ok());
        assert!(
            opened
                .ecosystem(&ArtifactId::new(EcosystemId::maven(), Some("g"), "a"))
                .is_err()
        );
        assert_eq!(opened.ecosystems(), vec![EcosystemId::raw()]);
    }

    // -- Versions ----------------------------------------------------------

    /// **The directory mapping has no versions, and costs no request to
    /// say so.** The mapping declares there is exactly one thing; a request
    /// could only confirm it, and whether the artifact is there at all is a
    /// question `metadata` answers where the files are.
    #[tokio::test]
    async fn directory_mapping_has_no_versions() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt"]));
        let ctx = ctx();

        assert!(!f.subject.versioned(&id("a/b")));
        assert!(
            f.subject
                .versions(&id("a/b"), &ctx)
                .await
                .expect("asked")
                .is_empty()
        );
        assert!(f.requested().is_empty(), "{:?}", f.requested());
    }

    /// `name-version-file` does have versions, read off the paths under one
    /// name.
    #[tokio::test]
    async fn mapping_name_version_file_reads_versions() {
        let f = fixture(
            "name-version-file",
            "%2Facme%2F%2A",
            page(&["/acme/1.0/x.tgz", "/acme/2.0/x.tgz", "/acme/2.0/x.tgz.sha1"]),
        );
        let ctx = ctx();

        assert!(f.subject.versioned(&id("acme")));

        let versions = f.subject.versions(&id("acme"), &ctx).await.expect("asked");

        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(texts, ["1.0", "2.0"]);
    }

    // -- Metadata ----------------------------------------------------------

    /// **The leading `/` is not optional.** Measured: a group without one
    /// returns an empty page, which would read as "this artifact is not
    /// here" rather than as a malformed query.
    #[tokio::test]
    async fn metadata_asks_once_by_group_with_leading_separator() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt"]));
        let ctx = ctx();

        f.subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        assert_eq!(f.requested(), vec![url("%2Fa%2Fb")]);
    }

    /// A directory's files are its own, and a sub-directory's are not --
    /// which is what keeps a deep tree from collapsing into one artifact
    /// holding everything beneath it.
    #[tokio::test]
    async fn directory_files_are_its_own() {
        let f = fixture(
            "directory",
            "%2Fa%2Fb",
            page(&["/a/b/x.txt", "/a/b/y.txt", "/a/b/c/z.txt"]),
        );
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        let names: Vec<&str> = artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["x.txt", "y.txt"]);
        assert_eq!(artifact.version, None);
        assert_eq!(artifact.purl(), "pkg:raw/a%2Fb");
    }

    /// **A `*` in a real path is a path, not a pattern.**
    ///
    /// `group` accepts `*` as a glob that crosses `/`, so a server asked
    /// about a directory whose name contains one could answer with a whole
    /// subtree. Every asset is re-read through the mapping, which is the
    /// one check that makes that safe.
    #[tokio::test]
    async fn path_star_is_literal() {
        let f = fixture(
            "directory",
            "%2Fa%2F%2A",
            page(&["/a/*/kept.txt", "/a/b/matched-by-the-glob.txt"]),
        );
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/*"), None, &ctx)
            .await
            .expect("fetched");

        let names: Vec<&str> = artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["kept.txt"]);
    }

    /// Every checksum the server declared, and the strongest is what a
    /// verification will use.
    #[tokio::test]
    async fn metadata_every_declared_checksum_reaches_file() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt"]));
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        let file = &artifact.files[0];

        assert_eq!(file.size, Some(15));
        assert_eq!(file.best_digest().expect("one").alg, DigestAlg::Sha256);
        assert_eq!(file.digests.len(), 2);
        assert!(file.url.ends_with("/a/b/x.txt"));
    }

    /// **A zero size is undeclared**, because Nexus search reports 0 when
    /// its index lacks the size. Trusting it failed every copy.
    #[tokio::test]
    async fn metadata_zero_size_undeclared() {
        let body = r#"{"items": [
            {"path": "/a/b/x.txt", "downloadUrl": "h://nexus.test/repository/raw-hosted/a/b/x.txt",
             "checksum": {"sha256": "bb"}, "fileSize": 0}
        ], "continuationToken": null}"#;

        let f = fixture("directory", "%2Fa%2Fb", body.to_owned());
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        let file = &artifact.files[0];

        assert_eq!(file.size, None);
        assert_eq!(file.digests, [Digest::new(DigestAlg::Sha256, "bb")]);
    }

    /// **`blobCreated`, not `lastModified`**, and the newest of the
    /// artifact's own files: a publish window asks whether anything here is
    /// too new to trust yet.
    #[tokio::test]
    async fn metadata_published_is_newest_blob_creation() {
        let body = r#"{"items": [
            {"path": "/a/b/old.txt", "blobCreated": "2020-01-01T00:00:00+00:00",
             "lastModified": "2026-09-22T23:33:08.066+00:00"},
            {"path": "/a/b/new.txt", "blobCreated": "2024-06-01T00:00:00+00:00",
             "lastModified": "2026-09-22T23:33:08.066+00:00"}
        ]}"#
        .to_owned();

        let f = fixture("directory", "%2Fa%2Fb", body);
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        assert_eq!(
            artifact.published.expect("a time").to_rfc3339(),
            "2024-06-01T00:00:00+00:00"
        );
    }

    /// A directory this repository does not hold is `Absent`, not
    /// `Malformed`: a proxy asks the next upstream about the first and
    /// gives up on the second.
    #[tokio::test]
    async fn directory_absent_when_nobody_has() {
        let f = fixture("directory", "%2Fa%2Fb", r#"{"items": []}"#.to_owned());
        let ctx = ctx();

        let err = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect_err("nothing there");

        assert!(matches!(err, Error::Absent { .. }), "{err:?}");
    }

    /// A raw repository publishes no dependency information of any kind,
    /// and finding that out costs nothing.
    #[tokio::test]
    async fn dependencies_none_from_raw_repository() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt"]));
        let ctx = ctx();

        let artifact = ResolvedArtifact {
            id: id("a/b"),
            version: None,
            files: Vec::new(),
            license: None,
            published: None,
        };

        assert!(
            f.subject
                .deps(&artifact, &ctx)
                .await
                .expect("asked")
                .is_empty()
        );
        assert!(f.requested().is_empty());
    }

    /// A raw repository declares no licence, and there is nowhere it
    /// could. An invented one would read as a licence somebody published.
    #[tokio::test]
    async fn metadata_no_licence_claimed() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt"]));
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.license, None);
    }

    /// The leading separator a server happens to send does not change
    /// whose file it is: a production Nexus reports paths without one and a
    /// freshly configured one with.
    #[tokio::test]
    async fn path_without_leading_separator_matches() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["a/b/x.txt"]));
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.files.len(), 1);
    }

    // -- Paging ------------------------------------------------------------

    /// A directory bigger than one page is followed to the end.
    #[tokio::test]
    async fn directory_followed_across_pages() {
        let first = format!(
            r#"{{"items": [{}], "continuationToken": "next"}}"#,
            asset("/a/b/x.txt")
        );

        let client = FixtureClient::new()
            .with_body(url("%2Fa%2Fb"), first)
            .with_body(
                format!("{}&continuationToken=next", url("%2Fa%2Fb")),
                page(&["/a/b/y.txt"]),
            );

        let f = Fixture::build(client, |host| source("directory", host));
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        assert_eq!(artifact.files.len(), 2);
    }

    /// **A repeated continuation token ends the walk rather than looping
    /// forever.** Not defensive programming: Nexus has been observed
    /// handing back the token that produced the page.
    #[tokio::test]
    async fn continuation_token_repeated_ends_walk() {
        let stuck = format!(
            r#"{{"items": [{}], "continuationToken": "same"}}"#,
            asset("/a/b/x.txt")
        );

        let client = FixtureClient::new()
            .with_body(url("%2Fa%2Fb"), stuck.clone())
            .with_body(format!("{}&continuationToken=same", url("%2Fa%2Fb")), stuck);

        let f = Fixture::build(client, |host| source("directory", host));
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id("a/b"), None, &ctx)
            .await
            .expect("fetched");

        // Two requests: the first page, and the one that repeated itself.
        assert_eq!(f.requested().len(), 2);
        assert_eq!(artifact.files.len(), 2);
    }
    // -- Resolution --------------------------------------------------------

    /// **A versionless artifact resolves**, which is the whole point of
    /// `Source::versioned`.
    ///
    /// `resolve` normally asks for a version list and steps down through
    /// it; here there is nothing to step through, and a source answering
    /// `versioned() == false` makes it skip selection rather than fail on
    /// an empty candidate list. Without this the directory mapping would
    /// walk and record a repository it could never copy.
    #[tokio::test]
    async fn resolve_versionless_without_selecting() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt", "/a/b/y.txt"]));
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id("a/b"),
            spec: crate::model::VersionSpec::Any,
            prov: std::sync::Arc::new(crate::model::Provenance::root(Cause::Requested {
                arg: "a/b".to_owned(),
            })),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version, None);
        assert_eq!(artifact.files.len(), 2);

        // One request: `versions` asked nothing, so the whole resolution
        // costs what `metadata` costs.
        assert_eq!(f.requested().len(), 1);
    }

    /// And the ecosystem's own coordinate parser reaches the same artifact,
    /// so `inspect nexus-local-raw artifact1/1.0` and a report row naming
    /// `pkg:raw/artifact1%2F1.0` are the same request.
    #[tokio::test]
    async fn resolve_typed_coordinate_same_artifact() {
        let f = fixture("directory", "%2Fa%2Fb", page(&["/a/b/x.txt"]));
        let ctx = ctx();

        let request = crate::ecosystem::Raw.parse_req("a/b").expect("parsed");

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.purl(), "pkg:raw/a%2Fb");
    }
}
