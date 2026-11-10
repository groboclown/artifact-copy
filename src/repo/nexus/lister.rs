//! What a Nexus repository stores for one artifact, from its search API.
//!
//! ```text
//!   GET {base}/service/rest/v1/search?repository={r}&maven.groupId={g}&maven.artifactId={a}[&maven.baseVersion={v}]
//!   GET {base}/service/rest/v1/search?repository={r}&name={n}[&group={scope}][&version={v}]
//! ```
//!
//! Measured on 3.96.3: `name` matches exactly, but `*` is a glob, so every
//! match is checked again here rather than trusted.
//!
//! # Versions
//!
//! Only Maven's come from here.  Nexus does not rebuild `maven-metadata.xml`
//! on upload, so the index a Maven client reads can miss what the
//! repository holds; npm's packument and PyPI's simple index are generated
//! from what it holds, and stay with the protocol source.  Snapshot builds
//! fold into their `-SNAPSHOT` version, as the enumerator folds them.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::asset::{Asset, Match, SearchPage};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ext::ExtHost;
use crate::model::{ArtifactId, EcosystemId, FileRef, Version};
use crate::net::encode_unreserved;
use crate::repo::PageCap;
use crate::repo::manager::{Lister, Listing};

/// The component search endpoint, relative to the Nexus base URL.
const SEARCH: &str = "service/rest/v1/search";

pub(super) struct NexusLister {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    repository: String,
    ecosystem: EcosystemId,
    page_cap: PageCap,
}

impl NexusLister {
    pub(super) fn new(
        base_url: String,
        host: Arc<dyn ExtHost>,
        repository: String,
        ecosystem: EcosystemId,
        page_cap: PageCap,
    ) -> Self {
        Self {
            base_url,
            host,
            repository,
            ecosystem,
            page_cap,
        }
    }

    /// The search for one artifact, or one version of it.
    fn search_url(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        cursor: Option<&str>,
    ) -> String {
        let mut filters: Vec<(&str, String)> = match self.ecosystem.as_str() {
            EcosystemId::MAVEN => vec![
                (
                    "maven.groupId",
                    id.namespace().unwrap_or_default().to_owned(),
                ),
                ("maven.artifactId", id.name().to_owned()),
            ],

            // Nexus keeps an npm scope in `group`, without its `@`.
            _ => {
                let mut filters = vec![("name", id.name().to_owned())];

                if let Some(scope) = id.namespace() {
                    filters.push(("group", scope.trim_start_matches('@').to_owned()));
                }

                filters
            }
        };

        // A Maven snapshot's components carry timestamped versions, and its
        // base version is what selects them all.
        if let Some(version) = version {
            let key = match self.ecosystem.as_str() {
                EcosystemId::MAVEN => "maven.baseVersion",
                _ => "version",
            };

            filters.push((key, version.text().to_owned()));
        }

        let mut url = format!(
            "{}/{SEARCH}?repository={}",
            self.base_url,
            encode_unreserved(&self.repository)
        );

        for (key, value) in filters {
            url.push_str(&format!("&{key}={}", encode_unreserved(&value)));
        }

        if let Some(cursor) = cursor {
            url.push_str("&continuationToken=");
            url.push_str(&encode_unreserved(cursor));
        }

        url
    }

    async fn matches(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<Vec<Match>> {
        let found = super::paged::<SearchPage>(
            &*self.host,
            |cursor| self.search_url(id, version, cursor),
            "nexus search page",
            self.page_cap,
            ctx,
        )
        .await?;

        Ok(found.into_iter().filter(|one| self.is(one, id)).collect())
    }

    /// Whether a match is the artifact asked for, exactly.
    fn is(&self, one: &Match, id: &ArtifactId) -> bool {
        let group = one.group.as_deref().filter(|text| !text.is_empty());

        match self.ecosystem.as_str() {
            EcosystemId::NPM => {
                let scope = id.namespace().map(|scope| scope.trim_start_matches('@'));

                one.name == id.name() && group.map(|g| g.trim_start_matches('@')) == scope
            }

            EcosystemId::PYPI => {
                crate::ecosystem::pypi::normalize(&one.name)
                    == crate::ecosystem::pypi::normalize(id.name())
            }

            _ => one.name == id.name() && group == id.namespace(),
        }
    }

    /// The version a match belongs to: a Maven build folds into its
    /// snapshot.
    fn version_of(&self, one: &Match) -> Option<String> {
        let text = one.version.as_deref().filter(|text| !text.is_empty())?;

        let snapshot = match self.ecosystem.as_str() {
            EcosystemId::MAVEN => crate::ecosystem::maven::snapshot_of(text),
            _ => None,
        };

        Some(snapshot.unwrap_or_else(|| text.to_owned()))
    }
}

/// One asset as a file, when it names one.
fn file_of(asset: &Asset) -> Option<FileRef> {
    let mut file = FileRef::new(asset.file_name()?, asset.download_url.clone()?);

    // Nexus search reports 0 when its index lacks the size.
    file.size = asset.file_size.filter(|&size| size > 0);
    file.digests = asset.digests();

    Some(file)
}

#[async_trait]
impl Lister for NexusLister {
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Option<Vec<String>>> {
        if self.ecosystem.as_str() != EcosystemId::MAVEN {
            return Ok(None);
        }

        let texts: BTreeSet<String> = self
            .matches(id, None, ctx)
            .await?
            .iter()
            .filter_map(|one| self.version_of(one))
            .collect();

        Ok(Some(texts.into_iter().collect()))
    }

    async fn listing(&self, id: &ArtifactId, version: &Version, ctx: &Ctx) -> Result<Listing> {
        let wanted = version.text();
        let matches = self.matches(id, Some(version), ctx).await?;
        let assets: Vec<&Asset> = matches
            .iter()
            .filter(|one| self.version_of(one).as_deref() == Some(wanted))
            .flat_map(|one| &one.assets)
            .collect();

        Ok(Listing {
            files: assets.iter().filter_map(|asset| file_of(asset)).collect(),

            // The newest, because a publish window asks whether anything
            // here is too new to trust yet.
            published: assets.iter().filter_map(|asset| asset.published()).max(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::testing::TestHost;
    use crate::model::{Cause, Release};
    use crate::net::FixtureClient;

    const BASE: &str = "h://nexus.test";
    const REPO: &str = "maven-a";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    fn lister(ecosystem: EcosystemId, body: (&str, &str)) -> NexusLister {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(body.0.to_owned(), body.1.to_owned()),
        ));

        let cap = super::super::page_cap(&crate::ext::Options::default()).expect("default cap");

        NexusLister::new(BASE.into(), host, REPO.into(), ecosystem, cap)
    }

    fn maven() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    const MAVEN_SEARCH: &str = "h://nexus.test/service/rest/v1/search?repository=maven-a&maven.groupId=org.example&maven.artifactId=lib";

    /// A trimmed copy of what 3.96.3 answered.
    const MAVEN_BODY: &str = r#"{"items": [
        {"format": "maven2", "group": "org.example", "name": "lib", "version": "1.0",
         "assets": [
            {"path": "/org/example/lib/1.0/lib-1.0.jar",
             "downloadUrl": "h://nexus.test/repository/maven-a/org/example/lib/1.0/lib-1.0.jar",
             "checksum": {"sha1": "aa", "sha256": "bb"}, "fileSize": 42,
             "blobCreated": "2026-09-29T15:42:36.951+00:00"},
            {"path": "/org/example/lib/1.0/lib-1.0.module",
             "downloadUrl": "h://nexus.test/repository/maven-a/org/example/lib/1.0/lib-1.0.module",
             "checksum": {"sha1": "cc"}, "fileSize": 0,
             "blobCreated": "2026-09-29T15:43:00.000+00:00"}
         ]},
        {"format": "maven2", "group": "org.example", "name": "lib",
         "version": "2.0-20240101.123456-3", "assets": []},
        {"format": "maven2", "group": "org.example", "name": "lib-extra", "version": "9.0",
         "assets": []}
    ], "continuationToken": null}"#;

    #[tokio::test]
    async fn maven_versions_fold_snapshots_and_skip_glob_matches() {
        let versions = lister(EcosystemId::maven(), (MAVEN_SEARCH, MAVEN_BODY))
            .versions(&maven(), &ctx())
            .await
            .expect("lists")
            .expect("maven answers");

        assert_eq!(versions, ["1.0", "2.0-SNAPSHOT"]);
    }

    #[tokio::test]
    async fn listing_carries_digests_sizes_newest_time() {
        let url = format!("{MAVEN_SEARCH}&maven.baseVersion=1.0");
        let listing = lister(EcosystemId::maven(), (&url, MAVEN_BODY))
            .listing(&maven(), &Version::new("1.0", Release::General), &ctx())
            .await
            .expect("lists");

        let names: Vec<&str> = listing.files.iter().map(|f| f.name.as_str()).collect();

        assert_eq!(names, ["lib-1.0.jar", "lib-1.0.module"]);
        assert_eq!(listing.files[0].size, Some(42));
        assert_eq!(listing.files[0].digests.len(), 2);

        // Zero is an index gap, not an empty file.
        assert_eq!(listing.files[1].size, None);
        assert_eq!(
            listing.published.map(|when| when.to_rfc3339()),
            Some("2026-09-29T15:43:00+00:00".to_owned())
        );
    }

    #[tokio::test]
    async fn npm_leaves_versions_to_packument() {
        let id = ArtifactId::new(EcosystemId::npm(), None, "left-pad");
        let answer = lister(EcosystemId::npm(), ("h://unused.test", "{}"))
            .versions(&id, &ctx())
            .await
            .expect("answers");

        assert_eq!(answer, None);
    }

    #[test]
    fn npm_scope_searched_without_at() {
        let id = ArtifactId::new(EcosystemId::npm(), Some("@acme"), "widget");
        let url = lister(EcosystemId::npm(), ("h://unused.test", "{}")).search_url(
            &id,
            Some(&Version::new("1.0.0", Release::General)),
            None,
        );

        assert!(
            url.ends_with("&name=widget&group=acme&version=1.0.0"),
            "{url}"
        );
    }

    #[test]
    fn pypi_names_compare_normalized() {
        let lister = lister(EcosystemId::pypi(), ("h://unused.test", "{}"));
        let id = ArtifactId::new(EcosystemId::pypi(), None, "my-pkg");
        let stored = Match {
            group: None,
            name: "My_Pkg".into(),
            version: Some("1.0".into()),
            assets: Vec::new(),
        };

        assert!(lister.is(&stored, &id));
    }
}
