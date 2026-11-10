//! Reading a raw repository's components through the path mapping.

use crate::core::ctx::Ctx;
use crate::core::problem::Code;
use crate::message;
use crate::model::ArtifactId;
use crate::repo::Coordinate;
use crate::repo::enumerate::Found;

use super::NexusEnumerator;
use super::component::Component;

impl NexusEnumerator {
    /// The coordinate a raw component's path names, or `None` with a
    /// problem recorded.
    ///
    /// A raw repository holds whatever somebody put in it, so a path the
    /// mapping does not fit is a finding rather than a failure -- one stray
    /// file must not fail a walk of a million laid out correctly. That rule
    /// is `Mapping::read`'s; this is where it is acted on.
    fn raw_id(&self, component: &Component, ctx: &Ctx) -> Option<(ArtifactId, Coordinate)> {
        // One asset: `found` splits a component per asset before asking.
        let path = component.paths().next().or(Some(&component.name))?;

        let Some(at) = self.mapping.read(path) else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "nexus-raw-path-unmapped",
                    "{path} in {repository} does not fit the {mapping} mapping; \
                     it is skipped",
                    path = path,
                    repository = &self.repository,
                    mapping = self.mapping.as_str(),
                ),
            );

            return None;
        };

        Some((ArtifactId::new(self.ecosystem.clone(), None, &at.name), at))
    }

    /// One single-asset component read through the mapping.
    ///
    /// Raw takes its coordinate from the asset path rather than from
    /// `group` and `name`, and its version from the mapping rather than
    /// from the component -- which reports none.
    pub(super) fn raw_found(&self, component: &Component, ctx: &Ctx) -> Option<Found> {
        let (id, at) = self.raw_id(component, ctx)?;

        Some(
            Found::new(id)
                .maybe_version(at.version.as_deref().map(|text| self.classify(text)))
                .last_download(component.last_download())
                .files(self.listed(component)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ext::testing::{TestHost, options};
    use crate::model::EcosystemId;
    use crate::model::LastDownload;
    use crate::net::FixtureClient;
    use crate::repo::enumerate::{Enumerator, Page};
    use crate::repo::nexus::enumerator::testing::*;
    use std::sync::Arc;

    /// A raw walk against the local test server, in the shape it answers:
    /// one asset per component, `group` the directory, `version` an empty
    /// string rather than null.
    const RAW_PAGE: &str = r#"{"items": [
        {"format": "raw", "group": "/artifact1/1.0", "name": "/artifact1/1.0/a1.txt",
         "version": "", "assets": [{"path": "/artifact1/1.0/a1.txt"}]},
        {"format": "raw", "group": "/artifact1/1.0", "name": "/artifact1/1.0/a2.txt",
         "version": "", "assets": [{"path": "/artifact1/1.0/a2.txt"}]},
        {"format": "raw", "group": "/artifact3", "name": "/artifact3/versionless.txt",
         "version": "", "assets": [{"path": "/artifact3/versionless.txt"}]}
    ]}"#;

    async fn raw_walk(body: &str, ctx: &Ctx) -> Page {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(url(None), body.to_owned()),
        ));

        NexusEnumerator::open(BASE, &config("raw"), host.clone())
            .expect("opens")
            .walk(None, ctx)
            .await
            .expect("walked")
    }

    /// Read as raw, a Maven component's assets are paths like any other:
    /// its folder is one artifact, with the sidecars among its files.
    #[tokio::test]
    async fn other_format_reads_as_raw() {
        let body = r#"{"items": [
            {"format": "maven2", "group": "example.lib", "name": "echo", "version": "1.0",
             "assets": [
                {"path": "example/lib/echo/1.0/echo-1.0.jar",
                 "downloadUrl": "h://nexus.test/repository/r/example/lib/echo/1.0/echo-1.0.jar"},
                {"path": "example/lib/echo/1.0/echo-1.0.jar.sha1",
                 "downloadUrl": "h://nexus.test/repository/r/example/lib/echo/1.0/echo-1.0.jar.sha1"},
                {"path": "example/lib/echo/1.0/echo-1.0.pom",
                 "downloadUrl": "h://nexus.test/repository/r/example/lib/echo/1.0/echo-1.0.pom"}
             ]}
        ]}"#;

        let ctx = ctx();
        let page = raw_walk(body, &ctx).await;

        assert_eq!(page.found.len(), 1, "{:?}", page.found);
        assert_eq!(page.found[0].id.name(), "example/lib/echo/1.0");
        assert_eq!(page.found[0].files.len(), 3);
        assert!(ctx.problems().counts().is_empty());
    }

    /// A directory's components are one artifact, and so are their files.
    /// Raw has no sidecar convention, so a `.sha1` here is a file.
    #[tokio::test]
    async fn raw_components_list_files() {
        let body = r#"{"items": [
            {"format": "raw", "group": "/tools/1.0", "name": "/tools/1.0/cli.tgz",
             "assets": [{"path": "/tools/1.0/cli.tgz", "downloadUrl": "h://nexus.test/r/tools/1.0/cli.tgz"}]},
            {"format": "raw", "group": "/tools/1.0", "name": "/tools/1.0/cli.tgz.sha1",
             "assets": [{"path": "/tools/1.0/cli.tgz.sha1", "downloadUrl": "h://nexus.test/r/tools/1.0/cli.tgz.sha1"}]}
        ]}"#;
        let ctx = ctx();
        let page = raw_walk(body, &ctx).await;

        let names: Vec<&str> = page.found[0]
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(page.found.len(), 1);
        assert_eq!(names, ["cli.tgz", "cli.tgz.sha1"]);
    }

    /// **The basic reading.** Files in one directory are one artifact's
    /// files, so three components become two artifacts.
    #[tokio::test]
    async fn directory_is_one_artifact() {
        let ctx = ctx();
        let page = raw_walk(RAW_PAGE, &ctx).await;

        let names: Vec<&str> = page.found.iter().map(|one| one.id.name()).collect();

        assert_eq!(names, ["artifact1/1.0", "artifact3"]);
    }

    /// **A raw artifact has no version**, and the empty string this server
    /// sends is no version either.
    ///
    /// A `Version` whose text is empty would be written to the report as a
    /// version that is blank rather than absent, and `purl_at("")` renders
    /// a trailing `@` that parses back to nothing -- so every purl
    /// comparison deciding a copy would be comparing two spellings of one
    /// artifact.
    #[tokio::test]
    async fn raw_artifact_has_no_version() {
        let ctx = ctx();
        let page = raw_walk(RAW_PAGE, &ctx).await;

        assert!(page.found.iter().all(|one| one.version.is_none()));
        assert_eq!(page.found[0].id.purl(), "pkg:raw/artifact1%2F1.0");
    }

    /// A sub-directory is a different artifact, which is what keeps a deep
    /// tree from collapsing into one artifact holding everything beneath
    /// it.
    #[tokio::test]
    async fn directory_sub_is_different_artifact() {
        let body = r#"{"items": [
            {"format": "raw", "name": "a/b/x.tgz", "assets": [{"path": "a/b/x.tgz"}]},
            {"format": "raw", "name": "a/b/c/y.tgz", "assets": [{"path": "a/b/c/y.tgz"}]}
        ]}"#;

        let ctx = ctx();
        let page = raw_walk(body, &ctx).await;

        let names: Vec<&str> = page.found.iter().map(|one| one.id.name()).collect();

        assert_eq!(names, ["a/b", "a/b/c"]);
    }

    /// The leading separator a server happens to send does not change the
    /// coordinate.
    ///
    /// Measured: a production Nexus reports `some-project/tool/file` and a
    /// freshly configured one reports `/artifact1/1.0/a1.txt`, for the same
    /// field of the same API. One file must not read as two artifacts
    /// depending on which answered.
    #[tokio::test]
    async fn separator_leading_keeps_coordinate() {
        let bare = r#"{"items": [
            {"format": "raw", "name": "a/b/x.tgz", "assets": [{"path": "a/b/x.tgz"}]}
        ]}"#;
        let led = r#"{"items": [
            {"format": "raw", "name": "/a/b/x.tgz", "assets": [{"path": "/a/b/x.tgz"}]}
        ]}"#;

        let ctx = ctx();

        assert_eq!(
            raw_walk(bare, &ctx).await.found[0].id,
            raw_walk(led, &ctx).await.found[0].id
        );
    }

    /// A file at the repository root is its own artifact rather than being
    /// dropped: losing a file from a migration silently is the worse
    /// answer.
    ///
    /// Reachable, though only through one door -- Nexus refuses a component
    /// upload with no directory and accepts a plain `PUT` to the repository
    /// root, measured.
    #[tokio::test]
    async fn root_file_is_own_artifact() {
        let body = r#"{"items": [
            {"format": "raw", "name": "/readme.txt", "assets": [{"path": "/readme.txt"}]}
        ]}"#;

        let ctx = ctx();
        let page = raw_walk(body, &ctx).await;

        assert_eq!(page.found.len(), 1);
        assert_eq!(page.found[0].id.name(), "readme.txt");
    }

    /// **Repeats fold within a page, and usage folds with them.**
    ///
    /// Downloading any file is using the artifact, so a directory whose
    /// files report `Never` and a timestamp is an artifact that was used.
    /// Reporting disuse for something in use is the mistake that gets a
    /// live artifact deleted.
    #[tokio::test]
    async fn page_repeats_fold_with_usage() {
        let body = r#"{"items": [
            {"format": "raw", "name": "a/b/x.tgz",
             "assets": [{"path": "a/b/x.tgz", "lastDownloaded": null}]},
            {"format": "raw", "name": "a/b/y.tgz",
             "assets": [{"path": "a/b/y.tgz",
                         "lastDownloaded": "2026-09-10T04:42:28.414+00:00"}]}
        ]}"#;

        let ctx = ctx();
        let page = raw_walk(body, &ctx).await;

        assert_eq!(page.found.len(), 1);
        assert!(
            matches!(page.found[0].last_download, LastDownload::At(_)),
            "the timestamp was thrown away: {:?}",
            page.found[0].last_download
        );
    }

    /// **Findings still repeat across pages, deliberately.**
    ///
    /// Deduplicating would need a set of every artifact seen, which grows
    /// with the catalog and is exactly what the memory discipline forbids.
    /// A directory's files really do straddle pages -- a captured
    /// repository has 42 of 65 components in one group -- and the report
    /// database converges the repeats through its upserts.
    #[tokio::test]
    async fn findings_repeat_across_pages() {
        let one = r#"{"items": [
            {"format": "raw", "name": "a/b/x.tgz", "assets": [{"path": "a/b/x.tgz"}]}
        ], "continuationToken": "next"}"#;
        let two = r#"{"items": [
            {"format": "raw", "name": "a/b/y.tgz", "assets": [{"path": "a/b/y.tgz"}]}
        ]}"#;

        let ctx = ctx();
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with_body(url(None), one.to_owned())
                .with_body(url(Some("next")), two.to_owned()),
        ));

        let enumerator = NexusEnumerator::open(BASE, &config("raw"), host.clone()).expect("opens");

        let first = enumerator.walk(None, &ctx).await.expect("walked");
        let cursor = first.next.clone().expect("more to come");
        let second = enumerator.walk(Some(&cursor), &ctx).await.expect("walked");

        assert_eq!(first.found[0].id, second.found[0].id);
    }

    /// A raw repository holds whatever somebody put in it, so a path the
    /// mapping does not fit is a finding rather than a failure: one stray
    /// file must not fail a walk of a million laid out correctly.
    #[tokio::test]
    async fn path_misfit_skipped_reported() {
        let body = r#"{"items": [
            {"format": "raw", "name": "acme/1.0/x.tgz",
             "assets": [{"path": "acme/1.0/x.tgz"}]},
            {"format": "raw", "name": "stray.txt", "assets": [{"path": "stray.txt"}]}
        ]}"#;

        let ctx = ctx();
        let options = options(serde_json::json!({
            "repository": REPO,
            "ecosystem": "raw",
            "mapping": "name-version-file",
        }));

        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(url(None), body.to_owned()),
        ));
        let page = NexusEnumerator::open(BASE, &options, host.clone())
            .expect("opens")
            .walk(None, &ctx)
            .await
            .expect("walked");

        assert_eq!(page.found.len(), 1);
        assert_eq!(page.found[0].id.name(), "acme");
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// There is no OSV ecosystem for arbitrary files, and the enumerator must
    /// say the same thing the ecosystem does -- otherwise a screen looks up
    /// an ecosystem that does not exist and reports a failed lookup where
    /// the truth is "nothing screens this".
    #[test]
    fn raw_has_no_osv_name() {
        assert_eq!(crate::repo::enumerate::osv_name_of(&EcosystemId::raw()), "");
    }
}
