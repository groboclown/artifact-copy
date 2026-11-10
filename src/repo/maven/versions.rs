//! Which versions an artifact has: `maven-metadata.xml`, the artifact
//! directory's index, a probe, and a snapshot's builds.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use std::sync::Arc;

use http::StatusCode;

use super::metadata::{self, Snapshot};
use super::{METADATA_FILE, MavenSource, is_safe_segment};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::{Action, Code};
use crate::ext::Options;
use crate::message;
use crate::model::ArtifactId;
use crate::net::{ByteLimit, Req};

/// Option: how versions `maven-metadata.xml` does not list are found.
const VERSION_DISCOVERY: &str = "version-discovery";

/// One artifact directory's HTML index: a line per version.
const ARTIFACT_INDEX_LIMIT: ByteLimit = ByteLimit::mib(4);

/// The `version-discovery` option.
///
/// `maven-metadata.xml` can be stale: Central's for `qdox:qdox` lists
/// `0.1` to `1.5`, while `1.6/` and `1.6.1/` are served beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VersionDiscovery {
    /// `maven-metadata.xml` alone.
    Metadata,

    /// The default: an exact version the metadata does not list is
    /// confirmed by its POM, one `HEAD` only when the list falls short.
    Probe,

    /// The artifact directory's HTML index joined with the metadata, one
    /// request per artifact; for a host serving an autoindex.
    HtmlIndex,

    /// Both.
    Both,
}

impl VersionDiscovery {
    pub(super) fn read(options: &Options) -> Result<Self> {
        match options.string(VERSION_DISCOVERY)? {
            None | Some("probe") => Ok(Self::Probe),
            Some("metadata") => Ok(Self::Metadata),
            Some("html-index") => Ok(Self::HtmlIndex),
            Some("both") => Ok(Self::Both),

            Some(other) => Err(Error::Config(format!(
                "the maven source's {VERSION_DISCOVERY:?} option is \"probe\", \"metadata\", \
                 \"html-index\", or \"both\", not {other:?}"
            ))),
        }
    }

    pub(super) fn probes(self) -> bool {
        matches!(self, Self::Probe | Self::Both)
    }

    /// Whether an exact release version is confirmed by its POM before
    /// any list: every mode but `metadata`, which trusts the list alone.
    pub(super) fn confirms(self) -> bool {
        self != Self::Metadata
    }

    fn indexes(self) -> bool {
        matches!(self, Self::HtmlIndex | Self::Both)
    }
}

/// A link naming a version folder in an artifact directory's index, rather
/// than a parent, a file, a sort control, or another site.
fn version_folder(href: &str) -> Option<&str> {
    let name = href.strip_prefix("./").unwrap_or(href).strip_suffix('/')?;

    (name != ".." && is_safe_segment(name)).then_some(name)
}

impl MavenSource {
    /// The latest build of a snapshot version, or an empty one for a
    /// release, whose files are named with the version as it is.
    ///
    /// A snapshot directory with no `maven-metadata.xml` is a non-unique
    /// snapshot rather than a missing one: its files carry the literal
    /// `-SNAPSHOT` name, which an empty [`Snapshot`] answers with.
    pub(super) async fn snapshot(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
        ctx: &Ctx,
    ) -> Result<Arc<Snapshot>> {
        if !metadata::is_snapshot(version) {
            return Ok(Arc::new(Snapshot::default()));
        }

        let url = format!(
            "{}/{METADATA_FILE}",
            self.version_dir(group, artifact, version)
        );

        self.snapshots
            .get_or_try_init(&url, || async {
                let body = match crate::ext::document(
                    &*self.host,
                    &Req::get(&url),
                    METADATA_FILE,
                    ByteLimit::METADATA,
                    ctx,
                )
                .await
                {
                    Ok(body) => body,
                    // HTTP 404: nothing at that path.
                    Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                        return Ok(Snapshot::default());
                    }
                    Err(err) => return Err(err),
                };

                metadata::parse_snapshot(&String::from_utf8_lossy(&body)).map_err(|detail| {
                    Error::Malformed {
                        what: METADATA_FILE,
                        url: url.clone(),
                        detail,
                    }
                })
            })
            .await
    }
    /// Every version this repository lists for an artifact.
    async fn version_list(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Arc<Vec<String>>> {
        let group = Self::group_of(id)?;
        let url = format!("{}/{METADATA_FILE}", self.artifact_dir(group, id.name()));

        self.versions
            .get_or_try_init(&url, || async {
                let body = crate::ext::document(
                    &*self.host,
                    &Req::get(&url),
                    METADATA_FILE,
                    ByteLimit::METADATA,
                    ctx,
                )
                .await?;
                let text = String::from_utf8_lossy(&body);

                let listed =
                    metadata::parse_version_list(&text).map_err(|detail| Error::Malformed {
                        what: METADATA_FILE,
                        url: url.clone(),
                        detail,
                    })?;

                let (usable, corrupt): (Vec<String>, Vec<String>) =
                    listed.into_iter().partition(|entry| is_safe_segment(entry));

                for entry in corrupt {
                    ctx.report(
                        Code::MetadataMalformed,
                        message!(
                            "maven-unusable-version-entry",
                            "{url} lists {entry:?} as a version, which cannot name a \
                             directory; it is ignored",
                            url = &url,
                            entry = &entry,
                        ),
                    );
                }

                Ok(usable)
            })
            .await
    }

    /// The version folders the artifact directory's HTML index lists, or
    /// `None` where there is no index.
    ///
    /// ```text
    ///   GET {base}/{group path}/{artifact}/
    ///   <a href="1.6.1/">1.6.1/</a>
    /// ```
    async fn indexed_versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Option<Vec<String>>> {
        let group = Self::group_of(id)?;
        let url = format!("{}/", self.artifact_dir(group, id.name()));

        let indexed = self
            .indexes
            .get_or_try_init(&url, || async {
                let body = match crate::ext::document(
                    &*self.host,
                    &Req::get(&url),
                    crate::ecosystem::maven::LISTING_DOCUMENT,
                    ARTIFACT_INDEX_LIMIT,
                    ctx,
                )
                .await
                {
                    Err(err) if err.code() == Code::ArtifactNotFound => return Ok(None),
                    other => other?,
                };

                let html = String::from_utf8_lossy(&body);
                let links =
                    crate::repo::pep503::links(&html).map_err(|detail| Error::Malformed {
                        what: "maven artifact index",
                        url: url.clone(),
                        detail,
                    })?;

                Ok(Some(
                    links
                        .iter()
                        .filter_map(|link| version_folder(&link.href))
                        .map(str::to_owned)
                        .collect(),
                ))
            })
            .await?;

        Ok((*indexed).clone())
    }

    /// The listed versions, joined with the index's under `html-index`.
    ///
    /// A missing `maven-metadata.xml` is no answer where the index lists
    /// versions; where neither has any, the metadata's error stands.
    pub(super) async fn listed_versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<String>> {
        let listed = self.version_list(id, ctx).await;

        if !self.discovery.indexes() {
            return Ok(listed?.to_vec());
        }

        let (mut versions, missing) = match listed {
            Ok(listed) => (listed.to_vec(), None),
            Err(err) if err.code() == Code::ArtifactNotFound => (Vec::new(), Some(err)),
            Err(err) => return Err(err),
        };

        let indexed = match self.indexed_versions(id, ctx).await {
            Ok(indexed) => indexed,

            // The index only adds what the metadata missed. With the
            // metadata in hand, an index the host cannot serve right now --
            // Central throttling, say -- costs those additions, not the
            // artifact.
            Err(err) if missing.is_none() && err.code() == Code::HostUnreachable => {
                ctx.report_as(
                    Code::HostUnreachable,
                    Action::Warn,
                    message!(
                        "maven-index-unreachable",
                        "{error}; versions come from {metadata} alone",
                        error = err.to_string(),
                        metadata = METADATA_FILE,
                    ),
                );

                None
            }

            Err(err) => return Err(err),
        };

        if let (None, Some(err)) = (&indexed, missing) {
            return Err(err);
        }

        for version in indexed.unwrap_or_default() {
            if !versions.contains(&version) {
                versions.push(version);
            }
        }

        Ok(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ext::testing::Fixture;
    use crate::model::ArtifactRequest;
    use crate::net::{Canned, FixtureClient};
    use crate::repo::Criteria;
    use crate::repo::maven::testing::*;
    use crate::version::PreRelease;

    use crate::core::problem::Code;

    use crate::model::VersionSpec;

    use crate::repo::Source;
    use crate::repo::maven::MavenSource;

    fn discovering(mode: &str, client: FixtureClient) -> Fixture<MavenSource> {
        let options =
            crate::ext::testing::options(serde_json::json!({ "version-discovery": mode }));

        Fixture::build(client, |host| {
            MavenSource::open(REPO, &options, host).expect("opens")
        })
    }

    /// `maven-metadata.xml` lists 1.0, 1.10, 1.9, and 2.0-SNAPSHOT; 1.6.1
    /// is served beside them, as qdox:qdox's 1.6.1 is on Central.
    fn stale_client() -> FixtureClient {
        client()
            .with_body(format!("{DIR}/1.6.1/lib-1.6.1.pom"), LIB_POM)
            .with(
                format!("{DIR}/1.6.1/lib-1.6.1.jar"),
                Canned::ok("").header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
            )
    }

    /// An artifact directory's autoindex: two version folders, the parent,
    /// and the metadata file.
    const ARTIFACT_INDEX: &str = r#"<html><body><pre>
<a href="../">../</a>
<a href="1.0/">1.0/</a>
<a href="1.6.1/">1.6.1/</a>
<a href="maven-metadata.xml">maven-metadata.xml</a>
</pre></body></html>"#;

    #[test]
    fn discovery_option_checked() {
        let with = |value: &str| {
            crate::ext::testing::options(serde_json::json!({ "version-discovery": value }))
        };

        assert_eq!(
            VersionDiscovery::read(&crate::ext::Options::default()).expect("reads"),
            VersionDiscovery::Probe
        );
        assert_eq!(
            VersionDiscovery::read(&with("both")).expect("reads"),
            VersionDiscovery::Both
        );
        assert!(
            VersionDiscovery::read(&with("sometimes"))
                .expect_err("refused")
                .to_string()
                .contains("version-discovery")
        );
    }

    #[test]
    fn version_folder_names_only_folders() {
        assert_eq!(version_folder("1.6.1/"), Some("1.6.1"));
        assert_eq!(version_folder("./1.0/"), Some("1.0"));
        assert_eq!(version_folder("../"), None);
        assert_eq!(version_folder("maven-metadata.xml"), None);
        assert_eq!(version_folder("https://elsewhere.test/"), None);
    }

    /// The default: an exact version the stale metadata omits is confirmed
    /// by its POM.
    #[tokio::test]
    async fn exact_unlisted_probed() {
        let f = fixture_from(stale_client());
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &exact("1.6.1", &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("1.6.1"));
    }

    /// A missing `maven-metadata.xml` does not stop an exact version whose
    /// POM is served.
    #[tokio::test]
    async fn exact_without_metadata_probed() {
        let f = fixture_from(stale_client().with(
            format!("{DIR}/maven-metadata.xml"),
            Canned::status(StatusCode::NOT_FOUND),
        ));
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &exact("1.6.1", &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("1.6.1"));
    }

    /// An exact release comes from its POM before any list: neither the
    /// metadata nor the index is read, so a throttled Central costs it
    /// nothing a mirror cannot serve.
    #[tokio::test]
    async fn exact_reads_no_list() {
        let f = discovering(
            "html-index",
            stale_client().with_body(format!("{DIR}/"), ARTIFACT_INDEX),
        );
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &exact("1.6.1", &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("1.6.1"));
        assert_eq!(f.host.hits(&format!("{DIR}/maven-metadata.xml")), 0);
        assert_eq!(f.host.hits(&format!("{DIR}/")), 0);
        assert_eq!(f.host.hits(&format!("{DIR}/1.6.1/lib-1.6.1.pom")), 1);
    }

    /// `metadata` trusts the list alone, so it reads the list first.
    #[tokio::test]
    async fn metadata_mode_reads_list_first() {
        let f = discovering("metadata", client());
        let ctx = ctx();

        f.subject
            .resolve(
                &exact("1.0", &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(f.host.hits(&format!("{DIR}/maven-metadata.xml")), 1);
    }

    /// A version neither listed nor served is still unresolvable.
    #[tokio::test]
    async fn exact_missing_unresolvable() {
        let f = fixture();
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &exact("9.9", &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::VersionUnresolvable);
    }

    /// `metadata` trusts the list and asks nothing else.
    #[tokio::test]
    async fn metadata_mode_trusts_list() {
        let f = discovering("metadata", stale_client());
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &exact("1.6.1", &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert_eq!(f.host.hits(&format!("{DIR}/1.6.1/lib-1.6.1.pom")), 0);
    }

    /// `html-index` joins the index's folders with the metadata's list.
    #[tokio::test]
    async fn html_index_joins_metadata() {
        let f = discovering(
            "html-index",
            stale_client().with_body(format!("{DIR}/"), ARTIFACT_INDEX),
        );
        let ctx = ctx();

        let versions = f.subject.versions(&id(), &ctx).await.expect("read");
        let texts: Vec<&str> = versions.iter().map(|v| v.text()).collect();

        assert_eq!(texts, ["1.0", "1.10", "1.9", "2.0-SNAPSHOT", "1.6.1"]);
    }

    /// Resolutions of one artifact at once share one index fetch.
    #[tokio::test]
    async fn html_index_fetched_once() {
        let f = discovering(
            "html-index",
            stale_client().with_body(format!("{DIR}/"), ARTIFACT_INDEX),
        );
        let ctx = ctx();
        let id = id();

        let (first, second) =
            tokio::join!(f.subject.versions(&id, &ctx), f.subject.versions(&id, &ctx));

        first.expect("read");
        second.expect("read");

        assert_eq!(f.host.hits(&format!("{DIR}/")), 1);
    }

    /// Central throttling its index (a 404 with a retry time) costs the
    /// index's additions and warns; the metadata still answers.
    #[tokio::test]
    async fn html_index_throttled_keeps_metadata() {
        let f = discovering(
            "html-index",
            stale_client().with(format!("{DIR}/"), throttled()),
        );
        let ctx = ctx();

        let versions = f.subject.versions(&id(), &ctx).await.expect("read");
        let texts: Vec<&str> = versions.iter().map(|v| v.text()).collect();

        assert_eq!(texts, ["1.0", "1.10", "1.9", "2.0-SNAPSHOT"]);
        assert_eq!(ctx.problems().counts()[&Code::HostUnreachable], 1);
        assert_eq!(ctx.problems().worst(), Some(Action::Warn));
    }

    /// Without the metadata there is nothing to fall back to.
    #[tokio::test]
    async fn html_index_throttled_without_metadata_fails() {
        let client = FixtureClient::new()
            .with(
                format!("{DIR}/maven-metadata.xml"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with(format!("{DIR}/"), throttled());
        let f = discovering("html-index", client);

        let err = f.subject.versions(&id(), &ctx()).await.unwrap_err();

        assert_eq!(err.code(), Code::HostUnreachable);
    }

    /// Central's throttle: a 404 that says when to come back.
    fn throttled() -> Canned {
        Canned::status(StatusCode::NOT_FOUND).header("retry-after", "120")
    }

    /// A missing `maven-metadata.xml` is no answer where the index lists
    /// versions.
    #[tokio::test]
    async fn html_index_stands_without_metadata() {
        let client = FixtureClient::new()
            .with(
                format!("{DIR}/maven-metadata.xml"),
                Canned::status(StatusCode::NOT_FOUND),
            )
            .with_body(format!("{DIR}/"), ARTIFACT_INDEX);
        let f = discovering("html-index", client);
        let ctx = ctx();

        let versions = f.subject.versions(&id(), &ctx).await.expect("read");
        let texts: Vec<&str> = versions.iter().map(|v| v.text()).collect();

        assert_eq!(texts, ["1.0", "1.6.1"]);
    }

    #[tokio::test]
    async fn versions_from_metadata_file() {
        let f = fixture();
        let ctx = ctx();

        let versions = f.subject.versions(&id(), &ctx).await.expect("read");
        let texts: Vec<&str> = versions.iter().map(|v| v.text()).collect();

        assert_eq!(texts, ["1.0", "1.10", "1.9", "2.0-SNAPSHOT"]);
    }

    /// The version list is not ordered in the file, and must not be
    /// assumed to be: `1.10` is listed before `1.9` above.
    #[tokio::test]
    async fn resolution_takes_highest_by_maven_order() {
        let f = fixture();
        let ctx = ctx();

        let request = ArtifactRequest {
            id: id(),
            spec: VersionSpec::Any,
            prov: ctx.prov().clone(),
        };

        let artifact = f
            .subject
            .resolve(&request, Criteria::new(PreRelease::Exclude), &ctx)
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("1.10"));
    }

    /// Versions like `1.0 / maven-metadata.xml` turn up in real indexes.
    /// Beyond being nonsense, a slash in a version escapes the artifact's
    /// directory, so the entry is dropped and reported rather than used to
    /// build a URL.
    #[tokio::test]
    async fn version_escaping_directory_dropped() {
        let corrupt = r#"<metadata><versioning><versions>
              <version>1.0</version>
              <version>1.0 / maven-metadata.xml</version>
              <version>../../../etc/passwd</version>
              <version>2.0</version>
            </versions></versioning></metadata>"#;

        let f = fixture_from(
            FixtureClient::new().with_body(format!("{DIR}/maven-metadata.xml"), corrupt),
        );

        let ctx = ctx();
        let versions = f.subject.versions(&id(), &ctx).await.expect("read");
        let texts: Vec<&str> = versions.iter().map(|v| v.text()).collect();

        assert_eq!(texts, ["1.0", "2.0"]);
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 2);
    }
}
