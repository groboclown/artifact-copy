//! Reading GitHub releases as a source.

use std::sync::Arc;

use async_trait::async_trait;

use super::allowed::Allowed;
use super::release::ReleaseDoc;
use crate::cache::Coalesced;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::{Action, Code};
use crate::ecosystem::{Ecosystem, Raw};
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::{
    ArtifactId, ArtifactRequest, Dependency, EcosystemId, FileRef, ResolvedArtifact, Version,
    VersionSpec,
};
use crate::net::{ByteLimit, Expectation, Req, encode_unreserved, normalized_base};
use crate::repo::{Criteria, Downloaded, Lookup, NameCase, NameMap, PageCap, Source};

/// The document name a release is cached under. A published release's
/// assets can still change, but rarely, so it takes no default.
const RELEASE_DOCUMENT: &str = "release.json";

/// What a raw coordinate splits its version off at, and so what a tag may
/// not hold.
const VERSION_SEPARATOR: char = '@';

/// GitHub's JSON media type, which pins the response shape to a version.
const ACCEPT: &str = "application/vnd.github+json";

/// One page of releases. GitHub caps `per_page` at 100.
const PER_PAGE: usize = 100;

/// How many releases to walk, unless `max-listing-rows` says otherwise.
///
/// Ten thousand releases is far past any real project, and the cap exists
/// so a misconfigured base URL that answers every request identically
/// cannot loop forever.
const DEFAULT_MAX_ROWS: u32 = 10_000;

/// A release document, with its asset list.
const RELEASE_LIMIT: ByteLimit = ByteLimit::mib(8);

/// A page of releases, each with its assets.
const PAGE_LIMIT: ByteLimit = ByteLimit::mib(32);

/// How many release documents to keep.
///
/// A release is resolved and then read again for its metadata, so a cache
/// turns two requests into one. Bounded because a walk covers many
/// repositories.
const RELEASE_CACHE: usize = 64;

pub struct GitHubSource {
    base_url: String,

    /// Where every request goes, and whose directory caches the files.
    host: Arc<dyn ExtHost>,
    ecosystem: Raw,

    /// The repositories this source may read.
    allowed: Allowed,

    /// Release documents, keyed by URL.
    releases: Coalesced<ReleaseDoc>,

    /// How a request's names become repositories and tags.
    names: NameMap,

    /// How many pages of releases one walk may read.
    page_cap: PageCap,
}

/// Where a request lands on GitHub: the `owner/repo` the releases
/// endpoints read, and the tag when a version was asked for.
struct Sourced {
    id: ArtifactId,
    tag: Option<String>,
}

impl GitHubSource {
    /// `base_url` is the API root: `https://api.github.com` for
    /// github.com, or `https://ghe.example.com/api/v3` for an Enterprise
    /// install. `options` must list the repositories it may read.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            base_url: normalized_base(base_url),
            host,
            ecosystem: Raw,
            allowed: Allowed::read(options)?,
            releases: Coalesced::new(RELEASE_CACHE),
            names: NameMap::default(),
            page_cap: page_cap(options)?,
        })
    }

    /// Read names through `names`, comparing repositories as GitHub does.
    pub fn naming(mut self, names: NameMap) -> Self {
        self.names = names.comparing(NameCase::Insensitive);
        self
    }

    /// Where a request for `id` at `version` reads from.
    ///
    /// ```text
    ///   tools/gitleaks@8.18.0  ->  gitleaks/gitleaks, tag v8.18.0
    ///   other/thing@v1         ->  other/thing, tag v1      (no rule)
    /// ```
    fn sourced(&self, id: &ArtifactId, version: Option<&str>, ctx: &Ctx) -> Result<Sourced> {
        let message = match self.names.to_source(id.name(), version) {
            Lookup::Unmapped => {
                return Ok(Sourced {
                    id: id.clone(),
                    tag: version.map(str::to_owned),
                });
            }

            Lookup::Mapped { name, version } => {
                return Ok(Sourced {
                    id: ArtifactId::new(EcosystemId::raw(), None, &name),
                    tag: version,
                });
            }

            Lookup::Refused(why) => message!(
                "name-mapping-refused",
                "{purl} cannot be read: {why}",
                purl = id.purl(),
                why = why,
            ),

            // Refused rather than settled by rule order: which repository
            // a write comes from is not something to guess.
            Lookup::Ambiguous(rules) => message!(
                "name-mapping-ambiguous",
                "{purl} can come from more than one 'names' rule ({rules}); \
                 name a version only one of them admits",
                purl = id.purl(),
                rules = rules.join("; "),
            ),
        };

        Err(unresolvable(id, message, ctx))
    }

    /// The version `release` of `source` is as artifact `id`, or why no
    /// request could name it.
    fn version_of(
        &self,
        id: &ArtifactId,
        source: &ArtifactId,
        release: &ReleaseDoc,
    ) -> std::result::Result<Version, String> {
        let tag = &release.tag_name;

        let text = match self.names.to_artifact(source.name(), tag, id.name()) {
            Lookup::Unmapped => tag.clone(),
            Lookup::Mapped { version, .. } => version.unwrap_or_default(),
            Lookup::Refused(why) => return Err(why),

            Lookup::Ambiguous(rules) => {
                return Err(format!(
                    "it matches more than one 'names' rule ({})",
                    rules.join("; ")
                ));
            }
        };

        if text.contains(VERSION_SEPARATOR) {
            return Err(format!(
                "a raw coordinate cannot name a version holding '{VERSION_SEPARATOR}'"
            ));
        }

        Ok(release.version_as(&text))
    }

    /// Check a source's options without building it, for `validate-config`.
    pub(crate) fn check_options(options: &Options) -> Result<()> {
        Allowed::read(options)?;
        page_cap(options).map(|_| ())
    }

    /// Check that every repository `names` maps is one `options` lists, for
    /// `validate-config`.
    pub(crate) fn check_names(options: &Options, names: &NameMap) -> Result<()> {
        let allowed = Allowed::read(options)?;

        for name in names.source_names() {
            let permitted = name
                .split_once('/')
                .is_some_and(|(owner, repo)| allowed.permits(owner, repo));

            if !permitted {
                return Err(Error::Config(format!(
                    "'names' maps {name}, which is outside the repositories this github \
                     source may read ({})",
                    allowed.describe()
                )));
            }
        }

        Ok(())
    }

    /// The `owner` and `repo` of an artifact named `owner/repo`.
    fn repo_path<'i>(&self, id: &'i ArtifactId) -> Result<(&'i str, &'i str)> {
        let refused = || Error::BadRequest {
            ecosystem: "raw",
            text: id.purl(),
            detail: "a GitHub release is named owner/repo, optionally with @tag".to_owned(),
        };

        let (owner, repo) = id.name().split_once('/').ok_or_else(refused)?;

        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            return Err(refused());
        }

        // Refused as the host refuses a URL outside its allow-list.
        if !self.allowed.permits(owner, repo) {
            return Err(Error::Config(format!(
                "{owner}/{repo} is outside the repositories this github source may read ({})",
                self.allowed.describe()
            )));
        }

        Ok((owner, repo))
    }

    fn releases_url(&self, id: &ArtifactId, suffix: &str) -> Result<String> {
        let (owner, repo) = self.repo_path(id)?;

        Ok(format!(
            "{}/repos/{}/{}/releases{suffix}",
            self.base_url,
            encode_unreserved(owner),
            encode_unreserved(repo)
        ))
    }

    async fn release_at(&self, url: &str, ctx: &Ctx) -> Result<ReleaseDoc> {
        let doc = self
            .releases
            .get_or_try_init(url, || async {
                crate::ext::document_json(
                    &*self.host,
                    &Req::get(url).accept(ACCEPT),
                    RELEASE_DOCUMENT,
                    RELEASE_LIMIT,
                    "github release",
                    ctx,
                )
                .await
            })
            .await?;

        Ok((*doc).clone())
    }

    /// Every published release, newest first.
    ///
    /// Paged, because a long-lived project has hundreds and GitHub returns
    /// a hundred at a time.
    async fn all_releases(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<ReleaseDoc>> {
        let mut out = Vec::new();

        for page in 1..=self.page_cap.pages() {
            let url = self.releases_url(id, &format!("?per_page={PER_PAGE}&page={page}"))?;
            let batch: Vec<ReleaseDoc> = crate::ext::fetch_json(
                &*self.host,
                &Req::get(&url).accept(ACCEPT),
                PAGE_LIMIT,
                "github release list",
                ctx,
            )
            .await?;

            let exhausted = batch.len() < PER_PAGE;

            // A draft is unpublished: invisible to anyone without write
            // access and with undownloadable assets. Dropped here so
            // nothing downstream has to remember it exists.
            out.extend(batch.into_iter().filter(|release| !release.draft));

            if exhausted {
                return Ok(out);
            }
        }

        // Reached only by a base URL answering every page identically.
        ctx.report(
            Code::MetadataMalformed,
            message!(
                "github-release-pages-exhausted",
                "{purl} returned more than {pages} pages of releases; the walk \
                 was stopped. Raise 'max-listing-rows' for a project that large",
                purl = id.purl(),
                pages = self.page_cap.pages(),
            ),
        );

        Ok(out)
    }

    /// Build the artifact for one release document, as `version`.
    fn artifact(
        &self,
        id: &ArtifactId,
        version: Version,
        release: &ReleaseDoc,
    ) -> ResolvedArtifact {
        ResolvedArtifact {
            id: id.clone(),
            version: Some(version),

            files: release
                .assets
                .iter()
                .map(|asset| {
                    let mut file = FileRef::new(&asset.name, &asset.browser_download_url);
                    file.size = asset.size;

                    file
                })
                .collect(),

            // A release has no license field. The *repository* has one, on
            // a different endpoint -- fetching it would cost a request per
            // artifact to learn something that is not a property of the
            // release at all.
            license: None,

            published: release.published(),
        }
    }
}

#[async_trait]
impl Source for GitHubSource {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    fn ecosystems(&self) -> Vec<EcosystemId> {
        vec![self.ecosystem.id()]
    }

    /// Every published release a request could name: not a tag holding
    /// `@`, and under a name mapping, only the tags its rules admit.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let source = self.sourced(id, None, ctx)?;

        Ok(self
            .all_releases(&source.id, ctx)
            .await?
            .iter()
            .filter_map(|release| self.version_of(id, &source.id, release).ok())
            .collect())
    }

    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let version = crate::repo::version_required(id, version)?;
        let source = self.sourced(id, Some(version.text()), ctx)?;
        let tag = source.tag.as_deref().unwrap_or(version.text());

        let url = self.releases_url(&source.id, &format!("/tags/{}", encode_unreserved(tag)))?;
        let release = self.release_at(&url, ctx).await?;

        if release.draft {
            return Err(Error::Malformed {
                what: "github release",
                url,
                detail: format!("{} is a draft and is not published", version.text()),
            });
        }

        let version = self
            .version_of(id, &source.id, &release)
            .map_err(|why| unnameable(id, &release, why, ctx))?;

        Ok(self.artifact(id, version, &release))
    }

    /// GitHub releases declare no dependencies.
    ///
    /// Empty rather than an error: there is genuinely nothing to follow,
    /// and the ecosystem's empty `dep_kinds` is what makes asking for a
    /// kind say so.
    async fn deps(&self, _artifact: &ResolvedArtifact, _ctx: &Ctx) -> Result<Vec<Dependency>> {
        Ok(Vec::new())
    }

    /// Ask GitHub, rather than ordering a tag list.
    ///
    /// The only adapter that overrides this, for the reason in the module
    /// documentation: there is no highest tag. An exact request is one
    /// request by tag; a versionless one is `/releases/latest`, which is
    /// GitHub's own answer and already excludes drafts and pre-releases.
    async fn resolve(
        &self,
        request: &ArtifactRequest,
        criteria: Criteria,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let (source, chosen) = self.chosen_release(request, criteria, ctx).await?;

        refuse_draft(request, &chosen, ctx)?;

        // Reached through `/latest` or the list, since a request cannot
        // name such a tag.
        let version = self
            .version_of(&request.id, &source.id, &chosen)
            .map_err(|why| unnameable(&request.id, &chosen, why, ctx))?;

        refuse_pre_release(request, &chosen, &version, criteria, ctx)?;

        let artifact = self.artifact(&request.id, version, &chosen);

        // Narrowed to the chosen release before the window is judged, for
        // the reason `repo::resolve` narrows: everything from here on is
        // about *that* release, and a per-artifact rule naming a tag has
        // nothing to match against until one is picked. This override used
        // to report without narrowing, which left every finding it raised
        // decided by the code table alone -- so no quarantine rule could
        // reach a GitHub release at all.
        let about = ctx.for_artifact(request.id.clone(), artifact.version.clone());

        check_window(request, &chosen, &artifact, criteria, &about)?;

        Ok(artifact)
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

impl GitHubSource {
    /// The release a request names: by tag, GitHub's latest, or the first
    /// the list publishes under `--pre-release`. A range is refused.
    async fn chosen_release(
        &self,
        request: &ArtifactRequest,
        criteria: Criteria,
        ctx: &Ctx,
    ) -> Result<(Sourced, ReleaseDoc)> {
        match &request.spec {
            VersionSpec::Exact(text) => {
                let source = self.sourced(&request.id, Some(text), ctx)?;
                let tag = source.tag.as_deref().unwrap_or(text);
                let url =
                    self.releases_url(&source.id, &format!("/tags/{}", encode_unreserved(tag)))?;
                let release = self.release_at(&url, ctx).await?;

                Ok((source, release))
            }

            // `/releases/latest` is GitHub's own definition and skips
            // drafts and pre-releases already. With `--pre-release` that is
            // the wrong answer, so the list is walked instead and the first
            // published release wins.
            // Under a name mapping, the first release whose tag its rules
            // admit; `/latest` is still GitHub's answer, and one outside
            // the rules is refused below rather than stepped past.
            VersionSpec::Any => {
                let source = self.sourced(&request.id, None, ctx)?;

                let release = match criteria.pre {
                    crate::version::PreRelease::Exclude => {
                        let url = self.releases_url(&source.id, "/latest")?;

                        self.release_at(&url, ctx).await?
                    }

                    crate::version::PreRelease::Include => self
                        .all_releases(&source.id, ctx)
                        .await?
                        .into_iter()
                        .find(|release| self.version_of(&request.id, &source.id, release).is_ok())
                        .ok_or_else(|| self.nothing_published(request, ctx))?,
                };

                Ok((source, release))
            }

            // Refused outright rather than approximated. A tag list is not
            // a version index, and a comparator invented to make `^1.0`
            // work against one would pick a plausible wrong release.
            VersionSpec::Range(range) => {
                let message = message!(
                    "github-range-unsupported",
                    "{purl} was asked for the range {range}, but GitHub tags have \
                     no version order to match a range against; name an exact tag, or \
                     omit the version for the latest release",
                    purl = request.id.purl(),
                    range = range,
                );

                Err(unresolvable(&request.id, message, ctx))
            }
        }
    }

    fn nothing_published(&self, request: &ArtifactRequest, ctx: &Ctx) -> Error {
        let message = message!(
            "github-no-releases",
            "{purl} has published no releases",
            purl = request.id.purl(),
        );

        let detail = message.render();
        let problem = ctx.reported(Code::VersionUnresolvable, message);

        Error::Unresolvable {
            artifact: request.id.purl(),
            detail,
            problem: Box::new(problem),
        }
    }
}

/// Refuse a draft, which is not published and has no assets.
fn refuse_draft(request: &ArtifactRequest, chosen: &ReleaseDoc, ctx: &Ctx) -> Result<()> {
    if !chosen.draft {
        return Ok(());
    }

    let message = message!(
        "github-draft-release",
        "{purl} is a draft, which is not published and has no \
         downloadable assets",
        purl = request.id.purl_at(&chosen.tag_name),
        tag = &chosen.tag_name,
    );

    Err(unresolvable(&request.id, message, ctx))
}

/// Refuse a release GitHub marks as a pre-release, unless asked for.
fn refuse_pre_release(
    request: &ArtifactRequest,
    chosen: &ReleaseDoc,
    version: &Version,
    criteria: Criteria,
    ctx: &Ctx,
) -> Result<()> {
    if criteria.pre != crate::version::PreRelease::Exclude || !chosen.prerelease {
        return Ok(());
    }

    let message = message!(
        "github-pre-release",
        "{purl} is marked as a pre-release; try --pre-release",
        purl = request.id.purl_at(version.text()),
        tag = &chosen.tag_name,
    );

    Err(unresolvable(&request.id, message, ctx))
}

/// Refuse a release inside the publish window, unless a quarantine rule
/// excuses it.
///
/// The publish window applies here as anywhere: a release cut an hour ago
/// is exactly what it is meant to keep out. There is no stepping down to an
/// older tag, because there is no order to step down through.
fn check_window(
    request: &ArtifactRequest,
    chosen: &ReleaseDoc,
    artifact: &ResolvedArtifact,
    criteria: Criteria,
    ctx: &Ctx,
) -> Result<()> {
    if criteria.old_enough(artifact.published) {
        return Ok(());
    }

    // Two different facts, and a user debugging a skipped artifact
    // needs to know which. Neither says what happens next, because
    // the disposition below decides.
    let message = match artifact.published {
        Some(published) => message!(
            "publish-too-recent",
            "{purl} was published {published}, which is inside the \
             configured publish window",
            purl = artifact.purl(),
            tag = &chosen.tag_name,
            published = &published.to_rfc3339(),
        ),

        None => message!(
            "publish-time-unknown",
            "{purl} has no publish time, so it cannot be shown to \
             satisfy the configured publish window. Set unknown-publish-time \
             to allow if this repository never reports one",
            purl = artifact.purl(),
            tag = &chosen.tag_name,
        ),
    };

    let detail = message.render();

    // A quarantine rule may excuse the window for one artifact; see
    // `repo::resolve`. Refusing outright is the *only* other answer
    // here, since there is no older tag to try.
    let problem = ctx.reported(Code::PublishTooRecent, message);

    if problem.action() < Action::SkipArtifact {
        return Ok(());
    }

    Err(Error::Unresolvable {
        artifact: request.id.purl(),
        detail,
        problem: Box::new(problem),
    })
}

/// A refusal reported under `id`, which is the name the request used.
fn unresolvable(id: &ArtifactId, message: crate::core::message::Message, ctx: &Ctx) -> Error {
    let detail = message.render();
    let problem = ctx.reported(Code::VersionUnresolvable, message);

    Error::Unresolvable {
        artifact: id.purl(),
        detail,
        problem: Box::new(problem),
    }
}

/// A release `id` resolved to, whose tag no request could name.
fn unnameable(id: &ArtifactId, release: &ReleaseDoc, why: String, ctx: &Ctx) -> Error {
    let message = message!(
        "github-tag-unsupported",
        "{purl} is tagged {tag}, which no request can name: {why}; name another tag",
        purl = id.purl(),
        tag = &release.tag_name,
        why = why,
    );

    unresolvable(id, message, ctx)
}

/// The page cap `options` configures, at GitHub's page size.
fn page_cap(options: &Options) -> Result<PageCap> {
    PageCap::from_options(options, PER_PAGE as u32, DEFAULT_MAX_ROWS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::testing::{Fixture, TestHost};
    use crate::model::{Cause, EcosystemId, Release};
    use crate::net::FixtureClient;
    use crate::version::PreRelease;

    const API: &str = "h://api.github.test";
    const REPO: &str = "h://api.github.test/repos/owner/project/releases";

    fn release(tag: &str, draft: bool, prerelease: bool, published: &str) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "published_at": published,
            "assets": [{
                "name": format!("project-{tag}.tar.gz"),
                "browser_download_url": format!("h://github.test/{tag}.tar.gz"),
                "size": 1024,
            }],
        })
    }

    fn fixture(client: FixtureClient) -> Fixture<GitHubSource> {
        Fixture::build(client, |host| {
            GitHubSource::open(API, &allowing(&["owner/*"]), host).expect("opens")
        })
    }

    fn allowing(entries: &[&str]) -> crate::ext::Options {
        crate::ext::testing::options(serde_json::json!({ "repositories": entries }))
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "owner/project".into(),
        })
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::raw(), None, "owner/project")
    }

    fn request(spec: VersionSpec, ctx: &Ctx) -> ArtifactRequest {
        ArtifactRequest {
            id: id(),
            spec,
            prov: ctx.prov().clone(),
        }
    }

    /// A repository with a latest release, a pre-release, and a draft.
    fn standard() -> FixtureClient {
        let listing = serde_json::json!([
            release("v2.0.0-rc1", false, true, "2024-06-01T00:00:00Z"),
            release("v1.9.0-draft", true, false, "2024-05-15T00:00:00Z"),
            release("v1.8.0", false, false, "2024-05-01T00:00:00Z"),
        ]);

        FixtureClient::new()
            .with_body(format!("{REPO}?per_page=100&page=1"), listing.to_string())
            .with_body(
                format!("{REPO}/latest"),
                release("v1.8.0", false, false, "2024-05-01T00:00:00Z").to_string(),
            )
            .with_body(
                format!("{REPO}/tags/v1.8.0"),
                release("v1.8.0", false, false, "2024-05-01T00:00:00Z").to_string(),
            )
            .with_body(
                format!("{REPO}/tags/v2.0.0-rc1"),
                release("v2.0.0-rc1", false, true, "2024-06-01T00:00:00Z").to_string(),
            )
            .with_body(
                format!("{REPO}/tags/v1.9.0-draft"),
                release("v1.9.0-draft", true, false, "2024-05-15T00:00:00Z").to_string(),
            )
    }

    // -- Resolution -------------------------------------------------------

    /// A versionless request is one request to GitHub's own `/latest`, not
    /// a paged walk and a comparison.
    #[tokio::test]
    async fn version_absent_asks_for_latest() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("v1.8.0"));
        assert_eq!(f.host.hits(&format!("{REPO}/latest")), 1);

        // No listing walked: `/latest` answered it outright.
        assert_eq!(f.host.hits(&format!("{REPO}?per_page=100&page=1")), 0);
    }

    #[tokio::test]
    async fn tag_exact_fetched_by_tag() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &request(VersionSpec::Exact("v1.8.0".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("v1.8.0"));
        assert_eq!(f.host.hits(&format!("{REPO}/tags/v1.8.0")), 1);
    }

    /// `/releases/latest` already excludes pre-releases, which is the wrong
    /// answer when they were asked for -- so the list is walked instead.
    #[tokio::test]
    async fn pre_release_walks_list_not_latest() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Include),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("v2.0.0-rc1"));
        assert_eq!(f.host.hits(&format!("{REPO}/latest")), 0);
    }

    /// The only-GA requirement. Asking for a pre-release tag by name
    /// without the flag is refused, with the flag named.
    #[tokio::test]
    async fn pre_release_tag_refused_without_flag() {
        let f = fixture(standard());
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Exact("v2.0.0-rc1".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("--pre-release"), "{err}");
    }

    /// A draft is unpublished and its assets are not downloadable, so it is
    /// never a candidate -- and never counted as a pre-release either.
    /// `--pre-release` asks for release candidates, not unfinished drafts.
    #[tokio::test]
    async fn draft_never_resolved_even_with_pre_release() {
        for pre in [PreRelease::Exclude, PreRelease::Include] {
            let f = fixture(standard());
            let ctx = ctx();

            let err = f
                .subject
                .resolve(
                    &request(VersionSpec::Exact("v1.9.0-draft".into()), &ctx),
                    Criteria::new(pre),
                    &ctx,
                )
                .await
                .unwrap_err();

            assert!(err.to_string().contains("draft"), "{pre:?}: {err}");
        }
    }

    #[tokio::test]
    async fn draft_absent_from_version_list() {
        let f = fixture(standard());
        let ctx = ctx();

        let versions = f.subject.versions(&id(), &ctx).await.expect("listed");
        let tags: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(tags, ["v2.0.0-rc1", "v1.8.0"]);
    }

    /// A range is refused with an explanation, not approximated. A
    /// comparator invented for tag strings would pick a plausible wrong
    /// release.
    #[tokio::test]
    async fn version_range_refused_with_reason() {
        let f = fixture(standard());
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Range("^1.0".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        let text = err.to_string();

        assert!(text.contains("no version order"), "{text}");
        assert!(text.contains("exact tag"), "{text}");
        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert_eq!(ctx.problems().counts()[&Code::VersionUnresolvable], 1);
    }

    // -- Metadata ---------------------------------------------------------

    #[tokio::test]
    async fn release_assets_become_files() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id(), Some(&Version::new("v1.8.0", Release::General)), &ctx)
            .await
            .expect("read");

        assert_eq!(artifact.files.len(), 1);
        assert_eq!(artifact.files[0].name, "project-v1.8.0.tar.gz");
        assert_eq!(artifact.files[0].size, Some(1024));
    }

    #[tokio::test]
    async fn release_publish_time() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id(), Some(&Version::new("v1.8.0", Release::General)), &ctx)
            .await
            .expect("read");

        assert_eq!(
            artifact.published.expect("dated").to_rfc3339(),
            "2024-05-01T00:00:00+00:00"
        );
    }

    /// A release has no license; the repository does, on a different
    /// endpoint. Fetching it would cost a request per artifact to learn
    /// something that is not a property of the release.
    #[tokio::test]
    async fn release_declares_no_license() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id(), Some(&Version::new("v1.8.0", Release::General)), &ctx)
            .await
            .expect("read");

        assert!(artifact.license.is_none());
    }

    /// Nothing to follow, and the ecosystem's empty `dep_kinds` is what
    /// makes asking for a kind say so rather than returning silence.
    #[tokio::test]
    async fn release_has_no_dependencies() {
        let f = fixture(standard());
        let ctx = ctx();

        let artifact = f
            .subject
            .metadata(&id(), Some(&Version::new("v1.8.0", Release::General)), &ctx)
            .await
            .expect("read");

        assert!(
            f.subject
                .deps(&artifact, &ctx)
                .await
                .expect("read")
                .is_empty()
        );
        assert!(
            f.subject
                .ecosystem(&id())
                .expect("raw")
                .dep_kinds()
                .is_empty()
        );
    }

    // -- The publish window -----------------------------------------------

    /// The window applies here as anywhere -- a release cut an hour ago is
    /// exactly what it exists to keep out -- but there is no stepping down
    /// to an older tag, because there is no order to step down through.
    #[tokio::test]
    async fn release_inside_publish_window_refused() {
        let fresh = release("v3.0.0", false, false, &chrono::Utc::now().to_rfc3339());

        let f =
            fixture(FixtureClient::new().with_body(format!("{REPO}/latest"), fresh.to_string()));
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude)
                    .minimum_age(std::time::Duration::from_secs(86_400)),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert!(
            err.to_string()
                .contains("inside the configured publish window"),
            "{err}"
        );
        assert_eq!(ctx.problems().counts()[&Code::PublishTooRecent], 1);
    }

    /// A quarantine rule excuses the window here too, and there is nothing
    /// else it could mean: with no order among tags there is no older
    /// release to step down to, so the disposition either takes this one or
    /// refuses the request.
    #[tokio::test]
    async fn release_window_excused_by_quarantine_rule() {
        let fresh = release("v3.0.0", false, false, &chrono::Utc::now().to_rfc3339());

        let f =
            fixture(FixtureClient::new().with_body(format!("{REPO}/latest"), fresh.to_string()));
        let ctx = excusing("pkg:raw/owner%2Fproject");

        let artifact = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude)
                    .minimum_age(std::time::Duration::from_secs(86_400)),
                &ctx,
            )
            .await
            .expect("the rule excused the window");

        assert_eq!(artifact.version_text(), Some("v3.0.0"));
        assert_eq!(
            ctx.problems().counts()[&Code::PublishTooRecent],
            1,
            "and it is still reported"
        );
    }

    /// The narrowing this override was missing. Every finding it raised was
    /// decided without a subject, so no per-artifact rule could reach a
    /// GitHub release at all - the rule below would have changed nothing.
    #[tokio::test]
    async fn finding_decided_under_chosen_release() {
        let fresh = release("v3.0.0", false, false, &chrono::Utc::now().to_rfc3339());

        let f =
            fixture(FixtureClient::new().with_body(format!("{REPO}/latest"), fresh.to_string()));

        // Named for a version this release is not, so the rule must not
        // answer: without narrowing there is no subject to compare at all
        // and the rule is simply skipped, which would pass for the wrong
        // reason. Paired with the test above, which shares everything but
        // the version range.
        let ctx = excusing("pkg:raw/owner%2Fproject@v1.0.0");

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude)
                    .minimum_age(std::time::Duration::from_secs(86_400)),
                &ctx,
            )
            .await
            .expect_err("the rule names another version");

        assert_eq!(err.code(), Code::VersionUnresolvable);
    }

    /// A context whose quarantine policy allows `publish-too-recent` for
    /// `purl`, collecting reservations as a real walk does.
    fn excusing(purl: &str) -> Ctx {
        let policy: crate::policy::QuarantinePolicy = serde_json::from_str(&format!(
            r#"{{"rules":[{{"purl":"{purl}","codes":["publish-too-recent"],
                 "class":"soft","justification":"patch for a critical CVE",
                 "expires":"never"}}]}}"#
        ))
        .expect("parses");

        ctx()
            .deciding_with(std::sync::Arc::new(crate::policy::Dispositions::new(
                crate::core::problem::Policy::default(),
                [policy],
                crate::policy::Hardening::Off,
            )))
            .collecting()
    }

    // -- Paging and edges -------------------------------------------------

    #[tokio::test]
    async fn release_list_paged() {
        let full: Vec<serde_json::Value> = (0..PER_PAGE)
            .map(|index| release(&format!("v1.{index}"), false, false, "2024-01-01T00:00:00Z"))
            .collect();

        let f = fixture(
            FixtureClient::new()
                .with_body(
                    format!("{REPO}?per_page=100&page=1"),
                    serde_json::Value::Array(full).to_string(),
                )
                .with_body(
                    format!("{REPO}?per_page=100&page=2"),
                    serde_json::json!([release("v0.9", false, false, "2023-01-01T00:00:00Z")])
                        .to_string(),
                ),
        );

        let ctx = ctx();
        let versions = f.subject.versions(&id(), &ctx).await.expect("listed");

        assert_eq!(versions.len(), PER_PAGE + 1);
        assert_eq!(versions.last().expect("last").text(), "v0.9");
    }

    #[tokio::test]
    async fn release_none_in_repository_reported() {
        let f =
            fixture(FixtureClient::new().with_body(format!("{REPO}?per_page=100&page=1"), "[]"));

        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Include),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("no releases"), "{err}");
    }

    #[tokio::test]
    async fn tag_unknown_reported_not_found() {
        let f = fixture(standard());
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Exact("v99".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::ArtifactNotFound);
    }

    #[tokio::test]
    async fn name_owner_repo_encoded_into_path() {
        let f = Fixture::build(standard(), |host| {
            GitHubSource::open(API, &allowing(&["own er/*"]), host).expect("opens")
        });
        let odd = ArtifactId::new(EcosystemId::raw(), None, "own er/pro ject");

        assert_eq!(
            f.subject.releases_url(&odd, "/latest").expect("built"),
            "h://api.github.test/repos/own%20er/pro%20ject/releases/latest"
        );
    }

    /// Exactly two segments: `owner/repo`.
    #[tokio::test]
    async fn name_other_than_owner_repo_refused() {
        let f = fixture(standard());

        for name in ["project", "/project", "owner/", "owner/repo/extra"] {
            let id = ArtifactId::new(EcosystemId::raw(), None, name);

            assert!(f.subject.releases_url(&id, "/latest").is_err(), "{name}");
        }
    }

    /// A raw coordinate could never name it, so it is neither listed nor
    /// taken as the latest.
    #[tokio::test]
    async fn tag_holding_at_refused() {
        let at = release("release@2024", false, false, "2024-05-01T00:00:00Z");
        let f = fixture(
            FixtureClient::new()
                .with_body(
                    format!("{REPO}?per_page=100&page=1"),
                    serde_json::json!([at.clone()]).to_string(),
                )
                .with_body(format!("{REPO}/latest"), at.to_string()),
        );
        let ctx = ctx();

        assert!(
            f.subject
                .versions(&id(), &ctx)
                .await
                .expect("listed")
                .is_empty()
        );

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert!(err.to_string().contains("'@'"), "{err}");
    }

    /// A repository the list does not name is refused before any request.
    #[tokio::test]
    async fn repository_unlisted_refused() {
        let f = Fixture::build(standard(), |host| {
            GitHubSource::open(API, &allowing(&["owner/web-*"]), host).expect("opens")
        });
        let ctx = ctx();

        let err = f.subject.versions(&id(), &ctx).await.unwrap_err();

        assert!(err.to_string().contains("owner/web-*"), "{err}");
        assert!(f.host.requested().is_empty());
    }

    #[test]
    fn repositories_required() {
        assert!(
            GitHubSource::open(
                API,
                &crate::ext::Options::default(),
                crate::ext::testing::idle()
            )
            .is_err()
        );
        assert!(GitHubSource::check_options(&allowing(&["*/gitleaks"])).is_err());
        assert!(GitHubSource::check_options(&allowing(&["gitleaks/*"])).is_ok());
    }

    /// A raw coordinate: `owner/repo` with the tag split off at the `@`.
    #[test]
    fn request_parses_as_raw() {
        let parsed = Raw.parse_req("gitleaks/gitleaks@v8.18.0").expect("parses");

        assert_eq!(
            parsed.id.purl_at("v8.18.0"),
            "pkg:raw/gitleaks%2Fgitleaks@v8.18.0"
        );
        assert_eq!(parsed.spec, VersionSpec::Exact("v8.18.0".into()));
    }

    /// Every configured source is wrapped in `Bound`, which once never
    /// forwarded `resolve`, so this override ran only in these tests.
    #[tokio::test]
    async fn bound_source_resolves_through_override() {
        let host = Arc::new(TestHost::allowing(standard(), API));
        let source = GitHubSource::open(API, &allowing(&["owner/*"]), host.clone()).expect("opens");
        let bound = crate::repo::Bound::new(Arc::new(source));
        let ctx = ctx();

        let artifact = bound
            .resolve(
                &request(VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("v1.8.0"));
        assert_eq!(host.hits(&format!("{REPO}/latest")), 1);
    }

    // -- Name mapping -----------------------------------------------------

    /// `owner/project@v*` read as `tools/project@*`, plus any further rules.
    fn mapped(client: FixtureClient, extra: serde_json::Value) -> Fixture<GitHubSource> {
        let mut rules = vec![serde_json::json!({
            "from": { "name": "owner/project", "version": "v*" },
            "to": { "name": "tools/project", "version": "*" },
        })];

        if let serde_json::Value::Array(more) = extra {
            rules.extend(more);
        }

        let rules: Vec<crate::config::NameRule> =
            serde_json::from_value(serde_json::Value::Array(rules)).expect("rules");
        let names = NameMap::parse(&rules).expect("parses");

        Fixture::build(client, |host| {
            GitHubSource::open(API, &allowing(&["owner/*"]), host)
                .expect("opens")
                .naming(names)
        })
    }

    fn mapped_request(name: &str, spec: VersionSpec, ctx: &Ctx) -> ArtifactRequest {
        ArtifactRequest {
            id: ArtifactId::new(EcosystemId::raw(), None, name),
            spec,
            prov: ctx.prov().clone(),
        }
    }

    #[tokio::test]
    async fn mapped_name_reads_repository() {
        let f = mapped(standard(), serde_json::Value::Null);
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &mapped_request("tools/project", VersionSpec::Exact("1.8.0".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.id.name(), "tools/project");
        assert_eq!(artifact.version_text(), Some("1.8.0"));
        assert_eq!(f.host.hits(&format!("{REPO}/tags/v1.8.0")), 1);
    }

    #[tokio::test]
    async fn mapped_latest_carries_mapped_version() {
        let f = mapped(standard(), serde_json::Value::Null);
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &mapped_request("tools/project", VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.purl(), "pkg:raw/tools%2Fproject@1.8.0");
    }

    /// One release must not land under two names.
    #[tokio::test]
    async fn mapped_repository_refused_by_own_name() {
        let f = mapped(standard(), serde_json::Value::Null);
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &request(VersionSpec::Exact("v1.8.0".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("tools/project"), "{err}");
        assert!(f.host.requested().is_empty());
    }

    #[tokio::test]
    async fn mapped_versions_hide_unmatched_tags() {
        let listing = serde_json::json!([
            release("v1.8.0", false, false, "2024-05-01T00:00:00Z"),
            release("nightly", false, false, "2024-05-02T00:00:00Z"),
        ]);

        let f = mapped(
            FixtureClient::new()
                .with_body(format!("{REPO}?per_page=100&page=1"), listing.to_string()),
            serde_json::Value::Null,
        );
        let ctx = ctx();

        let id = ArtifactId::new(EcosystemId::raw(), None, "tools/project");
        let versions = f.subject.versions(&id, &ctx).await.expect("listed");
        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(texts, ["1.8.0"]);
    }

    /// The mapping lifts the `@` refusal: only the mapped version must be
    /// nameable.
    #[tokio::test]
    async fn mapped_tag_may_hold_at() {
        let at = release("release@2024", false, false, "2024-05-01T00:00:00Z");
        let f = mapped(
            FixtureClient::new().with_body(format!("{REPO}/tags/release%402024"), at.to_string()),
            serde_json::json!([{
                "from": { "name": "owner/project", "version": "release@*" },
                "to": { "name": "tools/project-release", "version": "*" },
            }]),
        );
        let ctx = ctx();

        let artifact = f
            .subject
            .resolve(
                &mapped_request(
                    "tools/project-release",
                    VersionSpec::Exact("2024".into()),
                    &ctx,
                ),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .expect("resolved");

        assert_eq!(artifact.version_text(), Some("2024"));
    }

    /// The destination can come from two repositories, so nothing is read.
    #[tokio::test]
    async fn ambiguous_destination_refused() {
        let f = mapped(
            standard(),
            serde_json::json!([{
                "from": { "name": "owner/other" },
                "to": { "name": "tools/project" },
            }]),
        );
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &mapped_request("tools/project", VersionSpec::Exact("1.8.0".into()), &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert!(err.to_string().contains("more than one"), "{err}");
        assert!(f.host.requested().is_empty());
    }

    #[tokio::test]
    async fn mapped_latest_outside_mapping_refused() {
        let f = mapped(
            FixtureClient::new().with_body(
                format!("{REPO}/latest"),
                release("nightly", false, false, "2024-05-01T00:00:00Z").to_string(),
            ),
            serde_json::Value::Null,
        );
        let ctx = ctx();

        let err = f
            .subject
            .resolve(
                &mapped_request("tools/project", VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude),
                &ctx,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::VersionUnresolvable);
        assert!(err.to_string().contains("nightly"), "{err}");
    }

    /// A rule names the artifact a request names, not the repository.
    #[tokio::test]
    async fn mapped_name_reached_by_quarantine_rule() {
        let fresh = release("v3.0.0", false, false, &chrono::Utc::now().to_rfc3339());

        let f = mapped(
            FixtureClient::new().with_body(format!("{REPO}/latest"), fresh.to_string()),
            serde_json::Value::Null,
        );
        let ctx = excusing("pkg:raw/tools%2Fproject");

        let artifact = f
            .subject
            .resolve(
                &mapped_request("tools/project", VersionSpec::Any, &ctx),
                Criteria::new(PreRelease::Exclude)
                    .minimum_age(std::time::Duration::from_secs(86_400)),
                &ctx,
            )
            .await
            .expect("the rule excused the window");

        assert_eq!(artifact.version_text(), Some("3.0.0"));
    }

    #[test]
    fn mapped_repository_must_be_listed() {
        let rules: Vec<crate::config::NameRule> = serde_json::from_value(serde_json::json!([{
            "from": { "name": "elsewhere/project" },
            "to": { "name": "tools/project" },
        }]))
        .expect("rules");
        let names = NameMap::parse(&rules).expect("parses");

        assert!(GitHubSource::check_names(&allowing(&["owner/*"]), &names).is_err());
        assert!(GitHubSource::check_names(&allowing(&["elsewhere/*"]), &names).is_ok());
    }

    /// The source cannot reach a host it was not configured for, however it
    /// spells the URL.
    #[tokio::test]
    async fn source_cannot_reach_unconfigured_host() {
        let host = Arc::new(TestHost::allowing(standard(), "h://elsewhere.test/"));
        let source = GitHubSource::open(API, &allowing(&["owner/*"]), host.clone()).expect("opens");
        let ctx = ctx();

        let err = source.versions(&id(), &ctx).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("outside what this extension may fetch")
        );
    }
}
