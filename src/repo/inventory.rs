//! A source backed by a report database, falling back to the real one.
//!
//! What a `find` and a `inspect` already learned about a repository,
//! served as though it were the repository. A `copy` fed by this pays no
//! metadata request for an artifact somebody already resolved, which is the
//! difference between a migration that costs one request per artifact and
//! one that costs three.
//!
//! # The inventory is the manifest
//!
//! Where this has an answer it gives it, even if the repository has moved
//! on since the artifact enumeration. That is deliberate: a migration
//! driven from a report copies **what the report says**, so re-running it
//! produces the same result rather than quietly widening. A mirror that
//! wants the newest state re-enumerates the artifacts; that is what
//! enumeration is for.
//!
//! # Falling back, per artifact rather than per run
//!
//! An inspection that did not finish leaves an inventory that knows some
//! artifacts and not others -- and a `find` alone leaves coordinates
//! with no files at all, because an enumerator reports what a repository holds
//! and not what each thing is. So the fallback is decided per question:
//!
//! | Question | From the inventory when | Otherwise |
//! | --- | --- | --- |
//! | `confirmed` | that exact version is recorded or listed | the source |
//! | `versions` | a whole-catalog walk listed the source, and it has any version of that name | the source |
//! | `unlisted` | never -- an exact version the listing lacks is the source's | the source |
//! | `metadata` | that exact version has files recorded | the source |
//! | `deps` | never -- no dependency edges are stored | the source |
//!
//! Anything that describes the *repository* rather than its contents --
//! which ecosystems it speaks, how its versions order -- always comes from
//! the real source, which is the thing that knows.
//!
//! An artifact with an inventory row and no files is the case worth being
//! precise about: it is what `find` produces, and treating it as "no
//! files to copy" would publish an empty release. It falls back.
//!
//! # An artifact enumeration's listing joins the resolution
//!
//! A `find` may list the files the catalog holds, and those are never
//! an answer on their own: only a file a *resolution* named -- from the
//! source, or from a recorded `inspect` -- counts toward the `metadata`
//! row above. Whatever the resolution, the listing is then folded in by
//! [`combine`], and a disagreement refuses the artifact with
//! `listing-mismatch`.

mod combine;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Code;
use crate::ecosystem::Ecosystem;
use crate::message;
use crate::model::{ArtifactId, Dependency, FileRef, Release, ResolvedArtifact, Version};
use crate::net::Expectation;
use crate::report::{ReportQuery, Work, WorkFile};

use super::{Downloaded, Source};

/// A source that answers from a report database first.
pub struct InventorySource {
    query: Arc<dyn ReportQuery>,

    /// The configured name the inventory is keyed by. A report holds many
    /// repositories, and only one of them is the one being copied from.
    source: String,

    /// The repository itself, for everything the inventory cannot answer.
    ///
    /// Not optional. An inventory is a record of what somebody looked at,
    /// never a claim to be the repository, so there is always something
    /// behind it.
    fallback: Arc<dyn Source>,
}

impl InventorySource {
    pub fn new(
        query: Arc<dyn ReportQuery>,
        source: impl Into<String>,
        fallback: Arc<dyn Source>,
    ) -> Self {
        Self {
            query,
            source: source.into(),
            fallback,
        }
    }

    /// The versions of `id` the inventory lists: none unless an artifact
    /// enumeration walked the whole source; see `versions`.
    fn listing(&self, id: &ArtifactId) -> Result<Vec<(String, bool)>> {
        if !self.query.source_listed(&self.source)? {
            return Ok(Vec::new());
        }

        self.query.versions_held(&self.source, &id.purl())
    }

    /// What the inventory holds for one exact version, listed or resolved.
    fn recorded(&self, id: &ArtifactId, version: Option<&Version>) -> Result<Option<Work>> {
        // The versionless purl where there is no version, which is the
        // string `ids::artifact` stored for such a row. `purl_at("")` would
        // render a trailing `@` and match nothing.
        let purl = match version {
            Some(version) => id.purl_at(version.text()),
            None => id.purl(),
        };

        self.query.held(&self.source, &purl)
    }

    /// Say that the listing and the resolution disagree, which refuses the
    /// artifact: `listing-mismatch` is `skip-artifact` by default.
    ///
    /// Reported and not returned as an error as well, which would record
    /// the same failure twice.
    fn mismatched(&self, artifact: &ResolvedArtifact, mismatches: &[combine::Mismatch], ctx: &Ctx) {
        let files = mismatches
            .iter()
            .map(|mismatch| format!("{} ({})", mismatch.file, mismatch.detail))
            .collect::<Vec<_>>()
            .join("; ");

        ctx.report(
            Code::ListingMismatch,
            message!(
                "inventory-listing-mismatch",
                "{purl}: the scan of {source} and the resolution disagree about {files}",
                purl = artifact.purl(),
                source = &self.source,
                files = &files,
            ),
        );
    }
}

/// The recorded answer to `metadata`, when a resolution was recorded.
///
/// A row with no resolved files is not an answer: `find` records
/// coordinates, and perhaps a listing, without resolving anything, and
/// publishing only what a catalog listed would skip every check the source
/// makes -- and, with no files at all, put an empty release in the target
/// that nobody could tell from a real one.
fn resolved_from(
    id: &ArtifactId,
    version: Option<&Version>,
    work: &Work,
) -> Option<ResolvedArtifact> {
    let files: Vec<FileRef> = work
        .files
        .iter()
        .filter(|file| file.resolved)
        .map(as_file)
        .collect();

    if files.is_empty() {
        return None;
    }

    Some(ResolvedArtifact {
        id: id.clone(),
        version: version.cloned(),
        files,
        license: work.declared_license.clone(),
        published: work.published,
    })
}

#[async_trait]
impl Source for InventorySource {
    /// From the repository, which is the thing that knows its own rules.
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        self.fallback.ecosystem(id)
    }

    fn ecosystems(&self) -> Vec<crate::model::EcosystemId> {
        self.fallback.ecosystems()
    }

    fn version_handler(&self, id: &ArtifactId) -> Result<&dyn crate::version::VersionHandler> {
        self.fallback.version_handler(id)
    }

    /// Every version of this name the inventory holds, or the repository's
    /// answer when it holds none.
    ///
    /// **The inventory wins where it is a listing.** A report-fed copy is
    /// working through a manifest, and a version the repository gained
    /// since the artifact enumeration is not in it -- taking one would make
    /// a re-run copy more than the run it repeats.
    ///
    /// Only an artifact enumeration that walked the whole catalog makes the
    /// inventory a listing. Without one, its rows are whatever resolutions
    /// recorded, and a dependency walk that resolved `2.1.4` first would
    /// see that version alone when it later asked for `2.0.1`.
    async fn versions(&self, id: &ArtifactId, ctx: &Ctx) -> Result<Vec<Version>> {
        let held = self.listing(id)?;

        if held.is_empty() {
            return self.fallback.versions(id, ctx).await;
        }

        Ok(held
            .into_iter()
            .map(|(text, pre_release)| {
                Version::new(
                    text,
                    match pre_release {
                        true => Release::PreRelease,
                        false => Release::General,
                    },
                )
            })
            .collect())
    }

    /// An exact version the inventory recorded, or else whatever the
    /// repository confirms directly.
    ///
    /// A recorded version is the inventory's answer, as for `metadata`, so
    /// it reaches the repository no sooner than the listing would.
    async fn confirmed(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        let asked = Version::new(text, Release::General);

        if let Some(work) = self.recorded(id, Some(&asked))? {
            return Ok(Some(Version::new(text, release_of(work.pre_release))));
        }

        if let Some((_, pre_release)) = self.listing(id)?.into_iter().find(|(held, _)| held == text)
        {
            return Ok(Some(Version::new(text, release_of(pre_release))));
        }

        self.fallback.confirmed(id, text, ctx).await
    }

    /// An exact version the listing lacks, from the repository.
    ///
    /// A manifest names what to copy, not every dependency a walk will
    /// meet: a dependency pinned to a version the enumeration did not see
    /// is still the repository's to answer. Its version list first, then
    /// whatever it confirms directly.
    async fn unlisted(&self, id: &ArtifactId, text: &str, ctx: &Ctx) -> Result<Option<Version>> {
        if !self.listing(id)?.is_empty() {
            let listed = match self.fallback.versions(id, ctx).await {
                Ok(listed) => listed,
                Err(err) if err.code() == crate::core::problem::Code::ArtifactNotFound => {
                    Vec::new()
                }
                Err(err) => return Err(err),
            };

            if let Some(found) = listed.into_iter().find(|version| version.text() == text) {
                return Ok(Some(found));
            }
        }

        self.fallback.unlisted(id, text, ctx).await
    }

    /// From the repository, which is the thing that knows whether its own
    /// artifacts have versions.
    fn versioned(&self, id: &ArtifactId) -> bool {
        self.fallback.versioned(id)
    }

    /// Files, checksums, license, and publish time, from whichever knows.
    async fn metadata(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        ctx: &Ctx,
    ) -> Result<ResolvedArtifact> {
        let recorded = self.recorded(id, version)?;
        let rows: &[WorkFile] = recorded.as_ref().map_or(&[], |work| work.files.as_slice());

        let resolved = match recorded
            .as_ref()
            .and_then(|work| resolved_from(id, version, work))
        {
            Some(resolved) => resolved,
            None => self.fallback.metadata(id, version, ctx).await?,
        };

        let combined = combine::combine(resolved, rows);

        if !combined.mismatches.is_empty() {
            self.mismatched(&combined.artifact, &combined.mismatches, ctx);
        }

        // A recorded answer is still only what the source offers today:
        // an `omit` rule added since the record was made applies to it.
        self.fallback.offered(combined.artifact, ctx).await
    }

    /// Always the repository.
    ///
    /// No dependency edges are stored: `provenance_item` records why an
    /// artifact was reached, which is the reverse edge and only for
    /// artifacts an earlier walk already reached. A copy fed by a complete
    /// inventory has no reason to spider anyway -- the inventory is the
    /// list -- so this is the seldom-taken path rather than the hot one.
    async fn deps(&self, artifact: &ResolvedArtifact, ctx: &Ctx) -> Result<Vec<Dependency>> {
        self.fallback.deps(artifact, ctx).await
    }

    /// The live source's, because an inventory records where the bytes
    /// are and has no host to fetch them through.
    async fn download(
        &self,
        file: &FileRef,
        expect: &Expectation,
        ctx: &Ctx,
    ) -> Result<Downloaded> {
        self.fallback.download(file, expect, ctx).await
    }

    /// The live source's, whose keys the check needs.
    async fn verify(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &crate::repo::Companions,
        ctx: &Ctx,
    ) -> Result<()> {
        self.fallback.verify(artifact, files, companions, ctx).await
    }

    fn serves(&self, url: &str) -> bool {
        self.fallback.serves(url)
    }

    fn companion(
        &self,
        artifact: &ResolvedArtifact,
        file: &FileRef,
        kind: crate::ecosystem::Companion,
    ) -> Option<(FileRef, Expectation)> {
        // The live source names it: a URL it computes needs no record.
        self.fallback.companion(artifact, file, kind)
    }
}

/// One recorded file as the rest of the crate expects it.
///
/// The core-metadata document and the signatures come back as a resolution
/// recorded them, so a copy fed from here fetches the same companions a
/// copy fed from the source would; see
/// `docs/contributors/report-as-database.md`.
/// How the inventory recorded a version's release status.
fn release_of(pre_release: bool) -> Release {
    match pre_release {
        true => Release::PreRelease,
        false => Release::General,
    }
}

fn as_file(file: &WorkFile) -> FileRef {
    FileRef {
        name: file.name.clone(),
        url: file.url.clone(),
        size: file.size,
        digests: file.digests.clone(),
        signatures: file.signatures.clone(),
        core_metadata: file.core_metadata.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::core::ctx::Ctx;
    use crate::model::{Cause, Digest, DigestAlg, EcosystemId};
    use crate::report::{Resume, Role, WorkFile};

    /// A report that holds whatever a test puts in it, and counts what it
    /// was asked, so a test can assert the source did **not** go to the
    /// repository.
    #[derive(Default)]
    struct Held {
        artifacts: Vec<Work>,

        /// Whether an artifact enumeration walked the whole source.
        listed: bool,
    }

    impl ReportQuery for Held {
        fn resume_enumeration(&self, _role: Role, _name: &str) -> Result<Option<Resume>> {
            Ok(None)
        }

        fn last_complete_enumeration(
            &self,
            _role: Role,
            _name: &str,
        ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
            Ok(None)
        }

        fn outstanding(
            &self,
            _source: &str,
            _destinations: &[&str],
            _after: i64,
            _limit: u32,
        ) -> Result<Vec<Work>> {
            Ok(self.artifacts.clone())
        }

        fn inventory(&self, _source: &str, _after: i64, _limit: u32) -> Result<Vec<Work>> {
            Ok(self.artifacts.clone())
        }

        fn cached(
            &self,
            _source: &str,
            _purl: &str,
            _file: &str,
        ) -> Result<Option<crate::report::CacheRecord>> {
            Ok(None)
        }

        fn holds(&self, _target: &str, _purl: &str) -> Result<bool> {
            Ok(false)
        }

        fn held(&self, _source: &str, purl: &str) -> Result<Option<Work>> {
            Ok(self
                .artifacts
                .iter()
                .find(|work| work.purl == purl)
                .cloned())
        }

        fn source_listed(&self, _source: &str) -> Result<bool> {
            Ok(self.listed)
        }

        fn versions_held(&self, _source: &str, package: &str) -> Result<Vec<(String, bool)>> {
            Ok(self
                .artifacts
                .iter()
                .filter_map(|work| {
                    let version = work.version.as_ref()?;
                    let id = ArtifactId::parse(&work.purl).ok()?;

                    (id.id.purl() == package).then(|| (version.clone(), work.pre_release))
                })
                .collect())
        }
    }

    /// A repository that records every question it was asked, so a test can
    /// show the inventory answered instead of it.
    #[derive(Default)]
    struct Asked {
        questions: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Source for Asked {
        fn ecosystem(&self, _id: &ArtifactId) -> Result<&dyn Ecosystem> {
            Err(crate::core::error::Error::Unimplemented("the test source"))
        }

        fn ecosystems(&self) -> Vec<EcosystemId> {
            vec![EcosystemId::npm()]
        }

        async fn versions(&self, id: &ArtifactId, _ctx: &Ctx) -> Result<Vec<Version>> {
            self.questions
                .lock()
                .expect("not poisoned")
                .push(format!("versions {id}"));

            Ok(vec![Version::new("9.9.9", Release::General)])
        }

        async fn metadata(
            &self,
            id: &ArtifactId,
            version: Option<&Version>,
            _ctx: &Ctx,
        ) -> Result<ResolvedArtifact> {
            self.questions.lock().expect("not poisoned").push(format!(
                "metadata {id}@{}",
                version.map(|v| v.text()).unwrap_or_default()
            ));

            Ok(ResolvedArtifact {
                id: id.clone(),
                version: version.cloned(),
                files: vec![FileRef::new("from-source.tgz", "h://origin.test/x.tgz")],
                license: Some("from the source".to_owned()),
                published: None,
            })
        }

        async fn deps(&self, artifact: &ResolvedArtifact, _ctx: &Ctx) -> Result<Vec<Dependency>> {
            self.questions
                .lock()
                .expect("not poisoned")
                .push(format!("deps {}", artifact.id));

            Ok(Vec::new())
        }

        async fn download(
            &self,
            _file: &FileRef,
            _expect: &Expectation,
            _ctx: &Ctx,
        ) -> Result<Downloaded> {
            unreachable!("not exercised")
        }

        fn serves(&self, url: &str) -> bool {
            self.questions
                .lock()
                .expect("not poisoned")
                .push(format!("serves {url}"));

            true
        }
    }

    impl Asked {
        fn questions(&self) -> Vec<String> {
            self.questions.lock().expect("not poisoned").clone()
        }
    }

    fn work(purl: &str, version: &str, files: Vec<WorkFile>) -> Work {
        Work {
            key: 1,
            purl: purl.to_owned(),
            version: Some(version.to_owned()),
            pre_release: false,
            declared_license: Some("MIT".to_owned()),
            published: None,
            run: None,
            files,
        }
    }

    fn payload() -> WorkFile {
        WorkFile {
            name: "tuna-1.0.0.tgz".to_owned(),
            url: "h://origin.test/tuna-1.0.0.tgz".to_owned(),
            size: Some(1024),
            digests: vec![Digest::new(DigestAlg::Sha256, "ab")],
            core_metadata: None,
            signatures: Vec::new(),
            listed: false,
            resolved: true,
        }
    }

    fn listed(name: &str, digests: Vec<Digest>) -> WorkFile {
        WorkFile {
            name: name.to_owned(),
            url: format!("h://catalog.test/{name}"),
            size: None,
            digests,
            core_metadata: None,
            signatures: Vec::new(),
            listed: true,
            resolved: false,
        }
    }

    /// A listing alone is not a resolution: the source is still asked, and
    /// what it names comes first, with the catalog's extra files after.
    #[tokio::test]
    async fn listing_joins_resolution() {
        let held = Held {
            artifacts: vec![work(
                "pkg:npm/tuna@1.0.0",
                "1.0.0",
                vec![listed("extra.txt", Vec::new())],
            )],
            ..Held::default()
        };

        let (source, asked) = built(held);
        let version = Version::new("1.0.0", Release::General);

        let resolved = with_ctx(async |ctx| source.metadata(&id(), Some(&version), ctx).await)
            .await
            .expect("metadata");

        let names: Vec<&str> = resolved
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();

        assert_eq!(names, ["from-source.tgz", "extra.txt"]);
        assert_eq!(asked.questions(), ["metadata pkg:npm/tuna@1.0.0"]);
    }

    /// A disagreement is reported once, as `listing-mismatch`, which
    /// refuses the artifact without failing the call as well.
    #[tokio::test]
    async fn listing_mismatch_refuses_once() {
        let held = Held {
            artifacts: vec![work(
                "pkg:npm/tuna@1.0.0",
                "1.0.0",
                vec![listed(
                    "from-source.tgz",
                    vec![
                        Digest::new(DigestAlg::Sha1, "aa"),
                        Digest::new(DigestAlg::Sha1, "bb"),
                    ],
                )],
            )],
            ..Held::default()
        };

        let (source, _) = built(held);
        let version = Version::new("1.0.0", Release::General);
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });

        source
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("reported, not failed");

        assert_eq!(ctx.problems().counts()[&Code::ListingMismatch], 1);
        assert_eq!(
            ctx.problems().worst(),
            Some(crate::core::problem::Action::SkipArtifact)
        );
    }

    fn built(held: Held) -> (InventorySource, Arc<Asked>) {
        let asked = Arc::new(Asked::default());
        let source = InventorySource::new(Arc::new(held), "origin", asked.clone());

        (source, asked)
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "tuna")
    }

    async fn with_ctx<T>(run: impl AsyncFnOnce(&Ctx) -> T) -> T {
        let ctx = Ctx::for_test(Cause::Requested { arg: "x".into() });

        run(&ctx).await
    }

    /// The whole point: an artifact somebody already resolved costs no
    /// request at all.
    #[tokio::test]
    async fn recorded_artifact_never_reaches_repository() {
        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", vec![payload()])],
            ..Held::default()
        };

        let (source, asked) = built(held);
        let version = Version::new("1.0.0", Release::General);

        let resolved = with_ctx(async |ctx| source.metadata(&id(), Some(&version), ctx).await)
            .await
            .expect("metadata");

        assert_eq!(resolved.license.as_deref(), Some("MIT"));
        assert_eq!(resolved.files.len(), 1);
        assert_eq!(resolved.files[0].name, "tuna-1.0.0.tgz");
        assert_eq!(
            resolved.files[0].digests,
            vec![Digest::new(DigestAlg::Sha256, "ab")]
        );

        assert!(asked.questions().is_empty(), "the repository was asked");
    }

    /// A recorded core-metadata document and signature come back on the
    /// file, so a copy fed from here fetches the companions a copy fed from
    /// the source would.
    #[tokio::test]
    async fn recorded_file_keeps_companions() {
        let signature = crate::model::SigRef {
            scheme: crate::model::SigScheme::PypiAttestation,
            key_id: None,
            value: None,
            url: Some("h://origin.test/provenance".to_owned()),
        };

        let mut file = payload();
        file.core_metadata = Some(vec![Digest::new(DigestAlg::Sha256, "cc")]);
        file.signatures = vec![signature.clone()];

        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", vec![file])],
            ..Held::default()
        };

        let (source, _) = built(held);
        let version = Version::new("1.0.0", Release::General);

        let resolved = with_ctx(async |ctx| source.metadata(&id(), Some(&version), ctx).await)
            .await
            .expect("metadata");

        assert_eq!(
            resolved.files[0].core_metadata,
            Some(vec![Digest::new(DigestAlg::Sha256, "cc")])
        );
        assert_eq!(resolved.files[0].signatures, vec![signature]);
    }

    /// An inspection that did not run, or did not reach this artifact, leaves
    /// nothing to answer with. The repository is still there.
    #[tokio::test]
    async fn unrecorded_artifact_falls_back() {
        let (source, asked) = built(Held::default());
        let version = Version::new("1.0.0", Release::General);

        let resolved = with_ctx(async |ctx| source.metadata(&id(), Some(&version), ctx).await)
            .await
            .expect("metadata");

        assert_eq!(resolved.license.as_deref(), Some("from the source"));
        assert_eq!(asked.questions(), vec!["metadata pkg:npm/tuna@1.0.0"]);
    }

    /// **The case a `find` produces.** A coordinate with no files is
    /// not an answer: treating it as "nothing to copy" would publish an
    /// empty release that nobody could tell from a real one.
    #[tokio::test]
    async fn coordinate_without_files_falls_back() {
        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", Vec::new())],
            ..Held::default()
        };

        let (source, asked) = built(held);
        let version = Version::new("1.0.0", Release::General);

        let resolved = with_ctx(async |ctx| source.metadata(&id(), Some(&version), ctx).await)
            .await
            .expect("metadata");

        assert_eq!(resolved.license.as_deref(), Some("from the source"));
        assert_eq!(asked.questions(), vec!["metadata pkg:npm/tuna@1.0.0"]);
    }

    /// The inventory is the manifest: a version the repository gained since
    /// the artifact enumeration is not in it, and taking one would make a
    /// re-run copy more than the run it repeats.
    #[tokio::test]
    async fn recorded_versions_win_over_repository() {
        let held = Held {
            artifacts: vec![
                work("pkg:npm/tuna@1.0.0", "1.0.0", vec![payload()]),
                work("pkg:npm/tuna@1.1.0", "1.1.0", vec![payload()]),
            ],
            listed: true,
        };

        let (source, asked) = built(held);

        let versions = with_ctx(async |ctx| source.versions(&id(), ctx).await)
            .await
            .expect("versions");

        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(texts, vec!["1.0.0", "1.1.0"]);
        assert!(asked.questions().is_empty());
    }

    /// Without a whole-catalog walk, recorded rows are what resolutions
    /// happened to write, not a listing: the repository answers.
    #[tokio::test]
    async fn resolved_rows_not_listing() {
        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", vec![payload()])],
            listed: false,
        };

        let (source, asked) = built(held);

        let versions = with_ctx(async |ctx| source.versions(&id(), ctx).await)
            .await
            .expect("versions");
        let texts: Vec<&str> = versions.iter().map(Version::text).collect();

        assert_eq!(texts, vec!["9.9.9"]);
        assert_eq!(asked.questions(), vec!["versions pkg:npm/tuna"]);
    }

    /// A recorded exact version is confirmed from the record, without the
    /// repository.
    #[tokio::test]
    async fn recorded_version_confirmed_locally() {
        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", vec![payload()])],
            ..Held::default()
        };

        let (source, asked) = built(held);

        let found = with_ctx(async |ctx| source.confirmed(&id(), "1.0.0", ctx).await)
            .await
            .expect("confirmed");

        assert_eq!(found.as_ref().map(Version::text), Some("1.0.0"));
        assert!(asked.questions().is_empty(), "the repository was asked");
    }

    /// An exact version the listing lacks, such as a dependency pinned
    /// below what the enumeration saw, is the repository's to answer.
    #[tokio::test]
    async fn exact_version_beyond_listing_asks_repository() {
        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", vec![payload()])],
            listed: true,
        };

        let (source, _) = built(held);

        let found = with_ctx(async |ctx| source.unlisted(&id(), "9.9.9", ctx).await)
            .await
            .expect("asked");

        assert_eq!(found.as_ref().map(Version::text), Some("9.9.9"));
    }

    /// A name the inventory has never seen falls back, rather than
    /// answering "no versions" and reporting the artifact unresolvable.
    #[tokio::test]
    async fn unknown_name_asks_repository_for_versions() {
        let (source, asked) = built(Held::default());

        let versions = with_ctx(async |ctx| source.versions(&id(), ctx).await)
            .await
            .expect("versions");

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].text(), "9.9.9");
        assert_eq!(asked.questions(), vec!["versions pkg:npm/tuna"]);
    }

    /// No dependency edges are stored, so this is always the repository's
    /// answer. A copy fed by a complete inventory has no reason to spider,
    /// which is what keeps this off the hot path.
    #[tokio::test]
    async fn dependencies_always_from_repository() {
        let held = Held {
            artifacts: vec![work("pkg:npm/tuna@1.0.0", "1.0.0", vec![payload()])],
            ..Held::default()
        };

        let (source, asked) = built(held);

        let artifact = ResolvedArtifact {
            id: id(),
            version: Some(Version::new("1.0.0", Release::General)),
            files: Vec::new(),
            license: None,
            published: None,
        };

        with_ctx(async |ctx| source.deps(&artifact, ctx).await)
            .await
            .expect("deps");

        assert_eq!(asked.questions(), vec!["deps pkg:npm/tuna"]);
    }
}
