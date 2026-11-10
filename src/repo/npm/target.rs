//! Publishing to an npm registry.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md), [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ecosystem::{Companion, Ecosystem, Npm};
use crate::ext::{ExtHost, Options};
use crate::model::{ArtifactId, ResolvedArtifact, Version, VersionSpec};
use crate::net::{ByteLimit, Req, encode_unreserved, normalized_base};
use crate::repo::{Companions, Delivered, Delivery, Target};
use crate::version::{PreRelease, VersionHandler};

use super::{manifest, package_name, publish};
/// Publishing to an npm registry.
///
/// One `PUT` per version, which is what `npm publish` does and what every
/// registry claiming npm compatibility implements.
///
/// The document's shape -- and what it cannot carry, which matters -- is set
/// out in this module's `publish` submodule.
pub struct NpmTarget {
    base_url: String,

    /// Where every request goes.
    host: Arc<dyn ExtHost>,
    ecosystem: Npm,

    /// Whether a publish asserts `latest`, and on what terms.
    dist_tags: DistTags,

    /// Whether a copied manifest keeps the origin registry's own keys.
    registry_fields: manifest::RegistryFields,

    /// Serializes read-then-publish per package.
    ///
    /// `latest_after` reads the target's current tag and then publishes a
    /// decision based on it, which is a read-modify-write. Two versions of
    /// one package published concurrently would otherwise both read "no
    /// latest", both claim it, and leave the tag on whichever wrote last --
    /// the exact failure the read was added to prevent, since a lock file
    /// naming two versions puts both in the spider's first level.
    ///
    /// **Striped rather than per package**, so this is a fixed-size array
    /// and not a map that grows with the number of packages copied. Two
    /// unrelated packages landing on one stripe serialize needlessly; with
    /// far more stripes than workers that is rare, and the cost is a wait
    /// rather than a wrong answer.
    publishing: [tokio::sync::Mutex<()>; PUBLISH_STRIPES],
}

/// How many locks guard the read-then-publish.
///
/// Comfortably above the spider's default concurrency, so unrelated
/// packages rarely collide; small enough to be nothing in a struct that
/// exists once per run.
const PUBLISH_STRIPES: usize = 64;

impl NpmTarget {
    /// No HTTP client, for the same reason [`NpmSource`](super::NpmSource) has none: every
    /// request goes through `host`, which confines it to the host it was
    /// configured for.
    pub fn new(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: normalized_base(base_url),
            host,
            ecosystem: Npm,
            dist_tags: DistTags::default(),
            registry_fields: manifest::RegistryFields::default(),
            publishing: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        }
    }

    /// Build from configuration, which is where `dist-tags` is read.
    pub fn open(base_url: &str, options: &Options, host: Arc<dyn ExtHost>) -> Result<Self> {
        Ok(Self {
            dist_tags: DistTags::from_options(options)?,
            registry_fields: manifest::RegistryFields::from_options(options)?,
            ..Self::new(base_url, host)
        })
    }

    /// Assert `latest` on these terms.
    pub fn tagging(mut self, dist_tags: DistTags) -> Self {
        self.dist_tags = dist_tags;
        self
    }

    /// The lock covering one package's read-then-publish.
    fn stripe(&self, id: &ArtifactId) -> &tokio::sync::Mutex<()> {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        package_name(id).hash(&mut hasher);

        &self.publishing[hasher.finish() as usize % PUBLISH_STRIPES]
    }

    /// Where a published version's tarball will live.
    ///
    /// Written into the document because npm's format requires it. Most
    /// registries rewrite it to their own address on receipt -- they have
    /// to, since the publisher cannot know where it will be served from --
    /// so this is the conventional layout rather than a promise.
    fn tarball_url(&self, id: &ArtifactId, version: &Version) -> String {
        let name = package_name(id);

        format!(
            "{}/{name}/-/{}-{}.tgz",
            self.base_url,
            id.name(),
            version.text()
        )
    }
}

/// Whether a publish asserts the package's `latest` tag, and on what
/// terms.
///
/// **`latest` is repository state, not a property of a version.** It is the
/// same shape as `maven-metadata.xml`, which this tool deliberately refuses
/// to copy, as its Maven module explains -- and it is a *publisher's
/// editorial choice* rather than a fact: `npm dist-tag add foo@1.9.5
/// latest` after a bad 2.0 is routine, and a version newer than `latest`
/// is a normal state for a package to be in.
///
/// The disanalogy with Maven is why this is a setting rather than a flat
/// refusal: a target **regenerates** `maven-metadata.xml` from what it
/// holds, so not copying costs nothing, while nothing regenerates
/// `dist-tags` -- a mirror with none may not answer `npm install foo` at
/// all. npm has no specification requiring a publish to set it, so what is
/// correct here depends on what the mirror is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DistTags {
    /// Never send `dist-tags`.
    ///
    /// **The default**, because it is the only mode that cannot produce a
    /// tag that is wrong and looks right. The tag stays the target's
    /// business, exactly as `maven-metadata.xml` does.
    ///
    /// What it costs is visible and recoverable: a mirror that did not have
    /// the package has no `latest` for it, so `npm install foo` does not
    /// resolve until somebody runs `npm dist-tag`. An operator notices
    /// that immediately. The alternative failures are silent.
    #[default]
    Never,

    /// Set `latest` only when creating the package, and never move it.
    ///
    /// A mirror that did not have the package gets a working `latest`; one
    /// that did keeps whatever its operator chose, including a deliberate
    /// downgrade.
    ///
    /// **Not the default, and the reason is the same one that motivated
    /// all of this.** Several versions of a new package copied in one run
    /// are created concurrently, so "the version that created it" is
    /// whichever upload went first -- which may be the oldest. The tag is
    /// then wrong and looks right, which is worse than absent.
    OnCreate,

    /// Keep `latest` on the highest version the target holds.
    ///
    /// Predictable and order-independent, and **wrong wherever a publisher
    /// meant something by `latest`**: it silently undoes a deliberate
    /// downgrade every time a copy touches the package. For a mirror whose
    /// tags nobody curates.
    Highest,
}

/// The option that selects one.
const DIST_TAGS_OPTION: &str = "dist-tags";

impl DistTags {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "never" => Some(DistTags::Never),
            "on-create" => Some(DistTags::OnCreate),
            "highest" => Some(DistTags::Highest),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["never", "on-create", "highest"]
    }

    /// Read from a target's options, defaulting to [`DistTags::OnCreate`].
    pub fn from_options(options: &Options) -> Result<Self> {
        let Some(named) = options.string(DIST_TAGS_OPTION)? else {
            return Ok(DistTags::default());
        };

        Self::parse(named).ok_or_else(|| {
            Error::Config(format!(
                "{DIST_TAGS_OPTION} is {named:?}, which is not one of: {known}",
                known = Self::names().join(", "),
            ))
        })
    }
}

impl NpmTarget {
    /// What the package's `latest` tag should name once `version` is
    /// published, or `None` to send no `dist-tags` at all.
    ///
    /// # Why the target is asked rather than assumed
    ///
    /// A registry takes `dist-tags` as given, so a publish either states a
    /// tag or leaves the package without one. Stating *this version* every
    /// time is the one answer that is definitely wrong: copying several
    /// versions of one package is **ordinary** for npm -- a lock file names
    /// them, a user names them (`abc@1.0 abc@2.0`) -- and a spider walks
    /// them concurrently, so the tag would land on whichever upload
    /// finished last.
    ///
    /// Both answering modes therefore read what the target already says
    /// before deciding, which also makes them order-independent and needs
    /// nothing remembered between publishes.
    ///
    /// # What it costs
    ///
    /// One request to `/-/package/{name}/dist-tags`, which returns the tags
    /// and nothing else -- deliberately not the packument, which for a
    /// popular package is megabytes, the same reason [`NpmTarget::exists`]
    /// asks the version document. [`DistTags::Never`] makes no request at
    /// all.
    async fn latest_after(
        &self,
        id: &ArtifactId,
        version: &Version,
        ctx: &Ctx,
    ) -> Result<Option<String>> {
        if self.dist_tags == DistTags::Never {
            return Ok(None);
        }

        let url = format!(
            "{}/-/package/{}/dist-tags",
            self.base_url,
            encode_unreserved(&package_name(id))
        );

        let tags: BTreeMap<String, String> = match crate::ext::fetch_json(
            &*self.host,
            &Req::get(&url),
            ByteLimit::kib(64),
            "npm dist-tags",
            ctx,
        )
        .await
        {
            Ok(tags) => tags,

            // No package, so no tag to preserve.
            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                BTreeMap::new()
            }

            // A registry that will not answer is **not** a reason to
            // clobber a tag it may well hold. Publishing this version
            // as latest on a guess is the one outcome that loses
            // information, so the failure is reported instead.
            Err(err) => return Err(err),
        };

        let Some(current) = tags.get("latest") else {
            // Creating the package, so there is no choice of the
            // operator's to respect and nothing to compare against.
            return Ok(Some(version.text().to_owned()));
        };

        // The package exists and already says something. Under `on-create`
        // that is the operator's answer, deliberate or not, and this
        // publish has no standing to change it.
        if self.dist_tags == DistTags::OnCreate {
            return Ok(Some(current.clone()));
        }

        let candidates = self
            .ecosystem
            .classify(&[current.clone(), version.text().to_owned()]);

        // Pre-releases included: `latest` is a claim about what the target
        // holds, and refusing to consider one that is already the tag would
        // silently demote it.
        let highest = self
            .ecosystem
            .select(&VersionSpec::Any, &candidates, PreRelease::Include);

        // `select` drops what it cannot parse, so a current tag naming
        // something that is not a version loses to this one. That repairs
        // a tag already pointing at nothing orderable rather than
        // preserving it -- and the alternative, keeping it forever, leaves
        // a mirror whose `latest` no version resolver can use.
        //
        // The residual risk is a version this build's parser rejects but
        // the registry accepts, which would demote a legitimately higher
        // tag. That is a parser bug rather than a policy, and npm versions
        // are semver by definition.
        //
        // Both unparseable: nothing to choose between them, so the
        // existing tag stays.
        Ok(Some(match highest {
            Some(highest) => highest.text().to_owned(),
            None => current.clone(),
        }))
    }
}

#[async_trait]
impl Target for NpmTarget {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        crate::repo::sole_ecosystem(&self.ecosystem, id)
    }

    /// Whether the registry already serves this exact version.
    ///
    /// Asked of the **version document** rather than the packument: a
    /// packument for a popular package is megabytes, and this question is
    /// asked once per artifact in a migration that may run to millions.
    ///
    /// A 404 is the answer "no", not a failure -- which is why it is caught
    /// here rather than propagated. Any other failure is propagated: a
    /// registry that is unreachable has not told us the version is absent,
    /// and treating that as "no" would republish everything.
    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        let version = crate::repo::version_required(id, version)?;

        let url = format!(
            "{}/{}/{}",
            self.base_url,
            encode_unreserved(&package_name(id)),
            version.text()
        );

        match self.host.head(&Req::head(&url), ctx).await {
            Ok(_) => Ok(true),

            Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => Ok(false),

            Err(err) => Err(err),
        }
    }

    /// Publish one version.
    ///
    /// `files` are the payloads; npm publishes exactly one per
    /// version, so anything else -- a signature, a checksum file -- is not
    /// part of the document and is not sent.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        let [tarball] = files else {
            return Err(Error::BadRequest {
                ecosystem: "npm",
                text: artifact.id.purl(),
                detail: format!(
                    "npm publishes one tarball per version, and {} files were staged",
                    files.len()
                ),
            });
        };

        let name = artifact.files.first().map_or("", |file| file.name.as_str());

        delivery.start(name);

        // Held across the read *and* the upload: deciding `latest` from
        // what the target holds is only sound if nothing else publishes
        // this package in between. `Never` reads nothing and so needs no
        // lock, but taking it anyway keeps one code path rather than two.
        let _publishing = self.stripe(&artifact.id).lock().await;

        // npm names a tarball and a dist-tag by version, so there is
        // nothing to publish without one.
        let version = crate::repo::version_required(&artifact.id, artifact.version.as_ref())?;

        // The origin's manifest, so the target serves its dependencies;
        // see `manifest` for where it comes from when the source staged
        // none.
        let staged = companions.get(name, Companion::PackageManifest);
        let (manifest, _) =
            manifest::manifest(artifact, tarball, staged, self.registry_fields, ctx);

        let document = publish::document(
            artifact,
            tarball,
            &self.tarball_url(&artifact.id, version),
            manifest,
            self.latest_after(&artifact.id, version, ctx)
                .await?
                .as_deref(),
        )?;

        let url = format!(
            "{}/{}",
            self.base_url,
            encode_unreserved(&package_name(&artifact.id))
        );

        self.host
            .send_file(
                &Req::put(&url).header("content-type", "application/json"),
                document.path(),
                self.host.constraints().max_in_memory(),
                ctx,
            )
            .await?;

        delivery.finish(name, Delivered::Uploaded);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::ExtHost;
    use crate::ext::testing::{Fixture, TestHost};
    use crate::model::{Cause, Digest, DigestAlg, EcosystemId, FileRef, Release};
    use crate::net::{Canned, FixtureClient};
    use base64::Engine as _;

    const MIRROR: &str = "h://mirror.test";
    const ORIGIN: &str = "h://registry.test";

    fn target(client: FixtureClient) -> Fixture<NpmTarget> {
        Fixture::build(client, |host| NpmTarget::new(MIRROR, host))
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "tuna".into() })
    }

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "tuna")
    }

    fn artifact() -> ResolvedArtifact {
        ResolvedArtifact {
            id: id(),
            version: Some(Version::new("1.2.0", Release::General)),
            files: vec![FileRef {
                name: "tuna-1.2.0.tgz".into(),
                url: format!("{ORIGIN}/tuna/-/tuna-1.2.0.tgz"),
                size: None,
                digests: vec![Digest {
                    alg: DigestAlg::Sha1,
                    hex: "ab".repeat(20),
                }],
                signatures: Vec::new(),
                core_metadata: None,
            }],
            license: Some("MIT".into()),
            published: None,
        }
    }

    /// Asked of the version document, not the packument: a packument for a
    /// popular package is megabytes and this is asked once per artifact.
    #[tokio::test]
    async fn exists_version_present() {
        let f = target(
            FixtureClient::new().with_body(format!("{MIRROR}/tuna/1.2.0"), r#"{"name":"tuna"}"#),
        );
        let ctx = ctx();

        let present = f
            .subject
            .exists(&id(), Some(&Version::new("1.2.0", Release::General)), &ctx)
            .await
            .expect("asked");

        assert!(present);
    }

    /// A 404 is the answer "no", not a failure -- which is the whole reason
    /// it is caught rather than propagated.
    #[tokio::test]
    async fn exists_version_absent() {
        let f = target(FixtureClient::new().with(
            format!("{MIRROR}/tuna/9.9.9"),
            Canned::status(StatusCode::NOT_FOUND),
        ));
        let ctx = ctx();

        let present = f
            .subject
            .exists(&id(), Some(&Version::new("9.9.9", Release::General)), &ctx)
            .await
            .expect("asked");

        assert!(!present);
    }

    /// Anything else propagates. A registry that is unreachable has not
    /// said the version is absent, and treating that as "no" would
    /// republish everything.
    #[tokio::test]
    async fn exists_unreachable_registry_not_absent() {
        let f = target(FixtureClient::new().with(
            format!("{MIRROR}/tuna/1.2.0"),
            Canned::status(StatusCode::SERVICE_UNAVAILABLE),
        ));
        let ctx = ctx();

        assert!(
            f.subject
                .exists(&id(), Some(&Version::new("1.2.0", Release::General)), &ctx)
                .await
                .is_err()
        );
    }

    /// The whole publish path: a staged tarball becomes a document, and the
    /// document is PUT to the package's URL with the tarball inside it.
    #[tokio::test]
    async fn publish_puts_document_with_tarball() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#),
        ));

        let payload = b"tarball bytes";
        let staged = host.cache().path("tuna-1.2.0.tgz").expect("path");
        std::fs::write(host.cache().resolve(&staged), payload).expect("staged");
        let staged = host.cache().resolve(&staged);

        let ctx = ctx();
        let published = NpmTarget::new(MIRROR, host.clone())
            .publish(
                &artifact(),
                &[staged],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await;

        published.expect("published");

        let sent = host.sent_to(&format!("{MIRROR}/tuna"));
        let [body] = sent.as_slice() else {
            panic!("expected one upload, got {}", sent.len());
        };

        let doc: serde_json::Value = serde_json::from_slice(body).expect("valid JSON");

        assert_eq!(doc["name"], "tuna");
        assert_eq!(doc["versions"]["1.2.0"]["dist"]["shasum"], "ab".repeat(20));

        // No `dist-tags` under the default: the tag is the target's
        // business. The modes that do assert one are tested below.
        assert!(doc["dist-tags"].is_null());

        let data = doc["_attachments"]["tuna-1.2.0.tgz"]["data"]
            .as_str()
            .expect("base64");

        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .expect("decodes"),
            payload
        );
    }

    /// Two versions of one package publishing **concurrently** must not
    /// interleave their read-then-publish.
    ///
    /// This is the lock-file case: both versions are roots, so both sit in
    /// the spider's first level and run at once. Deciding `latest` means
    /// reading the target's tag and then publishing a decision based on
    /// it, so an interleaving would have both read "no latest", both claim
    /// it, and the tag land on whichever wrote last -- the very failure the
    /// read was added to prevent.
    ///
    /// Asserted on the **request order**, which is the observable shape of
    /// the property: one package's read and write must be adjacent. A
    /// timing assertion would say the same thing less reliably.
    #[tokio::test]
    async fn publish_read_and_write_do_not_interleave() {
        let tags = format!("{MIRROR}/-/package/tuna/dist-tags");
        let upload = format!("{MIRROR}/tuna");

        // Slow, so an unlocked pair would certainly overlap rather than
        // happening to finish in order.
        let client = Arc::new(
            FixtureClient::new()
                .with(tags.clone(), Canned::status(StatusCode::NOT_FOUND))
                .with(
                    upload.clone(),
                    Canned::ok(r#"{"ok":true}"#).slow(std::time::Duration::from_millis(25)),
                ),
        );

        let host = Arc::new(TestHost::sharing(client.clone()));
        let target = Arc::new(NpmTarget::new(MIRROR, host.clone()).tagging(DistTags::Highest));

        let publish = |version: &'static str| {
            let host = host.clone();
            let target = target.clone();

            async move {
                // One cache for every publish, so each writes its own name.
                let staged = host
                    .cache()
                    .path(&format!("tuna-{version}.tgz"))
                    .expect("path");
                std::fs::write(host.cache().resolve(&staged), b"x").expect("staged");
                let staged = host.cache().resolve(&staged);

                let mut artifact = artifact();
                artifact.version = Some(Version::new(version, Release::General));

                let ctx = ctx();

                target
                    .publish(
                        &artifact,
                        &[staged],
                        &Companions::default(),
                        &mut Delivery::default(),
                        &ctx,
                    )
                    .await
                    .expect("published");
            }
        };

        tokio::join!(publish("2.0.0"), publish("1.0.0"));

        let order = client.requested();
        let seen: Vec<&str> = order.iter().map(String::as_str).collect();

        assert_eq!(
            seen,
            [
                tags.as_str(),
                upload.as_str(),
                tags.as_str(),
                upload.as_str()
            ],
            "the two publishes interleaved, so both decided `latest` from the same read"
        );
    }

    // -- `latest` ----------------------------------------------------------

    /// Publishes `version` under `mode` against a target whose dist-tags
    /// say `current`, and returns what `latest` ended up naming -- `None`
    /// when the document carried no `dist-tags` at all.
    async fn latest_after_publishing(
        mode: DistTags,
        version: &str,
        current: Option<&str>,
    ) -> Option<String> {
        let tags = format!("{MIRROR}/-/package/tuna/dist-tags");

        let mut client = FixtureClient::new().with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#);

        client = match current {
            Some(current) => client.with_body(tags, format!(r#"{{"latest":"{current}"}}"#)),
            None => client.with(tags, Canned::status(StatusCode::NOT_FOUND)),
        };

        let host = Arc::new(TestHost::new(client));

        let staged = host.cache().path("tuna.tgz").expect("path");
        std::fs::write(host.cache().resolve(&staged), b"x").expect("staged");
        let staged = host.cache().resolve(&staged);

        let mut artifact = artifact();
        artifact.version = Some(Version::new(version, Release::General));

        let ctx = ctx();

        NpmTarget::new(MIRROR, host.clone())
            .tagging(mode)
            .publish(
                &artifact,
                &[staged],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect("published");

        let sent = host.sent_to(&format!("{MIRROR}/tuna"));
        let doc: serde_json::Value = serde_json::from_slice(&sent[0]).expect("valid JSON");

        doc["dist-tags"]["latest"].as_str().map(ToOwned::to_owned)
    }

    /// **The default asserts nothing.** `latest` is repository state and a
    /// publisher's editorial choice, not a property of the version being
    /// published -- the same argument that keeps `maven-metadata.xml` out of
    /// a copy. Asking for nothing is the only answer that cannot write a
    /// tag that is wrong and looks right.
    #[tokio::test]
    async fn tags_none_asserted_by_default() {
        assert_eq!(
            latest_after_publishing(DistTags::default(), "1.2.0", None).await,
            None
        );
        assert_eq!(DistTags::default(), DistTags::Never);
    }

    /// And it asks the target nothing either, so the default costs no
    /// request per publish.
    #[tokio::test]
    async fn tags_not_read_by_default() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new().with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#),
        ));

        let staged = host.cache().path("tuna.tgz").expect("path");
        std::fs::write(host.cache().resolve(&staged), b"x").expect("staged");
        let staged = host.cache().resolve(&staged);

        let ctx = ctx();

        NpmTarget::new(MIRROR, host.clone())
            .publish(
                &artifact(),
                &[staged],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect("published");

        assert_eq!(host.hits(&format!("{MIRROR}/-/package/tuna/dist-tags")), 0);
    }

    /// `on-create` gives a package the target did not have a working tag.
    #[tokio::test]
    async fn tags_on_create_tags_new_package() {
        assert_eq!(
            latest_after_publishing(DistTags::OnCreate, "1.2.0", None).await,
            Some("1.2.0".to_owned())
        );
    }

    /// And never moves one it did have, however the versions compare -- the
    /// existing tag is the operator's answer, including a deliberate
    /// `npm dist-tag add foo@1.9.5 latest` after a bad 2.0.
    #[tokio::test]
    async fn tags_on_create_keeps_existing() {
        for version in ["1.0.0", "9.0.0"] {
            assert_eq!(
                latest_after_publishing(DistTags::OnCreate, version, Some("2.0.0")).await,
                Some("2.0.0".to_owned()),
                "publishing {version} moved a tag it should not have"
            );
        }
    }

    /// A package the target does not have: this version is the only one
    /// there is.
    #[tokio::test]
    async fn tags_first_version_becomes_latest() {
        assert_eq!(
            latest_after_publishing(DistTags::Highest, "1.2.0", None).await,
            Some("1.2.0".to_owned())
        );
    }

    /// **The case `highest` exists for.** Copying several versions of one
    /// package is ordinary for npm, and the walk is concurrent, so an older
    /// version can finish last. Under `highest` it does not take the tag.
    #[tokio::test]
    async fn tags_older_version_keeps_newer_latest() {
        assert_eq!(
            latest_after_publishing(DistTags::Highest, "1.0.0", Some("2.0.0")).await,
            Some("2.0.0".to_owned()),
            "backfilling an old version demoted the tag"
        );
    }

    /// And a newer one does take it -- which is also the mode's flaw: a
    /// publisher who deliberately pinned `latest` lower gets overruled.
    #[tokio::test]
    async fn tags_newer_version_takes_latest() {
        assert_eq!(
            latest_after_publishing(DistTags::Highest, "3.0.0", Some("2.0.0")).await,
            Some("3.0.0".to_owned())
        );
    }

    /// Order-independence in one assertion: whichever of two versions is
    /// published second, the tag ends up on the higher.
    #[tokio::test]
    async fn tags_independent_of_publish_order() {
        let ascending = latest_after_publishing(DistTags::Highest, "1.0.0", Some("2.0.0")).await;
        let descending = latest_after_publishing(DistTags::Highest, "2.0.0", Some("1.0.0")).await;

        assert_eq!(ascending, descending);
        assert_eq!(ascending, Some("2.0.0".to_owned()));
    }

    /// Compared by npm's own ordering, not as text -- `1.10.0` is above
    /// `1.9.0` and a string comparison says the opposite.
    #[tokio::test]
    async fn tags_versions_compared_numerically() {
        assert_eq!(
            latest_after_publishing(DistTags::Highest, "1.10.0", Some("1.9.0")).await,
            Some("1.10.0".to_owned())
        );
    }

    /// A current tag naming something that is not a version loses to one
    /// that is. Keeping it would leave a mirror whose `latest` no resolver
    /// can use.
    #[tokio::test]
    async fn tags_unorderable_loses_to_real_version() {
        assert_eq!(
            latest_after_publishing(DistTags::Highest, "1.0.0", Some("nightly-build")).await,
            Some("1.0.0".to_owned())
        );
    }

    /// With nothing to choose between them, the existing tag stays.
    #[tokio::test]
    async fn tags_two_unorderable_keep_existing() {
        assert_eq!(
            latest_after_publishing(
                DistTags::Highest,
                "also-not-a-version",
                Some("nightly-build")
            )
            .await,
            Some("nightly-build".to_owned())
        );
    }

    /// A typo names the alternatives rather than falling back to a mode
    /// the user did not ask for.
    #[test]
    fn tags_unknown_mode_refused() {
        let options = crate::ext::Options::new(
            serde_json::json!({"dist-tags": "newest"})
                .as_object()
                .expect("an object")
                .clone(),
        );

        let err = DistTags::from_options(&options).expect_err("not a mode");

        assert!(err.to_string().contains("newest"), "{err}");
        assert!(err.to_string().contains("on-create"), "{err}");
    }

    /// A registry that will not say what its tags are is **not** a reason
    /// to overwrite one it may well hold. Guessing is the one outcome that
    /// loses information, so the publish fails instead.
    #[tokio::test]
    async fn tags_unreadable_endpoint_stops_publish() {
        let host = Arc::new(TestHost::new(
            FixtureClient::new()
                .with(
                    format!("{MIRROR}/-/package/tuna/dist-tags"),
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                )
                .with_body(format!("{MIRROR}/tuna"), r#"{"ok":true}"#),
        ));

        let staged = host.cache().path("tuna.tgz").expect("path");
        std::fs::write(host.cache().resolve(&staged), b"x").expect("staged");
        let staged = host.cache().resolve(&staged);

        let ctx = ctx();
        let refused = NpmTarget::new(MIRROR, host.clone())
            .tagging(DistTags::Highest)
            .publish(
                &artifact(),
                &[staged],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await;

        assert!(refused.is_err());
        assert!(
            host.sent_to(&format!("{MIRROR}/tuna")).is_empty(),
            "a version was published with a guessed tag"
        );
    }

    /// npm publishes one payload per version, so staging two is a caller
    /// mistake worth naming rather than a guess about which to send.
    #[tokio::test]
    async fn publish_more_than_one_file_refused() {
        let host = Arc::new(TestHost::new(FixtureClient::new()));

        let one = host
            .cache()
            .resolve(&host.cache().path("a.tgz").expect("path"));
        let two = host
            .cache()
            .resolve(&host.cache().path("b.tgz").expect("path"));

        for path in [&one, &two] {
            std::fs::write(path, b"x").expect("staged");
        }

        let ctx = ctx();
        let err = NpmTarget::new(MIRROR, host.clone())
            .publish(
                &artifact(),
                &[one, two],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect_err("refused");

        assert!(err.to_string().contains("one tarball"), "{err}");
    }

    /// A target reaches only the host it was built with, exactly as
    /// a source does -- it has no client of its own to try with.
    #[tokio::test]
    async fn publish_only_where_configured() {
        let host = Arc::new(TestHost::allowing(
            FixtureClient::new(),
            "h://elsewhere.test/",
        ));

        let staged = host.cache().path("tuna-1.2.0.tgz").expect("path");
        std::fs::write(host.cache().resolve(&staged), b"x").expect("staged");
        let staged = host.cache().resolve(&staged);

        let ctx = ctx();
        let err = NpmTarget::new(MIRROR, host.clone())
            .publish(
                &artifact(),
                &[staged],
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect_err("refused");

        assert!(err.to_string().contains("mirror.test"), "{err}");
    }
}
