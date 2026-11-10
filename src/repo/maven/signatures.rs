//! The `.asc` signatures beside a Maven file: finding them, and checking
//! them once staged.

use std::path::{Path, PathBuf};

use super::sidecar::{self, SIGNATURE, SIGNATURE_LIMIT, Signed};
use super::{FetchedPom, MavenSource};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::ExtHost;
use crate::model::{FileRef, ResolvedArtifact, SigScheme};
use crate::net::Req;

impl MavenSource {
    /// What a signature is checked with.
    pub(super) fn keyring(&self) -> sidecar::Keyring<'_> {
        sidecar::Keyring {
            keys: &self.keys,
            lookup: self.lookup(),
            policy: &self.signing,
        }
    }

    /// Where a key nothing pinned answers to is looked up: the keyserver
    /// capability, or the source's own host when there is none -- which is
    /// never asked then, since the key store has no keyserver to ask.
    fn lookup(&self) -> &dyn ExtHost {
        self.keyservers.as_deref().unwrap_or(&*self.host)
    }
    /// The `.asc` beside each file, where one is published, with the index
    /// of the file it signs.
    ///
    /// Copied so a target serves what the source did: a consumer that
    /// verifies signatures would otherwise find none on the mirror.
    ///
    /// The POM's is already known, since resolution fetched and checked it.
    /// The payload's costs one `HEAD` per artifact, because the payload is
    /// not downloaded here and nothing else says whether it was signed. Its
    /// checksum sidecars are still left alone; see [`sidecar`].
    pub(super) async fn signature_files(
        &self,
        files: &[FileRef],
        pom: &FetchedPom,
        ctx: &Ctx,
    ) -> Vec<(usize, FileRef)> {
        let mut found = Vec::new();

        for (at, file) in files.iter().enumerate() {
            let name = format!("{}.{SIGNATURE}", file.name);

            // The POM is always first; see `files_of`.
            let url = match at {
                0 => pom
                    .sidecars
                    .signature
                    .as_ref()
                    .and_then(|sig| sig.url.clone()),

                _ => {
                    let url = format!("{}.{SIGNATURE}", file.url);

                    // Presence only, so a mirror may answer.
                    match self.host.exists(&Req::head(&url), ctx).await {
                        Ok(true) => Some(url),
                        _ => None,
                    }
                }
            };

            let Some(url) = url else {
                continue;
            };

            found.push((at, FileRef::new(&name, url)));
        }

        found
    }

    /// Each copied `.asc` against the file it signs, now that both are
    /// staged.
    ///
    /// Paired by name rather than by position, because an artifact
    /// enumeration's listing may put a signature anywhere. A file already
    /// carrying a detached signature -- the POM, checked against its bytes
    /// during inspection -- is not checked twice.
    pub(super) async fn verify_signatures(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        ctx: &Ctx,
    ) -> Result<()> {
        let suffix = format!(".{SIGNATURE}");

        for (signature, staged) in artifact.files.iter().zip(files) {
            let Some(name) = signature.name.strip_suffix(&suffix) else {
                continue;
            };

            let Some(at) = artifact.files.iter().position(|file| file.name == name) else {
                continue;
            };

            let signed = &artifact.files[at];

            if signed
                .signatures
                .iter()
                .any(|known| known.scheme == SigScheme::PgpDetached)
            {
                continue;
            }

            let Some(payload) = files.get(at) else {
                continue;
            };

            let Some(armored) = sidecar::armored(&signature.url, &read_signature(staged)?, ctx)
            else {
                continue;
            };

            sidecar::judge(
                &signed.url,
                &signature.url,
                &armored,
                Signed::File(payload),
                &self.keyring(),
                &sidecar::Subject {
                    id: &artifact.id,
                    version: artifact.version.as_ref(),
                },
                ctx,
            )
            .await?;
        }

        Ok(())
    }
}

/// A staged `.asc`, no more than a signature may weigh. A longer one is
/// cut short and then fails to parse, which reports it as unreadable.
fn read_signature(staged: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let mut bytes = Vec::new();

    std::fs::File::open(staged)
        .and_then(|file| file.take(SIGNATURE_LIMIT.get()).read_to_end(&mut bytes))
        .map_err(|source| Error::ReadFile {
            path: staged.to_path_buf(),
            source,
        })?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;

    use crate::ext::testing::{TestHost, idle};
    use crate::model::SigRef;
    use crate::net::FixtureClient;

    use crate::repo::maven::testing::*;

    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::core::error::Result;
    use crate::core::problem::Code;

    use crate::model::{FileRef, ResolvedArtifact, SigScheme, Version};
    use crate::net::sig::KeyStore;
    use crate::policy::SigningPolicy;
    use crate::repo::Source;
    use crate::repo::maven::MavenSource;

    const JAR: &[u8] = b"the payload";

    fn pinned(secret: &pgp::composed::SignedSecretKey) -> KeyStore {
        KeyStore::new(vec![public_key_of(secret)])
    }

    /// Stage `files` as `(name, bytes)` and verify them as one artifact
    /// whose POM carries `pom_signature`, against `keys`.
    async fn verified(
        keys: KeyStore,
        files: &[(&str, &[u8])],
        pom_signature: Option<SigRef>,
    ) -> (Ctx, Result<()>) {
        verified_by(
            MavenSource::new(REPO, idle()).with_keys(keys),
            files,
            pom_signature,
        )
        .await
    }

    /// The same, through a source built by the caller.
    async fn verified_by(
        source: MavenSource,
        files: &[(&str, &[u8])],
        pom_signature: Option<SigRef>,
    ) -> (Ctx, Result<()>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = ctx();

        let staged: Vec<PathBuf> = files
            .iter()
            .map(|(name, bytes)| {
                let path = dir.path().join(name);
                std::fs::write(&path, bytes).expect("staged");
                path
            })
            .collect();

        let mut described: Vec<FileRef> = files
            .iter()
            .map(|(name, _)| FileRef::new(*name, format!("{DIR}/1.0/{name}")))
            .collect();

        described[0].signatures = pom_signature.into_iter().collect();

        let artifact = ResolvedArtifact {
            id: id(),
            version: Some(Version::new("1.0", crate::model::Release::General)),
            files: described,
            license: None,
            published: None,
        };

        let result = source
            .verify(
                &artifact,
                &staged,
                &crate::repo::Companions::default(),
                &ctx,
            )
            .await;

        (ctx, result)
    }

    /// A payload signed by a pinned key passes without a word.
    #[tokio::test]
    async fn verify_accepts_signed_payload() {
        let secret = signing_key();
        let asc = detached_signature(&secret, JAR);

        let (ctx, result) = verified(
            pinned(&secret),
            &[
                ("lib-1.0.pom", b"<project/>"),
                ("lib-1.0.jar", JAR),
                ("lib-1.0.jar.asc", asc.as_bytes()),
            ],
            None,
        )
        .await;

        result.expect("checked");
        assert!(
            ctx.problems().counts().is_empty(),
            "{:?}",
            ctx.problems().counts()
        );
    }

    /// Verify a payload signed by a key only a keyserver holds, under
    /// `policy`, with the fingerprint the key has handed to `policy` first.
    async fn keyserver_verified(policy: impl FnOnce(&str) -> SigningPolicy) -> Ctx {
        const KEYSERVER: &str = "h://keys.test";

        let secret = signing_key();
        let asc = detached_signature(&secret, JAR);
        let issuer = crate::net::sig::issuers_of(&asc).expect("issuer")[0].clone();
        let lookup = format!("{KEYSERVER}/pks/lookup?op=get&options=mr&search=0x{issuer}");
        let armored = public_key_of(&secret).key;
        let fingerprint = crate::net::sig::fingerprint_of(&armored).expect("fingerprint");

        let repository = Arc::new(TestHost::allowing(
            FixtureClient::new().with_body(&lookup, armored.clone()),
            REPO,
        ));
        let keyservers: Arc<dyn ExtHost> = Arc::new(TestHost::allowing(
            FixtureClient::new().with_body(&lookup, armored),
            KEYSERVER,
        ));

        let source = MavenSource::new(REPO, repository)
            .with_keys(KeyStore::new(Vec::new()).with_servers(vec![KEYSERVER.to_owned()]))
            .with_keyservers(Some(keyservers))
            .with_signing(Arc::new(policy(&fingerprint)));

        let (ctx, result) = verified_by(
            source,
            &[
                ("lib-1.0.pom", b"<project/>"),
                ("lib-1.0.jar", JAR),
                ("lib-1.0.jar.asc", asc.as_bytes()),
            ],
            None,
        )
        .await;

        result.expect("checked");

        ctx
    }

    /// A key found only on a keyserver is fetched through the keyserver
    /// capability -- the source's own host, confined to the repository,
    /// would refuse it -- and vouches where the signing policy names it.
    #[tokio::test]
    async fn verify_asks_keyservers_through_capability() {
        let ctx = keyserver_verified(|fingerprint| SigningPolicy {
            rules: vec![crate::policy::SigningRule {
                comment: None,
                comments: Vec::new(),
                purl: "pkg:maven/org.example/*".to_owned(),
                fingerprints: vec![fingerprint.to_owned()],
                justification: None,
            }],
            ..SigningPolicy::default()
        })
        .await;

        assert!(
            ctx.problems().counts().is_empty(),
            "{:?}",
            ctx.problems().counts()
        );
    }

    /// With no policy naming it, a keyserver key proves only that its
    /// holder signed: `signature-key-unvouched`.
    #[tokio::test]
    async fn verify_unmapped_keyserver_key_is_unvouched() {
        let ctx = keyserver_verified(|_| SigningPolicy::default()).await;

        assert_eq!(ctx.problems().counts()[&Code::SignatureKeyUnvouched], 1);
    }

    /// A pinned key the policy assigns elsewhere does not vouch here.
    #[tokio::test]
    async fn verify_pinned_key_assigned_elsewhere_is_unvouched() {
        let secret = signing_key();
        let asc = detached_signature(&secret, JAR);
        let fingerprint =
            crate::net::sig::fingerprint_of(&public_key_of(&secret).key).expect("fingerprint");

        let source = MavenSource::new(REPO, idle())
            .with_keys(pinned(&secret))
            .with_signing(Arc::new(SigningPolicy {
                rules: vec![crate::policy::SigningRule {
                    comment: None,
                    comments: Vec::new(),
                    purl: "pkg:maven/org.other/*".to_owned(),
                    fingerprints: vec![fingerprint],
                    justification: None,
                }],
                ..SigningPolicy::default()
            }));

        let (ctx, result) = verified_by(
            source,
            &[
                ("lib-1.0.pom", b"<project/>"),
                ("lib-1.0.jar", JAR),
                ("lib-1.0.jar.asc", asc.as_bytes()),
            ],
            None,
        )
        .await;

        result.expect("checked");
        assert_eq!(ctx.problems().counts()[&Code::SignatureKeyUnvouched], 1);
    }

    /// Paired by name: a signature listed before its payload still checks
    /// it, and bytes it does not cover fail.
    #[tokio::test]
    async fn verify_refuses_tampered_payload() {
        let secret = signing_key();
        let asc = detached_signature(&secret, JAR);

        let (ctx, result) = verified(
            pinned(&secret),
            &[
                ("lib-1.0.pom", b"<project/>"),
                ("lib-1.0.jar.asc", asc.as_bytes()),
                ("lib-1.0.jar", b"other bytes"),
            ],
            None,
        )
        .await;

        result.expect("checked");
        assert_eq!(ctx.problems().counts()[&Code::SignatureInvalid], 1);
    }

    #[tokio::test]
    async fn verify_unknown_key_is_missing() {
        let asc = detached_signature(&signing_key(), JAR);

        let (ctx, result) = verified(
            KeyStore::new(Vec::new()),
            &[
                ("lib-1.0.pom", b"<project/>"),
                ("lib-1.0.jar", JAR),
                ("lib-1.0.jar.asc", asc.as_bytes()),
            ],
            None,
        )
        .await;

        result.expect("checked");
        assert_eq!(ctx.problems().counts()[&Code::SignatureMissing], 1);
    }

    /// The POM's signature was checked during inspection, which its
    /// recorded signature says, so its `.asc` is not read again.
    #[tokio::test]
    async fn verify_skips_checked_pom() {
        let discovered = SigRef {
            scheme: SigScheme::PgpDetached,
            key_id: None,
            value: None,
            url: None,
        };

        let (ctx, result) = verified(
            KeyStore::new(Vec::new()),
            &[
                ("lib-1.0.pom", b"<project/>"),
                ("lib-1.0.pom.asc", b"not a signature"),
            ],
            Some(discovered),
        )
        .await;

        result.expect("checked");
        assert!(
            ctx.problems().counts().is_empty(),
            "{:?}",
            ctx.problems().counts()
        );
    }
}
