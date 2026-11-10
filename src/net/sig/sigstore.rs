//! Sigstore bundles: the trust root, and checking a bundle against it.
//!
//! The one place that names the `sigstore-verify` crate, so an ecosystem
//! that carries Sigstore signatures -- PyPI's PEP 740 attestations today --
//! hands over a bundle and a digest and gets back who signed.
//!
//! ```text
//!   trust root:  setup.sigstore-trusted-root, when set   (a file)
//!                otherwise Sigstore's TUF repository      (fetched once per
//!                                                          run, cached)
//!   bundle + sha256  ->  certificate chain, transparency log, signature,
//!                        subject digest  ->  the signer's identity
//! ```
//!
//! The root is loaded on first use rather than at start, so a run that
//! meets no attestation makes no request for one. The TUF fetch goes
//! through the crate's own HTTP client, not a configured host: TUF has its
//! own chain of trust, and its repository is Sigstore's rather than one
//! this configuration names.
//!
//! References: [Sigstore](https://docs.sigstore.dev/), [TUF](https://theupdateframework.github.io/specification/latest/).

use std::path::PathBuf;
use std::sync::Arc;

use sigstore_verify::trust_root::{TrustedRoot, TufConfig};
use sigstore_verify::types::{Artifact, ArtifactDigest, Bundle, Sha256Hash};
use sigstore_verify::{SubjectAltName, VerificationPolicy, Verifier};
use tokio::sync::OnceCell;

/// Where the trust root comes from.
#[derive(Debug, Clone)]
pub enum RootSource {
    /// Sigstore's public TUF repository, cached in this directory, or in
    /// the crate's default location when `None`.
    Tuf(Option<PathBuf>),

    /// A `trusted_root.json` the configuration names.
    File(PathBuf),

    /// The production root the crate embeds, so a test needs no network.
    #[cfg(test)]
    Embedded,
}

/// The Sigstore trust root for a run, loaded once.
///
/// Shared by every source that needs it, so a run fetches it at most once
/// however many attestations it checks. A failure to load is kept too: a
/// root that cannot be had is not retried per file.
pub struct SigstoreRoot {
    source: RootSource,
    verifier: OnceCell<Result<Arc<Verifier>, String>>,
}

/// Who signed a bundle that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// The certificate's subject alternative name: a workflow URI or an
    /// email address.
    pub identity: String,

    /// The OIDC issuer that vouched for it.
    pub issuer: String,
}

impl SigstoreRoot {
    pub fn new(source: RootSource) -> Self {
        Self {
            source,
            verifier: OnceCell::new(),
        }
    }

    /// Cache a TUF-fetched root in `dir`, unless a file was configured.
    pub fn cache_in(&mut self, dir: PathBuf) {
        if let RootSource::Tuf(_) = self.source {
            self.source = RootSource::Tuf(Some(dir));
        }
    }

    /// Where the root comes from, for a message about it.
    pub fn describe(&self) -> String {
        match &self.source {
            RootSource::Tuf(_) => "Sigstore's TUF repository".to_owned(),
            RootSource::File(path) => path.display().to_string(),
            #[cfg(test)]
            RootSource::Embedded => "the embedded root".to_owned(),
        }
    }

    /// The verifier built from the root, loading the root on first use.
    pub async fn verifier(&self) -> Result<Arc<Verifier>, String> {
        self.verifier
            .get_or_init(|| async { load(&self.source).await.map(Arc::new) })
            .await
            .clone()
    }

    /// Verify a Sigstore bundle, given as JSON, over a file whose sha256 is
    /// `sha256_hex`, accepting any signer; the caller judges the identity.
    ///
    /// `Err` is a bundle that does not verify, or a root that could not be
    /// loaded; [`Failure`] says which, since the two mean different things.
    pub async fn verify(&self, bundle_json: &str, sha256_hex: &str) -> Result<Signer, Failure> {
        let verifier = self.verifier().await.map_err(Failure::Root)?;

        let bundle =
            Bundle::from_json(bundle_json).map_err(|err| Failure::Invalid(err.to_string()))?;
        let digest = Sha256Hash::from_hex(sha256_hex)
            .map_err(|err| Failure::Invalid(format!("the sha256 {sha256_hex:?}: {err}")))?;

        let result = verifier
            .verify(
                Artifact::Digest(ArtifactDigest::sha256(digest)),
                &bundle,
                &VerificationPolicy::any_identity(),
            )
            .map_err(|err| Failure::Invalid(err.to_string()))?;

        let Some(identity) = result.identity().map(SubjectAltName::as_str) else {
            return Err(Failure::Invalid(
                "the certificate names no identity".to_owned(),
            ));
        };

        let Some(issuer) = result.issuer() else {
            return Err(Failure::Invalid(
                "the certificate names no issuer".to_owned(),
            ));
        };

        Ok(Signer {
            identity: identity.to_owned(),
            issuer: issuer.to_owned(),
        })
    }
}

/// Why a bundle was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The trust root could not be loaded, so nothing could be checked.
    Root(String),

    /// The bundle does not verify: the chain, the log, the signature, or
    /// the digest.
    Invalid(String),
}

async fn load(source: &RootSource) -> Result<Verifier, String> {
    let root = match source {
        RootSource::File(path) => {
            TrustedRoot::from_file(path).map_err(|err| format!("{}: {err}", path.display()))?
        }

        #[cfg(test)]
        RootSource::Embedded => {
            TrustedRoot::from_json(sigstore_verify::trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT)
                .map_err(|err| err.to_string())?
        }

        RootSource::Tuf(cache) => {
            let config = match cache {
                Some(dir) => TufConfig::production().with_cache_dir(dir.clone()),
                None => TufConfig::production(),
            };

            TrustedRoot::from_tuf(config)
                .await
                .map_err(|err| format!("Sigstore's TUF repository: {err}"))?
        }
    };

    Verifier::new(&root).map_err(|err| err.to_string())
}

/// A root for tests: the production root the crate embeds.
#[cfg(test)]
pub fn embedded() -> SigstoreRoot {
    SigstoreRoot::new(RootSource::Embedded)
}
