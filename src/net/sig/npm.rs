//! npm's registry signatures.
//!
//! ECDSA P-256 over `{name}@{version}:{integrity}` -- the signature covers
//! the **integrity hash**, not the bytes. That is what makes it the useful
//! scheme here: a registry's claim about a tarball can be checked from
//! metadata alone, which is exactly what `inspect` has, and checking the
//! tarball against the hash later chains the proof to the bytes.
//!
//! References: [npm registry signatures](https://docs.npmjs.com/about-registry-signatures).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use crate::core::error::{Error, Result};

use super::key::{RegistryKey, SigOutcome, Untrusted};

/// Verify an npm `dist.signatures` entry.
///
/// The signed message is `{name}@{version}:{integrity}`, so a valid
/// signature proves the registry vouches for that integrity hash -- and
/// checking the tarball against the hash then chains to the bytes.
pub fn verify_npm(
    name: &str,
    version: &str,
    integrity: &str,
    keyid: &str,
    signature: &str,
    keys: &[RegistryKey],
) -> Result<SigOutcome> {
    let Some(key) = keys.iter().find(|candidate| candidate.keyid == keyid) else {
        return Ok(SigOutcome::UnknownKey);
    };

    // An npm `dist.signatures` entry carries no creation time, so unlike
    // PGP there is nothing to compare an expiry against but the clock.
    // That is weaker -- a signature made while the key was good now reads
    // as untrusted once it lapses -- and it is the only question the data
    // supports asking.
    if key.expires.is_some_and(|when| chrono::Utc::now() > when) {
        return Ok(SigOutcome::UntrustedKey(Untrusted::Expired));
    }

    let message = format!("{name}@{version}:{integrity}");

    let der = BASE64.decode(key.key.as_bytes()).map_err(|source| {
        Error::Integrity(format!("registry key {keyid} is not base64: {source}"))
    })?;

    let verifying = VerifyingKey::from_public_key_der(&der).map_err(|source| {
        Error::Integrity(format!("registry key {keyid} is not a P-256 key: {source}"))
    })?;

    let raw = BASE64.decode(signature.as_bytes()).map_err(|source| {
        Error::Integrity(format!(
            "signature for {name}@{version} is not base64: {source}"
        ))
    })?;

    // npm emits DER-encoded ECDSA signatures.
    let parsed = Signature::from_der(&raw).map_err(|source| {
        Error::Integrity(format!(
            "signature for {name}@{version} is not a DER ECDSA signature: {source}"
        ))
    })?;

    verifying
        .verify(message.as_bytes(), &parsed)
        .map_err(|_| Error::Integrity(format!("signature for {name}@{version} does not verify")))?;

    Ok(SigOutcome::Valid)
}

/// Convert an SRI string such as `sha512-Base64==` into a hex digest.
///
/// npm states integrity in Subresource Integrity form; every other part of
/// this tool speaks hex, so the conversion belongs here rather than in three
/// call sites.
pub fn sri_to_digest(sri: &str) -> Option<crate::model::Digest> {
    let (algorithm, encoded) = sri.split_once('-')?;
    let alg = crate::model::DigestAlg::parse(algorithm)?;
    let raw = BASE64.decode(encoded.as_bytes()).ok()?;

    Some(crate::model::Digest::new(alg, hex::encode(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::EncodePublicKey;

    /// Sign a message with a throwaway key, exactly as a registry would.
    fn signed(message: &str) -> (String, String) {
        // Fixed bytes so the test is deterministic.
        let signing = SigningKey::from_bytes(&[7u8; 32].into()).expect("key");

        let signature: Signature = signing.sign(message.as_bytes());

        let public = signing
            .verifying_key()
            .to_public_key_der()
            .expect("der")
            .into_vec();

        (
            BASE64.encode(public),
            BASE64.encode(signature.to_der().as_bytes()),
        )
    }

    const NAME: &str = "lodash";
    const VERSION: &str = "4.17.21";
    const INTEGRITY: &str = "sha512-abc==";

    fn message() -> String {
        format!("{NAME}@{VERSION}:{INTEGRITY}")
    }

    #[test]
    fn signature_genuine_verifies() {
        let (key, signature) = signed(&message());

        let keys = vec![RegistryKey::published("SHA256:test", key)];

        let outcome =
            verify_npm(NAME, VERSION, INTEGRITY, "SHA256:test", &signature, &keys).expect("checks");

        assert_eq!(outcome, SigOutcome::Valid);
    }

    /// The signature covers the integrity hash, so swapping the hash must
    /// break it -- that is the whole property being relied on.
    #[test]
    fn signature_tampered_integrity_fails() {
        let (key, signature) = signed(&message());

        let keys = vec![RegistryKey::published("SHA256:test", key)];

        let err = verify_npm(
            NAME,
            VERSION,
            "sha512-TAMPERED==",
            "SHA256:test",
            &signature,
            &keys,
        )
        .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::ChecksumMismatch);
        assert!(err.to_string().contains("does not verify"));
    }

    #[test]
    fn signature_tampered_version_fails() {
        let (key, signature) = signed(&message());

        let keys = vec![RegistryKey::published("SHA256:test", key)];

        assert!(verify_npm(NAME, "9.9.9", INTEGRITY, "SHA256:test", &signature, &keys).is_err());
    }

    /// Key rotation is routine, so an unrecognized key id is reported rather
    /// than treated as a forgery.
    #[test]
    fn signature_from_unpublished_key_reported() {
        let (key, signature) = signed(&message());

        let keys = vec![RegistryKey::published("SHA256:other", key)];

        let outcome = verify_npm(
            NAME,
            VERSION,
            INTEGRITY,
            "SHA256:missing",
            &signature,
            &keys,
        )
        .expect("checks");

        assert_eq!(outcome, SigOutcome::UnknownKey);
    }

    #[test]
    fn signature_malformed_is_error() {
        let (key, _) = signed(&message());

        let keys = vec![RegistryKey::published("SHA256:test", key)];

        assert!(verify_npm(NAME, VERSION, INTEGRITY, "SHA256:test", "!!!", &keys).is_err());
    }

    /// npm states integrity in SRI; the rest of the tool speaks hex.
    #[test]
    fn sri_converts_to_hex() {
        // The FIPS 180-4 sha256 of "abc", re-encoded as npm would state it.
        const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        let raw = hex::decode(ABC_SHA256).expect("hex");
        let sri = format!("sha256-{}", BASE64.encode(&raw));

        let digest = sri_to_digest(&sri).expect("converts");

        assert_eq!(digest.alg, crate::model::DigestAlg::Sha256);
        assert_eq!(digest.hex, ABC_SHA256);
    }

    #[test]
    fn sri_malformed_converts_to_nothing() {
        assert!(sri_to_digest("not-sri").is_none());
        assert!(sri_to_digest("sha512").is_none());
    }
}
