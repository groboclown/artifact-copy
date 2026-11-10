//! Detached PGP signatures.
//!
//! The Maven case, and the reason `signing-keys` exists at all: a `.asc`
//! names an issuer key id and nothing more, so there is nowhere to get the
//! key from except a keyring the user supplies or a keyserver they opted
//! into. An unconfigured key is [`SigOutcome::UnknownKey`], never a silent
//! pass.
//!
//! References: [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580).

use std::io::Read;
use std::path::Path;

use chrono::{DateTime, Utc};
use pgp::composed::{DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::Signature;
use pgp::types::{KeyDetails as _, Tag, Timestamp};

use crate::core::error::{Error, Result};
use crate::core::expiry::Expiry;

use super::key::{RegistryKey, SigOutcome, Untrusted};

/// The key identifiers a detached signature names.
///
/// A v4 signature carries a 16-hex key id; a v6 one carries a full
/// fingerprint. Both are returned, so a caller can match whichever form a
/// configuration or a keyserver understands.
/// The armor header of a detached signature.
const SIGNATURE_ARMOR: &str = "-----BEGIN PGP SIGNATURE-----";

/// The armor header of an OpenPGP message.
const MESSAGE_ARMOR: &str = "-----BEGIN PGP MESSAGE-----";

/// The most a compressed signature may expand to. One signature packet is
/// well under a kilobyte; the cap stops a crafted one inflating without end.
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;

/// How deep compressed packets may nest inside one another.
const MAX_COMPRESSION_DEPTH: usize = 2;

/// A detached signature, armored as `PGP SIGNATURE`.
///
/// Returned as given when it already is one. BouncyCastle-based signers,
/// such as Testcontainers' on Central, instead write the signature inside a
/// compressed-data packet armored as `PGP MESSAGE`, which GnuPG verifies
/// all the same:
///
/// ```text
///   -----BEGIN PGP MESSAGE-----        compressed data
///   owDCXgQAFgIABgW...                   signature        <- the detached signature
/// ```
///
/// Exactly one signature, and nothing else, is taken out of the message: a
/// message carrying literal data is a signed document, not a detached
/// signature, and is refused.
pub fn detached_armor(armored: &str) -> Result<String> {
    let armored = armored.trim();

    if armored.starts_with(SIGNATURE_ARMOR) {
        return Ok(armored.to_owned());
    }

    if !armored.starts_with(MESSAGE_ARMOR) {
        return Err(unreadable("it is not armored as a signature or a message"));
    }

    let mut bytes = Vec::new();

    pgp::armor::Dearmor::new(armored.as_bytes())
        .read_to_end(&mut bytes)
        .map_err(|err| unreadable(&format!("its armor cannot be read: {err}")))?;

    let mut signatures = Vec::new();
    signatures_in(&bytes, 0, &mut signatures)?;

    let [signature] = <[Signature; 1]>::try_from(signatures).map_err(|found| {
        unreadable(&format!(
            "it holds {} signatures where one was expected",
            found.len()
        ))
    })?;

    DetachedSignature::new(signature)
        .to_armored_string(Default::default())
        .map_err(|err| unreadable(&format!("it cannot be armored again: {err}")))
}

/// Collect the signature packets in `bytes`, opening compressed ones.
fn signatures_in(bytes: &[u8], depth: usize, out: &mut Vec<Signature>) -> Result<()> {
    use pgp::packet::{Packet, PacketParser, PacketTrait as _};

    for packet in PacketParser::new(bytes) {
        let packet =
            packet.map_err(|err| unreadable(&format!("a packet cannot be read: {err}")))?;

        match packet {
            Packet::Signature(signature) => out.push(signature),

            Packet::CompressedData(compressed) if depth < MAX_COMPRESSION_DEPTH => {
                let mut inner = Vec::new();

                compressed
                    .decompress()
                    .map_err(|err| unreadable(&format!("it cannot be decompressed: {err}")))?
                    .take(MAX_SIGNATURE_BYTES)
                    .read_to_end(&mut inner)
                    .map_err(|err| unreadable(&format!("it cannot be decompressed: {err}")))?;

                signatures_in(&inner, depth + 1, out)?;
            }

            other => {
                return Err(unreadable(&format!(
                    "it carries a {:?} packet, so it is not a detached signature",
                    other.tag()
                )));
            }
        }
    }

    Ok(())
}

fn unreadable(why: &str) -> Error {
    Error::Integrity(format!("the detached signature is unreadable: {why}"))
}

pub fn issuers_of(armored: &str) -> Result<Vec<String>> {
    use pgp::composed::{Deserializable, DetachedSignature};

    let (signature, _) = DetachedSignature::from_string(armored)
        .map_err(|err| Error::Integrity(format!("the detached signature is unreadable: {err}")))?;

    Ok(signature
        .signature
        .issuer_fingerprint()
        .iter()
        .map(|fingerprint| hex::encode(fingerprint.as_bytes()))
        .chain(
            signature
                .signature
                .issuer_key_id()
                .iter()
                .map(|id| hex::encode(id.as_ref())),
        )
        .collect())
}

/// The primary key's fingerprint, as lowercase hex, of an armored public
/// key; `None` when it is not one.
///
/// The primary key rather than whichever subkey signed, because that is
/// what a signing policy and a project's KEYS file name.
pub fn fingerprint_of(armored_key: &str) -> Option<String> {
    use pgp::composed::Deserializable;

    let (public, _) = SignedPublicKey::from_string(armored_key).ok()?;

    Some(hex::encode(public.primary_key.fingerprint().as_bytes()))
}

/// Verify a detached PGP signature against the configured key store.
///
/// This is the whole reason `signing-keys` exists. Maven signatures are
/// checked against a keyring the user supplies, because there is nowhere
/// else to get one: a `.asc` names an issuer key id and nothing more, and
/// fetching that key from a keyserver at verification time would mean
/// trusting whatever the network returned -- which is not verification, it
/// is a lookup wearing verification's clothes. So an unconfigured key is
/// [`SigOutcome::UnknownKey`], never a silent pass.
///
/// `keys` are the entries [`super::pinned::resolve_pinned`] produced for
/// [`crate::config::SigningScheme::Pgp`].
pub fn verify_pgp(payload: &[u8], armored: &str, keys: &[RegistryKey]) -> Result<SigOutcome> {
    verify_read(|| Ok(payload), armored, keys)
}

/// [`verify_pgp`], reading the payload from a file.
///
/// Streamed rather than read whole, because a payload is a jar or a
/// distribution archive and may run to gigabytes. The file is opened once
/// per key tried, which is once in the ordinary case.
pub fn verify_pgp_file(payload: &Path, armored: &str, keys: &[RegistryKey]) -> Result<SigOutcome> {
    let open = || {
        std::fs::File::open(payload)
            .map(std::io::BufReader::new)
            .map_err(|source| Error::ReadFile {
                path: payload.to_path_buf(),
                source,
            })
    };

    verify_read(open, armored, keys)
}

/// The verifier behind both forms. `open` hands a fresh reader over the
/// payload for each attempt, since a signature is checked against it once
/// per candidate key.
fn verify_read<R: Read>(
    open: impl Fn() -> Result<R>,
    armored: &str,
    keys: &[RegistryKey],
) -> Result<SigOutcome> {
    use pgp::composed::Deserializable;

    let (signature, _) = DetachedSignature::from_string(armored)
        .map_err(|err| Error::Integrity(format!("the detached signature is unreadable: {err}")))?;

    // A signature names its issuer, and that is what selects the key. A
    // v4 signature carries a 16-hex key id; a v6 one carries a full
    // fingerprint. Both are accepted, and matched by suffix -- see
    // `key_id_matches`.
    let issuers: Vec<String> = signature
        .signature
        .issuer_fingerprint()
        .iter()
        .map(|fingerprint| hex::encode(fingerprint.as_bytes()))
        .chain(
            signature
                .signature
                .issuer_key_id()
                .iter()
                .map(|id| hex::encode(id.as_ref())),
        )
        .collect();

    // When the signature was made, which is what an expiry is judged
    // against. A signature made while a key was still trusted stays
    // trusted; only one made afterwards is refused.
    let signed_at = signature.signature.created().map(utc);

    let mut saw_candidate = false;
    let mut untrusted: Option<Untrusted> = None;

    for entry in keys {
        // An unusable key in the store must not veto a usable one later in
        // it, so a parse failure is skipped rather than returned.
        let Ok((public, _)) = SignedPublicKey::from_string(&entry.key) else {
            continue;
        };

        if !issuers.is_empty()
            && !issuers
                .iter()
                .any(|issuer| key_id_matches(&entry.keyid, issuer))
        {
            continue;
        }

        saw_candidate = true;

        // Checked **before** verifying, not after. A revoked key that
        // produces an arithmetically valid signature is exactly the case
        // this exists for, and asking afterwards would mean deciding
        // whether to discard an answer already obtained.
        if let Some(reason) = untrustworthy(&public, entry, signed_at) {
            // Revocation outranks expiry: an expiry is a plan made in
            // advance, a revocation is a statement made after something
            // happened.
            if reason == Untrusted::Revoked || untrusted.is_none() {
                untrusted = Some(reason);
            }

            continue;
        }

        let Some(material) = verifying_expiry(&signature, &public, &open)? else {
            continue;
        };

        // The key's own expiry, judged like the configured one against when
        // the signature was made. Checked after verifying because it
        // depends on which component signed: a subkey may lapse before its
        // primary.
        if predates(material, signed_at) {
            return Ok(SigOutcome::Valid);
        }

        untrusted.get_or_insert(Untrusted::Expired);
    }

    // A key claimed it and may not vouch for it. Reported ahead of the
    // failure below because "the key is revoked" explains the situation and
    // "it does not verify" would merely describe a symptom.
    if let Some(reason) = untrusted {
        return Ok(SigOutcome::UntrustedKey(reason));
    }

    // Nothing in the store claims this signature. Not a forgery on its own
    // -- a key the user has not configured is simply a key they cannot
    // check -- but it proves nothing either, so it must not read as valid.
    if !saw_candidate {
        return Ok(SigOutcome::UnknownKey);
    }

    Err(Error::Integrity(
        "the signature does not verify against the configured key".to_owned(),
    ))
}

/// Whether a configured key id names the key a signature was issued by.
///
/// PGP identifies a key at several lengths -- an 8-hex short id, a 16-hex
/// long id, a 40-hex v4 fingerprint, a 64-hex v6 one -- and a configuration
/// may reasonably hold any of them, as may a signature. Matching by suffix
/// lets a user paste whichever form their key provider showed them.
///
/// A short id is **not** accepted, because 32 bits is forgeable and has
/// been forged in the wild: matching on one would let an attacker mint a
/// key that answers to a configured name.
pub(super) fn key_id_matches(configured: &str, issuer: &str) -> bool {
    let normalize = |text: &str| {
        text.trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase()
    };

    let configured = normalize(configured);
    let issuer = normalize(issuer);

    /// Sixteen hex characters: a 64-bit long key id. Anything shorter is
    /// cheap enough to collide deliberately.
    const MINIMUM: usize = 16;

    if configured.len() < MINIMUM || issuer.len() < MINIMUM {
        return false;
    }

    configured.ends_with(&issuer) || issuer.ends_with(&configured)
}

/// Whether a key may not vouch for a signature made at `signed_at`.
///
/// Two independent statements, and the key's own outranks the
/// configuration's because it is the holder speaking:
///
/// - **Revocation** is carried in the key material. Any revocation
///   signature disqualifies it. The reason code is deliberately not
///   consulted: `key-retired` and `key-compromised` differ in whether past
///   signatures should still count, and answering that needs each
///   signature's time compared against the revocation's -- worth doing, and
///   worth doing deliberately rather than as a guess buried here. Refusing
///   all of them is the conservative reading.
/// - **Configured expiry** is the user's own line, and is compared against
///   when the signature was *made*. A signature with no creation time
///   cannot be shown to predate the expiry, so it is refused -- the same
///   asymmetry the publish window uses, and for the same reason.
///
/// The key material's own expiry is checked in [`verifying_expiry`] once
/// a component verifies, because it depends on which component signed.
fn untrustworthy(
    public: &pgp::composed::SignedPublicKey,
    entry: &RegistryKey,
    signed_at: Option<DateTime<Utc>>,
) -> Option<Untrusted> {
    if !public.details.revocation_signatures.is_empty() {
        return Some(Untrusted::Revoked);
    }

    let expires = entry.expires?;

    match signed_at {
        Some(when) if when <= expires => None,
        _ => Some(Untrusted::Expired),
    }
}

/// Seconds of key lifetime that mean *no expiry*, per the RFC 9580 Key
/// Expiration Time subpacket.
const UNBOUNDED_LIFETIME_SECONDS: u32 = 0;

/// The key material's own expiry for whichever component of `public`
/// verifies `signature`, or `None` when none does. A payload that cannot be
/// opened is an error rather than a signature that failed to verify.
///
/// The primary key certifies; a subkey usually does the signing, so trying
/// only the primary would reject most real signatures. A subkey lapses at
/// the earlier of its own expiry and its primary's.
fn verifying_expiry<R: Read>(
    signature: &DetachedSignature,
    public: &SignedPublicKey,
    open: &impl Fn() -> Result<R>,
) -> Result<Option<Expiry>> {
    let primary = primary_expiry(public);

    if signature.signature.verify(public, open()?).is_ok() {
        return Ok(Some(primary));
    }

    for subkey in &public.public_subkeys {
        if signature.signature.verify(subkey, open()?).is_ok() {
            return Ok(Some(earlier(primary, subkey_expiry(public, subkey))));
        }
    }

    Ok(None)
}

/// The primary key's expiry, from its direct-key and user ID
/// self-signatures.
fn primary_expiry(public: &SignedPublicKey) -> Expiry {
    let primary = &public.primary_key;

    let direct = public
        .details
        .direct_signatures
        .iter()
        .filter(|sig| sig.verify_key(primary).is_ok());

    let certifications = public.details.users.iter().flat_map(|user| {
        user.signatures.iter().filter(move |sig| {
            sig.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        })
    });

    lifetime(primary.created_at(), direct.chain(certifications))
}

/// A subkey's expiry, from its binding signatures.
fn subkey_expiry(public: &SignedPublicKey, subkey: &SignedPublicSubKey) -> Expiry {
    let bindings = subkey.signatures.iter().filter(|sig| {
        sig.verify_subkey_binding(&public.primary_key, &subkey.key)
            .is_ok()
    });

    lifetime(subkey.key.created_at(), bindings)
}

/// When a key created at `created` lapses, per the newest of `signatures`.
///
/// Callers pass only self-signatures that verify: anything else in a
/// certificate could state a lifetime the holder never did. Signatures made
/// in the same second, such as a user ID certification and a direct-key
/// signature, yield the earlier expiry, the conservative reading.
fn lifetime<'s>(created: Timestamp, signatures: impl Iterator<Item = &'s Signature>) -> Expiry {
    let signatures: Vec<&Signature> = signatures.collect();

    let Some(newest) = signatures.iter().map(|sig| sig.created()).max() else {
        return Expiry::Never;
    };

    signatures
        .iter()
        .filter(|sig| sig.created() == newest)
        .map(|sig| stated(created, sig))
        .fold(Expiry::Never, earlier)
}

/// The expiry one self-signature states for a key created at `created`.
fn stated(created: Timestamp, signature: &Signature) -> Expiry {
    let Some(lifetime) = signature.key_expiration_time() else {
        return Expiry::Never;
    };

    if lifetime.as_secs() == UNBOUNDED_LIFETIME_SECONDS {
        return Expiry::Never;
    }

    Expiry::At(utc(created) + chrono::Duration::seconds(lifetime.as_secs().into()))
}

/// The earlier of two expiries; `never` loses to any date.
fn earlier(left: Expiry, right: Expiry) -> Expiry {
    match (left.at(), right.at()) {
        (Some(l), Some(r)) => Expiry::At(l.min(r)),
        (Some(_), None) => left,
        _ => right,
    }
}

/// Whether a signature made at `signed_at` falls within `expiry`.
///
/// One with no creation time cannot be shown to predate a date, so only
/// `never` admits it -- the asymmetry `untrustworthy` applies.
fn predates(expiry: Expiry, signed_at: Option<DateTime<Utc>>) -> bool {
    match signed_at {
        Some(when) => expiry.in_force(when),
        None => expiry == Expiry::Never,
    }
}

fn utc(when: Timestamp) -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::SystemTime::from(when))
}

#[cfg(test)]
mod pgp_tests {
    use super::*;
    use pgp::composed::{DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedSecretKey};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::types::Password;

    const PAYLOAD: &[u8] = b"<project><artifactId>lib</artifactId></project>";

    /// A real key, generated in the test.
    ///
    /// Ed25519 rather than RSA so generation costs microseconds, and
    /// generated rather than embedded so the test exercises the whole path
    /// -- parse a key, parse a signature, verify -- instead of asserting
    /// against a blob nobody can check by eye.
    fn keypair() -> SignedSecretKey {
        let mut rng = rand::thread_rng();

        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Test Signer <signer@example.test>".into())
            .passphrase(None)
            .build()
            .expect("params");

        params.generate(&mut rng).expect("generated")
    }

    fn armored_public(secret: &SignedSecretKey) -> String {
        pgp::composed::SignedPublicKey::from(secret.clone())
            .to_armored_string(Default::default())
            .expect("armored")
    }

    fn sign(secret: &SignedSecretKey, payload: &[u8]) -> String {
        DetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            payload,
        )
        .expect("signed")
        .to_armored_string(Default::default())
        .expect("armored")
    }

    fn fingerprint(secret: &SignedSecretKey) -> String {
        hex::encode(secret.primary_key.fingerprint().as_bytes())
    }

    fn store(secret: &SignedSecretKey) -> Vec<RegistryKey> {
        vec![RegistryKey::pinned(
            fingerprint(secret),
            armored_public(secret),
        )]
    }

    /// What Testcontainers' BOM 2.0.5 carries on Central: a BouncyCastle
    /// signature inside a compressed-data packet, armored as a message.
    const MESSAGE_WRAPPED: &str = "-----BEGIN PGP MESSAGE-----
Version: BCPG v1.81

owDCXgQAFgIABgWCaeZn4QAKCRDn2I24Qn3mUVSiAQDlJEotbHMzno6Lath1AYoB
zPzA67s6iapW+EuvFkVSMwEA1vqZ9lAT2U7nakU8tSjtrsbS2Mi/vh3GSOlg3R+L
dQg=
=B/2J
-----END PGP MESSAGE-----
";

    /// `signature`'s signature packet alone, armored as a message.
    fn as_message(signature: &str) -> String {
        use pgp::composed::Deserializable as _;

        let (detached, _) = DetachedSignature::from_string(signature).expect("parses");
        let mut out = Vec::new();

        pgp::armor::write(
            &detached,
            pgp::armor::BlockType::Message,
            &mut out,
            None,
            true,
        )
        .expect("armored");

        String::from_utf8(out).expect("ascii")
    }

    #[test]
    fn detached_armor_keeps_signature() {
        let signature = sign(&keypair(), PAYLOAD);

        assert_eq!(detached_armor(&signature).expect("read"), signature.trim());
    }

    /// The compressed BouncyCastle form becomes a plain detached signature
    /// naming the same issuer.
    #[test]
    fn detached_armor_opens_compressed_message() {
        let armored = detached_armor(MESSAGE_WRAPPED).expect("read");

        assert!(armored.starts_with(SIGNATURE_ARMOR), "{armored}");
        assert!(!issuers_of(&armored).expect("issuers").is_empty());
    }

    /// A signature taken out of a message verifies as it would have plain.
    #[test]
    fn verify_message_wrapped_signature() {
        let secret = keypair();
        let wrapped = as_message(&sign(&secret, PAYLOAD));
        let signature = detached_armor(&wrapped).expect("read");

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &store(&secret)).expect("checked"),
            SigOutcome::Valid
        );
    }

    /// A message carrying data is a signed document, not a detached
    /// signature.
    #[test]
    fn detached_armor_refuses_message_with_data() {
        let message = pgp::composed::MessageBuilder::from_bytes("", PAYLOAD)
            .to_armored_string(rand::thread_rng(), Default::default())
            .expect("armored");

        let err = detached_armor(&message).expect_err("refused").to_string();

        assert!(err.contains("not a detached signature"), "{err}");
        assert!(detached_armor("plain text").is_err());
    }

    #[test]
    fn verify_good_signature_against_configured_key() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &store(&secret)).expect("checked"),
            SigOutcome::Valid
        );
    }

    /// A payload on disk verifies as the same bytes in memory would, and a
    /// changed file does not.
    #[test]
    fn verify_file_payload() {
        use std::io::Write as _;

        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let mut file = tempfile::NamedTempFile::new().expect("temp");
        file.write_all(PAYLOAD).expect("written");

        assert_eq!(
            verify_pgp_file(file.path(), &signature, &store(&secret)).expect("checked"),
            SigOutcome::Valid
        );

        file.write_all(b" and more").expect("appended");

        assert!(verify_pgp_file(file.path(), &signature, &store(&secret)).is_err());
    }

    /// A payload that cannot be read is an error of its own, not a
    /// signature that failed.
    #[test]
    fn verify_missing_file_payload_read_error() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);
        let dir = tempfile::tempdir().expect("tempdir");

        let err = verify_pgp_file(&dir.path().join("absent"), &signature, &store(&secret))
            .expect_err("unreadable");

        assert!(matches!(err, Error::ReadFile { .. }), "{err:?}");
    }

    /// The thing verification is for: the bytes changed, so the signature
    /// no longer covers them.
    #[test]
    fn verify_different_bytes_fails() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let err =
            verify_pgp(b"tampered", &signature, &store(&secret)).expect_err("must not verify");

        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    /// A key the user has not configured cannot be checked. That is not a
    /// forgery, but it proves nothing either -- so it must not read as
    /// valid, and it must not be fetched from anywhere to make it check.
    #[test]
    fn verify_unconfigured_key_unknown_not_valid() {
        let signer = keypair();
        let stranger = keypair();

        let signature = sign(&signer, PAYLOAD);

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &store(&stranger)).expect("checked"),
            SigOutcome::UnknownKey
        );
    }

    #[test]
    fn store_empty_yields_unknown() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &[]).expect("checked"),
            SigOutcome::UnknownKey
        );
    }

    /// The store is searched, not merely indexed: the right key being
    /// somewhere in it is enough.
    #[test]
    fn store_finds_right_key_among_others() {
        let signer = keypair();
        let signature = sign(&signer, PAYLOAD);

        let mut keys = store(&keypair());
        keys.extend(store(&signer));
        keys.extend(store(&keypair()));

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &keys).expect("checked"),
            SigOutcome::Valid
        );
    }

    /// An unparseable entry must not veto a usable one later in the store,
    /// or one bad paste disables a whole keyring.
    #[test]
    fn store_survives_malformed_entry() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let mut keys = vec![RegistryKey::pinned(fingerprint(&secret), "not a key")];
        keys.extend(store(&secret));

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &keys).expect("checked"),
            SigOutcome::Valid
        );
    }

    #[test]
    fn verify_unreadable_signature_error() {
        let secret = keypair();

        let err = verify_pgp(
            PAYLOAD,
            "-----BEGIN PGP SIGNATURE-----\nrubbish\n",
            &store(&secret),
        )
        .expect_err("must not be accepted");

        assert!(err.to_string().contains("unreadable"), "{err}");
    }

    // -- Key identifiers --------------------------------------------------

    /// A configuration may hold a fingerprint while a v4 signature names a
    /// 16-hex long id. Both spellings identify the same key, and a user
    /// should be able to paste whichever their provider showed them.
    #[test]
    fn key_id_fingerprint_matches_long_id_suffix() {
        let fingerprint = "d4c4ee4a8a8b7d7c6d6e5f5a4b4c3d3e2f2a1b1c";
        let long_id = "2f2a1b1c00000000";

        assert!(key_id_matches(fingerprint, &fingerprint[24..]));
        assert!(key_id_matches(&fingerprint[24..], fingerprint));

        assert!(!key_id_matches(fingerprint, long_id));
    }

    #[test]
    fn key_id_formatting_ignored() {
        let fingerprint = "d4c4ee4a8a8b7d7c6d6e5f5a4b4c3d3e2f2a1b1c";

        assert!(key_id_matches(
            "0xD4C4EE4A8A8B7D7C6D6E5F5A4B4C3D3E2F2A1B1C",
            fingerprint
        ));
        assert!(key_id_matches(
            "D4C4 EE4A 8A8B 7D7C  6D6E 5F5A 4B4C 3D3E 2F2A 1B1C",
            fingerprint
        ));
    }

    /// Short key ids are 32 bits and have been forged in the wild. Matching
    /// on one would let an attacker mint a key answering to a configured
    /// name, so they are refused outright.
    #[test]
    fn key_id_short_never_matches() {
        let fingerprint = "d4c4ee4a8a8b7d7c6d6e5f5a4b4c3d3e2f2a1b1c";

        assert!(!key_id_matches("2f2a1b1c", fingerprint));
        assert!(!key_id_matches(fingerprint, "2f2a1b1c"));
        assert!(!key_id_matches("", fingerprint));
    }

    // -- Keys that may not vouch ------------------------------------------

    /// The same public key, carrying a real revocation signature made by
    /// its own holder.
    fn revoked_public(secret: &SignedSecretKey) -> String {
        use pgp::packet::RevocationCode;
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::types::KeyDetails as _;

        let mut config = SignatureConfig::from_key(
            rand::thread_rng(),
            &secret.primary_key,
            SignatureType::KeyRevocation,
        )
        .expect("config");

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                pgp::types::Timestamp::now(),
            ))
            .expect("creation time"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret.primary_key.fingerprint(),
            ))
            .expect("issuer"),
            Subpacket::regular(SubpacketData::RevocationReason(
                RevocationCode::KeyCompromised,
                "test".into(),
            ))
            .expect("reason"),
        ];

        let revocation = config
            .sign_key(
                &secret.primary_key,
                &Password::empty(),
                &secret.primary_key.public_key(),
            )
            .expect("revoked");

        let public = pgp::composed::SignedPublicKey::from(secret.clone());

        pgp::composed::SignedPublicKey::new(
            public.primary_key,
            pgp::composed::SignedKeyDetails::new(
                vec![revocation],
                public.details.direct_signatures,
                public.details.users,
                public.details.user_attributes,
            ),
            public.public_subkeys,
        )
        .to_armored_string(Default::default())
        .expect("armored")
    }

    /// A revoked key is refused even though the signature it made is
    /// arithmetically perfect -- which is the whole point, and the reason
    /// the check runs before verification rather than after.
    #[test]
    fn revoked_key_may_not_vouch() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        // Sanity: without the revocation this exact signature verifies.
        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &store(&secret)).expect("checked"),
            SigOutcome::Valid
        );

        let revoked = vec![RegistryKey::pinned(
            fingerprint(&secret),
            revoked_public(&secret),
        )];

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &revoked).expect("checked"),
            SigOutcome::UntrustedKey(Untrusted::Revoked)
        );
    }

    /// Distinct from `UnknownKey`, which is the opposite situation:
    /// nothing was available versus something was and it disavows itself.
    #[test]
    fn revoked_key_not_reported_unknown() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let revoked = vec![RegistryKey::pinned(
            fingerprint(&secret),
            revoked_public(&secret),
        )];

        let outcome = verify_pgp(PAYLOAD, &signature, &revoked).expect("checked");

        assert_ne!(outcome, SigOutcome::UnknownKey);
    }

    /// The configured expiry is judged against **when the signature was
    /// made**, not against the clock. A signature made while the key was
    /// still trusted stays trusted however long ago that was.
    #[test]
    fn expiry_configured_admits_earlier_signature() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let keys = vec![
            RegistryKey::pinned(fingerprint(&secret), armored_public(&secret))
                .expiring(Utc::now() + chrono::Duration::days(365)),
        ];

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &keys).expect("checked"),
            SigOutcome::Valid
        );
    }

    /// And one made after it is refused, which is what setting an expiry
    /// is for.
    #[test]
    fn expiry_configured_refuses_later_signature() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let keys = vec![
            RegistryKey::pinned(fingerprint(&secret), armored_public(&secret))
                .expiring(Utc::now() - chrono::Duration::days(365)),
        ];

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &keys).expect("checked"),
            SigOutcome::UntrustedKey(Untrusted::Expired)
        );
    }

    /// Revocation outranks expiry: an expiry is a plan made in advance, a
    /// revocation is a statement made after something happened, and the
    /// second is the one to put in front of a person.
    #[test]
    fn revoked_and_expired_reports_revocation() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let keys = vec![
            RegistryKey::pinned(fingerprint(&secret), revoked_public(&secret))
                .expiring(Utc::now() - chrono::Duration::days(365)),
        ];

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &keys).expect("checked"),
            SigOutcome::UntrustedKey(Untrusted::Revoked)
        );
    }

    /// An untrusted key must not veto a trusted one elsewhere in the
    /// store: a rotated key sits beside its replacement.
    #[test]
    fn store_usable_key_later_still_wins() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        let keys = vec![
            RegistryKey::pinned(fingerprint(&secret), armored_public(&secret))
                .expiring(Utc::now() - chrono::Duration::days(365)),
            RegistryKey::pinned(fingerprint(&secret), armored_public(&secret)),
        ];

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &keys).expect("checked"),
            SigOutcome::Valid
        );
    }

    // -- Keys whose own material expires -------------------------------------

    const DAY_SECONDS: u32 = 24 * 60 * 60;

    /// A key created two days ago, so a lifetime of one day has passed.
    fn aged_keypair() -> SignedSecretKey {
        let created = Timestamp::from_secs(Timestamp::now().as_secs() - 2 * DAY_SECONDS);

        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Test Signer <signer@example.test>".into())
            .passphrase(None)
            .created_at(created)
            .build()
            .expect("params")
            .generate(rand::thread_rng())
            .expect("generated")
    }

    /// The public key with a newer direct-key self-signature stating
    /// `lifetime_seconds`, the way a holder sets or extends an expiry.
    fn expiring_public(secret: &SignedSecretKey, lifetime_seconds: u32) -> Vec<RegistryKey> {
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};

        let mut config =
            SignatureConfig::from_key(rand::thread_rng(), &secret.primary_key, SignatureType::Key)
                .expect("config");

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                .expect("creation time"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret.primary_key.fingerprint(),
            ))
            .expect("issuer"),
            Subpacket::regular(SubpacketData::KeyExpirationTime(
                pgp::types::Duration::from_secs(lifetime_seconds),
            ))
            .expect("lifetime"),
        ];

        let direct = config
            .sign_key(
                &secret.primary_key,
                &Password::empty(),
                &secret.primary_key.public_key(),
            )
            .expect("signed");

        let public = pgp::composed::SignedPublicKey::from(secret.clone());

        let armored = pgp::composed::SignedPublicKey::new(
            public.primary_key,
            pgp::composed::SignedKeyDetails::new(
                public.details.revocation_signatures,
                vec![direct],
                public.details.users,
                public.details.user_attributes,
            ),
            public.public_subkeys,
        )
        .to_armored_string(Default::default())
        .expect("armored");

        vec![RegistryKey::pinned(fingerprint(secret), armored)]
    }

    /// The holder's own expiry is enforced with no configured one, which
    /// is what the configuration's "the scheme's own expiry still applies"
    /// promises.
    #[test]
    fn expiry_material_refuses_later_signature() {
        let secret = aged_keypair();
        let signature = sign(&secret, PAYLOAD);

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &expiring_public(&secret, DAY_SECONDS))
                .expect("checked"),
            SigOutcome::UntrustedKey(Untrusted::Expired)
        );
    }

    #[test]
    fn expiry_material_admits_earlier_signature() {
        let secret = aged_keypair();
        let signature = sign(&secret, PAYLOAD);

        assert_eq!(
            verify_pgp(
                PAYLOAD,
                &signature,
                &expiring_public(&secret, 30 * DAY_SECONDS)
            )
            .expect("checked"),
            SigOutcome::Valid
        );
    }

    /// A lifetime of zero means none, not a key that lapses at creation.
    #[test]
    fn expiry_zero_lifetime_unbounded() {
        let secret = aged_keypair();
        let signature = sign(&secret, PAYLOAD);

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &expiring_public(&secret, 0)).expect("checked"),
            SigOutcome::Valid
        );
    }

    /// No expiry configured means none enforced here; the key's own rules
    /// still apply.
    #[test]
    fn expiry_unconfigured_key_unaffected() {
        let secret = keypair();
        let signature = sign(&secret, PAYLOAD);

        assert_eq!(
            verify_pgp(PAYLOAD, &signature, &store(&secret)).expect("checked"),
            SigOutcome::Valid
        );
    }
}
