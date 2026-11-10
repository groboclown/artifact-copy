//! Verifying the files Maven makes you download in order to inspect one.
//!
//! Maven publishes integrity data *beside* a file rather than in it, so a
//! `commons-lang3-3.14.0.pom` sits next to
//! `commons-lang3-3.14.0.pom.sha1` and `commons-lang3-3.14.0.pom.asc`.
//!
//! The governing rule here is **verify what you actually download**. That
//! is what separates this from the existing decision that `inspect` skips
//! the payload's sidecars: the jar is not downloaded during inspection, so
//! there is nothing to check yet and fetching its checksum would cost a
//! request for nothing. The POM *is* downloaded -- it is the only way to
//! learn an artifact's license and dependencies -- so it gets checked.
//!
//! # The sidecar namespace is recursive
//!
//! A sidecar is itself a file, so it has sidecars of its own: `.pom.sha1.asc`
//! and `.pom.asc.sha1` both exist in the wild, and so, in principle, does
//! `.pom.sha1.asc.sha1`. Nothing may follow that pattern without a bound.
//!
//! This stops at a file's own sidecars, and the reasoning is worth stating
//! because the alternative is to keep walking:
//!
//! - A **signature over a checksum** adds nothing when the file itself is
//!   signed. It attests to a 40-character hex string, and the `.asc` beside
//!   the file already attests to the file.
//! - A **checksum over a signature** only detects a corrupted signature,
//!   which failing to verify would detect anyway.
//!
//! Each extra level multiplies the request count of an inspection run over a
//! catalog that may hold millions of artifacts, and buys one of those two
//! things. The bound is structural rather than a constant: nothing in this
//! module asks for a sidecar of a sidecar, so there is no depth to get
//! wrong. A test asserts it stays that way.

use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::{ExtHost, HostFetch, Options};
use crate::message;
use crate::model::{ArtifactId, Digest, DigestAlg, SigRef, SigScheme, Version};
use crate::net::sig::{self, KeyOrigin, KeyStore, RegistryKey, SigOutcome, code_for};
use crate::net::{ByteLimit, Expectation, Req};
use crate::policy::SigningPolicy;

/// Checksums a target writes when it configures none, and the ones a
/// source always probes when it configures none.
///
/// SHA-1 then MD5, which is Maven's own resolver default
/// (`aether.checksums.algorithms`). A source also tries SHA-512 and SHA-256
/// for a while and keeps them only if its repository serves them; see
/// [`Probe`].
///
/// These are collision-broken hashes, and that is less damning than it
/// sounds for what they are doing. An attacker who controls the repository
/// controls the sidecar too, so a checksum never was the adversarial
/// guarantee -- the `.asc` is. What a checksum catches is corruption in
/// transit or at rest, and a mirror that has drifted from its origin, and
/// SHA-1 catches both perfectly well.
pub const DEFAULT_CHECKSUMS: [DigestAlg; 2] = [DigestAlg::Sha1, DigestAlg::Md5];

/// A detached PGP signature is a couple of kilobytes armored.
pub(super) const SIGNATURE_LIMIT: ByteLimit = ByteLimit::kib(16);

/// The option a source sets to change that list.
pub const CHECKSUMS_OPTION: &str = "checksums";

/// Read the `checksums` option.
///
/// Order is preserved and meaningful: the first one published wins, so a
/// repository that serves both SHA-256 and SHA-1 is checked against
/// whichever the user put first.
///
/// An **empty list is legal** and means *probe none*. For a repository
/// known to publish no checksums that is not a loss of safety, it is the
/// removal of a request per file that was never going to find anything.
pub fn checksums_from(options: &Options) -> Result<Vec<DigestAlg>> {
    Ok(configured(options)?.unwrap_or_else(|| DEFAULT_CHECKSUMS.to_vec()))
}

/// The `checksums` option as configured, or `None` when it is absent.
fn configured(options: &Options) -> Result<Option<Vec<DigestAlg>>> {
    let Some(named) = options.string_list(CHECKSUMS_OPTION)? else {
        return Ok(None);
    };

    named
        .into_iter()
        .map(|name| {
            DigestAlg::parse(name).ok_or_else(|| {
                Error::Config(format!(
                    "{CHECKSUMS_OPTION} names {name:?}, which is not a checksum \
                     algorithm this tool knows; the choices are {known}",
                    known = KNOWN_CHECKSUMS.join(", "),
                ))
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// The order a source that configures no `checksums` probes in: strongest
/// first, so a repository that serves SHA-512 is checked against it.
const LEARNED_ORDER: [DigestAlg; 4] = [
    DigestAlg::Sha512,
    DigestAlg::Sha256,
    DigestAlg::Sha1,
    DigestAlg::Md5,
];

/// How many POMs a source checks while trying the algorithms outside
/// [`DEFAULT_CHECKSUMS`]. After that it probes one of them only if the
/// repository has served it.
const TRIAL_CHECKS: usize = 8;

/// Which checksum sidecars a source probes, and in what order.
///
/// ```text
///   Fixed    `checksums` as configured, in its order, every time
///   Learned  no `checksums`:
///              first 8 POMs  sha512, sha256, sha1, md5
///              afterwards    sha1, md5, plus any stronger one ever found
///              always        the algorithm found last goes first
/// ```
///
/// Learned because which algorithms a repository publishes is a property
/// of the repository, and each probe it does not serve is a round trip per
/// POM across a catalog that may hold millions. After the trial this never
/// costs more than probing SHA-1 and MD5, which is what it cost before.
#[derive(Debug)]
pub(super) enum Probe {
    Fixed(Vec<DigestAlg>),
    Learned(Learned),
}

/// What a source has learned of the sidecars its repository serves.
///
/// Atomics rather than a lock: workers check POMs concurrently, and an
/// order that is momentarily one POM out of date costs at most a request.
#[derive(Debug, Default)]
pub(super) struct Learned {
    checks: AtomicUsize,

    /// One bit per [`LEARNED_ORDER`] entry, set once that algorithm is
    /// found.
    seen: AtomicU8,

    /// The [`LEARNED_ORDER`] index found last, or [`NONE_FOUND`].
    last: AtomicU8,
}

/// [`Learned::last`] before anything is found.
const NONE_FOUND: u8 = u8::MAX;

impl Probe {
    /// The configured list, or learning when there is none.
    pub(super) fn from_options(options: &Options) -> Result<Self> {
        Ok(match configured(options)? {
            Some(listed) => Probe::Fixed(listed),
            None => Probe::learned(),
        })
    }

    pub(super) fn learned() -> Self {
        Probe::Learned(Learned {
            last: AtomicU8::new(NONE_FOUND),
            ..Learned::default()
        })
    }

    /// The algorithms to probe for the next POM, in order.
    pub(super) fn order(&self) -> Vec<DigestAlg> {
        let learned = match self {
            Probe::Fixed(listed) => return listed.clone(),
            Probe::Learned(learned) => learned,
        };

        let trial = learned.checks.load(Ordering::Relaxed) < TRIAL_CHECKS;
        let seen = learned.seen.load(Ordering::Relaxed);

        let mut order: Vec<DigestAlg> = LEARNED_ORDER
            .iter()
            .enumerate()
            .filter(|(at, alg)| trial || DEFAULT_CHECKSUMS.contains(alg) || seen & (1 << at) != 0)
            .map(|(_, alg)| *alg)
            .collect();

        let last = learned.last.load(Ordering::Relaxed);

        if let Some(found) = LEARNED_ORDER.get(usize::from(last))
            && let Some(at) = order.iter().position(|alg| alg == found)
        {
            let found = order.remove(at);
            order.insert(0, found);
        }

        order
    }

    /// Note what one POM's probe found, so the next is ordered by it.
    pub(super) fn record(&self, found: Option<DigestAlg>) {
        let Probe::Learned(learned) = self else {
            return;
        };

        learned.checks.fetch_add(1, Ordering::Relaxed);

        let Some(at) = found.and_then(|alg| LEARNED_ORDER.iter().position(|known| *known == alg))
        else {
            return;
        };

        learned.seen.fetch_or(1 << at, Ordering::Relaxed);
        learned.last.store(at as u8, Ordering::Relaxed);
    }
}

/// For the error above, so a typo is answered with the alternatives.
const KNOWN_CHECKSUMS: [&str; 4] = ["md5", "sha1", "sha256", "sha512"];

/// The detached signature extension.
pub(super) const SIGNATURE: &str = "asc";

/// What was found beside a file, and what it proved.
#[derive(Debug, Clone, Default)]
pub struct Sidecars {
    /// Checksums that were published *and* matched the bytes.
    ///
    /// A mismatch is reported rather than recorded: the point of this list
    /// is what the file has been shown to be, so a failed check must not
    /// leave a digest here that a later reader would take as verified.
    pub digests: Vec<Digest>,

    /// The detached signature beside the file, if one is published.
    pub signature: Option<SigRef>,
}

/// Check a file that has already been fetched against its sidecars.
///
/// A missing sidecar is not a problem and is not reported. Outside Maven
/// Central most repositories publish none at all, and a warning on every
/// artifact of an internal repository is noise that trains people to ignore
/// warnings.
///
/// A sidecar that is present and *wrong* is another matter entirely, and
/// raises [`Code::ChecksumMismatch`].
///
/// `host` fetches the sidecars; `keyring` checks the signature, for the
/// artifact `subject` names.
pub(super) async fn check(
    url: &str,
    body: &[u8],
    checksums: &[DigestAlg],
    host: &dyn ExtHost,
    keyring: &Keyring<'_>,
    subject: &Subject<'_>,
    ctx: &Ctx,
) -> Sidecars {
    let mut found = Sidecars::default();

    if let Some(digest) = checksum_of(url, body, checksums, host, ctx).await {
        found.digests.push(digest);
    }

    found.signature = signature_of(url, body, host, keyring, subject, ctx).await;

    found
}

/// Fetch the first published checksum and check the bytes against it.
async fn checksum_of(
    url: &str,
    body: &[u8],
    checksums: &[DigestAlg],
    host: &dyn ExtHost,
    ctx: &Ctx,
) -> Option<Digest> {
    for alg in checksums.iter().copied() {
        // The extension *is* the algorithm name for every one Maven
        // publishes: `.sha1`, `.md5`, `.sha256`, `.sha512`.
        let sidecar = format!("{url}.{}", alg.as_str());

        // A sidecar is a hash and maybe a filename, so a kilobyte is
        // generous. Anything larger is not a checksum file.
        let Ok(bytes) = crate::ext::document(
            host,
            &Req::get(&sidecar),
            crate::ext::leaf(&sidecar),
            ByteLimit::SIDECAR,
            ctx,
        )
        .await
        else {
            // Absent, or unreachable. Either way there is nothing to check
            // against, and the next algorithm is worth a try.
            continue;
        };

        let Some(hex) = parse_checksum(&bytes) else {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "maven-checksum-unreadable",
                    "{url} does not contain a hexadecimal checksum",
                    url = &sidecar,
                ),
            );

            continue;
        };

        let expected = Digest::new(alg, &hex);
        let mut verifier = Expectation::new().with_digest(expected.clone()).verifier();

        verifier.update(body);

        return match verifier.finish() {
            Ok(()) => Some(expected),

            Err(err) => {
                // Loud, and fatal by default: a file that does not match
                // the checksum published beside it is either corrupt or
                // tampered with, and neither should be read as metadata.
                ctx.report(
                    Code::ChecksumMismatch,
                    message!(
                        "maven-sidecar-mismatch",
                        "{url} does not match the {alg} checksum published beside it: \
                         {reason}",
                        url = url,
                        alg = alg.as_str(),
                        reason = &err,
                    ),
                );

                None
            }
        };
    }

    None
}

/// Fetch and check the detached signature beside a file.
///
/// The verdict depends on what the key store can answer for, which is the
/// point of configuring one:
///
/// - **Verified** -- the signature checks out against a key the user pinned
///   or a keyserver supplied. The key id is recorded.
/// - **Unknown key** -- nothing available claims the signature. Reported as
///   `signature-missing`, because a signature nobody can check is, for
///   verification purposes, the same as none: not a forgery, not evidence.
/// - **Invalid** -- the signature exists and does not verify. Reported as
///   `signature-invalid`, which aborts by default.
async fn signature_of(
    url: &str,
    body: &[u8],
    host: &dyn ExtHost,
    keyring: &Keyring<'_>,
    subject: &Subject<'_>,
    ctx: &Ctx,
) -> Option<SigRef> {
    let sidecar = format!("{url}.{SIGNATURE}");

    let bytes = crate::ext::document(
        host,
        &Req::get(&sidecar),
        crate::ext::leaf(&sidecar),
        SIGNATURE_LIMIT,
        ctx,
    )
    .await
    .ok()?;

    let armored = armored(&sidecar, &bytes, ctx)?;

    // Bytes in memory cannot fail to read, so the only error is none.
    let key_id = judge(
        url,
        &sidecar,
        &armored,
        Signed::Bytes(body),
        keyring,
        subject,
        ctx,
    )
    .await
    .unwrap_or_default();

    Some(SigRef {
        scheme: SigScheme::PgpDetached,
        key_id,
        value: Some(armored),
        url: Some(sidecar),
    })
}

/// What a signature is checked with: the keys, where more are looked up,
/// and which of them may vouch for what.
pub(super) struct Keyring<'a> {
    pub keys: &'a KeyStore,

    /// Where a keyserver is asked for a key nothing pinned answers to,
    /// which is not the repository's host.
    pub lookup: &'a dyn ExtHost,

    pub policy: &'a SigningPolicy,
}

/// The artifact a signature is about, for the signing policy.
pub(super) struct Subject<'a> {
    pub id: &'a ArtifactId,
    pub version: Option<&'a Version>,
}

/// What a detached signature covers.
pub(super) enum Signed<'a> {
    /// Bytes already in memory, such as a POM read during inspection.
    Bytes(&'a [u8]),

    /// A staged file, such as a payload, streamed rather than read whole.
    File(&'a Path),
}

/// The armored signature in `bytes`, read from `sidecar`, or `None` after
/// reporting that it is not one.
///
/// A signature a BouncyCastle signer wrapped in a compressed `PGP MESSAGE`
/// is taken out of it; see [`sig::detached_armor`].
pub(super) fn armored(sidecar: &str, bytes: &[u8], ctx: &Ctx) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);

    let reason = match sig::detached_armor(&text) {
        Ok(armored) => return Some(armored),
        Err(err) => err.to_string(),
    };

    ctx.report(
        Code::MetadataMalformed,
        message!(
            "maven-signature-unreadable",
            "{url} is not an armored PGP signature: {reason}",
            url = sidecar,
            reason = &reason,
        ),
    );

    None
}

/// Check `armored`, read from `sidecar`, against what it signs, and report
/// the verdict about `url`. The issuer's key id when the signature names
/// one.
///
/// Only a staged file that cannot be read is an error; every verdict about
/// the signature itself is reported instead, including a valid signature
/// by a key the signing policy does not let vouch for `subject`.
pub(super) async fn judge(
    url: &str,
    sidecar: &str,
    armored: &str,
    signed: Signed<'_>,
    keyring: &Keyring<'_>,
    subject: &Subject<'_>,
    ctx: &Ctx,
) -> Result<Option<String>> {
    let Some(issuers) = issuers_or_report(sidecar, armored, ctx) else {
        return Ok(None);
    };

    let candidates = candidate_keys(&issuers, keyring, ctx).await;
    let outcome = verified(&signed, armored, &candidates);

    if let Ok(SigOutcome::Valid) = outcome {
        let signer = signer_of(&signed, armored, &candidates)?;

        report_unvouched(url, signer, keyring.policy, subject, ctx);
    }

    report_outcome(url, &issuers, outcome, ctx)?;

    Ok(issuers.first().cloned())
}

/// The key ids a signature names, or `None` after reporting it unreadable.
///
/// An unreadable signature is not the same as a bad one, and is worth
/// saying so rather than reporting a failed verification.
fn issuers_or_report(sidecar: &str, armored: &str, ctx: &Ctx) -> Option<Vec<String>> {
    let err = match sig::issuers_of(armored) {
        Ok(issuers) => return Some(issuers),
        Err(err) => err,
    };

    ctx.report(
        Code::MetadataMalformed,
        message!(
            "maven-signature-unreadable",
            "{url}: {reason}",
            url = sidecar,
            reason = &err,
        ),
    );

    None
}

/// The keys that may have made a signature by `issuers`: pinned, or looked
/// up on a keyserver.
async fn candidate_keys(issuers: &[String], keyring: &Keyring<'_>, ctx: &Ctx) -> Vec<RegistryKey> {
    keyring
        .keys
        .keys_for(issuers, &HostFetch::new(keyring.lookup, ctx))
        .await
}

/// Report a valid signature by a key the signing policy does not let vouch
/// for `subject`.
fn report_unvouched(
    url: &str,
    signer: Option<&RegistryKey>,
    policy: &SigningPolicy,
    subject: &Subject<'_>,
    ctx: &Ctx,
) {
    let Some(key) = signer else {
        return;
    };

    if vouched(policy, subject, key) {
        return;
    }

    ctx.report(
        Code::SignatureKeyUnvouched,
        message!(
            "maven-signing-key-unvouched",
            "{url} is signed by {key}, from {origin}, which the signing policy \
             does not let vouch for {purl}",
            url = url,
            key = sig::fingerprint_of(&key.key).unwrap_or_else(|| key.keyid.clone()),
            origin = origin_of(key.origin),
            purl = match subject.version {
                Some(version) => subject.id.purl_at(version.text()),
                None => subject.id.purl(),
            },
        ),
    );
}

/// Report a verification that did not succeed. Only a staged file that
/// cannot be read is an error.
fn report_outcome(
    url: &str,
    issuers: &[String],
    outcome: Result<SigOutcome>,
    ctx: &Ctx,
) -> Result<()> {
    let issuer = issuers
        .first()
        .map(String::as_str)
        .unwrap_or("an unnamed key");

    match outcome {
        // Whether the key may vouch is `report_unvouched`'s question.
        Ok(SigOutcome::Valid) => {}

        // A key was available and says, on its own terms, not to rely on
        // it. Reported under its own code rather than `signature-invalid`,
        // because nothing failed to verify: this is a judgement about
        // whether the key may be trusted, and the two want different
        // answers from a policy.
        Ok(SigOutcome::UntrustedKey(reason)) => {
            ctx.report(
                code_for(reason),
                message!(
                    "maven-signing-key-untrusted",
                    "{url} is signed by {issuer}, whose key is {reason} and may not \
                     vouch for it",
                    url = url,
                    issuer = issuer,
                    reason = reason.as_str(),
                ),
            );
        }

        Ok(SigOutcome::UnknownKey) => {
            ctx.report(
                Code::SignatureMissing,
                message!(
                    "maven-signing-key-unavailable",
                    "{url} is signed by {issuer}, which is neither pinned in \
                     signing-keys nor available from a configured keyserver, so the \
                     signature could not be checked",
                    url = url,
                    issuer = issuer,
                ),
            );
        }

        Err(err @ Error::ReadFile { .. }) => return Err(err),

        Err(err) => {
            ctx.report(
                Code::SignatureInvalid,
                message!(
                    "maven-signature-invalid",
                    "{url} does not match the signature published beside it: {reason}",
                    url = url,
                    reason = &err,
                ),
            );
        }
    }

    Ok(())
}

/// A signature checked against `keys`, over whatever `signed` holds.
fn verified(signed: &Signed<'_>, armored: &str, keys: &[RegistryKey]) -> Result<SigOutcome> {
    match signed {
        Signed::Bytes(bytes) => sig::verify_pgp(bytes, armored, keys),
        Signed::File(path) => sig::verify_pgp_file(path, armored, keys),
    }
}

/// Which of `candidates` made a signature already known to verify.
///
/// Asked one key at a time only when there are several; ordinarily the
/// issuer names one, and that one is the answer.
fn signer_of<'k>(
    signed: &Signed<'_>,
    armored: &str,
    candidates: &'k [RegistryKey],
) -> Result<Option<&'k RegistryKey>> {
    if let [only] = candidates {
        return Ok(Some(only));
    }

    for key in candidates {
        if let Ok(SigOutcome::Valid) = verified(signed, armored, std::slice::from_ref(key)) {
            return Ok(Some(key));
        }
    }

    Ok(None)
}

/// Whether the signing policy lets `key` vouch for `subject`. A key whose
/// fingerprint cannot be read vouches for nothing a policy would need to
/// know it for.
fn vouched(policy: &SigningPolicy, subject: &Subject<'_>, key: &RegistryKey) -> bool {
    let Some(fingerprint) = sig::fingerprint_of(&key.key) else {
        return key.origin == KeyOrigin::Pinned && policy.rules.is_empty();
    };

    policy.vouches(subject.id, subject.version, &fingerprint, key.origin)
}

/// Where a key came from, for a message.
fn origin_of(origin: KeyOrigin) -> &'static str {
    match origin {
        KeyOrigin::Pinned => "signing-keys",
        KeyOrigin::Keyserver => "a keyserver",
        KeyOrigin::Registry => "the registry",
    }
}

/// Read the hex digest out of a Maven checksum file.
///
/// The format is not quite fixed. Most are a bare hex string; some carry a
/// trailing filename in the `sha1sum` style (`<hex>  <name>`), some have a
/// trailing newline, and a few are uppercase. The first whitespace-delimited
/// token that is entirely hexadecimal is the digest.
pub(super) fn parse_checksum(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;

    text.split_whitespace()
        .find(|token| !token.is_empty() && token.chars().all(|ch| ch.is_ascii_hexdigit()))
        .map(|token| token.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::ext::testing::TestHost;
    use crate::net::FixtureClient;
    use crate::repo::maven::testing::{detached_signature, public_key_of, signing_key};

    const POM_URL: &str = "h://repo.test/g/a/1.0/a-1.0.pom";
    const BODY: &str = "<project><artifactId>a</artifactId></project>";

    /// SHA-1 of `BODY`, computed by the same library that checks it -- which
    /// is circular for proving the hash is SHA-1, and is not what these
    /// tests are for. They test the sidecar plumbing; `net::verify` tests
    /// the hashing.
    fn sha1_of(body: &str) -> String {
        use sha1::{Digest as _, Sha1};

        let mut hasher = Sha1::new();
        hasher.update(body.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// A BouncyCastle signature armored as a compressed message is taken
    /// out of it; text that is no signature is reported and skipped.
    #[test]
    fn signature_armored_opens_message_refuses_text() {
        const MESSAGE_WRAPPED: &str = "-----BEGIN PGP MESSAGE-----
Version: BCPG v1.81

owDCXgQAFgIABgWCaeZn4QAKCRDn2I24Qn3mUVSiAQDlJEotbHMzno6Lath1AYoB
zPzA67s6iapW+EuvFkVSMwEA1vqZ9lAT2U7nakU8tSjtrsbS2Mi/vh3GSOlg3R+L
dQg=
=B/2J
-----END PGP MESSAGE-----
";
        let ctx = Ctx::for_test(crate::model::Cause::Requested { arg: "a".into() });

        let opened = armored(POM_URL, MESSAGE_WRAPPED.as_bytes(), &ctx).expect("opened");

        assert!(
            opened.starts_with("-----BEGIN PGP SIGNATURE-----"),
            "{opened}"
        );
        assert!(armored(POM_URL, b"<html>not here</html>", &ctx).is_none());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    fn md5_of(body: &str) -> String {
        use md5::{Digest as _, Md5};

        let mut hasher = Md5::new();
        hasher.update(body.as_bytes());

        hex::encode(hasher.finalize())
    }

    const SIGNATURE_BODY: &str =
        "-----BEGIN PGP SIGNATURE-----\n\niQEc\n-----END PGP SIGNATURE-----";

    async fn check_with(client: FixtureClient, ctx: &Ctx) -> (Sidecars, TestHost) {
        check_against(client, ctx, KeyStore::new(Vec::new())).await
    }

    async fn check_against(
        client: FixtureClient,
        ctx: &Ctx,
        keys: KeyStore,
    ) -> (Sidecars, TestHost) {
        check_probing(client, ctx, keys, &DEFAULT_CHECKSUMS).await
    }

    /// The same, against an explicit algorithm list.
    async fn check_probing(
        client: FixtureClient,
        ctx: &Ctx,
        keys: KeyStore,
        checksums: &[DigestAlg],
    ) -> (Sidecars, TestHost) {
        check_under(client, ctx, keys, checksums, &SigningPolicy::default()).await
    }

    /// The same, under a signing policy, for `org.example:lib` 1.0.
    async fn check_under(
        client: FixtureClient,
        ctx: &Ctx,
        keys: KeyStore,
        checksums: &[DigestAlg],
        policy: &SigningPolicy,
    ) -> (Sidecars, TestHost) {
        let host = TestHost::new(client);
        let keyring = Keyring {
            keys: &keys,
            lookup: &host,
            policy,
        };
        let id = ArtifactId::new(
            crate::model::EcosystemId::maven(),
            Some("org.example"),
            "lib",
        );
        let version = Version::new("1.0", crate::model::Release::General);
        let subject = Subject {
            id: &id,
            version: Some(&version),
        };

        let found = check(
            POM_URL,
            BODY.as_bytes(),
            checksums,
            &host,
            &keyring,
            &subject,
            ctx,
        )
        .await;

        (found, host)
    }

    // -- Learning which sidecars a repository serves -------------------------

    use DigestAlg::{Md5, Sha1, Sha256, Sha512};

    /// A configured list is probed as written, whatever is found.
    #[test]
    fn probe_fixed_keeps_its_order() {
        let probe = Probe::Fixed(vec![Md5, Sha256]);

        probe.record(Some(Sha256));

        assert_eq!(probe.order(), [Md5, Sha256]);
    }

    /// Unconfigured: strongest first, while the trial lasts.
    #[test]
    fn probe_learned_starts_strongest_first() {
        assert_eq!(Probe::learned().order(), [Sha512, Sha256, Sha1, Md5]);
    }

    /// A repository that never served a strong checksum costs what it did
    /// before learning existed: SHA-1 and MD5.
    #[test]
    fn probe_learned_drops_unseen_after_trial() {
        let probe = Probe::learned();

        for _ in 0..TRIAL_CHECKS {
            probe.record(None);
        }

        assert_eq!(probe.order(), [Sha1, Md5]);
    }

    /// A strong checksum found once stays in the order after the trial,
    /// and the one found last is probed first.
    #[test]
    fn probe_learned_keeps_found() {
        let probe = Probe::learned();

        probe.record(Some(Sha256));

        for _ in 1..TRIAL_CHECKS {
            probe.record(None);
        }

        assert_eq!(probe.order(), [Sha256, Sha1, Md5]);

        probe.record(Some(Sha1));

        assert_eq!(probe.order(), [Sha1, Sha256, Md5]);
    }

    #[test]
    fn probe_follows_the_option() {
        let learned = Probe::from_options(&Options::default()).expect("reads");
        assert!(matches!(learned, Probe::Learned(_)));

        let fixed = Probe::from_options(&crate::ext::testing::options(
            serde_json::json!({"checksums": ["sha256"]}),
        ))
        .expect("reads");
        assert_eq!(fixed.order(), [Sha256]);
    }

    #[tokio::test]
    async fn checksum_matching_sha1_recorded() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new().with_body(format!("{POM_URL}.sha1"), sha1_of(BODY)),
            &ctx,
        )
        .await;

        assert_eq!(found.digests, [Digest::new(DigestAlg::Sha1, sha1_of(BODY))]);
        assert!(ctx.problems().counts().is_empty());
    }

    /// The reason to do any of this. A POM that does not match the checksum
    /// published beside it is corrupt or tampered with, and must not be
    /// read as metadata.
    #[tokio::test]
    async fn checksum_mismatch_reported_not_recorded() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new().with_body(
                format!("{POM_URL}.sha1"),
                "0000000000000000000000000000000000000000",
            ),
            &ctx,
        )
        .await;

        // Not recorded: this list is what the file has been *shown* to be,
        // and a failed check must not leave a digest a later reader trusts.
        assert!(found.digests.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::ChecksumMismatch], 1);
    }

    /// Most repositories outside Central publish nothing beside a file. A
    /// warning per artifact there is noise that teaches people to ignore
    /// warnings.
    #[tokio::test]
    async fn sidecar_missing_silent() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(FixtureClient::new(), &ctx).await;

        assert!(found.digests.is_empty());
        assert!(found.signature.is_none());
        assert!(ctx.problems().counts().is_empty());
    }

    /// SHA-1 first, MD5 only when there is no SHA-1 -- Maven's own order.
    #[tokio::test]
    async fn checksums_md5_fallback_not_first() {
        let ctx = Ctx::anonymous_for_test();

        let (found, host) = check_with(
            FixtureClient::new()
                .with_body(format!("{POM_URL}.sha1"), sha1_of(BODY))
                .with_body(format!("{POM_URL}.md5"), md5_of(BODY)),
            &ctx,
        )
        .await;

        assert_eq!(found.digests[0].alg, DigestAlg::Sha1);

        // And having found one, it does not go on asking.
        assert_eq!(host.hits(&format!("{POM_URL}.md5")), 0);
    }

    #[tokio::test]
    async fn checksums_md5_used_when_only_one() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new().with_body(format!("{POM_URL}.md5"), md5_of(BODY)),
            &ctx,
        )
        .await;

        assert_eq!(found.digests[0].alg, DigestAlg::Md5);
    }

    #[tokio::test]
    async fn signature_recorded_with_location() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new().with_body(format!("{POM_URL}.asc"), SIGNATURE_BODY),
            &ctx,
        )
        .await;

        let signature = found.signature.expect("recorded");

        assert_eq!(signature.scheme, SigScheme::PgpDetached);
        assert_eq!(
            signature.url.as_deref(),
            Some(format!("{POM_URL}.asc").as_str())
        );
    }

    /// A signature nobody can check is, for verification purposes, the
    /// same as none: not a forgery, not evidence. It must be reported
    /// rather than pass silently.
    #[tokio::test]
    async fn signature_without_available_key_reported() {
        let secret = signing_key();
        let ctx = Ctx::anonymous_for_test();

        let (found, _) = check_with(
            FixtureClient::new()
                .with_body(format!("{POM_URL}.asc"), detached_signature(&secret, BODY)),
            &ctx,
        )
        .await;

        assert!(found.signature.is_some());
        assert_eq!(ctx.problems().counts()[&Code::SignatureMissing], 1);
    }

    /// The point of configuring a key store: with the right key available,
    /// the signature is actually checked and passes.
    #[tokio::test]
    async fn signature_verifies_against_key_store() {
        let secret = signing_key();
        let ctx = Ctx::anonymous_for_test();

        let (found, _) = check_against(
            FixtureClient::new()
                .with_body(format!("{POM_URL}.asc"), detached_signature(&secret, BODY)),
            &ctx,
            KeyStore::new(vec![public_key_of(&secret)]),
        )
        .await;

        assert!(found.signature.expect("recorded").key_id.is_some());
        assert!(
            ctx.problems().counts().is_empty(),
            "{:?}",
            ctx.problems().counts()
        );
    }

    /// A signature over different bytes is a failure, not a missing key,
    /// and `signature-invalid` aborts by default.
    #[tokio::test]
    async fn signature_over_other_bytes_invalid() {
        let secret = signing_key();
        let ctx = Ctx::anonymous_for_test();

        let (_, _) = check_against(
            FixtureClient::new().with_body(
                format!("{POM_URL}.asc"),
                detached_signature(&secret, "something else entirely"),
            ),
            &ctx,
            KeyStore::new(vec![public_key_of(&secret)]),
        )
        .await;

        assert_eq!(ctx.problems().counts()[&Code::SignatureInvalid], 1);
    }

    /// An expired key is not a failed verification, and reporting it as
    /// one would abort a run over something that is often ordinary -- a key
    /// lapsing after it signed. It gets its own code so a policy can
    /// answer it separately.
    #[tokio::test]
    async fn signature_key_expired_own_code() {
        let secret = signing_key();
        let ctx = Ctx::anonymous_for_test();

        let expired = crate::net::sig::RegistryKey::pinned(
            hex::encode(
                {
                    use pgp::types::KeyDetails as _;
                    secret.primary_key.fingerprint()
                }
                .as_bytes(),
            ),
            pgp::composed::SignedPublicKey::from(secret.clone())
                .to_armored_string(Default::default())
                .expect("armored"),
        )
        .expiring(chrono::Utc::now() - chrono::Duration::days(365));

        let (_, _) = check_against(
            FixtureClient::new()
                .with_body(format!("{POM_URL}.asc"), detached_signature(&secret, BODY)),
            &ctx,
            KeyStore::new(vec![expired]),
        )
        .await;

        let counts = ctx.problems().counts();

        assert_eq!(counts[&Code::SignatureKeyExpired], 1, "{counts:?}");
        assert!(
            !counts.contains_key(&Code::SignatureInvalid),
            "an expired key is not a failed verification: {counts:?}"
        );
    }

    /// And the two trust judgements are separate from each other, because a
    /// user who tolerates a lapsed key should not thereby tolerate a
    /// disavowed one.
    #[test]
    fn signature_key_revoked_and_expired_differ() {
        use crate::net::sig::{Untrusted, code_for};

        assert_eq!(code_for(Untrusted::Revoked), Code::SignatureKeyRevoked);
        assert_eq!(code_for(Untrusted::Expired), Code::SignatureKeyExpired);
        assert_ne!(code_for(Untrusted::Revoked), code_for(Untrusted::Expired));
    }

    #[tokio::test]
    async fn signature_unreadable_reported() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new().with_body(format!("{POM_URL}.asc"), "<html>404</html>"),
            &ctx,
        )
        .await;

        assert!(found.signature.is_none());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// The bound that stops the recursive sidecar namespace being walked
    /// forever. Nothing here asks for `.sha1.asc` or `.asc.sha1`.
    #[tokio::test]
    async fn sidecar_of_sidecar_not_followed() {
        let ctx = Ctx::anonymous_for_test();

        let (_, host) = check_with(
            FixtureClient::new()
                .with_body(format!("{POM_URL}.sha1"), sha1_of(BODY))
                .with_body(format!("{POM_URL}.asc"), SIGNATURE_BODY)
                .with_body(format!("{POM_URL}.sha1.asc"), SIGNATURE_BODY)
                .with_body(format!("{POM_URL}.asc.sha1"), sha1_of(SIGNATURE_BODY)),
            &ctx,
        )
        .await;

        let asked: Vec<String> = host.requested();

        assert!(
            !asked.iter().any(|url| url.ends_with(".sha1.asc")),
            "{asked:?}"
        );
        assert!(
            !asked.iter().any(|url| url.ends_with(".asc.sha1")),
            "{asked:?}"
        );
    }

    /// Verifying one file costs at most one checksum probe and one
    /// signature probe, whatever is or is not published. Over a catalog of
    /// millions that ratio is the whole cost model.
    #[tokio::test]
    async fn sidecar_check_costs_bounded_requests() {
        let ctx = Ctx::anonymous_for_test();
        let (_, host) = check_with(FixtureClient::new(), &ctx).await;

        // Both checksum algorithms probed, then the signature: three, and
        // only because nothing at all was published.
        assert_eq!(host.requested().len(), 3);
    }

    // -- Checksum file parsing --------------------------------------------

    #[test]
    fn parse_checksum_bare_hex() {
        assert_eq!(
            parse_checksum(b"da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned())
        );
    }

    /// Some repositories write the `sha1sum` form, with the filename after
    /// the digest.
    #[test]
    fn parse_checksum_trailing_filename() {
        assert_eq!(
            parse_checksum(b"da39a3ee5e6b4b0d3255bfef95601890afd80709  a-1.0.pom\n"),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned())
        );
    }

    #[test]
    fn parse_checksum_whitespace_and_case_ignored() {
        assert_eq!(
            parse_checksum(b"  DA39A3EE5E6B4B0D3255BFEF95601890AFD80709  \n"),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned())
        );
    }

    /// An error page served with a 200 is a real failure mode for a
    /// repository behind a proxy, and must not be read as a digest.
    #[test]
    fn parse_checksum_non_checksum_refused() {
        assert_eq!(parse_checksum(b"<html>not found</html>"), None);
        assert_eq!(parse_checksum(b""), None);
        assert_eq!(parse_checksum(b"   \n  "), None);
        assert_eq!(parse_checksum(&[0xff, 0xfe, 0x00]), None);
    }

    /// A checksum file that is not a checksum is worth saying out loud: it
    /// means the repository is serving something unexpected.
    #[tokio::test]
    async fn checksum_unreadable_file_reported() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new().with_body(format!("{POM_URL}.sha1"), "<html>oops</html>"),
            &ctx,
        )
        .await;

        assert!(found.digests.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// And having found the first unreadable, it still tries the next
    /// algorithm rather than giving up on the file.
    #[tokio::test]
    async fn checksum_unreadable_falls_through() {
        let ctx = Ctx::anonymous_for_test();
        let (found, _) = check_with(
            FixtureClient::new()
                .with_body(format!("{POM_URL}.sha1"), "<html>oops</html>")
                .with_body(format!("{POM_URL}.md5"), md5_of(BODY)),
            &ctx,
        )
        .await;

        assert_eq!(found.digests[0].alg, DigestAlg::Md5);
    }

    // -- The configured algorithm list ------------------------------------

    fn options(value: serde_json::Value) -> Options {
        crate::ext::testing::options(value)
    }

    /// The default is Maven's own resolver order, and probing stops at the
    /// first published one -- so a repository serving both is asked once.
    #[test]
    fn checksums_default_in_mavens_order() {
        assert_eq!(
            checksums_from(&Options::default()).expect("defaults"),
            vec![DigestAlg::Sha1, DigestAlg::Md5]
        );
    }

    /// The reason the option exists: a repository that publishes SHA-256
    /// can be checked against it, which the defaults never probe.
    #[tokio::test]
    async fn checksums_configured_algorithm_probed() {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(BODY.as_bytes());
        let hex = hex::encode(hasher.finalize());

        let ctx = Ctx::anonymous_for_test();

        let (found, host) = check_probing(
            FixtureClient::new().with_body(format!("{POM_URL}.sha256"), hex.clone()),
            &ctx,
            KeyStore::new(Vec::new()),
            &[DigestAlg::Sha256],
        )
        .await;

        assert_eq!(found.digests.len(), 1);
        assert_eq!(found.digests[0].alg, DigestAlg::Sha256);
        assert_eq!(found.digests[0].hex, hex);

        // And the defaults were never asked for.
        assert_eq!(host.hits(&format!("{POM_URL}.sha1")), 0);
        assert_eq!(host.hits(&format!("{POM_URL}.md5")), 0);
    }

    /// Order is precedence: the first published one wins, so a user who
    /// prefers SHA-256 over SHA-1 says so by listing it first.
    #[tokio::test]
    async fn checksums_first_published_wins() {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(BODY.as_bytes());
        let sha256 = hex::encode(hasher.finalize());

        let client = FixtureClient::new()
            .with_body(format!("{POM_URL}.sha256"), sha256)
            .with_body(format!("{POM_URL}.sha1"), sha1_of(BODY));

        let ctx = Ctx::anonymous_for_test();

        let (found, host) = check_probing(
            client,
            &ctx,
            KeyStore::new(Vec::new()),
            &[DigestAlg::Sha256, DigestAlg::Sha1],
        )
        .await;

        assert_eq!(found.digests[0].alg, DigestAlg::Sha256);
        assert_eq!(
            host.hits(&format!("{POM_URL}.sha1")),
            0,
            "stops at the first"
        );
    }

    /// An empty list is a value, not an absence: a repository known to
    /// publish none is not probed at all, which removes a request per file
    /// that was never going to find anything.
    #[tokio::test]
    async fn checksums_empty_probe_nothing() {
        let ctx = Ctx::anonymous_for_test();

        let (found, host) = check_probing(
            FixtureClient::new().with_body(format!("{POM_URL}.sha1"), sha1_of(BODY)),
            &ctx,
            KeyStore::new(Vec::new()),
            &[],
        )
        .await;

        assert!(found.digests.is_empty());
        assert_eq!(host.hits(&format!("{POM_URL}.sha1")), 0);

        assert_eq!(
            checksums_from(&options(serde_json::json!({"checksums": []}))).expect("empty"),
            Vec::<DigestAlg>::new()
        );
    }

    #[test]
    fn checksums_configured_read_in_order() {
        let read = checksums_from(&options(
            serde_json::json!({"checksums": ["sha512", "sha256"]}),
        ))
        .expect("parses");

        assert_eq!(read, vec![DigestAlg::Sha512, DigestAlg::Sha256]);
    }

    /// A typo must not silently disable checking, which is what ignoring
    /// the entry would do.
    #[test]
    fn checksums_unknown_algorithm_names_alternatives() {
        let err = checksums_from(&options(serde_json::json!({"checksums": ["sha-256"]})))
            .expect_err("not an algorithm");

        let text = err.to_string();

        assert!(text.contains("sha-256"), "{text}");
        assert!(text.contains("sha256"), "{text}: name the alternatives");
    }

    #[test]
    fn checksums_option_wrong_shape_refused() {
        assert!(checksums_from(&options(serde_json::json!({"checksums": "sha1"}))).is_err());
        assert!(checksums_from(&options(serde_json::json!({"checksums": [1]}))).is_err());
    }
}
