# Verification and Trust

References: [Sigstore](https://docs.sigstore.dev/), [TUF](https://theupdateframework.github.io/specification/latest/).

Checksums, signatures, and the keys they are checked against.

## Verify what you actually download

The governing rule for sidecars. A POM is fetched during inspection -- it is the only way to learn an artifact's license and dependencies -- so it is checked against the sidecars published beside it. The payload jar is not fetched during inspection, so fetching its checksum would cost a request for nothing.

- **Checksums** are verified, and a mismatch raises `checksum-mismatch`, which aborts by default. The list is configurable per source through the `checksums` option: an ordered list, probed until one is found. Configured, it is probed exactly as listed. Absent, the source learns what its repository serves (`sidecar::Probe`): its first 8 POMs are probed for SHA-512, SHA-256, SHA-1, and MD5, and afterwards only SHA-1, MD5, and any stronger algorithm it found, the one found last first. Probing all four forever would cost two more round trips per POM on the many repositories that publish neither strong hash; after the trial this costs no more than Maven's own resolver order, `["sha1", "md5"]`, did. An empty list means *probe none*, which is the right setting for a repository known to publish none -- not a loss of safety but the removal of a request that was never going to find anything. An unrecognized name is an error naming the alternatives, because ignoring it would silently disable checking.
- **Signatures** are verified against the `KeyStore` assembled from `signing-keys` and any configured keyservers. `SigRef.key_id` is set only once an issuer has actually been read from the signature. The three outcomes are distinct: verified, `signature-missing` when nothing available claims the signature, and `signature-invalid` when it does not verify, which aborts by default.

### An artifact enumeration's digests are expectations too

A Maven payload arrives from the source with no digest, because its sidecars are not fetched during inspection. A repository manager's catalog reports the checksums it computed, and when a `find` listed the file, those are merged into the file's digests and checked in flight like any other. They are the same server's claim a `.sha1` sidecar would have been, so they count for as much and no more. A disagreement between the catalog's digest and the source's refuses the artifact with `listing-mismatch`; see [sources-and-targets.md](sources-and-targets.md#the-combination-rule).

### Signatures are copied, and checked once the payload is staged

`MavenSource::metadata` lists each file's `.asc` as a file of the artifact, directly after the file it signs, so a Maven target serves what the source did. The POM's is already known from its check. The payload's costs one `HEAD` per artifact, because the payload is not downloaded during inspection and nothing else says whether it was signed; its checksum sidecars are still never requested.

The payload's signature is checked when it is copied, not during inspection: `upload` downloads every file of the artifact, then calls `Source::verify` with the staged paths before anything is published. `MavenSource::verify` pairs each `.asc` with the file it signs **by name** -- an artifact enumeration's listing may put a signature anywhere -- and checks it against the staged file, streamed, with the same verdicts and codes as the POM's. A file already carrying a detached signature, the POM, is not checked twice. A `signature-invalid` aborts the run before the publish, and a key that may not vouch (`signature-key-revoked`) refuses the artifact, recorded as `refused`. Wrapping sources forward the call: a proxy to the upstream serving the artifact's first file, an inventory to its live source, whose keys apply.

A copied `.asc` carries no digest, so `copy` reports `upload-unverifiable-file` for it. That is deliberate: no checksum is probed for a signature, for the reason under *Sidecar depth* below, and the target writes none beside one either.

### Attestations are verified once the file is staged

A PyPI file's PEP 740 attestations are checked by `PyPiSource::verify`, which `upload` calls once every file of the artifact is downloaded and before anything is published. Each attestation in the file's provenance object must hold three things, and the file passes only if every one does:

- **Its statement names this file**: the distribution's filename (compared case-insensitively, `-` and `_` alike) with the sha256 the download was checked against.
- **Its signature verifies** as a Sigstore bundle: the certificate chains to Fulcio, the transparency log entry is included and consistent, and the DSSE signature covers the statement. An attestation is rewritten into a Sigstore bundle first, as the `pypi-attestations` library does; the cryptography is the `sigstore-verify` crate's, behind `net::sig::sigstore`.
- **Its signer is the publisher the provenance names**, PyPI's Trusted Publisher, which PyPI checked at upload: for GitHub the certificate's identity must start with `https://github.com/{repository}/.github/workflows/{workflow}@` and its issuer be GitHub Actions; for GitLab `https://gitlab.com/{repository}//{workflow_filepath}@`; for Google the account's email.

A statement that does not hold is `signature-invalid`, which aborts by default. A publisher kind with no identity rule (ActiveState, or one added later), a trust root that will not load, and a provenance object the index advertised and does not serve are each `signature-missing`: nothing was proven, and nothing was shown false. A provenance object that is not one is `metadata-malformed`. A file whose index names no provenance says nothing, since most PyPI files have none.

**The trust root is Sigstore's current one**, fetched from its TUF repository the first time a run checks an attestation and cached under `setup.cache-dir` (`sigstore-tuf`), or the `trusted_root.json` that `setup.sigstore-trusted-root` names. The TUF fetch uses the crate's own HTTP client rather than a configured host: TUF carries its own chain of trust, rooted in the crate. A run that meets no attestation fetches nothing.

`inspect` does not verify attestations, because it downloads nothing. A copy forwarding the attestations (see [write-path.md](write-path.md#attestations-travel-as-a-companion)) reads the provenance the check already fetched.

### Sidecar depth stays at one, by decision

The recursion is tempting: `.pom.sha1.asc` and `.pom.asc.sha1` both exist in the wild. Following them buys one of two things, and neither is worth a request:

- A **signature over a checksum** adds nothing when the file itself is signed. It attests to a 40-character hex string; the `.asc` beside the file already attests to the file.
- A **checksum over a signature** only detects a corrupted signature, which failing to verify detects anyway.

Each level multiplies the request count of an inspection run over a catalog that may hold millions of artifacts. The bound is structural rather than a constant -- nothing in the module asks for a sidecar of a sidecar, so there is no depth to get wrong -- and a test asserts it stays that way. Making it configurable would mean building the recursion in order to leave it turned off.

## Keys, expiry, and revocation

`net::sig::verify_pgp` checks a detached signature against a `KeyStore`, which holds keys pinned in `signing-keys` and, when `keyservers` is configured, keys fetched on demand by the issuer the signature names. Pinned keys win; a keyserver is asked only for an identifier nothing pinned answers to; with no keyservers configured nothing is fetched at all and an unpinned key reports `signature-missing`.

**A keyserver has a capability of its own.** It is not the repository, so the source's host, confined to the repository's URL, would refuse it; and a route on that host would let every capability built from it -- sources, targets, enumerators, advisors -- read from the keyserver too. So `Hosts::keyserving` builds one capability per keyserver list, permitting exactly those URLs, with no credentials and default TLS and retry, and `MavenSource` asks for keys through it while fetching everything else through its host. Its cache folder is `(keyservers)` under `setup.cache-dir`, a name no host's folder can take.

### Which key may vouch for what

The key material says a signature was made by the holder of a key; it does not say that key is the right one for this artifact. The signing policy (`setup.signing-policy`, or a host's own, which replaces setup's) says that, the way `pgpverify-maven-plugin`'s keys map does: each rule pairs a purl pattern -- a name glob with an optional ecosystem version range, matched as the quarantine policy matches -- with the primary-key fingerprints allowed to vouch for it.

```text
  an artifact the rules cover   vouched for only by the keys they name
  a key the rules name          vouches only where its rules cover
  a key never mentioned         pinned: vouches for everything
                                from a keyserver: for nothing
```

A keyserver supplies material, not trust: it answers with whatever key claims an identifier. So with no signing policy, which is an empty one, every pinned key keeps vouching as before and a keyserver key vouches for nothing until a rule names its fingerprint. **That is a change for a configuration using keyservers**: signatures that used to verify through a keyserver key now report `signature-key-unvouched` until the policy names the key.

The check runs after a signature verifies: the key that made it is found among the candidates, its primary fingerprint read from the material, and the policy asked. A valid signature by a key that may not vouch reports `signature-key-unvouched` -- warn by default, soft quarantine, and configurable in `problem-policy` and the quarantine policy -- apart from `signature-missing` (no key could check it) and `signature-invalid` (it does not verify). Fingerprints must be full: 40 hexadecimal digits for a version 4 key, 64 for version 6. A key id is refused when the file is read, since a key id can be forged where a fingerprint cannot. It covers Maven's detached PGP signatures; npm's registry keys and PyPI's attestations answer to their own trust.

A key that fails expiry or revocation is `SigOutcome::UntrustedKey` -- a third outcome, deliberately not folded into `UnknownKey`. The two are opposite situations that a report must not blur: *unknown* means nothing was available to check against, which is common and often benign; *untrusted* means something **was** available and says, on its own terms, not to rely on it.

- **Revocation** comes from the key material: any revocation signature disqualifies the key. Checked *before* verifying rather than after, so a revoked key producing an arithmetically perfect signature never yields an answer that then has to be discarded.
- **Configured expiry** (`SigningKey.expires`) is a required `core::expiry::Expiry`, the type quarantine rules use: an RFC 3339 timestamp or `never`, written out. A pinned key is a trust anchor somebody placed, so an open-ended one should be a decision written down, not an omitted field. It is parsed at load; an unreadable timestamp is an error, not an absent expiry -- reading `expires: "next tuesday"` as "never expires" would turn a safety setting off at the moment its author believed it was on. `validate-config` logs keys whose date has passed, as information only: such a key still verifies signatures made before it.
- **Material expiry** is the Key Expiration Time the holder stated in the newest verified self-signature of the component that signed; a subkey also lapses with its primary. It is checked after verifying, since it depends on which component signed. The earlier of it and the configured expiry wins.
- For PGP the expiry is judged against **when the signature was made**, not against the clock, which is both more precise and what the configuration already described. A signature made while the key was still trusted stays trusted. A signature carrying no creation time cannot be shown to predate the expiry and is refused -- the same asymmetry the publish window uses.
- npm's `dist.signatures` carry no creation time, so there the clock is the only question the data supports. Weaker, and noted where it happens.
- An untrusted key does not veto a usable one later in the store: a rotated key sits beside its replacement.

**Revocation reason codes are deliberately not consulted.** `key-retired` and `key-compromised` differ in whether past signatures should still count, and answering that means comparing each signature's time against the revocation's. Worth doing, and worth doing deliberately rather than as a guess buried in a helper. Refusing all revocations is the conservative reading and is what happens today.

## The module split

`net/sig.rs` is a declaration file over five modules, along the lines its four test modules already drew:

| | |
| --- | --- |
| `sig/key.rs` | `RegistryKey`, `KeyOrigin`, `SigOutcome` -- the vocabulary |
| `sig/pgp.rs` | detached signatures, issuer identifiers |
| `sig/npm.rs` | ECDSA over the integrity hash |
| `sig/store.rs` | pinned keys first, keyservers second |
| `sig/pinned.rs` | configuration entries to keys |

The split made one dependency visible that was invisible inside one file: **`store` uses `pgp`'s key-identifier rule**, because keyservers are a PGP institution -- a signature names an issuer in one of PGP's several identifier lengths and the store has to decide whether a pinned key answers to it. The two verifiers refer to neither the store nor each other, which is the property worth keeping: a verifier is handed the keys it should use and has no say in where they came from.
