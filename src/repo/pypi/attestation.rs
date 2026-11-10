//! Verifying PEP 740 attestations.
//!
//! A file's provenance object holds one bundle per publisher, each with
//! the attestations that publisher made. Every attestation is checked, and
//! the file passes only if all of them do:
//!
//! ```text
//!   statement   names this file, with this file's sha256
//!   signature   a Sigstore bundle that verifies: certificate chain,
//!               transparency log, DSSE signature, subject digest
//!   signer      the certificate's identity is the publisher the
//!               provenance names -- PyPI's Trusted Publisher, which it
//!               checked when the file was uploaded
//! ```
//!
//! An attestation is not quite a Sigstore bundle, so each is rewritten as
//! one first, as the `pypi-attestations` library does; the cryptography is
//! [`crate::net::sig::sigstore`]'s.
//!
//! References: [PEP 740](https://peps.python.org/pep-0740/), [Sigstore](https://docs.sigstore.dev/).

use base64::Engine as _;
use serde::Deserialize;

use crate::net::ByteLimit;
use crate::net::sig::sigstore::{Failure, Signer, SigstoreRoot};

/// What a provenance object may weigh. One attestation is a few kilobytes
/// of Sigstore bundle, and a file carries one or two.
pub(super) const PROVENANCE_LIMIT: ByteLimit = ByteLimit::mib(1);

/// The bundle format an attestation is rewritten into.
const BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// What a PEP 740 envelope's payload is.
const STATEMENT_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The OIDC issuer each Trusted Publisher kind signs through.
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITLAB_ISSUER: &str = "https://gitlab.com";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// What became of one file's attestations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Every attestation verified and was signed by its publisher.
    Verified,

    /// An attestation did not verify, named another file, or was signed by
    /// someone other than its publisher.
    Invalid(String),

    /// The signatures verified, and the publisher is of a kind whose
    /// identity this tool does not know how to match.
    UnknownPublisher(String),

    /// Nothing could be checked: the trust root would not load.
    Unchecked(String),

    /// The provenance object is not one.
    Malformed(String),
}

#[derive(Debug, Deserialize)]
struct Provenance {
    attestation_bundles: Vec<AttestationBundle>,
}

#[derive(Debug, Deserialize)]
struct AttestationBundle {
    publisher: Publisher,
    attestations: Vec<Attestation>,
}

/// The Trusted Publisher an attestation bundle names.
///
/// The fields that decide the signer's identity; the rest of each kind's
/// object is ignored.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
enum Publisher {
    GitHub {
        repository: String,
        workflow: String,
    },
    GitLab {
        repository: String,
        workflow_filepath: String,
    },
    Google {
        email: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct Attestation {
    verification_material: VerificationMaterial,
    envelope: Envelope,
}

#[derive(Debug, Deserialize)]
struct VerificationMaterial {
    certificate: String,
    transparency_entries: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    statement: String,
    signature: String,
}

/// The part of an in-toto statement that names what it is about.
#[derive(Debug, Deserialize)]
struct Statement {
    subject: Vec<Subject>,
}

#[derive(Debug, Deserialize)]
struct Subject {
    name: String,

    #[serde(default)]
    digest: std::collections::BTreeMap<String, String>,
}

/// Check every attestation in `provenance` for the file `filename` whose
/// sha256 is `sha256`.
pub(super) async fn verify(
    root: &SigstoreRoot,
    provenance: &[u8],
    filename: &str,
    sha256: &str,
) -> Verdict {
    let provenance: Provenance = match serde_json::from_slice(provenance) {
        Ok(provenance) => provenance,
        Err(err) => return Verdict::Malformed(err.to_string()),
    };

    let mut unknown = None;
    let mut checked = 0;

    for bundle in &provenance.attestation_bundles {
        for attestation in &bundle.attestations {
            checked += 1;

            if let Err(reason) = names_file(attestation, filename, sha256) {
                return Verdict::Invalid(reason);
            }

            let signer = match root.verify(&to_bundle(attestation), sha256).await {
                Ok(signer) => signer,
                Err(Failure::Root(reason)) => return Verdict::Unchecked(reason),
                Err(Failure::Invalid(reason)) => return Verdict::Invalid(reason),
            };

            match signed_by(&bundle.publisher, &signer) {
                Some(Ok(())) => {}
                Some(Err(reason)) => return Verdict::Invalid(reason),
                None => unknown = Some(signer.identity),
            }
        }
    }

    if checked == 0 {
        return Verdict::Malformed("it holds no attestations".to_owned());
    }

    match unknown {
        Some(identity) => Verdict::UnknownPublisher(identity),
        None => Verdict::Verified,
    }
}

/// An attestation as the Sigstore bundle it stands for.
fn to_bundle(attestation: &Attestation) -> String {
    serde_json::json!({
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "certificate": {"rawBytes": attestation.verification_material.certificate},
            "tlogEntries": attestation.verification_material.transparency_entries,
        },
        "dsseEnvelope": {
            "payload": attestation.envelope.statement,
            "payloadType": STATEMENT_PAYLOAD_TYPE,
            "signatures": [{"sig": attestation.envelope.signature}],
        },
    })
    .to_string()
}

/// Whether the statement is about this file: its name and its sha256.
///
/// The digest alone would verify, and would let a statement about one
/// distribution stand for another with the same bytes under a different
/// name.
fn names_file(attestation: &Attestation, filename: &str, sha256: &str) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&attestation.envelope.statement)
        .map_err(|err| format!("the statement is not base64: {err}"))?;

    let statement: Statement =
        serde_json::from_slice(&bytes).map_err(|err| format!("the statement: {err}"))?;

    let named = statement.subject.iter().any(|subject| {
        same_filename(&subject.name, filename)
            && subject
                .digest
                .get("sha256")
                .is_some_and(|hex| hex.eq_ignore_ascii_case(sha256))
    });

    match named {
        true => Ok(()),
        false => Err(format!(
            "its statement does not name {filename} with sha256 {sha256}"
        )),
    }
}

/// Distribution filenames compare case-insensitively, with `-` and `_`
/// the same: an index may normalize a project name either way.
fn same_filename(left: &str, right: &str) -> bool {
    let normal = |name: &str| name.to_ascii_lowercase().replace('-', "_");

    normal(left) == normal(right)
}

/// Whether `signer` is the publisher named, or `None` for a publisher kind
/// this does not know how to match.
///
/// ```text
///   GitHub  https://github.com/{repository}/.github/workflows/{workflow}@{ref}
///   GitLab  https://gitlab.com/{repository}//{workflow_filepath}@{ref}
///   Google  the account's email
/// ```
fn signed_by(publisher: &Publisher, signer: &Signer) -> Option<Result<(), String>> {
    let (issuer, matches, expected) = match publisher {
        Publisher::GitHub {
            repository,
            workflow,
        } => {
            let prefix = format!("https://github.com/{repository}/.github/workflows/{workflow}@");
            let matches = starts_with_ignoring_case(&signer.identity, &prefix);

            (GITHUB_ISSUER, matches, prefix)
        }

        Publisher::GitLab {
            repository,
            workflow_filepath,
        } => {
            let prefix = format!("https://gitlab.com/{repository}//{workflow_filepath}@");
            let matches = starts_with_ignoring_case(&signer.identity, &prefix);

            (GITLAB_ISSUER, matches, prefix)
        }

        Publisher::Google { email } => (
            GOOGLE_ISSUER,
            signer.identity.eq_ignore_ascii_case(email),
            email.clone(),
        ),

        Publisher::Other => return None,
    };

    if signer.issuer != issuer {
        return Some(Err(format!(
            "it was signed through {}, not {issuer}",
            signer.issuer
        )));
    }

    match matches {
        true => Some(Ok(())),
        false => Some(Err(format!(
            "it was signed by {}, not its publisher {expected}",
            signer.identity
        ))),
    }
}

/// GitHub and GitLab paths compare case-insensitively.
fn starts_with_ignoring_case(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::sig::sigstore;

    /// Captured from pypi.org for `sampleproject` 4.0.0's wheel, published
    /// from GitHub Actions under the `pypa/sampleproject` Trusted
    /// Publisher.
    const PROVENANCE: &str = include_str!("testdata/sampleproject-4.0.0-provenance.json");

    const WHEEL: &str = "sampleproject-4.0.0-py3-none-any.whl";
    const WHEEL_SHA256: &str = "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b";

    /// The provenance with its publisher replaced.
    fn published_by(publisher: serde_json::Value) -> Vec<u8> {
        let mut provenance: serde_json::Value = serde_json::from_str(PROVENANCE).expect("json");
        provenance["attestation_bundles"][0]["publisher"] = publisher;

        serde_json::to_vec(&provenance).expect("json")
    }

    #[tokio::test]
    async fn real_attestation_verifies() {
        let verdict = verify(
            &sigstore::embedded(),
            PROVENANCE.as_bytes(),
            WHEEL,
            WHEEL_SHA256,
        )
        .await;

        assert_eq!(verdict, Verdict::Verified);
    }

    /// Another file's bytes: the statement does not name them.
    #[tokio::test]
    async fn other_bytes_invalid() {
        let verdict = verify(
            &sigstore::embedded(),
            PROVENANCE.as_bytes(),
            WHEEL,
            &"00".repeat(32),
        )
        .await;

        assert!(matches!(verdict, Verdict::Invalid(_)), "{verdict:?}");
    }

    /// The same bytes under another name are not what the statement is
    /// about.
    #[tokio::test]
    async fn other_name_invalid() {
        let verdict = verify(
            &sigstore::embedded(),
            PROVENANCE.as_bytes(),
            "sampleproject-4.0.0.tar.gz",
            WHEEL_SHA256,
        )
        .await;

        assert!(matches!(verdict, Verdict::Invalid(_)), "{verdict:?}");
    }

    /// A valid signature by someone other than the named publisher.
    #[tokio::test]
    async fn publisher_other_invalid() {
        let provenance = published_by(serde_json::json!({
            "kind": "GitHub", "repository": "attacker/sampleproject", "workflow": "release.yml",
        }));

        let verdict = verify(&sigstore::embedded(), &provenance, WHEEL, WHEEL_SHA256).await;

        assert!(
            matches!(verdict, Verdict::Invalid(ref why) if why.contains("attacker")),
            "{verdict:?}"
        );
    }

    /// A publisher kind with no identity rule: the signature still has to
    /// verify, and the verdict says the signer went unmatched.
    #[tokio::test]
    async fn publisher_unknown_reported() {
        let provenance =
            published_by(serde_json::json!({"kind": "ActiveState", "organization": "x"}));

        let verdict = verify(&sigstore::embedded(), &provenance, WHEEL, WHEEL_SHA256).await;

        assert!(
            matches!(verdict, Verdict::UnknownPublisher(_)),
            "{verdict:?}"
        );
    }

    #[tokio::test]
    async fn provenance_malformed_reported() {
        for provenance in [&b"not json"[..], br#"{"attestation_bundles": []}"#] {
            let verdict = verify(&sigstore::embedded(), provenance, WHEEL, WHEEL_SHA256).await;

            assert!(matches!(verdict, Verdict::Malformed(_)), "{verdict:?}");
        }
    }

    /// A root that will not load checks nothing, and says so apart from a
    /// signature that failed.
    #[tokio::test]
    async fn root_unloadable_unchecked() {
        let root = SigstoreRoot::new(sigstore::RootSource::File("/no/such/root.json".into()));

        let verdict = verify(&root, PROVENANCE.as_bytes(), WHEEL, WHEEL_SHA256).await;

        assert!(matches!(verdict, Verdict::Unchecked(_)), "{verdict:?}");
    }

    #[test]
    fn filenames_compare_normalized() {
        assert!(same_filename(
            "Sample_Project-1.0.tar.gz",
            "sample-project-1.0.tar.gz"
        ));
        assert!(!same_filename(
            "sampleproject-1.0.tar.gz",
            "sampleproject-1.1.tar.gz"
        ));
    }
}
