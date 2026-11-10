//! Which PGP keys may vouch for which artifacts.
//!
//! `signing-keys` supplies key material; this file says whose signature
//! counts for what, the way `pgpverify-maven-plugin`'s keys map does.
//!
//! ```text
//!   an artifact the rules cover   vouched for only by the keys they name
//!   a key the rules name          vouches only where its rules cover
//!   a key never mentioned         pinned: vouches for everything
//!                                 fetched from a keyserver: for nothing
//! ```
//!
//! A keyserver supplies material, not trust: it answers with whatever key
//! claims an identifier, so a signature by a key only a keyserver vouched
//! for proves the signer holds that key and not that the key is the
//! project's. An empty policy, which is what no file means, therefore keeps
//! every pinned key working and no keyserver key.

use std::path::Path;

use serde::Deserialize;

use crate::core::error::{Error, Result};
use crate::model::{ArtifactId, Version};
use crate::net::sig::KeyOrigin;

/// The `$schema` a signing policy file must declare.
pub const SIGNING_POLICY_SCHEMA_ID: &str =
    "https://github.com/groboclown/artifact-copy/schema/signing-policy.schema.json";

const SIGNING_POLICY_SCHEMA: &str = include_str!("../../schema/signing-policy.schema.json");

/// How many hexadecimal digits a version 4 and a version 6 fingerprint
/// have.
const FINGERPRINT_LENGTHS: [usize; 2] = [40, 64];

/// A file of key assignments.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SigningPolicy {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,

    #[serde(rename = "$comment")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default)]
    pub comments: Vec<String>,

    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Which keys may vouch for which artifacts.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "$comment")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default)]
    pub comments: Vec<String>,

    /// Which artifacts: a name glob, with an optional version range.
    pub purl: String,

    /// Primary-key fingerprints, normalized to lowercase hex on load.
    pub fingerprints: Vec<String>,

    pub justification: Option<String>,
}

impl SigningPolicy {
    /// Read and validate a policy file.
    ///
    /// A fingerprint that is not 40 or 64 hexadecimal digits is refused
    /// here rather than never matching: a key id pasted by mistake would
    /// otherwise be a rule that quietly vouches for nothing.
    pub fn load(path: &Path) -> Result<Self> {
        let value = super::read_validated(path, SIGNING_POLICY_SCHEMA, "signing policy")?;

        let mut policy: Self = serde_json::from_value(value).map_err(|source| {
            Error::Config(format!(
                "{} is not a usable signing policy: {source}",
                path.display()
            ))
        })?;

        for (at, rule) in policy.rules.iter_mut().enumerate() {
            for fingerprint in &mut rule.fingerprints {
                *fingerprint = fingerprint_of(fingerprint).ok_or_else(|| {
                    Error::Config(format!(
                        "{} rule {}: {fingerprint:?} is not a full key fingerprint of \
                         40 or 64 hexadecimal digits",
                        path.display(),
                        at + 1
                    ))
                })?;
            }
        }

        Ok(policy)
    }

    /// Whether the key with `fingerprint`, which came from `origin`, may
    /// vouch for this artifact.
    pub fn vouches(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        fingerprint: &str,
        origin: KeyOrigin,
    ) -> bool {
        let Some(fingerprint) = fingerprint_of(fingerprint) else {
            return false;
        };

        let ecosystem = crate::ecosystem::open(id.ecosystem().as_str()).ok();

        let mut covered = false;

        for rule in &self.rules {
            if !crate::internal::purl::pattern::covers(
                &rule.purl,
                id,
                version,
                ecosystem.as_deref(),
            ) {
                continue;
            }

            covered = true;

            if rule.fingerprints.contains(&fingerprint) {
                return true;
            }
        }

        // Covered, and by none of this key's rules.
        if covered {
            return false;
        }

        // A key the policy assigns elsewhere is confined to those artifacts.
        if self.mentions(&fingerprint) {
            return false;
        }

        origin == KeyOrigin::Pinned
    }

    fn mentions(&self, fingerprint: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.fingerprints.iter().any(|named| named == fingerprint))
    }
}

/// A fingerprint as lowercase hex, without spaces or a `0x`, or `None` when
/// it is not a full fingerprint.
fn fingerprint_of(text: &str) -> Option<String> {
    let bare: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();

    let full =
        FINGERPRINT_LENGTHS.contains(&bare.len()) && bare.chars().all(|ch| ch.is_ascii_hexdigit());

    full.then_some(bare)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EcosystemId, Release};

    const APACHE: &str = "AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA";
    const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const STRANGER: &str = "cccccccccccccccccccccccccccccccccccccccc";

    fn policy(body: &str) -> Result<SigningPolicy> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-policy.yaml");

        std::fs::write(
            &path,
            format!("$schema: {SIGNING_POLICY_SCHEMA_ID}\n{body}"),
        )
        .expect("written");

        SigningPolicy::load(&path)
    }

    fn apache_policy() -> SigningPolicy {
        policy(&format!(
            "rules:\n  - purl: pkg:maven/org.apache.*/*\n    fingerprints: [\"{APACHE}\"]\n"
        ))
        .expect("loads")
    }

    fn maven(group: &str, name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some(group), name)
    }

    fn vouches(policy: &SigningPolicy, id: &ArtifactId, key: &str, origin: KeyOrigin) -> bool {
        policy.vouches(
            id,
            Some(&Version::new("1.0", Release::General)),
            key,
            origin,
        )
    }

    /// A covered artifact is vouched for by its key, spelled any way.
    #[test]
    fn artifact_covered_takes_key() {
        let policy = apache_policy();
        let lang = maven("org.apache.commons", "commons-lang3");

        assert!(vouches(&policy, &lang, APACHE, KeyOrigin::Pinned));
        assert!(vouches(
            &policy,
            &lang,
            &APACHE.replace(' ', "").to_lowercase(),
            KeyOrigin::Keyserver
        ));
    }

    /// And by no other, pinned or not.
    #[test]
    fn artifact_covered_refuses_other_keys() {
        let policy = apache_policy();
        let lang = maven("org.apache.commons", "commons-lang3");

        assert!(!vouches(&policy, &lang, OTHER, KeyOrigin::Pinned));
    }

    /// A key the policy assigns is confined to its artifacts.
    #[test]
    fn key_assigned_confined() {
        let policy = apache_policy();

        assert!(!vouches(
            &policy,
            &maven("com.example", "lib"),
            APACHE,
            KeyOrigin::Pinned
        ));
    }

    /// An uncovered artifact: a pinned key never mentioned vouches, a
    /// keyserver key does not.
    #[test]
    fn key_unmentioned_follows_origin() {
        let policy = apache_policy();
        let lib = maven("com.example", "lib");

        assert!(vouches(&policy, &lib, STRANGER, KeyOrigin::Pinned));
        assert!(!vouches(&policy, &lib, STRANGER, KeyOrigin::Keyserver));
    }

    /// No file is an empty policy: every pinned key works, no keyserver
    /// key does.
    #[test]
    fn policy_empty_trusts_pins_only() {
        let policy = SigningPolicy::default();
        let lib = maven("com.example", "lib");

        assert!(vouches(&policy, &lib, STRANGER, KeyOrigin::Pinned));
        assert!(!vouches(&policy, &lib, STRANGER, KeyOrigin::Keyserver));
    }

    /// A version range covers only the versions it names.
    #[test]
    fn version_range_honored() {
        let policy = policy(&format!(
            "rules:\n  - purl: \"pkg:maven/com.example/lib@[2.0,)\"\n    fingerprints: [\"{OTHER}\"]\n"
        ))
        .expect("loads");
        let lib = maven("com.example", "lib");

        let at = |text: &str| {
            policy.vouches(
                &lib,
                Some(&Version::new(text, Release::General)),
                OTHER,
                KeyOrigin::Keyserver,
            )
        };

        assert!(at("2.1"));
        assert!(!at("1.9"));
    }

    /// A key id where a fingerprint belongs is refused on load.
    #[test]
    fn key_short_id_refused() {
        let refused = policy(
            "rules:\n  - purl: pkg:maven/com.example/lib\n    fingerprints: [\"0123456789abcdef0123456789abcdef01234567x\"]\n",
        );

        assert!(refused.is_err());

        assert!(fingerprint_of("0x0123456789ABCDEF").is_none());
    }

    #[test]
    fn committed_schema_compiles() {
        let schema: serde_json::Value =
            serde_json::from_str(SIGNING_POLICY_SCHEMA).expect("parses");

        jsonschema::validator_for(&schema).expect("compiles");
    }
}
