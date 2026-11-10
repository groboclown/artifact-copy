//! Turning configured `signing-keys` entries into verifying keys.
//!
//! The bridge from `config` to [`RegistryKey`], and the only part of `sig`
//! that reads a secret. Its rules are about **reporting**, not
//! cryptography: an error names the entry rather than the value, and an
//! unknown name is refused rather than skipped, because silently verifying
//! against fewer keys than the user listed looks like a passing run while
//! checking less than was asked for.

use crate::core::error::{Error, Result};

use super::key::RegistryKey;

/// Resolve the keys a host has pinned, in configuration order.
///
/// Errors name the entry rather than the value: a misspelled environment
/// variable should say which key could not be read, and never what it
/// nearly read.
///
/// An unknown name is an error rather than a skip. Silently verifying
/// against fewer keys than the user listed is the failure mode worth
/// avoiding here -- it would look like a passing run while checking less
/// than was asked for.
pub fn resolve_pinned(
    named: &[String],
    available: &std::collections::BTreeMap<String, crate::config::SigningKey>,
    scheme: crate::config::SigningScheme,
) -> Result<Vec<RegistryKey>> {
    let mut keys = Vec::new();

    for name in named {
        let entry = available.get(name).ok_or_else(|| {
            Error::Config(format!(
                "no signing key named {name:?} is configured; \
                 add it to the signing-keys collection"
            ))
        })?;

        // A host may pin keys for several schemes at once; each verifier
        // takes the ones it can actually check.
        if entry.scheme != scheme {
            continue;
        }

        let value = entry.value.resolve().map_err(|err| {
            Error::Config(format!(
                "signing key {name:?} ({}): {err}",
                entry.value.describe()
            ))
        })?;

        let mut key = RegistryKey::pinned(entry.key_id.clone(), value.expose().to_owned());

        if let Some(when) = entry.expires.at() {
            key = key.expiring(when);
        }

        keys.push(key);
    }

    Ok(keys)
}

#[cfg(test)]
mod pinned_tests {
    use super::*;
    use crate::config::{Comments, SecretValue, SigningKey, SigningScheme};
    use crate::core::expiry::Expiry;
    use crate::net::sig::KeyOrigin;
    use std::collections::BTreeMap;

    fn entry(scheme: SigningScheme, key_id: &str, value: SecretValue) -> SigningKey {
        SigningKey {
            comments: Comments::default(),
            scheme,
            key_id: key_id.to_owned(),
            value,
            citation_url: None,
            expires: Expiry::Never,
        }
    }

    fn inline(text: &str) -> SecretValue {
        SecretValue::Text {
            value: text.to_owned(),
        }
    }

    fn available() -> BTreeMap<String, SigningKey> {
        BTreeMap::from([
            (
                "npmjs".to_owned(),
                entry(SigningScheme::NpmEcdsa, "SHA256:abc", inline("MFkwEwYH")),
            ),
            (
                "central".to_owned(),
                entry(SigningScheme::Pgp, "BCF4173197ABD5AE", inline("-----BEGIN")),
            ),
        ])
    }

    #[test]
    fn key_named_resolves() {
        let keys = resolve_pinned(&["npmjs".to_owned()], &available(), SigningScheme::NpmEcdsa)
            .expect("resolved");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].keyid, "SHA256:abc");
        assert_eq!(keys[0].key, "MFkwEwYH");
    }

    /// A pinned key is distinguishable from a fetched one for reporting,
    /// and identical to it for verification.
    #[test]
    fn key_resolved_records_pinned() {
        let keys = resolve_pinned(&["npmjs".to_owned()], &available(), SigningScheme::NpmEcdsa)
            .expect("resolved");

        assert_eq!(keys[0].origin, KeyOrigin::Pinned);
        assert_eq!(RegistryKey::published("k", "v").origin, KeyOrigin::Registry);
    }

    /// A host may pin keys for several schemes at once; each verifier takes
    /// only the ones it can actually check.
    #[test]
    fn key_for_other_scheme_left_alone() {
        let named = vec!["npmjs".to_owned(), "central".to_owned()];

        let npm = resolve_pinned(&named, &available(), SigningScheme::NpmEcdsa).expect("resolved");
        let pgp = resolve_pinned(&named, &available(), SigningScheme::Pgp).expect("resolved");

        assert_eq!(npm.len(), 1);
        assert_eq!(npm[0].keyid, "SHA256:abc");

        assert_eq!(pgp.len(), 1);
        assert_eq!(pgp[0].keyid, "BCF4173197ABD5AE");
    }

    /// Verifying against fewer keys than were asked for would look like a
    /// passing run while checking less than the user requested.
    #[test]
    fn key_unknown_name_is_error() {
        let err = resolve_pinned(&["typo".to_owned()], &available(), SigningScheme::NpmEcdsa)
            .expect_err("should be refused");

        assert!(err.to_string().contains("typo"), "{err}");
        assert!(err.to_string().contains("signing-keys"), "{err}");
    }

    /// The error has to name the entry so the user can fix it, and must not
    /// leak what it nearly read.
    #[test]
    fn key_unreadable_names_entry_not_value() {
        let broken = BTreeMap::from([(
            "npmjs".to_owned(),
            entry(
                SigningScheme::NpmEcdsa,
                "SHA256:abc",
                SecretValue::Env {
                    name: "DEFINITELY_NOT_SET_FOR_THIS_TEST".to_owned(),
                },
            ),
        )]);

        let err = resolve_pinned(&["npmjs".to_owned()], &broken, SigningScheme::NpmEcdsa)
            .expect_err("should be refused");

        let text = err.to_string();

        assert!(text.contains("npmjs"), "{text}");
        assert!(text.contains("DEFINITELY_NOT_SET_FOR_THIS_TEST"), "{text}");
    }

    /// The material may live outside the config file entirely, which is
    /// what lets an organization keep it under secret management.
    #[test]
    fn key_from_environment() {
        let name = "ARTIFACT_COPY_TEST_SIGNING_KEY";

        // SAFETY: single-threaded test, and the variable is unique to it.
        unsafe { std::env::set_var(name, "from-the-environment") };

        let stored = BTreeMap::from([(
            "npmjs".to_owned(),
            entry(
                SigningScheme::NpmEcdsa,
                "SHA256:abc",
                SecretValue::Env {
                    name: name.to_owned(),
                },
            ),
        )]);

        let keys = resolve_pinned(&["npmjs".to_owned()], &stored, SigningScheme::NpmEcdsa)
            .expect("resolved");

        assert_eq!(keys[0].key, "from-the-environment");

        unsafe { std::env::remove_var(name) };
    }

    /// A key is never printed, so a stray `{:?}` cannot dump a keyring.
    #[test]
    fn key_redacted_in_debug() {
        let rendered = format!("{:?}", inline("MFkwEwYHsecret"));

        assert!(!rendered.contains("MFkwEwYHsecret"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn key_none_pinned_resolves_nothing() {
        assert!(
            resolve_pinned(&[], &available(), SigningScheme::NpmEcdsa)
                .expect("resolved")
                .is_empty()
        );
    }

    /// The configured expiry reaches the key, which is what makes it
    /// enforceable at all.
    #[test]
    fn expiry_configured_carried_onto_key() {
        let mut entry = entry(SigningScheme::Pgp, "ABCD", inline("material"));
        entry.expires = Expiry::At(
            chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
                .expect("valid")
                .with_timezone(&chrono::Utc),
        );

        let available = BTreeMap::from([("legacy".to_owned(), entry)]);

        let keys = resolve_pinned(&["legacy".to_owned()], &available, SigningScheme::Pgp)
            .expect("resolves");

        assert_eq!(
            keys[0].expires,
            Some(
                chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
                    .expect("valid")
                    .with_timezone(&chrono::Utc)
            )
        );
    }

    /// `never` means no expiry enforced here, not an expiry of zero.
    #[test]
    fn expiry_never_leaves_key_unbounded() {
        let available = BTreeMap::from([(
            "k".to_owned(),
            entry(SigningScheme::Pgp, "ABCD", inline("material")),
        )]);

        let keys =
            resolve_pinned(&["k".to_owned()], &available, SigningScheme::Pgp).expect("resolves");

        assert!(keys[0].expires.is_none());
    }

    /// A timestamp that does not parse is refused at load, not read as
    /// `never`. Reading `expires: "next tuesday"` as "never expires" would
    /// turn a safety setting off at the moment its author believed it was on.
    #[test]
    fn expiry_unreadable_refused() {
        let err = serde_json::from_value::<SigningKey>(serde_json::json!({
            "scheme": "pgp",
            "key-id": "ABCD",
            "value": { "kind": "text", "value": "material" },
            "expires": "next tuesday",
        }))
        .expect_err("not a timestamp");

        assert!(err.to_string().contains("RFC 3339"), "{err}");
    }

    /// Omitting it is refused: a trust anchor with no end date has to be a
    /// decision somebody wrote down.
    #[test]
    fn expiry_required() {
        let err = serde_json::from_value::<SigningKey>(serde_json::json!({
            "scheme": "pgp",
            "key-id": "ABCD",
            "value": { "kind": "text", "value": "material" },
        }))
        .expect_err("expires is required");

        assert!(err.to_string().contains("expires"), "{err}");
    }
}
