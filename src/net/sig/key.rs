//! What a verifying key is, and what checking one against a signature can
//! conclude.
//!
//! The vocabulary the rest of `sig` is written in: no verification happens
//! here, and nothing here knows about PGP or ECDSA.
//!
//! The one decision worth restating is that a key's **origin is recorded
//! and never acted on**. A pinned key and a fetched key verify identically
//! -- verification must not behave differently depending on where the trust
//! anchor came from -- but a report that could not tell them apart would be
//! hiding a real difference in strength.
//!
//! **Trustworthiness is a different question from origin, and is acted
//! on.** A revoked or expired key is refused whatever it came from.

use chrono::{DateTime, Utc};

/// A public key used to verify a registry's signatures.
///
/// Either fetched from the registry's own key endpoint or pinned in
/// configuration; once resolved the two are indistinguishable, which is
/// deliberate -- verification should not behave differently depending on
/// where the trust anchor came from. Where it came from is recorded in
/// [`RegistryKey::origin`] for reporting, not for logic.
#[derive(Debug, Clone)]
pub struct RegistryKey {
    pub keyid: String,
    pub key: String,
    pub origin: KeyOrigin,

    /// When the **configuration** says this key stops being trusted.
    ///
    /// Set only for a pinned key, because it is the user's statement and
    /// nothing else can make it. It is *not* the key's own expiry, which
    /// is carried inside the key material and checked separately -- a user
    /// may distrust a key earlier than its holder does, and the earlier of
    /// the two wins.
    pub expires: Option<DateTime<Utc>>,
}

/// Where a verifying key came from.
///
/// Recorded for the report, never for the verification logic -- but the
/// three are not equally strong, and a report that could not tell them
/// apart would be hiding the difference. A pinned key is a trust anchor the
/// user placed. A registry key is whatever the host serving the artifacts
/// also says about its own signatures. A keyserver key is whatever a third
/// party returned for an identifier the signature itself supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Published by the registry at its key endpoint.
    Registry,

    /// Supplied by the user in configuration.
    Pinned,

    /// Fetched from a configured keyserver.
    Keyserver,
}

impl RegistryKey {
    /// A key as published by a registry.
    pub fn published(keyid: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            keyid: keyid.into(),
            key: key.into(),
            origin: KeyOrigin::Registry,
            expires: None,
        }
    }

    /// A key the user pinned in configuration.
    pub fn pinned(keyid: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            keyid: keyid.into(),
            key: key.into(),
            origin: KeyOrigin::Pinned,
            expires: None,
        }
    }

    /// Stop trusting this key at `when`.
    pub fn expiring(mut self, when: DateTime<Utc>) -> Self {
        self.expires = Some(when);
        self
    }

    /// A key fetched from a keyserver.
    pub fn from_keyserver(keyid: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            keyid: keyid.into(),
            key: key.into(),
            origin: KeyOrigin::Keyserver,
            expires: None,
        }
    }
}

/// Outcome of checking one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigOutcome {
    Valid,

    /// The registry signed with a key it does not publish.  Not a forgery on
    /// its own -- keys get rotated -- but not proof of anything either.
    UnknownKey,

    /// A key claiming the signature exists and may not be trusted to vouch
    /// for it.
    ///
    /// Separate from [`SigOutcome::UnknownKey`] because the two are
    /// opposite situations that a report must not blur. *Unknown* means
    /// nothing was available to check against, which is common and often
    /// benign. *Untrusted* means something **was** available and it says,
    /// on its own terms, not to rely on it.
    UntrustedKey(Untrusted),
}

/// Why a key that claimed a signature may not vouch for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Untrusted {
    /// The key carries a revocation signature: its holder has disavowed
    /// it.
    ///
    /// Outranks [`Untrusted::Expired`] in reporting. An expiry is a plan
    /// made in advance; a revocation is a statement made after something
    /// happened, and is the more urgent of the two to put in front of a
    /// person.
    Revoked,

    /// The key had stopped being trusted before the signature was made.
    ///
    /// For PGP that is judged against the signature's own creation time
    /// rather than against the clock, which is the more precise question
    /// and the one the configuration describes: a signature made while the
    /// key was still good stays good. Schemes whose signatures carry no
    /// timestamp fall back to the clock.
    Expired,
}

/// The problem code a reason reports under.
///
/// Two codes rather than one, because a policy has to be able to answer
/// them differently: a revoked key is a statement made after something
/// happened, and an expired one is a plan that lapsed. Folding them
/// together would mean a user who wants to tolerate the second also
/// tolerating the first.
pub fn code_for(reason: Untrusted) -> crate::core::problem::Code {
    use crate::core::problem::Code;

    match reason {
        Untrusted::Revoked => Code::SignatureKeyRevoked,
        Untrusted::Expired => Code::SignatureKeyExpired,
    }
}

impl Untrusted {
    pub fn as_str(self) -> &'static str {
        match self {
            Untrusted::Revoked => "revoked",
            Untrusted::Expired => "expired",
        }
    }
}
