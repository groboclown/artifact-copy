//! Signature verification.
//!
//! Coverage is genuinely uneven across ecosystems, and pretending otherwise
//! would be worse than saying so:
//!
//! | Ecosystem | Scheme | Needs the payload? | Where |
//! | --- | --- | --- | --- |
//! | npm | ECDSA P-256 over `name@version:integrity` | **No** | [`npm`] |
//! | Maven | detached PGP in a sibling `.asc` | Yes | [`pgp`] |
//! | PyPI | none since GPG was removed in 2023 | -- | -- |
//!
//! npm is the useful case here: the signature covers the *integrity hash*
//! rather than the bytes, so a registry's own claim about a tarball can be
//! checked from metadata alone -- which is exactly what `inspect` has.
//!
//! # The shape of this module
//!
//! Two schemes that share nothing but a vocabulary, and three ways to get
//! a key. They split along that seam:
//!
//! ```text
//!   key      RegistryKey, KeyOrigin, SigOutcome   what a key is
//!    +- pgp     detached signatures, issuer ids   scheme
//!    +- npm     ECDSA over the integrity hash     scheme
//!    +- store   pinned first, then keyservers     where keys come from
//!    `- pinned  config entries to keys            where keys come from
//! ```
//!
//! [`pgp`] and [`npm`] do not refer to each other, and neither refers to
//! [`store`] or [`pinned`] -- a verifier is handed the keys it should use
//! and has no say in where they came from. That is deliberate: the decision
//! about how much a key is worth belongs to whoever assembled the list.
//!
//! The one edge that does cross is [`store`] borrowing `pgp`'s key
//! identifier rule, because keyservers are a PGP institution: a signature
//! names an issuer in one of PGP's several identifier lengths, and the
//! store has to decide whether a pinned key answers to it.
//!
//! This module declares nothing of its own.

mod key;
mod npm;
mod pgp;
mod pinned;
pub mod sigstore;
mod store;

pub(crate) use key::code_for;
pub use key::{KeyOrigin, RegistryKey, SigOutcome, Untrusted};
pub(crate) use npm::{sri_to_digest, verify_npm};
pub(crate) use pgp::{detached_armor, fingerprint_of, issuers_of, verify_pgp, verify_pgp_file};
pub(crate) use pinned::resolve_pinned;
pub use store::KeyStore;
