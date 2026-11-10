//! What a source checks signatures against.
//!
//! References: [Sigstore](https://docs.sigstore.dev/).

use std::sync::Arc;

use crate::ext::ExtHost;
use crate::net::sig::KeyStore;
use crate::net::sig::sigstore::{RootSource, SigstoreRoot};
use crate::policy::SigningPolicy;

/// What a source checks signatures against: the PGP keys for its host,
/// where keyservers are asked for more, and the run's Sigstore trust root.
///
/// One value rather than several parameters, so a signature scheme added
/// later is a field here rather than a change to every constructor that
/// passes trust along.
pub struct Trust {
    pub keys: KeyStore,

    /// The capability keyservers are reached through, apart from the
    /// source's host; `None` when no keyserver is configured.
    pub keyservers: Option<Arc<dyn ExtHost>>,

    pub sigstore: Arc<SigstoreRoot>,

    /// Which PGP keys may vouch for which artifacts.
    pub signing: Arc<SigningPolicy>,
}

impl Trust {
    /// No pinned keys, no keyservers, and Sigstore's root fetched when first
    /// needed.
    pub fn untrusting() -> Self {
        Self {
            keys: KeyStore::new(Vec::new()),
            keyservers: None,
            sigstore: Arc::new(SigstoreRoot::new(RootSource::Tuf(None))),
            signing: Arc::new(SigningPolicy::default()),
        }
    }
}
