//! Where keys come from at verification time.
//!
//! Two sources in strict order, and the order is the policy: pinned keys
//! first, keyservers only for an identifier nothing pinned answers to.
//! Fetching a key in order to check a signature is much weaker than
//! checking against a key someone decided to trust, so the weaker route is
//! opt-in and is never reached while the stronger one has an answer.

use crate::cache::Coalesced;
use crate::net::{ByteLimit, Fetch, Req, normalized_base};

use super::key::RegistryKey;

// The store's identifier matching is PGP's, because keyservers are: a
// signature names a key id in one of PGP's several lengths and the
// configuration may hold another. See [`super::pgp::key_id_matches`].
use super::pgp::key_id_matches;

/// The keys available for checking PGP signatures, and where to look for
/// more.
///
/// Two sources, in strict order:
///
/// 1. **Pinned keys** from `signing-keys`. Trust anchors the user placed,
///    and the only ones available when a PKI has been retired.
/// 2. **Keyservers**, when configured. A signature names its issuer, so a
///    key can be fetched on demand for an identifier the signature itself
///    supplied.
///
/// The order is not arbitrary. A keyserver lookup is *opt-in* and is asked
/// only for a key nothing pinned answers to, because fetching a key to
/// check a signature is much weaker than checking against a key someone
/// decided to trust: at best it proves the signature was made by whoever
/// holds that key, not that the key is the right one. Some ecosystems ship
/// their own keyring references -- a Debian archive keyring, for instance --
/// and those belong in the same list.
///
/// With no keyservers configured, nothing is fetched and an unpinned key is
/// [`super::key::SigOutcome::UnknownKey`].
#[derive(Debug)]
pub struct KeyStore {
    pinned: Vec<RegistryKey>,
    servers: Vec<String>,

    /// Keys already fetched, keyed by issuer.
    ///
    /// Artifact enumeration over a catalog meets the same handful of
    /// signing keys over and over -- one project signs every one of its
    /// artifacts -- so this turns a lookup per artifact into a lookup per
    /// key. [`Coalesced`] also collapses concurrent misses, which matters
    /// because a worker pool reaches those artifacts at the same moment.
    fetched: Coalesced<Vec<RegistryKey>>,
}

/// How many distinct signing keys to remember.
const KEY_CACHE: usize = 64;

/// An armored public key is a few kilobytes; a keyring bundle rather more.
const KEY_LIMIT: ByteLimit = ByteLimit::kib(512);

impl KeyStore {
    pub fn new(pinned: Vec<RegistryKey>) -> Self {
        Self {
            pinned,
            servers: Vec::new(),
            fetched: Coalesced::new(KEY_CACHE),
        }
    }

    /// Consult these keyservers for keys nothing pinned answers to.
    ///
    /// Each is an HKP base URL, such as `https://keys.openpgp.org`.
    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        self.servers = servers;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty() && self.servers.is_empty()
    }

    /// The keys that might have issued a signature.
    ///
    /// Pinned keys that match come back alone: having decided which key to
    /// trust for an identifier, there is nothing to gain from also asking a
    /// keyserver what *it* thinks that identifier means.
    ///
    /// Takes a [`Fetch`] rather than a host so that `net` does not name
    /// `ext`; callers pass an `ext::HostFetch`.
    pub async fn keys_for(&self, issuers: &[String], fetch: &dyn Fetch) -> Vec<RegistryKey> {
        let matching: Vec<RegistryKey> = self
            .pinned
            .iter()
            .filter(|key| {
                issuers.is_empty()
                    || issuers
                        .iter()
                        .any(|issuer| key_id_matches(&key.keyid, issuer))
            })
            .cloned()
            .collect();

        if !matching.is_empty() || self.servers.is_empty() {
            return matching;
        }

        let mut fetched = Vec::new();

        for issuer in issuers {
            fetched.extend(self.lookup(issuer, fetch).await);
        }

        fetched
    }

    /// Ask each configured keyserver for one identifier, in order.
    async fn lookup(&self, issuer: &str, fetch: &dyn Fetch) -> Vec<RegistryKey> {
        let found = self
            .fetched
            .get_or_try_init(issuer, || async {
                for server in &self.servers {
                    // The HKP machine-readable form, which every keyserver
                    // worth querying speaks.
                    let url = format!(
                        "{}/pks/lookup?op=get&options=mr&search=0x{issuer}",
                        normalized_base(server)
                    );

                    let Ok(bytes) = fetch.fetch(&Req::get(&url), KEY_LIMIT).await else {
                        continue;
                    };

                    let armored = String::from_utf8_lossy(&bytes).trim().to_owned();

                    if !armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
                        continue;
                    }

                    return Ok(vec![RegistryKey::from_keyserver(issuer, armored)]);
                }

                // Nothing found is a real answer and worth remembering, so
                // artifact enumeration does not re-ask every keyserver per
                // artifact.
                Ok(Vec::new())
            })
            .await;

        found.map(|keys| (*keys).clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod key_store_tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::net::sig::KeyOrigin;

    // A real `HostFetch` on purpose: the production signature takes
    // `&dyn Fetch` so that `net` does not name `ext`, and these tests are
    // what prove a `HostFetch` still satisfies it.
    use crate::ext::HostFetch;
    use crate::ext::testing::TestHost;
    use crate::net::FixtureClient;

    const SERVER: &str = "h://keys.test";

    /// The full v4 fingerprint of the test key.
    const FINGERPRINT: &str = "d4c4ee4a8a8b7d7c6d6e5f5a4b4c3d3e2f2a1b1c";

    /// What a v4 signature names: the **last** 16 hex of the fingerprint,
    /// not the first. Getting that backwards is why `key_id_matches`
    /// compares suffixes.
    const ISSUER: &str = "4b4c3d3e2f2a1b1c";
    const KEY: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ\n-----END PGP PUBLIC KEY BLOCK-----";

    fn hkp_url(issuer: &str) -> String {
        format!("{SERVER}/pks/lookup?op=get&options=mr&search=0x{issuer}")
    }

    fn pinned() -> RegistryKey {
        RegistryKey::pinned(FINGERPRINT, "pinned-material")
    }

    /// Nothing is fetched unless keyservers are configured. Asking a third
    /// party for a key is opt-in, not a silent fallback.
    #[tokio::test]
    async fn keyservers_none_fetch_nothing() {
        let host = TestHost::new(FixtureClient::new().with_body(hkp_url(ISSUER), KEY));
        let ctx = Ctx::anonymous_for_test();

        let store = KeyStore::new(Vec::new());
        let found = store
            .keys_for(&[ISSUER.to_owned()], &HostFetch::new(&host, &ctx))
            .await;

        assert!(found.is_empty());
        assert!(host.requested().is_empty());
    }

    /// Having decided which key to trust for an identifier, there is
    /// nothing to gain from also asking a keyserver what it thinks that
    /// identifier means.
    #[tokio::test]
    async fn key_pinned_used_without_asking() {
        let host = TestHost::new(FixtureClient::new().with_body(hkp_url(ISSUER), KEY));
        let ctx = Ctx::anonymous_for_test();

        let store = KeyStore::new(vec![pinned()]).with_servers(vec![SERVER.to_owned()]);
        let found = store
            .keys_for(&[ISSUER.to_owned()], &HostFetch::new(&host, &ctx))
            .await;

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, KeyOrigin::Pinned);
        assert!(host.requested().is_empty());
    }

    #[tokio::test]
    async fn key_unpinned_fetched_from_keyserver() {
        let host = TestHost::new(FixtureClient::new().with_body(hkp_url(ISSUER), KEY));
        let ctx = Ctx::anonymous_for_test();

        let store = KeyStore::new(Vec::new()).with_servers(vec![SERVER.to_owned()]);
        let found = store
            .keys_for(&[ISSUER.to_owned()], &HostFetch::new(&host, &ctx))
            .await;

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, KEY);

        // Recorded as weaker evidence than a pinned key, so a report can
        // tell the two apart.
        assert_eq!(found[0].origin, KeyOrigin::Keyserver);
    }

    /// Servers are tried in order, so a fast internal mirror can sit ahead
    /// of a public one.
    #[tokio::test]
    async fn keyservers_tried_in_order() {
        let host = TestHost::new(FixtureClient::new().with_body(
            format!("h://second.test/pks/lookup?op=get&options=mr&search=0x{ISSUER}"),
            KEY,
        ));

        let ctx = Ctx::anonymous_for_test();
        let store = KeyStore::new(Vec::new()).with_servers(vec![
            "h://first.test".to_owned(),
            "h://second.test".to_owned(),
        ]);

        let found = store
            .keys_for(&[ISSUER.to_owned()], &HostFetch::new(&host, &ctx))
            .await;

        assert_eq!(found.len(), 1);

        let asked = host.requested();
        assert!(asked[0].starts_with("h://first.test"), "{asked:?}");
    }

    /// An error page served with a 200 must not be mistaken for a key.
    #[tokio::test]
    async fn keyservers_non_key_answer_ignored() {
        let host = TestHost::new(
            FixtureClient::new().with_body(hkp_url(ISSUER), "<html>no such key</html>"),
        );

        let ctx = Ctx::anonymous_for_test();
        let store = KeyStore::new(Vec::new()).with_servers(vec![SERVER.to_owned()]);

        assert!(
            store
                .keys_for(&[ISSUER.to_owned()], &HostFetch::new(&host, &ctx))
                .await
                .is_empty()
        );
    }

    /// One project signs every one of its artifacts, so artifact
    /// enumeration over a catalog meets the same key thousands of times.
    /// Looking it up once is the difference between a lookup per key and a
    /// lookup per artifact.
    #[tokio::test]
    async fn key_looked_up_once_per_scan() {
        let host = TestHost::new(FixtureClient::new().with_body(hkp_url(ISSUER), KEY));
        let ctx = Ctx::anonymous_for_test();
        let fetch = HostFetch::new(&host, &ctx);

        let store = KeyStore::new(Vec::new()).with_servers(vec![SERVER.to_owned()]);

        for _ in 0..25 {
            assert_eq!(store.keys_for(&[ISSUER.to_owned()], &fetch).await.len(), 1);
        }

        assert_eq!(host.hits(&hkp_url(ISSUER)), 1);
    }

    /// And a key that is genuinely absent is remembered as absent, so a
    /// artifact enumeration does not re-ask every keyserver once per
    /// artifact.
    #[tokio::test]
    async fn key_missing_not_asked_repeatedly() {
        let host = TestHost::new(FixtureClient::new());
        let ctx = Ctx::anonymous_for_test();
        let fetch = HostFetch::new(&host, &ctx);

        let store = KeyStore::new(Vec::new()).with_servers(vec![SERVER.to_owned()]);

        for _ in 0..10 {
            assert!(
                store
                    .keys_for(&[ISSUER.to_owned()], &fetch)
                    .await
                    .is_empty()
            );
        }

        assert_eq!(host.hits(&hkp_url(ISSUER)), 1);
    }

    #[test]
    fn store_empty_says_so() {
        assert!(KeyStore::new(Vec::new()).is_empty());
        assert!(!KeyStore::new(vec![pinned()]).is_empty());
        assert!(
            !KeyStore::new(Vec::new())
                .with_servers(vec![SERVER.to_owned()])
                .is_empty()
        );
    }
}
