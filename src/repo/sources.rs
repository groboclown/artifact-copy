//! Turning configured sources into live ones.
//!
//! Everything a `sources` block means that [`open_source`](super::open_source)
//! and [`open_proxy_source`](super::open_proxy_source) do not: resolving a
//! host name to a URL, following a proxy's `proxy-to` entries, and refusing
//! the declarations that the schema can accept but that cannot work.
//!
//! # Named sources are shared
//!
//! [`Sources`] memoizes by name, so two proxies naming `central` get the
//! **same** `Arc<dyn Source>`. That is both the intuitive reading of a
//! reference and the useful one: a source owns caches, so sharing means one
//! packument cache rather than one per referring proxy.
//!
//! The map is keyed by configured name and is therefore bounded by the
//! configuration file, not by anything a run finds.
//!
//! # How cycles are prevented
//!
//! One rule, checked here: **a `ref` may not name a proxy.** Only an inline
//! `source` may be one.
//!
//! That is sufficient, and it is worth seeing why so nobody adds a graph
//! walk later. A name is the only way a declaration can point at something
//! that might point back at it; an inline definition nests structurally, so
//! it can only contain things, never refer to a container. Forbidding names
//! from reaching proxies leaves no way to write a loop.
//!
//! Inline nesting is still bounded, by [`MAX_PROXY_DEPTH`] -- not against
//! cycles, which cannot occur, but against a configuration deep enough to
//! exhaust the stack while being built.
//!
//! References: [Sigstore](https://docs.sigstore.dev/).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{Config, ProxyTo, ProxyUpstream, SigningScheme, Source as SourceConfig};
use crate::core::error::{Error, Result};
use crate::ext::{Capabilities, Options};
use crate::net::sig::KeyStore;
use crate::net::sig::resolve_pinned;
use crate::net::sig::sigstore::{RootSource, SigstoreRoot};
use crate::policy::SigningPolicy;

use super::proxy::{SourceUpstreams, Upstream, Upstreams};
use super::{
    NameMap, Omit, OmittingSource, Source, Trust, is_proxy_kind, open_named_source,
    open_proxy_source,
};

/// How deeply inline `proxy-to` definitions may nest.
///
/// Not a cycle guard -- cycles are unwritable, see the module documentation
/// -- but a configuration file is user input, and recursion over user input
/// wants a bound. Far past anything a person would write by hand.
pub const MAX_PROXY_DEPTH: usize = 16;

/// Join a source's `path` onto its host's url.
///
/// Slashes on either side are optional, because a configuration is written
/// by a person and `repository/npm-group`, `/repository/npm-group` and
/// `repository/npm-group/` all plainly mean the same thing.
///
/// `.` and `..` are **refused** rather than resolved. A prefix that climbed
/// out of the host would make the capability's constraint something nobody
/// could read off the configuration, and a constraint carrying a literal
/// `..` matches no real URL -- so a source configured that way would fail
/// every fetch with a confusing message instead of failing to load with a
/// clear one.
pub fn under(url: &str, path: Option<&str>) -> std::result::Result<String, String> {
    let base = crate::net::normalized_base(url);

    let Some(path) = path else {
        return Ok(base);
    };

    let mut joined = base;

    for segment in path.split('/').filter(|part| !part.is_empty()) {
        if segment == "." || segment == ".." {
            return Err(format!(
                "{path:?} contains a {segment:?} segment; a path names where under the \
                 host this repository lives and cannot climb out of it"
            ));
        }

        joined.push('/');
        joined.push_str(segment);
    }

    Ok(joined)
}

/// The live sources a configuration describes.
///
/// Built lazily and shared: ask for one by name and get the same instance
/// every time.
pub struct Sources<'c> {
    config: &'c Config,

    /// The run's Sigstore trust root, shared by every source so it loads at
    /// most once.
    sigstore: Arc<SigstoreRoot>,

    /// Sources already built, by configured name. Inline definitions are
    /// absent from here because they have no name to share under -- each
    /// one belongs to exactly one proxy.
    built: HashMap<String, Arc<dyn Source>>,
}

impl<'c> Sources<'c> {
    pub fn new(config: &'c Config) -> Self {
        let root = match &config.setup.sigstore_trusted_root {
            Some(path) => RootSource::File(path.clone()),
            None => RootSource::Tuf(None),
        };

        Self {
            config,
            sigstore: Arc::new(SigstoreRoot::new(root)),
            built: HashMap::new(),
        }
    }

    /// Cache a Sigstore root fetched over TUF in `dir`.
    pub fn caching_sigstore_in(mut self, dir: PathBuf) -> Self {
        // Only before any source shares it, which is when this is called.
        if let Some(root) = Arc::get_mut(&mut self.sigstore) {
            root.cache_in(dir);
        }

        self
    }

    /// The source configured under `name`.
    ///
    /// The same instance on every call, which is what makes a `ref` a
    /// reference rather than a copy.
    pub fn open(&mut self, name: &str, caps: &mut dyn Capabilities) -> Result<Arc<dyn Source>> {
        if let Some(built) = self.built.get(name) {
            return Ok(Arc::clone(built));
        }

        let declared = self.declaration(name)?;
        let source = self.build(name, declared, 0, caps)?;

        self.built.insert(name.to_owned(), Arc::clone(&source));

        Ok(source)
    }

    fn declaration(&self, name: &str) -> Result<&'c SourceConfig> {
        self.config
            .sources
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "source",
                name: name.to_owned(),
            })
    }

    /// Build one declaration, named or inline, without what its `omit`
    /// rules and its ecosystem's built-ins leave out.
    ///
    /// `what` names it for error messages: a configured name, or a
    /// description of where an inline definition sits.
    fn build(
        &mut self,
        what: &str,
        declared: &'c SourceConfig,
        depth: usize,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Source>> {
        let omit = Omit::parse(&declared.omit)?;
        let built = self.construct(what, declared, depth, caps)?;

        Ok(Arc::new(OmittingSource::new(built, omit)))
    }

    /// Build one declaration as its kind makes it.
    fn construct(
        &mut self,
        what: &str,
        declared: &'c SourceConfig,
        depth: usize,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Source>> {
        let options = Options::from(declared.options.clone());

        if !is_proxy_kind(&declared.kind) {
            return self.build_direct(what, declared, &options, caps);
        }

        if depth > MAX_PROXY_DEPTH {
            return Err(Error::Config(format!(
                "{what} nests inline 'proxy-to' definitions more than {MAX_PROXY_DEPTH} \
                 deep; a reference to a declared source is almost certainly what was meant"
            )));
        }

        // The schema forbids `host` beside `proxy-to`, and cannot forbid it
        // beside a proxy *kind* -- it does not know which kinds are proxies.
        if let Some(host) = &declared.host {
            return Err(Error::Config(format!(
                "{what} is a {kind} proxy and names host {host:?}. A proxy has no host \
                 of its own; its upstreams each name theirs. A proxy that genuinely \
                 needs one takes it from 'options'",
                kind = declared.kind,
            )));
        }

        // A proxy names nothing itself; each upstream maps its own names.
        if !declared.names.is_empty() {
            return Err(Error::Config(format!(
                "{what} is a {kind} proxy and has 'names'. Put them on the upstream \
                 whose names they map",
                kind = declared.kind,
            )));
        }

        let upstreams = self.upstreams(what, &declared.proxy_to, depth, caps)?;

        open_proxy_source(&declared.kind, upstreams, &options)
    }

    /// An ordinary source: a host, and no upstreams.
    fn build_direct(
        &self,
        what: &str,
        declared: &SourceConfig,
        options: &Options,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Source>> {
        // Also unreachable through the schema alone: `proxy-to` satisfies
        // the "host or proxy-to" rule, so `{kind: maven, proxy-to: [..]}`
        // parses. Only the kind list can tell that it is nonsense.
        if !declared.proxy_to.is_empty() {
            return Err(Error::Config(format!(
                "{what} has 'proxy-to' entries but its kind {kind:?} is not a proxy. \
                 The proxy kinds are {kinds}",
                kind = declared.kind,
                kinds = quoted(super::proxy_source_kinds()),
            )));
        }

        let host = declared.host.as_deref().ok_or_else(|| {
            Error::Config(format!(
                "{what} names no host, and its kind {kind:?} is not a proxy",
                kind = declared.kind,
            ))
        })?;

        let url = self
            .config
            .hosts
            .get(host)
            .map(|entry| entry.url.as_str())
            .ok_or_else(|| Error::UnknownName {
                collection: "host",
                name: host.to_owned(),
            })?;

        let base_url = under(url, declared.host_path.as_deref())
            .map_err(|detail| Error::Config(format!("{what} has an unusable path: {detail}")))?;

        // Given its host here rather than by the caller, because a proxy's
        // upstreams are built inside this recursion and never handed out on
        // their own. Each one therefore reaches its own host, which is what
        // keeps one upstream's credentials off another upstream's requests.
        // Wrapped per binding: the capability is shared by every source
        // reading this repository, and each was configured on its own.
        let policy = super::cache_policy(
            &self.config.setup,
            declared.cache_retention,
            &declared.cache_freshness,
            declared.cache_size,
        );
        let capability: Arc<dyn crate::ext::ExtHost> = Arc::new(crate::ext::Policed::new(
            caps.host(host, &base_url)?,
            policy,
        ));
        // An extension kind goes to the gearing, reaching only this host.
        if let Some(extension) = self.config.extensions.get(&declared.kind) {
            let gear = crate::ext::gear::launch(&declared.kind, extension)?;
            let source =
                super::extension::ExtensionSource::open(gear, &base_url, options, capability)?;

            return Ok(Arc::new(
                super::Bound::new(Arc::new(source)).reading_versions(declared.versions()?),
            ));
        }

        let trust = self.trust(host, caps)?;
        let names = NameMap::parse(&declared.names)?;
        let source =
            open_named_source(&declared.kind, &base_url, options, names, capability, trust)?;

        Ok(Arc::new(
            super::Bound::new(source).reading_versions(declared.versions()?),
        ))
    }

    /// What a host's signatures are checked against: its PGP keys, a
    /// capability reaching its keyservers, and the run's Sigstore root.
    ///
    /// The keyservers get a capability of their own rather than a route on
    /// the host, so only a key lookup reaches them.
    fn trust(&self, host: &str, caps: &mut dyn Capabilities) -> Result<Trust> {
        let (keys, servers) = self.keys(host)?;

        let keyservers = match servers.is_empty() {
            true => None,
            false => Some(caps.keyservers(&servers)?),
        };

        Ok(Trust {
            keys,
            keyservers,
            sigstore: Arc::clone(&self.sigstore),
            signing: Arc::new(self.signing(host)?),
        })
    }

    /// The signing policy for a host's sources: its own file, or setup's,
    /// or an empty policy when neither names one.
    ///
    /// Replaced rather than layered, as a host's license and security
    /// policies are: which keys vouch for what is one decision, and half
    /// of it from each file would be a decision nobody wrote.
    fn signing(&self, host: &str) -> Result<SigningPolicy> {
        let own = self
            .config
            .hosts
            .get(host)
            .and_then(|entry| entry.signing_policy.as_ref());

        match own.or(self.config.setup.signing_policy.as_ref()) {
            Some(path) => SigningPolicy::load(path),
            None => Ok(SigningPolicy::default()),
        }
    }

    /// The PGP keys a host names from `signing-keys`, and the keyservers it
    /// asks for more: its own, or `setup.keyservers` when it names none.
    fn keys(&self, host: &str) -> Result<(KeyStore, Vec<String>)> {
        let entry = self
            .config
            .hosts
            .get(host)
            .ok_or_else(|| Error::UnknownName {
                collection: "host",
                name: host.to_owned(),
            })?;

        let pinned = resolve_pinned(
            &entry.signing_keys,
            &self.config.signing_keys,
            SigningScheme::Pgp,
        )?;

        let servers = match entry.keyservers.is_empty() {
            true => self.config.setup.keyservers.clone(),
            false => entry.keyservers.clone(),
        };

        Ok((KeyStore::new(pinned).with_servers(servers.clone()), servers))
    }

    /// Resolve a proxy's entries, in configuration order.
    fn upstreams(
        &mut self,
        what: &str,
        entries: &'c [ProxyTo],
        depth: usize,
        caps: &mut dyn Capabilities,
    ) -> Result<SourceUpstreams> {
        let mut out = Vec::with_capacity(entries.len());

        for (at, entry) in entries.iter().enumerate() {
            let source = match &entry.upstream {
                ProxyUpstream::Ref(name) => self.referenced(what, at, name, caps)?,

                ProxyUpstream::Source(inline) => {
                    self.build(&format!("{what} entry {at}"), inline, depth + 1, caps)?
                }
            };

            out.push(match &entry.classifier {
                Some(classifier) => Upstream::classified(source, classifier),
                None => Upstream::new(source),
            });
        }

        Ok(Upstreams::new(out))
    }

    /// Follow one `ref`, refusing to follow it into another proxy.
    ///
    /// This is the cycle prevention, and the message says so: a user who
    /// wanted a proxy of a proxy can have one by writing it inline, which
    /// is not a restriction on what they can express, only on how.
    fn referenced(
        &mut self,
        what: &str,
        at: usize,
        name: &str,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Source>> {
        let declared = self.declaration(name).map_err(|_| {
            Error::Config(format!(
                "{what} entry {at} refers to source {name:?}, which is not configured"
            ))
        })?;

        if is_proxy_kind(&declared.kind) {
            return Err(Error::Config(format!(
                "{what} entry {at} refers to source {name:?}, which is itself a \
                 {kind} proxy. A 'ref' may only name a non-proxy source, which is what \
                 keeps proxy configurations acyclic; write the inner proxy inline under \
                 'source' instead",
                kind = declared.kind,
            )));
        }

        self.open(name, caps)
    }
}

fn quoted(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use crate::ext::Unbound;

    /// Slashes on either side are optional, because a person writing a
    /// configuration plainly means the same thing by all three spellings.
    #[test]
    fn path_slashes_ignored() {
        for path in [
            "repository/npm-group",
            "/repository/npm-group",
            "repository/npm-group/",
        ] {
            assert_eq!(
                under("https://nexus.test/", Some(path)).expect("joins"),
                "https://nexus.test/repository/npm-group",
                "{path}"
            );
        }

        // And no path leaves the host's url as the root, which is what
        // every configuration written before this key says.
        assert_eq!(
            under("https://registry.test/", None).expect("joins"),
            "https://registry.test"
        );
    }

    /// A prefix that climbed out of the host would make the confinement
    /// something nobody could read off the configuration.
    #[test]
    fn path_cannot_climb_out_of_host() {
        for path in ["../elsewhere", "repository/../../root", "./here"] {
            assert!(under("https://nexus.test/", Some(path)).is_err(), "{path}");
        }
    }
    use super::*;
    use crate::model::EcosystemId;

    /// A configuration from one `sources`/`hosts` pair, without going
    /// through the file loader -- these tests are about what the builder
    /// makes of a declaration, not about how it was read.
    fn config(json: serde_json::Value) -> Config {
        serde_json::from_value(json).expect("parses")
    }

    fn hosts() -> serde_json::Value {
        serde_json::json!({
            "registry": {"url": "h://registry.test"},
            "mirror": {"url": "h://mirror.test"},
        })
    }

    fn built(sources: serde_json::Value) -> Config {
        config(serde_json::json!({"hosts": hosts(), "sources": sources}))
    }

    /// A host's `signing-keys` reach its source: naming a key nobody
    /// declared refuses the source rather than checking against fewer keys
    /// than listed.
    #[test]
    fn host_signing_keys_resolved() {
        let config = config(serde_json::json!({
            "hosts": {"registry": {"url": "h://registry.test", "signing-keys": ["missing"]}},
            "sources": {"central": {"host": "registry", "kind": "maven"}},
        }));

        let Err(err) = Sources::new(&config).open("central", &mut Unbound::default()) else {
            panic!("an undeclared signing key should refuse the source");
        };

        assert!(err.to_string().contains("missing"), "{err}");
    }

    /// A host's signing policy reaches its source; one that will not load
    /// refuses the source rather than trusting keys it was meant to limit.
    #[test]
    fn host_signing_policy_read() {
        let config = config(serde_json::json!({
            "hosts": {"registry": {"url": "h://registry.test", "signing-policy": "/no/such/policy.yaml"}},
            "sources": {"central": {"host": "registry", "kind": "maven"}},
        }));

        let Err(err) = Sources::new(&config).open("central", &mut Unbound::default()) else {
            panic!("an unreadable signing policy should refuse the source");
        };

        assert!(err.to_string().contains("policy.yaml"), "{err}");
    }

    #[test]
    fn host_resolved_for_ordinary_source() {
        let config = built(serde_json::json!({
            "npm": {"host": "registry", "kind": "npm"},
        }));

        let source = Sources::new(&config)
            .open("npm", &mut Unbound::default())
            .expect("opens");

        assert_eq!(source.ecosystems(), vec![EcosystemId::npm()]);
    }

    /// A kind naming an extension reaches the gearing, which says it
    /// cannot run one yet, rather than reporting an unknown kind.
    #[test]
    fn kind_extension_reaches_gearing() {
        let config = config(serde_json::json!({
            "hosts": hosts(),
            "extensions": {"custom": {"kind": "executable", "command": "custom-source", "arguments": []}},
            "sources": {"ext": {"host": "registry", "kind": "custom"}},
        }));

        let err = match Sources::new(&config).open("ext", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an extension cannot run yet"),
        };

        assert_eq!(err.code(), crate::core::problem::Code::Unimplemented);
    }

    /// A WASM extension kind opens as a source speaking what it described.
    #[test]
    fn kind_wasm_opens() {
        use crate::ext::gear::testing::{DESCRIBE_RAW_SOURCE, binary, router};

        let dir = tempfile::tempdir().expect("temp dir");
        let module = dir.path().join("source.wasm");
        std::fs::write(&module, binary(&router(&[DESCRIBE_RAW_SOURCE]))).expect("written");

        let config = config(serde_json::json!({
            "hosts": hosts(),
            "extensions": {"custom": {"kind": "wasm", "module": module}},
            "sources": {"ext": {"host": "registry", "kind": "custom"}},
        }));

        let source = Sources::new(&config)
            .open("ext", &mut Unbound::default())
            .expect("opens");

        assert_eq!(source.ecosystems(), vec![EcosystemId::raw()]);
    }

    #[test]
    fn host_unconfigured_named() {
        let config = built(serde_json::json!({
            "npm": {"host": "nowhere", "kind": "npm"},
        }));

        let err = match Sources::new(&config).open("npm", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an unknown host must not open"),
        };

        assert!(err.to_string().contains("nowhere"), "{err}");
    }

    #[test]
    fn source_unconfigured_named() {
        let config = built(serde_json::json!({}));

        let err = match Sources::new(&config).open("absent", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an unknown source must not open"),
        };

        assert!(err.to_string().contains("absent"), "{err}");
    }

    /// The point of `ref` being a reference: one instance, one set of
    /// caches, however many proxies name it.
    #[test]
    fn source_named_shared_by_referrers() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "npm"},
            "fallback": {"host": "mirror", "kind": "npm"},
            "a": {"kind": "proxy-failover", "proxy-to": [{"ref": "primary"}, {"ref": "fallback"}]},
            "b": {"kind": "proxy-failover", "proxy-to": [{"ref": "primary"}]},
        }));

        let mut sources = Sources::new(&config);

        let once = sources
            .open("primary", &mut Unbound::default())
            .expect("opens");
        let again = sources
            .open("primary", &mut Unbound::default())
            .expect("opens");

        assert!(Arc::ptr_eq(&once, &again), "a name must yield one instance");

        // And building the proxies does not produce further copies.
        sources.open("a", &mut Unbound::default()).expect("opens");
        sources.open("b", &mut Unbound::default()).expect("opens");

        let after = sources
            .open("primary", &mut Unbound::default())
            .expect("opens");

        assert!(Arc::ptr_eq(&once, &after));
    }

    #[test]
    fn proxy_built_over_upstreams_in_order() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "npm"},
            "combined": {
                "kind": "proxy-failover",
                "proxy-to": [
                    {"ref": "primary", "classifier": "first"},
                    {"source": {"host": "mirror", "kind": "npm"}},
                ],
            },
        }));

        let source = Sources::new(&config)
            .open("combined", &mut Unbound::default())
            .expect("opens");

        assert_eq!(source.ecosystems(), vec![EcosystemId::npm()]);
    }

    /// The half of the rule that allows: a proxy of a proxy, written
    /// inline, which is a shape that cannot close a loop.
    #[test]
    fn proxy_upstream_inline_may_be_proxy() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "npm"},
            "outer": {
                "kind": "proxy-failover",
                "proxy-to": [{
                    "source": {
                        "kind": "proxy-failover",
                        "proxy-to": [{"ref": "primary"}],
                    },
                }],
            },
        }));

        assert!(
            Sources::new(&config)
                .open("outer", &mut Unbound::default())
                .is_ok()
        );
    }

    /// The half that refuses, and the whole of the cycle prevention. The
    /// message has to say what to do instead, because the user's intent is
    /// expressible -- just not this way.
    #[test]
    fn ref_may_not_name_proxy() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "npm"},
            "inner": {"kind": "proxy-failover", "proxy-to": [{"ref": "primary"}]},
            "outer": {"kind": "proxy-failover", "proxy-to": [{"ref": "inner"}]},
        }));

        let err = match Sources::new(&config).open("outer", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a ref to a proxy must not open"),
        };

        let text = err.to_string();

        assert!(text.contains("inner"), "{text}");
        assert!(text.contains("inline"), "{text}: say what to do instead");
    }

    /// Two mutually referring proxies are the loop the rule exists for, and
    /// each half of it is refused on its own terms.
    #[test]
    fn proxy_mutual_reference_refused() {
        let config = built(serde_json::json!({
            "a": {"kind": "proxy-failover", "proxy-to": [{"ref": "b"}]},
            "b": {"kind": "proxy-failover", "proxy-to": [{"ref": "a"}]},
        }));

        let mut sources = Sources::new(&config);

        assert!(sources.open("a", &mut Unbound::default()).is_err());
        assert!(sources.open("b", &mut Unbound::default()).is_err());
    }

    /// The schema cannot catch this: it does not know which kinds are
    /// proxies, so `{kind: proxy-failover, host: h}` parses.
    #[test]
    fn proxy_kind_naming_host_refused() {
        let config = built(serde_json::json!({
            "p": {"host": "registry", "kind": "proxy-failover"},
        }));

        let err = match Sources::new(&config).open("p", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a proxy with a host must not open"),
        };

        let text = err.to_string();

        assert!(text.contains("registry"), "{text}");
        assert!(text.contains("options"), "{text}: name the exception");
    }

    /// And the mirror image, which the schema also accepts: `proxy-to`
    /// satisfies the "host or proxy-to" rule whatever the kind is.
    #[test]
    fn proxy_to_on_ordinary_kind_refused() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "npm"},
            "odd": {"kind": "npm", "proxy-to": [{"ref": "primary"}]},
        }));

        let err = match Sources::new(&config).open("odd", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("proxy-to on an ordinary kind must not open"),
        };

        let text = err.to_string();

        assert!(
            text.contains("proxy-failover"),
            "{text}: name the alternatives"
        );
    }

    /// A proxy's own rules are the proxy's, and reach the user unchanged.
    #[test]
    fn proxy_own_refusal_reported() {
        let config = built(serde_json::json!({
            "empty": {"kind": "proxy-failover", "proxy-to": []},
        }));

        let err = match Sources::new(&config).open("empty", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a failover over nothing must not open"),
        };

        assert!(err.to_string().contains("at least 1"), "{err}");
    }

    /// Disjoint ecosystems behind a failover, refused where it is checked.
    #[test]
    fn proxy_upstream_other_ecosystem_refused() {
        let config = built(serde_json::json!({
            "js": {"host": "registry", "kind": "npm"},
            "jvm": {"host": "mirror", "kind": "maven"},
            "both": {"kind": "proxy-failover", "proxy-to": [{"ref": "js"}, {"ref": "jvm"}]},
        }));

        let err = match Sources::new(&config).open("both", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("npm and maven are not alternatives"),
        };

        assert!(err.to_string().contains("disjoint"), "{err}");
    }

    /// Recursion over user input wants a bound even where cycles cannot
    /// occur. Built as a string because nothing sane produces this.
    #[test]
    fn proxy_inline_nesting_bounded() {
        let mut inner = serde_json::json!({"host": "registry", "kind": "npm"});

        for _ in 0..(MAX_PROXY_DEPTH + 2) {
            inner = serde_json::json!({
                "kind": "proxy-failover",
                "proxy-to": [{"source": inner}],
            });
        }

        let config = built(serde_json::json!({"deep": inner}));

        let err = match Sources::new(&config).open("deep", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("nesting past the bound must not open"),
        };

        assert!(err.to_string().contains("deep"), "{err}");
    }

    /// A kind's own options reach it through the builder, which is the
    /// path a real configuration takes. Maven's `checksums` is the first
    /// option any source kind reads, so this is what proves they arrive.
    #[test]
    fn kind_options_reach_source() {
        let config = built(serde_json::json!({
            "ok": {
                "host": "registry",
                "kind": "maven",
                "options": {"checksums": ["sha256"]},
            },
            "typo": {
                "host": "registry",
                "kind": "maven",
                "options": {"checksums": ["sha-256"]},
            },
        }));

        let mut sources = Sources::new(&config);

        assert!(sources.open("ok", &mut Unbound::default()).is_ok());

        let err = match sources.open("typo", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an unknown checksum algorithm must not open"),
        };

        assert!(err.to_string().contains("sha-256"), "{err}");
    }
}
