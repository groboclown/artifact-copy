//! Turning configured enumerators into live ones.
//!
//! The enumeration twin of [`crate::repo::Sources`], and it follows the
//! same three rules: a named enumerator is **shared** rather than copied, a
//! `ref` may not name a proxy, and an inline `enumerator` may be one. See that
//! module for why the last two are the whole of the cycle prevention.
//!
//! # Not the same list as a source's
//!
//! A `proxy-to` here names **enumerators**. Enumeration is a different
//! capability from resolution -- Maven Central speaks the Maven protocol and
//! cannot be enumerated over it at all -- so a repository may have a source
//! and no enumerator, or an enumerator of a different shape entirely. Letting a
//! enumerator proxy borrow a source proxy's upstream list would assume a
//! correspondence that does not hold.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{
    Config, Enumerator as EnumeratorConfig, ProxyEnumeratorUpstream, ProxyToEnumerator,
};
use crate::core::error::{Error, Result};
use crate::ext::{Capabilities, Options};
use crate::repo::{MAX_PROXY_DEPTH, under};

use super::{Enumerator, Login, login, login_advice, open_enumerator, proxy_enumerator_kinds};
use crate::repo::proxy::enumerator::{
    EnumeratorUpstreams, is_proxy_enumerator_kind, open_proxy_enumerator,
};

/// The live enumerators a configuration describes.
pub struct Enumerators<'c> {
    config: &'c Config,
    built: HashMap<String, Arc<dyn Enumerator>>,
}

impl<'c> Enumerators<'c> {
    pub fn new(config: &'c Config) -> Self {
        Self {
            config,
            built: HashMap::new(),
        }
    }

    /// The enumerator configured under `name`, the same instance every time.
    pub fn open(&mut self, name: &str, caps: &mut dyn Capabilities) -> Result<Arc<dyn Enumerator>> {
        if let Some(built) = self.built.get(name) {
            return Ok(Arc::clone(built));
        }

        let declared = self.declaration(name)?;
        let enumerator = self.build(name, declared, 0, caps)?;

        self.built.insert(name.to_owned(), Arc::clone(&enumerator));

        Ok(enumerator)
    }

    fn declaration(&self, name: &str) -> Result<&'c EnumeratorConfig> {
        self.config
            .enumerators
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "enumerator",
                name: name.to_owned(),
            })
    }

    /// Build one declaration without what its `omit` rules and its
    /// ecosystem's built-ins leave out.
    fn build(
        &mut self,
        what: &str,
        declared: &'c EnumeratorConfig,
        depth: usize,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Enumerator>> {
        let omit = crate::repo::Omit::parse(&declared.omit)?;
        let built = self.construct(what, declared, depth, caps)?;

        Ok(Arc::new(crate::repo::OmittingEnumerator::new(built, omit)))
    }

    /// Build one declaration as its kind makes it.
    fn construct(
        &mut self,
        what: &str,
        declared: &'c EnumeratorConfig,
        depth: usize,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Enumerator>> {
        let options = Options::from(declared.options.clone());

        if !is_proxy_enumerator_kind(&declared.kind) {
            return self.build_direct(what, declared, &options, caps);
        }

        if depth > MAX_PROXY_DEPTH {
            return Err(Error::Config(format!(
                "{what} nests inline 'proxy-to' definitions more than {MAX_PROXY_DEPTH} \
                 deep; a reference to a declared enumerator is almost certainly what was meant"
            )));
        }

        // The schema forbids `host` beside `proxy-to` and cannot forbid it
        // beside a proxy *kind*, because it does not know which kinds are
        // proxies.
        if let Some(host) = &declared.host {
            return Err(Error::Config(format!(
                "{what} is a {kind} proxy and names host {host:?}. A proxy has no host \
                 of its own; its upstreams each name theirs. A proxy that genuinely \
                 needs one takes it from 'options'",
                kind = declared.kind,
            )));
        }

        let upstreams = self.upstreams(what, &declared.proxy_to, depth, caps)?;

        open_proxy_enumerator(&declared.kind, upstreams, &options)
    }

    fn build_direct(
        &self,
        what: &str,
        declared: &EnumeratorConfig,
        options: &Options,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Enumerator>> {
        // An extension kind goes to the gearing, which runs only sources yet.
        if self.config.extensions.contains_key(&declared.kind) {
            return Err(Error::Unimplemented("running an enumerator extension"));
        }

        if !declared.proxy_to.is_empty() {
            return Err(Error::Config(format!(
                "{what} has 'proxy-to' entries but its kind {kind:?} is not a proxy. \
                 The proxy enumerator kinds are {kinds}",
                kind = declared.kind,
                kinds = quoted(proxy_enumerator_kinds()),
            )));
        }

        let host = declared.host.as_deref().ok_or_else(|| {
            Error::Config(format!(
                "{what} names no host, and its kind {kind:?} is not a proxy",
                kind = declared.kind,
            ))
        })?;

        let entry = self
            .config
            .hosts
            .get(host)
            .ok_or_else(|| Error::UnknownName {
                collection: "host",
                name: host.to_owned(),
            })?;

        // Refused here, before any request, rather than on the first page.
        if entry.authentication.is_none() && login(&declared.kind, options)? == Login::Required {
            return Err(Error::Config(format!(
                "enumerator {what}: {}",
                login_advice(&declared.kind, host, options)
            )));
        }

        let base_url = entry.url.as_str();

        // Confined to the joined prefix. A manager's catalog lives behind a
        // REST API at the server root, so its enumerator leaves `host-path`
        // absent and stays confined to the host's own url.
        let base_url = under(base_url, declared.host_path.as_deref()).map_err(|detail| {
            Error::Config(format!("{what} has an unusable host-path: {detail}"))
        })?;

        // Wrapped per binding, as a source's is.
        let policy = crate::repo::cache_policy(
            &self.config.setup,
            declared.cache_retention,
            &declared.cache_freshness,
            declared.cache_size,
        );
        let capability: std::sync::Arc<dyn crate::ext::ExtHost> = std::sync::Arc::new(
            crate::ext::Policed::new(caps.host(host, &base_url)?, policy),
        );

        open_enumerator(&declared.kind, &base_url, options, capability)
    }

    fn upstreams(
        &mut self,
        what: &str,
        entries: &'c [ProxyToEnumerator],
        depth: usize,
        caps: &mut dyn Capabilities,
    ) -> Result<EnumeratorUpstreams> {
        let mut out = Vec::with_capacity(entries.len());

        for (at, entry) in entries.iter().enumerate() {
            let enumerator = match &entry.upstream {
                ProxyEnumeratorUpstream::Ref(name) => self.referenced(what, at, name, caps)?,

                ProxyEnumeratorUpstream::Enumerator(inline) => {
                    self.build(&format!("{what} entry {at}"), inline, depth + 1, caps)?
                }
            };

            out.push(match &entry.classifier {
                Some(classifier) => {
                    crate::repo::proxy::enumerator::Upstream::classified(enumerator, classifier)
                }
                None => crate::repo::proxy::enumerator::Upstream::new(enumerator),
            });
        }

        Ok(EnumeratorUpstreams::new(out))
    }

    /// Follow one `ref`, refusing to follow it into another proxy.
    fn referenced(
        &mut self,
        what: &str,
        at: usize,
        name: &str,
        caps: &mut dyn Capabilities,
    ) -> Result<Arc<dyn Enumerator>> {
        let declared = self.declaration(name).map_err(|_| {
            Error::Config(format!(
                "{what} entry {at} refers to enumerator {name:?}, which is not configured"
            ))
        })?;

        if is_proxy_enumerator_kind(&declared.kind) {
            return Err(Error::Config(format!(
                "{what} entry {at} refers to enumerator {name:?}, which is itself a \
                 {kind} proxy. A 'ref' may only name a non-proxy enumerator, which is what \
                 keeps proxy configurations acyclic; write the inner proxy inline under \
                 'enumerator' instead",
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
    use super::*;
    use crate::ext::Unbound;

    fn built(enumerators: serde_json::Value) -> Config {
        serde_json::from_value(serde_json::json!({
            "hosts": {
                "registry": {"url": "h://registry.test"},
                "mirror": {"url": "h://mirror.test"},
            },
            "enumerators": enumerators,
        }))
        .expect("parses")
    }

    /// A kind naming an extension reaches the gearing.
    #[test]
    fn kind_extension_reaches_gearing() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "hosts": {"registry": {"url": "h://registry.test"}},
            "extensions": {"custom": {"kind": "executable", "command": "custom-source", "arguments": []}},
            "enumerators": {"ext": {"host": "registry", "kind": "custom"}},
        }))
        .expect("parses");

        let err = match Enumerators::new(&config).open("ext", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an extension cannot run yet"),
        };

        assert_eq!(err.code(), crate::core::problem::Code::Unimplemented);
    }

    #[test]
    fn host_resolved_for_ordinary_enumerator() {
        let config = built(serde_json::json!({
            "pypi": {"host": "registry", "kind": "pypi-simple"},
        }));

        assert!(
            Enumerators::new(&config)
                .open("pypi", &mut Unbound::default())
                .is_ok()
        );
    }

    /// AQL on OSS needs a login, so an anonymous host is refused before
    /// the walk rather than on its first page.
    #[test]
    fn kind_login_needs_credentials() {
        let config = |options: serde_json::Value| -> Config {
            serde_json::from_value(serde_json::json!({
                "hosts": {
                    "anonymous": {"url": "h://oss.test"},
                    "signed-in": {"url": "h://oss.test", "authentication": {
                        "kind": "bearer", "token": {"kind": "text", "value": "t"}}},
                },
                "enumerators": {
                    "anonymous": {"host": "anonymous", "kind": "artifactory-oss",
                                  "options": options.clone()},
                    "signed-in": {"host": "signed-in", "kind": "artifactory-oss",
                                  "options": options},
                },
            }))
            .expect("parses")
        };

        let plain = config(serde_json::json!({"repository": "r", "ecosystem": "maven"}));
        let mut enumerators = Enumerators::new(&plain);

        let err = match enumerators.open("anonymous", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an anonymous host should be refused"),
        };

        assert!(err.to_string().contains("anonymous: attempt"), "{err}");

        // Someone who cannot log in at all is pointed at the protocol walk.
        assert!(err.to_string().contains("maven-html-index"), "{err}");
        assert!(
            enumerators
                .open("signed-in", &mut Unbound::default())
                .is_ok()
        );

        let attempting = config(serde_json::json!(
            {"repository": "r", "ecosystem": "maven", "anonymous": "attempt"}
        ));

        assert!(
            Enumerators::new(&attempting)
                .open("anonymous", &mut Unbound::default())
                .is_ok()
        );
    }

    /// Records the base each host is confined to, and otherwise denies.
    #[derive(Default)]
    struct Recording {
        bases: Vec<String>,
        inner: Unbound,
    }

    impl Capabilities for Recording {
        fn host(&mut self, name: &str, base: &str) -> Result<Arc<dyn crate::ext::ExtHost>> {
            self.bases.push(base.to_owned());
            self.inner.host(name, base)
        }

        fn keyservers(&mut self, urls: &[String]) -> Result<Arc<dyn crate::ext::ExtHost>> {
            self.inner.keyservers(urls)
        }
    }

    /// `host-path` narrows the capability, so an index rooted under a server
    /// shares that server's host.  Example: Artifact Keeper's `pypi/{repo}`.
    #[test]
    fn host_path_narrows_capability() {
        let config = built(serde_json::json!({
            "pypi": {"host": "registry", "kind": "pypi-simple", "host-path": "pypi/pypi-a"},
        }));

        let mut caps = Recording::default();

        assert!(Enumerators::new(&config).open("pypi", &mut caps).is_ok());
        assert_eq!(caps.bases, ["h://registry.test/pypi/pypi-a"]);
    }

    #[test]
    fn path_cannot_climb_out_of_host() {
        let config = built(serde_json::json!({
            "pypi": {"host": "registry", "kind": "pypi-simple", "host-path": "../other"},
        }));

        let err = match Enumerators::new(&config).open("pypi", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a climbing host-path must be refused"),
        };

        assert!(err.to_string().contains("host-path"), "{err}");
    }

    /// The same sharing rule sources have, for the same reason: an enumerator
    /// may hold state, and two proxies naming one should get one.
    #[test]
    fn enumerator_named_shared() {
        let config = built(serde_json::json!({
            "a": {"host": "registry", "kind": "pypi-simple"},
            "b": {"host": "mirror", "kind": "pypi-simple"},
            "p": {"kind": "proxy-failover", "proxy-to": [{"ref": "a"}, {"ref": "b"}]},
        }));

        let mut enumerators = Enumerators::new(&config);

        let once = enumerators
            .open("a", &mut Unbound::default())
            .expect("opens");
        enumerators
            .open("p", &mut Unbound::default())
            .expect("opens");
        let again = enumerators
            .open("a", &mut Unbound::default())
            .expect("opens");

        assert!(Arc::ptr_eq(&once, &again));
    }

    #[test]
    fn proxy_built_over_upstreams() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "pypi-simple"},
            "combined": {
                "kind": "proxy-failover",
                "proxy-to": [
                    {"ref": "primary", "classifier": "first"},
                    {"enumerator": {"host": "mirror", "kind": "pypi-simple"}},
                ],
            },
        }));

        assert!(
            Enumerators::new(&config)
                .open("combined", &mut Unbound::default())
                .is_ok()
        );
    }

    /// The half of the cycle rule that allows.
    #[test]
    fn proxy_upstream_inline_may_be_proxy() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "pypi-simple"},
            "outer": {
                "kind": "proxy-failover",
                "proxy-to": [{
                    "enumerator": {
                        "kind": "proxy-failover",
                        "proxy-to": [{"ref": "primary"}],
                    },
                }],
            },
        }));

        assert!(
            Enumerators::new(&config)
                .open("outer", &mut Unbound::default())
                .is_ok()
        );
    }

    /// The half that refuses, which is the whole of the cycle prevention.
    #[test]
    fn ref_may_not_name_proxy() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "pypi-simple"},
            "inner": {"kind": "proxy-failover", "proxy-to": [{"ref": "primary"}]},
            "outer": {"kind": "proxy-failover", "proxy-to": [{"ref": "inner"}]},
        }));

        let err = match Enumerators::new(&config).open("outer", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a ref to a proxy must not open"),
        };

        let text = err.to_string();

        assert!(text.contains("inner"), "{text}");
        assert!(text.contains("inline"), "{text}: say what to do instead");
    }

    #[test]
    fn proxy_mutual_reference_refused() {
        let config = built(serde_json::json!({
            "a": {"kind": "proxy-failover", "proxy-to": [{"ref": "b"}]},
            "b": {"kind": "proxy-failover", "proxy-to": [{"ref": "a"}]},
        }));

        let mut enumerators = Enumerators::new(&config);

        assert!(enumerators.open("a", &mut Unbound::default()).is_err());
        assert!(enumerators.open("b", &mut Unbound::default()).is_err());
    }

    /// The schema cannot catch this: it does not know which kinds are
    /// proxies.
    #[test]
    fn proxy_kind_naming_host_refused() {
        let config = built(serde_json::json!({
            "p": {"host": "registry", "kind": "proxy-failover"},
        }));

        let err = match Enumerators::new(&config).open("p", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a proxy with a host must not open"),
        };

        assert!(
            err.to_string().contains("options"),
            "{err}: name the exception"
        );
    }

    #[test]
    fn proxy_to_on_ordinary_kind_refused() {
        let config = built(serde_json::json!({
            "primary": {"host": "registry", "kind": "pypi-simple"},
            "odd": {"kind": "pypi-simple", "proxy-to": [{"ref": "primary"}]},
        }));

        let err = match Enumerators::new(&config).open("odd", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("proxy-to on an ordinary kind must not open"),
        };

        assert!(err.to_string().contains("proxy-failover"), "{err}");
    }

    /// A source proxy list and an enumerator proxy list are not
    /// interchangeable, and the two collections are separate namespaces: a
    /// enumerator `ref` naming a *source* resolves against nothing.
    #[test]
    fn ref_does_not_reach_sources_collection() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "hosts": {"registry": {"url": "h://registry.test"}},
            "sources": {"shared-name": {"host": "registry", "kind": "pypi"}},
            "enumerators": {
                "p": {"kind": "proxy-failover", "proxy-to": [{"ref": "shared-name"}]},
            },
        }))
        .expect("parses");

        let err = match Enumerators::new(&config).open("p", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("an enumerator ref must not resolve against sources"),
        };

        assert!(err.to_string().contains("shared-name"), "{err}");
    }

    /// A proxy's own rules reach the user unchanged.
    #[test]
    fn proxy_own_refusal_reported() {
        let config = built(serde_json::json!({
            "empty": {"kind": "proxy-failover", "proxy-to": []},
        }));

        let err = match Enumerators::new(&config).open("empty", &mut Unbound::default()) {
            Err(err) => err,
            Ok(_) => panic!("a failover over nothing must not open"),
        };

        assert!(err.to_string().contains("at least 1"), "{err}");
    }
}
