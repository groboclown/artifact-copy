//! Which configured urls travel without TLS, and whether that was asked for.
//!
//! An `http://` url sends credentials in the clear and lets anything on the
//! path supply the bytes, checksums, and signatures the tool then trusts.
//! The tool does not decide that a network is safe; the user does, by
//! setting `insecure-transport` on the host. Without it the url is refused
//! when the configuration loads, so plain HTTP is never an accident.
//!
//! ```text
//!   hosts.NAME.url          http://  needs hosts.NAME.insecure-transport
//!   hosts.NAME.mirrors[].url
//!   hosts.NAME.keyservers[]
//!   setup.keyservers[]      http://  always refused: no host to opt in
//! ```
//!
//! A `file://` host and a bare `additional-hosts` hostname, which is always
//! reached over `https`, never travel over plain HTTP.

use super::Config;

/// The scheme that carries no TLS.
const PLAIN_SCHEME: &str = "http";

/// Every url that travels without TLS and was not allowed to, described
/// for an error: `host "mirror" url http://mirror.internal/`.
pub(crate) fn refused(config: &Config) -> Vec<String> {
    let mut refused = Vec::new();

    for (name, host) in &config.hosts {
        if host.insecure_transport {
            continue;
        }

        let urls = std::iter::once(("url", host.url.as_str()))
            .chain(
                host.mirrors
                    .iter()
                    .map(|mirror| ("mirror", mirror.url.as_str())),
            )
            .chain(
                host.keyservers
                    .iter()
                    .map(|url| ("keyserver", url.as_str())),
            );

        for (what, url) in urls {
            if is_plain(url) {
                refused.push(format!("host {name:?} {what} {url}"));
            }
        }
    }

    for url in &config.setup.keyservers {
        if is_plain(url) {
            refused.push(format!("setup keyserver {url}"));
        }
    }

    refused
}

/// The hosts that accept plain HTTP, for `validate-config` to name.
pub(crate) fn insecure_hosts(config: &Config) -> Vec<&str> {
    config
        .hosts
        .iter()
        .filter(|(_, host)| host.insecure_transport)
        .map(|(name, _)| name.as_str())
        .collect()
}

/// Whether `url` names the `http` scheme. A url that will not parse is
/// another check's to refuse.
fn is_plain(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == PLAIN_SCHEME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: serde_json::Value) -> Config {
        serde_json::from_value(json).expect("a configuration")
    }

    /// Every place a url can name plain HTTP is refused, and each is named.
    #[test]
    fn plain_http_refused_everywhere() {
        let refused = refused(&config(serde_json::json!({
            "setup": {"keyservers": ["http://keys.test/"]},
            "hosts": {
                "plain": {"url": "http://plain.test/"},
                "mirrored": {
                    "url": "https://secure.test/",
                    "mirrors": [{"url": "http://mirror.test/"}],
                    "keyservers": ["http://hostkeys.test/"]
                }
            }
        })));

        assert_eq!(
            refused,
            [
                "host \"mirrored\" mirror http://mirror.test/",
                "host \"mirrored\" keyserver http://hostkeys.test/",
                "host \"plain\" url http://plain.test/",
                "setup keyserver http://keys.test/",
            ]
        );
    }

    /// A host that opts in may use plain HTTP for its url, mirrors, and
    /// keyservers; TLS and local directories never need it.
    #[test]
    fn opted_in_and_tls_accepted() {
        let config = config(serde_json::json!({
            "hosts": {
                "lab": {
                    "url": "http://lab.test/",
                    "insecure-transport": true,
                    "mirrors": [{"url": "http://lab-mirror.test/"}],
                    "keyservers": ["http://lab-keys.test/"]
                },
                "secure": {"url": "https://secure.test/"},
                "local": {"url": "file:///srv/mirror/"}
            }
        }));

        assert!(refused(&config).is_empty());
        assert_eq!(insecure_hosts(&config), ["lab"]);
    }
}
