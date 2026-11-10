//! A binding's cache policy, from its configuration.
//!
//! Freshness rules are tried in this order, and the first match wins:
//!
//! ```text
//!   the binding's cache-freshness   (or its server kind's, when it sets none)
//!   setup.cache-freshness
//!   each ecosystem's built-in rules
//! ```
//!
//! Retention is the binding's own `cache-retention`, else `setup`'s, else
//! forever. A binding's `cache-size` caps its repository's folder; the
//! whole cache directory's cap is not a binding's, so it is not here.

use crate::config::{ByteSize, ConfigLifetime, FreshnessRule as RuleConfig, Setup};
use crate::ext::{CachePolicy, FreshnessRule};

/// The policy for a binding configured with `retention`, `rules`, and
/// `size`.
pub fn policy(
    setup: &Setup,
    retention: Option<ConfigLifetime>,
    rules: &[RuleConfig],
    size: Option<ByteSize>,
) -> CachePolicy {
    let configured = rules
        .iter()
        .chain(&setup.cache_freshness)
        .map(|rule| FreshnessRule::new(&rule.files, rule.fresh_for.get()));

    let built_in = crate::ecosystem::freshness_defaults()
        .into_iter()
        .map(|(pattern, fresh_for)| FreshnessRule::new(pattern, Some(fresh_for)));

    CachePolicy::new(
        retention
            .or(setup.cache_retention)
            .and_then(ConfigLifetime::get),
        configured.chain(built_in).collect(),
    )
    .with_size_cap(size.map(ByteSize::get))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::ConfigDuration;

    const MINUTE: Duration = Duration::from_secs(60);

    fn rule(files: &str, fresh_for: ConfigLifetime) -> RuleConfig {
        RuleConfig {
            files: files.to_owned(),
            fresh_for,
        }
    }

    fn minutes(count: u64) -> ConfigLifetime {
        ConfigLifetime::For(ConfigDuration::from_secs(count * 60))
    }

    /// The binding's rule, then setup's, then the built-in one.
    #[test]
    fn binding_rule_wins() {
        let setup = Setup {
            cache_freshness: vec![rule("maven-metadata.xml", minutes(10))],
            ..Setup::default()
        };

        let binding = policy(
            &setup,
            None,
            &[rule("maven-metadata.xml", minutes(1))],
            None,
        );
        let unset = policy(&setup, None, &[], None);
        let bare = policy(&Setup::default(), None, &[], None);

        assert_eq!(
            binding.lifetime("maven-metadata.xml").freshness,
            Some(MINUTE)
        );
        assert_eq!(
            unset.lifetime("maven-metadata.xml").freshness,
            Some(MINUTE * 10)
        );
        assert_eq!(
            bare.lifetime("maven-metadata.xml").freshness,
            Some(MINUTE * 60)
        );
    }

    /// A payload no rule names is fresh forever.
    #[test]
    fn payload_unnamed_fresh_forever() {
        assert_eq!(
            policy(&Setup::default(), None, &[], None)
                .lifetime("core-1.0.jar")
                .freshness,
            None
        );
    }

    /// A binding's `forever` lifts a limit set in `setup`.
    #[test]
    fn binding_forever_lifts_setup() {
        let setup = Setup {
            cache_retention: Some(minutes(5)),
            ..Setup::default()
        };

        assert_eq!(
            policy(&setup, None, &[], None).lifetime("x").retention,
            Some(MINUTE * 5)
        );
        assert_eq!(
            policy(&setup, Some(ConfigLifetime::Forever), &[], None)
                .lifetime("x")
                .retention,
            None
        );
    }

    /// A binding's `cache-size` becomes its policy's cap; the cache
    /// directory's cap is not a binding's.
    #[test]
    fn binding_size_is_cap() {
        let setup = Setup {
            cache_size: Some(ByteSize::mib(10)),
            ..Setup::default()
        };

        assert_eq!(policy(&setup, None, &[], None).size_cap_bytes(), None);
        assert_eq!(
            policy(&setup, None, &[], Some(ByteSize::mib(1))).size_cap_bytes(),
            Some(1_048_576)
        );
    }
}
