//! AWS Secrets Manager driver.
//!
//! Hides the SDK, its async client, and the process cache behind one
//! blocking call, so [`super::SecretValue::resolve`] stays synchronous.
//!
//! ```text
//!   resolve() --> fetch() --> CACHE hit? --yes--> Secret
//!                                 | no
//!                                 v
//!                   scoped thread + current-thread runtime
//!                                 |
//!                                 v
//!                   GetSecretValue --> CACHE insert --> Secret
//! ```

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use aws_config::{BehaviorVersion, Region};
use aws_sdk_secretsmanager::error::DisplayErrorContext;

use super::Secret;
use crate::core::error::{Error, Result};

/// Which secret to read, and through which region and profile.
pub(super) struct Locator<'a> {
    pub(super) name: &'a str,
    pub(super) region: Option<&'a str>,
    pub(super) profile: Option<&'a str>,
}

/// The owned form of a [`Locator`], for the cache.
#[derive(Clone, PartialEq, Eq, Hash)]
struct LocatorKey {
    name: String,
    region: Option<String>,
    profile: Option<String>,
}

impl From<&Locator<'_>> for LocatorKey {
    fn from(locator: &Locator<'_>) -> Self {
        LocatorKey {
            name: locator.name.to_owned(),
            region: locator.region.map(str::to_owned),
            profile: locator.profile.map(str::to_owned),
        }
    }
}

/// Every secret fetched this run.  `resolve` runs per request, and one
/// Secrets Manager call per request would be slow and billed.
static CACHE: OnceLock<Mutex<HashMap<LocatorKey, Secret>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<LocatorKey, Secret>> {
    CACHE.get_or_init(Mutex::default)
}

/// The secret's whole `SecretString`.
///
/// Only successes are cached, so a transient failure is retried next call.
pub(super) fn fetch(locator: &Locator<'_>) -> Result<Secret> {
    let key = LocatorKey::from(locator);

    if let Some(hit) = lock_cache().get(&key) {
        return Ok(hit.clone());
    }

    let secret = fetch_blocking(locator)?;

    lock_cache().insert(key, secret.clone());
    Ok(secret)
}

/// A poisoned lock only means another thread panicked mid-insert; the map
/// itself is still sound.
fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<LocatorKey, Secret>> {
    cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Run the async lookup to completion from synchronous code.
///
/// A dedicated thread with its own runtime works whether or not the caller
/// is inside tokio; `block_in_place` panics on a current-thread runtime.
fn fetch_blocking(locator: &Locator<'_>) -> Result<Secret> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| {
                        Error::Config(format!(
                            "AWS secret {}: cannot start runtime: {err}",
                            locator.name
                        ))
                    })?;

                runtime.block_on(fetch_async(locator))
            })
            .join()
            .unwrap_or_else(|_| {
                Err(Error::Config(format!(
                    "AWS secret {}: lookup panicked",
                    locator.name
                )))
            })
    })
}

async fn fetch_async(locator: &Locator<'_>) -> Result<Secret> {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());

    if let Some(region) = locator.region {
        loader = loader.region(Region::new(region.to_owned()));
    }

    if let Some(profile) = locator.profile {
        loader = loader.profile_name(profile);
    }

    let client = aws_sdk_secretsmanager::Client::new(&loader.load().await);

    // The error context names the failure, never the payload.
    let output = client
        .get_secret_value()
        .secret_id(locator.name)
        .send()
        .await
        .map_err(|err| {
            Error::Config(format!(
                "AWS secret {}: {}",
                locator.name,
                DisplayErrorContext(&err)
            ))
        })?;

    let Some(body) = output.secret_string() else {
        return Err(Error::Config(format!(
            "AWS secret {} holds binary data, not a string",
            locator.name
        )));
    };

    Ok(Secret(body.to_owned()))
}

/// Read one scalar from a JSON-object secret.
///
/// `{"user":"ci","port":5432}` gives `ci` for `user` and `5432` for `port`.
/// Errors name the secret and key, never the body, since a parser message
/// can echo the content it choked on.
pub(super) fn json_key(name: &str, body: &str, key: &str) -> Result<String> {
    let Ok(serde_json::Value::Object(mut fields)) = serde_json::from_str(body) else {
        return Err(Error::Config(format!(
            "AWS secret {name} is not a JSON object"
        )));
    };

    let Some(value) = fields.remove(key) else {
        return Err(Error::Config(format!(
            "AWS secret {name} defines no key {key:?}"
        )));
    };

    match value {
        serde_json::Value::String(text) => Ok(text),
        serde_json::Value::Number(number) => Ok(number.to_string()),
        serde_json::Value::Bool(flag) => Ok(flag.to_string()),

        _ => Err(Error::Config(format!(
            "AWS secret {name} key {key:?} is not a scalar"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "db-creds";

    const BODY: &str =
        r#"{"user":"ci","port":5432,"tls":true,"none":null,"nested":{"a":1},"list":[1]}"#;

    fn key(wanted: &str) -> Result<String> {
        json_key(NAME, BODY, wanted)
    }

    /// A cached secret never reaches the network: this name does not exist,
    /// and no credentials are needed.
    #[test]
    fn cached_secret_skips_lookup() {
        let locator = Locator {
            name: "artifact-copy-test-cached",
            region: Some("us-east-1"),
            profile: None,
        };

        lock_cache().insert(LocatorKey::from(&locator), Secret("seeded".to_owned()));

        assert_eq!(fetch(&locator).expect("cached").expose(), "seeded");
    }

    #[test]
    fn key_string_read() {
        assert_eq!(key("user").expect("read"), "ci");
    }

    #[test]
    fn key_scalar_stringified() {
        assert_eq!(key("port").expect("read"), "5432");
        assert_eq!(key("tls").expect("read"), "true");
    }

    #[test]
    fn key_non_scalar_refused() {
        for wanted in ["none", "nested", "list"] {
            let err = key(wanted).expect_err("not a scalar");

            assert!(err.to_string().contains("not a scalar"), "{err}");
        }
    }

    #[test]
    fn key_missing_named() {
        let err = key("password").expect_err("missing");

        assert!(err.to_string().contains("password"), "{err}");
        assert!(err.to_string().contains(NAME), "{err}");
    }

    /// A parser message can echo the content, so the body must not appear.
    #[test]
    fn key_non_object_hides_body() {
        for body in ["hunter2", r#"["hunter2"]"#, r#""hunter2""#] {
            let err = json_key(NAME, body, "user").expect_err("not an object");

            assert!(!err.to_string().contains("hunter2"), "{err}");
            assert!(err.to_string().contains("not a JSON object"), "{err}");
        }
    }
}
