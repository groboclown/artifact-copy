//! Credentials, and where they come from.
//!
//! The `Debug` impls here redact deliberately.  `--unsafe-debug` is the only
//! path allowed to print a resolved credential, and a stray `{:?}` in an
//! error message must not be able to defeat that.
//!
//! # A secret follows its named path rule
//!
//! A `config-relative-path` resolves against **the file that declared it**.
//! A `working-dir-path` resolves against **the working directory**. A
//! [`SecretValue::PropertyFile`] accepts either key.
//!
//! That is deliberate rather than an oversight, and it is the `.env`
//! convention: a `.env` is read relative to where the command was run, and a
//! credential file is the thing an operator supplies per invocation rather
//! than something checked in beside a policy.  There is no way to ask for
//! the other behaviour, which is the point - an API for resolving a secret
//! against some other base is how the rule quietly changes and credentials
//! start being read from somewhere else.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};

mod authentication;
mod aws;
mod property_file;

pub use authentication::Authentication;

/// Where a secret's value comes from.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretValue {
    /// Written in the config file itself.
    Text { value: String },

    /// Read from an environment variable.
    Env { name: String },

    /// An AWS Secrets Manager secret held as a plain string.
    ///
    /// Credentials and region come from the AWS default chain unless
    /// `region` or `profile` is given.
    AwsSecret {
        name: String,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
    },

    /// One key of a JSON-encoded AWS Secrets Manager secret.
    ///
    /// A number or boolean value becomes its JSON text.
    AwsSecretKey {
        name: String,
        key: String,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
    },

    /// One entry of a `.env`-style property file.
    ///
    /// **The file is the only source.** Ordinary `.env` tooling treats the
    /// file as defaults and lets the process environment override or fill
    /// in what is missing; this deliberately does not. Two reasons, and
    /// both matter more than the convenience:
    ///
    /// - A configuration that resolves differently depending on the
    ///   surrounding environment is not reproducible, and a migration that
    ///   silently authenticated as somebody else is a bad way to find out.
    /// - Falling back to the environment means anything that can set a
    ///   variable can substitute a credential. Naming a file and then
    ///   honoring something else is the shape of that mistake.
    ///
    /// A missing file, or a missing key within it, is an error naming what
    /// was looked for -- never a quiet fallback.
    ///
    /// `working-dir-path` resolves against the working directory.
    /// `config-relative-path` resolves against its declaring configuration.
    PropertyFile {
        #[serde(rename = "working-dir-path", alias = "config-relative-path")]
        working_dir_path: PathBuf,
        key: String,
    },
}

/// Redacts.  The variant and any non-secret locator are useful in a log; the
/// value never is.
impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretValue::Text { .. } => f.write_str("SecretValue::Text(<redacted>)"),

            SecretValue::Env { name } => write!(f, "SecretValue::Env({name})"),

            SecretValue::AwsSecret { name, .. } => write!(f, "SecretValue::AwsSecret({name})"),

            SecretValue::AwsSecretKey { name, key, .. } => {
                write!(f, "SecretValue::AwsSecretKey({name}#{key})")
            }

            SecretValue::PropertyFile {
                working_dir_path,
                key,
            } => {
                write!(
                    f,
                    "SecretValue::PropertyFile({}#{key})",
                    working_dir_path.display()
                )
            }
        }
    }
}

impl SecretValue {
    /// A description safe to log: says where the value comes from, never
    /// what it is.
    pub fn describe(&self) -> String {
        match self {
            SecretValue::Text { .. } => "inline text".to_owned(),
            SecretValue::Env { name } => format!("environment variable {name}"),
            SecretValue::AwsSecret { name, region, .. } => {
                format!("AWS secret {name}{}", in_region(region))
            }

            SecretValue::AwsSecretKey {
                name, key, region, ..
            } => format!("AWS secret {name}{} key {key}", in_region(region)),

            SecretValue::PropertyFile {
                working_dir_path,
                key,
            } => {
                format!("property {key} in {}", working_dir_path.display())
            }
        }
    }

    /// Resolve to the actual value.
    ///
    /// `validate-config` calls this for every configured secret, per
    /// the README, which is how a misspelled environment variable is caught
    /// before a migration starts rather than an hour into one.
    ///
    /// The named path key selects the resolution base before deserialization.
    pub fn resolve(&self) -> Result<Secret> {
        match self {
            SecretValue::Text { value } => Ok(Secret(value.clone())),

            SecretValue::Env { name } => std::env::var(name)
                .map(Secret)
                .map_err(|_| Error::Config(format!("environment variable {name} is not set"))),

            SecretValue::AwsSecret {
                name,
                region,
                profile,
            } => aws::fetch(&aws::Locator {
                name,
                region: region.as_deref(),
                profile: profile.as_deref(),
            }),

            SecretValue::AwsSecretKey {
                name,
                key,
                region,
                profile,
            } => {
                let body = aws::fetch(&aws::Locator {
                    name,
                    region: region.as_deref(),
                    profile: profile.as_deref(),
                })?;

                aws::json_key(name, body.expose(), key).map(Secret)
            }

            SecretValue::PropertyFile {
                working_dir_path,
                key,
            } => property_file::load(working_dir_path, key),
        }
    }
}

/// The `describe` suffix for an explicit region, e.g. ` (us-east-1)`.
fn in_region(region: &Option<String>) -> String {
    match region {
        Some(region) => format!(" ({region})"),
        None => String::new(),
    }
}

/// A resolved credential.
///
/// Wrapped so it cannot be printed by accident; [`Secret::expose`] is the
/// only way out, and it is greppable.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Read the value.  Every call site is a place a credential could leak,
    /// so keep them few and obvious.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod property_file_tests {
    use super::*;

    /// The locator is useful in a log; the value never is.
    #[test]
    fn debug_property_file_shows_locator() {
        let secret = SecretValue::PropertyFile {
            working_dir_path: std::path::PathBuf::from("secrets/.env"),
            key: "TOKEN".to_owned(),
        };

        let rendered = format!("{secret:?}");

        assert!(rendered.contains("secrets/.env"), "{rendered}");
        assert!(rendered.contains("TOKEN"), "{rendered}");
        assert!(secret.describe().contains("secrets/.env"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the wrapper: a stray `{:?}` must not leak.
    #[test]
    fn debug_never_prints_inline_value() {
        let secret = SecretValue::Text {
            value: "hunter2".into(),
        };

        let rendered = format!("{secret:?}");

        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn resolved_secret_redacted_in_both_traits() {
        let secret = Secret("hunter2".into());

        assert!(!format!("{secret:?}").contains("hunter2"));
        assert!(!format!("{secret}").contains("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
    }

    /// A locator is safe to print and genuinely useful when a lookup fails.
    #[test]
    fn debug_keeps_non_secret_locator() {
        let secret = SecretValue::Env {
            name: "NPM_TOKEN".into(),
        };

        assert!(format!("{secret:?}").contains("NPM_TOKEN"));
        assert_eq!(secret.describe(), "environment variable NPM_TOKEN");
    }

    #[test]
    fn environment_unset_is_config_error() {
        let secret = SecretValue::Env {
            name: "ARTIFACT_COPY_DEFINITELY_UNSET".into(),
        };

        let err = secret.resolve().unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::ConfigInvalid);
    }
}

#[cfg(test)]
mod aws_secret_tests {
    use super::*;

    const NAME: &str = "db-creds";

    #[test]
    fn optional_fields_round_trip() {
        let bare: SecretValue =
            serde_json::from_str(r#"{"kind":"aws-secret","name":"n"}"#).expect("parses");

        assert_eq!(
            serde_json::to_string(&bare).expect("serializes"),
            r#"{"kind":"aws-secret","name":"n"}"#
        );

        let full: SecretValue = serde_json::from_str(
            r#"{"kind":"aws-secret-key","name":"n","key":"k","region":"eu-west-1","profile":"ci"}"#,
        )
        .expect("parses");

        assert_eq!(
            full,
            SecretValue::AwsSecretKey {
                name: "n".into(),
                key: "k".into(),
                region: Some("eu-west-1".into()),
                profile: Some("ci".into()),
            }
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let parsed: std::result::Result<SecretValue, _> =
            serde_json::from_str(r#"{"kind":"aws-secret","name":"n","regoin":"x"}"#);

        assert!(parsed.is_err());
    }

    #[test]
    fn describe_shows_locator_only() {
        let secret = SecretValue::AwsSecretKey {
            name: NAME.into(),
            key: "user".into(),
            region: Some("us-east-1".into()),
            profile: Some("ci".into()),
        };

        assert_eq!(
            secret.describe(),
            "AWS secret db-creds (us-east-1) key user"
        );
        assert_eq!(
            format!("{secret:?}"),
            "SecretValue::AwsSecretKey(db-creds#user)"
        );
    }
}
