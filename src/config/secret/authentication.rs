//! How to authenticate with a host, and the secrets that takes.

use serde::{Deserialize, Serialize};

use super::SecretValue;

/// How to authenticate with a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Authentication {
    /// HTTP basic.  Credentials travel in plain text, so this belongs only
    /// on a TLS connection.
    Basic {
        username: Option<SecretValue>,
        password: Option<SecretValue>,
    },

    /// A bearer token, passed through as-is.
    Bearer {
        token: Option<SecretValue>,

        #[serde(default = "default_bearer_header")]
        header: String,

        #[serde(default = "default_bearer_prefix")]
        prefix: String,
    },
}

fn default_bearer_header() -> String {
    "Authorization".to_owned()
}

fn default_bearer_prefix() -> String {
    "Bearer ".to_owned()
}

impl Authentication {
    /// Every secret this configuration references, for `validate-config`.
    pub fn secrets(&self) -> Vec<&SecretValue> {
        match self {
            Authentication::Basic { username, password } => [username.as_ref(), password.as_ref()]
                .into_iter()
                .flatten()
                .collect(),

            Authentication::Bearer { token, .. } => token.iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_defaults_match_schema() {
        let auth: Authentication =
            serde_json::from_str(r#"{"kind":"bearer","token":{"kind":"text","value":"x"}}"#)
                .expect("parses");

        let Authentication::Bearer { header, prefix, .. } = &auth else {
            panic!("expected bearer");
        };

        assert_eq!(header, "Authorization");
        assert_eq!(prefix, "Bearer ");
    }

    #[test]
    fn basic_auth_reports_both_secrets() {
        let auth = Authentication::Basic {
            username: Some(SecretValue::Env { name: "U".into() }),
            password: Some(SecretValue::Env { name: "P".into() }),
        };

        assert_eq!(auth.secrets().len(), 2);
    }
}
