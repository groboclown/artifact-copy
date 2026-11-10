//! The `options` block of a configured extension.
//!
//! Free-form by design -- an extension knows what it needs and the schema
//! cannot -- but with a few **well-known keys** that mean the same thing
//! everywhere, so a user does not have to learn a different spelling of
//! "which repository" for each product.
//!
//! # Why `ecosystem` is one of them
//!
//! A repository manager such as Nexus or Artifactory hosts many formats
//! behind one API, so its *implementation* speaks several ecosystems -- that
//! is what [`crate::repo::enumerate::Enumerator::ecosystems`] records. A configured
//! *instance* of it points at one repository, which holds one format:
//!
//! ```yaml
//! sources:
//!   internal-maven:
//!     kind: nexus3
//!     host: nexus
//!     options:
//!       repository: maven-releases
//!       ecosystem: maven
//! ```
//!
//! The user states the ecosystem rather than the tool detecting it. Probing
//! a repository to find out what it holds is a round trip, a guess, and a
//! failure mode on an empty repository; declaring it is none of those. An
//! auto-detect capability could be added later without changing this, since
//! the key would simply become optional.

use serde_json::{Map, Value};

use crate::core::error::{Error, Result};
use crate::model::EcosystemId;

/// Which repository within the host this entry refers to.
///
/// Meaningless for a registry that is itself one repository -- npmjs.org has
/// no such notion -- and required by every repository manager.
pub const REPOSITORY: &str = "repository";

/// Which ecosystem a configured instance handles.
///
/// Only meaningful for an extension whose implementation speaks more than
/// one; a registry adapter ignores it.
pub const ECOSYSTEM: &str = "ecosystem";

/// A configured extension's options.
#[derive(Debug, Clone, Default)]
pub struct Options {
    raw: Map<String, Value>,
}

impl Options {
    pub fn new(raw: Map<String, Value>) -> Self {
        Self { raw }
    }

    /// Every option as written, for handing to an extension.
    pub(crate) fn as_map(&self) -> &Map<String, Value> {
        &self.raw
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// The declared ecosystem, if any.
    pub fn ecosystem(&self) -> Result<Option<EcosystemId>> {
        Ok(self.string(ECOSYSTEM)?.map(EcosystemId::new))
    }

    /// The declared repository name, if any.
    pub fn repository(&self) -> Result<Option<&str>> {
        self.string(REPOSITORY)
    }

    /// A string option.
    ///
    /// A wrong *type* is an error rather than a silent `None`: a user who
    /// wrote `repository: 42` made a mistake and should hear about it, not
    /// watch the setting be ignored.
    pub fn string(&self, key: &str) -> Result<Option<&str>> {
        match self.raw.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(other) => Err(self.wrong_type(key, "a string", other)),
        }
    }

    /// A string option that must be present.
    pub fn require_string(&self, key: &str) -> Result<&str> {
        self.string(key)?
            .ok_or_else(|| Error::Config(format!("this extension requires the {key:?} option")))
    }

    pub fn bool(&self, key: &str) -> Result<Option<bool>> {
        match self.raw.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(other) => Err(self.wrong_type(key, "true or false", other)),
        }
    }

    /// A list of strings.
    ///
    /// An **empty list is a value**, not an absence: a source told
    /// `checksums: []` has been asked to probe none, which is a reasonable
    /// thing to say about a repository that publishes none and saves a
    /// request per file. Only a missing key and an explicit null are
    /// `None`.
    pub fn string_list(&self, key: &str) -> Result<Option<Vec<&str>>> {
        let Some(value) = self.raw.get(key) else {
            return Ok(None);
        };

        let items = match value {
            Value::Null => return Ok(None),
            Value::Array(items) => items,
            other => return Err(self.wrong_type(key, "a list of strings", other)),
        };

        items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.as_str()),
                other => Err(self.wrong_type(key, "a list of strings", other)),
            })
            .collect::<Result<Vec<&str>>>()
            .map(Some)
    }

    pub fn integer(&self, key: &str) -> Result<Option<i64>> {
        match self.raw.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(number)) => number.as_i64().map(Some).ok_or_else(|| {
                self.wrong_type(key, "a whole number", &Value::Number(number.clone()))
            }),
            Some(other) => Err(self.wrong_type(key, "a whole number", other)),
        }
    }

    /// A span of time, spelled as the configuration spells one: a bare
    /// number of seconds or a suffixed string such as `"24 hours"`.
    pub fn duration(&self, key: &str) -> Result<Option<std::time::Duration>> {
        match self.raw.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => serde_json::from_value::<crate::config::ConfigDuration>(value.clone())
                .map(|parsed| Some(parsed.get()))
                .map_err(|source| {
                    Error::Config(format!(
                        "extension option {key:?} is not a duration: {source}"
                    ))
                }),
        }
    }

    /// A quantity of bytes, spelled as the configuration spells one: a bare
    /// number of bytes or a suffixed string such as `"50 MiB"`.
    pub fn size(&self, key: &str) -> Result<Option<u64>> {
        match self.raw.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => serde_json::from_value::<crate::config::ByteSize>(value.clone())
                .map(|parsed| Some(parsed.get()))
                .map_err(|source| {
                    Error::Config(format!("extension option {key:?} is not a size: {source}"))
                }),
        }
    }

    /// Keys this extension was given.  For reporting one it does not know,
    /// which is usually a typo.
    pub fn keys(&self) -> Vec<&str> {
        self.raw.keys().map(String::as_str).collect()
    }

    fn wrong_type(&self, key: &str, wanted: &str, found: &Value) -> Error {
        let kind = match found {
            Value::Null => "null",
            Value::Bool(_) => "true or false",
            Value::Number(_) => "a number",
            Value::String(_) => "a string",
            Value::Array(_) => "a list",
            Value::Object(_) => "a map",
        };

        Error::Config(format!(
            "the {key:?} option should be {wanted}, but it is {kind}"
        ))
    }
}

impl From<Map<String, Value>> for Options {
    fn from(raw: Map<String, Value>) -> Self {
        Self::new(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(json: &str) -> Options {
        let raw: Map<String, Value> = serde_json::from_str(json).expect("parses");

        Options::new(raw)
    }

    /// The shape a repository-manager entry takes: which repository, and
    /// which of the formats that manager hosts it holds.
    #[test]
    fn entry_repository_manager_declares_both() {
        let configured = options(r#"{"repository": "maven-releases", "ecosystem": "maven"}"#);

        assert_eq!(configured.repository().unwrap(), Some("maven-releases"));
        assert_eq!(configured.ecosystem().unwrap(), Some(EcosystemId::maven()));
    }

    /// A registry adapter needs neither, and absence is not an error.
    #[test]
    fn entry_registry_needs_neither() {
        let configured = Options::default();

        assert!(configured.is_empty());
        assert_eq!(configured.repository().unwrap(), None);
        assert_eq!(configured.ecosystem().unwrap(), None);
    }

    /// The ecosystem is an open string, so a third-party one is nameable
    /// here exactly as a built-in is.
    #[test]
    fn ecosystem_unknown_still_nameable() {
        let configured = options(r#"{"ecosystem": "cargo"}"#);

        assert_eq!(
            configured.ecosystem().unwrap(),
            Some(EcosystemId::new("cargo"))
        );
    }

    /// A user who wrote the wrong type made a mistake and should hear about
    /// it, rather than watch the setting be silently ignored.
    #[test]
    fn option_wrong_type_refused() {
        let configured = options(r#"{"repository": 42}"#);

        let err = match configured.repository() {
            Err(err) => err,
            Ok(_) => panic!("42 is not a repository name"),
        };

        assert!(err.to_string().contains("should be a string"));
        assert!(err.to_string().contains("it is a number"));
    }

    /// An explicit null reads as absent, which is what a YAML writer means
    /// by an empty value.
    #[test]
    fn option_null_reads_absent() {
        let configured = options(r#"{"repository": null}"#);

        assert_eq!(configured.repository().unwrap(), None);
    }

    #[test]
    fn option_required_names_itself_when_missing() {
        let err = match Options::default().require_string(REPOSITORY) {
            Err(err) => err,
            Ok(_) => panic!("nothing was configured"),
        };

        assert!(err.to_string().contains("repository"));
    }

    #[test]
    fn option_typed_readers_reject_mismatches() {
        let configured = options(r#"{"flag": "yes", "count": "many"}"#);

        assert!(configured.bool("flag").is_err());
        assert!(configured.integer("count").is_err());
    }

    #[test]
    fn option_keys_reported_for_diagnostics() {
        let configured = options(r#"{"repository": "r", "unknown-thing": 1}"#);

        assert_eq!(configured.keys(), vec!["repository", "unknown-thing"]);
    }

    #[test]
    fn duration_reads_either_spelling() {
        let configured = crate::ext::testing::options(serde_json::json!({
            "seconds": 90,
            "spelled": "2 hours",
            "wrong": true,
        }));

        assert_eq!(
            configured.duration("seconds").expect("read"),
            Some(std::time::Duration::from_secs(90))
        );
        assert_eq!(
            configured.duration("spelled").expect("read"),
            Some(std::time::Duration::from_secs(7_200))
        );
        assert_eq!(configured.duration("absent").expect("read"), None);
        assert!(configured.duration("wrong").is_err());
    }

    #[test]
    fn size_reads_either_spelling() {
        let configured = crate::ext::testing::options(serde_json::json!({
            "bytes": 1_024,
            "spelled": "50 MiB",
            "wrong": true,
        }));

        assert_eq!(configured.size("bytes").expect("read"), Some(1_024));
        assert_eq!(
            configured.size("spelled").expect("read"),
            Some(50 * 1_048_576)
        );
        assert_eq!(configured.size("absent").expect("read"), None);
        assert!(configured.size("wrong").is_err());
    }
}
