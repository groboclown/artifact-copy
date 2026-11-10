//! What a packument is, and nothing else.
//!
//! One document carries every version of a package, so this is the largest
//! wire shape in the crate -- which is exactly why it is not in the source
//! module. A reader looking for how npm resolves a version should not have
//! to scroll past a hundred lines of field declarations first.
//!
//! Two of the fields are historical rather than current, and both are
//! carried because the registry still serves packages that use them:
//! [`License`] is a string on modern packages and an object on some old
//! ones, and pre-3.0 packages put an array in `licenses` instead.
//! Some early packages also publish an empty dependency map as `[]`.
//!
//! References: [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
pub(super) struct Packument {
    #[serde(default)]
    pub(super) versions: BTreeMap<String, VersionEntry>,

    /// Version to ISO 8601 publish time, plus `created` and `modified`.
    #[serde(default)]
    pub(super) time: BTreeMap<String, String>,

    /// Whole-package fallback for packages that declare it only here.
    #[serde(default)]
    pub(super) license: Option<License>,
}

#[derive(Debug, Deserialize)]
pub(super) struct VersionEntry {
    #[serde(default)]
    pub(super) license: Option<License>,

    /// Pre-3.0 packages carry this array instead of `license`.
    #[serde(default)]
    pub(super) licenses: Vec<LegacyLicense>,

    #[serde(default)]
    pub(super) dist: Option<Dist>,

    #[serde(default, deserialize_with = "deps")]
    pub(super) dependencies: BTreeMap<String, String>,

    #[serde(rename = "devDependencies", default, deserialize_with = "deps")]
    pub(super) dev_dependencies: BTreeMap<String, String>,

    #[serde(rename = "optionalDependencies", default, deserialize_with = "deps")]
    pub(super) optional_dependencies: BTreeMap<String, String>,

    #[serde(rename = "peerDependencies", default, deserialize_with = "deps")]
    pub(super) peer_dependencies: BTreeMap<String, String>,

    #[serde(rename = "peerDependenciesMeta", default)]
    peer_meta: BTreeMap<String, PeerMeta>,
}

/// Reads a dependency map, accepting `[]` as an empty one.
///
/// `underscore@1.1.7` publishes `"dependencies": []`; a non-empty array
/// carries no ranges, so it stays an error rather than a guess.
fn deps<'de, D: Deserializer<'de>>(input: D) -> Result<BTreeMap<String, String>, D::Error> {
    input.deserialize_any(DepsVisitor)
}

struct DepsVisitor;

impl<'de> Visitor<'de> for DepsVisitor {
    type Value = BTreeMap<String, String>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a map, or an empty array")
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_value(de::Unexpected::Seq, &self));
        }

        Ok(BTreeMap::new())
    }
}

impl VersionEntry {
    pub(super) fn is_optional_peer(&self, name: &str) -> bool {
        self.peer_meta
            .get(name)
            .map(|meta| meta.optional)
            .unwrap_or(false)
    }
}

#[derive(Debug, Deserialize)]
struct PeerMeta {
    #[serde(default)]
    optional: bool,
}

/// `license` is a string on modern packages and an object on some old ones.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum License {
    Text(String),
    Object {
        #[serde(rename = "type")]
        type_name: Option<String>,
    },
}

impl License {
    pub(super) fn text(&self) -> Option<String> {
        match self {
            License::Text(text) => Some(text.clone()),
            License::Object { type_name } => type_name.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct LegacyLicense {
    #[serde(rename = "type", default)]
    pub(super) type_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Dist {
    #[serde(default)]
    pub(super) tarball: Option<String>,

    #[serde(default)]
    pub(super) shasum: Option<String>,

    #[serde(default)]
    pub(super) integrity: Option<String>,

    /// Registry signatures over the integrity hash rather than the bytes,
    /// which is what lets them be checked without the tarball.
    #[serde(default)]
    pub(super) signatures: Vec<DistSignature>,
}

impl Dist {
    /// The tarball's digests. `integrity` is SRI and usually sha512;
    /// `shasum` is the legacy sha1 and still the only digest on older
    /// versions.
    pub(super) fn digests(&self) -> Vec<crate::model::Digest> {
        let integrity = self
            .integrity
            .as_deref()
            .and_then(crate::net::sig::sri_to_digest);

        let shasum = self
            .shasum
            .as_deref()
            .map(|hex| crate::model::Digest::new(crate::model::DigestAlg::Sha1, hex));

        integrity.into_iter().chain(shasum).collect()
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DistSignature {
    pub(super) keyid: String,
    pub(super) sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(json: &str) -> VersionEntry {
        serde_json::from_str(json).expect("parsed")
    }

    /// Every dependency map, so one fixture exercises all four fields.
    fn all_deps(value: &str) -> String {
        format!(
            r#"{{"dependencies":{value},"devDependencies":{value},
                "optionalDependencies":{value},"peerDependencies":{value}}}"#
        )
    }

    fn maps(entry: &VersionEntry) -> [&BTreeMap<String, String>; 4] {
        [
            &entry.dependencies,
            &entry.dev_dependencies,
            &entry.optional_dependencies,
            &entry.peer_dependencies,
        ]
    }

    #[test]
    fn dependencies_empty_array_read() {
        let parsed = entry(&all_deps("[]"));

        for map in maps(&parsed) {
            assert!(map.is_empty());
        }
    }

    #[test]
    fn dependencies_map_still_parses() {
        let parsed = entry(&all_deps(r#"{"a":"^1"}"#));

        for map in maps(&parsed) {
            assert_eq!(map.get("a").map(String::as_str), Some("^1"));
        }
    }

    #[test]
    fn dependencies_missing_field_empty() {
        let parsed = entry("{}");

        for map in maps(&parsed) {
            assert!(map.is_empty());
        }
    }

    #[test]
    fn dependencies_nonempty_array_malformed() {
        let err = serde_json::from_str::<VersionEntry>(r#"{"dependencies":["x"]}"#).unwrap_err();

        assert!(
            err.to_string().contains("a map, or an empty array"),
            "{err}"
        );
    }
}
