//! The exchange format: what an extension says about itself, and the
//! schema every message validates against.
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::lock::LockFormat;
use crate::model::{DepKind, ListingDepth};

/// The one exchange format, compiled in so validation needs no source tree.
///
/// Every message in either direction validates against this, which is what
/// "unique and well defined" means in practice rather than as an aspiration.
pub(crate) const PROTOCOL_SCHEMA: &str =
    include_str!("../../../schema/extension-protocol.schema.json");

/// The exchange-format version this build speaks.
///
/// Carried in every [`Description`], so a mismatch is a clear refusal rather
/// than a confusing parse failure somewhere downstream.
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// Which interface an extension provides.
///
/// An implementation may declare several: a registry that can be both read
/// and written provides `Source` and `Target`, and one that is read-only
/// provides just `Source`. Nothing requires a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PointKind {
    Ecosystem,
    Source,
    Target,
    Enumerator,
    Advisory,
    Lock,
}

impl PointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PointKind::Ecosystem => "ecosystem",
            PointKind::Source => "source",
            PointKind::Target => "target",
            PointKind::Enumerator => "enumerator",
            PointKind::Advisory => "advisory",
            PointKind::Lock => "lock",
        }
    }
}

impl fmt::Display for PointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What an extension says about itself, before anything else is asked of it.
///
/// This is what lets `kind` be a free string: the host needs no hardcoded
/// table saying `maven-html-index` is a Maven enumerator, because the
/// enumerator says so. It is also how an ecosystem extension supplies its purl
/// type and OSV name, which is what makes a third-party ecosystem possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Description {
    pub protocol: u32,
    pub points: Vec<PointKind>,

    /// The ecosystems this extension speaks.
    ///
    /// **Plural, and that is not future-proofing for its own sake.** A
    /// repository manager -- Nexus, Artifactory -- exposes one REST API
    /// covering every format it hosts: a single `components` endpoint
    /// returns Maven, npm and PyPI artifacts together, behind one host, one
    /// credential and one pagination cursor.  Forcing such an extension to
    /// register as `nexus-maven`, `nexus-npm` and `nexus-pypi` would split
    /// one implementation into three that must then share state they have
    /// no way to share.
    ///
    /// Artifacts are already self-describing -- an [`crate::model::ArtifactId`]
    /// carries its own ecosystem -- so the only thing that ever assumed a
    /// single ecosystem per extension was this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ecosystems: Vec<EcosystemDesc>,

    /// Dependency kinds this extension can report.  Not `&'static` because
    /// an out-of-process extension cannot supply one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dep_kinds: Vec<DepKind>,

    /// Lock formats this extension reads, for `Lock` providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_formats: Vec<LockFormat>,

    /// Whether a `Enumerator` can report when an artifact was last downloaded.
    ///
    /// Declared rather than probed, so a command that depends on usage
    /// data can **refuse before it starts** instead of walking a catalog
    /// and finding every answer is
    /// [`Unknown`](crate::model::LastDownload::Unknown). Over a repository
    /// of millions that is the difference between an immediate error and a
    /// long walk that produces nothing usable.
    ///
    /// `false` by default, which is the honest default: almost nothing can
    /// report this. A Maven directory index, npm's replication feed and
    /// PyPI's simple index carry no usage data at all. Repository managers
    /// do, which is why `nexus` and `artifactory` set it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reports_last_download: bool,

    /// How far an `Enumerator`'s listing reaches. `names` by default,
    /// which claims least.
    #[serde(default)]
    pub depth: ListingDepth,

    /// How a source's versions read and order, as a `version-handler`
    /// name such as `semver`. Absent leaves the ecosystem's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_scheme: Option<String>,
}

impl Description {
    /// Whether this build can talk to it.
    pub fn is_compatible(&self) -> bool {
        self.protocol == PROTOCOL_VERSION
    }

    /// Whether this extension can answer when an artifact was last
    /// downloaded.
    pub fn reports_last_download(&self) -> bool {
        self.reports_last_download
    }

    /// How far this extension's enumerator listing reaches.
    pub fn depth(&self) -> ListingDepth {
        self.depth
    }

    pub fn provides(&self, point: PointKind) -> bool {
        self.points.contains(&point)
    }

    /// Whether this extension speaks an ecosystem.
    pub fn speaks(&self, id: &crate::model::EcosystemId) -> bool {
        self.ecosystems
            .iter()
            .any(|ecosystem| ecosystem.id == id.as_str())
    }

    /// The single ecosystem this extension speaks, where there is one.
    ///
    /// `None` for an extension that speaks several, which is a repository
    /// manager rather than a registry adapter.
    pub fn sole_ecosystem(&self) -> Option<&EcosystemDesc> {
        match self.ecosystems.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }
}

/// An ecosystem's identity, as the extension declares it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EcosystemDesc {
    pub id: String,

    /// The `pkg:<type>` segment of a purl.
    pub purl_type: String,

    /// The OSV name, which is capitalized differently from purl and
    /// differently again per ecosystem: `Maven`, `PyPI`, `npm`.
    pub osv_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::gear::testing::validate_against;

    /// An extension may declare any scheme `version::open` knows, and no
    /// other, so the protocol schema's list must be that one.
    #[test]
    fn protocol_lists_every_version_scheme() {
        let schema: serde_json::Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("parses");
        let listed: Vec<&str> = schema
            .pointer("/$defs/Description/properties/version-scheme/enum")
            .and_then(serde_json::Value::as_array)
            .expect("an enum of schemes")
            .iter()
            .map(|name| name.as_str().expect("a string"))
            .collect();

        assert_eq!(listed, crate::version::kinds());
    }

    /// What the npm ecosystem declares, spelled as an extension would.
    fn npm_described() -> Description {
        Description {
            protocol: PROTOCOL_VERSION,
            points: vec![PointKind::Ecosystem],
            ecosystems: vec![EcosystemDesc {
                id: "npm".into(),
                purl_type: "npm".into(),
                osv_name: "npm".into(),
            }],
            dep_kinds: vec![
                DepKind::Runtime,
                DepKind::Dev,
                DepKind::Optional,
                DepKind::Peer,
            ],
            lock_formats: Vec::new(),
            reports_last_download: false,
            depth: ListingDepth::Names,
            version_scheme: None,
        }
    }

    #[test]
    fn point_kinds_serialize_as_they_read() {
        for point in [
            PointKind::Ecosystem,
            PointKind::Source,
            PointKind::Target,
            PointKind::Enumerator,
            PointKind::Advisory,
            PointKind::Lock,
        ] {
            let json = serde_json::to_string(&point).expect("serializable");

            assert_eq!(json, format!("\"{}\"", point.as_str()));
        }
    }

    #[test]
    fn description_reports_what_it_provides() {
        let described = Description {
            protocol: PROTOCOL_VERSION,
            points: vec![PointKind::Source, PointKind::Target],
            ecosystems: Vec::new(),
            dep_kinds: vec![DepKind::Runtime],
            lock_formats: Vec::new(),
            reports_last_download: false,
            depth: ListingDepth::Names,
            version_scheme: None,
        };

        assert!(described.is_compatible());
        assert!(described.provides(PointKind::Source));
        assert!(described.provides(PointKind::Target));
        assert!(!described.provides(PointKind::Enumerator));
    }

    #[test]
    fn protocol_schema_compiles() {
        let document: serde_json::Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("parses");

        jsonschema::validator_for(&document).expect("compiles");
    }

    /// A schema nothing is checked against is a document, not a contract.
    /// Every shape of description has to satisfy it.
    #[test]
    fn description_every_shape_validates() {
        let described: Vec<Description> = vec![
            npm_described(),
            Description {
                protocol: PROTOCOL_VERSION,
                points: vec![PointKind::Lock],
                ecosystems: Vec::new(),
                dep_kinds: Vec::new(),
                lock_formats: vec![LockFormat {
                    name: "package-lock".into(),
                    filenames: vec!["package-lock.json".into()],
                }],
                reports_last_download: false,
                depth: ListingDepth::Names,
                version_scheme: None,
            },
        ];

        for description in described {
            let value = serde_json::to_value(&description).expect("serializable");
            let problems = validate_against("Description", &value);

            assert!(problems.is_empty(), "{description:?}: {problems:?}");
        }
    }

    /// An extension that says nothing about depth claims names only.
    #[test]
    fn depth_defaults_to_names() {
        let mut value = serde_json::to_value(npm_described()).expect("serializable");
        value.as_object_mut().expect("an object").remove("depth");

        let back: Description = serde_json::from_value(value).expect("deserializes");

        assert_eq!(back.depth(), ListingDepth::Names);
    }

    #[test]
    fn depth_validates_on_the_wire() {
        let described = Description {
            depth: ListingDepth::Files,
            version_scheme: None,
            ..npm_described()
        };
        let value = serde_json::to_value(&described).expect("serializable");

        assert_eq!(value["depth"], "files");
        assert!(validate_against("Description", &value).is_empty());
    }

    /// The serde field names are the wire names, so a `rename_all` slip
    /// would silently produce messages nothing else can read.
    #[test]
    fn wire_names_kebab_case() {
        let value = serde_json::to_value(npm_described()).expect("serializable");

        assert!(value.get("dep-kinds").is_some());
        assert!(value["ecosystems"][0].get("purl-type").is_some());
        assert!(value["ecosystems"][0].get("osv-name").is_some());
    }

    /// A description that claims no interface at all is meaningless, and the
    /// schema is where that gets caught.
    #[test]
    fn description_providing_nothing_rejected() {
        let value = serde_json::json!({"protocol": 1, "points": []});

        assert!(!validate_against("Description", &value).is_empty());
    }

    /// A repository manager speaks several ecosystems from one API, so the
    /// format has to permit that and `sole_ecosystem` has to decline to
    /// guess which one it "really" is.
    #[test]
    fn extension_may_speak_several_ecosystems() {
        let manager = Description {
            protocol: PROTOCOL_VERSION,
            points: vec![PointKind::Source, PointKind::Target, PointKind::Enumerator],
            ecosystems: vec![
                EcosystemDesc {
                    id: "maven".into(),
                    purl_type: "maven".into(),
                    osv_name: "Maven".into(),
                },
                EcosystemDesc {
                    id: "npm".into(),
                    purl_type: "npm".into(),
                    osv_name: "npm".into(),
                },
            ],
            dep_kinds: Vec::new(),
            lock_formats: Vec::new(),
            reports_last_download: false,
            depth: ListingDepth::Names,
            version_scheme: None,
        };

        assert!(manager.speaks(&crate::model::EcosystemId::npm()));
        assert!(manager.speaks(&crate::model::EcosystemId::maven()));
        assert!(!manager.speaks(&crate::model::EcosystemId::pypi()));

        // Several means no single one, and saying so beats picking the first.
        assert!(manager.sole_ecosystem().is_none());

        let value = serde_json::to_value(&manager).expect("serializable");
        assert!(validate_against("Description", &value).is_empty());
    }

    /// A message must name itself: prose alone cannot be translated, which
    /// is the whole reason for the type.
    #[test]
    fn message_without_id_rejected() {
        let value = serde_json::json!({"text": "something went wrong"});

        assert!(!validate_against("Message", &value).is_empty());
    }

    /// Message ids are API once anyone translates against them, so the
    /// schema pins their shape the way it pins problem codes.
    #[test]
    fn message_id_shouty_rejected() {
        let value = serde_json::json!({"id": "Source_Host_Unknown"});

        assert!(!validate_against("Message", &value).is_empty());
    }

    /// What this crate actually emits has to satisfy the format.
    #[test]
    fn message_built_validates() {
        let built = crate::message!(
            "source-host-unknown",
            "source {source:?} names host {host:?}, which is not configured",
            source = "central",
            host = "nowhere",
        );

        let value = serde_json::to_value(&built).expect("serializable");

        assert!(validate_against("Message", &value).is_empty());
        assert_eq!(value["args"]["host"], "nowhere");
        assert!(value.get("text").is_some());
    }

    /// A format name lands in scripts via `--lock=FORMAT,FILE`, so the
    /// schema pins its shape.
    #[test]
    fn lock_format_name_shouty_rejected() {
        let value = serde_json::json!({
            "name": "Package_Lock",
            "filenames": ["package-lock.json"],
        });

        assert!(!validate_against("LockFormat", &value).is_empty());
    }

    /// A version mismatch has to be a clear refusal, or it surfaces later as
    /// a baffling deserialization error.
    #[test]
    fn protocol_unknown_incompatible() {
        let described = Description {
            protocol: PROTOCOL_VERSION + 1,
            points: vec![PointKind::Source],
            ecosystems: Vec::new(),
            dep_kinds: Vec::new(),
            lock_formats: Vec::new(),
            reports_last_download: false,
            depth: ListingDepth::Names,
            version_scheme: None,
        };

        assert!(!described.is_compatible());
    }
}
