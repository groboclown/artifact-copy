//! The server-kind templates: built-in, plus a user directory.
//!
//! One directory per server kind.  `kind.yaml` is its manifest and names
//! every other file:
//!
//! ```text
//! server-kinds/
//!   nexus3/
//!     kind.yaml          manifest: files, roles, values   (not rendered)
//!     server.yaml.hbs    host, access, default-repository (server context)
//!     maven2.yaml.hbs    source / target / enumerator     (repository context)
//! ```
//!
//! Manifest:
//!
//! ```yaml
//! description: Sonatype Nexus Repository 3
//! server:
//!   file: server.yaml.hbs
//!   values: {JSON Schema for servers.*.values}          # optional
//! repositories:
//!   raw:                                                 # repository kind
//!     file: raw.yaml.hbs                                 # may be shared
//!     roles: [source, enumerator]                        # verified on render
//!     values: {JSON Schema for repositories.*.values}    # optional
//! ```
//!
//! Absent `values` accepts none.  A top-level property's `default` fills a
//! value the user left out, before validation.
//!
//! One file per render context keeps strict mode meaningful: a repository
//! file renders only for a repository of a kind that names it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::Role;

/// The manifest's file name in each kind directory.
const MANIFEST: &str = "kind.yaml";

/// The suffix every template file carries.
const TEMPLATE_SUFFIX: &str = ".yaml.hbs";

/// The label a built-in file reports as its origin.
const BUILT_IN: &str = "built-in";

/// One built-in file, embedded from `server-kinds/{kind}/{file}`.
macro_rules! builtin {
    ($kind:literal, $file:literal) => {
        (
            $kind,
            $file,
            include_str!(concat!("../../../server-kinds/", $kind, "/", $file)),
        )
    };
}

/// Built-in files, as (kind, file, text).
const BUILT_INS: &[(&str, &str, &str)] = &[
    builtin!("artifact-keeper", "generic.yaml.hbs"),
    builtin!("artifact-keeper", "kind.yaml"),
    builtin!("artifact-keeper", "maven.yaml.hbs"),
    builtin!("artifact-keeper", "npm.yaml.hbs"),
    builtin!("artifact-keeper", "pypi.yaml.hbs"),
    builtin!("artifact-keeper", "server.yaml.hbs"),
    builtin!("artifactory-oss", "generic.yaml.hbs"),
    builtin!("artifactory-oss", "ivy.yaml.hbs"),
    builtin!("artifactory-oss", "kind.yaml"),
    builtin!("artifactory-oss", "maven.yaml.hbs"),
    builtin!("artifactory-oss", "server.yaml.hbs"),
    builtin!("artifactory-pro", "generic.yaml.hbs"),
    builtin!("artifactory-pro", "ivy.yaml.hbs"),
    builtin!("artifactory-pro", "kind.yaml"),
    builtin!("artifactory-pro", "maven.yaml.hbs"),
    builtin!("artifactory-pro", "server.yaml.hbs"),
    builtin!("local-directory", "generic.yaml.hbs"),
    builtin!("local-directory", "kind.yaml"),
    builtin!("local-directory", "server.yaml.hbs"),
    builtin!("maven-central", "kind.yaml"),
    builtin!("maven-central", "maven.yaml.hbs"),
    builtin!("maven-central", "server.yaml.hbs"),
    builtin!("nexus3", "kind.yaml"),
    builtin!("nexus3", "maven2.yaml.hbs"),
    builtin!("nexus3", "npm.yaml.hbs"),
    builtin!("nexus3", "pypi.yaml.hbs"),
    builtin!("nexus3", "raw.yaml.hbs"),
    builtin!("nexus3", "server.yaml.hbs"),
    builtin!("npmjs", "kind.yaml"),
    builtin!("npmjs", "npm.yaml.hbs"),
    builtin!("npmjs", "server.yaml.hbs"),
    builtin!("public-pypi.org", "kind.yaml"),
    builtin!("public-pypi.org", "pypi.yaml.hbs"),
    builtin!("public-pypi.org", "server.yaml.hbs"),
];

/// `kind.yaml`, as written.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Manifest {
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,

    server: ServerSpec,

    #[serde(default)]
    repositories: BTreeMap<String, RepositorySpec>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ServerSpec {
    file: String,

    #[serde(default)]
    values: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RepositorySpec {
    file: String,
    roles: BTreeSet<Role>,

    #[serde(default)]
    values: Option<Value>,
}

/// One template file's text and where it came from.
pub(super) struct Template {
    pub(super) source: String,
    pub(super) origin: String,
}

/// The values one scope accepts.
pub(super) struct Values {
    validator: Option<jsonschema::Validator>,
    defaults: Map<String, Value>,
}

impl Values {
    fn compile(schema: Option<Value>, origin: &str) -> Result<Self, String> {
        let Some(schema) = schema else {
            return Ok(Self {
                validator: None,
                defaults: Map::new(),
            });
        };

        let validator = jsonschema::validator_for(&schema)
            .map_err(|err| format!("{origin}: 'values' is not a usable JSON Schema: {err}"))?;

        // Example: `properties: {mapping: {default: directory}}`.
        let defaults = schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(name, property)| Some((name.clone(), property.get("default")?.clone())))
            .collect();

        Ok(Self {
            validator: Some(validator),
            defaults,
        })
    }

    /// The user's values with defaults filled in, or every violation.
    pub(super) fn apply(&self, given: Option<&Value>) -> Result<Value, Vec<String>> {
        let mut values = match given {
            Some(Value::Object(fields)) => fields.clone(),
            Some(other) => return Err(vec![format!("values must be a mapping, not {other}")]),
            None => Map::new(),
        };

        let Some(validator) = &self.validator else {
            if values.is_empty() {
                return Ok(Value::Object(values));
            }

            let names: Vec<&str> = values.keys().map(String::as_str).collect();

            return Err(vec![format!(
                "takes no values, and was given {}",
                names.join(", ")
            )]);
        };

        for (name, default) in &self.defaults {
            values
                .entry(name.clone())
                .or_insert_with(|| default.clone());
        }

        let values = Value::Object(values);

        let violations: Vec<String> = validator
            .iter_errors(&values)
            .map(|err| crate::internal::schema::violation("values", &err))
            .collect();

        match violations.is_empty() {
            true => Ok(values),
            false => Err(violations),
        }
    }
}

/// One repository kind a server kind supports.
pub(super) struct RepositoryKind {
    pub(super) template: Template,
    pub(super) roles: BTreeSet<Role>,
    pub(super) values: Values,
}

/// Every template for one server kind.
pub(super) struct Kind {
    pub(super) server: Template,
    pub(super) values: Values,
    pub(super) repositories: BTreeMap<String, RepositoryKind>,
}

/// All known server kinds.
pub(super) struct Catalog {
    kinds: BTreeMap<String, Kind>,
}

impl Catalog {
    /// The built-ins, with each kind in `dir` replacing a built-in of the
    /// same name as a whole.
    pub(super) fn load(dir: Option<&Path>) -> Result<Self, String> {
        let mut catalog = Self::builtin()?;

        let Some(dir) = dir else {
            return Ok(catalog);
        };

        let entries = std::fs::read_dir(dir).map_err(|err| {
            format!(
                "setup.server-kinds-dir {} cannot be read: {err}",
                dir.display()
            )
        })?;

        for entry in entries {
            let path = entry
                .map_err(|err| format!("{} cannot be read: {err}", dir.display()))?
                .path();

            if !path.is_dir() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            let kind = build_kind(|file| {
                let at = path.join(file);
                let text = std::fs::read_to_string(&at)
                    .map_err(|err| format!("{} cannot be read: {err}", at.display()))?;

                Ok((text, at.display().to_string()))
            })?;

            catalog.kinds.insert(name.to_owned(), kind);
        }

        Ok(catalog)
    }

    pub(super) fn get(&self, kind: &str) -> Option<&Kind> {
        self.kinds.get(kind)
    }

    /// The kind names, for an error listing the choices.
    pub(super) fn names(&self) -> Vec<&str> {
        self.kinds.keys().map(String::as_str).collect()
    }

    fn builtin() -> Result<Self, String> {
        let names: BTreeSet<&str> = BUILT_INS.iter().map(|(kind, _, _)| *kind).collect();
        let mut kinds = BTreeMap::new();

        for name in names {
            let kind = build_kind(|file| {
                BUILT_INS
                    .iter()
                    .find(|(kind, at, _)| *kind == name && *at == file)
                    .map(|(_, _, text)| ((*text).to_owned(), format!("{BUILT_IN} {name}/{file}")))
                    .ok_or_else(|| format!("{BUILT_IN} kind {name} has no file {file}"))
            })?;

            kinds.insert(name.to_owned(), kind);
        }

        Ok(Self { kinds })
    }
}

/// Build one kind from its manifest, reading each named file with `read`,
/// which answers (text, origin).
fn build_kind(read: impl Fn(&str) -> Result<(String, String), String>) -> Result<Kind, String> {
    let (text, origin) = read(MANIFEST)?;

    let manifest: Manifest =
        serde_norway::from_str(&text).map_err(|err| format!("{origin} is not usable: {err}"))?;

    let template = |file: &str| -> Result<Template, String> {
        check_file(file, &origin)?;

        let (source, origin) = read(file)?;

        Ok(Template { source, origin })
    };

    let server = template(&manifest.server.file)?;
    let values = Values::compile(manifest.server.values, &origin)?;
    let mut repositories = BTreeMap::new();

    for (name, spec) in manifest.repositories {
        if spec.roles.is_empty() {
            return Err(format!("{origin}: repository kind {name:?} lists no roles"));
        }

        let kind = RepositoryKind {
            template: template(&spec.file)?,
            roles: spec.roles,
            values: Values::compile(spec.values, &origin)?,
        };

        repositories.insert(name, kind);
    }

    Ok(Kind {
        server,
        values,
        repositories,
    })
}

/// A manifest names files beside it, and only templates.
fn check_file(file: &str, origin: &str) -> Result<(), String> {
    let plain = !file.contains(['/', '\\']) && file != "." && file != "..";

    if plain && file.ends_with(TEMPLATE_SUFFIX) {
        return Ok(());
    }

    Err(format!(
        "{origin}: {file:?} must be a file name beside the manifest ending in {TEMPLATE_SUFFIX}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every file under `server-kinds/` is embedded, so a new file is not
    /// silently left out of the binary.
    #[test]
    fn every_file_is_built_in() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("server-kinds");
        let mut on_disk = Vec::new();

        for kind in std::fs::read_dir(&root).expect("server-kinds") {
            let kind = kind.expect("entry").path();
            let kind_name = kind
                .file_name()
                .and_then(|n| n.to_str())
                .expect("name")
                .to_owned();

            for file in std::fs::read_dir(&kind).expect("kind") {
                let file = file.expect("entry").path();
                let name = file.file_name().and_then(|n| n.to_str()).expect("name");

                on_disk.push(format!("{kind_name}/{name}"));
            }
        }

        on_disk.sort();

        let built_in: Vec<String> = BUILT_INS
            .iter()
            .map(|(kind, file, _)| format!("{kind}/{file}"))
            .collect();

        assert_eq!(on_disk, built_in);
    }

    /// A built-in kind leaves `insecure-transport` at the host's default,
    /// so plain HTTP is only ever accepted by a kind or server the user
    /// wrote.
    #[test]
    fn built_ins_keep_tls_default() {
        for (kind, file, text) in BUILT_INS {
            assert!(
                !text.contains("insecure-transport"),
                "{kind}/{file} sets insecure-transport"
            );
        }
    }

    fn user_kind(files: &[(&str, &str)]) -> Result<Catalog, String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let kind = dir.path().join("nexus3");

        std::fs::create_dir(&kind).expect("mkdir");

        for (name, text) in files {
            std::fs::write(kind.join(name), text).expect("write");
        }

        Catalog::load(Some(dir.path()))
    }

    #[test]
    fn user_kind_replaces_built_in() {
        let catalog = user_kind(&[
            ("kind.yaml", "server:\n  file: server.yaml.hbs\n"),
            ("server.yaml.hbs", "access: [read]"),
        ])
        .expect("loads");

        let nexus = catalog.get("nexus3").expect("present");

        assert_eq!(nexus.server.source, "access: [read]");
        assert!(nexus.repositories.is_empty(), "replaced as a whole");
        assert!(catalog.get("npmjs").is_some(), "other built-ins remain");
    }

    #[test]
    fn user_kind_needs_manifest() {
        let err = user_kind(&[("server.yaml.hbs", "")])
            .err()
            .expect("refused");

        assert!(err.contains("kind.yaml"), "{err}");
    }

    #[test]
    fn manifest_unknown_fields_refused() {
        let err = user_kind(&[(
            "kind.yaml",
            "server:\n  file: server.yaml.hbs\naccess: [read]\n",
        )])
        .err()
        .expect("refused");

        assert!(err.contains("access"), "{err}");
    }

    #[test]
    fn manifest_file_stays_beside_it() {
        let err = user_kind(&[("kind.yaml", "server:\n  file: ../elsewhere.yaml.hbs\n")])
            .err()
            .expect("refused");

        assert!(err.contains("beside the manifest"), "{err}");
    }

    /// Two repository kinds may share one template.
    #[test]
    fn repository_kinds_share_file() {
        let catalog = user_kind(&[
            (
                "kind.yaml",
                "server:\n  file: server.yaml.hbs\nrepositories:\n  maven:\n    file: m.yaml.hbs\n    roles: [source]\n  maven2:\n    file: m.yaml.hbs\n    roles: [source]\n",
            ),
            ("server.yaml.hbs", ""),
            ("m.yaml.hbs", "source: {kind: maven}"),
        ])
        .expect("loads");

        let nexus = catalog.get("nexus3").expect("present");

        assert_eq!(nexus.repositories.len(), 2);
    }

    #[test]
    fn values_default_then_validate() {
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"mapping": {"enum": ["directory", "as-is"], "default": "directory"}},
        });
        let values = Values::compile(Some(schema), "t").expect("compiles");

        assert_eq!(
            values.apply(None).expect("defaults")["mapping"],
            "directory"
        );

        let wrong = serde_json::json!({"mapping": "sideways"});
        assert!(values.apply(Some(&wrong)).is_err(), "outside the enum");

        let unknown = serde_json::json!({"other": 1});
        assert!(values.apply(Some(&unknown)).is_err(), "not declared");
    }

    #[test]
    fn values_refused_without_schema() {
        let values = Values::compile(None, "t").expect("compiles");
        let given = serde_json::json!({"x": 1});

        assert!(values.apply(None).is_ok());
        assert!(values.apply(Some(&given)).is_err());
    }

    /// The schema lists the built-in kinds in prose; every one must be
    /// there, quoted, so a new kind is not left undocumented.
    #[test]
    fn schema_names_every_built_in() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schema/config.schema.json"))
                .expect("parses");
        let described = schema["$defs"]["Server"]["properties"]["kind"]["description"]
            .as_str()
            .expect("a description");

        for (kind, _, _) in BUILT_INS {
            assert!(
                described.contains(&format!("'{kind}'")),
                "schema omits {kind}"
            );
        }
    }
}
