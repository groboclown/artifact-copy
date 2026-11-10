//! Lowering `servers` and `repositories` into low-level entries.
//!
//! A user names a server technology and its repositories; the server
//! kind's templates say which hosts, sources, targets, and enumerators that
//! implies.  The result is ordinary low-level configuration, so everything
//! past the loader is unchanged.
//!
//! ```text
//!   servers.nexus  (kind: nexus3) ----------> hosts.nexus
//!     repositories.m2 (kind: maven2) --+----> sources.m2
//!                                      +----> targets.m2
//!                                      +----> enumerators.m2
//!   repositories.py (server: nexus) -------> sources.py, ...
//!
//!   server-kinds/nexus3/server.yaml.hbs    rendered once per server
//!   server-kinds/nexus3/maven2.yaml.hbs    rendered once per repository
//! ```
//!
//! Runs on the merged document, before it becomes a typed
//! [`Config`](super::Config), because a template renders YAML and a user's
//! override blocks deep-merge over it.

mod access;
mod catalog;
mod keys;
mod lowering;
mod render;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::core::error::{Error, Result};
use access::{Collection, Role};
use catalog::Catalog;
use keys::{OVERRIDE_TEMPLATE, REPOSITORIES, SERVER, SERVER_KINDS_DIR, SERVERS, SETUP};
use lowering::{Declared, Lowering};
use render::renderer;

/// Rewrites a lowered entry's relative paths against a directory.  The
/// loader's own anchoring, handed in so this layer does not reach up into
/// the command line.
pub(crate) type Anchor = fn(&mut Value, &Path);

/// Which file declared each server and repository.
///
/// Recorded per file before the merge, which loses it.  Needed to anchor a
/// template's paths to the file that asked for the template, and to refuse
/// a name declared twice rather than silently merging the two.
#[derive(Debug, Default)]
pub(crate) struct Origins {
    servers: BTreeMap<String, PathBuf>,
    repositories: BTreeMap<String, PathBuf>,
}

impl Origins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one file's declarations.
    pub fn record(&mut self, document: &Value, file: &Path) -> Result<()> {
        let servers = document.get(SERVERS).and_then(Value::as_object);

        for name in servers.into_iter().flat_map(Map::keys) {
            claim(&mut self.servers, SERVER, name, file)?;
        }

        let nested = servers
            .into_iter()
            .flat_map(Map::values)
            .filter_map(|server| server.get(REPOSITORIES).and_then(Value::as_object));

        let standalone = document.get(REPOSITORIES).and_then(Value::as_object);

        for name in nested.chain(standalone).flat_map(Map::keys) {
            claim(&mut self.repositories, "repository", name, file)?;
        }

        Ok(())
    }
}

/// Record `name` as declared in `file`, unless something already was.
fn claim(seen: &mut BTreeMap<String, PathBuf>, what: &str, name: &str, file: &Path) -> Result<()> {
    let Some(earlier) = seen.get(name) else {
        seen.insert(name.to_owned(), file.to_path_buf());
        return Ok(());
    };

    let place = match earlier == file {
        true => format!("twice in {}", file.display()),
        false => format!("in both {} and {}", earlier.display(), file.display()),
    };

    Err(Error::Config(format!(
        "{what} {name:?} is declared {place}; each name must be declared once"
    )))
}

/// Expand `servers` and `repositories` in `document` into low-level entries.
pub(crate) fn lower(document: &mut Value, origins: &Origins, anchor: Anchor) -> Result<()> {
    let Some(root) = document.as_object_mut() else {
        return Ok(());
    };

    let servers = take(root, SERVERS);
    let standalone = take(root, REPOSITORIES);
    let overrides = strip_overrides(root);

    if servers.is_empty() && standalone.is_empty() {
        return Ok(());
    }

    let catalog = Catalog::load(kinds_dir(root).as_deref()).map_err(Error::Config)?;

    let mut lowering = Lowering {
        renderer: renderer(),
        origins,
        anchor,
        problems: Vec::new(),
        generated: BTreeMap::new(),
    };

    let mut declared = lowering.gather(&servers, standalone);
    let mut lowered = BTreeMap::new();

    // A server first, because its repositories render against it.
    for (alias, body) in &servers {
        let Some(server) = lowering.server(&catalog, alias, body) else {
            continue;
        };

        // Example: `pypi-org: {kind: public-pypi.org}` is one source, named
        // for the server, with no repositories written out.
        let has_repositories = declared.iter().any(|repo| &repo.server == alias);

        if let (false, Some(default)) = (has_repositories, &server.default) {
            declared.push(Declared {
                alias: alias.clone(),
                server: alias.clone(),
                body: default.clone(),
            });
        }

        lowered.insert(alias.clone(), server);
    }

    for repo in &declared {
        lowering.repository(repo, &servers, &lowered);
    }

    lowering.place(root, &overrides);
    lowering.finish()
}

/// Remove and return one top-level collection.
fn take(root: &mut Map<String, Value>, key: &str) -> Map<String, Value> {
    match root.remove(key) {
        Some(Value::Object(entries)) => entries,
        _ => Map::new(),
    }
}

/// The user's template directory, already anchored by the loader.
fn kinds_dir(root: &Map<String, Value>) -> Option<PathBuf> {
    root.get(SETUP)?
        .get(SERVER_KINDS_DIR)?
        .as_str()
        .map(PathBuf::from)
}

/// Remove every `override-template` flag, returning the entries that set it.
fn strip_overrides(root: &mut Map<String, Value>) -> BTreeSet<(Collection, String)> {
    let mut flagged = BTreeSet::new();

    for collection in Collection::ALL {
        let Some(Value::Object(entries)) = root.get_mut(collection.key()) else {
            continue;
        };

        for (name, entry) in entries.iter_mut() {
            let Some(fields) = entry.as_object_mut() else {
                continue;
            };

            if fields.remove(OVERRIDE_TEMPLATE) == Some(Value::Bool(true)) {
                flagged.insert((collection, name.clone()));
            }
        }
    }

    flagged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unanchored(_: &mut Value, _: &Path) {}

    /// Every built-in template renders, for every repository kind it
    /// supports, into entries that deserialize.
    #[test]
    fn every_builtin_renders() {
        let catalog = Catalog::load(None).expect("built-ins");

        for kind in catalog.names() {
            let supported = catalog.get(kind).expect("kind").repositories.keys();
            let repositories: Map<String, Value> = supported
                .map(|repo| (format!("r-{repo}"), serde_json::json!({ "kind": repo })))
                .collect();

            let mut document = serde_json::json!({
                "servers": {
                    "s": {
                        "kind": kind,
                        "url": "https://s.test/",
                        "repositories": repositories,
                    },
                },
            });

            let lowered = lower(&mut document, &Origins::new(), unanchored);

            assert!(lowered.is_ok(), "{kind}: {lowered:?}");
            assert!(document["hosts"]["s"].is_object(), "{kind}: {document}");
        }
    }

    /// Maven Central's server kind supplies its own `cache-freshness`,
    /// ahead of the ecosystem's built-in rules.
    #[test]
    fn maven_central_supplies_freshness() {
        let mut document = serde_json::json!({
            "servers": {
                "central": {
                    "kind": "maven-central",
                    "url": "https://repo.test/",
                    "repositories": { "maven": { "kind": "maven" } },
                },
            },
        });

        lower(&mut document, &Origins::new(), unanchored).expect("lowered");

        let rules = &document["sources"]["maven"]["cache-freshness"];

        assert_eq!(rules[0]["files"], "maven-metadata.xml*", "{document}");
        assert_eq!(rules[0]["fresh-for"], "24 hours", "{document}");
    }

    /// The host `maven-central` lowers to, given `values`.
    fn central_host(values: Value) -> Value {
        let mut document = serde_json::json!({
            "servers": { "central": { "kind": "maven-central", "values": values } },
        });

        lower(&mut document, &Origins::new(), unanchored).expect("lowered");

        document["hosts"]["central"].clone()
    }

    /// Central's files come from Google's copy first; its indexes do not.
    #[test]
    fn maven_central_mirrors_gcs() {
        let host = central_host(serde_json::json!({}));

        assert_eq!(
            host["mirrors"],
            serde_json::json!([{
                "url": "https://maven-central.storage-download.googleapis.com/maven2/",
                "skip": ["*/"],
            }]),
            "{host}"
        );
    }

    #[test]
    fn maven_central_mirrors_replaced() {
        const EU: &str = "https://maven-central-eu.storage-download.googleapis.com/maven2/";

        let host = central_host(serde_json::json!({ "mirrors": [EU] }));

        assert_eq!(host["mirrors"][0]["url"], EU, "{host}");
        assert_eq!(host["mirrors"].as_array().map(Vec::len), Some(1), "{host}");
    }

    #[test]
    fn maven_central_mirrors_off() {
        let host = central_host(serde_json::json!({ "mirrors": [] }));

        assert!(host.get("mirrors").is_none(), "{host}");
    }

    /// A server's tuning values reach its host; ones left out stay absent,
    /// so the host keeps its own defaults.
    #[test]
    fn server_values_reach_host() {
        let mut document = serde_json::json!({
            "servers": {
                "nx": {
                    "kind": "nexus3",
                    "url": "https://nx.test/",
                    "values": {
                        "connect-timeout": "2 min",
                        "maximum-concurrent-uploads": 3,
                    },
                },
                "npm": {
                    "kind": "npmjs",
                    "values": { "maximum-concurrent-downloads": 4 },
                },
            },
        });

        lower(&mut document, &Origins::new(), unanchored).expect("lowered");

        let nexus = &document["hosts"]["nx"];

        assert_eq!(nexus["connect-timeout"], "2 min", "{document}");
        assert_eq!(nexus["maximum-concurrent-uploads"], 3, "{document}");
        assert!(nexus.get("request-timeout").is_none(), "{document}");
        assert!(
            nexus.get("maximum-concurrent-downloads").is_none(),
            "{document}"
        );

        let npm = &document["hosts"]["npm"];

        assert_eq!(npm["maximum-concurrent-downloads"], 4, "{document}");
        assert_eq!(npm["url"], "https://registry.npmjs.org/", "{document}");
    }

    /// A local directory's repositories are sub-directories, except one
    /// named `/`, which is the directory itself; the symlink mode reaches
    /// the host as an option.
    #[test]
    fn local_dir_lowers_to_subdirs() {
        let mut document = serde_json::json!({
            "servers": {
                "backup": {
                    "kind": "local-directory",
                    "url": "file:///srv/backup/",
                    "values": { "symlinks": "skip" },
                    "repositories": {
                        "tools": { "kind": "generic", "name": "tools" },
                        "whole": { "kind": "generic", "name": "/" },
                    },
                },
            },
        });

        lower(&mut document, &Origins::new(), unanchored).expect("lowered");

        assert_eq!(
            document["hosts"]["backup"]["options"]["symlinks"], "skip",
            "{document}"
        );

        for collection in ["sources", "targets", "enumerators"] {
            assert_eq!(
                document[collection]["tools"]["host-path"], "tools",
                "{document}"
            );
            assert_eq!(
                document[collection]["tools"]["kind"], "local-directory",
                "{document}"
            );
            assert!(
                document[collection]["whole"].get("host-path").is_none(),
                "{document}"
            );
        }

        assert_eq!(
            document["targets"]["tools"]["options"]["overwrite-guard"], "check",
            "{document}"
        );
    }

    /// An Artifact Keeper repository's `mode` reaches its source and
    /// enumerator when set, and neither when not.
    #[test]
    fn artifact_keeper_mode_optional() {
        let mut document = serde_json::json!({
            "servers": {
                "keeper": {
                    "kind": "artifact-keeper",
                    "url": "https://keeper.test/",
                    "repositories": {
                        "pypi-remote": { "kind": "pypi", "values": { "mode": "proxy-cache" } },
                        "pypi-hosted": { "kind": "pypi" },
                    },
                },
            },
        });

        lower(&mut document, &Origins::new(), unanchored).expect("lowered");

        for collection in ["sources", "enumerators"] {
            assert_eq!(
                document[collection]["pypi-remote"]["options"]["mode"], "proxy-cache",
                "{document}"
            );
            assert!(
                document[collection]["pypi-hosted"]["options"]
                    .get("mode")
                    .is_none(),
                "{document}"
            );
        }

        assert!(
            document["targets"]["pypi-remote"]["options"]
                .get("mode")
                .is_none(),
            "{document}"
        );
    }

    #[test]
    fn artifact_keeper_mode_misspelled_refused() {
        let err = lowering_err(serde_json::json!({
            "servers": {
                "keeper": {
                    "kind": "artifact-keeper",
                    "url": "https://keeper.test/",
                    "repositories": {
                        "r": { "kind": "maven", "values": { "mode": "remote" } },
                    },
                },
            },
        }));

        assert!(err.contains("mode"), "{err}");
    }

    /// The problems `document` lowers to, joined.
    fn lowering_err(mut document: Value) -> String {
        match lower(&mut document, &Origins::new(), unanchored) {
            Err(err) => err.to_string(),
            Ok(()) => panic!("lowered: {document}"),
        }
    }

    #[test]
    fn server_unknown_refused() {
        let err = lowering_err(serde_json::json!({
            "repositories": { "r": { "server": "nowhere", "kind": "maven" } },
        }));

        assert!(
            err.contains("names server \"nowhere\", which is not configured"),
            "{err}"
        );
    }

    #[test]
    fn repository_kind_unsupported_refused() {
        let err = lowering_err(serde_json::json!({
            "servers": {
                "central": {
                    "kind": "maven-central",
                    "repositories": { "r": { "kind": "npm" } },
                },
            },
        }));

        assert!(
            err.contains("has kind \"npm\", which server kind \"maven-central\" does not support"),
            "{err}"
        );
    }

    /// A repository with no `name` is named by its alias.
    #[test]
    fn repository_name_defaults_to_alias() {
        let mut document = serde_json::json!({
            "servers": {
                "backup": {
                    "kind": "local-directory",
                    "url": "file:///srv/backup/",
                    "repositories": { "tools": { "kind": "generic" } },
                },
            },
        });

        lower(&mut document, &Origins::new(), unanchored).expect("lowered");

        assert_eq!(
            document["sources"]["tools"]["host-path"], "tools",
            "{document}"
        );
    }

    #[test]
    fn repository_read_needs_reader() {
        // A user kind, because no built-in repository kind is write-only.
        let dir = tempfile::tempdir().expect("tempdir");
        let kind = dir.path().join("write-only");

        std::fs::create_dir(&kind).expect("mkdir");

        for (name, text) in [
            (
                "kind.yaml",
                "server:\n  file: server.yaml.hbs\n\
                 repositories:\n  generic:\n    file: generic.yaml.hbs\n    roles: [target]\n",
            ),
            ("server.yaml.hbs", "access: [read, write]\n"),
            (
                "generic.yaml.hbs",
                "target:\n  kind: artifact-keeper-generic\n  options:\n    \
                 repository: {{yaml repository.name}}\n",
            ),
        ] {
            std::fs::write(kind.join(name), text).expect("write");
        }

        let mut document = serde_json::json!({
            "setup": {"server-kinds-dir": dir.path()},
            "servers": {
                "w": {
                    "kind": "write-only",
                    "url": "https://w.test/",
                    "repositories": {"g": {"kind": "generic", "access": "read"}},
                },
            },
        });

        let err = match lower(&mut document, &Origins::new(), unanchored) {
            Err(err) => err.to_string(),
            Ok(()) => panic!("a write-only kind cannot be read"),
        };

        assert!(err.contains("read access"), "{err}");
    }
}
