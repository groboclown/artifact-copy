//! Loading, validating, and merging configuration files.
//!
//! Merging is **first wins**, which is the reverse of most config systems and
//! is what `README.md` specifies: given `--config=a.yaml --config=b.yaml`,
//! a setting in `a.yaml` beats the same setting in `b.yaml`.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::config::{Config, Origins, lower};
use crate::core::error::{Error, Result};

/// The `$schema` every configuration file must declare.
const CONFIG_SCHEMA_ID: &str =
    "https://github.com/groboclown/artifact-copy/schema/config.schema.json";

/// The committed schema, compiled into the binary so validation works with
/// no reference to the source tree.
const CONFIG_SCHEMA: &str = include_str!("../../schema/config.schema.json");

/// Extensions a directory scan picks up, in the order the README gives.
const CONFIG_EXTENSIONS: [&str; 3] = ["yaml", "yml", "json"];

/// Collects configuration files and produces one merged [`Config`].
#[derive(Debug, Default)]
pub struct ConfigLoader {
    paths: Vec<PathBuf>,
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file, or a directory of files.
    ///
    /// Order matters: earlier paths win.
    pub fn add_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.paths.push(path.into());
        self
    }

    /// Read, validate, and merge everything.
    pub fn load(&self) -> Result<Config> {
        let mut documents = Vec::new();

        for path in &self.paths {
            collect(path, &mut documents)?;
        }

        if documents.is_empty() {
            return Err(Error::Config("no configuration files were found".into()));
        }

        let validator = compile_schema()?;
        let mut merged = Value::Object(Map::new());
        let mut origins = Origins::new();

        // Each file is validated on its own so an error names the file it
        // came from, rather than pointing at a merged document that exists
        // nowhere on disk.
        for (path, mut document) in documents {
            validate(&validator, &path, &document)?;

            // Anchored **before** the merge, which is the only moment this
            // is possible: afterwards the merged document is one object
            // with no record of which file any key came from, and a single
            // base for the whole configuration is exactly the rule this
            // avoids. Validation runs first so a schema error still quotes
            // what the user wrote rather than a rewritten path.
            anchor(&mut document, &holding(&path));
            origins.record(&document, &path)?;

            merge_first_wins(&mut merged, document);
        }

        // After the merge, so a repository may name a server from another
        // file; before typing, because templates render untyped YAML.
        lower(&mut merged, &origins, anchor)?;

        let config: Config = serde_json::from_value(merged)
            .map_err(|source| Error::Config(format!("configuration is not usable: {source}")))?;

        refuse_plain_http(&config)?;

        Ok(config)
    }
}

/// Refuse every url that would travel without TLS on a host that did not
/// say `insecure-transport`, naming them all at once.
fn refuse_plain_http(config: &Config) -> Result<()> {
    let refused = crate::config::refused_plain_http(config);

    if refused.is_empty() {
        return Ok(());
    }

    Err(Error::Config(format!(
        "plain http:// is refused unless the host sets 'insecure-transport: true': {}",
        refused.join("; ")
    )))
}

/// The directory a configuration file lives in.
fn holding(file: &Path) -> PathBuf {
    file.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Every `config-relative-path`, as a route through the document.
///
/// `*` matches any key, which is how the collections are reached: `hosts` is
/// a map of user-chosen names, and every one of them may carry a policy.
/// `items` matches every element of a list, as the schema spells one:
/// `additional-hosts` is a list whose entries may carry credentials.
///
/// **This list is the rule.** `schema/config.schema.json` marks each of these
/// `ConfigRelativePath`, and a test walks the schema to assert the two agree.
/// A new configuration-relative path needs anchoring here.
const ANCHORED: [&[&str]; 23] = [
    &["setup", "cache-dir"],
    &["extensions", "*", "module"],
    &["setup", "server-kinds-dir"],
    &["setup", "sigstore-trusted-root"],
    &["setup", "license-policy"],
    &["setup", "security-policy"],
    &["setup", "quarantine-policy"],
    &["setup", "signing-policy"],
    &["hosts", "*", "license-policy"],
    &["hosts", "*", "security-policy"],
    &["hosts", "*", "quarantine-policy"],
    &["hosts", "*", "signing-policy"],
    &["setup", "log", "config-relative-path"],
    &[
        "hosts",
        "*",
        "authentication",
        "username",
        "config-relative-path",
    ],
    &[
        "hosts",
        "*",
        "authentication",
        "password",
        "config-relative-path",
    ],
    &[
        "hosts",
        "*",
        "authentication",
        "token",
        "config-relative-path",
    ],
    &["signing-keys", "*", "value", "config-relative-path"],
    &[
        "servers",
        "*",
        "authentication",
        "username",
        "config-relative-path",
    ],
    &[
        "servers",
        "*",
        "authentication",
        "password",
        "config-relative-path",
    ],
    &[
        "servers",
        "*",
        "authentication",
        "token",
        "config-relative-path",
    ],
    &[
        "hosts",
        "*",
        "additional-hosts",
        "items",
        "authentication",
        "username",
        "config-relative-path",
    ],
    &[
        "hosts",
        "*",
        "additional-hosts",
        "items",
        "authentication",
        "password",
        "config-relative-path",
    ],
    &[
        "hosts",
        "*",
        "additional-hosts",
        "items",
        "authentication",
        "token",
        "config-relative-path",
    ],
];

/// Rewrite this document's relative file paths against the directory it was
/// read from.
///
/// Why paths rather than a walk over every string: a configuration holds
/// plenty of strings that are not file paths - urls, repository names,
/// arguments to an extension - and absolutising one of those would corrupt
/// it. Naming the places is narrow enough to be obviously correct and is
/// checked against the schema by a test.
///
/// A `working-dir-path` stays outside this list and follows the `.env`
/// convention. A `config-relative-path` receives anchoring wherever it occurs.
fn anchor(document: &mut Value, base: &Path) {
    for route in ANCHORED {
        anchor_at(document, route, base);
    }
}

/// Rewrite one route through the document, expanding `*` over a map's keys.
fn anchor_at(node: &mut Value, route: &[&str], base: &Path) {
    let Some((step, rest)) = route.split_first() else {
        anchor_value(node, base);
        return;
    };

    if *step == "items"
        && let Some(items) = node.as_array_mut()
    {
        for item in items {
            anchor_at(item, rest, base);
        }

        return;
    }

    let Some(object) = node.as_object_mut() else {
        return;
    };

    if *step == "*" {
        for (_, child) in object.iter_mut() {
            anchor_at(child, rest, base);
        }

        return;
    }

    if let Some(child) = object.get_mut(*step) {
        anchor_at(child, rest, base);
    }
}

/// Make one path absolute, if it is a relative path at all.
fn anchor_value(node: &mut Value, base: &Path) {
    let Some(text) = node.as_str() else {
        return;
    };

    let path = Path::new(text);

    // An absolute path is what the user meant; leave it exactly as written.
    if path.is_absolute() {
        return;
    }

    *node = Value::String(base.join(path).to_string_lossy().into_owned());
}

/// Gather one path, expanding a directory into its config files.
fn collect(path: &Path, out: &mut Vec<(PathBuf, Value)>) -> Result<()> {
    if !path.exists() {
        return Err(Error::Config(format!("{} does not exist", path.display())));
    }

    if path.is_file() {
        out.push((path.to_path_buf(), read_document(path)?));
        return Ok(());
    }

    // Alphabetical, and only this directory: the README rules out recursing
    // into sub-directories.
    let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|candidate| candidate.is_file() && has_config_extension(candidate))
        .collect();

    entries.sort();

    for entry in entries {
        out.push((entry.clone(), read_document(&entry)?));
    }

    Ok(())
}

fn has_config_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| CONFIG_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Read one file as JSON or YAML, landing on `serde_json::Value` either way.
///
/// YAML is a superset, so a construct with no JSON equivalent -- a non-string
/// key, a tag, `NaN` -- is rejected here with a clear message rather than
/// deserializing into something surprising later.
fn read_document(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    let is_json = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));

    if is_json {
        return serde_json::from_str(&text).map_err(|source| {
            Error::Config(format!("{} is not valid JSON: {source}", path.display()))
        });
    }

    serde_norway::from_str(&text).map_err(|source| {
        Error::Config(format!(
            "{} is not valid YAML, or uses YAML constructs with no JSON \
             equivalent such as non-string keys or tags: {source}",
            path.display()
        ))
    })
}

fn compile_schema() -> Result<jsonschema::Validator> {
    let schema: Value = serde_json::from_str(CONFIG_SCHEMA)
        .map_err(|source| Error::Config(format!("built-in schema is broken: {source}")))?;

    jsonschema::validator_for(&schema)
        .map_err(|source| Error::Config(format!("built-in schema is broken: {source}")))
}

/// Report *every* violation, not just the first.
///
/// A config with four mistakes should take one run to fix, not four.
fn validate(validator: &jsonschema::Validator, path: &Path, document: &Value) -> Result<()> {
    let mut problems: Vec<String> = validator
        .iter_errors(document)
        .map(|err| format!("  {}", crate::internal::schema::violation("", &err)))
        .collect();

    problems.extend(renamed_keys(document));

    if problems.is_empty() {
        return Ok(());
    }

    Err(Error::Config(format!(
        "{} does not match the configuration schema:\n{}",
        path.display(),
        problems.join("\n")
    )))
}

/// Keys that were renamed, as `(old, new)`: at the top level, and in each
/// source.
const RENAMED_TOP_KEYS: [(&str, &str); 1] = [("scanners", "enumerators")];
const RENAMED_SOURCE_KEYS: [(&str, &str); 1] = [("scanner", "enumerator")];

/// A line for each renamed key the document still uses, naming the new
/// one, since the schema can only say the old one is unexpected.
fn renamed_keys(document: &Value) -> Vec<String> {
    let mut out: Vec<String> = RENAMED_TOP_KEYS
        .iter()
        .filter(|(old, _)| document.get(old).is_some())
        .map(|(old, new)| format!("  '{old}' is now '{new}'"))
        .collect();

    let Some(sources) = document.get("sources").and_then(Value::as_object) else {
        return out;
    };

    for (name, source) in sources {
        for (old, new) in RENAMED_SOURCE_KEYS {
            if source.get(old).is_some() {
                out.push(format!("  at /sources/{name}: '{old}' is now '{new}'"));
            }
        }
    }

    out
}

/// Merge `next` into `base`, keeping what `base` already has.
///
/// Objects merge key by key.  Everything else -- scalars and arrays alike --
/// is taken whole from whichever document got there first, so a later file
/// cannot append to an earlier file's list.
fn merge_first_wins(base: &mut Value, next: Value) {
    let (Value::Object(base_map), Value::Object(next_map)) = (&mut *base, next) else {
        return;
    };

    for (key, value) in next_map {
        match base_map.get_mut(&key) {
            Some(existing) => merge_first_wins(existing, value),
            None => {
                base_map.insert(key, value);
            }
        }
    }
}

/// The schema identifier a configuration file must declare.
pub fn config_schema_id() -> &'static str {
    CONFIG_SCHEMA_ID
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A renamed key is named with its replacement, top-level and per
    /// source; a current document gets no such line.
    #[test]
    fn renamed_keys_name_new() {
        let old = serde_json::json!({
            "scanners": {},
            "sources": {"s": {"scanner": "x"}},
        });

        assert_eq!(
            renamed_keys(&old),
            [
                "  'scanners' is now 'enumerators'",
                "  at /sources/s: 'scanner' is now 'enumerator'",
            ]
        );

        let current = serde_json::json!({"enumerators": {}, "sources": {"s": {"enumerator": "x"}}});

        assert!(renamed_keys(&current).is_empty());
    }

    use crate::config::LogLevel;

    fn level(config: &Config) -> Option<LogLevel> {
        config.setup.log.as_ref().and_then(|log| log.level)
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("written");

        path
    }

    fn doc(body: &str) -> String {
        format!(r#"{{"$schema":"{CONFIG_SCHEMA_ID}",{body}}}"#)
    }

    #[test]
    fn committed_schema_compiles() {
        compile_schema().expect("schema is valid");
    }

    /// The shipped example exercises every top-level collection, so this is
    /// what catches the schema and the typed model drifting apart: the
    /// schema would accept a key the model then rejects as unknown.
    #[test]
    fn shipped_example_loads() {
        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/configuration/config.yaml");

        let config = ConfigLoader::new()
            .add_path(&example)
            .load()
            .expect("the shipped example must stay loadable");

        assert!(config.sources.contains_key("central"));
        assert!(config.enumerators.contains_key("internal-index"));
        assert!(config.advisors.contains_key("ossf"));
        assert!(config.hosts.contains_key("internal"));
        assert!(config.setup.log.is_some());
    }

    /// Three `SecretValue` variants used to declare `"kind": "env"`, which
    /// made the schema's `oneOf` unsatisfiable for environment secrets.
    #[test]
    fn secret_environment_validates() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "auth.json",
            &doc(r#""hosts":{"h":{"url":"https://example.test/",
                   "authentication":{"kind":"bearer",
                   "token":{"kind":"env","name":"TOKEN"}}}}"#),
        );

        ConfigLoader::new().add_path(&path).load().expect("loads");
    }

    /// `region` and `profile` are optional on both AWS variants.
    #[test]
    fn secret_aws_validates() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "aws.json",
            &doc(r#""hosts":{"h":{"url":"https://example.test/",
                   "authentication":{"kind":"basic",
                   "username":{"kind":"aws-secret","name":"u",
                               "region":"us-east-1","profile":"ci"},
                   "password":{"kind":"aws-secret-key","name":"p","key":"k"}}}}"#),
        );

        ConfigLoader::new().add_path(&path).load().expect("loads");
    }

    #[test]
    fn secret_aws_unknown_key_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "aws.json",
            &doc(r#""hosts":{"h":{"url":"https://example.test/",
                   "authentication":{"kind":"bearer",
                   "token":{"kind":"aws-secret","name":"t","regoin":"x"}}}}"#),
        );

        ConfigLoader::new()
            .add_path(&path)
            .load()
            .expect_err("unknown key");
    }

    /// Advisors load in the order written, not by name: the first corpus to
    /// carry a record is the one screening reports. A later file's new
    /// advisors follow the earlier file's.
    #[test]
    fn advisors_keep_configuration_order() {
        let dir = tempfile::tempdir().expect("tempdir");

        let a = write(
            dir.path(),
            "a.yaml",
            &format!(
                "$schema: {CONFIG_SCHEMA_ID}\n\
                 advisors:\n\
                 \x20 zulu: {{kind: osv-offline, host: h}}\n\
                 \x20 alpha: {{kind: ossf-malicious, host: h}}\n"
            ),
        );
        let b = write(
            dir.path(),
            "b.json",
            &doc(r#""advisors":{"mike":{"kind":"osv-offline","host":"h"},
                               "alpha":{"kind":"osv-offline","host":"h"}}"#),
        );

        let config = ConfigLoader::new()
            .add_path(a)
            .add_path(b)
            .load()
            .expect("loads");

        let names: Vec<&str> = config.advisors.keys().map(String::as_str).collect();

        assert_eq!(names, ["zulu", "alpha", "mike"]);
        assert_eq!(config.advisors["alpha"].kind, "ossf-malicious");
    }

    /// The README's own example: `a.yaml` says debug, `b.yaml` says warn,
    /// and the answer is debug.
    #[test]
    fn merge_earlier_files_win() {
        let dir = tempfile::tempdir().expect("tempdir");

        let a = write(
            dir.path(),
            "a.json",
            &doc(r#""setup":{"log":{"level":"debug"}}"#),
        );
        let b = write(
            dir.path(),
            "b.json",
            &doc(r#""setup":{"log":{"level":"warn"}}"#),
        );

        let config = ConfigLoader::new()
            .add_path(a)
            .add_path(b)
            .load()
            .expect("loads");

        assert_eq!(level(&config), Some(LogLevel::Debug));
    }

    /// First-wins applies per key, so a later file still contributes
    /// settings the earlier one never mentioned.
    #[test]
    fn merge_per_key_not_per_file() {
        let dir = tempfile::tempdir().expect("tempdir");

        let a = write(
            dir.path(),
            "a.json",
            &doc(r#""setup":{"log":{"level":"debug"}}"#),
        );
        let b = write(
            dir.path(),
            "b.json",
            &doc(r#""setup":{"log":{"level":"warn"},"thread-pool-size":4}"#),
        );

        let config = ConfigLoader::new()
            .add_path(a)
            .add_path(b)
            .load()
            .expect("loads");

        assert_eq!(level(&config), Some(LogLevel::Debug));
        assert_eq!(config.setup.thread_pool_size, Some(4));
    }

    #[test]
    fn load_directory_scanned_alphabetically() {
        let dir = tempfile::tempdir().expect("tempdir");

        write(
            dir.path(),
            "20-later.json",
            &doc(r#""setup":{"log":{"level":"error"}}"#),
        );
        write(
            dir.path(),
            "10-first.json",
            &doc(r#""setup":{"log":{"level":"trace"}}"#),
        );
        write(dir.path(), "notes.txt", "ignored");

        let config = ConfigLoader::new()
            .add_path(dir.path())
            .load()
            .expect("loads");

        assert_eq!(level(&config), Some(LogLevel::Trace));
    }

    #[test]
    fn yaml_and_json_mix_freely() {
        let dir = tempfile::tempdir().expect("tempdir");

        let yaml = write(
            dir.path(),
            "a.yaml",
            &format!("$schema: {CONFIG_SCHEMA_ID}\nsetup:\n  log:\n    level: info\n"),
        );
        let json = write(
            dir.path(),
            "b.json",
            &doc(r#""setup":{"thread-pool-size":2}"#),
        );

        let config = ConfigLoader::new()
            .add_path(yaml)
            .add_path(json)
            .load()
            .expect("loads");

        assert_eq!(level(&config), Some(LogLevel::Info));
        assert_eq!(config.setup.thread_pool_size, Some(2));
    }

    /// An error must name the offending file, which is why each document is
    /// validated before it is merged into an anonymous whole.
    #[test]
    fn schema_violation_names_file() {
        let dir = tempfile::tempdir().expect("tempdir");

        let bad = write(
            dir.path(),
            "broken.json",
            &doc(r#""setup":{"log":{"level":"shouty"}}"#),
        );

        let err = ConfigLoader::new().add_path(&bad).load().unwrap_err();
        let message = err.to_string();

        assert!(message.contains("broken.json"));
        assert!(message.contains("/setup/log/level"));
    }

    /// Four mistakes should cost one run to fix, not four.
    #[test]
    fn every_violation_reported_at_once() {
        let dir = tempfile::tempdir().expect("tempdir");

        let bad = write(
            dir.path(),
            "broken.json",
            &doc(r#""setup":{"log":{"level":"shouty","output-format":"interpretive-dance"}}"#),
        );

        let err = ConfigLoader::new().add_path(&bad).load().unwrap_err();
        let message = err.to_string();

        assert!(message.contains("/setup/log/level"));
        assert!(message.contains("/setup/log/output-format"));
    }

    #[test]
    fn schema_declaration_missing_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");

        let bad = write(dir.path(), "bare.json", r#"{"setup":{}}"#);

        let err = ConfigLoader::new().add_path(&bad).load().unwrap_err();

        assert!(err.to_string().contains("$schema"));
    }

    #[test]
    fn load_missing_path_is_error() {
        let err = ConfigLoader::new()
            .add_path("/nonexistent/config.yaml")
            .load()
            .unwrap_err();

        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn load_nothing_is_error() {
        let err = ConfigLoader::new().load().unwrap_err();

        assert!(err.to_string().contains("no configuration files"));
    }

    /// Arrays are replaced whole, never concatenated: a later file must not
    /// be able to add an entry to an earlier file's list.
    #[test]
    fn merge_arrays_do_not_accumulate() {
        let mut base: Value = serde_json::json!({"xs": [1, 2]});
        merge_first_wins(&mut base, serde_json::json!({"xs": [3, 4, 5]}));

        assert_eq!(base["xs"], serde_json::json!([1, 2]));
    }

    #[test]
    fn yaml_constructs_without_json_form_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");

        // A mapping with a sequence as its key: legal YAML, inexpressible
        // in JSON.
        let bad = write(dir.path(), "odd.yaml", "? [a, b]\n: value\n");

        let err = ConfigLoader::new().add_path(&bad).load().unwrap_err();

        assert!(err.to_string().contains("odd.yaml"));
    }

    // -- Proxy sources ----------------------------------------------------

    /// Load one `sources` block and return what it parsed to.
    fn sources(body: &str) -> Result<crate::config::Config> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "c.json", &doc(body));

        ConfigLoader::new().add_path(&path).load()
    }

    /// The ordinary shape stays exactly as it was.
    #[test]
    fn source_names_host() {
        let config =
            sources(r#""sources":{"central":{"host":"h","kind":"maven"}}"#).expect("loads");

        let central = &config.sources["central"];

        assert_eq!(central.host.as_deref(), Some("h"));
        assert!(central.proxy_to.is_empty());
    }

    /// A proxy names what it stands in front of instead of a host.
    #[test]
    fn proxy_names_upstreams_not_host() {
        let config = sources(
            r#""sources":{
                "central":{"host":"h","kind":"maven"},
                "combined":{
                    "kind":"proxy-failover",
                    "proxy-to":[
                        {"ref":"central","classifier":"primary"},
                        {"source":{"host":"h","kind":"maven"}}
                    ]
                }
            }"#,
        )
        .expect("loads");

        let combined = &config.sources["combined"];

        assert!(combined.host.is_none());
        assert_eq!(combined.proxy_to.len(), 2);

        assert_eq!(combined.proxy_to[0].referenced(), Some("central"));
        assert_eq!(combined.proxy_to[0].classifier.as_deref(), Some("primary"));

        assert!(combined.proxy_to[1].referenced().is_none());
        assert_eq!(
            combined.proxy_to[1].defined().expect("inline").kind,
            "maven"
        );
        assert!(combined.proxy_to[1].classifier.is_none());
    }

    /// Order is the configuration's, and a proxy may use it.
    #[test]
    fn proxy_upstreams_keep_their_order() {
        let config = sources(
            r#""sources":{"p":{"kind":"proxy-failover","proxy-to":[
                {"ref":"c"},{"ref":"b"},{"ref":"a"}
            ]}}"#,
        )
        .expect("loads");

        let names: Vec<Option<&str>> = config.sources["p"]
            .proxy_to
            .iter()
            .map(|entry| entry.referenced())
            .collect();

        assert_eq!(names, [Some("c"), Some("b"), Some("a")]);
    }

    /// Classifiers are tags, not keys: the schema must not require them to
    /// be distinct, because a proxy with two snapshot repositories is a
    /// reasonable thing to configure.
    #[test]
    fn repeated_classifiers_load() {
        let config = sources(
            r#""sources":{"p":{"kind":"proxy-failover","proxy-to":[
                {"ref":"a","classifier":"snapshot"},
                {"ref":"b","classifier":"snapshot"}
            ]}}"#,
        )
        .expect("loads");

        assert_eq!(config.sources["p"].proxy_to.len(), 2);
    }

    /// An inline entry may itself be a proxy: nesting is structural and
    /// cannot close a loop. This is the half of the rule that allows.
    #[test]
    fn proxy_upstream_inline_may_be_proxy() {
        let config = sources(
            r#""sources":{"outer":{"kind":"proxy-failover","proxy-to":[
                {"source":{"kind":"proxy-failover","proxy-to":[
                    {"ref":"central"}
                ]}}
            ]}}"#,
        )
        .expect("nesting is allowed");

        let inner = config.sources["outer"].proxy_to[0]
            .defined()
            .expect("inline");

        assert_eq!(inner.proxy_to[0].referenced(), Some("central"));
    }

    /// The field is forbidden rather than ignored: an ignored key a user
    /// can still set is worse than one they cannot, because they would
    /// reasonably expect it to mean something.
    #[test]
    fn proxy_to_beside_host_refused() {
        let err = sources(
            r#""sources":{"p":{"host":"h","kind":"proxy-failover","proxy-to":[{"ref":"a"}]}}"#,
        )
        .expect_err("host and proxy-to are exclusive");

        assert!(err.to_string().contains("host"), "{err}");
    }

    /// And a source with neither is not a description of anything.
    #[test]
    fn source_without_host_or_upstreams_refused() {
        assert!(sources(r#""sources":{"p":{"kind":"maven"}}"#).is_err());
    }

    /// One entry is a reference or a definition, never both and never
    /// neither - otherwise which one the loader should follow is a guess.
    #[test]
    fn proxy_entry_one_shape_or_other() {
        let both = r#""sources":{"p":{"kind":"proxy-failover","proxy-to":[
            {"ref":"a","source":{"host":"h","kind":"maven"}}
        ]}}"#;

        let neither = r#""sources":{"p":{"kind":"proxy-failover","proxy-to":[
            {"classifier":"primary"}
        ]}}"#;

        assert!(sources(both).is_err(), "a ref and a definition at once");
        assert!(sources(neither).is_err(), "neither a ref nor a definition");
    }

    // -- Problem policy ---------------------------------------------------

    /// The schema enumerates the configurable problem codes, so it has to be
    /// checked against the enum or a code added in Rust becomes one the
    /// schema silently rejects.
    ///
    /// Enumerating is worth that upkeep: codes are a closed set, so a
    /// misspelling is a typo the schema can name outright rather than
    /// something to resolve at validate time.
    ///
    /// Checked in both directions, because either drift is a bug: a code
    /// missing from the schema is one nobody can configure, and a code
    /// listed that should not be is a setup fault a configuration could
    /// excuse -- which is the one thing the fail-fast tier exists to prevent.
    #[test]
    fn schema_knows_every_configurable_problem_code() {
        let schema: Value = serde_json::from_str(CONFIG_SCHEMA).expect("parses");

        let listed: Vec<&str> = schema["properties"]["problem-policy"]["propertyNames"]["enum"]
            .as_array()
            .expect("an enum of code names")
            .iter()
            .map(|name| name.as_str().expect("a string"))
            .collect();

        for code in crate::core::problem::Code::all() {
            assert_eq!(
                listed.contains(&code.as_str()),
                code.concerns_an_artifact(),
                "{code} concerns {:?}, but listed={}",
                code.concerns(),
                listed.contains(&code.as_str()),
            );
        }
    }

    /// A configuration cannot excuse the file it is written in, nor the
    /// files that name the artifacts.  `docs/contributors/exit-codes.md`
    /// makes this tier unconditional, and the schema is where that is
    /// enforced for the `problem-policy` table.
    #[test]
    fn setup_fault_cannot_be_configured_away() {
        let schema: Value = serde_json::from_str(CONFIG_SCHEMA).expect("parses");

        let listed = schema["properties"]["problem-policy"]["propertyNames"]["enum"]
            .as_array()
            .expect("an enum of code names");

        for name in [
            "config-invalid",
            "config-unreadable",
            "file-unreadable",
            "lock-format-unknown",
            "lock-unrecognized",
            "lock-malformed",
            "enumeration-unsupported",
            "sample-percent-unsupported",
        ] {
            assert!(
                !listed.iter().any(|listed| listed == name),
                "{name} is a setup fault and must not be configurable"
            );
        }
    }

    #[test]
    fn problem_policy_loads() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""problem-policy":{"signature-missing":"allowed","malware-known":"hard"}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let policy = config.resolved_problem_policy();

        use crate::core::problem::{Class, Code};

        assert_eq!(policy.class(Code::SignatureMissing), Some(Class::Allowed));
        assert_eq!(policy.class(Code::MalwareKnown), Some(Class::Hard));

        // And an unmentioned code is untouched.
        assert_eq!(policy.class(Code::ChecksumMismatch), None);
    }

    /// No table is exactly the built-in behavior, which is what makes this
    /// a pure addition to an existing configuration.
    #[test]
    fn problem_policy_absent_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "c.json", &doc(r#""setup":{}"#));

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        assert!(config.resolved_problem_policy().is_empty());
    }

    /// A closed set is worth enumerating precisely so this is caught at
    /// load rather than becoming a setting that silently does nothing.
    #[test]
    fn problem_policy_code_misspelled_refused() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""problem-policy":{"signature-mising":"allowed"}"#),
        );

        let err = ConfigLoader::new().add_path(&path).load().unwrap_err();

        assert!(err.to_string().contains("signature-mising"), "{err}");
    }

    #[test]
    fn problem_policy_class_outside_four_refused() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""problem-policy":{"malware-known":"quarantine"}"#),
        );

        assert!(ConfigLoader::new().add_path(&path).load().is_err());
    }

    // -- Dispositions ------------------------------------------------------

    use crate::core::problem::{Action, Code, Decide, Quarantine};
    use crate::model::{ArtifactId, EcosystemId, Release, Version};

    fn subject() -> crate::core::problem::Subject {
        crate::core::problem::Subject::new(
            ArtifactId::new(EcosystemId::npm(), None, "tuna"),
            Some(Version::new("1.0.0", Release::General)),
        )
    }

    /// The two halves a user may have written -- a table in the
    /// configuration and a file beside it -- reach one decision.
    #[test]
    fn dispositions_join_table_and_quarantine_file() {
        let dir = tempfile::tempdir().expect("tempdir");

        write(
            dir.path(),
            "q.json",
            &format!(
                r#"{{"$schema":"{}","rules":[{{"purl":"pkg:npm/tuna","codes":["malware-known"],"class":"allowed","expires":"never"}}]}}"#,
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"q.json"},
                   "problem-policy":{"signature-missing":"hard"}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let decided = config.dispositions(false).expect("assembled");

        // Through `Decide`, which is the interface a `Ctx` consults.
        let at = subject();
        let quarantine = |code, at| Decide::decide(&decided, code, at).disposition.quarantine;

        // From the table.
        assert_eq!(
            quarantine(Code::SignatureMissing, None),
            Some(Quarantine::Hard)
        );

        // From the file, and only for the artifact it names.
        assert_eq!(quarantine(Code::MalwareKnown, Some(&at)), None);
        assert_eq!(quarantine(Code::MalwareKnown, None), Some(Quarantine::Hard));
    }

    /// The flag may turn hardening on and never off: a configuration that
    /// asked for strict runs is not relaxed by omitting a command-line
    /// argument.
    #[test]
    fn hardening_from_either_place_only_turns_on() {
        let dir = tempfile::tempdir().expect("tempdir");

        let relaxed = write(dir.path(), "a.json", &doc(r#""setup":{}"#));
        let strict = write(
            dir.path(),
            "b.json",
            &doc(r#""setup":{"harden-quarantine":true}"#),
        );

        let load = |path: &Path| ConfigLoader::new().add_path(path).load().expect("loads");

        // A soft code, so there is something for hardening to act on.
        let soft = Code::SignatureMissing;
        let at = subject();
        let of = |config: &Config, harden: bool| {
            Decide::decide(
                &config.dispositions(harden).expect("assembled"),
                soft,
                Some(&at),
            )
            .disposition
            .action
        };

        assert_eq!(of(&load(&relaxed), false), Action::Warn);
        assert_eq!(of(&load(&relaxed), true), Action::SkipArtifact);
        assert_eq!(of(&load(&strict), false), Action::SkipArtifact);
        assert_eq!(of(&load(&strict), true), Action::SkipArtifact);
    }

    /// A named file that will not load stops the run rather than leaving
    /// the overrides silently absent -- which would read as every exception
    /// having been revoked.
    #[test]
    fn quarantine_policy_unreadable_is_error() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"nowhere.json"}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        assert!(config.dispositions(false).is_err());
    }

    // -- Where a relative path points -------------------------------------

    /// The rule, and the guard that keeps it true.
    ///
    /// Every `ConfigRelativePath` in the schema must be anchored, and the anchoring
    /// list is hand-written - so this walks the schema and asserts the two
    /// agree, as whole routes rather than by name. A new file-bearing
    /// setting then cannot be added without either anchoring it or
    /// consciously typing it `Command`, which is not a file path and is
    /// resolved by the operating system instead.
    ///
    /// Comparing names alone was the first attempt and was not a guard:
    /// `config-relative-path` appears in both `setup.log` and `caches`.
    #[test]
    fn path_every_config_relative_anchored() {
        let schema: Value = serde_json::from_str(CONFIG_SCHEMA).expect("schema parses");

        let mut refs = Vec::new();
        collect_refs(&schema, &mut Vec::new(), &mut refs);

        let mut found: std::collections::BTreeSet<String> = Default::default();

        for (route, target) in &refs {
            if target != "ConfigRelativePath" {
                continue;
            }

            match route.first().map(String::as_str) {
                Some("$defs") => {
                    expand_refs(&refs, &route[1], &document_route(route), &mut found);
                }

                _ => {
                    found.insert(document_route(route));
                }
            }
        }

        let anchored: std::collections::BTreeSet<String> =
            ANCHORED.iter().map(|route| route.join("/")).collect();

        assert_eq!(
            found, anchored,
            "every ConfigRelativePath in the schema must be anchored, and every anchored \
             route must still be a ConfigRelativePath -- if this fails, either add the \
             route to ANCHORED or give the setting a distinct path type"
        );
    }

    /// Every `$ref` in the schema, as (route, target definition name).
    fn collect_refs(node: &Value, trail: &mut Vec<String>, found: &mut Vec<(Vec<String>, String)>) {
        match node {
            Value::Object(fields) => {
                if let Some(Value::String(target)) = fields.get("$ref")
                    && let Some(name) = target.strip_prefix("#/$defs/")
                {
                    found.push((trail.clone(), name.to_owned()));
                }

                for (key, value) in fields {
                    trail.push(key.clone());
                    collect_refs(value, trail, found);
                    trail.pop();
                }
            }

            Value::Array(items) => {
                for (index, value) in items.iter().enumerate() {
                    trail.push(index.to_string());
                    collect_refs(value, trail, found);
                    trail.pop();
                }
            }

            _ => {}
        }
    }

    /// Expand a definition route through each definition that uses it.
    fn expand_refs(
        refs: &[(Vec<String>, String)],
        holder: &str,
        suffix: &str,
        found: &mut std::collections::BTreeSet<String>,
    ) {
        for (route, target) in refs {
            if target != holder {
                continue;
            }

            let prefix = document_route(route);
            let combined = match prefix.is_empty() {
                true => suffix.to_owned(),
                false => format!("{prefix}/{suffix}"),
            };

            match route.first().map(String::as_str) {
                Some("$defs") => expand_refs(refs, &route[1], &combined, found),
                _ => {
                    found.insert(combined);
                }
            }
        }
    }

    /// A schema route as the document route a user writes.
    ///
    /// `properties` is scaffolding, a map of user-chosen names is the `*`
    /// the anchoring list spells - written `patternProperties` here, since
    /// the schema constrains what a name may contain - and a `oneOf` branch
    /// is a variant rather than a step in the path.
    fn document_route(route: &[String]) -> String {
        let mut steps: Vec<&str> = Vec::new();
        let mut skip_next = false;

        for (index, step) in route.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }

            match step.as_str() {
                "properties" => {}
                "oneOf" | "anyOf" | "allOf" => skip_next = true,
                "additionalProperties" => steps.push("*"),

                // A collection keyed by a user-chosen name, whose key is a
                // regex in the schema and a `*` in the anchoring list.
                "patternProperties" => {
                    steps.push("*");
                    skip_next = true;
                }

                // The definition's own name is replaced by wherever it is
                // used, which the caller supplies.
                "$defs" => skip_next = true,

                other if index == 0 && other == "$defs" => {}
                other => steps.push(other),
            }
        }

        steps.join("/")
    }

    /// The point of anchoring per file rather than once per run: two
    /// configurations in different directories each name a policy beside
    /// themselves, and each must find its own.
    #[test]
    fn path_policy_resolves_against_own_file() {
        let root = tempfile::tempdir().expect("tempdir");

        let first = root.path().join("one");
        let second = root.path().join("two");

        fs::create_dir_all(&first).expect("created");
        fs::create_dir_all(&second).expect("created");

        let a = write(
            &first,
            "a.json",
            &doc(r#""setup":{"license-policy":"policy.yaml"}"#),
        );
        let b = write(
            &second,
            "b.json",
            &doc(
                r#""hosts":{"h":{"url":"https://example.test/","quarantine-policy":"rules.yaml"}}"#,
            ),
        );

        let config = ConfigLoader::new()
            .add_path(&a)
            .add_path(&b)
            .load()
            .expect("loads");

        assert_eq!(
            config.setup.license_policy.as_deref(),
            Some(first.join("policy.yaml").as_path()),
            "the first file's policy is beside the first file"
        );

        assert_eq!(
            config.hosts["h"].quarantine_policy.as_deref(),
            Some(second.join("rules.yaml").as_path()),
            "and the second file's is beside the second, not the first"
        );
    }

    /// A directory argument anchors each file inside it, not the argument.
    #[test]
    fn path_directory_argument_anchors_each_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let inner = root.path().join("conf.d");

        fs::create_dir_all(&inner).expect("created");

        write(
            &inner,
            "10-base.json",
            &doc(r#""setup":{"cache-dir":"../cache"}"#),
        );

        let config = ConfigLoader::new().add_path(&inner).load().expect("loads");

        assert_eq!(
            config.setup.cache_dir.as_deref(),
            Some(inner.join("../cache").as_path())
        );
    }

    #[test]
    fn path_absolute_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let absolute = dir.path().join("elsewhere").join("policy.yaml");

        let path = write(
            dir.path(),
            "a.json",
            &doc(&format!(
                r#""setup":{{"license-policy":{}}}"#,
                serde_json::to_string(&absolute.to_string_lossy()).expect("json")
            )),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        assert_eq!(
            config.setup.license_policy.as_deref(),
            Some(absolute.as_path())
        );
    }

    /// The two rules, pinned apart.
    ///
    /// A `property-file` secret follows the `.env` convention and resolves
    /// against the working directory, so the loader must leave it exactly as
    /// written -- this catches a future "absolutise every path"
    /// walk quietly moving where credentials are read from.
    #[test]
    fn path_working_dir_not_anchored() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "a.json",
            &doc(
                r#""hosts":{"h":{"url":"https://example.test/","authentication":{
                    "kind":"basic",
                    "password":{"kind":"property-file","working-dir-path":"secrets/.env","key":"TOKEN"}}}}"#,
            ),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        let Some(crate::config::Authentication::Basic { password, .. }) =
            &config.hosts["h"].authentication
        else {
            panic!("expected basic authentication");
        };

        let Some(crate::config::SecretValue::PropertyFile {
            working_dir_path, ..
        }) = password
        else {
            panic!("expected a property-file secret");
        };

        assert_eq!(
            working_dir_path,
            Path::new("secrets/.env"),
            "a working-dir-path stays relative to the working directory"
        );
    }

    #[test]
    fn path_keys_legacy_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            dir.path(),
            "a.json",
            &doc(r#""setup":{"log":{"path":"audit.log"}}"#),
        );

        assert!(ConfigLoader::new().add_path(&path).load().is_err());
    }

    #[test]
    fn path_keys_both_rejected() {
        let cases = [
            r#""setup":{"log":{"config-relative-path":"audit.log","working-dir-path":"audit.log"}}"#,
            r#""hosts":{"h":{"url":"https://example.test/","authentication":{"kind":"bearer","token":{"kind":"property-file","config-relative-path":"token.env","working-dir-path":"token.env","key":"TOKEN"}}}}"#,
        ];

        for (index, body) in cases.into_iter().enumerate() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = write(dir.path(), &format!("{index}.json"), &doc(body));

            assert!(
                ConfigLoader::new().add_path(&path).load().is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn path_keys_alternate_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            dir.path(),
            "a.json",
            &doc(r#""setup":{"log":{"working-dir-path":"audit.log"}},
                   "hosts":{"h":{"url":"https://example.test/","authentication":{"kind":"bearer","token":{"kind":"property-file","config-relative-path":"token.env","key":"TOKEN"}}}}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let Some(crate::config::Authentication::Bearer { token, .. }) =
            &config.hosts["h"].authentication
        else {
            panic!("expected bearer authentication");
        };
        let Some(crate::config::SecretValue::PropertyFile {
            working_dir_path, ..
        }) = token
        else {
            panic!("expected property-file secret");
        };

        assert_eq!(working_dir_path, &dir.path().join("token.env"));
    }

    /// A command is resolved by the operating system, so `python3` has to
    /// stay `python3` rather than becoming `<config-dir>/python3`.
    #[test]
    fn path_extension_command_not_anchored() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "a.json",
            &doc(r#""extensions":{"e":{"kind":"executable","command":"python3","arguments":[]}}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        assert!(
            format!("{:?}", config.extensions["e"]).contains("python3"),
            "{:?}",
            config.extensions["e"]
        );
    }

    // -- Servers and repositories ------------------------------------------

    /// Lowering through the whole loader: schema, anchoring, origins, merge.
    mod lowering {
        use super::*;

        fn yaml(body: &str) -> String {
            format!("$schema: {CONFIG_SCHEMA_ID}\n{body}")
        }

        fn load(files: &[(&str, &str)]) -> (tempfile::TempDir, Result<Config>) {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut loader = ConfigLoader::new();

            for (name, body) in files {
                loader = loader.add_path(write(dir.path(), name, &yaml(body)));
            }

            let loaded = loader.load();

            (dir, loaded)
        }

        fn refusal(files: &[(&str, &str)]) -> String {
            match load(files).1 {
                Err(err) => err.to_string(),
                Ok(_) => panic!("expected the configuration to be refused"),
            }
        }

        const NEXUS: &str = "
servers:
  nexus:
    kind: nexus3
    url: https://nexus.test/
    repositories:
      m2:
        name: maven-releases
        kind: maven2
";

        #[test]
        fn repository_nexus_fills_every_role() {
            let (_dir, config) = load(&[("a.yaml", NEXUS)]);
            let config = config.expect("loads");

            assert_eq!(config.hosts["nexus"].url, "https://nexus.test/");

            let source = &config.sources["m2"];
            assert_eq!(source.host.as_deref(), Some("nexus"));
            assert_eq!(source.kind, "nexus");
            assert_eq!(source.options["repository"], "maven-releases");
            assert_eq!(source.options["ecosystem"], "maven");

            let target = &config.targets["m2"];
            assert_eq!(target.host, "nexus");
            assert_eq!(target.options["metadata"], "merge");

            let enumerator = &config.enumerators["m2"];
            assert_eq!(enumerator.kind, "nexus");
            assert_eq!(enumerator.options["repository"], "maven-releases");
            assert_eq!(enumerator.options["ecosystem"], "maven");
        }

        /// A repository in another file names the server; the name defaults
        /// to the alias.
        #[test]
        fn repository_standalone_joins_server() {
            let (_dir, config) = load(&[
                ("a.yaml", NEXUS),
                (
                    "b.yaml",
                    "repositories:\n  npm-a:\n    server: nexus\n    kind: npm\n",
                ),
            ]);
            let config = config.expect("loads");

            assert_eq!(config.sources["npm-a"].options["repository"], "npm-a");
            assert!(config.sources.contains_key("m2"), "the server's own remain");
        }

        /// A public server without repositories is one repository named for
        /// the server, read only.
        #[test]
        fn server_public_implies_repository() {
            let (_dir, config) = load(&[(
                "a.yaml",
                "servers:\n  pypi-org:\n    kind: public-pypi.org\n",
            )]);
            let config = config.expect("loads");

            assert_eq!(config.hosts["pypi-org"].url, "https://pypi.org/");
            assert_eq!(config.hosts["pypi-org"].additional_hosts.len(), 1);
            assert_eq!(config.sources["pypi-org"].kind, "pypi");
            assert_eq!(config.enumerators["pypi-org"].kind, "pypi-simple");
            assert!(config.targets.is_empty(), "a public registry is read only");
        }

        #[test]
        fn server_public_refuses_writes() {
            let complaint = refusal(&[(
                "a.yaml",
                "servers:\n  central:\n    kind: maven-central\n    repositories:\n      c:\n        kind: maven\n        access: write\n",
            )]);

            assert!(complaint.contains("write access"), "{complaint}");
        }

        /// Read access generates no target, and overriding one is a mistake.
        #[test]
        fn read_access_omits_target() {
            let body = NEXUS.replace("kind: maven2", "kind: maven2\n        access: read");
            let (_dir, config) = load(&[("a.yaml", &body)]);

            assert!(config.expect("loads").targets.is_empty());

            let body = format!(
                "{body}        target:\n          options:\n            metadata: server\n"
            );
            let complaint = refusal(&[("a.yaml", &body)]);

            assert!(complaint.contains("overrides its target"), "{complaint}");
        }

        /// Override blocks deep-merge over the template's entry.
        #[test]
        fn override_block_merges() {
            let body = format!(
                "{NEXUS}        target:\n          options:\n            overwrite-guard: check\n"
            );
            let (_dir, config) = load(&[("a.yaml", &body)]);
            let options = &config.expect("loads").targets["m2"].options;

            assert_eq!(options["overwrite-guard"], "check");
            assert_eq!(options["metadata"], "merge", "the template's stays");
        }

        #[test]
        fn collision_refused() {
            let direct = "sources:\n  m2:\n    host: nexus\n    kind: maven\n";
            let complaint = refusal(&[("a.yaml", NEXUS), ("b.yaml", direct)]);

            assert!(complaint.contains("override-template"), "{complaint}");
        }

        #[test]
        fn template_override_wins() {
            let direct =
                "sources:\n  m2:\n    host: nexus\n    kind: maven\n    override-template: true\n";
            let (_dir, config) = load(&[("a.yaml", NEXUS), ("b.yaml", direct)]);
            let config = config.expect("loads");

            assert_eq!(config.sources["m2"].host_path, None, "the direct entry");
            assert!(config.targets.contains_key("m2"), "other roles still lower");
        }

        /// The user's `on-status` rules add codes and replace the kind's.
        #[test]
        fn retry_merges_by_status() {
            let body = "
servers:
  central:
    kind: maven-central
    retry:
      max-retries: 7
      on-status:
        500:
          retry: true
";
            let (_dir, config) = load(&[("a.yaml", body)]);
            let config = config.expect("loads");
            let retry = config.hosts["central"].retry.as_ref().expect("retry");

            assert!(retry.on_status.contains_key("429"), "the kind's rule stays");
            assert!(retry.on_status.contains_key("500"), "the user's rule joins");
            assert_eq!(retry.base.max_retries, Some(7));
        }

        #[test]
        fn unknown_names_listed() {
            let complaint = refusal(&[(
                "a.yaml",
                "servers:\n  s:\n    kind: gitea\n    url: https://s.test/\nrepositories:\n  r:\n    server: missing\n    kind: npm\n",
            )]);

            assert!(complaint.contains("\"gitea\""), "{complaint}");
            assert!(complaint.contains("nexus3"), "lists the kinds: {complaint}");
            assert!(
                complaint.contains("\"missing\""),
                "every problem at once: {complaint}"
            );

            let body = NEXUS.replace("kind: maven2", "kind: docker");
            let complaint = refusal(&[("a.yaml", &body)]);

            assert!(
                complaint.contains("maven2"),
                "lists the supported: {complaint}"
            );
        }

        #[test]
        fn repository_duplicate_refused() {
            let other = "repositories:\n  m2:\n    server: nexus\n    kind: npm\n";
            let complaint = refusal(&[("a.yaml", NEXUS), ("b.yaml", other)]);

            assert!(complaint.contains("in both"), "{complaint}");
        }

        /// A server's plain http:// url loads only with its opt-in, which
        /// reaches the host it generates.
        #[test]
        fn server_plain_http_needs_opt_in() {
            let plain = "servers:\n  n:\n    kind: nexus3\n    url: http://n.test/\n";
            let complaint = refusal(&[("a.yaml", plain)]);

            assert!(complaint.contains("insecure-transport"), "{complaint}");
            assert!(complaint.contains("http://n.test/"), "{complaint}");

            let opted = format!("{plain}    insecure-transport: true\n");
            let (_dir, config) = load(&[("a.yaml", &opted)]);

            assert!(config.expect("loads").hosts["n"].insecure_transport);
        }

        #[test]
        fn server_without_url_refused() {
            let complaint = refusal(&[("a.yaml", "servers:\n  n:\n    kind: nexus3\n")]);

            assert!(complaint.contains("no url"), "{complaint}");
        }

        const CUSTOM_MANIFEST: &str = "
server:
  file: server.yaml.hbs
repositories:
  npm:
    file: npm.yaml.hbs
    roles: [source]
    values:
      type: object
      additionalProperties: false
      properties:
        prefix:
          type: string
";

        /// The server's own paths were anchored as its file loaded; lowering
        /// must not anchor them again.  Only a relative config path shows
        /// the doubling, so this loads through one.
        #[test]
        fn path_server_anchored_once() {
            let dir = tempfile::tempdir_in(".").expect("tempdir");
            let relative = PathBuf::from(dir.path().file_name().expect("name"));
            let body = "
servers:
  n:
    kind: nexus3
    url: https://n.test/
    authentication:
      kind: basic
      password:
        kind: property-file
        config-relative-path: n.env
        key: PASSWORD
";

            write(dir.path(), "a.yaml", &yaml(body));

            let config = ConfigLoader::new()
                .add_path(relative.join("a.yaml"))
                .load()
                .expect("loads");

            let Some(crate::config::Authentication::Basic {
                password:
                    Some(crate::config::SecretValue::PropertyFile {
                        working_dir_path, ..
                    }),
                ..
            }) = &config.hosts["n"].authentication
            else {
                panic!("expected a property-file password");
            };

            assert_eq!(working_dir_path, &relative.join("n.env"));
        }

        /// A user kind in `setup.server-kinds-dir`.
        fn custom(dir: &Path, server: &str, npm: &str) {
            let kind = dir.join("kinds").join("custom");

            fs::create_dir_all(&kind).expect("mkdir");
            fs::write(kind.join("kind.yaml"), CUSTOM_MANIFEST).expect("write");
            fs::write(kind.join("server.yaml.hbs"), server).expect("write");
            fs::write(kind.join("npm.yaml.hbs"), npm).expect("write");
        }

        fn load_custom(
            server: &str,
            npm: &str,
            repository: &str,
        ) -> (tempfile::TempDir, Result<Config>) {
            load_custom_entry(server, npm, "", repository)
        }

        /// [`load_custom`] with the npm template fixed, and `entry` added
        /// to the server entry: `    insecure-transport: false\n`.
        fn load_custom_server(
            server: &str,
            entry: &str,
            repository: &str,
        ) -> (tempfile::TempDir, Result<Config>) {
            load_custom_entry(server, "source:\n  kind: npm\n", entry, repository)
        }

        fn load_custom_entry(
            server: &str,
            npm: &str,
            entry: &str,
            repository: &str,
        ) -> (tempfile::TempDir, Result<Config>) {
            let dir = tempfile::tempdir().expect("tempdir");
            let conf = dir.path().join("conf");

            fs::create_dir(&conf).expect("mkdir");
            custom(dir.path(), server, npm);

            let body = format!(
                "setup:\n  server-kinds-dir: ../kinds\nservers:\n  s:\n    kind: custom\n    url: https://s.test/\n{entry}    repositories:\n{repository}"
            );
            let path = write(&conf, "a.yaml", &yaml(&body));
            let loaded = ConfigLoader::new().add_path(path).load();

            (dir, loaded)
        }

        /// A template's relative path is taken against the file declaring
        /// the server, not the template's own directory.
        #[test]
        fn path_template_anchored_to_declaring_file() {
            let (dir, config) = load_custom(
                "host:\n  license-policy: licenses.yaml\n",
                "source:\n  kind: npm\n",
                "      r:\n        kind: npm\n",
            );
            let config = config.expect("loads");

            assert_eq!(
                config.hosts["s"].license_policy.as_deref(),
                Some(dir.path().join("conf").join("licenses.yaml").as_path())
            );
        }

        #[test]
        fn template_authentication_refused() {
            let (_dir, config) = load_custom(
                "host:\n  authentication:\n    kind: bearer\n",
                "source:\n  kind: npm\n",
                "      r:\n        kind: npm\n",
            );
            let complaint = config.expect_err("refused").to_string();

            assert!(complaint.contains("authentication"), "{complaint}");
        }

        /// A user's kind may accept plain HTTP for its host, and the
        /// server entry's own setting replaces the kind's either way.
        #[test]
        fn template_insecure_transport_overridable() {
            let template = "host:\n  insecure-transport: true\n";
            let (_dir, config) = load_custom(
                template,
                "source:\n  kind: npm\n",
                "      r:\n        kind: npm\n",
            );

            assert!(config.expect("loads").hosts["s"].insecure_transport);

            let (_dir, config) = load_custom_server(
                template,
                "    insecure-transport: false\n",
                "      r:\n        kind: npm\n",
            );

            assert!(!config.expect("loads").hosts["s"].insecure_transport);
        }

        /// Strict mode: a variable the template names must exist.
        #[test]
        fn missing_variable_refused() {
            let (_dir, config) = load_custom(
                "access: [read]\n",
                "source:\n  kind: npm\n  host-path: {{values.prefix}}\n",
                "      r:\n        kind: npm\n",
            );
            let complaint = config.expect_err("refused").to_string();

            assert!(complaint.contains("failed to render"), "{complaint}");
        }

        /// The manifest's schema checks a repository's values.
        #[test]
        fn undeclared_value_refused() {
            let (_dir, config) = load_custom(
                "access: [read]\n",
                "source:\n  kind: npm\n",
                "      r:\n        kind: npm\n        values:\n          other: 1\n",
            );
            let complaint = config.expect_err("refused").to_string();

            assert!(complaint.contains("values"), "{complaint}");
        }

        /// A template rendering a role its manifest does not declare.
        #[test]
        fn undeclared_role_refused() {
            let (_dir, config) = load_custom(
                "access: [read]\n",
                "source:\n  kind: npm\nenumerator:\n  kind: pypi-simple\n",
                "      r:\n        kind: npm\n",
            );
            let complaint = config.expect_err("refused").to_string();

            assert!(complaint.contains("manifest declares"), "{complaint}");
        }

        /// `yaml` quotes a value, so YAML syntax in it stays text.  No HTML
        /// escaping either: `&` stays `&`.
        #[test]
        fn yaml_helper_quotes_values() {
            let (_dir, config) = load_custom(
                "access: [read]\n",
                "source:\n  kind: npm\n  host-path: {{yaml (concat \"a/\" values.prefix)}}\n",
                "      r:\n        kind: npm\n        values:\n          prefix: \"x: y # z & w\"\n",
            );
            let config = config.expect("loads");

            assert_eq!(
                config.sources["r"].host_path.as_deref(),
                Some("a/x: y # z & w")
            );
        }
    }
}
