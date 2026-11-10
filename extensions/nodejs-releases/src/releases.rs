//! NodeJS releases, as nodejs.org/dist lays them out.
//!
//! ```text
//!   {base}                       index: one `v24.1.0/` link per release
//!   {base}v24.1.0/               the release's files
//!   {base}v24.1.0/SHASUMS256.txt `<sha256>  <file name>` per line
//! ```

use serde::Deserialize;
use serde_json::{Value, json};

use guest_kit::{Failure, Host, wildcard};

use crate::links;

/// The one artifact name this source answers.
const ARTIFACT_NAME: &str = "nodejs";

/// The checksum list in each release directory.
const SHASUMS_FILE: &str = "SHASUMS256.txt";

/// The largest index page or checksum list accepted.
const MAX_PAGE_BYTES: u64 = 4 * 1024 * 1024;

/// What `versions` and `metadata` are given.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Input {
    artifact: Artifact,
    base_url: String,

    #[serde(default)]
    version: Option<String>,

    #[serde(default)]
    options: Options,
}

#[derive(Deserialize)]
struct Artifact {
    #[serde(default)]
    namespace: Option<String>,
    name: String,
}

/// The source's configured options.
#[derive(Deserialize, Default)]
struct Options {
    /// File name patterns to keep, `!` dropping; absent keeps every file.
    /// See `guest_kit::wildcard::keeps`.
    #[serde(default)]
    files: Option<Vec<String>>,
}

impl Input {
    /// The dist root, ending in `/`.
    fn base(&self) -> String {
        match self.base_url.ends_with('/') {
            true => self.base_url.clone(),
            false => format!("{}/", self.base_url),
        }
    }

    /// Refuse any artifact other than `nodejs`.
    fn check_artifact(&self) -> Result<(), Failure> {
        if self.artifact.namespace.is_none() && self.artifact.name == ARTIFACT_NAME {
            return Ok(());
        }

        Err(Failure::not_found(format!(
            "only {ARTIFACT_NAME:?} is published here, not {:?}",
            self.artifact.name
        )))
    }
}

/// Every release, oldest to newest as the index lists them.
pub fn versions(input: &Input, host: &dyn Host) -> Result<Value, Failure> {
    input.check_artifact()?;

    let page = host.fetch(&input.base(), MAX_PAGE_BYTES)?;

    let versions: Vec<Value> = links::parse(&page)
        .iter()
        .filter_map(|link| release_version(&link.text))
        .map(|text| json!({"text": text, "release": "general"}))
        .collect();

    Ok(json!({ "versions": versions }))
}

/// `v24.1.0/` to `24.1.0`; anything else, such as `latest/`, to `None`.
fn release_version(text: &str) -> Option<&str> {
    let text = text.trim();
    let text = text.strip_suffix('/').unwrap_or(text);
    let digits = text.strip_prefix('v')?;

    let well_formed = !digits.is_empty()
        && digits
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));

    well_formed.then_some(digits)
}

/// The files of one release, each with its sha256 where the checksum list
/// names it.
pub fn metadata(input: &Input, host: &dyn Host) -> Result<Value, Failure> {
    input.check_artifact()?;

    let version = input
        .version
        .as_deref()
        .ok_or_else(|| Failure::malformed("metadata needs a version"))?;
    let page_url = format!("{}v{version}/", input.base());

    let page = host.fetch(&page_url, MAX_PAGE_BYTES)?;
    let sums = host.fetch(&format!("{page_url}{SHASUMS_FILE}"), MAX_PAGE_BYTES)?;
    let sums = parse_sums(&sums);

    let files: Vec<Value> = links::parse(&page)
        .into_iter()
        .filter(|link| !link.href.ends_with('/'))
        .filter(|link| input.options.keeps(&link.text))
        .map(|link| {
            let url = resolve(&page_url, &link.href);

            match sums.iter().find(|(name, _)| *name == link.text) {
                Some((_, hex)) => json!({
                    "name": link.text,
                    "url": url,
                    "digests": [{"algorithm": "sha256", "hex": hex}],
                }),
                None => json!({"name": link.text, "url": url}),
            }
        })
        .collect();

    Ok(json!({ "files": files }))
}

impl Options {
    fn keeps(&self, name: &str) -> bool {
        match &self.files {
            None => true,
            Some(patterns) => wildcard::keeps(patterns, name),
        }
    }
}

/// `<hex>  <name>` lines; anything else is skipped.
fn parse_sums(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter_map(|line| {
            let (hex, name) = line.split_once(char::is_whitespace)?;
            let name = name.trim_start().trim_start_matches('*');

            let is_sha256 = hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit());

            is_sha256.then_some((name, hex))
        })
        .collect()
}

/// An `href` as an absolute URL, relative to the page it was on.
///
/// ```text
///   /dist/v1/a.tgz  on  https://nodejs.org/dist/v1/   ->  https://nodejs.org/dist/v1/a.tgz
///   a.tgz           on  https://nodejs.org/dist/v1/   ->  https://nodejs.org/dist/v1/a.tgz
/// ```
fn resolve(page_url: &str, href: &str) -> String {
    if href.contains("://") {
        return href.to_owned();
    }

    if href.starts_with('/') {
        return format!("{}{href}", origin(page_url));
    }

    format!("{page_url}{href}")
}

/// `scheme://host[:port]` of a URL.
fn origin(url: &str) -> &str {
    let Some(scheme_end) = url.find("://") else {
        return url;
    };
    let host_start = scheme_end + "://".len();

    match url[host_start..].find('/') {
        Some(path_start) => &url[..host_start + path_start],
        None => url,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const BASE: &str = "h://nodejs.test/dist/";

    /// Pages by URL; anything else is not found.
    struct Pages(BTreeMap<String, String>);

    impl Host for Pages {
        fn fetch(&self, url: &str, _max_bytes: u64) -> Result<String, Failure> {
            self.0
                .get(url)
                .cloned()
                .ok_or_else(|| Failure::not_found(format!("{url} not found")))
        }
    }

    fn pages() -> Pages {
        Pages(BTreeMap::from([
            (
                BASE.to_owned(),
                include_str!("../fixtures/node-dist.html").to_owned(),
            ),
            (
                format!("{BASE}v24.1.0/"),
                include_str!("../fixtures/node-v24.1.0.html").to_owned(),
            ),
            (
                format!("{BASE}v24.1.0/SHASUMS256.txt"),
                include_str!("../fixtures/node-v24.1.0.sha256.txt").to_owned(),
            ),
        ]))
    }

    fn input(value: Value) -> Input {
        serde_json::from_value(value).expect("valid input")
    }

    fn metadata_input(options: Value) -> Input {
        input(json!({
            "artifact": {"name": "nodejs"},
            "version": "24.1.0",
            "base-url": BASE,
            "options": options,
        }))
    }

    #[test]
    fn versions_from_index() {
        let input = input(json!({"artifact": {"name": "nodejs"}, "base-url": BASE, "options": {}}));

        let output = versions(&input, &pages()).expect("listed");
        let texts: Vec<&str> = output["versions"]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v["text"].as_str().expect("text"))
            .collect();

        assert!(texts.contains(&"24.1.0"));
        assert!(texts.contains(&"0.1.14"));
        assert!(!texts.iter().any(|t| t.starts_with("latest")));
    }

    #[test]
    fn release_version_shapes() {
        assert_eq!(release_version("v24.1.0/"), Some("24.1.0"));
        assert_eq!(release_version(" v8 "), Some("8"));
        assert_eq!(release_version("latest-v24.x/"), None);
        assert_eq!(release_version("v1..2/"), None);
        assert_eq!(release_version("v/"), None);
        assert_eq!(release_version("index.json"), None);
    }

    #[test]
    fn metadata_lists_files_with_digests() {
        let output = metadata(&metadata_input(json!({})), &pages()).expect("listed");
        let files = output["files"].as_array().expect("array");

        let tarball = files
            .iter()
            .find(|f| f["name"] == "node-v24.1.0-linux-x64.tar.gz")
            .expect("listed");

        assert_eq!(
            tarball["url"],
            "h://nodejs.test/dist/v24.1.0/node-v24.1.0-linux-x64.tar.gz"
        );
        assert_eq!(tarball["digests"][0]["algorithm"], "sha256");
        assert_eq!(
            tarball["digests"][0]["hex"].as_str().map(str::len),
            Some(64)
        );

        // Directories are not files.
        assert!(!files.iter().any(|f| f["name"] == "docs/"));
    }

    #[test]
    fn file_patterns_narrow() {
        let options = json!({"files": ["node-v*-linux-x64.tar.gz", "node-v*.tar.xz"]});

        let output = metadata(&metadata_input(options), &pages()).expect("listed");
        let names: Vec<&str> = output["files"]
            .as_array()
            .expect("array")
            .iter()
            .map(|f| f["name"].as_str().expect("name"))
            .collect();

        assert!(names.contains(&"node-v24.1.0-linux-x64.tar.gz"));
        assert!(names.contains(&"node-v24.1.0.tar.xz"));
        assert!(!names.contains(&"node-v24.1.0-win-x64.zip"));
    }

    #[test]
    fn unlisted_file_has_no_digest() {
        let options = json!({"files": ["SHASUMS256.txt.asc"]});

        let output = metadata(&metadata_input(options), &pages()).expect("listed");

        assert!(output["files"][0].get("digests").is_none());
    }

    #[test]
    fn missing_release_is_not_found() {
        let mut input = metadata_input(json!({}));
        input.version = Some("99.0.0".into());

        let failure = metadata(&input, &pages()).expect_err("absent");

        assert_eq!(failure.code, guest_kit::protocol::ARTIFACT_NOT_FOUND);
    }

    #[test]
    fn other_artifact_is_not_found() {
        let input = input(json!({"artifact": {"name": "deno"}, "base-url": BASE, "options": {}}));

        let failure = versions(&input, &pages()).expect_err("refused");

        assert_eq!(failure.code, guest_kit::protocol::ARTIFACT_NOT_FOUND);
    }

    #[test]
    fn href_resolution() {
        let page = "https://nodejs.org/dist/v1/";

        assert_eq!(resolve(page, "/dist/v1/a"), "https://nodejs.org/dist/v1/a");
        assert_eq!(resolve(page, "a"), "https://nodejs.org/dist/v1/a");
        assert_eq!(resolve(page, "https://cdn.test/a"), "https://cdn.test/a");
    }

    #[test]
    fn sums_parse() {
        let hex = "a".repeat(64);
        let text = format!("{hex}  one.tgz\n{hex} *two.zip\nnot a line\n");

        assert_eq!(
            parse_sums(&text),
            vec![("one.tgz", hex.as_str()), ("two.zip", hex.as_str())]
        );
    }
}
