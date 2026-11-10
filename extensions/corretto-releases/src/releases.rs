//! Amazon Corretto releases, as the GitHub releases of `corretto/corretto-<major>`.
//!
//! The artifact is the major, `corretto-25`, and each release tag is a
//! version. A release lists its files as links in its Markdown body.
//!
//! **A partial release carries the rest forward.** A build that fixes some
//! platforms lists only those ("Linux only release; for other platforms,
//! please use 25.0.1.8.1"). It takes every platform it lacks from the
//! release before it, when both are builds of one OpenJDK update:
//!
//! ```text
//!   25.0.1.8.1   linux, windows, macos          own files
//!   25.0.1.9.1   linux                          own linux + 25.0.1.8.1's windows, macos
//!   25.0.2.10.1  linux, windows, macos          own files; another update, nothing carried
//! ```
//!
//! A release with no files of its own, such as an AL2023-only build, is not
//! listed.

use std::collections::BTreeSet;

use guest_kit::{Failure, Host, wildcard};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::table::{self, Row};
use crate::tag::Tag;

/// The GitHub owner of every Corretto repository.
const OWNER: &str = "corretto";

/// Artifact names are `corretto-<major>`, as the repositories are.
const ARTIFACT_PREFIX: &str = "corretto-";

/// Releases per listing page; GitHub's maximum.
const PAGE_SIZE: usize = 100;

/// The most listing pages read, far beyond any Corretto major today.
const MAX_PAGES: usize = 20;

/// The largest listing page accepted.
const MAX_PAGE_BYTES: u64 = 8 * 1024 * 1024;

const COMPOUND_EXTENSION: &str = "tar.gz";

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

/// One release as the GitHub API lists it.
#[derive(Deserialize)]
struct Release {
    tag_name: String,

    #[serde(default)]
    draft: bool,

    #[serde(default)]
    prerelease: bool,

    #[serde(default)]
    published_at: Option<String>,

    #[serde(default)]
    body: Option<String>,
}

/// A release with the files it offers, carried ones included.
struct Listed {
    text: String,
    tag: Tag,
    pre_release: bool,
    published: Option<String>,
    rows: Vec<Row>,
}

impl Input {
    /// The API root, ending in `/`.
    fn base(&self) -> String {
        match self.base_url.ends_with('/') {
            true => self.base_url.clone(),
            false => format!("{}/", self.base_url),
        }
    }

    /// The major `corretto-25` names; anything else is not published here.
    fn major(&self) -> Result<u64, Failure> {
        let major = match &self.artifact.namespace {
            Some(_) => None,
            None => self
                .artifact
                .name
                .strip_prefix(ARTIFACT_PREFIX)
                .and_then(|digits| digits.parse::<u64>().ok()),
        };

        major.ok_or_else(|| {
            Failure::not_found(format!(
                "Corretto artifacts are named {ARTIFACT_PREFIX}<major>, not {:?}",
                self.artifact.name
            ))
        })
    }
}

impl Options {
    fn keeps(&self, name: &str) -> bool {
        match &self.files {
            None => true,
            Some(patterns) => wildcard::keeps(patterns, name),
        }
    }
}

/// Every release offering a file the `files` option keeps, oldest first.
pub fn versions(input: &Input, host: &dyn Host) -> Result<Value, Failure> {
    let versions: Vec<Value> = catalog(input, host)?
        .iter()
        .filter(|listed| !files(listed, &input.options).is_empty())
        .map(|listed| {
            let release = match listed.pre_release {
                true => "pre-release",
                false => "general",
            };

            json!({"text": listed.text, "release": release})
        })
        .collect();

    Ok(json!({ "versions": versions }))
}

/// The files of one release, carried ones included.
pub fn metadata(input: &Input, host: &dyn Host) -> Result<Value, Failure> {
    let version = input
        .version
        .as_deref()
        .ok_or_else(|| Failure::malformed("metadata needs a version"))?;

    let catalog = catalog(input, host)?;
    let Some(listed) = catalog.iter().find(|listed| listed.text == version) else {
        return Err(Failure::not_found(format!(
            "{} has no release {version:?} with downloads",
            input.artifact.name
        )));
    };

    let mut output = json!({ "files": files(listed, &input.options) });

    if let Some(published) = &listed.published {
        output["published"] = published.clone().into();
    }

    Ok(output)
}

/// The kept files of a release: each download, then its signature.
fn files(listed: &Listed, options: &Options) -> Vec<Value> {
    let mut files = Vec::new();

    for row in &listed.rows {
        let name = file_name(&row.url);

        if options.keeps(name) {
            files.push(json!({"name": name, "url": row.url, "digests": digests(row)}));
        }

        let Some(sig_url) = &row.sig_url else {
            continue;
        };

        let sig_name = file_name(sig_url);
        if options.keeps(sig_name) {
            files.push(json!({"name": sig_name, "url": sig_url}));
        }
    }

    files
}

fn digests(row: &Row) -> Vec<Value> {
    let sha256 = row
        .sha256
        .iter()
        .map(|hex| json!({"algorithm": "sha256", "hex": hex}));
    let md5 = row
        .md5
        .iter()
        .map(|hex| json!({"algorithm": "md5", "hex": hex}));

    sha256.chain(md5).collect()
}

/// Every listed release of the major, oldest first, partial ones filled in.
fn catalog(input: &Input, host: &dyn Host) -> Result<Vec<Listed>, Failure> {
    let major = input.major()?;

    let mut releases: Vec<(Tag, Release)> = fetch_all(input, host)?
        .into_iter()
        .filter(|release| !release.draft)
        .filter_map(|release| Tag::parse(&release.tag_name).map(|tag| (tag, release)))
        .filter(|(tag, _)| tag.major() == major)
        .collect();

    releases.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut listed: Vec<Listed> = Vec::new();

    // The last listed non-preview release, the only one a build carries from.
    let mut last: Option<usize> = None;

    for (tag, release) in releases {
        let mut rows = table::parse(release.body.as_deref().unwrap_or_default());

        if rows.is_empty() {
            continue;
        }

        let carries = !tag.is_preview()
            && last.is_some_and(|previous| listed[previous].tag.same_update(&tag));

        if let (true, Some(previous)) = (carries, last) {
            carry(&mut rows, &listed[previous].rows);
        }

        if !tag.is_preview() {
            last = Some(listed.len());
        }

        listed.push(Listed {
            text: release.tag_name,
            pre_release: release.prerelease || tag.is_preview(),
            tag,
            published: release.published_at,
            rows,
        });
    }

    Ok(listed)
}

/// Add each of `previous`'s platforms that `rows` lacks.
fn carry(rows: &mut Vec<Row>, previous: &[Row]) {
    let own: BTreeSet<(String, String, String)> = rows.iter().map(platform).collect();

    let missing = previous
        .iter()
        .filter(|row| !own.contains(&platform(row)))
        .cloned();

    rows.extend(missing.collect::<Vec<Row>>());
}

/// What a row offers, independent of the build: `(Linux x64, JDK, tar.gz)`.
fn platform(row: &Row) -> (String, String, String) {
    (
        row.platform.to_ascii_lowercase(),
        row.kind.to_ascii_lowercase(),
        extension(file_name(&row.url)).to_owned(),
    )
}

/// `a.tar.gz` to `tar.gz`, and `a.msi` to `msi`.
fn extension(name: &str) -> &str {
    if name.ends_with(&format!(".{COMPOUND_EXTENSION}")) {
        return COMPOUND_EXTENSION;
    }

    name.rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or_default()
}

/// The last path segment of a URL.
fn file_name(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

/// Every release, page by page, until a short page.
fn fetch_all(input: &Input, host: &dyn Host) -> Result<Vec<Release>, Failure> {
    let mut all = Vec::new();

    for page in 1..=MAX_PAGES {
        let url = format!(
            "{}repos/{OWNER}/{}/releases?per_page={PAGE_SIZE}&page={page}",
            input.base(),
            input.artifact.name
        );

        let text = host.fetch(&url, MAX_PAGE_BYTES)?;
        let releases: Vec<Release> =
            serde_json::from_str(&text).map_err(|err| Failure::malformed(err.to_string()))?;

        let short = releases.len() < PAGE_SIZE;
        all.extend(releases);

        if short {
            break;
        }
    }

    Ok(all)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use guest_kit::protocol::ARTIFACT_NOT_FOUND;

    use super::*;

    const BASE: &str = "h://api.test/";

    /// Pages by URL; anything else is not found.
    struct Pages(BTreeMap<String, &'static str>);

    impl Host for Pages {
        fn fetch(&self, url: &str, _max_bytes: u64) -> Result<String, Failure> {
            self.0
                .get(url)
                .map(|page| (*page).to_owned())
                .ok_or_else(|| Failure::not_found(format!("{url} not found")))
        }
    }

    fn page_url(major: u64) -> String {
        format!("{BASE}repos/corretto/corretto-{major}/releases?per_page=100&page=1")
    }

    fn pages() -> Pages {
        Pages(BTreeMap::from([
            (
                page_url(8),
                include_str!("../fixtures/corretto-8-releases.json"),
            ),
            (
                page_url(11),
                include_str!("../fixtures/corretto-11-releases.json"),
            ),
            (
                page_url(25),
                include_str!("../fixtures/corretto-25-releases.json"),
            ),
        ]))
    }

    fn input(major: u64, version: Option<&str>, files: Value) -> Input {
        serde_json::from_value(json!({
            "artifact": {"name": format!("corretto-{major}")},
            "base-url": BASE,
            "version": version,
            "options": {"files": files},
        }))
        .expect("valid input")
    }

    fn version_texts(major: u64, files: Value) -> Vec<String> {
        let output = versions(&input(major, None, files), &pages()).expect("listed");

        output["versions"]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v["text"].as_str().expect("text").to_owned())
            .collect()
    }

    fn names(major: u64, version: &str, files: Value) -> Vec<String> {
        let output = metadata(&input(major, Some(version), files), &pages()).expect("listed");

        output["files"]
            .as_array()
            .expect("array")
            .iter()
            .map(|f| f["name"].as_str().expect("name").to_owned())
            .collect()
    }

    #[test]
    fn al2023_only_not_listed() {
        let texts = version_texts(25, Value::Null);

        assert!(texts.contains(&"25.0.4.10.1".to_owned()));
        assert!(!texts.contains(&"25.0.4.11.1".to_owned()));
    }

    #[test]
    fn partial_release_carries_forward() {
        let windows = json!(["*-windows-x64-jdk.zip"]);

        let carried = names(25, "25.0.1.9.1", windows.clone());

        assert_eq!(
            carried,
            vec!["amazon-corretto-25.0.1.8.1-windows-x64-jdk.zip"]
        );
    }

    #[test]
    fn own_platform_wins() {
        let linux = json!(["amazon-corretto-*.?-linux-x64.tar.gz"]);

        assert_eq!(
            names(25, "25.0.1.9.1", linux),
            vec!["amazon-corretto-25.0.1.9.1-linux-x64.tar.gz"]
        );
    }

    #[test]
    fn next_update_carries_nothing() {
        // 8.402.07.1 is Linux-only and carries 8.402.06.1's Windows build;
        // 8.412 is another update and lists its own.
        let windows = json!(["*-windows-x64-jdk.zip"]);

        assert_eq!(
            names(8, "8.402.07.1", windows.clone()),
            vec!["amazon-corretto-8.402.06.1-windows-x64-jdk.zip"]
        );
        assert_eq!(
            names(8, "8.412.08.1", windows),
            vec!["amazon-corretto-8.412.08.1-windows-x64-jdk.zip"]
        );
    }

    #[test]
    fn digests_and_signature() {
        let output = metadata(
            &input(25, Some("25.0.5.0.10"), json!(["*-linux-x64.tar.gz*"])),
            &pages(),
        )
        .expect("listed");
        let files = output["files"].as_array().expect("array");

        assert_eq!(
            files[0]["name"],
            "amazon-corretto-25.0.5.0.10-linux-x64.tar.gz"
        );
        assert_eq!(
            files[0]["url"],
            "https://corretto.aws/downloads/resources/25.0.5.0.10/amazon-corretto-25.0.5.0.10-linux-x64.tar.gz"
        );
        assert_eq!(
            files[0]["digests"][0],
            json!({"algorithm": "sha256", "hex": "1d89b4194f20ee513f4dd9fc2aadd038de3c713c37fd444d77566b3da7b0ee65"})
        );
        assert_eq!(files[0]["digests"][1]["algorithm"], "md5");
        assert_eq!(
            files[1]["name"],
            "amazon-corretto-25.0.5.0.10-linux-x64.tar.gz.sig"
        );
        assert!(files[1].get("digests").is_none());
        assert!(output["published"].is_string());
    }

    #[test]
    fn md5_only_release() {
        let output =
            metadata(&input(8, Some("8.232.09.1"), Value::Null), &pages()).expect("listed");
        let file = &output["files"][0];

        assert!(
            file["url"]
                .as_str()
                .expect("url")
                .contains("cloudfront.net")
        );
        assert_eq!(
            file["digests"],
            json!([{"algorithm": "md5", "hex": "88ea4a5a1dbdf8b11437cf945552f14c"}])
        );
    }

    #[test]
    fn respin_and_preview() {
        let output = versions(&input(11, None, Value::Null), &pages()).expect("listed");
        let release_of = |text: &str| {
            output["versions"]
                .as_array()
                .expect("array")
                .iter()
                .find(|v| v["text"] == text)
                .map(|v| v["release"].clone())
        };

        assert_eq!(release_of("11.0.6.10.1-1"), Some("general".into()));
        assert_eq!(
            release_of("preview-11.0.15.2.1"),
            Some("pre-release".into())
        );
    }

    #[test]
    fn filter_drops_releases_without_matches() {
        // Early Corretto 8 releases had no Alpine build at all.
        let alpine = version_texts(8, json!(["*-alpine-linux-x64.tar.gz"]));

        assert!(!alpine.contains(&"8.232.09.1".to_owned()));
        assert!(alpine.contains(&"8.262.10.2".to_owned()));
    }

    /// The carry key must tell every row of one release apart, or a
    /// carried platform would be dropped as already present.
    #[test]
    fn platform_keys_unique() {
        for major in [8, 11, 25] {
            for listed in catalog(&input(major, None, Value::Null), &pages()).expect("listed") {
                let keys: BTreeSet<_> = listed.rows.iter().map(platform).collect();

                assert_eq!(keys.len(), listed.rows.len(), "{}", listed.text);
            }
        }
    }

    #[test]
    fn other_artifact_not_found() {
        let input: Input = serde_json::from_value(
            json!({"artifact": {"name": "temurin-25"}, "base-url": BASE, "options": {}}),
        )
        .expect("valid input");

        let failure = versions(&input, &pages()).expect_err("refused");

        assert_eq!(failure.code, ARTIFACT_NOT_FOUND);
    }

    #[test]
    fn missing_release_not_found() {
        let failure =
            metadata(&input(25, Some("25.0.4.11.1"), Value::Null), &pages()).expect_err("absent");

        assert_eq!(failure.code, ARTIFACT_NOT_FOUND);
    }
}
