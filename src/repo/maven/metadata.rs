//! Reading `maven-metadata.xml`.
//!
//! The repository's index of what it holds under one coordinate, and the
//! only way to learn which versions exist -- Maven has no version endpoint.
//!
//! A format reader beside the source that fetches it, in the same shape as
//! [`super::pom`]: both are document formats, both are built on the generic
//! tree in [`super::xml`], and neither belongs inside the adapter that
//! happens to request them.
//!
//! What this document is *not* is part of an artifact. It belongs to the
//! repository, is rewritten whenever anything is published under the same
//! coordinate, and a target generates its own on upload -- see the module
//! documentation on [`super`].
//!
//! It is also *written* here, for a target configured to maintain its own
//! index -- see [`merge_versions`] and [`render_snapshot`].
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use chrono::{DateTime, Utc};
use quick_xml::escape::escape;

use super::xml;
use crate::model::Version;
use crate::version::{MavenVersions, VersionHandler};

/// Read `versioning/versions/version` out of a `maven-metadata.xml`.
///
/// `<latest>` and `<release>` are **ignored**. Both are routinely stale --
/// they are written by whichever tool published last and are not corrected
/// when a version is removed -- and Maven's own resolver ignores them too.
/// The version list is the fact; those two are a claim.
pub(super) fn parse_version_list(document: &str) -> Result<Vec<String>, String> {
    let root = metadata_root(document)?;

    let Some(versions) = root.at(&["versioning", "versions"]) else {
        // A metadata file with no versions block is well-formed and means
        // the coordinate has nothing published under it.
        return Ok(Vec::new());
    };

    Ok(versions
        .children("version")
        .map(|node| node.text.clone())
        .filter(|text| !text.is_empty())
        .collect())
}

/// The versions an artifact directory's `maven-metadata.xml` lists, or
/// `None` when the document belongs to another kind of directory.
///
/// Three directories hold one, and only the first names itself:
///
/// ```text
///   org/example/lib/              <artifactId>lib</artifactId>
///   org/example/lib/1.0-SNAPSHOT/ <artifactId>lib</artifactId>, not the directory
///   org/example/                  a plugin group's <plugins>, no <artifactId>
/// ```
///
/// A top-level `<version>` decides nothing: Maven 2 wrote one into
/// artifact directories too.
pub(super) fn parse_artifact_index(
    document: &str,
    artifact: &str,
) -> Result<Option<Vec<String>>, String> {
    let root = metadata_root(document)?;

    if root.text_of("artifactId") != Some(artifact) {
        return Ok(None);
    }

    parse_version_list(document).map(Some)
}

/// The suffix every snapshot version carries.
pub(super) const SNAPSHOT_SUFFIX: &str = "-SNAPSHOT";

/// `lastUpdated`, as Maven writes it.
const LAST_UPDATED_FORMAT: &str = "%Y%m%d%H%M%S";

/// The element `merge_versions` replaces.
const VERSIONING: &str = "versioning";

/// Where a missing `<versioning>` goes.
const METADATA_CLOSE: &str = "</metadata>";

/// A snapshot build's timestamp, as Maven writes it: `20240101.123456`.
const SNAPSHOT_TIMESTAMP_FORMAT: &str = "%Y%m%d.%H%M%S";

/// How long [`SNAPSHOT_TIMESTAMP_FORMAT`] renders.
const SNAPSHOT_TIMESTAMP_LEN: usize = 15;

/// Whether a version is a snapshot, which Maven decides by its spelling.
pub(super) fn is_snapshot(version: &str) -> bool {
    version.ends_with(SNAPSHOT_SUFFIX)
}

/// One file of a snapshot build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SnapshotFile {
    pub classifier: Option<String>,
    pub extension: String,

    /// The version as the file name spells it: `2.0-20240101.123456-3`.
    pub value: String,
}

/// What a snapshot version directory's `maven-metadata.xml` says about
/// its latest build.
///
/// Only the latest: the document names no other, and the Maven layout
/// offers no listing that would. Older builds stay where they are.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Snapshot {
    /// `20240101.123456-3`, when the build is timestamped at all. A
    /// `localCopy` snapshot is not, and its files carry the literal
    /// `-SNAPSHOT` name.
    pub build: Option<String>,

    pub files: Vec<SnapshotFile>,
}

impl Snapshot {
    /// The version one file of this build is named with.
    ///
    /// The `snapshotVersions` entry when there is one, since a build's
    /// files need not share a timestamp. The `<snapshot>` element's build
    /// otherwise, which is how Maven 2 wrote it. The literal version last:
    /// a non-unique snapshot names its files `lib-2.0-SNAPSHOT.jar`.
    pub fn value_for(&self, version: &str, classifier: Option<&str>, extension: &str) -> String {
        let listed = self
            .files
            .iter()
            .find(|file| file.classifier.as_deref() == classifier && file.extension == extension);

        if let Some(file) = listed {
            return file.value.clone();
        }

        match &self.build {
            Some(build) => format!("{}-{build}", snapshot_base(version)),
            None => version.to_owned(),
        }
    }
}

/// `2.0-SNAPSHOT` becomes `2.0`.
fn snapshot_base(version: &str) -> &str {
    version.strip_suffix(SNAPSHOT_SUFFIX).unwrap_or(version)
}

/// Read a snapshot version directory's `maven-metadata.xml`.
pub(super) fn parse_snapshot(document: &str) -> Result<Snapshot, String> {
    let root = metadata_root(document)?;

    let Some(versioning) = root.child("versioning") else {
        return Ok(Snapshot::default());
    };

    let build = versioning.child("snapshot").and_then(|snapshot| {
        if snapshot.text_of("localCopy") == Some("true") {
            return None;
        }

        let timestamp = snapshot.text_of("timestamp")?;
        let number = snapshot.text_of("buildNumber")?;

        Some(format!("{timestamp}-{number}"))
    });

    let files = versioning
        .at(&["snapshotVersions"])
        .map(|listed| {
            listed
                .children("snapshotVersion")
                .filter_map(|entry| {
                    Some(SnapshotFile {
                        classifier: entry.text_of("classifier").map(str::to_owned),
                        extension: entry.text_of("extension")?.to_owned(),
                        value: entry.text_of("value")?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Snapshot { build, files })
}

/// The root of a document that must be `<metadata>`.
fn metadata_root(document: &str) -> Result<xml::Node, String> {
    let root = xml::parse(document)?;

    if root.name != "metadata" {
        return Err(format!(
            "the root element is <{}>, not <metadata>",
            root.name
        ));
    }

    Ok(root)
}

/// An artifact directory's `maven-metadata.xml`, with one more version.
///
/// **Only `<versioning>` is replaced**: the rest of `existing` stays as it
/// was, byte for byte, so a plugin prefix, a vendor extension, or an
/// attribute the tree reader drops survives. The result is read back and
/// must list exactly the versions written, so a document the splice could
/// not follow is refused rather than written half-edited.
///
/// `<latest>` and `<release>` are set to the highest version by Maven's
/// ordering, `<release>` over non-snapshots only. That is what an index
/// rebuilt from the directory would say, and it does not depend on the
/// order a copy happened to publish in.
pub(super) fn merge_versions(
    existing: Option<&str>,
    group: &str,
    artifact: &str,
    version: &str,
    now: DateTime<Utc>,
) -> Result<String, String> {
    let mut listed = match existing {
        Some(document) => parse_version_list(document)?,
        None => Vec::new(),
    };

    if !listed.iter().any(|held| held == version) {
        listed.push(version.to_owned());
    }

    let mut ordered = MavenVersions.classify(&listed);
    MavenVersions.sort(&mut ordered);

    let block = versioning(&ordered, now);

    let spliced = existing.and_then(|document| splice_versioning(document, &block));

    let Some(spliced) = spliced else {
        let mut out = document_head(group, artifact);
        out.push_str(&format!("  {block}\n</metadata>\n"));

        return Ok(out);
    };

    let written: Vec<&str> = ordered.iter().map(Version::text).collect();

    if parse_version_list(&spliced)? != written {
        return Err("the document's <versioning> element could not be replaced cleanly".to_owned());
    }

    Ok(spliced)
}

/// The `<versioning>` element for `ordered`, lowest first, unindented on
/// its first line so it can stand where the old one stood.
fn versioning(ordered: &[Version], now: DateTime<Utc>) -> String {
    let latest = ordered.last().map(Version::text);
    let release = ordered
        .iter()
        .rev()
        .map(Version::text)
        .find(|text| !is_snapshot(text));

    let mut out = String::from("<versioning>\n");

    if let Some(latest) = latest {
        out.push_str(&element(4, "latest", latest));
    }

    if let Some(release) = release {
        out.push_str(&element(4, "release", release));
    }

    out.push_str("    <versions>\n");

    for held in ordered {
        out.push_str(&element(6, "version", held.text()));
    }

    out.push_str("    </versions>\n");
    out.push_str(&element(
        4,
        "lastUpdated",
        &now.format(LAST_UPDATED_FORMAT).to_string(),
    ));
    out.push_str("  </versioning>");

    out
}

/// `document` with its `<versioning>` element replaced by `block`, or
/// `block` added before `</metadata>` when it has none.
///
/// `None` when there is nowhere to put it -- a self-closing `<metadata/>`
/// -- and the document is rendered afresh instead, losing nothing.
///
/// ```text
///   <metadata>                 <metadata>
///     <groupId>g</groupId>       <groupId>g</groupId>
///     <versioning>...     ->     <versioning>(block)
///     </versioning>              </versioning>
///     <plugins>...               <plugins>...
/// ```
fn splice_versioning(document: &str, block: &str) -> Option<String> {
    let Some(start) = element_start(document, VERSIONING) else {
        let at = document.rfind(METADATA_CLOSE)?;

        return Some(format!("{}  {block}\n{}", &document[..at], &document[at..]));
    };

    let open_end = start + document[start..].find('>')? + 1;

    let end = match document[..open_end].ends_with("/>") {
        true => open_end,
        false => {
            let close = format!("</{VERSIONING}>");

            open_end + document[open_end..].find(&close)? + close.len()
        }
    };

    Some(format!("{}{block}{}", &document[..start], &document[end..]))
}

/// Where the first `<{name}` tag opens: the name followed by `>`, `/`, or
/// whitespace, so `<versioningX>` is not taken for it.
fn element_start(document: &str, name: &str) -> Option<usize> {
    let tag = format!("<{name}");

    document.match_indices(&tag).map(|(at, _)| at).find(|at| {
        document[at + tag.len()..]
            .chars()
            .next()
            .is_some_and(|next| next == '>' || next == '/' || next.is_whitespace())
    })
}

/// A snapshot version directory's `maven-metadata.xml`, from the names of
/// the files published, signatures excluded.
///
/// Several builds may arrive at once, from a catalog listing every one.
/// The document names the newest build of each file, and the newest build
/// overall as `<snapshot>`: what Maven would have written after publishing
/// them in order.
///
/// `None` when no file name carries a build timestamp: a non-unique
/// snapshot has nothing to index, and a document claiming a build would
/// point every consumer at files that do not exist.
///
/// ```text
///   lib-2.0-20240101.123456-3.jar          -> (none,    jar)
///   lib-2.0-20240101.123456-3-sources.jar  -> (sources, jar)
/// ```
pub(super) fn render_snapshot(
    group: &str,
    artifact: &str,
    version: &str,
    names: &[&str],
    now: DateTime<Utc>,
) -> Option<String> {
    let prefix = format!("{artifact}-{}-", snapshot_base(version));
    let mut built: Vec<(String, SnapshotFile)> = Vec::new();

    for (build, file) in names
        .iter()
        .filter_map(|name| build_of(name.strip_prefix(&prefix)?, snapshot_base(version)))
    {
        let held = built.iter_mut().find(|(_, held)| {
            held.classifier == file.classifier && held.extension == file.extension
        });

        match held {
            Some(entry) if build_order(&build) > build_order(&entry.0) => *entry = (build, file),
            Some(_) => {}
            None => built.push((build, file)),
        }
    }

    let (build, _) = built.iter().max_by_key(|(build, _)| build_order(build))?;
    let (timestamp, number) = build.split_once('-')?;
    let updated = now.format(LAST_UPDATED_FORMAT).to_string();

    let mut out = document_head(group, artifact);
    out.push_str(&element(2, "version", version));
    out.push_str("  <versioning>\n    <snapshot>\n");
    out.push_str(&element(6, "timestamp", timestamp));
    out.push_str(&element(6, "buildNumber", number));
    out.push_str("    </snapshot>\n");
    out.push_str(&element(4, "lastUpdated", &updated));
    out.push_str("    <snapshotVersions>\n");

    for (_, file) in &built {
        out.push_str("      <snapshotVersion>\n");

        if let Some(classifier) = &file.classifier {
            out.push_str(&element(8, "classifier", classifier));
        }

        out.push_str(&element(8, "extension", &file.extension));
        out.push_str(&element(8, "value", &file.value));
        out.push_str(&element(8, "updated", &updated));
        out.push_str("      </snapshotVersion>\n");
    }

    out.push_str("    </snapshotVersions>\n  </versioning>\n</metadata>\n");

    Some(out)
}

/// How builds order: by timestamp, then by build number as a number, so
/// build `-10` follows `-9`.
fn build_order(build: &str) -> (&str, u64) {
    let (timestamp, number) = build.split_once('-').unwrap_or((build, ""));

    (timestamp, number.parse().unwrap_or(0))
}

/// Read one snapshot file name, after `{artifact}-{base}-`.
///
/// `20240101.123456-3-sources.jar` is build `20240101.123456-3`,
/// classifier `sources`, extension `jar`. A classifier carries no `.`, so
/// the extension is everything after the first one past the build and may
/// itself hold several: `tar.gz`.
fn build_of(rest: &str, base: &str) -> Option<(String, SnapshotFile)> {
    let timestamp = rest.get(..SNAPSHOT_TIMESTAMP_LEN)?;

    if chrono::NaiveDateTime::parse_from_str(timestamp, SNAPSHOT_TIMESTAMP_FORMAT).is_err() {
        return None;
    }

    let after = rest[SNAPSHOT_TIMESTAMP_LEN..].strip_prefix('-')?;
    let digits = after.chars().take_while(char::is_ascii_digit).count();

    if digits == 0 {
        return None;
    }

    let (number, tail) = after.split_at(digits);
    let build = format!("{timestamp}-{number}");

    let (classifier, extension) = match tail.strip_prefix('-') {
        Some(classified) => {
            let (classifier, extension) = classified.split_once('.')?;
            (Some(classifier.to_owned()), extension)
        }

        None => (None, tail.strip_prefix('.')?),
    };

    if extension.is_empty() {
        return None;
    }

    let file = SnapshotFile {
        classifier,
        extension: extension.to_owned(),
        value: format!("{base}-{build}"),
    };

    Some((build, file))
}

/// The declaration and the coordinate every metadata document opens with.
fn document_head(group: &str, artifact: &str) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n");
    out.push_str(&element(2, "groupId", group));
    out.push_str(&element(2, "artifactId", artifact));

    out
}

/// One indented text element, escaped.
fn element(indent: usize, name: &str, text: &str) -> String {
    format!("{:indent$}<{name}>{}</{name}>\n", "", escape(text))
}

/// A realistic document, shared with the source's own tests.
///
/// Deliberately one copy: the source serves it as an HTTP fixture while the
/// tests below parse it directly, and two samples that drifted apart would
/// let one of those pass against a document the other never sees.
///
/// `<latest>` names a version that is **not** in the list, which is the
/// whole point -- see [`parse_version_list`].
#[cfg(test)]
pub(super) const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
        <metadata>
          <groupId>org.example</groupId>
          <artifactId>lib</artifactId>
          <versioning>
            <latest>9.9.9-SNAPSHOT</latest>
            <release>1.0</release>
            <versions>
              <version>1.0</version>
              <version>1.10</version>
              <version>1.9</version>
              <version>2.0-SNAPSHOT</version>
            </versions>
            <lastUpdated>20240101000000</lastUpdated>
          </versioning>
        </metadata>"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// `<latest>` here says `9.9.9-SNAPSHOT`, which is not in the version
    /// list at all. Trusting it would resolve to an artifact the
    /// repository does not hold -- which is exactly why Maven's own
    /// resolver ignores it too.
    #[test]
    fn versions_ignore_latest_and_release() {
        let listed = parse_version_list(SAMPLE).expect("parsed");

        assert!(!listed.iter().any(|version| version.contains("9.9.9")));
        assert_eq!(listed.len(), 4);
    }

    /// The order in the file is not the order to resolve in -- `1.10` is
    /// listed before `1.9` -- so the reader preserves it and leaves sorting
    /// to the ecosystem.
    #[test]
    fn versions_listed_order_preserved() {
        let listed = parse_version_list(SAMPLE).expect("parsed");

        assert_eq!(listed, ["1.0", "1.10", "1.9", "2.0-SNAPSHOT"]);
    }

    #[test]
    fn versions_none_is_empty_not_error() {
        let listed = parse_version_list("<metadata><versioning/></metadata>").expect("parsed");

        assert!(listed.is_empty());
    }

    #[test]
    fn document_not_metadata_refused() {
        assert!(parse_version_list("<project><artifactId>a</artifactId></project>").is_err());
    }

    /// An empty `<version/>` names nothing, and an empty coordinate would
    /// 404 later in a way that looks like a missing artifact.
    #[test]
    fn versions_empty_elements_dropped() {
        let listed = parse_version_list(
            "<metadata><versioning><versions>
               <version>1.0</version><version></version><version/>
             </versions></versioning></metadata>",
        )
        .expect("parsed");

        assert_eq!(listed, ["1.0"]);
    }
    fn noon() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2024-01-01T12:34:56Z")
            .expect("valid")
            .with_timezone(&Utc)
    }

    const SNAPSHOT_SAMPLE: &str = r#"<metadata>
          <groupId>org.example</groupId><artifactId>lib</artifactId>
          <version>2.0-SNAPSHOT</version>
          <versioning>
            <snapshot><timestamp>20240101.123456</timestamp><buildNumber>3</buildNumber></snapshot>
            <snapshotVersions>
              <snapshotVersion>
                <extension>jar</extension><value>2.0-20240101.123456-3</value>
              </snapshotVersion>
              <snapshotVersion>
                <classifier>sources</classifier><extension>jar</extension>
                <value>2.0-20240101.123400-2</value>
              </snapshotVersion>
            </snapshotVersions>
          </versioning>
        </metadata>"#;

    /// Each file of a build may carry its own timestamp, so the listed
    /// entry wins over the `<snapshot>` element.
    #[test]
    fn snapshot_value_prefers_listed_entry() {
        let snapshot = parse_snapshot(SNAPSHOT_SAMPLE).expect("parsed");

        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", None, "jar"),
            "2.0-20240101.123456-3"
        );
        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", Some("sources"), "jar"),
            "2.0-20240101.123400-2"
        );

        // Not listed: the build from `<snapshot>`.
        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", None, "pom"),
            "2.0-20240101.123456-3"
        );
    }

    /// A `localCopy` snapshot names its files with the literal version.
    #[test]
    fn snapshot_local_copy_keeps_literal_name() {
        let snapshot = parse_snapshot(
            "<metadata><versioning><snapshot><localCopy>true</localCopy></snapshot>\
             </versioning></metadata>",
        )
        .expect("parsed");

        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", None, "jar"),
            "2.0-SNAPSHOT"
        );
    }

    #[test]
    fn merge_adds_version_and_orders() {
        let merged =
            merge_versions(Some(SAMPLE), "org.example", "lib", "1.2", noon()).expect("merged");
        let listed = parse_version_list(&merged).expect("parsed");

        assert_eq!(listed, ["1.0", "1.2", "1.9", "1.10", "2.0-SNAPSHOT"]);
        assert!(merged.contains("<latest>2.0-SNAPSHOT</latest>"));
        assert!(merged.contains("<release>1.10</release>"));
        assert!(merged.contains("<lastUpdated>20240101123456</lastUpdated>"));
    }

    /// Everything outside `<versioning>` survives, attributes included.
    #[test]
    fn merge_keeps_other_elements() {
        let existing = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata modelVersion="1.1.0">
  <!-- written by hand -->
  <groupId>org.example</groupId>
  <artifactId>lib</artifactId>
  <versioning>
    <versions><version>1.0</version></versions>
  </versioning>
  <plugins><plugin><prefix>ex</prefix></plugin></plugins>
</metadata>
"#;

        let merged =
            merge_versions(Some(existing), "org.example", "lib", "2.0", noon()).expect("merged");

        assert_eq!(parse_version_list(&merged).expect("parsed"), ["1.0", "2.0"]);
        assert!(
            merged.contains(r#"<metadata modelVersion="1.1.0">"#),
            "{merged}"
        );
        assert!(merged.contains("<!-- written by hand -->"), "{merged}");
        assert!(merged.contains("<plugins><plugin><prefix>ex</prefix></plugin></plugins>"));
        assert!(merged.contains("<release>2.0</release>"));
    }

    /// A document with no `<versioning>` gains one; so does one whose
    /// element is empty.
    #[test]
    fn merge_adds_missing_versioning() {
        for existing in [
            "<metadata><groupId>g</groupId><plugins/></metadata>",
            "<metadata><groupId>g</groupId><versioning/><plugins/></metadata>",
        ] {
            let merged = merge_versions(Some(existing), "g", "a", "1.0", noon()).expect("merged");

            assert_eq!(
                parse_version_list(&merged).expect("parsed"),
                ["1.0"],
                "{existing}"
            );
            assert!(merged.contains("<plugins/>"), "{merged}");
        }
    }

    /// A tag in a comment misleads the splice; the result does not read
    /// back as written, so it is refused rather than stored.
    #[test]
    fn merge_refuses_unfollowable_document() {
        let existing = "<metadata><!-- <versioning> --><versioning><versions>\
                        <version>1.0</version></versions></versioning></metadata>";

        assert!(merge_versions(Some(existing), "g", "a", "2.0", noon()).is_err());
    }

    /// No index yet: the document is created with the one version.
    #[test]
    fn merge_creates_missing_document() {
        let merged = merge_versions(None, "org.example", "lib", "1.0", noon()).expect("merged");

        assert_eq!(parse_version_list(&merged).expect("parsed"), ["1.0"]);
        assert!(merged.contains("<groupId>org.example</groupId>"));
    }

    /// A version already listed is not listed twice.
    #[test]
    fn merge_keeps_versions_unique() {
        let merged =
            merge_versions(Some(SAMPLE), "org.example", "lib", "1.0", noon()).expect("merged");

        assert_eq!(parse_version_list(&merged).expect("parsed").len(), 4);
    }

    /// Text is escaped, so a coordinate cannot inject markup.
    #[test]
    fn merge_escapes_text() {
        let merged = merge_versions(None, "a&b", "lib", "1.0", noon()).expect("merged");

        assert!(merged.contains("<groupId>a&amp;b</groupId>"));
    }

    #[test]
    fn merge_refuses_unreadable_document() {
        assert!(merge_versions(Some("<project/>"), "g", "a", "1.0", noon()).is_err());
    }

    /// The rendered document reads back as the build it was made from.
    #[test]
    fn snapshot_render_round_trips() {
        let names = [
            "lib-2.0-20240101.123456-3.pom",
            "lib-2.0-20240101.123456-3.jar",
            "lib-2.0-20240101.123456-3-sources.jar",
            "lib-2.0-20240101.123456-3.tar.gz",
        ];

        let rendered = render_snapshot("org.example", "lib", "2.0-SNAPSHOT", &names, noon())
            .expect("rendered");
        let snapshot = parse_snapshot(&rendered).expect("parsed");

        assert_eq!(snapshot.build.as_deref(), Some("20240101.123456-3"));
        assert_eq!(snapshot.files.len(), 4);
        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", Some("sources"), "jar"),
            "2.0-20240101.123456-3"
        );
        assert!(snapshot.files.iter().any(|file| file.extension == "tar.gz"));
    }

    /// Several builds name the newest of each file, and the newest build
    /// overall, whatever order they arrive in.
    #[test]
    fn snapshot_render_keeps_newest_build() {
        let names = [
            "lib-2.0-20240102.000000-10.jar",
            "lib-2.0-20240101.123456-9.jar",
            "lib-2.0-20240101.123456-9.pom",
            "lib-2.0-20240102.000000-10.pom",
            "lib-2.0-20240101.123456-9-sources.jar",
        ];

        let rendered = render_snapshot("org.example", "lib", "2.0-SNAPSHOT", &names, noon())
            .expect("rendered");
        let snapshot = parse_snapshot(&rendered).expect("parsed");

        assert_eq!(snapshot.build.as_deref(), Some("20240102.000000-10"));
        assert_eq!(snapshot.files.len(), 3);
        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", None, "jar"),
            "2.0-20240102.000000-10"
        );
        assert_eq!(
            snapshot.value_for("2.0-SNAPSHOT", Some("sources"), "jar"),
            "2.0-20240101.123456-9"
        );
    }

    /// A non-unique snapshot has no build to index.
    #[test]
    fn snapshot_render_skips_non_unique() {
        let names = ["lib-2.0-SNAPSHOT.pom", "lib-2.0-SNAPSHOT.jar"];

        assert!(render_snapshot("org.example", "lib", "2.0-SNAPSHOT", &names, noon()).is_none());
    }
}
