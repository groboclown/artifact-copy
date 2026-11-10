//! What the Nexus components endpoint returns, and nothing else.
//!
//! These types exist to be the shape `serde` reads. They are kept apart
//! from the enumerator so that a change to the wire format -- Nexus adding a
//! field, or an older server omitting one -- is a change to this file only,
//! and so that reading the enumerator does not mean reading a hundred lines of
//! field declarations first.
//!
//! [`Component::last_download`] is here rather than in the enumerator because
//! it is a property of the document: it answers what this page said, not
//! what the tool should do about it.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

use crate::model::{Digest, DigestAlg, LastDownload};
use crate::repo::enumerate::Listed;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ComponentPage {
    #[serde(default)]
    pub(super) items: Vec<Component>,

    #[serde(default)]
    pub(super) continuation_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Component {
    #[serde(default)]
    pub(super) format: Option<String>,

    #[serde(default)]
    pub(super) group: Option<String>,

    pub(super) name: String,

    #[serde(default)]
    pub(super) version: Option<String>,

    #[serde(default)]
    assets: Vec<Asset>,
}

impl Component {
    /// Where this component's files sit in the repository.
    ///
    /// For the raw format this is the coordinate: a raw component holds
    /// exactly one asset, and its path is what a `Mapping` reads. The
    /// component's own `name` carries the same string today and `group`
    /// carries its directory, but both are Nexus's grouping rules rather
    /// than the repository's layout -- deriving from the path keeps the
    /// mapping shared with an Artifactory reader, and keeps a change to how
    /// Nexus fills `group` from silently moving an artifact.
    pub(super) fn paths(&self) -> impl Iterator<Item = &str> {
        self.assets.iter().filter_map(|asset| asset.path.as_deref())
    }

    /// The component split into one per asset.
    ///
    /// A raw-format component holds one asset, and any other format's
    /// several: read as raw, each path is its own coordinate, so a Maven
    /// component's jar and its `-sources.jar` are each read by the mapping.
    pub(super) fn per_asset(&self) -> Vec<Component> {
        self.assets
            .iter()
            .map(|asset| Component {
                assets: vec![asset.clone()],
                ..self.clone()
            })
            .collect()
    }

    /// Every asset as a listed file, named by its path's last segment.
    ///
    /// Unfiltered: which of them belong to the artifact is the
    /// ecosystem's call, not the document's. An asset without a path or a
    /// download URL cannot be copied and is left out.
    pub(super) fn listed(&self) -> Vec<Listed> {
        self.assets
            .iter()
            .filter_map(|asset| {
                let path = asset.path.as_deref()?;
                let name = path.rsplit('/').next().filter(|name| !name.is_empty())?;

                Some(Listed {
                    name: name.to_owned(),
                    url: asset.download_url.clone()?,
                    // Nexus reports 0 when its index lacks the size;
                    // undeclared rather than trusted, as in the raw source.
                    size: asset.file_size.filter(|&size| size > 0),
                    digests: asset.digests(),
                })
            })
            .collect()
    }

    /// When this component was last served, across all of its assets.
    ///
    /// A component is several files -- a jar, a POM, their checksums -- and
    /// downloading any of them is using the artifact, so the most recent
    /// wins.
    pub(super) fn last_download(&self) -> LastDownload {
        let mut latest: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut tracked = false;

        for asset in &self.assets {
            match &asset.last_downloaded {
                // The field was absent: this server does not report it.
                None => continue,

                // The field was present. Either way Nexus is tracking.
                Some(reported) => {
                    tracked = true;

                    if let Some(stamp) = reported
                        .as_deref()
                        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
                    {
                        let stamp = stamp.with_timezone(&chrono::Utc);
                        latest = Some(latest.map_or(stamp, |current| current.max(stamp)));
                    }
                }
            }
        }

        match (latest, tracked) {
            (Some(when), _) => LastDownload::At(when),

            // Tracked, and nothing has ever been served.
            (None, true) => LastDownload::Never,

            // Nothing said anything. Not evidence of disuse.
            (None, false) => LastDownload::Unknown,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Asset {
    /// Where the file sits in the repository.
    ///
    /// Read for the raw format, whose coordinate *is* the path. Every other
    /// format takes its coordinate from the component's `group` and `name`,
    /// so this is the one field an enumerator needs off an asset besides the
    /// download time.
    path: Option<String>,

    /// Absent, explicitly null, or a timestamp -- and all three are
    /// different answers.
    ///
    /// The doubled `Option` is what keeps them apart: a missing key and an
    /// explicit `null` would otherwise collapse into the same `None`.
    /// Absent means the server does not report downloads; `null` means it
    /// does and there have been none. A retention tool that confused the
    /// two would delete things people are using.
    last_downloaded: Option<Option<String>>,

    /// Where the file is fetched from, as the server spells it.
    download_url: Option<String>,

    /// Absent on servers too old to report it.
    file_size: Option<u64>,

    /// Algorithm name to hex, as Nexus reports them: `sha1`, `sha256`,
    /// `sha512`, `md5`.
    checksum: BTreeMap<String, String>,
}

impl Asset {
    /// The checksums this build knows the algorithm of. An unknown name is
    /// dropped rather than guessed at, because something would check
    /// against it.
    fn digests(&self) -> Vec<Digest> {
        self.checksum
            .iter()
            .filter_map(|(name, hex)| Some(Digest::new(DigestAlg::parse(name)?, hex.clone())))
            .collect()
    }
}

/// Read one asset, tolerating a **repeated** `lastDownloaded`.
///
/// Nexus really does emit the field twice on one asset -- `null` first, then
/// the real timestamp:
///
/// ```text
///   "lastDownloaded" : null,
///   "uploader" : "admin",
///   ...
///   "lastDownloaded" : "2026-09-10T04:42:28.414+00:00",
/// ```
///
/// A derived `Deserialize` refuses that outright with *duplicate field
/// `lastDownloaded`*, which fails the whole page and so the whole walk. A
/// catalog enumerator cannot be that brittle about a server it does not
/// control, so this is hand-written to fold the repeats instead.
///
/// **The most recent observation wins**, which is not "the last one wins".
/// It is the same rule [`Component::last_download`] already applies *across*
/// an artifact's assets -- downloading any file is using the artifact, so the
/// latest use counts -- and a repeated field is just another observation of
/// the same thing. Order-independent, so a server that emitted the
/// timestamp first and the `null` second would still be read correctly,
/// where last-wins would silently throw the timestamp away.
///
/// Duplicates of *other* fields are still refused. This one is a quirk that
/// has been seen; a duplicate `name` has not, and failing loudly on
/// something unexplained beats silently picking one of two values.
impl<'de> Deserialize<'de> for Asset {
    fn deserialize<D: Deserializer<'de>>(input: D) -> std::result::Result<Self, D::Error> {
        struct Fields;

        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = Asset;

            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("a Nexus asset")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Asset, M::Error> {
                let mut last_downloaded: Option<Option<String>> = None;
                let mut path: Option<String> = None;
                let mut download_url: Option<String> = None;
                let mut file_size: Option<u64> = None;
                let mut checksum: BTreeMap<String, String> = BTreeMap::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "lastDownloaded" => {
                            let seen = map.next_value::<Option<String>>()?;

                            last_downloaded = Some(match last_downloaded {
                                Some(before) => later_of(before, seen),
                                None => seen,
                            });
                        }

                        // A repeat would be the same quirk in a second
                        // field, which has not been seen. First wins rather
                        // than last, so a page that did repeat it reads the
                        // same either way.
                        "path" => {
                            let seen = map.next_value::<Option<String>>()?;

                            path = path.or(seen);
                        }

                        // First wins, for the same reason as `path`.
                        "downloadUrl" => {
                            let seen = map.next_value::<Option<String>>()?;

                            download_url = download_url.or(seen);
                        }

                        "fileSize" => {
                            let seen = map.next_value::<Option<u64>>()?;

                            file_size = file_size.or(seen);
                        }

                        // Values that are not strings are skipped rather
                        // than failing the page: a checksum is optional to
                        // a walk, and the page is not.
                        "checksum" => {
                            let seen = map
                                .next_value::<Option<BTreeMap<String, serde_json::Value>>>()?
                                .unwrap_or_default();

                            keep_checksums(&mut checksum, seen);
                        }

                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(Asset {
                    path,
                    last_downloaded,
                    download_url,
                    file_size,
                    checksum,
                })
            }
        }

        input.deserialize_map(Fields)
    }
}

/// Keep each of `seen`'s checksums whose value is a string. A name already
/// kept keeps its first value.
fn keep_checksums(
    checksum: &mut BTreeMap<String, String>,
    seen: BTreeMap<String, serde_json::Value>,
) {
    for (name, value) in seen {
        let serde_json::Value::String(hex) = value else {
            continue;
        };

        checksum.entry(name).or_insert(hex);
    }
}

/// The later of two reported download times, `null` meaning "never".
///
/// A real timestamp always beats a `null`: "never downloaded" and "last
/// downloaded on Tuesday" cannot both be true, and only one of them is a
/// reason to keep an artifact. An unparseable string loses to anything that
/// parses, and to nothing else.
fn later_of(before: Option<String>, seen: Option<String>) -> Option<String> {
    let parsed = |text: &Option<String>| {
        text.as_deref()
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
    };

    match (parsed(&before), parsed(&seen)) {
        (Some(left), Some(right)) => match right > left {
            true => seen,
            false => before,
        },

        (Some(_), None) => before,
        (None, Some(_)) => seen,

        // Neither parses. A present-but-unreadable value still says the
        // server tracks downloads, which is what the outer `Some` carries,
        // so either is as good as the other.
        (None, None) => before.or(seen),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed copy of a page a real Nexus 3 served, keeping the shape
    /// that matters: one asset, `lastDownloaded` twice, `null` first.
    const DOUBLED: &str = r#"{
      "items": [
        {
          "id": "abc",
          "repository": "nexus-npm",
          "format": "npm",
          "group": "@ampproject",
          "name": "remapping",
          "version": "2.1.2",
          "assets": [
            {
              "path": "@ampproject/remapping/-/remapping-2.1.2.tgz",
              "lastModified": "2022-08-30T20:40:03.571+00:00",
              "lastDownloaded": null,
              "uploader": "admin",
              "fileSize": 17497,
              "lastDownloaded": "2026-09-10T04:42:28.414+00:00"
            }
          ]
        }
      ],
      "continuationToken": null
    }"#;

    fn parsed(text: &str) -> ComponentPage {
        serde_json::from_str(text).expect("parses")
    }

    /// Nexus emits `lastDownloaded` twice on one asset. A derived
    /// `Deserialize` refuses that outright, which failed the page and so
    /// the whole walk.
    #[test]
    fn last_downloaded_repeated_does_not_fail_page() {
        let page = parsed(DOUBLED);

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name, "remapping");
    }

    /// And the informative observation wins: reporting `Never` for
    /// something downloaded last week is exactly the mistake that gets a
    /// used artifact deleted.
    #[test]
    fn last_downloaded_real_beats_null() {
        let page = parsed(DOUBLED);

        let LastDownload::At(when) = page.items[0].last_download() else {
            panic!(
                "expected a timestamp, got {:?}",
                page.items[0].last_download()
            );
        };

        assert_eq!(when.to_rfc3339(), "2026-09-10T04:42:28.414+00:00");
    }

    /// **Order-independent**, which is the difference between this and
    /// "the last one wins". A server that emitted the timestamp first
    /// would otherwise have it silently replaced by the `null`.
    #[test]
    fn last_downloaded_order_irrelevant() {
        let reversed = DOUBLED
            .replace(
                r#""lastDownloaded": null,"#,
                r#""lastDownloaded": "2026-09-10T04:42:28.414+00:00","#,
            )
            .replace(
                r#""lastDownloaded": "2026-09-10T04:42:28.414+00:00"
            }"#,
                r#""lastDownloaded": null
            }"#,
            );

        assert!(
            reversed.contains(
                r#""lastDownloaded": null
            }"#
            ),
            "the fixture did not reverse"
        );

        let page = parsed(&reversed);

        assert!(
            matches!(page.items[0].last_download(), LastDownload::At(_)),
            "the timestamp was thrown away: {:?}",
            page.items[0].last_download()
        );
    }

    /// Two real timestamps fold to the later, which is the same rule
    /// already applied across an artifact's assets.
    #[test]
    fn last_downloaded_two_fold_to_later() {
        let page = parsed(
            r#"{"items":[{"name":"a","assets":[{
                 "lastDownloaded": "2026-01-01T00:00:00+00:00",
                 "lastDownloaded": "2025-01-01T00:00:00+00:00"
               }]}]}"#,
        );

        let LastDownload::At(when) = page.items[0].last_download() else {
            panic!("expected a timestamp");
        };

        assert_eq!(when.to_rfc3339(), "2026-01-01T00:00:00+00:00");
    }

    /// The three-way distinction survives, because it is what a retention
    /// decision rests on.
    #[test]
    fn last_downloaded_three_states_kept() {
        let absent = parsed(r#"{"items":[{"name":"a","assets":[{"path":"x"}]}]}"#);
        let never = parsed(r#"{"items":[{"name":"a","assets":[{"lastDownloaded":null}]}]}"#);
        let used = parsed(
            r#"{"items":[{"name":"a","assets":[
                 {"lastDownloaded":"2026-01-01T00:00:00+00:00"}]}]}"#,
        );

        assert_eq!(absent.items[0].last_download(), LastDownload::Unknown);
        assert_eq!(never.items[0].last_download(), LastDownload::Never);
        assert!(matches!(used.items[0].last_download(), LastDownload::At(_)));
    }

    /// What a copy needs from each asset: its name, where to fetch it, its
    /// size, and every checksum of a known algorithm.
    #[test]
    fn assets_listed() {
        let page = parsed(
            r#"{"items":[{"name":"echo","assets":[{
                 "path": "example/lib/echo/1.0/echo-1.0-sources.jar",
                 "downloadUrl": "h://nexus.test/repository/m/example/lib/echo/1.0/echo-1.0-sources.jar",
                 "fileSize": 812,
                 "checksum": {"sha1": "aa", "sha256": "bb", "blake3": "cc", "odd": 7}
               }, {
                 "path": "example/lib/echo/1.0/no-url.jar"
               }]}]}"#,
        );

        let listed = page.items[0].listed();
        let [one] = listed.as_slice() else {
            panic!("expected one listed file, got {listed:?}");
        };

        assert_eq!(one.name, "echo-1.0-sources.jar");
        assert!(one.url.ends_with("/echo-1.0-sources.jar"));
        assert_eq!(one.size, Some(812));
        assert_eq!(
            one.digests,
            [
                Digest::new(DigestAlg::Sha1, "aa"),
                Digest::new(DigestAlg::Sha256, "bb")
            ]
        );
    }

    /// **A zero size is undeclared**, because Nexus reports 0 when its
    /// index lacks the size. Trusting it fails the copy's size check.
    #[test]
    fn size_zero_listed_undeclared() {
        let page = parsed(
            r#"{"items":[{"name":"echo","assets":[{
                 "path": "a/b/x.txt",
                 "downloadUrl": "h://nexus.test/repository/m/a/b/x.txt",
                 "fileSize": 0,
                 "checksum": {"sha256": "bb"}
               }]}]}"#,
        );

        let listed = page.items[0].listed();

        assert_eq!(listed[0].size, None);
        assert_eq!(listed[0].digests, [Digest::new(DigestAlg::Sha256, "bb")]);
    }

    /// A duplicate of something else is still refused. This quirk has been
    /// seen; a repeated `name` has not, and failing loudly on something
    /// unexplained beats silently picking one of two values.
    #[test]
    fn duplicate_other_field_still_refused() {
        let doubled_name = r#"{"items":[{"name":"a","name":"b","assets":[]}]}"#;

        assert!(serde_json::from_str::<ComponentPage>(doubled_name).is_err());
    }
}
