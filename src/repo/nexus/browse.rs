//! A Nexus repository folder, from its HTML browse page.
//!
//! ```text
//!   GET {base}/service/rest/repository/browse/{repository}/{folder}/
//!   <tr><td><a href="{download url}">{name}</a></td><td>{last modified}</td><td>{size}</td>...
//!   <tr><td><a href="{name}/">{name}</a></td>...                       a sub-folder
//! ```
//!
//! The one listing every format answers alike: `search/assets` matches
//! `group` against a folder only in a raw repository, where a Maven
//! repository's `group` is its groupId, and `q` matches component keywords
//! rather than paths (both measured on 3.96.3). So a non-raw repository
//! read as raw is read here.
//!
//! A file path with a trailing `/` answers 404, as a missing folder does,
//! so every request names a folder.
//!
//! # What a row does not say
//!
//! No digests, so a file read here is verified only by what `copy` fetches.
//! The time is the asset's last modification rather than its blob's
//! creation, which a server-side re-index can move later: a publish window
//! then errs toward "too new", never toward "old enough".

use chrono::{DateTime, NaiveDateTime, Utc};
use http::StatusCode;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::ExtHost;
use crate::net::{ByteLimit, Req, encode_unreserved};
use crate::repo::pep503;

/// The browse pages, relative to the Nexus base URL.
const BROWSE: &str = "service/rest/repository/browse";

/// One folder's page.
const PAGE_LIMIT: ByteLimit = ByteLimit::mib(4);

/// How a row spells its time: `Mon Oct 05 16:14:59 Z 2026`, Java's
/// `Date::toString`, with the zone taken off and checked apart.
const TIME_FORMAT: &str = "%a %b %d %H:%M:%S %Y";

/// Zone spellings that mean UTC. Any other zone leaves the time unknown
/// rather than guessed.
const UTC_ZONES: [&str; 3] = ["Z", "UTC", "GMT"];

/// One row of a folder's page.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Entry {
    File {
        name: String,
        url: String,
        size: Option<u64>,
        modified: Option<DateTime<Utc>>,
    },

    Folder(String),
}

/// The rows of the folder at `folder`, or `None` when there is none.
///
/// `folder` is the path under the repository root, without leading or
/// trailing `/`; empty is the root.
pub(super) async fn folder(
    host: &dyn ExtHost,
    base_url: &str,
    repository: &str,
    folder: &str,
    ctx: &Ctx,
) -> Result<Option<Vec<Entry>>> {
    let url = folder_url(base_url, repository, folder);

    let body = match host.fetch(&Req::get(&url), PAGE_LIMIT, ctx).await {
        // HTTP 404: no such folder.
        Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
            return Ok(None);
        }
        other => other?,
    };

    parse(&String::from_utf8_lossy(&body))
        .map(Some)
        .map_err(|detail| Error::Malformed {
            what: "nexus browse page",
            url,
            detail,
        })
}

/// `{base}/{BROWSE}/{repository}/{folder}/`, each segment encoded.
fn folder_url(base_url: &str, repository: &str, folder: &str) -> String {
    let mut url = format!("{base_url}/{BROWSE}/{}/", encode_unreserved(repository));

    for segment in folder.split('/').filter(|segment| !segment.is_empty()) {
        url.push_str(&encode_unreserved(segment));
        url.push('/');
    }

    url
}

/// Every row naming a file or a sub-folder.
///
/// A file's link is its absolute download URL; a sub-folder's is relative
/// and ends in `/`; the parent is `../`. The page's head links stylesheets
/// and icons, outside any row.
fn parse(html: &str) -> std::result::Result<Vec<Entry>, String> {
    let mut entries = Vec::new();

    for row in rows(html) {
        let Some(link) = pep503::links(row)?.into_iter().next() else {
            continue;
        };

        let name = link.text.trim().trim_end_matches('/').to_owned();

        if name.is_empty() || link.href.starts_with("../") {
            continue;
        }

        if link.href.ends_with('/') {
            entries.push(Entry::Folder(name));
            continue;
        }

        // Name, last modified, size, description.
        let cells = cells(row);

        entries.push(Entry::File {
            name,
            url: link.href,
            size: cells.get(2).and_then(|text| text.parse().ok()),
            modified: cells.get(1).and_then(|text| modified(text)),
        });
    }

    Ok(entries)
}

/// Each `<tr>...</tr>` of the page.
fn rows(html: &str) -> Vec<&str> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut at = 0;

    while let Some(start) = lower[at..].find("<tr").map(|found| at + found) {
        let end = lower[start..]
            .find("</tr>")
            .map_or(html.len(), |found| start + found);

        out.push(&html[start..end]);
        at = end;
    }

    out
}

/// The text of each `<td>` in one row, tags removed and trimmed.
fn cells(row: &str) -> Vec<String> {
    let lower = row.to_ascii_lowercase();

    lower
        .match_indices("<td")
        .map(|(start, _)| {
            let open_end = lower[start..]
                .find('>')
                .map_or(row.len(), |at| start + at + 1);
            let close = lower[open_end..]
                .find("</td>")
                .map_or(row.len(), |at| open_end + at);

            strip_tags(&row[open_end..close]).trim().to_owned()
        })
        .collect()
}

fn strip_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut inside = false;

    for character in text.chars() {
        match character {
            '<' => inside = true,
            '>' => inside = false,
            _ if !inside => out.push(character),
            _ => {}
        }
    }

    out
}

/// `Mon Oct 05 16:14:59 Z 2026`, when its zone is UTC.
fn modified(text: &str) -> Option<DateTime<Utc>> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [weekday, month, day, time, zone, year] = parts.as_slice() else {
        return None;
    };

    if !UTC_ZONES.contains(zone) {
        return None;
    }

    let joined = format!("{weekday} {month} {day} {time} {year}");

    NaiveDateTime::parse_from_str(&joined, TIME_FORMAT)
        .ok()
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed copy of what the local Nexus 3.96.3 served for
    /// `maven-a/example/lib/echo/`'s version folder, plus a sub-folder row.
    const PAGE: &str = r#"<html><head>
<link rel="icon" href="../../../../static/rapture/resources/favicon.svg?3.96.3-01">
</head><body>
<table cellspacing="10">
    <tr>
        <th align="left">Name</th>
        <th>Last Modified</th>
        <th>Size</th>
        <th>Description</th>
    </tr>
        <tr>
            <td><a href="../">Parent Directory</a></td>
        </tr>
        <tr>
            <td><a href="http://localhost:8081/repository/maven-a/example/lib/echo/1.0/echo-1.0.jar">echo-1.0.jar</a></td>
            <td>
                    Mon Oct 05 16:14:59 Z 2026
            </td>
            <td align="right">
                    884
            </td>
            <td></td>
        </tr>
        <tr>
            <td><a href="sub/">sub</a></td>
            <td>
            </td>
            <td align="right">
            </td>
            <td></td>
        </tr>
</table></body></html>"#;

    #[test]
    fn rows_become_files_and_folders() {
        let entries = parse(PAGE).expect("parses");

        assert_eq!(
            entries,
            [
                Entry::File {
                    name: "echo-1.0.jar".into(),
                    url:
                        "http://localhost:8081/repository/maven-a/example/lib/echo/1.0/echo-1.0.jar"
                            .into(),
                    size: Some(884),
                    modified: DateTime::parse_from_rfc3339("2026-10-05T16:14:59Z")
                        .ok()
                        .map(|stamp| stamp.with_timezone(&Utc)),
                },
                Entry::Folder("sub".into()),
            ]
        );
    }

    /// A zone other than UTC is not guessed at.
    #[test]
    fn zone_other_than_utc_unknown() {
        assert!(modified("Mon Oct 05 16:14:59 EDT 2026").is_none());
        assert!(modified("Mon Oct 05 16:14:59 UTC 2026").is_some());
        assert!(modified("garbage").is_none());
    }

    #[test]
    fn folder_url_encodes_each_segment() {
        assert_eq!(
            folder_url("h://nexus.test", "maven a", "a b/c"),
            "h://nexus.test/service/rest/repository/browse/maven%20a/a%20b/c/"
        );
        assert_eq!(
            folder_url("h://nexus.test", "raw", ""),
            "h://nexus.test/service/rest/repository/browse/raw/"
        );
    }
}
