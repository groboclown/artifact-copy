//! The download tables in a Corretto release's Markdown body.
//!
//! Three layouts are in use; columns are found by header, and a checksum is
//! told apart by its length rather than by its column:
//!
//! ```text
//!   |Platform|Type|Download Link|Checksum (MD5) / Checksum (SHA256)|Sig File|
//!   |Platform|Type|Download Link|Checksum (MD5)|Sig File|
//!   |Platform|Type|Download Link|Checksum (MD5)|Checksum (SHA256)|Sig File|
//!
//!   |[Linux x64](docs)|JDK|[a.tar.gz](https://corretto.aws/.../a.tar.gz)|`<md5>` /<br /> `<sha256>`|[Download](https://.../a.tar.gz.sig)|
//! ```

/// One downloadable file a table row names.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The Platform column's text, such as `Linux x64`.
    pub platform: String,

    /// The Type column, such as `JDK` or `DEBUGSYMBOLS`.
    pub kind: String,

    pub url: String,
    pub md5: Option<String>,
    pub sha256: Option<String>,

    /// The detached signature, where the Sig File column links one.
    pub sig_url: Option<String>,
}

/// Hex digits in an MD5 and a SHA256 digest.
const MD5_HEX_LEN: usize = 32;
const SHA256_HEX_LEN: usize = 64;

/// The columns a table's header names.
#[derive(Default)]
struct Columns {
    platform: Option<usize>,
    kind: Option<usize>,
    link: Option<usize>,
    checksums: Vec<usize>,
    sig: Option<usize>,
}

impl Columns {
    /// `None` for a table that is not a download table.
    fn read(header: &[&str]) -> Option<Self> {
        let mut columns = Self::default();

        for (at, name) in header.iter().enumerate() {
            let name = name.to_ascii_lowercase();

            if name.contains("download link") {
                columns.link = Some(at);
            } else if name.contains("checksum") {
                columns.checksums.push(at);
            } else if name.contains("sig") {
                columns.sig = Some(at);
            } else if name.contains("platform") {
                columns.platform = Some(at);
            } else if name.contains("type") {
                columns.kind = Some(at);
            }
        }

        columns.link.map(|_| columns)
    }
}

/// Every download row in every table of `body`.
pub fn parse(body: &str) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut columns: Option<Columns> = None;

    for line in body.lines().map(str::trim) {
        if !line.starts_with('|') {
            columns = None;
            continue;
        }

        let cells = cells(line);

        // The `|---|---|` line under a header.
        if cells.iter().all(|cell| is_rule(cell)) {
            continue;
        }

        let Some(known) = &columns else {
            columns = Columns::read(&cells);
            continue;
        };

        if let Some(row) = row(known, &cells) {
            rows.push(row);
        }
    }

    rows
}

/// `| a | b |` to `["a", "b"]`.
fn cells(line: &str) -> Vec<&str> {
    let inner = line.strip_prefix('|').unwrap_or(line);
    let inner = inner.strip_suffix('|').unwrap_or(inner);

    inner.split('|').map(str::trim).collect()
}

fn is_rule(cell: &str) -> bool {
    !cell.is_empty() && cell.chars().all(|c| c == '-' || c == ':')
}

fn row(columns: &Columns, cells: &[&str]) -> Option<Row> {
    let cell = |at: Option<usize>| at.and_then(|at| cells.get(at)).copied().unwrap_or("");

    let (_, url) = link(cell(columns.link))?;

    let platform = match link(cell(columns.platform)) {
        Some((text, _)) => text.to_owned(),
        None => cell(columns.platform).to_owned(),
    };

    let hexes: Vec<&str> = columns
        .checksums
        .iter()
        .flat_map(|&at| quoted(cells.get(at).copied().unwrap_or("")))
        .collect();

    let digest = |len: usize| {
        hexes
            .iter()
            .find(|hex| hex.len() == len)
            .map(|hex| hex.to_ascii_lowercase())
    };

    Some(Row {
        platform,
        kind: cell(columns.kind).to_owned(),
        url: url.to_owned(),
        md5: digest(MD5_HEX_LEN),
        sha256: digest(SHA256_HEX_LEN),
        sig_url: link(cell(columns.sig)).map(|(_, url)| url.to_owned()),
    })
}

/// The first `[text](url)` in a cell.
fn link(cell: &str) -> Option<(&str, &str)> {
    let open = cell.find('[')?;
    let close = open + cell[open..].find("](")?;
    let end = close + cell[close..].find(')')?;

    let text = cell[open + 1..close].trim();
    let url = cell[close + 2..end].trim();

    (!url.is_empty()).then_some((text, url))
}

/// Every hex string between backticks in a cell.
fn quoted(cell: &str) -> Vec<&str> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MD5: &str = "50de874f5fdd2b6b7f3788c199894117";
    const SHA256: &str = "1d89b4194f20ee513f4dd9fc2aadd038de3c713c37fd444d77566b3da7b0ee65";

    #[test]
    fn combined_checksum_column() {
        let body = format!(
            "intro\r\n\r\n|Platform|Type|Download Link|Checksum (MD5) / Checksum (SHA256)|Sig File|\r\n\
             |---|---|---|---|---|\r\n\
             |[Linux x64](https://docs/)|JDK|[a.tar.gz](https://corretto.aws/r/1/a.tar.gz)|`{MD5}` /<br /> `{SHA256}`|[Download](https://corretto.aws/r/1/a.tar.gz.sig)|\r\n"
        );

        let rows = parse(&body);

        assert_eq!(
            rows,
            vec![Row {
                platform: "Linux x64".into(),
                kind: "JDK".into(),
                url: "https://corretto.aws/r/1/a.tar.gz".into(),
                md5: Some(MD5.into()),
                sha256: Some(SHA256.into()),
                sig_url: Some("https://corretto.aws/r/1/a.tar.gz.sig".into()),
            }]
        );
    }

    #[test]
    fn separate_checksum_columns() {
        let body = format!(
            "|Platform |Type |Download Link |Checksum (MD5) |Checksum (SHA256) |Sig File |\n\
             |--- |--- |--- |--- |--- |--- |\n\
             |[Windows x64](d) |JDK |[b.zip](https://h/b.zip) |`{MD5}` |`{SHA256}` | |\n"
        );

        let row = &parse(&body)[0];

        assert_eq!(row.md5.as_deref(), Some(MD5));
        assert_eq!(row.sha256.as_deref(), Some(SHA256));
        assert_eq!(row.sig_url, None);
    }

    #[test]
    fn md5_only() {
        let body = format!(
            "|Platform\t|Type\t|Download Link\t|Checksum (MD5)\t|Sig File\t|\n\
             |---\t|---\t|---\t|---\t|---\t|\n\
             |[Linux x64](d)\t|JDK\t| [c.rpm](https://h/c.rpm)\t| `{MD5}`\t|\t|\n"
        );

        let row = &parse(&body)[0];

        assert_eq!(row.md5.as_deref(), Some(MD5));
        assert_eq!(row.sha256, None);
    }

    #[test]
    fn prose_has_no_rows() {
        assert!(
            parse("This is a AL2023-only release, for other platforms use 25.0.4.10.1").is_empty()
        );
    }

    #[test]
    fn non_download_table_skipped() {
        let body = "|Name|Value|\n|---|---|\n|[x](https://h/x)|y|\n";

        assert!(parse(body).is_empty());
    }
}
