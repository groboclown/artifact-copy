//! How a report is rendered.
//!
//! These live with the report rather than with the argument parser, because
//! a report writer is what they configure. `cli` reaches them through
//! `value_parser`, so the enums stay plain data and `clap` stays confined
//! to the command-line layer.

use std::fmt;
use std::path::{Path, PathBuf};

/// How a report's records are rendered.
///
/// Apart from [`ReportFormat`] because the rendering and the decision to
/// truncate are two facts, and a caller usually wants one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rendering {
    /// One JSON object per line.
    Json,

    /// One YAML document per record.
    Yaml,

    /// The same records, unquoted, for a human.
    Text,
}

/// What a format does to a report file that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opening {
    /// Discard what is there and start over.
    Truncate,

    /// Add this run's records after the ones already written.
    Append,
}

/// The renderings a report can be written in, and what each does to an
/// existing file.
///
/// The two are one value because a user picks them together, in one
/// argument.
///
/// A database is not a report format: `--db=FILE` opens one beside a report,
/// since the two serve different readers. See [`crate::report::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    JsonAppend,
    Yaml,
    YamlAppend,
    Text,
    TextAppend,
}

impl ReportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::JsonAppend => "json-append",
            ReportFormat::Yaml => "yaml",
            ReportFormat::YamlAppend => "yaml-append",
            ReportFormat::Text => "text",
            ReportFormat::TextAppend => "text-append",
        }
    }

    /// Every format, in the order a message lists them.
    pub fn every() -> &'static [ReportFormat] {
        &[
            ReportFormat::Json,
            ReportFormat::JsonAppend,
            ReportFormat::Yaml,
            ReportFormat::YamlAppend,
            ReportFormat::Text,
            ReportFormat::TextAppend,
        ]
    }

    /// Every spelling a user may write, for an error that names them.
    pub fn names() -> Vec<&'static str> {
        Self::every().iter().map(|format| format.as_str()).collect()
    }

    /// How this format renders one record.
    pub fn rendering(self) -> Rendering {
        match self {
            ReportFormat::Json | ReportFormat::JsonAppend => Rendering::Json,
            ReportFormat::Yaml | ReportFormat::YamlAppend => Rendering::Yaml,
            ReportFormat::Text | ReportFormat::TextAppend => Rendering::Text,
        }
    }

    /// What this format does to a file that already holds a report.
    ///
    /// Every line format truncates by default, because that is what writing
    /// a file has always meant.
    pub fn opening(self) -> Opening {
        match self {
            ReportFormat::JsonAppend | ReportFormat::YamlAppend | ReportFormat::TextAppend => {
                Opening::Append
            }

            ReportFormat::Json | ReportFormat::Yaml | ReportFormat::Text => Opening::Truncate,
        }
    }

    /// Parse one report TYPE.
    ///
    /// The database spellings a report TYPE once took are refused with
    /// the flag that replaced them, `sqllite` typo included.
    pub fn parse(text: &str) -> Result<Self, String> {
        let spelled = text.trim().to_ascii_lowercase();

        // Each spelling is written once, in `as_str`.
        if let Some(format) = Self::every().iter().find(|f| f.as_str() == spelled) {
            return Ok(*format);
        }

        match spelled.as_str() {
            "sqllite" | "sqlite" | "sqllite-new" | "sqlite-new" => Err(format!(
                "{text:?}: a database is not a report type; use --db=FILE, \
                 and --refresh=all to replace it"
            )),

            other => Err(format!(
                "unknown report format {other:?}; expected one of {}",
                Self::names().join(", ")
            )),
        }
    }
}

/// The FILE that names standard output.
const STDOUT: &str = "-";

/// Where a report goes and how it is rendered, written `[TYPE,]FILE`.
///
/// Examples: `run.jsonl` (text), `json,run.jsonl`, `json,-` (standard
/// output), `sqlite,report.db`.
///
/// Split on the first comma, as `--lock` is, so `json,odd,name.jsonl`
/// writes `odd,name.jsonl`; a bare FILE therefore cannot hold a comma.
///
/// The default is text on standard output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportSpec {
    format: Option<ReportFormat>,
    path: Option<PathBuf>,
}

impl ReportSpec {
    /// Parse one `[TYPE,]FILE` value.
    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();

        if trimmed.is_empty() {
            return Err("a report needs [TYPE,]FILE; use - for standard output".to_owned());
        }

        let (format, file) = match trimmed.split_once(',') {
            Some((format, file)) => (Some(ReportFormat::parse(format)?), file.trim()),
            None => (None, trimmed),
        };

        if file.is_empty() {
            return Err(format!(
                "{text:?} names a type but no file; use - for standard output"
            ));
        }

        let path = match file {
            STDOUT => None,
            other => Some(PathBuf::from(other)),
        };

        Ok(Self { format, path })
    }

    /// The rendering; text when no TYPE was given.
    pub fn format(&self) -> ReportFormat {
        self.format.unwrap_or(ReportFormat::Text)
    }

    /// The TYPE as written, if it was.
    pub fn declared(&self) -> Option<ReportFormat> {
        self.format
    }

    /// The file, or `None` for standard output.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for ReportSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file = self
            .path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| STDOUT.to_owned());

        match self.format {
            Some(format) => write!(f, "{format},{file}"),
            None => f.write_str(&file),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_spec_reads_type_and_file() {
        let spec = ReportSpec::parse("json,run.jsonl").expect("parses");

        assert_eq!(spec.format(), ReportFormat::Json);
        assert_eq!(spec.path(), Some(Path::new("run.jsonl")));
    }

    #[test]
    fn report_spec_defaults_to_text() {
        let spec = ReportSpec::parse("run.txt").expect("parses");

        assert_eq!(spec.format(), ReportFormat::Text);
        assert_eq!(spec.declared(), None);
    }

    #[test]
    fn report_spec_dash_is_stdout() {
        let spec = ReportSpec::parse("yaml,-").expect("parses");

        assert_eq!(spec.path(), None);
        assert_eq!(spec.to_string(), "yaml,-");
    }

    /// Split on the first comma, so a typed FILE may hold one.
    #[test]
    fn report_spec_keeps_later_commas() {
        let spec = ReportSpec::parse("json,odd,name.jsonl").expect("parses");

        assert_eq!(spec.path(), Some(Path::new("odd,name.jsonl")));
    }

    #[test]
    fn report_spec_refusals() {
        for (text, expect) in [
            ("", "[TYPE,]FILE"),
            ("json,", "no file"),
            ("csv,out.csv", "unknown report format"),
            ("sqlite,r.db", "--db=FILE"),
        ] {
            let err = ReportSpec::parse(text).expect_err(text);

            assert!(err.contains(expect), "{text}: {err}");
        }
    }

    #[test]
    fn every_name_parses_back_to_its_value() {
        for name in ReportFormat::names() {
            let parsed = ReportFormat::parse(name).expect(name);

            assert_eq!(parsed.as_str(), name);
        }
    }

    /// A database moved to `--db`; each old spelling names the new flag
    /// rather than reading as an unknown type.
    #[test]
    fn db_flag_named_by_sqlite_report_types() {
        for name in ["sqlite", "sqllite", "sqlite-new", "sqllite-new"] {
            let err = ReportFormat::parse(name).expect_err(name);

            assert!(err.contains("--db=FILE"), "{name}: {err}");
        }
    }

    /// The append variant renders exactly what its truncating twin does.
    /// Anything else would make `json-append` a second format to maintain
    /// rather than the same one opened differently.
    #[test]
    fn format_append_variants_render_same() {
        let pairs = [
            (ReportFormat::Json, ReportFormat::JsonAppend),
            (ReportFormat::Yaml, ReportFormat::YamlAppend),
            (ReportFormat::Text, ReportFormat::TextAppend),
        ];

        for (truncating, appending) in pairs {
            assert_eq!(truncating.rendering(), appending.rendering());
            assert_eq!(truncating.opening(), Opening::Truncate);
            assert_eq!(appending.opening(), Opening::Append);
        }
    }

    #[test]
    fn format_case_and_whitespace_ignored() {
        assert_eq!(ReportFormat::parse("  JSON "), Ok(ReportFormat::Json));
    }

    /// A misspelling has to name the alternatives, because the schema no
    /// longer constrains this value.
    #[test]
    fn format_unknown_names_alternatives() {
        let err = ReportFormat::parse("jsonl").expect_err("refused");

        assert!(err.contains("jsonl"), "{err}");
        assert!(err.contains("yaml"), "{err}");
    }
}
