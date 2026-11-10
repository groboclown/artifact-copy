//! `.env`-style property file driver.
//!
//! The file is the only source; see [`super::SecretValue::PropertyFile`].

use std::path::Path;

use super::Secret;
use crate::core::error::{Error, Result};

/// Read `key` from the property file at `path`.
///
/// No environment fallback, deliberately: see the variant's documentation.
pub(super) fn load(path: &Path, key: &str) -> Result<Secret> {
    let body = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    read_property(&body, key)
        .map(Secret)
        .ok_or_else(|| Error::Config(format!("{} defines no property {key:?}", path.display())))
}

/// Find one entry in a `.env`-style property file.
///
/// The format, kept deliberately small so that what a file means is never
/// in doubt:
///
/// - `KEY=value`, with whitespace around either side ignored.
/// - A leading `export ` is allowed, since `.env` files are routinely
///   sourced by a shell.
/// - `#` and `!` start a comment, at the beginning of a line.
/// - A value may be wrapped in matching single or double quotes, which
///   preserves leading and trailing spaces. Inside double quotes, `\n`,
///   `\t`, `\r`, `\\` and `\"` are unescaped; single quotes are literal.
/// - The **last** definition of a key wins, which is how a shell sourcing
///   the same file would read it.
///
/// There is deliberately no `${OTHER}` interpolation. It would be a way for
/// the surrounding environment back into a value that is documented as
/// coming only from the file.
fn read_property(body: &str, wanted: &str) -> Option<String> {
    let mut found = None;

    for line in body.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if key.trim() != wanted {
            continue;
        }

        found = Some(unquote(value.trim()));
    }

    found
}

/// Strip matching quotes, unescaping only within double quotes.
fn unquote(value: &str) -> String {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            let inner = &value[1..value.len() - 1];

            return match quote {
                '"' => unescape(inner),
                _ => inner.to_owned(),
            };
        }
    }

    value.to_owned()
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),

            // A trailing backslash is itself.
            None => out.push('\\'),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::secret::SecretValue;

    const SAMPLE: &str = r#"
# a comment
! also a comment

REGISTRY_TOKEN=plain-value
export EXPORTED=exported-value
QUOTED="  spaces kept  "
SINGLE='literal $NOT_EXPANDED'
ESCAPED="line\nbreak"
EMPTY=
SPACED  =  trimmed
DUPLICATE=first
DUPLICATE=last
"#;

    fn read(key: &str) -> Option<String> {
        read_property(SAMPLE, key)
    }

    #[test]
    fn entry_plain_read() {
        assert_eq!(read("REGISTRY_TOKEN").as_deref(), Some("plain-value"));
    }

    /// `.env` files are routinely sourced by a shell, so `export` is
    /// commonplace and must not make the key unreadable.
    #[test]
    fn entry_exported_read() {
        assert_eq!(read("EXPORTED").as_deref(), Some("exported-value"));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        assert_eq!(read("# a comment"), None);
        assert_eq!(read("MISSING"), None);
    }

    /// Quotes exist so that a credential with leading or trailing spaces
    /// survives, since trimming one out would produce a token that looks
    /// right and does not work.
    #[test]
    fn quotes_preserve_surrounding_space() {
        assert_eq!(read("QUOTED").as_deref(), Some("  spaces kept  "));
    }

    #[test]
    fn quotes_double_escapes_unescaped() {
        assert_eq!(read("ESCAPED").as_deref(), Some("line\nbreak"));
    }

    /// Single quotes are literal, which is also what stops a `$NOT_EXPANDED`
    /// looking like it might have been expanded.
    #[test]
    fn quotes_single_literal() {
        assert_eq!(read("SINGLE").as_deref(), Some("literal $NOT_EXPANDED"));
    }

    #[test]
    fn separator_surrounding_whitespace_ignored() {
        assert_eq!(read("SPACED").as_deref(), Some("trimmed"));
    }

    #[test]
    fn value_empty_is_empty_string_not_absent() {
        assert_eq!(read("EMPTY").as_deref(), Some(""));
    }

    /// The last definition wins, as a shell sourcing the file would read it.
    #[test]
    fn last_definition_wins() {
        assert_eq!(read("DUPLICATE").as_deref(), Some("last"));
    }

    /// The property this variant exists for. Ordinary `.env` tooling would
    /// fall back to the environment; doing so would mean anything able to
    /// set a variable could substitute a credential.
    #[test]
    fn environment_never_consulted() {
        let key = "ARTIFACT_COPY_TEST_ENV_FALLBACK";

        // SAFETY: single-threaded test with a name unique to it.
        unsafe { std::env::set_var(key, "from-the-environment") };

        // Absent from the file, present in the environment: still absent.
        assert_eq!(read_property("OTHER=x", key), None);

        // And the file wins where both define it.
        assert_eq!(
            read_property(&format!("{key}=from-the-file"), key).as_deref(),
            Some("from-the-file")
        );

        unsafe { std::env::remove_var(key) };
    }

    /// Interpolation would be a way for the environment back into a value
    /// documented as coming only from the file.
    #[test]
    fn value_not_interpolated() {
        assert_eq!(
            read_property("TOKEN=${HOME}/x", "TOKEN").as_deref(),
            Some("${HOME}/x")
        );
    }

    /// A URL contains a colon and a slash and must survive intact; only
    /// the first `=` separates.
    #[test]
    fn value_with_separator_kept_whole() {
        assert_eq!(
            read_property("URL=https://example.test/a=b", "URL").as_deref(),
            Some("https://example.test/a=b")
        );
    }

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "artifact-copy-secret-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));

        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn path_relative_resolves_against_base() {
        let dir = temp_dir();
        std::fs::write(
            dir.join(".env"),
            "TOKEN=from-file
",
        )
        .expect("written");

        let secret = SecretValue::PropertyFile {
            working_dir_path: dir.join(".env"),
            key: "TOKEN".to_owned(),
        };

        assert_eq!(secret.resolve().expect("resolved").expose(), "from-file");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A missing file names the file, so the user can see which one was
    /// looked for rather than guessing.
    #[test]
    fn file_missing_named() {
        let secret = SecretValue::PropertyFile {
            working_dir_path: std::path::PathBuf::from("definitely-not-here.env"),
            key: "TOKEN".to_owned(),
        };

        let err = secret.resolve().expect_err("should fail");

        assert!(err.to_string().contains("definitely-not-here.env"), "{err}");
    }

    #[test]
    fn key_missing_named() {
        let dir = temp_dir();
        std::fs::write(
            dir.join("keys.env"),
            "OTHER=x
",
        )
        .expect("written");

        let secret = SecretValue::PropertyFile {
            working_dir_path: dir.join("keys.env"),
            key: "TOKEN".to_owned(),
        };

        let err = secret.resolve().expect_err("should fail");

        assert!(err.to_string().contains("TOKEN"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
