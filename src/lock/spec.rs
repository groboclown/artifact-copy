//! The `--lock` value: a file, and optionally the format to read it as.

use std::path::PathBuf;

/// A parsed `--lock` value.
///
/// `--lock=FILE` detects the format; `--lock=FORMAT,FILE` states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockSpec {
    format: Option<String>,
    path: PathBuf,
}

impl LockSpec {
    /// Parse a `--lock` value, splitting on the **first** comma.
    ///
    /// Splitting on the first rather than the last is what keeps a
    /// pathological filename reachable: `npm,weird,name.lock` reads the file
    /// `weird,name.lock` with the `npm` reader. The cost is that a bare
    /// filename containing a comma cannot be auto-detected.  However, no
    /// known lock file name format has a comma in its name.
    pub fn parse(text: &str) -> std::result::Result<Self, String> {
        let trimmed = text.trim();

        if trimmed.is_empty() {
            return Err("a --lock value needs a filename".to_owned());
        }

        let Some((format, path)) = trimmed.split_once(',') else {
            return Ok(Self {
                format: None,
                path: PathBuf::from(trimmed),
            });
        };

        let format = format.trim();
        let path = path.trim();

        if format.is_empty() {
            return Err(format!("{text:?} names an empty lock format"));
        }

        if path.is_empty() {
            return Err(format!("{text:?} names a format but no file"));
        }

        Ok(Self {
            format: Some(format.to_owned()),
            path: PathBuf::from(path),
        })
    }

    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl std::fmt::Display for LockSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.format {
            Some(format) => write!(f, "{format},{}", self.path.display()),
            None => write!(f, "{}", self.path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_bare_path_detects_format() {
        let spec = LockSpec::parse("package-lock.json").expect("parses");

        assert_eq!(spec.format(), None);
        assert_eq!(spec.path(), std::path::Path::new("package-lock.json"));
    }

    #[test]
    fn spec_prefix_states_format() {
        let spec = LockSpec::parse("package-lock,deps.json").expect("parses");

        assert_eq!(spec.format(), Some("package-lock"));
        assert_eq!(spec.path(), std::path::Path::new("deps.json"));
    }

    /// Splitting on the first comma is what keeps this reachable.
    #[test]
    fn spec_filename_with_comma_reachable() {
        let spec = LockSpec::parse("npm,weird,name.lock").expect("parses");

        assert_eq!(spec.format(), Some("npm"));
        assert_eq!(spec.path(), std::path::Path::new("weird,name.lock"));
    }

    #[test]
    fn spec_round_trips() {
        for text in ["package-lock.json", "npm,weird,name.lock"] {
            assert_eq!(LockSpec::parse(text).unwrap().to_string(), text);
        }
    }

    #[test]
    fn spec_malformed_rejected() {
        assert!(LockSpec::parse("").is_err());
        assert!(LockSpec::parse(",file.json").is_err());
        assert!(LockSpec::parse("npm,").is_err());
    }
}
