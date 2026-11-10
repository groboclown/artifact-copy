//! Choosing the reader for a lock file.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{Lock, LockHead, LockSpec, bom, npm};
use crate::config::Extension;
use crate::core::error::{Error, Result};
use crate::internal::glob;

/// The readers available to a run.
///
/// Built-ins are registered without being declared, because `--lock=FILE`
/// names a file rather than a configured entry: a config that never mentions
/// locks still reads a `package-lock.json`. Declared readers go *before* the
/// built-ins, so a user's reader can take over a format the tool already
/// handles.
pub struct Registry {
    readers: Vec<Arc<dyn Lock>>,

    /// Configured extensions, by name, for a `--lock=FORMAT,FILE` whose
    /// format names one.
    extensions: BTreeMap<String, Extension>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    /// Just the built-in readers.
    pub fn builtin() -> Self {
        Self {
            readers: npm::readers().into_iter().chain(bom::readers()).collect(),
            extensions: BTreeMap::new(),
        }
    }

    /// Also offer each configured extension as a format of its own name.
    pub fn with_extensions(mut self, extensions: &BTreeMap<String, Extension>) -> Self {
        self.extensions = extensions.clone();
        self
    }

    /// Add a reader ahead of the built-ins.
    pub fn prepend(&mut self, reader: Arc<dyn Lock>) {
        self.readers.insert(0, reader);
    }

    /// Every registered format name, in precedence order.
    pub fn formats(&self) -> Vec<String> {
        self.readers
            .iter()
            .flat_map(|reader| reader.formats())
            .map(|format| format.name.clone())
            .collect()
    }

    /// The reader providing a named format.
    pub fn by_format(&self, name: &str) -> Option<Arc<dyn Lock>> {
        self.readers
            .iter()
            .find(|reader| reader.formats().iter().any(|format| format.name == name))
            .map(Arc::clone)
    }

    /// Choose a reader for a file.
    ///
    /// An explicit format skips detection entirely: if the named reader
    /// cannot parse the file, that is an error rather than a cue to go
    /// sniffing. Explicit means explicit.
    pub fn resolve<'n, 'h>(
        &self,
        spec: &LockSpec,
        name: &'n str,
        head: &LockHead<'h>,
    ) -> Result<Arc<dyn Lock>> {
        if let Some(format) = spec.format() {
            // A format an extension provides goes to the gearing, which
            // runs only sources yet.
            if self.extensions.contains_key(format) {
                return Err(Error::Unimplemented("running a lock extension"));
            }

            return self
                .by_format(format)
                .ok_or_else(|| Error::LockFormatUnknown {
                    format: format.to_owned(),
                    known: self.formats().join(", "),
                });
        }

        // Cheapest first: filename globs, then a head peek only where more
        // than one reader answers to the same name.
        let named: Vec<&Arc<dyn Lock>> = self
            .readers
            .iter()
            .filter(|reader| answers_to(reader.as_ref(), name))
            .collect();

        if named.len() == 1 {
            return Ok(Arc::clone(named[0]));
        }

        let candidates = if named.is_empty() {
            self.readers.iter().collect::<Vec<_>>()
        } else {
            named
        };

        candidates
            .into_iter()
            .find(|reader| reader.claims(name, head))
            .map(Arc::clone)
            .ok_or_else(|| Error::LockUnrecognized {
                name: name.to_owned(),
                tried: self.formats().join(", "),
            })
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("formats", &self.formats())
            .finish()
    }
}

/// Whether any of a reader's filename globs match.
fn answers_to(reader: &dyn Lock, name: &str) -> bool {
    reader
        .formats()
        .iter()
        .flat_map(|format| &format.filenames)
        .any(|pattern| glob::matches_file_name(pattern, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matcher itself is `core::glob`'s to test; this pins that the
    /// filename patterns *this* module declares behave as expected.
    #[test]
    fn filename_declared_patterns_match() {
        assert!(glob::matches_file_name(
            "package-lock.json",
            "package-lock.json"
        ));
        assert!(glob::matches_file_name("pylock*.toml", "pylock.prod.toml"));
        assert!(!glob::matches_file_name("pylock*.toml", "poetry.lock"));
        assert!(glob::matches_file_name("*.lock", "yarn.lock"));
    }

    #[test]
    fn registry_builtin_knows_npm_formats() {
        let registry = Registry::builtin();
        let formats = registry.formats();

        assert!(formats.contains(&"package-lock".to_owned()));
        assert!(formats.contains(&"yarn".to_owned()));
    }

    #[test]
    fn filename_alone_reaches_reader() {
        let registry = Registry::builtin();
        let spec = LockSpec::parse("package-lock.json").expect("parses");

        let reader = registry
            .resolve(&spec, "package-lock.json", &LockHead::of(b"{}"))
            .expect("resolved");

        assert!(reader.formats().iter().any(|f| f.name == "package-lock"));
    }

    /// An explicit format skips detection: the filename says nothing here.
    #[test]
    fn format_explicit_overrides_filename() {
        let registry = Registry::builtin();
        let spec = LockSpec::parse("package-lock,deps.txt").expect("parses");

        let reader = registry
            .resolve(&spec, "deps.txt", &LockHead::of(b"not json"))
            .expect("resolved");

        assert!(reader.formats().iter().any(|f| f.name == "package-lock"));
    }

    #[test]
    fn format_unknown_names_registered() {
        let registry = Registry::builtin();
        let spec = LockSpec::parse("cargo,Cargo.lock").expect("parses");

        let err = match registry.resolve(&spec, "Cargo.lock", &LockHead::of(b"")) {
            Err(err) => err,
            Ok(_) => panic!("cargo is not a registered format"),
        };

        assert_eq!(err.code(), crate::core::problem::Code::LockFormatUnknown);
        assert!(err.to_string().contains("cargo"));
        assert!(err.to_string().contains("package-lock"));
    }

    /// Silence would look exactly like a lock file with no dependencies in
    /// it, which is the kind of thing that costs someone an afternoon.
    #[test]
    fn filename_unrecognized_says_what_was_tried() {
        let registry = Registry::builtin();
        let spec = LockSpec::parse("mystery.bin").expect("parses");

        let err = match registry.resolve(&spec, "mystery.bin", &LockHead::of(b"\x00\x01")) {
            Err(err) => err,
            Ok(_) => panic!("nothing should have claimed it"),
        };

        assert_eq!(err.code(), crate::core::problem::Code::LockUnrecognized);
        assert!(err.to_string().contains("--lock=FORMAT,FILE"));
        assert!(err.to_string().contains("package-lock"));
    }

    /// A declared reader takes precedence over a built-in for the same glob.
    #[test]
    fn reader_declared_outranks_builtin() {
        let mut registry = Registry::builtin();
        registry.prepend(Arc::new(npm::testing::AlwaysClaims));

        let spec = LockSpec::parse("package-lock.json").expect("parses");

        let reader = registry
            .resolve(&spec, "package-lock.json", &LockHead::of(b"{}"))
            .expect("resolved");

        assert_eq!(reader.formats()[0].name, "always-claims");
    }

    /// A format naming a configured extension reaches the gearing.
    #[test]
    fn format_extension_reaches_gearing() {
        let extensions: BTreeMap<String, Extension> =
            serde_json::from_value(serde_json::json!({"custom": {"kind": "executable", "command": "custom-source", "arguments": []}})).expect("parses");
        let registry = Registry::builtin().with_extensions(&extensions);
        let spec = LockSpec::parse("custom,deps.lock").expect("parses");

        let err = match registry.resolve(&spec, "deps.lock", &LockHead::of(b"")) {
            Err(err) => err,
            Ok(_) => panic!("an extension cannot run yet"),
        };

        assert_eq!(err.code(), crate::core::problem::Code::Unimplemented);
    }
}
