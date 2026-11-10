//! A local directory, answered as though it were a server.
//!
//! A repository kind speaks requests: it lists, reads, and writes through
//! an `ExtHost`, which sends them through an [`HttpClient`]. For a
//! `file://` host that client is [`LocalClient`], which answers each request
//! from the directory instead of the network. The repository kind never
//! touches the filesystem, and the host never learns what repository type
//! sits on it.
//!
//! ```text
//!   repo kind  --Req-->  HostedExt  --Req-->  LocalClient
//!                        (confines,           |  plain path     GET, HEAD, PUT
//!                         caches,             |  ?api={name}    an emulation
//!                         verifies)           v
//!                                           fs::Root  (the only std::fs caller)
//! ```
//!
//! # Routes
//!
//! A plain path is a file: `GET` reads it, `HEAD` describes it, and `PUT`
//! creates it once. A query string never names a file on disk, so it is
//! the channel for anything a file server cannot answer, such as a
//! listing: `?api=generic-list` is the [`generic`] emulation.
//!
//! # More repository types
//!
//! Only the generic emulation exists. Another repository type may need
//! responses a directory does not hold as files: an npm packument, a PyPI
//! simple index, a regenerated `maven-metadata.xml`. Each would be an
//! emulation beside [`generic`], enabled through this host's `options`
//! when it is implemented, so the repository kind reading it stays the
//! one that reads a real server.

use serde_json::{Map, Value};

mod fs;
pub(crate) mod generic;
mod local;

pub use local::LocalClient;

#[cfg(doc)]
use super::HttpClient;

/// The URL scheme this client answers.
pub const FILE_SCHEME: &str = "file";

/// The host option naming how symbolic links are treated.
const SYMLINKS: &str = "symlinks";

/// How a symbolic link inside the directory is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Symlinks {
    /// The link reads as a file holding the link's target, exactly as
    /// stored: relative or absolute. Nothing outside the directory is
    /// reached, and a copy keeps what the link said.
    #[default]
    AsFile,

    /// Followed wherever it points, inside the directory or not.
    Follow,

    /// Left out of a listing, and refused when named.
    Skip,

    /// Followed while it resolves inside the directory, and otherwise
    /// treated as [`Symlinks::Skip`].
    WithinRoot,
}

impl Symlinks {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "as-file" => Some(Self::AsFile),
            "follow" => Some(Self::Follow),
            "skip" => Some(Self::Skip),
            "within-root" => Some(Self::WithinRoot),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    fn names() -> &'static [&'static str] {
        &["as-file", "follow", "skip", "within-root"]
    }
}

/// What a `file://` host's `options` say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    pub symlinks: Symlinks,
}

impl Settings {
    /// Read a host's `options`, refusing a key this client does not take.
    ///
    /// The message is the caller's to frame with the host's name.
    pub fn parse(options: &Map<String, Value>) -> Result<Self, String> {
        let mut settings = Self::default();

        for (key, value) in options {
            if key != SYMLINKS {
                return Err(format!(
                    "option {key:?} is not one a file:// host takes; it takes {SYMLINKS:?}"
                ));
            }

            settings.symlinks = value.as_str().and_then(Symlinks::parse).ok_or_else(|| {
                format!(
                    "option {SYMLINKS:?} is {value}, which is not one of: {}",
                    Symlinks::names().join(", ")
                )
            })?;
        }

        Ok(settings)
    }
}

/// Whether `url` names a local directory rather than a server.
pub fn is_local(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == FILE_SCHEME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(json: serde_json::Value) -> Map<String, Value> {
        json.as_object().expect("an object").clone()
    }

    #[test]
    fn symlinks_default_to_as_file() {
        let settings = Settings::parse(&Map::new()).expect("parsed");

        assert_eq!(settings.symlinks, Symlinks::AsFile);
    }

    #[test]
    fn symlinks_every_mode_parses() {
        for (text, mode) in [
            ("as-file", Symlinks::AsFile),
            ("follow", Symlinks::Follow),
            ("skip", Symlinks::Skip),
            ("within-root", Symlinks::WithinRoot),
        ] {
            let settings =
                Settings::parse(&options(serde_json::json!({ "symlinks": text }))).expect("parsed");

            assert_eq!(settings.symlinks, mode);
        }
    }

    #[test]
    fn symlinks_unknown_refused() {
        let err = Settings::parse(&options(serde_json::json!({ "symlinks": "sometimes" })))
            .expect_err("refused");

        assert!(err.contains("within-root"), "{err}");
    }

    #[test]
    fn option_unknown_refused() {
        let err =
            Settings::parse(&options(serde_json::json!({ "color": "blue" }))).expect_err("refused");

        assert!(err.contains("color"), "{err}");
    }

    #[test]
    fn local_only_for_file_urls() {
        assert!(is_local("file:///srv/backup"));
        assert!(!is_local("https://repo.test/"));
        assert!(!is_local("not a url"));
    }
}
