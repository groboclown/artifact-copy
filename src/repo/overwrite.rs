//! Who keeps a target's written paths from being replaced: the
//! `overwrite-guard` option.

use crate::core::error::{Error, Result};
use crate::ext::Options;

/// The option that selects an [`OverwriteGuard`].
const OVERWRITE_GUARD_OPTION: &str = "overwrite-guard";

/// Who keeps a written path from being replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverwriteGuard {
    /// The server, by refusing a rewrite; a refusal is then compared.
    ///
    /// **The default**, because checking first costs a request per file,
    /// and Nexus and Artifact Keeper refuse on their own.
    #[default]
    Server,

    /// This target: compare what is stored before writing anything.
    ///
    /// For a server that overwrites and says it succeeded, such as
    /// Artifactory OSS as admin.
    Check,
}

impl OverwriteGuard {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "server" => Some(OverwriteGuard::Server),
            "check" => Some(OverwriteGuard::Check),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["server", "check"]
    }

    pub fn from_options(options: &Options) -> Result<Self> {
        Self::from_options_or(options, OverwriteGuard::default())
    }

    /// As [`OverwriteGuard::from_options`], for a target whose server
    /// calls for another default.
    pub fn from_options_or(options: &Options, fallback: Self) -> Result<Self> {
        let Some(named) = options.string(OVERWRITE_GUARD_OPTION)? else {
            return Ok(fallback);
        };

        Self::parse(named).ok_or_else(|| {
            Error::Config(format!(
                "{OVERWRITE_GUARD_OPTION} is {named:?}, which is not one of: {known}",
                known = Self::names().join(", "),
            ))
        })
    }
}
