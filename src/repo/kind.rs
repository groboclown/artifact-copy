//! What a server module declares about the kinds it offers.
//!
//! Each server module (`nexus`, `maven`, `npm`, ...) holds one [`Kinds`]
//! naming its source, target, and enumerators, with the function that opens
//! each. `repo.rs` lists those descriptors once, and every kind list,
//! check, and opener is read from that list, so adding a server is one new
//! module plus one line.
//!
//! ```text
//!   repo.rs  SERVERS --+--> nexus::KINDS    source "nexus", target "nexus-raw", ...
//!                      +--> maven::KINDS    source "maven", target "maven", ...
//!                      +--> ...
//! ```
//!
//! Proxies are not here: they open from upstreams rather than from a URL,
//! and keep their own lists in [`super::proxy`].

use std::sync::Arc;

use super::enumerate::{Enumerator, Login};
use super::{Mapping, NameMap, Source, Target, Trust, VersionScheme, local_dir, manager};
use crate::core::error::Result;
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;

/// Opens a source from its base URL.
pub(in crate::repo) type OpenSource =
    fn(&str, &Options, Arc<dyn ExtHost>, Trust) -> Result<Arc<dyn Source>>;

/// Opens a source whose names a [`NameMap`] maps.
pub(in crate::repo) type OpenNamed =
    fn(&str, &Options, NameMap, Arc<dyn ExtHost>) -> Result<Arc<dyn Source>>;

/// Opens a target from its base URL.
pub(in crate::repo) type OpenTarget =
    fn(&str, &Options, Arc<dyn ExtHost>) -> Result<Arc<dyn Target>>;

/// Opens an enumerator from its base URL.
pub(in crate::repo) type OpenEnumerator =
    fn(&str, &Options, Arc<dyn ExtHost>) -> Result<Arc<dyn Enumerator>>;

/// Everything one server module offers.
pub(in crate::repo) struct Kinds {
    pub(in crate::repo) source: Option<SourceKind>,
    pub(in crate::repo) target: Option<TargetKind>,
    pub(in crate::repo) enumerators: &'static [EnumeratorKind],
}

/// A source kind.
pub(in crate::repo) struct SourceKind {
    pub(in crate::repo) name: &'static str,
    pub(in crate::repo) open: OpenSource,

    /// Refuses options that could never open, without building the source.
    pub(in crate::repo) check: fn(&Options) -> Result<()>,

    /// How `names` is read, for the kinds that read it.
    pub(in crate::repo) names: Option<Names>,

    /// Whose version scheme applies.
    pub(in crate::repo) versions: Versions,
}

/// How a source kind reads `names`.
pub(in crate::repo) struct Names {
    pub(in crate::repo) open: OpenNamed,

    /// Refuses names that could never be read.
    pub(in crate::repo) check: fn(&Options, &NameMap) -> Result<()>,
}

/// A target kind.
pub(in crate::repo) struct TargetKind {
    pub(in crate::repo) name: &'static str,
    pub(in crate::repo) open: OpenTarget,
}

/// An enumerator kind.
pub(in crate::repo) struct EnumeratorKind {
    pub(in crate::repo) name: &'static str,
    pub(in crate::repo) open: OpenEnumerator,

    /// Refuses configuration that could never walk, without building it.
    pub(in crate::repo) check: fn(&str, &Options) -> Result<()>,

    /// Whether the walk needs its host to log in.
    pub(in crate::repo) login: fn(&Options) -> Result<Login>,

    /// The ecosystem whose own protocol this walks, if any. The kind a
    /// login-bound server's advice points to instead.
    pub(in crate::repo) native_for: Option<&'static str>,
}

/// Whose version scheme a source kind's versions follow.
///
/// See [`super::version_scheme`] for why this is a property of the kind.
#[derive(Clone, Copy)]
pub(in crate::repo) enum Versions {
    /// The ecosystem's, always.
    Fixed,

    /// The user's, always.
    Declared,

    /// The user's under `ecosystem: raw` and `mapping: name-version-file`.
    RawMapping,

    /// The user's under `mapping: name-version-file`.
    DirectoryMapping,
}

impl Versions {
    /// The scheme a source configured with `options` follows.
    pub(in crate::repo) fn scheme(self, options: &Options) -> VersionScheme {
        let declared = match self {
            Versions::Fixed => false,
            Versions::Declared => true,
            Versions::RawMapping => raw_name_version_file(options),
            Versions::DirectoryMapping => directory_name_version_file(options),
        };

        if declared {
            return VersionScheme::Declared;
        }

        VersionScheme::Fixed
    }

    /// When kind `name` accepts a `version-handler`, for a message that
    /// lists them. `None` for a kind that never does.
    pub(in crate::repo) fn describe(self, name: &str) -> Option<String> {
        let mapping = Mapping::NameVersionFile.as_str();

        match self {
            Versions::Fixed => None,
            Versions::Declared => Some(name.to_owned()),
            Versions::RawMapping => Some(format!(
                "{name} with 'ecosystem: raw' and 'mapping: {mapping}'"
            )),
            Versions::DirectoryMapping => Some(format!("{name} with 'mapping: {mapping}'")),
        }
    }
}

/// Whether a repository manager holds raw files under `name-version-file`.
///
/// A misspelled mapping reads as unversioned here; `validate-config`
/// refuses the spelling on its own.
fn raw_name_version_file(options: &Options) -> bool {
    options
        .ecosystem()
        .ok()
        .flatten()
        .filter(|ecosystem| ecosystem.as_str() == EcosystemId::RAW)
        .and_then(|ecosystem| manager::raw_mapping(options, &ecosystem).ok())
        .is_some_and(|mapping| mapping == Mapping::NameVersionFile)
}

/// Whether a directory is mapped `name-version-file`. A directory is raw
/// whatever its options say.
fn directory_name_version_file(options: &Options) -> bool {
    options
        .string(local_dir::MAPPING)
        .ok()
        .flatten()
        .and_then(|text| Mapping::parse(text).ok())
        == Some(Mapping::NameVersionFile)
}

impl SourceKind {
    /// A source kind with no option check, no names, and a fixed scheme.
    pub(in crate::repo) const fn new(name: &'static str, open: OpenSource) -> Self {
        Self {
            name,
            open,
            check: accept,
            names: None,
            versions: Versions::Fixed,
        }
    }

    pub(in crate::repo) const fn checked(mut self, check: fn(&Options) -> Result<()>) -> Self {
        self.check = check;
        self
    }

    pub(in crate::repo) const fn named(mut self, names: Names) -> Self {
        self.names = Some(names);
        self
    }

    pub(in crate::repo) const fn versions(mut self, versions: Versions) -> Self {
        self.versions = versions;
        self
    }
}

impl EnumeratorKind {
    /// An enumerator kind with no check, an optional login, and no ecosystem.
    pub(in crate::repo) const fn new(name: &'static str, open: OpenEnumerator) -> Self {
        Self {
            name,
            open,
            check: accept_any,
            login: optional,
            native_for: None,
        }
    }

    pub(in crate::repo) const fn checked(
        mut self,
        check: fn(&str, &Options) -> Result<()>,
    ) -> Self {
        self.check = check;
        self
    }

    pub(in crate::repo) const fn login(mut self, login: fn(&Options) -> Result<Login>) -> Self {
        self.login = login;
        self
    }

    pub(in crate::repo) const fn native_for(mut self, ecosystem: &'static str) -> Self {
        self.native_for = Some(ecosystem);
        self
    }
}

fn accept(_: &Options) -> Result<()> {
    Ok(())
}

fn accept_any(_: &str, _: &Options) -> Result<()> {
    Ok(())
}

fn optional(_: &Options) -> Result<Login> {
    Ok(Login::Optional)
}
