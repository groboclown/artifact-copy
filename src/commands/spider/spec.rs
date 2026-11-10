//! What `--dependencies` means, once parsed.
//!
//! The spider is parameterized by these, so they live with it rather than
//! with the argument parser that happens to produce them. `cli` reaches
//! them through `value_parser`, the same way it reaches
//! [`crate::lock::LockSpec`] -- a library whose spider needed `clap` to
//! describe its own settings would have the dependency backwards.

use std::collections::BTreeSet;
use std::fmt;

use crate::model::DepKind;

/// How deep to follow dependencies.
///
/// An enum rather than a `bool`, so a call site says `Depth::Shallow` rather
/// than `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Direct dependencies only.
    Shallow,

    /// Follow the whole graph.
    Deep,
}

/// A parsed `--dependencies` value.
///
/// `runtime+dev`, `all`, `all+shallow`, `none`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiderSpec {
    kinds: BTreeSet<DepKind>,
    all: bool,
    depth: Depth,
}

/// Every kind, whatever the adapter supports.
const ALL_TOKEN: &str = "all";

/// Follow only the first level.
const SHALLOW_TOKEN: &str = "shallow";

/// Follow nothing.
const NONE_TOKEN: &str = "none";

impl SpiderSpec {
    /// Follow nothing.
    pub fn none() -> Self {
        Self {
            kinds: BTreeSet::new(),
            all: false,
            depth: Depth::Deep,
        }
    }

    pub fn depth(&self) -> Depth {
        self.depth
    }

    /// Whether anything at all is to be followed.
    pub fn is_empty(&self) -> bool {
        !self.all && self.kinds.is_empty()
    }

    /// The kinds to follow, narrowed to what this ecosystem actually has.
    ///
    /// `all` means "this adapter's union", which is why it resolves here
    /// rather than at parse time: `test` exists only for Maven and `peer`
    /// only for npm, so there is no ecosystem-independent answer.
    ///
    /// `build` joins any walk at all: a parent POM or an imported BOM is
    /// what resolving the others needs, so following `runtime` without it
    /// would copy dependencies no build could read.
    pub fn resolve(&self, supported: &[DepKind]) -> BTreeSet<DepKind> {
        if self.all {
            return supported.iter().copied().collect();
        }

        let mut kinds: BTreeSet<DepKind> = self
            .kinds
            .iter()
            .copied()
            .filter(|kind| supported.contains(kind))
            .collect();

        if !self.is_empty() && supported.contains(&DepKind::Build) {
            kinds.insert(DepKind::Build);
        }

        kinds
    }

    /// Kinds asked for that this ecosystem does not have.
    ///
    /// Reported as an error rather than silently returning nothing, so
    /// `--dependencies=test` against PyPI says so instead of looking like a
    /// package with no test dependencies.
    pub fn unsupported(&self, supported: &[DepKind]) -> Vec<DepKind> {
        if self.all {
            return Vec::new();
        }

        self.kinds
            .iter()
            .copied()
            .filter(|kind| !supported.contains(kind))
            .collect()
    }

    /// Parse a `--dependencies` value.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut kinds = BTreeSet::new();
        let mut all = false;
        let mut depth = Depth::Deep;
        let mut sought_none = false;

        for token in text.split('+').map(str::trim).filter(|t| !t.is_empty()) {
            match token {
                ALL_TOKEN => all = true,
                SHALLOW_TOKEN => depth = Depth::Shallow,
                NONE_TOKEN => sought_none = true,

                _ => {
                    let kind = DepKind::parse(token).ok_or_else(|| {
                        format!(
                            "unknown dependency kind {token:?}; expected one of \
                             runtime, dev, test, optional, peer, build, all, shallow, none"
                        )
                    })?;

                    kinds.insert(kind);
                }
            }
        }

        if sought_none && (all || !kinds.is_empty()) {
            return Err("'none' cannot be combined with other dependency kinds".into());
        }

        if !sought_none && !all && kinds.is_empty() {
            return Err(format!("{text:?} names no dependency kinds"));
        }

        Ok(Self { kinds, all, depth })
    }
}

impl fmt::Display for SpiderSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();

        if self.all {
            parts.push(ALL_TOKEN.to_owned());
        } else if self.kinds.is_empty() {
            parts.push(NONE_TOKEN.to_owned());
        } else {
            parts.extend(self.kinds.iter().map(|k| k.to_string()));
        }

        if self.depth == Depth::Shallow {
            parts.push(SHALLOW_TOKEN.to_owned());
        }

        f.write_str(&parts.join("+"))
    }
}

/// Defer to the source's configured `dependencies`.
const DEFAULT_TOKEN: &str = "default";

/// Which dependencies a run follows: a stated spec, or the source's own.
///
/// `--dependencies=default`, or no flag at all, is `SourceDefault`; the
/// source's `dependencies` key decides, and a source without one follows
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiderSetting {
    SourceDefault,
    Explicit(SpiderSpec),
}

impl SpiderSetting {
    /// Parse a `--dependencies` value: `default`, or a [`SpiderSpec`].
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.trim() == DEFAULT_TOKEN {
            return Ok(Self::SourceDefault);
        }

        SpiderSpec::parse(text).map(Self::Explicit)
    }

    /// The spec to walk with, given the source's configured default.
    ///
    /// `configured` is the raw `dependencies` value, e.g. `runtime+dev`.
    pub fn resolve(&self, configured: Option<&str>) -> Result<SpiderSpec, String> {
        if let Self::Explicit(spec) = self {
            return Ok(spec.clone());
        }

        match configured {
            Some(text) => SpiderSpec::parse(text),
            None => Ok(SpiderSpec::none()),
        }
    }

    /// Where [`SpiderSetting::resolve`] takes its spec from, given the same
    /// `configured`.
    pub(crate) fn origin(&self, configured: Option<&str>) -> SpecOrigin {
        match (self, configured) {
            (Self::Explicit(_), _) => SpecOrigin::Flag,
            (Self::SourceDefault, Some(_)) => SpecOrigin::Source,
            (Self::SourceDefault, None) => SpecOrigin::Unset,
        }
    }
}

/// Where a walk's [`SpiderSpec`] came from, so a log can say why a walk
/// follows what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecOrigin {
    /// `--dependencies`.
    Flag,

    /// The source's `dependencies` key.
    Source,

    /// Neither said, so nothing is followed.
    Unset,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAVEN: [DepKind; 4] = [
        DepKind::Runtime,
        DepKind::Dev,
        DepKind::Test,
        DepKind::Optional,
    ];
    const PYPI: [DepKind; 2] = [DepKind::Runtime, DepKind::Optional];

    /// A parent POM or an imported BOM joins any walk at all, and none.
    #[test]
    fn spec_build_joins_any_walk() {
        let with_build = [DepKind::Runtime, DepKind::Test, DepKind::Build];

        assert_eq!(
            SpiderSpec::parse("test")
                .expect("parses")
                .resolve(&with_build),
            BTreeSet::from([DepKind::Test, DepKind::Build])
        );
        assert!(SpiderSpec::none().resolve(&with_build).is_empty());
        assert_eq!(
            SpiderSpec::parse("runtime").expect("parses").resolve(&PYPI),
            BTreeSet::from([DepKind::Runtime])
        );
    }

    #[test]
    fn spec_kinds_join_with_plus() {
        let spec = SpiderSpec::parse("runtime+dev").expect("parses");

        assert_eq!(spec.depth(), Depth::Deep);
        assert_eq!(
            spec.resolve(&MAVEN),
            BTreeSet::from([DepKind::Runtime, DepKind::Dev])
        );
    }

    #[test]
    fn spec_shallow_modifier_not_kind() {
        let spec = SpiderSpec::parse("runtime+shallow").expect("parses");

        assert_eq!(spec.depth(), Depth::Shallow);
        assert_eq!(spec.resolve(&MAVEN), BTreeSet::from([DepKind::Runtime]));
    }

    /// `all` means this adapter's union, which differs per ecosystem.
    #[test]
    fn spec_all_resolves_per_ecosystem() {
        let spec = SpiderSpec::parse("all").expect("parses");

        assert_eq!(spec.resolve(&MAVEN).len(), 4);
        assert_eq!(spec.resolve(&PYPI).len(), 2);
        assert!(spec.unsupported(&PYPI).is_empty());
    }

    /// PyPI publishes no test dependencies, so asking for them must say so
    /// rather than return an empty set that reads as "there are none".
    #[test]
    fn spec_unsupported_kinds_reported() {
        let spec = SpiderSpec::parse("test").expect("parses");

        assert_eq!(spec.unsupported(&PYPI), vec![DepKind::Test]);
        assert!(spec.unsupported(&MAVEN).is_empty());
    }

    #[test]
    fn spec_none_follows_nothing() {
        let spec = SpiderSpec::parse("none").expect("parses");

        assert!(spec.is_empty());
        assert!(spec.resolve(&MAVEN).is_empty());
    }

    #[test]
    fn spec_none_cannot_be_combined() {
        assert!(SpiderSpec::parse("none+runtime").is_err());
    }

    #[test]
    fn spec_unknown_kind_names_alternatives() {
        let err = SpiderSpec::parse("runtime+provided").unwrap_err();

        assert!(err.contains("provided"));
        assert!(err.contains("peer"));
    }

    #[test]
    fn spec_round_trips() {
        for text in ["all", "all+shallow", "runtime+dev", "none"] {
            let spec = SpiderSpec::parse(text).expect("parses");
            assert_eq!(spec.to_string(), text);
        }
    }

    #[test]
    fn setting_default_defers_to_source() {
        let setting = SpiderSetting::parse("default").expect("parses");

        assert_eq!(setting, SpiderSetting::SourceDefault);
        assert_eq!(
            setting
                .resolve(Some("runtime"))
                .expect("resolves")
                .to_string(),
            "runtime"
        );
        assert!(setting.resolve(None).expect("resolves").is_empty());
    }

    #[test]
    fn setting_explicit_ignores_source() {
        let setting = SpiderSetting::parse("all").expect("parses");

        assert_eq!(
            setting
                .resolve(Some("runtime"))
                .expect("resolves")
                .to_string(),
            "all"
        );
    }

    #[test]
    fn setting_origin_names_what_decided() {
        let explicit = SpiderSetting::parse("runtime").expect("parses");

        assert_eq!(explicit.origin(Some("all")), SpecOrigin::Flag);
        assert_eq!(
            SpiderSetting::SourceDefault.origin(Some("all")),
            SpecOrigin::Source
        );
        assert_eq!(SpiderSetting::SourceDefault.origin(None), SpecOrigin::Unset);
    }

    #[test]
    fn setting_bad_source_default_refused() {
        assert!(SpiderSetting::SourceDefault.resolve(Some("bogus")).is_err());
    }
}
