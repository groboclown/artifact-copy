//! Turning a source's names into the artifact names a request uses.
//!
//! A source names what it holds its own way -- GitHub as `owner/repo` at a
//! tag -- and the user may want the artifact under another name. A rule
//! says how, with one `*` per side carrying the varying part across:
//!
//! ```text
//!   from: gitleaks/gitleaks @ v*        source name, tag pattern
//!   to:   tools/gitleaks    @ *         artifact name, version pattern
//!
//!   gitleaks/gitleaks@v8.18.0  <->  tools/gitleaks@8.18.0
//! ```
//!
//! **A request names the artifact side**, and the source maps it back, so
//! the mapped purl is the artifact's only identity: the report, quarantine
//! rules, and a target's holdings never see the source name.
//!
//! **A mapped source name is unreachable as itself.** Once a rule names
//! `gitleaks/gitleaks`, asking for it directly is refused, and its tags no
//! rule matches are hidden, so one release cannot land under two names.
//! A source name no rule mentions passes through unchanged.
//!
//! **Every rule is consulted.** Two rules may feed one artifact name, and a
//! request more than one of them answers is refused as ambiguous rather
//! than settled by rule order: a write decided by which rule came first is
//! a write nobody chose.
//!
//! # Why not a regular expression
//!
//! For the reason `raw::Mapping` gives, and one more: a rule here decides
//! where a write lands. One `*` per side is always reversible and cannot be
//! written to match more than its author meant.

use crate::config::{NamePattern, NameRule};
use crate::core::error::{Error, Result};

/// What carries the varying part of a version across a rule.
const WILDCARD: char = '*';

/// What a raw coordinate splits its version off at, and so what a mapped
/// version may not hold.
const VERSION_SEPARATOR: char = '@';

/// How a source compares its own names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NameCase {
    /// `Tools/CLI` and `tools/cli` differ, as on a raw repository.
    #[default]
    Exact,

    /// `GitLeaks` is `gitleaks`, as GitHub resolves names.
    Insensitive,
}

/// What a lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The name and version on the other side. The version is `None` when
    /// none was asked for.
    Mapped {
        name: String,
        version: Option<String>,
    },

    /// No rule mentions the name, so it stands as it is.
    Unmapped,

    /// A rule mentions the name and none admits this request.
    Refused(String),

    /// More than one rule admits it, each described as configured.
    Ambiguous(Vec<String>),
}

/// A version pattern: literal, or a prefix and suffix around one `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Glob {
    prefix: String,

    /// `None` for a literal.
    suffix: Option<String>,
}

impl Glob {
    /// Absent is `*`, which carries the whole version.
    fn parse(text: Option<&str>) -> std::result::Result<Self, &'static str> {
        let text = text.unwrap_or("*");

        let Some((prefix, suffix)) = text.split_once(WILDCARD) else {
            return Ok(Self {
                prefix: text.to_owned(),
                suffix: None,
            });
        };

        if suffix.contains(WILDCARD) {
            return Err("holds more than one '*'");
        }

        Ok(Self {
            prefix: prefix.to_owned(),
            suffix: Some(suffix.to_owned()),
        })
    }

    fn is_wild(&self) -> bool {
        self.suffix.is_some()
    }

    /// What `*` matched in `text`; empty for a literal that matched.
    ///
    /// ```text
    ///   v*      v8.18.0  ->  8.18.0
    ///   v*-bin  v1-bin   ->  1
    ///   v*      8.18.0   ->  no match
    /// ```
    fn capture<'t>(&self, text: &'t str) -> Option<&'t str> {
        let Some(suffix) = &self.suffix else {
            return (text == self.prefix).then_some("");
        };

        // Checked first so a prefix and suffix cannot overlap: `a*a`
        // does not match `a`.
        if text.len() < self.prefix.len() + suffix.len() {
            return None;
        }

        text.strip_prefix(self.prefix.as_str())?
            .strip_suffix(suffix.as_str())
    }

    fn fill(&self, captured: &str) -> String {
        match &self.suffix {
            Some(suffix) => format!("{}{captured}{suffix}", self.prefix),
            None => self.prefix.clone(),
        }
    }

    fn describe(&self) -> String {
        self.fill("*")
    }
}

/// One configured rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    from_name: String,
    from_version: Glob,
    to_name: String,
    to_version: Glob,
}

impl Rule {
    fn describe(&self) -> String {
        format!(
            "{}@{} -> {}@{}",
            self.from_name,
            self.from_version.describe(),
            self.to_name,
            self.to_version.describe()
        )
    }
}

/// A source's configured rules.
#[derive(Debug, Clone, Default)]
pub struct NameMap {
    rules: Vec<Rule>,
    case: NameCase,
}

impl NameMap {
    /// Read and check the `names` rules.
    pub fn parse(rules: &[NameRule]) -> Result<Self> {
        let mut out: Vec<Rule> = Vec::new();

        for (index, configured) in rules.iter().enumerate() {
            let rule = rule(configured)
                .map_err(|why| Error::Config(format!("'names' entry {index} {why}")))?;

            if out.contains(&rule) {
                return Err(Error::Config(format!(
                    "'names' entry {index} repeats {}",
                    rule.describe()
                )));
            }

            out.push(rule);
        }

        Ok(Self {
            rules: out,
            case: NameCase::default(),
        })
    }

    /// Compare source names this way.
    pub fn comparing(mut self, case: NameCase) -> Self {
        self.case = case;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every source name a rule mentions, as configured.
    pub fn source_names(&self) -> Vec<&str> {
        self.rules
            .iter()
            .map(|rule| rule.from_name.as_str())
            .collect()
    }

    /// The source name and tag a request for `name` at `version` reads.
    ///
    /// ```text
    ///   tools/gitleaks@8.18.0  ->  Mapped gitleaks/gitleaks@v8.18.0
    ///   tools/gitleaks         ->  Mapped gitleaks/gitleaks, any tag
    ///   gitleaks/gitleaks      ->  Refused, request tools/gitleaks
    ///   other/thing            ->  Unmapped
    /// ```
    ///
    /// A versionless request is ambiguous whenever two rules share its
    /// name, since there is no version to tell them apart.
    pub fn to_source(&self, name: &str, version: Option<&str>) -> Lookup {
        let named: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| rule.to_name == name)
            .collect();

        if named.is_empty() {
            return self.unmapped_as(name);
        }

        let Some(version) = version else {
            return match named.as_slice() {
                [only] => Lookup::Mapped {
                    name: only.from_name.clone(),
                    version: None,
                },

                _ => ambiguous(&named),
            };
        };

        let admitting: Vec<(&Rule, &str)> = named
            .iter()
            .filter_map(|rule| Some((*rule, rule.to_version.capture(version)?)))
            .collect();

        match admitting.as_slice() {
            [] => Lookup::Refused(format!(
                "{name}@{version} matches no version pattern for {name} ({})",
                patterns(&named, |rule| &rule.to_version)
            )),

            [(rule, captured)] => Lookup::Mapped {
                name: rule.from_name.clone(),
                version: Some(rule.from_version.fill(captured)),
            },

            _ => ambiguous(&admitting.iter().map(|(rule, _)| *rule).collect::<Vec<_>>()),
        }
    }

    /// The version a source's `tag` of `source` is, as artifact `name`.
    ///
    /// Only rules from `source` to `name` are consulted: the request has
    /// already chosen which artifact it is about.
    pub fn to_artifact(&self, source: &str, tag: &str, name: &str) -> Lookup {
        let named: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| self.same_source(&rule.from_name, source) && rule.to_name == name)
            .collect();

        if named.is_empty() {
            return self.unmapped_as(source);
        }

        let admitting: Vec<(&Rule, &str)> = named
            .iter()
            .filter_map(|rule| Some((*rule, rule.from_version.capture(tag)?)))
            .collect();

        match admitting.as_slice() {
            [] => Lookup::Refused(format!(
                "{source} tag {tag} matches no tag pattern for {name} ({})",
                patterns(&named, |rule| &rule.from_version)
            )),

            [(rule, captured)] => Lookup::Mapped {
                name: rule.to_name.clone(),
                version: Some(rule.to_version.fill(captured)),
            },

            _ => ambiguous(&admitting.iter().map(|(rule, _)| *rule).collect::<Vec<_>>()),
        }
    }

    /// `Unmapped`, unless a rule maps `name` away as a source name.
    fn unmapped_as(&self, name: &str) -> Lookup {
        let targets: Vec<&str> = self
            .rules
            .iter()
            .filter(|rule| self.same_source(&rule.from_name, name))
            .map(|rule| rule.to_name.as_str())
            .collect();

        if targets.is_empty() {
            return Lookup::Unmapped;
        }

        Lookup::Refused(format!(
            "{name} is mapped by 'names'; request it as {}",
            targets.join(" or ")
        ))
    }

    fn same_source(&self, left: &str, right: &str) -> bool {
        match self.case {
            NameCase::Exact => left == right,
            NameCase::Insensitive => left.to_lowercase() == right.to_lowercase(),
        }
    }
}

/// One configured rule, refused where it could not be reversed or could
/// produce a version no request can name.
fn rule(configured: &NameRule) -> std::result::Result<Rule, String> {
    let NameRule { from, to } = configured;

    let from_version = glob(from, "from")?;
    let to_version = glob(to, "to")?;

    if from_version.is_wild() != to_version.is_wild() {
        return Err("needs a '*' in both versions or in neither".to_owned());
    }

    if to_version.describe().contains(VERSION_SEPARATOR) {
        return Err(format!(
            "has '{VERSION_SEPARATOR}' in 'to.version', which a raw coordinate could never name"
        ));
    }

    Ok(Rule {
        from_name: name(from, "from")?,
        from_version,
        to_name: name(to, "to")?,
        to_version,
    })
}

fn name(side: &NamePattern, label: &str) -> std::result::Result<String, String> {
    let trimmed = side.name.trim().trim_matches('/');

    if trimmed.is_empty() {
        return Err(format!("has an empty '{label}.name'"));
    }

    if trimmed.contains(WILDCARD) {
        return Err(format!(
            "has a '*' in '{label}.name', which must be literal"
        ));
    }

    Ok(trimmed.to_owned())
}

fn glob(side: &NamePattern, label: &str) -> std::result::Result<Glob, String> {
    Glob::parse(side.version.as_deref()).map_err(|why| format!("'{label}.version' {why}"))
}

fn ambiguous(rules: &[&Rule]) -> Lookup {
    Lookup::Ambiguous(rules.iter().map(|rule| rule.describe()).collect())
}

fn patterns(rules: &[&Rule], side: impl Fn(&Rule) -> &Glob) -> String {
    rules
        .iter()
        .map(|rule| side(rule).describe())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side(name: &str, version: Option<&str>) -> NamePattern {
        NamePattern {
            name: name.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    /// A name and an optional version pattern, as a test writes one side.
    type Side<'a> = (&'a str, Option<&'a str>);

    fn map(rules: &[(Side, Side)]) -> Result<NameMap> {
        let rules: Vec<NameRule> = rules
            .iter()
            .map(|((from, from_version), (to, to_version))| NameRule {
                from: side(from, *from_version),
                to: side(to, *to_version),
            })
            .collect();

        NameMap::parse(&rules)
    }

    fn gitleaks() -> NameMap {
        map(&[(
            ("gitleaks/gitleaks", Some("v*")),
            ("tools/gitleaks", Some("*")),
        )])
        .expect("parses")
    }

    fn mapped(name: &str, version: Option<&str>) -> Lookup {
        Lookup::Mapped {
            name: name.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    #[test]
    fn glob_capture_and_fill() {
        let wild = Glob::parse(Some("v*-bin")).expect("parses");

        assert_eq!(wild.capture("v1.0-bin"), Some("1.0"));
        assert_eq!(wild.capture("v1.0"), None);
        assert_eq!(wild.fill("2.0"), "v2.0-bin");

        let literal = Glob::parse(Some("nightly")).expect("parses");

        assert_eq!(literal.capture("nightly"), Some(""));
        assert_eq!(literal.capture("nightly2"), None);
        assert_eq!(literal.fill(""), "nightly");

        // A prefix and suffix may not overlap.
        assert_eq!(Glob::parse(Some("a*a")).expect("parses").capture("a"), None);

        // Absent carries the whole version.
        assert_eq!(Glob::parse(None).expect("parses").capture("v1"), Some("v1"));
    }

    #[test]
    fn rule_malformed_refused() {
        let cases = [
            (("o/r", Some("v**")), ("t/r", Some("*"))),
            (("o/r", Some("v*")), ("t/r", Some("1.0"))),
            (("o/r", Some("v1")), ("t/r", Some("*"))),
            (("o/r", None), ("t/r", Some("x@*"))),
            (("", None), ("t/r", None)),
            (("o/r", None), ("/", None)),
            (("o/*", None), ("t/r", None)),
        ];

        for case in cases {
            assert!(map(&[case]).is_err(), "{case:?}");
        }
    }

    #[test]
    fn rule_repeated_refused() {
        let rule = (("o/r", Some("v*")), ("t/r", Some("*")));

        assert!(map(&[rule, rule]).is_err());
    }

    #[test]
    fn request_maps_to_source() {
        let names = gitleaks();

        assert_eq!(
            names.to_source("tools/gitleaks", Some("8.18.0")),
            mapped("gitleaks/gitleaks", Some("v8.18.0"))
        );
        assert_eq!(
            names.to_source("tools/gitleaks", None),
            mapped("gitleaks/gitleaks", None)
        );
    }

    #[test]
    fn tag_maps_to_artifact() {
        let names = gitleaks();

        assert_eq!(
            names.to_artifact("gitleaks/gitleaks", "v8.18.0", "tools/gitleaks"),
            mapped("tools/gitleaks", Some("8.18.0"))
        );
        assert!(matches!(
            names.to_artifact("gitleaks/gitleaks", "nightly", "tools/gitleaks"),
            Lookup::Refused(_)
        ));
    }

    #[test]
    fn round_trip() {
        let names = gitleaks();

        let Lookup::Mapped { name, version } = names.to_source("tools/gitleaks", Some("1.2"))
        else {
            panic!("mapped");
        };

        assert_eq!(
            names.to_artifact(&name, version.as_deref().expect("tag"), "tools/gitleaks"),
            mapped("tools/gitleaks", Some("1.2"))
        );
    }

    /// One release must not land under two names.
    #[test]
    fn source_name_mapped_refused() {
        let names = gitleaks();

        assert!(matches!(
            names.to_source("gitleaks/gitleaks", None),
            Lookup::Refused(_)
        ));

        // Exact by default: the source's case rule is the source's to set.
        assert_eq!(names.to_source("GitLeaks/GitLeaks", None), Lookup::Unmapped);

        let names = gitleaks().comparing(NameCase::Insensitive);

        let Lookup::Refused(why) = names.to_source("GitLeaks/GitLeaks", None) else {
            panic!("refused");
        };

        assert!(why.contains("tools/gitleaks"), "{why}");
    }

    #[test]
    fn unmentioned_name_passes_through() {
        assert_eq!(
            gitleaks().to_source("other/thing", Some("v1")),
            Lookup::Unmapped
        );
        assert_eq!(
            gitleaks().to_artifact("other/thing", "v1", "other/thing"),
            Lookup::Unmapped
        );
    }

    #[test]
    fn version_unmatched_refused() {
        let names = map(&[(("o/r", Some("v*")), ("t/r", Some("*-bin")))]).expect("parses");

        assert!(matches!(
            names.to_source("t/r", Some("1.0")),
            Lookup::Refused(_)
        ));
    }

    /// The destination can come from either repository.
    #[test]
    fn ambiguous_shared_destination() {
        let names = map(&[
            (("a/x", Some("v*")), ("tools/x", Some("*"))),
            (("b/x", Some("*")), ("tools/x", Some("*"))),
        ])
        .expect("parses");

        let Lookup::Ambiguous(rules) = names.to_source("tools/x", Some("1.0")) else {
            panic!("ambiguous");
        };

        assert_eq!(rules, ["a/x@v* -> tools/x@*", "b/x@* -> tools/x@*"]);
        assert!(matches!(
            names.to_source("tools/x", None),
            Lookup::Ambiguous(_)
        ));
    }

    /// Only the rules that admit the version count.
    #[test]
    fn ambiguous_not_for_disjoint_versions() {
        let names = map(&[
            (("a/x", Some("v*")), ("tools/x", Some("*"))),
            (("a/x", Some("rel-*")), ("tools/x", Some("legacy-*"))),
        ])
        .expect("parses");

        assert_eq!(
            names.to_source("tools/x", Some("1.0")),
            mapped("a/x", Some("v1.0"))
        );

        // `*` admits `legacy-1` too, so that one could come from either.
        assert!(matches!(
            names.to_source("tools/x", Some("legacy-1")),
            Lookup::Ambiguous(_)
        ));
    }

    #[test]
    fn ambiguous_tag_two_rules_match() {
        let names = map(&[
            (("a/x", Some("v*")), ("tools/x", Some("*"))),
            (("a/x", Some("*")), ("tools/x", Some("raw-*"))),
        ])
        .expect("parses");

        assert!(matches!(
            names.to_artifact("a/x", "v1", "tools/x"),
            Lookup::Ambiguous(_)
        ));
    }
}
