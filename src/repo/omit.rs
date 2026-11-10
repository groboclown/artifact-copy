//! What to leave out of a repository's artifacts.
//!
//! Two kinds of omission, applied by one rule set:
//!
//! - **Built in**, per ecosystem: a checksum sidecar, which a target writes
//!   for itself, and Maven's own `maven-metadata.xml` and
//!   `_remote.repositories`. See [`crate::ecosystem::joins_listing`].
//! - **Configured**, as `omit` on a source, an enumerator, or a target:
//!
//! ```yaml
//! omit:
//!   - files: "*.sha256"                          # from every artifact
//!   - purl: "pkg:maven/org.example/broken*"      # whole artifacts
//!   - purl: "pkg:maven/org.example/lib@[1.0,1.2)"
//!     files: "maven-meta.xml"                    # from matching artifacts
//! ```
//!
//! Configured rules only ever omit more: the built-ins encode what a
//! target writes for itself, and no rule brings one of those back.
//!
//! # Applied once per role
//!
//! ```text
//!   enumerator   Omitting wraps every one built   what `find` records
//!   source       Omitting wraps every one built   what `inspect` and `copy` resolve
//!   target       Omitting wraps every one opened  what is uploaded
//! ```
//!
//! A source's omission means the file is never fetched. A target's means
//! it is fetched and verified, and then not sent -- the case for a
//! repository whose own checksum files a target refuses.
//!
//! # Files, not documents
//!
//! An omission decides which files an artifact *has*, never what a source
//! or enumerator *reads* to learn that. Omitting `maven-metadata.xml` or
//! `*.pom` does not stop the Maven source fetching either to find versions,
//! files, and dependencies, nor an enumerator reading a directory index or
//! a packument; it only keeps the file out of the artifact.
//!
//! A configured omission is reported: `file-omitted` (ignored by default,
//! since `*.sha256` can match every artifact) and `artifact-omitted`
//! (a warning). A built-in one is not, as it never was.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use crate::config::OmitRule;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::{Code, Problem};
use crate::internal::purl::pattern::covers;
use crate::message;
use crate::model::{ArtifactId, Version};

mod enumerator;
mod source;
mod target;

pub use enumerator::OmittingEnumerator;
pub use source::OmittingSource;
pub use target::OmittingTarget;

/// What every purl pattern starts with.
const PURL_SCHEME: &str = "pkg:";

/// One checked rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    purl: Option<String>,
    files: Option<String>,
}

impl Rule {
    fn describe(&self) -> String {
        match (&self.purl, &self.files) {
            (Some(purl), Some(files)) => format!("purl {purl}, files {files}"),
            (Some(purl), None) => format!("purl {purl}"),
            (None, Some(files)) => format!("files {files}"),
            (None, None) => String::new(),
        }
    }

    fn covers(&self, id: &ArtifactId, version: Option<&Version>) -> bool {
        let Some(purl) = &self.purl else {
            return true;
        };

        let ecosystem = crate::ecosystem::open(id.ecosystem().as_str()).ok();

        covers(purl, id, version, ecosystem.as_deref())
    }
}

/// Why a file is left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Omission {
    /// The ecosystem says it is not an artifact's file.
    BuiltIn,

    /// A configured rule, as configured.
    Rule(String),
}

/// One entry's configured rules, plus the ecosystem built-ins.
#[derive(Debug, Clone, Default)]
pub struct Omit {
    rules: Vec<Rule>,
}

impl Omit {
    /// Read and check an `omit` list.
    pub fn parse(rules: &[OmitRule]) -> Result<Self> {
        let mut out = Vec::new();

        for (index, configured) in rules.iter().enumerate() {
            let refused = |why: &str| Error::Config(format!("'omit' entry {index} {why}"));

            let OmitRule { purl, files } = configured;

            if purl.is_none() && files.is_none() {
                return Err(refused("names neither 'purl' nor 'files'"));
            }

            if let Some(purl) = purl
                && !purl.starts_with(PURL_SCHEME)
            {
                return Err(refused(&format!(
                    "has purl {purl:?}, which does not start with {PURL_SCHEME:?}"
                )));
            }

            if files.as_deref().is_some_and(str::is_empty) {
                return Err(refused("has an empty 'files'"));
            }

            out.push(Rule {
                purl: purl.clone(),
                files: files.clone(),
            });
        }

        Ok(Self { rules: out })
    }

    /// The rule leaving out the whole artifact, described, if any does.
    pub fn artifact(&self, id: &ArtifactId, version: Option<&Version>) -> Option<String> {
        self.rules
            .iter()
            .filter(|rule| rule.files.is_none())
            .find(|rule| rule.covers(id, version))
            .map(Rule::describe)
    }

    /// Why the file `name` of an artifact is left out, if it is.
    pub fn file(&self, id: &ArtifactId, version: Option<&Version>, name: &str) -> Option<Omission> {
        if !crate::ecosystem::joins_listing(id.ecosystem(), name) {
            return Some(Omission::BuiltIn);
        }

        self.rules
            .iter()
            .filter(|rule| {
                rule.files
                    .as_deref()
                    .is_some_and(|pattern| crate::internal::glob::matches_file_name(pattern, name))
            })
            .find(|rule| rule.covers(id, version))
            .map(|rule| Omission::Rule(rule.describe()))
    }

    /// `files` without those left out, reporting each a rule left out.
    pub fn retain<T>(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        files: Vec<T>,
        name: impl Fn(&T) -> &str,
        ctx: &Ctx,
    ) -> Vec<T> {
        files
            .into_iter()
            .filter(|file| match self.file(id, version, name(file)) {
                None => true,
                Some(Omission::BuiltIn) => false,

                Some(Omission::Rule(rule)) => {
                    ctx.report(
                        Code::FileOmitted,
                        message!(
                            "file-omitted",
                            "{purl}: {file} is left out by the omit rule {rule}",
                            purl = &purl_of(id, version),
                            file = name(file),
                            rule = &rule,
                        ),
                    );

                    false
                }
            })
            .collect()
    }

    /// The problem leaving out a whole artifact, reported under `rule`.
    pub fn omitted(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        rule: &str,
        ctx: &Ctx,
    ) -> Problem {
        ctx.reported(
            Code::ArtifactOmitted,
            message!(
                "artifact-omitted",
                "{purl} is left out by the omit rule {rule}",
                purl = &purl_of(id, version),
                rule = rule,
            ),
        )
    }

    /// The error refusing a whole artifact a rule left out, reported.
    pub fn refusal(
        &self,
        id: &ArtifactId,
        version: Option<&Version>,
        rule: &str,
        ctx: &Ctx,
    ) -> Error {
        let problem = self.omitted(id, version, rule, ctx);

        Error::Unresolvable {
            artifact: purl_of(id, version),
            detail: problem.to_string(),
            problem: Box::new(problem),
        }
    }
}

fn purl_of(id: &ArtifactId, version: Option<&Version>) -> String {
    match version {
        Some(version) => id.purl_at(version.text()),
        None => id.purl(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cause, EcosystemId, Release};

    fn omit(rules: serde_json::Value) -> Result<Omit> {
        let rules: Vec<OmitRule> = serde_json::from_value(rules).expect("rules");

        Omit::parse(&rules)
    }

    fn lib() -> ArtifactId {
        ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
    }

    fn at(text: &str) -> Version {
        Version::new(text, Release::General)
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "lib".into() })
    }

    #[test]
    fn built_ins_follow_ecosystem() {
        let none = Omit::default();
        let raw = ArtifactId::new(EcosystemId::raw(), None, "tools/cli");

        assert_eq!(
            none.file(&lib(), None, "lib-1.0.jar.sha1"),
            Some(Omission::BuiltIn)
        );
        assert_eq!(
            none.file(&lib(), None, "maven-metadata.xml"),
            Some(Omission::BuiltIn)
        );
        assert_eq!(
            none.file(&lib(), None, "_remote.repositories"),
            Some(Omission::BuiltIn)
        );
        assert_eq!(none.file(&lib(), None, "lib-1.0.jar.asc"), None);
        assert_eq!(none.file(&raw, None, "cli.sha256"), None);
    }

    #[test]
    fn rule_file_applies_everywhere() {
        let rules = omit(serde_json::json!([{ "files": "*-javadoc.jar" }])).expect("parses");

        assert!(matches!(
            rules.file(&lib(), Some(&at("1.0")), "lib-1.0-javadoc.jar"),
            Some(Omission::Rule(_))
        ));
        assert_eq!(rules.file(&lib(), Some(&at("1.0")), "lib-1.0.jar"), None);
        assert_eq!(rules.artifact(&lib(), Some(&at("1.0"))), None);
    }

    #[test]
    fn rule_purl_omits_whole_artifacts() {
        let rules = omit(serde_json::json!([{ "purl": "pkg:maven/org.example/lib@[1.0,1.2)" }]))
            .expect("parses");

        assert!(rules.artifact(&lib(), Some(&at("1.1"))).is_some());
        assert!(rules.artifact(&lib(), Some(&at("1.2"))).is_none());

        // A purl rule alone names no file.
        assert_eq!(rules.file(&lib(), Some(&at("1.1")), "lib-1.1.jar"), None);
    }

    #[test]
    fn rule_both_fields_omit_matching_files() {
        let rules = omit(serde_json::json!([{
            "purl": "pkg:maven/org.example/*",
            "files": "maven-meta.xml",
        }]))
        .expect("parses");

        let other = ArtifactId::new(EcosystemId::maven(), Some("org.other"), "lib");

        assert!(rules.file(&lib(), None, "maven-meta.xml").is_some());
        assert_eq!(rules.file(&other, None, "maven-meta.xml"), None);
        assert!(rules.artifact(&lib(), None).is_none());
    }

    #[test]
    fn retain_reports_only_rule_omissions() {
        let rules = omit(serde_json::json!([{ "files": "*.zip" }])).expect("parses");
        let ctx = ctx();

        let kept = rules.retain(
            &lib(),
            None,
            vec!["lib.jar", "lib.jar.sha1", "lib.zip"],
            |name| name,
            &ctx,
        );

        assert_eq!(kept, ["lib.jar"]);
        assert_eq!(ctx.problems().counts()[&Code::FileOmitted], 1);
    }

    #[test]
    fn omit_malformed_refused() {
        for rules in [
            serde_json::json!([{}]),
            serde_json::json!([{ "purl": "maven/org.example/lib" }]),
            serde_json::json!([{ "files": "" }]),
        ] {
            assert!(omit(rules.clone()).is_err(), "{rules}");
        }
    }
}
