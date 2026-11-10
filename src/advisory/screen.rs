//! Screening one artifact against the loaded corpora.
//!
//! ```text
//!   index.advisories(id) --verdict(version)--> Affected | Unknown
//!         --Screening::answer--> VEX statement, if any
//!         --SecurityPolicy::screen--> Finding --> problem + Flag
//! ```
//!
//! Called by the walk for every versioned artifact, and by `find` for
//! every versioned artifact an enumerator lists. The problem is reported under
//! the caller's context, which is narrowed to the artifact, so a
//! per-artifact quarantine rule can excuse a finding for one artifact.

use std::path::Path;

use crate::core::ctx::Ctx;
use crate::core::problem::Code;
use crate::core::screened::{Category, Certainty, Flag};
use crate::message;
use crate::model::{ArtifactId, Version};
use crate::policy::{Finding, SecurityPolicy};
use crate::version::VersionHandler;

use super::index::{Index, Listing};
use super::matching::Match;
use super::screening::Screening;

/// What an artifact is screened against, for one run.
#[derive(Debug, Clone, Copy)]
pub struct Screen<'a> {
    pub index: &'a Index,
    pub screening: &'a Screening,
}

/// The security policy an artifact answers to, and the file it came from.
///
/// `None` in place of one screens under [`SecurityPolicy::default`]:
/// malware forbidden, vulnerabilities reported. Configuring an advisor is
/// enough to screen.
pub type Policed<'a> = Option<(&'a Path, &'a SecurityPolicy)>;

impl Screen<'_> {
    /// Screen one artifact, report each unsuppressed finding, and return
    /// every advisory that named it.
    pub fn artifact(
        &self,
        id: &ArtifactId,
        version: &Version,
        handler: &dyn VersionHandler,
        policed: Policed<'_>,
        ctx: &Ctx,
    ) -> Vec<Flag> {
        let purl = id.purl_at(version.text());
        let fallback = SecurityPolicy::default();
        let policy = policed.map_or(&fallback, |(_, policy)| policy);

        // Before any advisory, so a statement about this artifact that
        // answers nothing can later be called stale.
        self.screening.screened(&purl);

        let mut flags = Vec::new();

        for listing in self.index.advisories(id) {
            let certainty = match listing.verdict(version, handler) {
                Match::Unaffected => continue,
                Match::Affected => Certainty::Affected,
                Match::Unknown => Certainty::VersionUnusable,
            };

            let advisory = listing.advisory();
            let answer = self
                .screening
                .answer(&purl, &advisory.id, &advisory.aliases);
            let finding = policy.screen(&advisory.id, advisory.is_malware(), answer.as_ref());

            let flag = flagged(listing, certainty, &finding);

            // A suppression is the decision, so it is recorded and raises
            // nothing.
            if flag.suppressed_by.is_none() {
                report(&purl, &flag, &finding, ctx);
            }

            if certainty == Certainty::Affected && !advisory.is_malware() {
                self.incomplete(&purl, &flag, &advisory.aliases, ctx);
            }

            flags.push(flag);
        }

        flags
    }

    /// Report each VEX document that covers `purl` and says nothing about a
    /// vulnerability found against it: written before the advisory, so out
    /// of date. Malware is left out, since a VEX document triages
    /// vulnerabilities.
    fn incomplete(&self, purl: &str, flag: &Flag, aliases: &[String], ctx: &Ctx) {
        for document in self.screening.incomplete(purl, &flag.id, aliases) {
            ctx.report(
                Code::VexIncomplete,
                message!(
                    "vex-incomplete",
                    "{document} covers {purl} and says nothing about {id}, which \
                     {advisor} lists against it",
                    document = &document,
                    purl = purl,
                    id = &flag.id,
                    advisor = &flag.advisor,
                ),
            );
        }
    }
}

fn flagged(listing: &Listing, certainty: Certainty, finding: &Finding) -> Flag {
    let advisory = listing.advisory();

    Flag {
        advisor: listing.advisor().to_owned(),
        category: match advisory.is_malware() {
            true => Category::Malware,
            false => Category::Vulnerability,
        },
        id: advisory.id.clone(),
        summary: advisory.summary.clone(),
        certainty,
        suppressed_by: finding.suppressed_by.clone(),
    }
}

/// Report one unsuppressed finding.
///
/// An undecidable version is its own code whatever the policy's stance: the
/// stance is about a known finding, and this one is not known.
fn report(purl: &str, flag: &Flag, finding: &Finding, ctx: &Ctx) {
    if flag.certainty == Certainty::VersionUnusable {
        ctx.report(
            Code::AdvisoryVersionUnusable,
            message!(
                "advisory-version-unusable",
                "{advisor} lists {id} ({category}) against {purl}, and no version \
                 in it can be compared with this one",
                advisor = &flag.advisor,
                id = &flag.id,
                category = flag.category.as_str(),
                purl = purl,
            ),
        );

        return;
    }

    let message = message!(
        "advisory-affected",
        "{advisor} lists {id} ({category}) against {purl}",
        advisor = &flag.advisor,
        id = &flag.id,
        category = flag.category.as_str(),
        purl = purl,
    );

    match finding.floor {
        Some(floor) => ctx.report_at_least(finding.problem, floor, message),
        None => ctx.report(finding.problem, message),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::advisory::Ecosystems;
    use crate::core::problem::Action;
    use crate::core::screened::Suppression;
    use crate::model::EcosystemId;
    use crate::policy::{Statement, Status};

    const POLICY: &str = "security.json";
    const VEX: &str = "vex.json";

    /// A record naming npm `tuna`, affecting versions below 2.0.0.
    fn record(id: &str) -> crate::advisory::Advisory {
        serde_json::from_str(&format!(
            r#"{{"id":"{id}","modified":"2024-06-01T00:00:00Z",
                "affected":[{{"package":{{"ecosystem":"npm","name":"tuna"}},
                  "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"2.0.0"}}]}}]}}]}}"#
        ))
        .expect("record")
    }

    /// A record naming `tuna` whose only range is in commit hashes.
    fn git_only(id: &str) -> crate::advisory::Advisory {
        serde_json::from_str(&format!(
            r#"{{"id":"{id}","affected":[{{"package":{{"ecosystem":"npm","name":"tuna"}},
                  "ranges":[{{"type":"GIT","repo":"r","events":[{{"introduced":"abc"}}]}}]}}]}}"#
        ))
        .expect("record")
    }

    fn index(records: Vec<crate::advisory::Advisory>) -> Index {
        let mut index = Index::new(Ecosystems::builtin());

        index.attributing("feed");

        for record in records {
            index.insert(record);
        }

        index
    }

    fn tuna() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "tuna")
    }

    /// Screen `tuna` at `version`, answering the flags and the context the
    /// problems were reported through.
    fn screened(index: &Index, version: &str, policy: Policed<'_>) -> (Vec<Flag>, Ctx, Screening) {
        attested(index, version, policy, Vec::new())
    }

    /// [`screened`], with VEX statements a lock file made.
    fn attested(
        index: &Index,
        version: &str,
        policy: Policed<'_>,
        statements: Vec<Statement>,
    ) -> (Vec<Flag>, Ctx, Screening) {
        let npm = crate::ecosystem::open(EcosystemId::NPM).expect("npm");
        let version = npm.version(version);
        let screening = Screening::none();
        screening.attest(statements);
        let ctx = Ctx::anonymous_for_test().for_artifact(tuna(), Some(version.clone()));

        let flags = Screen {
            index,
            screening: &screening,
        }
        .artifact(&tuna(), &version, npm.as_ref(), policy, &ctx);

        (flags, ctx, screening)
    }

    fn count(ctx: &Ctx, code: Code) -> u64 {
        ctx.problems().counts().get(&code).copied().unwrap_or(0)
    }

    #[test]
    fn malware_flagged_skipped() {
        let index = index(vec![record("MAL-2024-1")]);

        let (flags, ctx, _) = screened(&index, "1.0.0", None);

        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].advisor, "feed");
        assert_eq!(flags[0].category, Category::Malware);
        assert_eq!(flags[0].certainty, Certainty::Affected);
        assert_eq!(count(&ctx, Code::MalwareKnown), 1);
        assert_eq!(ctx.problems().worst(), Some(Action::SkipArtifact));
    }

    #[test]
    fn version_unaffected_not_flagged() {
        let index = index(vec![record("MAL-2024-1")]);

        let (flags, ctx, _) = screened(&index, "2.0.0", None);

        assert!(flags.is_empty());
        assert_eq!(ctx.problems().worst(), None);
    }

    /// Not knowing is held back, for malware and vulnerabilities alike.
    #[test]
    fn version_uncomparable_held_back() {
        let index = index(vec![git_only("GHSA-1")]);

        let (flags, ctx, _) = screened(&index, "1.0.0", None);

        assert_eq!(flags[0].certainty, Certainty::VersionUnusable);
        assert_eq!(count(&ctx, Code::AdvisoryVersionUnusable), 1);
        assert_eq!(ctx.problems().worst(), Some(Action::SkipArtifact));
    }

    #[test]
    fn vulnerability_warns_by_default() {
        let index = index(vec![record("GHSA-1")]);

        let (flags, ctx, _) = screened(&index, "1.0.0", None);

        assert_eq!(flags[0].category, Category::Vulnerability);
        assert_eq!(count(&ctx, Code::VulnerabilityKnown), 1);
        assert_eq!(ctx.problems().worst(), Some(Action::Warn));
    }

    fn statement(vulnerability: &str, status: Status) -> Statement {
        Statement {
            vulnerability: vulnerability.to_owned(),
            products: vec!["pkg:npm/tuna@1.0.0".to_owned()],
            status,
            justification: Some("vulnerable_code_not_present".to_owned()),
            detail: None,
            source: VEX.to_owned(),
        }
    }

    /// A suppression is the decision: recorded, and nothing raised.
    #[test]
    fn finding_suppressed_recorded_only() {
        let index = index(vec![record("GHSA-1")]);

        let (flags, ctx, screening) = attested(
            &index,
            "1.0.0",
            None,
            vec![statement("GHSA-1", Status::NotAffected)],
        );

        assert_eq!(
            flags[0].suppressed_by,
            Some(Suppression {
                justification: Some("vulnerable_code_not_present".to_owned()),
                detail: None,
                source: VEX.to_owned(),
            })
        );
        assert_eq!(ctx.problems().worst(), None);
        assert!(
            screening.stale().is_empty(),
            "the statement answered, so it is live"
        );
    }

    /// A statement that answered nothing is dead policy, whether or not any
    /// advisory came back.
    #[test]
    fn statement_unanswering_stale() {
        let index = index(Vec::new());

        let (_, _, screening) = attested(
            &index,
            "1.0.0",
            None,
            vec![statement("GHSA-9", Status::NotAffected)],
        );

        assert_eq!(screening.stale(), [format!("{VEX}#GHSA-9")]);
    }

    /// A document covering `tuna` and silent about the advisory found
    /// against it is out of date; the finding is still reported.
    #[test]
    fn document_silent_incomplete() {
        let index = index(vec![record("GHSA-1")]);

        let (_, ctx, _) = attested(
            &index,
            "1.0.0",
            None,
            vec![statement("GHSA-9", Status::NotAffected)],
        );

        assert_eq!(count(&ctx, Code::VexIncomplete), 1);
        assert_eq!(count(&ctx, Code::VulnerabilityKnown), 1);
    }

    #[test]
    fn document_none_not_incomplete() {
        let index = index(vec![record("GHSA-1")]);

        let (_, ctx, _) = screened(&index, "1.0.0", None);

        assert_eq!(count(&ctx, Code::VexIncomplete), 0);
    }

    /// `vulnerabilities: forbid` escalates the finding it does not rename.
    #[test]
    fn vulnerability_forbidden_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(POLICY);

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","vulnerabilities":"forbid"}}"#,
                crate::policy::SECURITY_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let policy = SecurityPolicy::load(&path).expect("loads");
        let index = index(vec![record("GHSA-1")]);

        let (_, ctx, _) = screened(&index, "1.0.0", Some((&path, &policy)));

        assert_eq!(count(&ctx, Code::VulnerabilityKnown), 1);
        assert_eq!(count(&ctx, Code::LicenseForbidden), 0);
        assert_eq!(ctx.problems().worst(), Some(Action::SkipArtifact));
    }
}
