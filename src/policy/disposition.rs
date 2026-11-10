//! Deciding what happens about one problem on one artifact.
//!
//! Three inputs, consulted in a fixed order, and the order is the design:
//!
//! 1. The **quarantine policy file**, per artifact and code. The most
//!    specific thing anybody said, and the only one somebody wrote about
//!    *this* artifact.
//! 2. The **`problem-policy` table**, per code. What the rules are for
//!    everything this run touches.
//! 3. The **built-in default** for the code.
//!
//! Then **hardening**, which is not a fourth source but a modifier on the
//! result: it makes soft quarantines stop artifacts.
//!
//! # Why hardening is last, and why it only touches soft
//!
//! A hard quarantine already stops the artifact, and `allowed` and
//! `failure` are not quarantines at all, so there is nothing in the other
//! three for it to act on. Applying it after the sources rather than
//! between them is what makes *this run is strict* mean the same thing
//! whichever source decided the class.
//!
//! **A loosening override survives it.** An artifact whose rule says
//! `allowed` has no quarantine class, so hardening finds nothing to harden
//! -- which is the behaviour wanted, and it falls out of the ordering rather
//! than needing a special case. Somebody who wrote an exception did so
//! precisely for the runs where it matters.
//!
//! An artifact whose rule says `soft` *is* hardened, and that is also
//! right: they asked for soft, and hardening is a statement about what soft
//! means this run. A user who wants it left alone writes `allowed`.

use chrono::{DateTime, Utc};

use crate::core::problem::{
    Action, Bypass, Code, Decide, Disposition, Policy, Quarantine, Ruling, Subject,
};
use crate::model::{ArtifactId, Version};

use super::quarantine::{QuarantinePolicy, Rule};

/// Whether soft quarantines stop artifacts this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Hardening {
    /// Soft flags, hard stops. The default.
    #[default]
    Off,

    /// Soft stops too.
    ///
    /// A blanket, run-scoped switch rather than a reclassification, which
    /// is a different statement: reclassifying a code as `hard` says *this
    /// particular thing is serious* and lasts; hardening says *this run is
    /// strict*, which is what a release pipeline wants without rewriting a
    /// policy table it shares with development runs.
    On,
}

/// What was decided, and who decided it.
#[derive(Debug, Clone)]
pub struct Decided<'p> {
    pub disposition: Disposition,

    /// The per-artifact rule that answered, when one did.
    ///
    /// Carried so a report can say *who* excused this and on what grounds.
    /// A reservation that stopped an artifact is visible in the artifact's
    /// absence; one somebody waved through is visible nowhere else.
    pub rule: Option<&'p Rule>,

    /// Where that rule is written, for a reader who wants to go and look.
    ///
    /// `Some` exactly when `rule` is. Built here rather than left to the
    /// caller because the file and the position are the policy's to know,
    /// and a caller holding only a `&Rule` cannot recover either.
    pub source: Option<String>,

    /// Whether hardening changed the answer.
    ///
    /// Worth reporting separately from the class: "this was soft and the
    /// run was strict" explains a stopped artifact that a bare
    /// `skip-artifact` does not.
    pub hardened: bool,
}

impl Decided<'_> {
    /// The rule that answered, as something a recorded problem can keep.
    ///
    /// Owned, because a `Problem` outlives the policy file it borrowed
    /// from -- it is recorded now and written to a report later.
    pub fn bypass(&self) -> Option<Bypass> {
        let rule = self.rule?;

        Some(Bypass {
            justification: rule.justification.clone(),
            source: self.source.clone().unwrap_or_default(),
            expires: rule.expires.at(),
        })
    }
}

/// The three sources, resolved together.
#[derive(Debug, Default)]
pub struct Dispositions {
    codes: Policy,

    /// Quarantine policy files, **most specific first**.
    ///
    /// More than one because a host may name its own beside the run's: see
    /// `Setup::quarantine_policy` and `Host::quarantine_policy`. Checked in
    /// order and the first rule that answers wins, which is the same rule
    /// that already orders the entries *within* one file -- a reader follows
    /// it down the page, then on to the next page.
    ///
    /// Bounded by the configuration, not by anything a run finds.
    artifacts: Vec<QuarantinePolicy>,

    hardening: Hardening,
}

impl Dispositions {
    /// `artifacts` is the quarantine policy files, **most specific first**:
    /// checked in order, and the first rule that answers wins. That is the
    /// same rule that orders the entries within one file -- a reader follows
    /// it down the page, then on to the next page.
    pub fn new(
        codes: Policy,
        artifacts: impl IntoIterator<Item = QuarantinePolicy>,
        hardening: Hardening,
    ) -> Self {
        Self {
            codes,
            artifacts: artifacts.into_iter().collect(),
            hardening,
        }
    }

    /// Only the per-code half, for a caller with no artifact in hand.
    pub fn from_codes(codes: Policy) -> Self {
        Self {
            codes,
            ..Self::default()
        }
    }

    pub fn hardened(mut self, hardening: Hardening) -> Self {
        self.hardening = hardening;
        self
    }

    /// What happens about `code` on this artifact.
    pub fn decide<'p>(
        &'p self,
        id: &ArtifactId,
        version: Option<&Version>,
        code: Code,
        now: DateTime<Utc>,
    ) -> Decided<'p> {
        let found = self.artifacts.iter().find_map(|policy| {
            policy
                .rule_for(id, version, code, now)
                .map(|(index, rule)| (rule, policy.cite(index)))
        });

        let disposition = match &found {
            Some((rule, _)) => rule.class.disposition(code),
            None => self.codes.disposition(code),
        };

        self.harden(disposition, found)
    }

    /// What happens about `code` when no artifact is in hand.
    ///
    /// For problems that are not about one artifact -- a policy file that
    /// will not load, a host that cannot be reached before anything was
    /// resolved. The per-artifact half has nothing to say about those.
    pub fn decide_without_artifact(&self, code: Code) -> Decided<'_> {
        self.harden(self.codes.disposition(code), None)
    }

    fn harden<'p>(
        &self,
        disposition: Disposition,
        found: Option<(&'p Rule, String)>,
    ) -> Decided<'p> {
        let soft = disposition.quarantine == Some(Quarantine::Soft);
        let hardened = soft && self.hardening == Hardening::On;

        let (rule, source) = match found {
            Some((rule, source)) => (Some(rule), Some(source)),
            None => (None, None),
        };

        Decided {
            disposition: match hardened {
                true => Disposition {
                    action: Action::SkipArtifact,
                    ..disposition
                },
                false => disposition,
            },
            rule,
            source,
            hardened,
        }
    }
}

impl Decide for Dispositions {
    /// The whole answer, for `Ctx` to consult without knowing how it is
    /// reached.
    ///
    /// Expiry is evaluated **now**, at report time, rather than when the
    /// file was read. A long run that crosses an override's expiry sees it
    /// lapse partway through, which is the literal reading of a date and
    /// the one that cannot surprise anybody.
    fn decide(&self, code: Code, at: Option<&Subject>) -> Ruling {
        let decided = match at {
            Some(subject) => self.decide(&subject.id, subject.version.as_ref(), code, Utc::now()),
            None => self.decide_without_artifact(code),
        };

        Ruling {
            disposition: decided.disposition,
            bypass: decided.bypass(),
            hardened: decided.hardened,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::problem::Class;
    use crate::model::{EcosystemId, Release};

    fn id() -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, "tuna")
    }

    fn version() -> Version {
        Version::new("1.0.0", Release::General)
    }

    fn rules(body: &str) -> QuarantinePolicy {
        serde_json::from_str(body).expect("parses")
    }

    fn rule(purl: &str, code: &str, class: &str) -> QuarantinePolicy {
        rules(&format!(
            r#"{{"rules":[{{"purl":"{purl}","codes":["{code}"],"class":"{class}","expires":"never"}}]}}"#
        ))
    }

    fn decide(d: &Dispositions, code: Code) -> Decided<'_> {
        d.decide(&id(), Some(&version()), code, Utc::now())
    }

    /// With nothing configured, the built-in default answers.
    #[test]
    fn default_built_in_answers_unconfigured() {
        let d = Dispositions::default();
        let decided = decide(&d, Code::SignatureMissing);

        assert_eq!(decided.disposition, Disposition::of(Code::SignatureMissing));
        assert!(decided.rule.is_none());
        assert!(!decided.hardened);
    }

    #[test]
    fn table_beats_built_in_default() {
        let d = Dispositions::from_codes(Policy::new().set(Code::SignatureMissing, Class::Hard));

        assert_eq!(
            decide(&d, Code::SignatureMissing).disposition.quarantine,
            Some(Quarantine::Hard)
        );
    }

    /// The most specific thing anybody said wins, which is the whole point
    /// of a per-artifact file.
    #[test]
    fn rule_artifact_beats_table() {
        let d = Dispositions::new(
            Policy::new().set(Code::SignatureMissing, Class::Failure),
            [rule("pkg:npm/tuna", "signature-missing", "allowed")],
            Hardening::Off,
        );

        let decided = decide(&d, Code::SignatureMissing);

        assert_eq!(decided.disposition.action, Action::Warn);
        assert_eq!(decided.disposition.quarantine, None);
        assert!(decided.rule.is_some(), "and the rule came back with it");
    }

    /// A rule that does not match leaves the code table in charge.
    #[test]
    fn rule_other_artifact_changes_nothing() {
        let d = Dispositions::new(
            Policy::new().set(Code::SignatureMissing, Class::Failure),
            [rule("pkg:npm/salmon", "signature-missing", "allowed")],
            Hardening::Off,
        );

        assert_eq!(
            decide(&d, Code::SignatureMissing).disposition.action,
            Action::SkipArtifact
        );
    }

    // -- Hardening ---------------------------------------------------------

    #[test]
    fn hardening_soft_quarantine_stops_artifact() {
        let d = Dispositions::default().hardened(Hardening::On);
        let decided = decide(&d, Code::SignatureMissing);

        assert_eq!(decided.disposition.action, Action::SkipArtifact);
        assert!(decided.hardened, "and says that is why");

        // The class itself is unchanged: it was and remains a soft
        // reservation, which is what a report should say.
        assert_eq!(decided.disposition.quarantine, Some(Quarantine::Soft));
    }

    /// A loosening override survives hardening, because hardening finds no
    /// quarantine to harden. It falls out of the ordering rather than
    /// needing a special case, which is worth pinning.
    #[test]
    fn hardening_spares_loosening_override() {
        let d = Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/tuna", "signature-missing", "allowed")],
            Hardening::On,
        );

        let decided = decide(&d, Code::SignatureMissing);

        assert_eq!(decided.disposition.action, Action::Warn);
        assert!(!decided.hardened);
    }

    /// An override asking for soft *is* hardened: they asked for soft, and
    /// hardening is a statement about what soft means this run.
    #[test]
    fn hardening_still_applies_to_soft_override() {
        let d = Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/tuna", "signature-missing", "soft")],
            Hardening::On,
        );

        assert_eq!(
            decide(&d, Code::SignatureMissing).disposition.action,
            Action::SkipArtifact
        );
    }

    /// There is nothing in the other three classes for hardening to act
    /// on, so it leaves them exactly alone.
    #[test]
    fn hardening_touches_only_soft() {
        let d = Dispositions::default().hardened(Hardening::On);

        for code in [
            Code::MalwareKnown,     // hard: already stops
            Code::ChecksumMismatch, // not a quarantine at all
            Code::HostUnreachable,  // not a quarantine at all
        ] {
            let decided = decide(&d, code);

            assert_eq!(decided.disposition, Disposition::of(code), "{code}");
            assert!(!decided.hardened, "{code}");
        }
    }

    /// Problems that are not about an artifact still get the code table.
    #[test]
    fn table_used_without_artifact() {
        let d = Dispositions::from_codes(Policy::new().set(Code::HostUnreachable, Class::Allowed));

        let decided = d.decide_without_artifact(Code::HostUnreachable);

        assert_eq!(decided.disposition.action, Action::Warn);
        assert!(decided.rule.is_none());
    }

    // -- Reaching a report -------------------------------------------------

    /// Every field a report needs comes back from one decision, so the
    /// report path has nothing left to work out for itself.
    #[test]
    fn decision_carries_report_needs() {
        let d = Dispositions::new(
            Policy::default(),
            [rules(
                r#"{"rules":[{"purl":"pkg:npm/tuna","codes":["malware-known"],"class":"hard","justification":"known false positive","expires":"2999-01-01T00:00:00Z"}]}"#,
            )],
            Hardening::Off,
        );

        let decided = decide(&d, Code::MalwareKnown);
        let rule = decided.rule.expect("a rule answered");

        assert_eq!(rule.justification.as_deref(), Some("known false positive"));
        assert!(rule.expires.at().is_some());

        // And where to find it, which a caller holding only a `&Rule`
        // could not recover.
        assert_eq!(
            decided.source.as_deref(),
            Some("quarantine policy rule 1"),
            "in memory, so there is no file to name"
        );
    }

    /// `source` is `Some` exactly when `rule` is, so a report never has to
    /// handle a citation with nothing to cite.
    #[test]
    fn decision_cites_only_rules() {
        let with_rule = Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/tuna", "malware-known", "hard")],
            Hardening::Off,
        );
        let matched = decide(&with_rule, Code::MalwareKnown);

        assert_eq!(matched.rule.is_some(), matched.source.is_some());

        let bare = Dispositions::default();
        let unmatched = decide(&bare, Code::MalwareKnown);

        assert!(unmatched.rule.is_none());
        assert!(unmatched.source.is_none());
    }

    /// One reported problem, as the sink recorded it.
    ///
    /// Through a `Ctx` rather than from a bare decision, because that is
    /// the path a report record is actually built from: the record is made
    /// from what was recorded, never from a fresh decision.
    fn recorded(d: Dispositions, code: Code) -> crate::core::problem::Problem {
        let ctx = reporting(d).for_artifact(id(), Some(version()));

        ctx.report(code, Message::new("x"));

        ctx.problems().tail().last().expect("recorded").clone()
    }

    /// The whole feature, from a file on disk to the record a report
    /// carries. Every layer can be right while the citation is empty,
    /// which is what this catches.
    #[test]
    fn record_carries_rule_from_file() {
        use crate::report::QuarantineRecord;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("quarantine-policy.yaml");

        std::fs::write(
            &path,
            format!(
                "$schema: {}\nrules:\n  - purl: \"pkg:npm/salmon\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n  - purl: \"pkg:npm/tuna\"\n    codes: [malware-known]\n    class: hard\n    justification: \"reviewed by security\"\n    expires: never\n",
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let d = Dispositions::new(
            Policy::default(),
            [QuarantinePolicy::load(&path).expect("loads")],
            Hardening::Off,
        );

        let record = QuarantineRecord::of(&recorded(d, Code::MalwareKnown)).expect("a quarantine");

        assert_eq!(record.class, Quarantine::Hard);
        assert!(!record.hardened);

        let bypass = record.bypassed_by.expect("a rule answered");

        assert_eq!(
            bypass.justification.as_deref(),
            Some("reviewed by security")
        );
        assert_eq!(bypass.expires, None, "never, said out loud");

        // The second rule in the file, named so a reader can go and look.
        assert!(bypass.source.ends_with("rule 2"), "{}", bypass.source);
        assert!(bypass.source.contains("quarantine-policy.yaml"));
    }

    /// Two of the four classes are not quarantines, so they produce no
    /// record -- which is what lets a caller hand every decision over and
    /// keep whatever comes back.
    #[test]
    fn record_none_for_non_quarantine() {
        use crate::report::QuarantineRecord;

        for class in ["allowed", "failure"] {
            let d = Dispositions::new(
                Policy::default(),
                [rule("pkg:npm/tuna", "malware-known", class)],
                Hardening::Off,
            );

            assert!(
                QuarantineRecord::of(&recorded(d, Code::MalwareKnown)).is_none(),
                "{class}"
            );
        }
    }

    /// A hardened soft and a hard both stop the artifact, and a report has
    /// to be able to tell them apart: the first would not have stopped it
    /// yesterday.
    #[test]
    fn record_hardened_soft_as_soft_and_hardened() {
        use crate::report::QuarantineRecord;

        let d = Dispositions::default().hardened(Hardening::On);

        let record =
            QuarantineRecord::of(&recorded(d, Code::SignatureMissing)).expect("a quarantine");

        assert_eq!(record.class, Quarantine::Soft);
        assert!(record.hardened);
        assert!(record.bypassed_by.is_none(), "no rule was involved");
    }

    /// A rule that *tightened* an artifact is recorded the same way as one
    /// that excused it. Both are somebody's per-artifact decision, and a
    /// reader asking "why is this one different" needs the same answer.
    #[test]
    fn record_tightening_rule_too() {
        use crate::report::QuarantineRecord;

        let d = Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/tuna", "signature-missing", "hard")],
            Hardening::Off,
        );

        let record =
            QuarantineRecord::of(&recorded(d, Code::SignatureMissing)).expect("a quarantine");

        assert_eq!(record.class, Quarantine::Hard, "the default was soft");
        assert!(record.bypassed_by.is_some());
    }

    // -- Through a `Ctx` ---------------------------------------------------

    use crate::core::ctx::Ctx;
    use crate::core::message::Message;
    use crate::model::Cause;
    use std::sync::Arc;

    fn reporting(d: Dispositions) -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "tuna".into() }).deciding_with(Arc::new(d))
    }

    /// The whole feature, end to end: a rule in a file changes what a
    /// reported problem is. Every layer below can be right while nothing
    /// consults it, which is what this catches.
    #[test]
    fn reported_per_artifact_override_applies() {
        let ctx = reporting(Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/tuna", "malware-known", "allowed")],
            Hardening::Off,
        ))
        .for_artifact(id(), Some(version()));

        let action = ctx.report(Code::MalwareKnown, Message::new("x"));

        assert_eq!(action, Action::Warn, "the default would have skipped");

        let recorded = ctx.problems().tail();
        let problem = recorded.last().expect("recorded");

        assert_eq!(problem.quarantine(), None);
    }

    /// And an override for a *different* artifact does not reach it, which
    /// is the half that would be invisible if the subject were ignored.
    #[test]
    fn reported_other_artifact_override_ignored() {
        let ctx = reporting(Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/salmon", "malware-known", "allowed")],
            Hardening::Off,
        ))
        .for_artifact(id(), Some(version()));

        assert_eq!(
            ctx.report(Code::MalwareKnown, Message::new("x")),
            Action::SkipArtifact
        );
    }

    /// A context with no artifact cannot be answered per artifact, so the
    /// code table decides -- and the rule is simply not consulted.
    #[test]
    fn reported_without_artifact_ignores_rules() {
        let ctx = reporting(Dispositions::new(
            Policy::default(),
            [rule("pkg:npm/tuna", "malware-known", "allowed")],
            Hardening::Off,
        ));

        assert_eq!(
            ctx.report(Code::MalwareKnown, Message::new("x")),
            Action::SkipArtifact
        );
    }

    /// Hardening reaches a report too, so a strict run stops what a
    /// relaxed one would have merely flagged.
    #[test]
    fn reported_hardening_applies() {
        let ctx = reporting(Dispositions::default().hardened(Hardening::On))
            .for_artifact(id(), Some(version()));

        assert_eq!(
            ctx.report(Code::SignatureMissing, Message::new("x")),
            Action::SkipArtifact
        );

        // Still recorded as the soft reservation it is.
        let recorded = ctx.problems().tail();

        assert_eq!(
            recorded.last().expect("recorded").quarantine(),
            Some(Quarantine::Soft)
        );
    }
}
