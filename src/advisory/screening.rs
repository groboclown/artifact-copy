//! What a run screened against, and what it did not.
//!
//! The state the report's frame is built from: [`Header.corpus_age`] says
//! which corpora were consulted and how stale each was, and
//! [`Summary.unmatched_suppressions`] says which VEX statements turned out to
//! be dead policy. The statements themselves are held here too: they arrive
//! with the run's lock files, and every screened artifact is asked about
//! them.
//!
//! Both are here rather than assembled at each call site because both were
//! previously hardcoded empty, in three commands each, with nothing that could
//! have failed if a caller forgot. A single type that
//! [`header`](crate::report::header) *requires* is what makes forgetting
//! impossible.
//!
//! # Why an empty answer has to be distinguishable
//!
//! `docs/contributors/exit-codes.md` classifies a screening resource being
//! down as fail-fast rather than fail-eventually, because "a run that copies
//! everything and reports nothing looks identical to a clean run, and would be
//! read as one". A report whose `corpus-age` is simply absent is exactly that
//! run. So the field is always written, and every configured advisor appears
//! in it with a reason -- including the reason "nothing consulted this".
//!
//! [`Header.corpus_age`]: crate::report::Header::corpus_age
//! [`Summary.unmatched_suppressions`]: crate::report::Summary::unmatched_suppressions

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::policy::Statement;

/// What became of one configured advisor during a run.
///
/// Three states rather than an optional timestamp: "consulted, and this old"
/// and "not consulted, for this reason" are different claims, and a reader
/// deciding whether to trust a clean report needs to tell them apart without
/// also holding the configuration that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusAge {
    /// Consulted, with the corpus's own `modified` timestamp.
    ///
    /// Absolute rather than a duration: a report is read long after the run,
    /// and "14h old" stops meaning anything the moment it is filed.
    Consulted { modified: DateTime<Utc> },

    /// Configured, and `--no-advisories` turned it off for this run.
    ///
    /// Not a problem: the user asked. The entry is what keeps the asking
    /// visible in the report afterwards.
    SkippedByRequest,

    /// Configured, not skipped, and still not consulted.
    ///
    /// Accompanied by `advisory-source-unavailable`, which aborts by default
    /// and whose severity the `problem-policy` table can change.
    Unavailable { why: String },
}

/// The VEX statements a run's lock files made, which were asked, and which
/// answered.
///
/// A document names the artifacts the run requests, so a statement is asked
/// once an artifact it covers resolves and is screened. One whose artifact
/// never resolved was never asked: `artifact-not-found` already says so,
/// and calling the statement stale as well would point at the document
/// rather than at the package the source does not hold.
#[derive(Debug, Default)]
struct Attested {
    statements: Vec<Statement>,
    asked: BTreeSet<usize>,
    used: BTreeSet<usize>,
}

/// What a run screened against, and what it did not.
#[derive(Debug)]
pub struct Screening {
    /// One entry per configured advisor.
    corpora: BTreeMap<String, CorpusAge>,

    /// The run's VEX statements, and the ones that answered.
    ///
    /// Behind a lock because the walk is concurrent while the header is not:
    /// `corpora` is settled before the first artifact and read without one.
    attested: Mutex<Attested>,
}

impl Screening {
    /// Plan a run's screening from the advisors it configures.
    ///
    /// Every advisor starts out *not* consulted, which is the honest state
    /// before any corpus has been loaded, and the final one for an advisor
    /// nothing loads. `skip` is `--no-advisories`.
    ///
    /// Takes names rather than the configuration's `Advisor` values so this
    /// module stays free of `config`.
    pub fn plan(names: impl IntoIterator<Item = String>, skip: bool) -> Self {
        let state = match skip {
            true => CorpusAge::SkippedByRequest,
            false => CorpusAge::Unavailable {
                why: "not loaded".to_owned(),
            },
        };

        Self {
            corpora: names
                .into_iter()
                .map(|name| (name, state.clone()))
                .collect(),
            attested: Mutex::new(Attested::default()),
        }
    }

    /// A run that configures no advisors at all.
    pub fn none() -> Self {
        Self::plan(std::iter::empty(), false)
    }

    /// What became of each configured advisor, for the report's header.
    pub fn ages(&self) -> &BTreeMap<String, CorpusAge> {
        &self.corpora
    }

    /// Record that `name`'s corpus was consulted, and how stale it was.
    pub fn consulted(&mut self, name: &str, modified: DateTime<Utc>) {
        self.corpora
            .insert(name.to_owned(), CorpusAge::Consulted { modified });
    }

    /// Record that `name`'s corpus could not be consulted, and why.
    pub fn unavailable(&mut self, name: &str, why: impl Into<String>) {
        self.corpora
            .insert(name.to_owned(), CorpusAge::Unavailable { why: why.into() });
    }

    /// Whether this run was asked to screen at all.
    ///
    /// False both for a run configuring no advisors and for one that skipped
    /// them by request: neither is owed an `advisory-source-unavailable`,
    /// because neither asked for an answer it did not get.
    pub fn expected(&self) -> bool {
        self.corpora
            .values()
            .any(|age| !matches!(age, CorpusAge::SkippedByRequest))
    }

    /// Whether any corpus was actually consulted.
    pub fn ran(&self) -> bool {
        self.corpora
            .values()
            .any(|age| matches!(age, CorpusAge::Consulted { .. }))
    }

    /// Add statements a lock file made, before the walk screens anything
    /// they cover.
    pub fn attest(&self, statements: impl IntoIterator<Item = Statement>) {
        let mut attested = self.attested.lock().expect("screening poisoned");

        attested.statements.extend(statements);
    }

    /// Mark every statement covering `purl` as asked, once the artifact has
    /// resolved and is about to be screened.
    pub fn screened(&self, purl: &str) {
        let mut attested = self.attested.lock().expect("screening poisoned");

        let covering: Vec<usize> = attested
            .statements
            .iter()
            .enumerate()
            .filter(|(_, statement)| statement.covers(purl))
            .map(|(index, _)| index)
            .collect();

        attested.asked.extend(covering);
    }

    /// The statement that answers for an advisory against an artifact: one
    /// covering `purl` and naming the advisory, by `id` or one of its
    /// `aliases`, so a statement written against a GHSA identifier clears a
    /// finding reported under its CVE.
    ///
    /// Every statement that answers is marked used, an `affected` one
    /// included: it suppressed nothing, and it is still live rather than
    /// stale. The first is returned.
    pub fn answer(&self, purl: &str, id: &str, aliases: &[String]) -> Option<Statement> {
        let mut attested = self.attested.lock().expect("screening poisoned");

        let answering: Vec<usize> = attested
            .statements
            .iter()
            .enumerate()
            .filter(|(_, statement)| statement.covers(purl) && statement.names(id, aliases))
            .map(|(index, _)| index)
            .collect();

        attested.used.extend(answering.iter().copied());

        answering
            .first()
            .map(|index| attested.statements[*index].clone())
    }

    /// The documents that cover `purl` and say nothing about the advisory.
    ///
    /// Such a document was written before the advisory, so it is out of
    /// date: `vex-incomplete`. A document covering `purl` in no statement
    /// makes no claim about it, and is not listed.
    pub fn incomplete(&self, purl: &str, id: &str, aliases: &[String]) -> BTreeSet<String> {
        let attested = self.attested.lock().expect("screening poisoned");

        let covering = attested
            .statements
            .iter()
            .filter(|statement| statement.covers(purl));

        let mut silent = BTreeSet::new();
        let mut answered = BTreeSet::new();

        for statement in covering {
            match statement.names(id, aliases) {
                true => answered.insert(statement.source.clone()),
                false => silent.insert(statement.source.clone()),
            };
        }

        silent.difference(&answered).cloned().collect()
    }

    /// The statements this run showed to be dead policy: every one that was
    /// asked and answered nothing.
    ///
    /// Each rendered as `source#vulnerability`, which disambiguates two
    /// documents clearing the same advisory: `Statement.source` is the
    /// document the statement was read from.
    pub fn stale(&self) -> Vec<String> {
        let attested = self.attested.lock().expect("screening poisoned");

        attested
            .statements
            .iter()
            .enumerate()
            .filter(|(index, _)| attested.asked.contains(index) && !attested.used.contains(index))
            .map(|(_, statement)| format!("{}#{}", statement.source, statement.vulnerability))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Status;

    fn cleared_for(vulnerability: &str, purl: &str, source: &str) -> Statement {
        Statement {
            vulnerability: vulnerability.into(),
            products: vec![purl.into()],
            status: Status::NotAffected,
            justification: Some("vulnerable_code_not_present".into()),
            detail: None,
            source: source.into(),
        }
    }

    #[test]
    fn advisor_configured_starts_unavailable() {
        let screening = Screening::plan(["osv".to_owned()], false);

        assert!(screening.expected());
        assert!(!screening.ran());
        assert!(matches!(
            screening.ages()["osv"],
            CorpusAge::Unavailable { .. }
        ));
    }

    #[test]
    fn advisor_skipped_by_flag_not_failed() {
        let screening = Screening::plan(["osv".to_owned()], true);

        // Nothing was asked for, so nothing is owed an explanation.
        assert!(!screening.expected());
        assert_eq!(screening.ages()["osv"], CorpusAge::SkippedByRequest);
    }

    /// A run configuring no advisors asked for nothing, so it is not owed
    /// `advisory-source-unavailable` either.
    #[test]
    fn advisor_none_expects_no_screening() {
        let screening = Screening::none();

        assert!(!screening.expected());
        assert!(screening.ages().is_empty());
    }

    #[test]
    fn corpus_consulted_carries_timestamp() {
        let mut screening = Screening::plan(["osv".to_owned()], false);
        let when = Utc::now();

        screening.consulted("osv", when);

        assert!(screening.ran());
        assert_eq!(
            screening.ages()["osv"],
            CorpusAge::Consulted { modified: when }
        );
    }

    // -- Statements -------------------------------------------------------

    fn attested(statements: Vec<Statement>) -> Screening {
        let screening = Screening::plan(["osv".to_owned()], false);
        screening.attest(statements);

        screening
    }

    /// Asked, and said nothing.
    #[test]
    fn statement_unanswering_stale() {
        let screening = attested(vec![
            cleared_for("CVE-1", "pkg:npm/a@1", "vex.json"),
            cleared_for("CVE-2", "pkg:npm/b@1", "vex.json"),
        ]);

        screening.screened("pkg:npm/a@1");
        screening.screened("pkg:npm/b@1");
        assert!(screening.answer("pkg:npm/b@1", "CVE-2", &[]).is_some());

        assert_eq!(screening.stale(), vec!["vex.json#CVE-1".to_owned()]);
    }

    /// An artifact that never resolved is `artifact-not-found`, and its
    /// statement was never asked.
    #[test]
    fn statement_unresolved_artifact_not_stale() {
        let screening = attested(vec![cleared_for("CVE-1", "pkg:npm/a@1", "vex.json")]);

        assert!(screening.stale().is_empty());
    }

    #[test]
    fn statement_answered_not_stale() {
        let screening = attested(vec![cleared_for("CVE-1", "pkg:npm/a@1", "vex.json")]);

        screening.screened("pkg:npm/a@1");
        screening.answer("pkg:npm/a@1", "CVE-1", &[]);

        assert!(screening.stale().is_empty());
    }

    /// Routine in practice: the corpus reports a CVE, the VEX names the GHSA.
    #[test]
    fn statement_alias_answers() {
        let screening = attested(vec![cleared_for("GHSA-xxxx", "pkg:npm/a@1", "vex.json")]);

        let answer = screening.answer("pkg:npm/a@1", "CVE-2024-1", &["GHSA-xxxx".to_owned()]);

        assert!(answer.is_some());
    }

    #[test]
    fn statement_other_artifact_not_answering() {
        let screening = attested(vec![cleared_for("CVE-1", "pkg:npm/b@1", "vex.json")]);

        assert!(screening.answer("pkg:npm/a@1", "CVE-1", &[]).is_none());
    }

    /// Two documents clearing the same advisory have to be separable, or a
    /// user cannot tell which document to edit.
    #[test]
    fn document_two_same_advisory_labeled_apart() {
        let screening = attested(vec![
            cleared_for("CVE-1", "pkg:npm/a@1", "left.json"),
            cleared_for("CVE-1", "pkg:npm/a@1", "right.json"),
        ]);

        screening.screened("pkg:npm/a@1");

        assert_eq!(
            screening.stale(),
            vec!["left.json#CVE-1".to_owned(), "right.json#CVE-1".to_owned()]
        );
    }

    /// Both documents answered, so neither is stale.
    #[test]
    fn statement_every_answering_used() {
        let screening = attested(vec![
            cleared_for("CVE-1", "pkg:npm/a@1", "left.json"),
            cleared_for("CVE-1", "pkg:npm/a@1", "right.json"),
        ]);

        screening.screened("pkg:npm/a@1");
        screening.answer("pkg:npm/a@1", "CVE-1", &[]);

        assert!(screening.stale().is_empty());
    }

    /// A document covering an artifact and silent about an advisory found
    /// against it is out of date; one that names the advisory is not.
    #[test]
    fn document_silent_covering_incomplete() {
        let screening = attested(vec![
            cleared_for("CVE-1", "pkg:npm/a@1", "old.json"),
            cleared_for("CVE-2", "pkg:npm/a@1", "new.json"),
            cleared_for("CVE-1", "pkg:npm/a@1", "new.json"),
        ]);

        let incomplete = screening.incomplete("pkg:npm/a@1", "CVE-2", &[]);

        assert_eq!(incomplete, BTreeSet::from(["old.json".to_owned()]));
        assert!(screening.incomplete("pkg:npm/b@1", "CVE-2", &[]).is_empty());
    }
}
