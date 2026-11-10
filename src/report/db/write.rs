//! One [`Record`] becoming rows.
//!
//! Everything a line report would have written on one line, spread across
//! the tables that can answer questions about it. The stream order survives
//! in `report_record`, so a reader can hand back the same records in the
//! same order; the pieces beside it are what makes the database more than a
//! log.
//!
//! # One transaction per record
//!
//! A record is written whole or not at all, and the transaction closes
//! before the caller goes back to the network. A killed run therefore
//! leaves complete records rather than an artifact with half its files,
//! which is the same property JSON Lines gets from writing one line at a
//! time.

use rusqlite::{Connection, Transaction, params};

use crate::core::error::{Error, Result};
use crate::core::message::{Message, PURL_ARG};
use crate::model::{ArtifactId, CauseKind, LastDownload, Release, Version, cause_arg};
use crate::report::record::{
    AdvisoryRecord, ArtifactRecord, BypassRecord, DestinationOutcome, FileRecord, Header,
    LicenseRecord, Outcome, ProblemRecord, QuarantineRecord, Record, Summary, SuppressionRecord,
};
use crate::report::sink::{Completion, Role};

use super::conn::now_ms;
use super::enumeration;
use super::file_transfer;
use super::frontier;
use super::ids::{self, ChainId, ObservationId, ProblemId, RecordId, RepositoryId, RunId, failed};
use super::inventory;
use super::spell;
use super::transfer;

/// What a run wrote, and where in the stream it went.
pub(super) struct Writing {
    run: RunId,
    sequence: i64,

    /// The repository an observation describes, when the run bound exactly
    /// one to read from.
    ///
    /// A `Record` names no repository, so the inventory has to learn it
    /// from the run's bindings. One source or enumerator is every command
    /// there is today, and the rule is deliberately narrow: **zero or
    /// several and nothing is attributed.** A run that read from two
    /// sources cannot say which one an artifact came from, and filing it
    /// under a guess would corrupt the very answer the inventory exists to
    /// give -- which source should a copy take this from.
    inventory: Option<RepositoryId>,

    /// How many inventory bindings have been declared, so the rule above
    /// can tell one from several after the second arrives.
    inventory_bindings: usize,

    /// How the run ended, as the command said before closing it.
    completion: Completion,
}

impl Writing {
    /// Open a run from the header that opens its report.
    pub(super) fn open(conn: &mut Connection, header: &Header) -> Result<Self> {
        let transaction = conn.transaction().map_err(failed)?;

        transaction
            .execute(
                "INSERT INTO run (command, tool_version, started_ms) VALUES (?, ?, ?)",
                params![
                    header.command,
                    header.tool_version,
                    header.created.timestamp_millis()
                ],
            )
            .map_err(failed)?;

        let run = RunId(transaction.last_insert_rowid());

        // Always written, even when empty. An omitted corpus age and
        // "nothing screened this run" must not look alike, which is the
        // whole reason the field exists on the header.
        for (advisor, age) in &header.corpus_age {
            let (state, modified_ms, why) = corpus(age);

            transaction
                .execute(
                    "INSERT INTO run_corpus (run_id, advisor, state, modified_ms, why)
                     VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT (run_id, advisor) DO UPDATE
                        SET state = excluded.state,
                            modified_ms = excluded.modified_ms,
                            why = excluded.why",
                    params![run.0, advisor, state, modified_ms, why],
                )
                .map_err(failed)?;
        }

        let mut writing = Self {
            run,
            sequence: 0,
            inventory: None,
            inventory_bindings: 0,
            completion: Completion::Finished,
        };

        writing.record(&transaction, "header")?;
        transaction.commit().map_err(failed)?;

        Ok(writing)
    }

    /// Note that a run ended.
    ///
    /// The worst action is copied from the summary rather than passed in,
    /// so the run row and the summary it closes with cannot disagree. A run
    /// that never wrote a summary leaves it null, which is the same claim
    /// as a line report with no summary line: the run did not finish.
    pub(super) fn finish(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "UPDATE run
                SET finished_ms = ?,
                    completion = ?,
                    worst_action = (
                        SELECT worst_action FROM run_summary WHERE run_id = run.run_id
                    )
             WHERE run_id = ?",
            params![now_ms(), self.completion.as_str(), self.run.0],
        )
        .map_err(failed)?;

        Ok(())
    }

    /// Note how the run ended, for [`Writing::finish`] to write.
    pub(super) fn complete(&mut self, how: Completion) {
        self.completion = how;
    }

    /// Record a repository this run uses.
    pub(super) fn bind(
        &mut self,
        conn: &mut Connection,
        binding: &crate::report::sink::Binding<'_>,
    ) -> Result<()> {
        let transaction = conn.transaction().map_err(failed)?;

        let repository = ids::repository(
            &transaction,
            binding.role.as_str(),
            binding.name,
            binding.host,
            binding.base_url,
            binding.ecosystem,
        )?;

        ids::run_repository(&transaction, self.run, repository, binding.priority)?;
        transaction.commit().map_err(failed)?;

        // The binding says whether this run's records are about it, which
        // the role cannot: a `find` pointed at a mirror binds an enumerator
        // and describes the target that mirror is.
        use crate::report::sink::Observing;

        if binding.observing == Observing::Contents {
            self.inventory_bindings += 1;
            self.inventory = match self.inventory_bindings {
                1 => Some(repository),
                _ => None,
            };
        }

        Ok(())
    }

    /// Record where a catalog walk has got to.
    ///
    /// An enumerator binding, because that is what walks a catalog; a source is
    /// resolved against rather than enumerated.
    pub(super) fn checkpoint(
        &mut self,
        conn: &mut Connection,
        at: &crate::report::sink::Enumeration<'_>,
    ) -> Result<()> {
        let transaction = conn.transaction().map_err(failed)?;

        enumeration::checkpoint(
            &transaction,
            self.run,
            crate::report::sink::Role::Enumerator.as_str(),
            at,
        )?;

        transaction.commit().map_err(failed)
    }

    /// Start or adopt a dependency walk under this run.
    pub(super) fn start_walk(
        &self,
        conn: &mut Connection,
        source: &str,
        spec: &str,
        targets: &str,
        resume: Option<crate::report::sink::WalkId>,
    ) -> Result<crate::report::sink::WalkId> {
        let transaction = conn.transaction().map_err(failed)?;
        let walk = frontier::start(&transaction, self.run, source, spec, targets, resume)?;

        transaction.commit().map_err(failed)?;

        Ok(walk)
    }

    /// Claim one artifact for a destination.
    pub(super) fn claim(
        &self,
        conn: &mut Connection,
        claim: &crate::report::sink::Claim<'_>,
    ) -> Result<Option<crate::report::sink::Claimed>> {
        transfer::claim(conn, self.run, claim)
    }

    /// Close a claim with what became of it.
    pub(super) fn close_claim(
        &self,
        conn: &mut Connection,
        claimed: crate::report::sink::Claimed,
        outcome: crate::report::sink::Transfer,
    ) -> Result<()> {
        transfer::close(conn, claimed, outcome)
    }

    /// Record a payload the run fetched, or tried to.
    pub(super) fn downloaded(
        &self,
        conn: &mut Connection,
        at: &crate::report::sink::Download<'_>,
    ) -> Result<()> {
        file_transfer::downloaded(conn, self.run, at)
    }

    /// Record a file the run sent to a target, or tried to.
    pub(super) fn uploaded(
        &self,
        conn: &mut Connection,
        at: &crate::report::sink::Upload<'_>,
    ) -> Result<()> {
        file_transfer::uploaded(conn, self.run, at)
    }

    /// Write one record, whole.
    pub(super) fn write(&mut self, conn: &mut Connection, record: &Record) -> Result<()> {
        let transaction = conn.transaction().map_err(failed)?;

        match record {
            // A second header in one stream is a report appended to
            // another, which the line formats allow. The run is already
            // open, so this only keeps the stream position honest.
            Record::Header(_) => {
                self.record(&transaction, "header")?;
            }

            Record::Artifact(artifact) => {
                let at = self.record(&transaction, "artifact")?;

                self.artifact(&transaction, at, artifact)?;
            }

            Record::Problem(problem) => {
                let at = self.record(&transaction, "problem")?;

                self.problem(&transaction, Some(at), None, problem)?;
            }

            Record::Summary(summary) => {
                let at = self.record(&transaction, "summary")?;

                self.summary(&transaction, at, summary)?;
            }
        }

        transaction.commit().map_err(failed)?;

        Ok(())
    }

    /// Claim the next position in the stream.
    fn record(&mut self, conn: &Transaction<'_>, kind: &str) -> Result<RecordId> {
        self.sequence += 1;

        conn.execute(
            "INSERT INTO report_record (run_id, sequence, at_ms, kind) VALUES (?, ?, ?, ?)",
            params![self.run.0, self.sequence, now_ms(), kind],
        )
        .map_err(failed)?;

        Ok(RecordId(conn.last_insert_rowid()))
    }

    fn artifact(
        &mut self,
        conn: &Transaction<'_>,
        at: RecordId,
        record: &ArtifactRecord,
    ) -> Result<ObservationId> {
        let parsed = ArtifactId::parse(&record.purl)?;
        let version = record
            .version
            .as_ref()
            .map(|text| Version::new(text, Release::General));
        let artifact = ids::artifact(conn, &parsed.id, version.as_ref())?;

        let chain = self.chain(conn, &record.provenance)?;
        let (state, at_ms) = last_download(record.last_download);
        let outcome = record.outcome.as_ref().map(describe_outcome).transpose()?;

        conn.execute(
            "INSERT INTO artifact_observation
                (report_record_id, run_id, artifact_id, requested, version,
                 last_download_state, last_download_ms, declared_license, published_ms,
                 outcome, outcome_verification, provenance_chain_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                at.0,
                self.run.0,
                artifact.0,
                record.requested,
                record.version,
                state,
                at_ms,
                record.declared_license,
                record.published.map(|when| when.timestamp_millis()),
                outcome.as_ref().map(|(action, _)| *action),
                outcome.as_ref().and_then(|(_, how)| how.clone()),
                chain.map(|chain| chain.0),
            ],
        )
        .map_err(failed)?;

        let observation = ObservationId(conn.last_insert_rowid());

        // The inventory row, and the observation's link to it. Written in
        // the same transaction as the observation, so a killed run never
        // leaves an inventory that claims more than the history supports.
        if let Some(repository) = self.inventory {
            let inventoried =
                inventory::observed(conn, repository, artifact, record, self.run, now_ms())?;

            conn.execute(
                "UPDATE artifact_observation SET repository_artifact_id = ?
                 WHERE artifact_observation_id = ?",
                params![inventoried, observation.0],
            )
            .map_err(failed)?;
        }

        for file in &record.files {
            self.file(conn, observation, file)?;
        }

        if let Some(license) = &record.license {
            self.license(conn, observation, license)?;
        }

        for (ordinal, advisory) in record.advisories.iter().enumerate() {
            self.advisory(conn, observation, ordinal as i64, advisory)?;
        }

        for (ordinal, quarantine) in record.quarantine.iter().enumerate() {
            self.quarantine(conn, observation, ordinal as i64, quarantine)?;
        }

        // Several targets: each carries its own reason, and the overall
        // outcome's reason is one of them.
        if !record.outcomes.is_empty() {
            self.outcomes(conn, observation, artifact, &record.outcomes)?;

            return Ok(observation);
        }

        // The reason an outcome carries is a problem in its own right, so
        // it is stored as one and pointed at rather than flattened into
        // columns that only three of the five outcomes would use.
        if let Some(why) = record.outcome.as_ref().and_then(outcome_reason) {
            let problem = self.problem(conn, None, Some(observation), why)?;

            // A failed copy's attempt names the problem that failed it.
            if let Some(Outcome::Failed { .. }) = &record.outcome {
                transfer::blame(conn, self.run, artifact, None, problem)?;
            }
        }

        Ok(observation)
    }

    /// What became of an artifact at each target, in `--to` order.
    ///
    /// Each reason is a problem filed against the observation, and a failed
    /// target's attempt names the problem that failed it.
    fn outcomes(
        &mut self,
        conn: &Transaction<'_>,
        observation: ObservationId,
        artifact: ids::ArtifactRowId,
        outcomes: &[DestinationOutcome],
    ) -> Result<()> {
        for (ordinal, at) in outcomes.iter().enumerate() {
            let destination = ids::repository(
                conn,
                Role::Target.as_str(),
                &at.destination,
                None,
                None,
                None,
            )?;

            let (action, how) = describe_outcome(&at.outcome)?;

            let problem = outcome_reason(&at.outcome)
                .map(|why| self.problem(conn, None, Some(observation), why))
                .transpose()?;

            if let (Some(problem), Outcome::Failed { .. }) = (problem, &at.outcome) {
                transfer::blame(conn, self.run, artifact, Some(destination), problem)?;
            }

            conn.execute(
                "INSERT INTO observation_outcome
                    (artifact_observation_id, destination_repository_id, ordinal, outcome,
                     outcome_verification, problem_id)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    observation.0,
                    destination.0,
                    ordinal as i64,
                    action,
                    how,
                    problem.map(|problem| problem.0),
                ],
            )
            .map_err(failed)?;
        }

        Ok(())
    }

    fn file(
        &self,
        conn: &Transaction<'_>,
        observation: ObservationId,
        record: &FileRecord,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO observation_file
                (artifact_observation_id, name, url, size_bytes, verification, origin,
                 core_metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                observation.0,
                record.name,
                record.url,
                record.size.map(|size| size as i64),
                spell::text(&record.verification)?,
                spell::text(&record.origin)?,
                record.core_metadata.is_some(),
            ],
        )
        .map_err(failed)?;

        let file = conn.last_insert_rowid();

        for (ordinal, digest) in record.digests.iter().enumerate() {
            conn.execute(
                "INSERT INTO observation_file_digest
                    (observation_file_id, ordinal, algorithm, hex)
                 VALUES (?, ?, ?, ?)",
                params![file, ordinal as i64, spell::text(&digest.alg)?, digest.hex],
            )
            .map_err(failed)?;
        }

        for (ordinal, digest) in record.core_metadata.iter().flatten().enumerate() {
            conn.execute(
                "INSERT INTO observation_file_core_metadata_digest
                    (observation_file_id, ordinal, algorithm, hex)
                 VALUES (?, ?, ?, ?)",
                params![file, ordinal as i64, spell::text(&digest.alg)?, digest.hex],
            )
            .map_err(failed)?;
        }

        for (ordinal, signature) in record.signatures.iter().enumerate() {
            conn.execute(
                "INSERT INTO observation_file_signature
                    (observation_file_id, ordinal, scheme, key_id, value, url)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    file,
                    ordinal as i64,
                    spell::text(&signature.scheme)?,
                    signature.key_id,
                    signature.value,
                    signature.url,
                ],
            )
            .map_err(failed)?;
        }

        Ok(())
    }

    fn license(
        &self,
        conn: &Transaction<'_>,
        observation: ObservationId,
        record: &LicenseRecord,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO observation_license
                (artifact_observation_id, decision, spdx, reason_id, reason_args, reason_text)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                observation.0,
                spell::text(&record.decision)?,
                record.spdx,
                record.reason.id,
                args(&record.reason)?,
                record.reason.text,
            ],
        )
        .map_err(failed)?;

        // One allowed usage is enough to migrate an artifact, so these are
        // the usages that refused it; without them a reader sees only
        // "allowed" and loses the restriction.
        for (kind, decided) in &record.usage {
            conn.execute(
                "INSERT INTO observation_license_usage
                    (artifact_observation_id, dep_kind, decision)
                 VALUES (?, ?, ?)",
                params![observation.0, spell::text(kind)?, spell::text(decided)?],
            )
            .map_err(failed)?;
        }

        Ok(())
    }

    fn advisory(
        &self,
        conn: &Transaction<'_>,
        observation: ObservationId,
        ordinal: i64,
        record: &AdvisoryRecord,
    ) -> Result<()> {
        let advisory = ids::advisory(
            conn,
            &record.id,
            record.kind.as_str(),
            record.summary.as_deref(),
        )?;
        let suppression = record
            .suppressed_by
            .as_ref()
            .map(|by| self.suppression(conn, by))
            .transpose()?;

        conn.execute(
            "INSERT INTO observation_advisory
                (artifact_observation_id, ordinal, advisory_id, advisor, certainty,
                 suppression_id)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                observation.0,
                ordinal,
                advisory.0,
                record.advisor,
                spell::text(&record.certainty)?,
                suppression.map(|suppression| suppression.0)
            ],
        )
        .map_err(failed)?;

        Ok(())
    }

    fn quarantine(
        &self,
        conn: &Transaction<'_>,
        observation: ObservationId,
        ordinal: i64,
        record: &QuarantineRecord,
    ) -> Result<()> {
        let code = spell::text(&record.code)?;
        ids::code(conn, &code)?;

        let bypass = record
            .bypassed_by
            .as_ref()
            .map(|by| self.bypass(conn, by))
            .transpose()?;

        conn.execute(
            "INSERT INTO observation_quarantine
                (artifact_observation_id, ordinal, code, class, hardened, bypass_id)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                observation.0,
                ordinal,
                code,
                spell::text(&record.class)?,
                i64::from(record.hardened),
                bypass.map(|bypass| bypass.0),
            ],
        )
        .map_err(failed)?;

        Ok(())
    }

    fn problem(
        &mut self,
        conn: &Transaction<'_>,
        at: Option<RecordId>,
        outcome_of: Option<ObservationId>,
        record: &ProblemRecord,
    ) -> Result<ProblemId> {
        let code = spell::text(&record.code)?;
        ids::code(conn, &code)?;

        let chain = self.chain(conn, &record.provenance)?;
        let bypass = record
            .bypassed_by
            .as_ref()
            .map(|by| self.bypass(conn, by))
            .transpose()?;
        let artifact = about(conn, &record.message)?;

        conn.execute(
            "INSERT INTO problem
                (report_record_id, run_id, artifact_id, artifact_observation_id, code,
                 action, quarantine, bypass_id, message_id, message_args, message_text,
                 provenance_chain_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                at.map(|at| at.0),
                self.run.0,
                artifact.map(|artifact| artifact.0),
                outcome_of.map(|observation| observation.0),
                code,
                spell::text(&record.action)?,
                record
                    .quarantine
                    .map(|class| spell::text(&class))
                    .transpose()?,
                bypass.map(|bypass| bypass.0),
                record.message.id,
                args(&record.message)?,
                record.message.text,
                chain.map(|chain| chain.0),
            ],
        )
        .map_err(failed)?;

        Ok(ProblemId(conn.last_insert_rowid()))
    }

    fn summary(&self, conn: &Transaction<'_>, at: RecordId, record: &Summary) -> Result<()> {
        conn.execute(
            "INSERT INTO run_summary (run_id, report_record_id, artifacts, worst_action)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (run_id) DO UPDATE
                SET report_record_id = excluded.report_record_id,
                    artifacts = excluded.artifacts,
                    worst_action = excluded.worst_action",
            params![
                self.run.0,
                at.0,
                record.artifacts as i64,
                spell::text(&record.worst_action)?
            ],
        )
        .map_err(failed)?;

        for (code, count) in &record.counts {
            let code = spell::text(code)?;
            ids::code(conn, &code)?;

            conn.execute(
                "INSERT INTO summary_code_count (run_id, code, count) VALUES (?, ?, ?)
                 ON CONFLICT (run_id, code) DO UPDATE SET count = excluded.count",
                params![self.run.0, code, *count as i64],
            )
            .map_err(failed)?;
        }

        for (class, count) in &record.quarantined {
            conn.execute(
                "INSERT INTO summary_quarantine_count (run_id, class, count) VALUES (?, ?, ?)
                 ON CONFLICT (run_id, class) DO UPDATE SET count = excluded.count",
                params![self.run.0, spell::text(class)?, *count as i64],
            )
            .map_err(failed)?;
        }

        for statement in &record.unmatched_suppressions {
            conn.execute(
                "INSERT OR IGNORE INTO summary_unmatched_suppression (run_id, statement)
                 VALUES (?, ?)",
                params![self.run.0, statement],
            )
            .map_err(failed)?;
        }

        Ok(())
    }

    fn bypass(&self, conn: &Transaction<'_>, record: &BypassRecord) -> Result<ids::BypassId> {
        ids::bypass(
            conn,
            &record.source,
            record.justification.as_deref(),
            record.expires.map(|when| when.timestamp_millis()),
        )
    }

    fn suppression(
        &self,
        conn: &Transaction<'_>,
        record: &SuppressionRecord,
    ) -> Result<ids::SuppressionId> {
        ids::suppression(
            conn,
            &record.source,
            record.justification.as_deref(),
            record.detail.as_deref(),
        )
    }

    /// Store one causal chain, leaf first.
    ///
    /// Each link arrives as a message id plus named arguments, so its kind
    /// and pieces are read from those, never from the English. The English
    /// is kept beside them, so a database record and a JSONL record of the
    /// same run read alike.
    fn chain(&self, conn: &Transaction<'_>, causes: &[Message]) -> Result<Option<ChainId>> {
        if causes.is_empty() {
            return Ok(None);
        }

        conn.execute("INSERT INTO provenance_chain DEFAULT VALUES", [])
            .map_err(failed)?;

        let chain = ChainId(conn.last_insert_rowid());

        for (ordinal, cause) in causes.iter().enumerate() {
            let Some(kind) = CauseKind::of(&cause.id) else {
                return Err(Error::Report(format!(
                    "provenance link {:?} is not a cause",
                    cause.id
                )));
            };

            let arg = |name: &str| cause.args.get(name).map(String::as_str);
            let (lock_path, lock_entry) = match kind {
                CauseKind::LockFile => (arg(cause_arg::PATH), arg(cause_arg::ENTRY)),
                _ => (None, None),
            };

            let (report_path, report_entry) = match kind {
                CauseKind::Report => (arg(cause_arg::PATH), arg(cause_arg::PURL)),
                _ => (None, None),
            };

            let parent = match kind {
                CauseKind::Dependency => parent(conn, cause)?,
                _ => None,
            };

            conn.execute(
                "INSERT INTO provenance_item
                    (provenance_chain_id, ordinal, kind, arg, lock_path, lock_entry,
                     parent_artifact_id, dep_kind, enumerator, report_path, report_entry,
                     report_source, report_run_id, rendered)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    chain.0,
                    ordinal as i64,
                    kind.as_str(),
                    arg(cause_arg::ARG),
                    lock_path,
                    lock_entry,
                    parent.map(|row| row.0),
                    arg(cause_arg::KIND),
                    arg(cause_arg::ENUMERATOR),
                    report_path,
                    report_entry,
                    arg(cause_arg::SOURCE),
                    arg(cause_arg::RUN).and_then(|run| run.parse::<i64>().ok()),
                    cause.render(),
                ],
            )
            .map_err(failed)?;

            // One row per target, split from the one argument that names
            // them all.
            let destinations = match kind {
                CauseKind::Report => arg(cause_arg::DESTINATION),
                _ => None,
            };

            let named = destinations
                .into_iter()
                .flat_map(|joined| joined.split(cause_arg::DESTINATION_SEPARATOR));

            for (position, destination) in named.enumerate() {
                conn.execute(
                    "INSERT INTO provenance_destination
                        (provenance_chain_id, ordinal, position, destination)
                     VALUES (?, ?, ?, ?)",
                    params![chain.0, ordinal as i64, position as i64, destination],
                )
                .map_err(failed)?;
            }
        }

        Ok(Some(chain))
    }
}

/// The parent a dependency link names, at the version it resolved to.
///
/// Created when the database has not seen it, so every edge is keyed on a
/// row. `None` for a purl that does not parse, or a version arriving
/// without its release class, which would otherwise have to be guessed.
fn parent(conn: &Transaction<'_>, cause: &Message) -> Result<Option<ids::ArtifactRowId>> {
    let Some(purl) = cause.args.get(cause_arg::PURL) else {
        return Ok(None);
    };

    let Ok(parsed) = ArtifactId::parse(purl) else {
        return Ok(None);
    };

    let release = cause
        .args
        .get(cause_arg::RELEASE)
        .and_then(|text| Release::parse(text));

    let version = match (parsed.version, release) {
        (Some(text), Some(release)) => Some(Version::new(text, release)),
        (None, _) => None,
        (Some(_), None) => return Ok(None),
    };

    ids::artifact(conn, &parsed.id, version.as_ref()).map(Some)
}

/// A message's named arguments, as a JSON object.
///
/// A column rather than a child table because `Message::args` is always
/// string to string, and SQLite can index into JSON when somebody asks.
/// The artifact a problem is about, from its message's `purl`.
///
/// `None` for a message naming no artifact, and for a `purl` that does not
/// parse: a problem is worth keeping without its link, and refusing the
/// record would lose the problem too.
fn about(conn: &Transaction<'_>, message: &Message) -> Result<Option<ids::ArtifactRowId>> {
    let Some(purl) = message.args.get(PURL_ARG) else {
        return Ok(None);
    };

    let Ok(parsed) = ArtifactId::parse(purl) else {
        return Ok(None);
    };

    let version = parsed
        .version
        .as_ref()
        .map(|text| Version::new(text, Release::General));

    ids::artifact(conn, &parsed.id, version.as_ref()).map(Some)
}

fn args(message: &crate::core::message::Message) -> Result<Option<String>> {
    if message.args.is_empty() {
        return Ok(None);
    }

    serde_json::to_string(&message.args)
        .map(Some)
        .map_err(|source| {
            crate::core::error::Error::Report(format!(
                "a message argument would not encode: {source}"
            ))
        })
}

/// The three states of a last-download fact, kept apart.
///
/// Flattening them into an optional time would lose the difference between
/// a repository that has served this artifact to nobody and one that keeps
/// no statistics, and only the first is evidence of disuse.
fn last_download(last: LastDownload) -> (&'static str, Option<i64>) {
    match last {
        LastDownload::At(when) => ("at", Some(when.timestamp_millis())),
        LastDownload::Never => ("never", None),
        LastDownload::Unknown => ("unknown", None),
    }
}

/// What an outcome is called, and how far the copy was checked.
fn describe_outcome(outcome: &Outcome) -> Result<(&'static str, Option<String>)> {
    let how = match outcome {
        Outcome::Copied { verification } => Some(spell::text(verification)?),
        _ => None,
    };

    Ok((spell::outcome(outcome), how))
}

fn outcome_reason(outcome: &Outcome) -> Option<&ProblemRecord> {
    match outcome {
        Outcome::Refused { why } | Outcome::Unresolved { why } | Outcome::Failed { why } => {
            Some(why)
        }

        Outcome::Copied { .. } | Outcome::AlreadyPresent => None,
    }
}

fn corpus(age: &crate::advisory::CorpusAge) -> (&'static str, Option<i64>, Option<String>) {
    use crate::advisory::CorpusAge;

    match age {
        CorpusAge::Consulted { modified } => ("consulted", Some(modified.timestamp_millis()), None),

        CorpusAge::SkippedByRequest => ("skipped-by-request", None, None),
        CorpusAge::Unavailable { why } => ("unavailable", None, Some(why.clone())),
    }
}
