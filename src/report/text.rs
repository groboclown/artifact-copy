//! The `text` report rendering.
//!
//! Per `README.md`, the same records as YAML but without the quoting and
//! character escaping -- for a person reading a terminal, not for a parser.

use super::record::{AdvisoryRecord, ArtifactRecord, FileRecord, Header, ProblemRecord, Summary};
use super::{Outcome, Record, Verification};
use crate::advisory::CorpusAge;
use crate::core::message::Message;
use crate::core::screened::Certainty;
use crate::model::LastDownload;

/// What became of one advisor, as a phrase.
///
/// The reason travels with the state rather than being left to the reader:
/// "not consulted" and "not consulted because you asked" support different
/// conclusions about whether to trust the rest of the report.
fn corpus(age: &CorpusAge) -> String {
    match age {
        CorpusAge::Consulted { modified } => {
            format!("consulted, corpus of {}", modified.to_rfc3339())
        }

        CorpusAge::SkippedByRequest => "skipped by request".to_owned(),

        CorpusAge::Unavailable { why } => format!("not consulted ({why})"),
    }
}

/// One artifact's outcome, as a line.
///
/// The reason is rendered with the outcome rather than below it, because
/// "refused" without the reason is the half of the answer a reader already
/// has.
fn taken(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Copied { verification } => match verification {
            Verification::Verified => "copied".to_owned(),
            weaker => format!("copied [{weaker:?}]"),
        },

        Outcome::AlreadyPresent => "already present".to_owned(),

        Outcome::Refused { why } => format!("refused: {} ({})", why.message, why.code),

        Outcome::Unresolved { why } => format!("unresolved: {} ({})", why.message, why.code),

        Outcome::Failed { why } => format!("failed: {} ({})", why.message, why.code),
    }
}

/// Render one record as indented plain text.
pub fn render(record: &Record) -> String {
    match record {
        Record::Header(header) => render_header(header),
        Record::Artifact(artifact) => render_artifact(artifact),
        Record::Problem(problem) => render_problem(problem),
        Record::Summary(summary) => render_summary(summary),
    }
}

/// What produced the stream, and what it screened against.
fn render_header(header: &Header) -> String {
    let mut out = format!(
        "# {} {} at {}",
        header.command,
        header.tool_version,
        header.created.to_rfc3339()
    );

    // Said even when there is nothing to say, for the reason
    // `Header::corpus_age` gives: silence here reads as a clean
    // answer, and an unscreened run is not one.
    if header.corpus_age.is_empty() {
        out.push_str("\n#   screened against: nothing configured");
    }

    for (advisor, age) in &header.corpus_age {
        out.push_str(&format!("\n#   {advisor}: {}", corpus(age)));
    }

    out
}

/// One artifact: its name, what became of it, and what it holds.
fn render_artifact(artifact: &ArtifactRecord) -> String {
    // A name-only catalog entry has no version, and rendering an
    // empty one would read as a version that is blank rather than
    // absent.
    let mut out = match &artifact.version {
        Some(version) => format!("{} {version}", artifact.purl),
        None => artifact.purl.clone(),
    };

    if let Some(requested) = &artifact.requested {
        out.push_str(&format!("\n  requested: {requested}"));
    }

    push_outcomes(&mut out, artifact);
    push_last_download(&mut out, artifact.last_download);
    push_license(&mut out, artifact);

    if let Some(published) = artifact.published {
        out.push_str(&format!("\n  published: {}", published.to_rfc3339()));
    }

    push_files(&mut out, &artifact.files);
    push_advisories(&mut out, &artifact.advisories);
    push_provenance(&mut out, &artifact.provenance);

    out
}

/// The overall outcome, then each target's.
fn push_outcomes(out: &mut String, artifact: &ArtifactRecord) {
    // First after the name, because in a `copy` report it is the
    // line the reader came for: what happened to this artifact.
    if let Some(outcome) = &artifact.outcome {
        out.push_str(&format!("\n  {}", taken(outcome)));
    }

    // Each target's, under the overall one, when a copy had several.
    for at in &artifact.outcomes {
        out.push_str(&format!("\n    {}: {}", at.destination, taken(&at.outcome)));
    }
}

/// When the artifact was last downloaded, when the source knows.
fn push_last_download(out: &mut String, last_download: LastDownload) {
    if let LastDownload::At(when) = last_download {
        out.push_str(&format!("\n  last downloaded: {}", when.to_rfc3339()));
    }

    if last_download == LastDownload::Never {
        out.push_str("\n  last downloaded: never");
    }
}

/// The license decision and each usage's, or the declared license alone.
fn push_license(out: &mut String, artifact: &ArtifactRecord) {
    let Some(license) = &artifact.license else {
        if let Some(declared) = &artifact.declared_license {
            out.push_str(&format!("\n  license: {declared}"));
        }

        return;
    };

    out.push_str(&format!(
        "\n  license: {} ({:?})",
        license.spdx.as_deref().unwrap_or("unknown"),
        license.decision
    ));

    // The artifact is here because one usage allowed it, so the
    // ones that refused must stay visible.
    if !license.usage.is_empty() {
        let per_usage: Vec<String> = license
            .usage
            .iter()
            .map(|(kind, decision)| format!("{kind}={decision:?}"))
            .collect();

        out.push_str(&format!("\n  usage: {}", per_usage.join(" ")));
    }
}

/// A line per file: its strongest digest and how it was verified.
fn push_files(out: &mut String, files: &[FileRecord]) {
    for file in files {
        out.push_str(&format!("\n  file: {}", file.name));

        if let Some(digest) = file.digests.iter().max_by_key(|d| d.alg) {
            out.push_str(&format!(" {digest}"));
        }

        // Worth saying out loud: an unverified file is the normal
        // case for inspect, and a failed one must never be quiet.
        if file.verification != Verification::NotAttempted {
            out.push_str(&format!(" [{:?}]", file.verification));
        }
    }
}

/// A line per advisory, with its certainty and any suppression.
fn push_advisories(out: &mut String, advisories: &[AdvisoryRecord]) {
    for advisory in advisories {
        out.push_str(&format!(
            "\n  {} {} from {}",
            advisory.kind.as_str(),
            advisory.id,
            advisory.advisor
        ));

        if advisory.certainty == Certainty::VersionUnusable {
            out.push_str(" (version not comparable)");
        }

        if let Some(suppression) = &advisory.suppressed_by {
            out.push_str(&format!(
                " (suppressed: {} via {})",
                suppression.justification.as_deref().unwrap_or("no reason"),
                suppression.source
            ));
        }
    }
}

/// Why the artifact was reached, below its own request, indented by depth.
fn push_provenance(out: &mut String, provenance: &[Message]) {
    for (level, cause) in provenance.iter().enumerate() {
        if level == 0 {
            continue;
        }

        out.push_str(&format!("\n  {}<- {cause}", "  ".repeat(level)));
    }
}

/// A problem line, with the chain that led to it.
fn render_problem(problem: &ProblemRecord) -> String {
    let mut out = format!(
        "! {} [{}] {}",
        problem.code, problem.action, problem.message
    );

    for (level, cause) in problem.provenance.iter().enumerate() {
        out.push_str(&format!("\n  {}{cause}", "  ".repeat(level)));
    }

    out
}

/// The closing counts, and suppressions that cleared nothing.
fn render_summary(summary: &Summary) -> String {
    let mut out = format!(
        "# {} artifacts, worst action: {}",
        summary.artifacts, summary.worst_action
    );

    for (code, count) in &summary.counts {
        out.push_str(&format!("\n#   {code}: {count}"));
    }

    // "cleared nothing" rather than "matched nothing": every entry
    // here *was* asked, which is what makes it worth deleting.
    for stale in &summary.unmatched_suppressions {
        out.push_str(&format!("\n#   suppression cleared nothing: {stale}"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Screening;
    use crate::report::header;

    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use crate::core::message::Message;
    use crate::core::problem::{Action, Code};
    use crate::core::screened::Category;
    use crate::model::{ArtifactId, Cause, DepKind, Digest, DigestAlg, EcosystemId};
    use crate::policy::Decision;
    use crate::report::record::{
        AdvisoryRecord, ArtifactRecord, DestinationOutcome, FileOrigin, FileRecord, LicenseRecord,
        ProblemRecord, Summary, SuppressionRecord,
    };

    /// A failure, as a refusal or a problem line carries it.
    fn problem() -> ProblemRecord {
        ProblemRecord {
            code: Code::SignatureMissing,
            action: Action::SkipArtifact,
            quarantine: None,
            bypassed_by: None,
            message: Message::new("signature-missing").text("tuna is unsigned"),
            provenance: vec![
                Cause::Requested { arg: "app".into() }.message(),
                Cause::Dependency {
                    of: ArtifactId::new(EcosystemId::npm(), None, "app"),
                    version: None,
                    kind: DepKind::Runtime,
                }
                .message(),
            ],
        }
    }

    fn file(name: &str, digests: Vec<Digest>, verification: Verification) -> FileRecord {
        FileRecord {
            name: name.to_owned(),
            url: format!("h://origin.test/{name}"),
            size: None,
            digests,
            core_metadata: None,
            signatures: Vec::new(),
            verification,
            origin: FileOrigin::Resolved,
        }
    }

    /// Every line an artifact can render.
    fn artifact() -> ArtifactRecord {
        ArtifactRecord {
            purl: "pkg:npm/tuna".to_owned(),
            version: Some("1.0.0".to_owned()),
            requested: Some("tuna@^1".to_owned()),
            outcome: Some(Outcome::Copied {
                verification: Verification::WeakDigestOnly,
            }),
            outcomes: vec![
                DestinationOutcome {
                    destination: "mirror".to_owned(),
                    outcome: Outcome::AlreadyPresent,
                },
                DestinationOutcome {
                    destination: "backup".to_owned(),
                    outcome: Outcome::Refused {
                        why: Box::new(problem()),
                    },
                },
            ],
            last_download: LastDownload::At(Utc.timestamp_millis_opt(1_700_000_000_000).unwrap()),
            files: vec![
                file(
                    "tuna-1.0.0.tgz",
                    vec![
                        Digest::new(DigestAlg::Sha1, "aa"),
                        Digest::new(DigestAlg::Sha256, "bb"),
                    ],
                    Verification::Verified,
                ),
                file("tuna-1.0.0.sig", Vec::new(), Verification::NotAttempted),
            ],
            declared_license: Some("MIT License".to_owned()),
            license: Some(LicenseRecord {
                decision: Decision::Allow,
                spdx: Some("MIT".to_owned()),
                reason: Message::new("license-allowed"),
                usage: BTreeMap::from([
                    (DepKind::Runtime, Decision::Allow),
                    (DepKind::Test, Decision::Forbid),
                ]),
            }),
            published: Some(Utc.timestamp_millis_opt(1_690_000_000_000).unwrap()),
            advisories: vec![AdvisoryRecord {
                id: "GHSA-1".to_owned(),
                advisor: "osv".to_owned(),
                kind: Category::Vulnerability,
                certainty: Certainty::VersionUnusable,
                summary: None,
                suppressed_by: Some(SuppressionRecord {
                    justification: None,
                    detail: None,
                    source: "vex.json#1".to_owned(),
                }),
            }],
            quarantine: Vec::new(),
            provenance: vec![
                Cause::Requested { arg: "app".into() }.message(),
                Cause::Requested { arg: "tuna".into() }.message(),
                Cause::Requested { arg: "deep".into() }.message(),
            ],
        }
    }

    /// Pins the whole artifact rendering, line by line.
    #[test]
    fn artifact_renders_every_line() {
        let rendered = render(&Record::Artifact(Box::new(artifact())));

        assert_eq!(
            rendered,
            concat!(
                "pkg:npm/tuna 1.0.0\n",
                "  requested: tuna@^1\n",
                "  copied [WeakDigestOnly]\n",
                "    mirror: already present\n",
                "    backup: refused: tuna is unsigned (signature-missing)\n",
                "  last downloaded: 2023-11-14T22:13:20+00:00\n",
                "  license: MIT (Allow)\n",
                "  usage: runtime=Allow test=Forbid\n",
                "  published: 2023-07-22T04:26:40+00:00\n",
                "  file: tuna-1.0.0.tgz sha256:bb [Verified]\n",
                "  file: tuna-1.0.0.sig\n",
                "  vulnerability GHSA-1 from osv (version not comparable) ",
                "(suppressed: no reason via vex.json#1)\n",
                "    <- requested: \"tuna\"\n",
                "      <- requested: \"deep\"",
            )
        );
    }

    /// The other arms: no version, never downloaded, a declared license
    /// alone.
    #[test]
    fn artifact_sparse_renders_absences() {
        let sparse = ArtifactRecord {
            version: None,
            requested: None,
            outcome: None,
            outcomes: Vec::new(),
            last_download: LastDownload::Never,
            license: None,
            published: None,
            files: Vec::new(),
            advisories: Vec::new(),
            provenance: Vec::new(),
            ..artifact()
        };

        let rendered = render(&Record::Artifact(Box::new(sparse)));

        assert_eq!(
            rendered,
            concat!(
                "pkg:npm/tuna\n",
                "  last downloaded: never\n",
                "  license: MIT License",
            )
        );
    }

    #[test]
    fn problem_renders_provenance() {
        let rendered = render(&Record::Problem(problem()));

        assert_eq!(
            rendered,
            concat!(
                "! signature-missing [skip-artifact] tuna is unsigned\n",
                "  requested: \"app\"\n",
                "    runtime dependency of pkg:npm/app",
            )
        );
    }

    #[test]
    fn summary_renders_counts_and_stale_suppressions() {
        let summary = Summary {
            artifacts: 3,
            counts: BTreeMap::from([(Code::SignatureMissing, 2)]),
            quarantined: BTreeMap::new(),
            worst_action: Action::Warn,
            unmatched_suppressions: vec!["vex.json#9".to_owned()],
        };

        let rendered = render(&Record::Summary(summary));

        assert_eq!(
            rendered,
            concat!(
                "# 3 artifacts, worst action: warn\n",
                "#   signature-missing: 2\n",
                "#   suppression cleared nothing: vex.json#9",
            )
        );
    }

    /// Silence would read as a clean answer, so the text report says it too
    /// rather than leaving the distinction to the JSON one.
    #[test]
    fn corpus_age_unscreened_says_so() {
        let rendered = render(&Record::Header(header("inspect", &Screening::none())));

        assert!(
            rendered.contains("screened against: nothing configured"),
            "{rendered}"
        );
    }

    #[test]
    fn corpus_age_advisor_renders_reason() {
        let screening = Screening::plan(["osv".to_owned()], false);

        let rendered = render(&Record::Header(header("inspect", &screening)));

        assert!(
            rendered.contains("osv: not consulted (not loaded)"),
            "{rendered}"
        );
        assert!(!rendered.contains("nothing configured"), "{rendered}");
    }

    #[test]
    fn corpus_age_skipped_renders_as_asked() {
        let screening = Screening::plan(["osv".to_owned()], true);

        let rendered = render(&Record::Header(header("inspect", &screening)));

        assert!(rendered.contains("osv: skipped by request"), "{rendered}");
    }
}
