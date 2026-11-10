//! Combining what an artifact enumeration listed with what a source resolved.
//!
//! The one place the two meet, and the rule is strict because each side
//! can be wrong in a way the other catches:
//!
//! ```text
//!   R  files a resolution named      L  files an enumeration listed
//!
//!   in R and L    R's URL; digests merged; size from R, else L
//!   in L only     appended after R, with L's URL, size, digests
//!   in R only     kept -- a listing is never taken to be complete
//!   mismatch      one algorithm with two digests, or two known sizes
//! ```
//!
//! A URL is never compared. The source is what fetches, and a catalog's
//! download host may differ from it or move over time.
//!
//! Identity is the file name. Digests are compared case-insensitively,
//! because repositories disagree about hex case and not about bytes.
//!
//! See `docs/contributors/sources-and-targets.md` for why.

use crate::model::{Digest, FileRef, ResolvedArtifact};
use crate::report::WorkFile;

/// One file the two sides disagree about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mismatch {
    pub file: String,

    /// What differs: `sha1 aa, bb` or `size 10, 12`.
    pub detail: String,
}

/// A resolution with the listing folded in.
#[derive(Debug, Clone)]
pub(super) struct Combined {
    pub artifact: ResolvedArtifact,

    /// Empty when the two agree. Otherwise the artifact is refused; the
    /// combined files are still returned so a report can say what they
    /// were.
    pub mismatches: Vec<Mismatch>,
}

/// Fold every recorded file into a resolved artifact.
///
/// `recorded` is every row the report holds for this artifact, listed or
/// resolved. A row matching one of R's files contributes its digests and
/// size; a listed row matching none is appended.
pub(super) fn combine(mut artifact: ResolvedArtifact, recorded: &[WorkFile]) -> Combined {
    let mut mismatches = Vec::new();

    for file in &mut artifact.files {
        let Some(row) = recorded.iter().find(|row| row.name == file.name) else {
            continue;
        };

        match (file.size, row.size) {
            (Some(ours), Some(theirs)) if ours != theirs => mismatches.push(Mismatch {
                file: file.name.clone(),
                detail: format!("size {ours}, {theirs}"),
            }),

            (None, theirs) => file.size = theirs,

            _ => {}
        }

        merge(&mut file.digests, &row.digests);
    }

    let extra: Vec<FileRef> = recorded
        .iter()
        .filter(|row| row.listed)
        .filter(|row| !artifact.files.iter().any(|file| file.name == row.name))
        .map(|row| FileRef {
            name: row.name.clone(),
            url: row.url.clone(),
            size: row.size,
            digests: row.digests.clone(),
            signatures: Vec::new(),
            core_metadata: None,
        })
        .collect();

    artifact.files.extend(extra);

    // Every file, appended ones included: a listed row can hold two
    // digests of one algorithm when the repository changed its bytes
    // between enumerations, and that is the same disagreement.
    for file in &artifact.files {
        mismatches.extend(conflicts(file));
    }

    Combined {
        artifact,
        mismatches,
    }
}

/// Add each digest not already held.
fn merge(held: &mut Vec<Digest>, more: &[Digest]) {
    for digest in more {
        let known = held
            .iter()
            .any(|have| have.alg == digest.alg && have.hex.eq_ignore_ascii_case(&digest.hex));

        if !known {
            held.push(digest.clone());
        }
    }
}

/// One mismatch per algorithm holding more than one value.
fn conflicts(file: &FileRef) -> Vec<Mismatch> {
    let mut found = Vec::new();
    let mut algorithms: Vec<_> = file.digests.iter().map(|digest| digest.alg).collect();

    algorithms.sort();
    algorithms.dedup();

    for alg in algorithms {
        let mut values: Vec<String> = file
            .digests
            .iter()
            .filter(|digest| digest.alg == alg)
            .map(|digest| digest.hex.to_ascii_lowercase())
            .collect();

        values.sort();
        values.dedup();

        if values.len() > 1 {
            found.push(Mismatch {
                file: file.name.clone(),
                detail: format!("{alg} {}", values.join(", ")),
            });
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactId, DigestAlg, EcosystemId, Release, Version};

    fn resolved(files: Vec<FileRef>) -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::maven(), Some("g"), "a"),
            version: Some(Version::new("1.0", Release::General)),
            files,
            license: None,
            published: None,
        }
    }

    fn file(name: &str) -> FileRef {
        FileRef::new(name, format!("h://source.test/{name}"))
    }

    fn row(name: &str, listed: bool, resolved: bool) -> WorkFile {
        WorkFile {
            name: name.to_owned(),
            url: format!("h://catalog.test/{name}"),
            size: None,
            digests: Vec::new(),
            core_metadata: None,
            signatures: Vec::new(),
            listed,
            resolved,
        }
    }

    fn names(combined: &Combined) -> Vec<&str> {
        combined
            .artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect()
    }

    #[test]
    fn combine_without_listing_is_unchanged() {
        let combined = combine(resolved(vec![file("a-1.0.pom"), file("a-1.0.jar")]), &[]);

        assert_eq!(names(&combined), ["a-1.0.pom", "a-1.0.jar"]);
        assert!(combined.mismatches.is_empty());
    }

    /// The case this exists for: a classifier jar and Gradle metadata the
    /// Maven layout gives a source no way to find.
    #[test]
    fn combine_appends_listed_only() {
        let combined = combine(
            resolved(vec![file("a-1.0.pom"), file("a-1.0.jar")]),
            &[
                row("a-1.0.jar", true, false),
                row("a-1.0.module", true, false),
                row("a-1.0-sources.jar", true, false),
            ],
        );

        assert_eq!(
            names(&combined),
            [
                "a-1.0.pom",
                "a-1.0.jar",
                "a-1.0.module",
                "a-1.0-sources.jar"
            ]
        );
        assert_eq!(
            combined.artifact.files[2].url,
            "h://catalog.test/a-1.0.module"
        );
    }

    /// The source fetches, so its URL stands even where the catalog names
    /// another host.
    #[test]
    fn combine_keeps_resolved_url() {
        let combined = combine(
            resolved(vec![file("a-1.0.jar")]),
            &[row("a-1.0.jar", true, false)],
        );

        assert_eq!(combined.artifact.files[0].url, "h://source.test/a-1.0.jar");
        assert!(combined.mismatches.is_empty());
    }

    /// A listing is never complete, so a file only the source names is
    /// kept without complaint.
    #[test]
    fn combine_keeps_resolved_only() {
        let combined = combine(
            resolved(vec![file("a-1.0.pom"), file("a-1.0.jar")]),
            &[row("a-1.0.jar", true, false)],
        );

        assert_eq!(names(&combined), ["a-1.0.pom", "a-1.0.jar"]);
        assert!(combined.mismatches.is_empty());
    }

    /// Enumerator digests become expectations, which is what lets a Maven
    /// payload be verified at all.
    #[test]
    fn combine_merges_digests() {
        let mut listed = row("a-1.0.jar", true, false);
        listed.digests = vec![
            Digest::new(DigestAlg::Sha1, "AA"),
            Digest::new(DigestAlg::Sha256, "bb"),
        ];

        let mut ours = file("a-1.0.jar");
        ours.digests = vec![Digest::new(DigestAlg::Sha1, "aa")];

        let combined = combine(resolved(vec![ours]), &[listed]);
        let digests = &combined.artifact.files[0].digests;

        assert_eq!(digests.len(), 2, "{digests:?}");
        assert!(combined.mismatches.is_empty());
    }

    #[test]
    fn combine_different_digest_mismatches() {
        let mut listed = row("a-1.0.jar", true, false);
        listed.digests = vec![Digest::new(DigestAlg::Sha1, "bb")];

        let mut ours = file("a-1.0.jar");
        ours.digests = vec![Digest::new(DigestAlg::Sha1, "aa")];

        let combined = combine(resolved(vec![ours]), &[listed]);

        assert_eq!(
            combined.mismatches,
            [Mismatch {
                file: "a-1.0.jar".to_owned(),
                detail: "sha1 aa, bb".to_owned(),
            }]
        );
    }

    /// Two enumerations that disagree leave two values on one row, which is the
    /// same finding even with no resolution to compare against.
    #[test]
    fn combine_conflicting_listing_mismatches() {
        let mut listed = row("a-1.0-sources.jar", true, false);
        listed.digests = vec![
            Digest::new(DigestAlg::Sha1, "aa"),
            Digest::new(DigestAlg::Sha1, "bb"),
        ];

        let combined = combine(resolved(vec![file("a-1.0.pom")]), &[listed]);

        assert_eq!(combined.mismatches.len(), 1);
        assert_eq!(combined.mismatches[0].file, "a-1.0-sources.jar");
    }

    #[test]
    fn combine_size_mismatches() {
        let mut listed = row("a-1.0.jar", true, false);
        listed.size = Some(12);

        let mut ours = file("a-1.0.jar");
        ours.size = Some(10);

        let combined = combine(resolved(vec![ours]), &[listed]);

        assert_eq!(combined.mismatches[0].detail, "size 10, 12");
    }

    #[test]
    fn combine_fills_unknown_size() {
        let mut listed = row("a-1.0.jar", true, false);
        listed.size = Some(12);

        let combined = combine(resolved(vec![file("a-1.0.jar")]), &[listed]);

        assert_eq!(combined.artifact.files[0].size, Some(12));
    }

    /// A resolved row the resolution no longer names is not appended: only
    /// a listing adds files.
    #[test]
    fn combine_ignores_stale_resolved() {
        let combined = combine(
            resolved(vec![file("a-1.0.pom")]),
            &[row("a-1.0.old", false, true)],
        );

        assert_eq!(names(&combined), ["a-1.0.pom"]);
    }
}
