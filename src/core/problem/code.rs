//! Stable problem codes and their default actions.
//!
//! These codes are API: a user's future `problem-policy` config will name
//! them, so renaming one is a breaking change.  The kebab-case serialization
//! is what appears in reports and in that config.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{Action, Quarantine};

/// What a [`Code`] is about, which decides who may name it.
///
/// Two questions turn out to have one answer, so they are asked once here
/// rather than twice in two schemas that could drift apart:
///
/// - May the `problem-policy` table say how this code is handled?
/// - May a per-artifact rule in a policy file name it?
///
/// The answer to both is yes for [`Concern::Artifact`] and no for the other
/// three, and the reasons differ enough to be worth naming separately.
///
/// # Why setup is not configurable
///
/// `docs/contributors/exit-codes.md` classifies a fault in the input a run
/// was given as *fail-fast*: a non-zero exit "where no amount of configuring
/// can overcome". That is the whole point -- a configuration that could
/// downgrade `config-invalid` to a warning would be a configuration excusing
/// itself, and a lock file the tool cannot read is not a thing a rule about
/// artifacts can repair. Everything else the user may tune in both
/// directions.
///
/// This is why a setup code may not be named in either place: not because it
/// would be meaningless, but because it would be *effective*, and the tier
/// exists to be unconditional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Concern {
    /// The input the run was given: configuration, a lock file, a VEX
    /// document, the arguments themselves.
    ///
    /// Fail-fast, and deliberately beyond the reach of configuration.
    Setup,

    /// A particular artifact, which is the only kind a rule can be written
    /// against.
    ///
    /// Everything a run learns rather than was told, including the codes
    /// that are nobody's idea of a quarantine.
    Artifact,

    /// The tool's own state. `unimplemented` says a feature is not built;
    /// `aborted` says the run is already unwinding.
    ///
    /// Neither is a fault in the input nor a statement about an artifact, so
    /// there is nothing for a user to say about it: a rule naming one would
    /// be a setting that does nothing.
    Tool,

    /// The machine the run is on: a disk that cannot be written, a cache
    /// directory moved or cleaned out from under it.
    ///
    /// Not a fault in the input, so not [`Concern::Setup`]: reporting it as
    /// one sends somebody to check arguments that were fine. Not about an
    /// artifact, and not the tool's own state either. A rule naming one
    /// would do nothing, since the remedy is outside the run -- free the
    /// disk, fix the mount -- which is why none may.
    Environment,
}

/// Every distinct failure the tool can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Code {
    // -- Configuration ----------------------------------------------------
    ConfigInvalid,
    ConfigUnreadable,
    FileUnreadable,

    /// A file the run tried to write and could not.
    ///
    /// Apart from [`Code::FileUnreadable`] because the two belong to
    /// different tiers. A file the user named and the tool cannot open is a
    /// fault in the *input*; a cache that cannot be written is the
    /// *environment* failing while the run works -- a full disk, a
    /// read-only mount, a permission the process does not have. Reporting
    /// the second as though the user's arguments were at fault sends
    /// somebody to check a path that was fine all along.
    FileUnwritable,

    /// The report says a payload is cached and it is not where it says.
    ///
    /// The cache directory was moved, rebased, or cleaned out from under a
    /// run. Not a failure: the payload is fetched again and the run carries
    /// on. Worth a line because the alternative is a migration that
    /// silently re-downloads a repository somebody thought was cached, and
    /// looks merely slow.
    CacheFileMissing,

    /// A cached file passed its retention or its freshness, and was evicted
    /// and fetched again.
    ///
    /// Policy rather than a fault, so it changes nothing about the run and
    /// is only recorded. The `reason` argument says which limit.
    CacheEntryExpired,

    /// A cached document passed its freshness and could not be fetched
    /// again, so the stale copy was used.
    ///
    /// The run has an answer, though an older one than it was configured
    /// to accept, which is worth a warning.
    CacheEntryStale,

    /// A cached file was removed to keep a cache under its size cap, least
    /// recently used first.
    ///
    /// Policy rather than a fault, so it is only recorded. The `reason`
    /// argument says which cap: `repository` or `cache-dir`.
    CacheEntryEvicted,

    /// The report store failed: the database would not answer, a record
    /// would not serialize, or its bookkeeping disagreed with itself.
    ///
    /// Not [`Code::ConfigInvalid`], which it was filed under: nothing the
    /// user configured is wrong, and saying so sends somebody to check a
    /// configuration that was fine. The report is where every later result
    /// is written, so a run cannot carry on without it.
    ReportUnusable,

    // -- Integrity --------------------------------------------------------
    ChecksumMismatch,
    SizeMismatch,

    /// A signature that does not verify against the key that made it.
    ///
    /// **Evidence, not a judgement.** The bytes are not what the signature
    /// says they are. Distinct from the two below, which are both
    /// statements about whether a key may be *trusted* rather than about
    /// whether the arithmetic worked.
    SignatureInvalid,

    /// The signing key carries a revocation: its holder has disavowed it.
    SignatureKeyRevoked,

    /// The signing key had stopped being trusted before the signature was
    /// made.
    SignatureKeyExpired,

    SignatureMissing,

    /// The signature verifies, and the signing policy does not let its key
    /// vouch for this artifact: a key assigned to other artifacts, or one
    /// only a keyserver supplied.
    SignatureKeyUnvouched,

    // -- Transport --------------------------------------------------------
    ArtifactNotFound,
    VersionUnresolvable,
    HostUnreachable,

    /// The host answered and refused the request: a 4xx other than 404
    /// and the transient 408 and 429.
    ///
    /// Apart from [`Code::HostUnreachable`] because the host is reachable
    /// and gave an answer. A 409 from a target that will not accept the
    /// write is a statement about this artifact, and reporting it as a
    /// network fault sends somebody to check a connection that was fine.
    RequestRejected,

    /// A target refused one of an artifact's secondary files -- not the POM
    /// or the payload its packaging names, but a file a directory listing
    /// added -- by answer or by a name it cannot take, and published the
    /// rest.
    ///
    /// Apart from [`Code::RequestRejected`], which fails the artifact,
    /// because the copy did happen and only this file is missing: Central's
    /// `groovy/2.4.0` directory holds `groovy-all-2.4.0-groovydoc.jar`,
    /// which a Nexus refuses as outside the Maven layout. A failure by
    /// default, since a correct copy carries every file; a user who accepts
    /// the gap may lower it.
    SecondaryFileRejected,

    DownloadTooLarge,
    MetadataMalformed,

    // -- Licensing --------------------------------------------------------
    LicenseForbidden,
    LicenseUnknown,
    LicenseUnmatched,

    // -- Advisories -------------------------------------------------------
    MalwareKnown,
    VulnerabilityKnown,
    VulnerabilityUnderInvestigation,

    /// An advisory names the package, and whether this version is affected
    /// cannot be decided: the advisory lists no version the artifact's
    /// convention can compare, such as commit-hash ranges only, or a range
    /// bound that will not parse.
    ///
    /// Held back by default. Not knowing is not the same as clean, and the
    /// risk of copying malware outweighs an uncertain version match.
    AdvisoryVersionUnusable,
    AdvisorySourceStale,
    AdvisorySourceUnavailable,
    /// A VEX document given as a lock file that will not parse, or states
    /// something its format forbids: a `not_affected` with no
    /// justification, a CycloneDX `ref` naming no component.
    ///
    /// An artifact concern rather than a setup fault, unlike the other lock
    /// codes: the document vouches for artifacts, so a quarantine rule may
    /// excuse it. Aborts by default, since screening without the statements
    /// the user supplied would clear nothing they meant to clear.
    VexUnparsable,
    VexUnmatched,

    /// An advisory names an artifact a VEX document covers, and the
    /// document says nothing about that advisory: it was written before
    /// the advisory, and is out of date.
    VexIncomplete,

    /// An SBOM or VEX document names a product in an ecosystem the source
    /// does not serve, so it is not requested.
    ///
    /// Routine rather than a mistake: an SBOM generated from a container
    /// image lists the operating system's packages beside the
    /// application's. Recorded so `--verbose` shows what was left out.
    BomEcosystemForeign,

    // -- Inspection -------------------------------------------------------
    PublishTooRecent,
    DependencyUnresolved,
    DependencyMetadataDynamic,
    PomProfileUnsupported,
    PomPropertyUnresolved,

    // -- Lock files -------------------------------------------------------
    LockUnrecognized,
    LockFormatUnknown,
    LockMalformed,

    // -- Artifact enumeration ---------------------------------------------
    EnumerationUnsupported,
    SamplePercentUnsupported,
    ListingMismatch,

    // -- Publishing -------------------------------------------------------
    UploadMetadataIncomplete,
    DistributionTypeUnsupported,

    // -- Omission ---------------------------------------------------------
    /// A configured `omit` rule left a file out of an artifact.
    ///
    /// The user's choice rather than a fault, and a rule like `*.sha256`
    /// can match every artifact, so it is only recorded.
    FileOmitted,

    /// A configured `omit` rule left a whole artifact out.
    ///
    /// Still the user's choice, but a whole artifact going missing should
    /// be visible, so it warns rather than failing the run.
    ArtifactOmitted,

    // -- Control ----------------------------------------------------------
    Unimplemented,
    Aborted,
}

/// Every code, for [`Code::all`] and for the tests that walk them.
///
/// Exhaustive and kept manually, so adding a variant without deciding its
/// action and quarantine class fails a test here rather than at a user's
/// site.
const ALL: [Code; 53] = [
    Code::ConfigInvalid,
    Code::ConfigUnreadable,
    Code::FileUnreadable,
    Code::FileUnwritable,
    Code::CacheFileMissing,
    Code::CacheEntryExpired,
    Code::CacheEntryStale,
    Code::CacheEntryEvicted,
    Code::ReportUnusable,
    Code::ChecksumMismatch,
    Code::SizeMismatch,
    Code::SignatureInvalid,
    Code::SignatureKeyRevoked,
    Code::SignatureKeyExpired,
    Code::SignatureMissing,
    Code::SignatureKeyUnvouched,
    Code::ArtifactNotFound,
    Code::VersionUnresolvable,
    Code::HostUnreachable,
    Code::RequestRejected,
    Code::SecondaryFileRejected,
    Code::DownloadTooLarge,
    Code::MetadataMalformed,
    Code::LicenseForbidden,
    Code::LicenseUnknown,
    Code::LicenseUnmatched,
    Code::MalwareKnown,
    Code::VulnerabilityKnown,
    Code::VulnerabilityUnderInvestigation,
    Code::AdvisoryVersionUnusable,
    Code::AdvisorySourceStale,
    Code::AdvisorySourceUnavailable,
    Code::VexUnparsable,
    Code::VexUnmatched,
    Code::VexIncomplete,
    Code::BomEcosystemForeign,
    Code::PublishTooRecent,
    Code::DependencyUnresolved,
    Code::DependencyMetadataDynamic,
    Code::PomProfileUnsupported,
    Code::PomPropertyUnresolved,
    Code::LockUnrecognized,
    Code::LockFormatUnknown,
    Code::LockMalformed,
    Code::EnumerationUnsupported,
    Code::SamplePercentUnsupported,
    Code::ListingMismatch,
    Code::UploadMetadataIncomplete,
    Code::DistributionTypeUnsupported,
    Code::FileOmitted,
    Code::ArtifactOmitted,
    Code::Unimplemented,
    Code::Aborted,
];

impl Code {
    /// Every code, in declaration order.
    ///
    /// A closed set, unlike an extension `kind`: these are the vocabulary
    /// the `problem-policy` table is written against, so a configuration
    /// naming one that does not exist is a typo the schema can catch
    /// outright rather than something to resolve later.
    pub fn all() -> &'static [Code] {
        &ALL
    }

    /// The default action for this code.
    ///
    /// Hardcoded deliberately.  A `problem-policy` config table is a pure
    /// addition once these codes have settled, and adding it later cannot
    /// break a config nobody could write yet.
    pub fn action(self) -> Action {
        match self {
            // Bad config or an unreadable policy file makes every later
            // result untrustworthy.
            Code::ConfigInvalid | Code::ConfigUnreadable | Code::FileUnreadable => Action::Abort,

            // Nothing the run does next can be trusted to land either, so
            // this stops rather than skipping the artifact it happened to
            // be holding.
            Code::FileUnwritable => Action::Abort,

            // Every later result is written there, so a run that carried
            // on would do work nothing records.
            Code::ReportUnusable => Action::Abort,

            // The bytes are fetched again and the run carries on. Recorded
            // so a migration that quietly re-downloads a repository reads
            // as that rather than as slow.
            Code::CacheFileMissing => Action::Warn,

            // Configured expiry doing its job, shown at info as every
            // `ignore` is.
            Code::CacheEntryExpired => Action::Ignore,

            // An older answer than configured, which the run still uses.
            Code::CacheEntryStale => Action::Warn,

            // A size cap doing its job, shown at info as an expiry is.
            Code::CacheEntryEvicted => Action::Ignore,

            // Integrity failure is a security signal, not a per-artifact
            // hiccup: stop and have someone look.
            Code::ChecksumMismatch | Code::SizeMismatch | Code::SignatureInvalid => Action::Abort,

            // A key its own holder has disavowed may not vouch for
            // anything, so the artifact is dropped -- but this is a
            // judgement about trust rather than evidence of corruption, so
            // it does not stop the run the way a failed verification does.
            Code::SignatureKeyRevoked => Action::SkipArtifact,

            // The signature may well have been fine when it was made, and
            // the key lapsing afterwards is ordinary. Worth saying, not
            // worth dropping an artifact over.
            Code::SignatureKeyExpired => Action::Warn,

            // Signature coverage is genuinely uneven across ecosystems, so
            // absence cannot be fatal.
            Code::SignatureMissing => Action::Warn,

            // Proven signed, by someone the policy did not name for it.
            // Reviewable, since a policy can lag a project's new key.
            Code::SignatureKeyUnvouched => Action::Warn,

            Code::ArtifactNotFound
            | Code::VersionUnresolvable
            | Code::HostUnreachable
            | Code::RequestRejected
            | Code::DownloadTooLarge
            | Code::MetadataMalformed => Action::SkipArtifact,

            // A copy missing a file is not a correct copy, so a failure;
            // the rest of the artifact is already published.
            Code::SecondaryFileRejected => Action::SkipArtifact,

            // The catalog and the source disagree about a file's bytes, so
            // one of them is wrong and nothing says which. The artifact
            // goes; the run carries on, since it is one artifact's
            // evidence rather than a sign the whole source is corrupt.
            Code::ListingMismatch => Action::SkipArtifact,

            // The bytes arrive intact; what the target serves about them
            // is less than the origin did. Worth a line, not an artifact.
            Code::UploadMetadataIncomplete => Action::Warn,

            // One file of a version left behind by configuration, which is
            // a choice the user made rather than a fault.
            Code::DistributionTypeUnsupported => Action::Warn,

            // Configured omissions: see the variants.
            Code::FileOmitted => Action::Ignore,
            Code::ArtifactOmitted => Action::Warn,

            Code::LicenseForbidden => Action::SkipArtifact,

            // Resolved against the policy's `unknown-license` branch before
            // this is ever consulted; `warn` is the fallback.
            Code::LicenseUnknown | Code::LicenseUnmatched => Action::Warn,

            // Never copy known-malicious code.  Skip rather than abort so one
            // flagged package cannot derail a long migration, and let the
            // non-zero exit make it impossible to miss.
            Code::MalwareKnown => Action::SkipArtifact,

            // An unanswered screening question is held back rather than
            // passed, for the reason `unknown-publish-time` is.
            Code::AdvisoryVersionUnusable => Action::SkipArtifact,

            // Blunt until a maximum-CVSS threshold exists: nearly every real
            // dependency graph carries known vulnerabilities.
            Code::VulnerabilityKnown | Code::VulnerabilityUnderInvestigation => Action::Warn,

            Code::AdvisorySourceStale | Code::VexUnmatched | Code::VexIncomplete => Action::Warn,

            // A product the source cannot serve is expected in an SBOM.
            Code::BomEcosystemForeign => Action::Ignore,

            // Screening was asked for and could not run; a clean report would
            // be a lie.
            Code::AdvisorySourceUnavailable | Code::VexUnparsable => Action::Abort,

            Code::PublishTooRecent => Action::SkipArtifact,

            // The artifact cannot say what it is. Nothing read out of that
            // metadata can be trusted, so the artifact goes rather than
            // just its descent -- a Maven POM whose own version is an
            // unresolved `${revision}` names no artifact at all.
            Code::PomPropertyUnresolved => Action::SkipArtifact,

            // Keep the artifact, stop descending from it: a profile this
            // tool does not activate means the dependency list is
            // incomplete in a way that cannot be pointed at.
            Code::PomProfileUnsupported => Action::StopSpider,

            // **One edge of the graph, not the graph.** Whatever could not
            // be resolved -- a dependency with no version, a BOM left
            // unexpanded, a parent that would not load -- costs that
            // dependency and leaves the artifact's others intact, which is
            // what the call sites actually do.
            //
            // Warn rather than skip because `docs/contributors/exit-codes.md`
            // declines to guess which dependencies are load-bearing:
            // whether a missing one breaks the artifact needs the runtime
            // environment, so it is reported and left to the user.
            Code::DependencyUnresolved => Action::Warn,

            Code::DependencyMetadataDynamic => Action::Warn,

            // The user named the file, so silence would be wrong: an empty
            // result reads exactly like a lock file with no dependencies.
            Code::LockUnrecognized | Code::LockFormatUnknown | Code::LockMalformed => Action::Abort,

            Code::EnumerationUnsupported | Code::SamplePercentUnsupported => Action::Abort,

            Code::Unimplemented | Code::Aborted => Action::Abort,
        }
    }

    /// What this code is *about*.
    ///
    /// The single table behind both user-facing code lists, so the two
    /// cannot disagree about which codes a user may name. See [`Concern`]
    /// for what each answer means and what follows from it.
    ///
    /// Kept as a question about the code rather than a list in a schema, so
    /// each schema can be checked against it and neither can drift.
    pub fn concerns(self) -> Concern {
        match self {
            // The input the run was given, and a fault in it.
            Code::ConfigInvalid
            | Code::ConfigUnreadable
            | Code::FileUnreadable
            | Code::LockFormatUnknown
            | Code::LockUnrecognized
            | Code::LockMalformed
            | Code::EnumerationUnsupported
            | Code::SamplePercentUnsupported => Concern::Setup,

            // The tool's own state.
            Code::Unimplemented | Code::Aborted => Concern::Tool,

            // The machine the run is on.
            Code::FileUnwritable
            | Code::CacheFileMissing
            | Code::CacheEntryExpired
            | Code::CacheEntryStale
            | Code::CacheEntryEvicted
            | Code::ReportUnusable => Concern::Environment,

            _ => Concern::Artifact,
        }
    }

    /// Whether this code says something about an artifact.
    ///
    /// The question both a per-artifact override and the `problem-policy`
    /// table have to be able to answer, and it is **not** "is this a classic
    /// quarantine". `dependency-unresolved` and `pom-property-unresolved`
    /// are nobody's idea of quarantine and are still things a user may want
    /// to state a handling for on one package. The quarantine file is
    /// per-artifact *problem handling*; quarantine is its main use rather
    /// than its whole subject.
    pub fn concerns_an_artifact(self) -> bool {
        self.concerns() == Concern::Artifact
    }

    /// Whether this code holds an artifact for review by default, and how
    /// firmly.
    ///
    /// **Quarantine is for "we chose not to take this", never for "we could
    /// not take this."** A publish window is a rule we applied and the rule
    /// might be wrong about this artifact -- reviewable. A checksum mismatch
    /// is evidence the bytes are not what was claimed -- there is nothing to
    /// review and no acknowledgement that should let it through. That one
    /// line decides most of the table below, and it is why every transport,
    /// configuration and integrity code answers `None`.
    ///
    /// Being reviewable is necessary and not sufficient. `license-forbidden`
    /// is reviewable too and is still not a quarantine, because its review
    /// already has a home in the license policy file; a second way to excuse
    /// the same artifact would mean two places to look and two that can
    /// disagree.
    ///
    /// Hardcoded, like [`Code::action`], and for the same reason: the
    /// `problem-policy` table that overrides both is a pure addition once
    /// these have settled.
    pub fn quarantine(self) -> Option<Quarantine> {
        match self {
            // A signature nobody can check is common outside Maven Central
            // and says nothing on its own. Worth flagging, not worth
            // holding anything back over.
            Code::SignatureMissing => Some(Quarantine::Soft),

            // Signed by a key nobody vouched for here: flagged for review,
            // as a missing signature is, and for the same reason.
            Code::SignatureKeyUnvouched => Some(Quarantine::Soft),

            // The signature may well have been good when it was made.
            Code::SignatureKeyExpired => Some(Quarantine::Soft),

            // The holder has disavowed the key. Held back, but reviewable:
            // a revocation after a credential leak does not necessarily
            // mean everything signed before it was bad, and that judgement
            // is the user's to make per artifact.
            Code::SignatureKeyRevoked => Some(Quarantine::Hard),

            // Never mirrored on the ordinary path, and false positives do
            // happen -- so held back, and overridable only deliberately.
            Code::MalwareKnown => Some(Quarantine::Hard),

            // A judgement made without an answer, and reviewable per
            // artifact: somebody who has read the advisory can say this
            // version is outside it.
            Code::AdvisoryVersionUnusable => Some(Quarantine::Hard),

            // A rule restricting what may be pulled, which is exactly the
            // reviewable kind -- and **hard**, because the window exists to
            // prevent. Soft would copy the artifact and flag it, which
            // leaves a release cut an hour ago mirrored and the guard doing
            // nothing. Held back and overridable per artifact is what the
            // review workflow assumes anyway: there is nothing to review
            // about something already taken.
            Code::PublishTooRecent => Some(Quarantine::Hard),

            // Everything else is either evidence rather than a judgement,
            // or has its review somewhere better. Listed as a catch-all
            // deliberately: a new code defaults to *not* quarantined, which
            // is the answer that cannot silently weaken anything.
            _ => None,
        }
    }

    /// The kebab-case name used in reports and configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::ConfigInvalid => "config-invalid",
            Code::ConfigUnreadable => "config-unreadable",
            Code::FileUnreadable => "file-unreadable",
            Code::FileUnwritable => "file-unwritable",
            Code::CacheFileMissing => "cache-file-missing",
            Code::CacheEntryExpired => "cache-entry-expired",
            Code::CacheEntryStale => "cache-entry-stale",
            Code::CacheEntryEvicted => "cache-entry-evicted",
            Code::ReportUnusable => "report-unusable",
            Code::ChecksumMismatch => "checksum-mismatch",
            Code::SizeMismatch => "size-mismatch",
            Code::SignatureInvalid => "signature-invalid",
            Code::SignatureKeyRevoked => "signature-key-revoked",
            Code::SignatureKeyExpired => "signature-key-expired",
            Code::SignatureMissing => "signature-missing",
            Code::SignatureKeyUnvouched => "signature-key-unvouched",
            Code::ArtifactNotFound => "artifact-not-found",
            Code::VersionUnresolvable => "version-unresolvable",
            Code::HostUnreachable => "host-unreachable",
            Code::RequestRejected => "request-rejected",
            Code::SecondaryFileRejected => "secondary-file-rejected",
            Code::DownloadTooLarge => "download-too-large",
            Code::MetadataMalformed => "metadata-malformed",
            Code::LicenseForbidden => "license-forbidden",
            Code::LicenseUnknown => "license-unknown",
            Code::LicenseUnmatched => "license-unmatched",
            Code::MalwareKnown => "malware-known",
            Code::VulnerabilityKnown => "vulnerability-known",
            Code::VulnerabilityUnderInvestigation => "vulnerability-under-investigation",
            Code::AdvisoryVersionUnusable => "advisory-version-unusable",
            Code::AdvisorySourceStale => "advisory-source-stale",
            Code::AdvisorySourceUnavailable => "advisory-source-unavailable",
            Code::VexUnparsable => "vex-unparsable",
            Code::VexUnmatched => "vex-unmatched",
            Code::VexIncomplete => "vex-incomplete",
            Code::BomEcosystemForeign => "bom-ecosystem-foreign",
            Code::PublishTooRecent => "publish-too-recent",
            Code::DependencyUnresolved => "dependency-unresolved",
            Code::DependencyMetadataDynamic => "dependency-metadata-dynamic",
            Code::PomProfileUnsupported => "pom-profile-unsupported",
            Code::PomPropertyUnresolved => "pom-property-unresolved",
            Code::LockUnrecognized => "lock-unrecognized",
            Code::LockFormatUnknown => "lock-format-unknown",
            Code::LockMalformed => "lock-malformed",
            Code::EnumerationUnsupported => "enumeration-unsupported",
            Code::SamplePercentUnsupported => "sample-percent-unsupported",
            Code::ListingMismatch => "listing-mismatch",
            Code::UploadMetadataIncomplete => "upload-metadata-incomplete",
            Code::DistributionTypeUnsupported => "distribution-type-unsupported",
            Code::FileOmitted => "file-omitted",
            Code::ArtifactOmitted => "artifact-omitted",
            Code::Unimplemented => "unimplemented",
            Code::Aborted => "aborted",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The machine the run is on is its own tier: not the input, not the
    /// tool, and not an artifact a rule could name.
    #[test]
    fn code_environment_has_own_tier() {
        for code in [
            Code::FileUnwritable,
            Code::CacheFileMissing,
            Code::ReportUnusable,
        ] {
            assert_eq!(code.concerns(), Concern::Environment, "{code}");
            assert!(!code.concerns_an_artifact(), "{code}");
        }

        assert_eq!(Code::Unimplemented.concerns(), Concern::Tool);
        assert_eq!(Code::Aborted.concerns(), Concern::Tool);
    }

    /// The kebab name is API, so it must match what serde emits.  A typo in
    /// either table would otherwise only surface in a user's config file.
    #[test]
    fn as_str_matches_serde() {
        for code in ALL {
            let json = serde_json::to_string(&code).expect("serializable");
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }

    #[test]
    fn code_every_resolves_action() {
        for code in ALL {
            let _ = code.action();
        }
    }

    // -- Quarantine -------------------------------------------------------

    /// The two default tables must agree, or a code would be classified as
    /// soft while its action holds the artifact back -- which is the
    /// opposite of what soft means.
    ///
    /// This is the one place the two axes are tied together, and it walks
    /// every code so adding one cannot quietly break the correspondence.
    #[test]
    fn quarantine_class_agrees_with_action() {
        for code in ALL {
            let Some(class) = code.quarantine() else {
                continue;
            };

            assert_eq!(
                code.action(),
                class.implied_action(),
                "{code} is {class} quarantine, which implies {:?}, but its action is {:?}",
                class.implied_action(),
                code.action(),
            );
        }
    }

    /// Quarantine is for a judgement, never for evidence. A new code
    /// defaults to not quarantined, which is the answer that cannot
    /// silently weaken anything.
    #[test]
    fn quarantine_never_evidence() {
        for code in [
            Code::ChecksumMismatch,
            Code::SizeMismatch,
            Code::SignatureInvalid,
            Code::MetadataMalformed,
            Code::ListingMismatch,
            Code::HostUnreachable,
            Code::RequestRejected,
            Code::ArtifactNotFound,
            Code::ConfigInvalid,
        ] {
            assert_eq!(code.quarantine(), None, "{code} is not a judgement");
        }
    }

    /// Reviewable is necessary and not sufficient: a forbidden license is
    /// reviewable and is still not a quarantine, because the license policy
    /// file is where that review lives.
    #[test]
    fn quarantine_not_forbidden_license() {
        assert_eq!(Code::LicenseForbidden.quarantine(), None);
    }

    #[test]
    fn quarantine_trust_judgments_classified_apart() {
        assert_eq!(
            Code::SignatureKeyExpired.quarantine(),
            Some(Quarantine::Soft)
        );
        assert_eq!(
            Code::SignatureKeyRevoked.quarantine(),
            Some(Quarantine::Hard)
        );
    }

    /// The class has to survive the exchange format, or a report cannot be
    /// filtered on it by anything but this program.
    #[test]
    fn quarantine_class_round_trips() {
        for class in [Quarantine::Soft, Quarantine::Hard] {
            let json = serde_json::to_string(&class).expect("serialized");
            let back: Quarantine = serde_json::from_str(&json).expect("deserialized");

            assert_eq!(back, class);
            assert_eq!(json, format!("\"{}\"", class.as_str()));
        }
    }

    /// `docs/reports.md`'s problem code table states each code's defaults,
    /// so a code added or changed without the table fails here.
    #[test]
    fn reports_doc_table_matches() {
        const REPORTS_DOC: &str = include_str!("../../../docs/reports.md");

        let documented: Vec<String> = REPORTS_DOC
            .lines()
            .filter(|line| line.starts_with("| `"))
            .filter_map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                let code = cells.get(1)?.strip_prefix('`')?.strip_suffix('`')?;

                // Only this table's rows: another table may also open on a
                // code-styled cell.
                if !Code::all().iter().any(|known| known.as_str() == code) {
                    return None;
                }

                Some(cells[1..5].join(" | "))
            })
            .collect();

        let expected: Vec<String> = Code::all()
            .iter()
            .map(|code| {
                let quarantine = code
                    .quarantine()
                    .map_or("-".to_owned(), |q| format!("`{}`", q.as_str()));
                let per_artifact = match code.concerns_an_artifact() {
                    true => "yes",
                    false => "no",
                };

                format!(
                    "`{}` | `{}` | {quarantine} | {per_artifact}",
                    code.as_str(),
                    code.action()
                )
            })
            .collect();

        assert_eq!(documented, expected);
    }
}
