//! Known-vulnerability and known-malware screening.
//!
//! The sixth extension point, and the one that answers *is this artifact
//! known to be bad* rather than *where does it live*.
//!
//! ```text
//!   corpus  --(purl, version)-->  Advisory records  -->  SecurityPolicy
//! ```
//!
//! A corpus is downloaded once, cached, and answered from locally: a walk
//! of a million artifacts must cost a map lookup each rather than a
//! request each, which is why this is an index rather than a client.
//!
//! # What lives where
//!
//! ```text
//!   osv              the published record shape, and nothing else
//!   index            a corpus, keyed for lookup by (ecosystem, name)
//!   archive          reading records out of a downloaded zip
//!   osv_offline      the OSV bucket's per-ecosystem `all.zip`
//!   ossf_malicious   the ossf/malicious-packages snapshot
//!   matching         whether one version falls in an advisory's affected set
//!   screen           one artifact, screened and reported
//!   screening        what a run screened against, and what it did not
//! ```
//!
//! [`index`] is the shape of the arrow at the top of the diagram. A corpus
//! is published as a flat pile of records with no lookup structure, and OSV
//! spells both halves of a package's identity its own way, so the index
//! translates into purl's spelling as it is built and runs the same
//! translation over the artifact when it is asked. It is also where a record
//! is de-duplicated down to one listing per package, so one advisory cannot
//! report itself twice against one artifact.
//!
//! [`screening`] is the run-level state the report's frame is built from:
//! which corpora answered and how stale each was, and which VEX statements
//! this run showed to be dead policy. It is here rather than in `report`
//! because whether a screening question was even asked is a fact about
//! screening, and the report only writes it down.
//!
//! [`matching`] is separate because it is the part that can be quietly
//! wrong. Screening that answers "clean" when it could not evaluate a
//! range, or that places a version with the wrong convention's comparator,
//! produces a report nobody can act on - and looks identical to one that
//! worked. Its answers are three-valued for exactly that reason.
//!
//! The screening *decision* - whether a finding forbids, warns, or is
//! cleared by a VEX statement - is not here. That is
//! [`crate::policy::SecurityPolicy`], which already takes an identifier, its
//! aliases and whether the record is malware, and answers with a
//! [`Finding`](crate::policy::Finding).
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

mod archive;
mod index;
mod matching;
mod ossf_malicious;
pub mod osv;
mod osv_offline;
mod screen;
mod screening;

pub use archive::{DEFAULT_TTL, Freshness, Origin, Tally};
pub use index::{Ecosystems, Index, Listing};
pub use matching::Match;
pub use ossf_malicious::OssfMalicious;
pub use osv::Advisory;
pub use osv_offline::OsvOffline;
pub use screen::{Policed, Screen};
pub use screening::{CorpusAge, Screening};

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::{ExtHost, Options};
use crate::message;
use crate::model::EcosystemId;

/// What the configuration says about one advisor beyond its kind, its host
/// and its options.
///
/// The typed `advisors.*` keys, carried as their own struct so this module
/// stays free of `config`, as [`Screening::plan`] does.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// `advisors.*.ttl`, or [`DEFAULT_TTL`] when absent.
    pub ttl: Option<Duration>,

    /// `advisors.*.ecosystems`. Empty is every one.
    pub ecosystems: Vec<EcosystemId>,

    /// `advisors.*.path`: an archive to read instead of fetching.
    pub path: Option<PathBuf>,
}

/// Build the advisor for a configured `kind`.
///
/// `base_url` is the host's url, which replaces the corpus's published
/// location: a mirror is a host entry rather than an option.
pub fn open(
    kind: &str,
    base_url: &str,
    settings: &Settings,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Box<dyn Advisor>> {
    let Some(found) = ADVISORS.iter().find(|found| found.name == kind) else {
        return Err(Error::UnknownKind {
            collection: "advisor",
            kind: kind.to_owned(),
        });
    };

    (found.open)(base_url, settings, options, host)
}

/// Built-in advisor kinds, for an error message that names the
/// alternatives.
pub fn kinds() -> &'static [&'static str] {
    static KINDS: LazyLock<Vec<&'static str>> =
        LazyLock::new(|| ADVISORS.iter().map(|found| found.name).collect());

    &KINDS
}

/// Every corpus module's kind. Adding a corpus adds one line here.
const ADVISORS: &[&AdvisorKind] = &[&osv_offline::ADVISOR, &ossf_malicious::ADVISOR];

/// What a corpus module declares: its kind, and how to open it.
struct AdvisorKind {
    name: &'static str,
    open: OpenAdvisor,
}

/// Opens an advisor from its base URL.
type OpenAdvisor = fn(&str, &Settings, &Options, Arc<dyn ExtHost>) -> Result<Box<dyn Advisor>>;

/// Load one advisor into `index`, and record in `screening` what came of it.
///
/// A failed load is recorded rather than returned: one corpus down is a
/// fact for the report's header, and whether the run may go on without it
/// is `advisory-source-unavailable`'s question, asked once every advisor has
/// had its turn.
///
/// `ctx` must decide under the run's dispositions, so the `problem-policy`
/// table reaches `advisory-source-stale`.
pub async fn consult(
    name: &str,
    advisor: &dyn Advisor,
    index: &mut Index,
    screening: &mut Screening,
    freshness: Freshness,
    ctx: &Ctx,
) {
    index.attributing(name);

    let loaded = match advisor.load(index, freshness, ctx).await {
        Ok(loaded) => loaded,

        Err(err) => {
            screening.unavailable(name, err.to_string());
            return;
        }
    };

    // Undated is not fresh. See `Loaded::modified`.
    let Some(modified) = loaded.modified else {
        screening.unavailable(name, "no record in the corpus carries a timestamp");
        return;
    };

    screening.consulted(name, modified);

    if loaded.origin != Origin::Stale {
        return;
    }

    ctx.report(
        Code::AdvisorySourceStale,
        message!(
            "advisory-source-stale",
            "advisor {advisor:?} could not be refreshed and screened against \
             a cached corpus past its ttl, last modified {modified}",
            advisor = name,
            modified = modified.to_rfc3339(),
        ),
    );
}

/// One corpus of advisories: where it comes from, and how to read it.
///
/// **It loads into the caller's index rather than returning its own**, and
/// that is the point of the signature. Two corpora are the recommended
/// arrangement -- see [`OssfMalicious`] for why the redundancy is
/// deliberate -- and two indexes would mean two lookups per artifact and,
/// worse, the same `MAL-` record reported twice from the pair. One index fed
/// by each in turn de-duplicates by construction; see [`Index::insert`].
///
/// What stays per corpus is its *age*, which [`Loaded`] carries: a report
/// says how stale each corpus was, so a merged timestamp would let a fresh
/// malware feed vouch for a year-old vulnerability database.
#[async_trait::async_trait]
pub trait Advisor: Send + Sync {
    /// Read the corpus and key it into `index`.
    ///
    /// Everything that touches the network goes through the host the
    /// advisor was built with: an advisor holds no HTTP client, so it cannot
    /// reach a host the run did not approve. A cached copy is read from the
    /// same capability's directory under `setup.cache-dir`; see
    /// [`archive::acquire`].
    ///
    /// `freshness` is `--refresh-advisories`, and is a parameter rather
    /// than state on the advisor because it is a statement about one
    /// invocation. The TTL it is measured against is configuration and
    /// belongs to the advisor.
    async fn load(
        &self,
        index: &mut Index,
        freshness: Freshness,
        ctx: &crate::core::ctx::Ctx,
    ) -> crate::core::error::Result<Loaded>;
}

/// What one advisor contributed to a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    /// The newest record in this corpus, which is how stale it was.
    ///
    /// `None` when no record carried a parsable timestamp, and a caller must
    /// not read that as fresh: the honest report is
    /// [`CorpusAge::Unavailable`] rather than a consultation with no
    /// timestamp. See [`Index::modified`].
    pub modified: Option<chrono::DateTime<chrono::Utc>>,

    /// Records read, and records that would not parse, across every archive
    /// this advisor read.
    pub tally: Tally,

    /// Where the archives came from, folded worst-first.
    ///
    /// Carried so the wiring can say a corpus was served from an expired
    /// cache because the download failed. A clean screening against
    /// [`Origin::Stale`] is a weaker claim than one against a fresh
    /// download, and nothing downstream could work that out for itself.
    pub origin: Origin,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use chrono::{DateTime, Utc};

    use crate::ext::testing::{Fixture, idle, options};
    use crate::model::Cause;
    use crate::net::FixtureClient;

    const BASE: &str = "h://github.test";

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "advisories".to_owned(),
        })
    }

    fn when(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("timestamp")
            .with_timezone(&Utc)
    }

    /// A snapshot holding one npm malware record, last modified `modified`.
    fn snapshot(id: &str, modified: &str) -> Vec<u8> {
        let body = format!(
            r#"{{"id":"{id}","modified":"{modified}",
                "affected":[{{"package":{{"ecosystem":"npm","name":"tuna"}},
                              "versions":["1.0.0"]}}]}}"#
        );
        let mut buffer = Vec::new();

        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));

            writer
                .start_file(
                    format!("feed-main/osv/malicious/npm/tuna/{id}.json"),
                    zip::write::SimpleFileOptions::default(),
                )
                .expect("entry");
            writer.write_all(body.as_bytes()).expect("written");
            writer.finish().expect("finished");
        }

        buffer
    }

    /// Answers `load` with a canned outcome.
    struct Canned(fn() -> Result<Loaded>);

    #[async_trait::async_trait]
    impl Advisor for Canned {
        async fn load(&self, _: &mut Index, _: Freshness, _: &Ctx) -> Result<Loaded> {
            (self.0)()
        }
    }

    async fn consulted(advisor: Canned, ctx: &Ctx) -> CorpusAge {
        let mut index = Index::new(Ecosystems::builtin());
        let mut screening = Screening::plan(["feed".to_owned()], false);

        consult(
            "feed",
            &advisor,
            &mut index,
            &mut screening,
            Freshness::Cached,
            ctx,
        )
        .await;

        screening.ages()["feed"].clone()
    }

    #[test]
    fn kind_unknown_refused() {
        let outcome = open(
            "osv-online",
            BASE,
            &Settings::default(),
            &Options::default(),
            idle(),
        );

        assert!(matches!(outcome, Err(Error::UnknownKind { .. })));
    }

    /// Every advertised kind opens, so `kinds()` and `open` cannot drift.
    #[test]
    fn every_advertised_kind_opens() {
        for kind in kinds() {
            let outcome = open(
                kind,
                BASE,
                &Settings::default(),
                &Options::default(),
                idle(),
            );

            assert!(outcome.is_ok(), "{kind} should open");
        }
    }

    /// **The defect this pins.** Both corpora feed one index, so reading the
    /// index's age would let a fresh feed vouch for a stale one. The options
    /// reaching the URL are covered on the way: each snapshot is served only
    /// at its own repository and branch.
    #[tokio::test]
    async fn corpus_each_keeps_own_age() {
        let client = FixtureClient::new()
            .with_body(
                format!("{BASE}/acme/fresh/archive/refs/heads/main.zip"),
                snapshot("MAL-1", "2025-06-01T00:00:00Z"),
            )
            .with_body(
                format!("{BASE}/acme/stale/archive/refs/heads/trunk.zip"),
                snapshot("MAL-2", "2020-01-01T00:00:00Z"),
            );
        let f = Fixture::new((), client);
        let ctx = ctx();
        let mut index = Index::new(Ecosystems::builtin());

        let fresh = open(
            ossf_malicious::KIND,
            BASE,
            &Settings::default(),
            &options(serde_json::json!({"repository": "acme/fresh"})),
            f.shared(),
        )
        .expect("opened");
        let stale = open(
            ossf_malicious::KIND,
            BASE,
            &Settings::default(),
            &options(serde_json::json!({"repository": "acme/stale", "branch": "trunk"})),
            f.shared(),
        )
        .expect("opened");

        fresh
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("fresh loaded");
        let older = stale
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("stale loaded");

        assert_eq!(older.modified, Some(when("2020-01-01T00:00:00Z")));
        assert_eq!(index.modified(), Some(when("2025-06-01T00:00:00Z")));
    }

    #[tokio::test]
    async fn corpus_failed_load_unavailable() {
        let age = consulted(
            Canned(|| Err(Error::Config("unreachable".to_owned()))),
            &ctx(),
        )
        .await;

        assert!(matches!(age, CorpusAge::Unavailable { .. }), "{age:?}");
    }

    /// Undated is not fresh. See `Loaded::modified`.
    #[tokio::test]
    async fn corpus_undated_unavailable() {
        let age = consulted(Canned(|| Ok(Loaded::default())), &ctx()).await;

        assert!(matches!(age, CorpusAge::Unavailable { .. }), "{age:?}");
    }

    /// An expired copy still answers, and the run hears about it.
    #[tokio::test]
    async fn corpus_stale_consulted_reported() {
        let ctx = ctx();

        let age = consulted(
            Canned(|| {
                Ok(Loaded {
                    modified: Some(when("2024-06-01T00:00:00Z")),
                    tally: Tally::default(),
                    origin: Origin::Stale,
                })
            }),
            &ctx,
        )
        .await;

        assert_eq!(
            age,
            CorpusAge::Consulted {
                modified: when("2024-06-01T00:00:00Z")
            }
        );
        assert_eq!(
            ctx.problems().counts().get(&Code::AdvisorySourceStale),
            Some(&1)
        );
    }
}
