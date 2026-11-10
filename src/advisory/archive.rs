//! Reading OSV records out of a downloaded archive.
//!
//! Both corpora ship as one zip: OSV publishes `all.zip` per ecosystem, and
//! the malicious-packages feed is a repository whose snapshot GitHub serves
//! the same way. So the unpacking is here once rather than twice, and what
//! differs between the two -- the URL, and which entries inside are records
//! -- stays with each advisor.
//!
//! # Nothing is extracted
//!
//! An entry is decompressed into memory, parsed, keyed, and dropped. Writing
//! two hundred thousand small files to disk in order to read each one back
//! would cost more than the download, and it is also the step at which a
//! crafted path escapes its directory -- a class of bug that cannot occur in
//! code that never opens a file for writing.
//!
//! # An archive from the network is untrusted input
//!
//! This is a *screening* resource, so the consequence of mishandling one is
//! not a missing artifact but a run that copies everything and reports
//! nothing. That makes a zip bomb here a denial of screening, and it is the
//! reason for three caps rather than a comment saying to be careful:
//!
//! - [`ENTRY_LIMIT`] on one entry's decompressed size. A record is a few
//!   kilobytes; anything near this is not a record.
//! - [`CORPUS_LIMIT`] on the decompressed total, which is what actually
//!   bounds the work: a thousand entries each just under the entry cap would
//!   pass a per-entry check on its own.
//! - [`ENTRY_COUNT_LIMIT`] on how many entries are examined at all, because
//!   an archive of empty files costs time without costing bytes.
//!
//! Reaching any of them is an error rather than a truncated read. A corpus
//! cut short is a corpus that answers "nothing found" about whatever was in
//! the part not read, which is the one answer this must never invent.
//!
//! # One bad record is not a bad corpus
//!
//! A single entry that will not parse is skipped and counted, for the reason
//! [`super::osv`] ignores unknown fields: a corpus of a quarter of a million
//! records, published by machinery this tool does not control, will
//! eventually contain one file it cannot read, and taking screening down
//! over it would be a worse outcome than screening against the rest.
//!
//! **A corpus where nothing parsed is a different claim**, and it is an
//! error. Zero records is indistinguishable from a clean world, so an
//! archive that held candidate records and yielded none of them is reported
//! as malformed rather than consulted.
//!
//! # Where a corpus is kept between runs
//!
//! In the **host's own cache under `setup.cache-dir`**, reached the way
//! every other download is. It is not a
//! new place and not a new mechanism: [`Cache`](crate::ext::Cache) is
//! already keyed per host, already under `cache-dir`, and already survives
//! a run, so a corpus cached anywhere else would be a second cache
//! directory answering the same question.
//!
//! Re-downloading a few hundred megabytes per invocation is the difference
//! between a tool somebody uses and one they do not, so [`acquire`] reads a
//! cached copy when it is younger than the advisor's TTL.
//!
//! **An expired copy still answers when the download fails.** A stale
//! corpus is not the same as no corpus: it is an older answer, and
//! `corpus-age` says exactly how old, which is why that field is an
//! absolute timestamp rather than a duration. `docs/contributors/exit-codes.md` treats a
//! screening resource being down harshly because "a run that copies
//! everything and reports nothing looks identical to a clean run" -- and
//! yesterday's advisories, reported as yesterday's, is not that run.
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::core::ctx::Ctx;
use crate::core::error::{Contact, Error, Result};
use crate::ext::{CachePath, Expiry, ExtHost, Hold, Judged, Lifetime, report_expired, settle};
use crate::model::EcosystemId;
use crate::net::{ByteLimit, Expectation, Req};

use super::index::Index;
use super::osv::Advisory;

/// The largest decompressed size one entry may have.
///
/// An OSV record is a few kilobytes. The biggest real ones -- a Linux kernel
/// advisory enumerating thousands of affected versions -- run to a couple of
/// megabytes, so this is generous rather than tight, and still four orders
/// of magnitude below what a bomb needs.
pub const ENTRY_LIMIT: ByteLimit = ByteLimit::mib(16);

/// The largest decompressed total an archive may expand to.
///
/// The npm corpus is the biggest today at a few hundred megabytes expanded.
/// This leaves room for years of growth and still refuses an archive that
/// claims to be a corpus and is a bomb.
pub const CORPUS_LIMIT: ByteLimit = ByteLimit::mib(4096);

/// How many entries an archive may hold.
///
/// OSV's largest ecosystem is in the low hundreds of thousands of records.
pub const ENTRY_COUNT_LIMIT: usize = 4_000_000;

/// What reading one archive produced.
///
/// Counts rather than a verdict: whether a corpus with four skipped records
/// out of two hundred thousand is acceptable is the run's question, not
/// this module's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Entries that looked like records and parsed.
    pub parsed: usize,

    /// Entries that looked like records and did not parse.
    pub skipped: usize,

    /// The newest `modified` among the records parsed, which is how stale
    /// this corpus is.
    ///
    /// Counted here rather than read off the index, because the index is
    /// shared by every advisor: its age is the newest of all of them, and a
    /// fresh malware feed must not vouch for a stale vulnerability database.
    pub modified: Option<DateTime<Utc>>,
}

impl Tally {
    /// Entries that were offered to the parser at all.
    pub fn candidates(self) -> usize {
        self.parsed + self.skipped
    }

    /// Fold another archive's tally into this one.
    pub fn add(&mut self, other: Tally) {
        self.parsed += other.parsed;
        self.skipped += other.skipped;
        self.modified = match (self.modified, other.modified) {
            (Some(mine), Some(theirs)) => Some(mine.max(theirs)),
            (mine, theirs) => mine.or(theirs),
        };
    }
}

/// How long a cached corpus stays usable before a refresh is attempted.
///
/// A day. The OSV bucket rebuilds on its own schedule and the malicious
/// feed takes commits continuously, so there is no interval that is "the
/// right one" -- this is a cost statement. A shorter one spends a few
/// hundred megabytes more often; a longer one widens the window in which a
/// newly reported malicious package is not yet screened for, which is the
/// window `ossf-malicious` exists to narrow. Configurable per advisor
/// through `advisors.*.ttl`.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60 * 24);

/// Whether a cached corpus may answer.
///
/// Separate from the TTL, which is configuration, because this comes from
/// the command line: `--refresh-advisories` is a statement about one
/// invocation and an advisor cannot make it on a user's behalf. The same
/// split `Criteria::pre_release` makes, for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Freshness {
    /// Reuse a cached copy younger than the advisor's TTL.
    #[default]
    Cached,

    /// Download regardless of what is cached.
    Refresh,
}

/// Where the archive a run read actually came from.
///
/// Reported rather than inferred, because the four are different claims
/// about how much a clean screening is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Origin {
    /// Downloaded during this run.
    #[default]
    Downloaded,

    /// Read from the host's cache, inside the advisor's TTL.
    Cached,

    /// Supplied by the user as a local file.
    Local,

    /// Read from the host's cache after the download failed, and **past**
    /// the TTL.
    ///
    /// Ordered last so a fold keeps it: one stale archive is the fact worth
    /// surfacing about a corpus, however many of its others were current.
    Stale,
}

impl Origin {
    /// Fold two origins, keeping the one a reader most needs to know about.
    pub fn worst(self, other: Origin) -> Origin {
        self.max(other)
    }
}

/// The archive to read, and where it came from.
#[derive(Debug, Clone)]
pub struct Acquired {
    pub file: CachePath,
    pub origin: Origin,

    /// Keeps the archive from size eviction until it has been read.
    #[expect(dead_code, reason = "held for its drop, which releases the archive")]
    pub hold: Option<Hold>,
}

/// Put a local file the user supplied where an advisor can read it.
///
/// Copied into the host's cache rather than opened where it lies, so one
/// code path reads every corpus however it arrived, and the archive cannot
/// change under the reader part way through. The copy is not free -- a
/// corpus is hundreds of megabytes -- and a cache holding the one file is
/// planned to replace it; see `docs/contributors/extension-refactor-plan.md`.
pub async fn local(host: &dyn ExtHost, source: &Path, name: &str) -> Result<Acquired> {
    let file = host.cache().stage(source, name).await?;

    Ok(Acquired {
        hold: Some(host.cache().hold(&file)),
        file,
        origin: Origin::Local,
    })
}

/// The archive for one corpus: cached when it is fresh, downloaded when it
/// is not, and stale when the download fails.
///
/// The order is the whole of the caching policy, and each step is a
/// different claim:
///
/// 1. A copy younger than `ttl`, unless `--refresh-advisories` said
///    otherwise. Nothing is requested at all.
/// 2. A download. What a first run, an expired cache, and a cleared
///    `cache-dir` all do.
/// 3. Failing that, **any** copy that is there, however old. See the module
///    documentation for why an older answer beats none -- and note the
///    caller still learns it happened, through [`Origin::Stale`], because
///    silently serving an expired corpus is the failure this whole module
///    is arranged to prevent.
///
/// An error comes back only when there was nothing cached to fall back to,
/// so a caller that treats some failures as *absence* rather than as
/// failure -- a 404 for an ecosystem the bucket does not publish -- still
/// sees it. That case cannot collide with step 3 in practice: nothing was
/// ever downloaded for such an ecosystem, so there is no copy to be stale.
pub async fn acquire(
    host: &dyn ExtHost,
    req: &Req,
    name: &str,
    ttl: Duration,
    freshness: Freshness,
    ctx: &Ctx,
) -> Result<Acquired> {
    let cache = host.cache();
    let path = cache.path(name)?;

    // The advisor's `ttl` is the corpus's freshness; its retention is the
    // binding's, as for any other cached file.
    let lifetime = Lifetime {
        retention: host.cache_policy().lifetime(name).retention,
        freshness: Some(ttl),
    };

    match cache.judge(&path, &lifetime) {
        Judged::Usable if freshness == Freshness::Cached => {
            let _ = cache.touch(&path, &lifetime);

            return Ok(Acquired {
                hold: Some(cache.hold(&path)),
                file: path,
                origin: Origin::Cached,
            });
        }

        // Past retention the copy should not be here, so it is no fallback
        // either.
        Judged::Expired(Expiry::Retention) => {
            report_expired(ctx, &req.url, name, Expiry::Retention);
            cache.evict(&path);
        }

        Judged::Expired(Expiry::Freshness) => {
            report_expired(ctx, &req.url, name, Expiry::Freshness);
        }

        Judged::Usable | Judged::Absent | Judged::Undated => {}
    }

    // Streamed to disk. A corpus is not a document, and a capped in-memory
    // fetch large enough to hold one would defeat the point of the cap.
    match host
        .fetch_to_cache(req, name, &Expectation::new(), ctx)
        .await
    {
        Ok(file) => {
            let hold = cache.hold(&file);
            settle(host, &file, &req.url, name, &lifetime, ctx)?;

            Ok(Acquired {
                hold: Some(hold),
                file,
                origin: Origin::Downloaded,
            })
        }

        Err(err) => match cache.staged(name) {
            Some(staged) => Ok(Acquired {
                hold: Some(cache.hold(staged.path())),
                file: staged.into_path(),
                origin: Origin::Stale,
            }),

            None => Err(err),
        },
    }
}

/// Read every record `claims` accepts out of a zip in `host`'s cache, into
/// `index`. See [`read_zip`].
pub async fn read_zip_from_host(
    file: &CachePath,
    url: &str,
    claims: fn(&str) -> bool,
    only: &[EcosystemId],
    index: &mut Index,
    host: &dyn ExtHost,
) -> Result<Tally> {
    let path = host.cache().resolve_existing(file)?;

    read_zip(&path, url, claims, only, index).await
}

/// Read every record `claims` accepts out of the zip at `path`, into
/// `index`.
///
/// `claims` decides which entry paths are records, which is the only thing
/// the two corpora disagree about: OSV's archive is records and nothing
/// else, while a repository snapshot is mostly not.
///
/// `only` narrows the records to those ecosystems, or keeps every one when
/// empty: `advisors.*.ecosystems` on a corpus that holds several, such as a
/// repository snapshot. A record keeps only its `affected` entries in
/// `only`, and is dropped when none remain. It still dates the corpus,
/// since the file is no older for holding records the run did not ask for.
///
/// `url` is carried only so a failure names where the archive came from --
/// "cannot parse advisory corpus" with no origin is unactionable when three
/// are configured.
pub async fn read_zip(
    path: &Path,
    url: &str,
    claims: fn(&str) -> bool,
    only: &[EcosystemId],
    index: &mut Index,
) -> Result<Tally> {
    let path = path.to_path_buf();

    // Decompressing a corpus is seconds of CPU with no waiting in it, and
    // this runs on the same runtime as every download. Left on the async
    // worker it would stall the pool for the whole of that.
    //
    // The records come back rather than the index going in, because the
    // index is the caller's and moving it across the boundary and back
    // would mean the caller could not hold it while this ran.
    let (records, mut read) = tokio::task::spawn_blocking(move || scan(&path, claims))
        .await
        // A panic or a cancellation in the unpacking task. Surfaced rather
        // than swallowed for the same reason a cap is an error: the corpus
        // was not read, and anything that treats "not read" as "nothing
        // found" reports a clean run.
        .map_err(|source| Error::Transport {
            url: url.to_owned(),
            during: Contact::Connect,
            source: Box::new(source),
        })?
        .map_err(|detail| Error::Malformed {
            what: "advisory corpus",
            url: url.to_owned(),
            detail,
        })?;

    // Nothing parsed, and something was there to parse. Reported rather
    // than returned empty: a corpus that yields no records screens every
    // artifact clean, which is the one answer that must never be invented.
    if read.parsed == 0 && read.skipped > 0 {
        return Err(Error::Malformed {
            what: "advisory corpus",
            url: url.to_owned(),
            detail: format!("none of its {} records could be read", read.skipped),
        });
    }

    for mut record in records {
        read.modified = super::index::newer(read.modified, record.modified.as_deref());

        if !only.is_empty() {
            record.affected.retain(|entry| {
                index
                    .ecosystems()
                    .translate(&entry.package.ecosystem)
                    .is_some_and(|id| only.contains(&id))
            });

            if record.affected.is_empty() {
                continue;
            }
        }

        index.insert(record);
    }

    Ok(read)
}

/// The blocking half: open the zip and parse what `claims` accepts.
///
/// Errors are strings rather than [`Error`] values because this runs off the
/// async runtime and the caller is the one that knows the URL to name.
fn scan(
    path: &std::path::Path,
    claims: fn(&str) -> bool,
) -> std::result::Result<(Vec<Advisory>, Tally), String> {
    let file = std::fs::File::open(path).map_err(|source| source.to_string())?;

    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|source| format!("it is not a readable zip: {source}"))?;

    if archive.len() > ENTRY_COUNT_LIMIT {
        return Err(format!(
            "it holds {} entries, past the {ENTRY_COUNT_LIMIT} allowed",
            archive.len()
        ));
    }

    let mut records = Vec::new();
    let mut read = Tally::default();
    let mut expanded: u64 = 0;
    let mut body = Vec::new();

    for position in 0..archive.len() {
        let mut entry = archive
            .by_index(position)
            .map_err(|source| format!("entry {position} cannot be read: {source}"))?;

        // `name` rather than `enclosed_name`: nothing here is written to
        // disk, so a traversal in the path is only a string. What the path
        // decides is whether the entry is a record at all.
        if !entry.is_file() || !claims(entry.name()) {
            continue;
        }

        body.clear();

        // Capped while decompressing, never from the entry's declared size:
        // the declared size is a field in the archive, so trusting it is
        // precisely how the cap gets bypassed.
        let taken = entry
            .by_ref()
            .take(ENTRY_LIMIT.get() + 1)
            .read_to_end(&mut body)
            .map_err(|source| format!("{} cannot be decompressed: {source}", entry.name()))?;

        if taken as u64 > ENTRY_LIMIT.get() {
            return Err(format!(
                "{} expands past the {ENTRY_LIMIT} byte entry limit",
                entry.name()
            ));
        }

        expanded += taken as u64;

        if expanded > CORPUS_LIMIT.get() {
            return Err(format!("it expands past the {CORPUS_LIMIT} byte limit"));
        }

        match serde_json::from_slice::<Advisory>(&body) {
            Ok(record) => {
                read.parsed += 1;
                records.push(record);
            }

            // Skipped and counted. See the module documentation: one
            // unreadable file in a quarter of a million must not take
            // screening down, and nothing parsing at all is caught by the
            // caller.
            Err(_) => read.skipped += 1,
        }
    }

    Ok((records, read))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::io::Write;

    use crate::core::ctx::Ctx;
    use crate::ext::testing::{Fixture, TestHost};
    use crate::model::{ArtifactId, Cause, EcosystemId};
    use crate::net::{Canned, FixtureClient};

    use crate::advisory::index::Ecosystems;

    const URL: &str = "h://corpus.test/all.zip";

    /// Everything in the fixture archives is a record.
    fn every_entry(_name: &str) -> bool {
        true
    }

    /// Only `.json`, which is what a repository snapshot needs.
    fn only_json(name: &str) -> bool {
        name.ends_with(".json")
    }

    fn zipped(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buffer = Vec::new();

        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));

            for (name, body) in entries {
                writer
                    .start_file(*name, zip::write::SimpleFileOptions::default())
                    .expect("entry");
                writer.write_all(body).expect("written");
            }

            writer.finish().expect("finished");
        }

        buffer
    }

    fn record(id: &str, name: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"{id}","modified":"2024-06-01T00:00:00Z",
                "affected":[{{"package":{{"ecosystem":"npm","name":"{name}"}},
                              "versions":["1.0.0"]}}]}}"#
        )
        .into_bytes()
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "corpus".to_owned(),
        })
    }

    fn npm(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, name)
    }

    /// Stage an archive through the host capability, exactly as an advisor
    /// does, then read it.
    async fn read(body: Vec<u8>, claims: fn(&str) -> bool) -> (Result<Tally>, Index) {
        let f = Fixture::new((), FixtureClient::new().with_body(URL, body));
        let ctx = ctx();

        let staged = f
            .host
            .fetch_to_cache(&Req::get(URL), "corpus.zip", &Expectation::new(), &ctx)
            .await
            .expect("staged");

        let mut index = Index::new(Ecosystems::builtin());
        let outcome = read_zip_from_host(&staged, URL, claims, &[], &mut index, &*f.host).await;

        (outcome, index)
    }

    // -- The ordinary path -------------------------------------------------

    #[tokio::test]
    async fn archive_every_record_indexed() {
        let (outcome, index) = read(
            zipped(&[
                ("GHSA-1.json", &record("GHSA-1", "tuna")),
                ("GHSA-2.json", &record("GHSA-2", "marlin")),
            ]),
            every_entry,
        )
        .await;

        assert_eq!(outcome.expect("read").parsed, 2);
        assert_eq!(index.records(), 2);
        assert_eq!(index.advisories(&npm("tuna")).len(), 1);
        assert_eq!(index.advisories(&npm("marlin")).len(), 1);
    }

    // -- ZIP64 --------------------------------------------------------------

    /// The ZIP64 end-of-central-directory record's signature, `PK\x06\x06`.
    const ZIP64_END: &[u8] = b"PK\x06\x06";

    /// A ZIP64 archive, the shape OSV's npm corpus takes: more entries than
    /// a classic end record can count, so their number lives only in the
    /// ZIP64 record, and one record written with ZIP64 sizes as well.
    fn zip64(records: &[(&str, &[u8])]) -> Vec<u8> {
        let past_classic_count = usize::from(u16::MAX) + 1;
        let mut buffer = Vec::new();

        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            for (at, (name, body)) in records.iter().enumerate() {
                writer
                    .start_file(*name, options.large_file(at == 0))
                    .expect("entry");
                writer.write_all(body).expect("written");
            }

            // Filler the claim passes over, enough to need the ZIP64 count.
            for at in 0..past_classic_count {
                writer
                    .start_file(format!("filler/{at}.txt"), options)
                    .expect("entry");
            }

            writer.finish().expect("finished");
        }

        buffer
    }

    /// Past 65535 entries the classic end record cannot hold the count, and
    /// the reader must find it in the ZIP64 record. Every entry is read,
    /// and the records among them are indexed.
    #[tokio::test]
    async fn archive_zip64_read() {
        let body = zip64(&[
            ("GHSA-1.json", &record("GHSA-1", "tuna")),
            ("GHSA-2.json", &record("GHSA-2", "marlin")),
        ]);

        assert!(
            body.windows(ZIP64_END.len())
                .any(|window| window == ZIP64_END),
            "the fixture is not a ZIP64 archive"
        );

        let (outcome, index) = read(body, only_json).await;

        assert_eq!(outcome.expect("read").parsed, 2);
        assert_eq!(index.advisories(&npm("tuna")).len(), 1);
        assert_eq!(index.advisories(&npm("marlin")).len(), 1);
    }

    /// A repository snapshot is mostly not records, which is the whole
    /// reason the claim is the advisor's to make.
    #[tokio::test]
    async fn entry_unclaimed_not_read() {
        let (outcome, index) = read(
            zipped(&[
                ("README.md", b"not a record"),
                ("MAL-1.json", &record("MAL-1", "tuna")),
            ]),
            only_json,
        )
        .await;

        assert_eq!(
            outcome.expect("read").candidates(),
            1,
            "the README was never offered to the parser"
        );
        assert_eq!(index.records(), 1);
    }

    /// An archive that holds no records at all is empty rather than broken:
    /// an ecosystem with no published advisories is a real thing.
    #[tokio::test]
    async fn archive_without_records_reads_empty() {
        let (outcome, index) = read(zipped(&[("README.md", b"nothing here")]), only_json).await;

        assert_eq!(outcome.expect("read"), Tally::default());
        assert!(index.is_empty());
    }

    // -- One bad record, and a bad corpus ----------------------------------

    /// A quarter of a million machine-published files will eventually
    /// contain one this cannot read, and screening against the rest beats
    /// screening against nothing.
    #[tokio::test]
    async fn record_unreadable_keeps_others() {
        let (outcome, index) = read(
            zipped(&[
                ("GHSA-1.json", &record("GHSA-1", "tuna")),
                ("GHSA-2.json", b"{not json"),
            ]),
            every_entry,
        )
        .await;

        let read = outcome.expect("read");

        assert_eq!(read.parsed, 1);
        assert_eq!(read.skipped, 1);
        assert_eq!(index.advisories(&npm("tuna")).len(), 1);
    }

    /// **The case that must not read as clean.** Zero records screens every
    /// artifact clean, so an archive that held records and yielded none is
    /// malformed rather than consulted.
    #[tokio::test]
    async fn archive_nothing_parses_refused() {
        let (outcome, _) = read(
            zipped(&[("GHSA-1.json", b"{not json"), ("GHSA-2.json", b"<html>")]),
            every_entry,
        )
        .await;

        let message = outcome.expect_err("refused").to_string();

        assert!(message.contains(URL), "{message}");
        assert!(message.contains("none of its 2 records"), "{message}");
    }

    // -- The caps ----------------------------------------------------------

    /// A screening resource mishandled does not lose an artifact, it
    /// reports a clean run, so a bomb here is a denial of screening.
    #[tokio::test]
    async fn entry_past_cap_refused() {
        // Compresses to almost nothing and expands past the cap, which is
        // the shape of the attack.
        let bomb = vec![b'a'; ENTRY_LIMIT.get() as usize + 1];

        let (outcome, _) = read(zipped(&[("GHSA-1.json", &bomb)]), every_entry).await;

        let message = outcome.expect_err("refused").to_string();

        assert!(message.contains("entry limit"), "{message}");
    }

    /// Reaching a cap is an error and never a short read: a corpus cut off
    /// part way answers "nothing found" about the rest.
    #[tokio::test]
    async fn archive_refused_indexes_nothing() {
        let bomb = vec![b'a'; ENTRY_LIMIT.get() as usize + 1];

        let (outcome, index) = read(
            zipped(&[
                ("GHSA-1.json", &record("GHSA-1", "tuna")),
                ("GHSA-2.json", &bomb),
            ]),
            every_entry,
        )
        .await;

        assert!(outcome.is_err());
        assert!(
            index.is_empty(),
            "a partly read corpus must not answer questions"
        );
    }

    #[tokio::test]
    async fn archive_not_zip_says_so() {
        let (outcome, _) = read(b"not an archive at all".to_vec(), every_entry).await;

        let message = outcome.expect_err("refused").to_string();

        assert!(message.contains("readable zip"), "{message}");
    }

    /// The host capability is the only way out, so a `TestHost` that
    /// permits nothing is what proves an advisor cannot reach around it.
    #[tokio::test]
    async fn archive_fetched_through_capability() {
        let host = TestHost::allowing(
            FixtureClient::new()
                .with_body(URL, zipped(&[("GHSA-1.json", &record("GHSA-1", "tuna"))])),
            "h://elsewhere.test/",
        );

        let ctx = ctx();

        let refused = host
            .fetch_to_cache(&Req::get(URL), "corpus.zip", &Expectation::new(), &ctx)
            .await;

        assert!(refused.is_err(), "the corpus host was not permitted");
    }

    // -- Caching in the host's own directory -------------------------------

    const HOUR: Duration = Duration::from_secs(3_600);

    fn one_record() -> Vec<u8> {
        zipped(&[("GHSA-1.json", &record("GHSA-1", "tuna"))])
    }

    /// A fixture whose cache two `acquire` calls share, which is what a
    /// second run against the same `cache-dir` sees.
    fn serving(body: Vec<u8>) -> Fixture<()> {
        Fixture::new((), FixtureClient::new().with_body(URL, body))
    }

    async fn acquired(
        f: &Fixture<()>,
        ctx: &Ctx,
        ttl: Duration,
        freshness: Freshness,
    ) -> Result<Acquired> {
        acquire(&*f.host, &Req::get(URL), "corpus.zip", ttl, freshness, ctx).await
    }

    /// The first run downloads.
    #[tokio::test]
    async fn cache_cold_downloads() {
        let f = serving(one_record());
        let ctx = ctx();

        let first = acquired(&f, &ctx, HOUR, Freshness::Cached)
            .await
            .expect("downloaded");

        assert_eq!(first.origin, Origin::Downloaded);
        assert_eq!(f.host.hits(URL), 1);
    }

    /// **The reason any of this exists.** A corpus is a few hundred
    /// megabytes, and a second run inside the TTL must not ask for it
    /// again.
    #[tokio::test]
    async fn cache_fresh_copy_costs_no_request() {
        let f = serving(one_record());
        let ctx = ctx();

        acquired(&f, &ctx, HOUR, Freshness::Cached)
            .await
            .expect("downloaded");

        let second = acquired(&f, &ctx, HOUR, Freshness::Cached)
            .await
            .expect("reused");

        assert_eq!(second.origin, Origin::Cached);
        assert_eq!(f.host.hits(URL), 1, "the second run asked for nothing");
    }

    /// A zero TTL expires everything, which is what an advisor configured
    /// to always refresh reduces to.
    #[tokio::test]
    async fn cache_expired_downloaded_again() {
        let f = serving(one_record());
        let ctx = ctx();

        acquired(&f, &ctx, Duration::ZERO, Freshness::Cached)
            .await
            .expect("downloaded");

        let second = acquired(&f, &ctx, Duration::ZERO, Freshness::Cached)
            .await
            .expect("downloaded again");

        assert_eq!(second.origin, Origin::Downloaded);
        assert_eq!(f.host.hits(URL), 2);
    }

    /// `--refresh-advisories`, which must beat a cached copy that is still
    /// inside its TTL or the flag does nothing.
    #[tokio::test]
    async fn cache_refresh_ignores_fresh_copy() {
        let f = serving(one_record());
        let ctx = ctx();

        acquired(&f, &ctx, HOUR, Freshness::Cached)
            .await
            .expect("downloaded");

        let second = acquired(&f, &ctx, HOUR, Freshness::Refresh)
            .await
            .expect("downloaded again");

        assert_eq!(second.origin, Origin::Downloaded);
        assert_eq!(f.host.hits(URL), 2);
    }

    /// **Yesterday's advisories, reported as yesterday's, beats none.** The
    /// caller still learns it happened, which is what keeps this from being
    /// the silently-clean run the architecture document warns about.
    #[tokio::test]
    async fn download_failed_falls_back_to_expired() {
        let client = FixtureClient::new().with_sequence(
            URL,
            vec![
                Canned::ok(one_record()),
                Canned::status(StatusCode::SERVICE_UNAVAILABLE),
            ],
        );

        let f = Fixture::new((), client);
        let ctx = ctx();

        acquired(&f, &ctx, Duration::ZERO, Freshness::Cached)
            .await
            .expect("the first download worked");

        let second = acquired(&f, &ctx, Duration::ZERO, Freshness::Cached)
            .await
            .expect("the expired copy answered");

        assert_eq!(second.origin, Origin::Stale);
        assert_eq!(f.host.hits(URL), 2, "and it did try");
    }

    /// With nothing cached there is nothing to fall back to, so the failure
    /// is the answer -- which is what lets `osv-offline` tell a 404 for an
    /// unpublished ecosystem apart from a corpus it could not reach.
    #[tokio::test]
    async fn download_failed_without_copy_is_error() {
        let f = Fixture::new(
            (),
            FixtureClient::new().with(URL, Canned::status(StatusCode::SERVICE_UNAVAILABLE)),
        );
        let ctx = ctx();

        let outcome = acquired(&f, &ctx, HOUR, Freshness::Cached).await;

        assert!(outcome.is_err());
    }

    // -- A file the user supplied ------------------------------------------

    /// An air-gapped run, or one whose corpora are mirrored by something
    /// other than this tool.
    #[tokio::test]
    async fn local_file_read_without_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("all.zip");

        std::fs::write(&path, one_record()).expect("written");

        let f = Fixture::new((), FixtureClient::new());
        let acquired = local(&*f.host, &path, "corpus.zip").await.expect("staged");

        assert_eq!(acquired.origin, Origin::Local);
        assert!(f.host.requested().is_empty(), "nothing was asked for");

        // And it reads as any other archive does.
        let mut index = Index::new(Ecosystems::builtin());
        let read = read_zip_from_host(
            &acquired.file,
            "all.zip",
            every_entry,
            &[],
            &mut index,
            &*f.host,
        )
        .await
        .expect("read");

        assert_eq!(read.parsed, 1);
    }

    #[tokio::test]
    async fn local_file_missing_says_so() {
        let f = Fixture::new((), FixtureClient::new());

        let outcome = local(&*f.host, Path::new("/nonexistent/all.zip"), "corpus.zip").await;

        assert!(outcome.is_err());
    }

    // -- Folding origins ---------------------------------------------------

    /// One stale archive is the fact worth surfacing about a corpus,
    /// however many of its others were current.
    #[test]
    fn origin_worst_wins() {
        assert_eq!(
            Origin::Downloaded.worst(Origin::Stale),
            Origin::Stale,
            "a corpus is only as trustworthy as its stalest part"
        );
        assert_eq!(Origin::Downloaded.worst(Origin::Cached), Origin::Cached);
        assert_eq!(
            Origin::Downloaded.worst(Origin::Downloaded),
            Origin::Downloaded
        );
    }
}
