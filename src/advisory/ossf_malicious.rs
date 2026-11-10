//! The `ossf/malicious-packages` feed.
//!
//! # Why this exists when OSV already carries it
//!
//! It is **deliberately redundant**, and the redundancy is the feature. OSV
//! ingests this feed, so nearly every record here arrives there too --
//! eventually. Two things make "eventually" the wrong thing to rely on for
//! malware:
//!
//! - **Ingestion lags.** A malicious package is reported, published here
//!   within hours, and appears in the OSV bucket's next build. A run in
//!   between screens against a corpus that does not know yet.
//! - **Malicious packages are yanked fast.** A registry removes one within
//!   days, which is what makes the window narrow -- and also what makes a
//!   mirror that already copied it the only place the package still exists.
//!
//! So the two corpora are configured together and read into one index, where
//! [`Index::insert`] drops the second copy of a record the first already
//! carried. The cost of the redundancy is a download; the cost of not having
//! it is copying malware during the window.
//!
//! # A repository, read as an archive
//!
//! This is a git repository rather than a published corpus, so it is read as
//! a snapshot of its default branch. GitHub answers the archive URL with a
//! redirect to `codeload.github.com`, so the configured host lists codeload
//! as an additional host: a redirect across hosts is followed only where
//! configuration says it may go.
//!
//! ```text
//!   {base}/{owner}/{repo}/archive/refs/heads/{branch}.zip
//!     -> 302 codeload.github.com/...
//!     -> {repo}-{branch}/osv/malicious/{ecosystem}/{name}/MAL-....json
//! ```
//!
//! # Which entries count
//!
//! A repository snapshot is mostly not records: a README, the tooling that
//! builds the feed, schemas, tests. The claim is therefore made on the path,
//! and it is made **loosely on the prefix and strictly on the exclusion**:
//!
//! - A `.json` file under a `malicious` directory is a record. The archive's
//!   top-level directory is named for the branch, so no absolute prefix can
//!   be hardcoded, and the layout beneath it is the feed's to change.
//! - Anything under a `withdrawn` directory is **not**, whatever else it
//!   looks like. The feed keeps retracted reports there, and screening
//!   against one reports malware nobody claims any more -- the same argument
//!   [`Index::insert`] drops a withdrawn record for, one step earlier.
//!
//! Being loose costs nothing: a stray JSON file that is not a record either
//! fails to parse, and is counted, or parses into a record naming no package
//! and is keyed under nothing.
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;
use crate::net::Req;

use super::archive::{self, Freshness};
use super::index::Index;
use super::{Advisor, Loaded, Settings};

/// Where GitHub serves repository snapshots, by a redirect to
/// `codeload.github.com`.
pub const GITHUB: &str = "https://github.com";

/// The feed's repository.
pub const REPOSITORY: &str = "ossf/malicious-packages";

/// The branch a snapshot is taken from.
pub const BRANCH: &str = "main";

/// This advisor's configured `kind`.
pub const KIND: &str = "ossf-malicious";

/// This corpus's kind, for [`super::open`].
pub(super) const ADVISOR: super::AdvisorKind = super::AdvisorKind {
    name: KIND,
    open: |base_url, settings, options, host| {
        Ok(Box::new(configured(base_url, settings, options, host)?))
    },
};

/// The corpus at `base_url`, as `settings` and `options` configure it.
fn configured(
    base_url: &str,
    settings: &Settings,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<OssfMalicious> {
    let repository = options.repository()?.unwrap_or(REPOSITORY);
    let branch = options.string(BRANCH_OPTION)?.unwrap_or(BRANCH);

    let mut advisor = OssfMalicious::at(base_url, host)
        .from_repository(repository, branch)
        .for_ecosystems(settings.ecosystems.clone());

    if let Some(ttl) = settings.ttl {
        advisor = advisor.with_ttl(ttl);
    }

    if let Some(path) = &settings.path {
        advisor = advisor.from_file(path);
    }

    Ok(advisor)
}

/// The option naming which branch of the repository to read.
///
/// Beside the well-known [`crate::ext::options::REPOSITORY`], which names the
/// repository.
pub const BRANCH_OPTION: &str = "branch";

/// What a supplied snapshot is called inside the cache.
const SNAPSHOT_FILE: &str = "ossf-malicious.zip";

/// The OpenSSF malicious-packages feed, read as a repository snapshot.
pub struct OssfMalicious {
    base_url: String,

    /// Where every request goes, and whose directory caches the corpus.
    host: Arc<dyn ExtHost>,
    repository: String,
    branch: String,

    /// How long a cached snapshot stays usable. `advisors.*.ttl`.
    ttl: Duration,

    /// Which ecosystems to keep, or empty for every one. `advisors.*.ecosystems`.
    ///
    /// Narrowed as the snapshot is read rather than as it is fetched: the
    /// feed is one archive holding every ecosystem.
    only: Vec<EcosystemId>,

    /// A snapshot on disk to read instead of fetching one.
    ///
    /// The case this exists for: an organization that already mirrors the
    /// feed, or a run with no route to GitHub at all. A **zip** of the
    /// repository, which is what `git archive` and GitHub's own download
    /// button both produce -- a working clone is a directory rather than an
    /// archive, and reading one is a separate to-do.
    local: Option<PathBuf>,
}

impl OssfMalicious {
    /// The published feed.
    pub fn new(host: Arc<dyn ExtHost>) -> Self {
        Self::at(GITHUB, host)
    }

    /// From somewhere else, which is how this is tested and how an internal
    /// mirror of the feed is used.
    pub fn at(base_url: &str, host: Arc<dyn ExtHost>) -> Self {
        Self {
            base_url: crate::net::normalized_base(base_url),
            host,
            repository: REPOSITORY.to_owned(),
            branch: BRANCH.to_owned(),
            ttl: archive::DEFAULT_TTL,
            only: Vec::new(),
            local: None,
        }
    }

    /// Read `path` instead of fetching, and make no request at all.
    ///
    /// `advisors.*.path`. A zip of the feed's repository: `git archive`,
    /// GitHub's download button, or a copy of the snapshot this advisor
    /// would have fetched. The entry claim is the same either way, so a
    /// snapshot taken any of those ways reads identically.
    pub fn from_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.local = Some(path.into());

        self
    }

    /// How long a cached snapshot stays usable before a refresh is
    /// attempted.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;

        self
    }

    /// Keep only records about these ecosystems.
    ///
    /// `advisors.*.ecosystems` in the configuration, whose documented
    /// meaning is that empty is all of them.
    pub fn for_ecosystems(mut self, only: Vec<EcosystemId>) -> Self {
        self.only = only;

        self
    }

    /// Read a different repository or branch.
    ///
    /// For an organization that maintains its own additions to the feed, and
    /// for pinning a branch when the upstream default moves.
    pub fn from_repository(mut self, repository: &str, branch: &str) -> Self {
        self.repository = repository.to_owned();
        self.branch = branch.to_owned();

        self
    }

    fn snapshot_url(&self) -> String {
        format!(
            "{}/{}/archive/refs/heads/{}.zip",
            self.base_url, self.repository, self.branch
        )
    }

    /// What a fetched snapshot is called inside the cache.
    ///
    /// Named for the repository and branch, so two advisors on one host
    /// reading different feeds do not answer from each other's copy.
    /// Anything outside a conservative set becomes `_`, since the name is a
    /// file in the host's cache: `acme/feed` on `main` is
    /// `ossf-acme_feed-main.zip`.
    fn cache_name(&self) -> String {
        let safe = |text: &str| -> String {
            text.chars()
                .map(
                    |ch| match ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                        true => ch,
                        false => '_',
                    },
                )
                .collect()
        };

        format!("ossf-{}-{}.zip", safe(&self.repository), safe(&self.branch))
    }
}

#[async_trait]
impl Advisor for OssfMalicious {
    async fn load(&self, index: &mut Index, freshness: Freshness, ctx: &Ctx) -> Result<Loaded> {
        // Refused rather than skipped, for the reason `osv-offline` gives:
        // an ecosystem the index cannot key would keep nothing, and the
        // user named it expecting it screened.
        if let Some(id) = self
            .only
            .iter()
            .find(|id| index.ecosystems().osv_name(id).is_none())
        {
            return Err(Error::Config(format!(
                "the {KIND} advisor was asked for the {id} ecosystem, \
                 which declares no OSV name to key its records under"
            )));
        }

        // A snapshot somebody supplied, read in place of asking GitHub for
        // one. Named for where it came from, so a failure inside it points
        // at the file rather than at a URL nothing fetched.
        let (acquired, named) = match &self.local {
            Some(path) => (
                archive::local(&*self.host, path, SNAPSHOT_FILE).await?,
                path.display().to_string(),
            ),

            None => {
                let url = self.snapshot_url();
                let acquired = archive::acquire(
                    &*self.host,
                    &Req::get(&url),
                    &self.cache_name(),
                    self.ttl,
                    freshness,
                    ctx,
                )
                .await?;

                (acquired, url)
            }
        };

        let tally = archive::read_zip_from_host(
            &acquired.file,
            &named,
            is_record,
            &self.only,
            index,
            &*self.host,
        )
        .await?;

        Ok(Loaded {
            modified: tally.modified,
            tally,
            origin: acquired.origin,
        })
    }
}

/// Whether an archive entry is a live malware record.
///
/// See the module documentation for why the prefix is matched loosely and
/// the exclusion strictly. The path is split on `/` because that is what a
/// zip entry uses whatever the host's separator is.
fn is_record(path: &str) -> bool {
    if !path.ends_with(".json") {
        return false;
    }

    let mut under_malicious = false;

    for part in path.split('/') {
        // A retracted report. Checked over the whole path rather than only
        // beside `malicious`, so a reorganization that nests the two
        // differently still cannot let one through.
        if part == "withdrawn" {
            return false;
        }

        if part == "malicious" {
            under_malicious = true;
        }
    }

    under_malicious
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::io::Write;

    use crate::advisory::archive::Origin;
    use crate::advisory::index::Ecosystems;
    use crate::core::ctx::Ctx;
    use crate::ext::testing::{Fixture, idle};
    use crate::model::{ArtifactId, Cause, EcosystemId};
    use crate::net::{Canned, FixtureClient};

    const BASE: &str = "h://github.test";

    /// The path shape a snapshot actually has, top-level directory and all.
    fn entry(ecosystem: &str, name: &str, id: &str) -> String {
        format!("malicious-packages-main/osv/malicious/{ecosystem}/{name}/{id}.json")
    }

    fn zipped(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut buffer = Vec::new();

        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));

            for (name, body) in entries {
                writer
                    .start_file(name.as_str(), zip::write::SimpleFileOptions::default())
                    .expect("entry");
                writer.write_all(body).expect("written");
            }

            writer.finish().expect("finished");
        }

        buffer
    }

    fn record(id: &str, ecosystem: &str, name: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"{id}","modified":"2024-06-01T00:00:00Z",
                "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{name}"}},
                              "versions":["1.0.0"]}}]}}"#
        )
        .into_bytes()
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "advisories".to_owned(),
        })
    }

    fn snapshot() -> String {
        format!("{BASE}/ossf/malicious-packages/archive/refs/heads/main.zip")
    }

    async fn load_from(entries: &[(String, Vec<u8>)]) -> (Result<Loaded>, Index) {
        let f = Fixture::new(
            (),
            FixtureClient::new().with_body(snapshot(), zipped(entries)),
        );
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());
        let loaded = OssfMalicious::at(BASE, f.shared())
            .load(&mut index, Freshness::Cached, &ctx)
            .await;

        (loaded, index)
    }

    // -- The URL -----------------------------------------------------------

    #[test]
    fn snapshot_url_github_archive() {
        assert_eq!(
            OssfMalicious::new(idle()).snapshot_url(),
            "https://github.com/ossf/malicious-packages/archive/refs/heads/main.zip"
        );
    }

    #[test]
    fn snapshot_other_repository_and_branch_read() {
        let advisor = OssfMalicious::at(BASE, idle()).from_repository("acme/feed", "trunk");

        assert_eq!(
            advisor.snapshot_url(),
            format!("{BASE}/acme/feed/archive/refs/heads/trunk.zip")
        );
    }

    // -- Ecosystems --------------------------------------------------------

    /// The feed is one archive holding every ecosystem, so
    /// `advisors.*.ecosystems` narrows it as it is read.
    #[tokio::test]
    async fn snapshot_narrowed_by_ecosystems() {
        let f = Fixture::new(
            (),
            FixtureClient::new().with_body(
                snapshot(),
                zipped(&[
                    (
                        entry("npm", "tuna", "MAL-2024-1"),
                        record("MAL-2024-1", "npm", "tuna"),
                    ),
                    (
                        entry("pypi", "marlin", "MAL-2024-2"),
                        record("MAL-2024-2", "PyPI", "marlin"),
                    ),
                ]),
            ),
        );
        let ctx = ctx();
        let mut index = Index::new(Ecosystems::builtin());

        OssfMalicious::at(BASE, f.shared())
            .for_ecosystems(vec![EcosystemId::npm()])
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("loaded");

        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");
        let marlin = ArtifactId::new(EcosystemId::pypi(), None, "marlin");

        assert_eq!(index.advisories(&tuna).len(), 1);
        assert!(index.advisories(&marlin).is_empty());
    }

    /// Named, and unkeyable: refused rather than silently screening nothing.
    #[tokio::test]
    async fn ecosystem_without_osv_name_refused() {
        let ctx = ctx();
        let mut index = Index::new(Ecosystems::builtin());

        let outcome = OssfMalicious::at(BASE, idle())
            .for_ecosystems(vec![EcosystemId::raw()])
            .load(&mut index, Freshness::Cached, &ctx)
            .await;

        assert!(matches!(outcome, Err(Error::Config(_))));
    }

    // -- Which entries count -----------------------------------------------

    #[tokio::test]
    async fn record_under_malicious_read() {
        let (loaded, index) = load_from(&[(
            entry("npm", "tuna", "MAL-2024-1"),
            record("MAL-2024-1", "npm", "tuna"),
        )])
        .await;

        assert_eq!(loaded.expect("loaded").tally.parsed, 1);

        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");
        let listing = &index.advisories(&tuna)[0];

        assert_eq!(listing.advisory().id, "MAL-2024-1");
        assert!(
            listing.advisory().is_malware(),
            "the feed's own identifiers are what make this a quarantine \
             rather than a warning"
        );
    }

    /// The feed keeps retracted reports in a `withdrawn` tree beside the
    /// live one, and screening against one reports malware nobody claims
    /// any more.
    ///
    /// What this pins is that a sibling tree is not swept up by the loose
    /// prefix: the path carries no `malicious` component, so it is not a
    /// record. The `withdrawn` exclusion itself is defence against a
    /// reorganization that nests the two, and is pinned separately by
    /// `claim_withdrawal_anywhere_in_path_excluded`.
    #[tokio::test]
    async fn record_withdrawn_beside_live_tree_not_read() {
        let (loaded, index) = load_from(&[
            (
                entry("npm", "tuna", "MAL-2024-1"),
                record("MAL-2024-1", "npm", "tuna"),
            ),
            (
                "malicious-packages-main/osv/withdrawn/npm/marlin/MAL-2024-2.json".to_owned(),
                record("MAL-2024-2", "npm", "marlin"),
            ),
        ])
        .await;

        assert_eq!(loaded.expect("loaded").tally.parsed, 1);

        let marlin = ArtifactId::new(EcosystemId::npm(), None, "marlin");

        assert!(index.advisories(&marlin).is_empty());
    }

    /// A repository snapshot is mostly not records.
    #[tokio::test]
    async fn record_excludes_repository_files() {
        let (loaded, _) = load_from(&[
            (
                "malicious-packages-main/README.md".to_owned(),
                b"the feed".to_vec(),
            ),
            (
                "malicious-packages-main/schema/osv.json".to_owned(),
                b"{\"not\": \"a record\"}".to_vec(),
            ),
            (
                entry("npm", "tuna", "MAL-2024-1"),
                record("MAL-2024-1", "npm", "tuna"),
            ),
        ])
        .await;

        assert_eq!(
            loaded.expect("loaded").tally.candidates(),
            1,
            "only the one under `malicious` was offered to the parser"
        );
    }

    /// The top-level directory is named for the branch, so no absolute
    /// prefix can be hardcoded and the layout beneath it is the feed's to
    /// change.
    #[test]
    fn claim_ignores_archive_top_directory() {
        assert!(is_record(
            "malicious-packages-trunk/osv/malicious/npm/tuna/MAL-1.json"
        ));
        assert!(is_record("anything/at/all/malicious/x/MAL-1.json"));
        assert!(!is_record("malicious-packages-main/osv/malicious/npm/tuna"));
        assert!(!is_record("malicious/notes.txt"));
    }

    /// A directory merely *named* like the prefix is not the prefix: the
    /// check is on path components, not on a substring.
    #[test]
    fn claim_similar_directory_not_matched() {
        assert!(!is_record("maliciousness/npm/tuna/MAL-1.json"));
        assert!(!is_record("osv/malicious-packages/npm/tuna/MAL-1.json"));
    }

    /// Checked over the whole path rather than only beside `malicious`, so a
    /// reorganization that nests the two differently still cannot let a
    /// retraction through.
    #[test]
    fn claim_withdrawal_anywhere_in_path_excluded() {
        assert!(!is_record("osv/malicious/withdrawn/npm/tuna/MAL-1.json"));
        assert!(!is_record("withdrawn/osv/malicious/npm/tuna/MAL-1.json"));
    }

    // -- Redundancy with the OSV corpus ------------------------------------

    /// The two corpora are configured together on purpose, and one index
    /// fed by both is what keeps a record carried by each from being
    /// reported twice.
    #[tokio::test]
    async fn record_already_in_osv_not_listed_twice() {
        let f = Fixture::new(
            (),
            FixtureClient::new().with_body(
                snapshot(),
                zipped(&[(
                    entry("npm", "tuna", "MAL-2024-1"),
                    record("MAL-2024-1", "npm", "tuna"),
                )]),
            ),
        );
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        // Standing in for the OSV corpus, which ingests this feed.
        index.insert(serde_json::from_slice(&record("MAL-2024-1", "npm", "tuna")).expect("parses"));

        OssfMalicious::at(BASE, f.shared())
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("loaded");

        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert_eq!(index.advisories(&tuna).len(), 1);
        assert_eq!(index.duplicates(), 1);
    }

    // -- Caching, and a snapshot the user supplied --------------------------

    /// The feed is a whole repository snapshot, so a second run inside the
    /// TTL asking for it again is the cost this avoids.
    #[tokio::test]
    async fn snapshot_cached_read_by_second_run() {
        let f = Fixture::new(
            (),
            FixtureClient::new().with_body(
                snapshot(),
                zipped(&[(
                    entry("npm", "tuna", "MAL-2024-1"),
                    record("MAL-2024-1", "npm", "tuna"),
                )]),
            ),
        );
        let ctx = ctx();

        let advisor = OssfMalicious::at(BASE, f.shared());

        let mut first = Index::new(Ecosystems::builtin());
        assert_eq!(
            advisor
                .load(&mut first, Freshness::Cached, &ctx)
                .await
                .expect("first run")
                .origin,
            Origin::Downloaded
        );

        let mut second = Index::new(Ecosystems::builtin());
        let loaded = advisor
            .load(&mut second, Freshness::Cached, &ctx)
            .await
            .expect("second run");

        assert_eq!(loaded.origin, Origin::Cached);
        assert_eq!(second.records(), 1, "and it still screens");
        assert_eq!(f.host.hits(&snapshot()), 1);
    }

    /// **The case the redundancy argument turns on.** A malicious package
    /// is yanked within days, so a run that cannot reach the feed is
    /// better served by yesterday's copy -- reported as yesterday's -- than
    /// by no screening at all.
    #[tokio::test]
    async fn snapshot_cached_when_feed_unreachable() {
        let body = zipped(&[(
            entry("npm", "tuna", "MAL-2024-1"),
            record("MAL-2024-1", "npm", "tuna"),
        )]);

        let f = Fixture::new(
            (),
            FixtureClient::new().with_sequence(
                snapshot(),
                vec![
                    Canned::ok(body),
                    Canned::status(StatusCode::SERVICE_UNAVAILABLE),
                ],
            ),
        );
        let ctx = ctx();

        // A zero TTL, so the second run tries the network and fails.
        let advisor = OssfMalicious::at(BASE, f.shared()).with_ttl(std::time::Duration::ZERO);

        let mut first = Index::new(Ecosystems::builtin());
        advisor
            .load(&mut first, Freshness::Cached, &ctx)
            .await
            .expect("first run");

        let mut second = Index::new(Ecosystems::builtin());
        let loaded = advisor
            .load(&mut second, Freshness::Cached, &ctx)
            .await
            .expect("the expired copy answered");

        assert_eq!(loaded.origin, Origin::Stale);

        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert_eq!(
            second.advisories(&tuna).len(),
            1,
            "and the malware is still screened for"
        );
    }

    /// Someone who mirrors the feed themselves, or has no route to GitHub,
    /// points at a snapshot instead. A zip of the repository, however it
    /// was made.
    #[tokio::test]
    async fn snapshot_supplied_read_instead_of_feed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("malicious-packages.zip");

        std::fs::write(
            &path,
            zipped(&[
                (
                    entry("npm", "tuna", "MAL-2024-1"),
                    record("MAL-2024-1", "npm", "tuna"),
                ),
                (
                    "malicious-packages-main/README.md".to_owned(),
                    b"the feed".to_vec(),
                ),
            ]),
        )
        .expect("written");

        let f = Fixture::new((), FixtureClient::new());
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        let loaded = OssfMalicious::at(BASE, f.shared())
            .from_file(&path)
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect("read from disk");

        assert_eq!(loaded.origin, Origin::Local);
        assert_eq!(loaded.tally.parsed, 1);
        assert!(f.host.requested().is_empty(), "nothing was asked for");

        // The same entry claim, so a snapshot reads identically however it
        // arrived -- the README included.
        let tuna = ArtifactId::new(EcosystemId::npm(), None, "tuna");

        assert!(index.advisories(&tuna)[0].advisory().is_malware());
    }

    /// A failure inside a supplied snapshot names the file, not a URL
    /// nothing fetched.
    #[tokio::test]
    async fn snapshot_supplied_broken_names_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-zip.zip");

        std::fs::write(&path, b"not an archive").expect("written");

        let f = Fixture::new((), FixtureClient::new());
        let ctx = ctx();

        let mut index = Index::new(Ecosystems::builtin());

        let message = OssfMalicious::at(BASE, f.shared())
            .from_file(&path)
            .load(&mut index, Freshness::Cached, &ctx)
            .await
            .expect_err("refused")
            .to_string();

        assert!(message.contains("not-a-zip.zip"), "{message}");
    }
}
