//! The purl-keyed index: what a corpus says about one package.
//!
//! A corpus is read once and then answered from memory. That is the whole
//! reason this type exists: a walk of a million artifacts must cost a map
//! lookup each rather than a request each, and the OSV corpora are published
//! as a flat pile of records with no lookup structure of their own.
//!
//! # `(ecosystem, name)`, spelled purl's way
//!
//! OSV keys a record on its own spellings -- `Maven` with
//! `org.apache.commons:commons-lang3`, `npm` with `@angular/core`, `PyPI`
//! with whatever case the publisher typed -- and this tool keys artifacts on
//! purl. Neither side is wrong, so the index **translates** as it is built,
//! and the lookup side runs the same translation over the artifact's own
//! parts. One function serving both directions is what keeps them from
//! drifting apart:
//!
//! ```text
//!   Maven   org.apache.commons:commons-lang3  ->  org.apache.commons/commons-lang3
//!   npm     @angular/core                     ->  @angular/core
//!   PyPI    Flask_SQLAlchemy                  ->  flask-sqlalchemy
//! ```
//!
//! The name half is built from an artifact's *parts* rather than from its
//! rendered purl, which drops the version and the qualifiers for free -- and
//! dropping the qualifiers is right rather than convenient: an advisory is
//! about a package, so a Maven sources jar is covered by whatever covers its
//! main jar.
//!
//! The ecosystem half cannot be translated by rule at all. `crates.io` is
//! purl's `cargo` and `Go` is purl's `golang`; lowercasing `PyPI` happens to
//! work only for the ones nobody had an opinion about. So it is a table --
//! [`Ecosystems`] -- seeded from what each ecosystem says about *itself*
//! rather than from a list kept here, because `ecosystem` is an extension
//! point and a list here could not know about a third party's.
//!
//! # A record is listed once per package, not once per entry
//!
//! One advisory may carry several `affected` entries for the same package:
//! a `SEMVER` range beside an `ECOSYSTEM` one is ordinary, and a record
//! ingested from two databases can repeat itself. Returning those as
//! separate hits would report the same finding twice against one artifact,
//! so the index groups them: one [`Listing`] per `(package, advisory)`,
//! holding every entry that named it, and [`Listing::verdict`] folds them
//! with [`Match::worst`]. The de-duplication is by construction rather than
//! by asking every caller to remember it.
//!
//! References: [OSV schema](https://ossf.github.io/osv-schema/).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::ecosystem::Ecosystem;
use crate::model::{ArtifactId, EcosystemId, Version};
use crate::version::VersionHandler;

use super::matching::{self, Match};
use super::osv::{Advisory, Affected};

/// OSV's ecosystem spellings, translated into this tool's.
///
/// A table rather than a rule, because there is no rule: the OSV name is
/// capitalized per ecosystem (`Maven`, `PyPI`, `npm`) and for two of the big
/// ones it is not even the same word as the purl type (`crates.io` is
/// `cargo`, `Go` is `golang`). [`Ecosystem::osv_name`] is where each
/// ecosystem states its own, so that is what seeds this.
#[derive(Debug, Clone, Default)]
pub struct Ecosystems {
    /// Keyed by the OSV name folded to lower case, because the corpora are
    /// not perfectly consistent about it and a case slip would drop every
    /// record for an ecosystem silently.
    by_osv_name: HashMap<String, EcosystemId>,

    /// The OSV name as published, which is **not** the lower-cased key.
    ///
    /// Kept because the reverse direction is a URL: a corpus is fetched from
    /// `.../{osv-name}/all.zip` and a bucket path is case-sensitive, so
    /// `pypi` would 404 where `PyPI` succeeds. Reading it back out of the
    /// same table is what keeps the ecosystems downloaded and the ecosystems
    /// keyed from being two lists that can disagree.
    osv_names: BTreeMap<EcosystemId, String>,
}

impl Ecosystems {
    /// Every ecosystem this build speaks.
    ///
    /// The starting point for a run that configures no ecosystem extension,
    /// which is the common case.
    pub fn builtin() -> Self {
        let mut ecosystems = Self::default();

        for kind in crate::ecosystem::kinds() {
            if let Ok(ecosystem) = crate::ecosystem::open(kind) {
                ecosystems.learn(ecosystem.as_ref());
            }
        }

        ecosystems
    }

    /// Learn an ecosystem's OSV name.
    ///
    /// How a third-party `cargo` or `nuget` reaches the index: it declares
    /// its own OSV name, and nothing here needs to have heard of it.
    ///
    /// An ecosystem declaring no OSV name is **skipped rather than
    /// recorded**, and that is load-bearing: `github` declares an empty one,
    /// because OSV has no GitHub-releases ecosystem and advisories are keyed
    /// to whichever registries a project publishes to. Recorded, the empty
    /// name would translate every record with a missing `ecosystem` field
    /// into a GitHub release and screen it against the wrong package.
    pub fn learn(&mut self, ecosystem: &dyn Ecosystem) {
        let osv_name = ecosystem.osv_name();

        if osv_name.is_empty() {
            return;
        }

        let id = ecosystem.id();

        self.by_osv_name.insert(osv_name.to_lowercase(), id.clone());
        self.osv_names.insert(id, osv_name.to_owned());
    }

    /// From `(osv_name, id)` pairs directly, for a caller holding no
    /// ecosystem.
    pub fn of(pairs: impl IntoIterator<Item = (String, EcosystemId)>) -> Self {
        let mut ecosystems = Self::default();

        for (osv_name, id) in pairs {
            if osv_name.is_empty() {
                continue;
            }

            ecosystems
                .by_osv_name
                .insert(osv_name.to_lowercase(), id.clone());
            ecosystems.osv_names.insert(id, osv_name);
        }

        ecosystems
    }

    /// Which ecosystem an OSV record's `ecosystem` names, if any here.
    ///
    /// OSV suffixes a distribution's release onto the ecosystem name --
    /// `Debian:11`, `Alpine:v3.16`, `Ubuntu:22.04` -- where the part before
    /// the colon is the ecosystem proper. Stripped rather than matched
    /// whole, or an extension declaring `Debian` would match none of the
    /// records about it.
    ///
    /// `None` for an ecosystem nothing here speaks, which is the ordinary
    /// state of most of a broad corpus rather than a fault. See
    /// [`Index::untranslated`].
    pub fn translate(&self, osv_ecosystem: &str) -> Option<EcosystemId> {
        let base = osv_ecosystem
            .split_once(':')
            .map(|(before, _)| before)
            .unwrap_or(osv_ecosystem);

        self.by_osv_name.get(&base.to_lowercase()).cloned()
    }

    /// The OSV name for one ecosystem, as published.
    ///
    /// The direction a *download* needs: a corpus lives under its OSV name
    /// in a bucket path, and that path is case-sensitive.
    pub fn osv_name(&self, ecosystem: &EcosystemId) -> Option<&str> {
        self.osv_names.get(ecosystem).map(String::as_str)
    }

    /// Every ecosystem this table knows, with its OSV name.
    ///
    /// What an advisor asked to fetch "all of them" fetches. Reading the set
    /// from the same table that keys the records is deliberate: an advisor
    /// that downloaded an ecosystem the index cannot key would file every
    /// record under [`Index::untranslated`] and report the run clean.
    pub fn all(&self) -> impl Iterator<Item = (&EcosystemId, &str)> {
        self.osv_names
            .iter()
            .map(|(id, osv_name)| (id, osv_name.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.osv_names.is_empty()
    }
}

/// One advisory, and the entries in it that named one package.
///
/// Holds the record behind an [`Arc`] because an advisory affecting a dozen
/// packages is listed under a dozen keys and cloning the record into each
/// would multiply a corpus by its own fan-out.
#[derive(Debug, Clone)]
pub struct Listing {
    advisory: Arc<Advisory>,

    /// The configured advisor whose corpus supplied the record.
    advisor: Arc<str>,

    /// Positions in `advisory.affected`. Never empty: a listing exists
    /// because an entry named the package.
    entries: Vec<usize>,
}

impl Listing {
    pub fn advisory(&self) -> &Advisory {
        &self.advisory
    }

    /// The configured advisor that supplied this record: the first to carry
    /// it, since a duplicate from a later corpus is dropped.
    pub fn advisor(&self) -> &str {
        &self.advisor
    }

    /// The record, shareable, for a caller that has to hold it past the
    /// index's borrow.
    pub fn shared(&self) -> Arc<Advisory> {
        Arc::clone(&self.advisory)
    }

    /// The entries of this record that named the package looked up.
    pub fn entries(&self) -> impl Iterator<Item = &Affected> {
        self.entries
            .iter()
            .filter_map(|position| self.advisory.affected.get(*position))
    }

    /// Whether this version falls in what the record describes.
    ///
    /// Folded with [`Match::worst`] across every entry that named the
    /// package, so an advisory that says `Affected` anywhere is a hit and one
    /// with a single unevaluable range answers [`Match::Unknown`] rather than
    /// letting the rest report it clean.
    ///
    /// The seed is [`Match::Unaffected`] and is never the answer on its own:
    /// `entries` is non-empty by construction, so some real entry always
    /// contributes.
    pub fn verdict(&self, version: &Version, handler: &dyn VersionHandler) -> Match {
        self.entries()
            .map(|entry| matching::affected(entry, version, handler))
            .fold(Match::Unaffected, Match::worst)
    }
}

/// A corpus, keyed for lookup.
#[derive(Debug)]
pub struct Index {
    ecosystems: Ecosystems,
    listings: HashMap<(EcosystemId, String), Vec<Listing>>,

    /// The newest `modified` any record carried.
    modified: Option<DateTime<Utc>>,

    records: usize,
    withdrawn: usize,
    duplicates: usize,
    untranslated: BTreeSet<String>,

    /// Whose records are being inserted. See [`Index::attributing`].
    advisor: Arc<str>,
}

/// The answer for a package nothing was published about, which is almost
/// every package.
const NOTHING: &[Listing] = &[];

impl Index {
    /// An empty index that will translate through `ecosystems`.
    pub fn new(ecosystems: Ecosystems) -> Self {
        Self {
            ecosystems,
            listings: HashMap::new(),
            modified: None,
            records: 0,
            withdrawn: 0,
            duplicates: 0,
            untranslated: BTreeSet::new(),
            advisor: Arc::from(""),
        }
    }

    /// Attribute every record inserted from now on to `advisor`.
    ///
    /// Set by the caller before each advisor loads, rather than passed to
    /// [`Index::insert`], so a corpus reader never has to know which
    /// configured name it is reading for.
    pub fn attributing(&mut self, advisor: &str) {
        self.advisor = Arc::from(advisor);
    }

    /// Index a whole corpus.
    pub fn of(records: impl IntoIterator<Item = Advisory>, ecosystems: Ecosystems) -> Self {
        let mut index = Self::new(ecosystems);

        for record in records {
            index.insert(record);
        }

        index
    }

    /// Add one record.
    ///
    /// Public alongside [`Index::of`] so a corpus reader can push records as
    /// it unpacks them: the OSV `all.zip` is hundreds of thousands of small
    /// files, and collecting them into a `Vec` first would hold the whole
    /// corpus twice.
    pub fn insert(&mut self, advisory: Advisory) {
        // Counted before anything can reject the record. The corpus's age is
        // a fact about the file, and a corpus whose newest record happens to
        // be a withdrawal is no staler for it.
        self.note_age(advisory.modified.as_deref());

        // A withdrawn record is one the publisher retracted. Screening
        // against it reports a finding nobody claims any more, which costs a
        // reviewer the same time as a real one and teaches them to discount
        // the list.
        if advisory.is_withdrawn() {
            self.withdrawn += 1;
            return;
        }

        let mut keys: BTreeMap<(EcosystemId, String), Vec<usize>> = BTreeMap::new();
        let mut untranslated = Vec::new();

        for (position, entry) in advisory.affected.iter().enumerate() {
            if entry.package.name.is_empty() {
                continue;
            }

            let Some(ecosystem) = self.ecosystems.translate(&entry.package.ecosystem) else {
                untranslated.push(entry.package.ecosystem.clone());
                continue;
            };

            let name = canonical(&ecosystem, &entry.package.name);

            keys.entry((ecosystem, name)).or_default().push(position);
        }

        self.untranslated.extend(untranslated);

        if keys.is_empty() {
            return;
        }

        let shared = Arc::new(advisory);
        let mut listed = false;

        for (key, entries) in keys {
            let under = self.listings.entry(key).or_default();

            // Already listed under this package, by an earlier corpus.
            // `osv-offline` and `ossf-malicious` overlap on purpose -- OSV
            // ingests the malicious-packages feed, and the redundancy is
            // there because that ingestion lags -- so the same `MAL-` record
            // routinely arrives twice, and two listings would report one
            // finding twice against one artifact.
            //
            // First wins, so configuration order is precedence. That is the
            // right resolution rather than a convenient one: the redundancy
            // exists for *availability*, not to merge two records' ranges,
            // and the finding a duplicate produces -- its id, its aliases,
            // whether it is malware -- is the same either way.
            if under.iter().any(|listing| listing.advisory.id == shared.id) {
                self.duplicates += 1;
                continue;
            }

            under.push(Listing {
                advisory: Arc::clone(&shared),
                advisor: Arc::clone(&self.advisor),
                entries,
            });

            listed = true;
        }

        if listed {
            self.records += 1;
        }
    }

    /// What this corpus says about one package.
    ///
    /// Keyed on the artifact's ecosystem, namespace and name -- the version
    /// and the qualifiers are deliberately not part of it. The version is
    /// the question [`Listing::verdict`] answers, and an advisory is about a
    /// package rather than about one of its files.
    pub fn advisories(&self, id: &ArtifactId) -> &[Listing] {
        self.at(id.ecosystem(), &qualified(id))
    }

    /// The same lookup from the parts, for a caller holding no
    /// [`ArtifactId`].
    pub fn at(&self, ecosystem: &EcosystemId, name: &str) -> &[Listing] {
        let key = (ecosystem.clone(), canonical(ecosystem, name));

        self.listings
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or(NOTHING)
    }

    /// How stale this corpus is, as the newest record it holds.
    ///
    /// Absolute rather than a duration, because that is what
    /// [`Screening::consulted`](super::Screening::consulted) records and a
    /// report is read long after the run that wrote it.
    ///
    /// `None` when no record carried a parsable `modified`, and a caller
    /// must **not** read that as fresh: a corpus that cannot say how old it
    /// is has not established that it is current, so the honest report is
    /// [`CorpusAge::Unavailable`](super::CorpusAge::Unavailable) rather than
    /// a consultation with no timestamp.
    pub fn modified(&self) -> Option<DateTime<Utc>> {
        self.modified
    }

    /// Records indexed under at least one package.
    pub fn records(&self) -> usize {
        self.records
    }

    /// Distinct packages anything was published about.
    pub fn packages(&self) -> usize {
        self.listings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.listings.is_empty()
    }

    /// Records dropped because the publisher retracted them.
    pub fn withdrawn(&self) -> usize {
        self.withdrawn
    }

    /// Listings dropped because an earlier corpus already carried the
    /// record.
    ///
    /// Expected to be large where two overlapping corpora are configured,
    /// which is the recommended arrangement rather than a mistake.
    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// How this index translates an OSV record's ecosystem.
    ///
    /// Read by an advisor to decide *which* corpora to fetch, so the set
    /// downloaded and the set keyable are one list.
    pub fn ecosystems(&self) -> &Ecosystems {
        &self.ecosystems
    }

    /// OSV ecosystem names this run does not speak.
    ///
    /// **Not a fault on its own.** A malicious-package feed covers every
    /// ecosystem there is, and a run copying Maven artifacts speaks one of
    /// them; the rest belong here and nothing is lost by it.
    ///
    /// It is carried because the *other* reading of the same fact is a
    /// configuration mistake -- an ecosystem extension whose description
    /// never reached [`Ecosystems::learn`] puts every record about it here,
    /// and the run then screens those artifacts against an index that knows
    /// nothing and reports them clean. Whether a name here is expected or a
    /// mistake depends on what the run was asked to copy, which the index
    /// does not know, so it reports and does not judge.
    pub fn untranslated(&self) -> &BTreeSet<String> {
        &self.untranslated
    }

    fn note_age(&mut self, modified: Option<&str>) {
        self.modified = newer(self.modified, modified);
    }
}

/// The later of `newest` and a record's `modified`.
///
/// Shared with the archive reader, which dates each corpus on its own: the
/// index is fed by several, so its own age is the newest of all of them.
pub(super) fn newer(
    newest: Option<DateTime<Utc>>,
    modified: Option<&str>,
) -> Option<DateTime<Utc>> {
    let Some(text) = modified else {
        return newest;
    };

    // Unparsable is ignored rather than fatal, for the reason the record
    // ignores unknown fields: one malformed timestamp in a corpus of
    // hundreds of thousands must not take screening down. It lowers the
    // claimed age at worst, and an age lower than the truth reports the
    // corpus as *older* than it is, which is the safe direction.
    let Ok(when) = DateTime::parse_from_rfc3339(text) else {
        return newest;
    };

    let when = when.with_timezone(&Utc);

    match newest {
        Some(newest) if newest >= when => Some(newest),
        _ => Some(when),
    }
}

/// An artifact's name as purl spells it: namespace and name, joined.
///
/// The join is what makes one key shape serve every ecosystem. Maven's
/// group and artifact, npm's scope and package, and a Go module's host and
/// path all render as `namespace/name`, which is exactly what each
/// ecosystem's own OSV name collapses to under [`canonical`].
fn qualified(id: &ArtifactId) -> String {
    match id.namespace() {
        Some(namespace) => format!("{namespace}/{}", id.name()),
        None => id.name().to_owned(),
    }
}

/// One package name, in the spelling the index keys on.
///
/// Run over **both** sides -- the corpus's OSV names as the index is built,
/// and the artifact's own parts as it is looked up -- so the two cannot be
/// normalized differently. That is why the Maven arm rewrites a separator
/// that an `ArtifactId` never contains, and why the PyPI arm re-normalizes
/// a name the PyPI adapters already normalized: each arm has to be a no-op
/// on the side that was already right.
fn canonical(ecosystem: &EcosystemId, name: &str) -> String {
    match ecosystem.as_str() {
        // OSV writes a Maven coordinate `group:artifact`; purl splits it
        // into a namespace and a name. Only the first colon separates them,
        // and neither half may contain another.
        EcosystemId::MAVEN => name.replacen(':', "/", 1),

        // PEP 503: `Flask_SQLAlchemy`, `flask.sqlalchemy` and
        // `flask-sqlalchemy` are one project, and a corpus carrying the
        // publisher's spelling must still answer for the normalized one.
        EcosystemId::PYPI => crate::ecosystem::pypi::normalize(name),

        _ => name.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::{Error, Result};
    use crate::model::{ArtifactRequest, DepKind, VersionSpec};
    use crate::version::{MavenVersions, PreRelease, Ranking, Semver, Tags, VersionHandler};

    fn advisory(json: &str) -> Advisory {
        serde_json::from_str(json).expect("parses")
    }

    /// One record naming one package, with an enumeration so no comparator
    /// is involved unless a test wants one.
    fn about(id: &str, ecosystem: &str, name: &str, versions: &str) -> Advisory {
        advisory(&format!(
            r#"{{"id":"{id}","modified":"2024-06-01T00:00:00Z",
                "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{name}"}},
                              "versions":{versions}}}]}}"#
        ))
    }

    fn index_of(records: Vec<Advisory>) -> Index {
        Index::of(records, Ecosystems::builtin())
    }

    fn npm(name: &str) -> ArtifactId {
        let (namespace, bare) = match name.split_once('/') {
            Some((scope, bare)) => (Some(scope), bare),
            None => (None, name),
        };

        ArtifactId::new(EcosystemId::npm(), namespace, bare)
    }

    // -- The ecosystem table ----------------------------------------------

    #[test]
    fn table_builtin_translates_every_shipped_spelling() {
        let ecosystems = Ecosystems::builtin();

        assert_eq!(ecosystems.translate("Maven"), Some(EcosystemId::maven()));
        assert_eq!(ecosystems.translate("PyPI"), Some(EcosystemId::pypi()));
        assert_eq!(ecosystems.translate("npm"), Some(EcosystemId::npm()));
    }

    /// The corpora are not perfectly consistent about case, and a slip must
    /// not drop every record for an ecosystem.
    #[test]
    fn ecosystem_osv_name_case_insensitive() {
        assert_eq!(
            Ecosystems::builtin().translate("pypi"),
            Some(EcosystemId::pypi())
        );
    }

    /// `github` declares no OSV name. Were the empty string a table entry,
    /// a record whose `ecosystem` field was missing would translate into a
    /// GitHub release and be screened against the wrong package.
    #[test]
    fn ecosystem_without_osv_name_matches_nothing() {
        let ecosystems = Ecosystems::builtin();

        assert_eq!(ecosystems.translate(""), None);
        assert_eq!(ecosystems.translate("github"), None);
    }

    /// A third-party ecosystem this crate has not heard of.
    struct Cargo;

    impl VersionHandler for Cargo {
        fn version_spec(&self, text: &str) -> VersionSpec {
            Semver.version_spec(text)
        }

        fn classify(&self, texts: &[String]) -> Vec<Version> {
            Semver.classify(texts)
        }

        fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version> {
            Semver.select(spec, of, pre)
        }

        fn compare(&self, a: &Version, b: &Version) -> Ranking {
            Semver.compare(a, b)
        }

        fn sort(&self, versions: &mut [Version]) {
            Semver.sort(versions)
        }
    }

    impl Ecosystem for Cargo {
        fn parse_req(&self, _text: &str) -> Result<ArtifactRequest> {
            Err(Error::Unimplemented("cargo coordinates"))
        }

        fn id(&self) -> EcosystemId {
            EcosystemId::new("cargo")
        }

        fn purl_type(&self) -> &str {
            "cargo"
        }

        fn osv_name(&self) -> &str {
            "crates.io"
        }

        fn dep_kinds(&self) -> &[DepKind] {
            &[]
        }
    }

    /// The point of an open ecosystem: a third party declares its own OSV
    /// name and the index translates it without this crate knowing of it.
    #[test]
    fn table_taught_extension_spelling() {
        let mut ecosystems = Ecosystems::builtin();

        assert_eq!(ecosystems.translate("crates.io"), None);

        ecosystems.learn(&Cargo);

        assert_eq!(
            ecosystems.translate("crates.io"),
            Some(EcosystemId::new("cargo")),
            "the purl type is not derivable from the OSV name"
        );
    }

    /// OSV suffixes a distribution release onto the ecosystem name, and an
    /// extension declaring `Debian` would otherwise match none of them.
    #[test]
    fn key_strips_distribution_release_suffix() {
        let ecosystems = Ecosystems::of([("Debian".to_owned(), EcosystemId::new("deb"))]);

        assert_eq!(
            ecosystems.translate("Debian:11"),
            Some(EcosystemId::new("deb"))
        );
    }

    // -- Translating the name ---------------------------------------------

    /// OSV writes a Maven coordinate with a colon; purl splits it into a
    /// namespace and a name.
    #[test]
    fn key_maven_coordinate_purl_spelling() {
        let index = index_of(vec![about(
            "GHSA-m",
            "Maven",
            "org.apache.commons:commons-lang3",
            r#"["3.0"]"#,
        )]);

        let id = ArtifactId::new(
            EcosystemId::maven(),
            Some("org.apache.commons"),
            "commons-lang3",
        );

        assert_eq!(index.advisories(&id).len(), 1);
    }

    /// An npm scope is a purl namespace and OSV's own spelling both, so the
    /// join has to produce the corpus's string exactly.
    #[test]
    fn key_npm_scoped_package() {
        let index = index_of(vec![about(
            "GHSA-n",
            "npm",
            "@angular/core",
            r#"["17.0.0"]"#,
        )]);

        assert_eq!(index.advisories(&npm("@angular/core")).len(), 1);
        assert!(index.advisories(&npm("core")).is_empty());
    }

    /// PEP 503: the publisher's spelling and the normalized one are one
    /// project, and the corpus may carry either.
    #[test]
    fn key_pypi_name_any_spelling() {
        let index = index_of(vec![about(
            "GHSA-p",
            "PyPI",
            "Flask_SQLAlchemy",
            r#"["2.0"]"#,
        )]);

        let id = ArtifactId::new(EcosystemId::pypi(), None, "flask-sqlalchemy");

        assert_eq!(index.advisories(&id).len(), 1);
    }

    /// An advisory is about a package, so the file within it that is being
    /// copied cannot change the answer.
    #[test]
    fn key_unchanged_by_qualifier() {
        let index = index_of(vec![about("GHSA-q", "Maven", "g:a", r#"["1.0"]"#)]);

        let sources = ArtifactId::new(EcosystemId::maven(), Some("g"), "a")
            .with_qualifier("classifier", "sources");

        assert_eq!(index.advisories(&sources).len(), 1);
    }

    #[test]
    fn listing_empty_for_unpublished_package() {
        let index = index_of(vec![about("GHSA-x", "npm", "tuna", r#"["1.0.0"]"#)]);

        assert!(index.advisories(&npm("marlin")).is_empty());
    }

    // -- What the index drops ---------------------------------------------

    /// A retracted record must not cost a reviewer the same time as a real
    /// one.
    #[test]
    fn withdrawn_record_not_indexed() {
        let mut withdrawn = about("GHSA-w", "npm", "tuna", r#"["1.0.0"]"#);
        withdrawn.withdrawn = Some("2024-07-01T00:00:00Z".to_owned());

        let index = index_of(vec![withdrawn]);

        assert!(index.advisories(&npm("tuna")).is_empty());
        assert_eq!(index.withdrawn(), 1);
    }

    /// Most of a broad corpus is about ecosystems a given run does not
    /// speak. Dropped, and said out loud, because the same fact read the
    /// other way is a configuration mistake that would report those
    /// artifacts clean.
    #[test]
    fn ecosystem_unspoken_dropped_reported() {
        let index = index_of(vec![about("MAL-1", "crates.io", "tuna", r#"["1.0.0"]"#)]);

        assert!(index.is_empty());
        assert_eq!(index.records(), 0);
        assert!(index.untranslated().contains("crates.io"));
    }

    // -- One listing per package, not per entry ---------------------------

    /// Two entries for the same package would report one finding twice. The
    /// range and the enumeration are the ordinary way that happens.
    #[test]
    fn listing_one_for_two_entries() {
        let index = index_of(vec![advisory(
            r#"{"id":"GHSA-d","affected":[
                 {"package":{"ecosystem":"npm","name":"tuna"},"versions":["1.0.0"]},
                 {"package":{"ecosystem":"npm","name":"tuna"},
                  "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]}]}
               ]}"#,
        )]);

        let listings = index.advisories(&npm("tuna"));

        assert_eq!(listings.len(), 1, "one advisory, one listing");
        assert_eq!(listings[0].entries().count(), 2);
    }

    /// The other half of the same argument: one record affecting several
    /// packages is listed under each, sharing the record rather than
    /// copying it.
    #[test]
    fn listing_per_package_for_multi_package_record() {
        let index = index_of(vec![advisory(
            r#"{"id":"GHSA-s","affected":[
                 {"package":{"ecosystem":"npm","name":"tuna"},"versions":["1.0.0"]},
                 {"package":{"ecosystem":"npm","name":"marlin"},"versions":["2.0.0"]}
               ]}"#,
        )]);

        assert_eq!(index.records(), 1);
        assert_eq!(index.packages(), 2);
        assert_eq!(index.advisories(&npm("tuna"))[0].advisory().id, "GHSA-s");
        assert_eq!(index.advisories(&npm("marlin"))[0].advisory().id, "GHSA-s");
    }

    /// `osv-offline` and `ossf-malicious` overlap on purpose, so the same
    /// `MAL-` record arrives twice. Two listings would report one finding
    /// twice against one artifact.
    #[test]
    fn listing_once_for_record_repeated_across_corpora() {
        let index = index_of(vec![
            about("MAL-2024-1", "npm", "tuna", r#"["1.0.0"]"#),
            about("MAL-2024-1", "npm", "tuna", r#"["1.0.0"]"#),
        ]);

        assert_eq!(index.advisories(&npm("tuna")).len(), 1);
        assert_eq!(index.records(), 1, "the repeat is not a second record");
        assert_eq!(index.duplicates(), 1);
    }

    /// The de-duplication is per package, not per corpus: a second record
    /// about a package the first corpus did not mention is still new.
    #[test]
    fn listing_repeat_does_not_hide_other_package() {
        let index = index_of(vec![
            about("MAL-2024-1", "npm", "tuna", r#"["1.0.0"]"#),
            about("MAL-2024-1", "npm", "marlin", r#"["1.0.0"]"#),
        ]);

        assert_eq!(index.advisories(&npm("tuna")).len(), 1);
        assert_eq!(index.advisories(&npm("marlin")).len(), 1);
    }

    // -- The ecosystems a corpus should be fetched for ---------------------

    /// The direction a download needs. A bucket path is case-sensitive, so
    /// `pypi` would 404 where `PyPI` succeeds.
    #[test]
    fn table_answers_published_spelling_for_url() {
        let ecosystems = Ecosystems::builtin();

        assert_eq!(ecosystems.osv_name(&EcosystemId::pypi()), Some("PyPI"));
        assert_eq!(ecosystems.osv_name(&EcosystemId::maven()), Some("Maven"));
        assert_eq!(
            ecosystems.osv_name(&EcosystemId::raw()),
            None,
            "there is no corpus for arbitrary files"
        );
    }

    /// An advisor asked for "all of them" reads the set from the same table
    /// that keys the records, so it cannot download an ecosystem the index
    /// would then file under `untranslated`.
    #[test]
    fn every_ecosystem_listed_is_one_the_index_can_key() {
        let ecosystems = Ecosystems::builtin();

        for (id, osv_name) in ecosystems.all() {
            assert_eq!(
                ecosystems.translate(osv_name).as_ref(),
                Some(id),
                "{osv_name} must round-trip"
            );
        }
    }

    #[test]
    fn listing_includes_every_advisory_for_package() {
        let index = index_of(vec![
            about("GHSA-1", "npm", "tuna", r#"["1.0.0"]"#),
            about("GHSA-2", "npm", "tuna", r#"["1.0.0"]"#),
        ]);

        assert_eq!(index.advisories(&npm("tuna")).len(), 2);
    }

    // -- The verdict ------------------------------------------------------

    #[test]
    fn listing_answers_for_asked_version() {
        let index = index_of(vec![about("GHSA-v", "npm", "tuna", r#"["1.0.0","1.0.1"]"#)]);

        let listing = &index.advisories(&npm("tuna"))[0];

        assert_eq!(
            listing.verdict(&Semver.version("1.0.1"), &Semver),
            Match::Affected
        );
        assert_eq!(
            listing.verdict(&Semver.version("2.0.0"), &Semver),
            Match::Unaffected
        );
    }

    /// Folded worst-first across the entries that named the package: an
    /// advisory that says `Affected` anywhere is a hit.
    #[test]
    fn listing_decided_by_worst_entry() {
        let index = index_of(vec![advisory(
            r#"{"id":"GHSA-f","affected":[
                 {"package":{"ecosystem":"npm","name":"tuna"},"versions":["9.9.9"]},
                 {"package":{"ecosystem":"npm","name":"tuna"},
                  "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]}]}
               ]}"#,
        )]);

        let listing = &index.advisories(&npm("tuna"))[0];

        assert_eq!(
            listing.verdict(&Semver.version("1.0.5"), &Semver),
            Match::Affected,
            "the second entry's range matches where the enumeration did not"
        );
    }

    /// The reason a verdict is three-valued reaches this far: a convention
    /// with no ordering cannot place a version in a range, and the index
    /// must not flatten that into a clean answer.
    #[test]
    fn verdict_unknown_for_unevaluable_range() {
        let index = Index::of(
            vec![advisory(
                r#"{"id":"GHSA-u","affected":[
                     {"package":{"ecosystem":"raw","name":"tuna"},
                      "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}
                   ]}"#,
            )],
            Ecosystems::of([("raw".to_owned(), EcosystemId::new("raw"))]),
        );

        let id = ArtifactId::new(EcosystemId::new("raw"), None, "tuna");
        let listing = &index.advisories(&id)[0];

        assert_eq!(
            listing.verdict(&Tags.version("nightly"), &Tags),
            Match::Unknown
        );
    }

    /// The comparator is the artifact's own, all the way through the index:
    /// Maven places `1.0-rc1` below `1.0`, so it is outside `[1.0, 2.0)`.
    #[test]
    fn verdict_uses_ecosystem_ordering() {
        let index = index_of(vec![advisory(
            r#"{"id":"GHSA-o","affected":[
                 {"package":{"ecosystem":"Maven","name":"g:a"},
                  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}
               ]}"#,
        )]);

        let id = ArtifactId::new(EcosystemId::maven(), Some("g"), "a");
        let listing = &index.advisories(&id)[0];

        assert_eq!(
            listing.verdict(&MavenVersions.version("1.0-rc1"), &MavenVersions),
            Match::Unaffected
        );
        assert_eq!(
            listing.verdict(&MavenVersions.version("1.5"), &MavenVersions),
            Match::Affected
        );
    }

    // -- Corpus age -------------------------------------------------------

    #[test]
    fn corpus_age_is_newest_record() {
        let index = index_of(vec![
            advisory(r#"{"id":"A","modified":"2024-01-01T00:00:00Z"}"#),
            advisory(r#"{"id":"B","modified":"2024-06-01T00:00:00Z"}"#),
            advisory(r#"{"id":"C","modified":"2024-03-01T00:00:00Z"}"#),
        ]);

        assert_eq!(
            index.modified().expect("a timestamp").to_rfc3339(),
            "2024-06-01T00:00:00+00:00"
        );
    }

    /// A withdrawal is still an edit to the corpus, so it counts toward how
    /// fresh the file is even though it is not indexed.
    #[test]
    fn corpus_age_includes_withdrawn_record() {
        let index = index_of(vec![advisory(
            r#"{"id":"A","modified":"2024-06-01T00:00:00Z",
                "withdrawn":"2024-06-01T00:00:00Z"}"#,
        )]);

        assert!(index.is_empty());
        assert!(index.modified().is_some());
    }

    /// One malformed timestamp must not take screening down, for the same
    /// reason an unknown field does not.
    #[test]
    fn corpus_age_ignores_unparsable_timestamp() {
        let index = index_of(vec![
            advisory(r#"{"id":"A","modified":"the day before yesterday"}"#),
            advisory(r#"{"id":"B","modified":"2024-06-01T00:00:00Z"}"#),
        ]);

        assert_eq!(
            index.modified().expect("the parsable one").to_rfc3339(),
            "2024-06-01T00:00:00+00:00"
        );
    }

    /// A corpus that cannot say how old it is has not established that it is
    /// current; the caller reports it unavailable rather than consulted.
    #[test]
    fn corpus_age_absent_without_timestamps() {
        let index = index_of(vec![about("GHSA-t", "npm", "tuna", r#"["1.0.0"]"#)]);

        assert!(index.modified().is_some(), "the fixture carries one");
        assert!(
            index_of(vec![advisory(r#"{"id":"A"}"#)])
                .modified()
                .is_none()
        );
    }

    // -- Streaming --------------------------------------------------------

    /// The corpus arrives as hundreds of thousands of small files, so it has
    /// to be pushable a record at a time rather than collected first.
    #[test]
    fn records_pushed_one_at_a_time() {
        let mut index = Index::new(Ecosystems::builtin());

        index.insert(about("GHSA-1", "npm", "tuna", r#"["1.0.0"]"#));
        index.insert(about("GHSA-2", "npm", "tuna", r#"["1.0.0"]"#));

        assert_eq!(index.advisories(&npm("tuna")).len(), 2);
    }
}
