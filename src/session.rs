//! Turning a configuration into the things a run actually uses.
//!
//! Everything below this module is written to be handed its dependencies:
//! a [`Source`] is built with an [`ExtHost`](crate::ext::ExtHost), which is
//! given an HTTP client and a set of [`Constraints`]. That is what keeps
//! them testable and what keeps a source unable to reach a host it was not
//! configured for. The cost is that somebody has to do the handing, and
//! this is that somebody.
//!
//! ```text
//!   Config --> Hosts::open(name) --> HostedExt --> Source
//!          \-> Sources::open(name) -------------/
//! ```
//!
//! [`crate::repo::Sources`] already builds the right-hand half. This module
//! builds the left.
//!
//! # Nothing here decides policy
//!
//! Which artifacts are wanted, what happens about a problem, whether a run
//! failed -- none of that is here. This is plumbing: it reads names out of a
//! configuration and returns live objects. That separation is why a command
//! can be tested against a fixture host without this module existing at
//! all.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::advisory::{self, Advisor, Policed};
use crate::config::Source as SourceConfig;
use crate::config::{Config, Host as HostConfig, TlsVerify};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::log::Log;
use crate::core::problem::{Code, Decide};
use crate::ext::{Cache, Constraints, Gate, Gates, HostedExt, Mirror, Options, Route};
use crate::model::{ArtifactId, EcosystemId, ResolvedArtifact};
use crate::net::emulate::{LocalClient, Settings as LocalSettings};
use crate::net::{ByteLimit, HttpClient, ReqwestClient, RetryPlan, RetryingClient};
use crate::policy::{Dispositions, LicensePolicy, QuarantinePolicy, SecurityPolicy};
use crate::repo::enumerate::{Enumerator, Enumerators};
use crate::repo::{Criteria, Source, Sources, Target, criteria_for};
use crate::report::{ReportQuery, ReportWriter};
use crate::version::{PreRelease, VersionHandler};

/// Where caches go when `setup.cache-dir` names nowhere.
///
/// Under the system temporary directory rather than the working directory,
/// because a cache is space a run may fill and a tool should not
/// leave debris where it was invoked from.
const DEFAULT_CACHE_DIR: &str = "artifact-copy";

/// Where a Sigstore trust root fetched over TUF is cached, under the cache
/// directory.
const SIGSTORE_CACHE_DIR: &str = "sigstore-tuf";

/// The keyserver capability's cache folder, under the cache directory.
/// Parenthesized, which [`cache_folder`] never produces from a host name,
/// so no host's cache shares it.
const KEYSERVERS_CACHE: &str = "(keyservers)";

/// One run's live objects.
///
/// Holds the three registries a command needs and nothing else: the hosts
/// it may reach, the sources it may read, and how it decides what happens
/// about a problem. Asking for a source by name returns one that can fetch.
///
/// Borrows its configuration rather than owning it, so a caller keeps the
/// `Config` alive alongside. That is deliberate: the configuration is the
/// single description of a run, and a session holding a private copy would
/// be a second one that could drift.
pub struct Session<'c> {
    config: &'c Config,
    hosts: Hosts<'c>,
    sources: Sources<'c>,
    enumerators: Enumerators<'c>,
    dispositions: Arc<Dispositions>,

    /// Where the run's caches go: `setup.cache-dir`, resolved.
    cache_root: PathBuf,

    /// Host-scoped quarantine policies, by resolved path.
    ///
    /// Bounded by the configuration: one entry per distinct file a host
    /// names, however many sources read through it.
    policies: HashMap<PathBuf, Arc<QuarantinePolicy>>,

    /// The same caching for license policies, keyed the same way.
    licenses: HashMap<PathBuf, Arc<LicensePolicy>>,

    /// And for security policies.
    securities: HashMap<PathBuf, Arc<SecurityPolicy>>,

    /// Kept because a per-source `Dispositions` has to be rebuilt with it.
    harden: bool,
}

impl<'c> Session<'c> {
    /// `harden` is the command line's `--harden`; see
    /// [`Config::dispositions`].
    pub fn open(config: &'c Config, harden: bool) -> Result<Self> {
        Self::build(config, harden, None)
    }

    /// Every fetch goes through `http` rather than through a real client.
    ///
    /// For a caller with a transport of its own -- a test serving canned
    /// responses, or an embedder that already has a client. Everything else
    /// is unchanged: constraints still confine each source to its host, and
    /// credentials are still attached by the capability rather than by the
    /// client.
    pub fn over(config: &'c Config, harden: bool, http: Arc<dyn HttpClient>) -> Result<Self> {
        Self::build(config, harden, Some(http))
    }

    fn build(config: &'c Config, harden: bool, http: Option<Arc<dyn HttpClient>>) -> Result<Self> {
        let root = config
            .setup
            .cache_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join(DEFAULT_CACHE_DIR));
        let sigstore_cache = root.join(SIGSTORE_CACHE_DIR);

        Ok(Self {
            config,
            hosts: match http {
                Some(http) => Hosts::over(config, root.clone(), http),
                None => Hosts::new(config, root.clone()),
            },
            sources: Sources::new(config).caching_sigstore_in(sigstore_cache),
            enumerators: Enumerators::new(config),
            dispositions: Arc::new(config.dispositions(harden)?),
            cache_root: root,
            policies: HashMap::new(),
            licenses: HashMap::new(),
            securities: HashMap::new(),
            harden,
        })
    }

    /// Log through this while binding hosts.
    pub fn logging_with(mut self, log: Log) -> Self {
        self.hosts.log = log;
        self
    }

    /// The configured cache directory, as written.
    ///
    /// Kept as the user spelled it rather than resolved, so that a report
    /// naming a cached file can be told apart from the same file under a
    /// directory somebody has since moved.
    pub fn cache_dir(&self) -> String {
        self.config
            .setup
            .cache_dir
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    }

    /// Where the run's caches go, resolved: `setup.cache-dir`, or a folder
    /// under the system temporary directory.
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// What becomes of a downloaded payload once it has been published.
    ///
    /// `reuse` by default, which is the safe answer rather than the frugal
    /// one: a later run reuses the download, and the disk is bounded by how
    /// long cache entries live rather than by the size of the migration.
    pub fn payloads(&self) -> crate::config::Payloads {
        self.config.setup.cache_payloads.unwrap_or_default()
    }

    /// The source configured under `name`, ready to fetch.
    ///
    /// The same instance on every call, and already built with the host it
    /// reaches -- including, for a proxy, one host per upstream.
    pub fn source(&mut self, name: &str) -> Result<ConfiguredSource> {
        let declared = self
            .config
            .sources
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "source",
                name: name.to_owned(),
            })?;

        Ok(ConfiguredSource {
            source: self.sources.open(name, &mut self.hosts)?,
            decide: self.decide_for(declared)?,
            licenses: self.licenses_for(declared)?,
            security: self.security_for(declared.host.as_deref())?,
            criteria: criteria_for(declared, &self.config.setup),
            dependencies: declared.dependencies.clone(),
            in_memory_queued_dependencies: self.config.setup.maximum_in_memory_queued_dependencies,
        })
    }

    /// How problems are decided for work against this source.
    ///
    /// The run's dispositions, with the source's **host** quarantine policy
    /// layered in front when it names one -- "this is a name-confusion
    /// attack" is true of a public registry and not of an internal mirror,
    /// which is why the file can be scoped that way at all.
    ///
    /// A proxy declares no host of its own, so only the run's policy
    /// applies to it. That is the honest answer rather than a gap: its
    /// upstreams' hosts describe where bytes come from, and a quarantine
    /// rule is about the artifact.
    fn decide_for(&mut self, declared: &SourceConfig) -> Result<Arc<dyn Decide>> {
        let Some(path) = declared
            .host
            .as_deref()
            .and_then(|host| self.config.hosts.get(host))
            .and_then(|host| host.quarantine_policy.as_ref())
        else {
            return Ok(self.dispositions.clone());
        };

        // Read once per file, not once per source: several sources on one
        // host is the ordinary case, and each would otherwise re-read and
        // re-validate the same document.
        let policy = match self.policies.get(path) {
            Some(policy) => policy.clone(),
            None => {
                let policy = Arc::new(QuarantinePolicy::load(path)?);

                self.policies.insert(path.clone(), policy.clone());

                policy
            }
        };

        Ok(Arc::new(self.config.dispositions_layered(
            self.harden,
            vec![(*policy).clone()],
        )?))
    }

    /// The license policy for work against this source.
    ///
    /// A host's own policy wins over `setup`'s, exactly as a quarantine
    /// policy does -- the two answer the same shape of question about the
    /// same repository, and a user who set one per host will expect the
    /// other to follow.
    fn licenses_for(&mut self, declared: &SourceConfig) -> Result<Option<Arc<LicensePolicy>>> {
        let path = declared
            .host
            .as_deref()
            .and_then(|host| self.config.hosts.get(host))
            .and_then(|host| host.license_policy.as_ref())
            .or(self.config.setup.license_policy.as_ref());

        let Some(path) = path else {
            return Ok(None);
        };

        // Read once per file, not once per source, for the reason
        // `decide_for` gives: several sources on one host is ordinary.
        if let Some(policy) = self.licenses.get(path) {
            return Ok(Some(policy.clone()));
        }

        let policy = Arc::new(LicensePolicy::load(path)?);

        self.licenses.insert(path.clone(), policy.clone());

        Ok(Some(policy))
    }

    /// The security policy for work against this source.
    ///
    /// Resolved and cached exactly as `licenses_for` does it -- a host's own
    /// policy over `setup`'s, read once per file -- because the two answer the
    /// same shape of question about the same repository.
    ///
    /// Loading it here rather than only in `validate-config` is what makes an
    /// unusable policy a fault of the **run** rather than a surprise on first
    /// screening. `SecurityPolicy::load` answers `Error::Config`, which is
    /// fail-fast.
    ///
    /// Takes the host rather than the source, since an enumerator answers to the
    /// same policy as a source on its host.
    fn security_for(&mut self, host: Option<&str>) -> Result<Option<Held<SecurityPolicy>>> {
        let path = host
            .and_then(|host| self.config.hosts.get(host))
            .and_then(|host| host.security_policy.as_ref())
            .or(self.config.setup.security_policy.as_ref());

        let Some(path) = path else {
            return Ok(None);
        };

        if let Some(policy) = self.securities.get(path) {
            return Ok(Some((path.clone(), policy.clone())));
        }

        let policy = Arc::new(SecurityPolicy::load(path)?);

        // Once per file, as it loads: the conflict is a fact about the
        // configuration, not about any artifact.
        let stated = self
            .config
            .problem_policy
            .get(&Code::VulnerabilityKnown)
            .copied();

        if let Some(warning) = policy.stance_conflict(path, stated) {
            self.hosts.log.warn(warning);
        }

        self.securities.insert(path.clone(), policy.clone());

        Ok(Some((path.clone(), policy)))
    }

    /// The names of the advisors this run configures.
    ///
    /// A narrow accessor rather than handing out the `Config`: a session
    /// answers by name for everything else, and this is the one thing a
    /// sub-command needs that no other accessor reaches. What each advisor
    /// *is* stays here, because nothing outside acts on it yet.
    pub fn advisors(&self) -> impl Iterator<Item = &str> {
        self.config.advisors.keys().map(String::as_str)
    }

    /// The advisor configured under `name`, ready to load.
    ///
    /// Confined to its host's own url, as an enumerator is: the corpus's path
    /// under the host is the advisor's to build, not configuration's.
    pub fn advisor(&mut self, name: &str) -> Result<Box<dyn Advisor>> {
        let declared = self
            .config
            .advisors
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "advisor",
                name: name.to_owned(),
            })?;

        // An extension kind goes to the gearing, which runs only sources yet.
        if self.config.extensions.contains_key(&declared.kind) {
            return Err(Error::Unimplemented("running an advisor extension"));
        }

        let settings = advisory::Settings {
            ttl: declared.ttl.map(|ttl| ttl.get()),
            ecosystems: declared
                .ecosystems
                .iter()
                .map(|id| EcosystemId::new(id.as_str()))
                .collect(),
            path: declared.path.clone(),
        };

        // Its corpus's freshness is its own `ttl`; its retention is setup's.
        let policy = crate::repo::cache_policy(&self.config.setup, None, &[], None);
        let host: Arc<dyn crate::ext::ExtHost> = Arc::new(crate::ext::Policed::new(
            self.hosts.open(&declared.host)?,
            policy,
        ));
        let base_url = self.hosts.url_of(&declared.host)?;

        advisory::open(
            &declared.kind,
            base_url,
            &settings,
            &Options::new(declared.options.clone()),
            host,
        )
    }

    /// The target configured under `name`, ready to publish.
    ///
    /// Built directly rather than through a registry like [`Sources`]:
    /// a target has no proxy kinds, so there is no recursion to bind
    /// through and nothing to share between two names.
    pub fn target(&mut self, name: &str) -> Result<ConfiguredTarget> {
        let declared = self
            .config
            .targets
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "target",
                name: name.to_owned(),
            })?;

        let url = self
            .config
            .hosts
            .get(&declared.host)
            .map(|entry| entry.url.as_str())
            .ok_or_else(|| Error::UnknownName {
                collection: "host",
                name: declared.host.clone(),
            })?;

        let base = crate::repo::under(url, declared.host_path.as_deref()).map_err(|detail| {
            Error::Config(format!("target {name:?} has an unusable path: {detail}"))
        })?;

        // An extension kind goes to the gearing, which runs only sources yet.
        if self.config.extensions.contains_key(&declared.kind) {
            return Err(Error::Unimplemented("running a target extension"));
        }

        // Confined to the joined prefix, exactly as a source is: a target
        // writing to one repository must not be able to write to another on
        // the same server.
        let host = self.hosts.under(&declared.host, &base)?;

        let opened = crate::repo::open_target(
            &declared.kind,
            &base,
            &crate::ext::Options::from(declared.options.clone()),
            host,
        )?;

        // Every target, so a configured `omit` never depends on its kind.
        let omit = crate::repo::Omit::parse(&declared.omit)?;

        Ok(ConfiguredTarget {
            target: Arc::new(crate::repo::OmittingTarget::new(opened, omit)),
        })
    }

    /// The enumerator configured under `name`, ready to walk.
    ///
    /// Confined to its host's url joined with its `host-path`. A
    /// manager's catalog lives behind a REST API at the server root, where
    /// the repository is an option rather than a path, so its enumerator
    /// leaves `host-path` absent; an index rooted under the server, such as
    /// Artifact Keeper's `pypi/{repo}`, sets one.
    pub fn enumerator(&mut self, name: &str) -> Result<ConfiguredEnumerator> {
        let declared = self
            .config
            .enumerators
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "enumerator",
                name: name.to_owned(),
            })?;

        Ok(ConfiguredEnumerator {
            enumerator: self.enumerators.open(name, &mut self.hosts)?,
            kind: declared.kind.clone(),
            security: self.security_for(declared.host.as_deref())?,
        })
    }

    /// The lock readers this run offers: the built-ins, and any format a
    /// configured extension names.
    pub fn locks(&self) -> crate::lock::Registry {
        crate::lock::Registry::builtin().with_extensions(&self.config.extensions)
    }

    /// Derive a context that decides problems under this run's policy.
    ///
    /// Applied here rather than by each command, because a command that
    /// forgot would silently fall back to the built-in dispositions and
    /// ignore everything a user configured.
    pub fn deciding(&self, ctx: &Ctx) -> Ctx {
        ctx.clone().deciding_with(self.dispositions.clone())
    }

    /// The capability for a configured host, for a caller that needs one
    /// without a source -- fetching a keyserver, say.
    pub fn host(&mut self, name: &str) -> Result<Arc<HostedExt>> {
        self.hosts.open(name)
    }
}

/// A target, ready to publish.
pub struct ConfiguredTarget {
    pub target: Arc<dyn Target>,
}

/// Whether a target already holds an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holding {
    Held,
    Absent,
}

impl ConfiguredTarget {
    /// Whether this target already holds `artifact`, recorded as
    /// `destination` in the report.
    ///
    /// **The report first, the repository second.** `NpmTarget::exists` is
    /// a `HEAD` per artifact, so a migration of a million of them is a
    /// million requests against the target purely to ask what it already
    /// holds. A report that has seen the target -- through `find
    /// --as-target` -- answers it without one. `query` is opened once by the
    /// caller, because opening a read view per artifact is the cost this
    /// exists to avoid.
    ///
    /// Whatever is learned is written down, so the second migration asks
    /// less than the first did.
    pub async fn holds(
        &self,
        artifact: &ResolvedArtifact,
        report: &dyn ReportWriter,
        query: Option<&dyn ReportQuery>,
        destination: &str,
        ctx: &Ctx,
    ) -> Result<Holding> {
        let purl = artifact.purl();

        // A report cannot prove an absence, so `false` here means only that
        // nothing says so and the repository is still worth asking.
        if let Some(query) = query
            && query.holds(destination, &purl)?
        {
            return Ok(Holding::Held);
        }

        let held = self
            .target
            .exists(&artifact.id, artifact.version.as_ref(), ctx)
            .await?;

        if !held {
            return Ok(Holding::Absent);
        }

        if let Some(state) = report.state() {
            state.present(destination, &purl)?;
        }

        Ok(Holding::Held)
    }
}

/// An enumerator, ready to walk.
///
/// No `criteria` and no `decide` of its own: an enumerator enumerates rather
/// than resolves, so there is no version to judge and no artifact to hold
/// a per-artifact rule against until something resolves one.
pub struct ConfiguredEnumerator {
    pub enumerator: Arc<dyn Enumerator>,

    /// The configured kind, which a resumed walk needs: a cursor belongs to
    /// the implementation that issued it, and handing one to a different
    /// kind means nothing.
    pub kind: String,

    /// The security policy what it lists is screened under: its host's, or
    /// `setup`'s.
    security: Option<Held<SecurityPolicy>>,
}

impl ConfiguredEnumerator {
    /// The security policy this enumerator's listings are screened under, with
    /// the file it came from.
    pub fn policed(&self) -> Policed<'_> {
        policed(&self.security)
    }
}

/// A policy file's contents, and the path it was read from.
type Held<T> = (PathBuf, Arc<T>);

fn policed(held: &Option<Held<SecurityPolicy>>) -> Policed<'_> {
    held.as_ref()
        .map(|(path, policy)| (path.as_path(), policy.as_ref()))
}

/// A source and everything the run decided about it.
pub struct ConfiguredSource {
    pub source: Arc<dyn Source>,

    /// How problems are decided for work against this source.
    ///
    /// Carried on the source rather than on the session because it may
    /// differ per source: a host can name its own quarantine policy. See
    /// [`ConfiguredSource::deciding`].
    decide: Arc<dyn Decide>,

    /// The license policy in force for work against this source.
    ///
    /// Per source for the same reason `decide` is: a host may name its own,
    /// falling back to `setup`. `None` when neither does, which is what
    /// leaves a report's `license` field absent rather than claiming an
    /// allow nobody decided.
    licenses: Option<Arc<LicensePolicy>>,

    /// The security policy in force for work against this source.
    ///
    /// Resolved exactly as `licenses` is, and for the same reason: a host may
    /// name its own, falling back to `setup`.
    ///
    /// With the path it was read from, which is how the run's screening
    /// state keys the statements it exercised.
    security: Option<Held<SecurityPolicy>>,

    /// What this source's configuration says a resolved artifact must
    /// satisfy: its publish window, and what to do when a publish time is
    /// unknown.
    ///
    /// Pre-releases are **not** settled here -- see [`ConfiguredSource::criteria`].
    criteria: Criteria,

    /// The source's `dependencies` default, unparsed, e.g. `runtime+dev`.
    dependencies: Option<String>,

    /// `setup.maximum-in-memory-queued-dependencies`, carried here because a walk
    /// sees the source and not the session.
    in_memory_queued_dependencies: Option<usize>,
}

impl ConfiguredSource {
    /// The same binding, reading through a different source.
    ///
    /// Everything a run decided about the repository -- its host, its
    /// quarantine policy, its license policy, its publish window -- is a
    /// decision about the *repository*, not about the code that answers for
    /// it. A wrapper that answers some questions from a report and the rest
    /// from the repository is still that repository, so it keeps all of it.
    ///
    /// The one thing that would be wrong is letting a wrapper reach a host
    /// the binding does not permit. Nothing here prevents it: the guarantee
    /// is the caller's. `source` must hold no host of its own and send every
    /// fetch through the source it wraps, whose host is confined to this
    /// repository. `InventorySource` does: it answers from the report and
    /// forwards `download`, `verify`, `serves`, and `companion`.
    pub fn reading_through(self, source: Arc<dyn Source>) -> Self {
        Self { source, ..self }
    }

    /// How this source's versions are read and ordered, for one artifact.
    ///
    /// The configured handler when there is one, and the artifact's
    /// ecosystem otherwise -- every `Ecosystem` is a `VersionHandler`, which
    /// is what makes the fallback a substitution rather than a special
    /// case.
    ///
    /// Per artifact rather than per source because a repository manager
    /// serves Maven, npm and PyPI from one host, and those three order
    /// versions differently. A source that speaks one ecosystem returns the
    /// same answer every time, which is the common case and costs nothing.
    ///
    /// Asked of the source rather than answered here, so this and
    /// resolution cannot disagree: `Source::resolve` consults the same
    /// method, which is what makes the configured handler take effect
    /// rather than merely validate.
    pub fn versions(&self, id: &ArtifactId) -> Result<&dyn VersionHandler> {
        self.source.version_handler(id)
    }

    /// The license policy this source's artifacts are judged under.
    pub fn licenses(&self) -> Option<&LicensePolicy> {
        self.licenses.as_deref()
    }

    /// The security policy this source's artifacts are screened under.
    pub fn security(&self) -> Option<&SecurityPolicy> {
        self.security.as_ref().map(|(_, policy)| policy.as_ref())
    }

    /// [`ConfiguredSource::security`], with the file it came from, for screening.
    pub fn policed(&self) -> Policed<'_> {
        policed(&self.security)
    }

    /// What a resolved artifact must satisfy, beyond the version asked for.
    ///
    /// The source's own publish window and unknown-publish-time rule,
    /// resolved against `setup`, with `pre` supplied by the caller: whether
    /// pre-releases are candidates comes from `--pre-release`, which is
    /// about one invocation rather than about a repository, so a source
    /// cannot say it on a user's behalf.
    ///
    /// For a **proxy** this is the proxy's own declaration, not its
    /// upstreams'. The proxy is the source being resolved against, and the
    /// default `resolve` drives the proxy's own `versions` and `metadata`,
    /// so an upstream's window never comes into play.
    pub fn criteria(&self, pre: PreRelease) -> Criteria {
        self.criteria.pre_release(pre)
    }

    /// The dependencies this source follows by default, unparsed.
    ///
    /// For a proxy, the proxy's own declaration, as with `criteria`.
    pub fn dependencies(&self) -> Option<&str> {
        self.dependencies.as_deref()
    }

    /// How many dependencies a walk may hold in memory, when `setup` says.
    pub fn in_memory_queued_dependencies(&self) -> Option<usize> {
        self.in_memory_queued_dependencies
    }

    /// Derive a context for work against this source.
    ///
    /// Use this rather than [`Session::deciding`] once a source is in hand:
    /// it is the one that knows about the host's own quarantine policy.
    /// `Session::deciding` is for work with no source -- reading a lock
    /// file, resolving a name -- where there is no host to scope by.
    pub fn deciding(&self, ctx: &Ctx) -> Ctx {
        ctx.clone().deciding_with(self.decide.clone())
    }
}

/// The host capabilities a configuration describes.
///
/// Built lazily and shared, exactly as [`crate::repo::Sources`] is and for
/// the same reason: two sources naming one host should reach it through one
/// capability, so its connection pool, its credentials and its cache are
/// shared rather than duplicated per source.
pub struct Hosts<'c> {
    config: &'c Config,

    /// Where each host's cache is created, one directory per host.
    root: PathBuf,

    /// One HTTP client per TLS setting.
    ///
    /// Keyed by the setting rather than by host because TLS verification is
    /// a property of the *client* -- `reqwest` decides it at build time -- so
    /// a host that disables it genuinely needs a different one. Everything
    /// else is per-request, which is why every host that agrees about TLS
    /// can share one connection pool.
    clients: HashMap<TlsVerify, Arc<dyn HttpClient>>,

    /// Used for every host instead of a real one, when supplied.
    ///
    /// For a caller with its own transport -- a test serving canned
    /// responses, or an embedder that already has a client it wants the
    /// fetches to go through. TLS is then that client's business, which is
    /// why the per-setting cache is skipped entirely rather than keyed by
    /// something meaningless.
    supplied: Option<Arc<dyn HttpClient>>,

    /// One per cache folder, shared by every capability reading that
    /// repository.
    caches: HashMap<String, Arc<Cache>>,

    /// `setup.cache-size`, shared by every cache folder under `root`.
    budget: Option<Arc<crate::ext::Budget>>,

    /// Keyed by host **and** the prefix the capability permits.
    ///
    /// Not by host alone: a repository manager serves many repositories
    /// from one server, and each source gets a capability confined to its
    /// own, so one host yields several. What they share -- the connection
    /// pool, the credentials, the retry plan -- is shared because it comes
    /// from the same host entry, which is the point of allowing one.
    built: HashMap<(String, String), Arc<HostedExt>>,

    /// Each configured host's caps, by host name, shared by every
    /// capability built from that entry and every route naming it.
    gates: HashMap<String, Gates>,

    /// Keyserver capabilities, by the list of keyserver URLs they permit.
    /// Apart from `built`, so no configured host name can share an entry.
    keyservers: HashMap<Vec<String>, Arc<HostedExt>>,

    /// Where building a client logs, such as a host that disables TLS
    /// verification.  Held because hosts bind lazily, with no `Ctx` in reach.
    log: Log,
}

/// A configured cap, or none when unset. Zero would admit no request at
/// all, so it is refused rather than hanging the run.
fn gate(host: &str, key: &str, limit: Option<usize>) -> Result<Gate> {
    let Some(limit) = limit else {
        return Ok(Gate::default());
    };

    let Some(limit) = std::num::NonZeroUsize::new(limit) else {
        return Err(Error::Config(format!(
            "host {host:?} sets {key} to 0, which would admit no request; use at least 1"
        )));
    };

    Ok(Gate::limited(limit))
}

impl<'c> Hosts<'c> {
    /// `root` is where each host's cache is created.
    pub fn new(config: &'c Config, root: impl Into<PathBuf>) -> Self {
        let root = root.into();

        Self {
            config,
            budget: config
                .setup
                .cache_size
                .map(|size| Arc::new(crate::ext::Budget::new(&root, size.get()))),
            root,
            clients: HashMap::new(),
            supplied: None,
            caches: HashMap::new(),
            built: HashMap::new(),
            gates: HashMap::new(),
            keyservers: HashMap::new(),
            log: Log::default(),
        }
    }

    /// Reach every host through `http` rather than through a real client.
    pub fn over(config: &'c Config, root: impl Into<PathBuf>, http: Arc<dyn HttpClient>) -> Self {
        Self {
            supplied: Some(http),
            ..Self::new(config, root)
        }
    }

    /// The capability for the host configured under `name`, permitting
    /// everything under its own url.
    ///
    /// For a caller with no narrower prefix in mind -- a keyserver fetch, a
    /// enumerator building a REST API off the server root. A source uses
    /// [`Hosts::under`] instead.
    pub fn open(&mut self, name: &str) -> Result<Arc<HostedExt>> {
        let url = self.url_of(name)?.to_owned();

        self.under(name, &url)
    }

    /// The capability for `name`, confined to `base`, and reading from the
    /// host's additional hosts.
    ///
    /// `base` must be at or below the host's url; a source's is the host's
    /// url with its `path` joined on. The same instance for the same pair,
    /// so two sources reading one repository share one capability and two
    /// reading different repositories on one server do not.
    ///
    /// Each additional host is a [`Route`]: its own client, TLS setting,
    /// retry plan and credentials, so nothing configured for `name` is sent
    /// to it unless the entry says so. See `docs/contributors/wiring.md`.
    pub fn under(&mut self, name: &str, base: &str) -> Result<Arc<HostedExt>> {
        // Canonical, so a trailing slash does not produce a second
        // capability permitting exactly the same thing.
        let base = crate::net::normalized_base(base);
        let key = (name.to_owned(), base.clone());

        if let Some(built) = self.built.get(&key) {
            return Ok(Arc::clone(built));
        }

        let declared = self
            .config
            .hosts
            .get(name)
            .ok_or_else(|| Error::UnknownName {
                collection: "host",
                name: name.to_owned(),
            })?;

        let routes = self.routes(name, declared)?;
        let mirrors = self.mirrors(name, declared)?;
        let gates = self.gates(name, declared)?;
        let host = Arc::new(
            self.build(name, &base, declared)?
                .with_routes(routes)
                .with_mirrors(mirrors)
                .with_gates(gates),
        );

        self.built.insert(key, Arc::clone(&host));

        Ok(host)
    }

    /// One capability permitting exactly these keyserver URLs, the same
    /// instance for the same list.
    ///
    /// Anonymous: no credentials, default TLS and retry, as a keyserver is
    /// a public service no configuration entry describes. Its cache folder
    /// is its own, so a key fetched here never lands in a repository's.
    pub fn keyserving(&mut self, urls: &[String]) -> Result<Arc<HostedExt>> {
        if let Some(built) = self.keyservers.get(urls) {
            return Ok(Arc::clone(built));
        }

        let client = self.retrying(TlsVerify::Enabled, None)?;

        let mut constraints = Constraints::new();

        for url in urls {
            constraints = constraints.allow(url).map_err(|detail| {
                Error::Config(format!("keyserver {url:?} is not usable: {detail}"))
            })?;
        }

        let constraints = constraints
            .with_tls(TlsVerify::Enabled)
            .with_max_in_memory(self.max_in_memory());

        let cache = self.cache(KEYSERVERS_CACHE)?;
        let host =
            Arc::new(HostedExt::new(client, constraints.clone(), cache).with_site(constraints));

        self.keyservers.insert(urls.to_vec(), Arc::clone(&host));

        Ok(host)
    }

    /// One route per additional host of `owner`.
    ///
    /// Not transitive: a named additional host brings its own url and
    /// settings, never its own additional hosts, so two hosts naming each
    /// other cannot loop.
    fn routes(&mut self, name: &str, owner: &HostConfig) -> Result<Vec<Route>> {
        let mut routes = Vec::with_capacity(owner.additional_hosts.len());

        for entry in &owner.additional_hosts {
            routes.push(self.route(name, owner, entry)?);
        }

        Ok(routes)
    }

    /// One mirror per entry of `owner`, in order.
    ///
    /// Each with the owner's TLS setting and retry plan and no credentials:
    /// a mirror is a public copy of the owner, never another login.
    fn mirrors(&mut self, name: &str, owner: &HostConfig) -> Result<Vec<Mirror>> {
        let mut mirrors = Vec::with_capacity(owner.mirrors.len());

        for entry in &owner.mirrors {
            // Parsed as an additional host's prefix is, so a typo fails
            // here rather than on the first read.
            Constraints::new().allow(&entry.url).map_err(|detail| {
                Error::Config(format!(
                    "host {name:?} has an unusable mirror {}: {detail}",
                    entry.url
                ))
            })?;

            let http = self.retrying(owner.tls_verify(), owner.retry.as_ref())?;

            mirrors.push(Mirror::new(
                &owner.url,
                &entry.url,
                http,
                entry.skip.clone(),
            ));
        }

        Ok(mirrors)
    }

    /// The route to one additional host.
    ///
    /// ```text
    ///   {host: n}      n's url;  n's TLS and retry;  n's credentials
    ///   {hostname: x}  https://x/;  defaults;  no credentials
    ///   inherit                          owner's TLS and retry instead
    ///   inherit-parent-authentication     owner's credentials instead
    ///   authentication                   these credentials instead
    /// ```
    fn route(
        &mut self,
        name: &str,
        owner: &HostConfig,
        entry: &crate::config::AdditionalHost,
    ) -> Result<Route> {
        let named = match (&entry.host, &entry.hostname) {
            (Some(host), None) => Some((
                host,
                self.config
                    .hosts
                    .get(host)
                    .ok_or_else(|| Error::UnknownName {
                        collection: "additional host",
                        name: host.to_owned(),
                    })?,
            )),

            (None, Some(_)) => None,

            _ => {
                return Err(Error::Config(format!(
                    "host {name:?} has an additional host naming {} of 'host' and \
                     'hostname'; name exactly one",
                    match entry.host.is_some() {
                        true => "both",
                        false => "neither",
                    },
                )));
            }
        };

        let prefix = match (&named, &entry.hostname) {
            (Some((_, declared)), _) => declared.url.clone(),
            (None, Some(hostname)) => anonymous_prefix(hostname)?,
            (None, None) => unreachable!("refused above"),
        };

        let (tls, retry) = match (entry.inherit, &named) {
            (true, _) => (owner.tls_verify(), owner.retry.as_ref()),
            (false, Some((_, declared))) => (declared.tls_verify(), declared.retry.as_ref()),
            (false, None) => (TlsVerify::Enabled, None),
        };

        let auth = match (&entry.authentication, entry.inherit_parent_authentication) {
            (Some(_), true) => {
                return Err(Error::Config(format!(
                    "host {name:?} has an additional host at {prefix} with both \
                     'authentication' and 'inherit-parent-authentication'; name one"
                )));
            }

            (Some(own), false) => Some(own.clone()),
            (None, true) => owner.authentication.clone(),
            (None, false) => named.and_then(|(_, declared)| declared.authentication.clone()),
        };

        let constraints = Constraints::new()
            .allow(&prefix)
            .map_err(|detail| {
                Error::Config(format!(
                    "host {name:?} has an unusable additional host {prefix}: {detail}"
                ))
            })?
            .with_tls(tls);

        let route = Route::new(constraints, self.retrying(tls, retry)?, auth);

        // A configured host counts its requests once, however it is
        // reached; a bare hostname has no limit to apply.
        let Some((host, declared)) = named else {
            return Ok(route);
        };

        Ok(route.with_gates(self.gates(host, declared)?))
    }

    /// The caps for the host configured under `name`, the same counters for
    /// every caller.
    fn gates(&mut self, name: &str, declared: &HostConfig) -> Result<Gates> {
        if let Some(gates) = self.gates.get(name) {
            return Ok(gates.clone());
        }

        let gates = Gates::new(
            gate(
                name,
                "maximum-concurrent-downloads",
                declared.maximum_concurrent_downloads,
            )?,
            gate(
                name,
                "maximum-concurrent-uploads",
                declared.maximum_concurrent_uploads,
            )?,
        );

        self.gates.insert(name.to_owned(), gates.clone());

        Ok(gates)
    }

    /// The shared client for a TLS setting, behind a host's retry plan.
    ///
    /// Retries wrap the shared client rather than replacing it: the plan
    /// is per host and the connection pool is not, so a host with an
    /// unusual retry rule still shares connections with its neighbours.
    fn retrying(
        &mut self,
        tls: TlsVerify,
        retry: Option<&crate::config::Retry>,
    ) -> Result<Arc<dyn HttpClient>> {
        let client = self.client_for(tls)?;
        let plan = RetryPlan::from_config(retry)?;

        Ok(Arc::new(RetryingClient::new(client, plan)))
    }

    fn url_of(&self, name: &str) -> Result<&'c str> {
        self.config
            .hosts
            .get(name)
            .map(|declared| declared.url.as_str())
            .ok_or_else(|| Error::UnknownName {
                collection: "host",
                name: name.to_owned(),
            })
    }

    fn build(&mut self, name: &str, base: &str, declared: &HostConfig) -> Result<HostedExt> {
        // A directory is answered by the emulation rather than the network;
        // everything above the client is the same for both.
        let client: Arc<dyn HttpClient> = match local_settings(name, declared)? {
            Some(settings) => {
                Arc::new(LocalClient::new(&declared.url, settings).map_err(|detail| {
                    Error::Config(format!("host {name:?} has an unusable url: {detail}"))
                })?)
            }
            None => self.retrying(declared.tls_verify(), declared.retry.as_ref())?,
        };

        // Confined to `base`, not to the host's url. For a source under a
        // manager those differ, and the narrower one is what keeps it off
        // the other repositories on the same server.
        let constraints = Constraints::new()
            .allow(base)
            .map_err(|detail| {
                Error::Config(format!("host {name:?} has an unusable url: {detail}"))
            })?
            .with_tls(declared.tls_verify())
            .with_max_in_memory(self.max_in_memory());

        // One cache per repository rather than per server. Two
        // capabilities reading one repository share it and reuse what the
        // other downloaded; two reading different repositories on one
        // manager must not, because the same relative name means different
        // bytes in each.
        //
        // Named for the host, plus the path when there is one, so a person
        // looking in the cache directory can tell which repository a folder
        // belongs to.
        let under = base.strip_prefix(&crate::net::normalized_base(&declared.url));
        let cache = self.cache(&cache_folder(&match under {
            Some("") | None => name.to_owned(),
            Some(path) => format!("{name}{path}"),
        }))?;

        // Handed over unresolved, and that is `HostedExt`'s design rather
        // than an omission here: it resolves each secret at the moment it
        // attaches one, so a token is never held in a long-lived object an
        // extension could be given. The cost is that a misspelled
        // environment variable surfaces on the first fetch rather than when
        // the host opens -- which `validate-config` is there to catch first.
        // A read may be redirected anywhere on the host with its own
        // credentials, while a first request stays under `base`.
        let site = Constraints::new()
            .allow(&declared.url)
            .map_err(|detail| {
                Error::Config(format!("host {name:?} has an unusable url: {detail}"))
            })?
            .with_tls(declared.tls_verify());

        Ok(HostedExt::new(client, constraints, cache)
            .with_site(site)
            .with_auth(declared.authentication.clone()))
    }

    /// The cache for one folder, the same instance every time.
    fn cache(&mut self, folder: &str) -> Result<Arc<Cache>> {
        if let Some(opened) = self.caches.get(folder) {
            return Ok(Arc::clone(opened));
        }

        let opened = match &self.budget {
            Some(budget) => Cache::open_within(self.root.join(folder), Arc::clone(budget))?,
            None => Arc::new(Cache::open(self.root.join(folder))?),
        };

        self.caches.insert(folder.to_owned(), Arc::clone(&opened));

        Ok(opened)
    }

    fn client_for(&mut self, tls: TlsVerify) -> Result<Arc<dyn HttpClient>> {
        if let Some(supplied) = &self.supplied {
            return Ok(Arc::clone(supplied));
        }

        if let Some(client) = self.clients.get(&tls) {
            return Ok(Arc::clone(client));
        }

        let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::with_tls(tls, &self.log)?);

        self.clients.insert(tls, Arc::clone(&client));

        Ok(client)
    }

    /// The ceiling on a response held in memory, from `setup`.
    ///
    /// One global answer rather than a per-host one: the limit exists to
    /// bound this process's memory, and which host the bytes came from does
    /// not change how many of them there are.
    fn max_in_memory(&self) -> ByteLimit {
        self.config
            .setup
            .maximum_in_memory_download
            .map(|size| ByteLimit::bytes(size.get()))
            .unwrap_or_else(|| Constraints::new().max_in_memory())
    }
}

/// Supplying capabilities is the whole reason `repo::Sources` asks for
/// them: a source is bound to its host **as it is built**, because a
/// proxy's upstreams are built inside that recursion and never handed out
/// on their own.
impl crate::ext::Capabilities for Hosts<'_> {
    fn host(&mut self, name: &str, base: &str) -> Result<Arc<dyn crate::ext::ExtHost>> {
        Ok(self.under(name, base)?)
    }

    fn keyservers(&mut self, urls: &[String]) -> Result<Arc<dyn crate::ext::ExtHost>> {
        Ok(self.keyserving(urls)?)
    }
}

/// The emulation settings for a `file://` host, or `None` for a network
/// host.
///
/// A directory has no certificate, no connection to time out or retry, and
/// nobody to log in to, so a file host setting any of those is refused
/// rather than silently ignored. A network host takes no `options`.
pub(crate) fn local_settings(name: &str, declared: &HostConfig) -> Result<Option<LocalSettings>> {
    if !crate::net::emulate::is_local(&declared.url) {
        if declared.options.is_empty() {
            return Ok(None);
        }

        return Err(Error::Config(format!(
            "host {name:?} has 'options', which only a file:// host takes"
        )));
    }

    let unusable: Vec<&str> = [
        (declared.tls_verify() == TlsVerify::Disabled, "tls-verify"),
        (declared.connect_timeout.is_some(), "connect-timeout"),
        (declared.request_timeout.is_some(), "request-timeout"),
        (declared.retry.is_some(), "retry"),
        (declared.authentication.is_some(), "authentication"),
        (!declared.additional_hosts.is_empty(), "additional-hosts"),
        (!declared.mirrors.is_empty(), "mirrors"),
    ]
    .into_iter()
    .filter_map(|(set, key)| set.then_some(key))
    .collect();

    if !unusable.is_empty() {
        return Err(Error::Config(format!(
            "host {name:?} is a local directory, which takes no {}",
            unusable.join(", ")
        )));
    }

    LocalSettings::parse(&declared.options)
        .map(Some)
        .map_err(|detail| Error::Config(format!("host {name:?}: {detail}")))
}

/// `https://{hostname}/`, for a hostname and nothing else.
///
/// Refused when it carries a scheme, a path, a port or anything else a
/// hostname does not: `files.pythonhosted.org` is the shape, and a value
/// like `evil.test/../` would otherwise become a prefix nobody meant.
fn anonymous_prefix(hostname: &str) -> Result<String> {
    let bare = !hostname.is_empty()
        && hostname
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.')
        && !hostname.starts_with(['.', '-'])
        && !hostname.ends_with(['.', '-']);

    if !bare {
        return Err(Error::Config(format!(
            "anonymous file host {hostname:?} is not a bare hostname; write it with no \
             scheme, port or path, like files.pythonhosted.org"
        )));
    }

    Ok(format!("https://{hostname}/"))
}

/// A directory name safe to build from a configured host name.
///
/// Host names come from a configuration file and are otherwise
/// unconstrained, so one containing a separator would put a cache
/// somewhere other than under the root. Anything outside a conservative set
/// becomes `_`, which may collide -- two hosts named `a/b` and `a:b` would
/// share a directory -- and that is harmless: a cache is only reused,
/// and sharing one costs nothing but the isolation two hosts did not
/// require.
fn cache_folder(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(
            |ch| match ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                true => ch,
                false => '_',
            },
        )
        .collect();

    match cleaned.trim_matches('.').is_empty() {
        true => "host".to_owned(),
        false => cleaned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::path::Path;

    use crate::cli::ConfigLoader;
    use crate::ext::ExtHost;
    use crate::model::{EcosystemId, Release};

    fn config(body: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",{body}}}"#,
                crate::cli::config_schema_id()
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        (dir, config)
    }

    /// A target kind naming an extension reaches the gearing.
    #[test]
    fn extension_target_reaches_gearing() {
        let (_dir, config) = config(
            r#""hosts":{"mirror":{"url":"h://mirror.test/"}},
               "extensions":{"custom":{"kind":"executable","command":"custom-target","arguments":[]}},
               "targets":{"ext":{"kind":"custom","host":"mirror"}}"#,
        );
        let client = Arc::new(crate::net::FixtureClient::new());
        let mut session = Session::over(&config, false, client).expect("opens");

        let err = match session.target("ext") {
            Err(err) => err,
            Ok(_) => panic!("an extension cannot run yet"),
        };

        assert_eq!(err.code(), crate::core::problem::Code::Unimplemented);
    }

    /// The keyserver capability reaches exactly its keyservers, with no
    /// credentials, and nothing else -- not the host whose keys it looks
    /// up. One list is one capability.
    #[tokio::test]
    async fn keyservers_reach_only_themselves() {
        const KEYSERVER: &str = "https://keys.test/pks/lookup?op=get&search=0xAB";
        const REPOSITORY: &str = "https://repo.test/lib.pom";

        let (dir, config) = config(
            r#""hosts":{"repo":{"url":"https://repo.test/",
                "authentication":{"kind":"bearer",
                                  "token":{"kind":"text","value":"repo-token"}}}}"#,
        );
        let client = Arc::new(
            crate::net::FixtureClient::new()
                .with_body(KEYSERVER, "key")
                .with_body(REPOSITORY, "pom"),
        );
        let mut hosts = Hosts::over(&config, dir.path().join("sandbox"), client.clone());
        let servers = vec!["https://keys.test".to_owned()];
        let keyservers = hosts.keyserving(&servers).expect("builds");
        let ctx = Ctx::anonymous_for_test();

        keyservers
            .fetch(&crate::net::Req::get(KEYSERVER), ByteLimit::kib(1), &ctx)
            .await
            .expect("a keyserver is reachable");

        assert!(
            keyservers
                .fetch(&crate::net::Req::get(REPOSITORY), ByteLimit::kib(1), &ctx)
                .await
                .is_err(),
            "the keyserver capability reached a repository"
        );

        let sent = client.headers_to(KEYSERVER);
        assert!(
            sent.iter()
                .flatten()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")),
            "{sent:?}"
        );

        assert!(Arc::ptr_eq(
            &keyservers,
            &hosts.keyserving(&servers).expect("again")
        ));
    }

    /// A configured mirror answers a read under its host, anonymously.
    #[tokio::test]
    async fn host_reads_from_mirror() {
        const ORIGIN: &str = "https://repo.test/m2/a/1/a-1.jar";
        const COPY: &str = "https://copy.test/m2/a/1/a-1.jar";

        let (dir, config) = config(
            r#""hosts":{"repo":{"url":"https://repo.test/m2/",
                "authentication":{"kind":"bearer",
                                  "token":{"kind":"text","value":"repo-token"}},
                "mirrors":[{"url":"https://copy.test/m2/","skip":["*/"]}]}}"#,
        );
        let client = Arc::new(crate::net::FixtureClient::new().with_body(COPY, "copy"));
        let mut hosts = Hosts::over(&config, dir.path().join("sandbox"), client.clone());
        let host = hosts.open("repo").expect("builds");

        let body = host
            .fetch(
                &crate::net::Req::get(ORIGIN),
                ByteLimit::kib(1),
                &Ctx::anonymous_for_test(),
            )
            .await
            .expect("read");

        assert_eq!(body.as_ref(), b"copy");
        assert_eq!(client.hits(ORIGIN), 0);
        assert!(
            client
                .headers_to(COPY)
                .iter()
                .flatten()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization"))
        );
    }

    /// Long enough for a request that is free to go to finish.
    const SETTLE: std::time::Duration = std::time::Duration::from_millis(50);

    /// Whether a read of `url` through `host` finishes within [`SETTLE`].
    async fn read_finishes(host: &HostedExt, url: &str) -> bool {
        let ctx = Ctx::anonymous_for_test();
        let get = crate::net::Req::get(url);
        let read = host.fetch(&get, ByteLimit::kib(1), &ctx);

        tokio::time::timeout(SETTLE, read).await.is_ok()
    }

    /// Two repositories on one server draw on that server's one counter.
    #[tokio::test]
    async fn gates_shared_by_capabilities_on_one_host() {
        const B: &str = "https://repo.test/b/x";

        let (dir, config) = config(
            r#""hosts":{"repo":{"url":"https://repo.test/","maximum-concurrent-downloads":1}}"#,
        );
        let client = Arc::new(crate::net::FixtureClient::new().with_body(B, "b"));
        let mut hosts = Hosts::over(&config, dir.path().join("sandbox"), client);

        hosts.under("repo", "https://repo.test/a/").expect("builds");
        let b = hosts.under("repo", "https://repo.test/b/").expect("builds");

        let held = hosts.gates["repo"].downloads().enter().await;

        assert!(
            !read_finishes(&b, B).await,
            "a second repository counted apart"
        );

        drop(held);

        assert!(read_finishes(&b, B).await, "the freed slot was not used");
    }

    /// An additional host naming a configured host draws on that host's
    /// counter, not its owner's.
    #[tokio::test]
    async fn gates_named_additional_host_shares_its_counter() {
        const FILE: &str = "https://files.test/pkg.tgz";
        const INDEX: &str = "https://index.test/pkg";

        let (dir, config) = config(
            r#""hosts":{
                "index":{"url":"https://index.test/","additional-hosts":[{"host":"files"}]},
                "files":{"url":"https://files.test/","maximum-concurrent-downloads":1}}"#,
        );
        let client = Arc::new(
            crate::net::FixtureClient::new()
                .with_body(FILE, "file")
                .with_body(INDEX, "index"),
        );
        let mut hosts = Hosts::over(&config, dir.path().join("sandbox"), client);
        let index = hosts.open("index").expect("builds");

        let _held = hosts.gates["files"].downloads().enter().await;

        assert!(
            !read_finishes(&index, FILE).await,
            "a routed read passed its full gate"
        );
        assert!(
            read_finishes(&index, INDEX).await,
            "the owner waited on its route"
        );
    }

    /// A cap of 0 would hold every request forever, so it is refused.
    #[test]
    fn gate_zero_refused() {
        let (dir, mut config) = config(r#""hosts":{"repo":{"url":"https://repo.test/"}}"#);

        config
            .hosts
            .get_mut("repo")
            .expect("configured")
            .maximum_concurrent_uploads = Some(0);

        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));
        let err = hosts.open("repo").expect_err("refused");

        assert!(
            err.to_string().contains("maximum-concurrent-uploads"),
            "{err}"
        );
    }

    /// A mirror is a web copy: a url with no scheme fails at load.
    #[test]
    fn mirror_url_must_be_web() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","hosts":{{"repo":{{"url":"https://repo.test/",
                    "mirrors":[{{"url":"copy.test/m2/"}}]}}}}}}"#,
                crate::cli::config_schema_id()
            ),
        )
        .expect("written");

        let err = ConfigLoader::new()
            .add_path(&path)
            .load()
            .expect_err("refused");

        assert!(err.to_string().contains("mirrors"), "{err}");
    }

    const FILE_HOSTS: &str = r#""hosts":{
          "index":{"url":"h://index.test/",
                   "additional-hosts":[{"host":"files"},{"hostname":"cdn.test"}]},
          "files":{"url":"h://files.test/"}
        },
        "sources":{"pypi":{"kind":"pypi","host":"index"}}"#;

    #[test]
    fn additional_host_must_be_configured() {
        let (dir, config) = config(
            r#""hosts":{"index":{"url":"h://index.test/",
                                "additional-hosts":[{"host":"nowhere"}]}}"#,
        );
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let err = hosts.open("index").expect_err("unknown");

        assert!(err.to_string().contains("nowhere"), "{err}");
    }

    /// Credentials reach an additional host only when its entry says so.
    #[tokio::test]
    async fn additional_host_credentials_explicit() {
        const INHERITED: &str = "https://inherited.test/x";
        const OWN: &str = "https://own.test/x";
        const NONE: &str = "https://none.test/x";

        let (dir, config) = config(
            r#""hosts":{"owner":{"url":"https://owner.test/",
                "authentication":{"kind":"bearer",
                                  "token":{"kind":"text","value":"owner-token"}},
                "additional-hosts":[
                  {"hostname":"inherited.test","inherit-parent-authentication":true},
                  {"hostname":"own.test",
                   "authentication":{"kind":"bearer",
                                     "token":{"kind":"text","value":"own-token"}}},
                  {"hostname":"none.test","inherit":true}
                ]}}"#,
        );
        let client = Arc::new(
            crate::net::FixtureClient::new()
                .with_body(INHERITED, "a")
                .with_body(OWN, "b")
                .with_body(NONE, "c"),
        );
        let mut hosts = Hosts::over(&config, dir.path().join("sandbox"), client.clone());
        let host = hosts.open("owner").expect("opens");
        let ctx = Ctx::anonymous_for_test();

        for url in [INHERITED, OWN, NONE] {
            host.fetch(&crate::net::Req::get(url), ByteLimit::kib(1), &ctx)
                .await
                .unwrap_or_else(|err| panic!("{url}: {err}"));
        }

        let authorization = |url: &str| -> Vec<String> {
            client
                .headers_to(url)
                .into_iter()
                .flatten()
                .filter(|(name, _)| name == "authorization")
                .map(|(_, value)| value)
                .collect()
        };

        assert_eq!(authorization(INHERITED), ["Bearer owner-token"]);
        assert_eq!(authorization(OWN), ["Bearer own-token"]);
        assert!(authorization(NONE).is_empty());
    }

    #[test]
    fn anonymous_prefix_bare_https() {
        assert_eq!(
            anonymous_prefix("files.pythonhosted.org").expect("bare"),
            "https://files.pythonhosted.org/"
        );

        for bad in [
            "",
            "https://x.test",
            "x.test/path",
            "x.test:443",
            ".x.test",
            "x test",
        ] {
            assert!(anonymous_prefix(bad).is_err(), "{bad:?}");
        }
    }

    /// pypi.org's shape: the index on one host lists files on another. The
    /// source resolves them, and its downloads -- what `copy` fetches
    /// through -- reach both the named additional host and the bare
    /// hostname.
    #[tokio::test]
    async fn additional_hosts_read_by_source() {
        const INDEX: &str = r#"{"versions": ["1.0"], "files": [
            {"filename": "pkg-1.0.tar.gz", "url": "h://files.test/pkg-1.0.tar.gz"},
            {"filename": "pkg-1.0-py3-none-any.whl", "url": "https://cdn.test/pkg-1.0-py3-none-any.whl"}
        ]}"#;

        let (_dir, config) = config(FILE_HOSTS);
        let client = Arc::new(
            crate::net::FixtureClient::new()
                .with_body("h://index.test/simple/pkg/", INDEX)
                .with_body("h://files.test/pkg-1.0.tar.gz", "sdist")
                .with_body("https://cdn.test/pkg-1.0-py3-none-any.whl", "wheel"),
        );
        let mut session = Session::over(&config, false, client).expect("opens");
        let opened = session.source("pypi").expect("opens");
        let ctx = Ctx::anonymous_for_test();

        let artifact = opened
            .source
            .metadata(
                &ArtifactId::new(EcosystemId::pypi(), None, "pkg"),
                Some(&crate::model::Version::new("1.0", Release::General)),
                &ctx,
            )
            .await
            .expect("resolved");

        for file in &artifact.files {
            assert!(opened.source.serves(&file.url), "{}", file.url);

            opened
                .source
                .download(file, &crate::net::Expectation::new(), &ctx)
                .await
                .unwrap_or_else(|err| panic!("{} was refused: {err}", file.url));
        }
    }

    #[test]
    fn host_configured_opens() {
        let (dir, config) = config(r#""hosts":{"h":{"url":"https://repo.test/maven2/"}}"#);
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let host = hosts.open("h").expect("opens");

        assert!(host.constraints().allows("https://repo.test/maven2/x.jar"));
    }

    /// The constraint is the point of the whole capability: a source cannot
    /// reach a host it was not configured for, because it has no client of
    /// its own to try with.
    #[test]
    fn host_may_not_reach_elsewhere() {
        let (dir, config) = config(r#""hosts":{"h":{"url":"https://repo.test/maven2/"}}"#);
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let host = hosts.open("h").expect("opens");

        assert!(!host.constraints().allows("https://evil.test/x.jar"));

        // And not a sibling path on the same host, which is the subtler
        // half: the prefix is the repository, not the origin.
        assert!(!host.constraints().allows("https://repo.test/other/x.jar"));
    }

    /// The same instance every time, so two sources on one registry share
    /// its connection pool, its credentials and its cache.
    #[test]
    fn host_built_once_shared() {
        let (dir, config) = config(r#""hosts":{"h":{"url":"https://repo.test/"}}"#);
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let first = hosts.open("h").expect("opens");
        let second = hosts.open("h").expect("opens");

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn host_unknown_names_itself() {
        let (dir, config) = config(r#""hosts":{"h":{"url":"https://repo.test/"}}"#);
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let err = hosts.open("nope").expect_err("no such host");

        assert!(err.to_string().contains("nope"), "{err}");
    }

    /// Each host gets its own scratch directory, and it is created eagerly
    /// so a failure to make one is reported when the host opens rather than
    /// on the first fetch.
    #[test]
    fn host_gets_own_cache() {
        let (dir, config) =
            config(r#""hosts":{"a":{"url":"https://a.test/"},"b":{"url":"https://b.test/"}}"#);
        let root = dir.path().join("sandbox");
        let mut hosts = Hosts::new(&config, &root);

        let a = hosts.open("a").expect("opens");
        let b = hosts.open("b").expect("opens");

        assert!(root.join("a").is_dir());
        assert!(root.join("b").is_dir());
        assert_ne!(a.cache().root(), b.cache().root());
    }

    /// A host name is free text from a configuration file, so one carrying
    /// a separator must not place its cache outside the root.
    ///
    /// Asserted as the property rather than as an expected spelling: what
    /// matters is that the result is one ordinary directory under the root,
    /// not which characters survived.
    #[test]
    fn host_name_cannot_escape_cache_root() {
        use std::path::Component;

        for name in [
            "../../etc",
            "a/b",
            "..",
            ".",
            "",
            "/absolute",
            "c:\\windows",
        ] {
            let cleaned = cache_folder(name);
            let joined = Path::new("/root").join(&cleaned);

            let inside: Vec<Component<'_>> = joined
                .components()
                .skip_while(|part| *part != Component::Normal("root".as_ref()))
                .skip(1)
                .collect();

            assert_eq!(
                inside.len(),
                1,
                "{name:?} became {cleaned:?}, which is not one directory"
            );
            assert!(
                matches!(inside[0], Component::Normal(_)),
                "{name:?} became {cleaned:?}"
            );
        }

        // An ordinary name is left alone, so a cache is findable by the
        // name its host is configured under.
        assert_eq!(cache_folder("repo.test"), "repo.test");

        // A name that cleans away to nothing still needs a directory.
        assert_eq!(cache_folder(".."), "host");
    }

    /// `setup` bounds this process's memory, so it applies to every host
    /// rather than being repeated per host.
    #[test]
    fn memory_ceiling_comes_from_setup() {
        let (dir, config) = config(
            r#""setup":{"maximum-in-memory-download":"1 MiB"},
               "hosts":{"h":{"url":"https://repo.test/"}}"#,
        );
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let host = hosts.open("h").expect("opens");

        assert_eq!(
            host.constraints().max_in_memory().get(),
            1024 * 1024,
            "from setup, not the built-in default"
        );
    }

    /// Absent, the built-in ceiling applies -- so a configuration that says
    /// nothing is still bounded.
    #[test]
    fn memory_ceiling_has_a_default() {
        let (dir, config) = config(r#""hosts":{"h":{"url":"https://repo.test/"}}"#);
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let host = hosts.open("h").expect("opens");

        assert_eq!(
            host.constraints().max_in_memory(),
            Constraints::new().max_in_memory()
        );
    }

    /// Hosts that agree about TLS share a client, and one that disagrees
    /// gets its own -- because `reqwest` decides verification when the
    /// client is built, not per request.
    #[test]
    fn client_shared_by_tls_setting() {
        let (dir, config) = config(
            r#""hosts":{
                 "a":{"url":"https://a.test/"},
                 "b":{"url":"https://b.test/"},
                 "c":{"url":"https://c.test/","tls-verify":false}
               }"#,
        );
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        for name in ["a", "b", "c"] {
            hosts.open(name).expect("opens");
        }

        assert_eq!(hosts.clients.len(), 2, "one per TLS setting, not per host");
    }

    // -- Session -----------------------------------------------------------

    fn npm_id() -> ArtifactId {
        ArtifactId::new(crate::model::EcosystemId::npm(), None, "tuna")
    }

    /// A source comes back ready to use, and its cache lands under the
    /// configured cache directory rather than wherever the tool was run
    /// from.
    #[test]
    fn source_opens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}","setup":{{"cache-dir":"scratch"}},
                    "hosts":{{"h":{{"url":"https://registry.test/"}}}},
                    "sources":{{"s":{{"kind":"npm","host":"h"}}}}}}"#,
                crate::cli::config_schema_id()
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let mut session = Session::open(&config, false).expect("opens");

        let opened = session.source("s").expect("opens");

        assert_eq!(opened.source.ecosystems(), vec![EcosystemId::npm()]);
        assert!(dir.path().join("scratch").join("h").is_dir());
    }

    // -- Security policies -------------------------------------------------

    /// Write a security policy clearing `CVE-1` for one artifact, and a
    /// configuration pointing at it from `where`.
    fn with_security_policy(place: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = dir.path().join("security.json");

        std::fs::write(
            &policy,
            format!(
                r#"{{"$schema":"{}","malware":"report"}}"#,
                crate::policy::SECURITY_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",{place}}}"#,
                crate::cli::config_schema_id()
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        (dir, config)
    }

    /// `vulnerabilities: forbid` beside a `problem-policy` entry lowering
    /// `vulnerability-known` is said once, as the policy loads.
    #[test]
    fn stance_conflicting_warned() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("security.json"),
            format!(
                r#"{{"$schema":"{}","vulnerabilities":"forbid"}}"#,
                crate::policy::SECURITY_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "setup":{{"security-policy":"security.json"}},
                    "problem-policy":{{"vulnerability-known":"allowed"}},
                    "hosts":{{"h":{{"url":"https://registry.test/"}}}},
                    "sources":{{"a":{{"kind":"npm","host":"h"}},
                                "b":{{"kind":"npm","host":"h"}}}}}}"#,
                crate::cli::config_schema_id()
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let (log, recorder) = Log::recording();
        let mut session = Session::open(&config, false)
            .expect("opens")
            .logging_with(log);

        session.source("a").expect("opens");
        session.source("b").expect("opens");

        let warned: Vec<String> = recorder
            .lines()
            .into_iter()
            .map(|(_, text)| text)
            .filter(|text| text.contains("vulnerabilities: forbid"))
            .collect();

        assert_eq!(warned.len(), 1, "once per file: {warned:?}");
    }

    /// Loaded once per file however many sources read through it.
    #[test]
    fn policy_security_read_once_shared() {
        let (_dir, config) = with_security_policy(
            r#""setup":{"security-policy":"security.json"},
               "hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"one":{"kind":"npm","host":"h"},
                          "two":{"kind":"npm","host":"h"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");

        let one = session.source("one").expect("opens");
        let two = session.source("two").expect("opens");

        // One file read, one policy, however many sources named it.
        assert!(std::ptr::eq(
            one.security().expect("loaded"),
            two.security().expect("loaded")
        ));
    }

    /// A host's own policy wins over `setup`'s, exactly as a license policy
    /// does -- the two answer the same shape of question about the same
    /// repository, so a user who scoped one will expect the other to follow.
    #[test]
    fn policy_security_host_wins_over_setup() {
        let (dir, config) = with_security_policy(
            r#""setup":{"security-policy":"security.json"},
               "hosts":{"h":{"url":"https://registry.test/",
                             "security-policy":"host.json"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        // The host's policy says nothing, which is what makes it
        // distinguishable from `setup`'s `malware: report`.
        std::fs::write(
            dir.path().join("host.json"),
            format!(
                r#"{{"$schema":"{}"}}"#,
                crate::policy::SECURITY_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let mut session = Session::open(&config, false).expect("opens");
        let opened = session.source("s").expect("opens");

        let finding = opened
            .security()
            .expect("loaded")
            .screen("MAL-1", true, None);

        assert_eq!(finding.problem, Code::MalwareKnown);
    }

    /// A run holds no policy when nothing names one.
    #[test]
    fn policy_none_configured_loads_nothing() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");

        assert!(session.source("s").expect("opens").security().is_none());
    }

    /// An unusable security policy is a fault of the **run**, not a surprise
    /// on first screening.
    #[test]
    fn policy_security_unusable_refuses_source() {
        let (dir, config) = with_security_policy(
            r#""setup":{"security-policy":"broken.json"},
               "hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        // Inline statements, which VEX documents on `--lock` replaced, so
        // the schema no longer knows them.
        std::fs::write(
            dir.path().join("broken.json"),
            format!(
                r#"{{"$schema":"{}","statements":[
                     {{"purl":"pkg:npm/a@1","vulnerability":"CVE-1",
                       "status":"fixed"}}]}}"#,
                crate::policy::SECURITY_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let mut session = Session::open(&config, false).expect("opens");

        assert!(session.source("s").is_err());
    }

    /// Saying nothing takes the artifact's ecosystem, which is what every
    /// configuration written before `version-handler` existed says.
    #[test]
    fn handler_falls_back_to_ecosystem() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let opened = session.source("s").expect("opens");

        // npm is semver, so a caret is a range.
        assert_eq!(
            opened
                .versions(&npm_id())
                .expect("npm")
                .version_spec("^1.0"),
            crate::model::VersionSpec::Range("^1.0".into())
        );
    }

    /// And a declared handler replaces it, which is the point of the key.
    #[test]
    fn handler_declared_replaces_ecosystems() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://api.github.test/"}},
               "sources":{"s":{"kind":"github","host":"h","version-handler":"semver",
                               "options":{"repositories":["owner/*"]}}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let opened = session.source("s").expect("opens");

        let id = ArtifactId::new(crate::model::EcosystemId::raw(), None, "owner/repo");

        // Tags would have called this an exact name; semver calls it a
        // range, which is what makes the range resolvable at all.
        assert_eq!(
            opened.versions(&id).expect("declared").version_spec("^1.0"),
            crate::model::VersionSpec::Range("^1.0".into())
        );
    }

    /// The fallback is per artifact rather than per source, because a
    /// source that speaks several ecosystems orders each differently. An
    /// artifact a source does not speak is an error, not a guess.
    #[test]
    fn handler_fallback_refuses_unspoken_ecosystem() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let opened = session.source("s").expect("opens");

        let maven = ArtifactId::new(
            crate::model::EcosystemId::maven(),
            Some("org.example"),
            "lib",
        );

        assert!(opened.versions(&maven).is_err());
    }

    /// A declared handler answers whatever it is asked about, because the
    /// user said which convention this repository follows and that is not
    /// an ecosystem question.
    #[test]
    fn handler_declared_answers_any_artifact() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://api.github.test/"}},
               "sources":{"s":{"kind":"github","host":"h","version-handler":"semver",
                               "options":{"repositories":["owner/*"]}}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let opened = session.source("s").expect("opens");

        assert!(opened.versions(&npm_id()).is_ok());
    }

    /// The policy a run was configured with reaches the context every
    /// command works through, or a command that forgot would silently use
    /// the built-in dispositions.
    #[test]
    fn context_decides_under_configured_policy() {
        let (_dir, config) = config(r#""problem-policy":{"signature-missing":"hard"}"#);

        let session = Session::open(&config, false).expect("opens");
        let ctx = session.deciding(&Ctx::for_test(crate::model::Cause::Requested {
            arg: "x".into(),
        }));

        assert_eq!(
            ctx.report(
                crate::core::problem::Code::SignatureMissing,
                crate::core::message::Message::new("x"),
            ),
            crate::core::problem::Action::SkipArtifact,
            "the built-in default is a warning"
        );
    }

    // -- Paths under one host ---------------------------------------------

    /// One server, many repositories: the host stays the server so a
    /// enumerator can build a REST API off it, and each source says where
    /// under it to read.
    #[test]
    fn host_path_narrows_source_to_repository() {
        let (_dir, config) = config(
            r#""hosts":{"nexus":{"url":"https://nexus.test/"}},
               "sources":{
                 "npm":{"kind":"npm","host":"nexus","host-path":"repository/npm-group"},
                 "maven":{"kind":"maven","host":"nexus","host-path":"/repository/maven-public/"}
               }"#,
        );

        let mut hosts = Hosts::new(&config, "unused");

        let npm = hosts
            .under("nexus", "https://nexus.test/repository/npm-group")
            .expect("opens");

        assert!(
            npm.constraints()
                .allows("https://nexus.test/repository/npm-group/lodash")
        );

        // The point of confining to the joined prefix rather than the
        // host: one repository's source cannot read another's.
        assert!(
            !npm.constraints()
                .allows("https://nexus.test/repository/maven-public/x.jar"),
            "the npm source must not reach the maven repository"
        );

        // Nor the server root, which is where the enumerator's REST API is.
        assert!(
            !npm.constraints()
                .allows("https://nexus.test/service/rest/v1/")
        );
    }

    /// Two repositories on one server share the host entry -- its
    /// credentials, its retry rule, its connection pool -- and get separate
    /// capabilities, which is the whole reason one host suffices.
    #[test]
    fn capability_separate_per_repository_on_one_host() {
        let (dir, config) = config(
            r#""hosts":{"nexus":{"url":"https://nexus.test/"}},
               "sources":{
                 "npm":{"kind":"npm","host":"nexus","host-path":"repository/npm-group"},
                 "maven":{"kind":"maven","host":"nexus","host-path":"repository/maven-public"}
               }"#,
        );

        let root = dir.path().join("sandbox");
        let mut hosts = Hosts::new(&config, &root);
        let mut sources = Sources::new(&config);

        sources.open("npm", &mut hosts).expect("opens");
        sources.open("maven", &mut hosts).expect("opens");

        assert_eq!(hosts.built.len(), 2, "one capability per repository");
        assert_eq!(hosts.clients.len(), 1, "sharing one connection pool");

        // Named so a person can tell which repository a cache belongs to.
        assert!(root.join("nexus_repository_npm-group").is_dir());
        assert!(root.join("nexus_repository_maven-public").is_dir());
    }

    /// Two sources reading the *same* repository share one capability, so
    /// they share its cache and its pool rather than duplicating both.
    #[test]
    fn capability_one_per_repository() {
        let (_dir, config) = config(
            r#""hosts":{"nexus":{"url":"https://nexus.test/"}},
               "sources":{
                 "a":{"kind":"npm","host":"nexus","host-path":"repository/npm-group"},
                 "b":{"kind":"npm","host":"nexus","host-path":"/repository/npm-group/"}
               }"#,
        );

        let mut hosts = Hosts::new(&config, "unused");
        let mut sources = Sources::new(&config);

        sources.open("a", &mut hosts).expect("opens");
        sources.open("b", &mut hosts).expect("opens");

        assert_eq!(hosts.built.len(), 1, "the two spellings are one prefix");
    }

    // -- Criteria ----------------------------------------------------------

    /// A source's publish window reaches the criteria a resolution uses,
    /// with `setup` filling in what the source leaves out.
    #[test]
    fn source_publish_window_reaches_criteria() {
        let (_dir, config) = config(
            r#""setup":{"unknown-publish-time":"allow"},
               "hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h","minimum-publish-time":"2 days"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let criteria = session
            .source("s")
            .expect("opens")
            .criteria(PreRelease::Exclude);

        assert_eq!(
            criteria.minimum_age,
            Some(std::time::Duration::from_secs(2 * 86_400))
        );
        assert_eq!(
            criteria.unknown_publish_time,
            crate::config::UnknownPublishTime::Allow,
            "inherited from setup"
        );
    }

    /// A source overrides `setup`, which is the precedence the whole
    /// configuration follows: the most specific setting wins.
    #[test]
    fn source_overrides_setup_default() {
        let (_dir, config) = config(
            r#""setup":{"unknown-publish-time":"allow"},
               "hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h","unknown-publish-time":"refuse"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");

        assert_eq!(
            session
                .source("s")
                .expect("opens")
                .criteria(PreRelease::Exclude)
                .unknown_publish_time,
            crate::config::UnknownPublishTime::Refuse
        );
    }

    /// Whether pre-releases are candidates comes from the command line,
    /// not from the repository, so the caller supplies it and the same
    /// source answers either way.
    #[test]
    fn pre_releases_from_caller() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let opened = session.source("s").expect("opens");

        assert_eq!(
            opened.criteria(PreRelease::Exclude).pre,
            PreRelease::Exclude
        );
        assert_eq!(
            opened.criteria(PreRelease::Include).pre,
            PreRelease::Include
        );
    }

    /// A **proxy's own** declaration supplies the window, not its
    /// upstreams'. The proxy is the source being resolved against, and the
    /// default `resolve` drives the proxy's own `versions` and `metadata`,
    /// so an upstream's setting never comes into play.
    #[test]
    fn proxy_own_window_applies_not_upstreams() {
        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{
                 "a":{"kind":"npm","host":"h","minimum-publish-time":"30 days"},
                 "p":{"kind":"proxy-failover","minimum-publish-time":"1 hour",
                      "proxy-to":[{"ref":"a"}]}
               }"#,
        );

        let mut session = Session::open(&config, false).expect("opens");

        assert_eq!(
            session
                .source("p")
                .expect("opens")
                .criteria(PreRelease::Exclude)
                .minimum_age,
            Some(std::time::Duration::from_secs(3_600)),
            "the proxy's hour, not the upstream's thirty days"
        );
    }

    /// A host may scope a quarantine rule, because an exception can
    /// reasonably depend on where an artifact came from: "this is a
    /// name-confusion attack" is true of a public registry and not of an
    /// internal mirror.
    #[test]
    fn policy_quarantine_host_applies_to_sources() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("public.yaml"),
            format!(
                "$schema: {}\nrules:\n  - purl: \"pkg:npm/tuna\"\n    codes: [malware-known]\n    class: allowed\n    expires: never\n",
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        )
        .expect("written");

        let path = dir.path().join("config.json");

        std::fs::write(
            &path,
            format!(
                r#"{{"$schema":"{}",
                    "hosts":{{
                      "public":{{"url":"https://public.test/","quarantine-policy":"public.yaml"}},
                      "internal":{{"url":"https://internal.test/"}}
                    }},
                    "sources":{{
                      "from-public":{{"kind":"npm","host":"public"}},
                      "from-internal":{{"kind":"npm","host":"internal"}}
                    }}}}"#,
                crate::cli::config_schema_id()
            ),
        )
        .expect("written");

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");
        let mut session = Session::open(&config, false).expect("opens");

        let reported = |opened: &ConfiguredSource| {
            let ctx = opened
                .deciding(&Ctx::for_test(crate::model::Cause::Requested {
                    arg: "tuna".into(),
                }))
                .for_artifact(
                    npm_id(),
                    Some(crate::model::Version::new("1.0.0", Release::General)),
                );

            ctx.report(
                crate::core::problem::Code::MalwareKnown,
                crate::core::message::Message::new("x"),
            )
        };

        let public = session.source("from-public").expect("opens");
        let internal = session.source("from-internal").expect("opens");

        assert_eq!(
            reported(&public),
            crate::core::problem::Action::Warn,
            "the host's rule excused it"
        );
        assert_eq!(
            reported(&internal),
            crate::core::problem::Action::SkipArtifact,
            "the same artifact from a host with no such rule is held back"
        );
    }

    /// A proxy declares no host, so only the run's policy applies. The
    /// honest answer rather than a gap: its upstreams' hosts say where
    /// bytes come from, and a quarantine rule is about the artifact.
    #[test]
    fn proxy_takes_only_runs_policy() {
        let (dir, config) = config(
            r#""hosts":{"h":{"url":"https://registry.test/"}},
               "sources":{
                 "a":{"kind":"npm","host":"h"},
                 "p":{"kind":"proxy-failover","proxy-to":[{"ref":"a"}]}
               }"#,
        );

        let mut session = Session::open(&config, false).expect("opens");
        let _ = dir;

        assert!(session.source("p").is_ok());
    }

    #[test]
    fn source_unknown_names_itself() {
        let (_dir, config) = config(r#""hosts":{"h":{"url":"https://registry.test/"}}"#);
        let mut session = Session::open(&config, false).expect("opens");

        let err = match session.source("nope") {
            Err(err) => err,
            Ok(_) => panic!("should not have opened"),
        };

        assert!(err.to_string().contains("nope"), "{err}");
    }

    // -- Advisors ----------------------------------------------------------

    /// The host's url replaces the published location, and the configured
    /// ecosystems narrow what is fetched.
    #[tokio::test]
    async fn advisor_fetches_through_host() {
        let (_dir, config) = config(
            r#""hosts":{"mirror":{"url":"https://osv-mirror.test/"}},
               "advisors":{"osv":{"kind":"osv-offline","host":"mirror",
                                  "ecosystems":["npm"]}}"#,
        );
        let client = Arc::new(crate::net::FixtureClient::new().with(
            "https://osv-mirror.test/npm/all.zip",
            crate::net::Canned::status(StatusCode::NOT_FOUND),
        ));
        let mut session = Session::over(&config, false, client.clone()).expect("opens");
        let ctx = Ctx::anonymous_for_test();
        let mut index = crate::advisory::Index::new(crate::advisory::Ecosystems::builtin());

        session
            .advisor("osv")
            .expect("built")
            .load(&mut index, crate::advisory::Freshness::Cached, &ctx)
            .await
            .expect("an unpublished ecosystem is skipped");

        assert_eq!(
            client.requested(),
            vec!["https://osv-mirror.test/npm/all.zip".to_owned()]
        );
    }

    #[test]
    fn advisor_host_must_be_configured() {
        let (_dir, config) = config(r#""advisors":{"osv":{"kind":"osv-offline","host":"ghost"}}"#);
        let mut session = Session::open(&config, false).expect("opens");

        let err = match session.advisor("osv") {
            Err(err) => err,
            Ok(_) => panic!("should not have opened"),
        };

        assert!(err.to_string().contains("ghost"), "{err}");
    }

    // -- Binding sources ---------------------------------------------------

    /// The reason `Capabilities` exists. A proxy hands one call to each
    /// upstream, so without per-upstream binding either the second
    /// upstream's fetch is refused, or -- if the constraints were widened to
    /// cover both -- the first upstream's credentials would ride along to
    /// the second's host.
    #[test]
    fn capability_own_per_proxy_upstream() {
        use crate::repo::Sources;

        let (dir, config) = config(
            r#""hosts":{
                 "mirror":{"url":"https://mirror.test/","authentication":{
                   "kind":"bearer","token":{"kind":"text","value":"internal-secret"}}},
                 "public":{"url":"https://public.test/"}
               },
               "sources":{
                 "internal":{"kind":"npm","host":"mirror"},
                 "upstream":{"kind":"npm","host":"public"},
                 "both":{"kind":"proxy-failover","proxy-to":[
                   {"ref":"internal"},{"ref":"upstream"}]}
               }"#,
        );

        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));
        let mut sources = Sources::new(&config);

        // Both upstreams build, which they could not if one capability had
        // to cover both hosts.
        assert!(sources.open("both", &mut hosts).is_ok());

        // And each host was opened separately, so each carries only its own
        // credentials.
        assert_eq!(hosts.built.len(), 2);
        assert!(
            hosts
                .open("mirror")
                .expect("opens")
                .constraints()
                .allows("https://mirror.test/x")
        );
        assert!(
            !hosts
                .open("public")
                .expect("opens")
                .constraints()
                .allows("https://mirror.test/x"),
            "the public host must not be permitted to reach the mirror"
        );
    }

    /// A caller that only wants to know a configuration *builds* takes no
    /// capabilities, so checking a file starts no HTTP clients.
    #[test]
    fn source_built_unbound() {
        use crate::ext::Unbound;
        use crate::repo::Sources;

        let (_dir, config) = config(
            r#""hosts":{"h":{"url":"https://repo.test/"}},
               "sources":{"s":{"kind":"npm","host":"h"}}"#,
        );

        assert!(
            Sources::new(&config)
                .open("s", &mut Unbound::default())
                .is_ok()
        );
    }

    /// A url the constraint cannot parse is the user's mistake, and the
    /// message has to name the host -- a configuration may have twenty.
    #[test]
    fn host_url_unusable_names_host() {
        let (dir, config) = config(r#""hosts":{"broken":{"url":"not a url"}}"#);
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        let err = hosts.open("broken").expect_err("unusable");

        assert!(err.to_string().contains("broken"), "{err}");
    }

    /// A `file://` host reads its directory through the emulation, with
    /// everything above the client unchanged.
    #[tokio::test]
    async fn file_host_reads_directory() {
        let files = tempfile::tempdir().expect("tempdir");
        std::fs::write(files.path().join("hello.txt"), b"hello").expect("written");

        let url = url::Url::from_directory_path(files.path()).expect("a url");
        let (dir, config) = config(&format!(
            r#""hosts":{{"local":{{"url":"{url}","options":{{"symlinks":"skip"}}}}}}"#
        ));
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));
        let host = hosts.open("local").expect("opens");

        let ctx = Ctx::for_test(crate::model::Cause::Requested {
            arg: "local".into(),
        });
        let body = host
            .fetch(
                &crate::net::Req::get(format!("{url}hello.txt")),
                ByteLimit::kib(1),
                &ctx,
            )
            .await
            .expect("read");

        assert_eq!(body.as_ref(), b"hello");
    }

    /// A directory has no certificate, connection, or login, so a file
    /// host setting one is refused rather than silently ignored.
    #[test]
    fn file_host_refuses_network() {
        for setting in [
            r#""tls-verify":false"#,
            r#""retry":{"max-retries":3}"#,
            r#""authentication":{"kind":"bearer","token":{"kind":"env","name":"T"}}"#,
            r#""mirrors":[{"url":"https://copy.test/"}]"#,
        ] {
            let (_dir, config) = config(&format!(
                r#""hosts":{{"local":{{"url":"file:///srv/backup/",{setting}}}}}"#
            ));

            let err = local_settings("local", &config.hosts["local"]).expect_err("refused");

            assert!(
                err.to_string().contains("local directory"),
                "{setting}: {err}"
            );
        }
    }

    #[test]
    fn host_network_takes_no_options() {
        let (_dir, config) =
            config(r#""hosts":{"h":{"url":"https://repo.test/","options":{"symlinks":"skip"}}}"#);

        let err = local_settings("h", &config.hosts["h"]).expect_err("refused");

        assert!(err.to_string().contains("file://"), "{err}");
    }

    #[test]
    fn file_host_checks_options() {
        let (_dir, config) = config(
            r#""hosts":{"local":{"url":"file:///srv/backup/","options":{"symlinks":"maybe"}}}"#,
        );

        let err = local_settings("local", &config.hosts["local"]).expect_err("refused");

        assert!(err.to_string().contains("local"), "{err}");
        assert!(err.to_string().contains("within-root"), "{err}");
    }

    /// Credentials reach the capability, which is the only thing that ever
    /// sees them: a source is built with this and has no way to
    /// read a token back out.
    ///
    /// Opening succeeds even though the variable does not exist, because
    /// `HostedExt` resolves each secret at the moment it attaches one
    /// rather than holding it. That is deliberate and it is why
    /// `validate-config` resolves secrets separately.
    #[test]
    fn capability_gets_credentials_unresolved() {
        let (dir, config) = config(
            r#""hosts":{"h":{"url":"https://repo.test/","authentication":{
                 "kind":"bearer","token":{"kind":"env","name":"NO_SUCH_VARIABLE_HERE"}}}}"#,
        );
        let mut hosts = Hosts::new(&config, dir.path().join("sandbox"));

        assert!(hosts.open("h").is_ok());
    }
}
