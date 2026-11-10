//! The typed configuration, mirroring `schema/config.schema.json`.
//!
//! Every struct denies unknown fields.  The schema already says
//! `additionalProperties: false`, so this is redundant against a valid
//! config -- but it means schema and model cannot silently drift apart, which
//! would otherwise show up as a setting the user wrote and the tool ignored.
//!
//! References: [Sigstore](https://docs.sigstore.dev/), [TUF](https://theupdateframework.github.io/specification/latest/).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::secret::{Authentication, SecretValue};
use super::units::{ByteSize, ConfigDuration, ConfigLifetime};
use crate::core::error::Result;
use crate::core::expiry::Expiry;
use crate::core::problem::{Class, Code, Policy as ProblemPolicy};
use crate::policy::{Dispositions, Hardening, QuarantinePolicy};
use crate::version::VersionHandler;

/// Comment fields the schema permits everywhere, carried so that
/// `deny_unknown_fields` does not reject a documented config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Comments {
    #[serde(rename = "$comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(rename = "$comments", default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<String>,
}

/// The whole configuration, after merging every file.
///
/// # File paths in here are already absolute
///
/// Every `config-relative-path` is anchored by the loader to the directory
/// of the file that declared it, before the documents are merged -- see
/// [`crate::cli::ConfigLoader`].
///
/// A `working-dir-path` stays relative to the working directory. This
/// includes a [`SecretValue::PropertyFile`](crate::config::SecretValue).
///
/// A `Config` built by hand rather than through the loader keeps whatever
/// paths it was given.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    #[serde(flatten)]
    pub comments: Comments,

    #[serde(default)]
    pub setup: Setup,

    #[serde(default)]
    pub sources: BTreeMap<String, Source>,

    #[serde(default)]
    pub targets: BTreeMap<String, Target>,

    #[serde(default)]
    pub enumerators: BTreeMap<String, Enumerator>,

    /// Public keys supplied by the user instead of fetched from a registry.
    ///
    /// Referenced by name from [`Host::signing_keys`]. Declaring one here
    /// without referencing it changes nothing -- trust is granted by a host
    /// naming a key, not by the key existing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signing_keys: BTreeMap<String, SigningKey>,

    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,

    /// In configuration order, which is load order: the first corpus to
    /// carry a record is the one screening reports. See
    /// [`crate::advisory::Index::insert`].
    #[serde(default)]
    pub advisors: indexmap::IndexMap<String, Advisor>,

    #[serde(default)]
    pub extensions: BTreeMap<String, Extension>,

    /// Per-code overrides of how problems are handled.
    ///
    /// Keyed by problem code, valued by one of four classes -- `allowed`,
    /// `soft`, `hard`, `failure`. Absent codes keep their built-in
    /// disposition, so an empty table is exactly the behavior without one.
    ///
    /// **Nothing here is keyed by an artifact**, which is the rule the
    /// whole configuration follows: per-artifact exceptions live in the
    /// policy files. This table says what the rules *are*.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub problem_policy: BTreeMap<Code, Class>,
}

impl Config {
    /// The `problem-policy` table as the runtime consults it.
    ///
    /// Built here rather than in `core` because the direction of the
    /// dependency runs this way: `core` knows nothing about configuration
    /// files, and a `Policy` is plain data over `core`'s own types.
    pub fn resolved_problem_policy(&self) -> ProblemPolicy {
        ProblemPolicy::from_classes(
            self.problem_policy
                .iter()
                .map(|(code, class)| (*code, *class)),
        )
    }

    /// Everything needed to decide what happens about a problem.
    ///
    /// The three sources `policy::Dispositions` documents, assembled from
    /// the two places a user may have written them: the `problem-policy`
    /// table here, and the quarantine policy file this configuration names.
    ///
    /// `harden` is the command line's `--harden`, which may only turn
    /// hardening **on**. A configuration that already asked for strict runs
    /// is not relaxed by omitting a flag.
    ///
    /// Built here rather than in `policy` because a configuration
    /// references policy files and never the reverse, so this is the
    /// direction that adds no edge back.
    ///
    /// **Setup-scoped.** A host may also name a quarantine policy, which is
    /// layered in front of this one by `session::Session` -- it needs to
    /// know which host a source reads from, and this does not. `layered`
    /// takes those extra files, most specific first.
    pub fn dispositions(&self, harden: bool) -> Result<Dispositions> {
        self.dispositions_layered(harden, Vec::new())
    }

    /// The run's dispositions with extra policy files in front.
    ///
    /// `layered` is most specific first and is checked before
    /// `setup.quarantine-policy`, so a host's rule about an artifact beats
    /// the run's about the same one.
    pub fn dispositions_layered(
        &self,
        harden: bool,
        layered: Vec<QuarantinePolicy>,
    ) -> Result<Dispositions> {
        let mut artifacts = layered;

        if let Some(path) = &self.setup.quarantine_policy {
            artifacts.push(QuarantinePolicy::load(path)?);
        }

        Ok(Dispositions::new(
            self.resolved_problem_policy(),
            artifacts,
            match self.setup.harden_quarantine || harden {
                true => Hardening::On,
                false => Hardening::Off,
            },
        ))
    }
}

/// A user-supplied extension.
///
/// Only a WASM module runs, and only as a source; an executable is modeled
/// so a config declaring one still loads and `validate-config` can check
/// its shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Extension {
    Executable {
        #[serde(flatten)]
        comments: Comments,

        command: PathBuf,

        /// `${}` placeholders are substituted per the consuming kind.
        arguments: Vec<String>,
    },

    /// A WebAssembly core module, run in-process by `ext::gear`.
    Wasm {
        #[serde(flatten)]
        comments: Comments,

        /// Anchored to the declaring file's directory by the loader.
        module: PathBuf,
    },
}

/// What becomes of a downloaded payload once it has been published.
///
/// A one-shot migration and a standing mirror want opposite things, and
/// neither answer is wrong: keeping every payload of a large repository
/// means a second copy of it on local disk, and discarding them means a
/// re-run fetches everything again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Payloads {
    /// Keep it, and let the cache's own expiry reap it.
    ///
    /// The default, because it is the safe answer rather than the frugal
    /// one: a later run reuses the download, and the disk is bounded by
    /// how long entries live rather than by the size of the migration.
    #[default]
    Reuse,

    /// Remove it. The transfer completed, so nothing needs those bytes.
    Discard,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Setup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<PathBuf>,

    /// Whether a downloaded payload stays cached once it has reached every
    /// destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_payloads: Option<Payloads>,

    /// How long a cached file stays after its last use, for every binding
    /// that does not set its own. Absent is forever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_retention: Option<ConfigLifetime>,

    /// Freshness rules tried after a binding's own and before the built-in
    /// ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_freshness: Vec<FreshnessRule>,

    /// The most the whole cache directory may hold. Past it, the least
    /// recently used files go first. Absent is no cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<ByteSize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Logging>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_pool_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_policy: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_policy: Option<PathBuf>,

    /// Per-artifact overrides of how quarantine issues are handled.
    ///
    /// The third of the policy files, beside the license and security ones
    /// and for the same reason: nothing keyed by an artifact belongs in the
    /// configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_policy: Option<PathBuf>,

    /// Which PGP signing keys may vouch for which artifacts.
    ///
    /// A policy file for the same reason as the other three: the key
    /// material is configuration, and which artifacts a key may sign is
    /// keyed by artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_policy: Option<PathBuf>,

    /// Make every soft quarantine stop its artifact.
    ///
    /// Off by default. A blanket, run-scoped switch rather than a
    /// reclassification: `problem-policy` says *this particular thing is
    /// serious* and lasts, while this says *runs from this configuration
    /// are strict*. The command line can turn it on for one run without
    /// touching the file.
    ///
    /// Only soft decisions are affected -- hard already stops, and `allowed`
    /// and `failure` are not quarantines at all.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub harden_quarantine: bool,

    /// Default ceiling for a response held in memory.  Individual call sites
    /// may ask for less, never for more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_in_memory_download: Option<ByteSize>,

    /// How many discovered dependencies a walk under `--db=-` holds before
    /// it prunes the rest.  Any other walk has a report database, named or
    /// temporary, queues on disk, and ignores this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_in_memory_queued_dependencies: Option<usize>,

    /// What to do about an artifact whose publish time a repository does
    /// not report, when a publish window is configured.
    ///
    /// The default for every source; a source may override it. Absent
    /// here too, the built-in default is [`UnknownPublishTime::Refuse`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_publish_time: Option<UnknownPublishTime>,

    /// Keyservers to consult for signing keys not pinned in
    /// `signing-keys`.
    ///
    /// The default for every host; a host may override it. **Empty by
    /// default, which means nothing is fetched**: a key looked up to check
    /// a signature is much weaker evidence than one a person decided to
    /// trust, so asking a third party for it is opt-in rather than a
    /// silent fallback.
    ///
    /// Some ecosystems distribute their own keyring -- a Debian archive
    /// keyring, for instance -- and those belong in this list too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keyservers: Vec<String>,

    /// A Sigstore `trusted_root.json` to check PEP 740 attestations
    /// against, instead of fetching Sigstore's current one over TUF.
    ///
    /// For an air-gapped run, or one that must not reach Sigstore's TUF
    /// repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigstore_trusted_root: Option<PathBuf>,

    /// A directory of server-kind templates, each replacing a built-in of
    /// the same name.  Read while loading, to lower `servers` and
    /// `repositories`; nothing reads it afterwards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_kinds_dir: Option<PathBuf>,
}

/// What to do when a repository does not say when an artifact was
/// published.
///
/// Only consulted when a publish window is configured; with no window,
/// publish time is not being asked about at all.
///
/// There is no answer that is right everywhere, which is why this is a
/// setting rather than a decision baked into the tool. Refusing is the
/// stricter reading and the default: the window exists to keep very new
/// artifacts out, and treating "no timestamp" as "old enough" lets through
/// exactly what it was turned on to exclude. But plenty of internal
/// repositories and mirrors report no publish time at all, and for those
/// refusing means refusing everything -- which is not a usable tool, and
/// worse, is the kind of blanket failure that gets a safety setting turned
/// off entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownPublishTime {
    /// Treat the artifact as satisfying the window.
    ///
    /// For a repository that is known not to report publish times, where
    /// the window is meant for the sources that do.
    Allow,

    /// Treat the artifact as failing the window.
    ///
    /// The artifact cannot be *shown* to be old enough, so it is skipped
    /// and reported. The default.
    Refuse,
}

impl UnknownPublishTime {
    pub fn as_str(self) -> &'static str {
        match self {
            UnknownPublishTime::Allow => "allow",
            UnknownPublishTime::Refuse => "refuse",
        }
    }
}

impl Default for UnknownPublishTime {
    /// [`UnknownPublishTime::Refuse`] -- a window that silently stopped
    /// applying would be worse than one that visibly refuses.
    fn default() -> Self {
        Self::Refuse
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

/// How the run logs.
///
/// A placeholder for richer logging configuration: the command line
/// overrides every part of it, and a log stream is chosen there alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Logging {
    #[serde(flatten)]
    pub comments: Comments,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormat>,

    /// The file to append log lines to.  Absent means standard error.
    #[serde(
        rename = "config-relative-path",
        alias = "working-dir-path",
        skip_serializing_if = "Option::is_none"
    )]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Color and live progress bars.
    #[default]
    Ansi,

    /// Plain text, for a log file or a non-terminal.
    Plain,

    /// One JSON object per event, sharing the log stream.
    JsonStream,
}

/// A repository this tool reads from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Source {
    #[serde(flatten)]
    pub comments: Comments,

    /// Where this repository lives.
    ///
    /// **Absent exactly for a proxy**, which has no host of its own: its
    /// I/O happens in the entries under [`Source::proxy_to`], each of
    /// which names its own. The schema forbids the two together rather
    /// than tolerating an ignored field, because a user who set one would
    /// reasonably expect it to mean something.
    ///
    /// A proxy that genuinely needs a host -- one consulting an index to
    /// decide which upstream should answer -- takes it from
    /// [`Source::options`] and never from here, since this field means
    /// *the host this repository is*. See [`crate::repo`]'s proxy
    /// documentation, which is where that exception is set out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Where under the host this repository lives.
    ///
    /// Joined onto [`Host::url`] to give the root this source reads from.
    /// Absent means the host's url is already that root, which is the
    /// ordinary case for a registry that is a whole site.
    ///
    /// Named for what it is a path *under* -- the host -- because a
    /// configuration has several other kinds: a policy file's path on disk,
    /// a cache path, a lock file's. This one is a URL prefix and nothing
    /// else.
    ///
    /// **This is why a repository manager needs one host and not several.**
    /// Nexus and Artifactory serve many repositories from one server, each
    /// under its own prefix, while their *enumerators* build a REST API off
    /// the server root. Putting the prefix here keeps `url` the server --
    /// shareable with the enumerator -- instead of forcing a host entry per
    /// repository, which would duplicate the credentials, the retry rule
    /// and the connection limits that belong to the server.
    ///
    /// The capability is confined to the **joined** prefix rather than to
    /// the host's url, so a source reading one repository still cannot
    /// reach another on the same server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_path: Option<String>,

    /// The sources this proxy stands in front of, in precedence order.
    ///
    /// Present only for a proxy kind, and meaningless on any other: an
    /// ordinary source reads one repository and has nothing to delegate
    /// to. `validate-config` reports the mismatch either way round.
    ///
    /// Bounded by the configuration file rather than by anything a run
    /// finds, so naming it in a public type does not violate the
    /// memory discipline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_to: Vec<ProxyTo>,

    /// Which implementation reads this repository.
    ///
    /// A free string: the built-in registry is consulted first, then the
    /// `extensions` collection, so a user's own source is named exactly the
    /// way a built-in is.  The cost is that the schema can no longer reject
    /// a typo, which is why `validate-config` resolves every kind.
    pub kind: String,

    /// How this repository's versions are read and ordered.
    ///
    /// **Only a kind whose contents decide its versions may set this** --
    /// see [`crate::repo::version_scheme`], which is where that line is
    /// drawn, and `validate-config`, which enforces it. A registry
    /// adapter's scheme is not a preference: npm *is* semver and Maven *is*
    /// `ComparableVersion`, so a configuration disagreeing is refused
    /// rather than ignored. Ignoring it would mean resolving a
    /// plausible-looking wrong artifact.
    ///
    /// Absent means *the ecosystem's own*, which is what every
    /// configuration written before this existed says -- so saying nothing
    /// keeps behaving exactly as it did.
    ///
    /// The cases it exists for are the two that motivated separating
    /// version handling from ecosystems at all. A **raw** repository has no
    /// ecosystem to take a convention from and still has versions to order.
    /// And **GitHub** tags are text a publisher chose, so the default
    /// refuses to order them and a project that does tag semver says so.
    ///
    /// A closed set, unlike `kind`: these are conventions rather than
    /// protocols, so the schema can enumerate them and catch a typo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_handler: Option<String>,

    /// How this repository's names become the artifacts a request names.
    ///
    /// Each rule maps one source name, and a tag pattern holding at most one
    /// `*`, to an artifact name and version pattern. A request names the
    /// artifact side; see [`crate::repo::NameMap`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<NameRule>,

    /// Files and whole artifacts to leave out, on top of the ecosystem's
    /// built-in omissions. See [`crate::repo::Omit`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omit: Vec<OmitRule>,

    /// Refuse artifacts published more recently than this.  A crude but
    /// effective guard against a compromised release being mirrored inside
    /// the window where it would be noticed and yanked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_publish_time: Option<ConfigDuration>,

    /// What to do about an artifact whose publish time this repository does
    /// not report.  Overrides `setup.unknown-publish-time`.
    ///
    /// Per-source because the answer is a property of the repository rather
    /// than of the run: a mirror that reports no timestamps sits in the
    /// same configuration as a registry that reports them all, and one
    /// global answer would be wrong for one of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_publish_time: Option<UnknownPublishTime>,

    /// Which dependencies to follow when `--dependencies` is absent or
    /// `default`, in the flag's syntax: `runtime+dev`, `all+shallow`.
    ///
    /// Absent means `none`. A proxy's setting governs the whole walk,
    /// including what its upstreams serve; theirs is not consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enumerator: Option<String>,

    /// How long this source's cached files stay after their last use.
    /// Overrides `setup.cache-retention`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_retention: Option<ConfigLifetime>,

    /// Freshness rules tried before `setup`'s and the built-in ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_freshness: Vec<FreshnessRule>,

    /// The most this source's repository folder in the cache may hold,
    /// within `setup.cache-size`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<ByteSize>,

    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// One `omit` entry. `files` alone omits matching files from every
/// artifact, `purl` alone omits whole artifacts, and both omit matching
/// files from matching artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OmitRule {
    /// A purl pattern, as a quarantine rule's: a glob, optionally with an
    /// `@` version range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    /// A file name glob, with `*` and `?`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<String>,
}

/// One `names` entry: `from` on the source becomes `to` in the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NameRule {
    pub from: NamePattern,
    pub to: NamePattern,
}

/// A literal name and a version pattern, where absent means `*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NamePattern {
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// One `cache-freshness` entry: cached files whose name matches `files`
/// are fresh for `fresh-for`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FreshnessRule {
    /// A whole file name, with `*` for any run of characters and `?` for
    /// one: `maven-metadata.xml*`.
    pub files: String,

    pub fresh_for: ConfigLifetime,
}

impl Source {
    /// The version handler this source names, if it names one.
    ///
    /// `None` means *use the ecosystem's own*, which is the default and
    /// cannot be resolved here: which ecosystem a source speaks is known
    /// only once it is opened, and a source may speak more than one. The
    /// caller that opens it applies the fallback.
    ///
    /// Errors on a name no handler answers to. The schema enumerates them,
    /// so a file that got this far already matched one -- this is the guard
    /// against the schema and the registry drifting apart.
    pub fn versions(&self) -> Result<Option<Arc<dyn VersionHandler>>> {
        self.version_handler
            .as_deref()
            .map(crate::version::open)
            .transpose()
    }
}

/// One source a proxy stands in front of, as configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyTo {
    #[serde(flatten)]
    pub comments: Comments,

    /// Which responsibility this upstream has, for a proxy that assigns
    /// any.
    ///
    /// Optional and **not unique**: two entries may share one. A proxy that
    /// reads a classifier as a role rather than a tag says so itself, and
    /// the ones that ignore classifiers entirely are the common case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<String>,

    #[serde(flatten)]
    pub upstream: ProxyUpstream,
}

/// Where a `proxy-to` entry's source comes from.
///
/// The two spellings are what keeps proxy configurations acyclic, and the
/// asymmetry between them is the entire mechanism:
///
/// - [`ProxyUpstream::Ref`] names a source in the top-level `sources`
///   collection, and **that source may not itself be a proxy**. A name can
///   close a loop; refusing to follow one into another proxy is what stops
///   it.
/// - [`ProxyUpstream::Source`] describes a source in place, and **may be a
///   proxy**. An inline definition nests structurally, so it cannot refer
///   back to anything containing it and no cycle is expressible.
///
/// No graph walk is needed to enforce this, and none should be added.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyUpstream {
    /// A source declared in the top-level `sources` collection.
    ///
    /// **Shared, not copied.** Two proxies naming the same source get the
    /// same instance and therefore the same caches, which is both the
    /// intuitive reading and the useful one.
    #[serde(rename = "ref")]
    Ref(String),

    /// A source described here and nowhere else.
    ///
    /// `Box`ed because a source may contain these, which would otherwise
    /// make [`Source`] infinitely sized.
    #[serde(rename = "source")]
    Source(Box<Source>),
}

impl ProxyTo {
    /// The name this entry refers to, if it refers to one.
    pub fn referenced(&self) -> Option<&str> {
        match &self.upstream {
            ProxyUpstream::Ref(name) => Some(name),
            ProxyUpstream::Source(_) => None,
        }
    }

    /// The source this entry defines, if it defines one.
    pub fn defined(&self) -> Option<&Source> {
        match &self.upstream {
            ProxyUpstream::Ref(_) => None,
            ProxyUpstream::Source(source) => Some(source),
        }
    }
}

/// A repository this tool writes to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Target {
    #[serde(flatten)]
    pub comments: Comments,

    pub host: String,

    /// Where under the host this repository lives.  See
    /// [`Source::host_path`], which this is the writing half of: a
    /// repository manager hosts many repositories on one server, and
    /// reading from one and writing to another should not need two host
    /// entries describing the same server twice.
    ///
    /// `Session::target` joins it onto the host's url and confines the
    /// target there, exactly as a source is confined, so a target writing
    /// to one repository cannot write to another on the same server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_path: Option<String>,

    /// Which implementation writes to this repository.  See [`Source::kind`].
    pub kind: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enumerator: Option<String>,

    /// Files and whole artifacts to leave out, on top of the ecosystem's
    /// built-in omissions. See [`crate::repo::Omit`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omit: Vec<OmitRule>,

    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// Enumerates everything a repository holds.
///
/// The kind is separate from a source's because enumeration is a different capability
/// from resolution: Maven Central speaks the Maven protocol perfectly well
/// and cannot be enumerated over it at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Enumerator {
    #[serde(flatten)]
    pub comments: Comments,

    /// Where this repository lives.
    ///
    /// **Absent exactly for a proxy**, on the same terms as
    /// [`Source::host`]: a proxy enumerator has no host of its own, and one
    /// that genuinely needs one takes it from [`Enumerator::options`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Where under the host this enumerator's catalog lives.  See
    /// [`Source::host_path`].
    ///
    /// Absent for a repository manager, whose catalog is a REST API at the
    /// server root with the repository as a query parameter. Present for
    /// an index rooted under the server, such as Artifact Keeper's
    /// `pypi/{repo}`, so it shares the server's host rather than needing
    /// its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_path: Option<String>,

    /// The enumerators this proxy stands in front of, in precedence order.
    ///
    /// Present only for a proxy kind. The entries name **enumerators**, not
    /// sources: enumeration is a different capability from resolution, so
    /// the two proxy lists are not interchangeable even when they describe
    /// the same repositories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_to: Vec<ProxyToEnumerator>,

    /// How to enumerate this repository.  See [`Source::kind`].
    pub kind: String,

    /// See [`Source::cache_retention`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_retention: Option<ConfigLifetime>,

    /// See [`Source::cache_freshness`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_freshness: Vec<FreshnessRule>,

    /// See [`Source::cache_size`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<ByteSize>,

    /// Files and whole artifacts to leave out, on top of the ecosystem's
    /// built-in omissions. See [`crate::repo::Omit`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omit: Vec<OmitRule>,

    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// One enumerator a proxy enumerator stands in front of, as configured.
///
/// The enumerator twin of [`ProxyTo`], and deliberately **not** the same type
/// parameterized. The inline key is the user-facing spelling -- `source`
/// there, `enumerator` here -- and a generic could not change it without
/// making both read as one or the other. Two short types that each say
/// what they hold beat one that says neither.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyToEnumerator {
    #[serde(flatten)]
    pub comments: Comments,

    /// See [`ProxyTo::classifier`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<String>,

    #[serde(flatten)]
    pub upstream: ProxyEnumeratorUpstream,
}

/// Where an enumerator `proxy-to` entry's enumerator comes from.
///
/// The same asymmetry [`ProxyUpstream`] documents, for the same reason: a
/// `ref` may not name a proxy and an inline `enumerator` may be one, which is
/// the whole of the cycle prevention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyEnumeratorUpstream {
    /// An enumerator declared in the top-level `enumerators` collection, shared
    /// rather than copied.
    #[serde(rename = "ref")]
    Ref(String),

    /// An enumerator described here and nowhere else, which may be a proxy.
    #[serde(rename = "enumerator")]
    Enumerator(Box<Enumerator>),
}

impl ProxyToEnumerator {
    /// The name this entry refers to, if it refers to one.
    pub fn referenced(&self) -> Option<&str> {
        match &self.upstream {
            ProxyEnumeratorUpstream::Ref(name) => Some(name),
            ProxyEnumeratorUpstream::Enumerator(_) => None,
        }
    }

    /// The enumerator this entry defines, if it defines one.
    pub fn defined(&self) -> Option<&Enumerator> {
        match &self.upstream {
            ProxyEnumeratorUpstream::Ref(_) => None,
            ProxyEnumeratorUpstream::Enumerator(enumerator) => Some(enumerator),
        }
    }
}

/// A source of vulnerability and malware advisories.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Advisor {
    #[serde(flatten)]
    pub comments: Comments,

    /// Which advisory corpus this is.  See [`Source::kind`].
    pub kind: String,

    /// Where the corpus is fetched from, and whose cache keeps it.  Its url
    /// replaces the corpus's published location.
    pub host: String,

    /// An archive on disk to read instead of fetching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// How long a cached corpus stays usable before a refresh is attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<ConfigDuration>,

    /// Which ecosystems to screen.  Empty means all of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ecosystems: Vec<String>,

    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Host {
    #[serde(flatten)]
    pub comments: Comments,

    pub url: String,

    /// Verify this host's TLS certificate.  Defaults to true; see
    /// [`Host::tls_verify`] before turning it off.
    #[serde(default = "enabled")]
    pub tls_verify: bool,

    /// Accept `http://`, without TLS, for this host's url, mirrors, and
    /// keyservers. Off by default, so plain HTTP is a stated choice rather
    /// than an unnoticed one; see `config::transport`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure_transport: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<ConfigDuration>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout: Option<ConfigDuration>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<Retry>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_policy: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_policy: Option<PathBuf>,

    /// See [`Setup::quarantine_policy`]. Host-scoped because an exception
    /// can reasonably depend on where an artifact came from: "this is a
    /// name-confusion attack" applies to a public registry and not to an
    /// internal one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_policy: Option<PathBuf>,

    /// See [`Setup::signing_policy`]. Replaces setup's for this host's
    /// sources, as a host's license and security policies do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_policy: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_concurrent_downloads: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_concurrent_uploads: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,

    /// Other hosts this host's reads may reach, by a link or by a redirect.
    ///
    /// pypi.org lists its files on `files.pythonhosted.org`, and github.com
    /// redirects an archive to `codeload.github.com`. Reads only: nothing is
    /// written to an additional host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_hosts: Vec<AdditionalHost>,

    /// Copies of this host asked first for each read, in order.
    ///
    /// Maven Central is served by a GCS bucket as well as `repo1`; reading
    /// files there spares Central's rate limit. URLs stay this host's, so
    /// caches and proxies see no difference.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirrors: Vec<Mirror>,

    /// Keyservers to consult for this host's signing keys, overriding
    /// `setup.keyservers`.
    ///
    /// Per-host because reachability is: an air-gapped mirror and a public
    /// registry sit in the same configuration, and one of them has no
    /// keyserver to ask.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keyservers: Vec<String>,

    /// Named entries from the `signing-keys` collection that this host's
    /// signatures are checked against.
    ///
    /// Naming any here **replaces** the registry's own key endpoint for
    /// this host rather than adding to it. That is the point: the endpoint
    /// is consulted when nothing is pinned, and a user pins keys precisely
    /// because the endpoint is gone, unreachable, or not to be trusted to
    /// vouch for the artifacts it is also serving. Calling it anyway would
    /// reintroduce the failure they configured their way out of.
    ///
    /// A registry that rotates to a key not listed here reports
    /// `signature-missing` naming the unknown key, so the substitution is
    /// visible rather than silent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,

    /// Settings for the client the url's scheme selects.
    ///
    /// Only a `file://` host takes any, and the client checks them; see
    /// `net::emulate::Settings`. A network host takes none, so a setting
    /// that only means something for a directory cannot sit unused on one.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// Another host a host's reads may reach.
///
/// Exactly one of `host` and `hostname`. A named `host` brings its own url,
/// TLS setting, retry plan, and credentials; a bare `hostname` is reached
/// over `https` with the defaults and no credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AdditionalHost {
    #[serde(flatten)]
    pub comments: Comments,

    /// An entry in `hosts`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// A bare hostname, such as `files.pythonhosted.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Use the owning host's TLS setting and retry plan instead of this
    /// entry's own. Never its credentials; see
    /// [`AdditionalHost::inherit_parent_authentication`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub inherit: bool,

    /// Send the owning host's credentials here too.
    #[serde(default, skip_serializing_if = "is_false")]
    pub inherit_parent_authentication: bool,

    /// Credentials for this host alone. Replaces a named host's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
}

/// A copy of a host, read before it.
///
/// Anonymous, with the owning host's TLS setting and retry plan: a mirror
/// is a public copy, and the owner's credentials must never reach it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Mirror {
    #[serde(flatten)]
    pub comments: Comments,

    /// Replaces the owning host's url in each mirrored request.
    pub url: String,

    /// Paths below the host's url never asked of this mirror, with `*` and
    /// `?` wildcards: `*/` sends directory indexes straight to the owner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip: Vec<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// A public key held in configuration rather than fetched.
///
/// Registries publish the keys they sign with, and that works right up
/// until it does not: a key endpoint is retired, an internal PKI is
/// decommissioned, a mirror serves artifacts but no key service, or an
/// archived repository outlives the infrastructure that signed it. The
/// signatures are still good; there is simply nowhere left to ask.
///
/// A pinned key is also the stronger arrangement even where the endpoint
/// lives, because a key fetched from the same host that serves the
/// artifacts proves rather less than one a user put there deliberately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SigningKey {
    #[serde(flatten)]
    pub comments: Comments,

    /// Which signature scheme this key verifies.
    pub scheme: SigningScheme,

    /// The identifier a signature names: an npm `keyid`, or a PGP key id or
    /// fingerprint.
    ///
    /// Matching is on this, not on position, so the order of the collection
    /// carries no meaning.
    pub key_id: String,

    /// The public key itself.
    ///
    /// A [`SecretValue`], which is what lets the material live outside the
    /// config file -- in an environment variable, or in a secret manager
    /// that holds it encrypted at rest. A public key need not be hidden,
    /// but an organization that keeps its trust anchors under management
    /// should not have to make an exception for this one, and the redacted
    /// `Debug` means a stray `{:?}` cannot dump a keyring into a log.
    pub value: SecretValue,

    /// Where this key came from, so a reviewer can check it independently.
    ///
    /// A **citation**, not a lookup -- and named for that, because the
    /// distinction is the whole point. It is never fetched. It is recorded
    /// so someone auditing the config can go and confirm the value against
    /// the publisher's own announcement, a keyserver, or an archived page.
    ///
    /// Fetching it would defeat the purpose twice over: these keys exist
    /// because the network source is gone or untrusted, and a tool that
    /// quietly re-fetched a key it was handed would turn a pinned trust
    /// anchor back into whatever the URL happens to serve today. The value
    /// in `value` is the key; this only says where to go and look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citation_url: Option<String>,

    /// When this key stops being trusted, or [`Expiry::Never`].
    ///
    /// A signature made after this is reported rather than accepted. The
    /// scheme's own expiry, where it has one, still applies; the earlier
    /// wins. Required, and *never* has to be written out: a trust anchor
    /// with no end date should be a decision somebody made, not what
    /// happens when a field is left out.
    pub expires: Expiry,
}

/// Which signature scheme a pinned key verifies.
///
/// Closed, unlike the extension `kind` strings: a scheme is a cryptographic
/// verifier compiled into this tool, and a name it does not know is a
/// mistake rather than something an extension could supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningScheme {
    /// npm registry ECDSA P-256, as published at `/-/npm/v1/keys`.
    NpmEcdsa,

    /// Detached PGP, as Maven publishes in a sibling `.asc`.
    Pgp,
}

impl SigningScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            SigningScheme::NpmEcdsa => "npm-ecdsa",
            SigningScheme::Pgp => "pgp",
        }
    }
}

/// Certificate verification is on unless a config says otherwise.
fn enabled() -> bool {
    true
}

/// Whether to verify a host's TLS certificate.
///
/// An enum at the API boundary, so a call site reads `TlsVerify::Disabled`
/// rather than a bare `false` whose meaning depends on the parameter order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVerify {
    Enabled,

    /// Accepts any certificate.  Nothing then distinguishes the real host
    /// from anything able to intercept the connection, so every checksum and
    /// signature read over it could come from the interceptor.
    Disabled,
}

impl Host {
    /// Whether this host's certificate is checked.
    pub fn tls_verify(&self) -> TlsVerify {
        match self.tls_verify {
            true => TlsVerify::Enabled,
            false => TlsVerify::Disabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Retry {
    #[serde(flatten)]
    pub base: RetryRule,

    /// Per-status overrides, keyed by an exact code (`504`) or a class
    /// (`5xx`).
    ///
    /// Different failures mean different things, and one back-off curve
    /// cannot serve them all. A 504 often means a gateway is restarting, so
    /// waiting minutes is right and giving up after three seconds is not.
    /// A 429 means the server is telling you the rate, so the sensible
    /// response is to honor `Retry-After` rather than guess. A 500 may be a
    /// transient fault or a permanent one, and only the operator of that
    /// particular system knows which.
    ///
    /// An exact code beats a class, a class beats the default statuses, and
    /// those beat the base policy.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub on_status: BTreeMap<String, RetryRule>,

    /// How to treat a connection that failed before any status arrived --
    /// a refused connection, a DNS failure, a TLS handshake error.
    ///
    /// Retried by default, because these are overwhelmingly transient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_transport_error: Option<RetryRule>,

    /// Whether the built-in retryable statuses apply.
    ///
    /// On by default: 408, 429, 500, 502, 503 and 504 retry, and nothing
    /// else does. A `404` must never retry, and neither must a `401` -- a
    /// blanket "retry every failure" turns a misconfiguration into a slow
    /// misconfiguration.
    ///
    /// Set it to `false` to start from nothing and enumerate exactly which
    /// statuses retry, for a system whose codes do not mean what the
    /// registry of HTTP status codes says they mean. Turning off a single
    /// status is `on-status: {500: {retry: false}}` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_default_statuses: Option<bool>,
}

/// One retry policy.
///
/// Every field is optional: a per-status rule inherits whatever it does not
/// state from the host's base policy, so overriding just the delay for 504
/// does not mean restating the retry count.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RetryRule {
    /// Whether to retry at all.
    ///
    /// Exists so a user can switch one status *off* -- `500: {retry: false}`
    /// against a system where a 500 is always permanent -- which a delay
    /// setting alone cannot express. At the base, `false` turns off every
    /// retry a rule does not switch back on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_delay: Option<ConfigDuration>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_delay: Option<ConfigDuration>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_total_retry_seconds: Option<ConfigDuration>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exponential_back_off: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub incremental_delay: Option<ConfigDuration>,

    /// Whether a `Retry-After` header overrides the computed delay.
    ///
    /// On by default. The server is stating the rate it will accept; a
    /// client that ignores that and applies its own curve is guessing
    /// against information it was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honor_retry_after: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_kebab_case_deserialize() {
        let config: Config = serde_json::from_str(
            r#"{
                "setup": {
                    "log": {"level": "debug"},
                    "thread-pool-size": 8,
                    "maximum-in-memory-download": "64 MiB"
                }
            }"#,
        )
        .expect("parses");

        assert_eq!(
            config.setup.log.and_then(|log| log.level),
            Some(LogLevel::Debug)
        );
        assert_eq!(config.setup.thread_pool_size, Some(8));
        assert_eq!(
            config.setup.maximum_in_memory_download,
            Some(ByteSize::mib(64))
        );
    }

    /// A typo must not be silently ignored; that is the whole reason for
    /// `deny_unknown_fields`.
    #[test]
    fn keys_unknown_rejected() {
        let err = serde_json::from_str::<Config>(r#"{"setup":{"log_level":"debug"}}"#).unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn comments_accepted_anywhere() {
        let config: Config = serde_json::from_str(
            r#"{
                "$comment": "top level",
                "hosts": {
                    "central": {
                        "$comments": ["a", "b"],
                        "url": "https://repo1.maven.org/maven2/"
                    }
                }
            }"#,
        )
        .expect("parses");

        assert_eq!(config.comments.comment.as_deref(), Some("top level"));
        assert_eq!(config.hosts["central"].comments.comments.len(), 2);
    }

    #[test]
    fn enumerator_kinds_distinct_from_repo_kinds() {
        let enumerator: Enumerator =
            serde_json::from_str(r#"{"host":"internal","kind":"maven-html-index"}"#)
                .expect("parses");

        assert_eq!(enumerator.kind, "maven-html-index");
    }

    /// Absent means verified.  A host that forgets to say must never end up
    /// accepting any certificate.
    #[test]
    fn tls_verification_defaults_to_on() {
        let host: Host = serde_json::from_str(r#"{"url":"https://e.test/"}"#).expect("parses");

        assert!(host.tls_verify);
        assert_eq!(host.tls_verify(), TlsVerify::Enabled);
    }

    #[test]
    fn tls_verification_can_be_turned_off() {
        let host: Host =
            serde_json::from_str(r#"{"url":"https://internal.test/","tls-verify":false}"#)
                .expect("parses");

        assert_eq!(host.tls_verify(), TlsVerify::Disabled);
    }

    #[test]
    fn source_options_free_form() {
        let source: Source = serde_json::from_str(
            r#"{"host":"pypi","kind":"pypi","options":{"python-version":"3.12"}}"#,
        )
        .expect("parses");

        assert_eq!(source.kind, "pypi");
        assert_eq!(source.options["python-version"], "3.12");
    }
}
