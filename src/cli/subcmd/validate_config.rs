//! `artifact-copy validate-config`.
//!
//! A full inspection, per `README.md`: it resolves every configured secret
//! and reads linked policy files.  The point is that a
//! misspelled environment variable or an unreadable policy is caught now,
//! rather than an hour into a migration.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::Ctx;
use crate::cli::ConfigLoader;
use crate::commands::spider::SpiderSpec;
use crate::config::{Config, Enumerator as EnumeratorConfig, Source as SourceConfig};
use crate::core::error::Result;
use crate::core::message::Message;
use crate::core::problem::Code;
use crate::message;
use crate::policy::{
    LicensePolicy, QuarantinePolicy, QuarantineRule, SecurityPolicy, SigningPolicy,
};

/// How hard to look at the configured extensions.
///
/// An enum rather than a `bool`, so a call site says `Probe::Extensions`
/// instead of `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Resolve every `kind` by name.  Runs nothing.
    NamesOnly,

    /// Also instantiate each extension and ask it to describe itself.
    Extensions,
}

/// What the check found.
#[derive(Debug, Default)]
pub struct Findings {
    pub checked_files: usize,
    pub resolved_kinds: usize,
    pub resolved_secrets: usize,
    pub policies: Vec<PathBuf>,
    pub complaints: Vec<Message>,
}

impl Findings {
    pub fn is_ok(&self) -> bool {
        self.complaints.is_empty()
    }
}

/// Load the configuration and check everything it points at.
pub fn run(configs: &[PathBuf], probe: Probe, ctx: &Ctx) -> Result<Findings> {
    let mut loader = ConfigLoader::new();

    for path in configs {
        loader = loader.add_path(path);
    }

    // A configuration that will not load is fatal; nothing below it can be
    // checked, so there is no value in continuing to collect complaints.
    let config = loader.load()?;

    let mut findings = Findings {
        checked_files: configs.len(),
        ..Default::default()
    };

    check_references(&config, &mut findings);
    check_additional_hosts(&config, &mut findings);
    check_local_hosts(&config, &mut findings);
    check_kinds(&config, probe, &mut findings);
    check_proxies(&config, &mut findings);
    check_policies(&config, &mut findings);
    check_secrets(&config, &mut findings);
    check_stances(&config, ctx);
    check_lapsed_keys(&config, ctx);
    note_insecure_hosts(&config, ctx);

    for complaint in &findings.complaints {
        ctx.report(Code::ConfigInvalid, complaint.clone());
    }

    Ok(findings)
}

/// A host's additional hosts must each name one configured host or one
/// hostname, and at most one source of credentials.
///
/// A hostname's shape is the schema's to check, which it does before this
/// runs.
fn check_additional_hosts(config: &Config, findings: &mut Findings) {
    for (name, host) in &config.hosts {
        for entry in &host.additional_hosts {
            if entry.host.is_some() == entry.hostname.is_some() {
                findings.complaints.push(message!(
                    "additional-host-ambiguous",
                    "host {host:?} has an additional host that must name exactly one \
                     of 'host' and 'hostname'",
                    host = name,
                ));
            }

            if entry.authentication.is_some() && entry.inherit_parent_authentication {
                findings.complaints.push(message!(
                    "additional-host-authentication-ambiguous",
                    "host {host:?} has an additional host with both 'authentication' \
                     and 'inherit-parent-authentication'; name one",
                    host = name,
                ));
            }

            if let Some(named) = &entry.host
                && !config.hosts.contains_key(named)
            {
                findings.complaints.push(message!(
                    "additional-host-unknown",
                    "host {host:?} names additional host {named:?}, which is not configured",
                    host = name,
                    named = named,
                ));
            }
        }
    }
}

/// A `file://` host takes only what a directory can use, and a network
/// host takes no `options`.
fn check_local_hosts(config: &Config, findings: &mut Findings) {
    for (name, host) in &config.hosts {
        if let Err(err) = crate::session::local_settings(name, host) {
            findings.complaints.push(message!(
                "local-host-unusable",
                "{detail}",
                detail = err.to_string(),
            ));
        }
    }
}

/// Every named cross-reference must point at something that exists.
///
/// The schema cannot check this: it validates one document's shape, and a
/// host name is only meaningful against the merged whole.
fn check_references(config: &Config, findings: &mut Findings) {
    let hosts: BTreeSet<&String> = config.hosts.keys().collect();
    let enumerators: BTreeSet<&String> = config.enumerators.keys().collect();

    for (name, source) in &config.sources {
        // Absent for a proxy, which has no host of its own. The schema
        // decides whether absence was allowed here; this check is only
        // about whether a name that *is* present resolves.
        if let Some(host) = &source.host
            && !hosts.contains(host)
        {
            findings.complaints.push(message!(
                "source-host-unknown",
                "source {source:?} names host {host:?}, which is not configured",
                source = name,
                host = host,
            ));
        }

        if let Some(enumerator) = &source.enumerator
            && !enumerators.contains(enumerator)
        {
            findings.complaints.push(message!(
                "source-enumerator-unknown",
                "source {source:?} names enumerator {enumerator:?}, which is not configured",
                source = name,
                enumerator = enumerator,
            ));
        }
    }

    for (name, target) in &config.targets {
        if !hosts.contains(&target.host) {
            findings.complaints.push(message!(
                "target-host-unknown",
                "target {target:?} names host {host:?}, which is not configured",
                target = name,
                host = &target.host,
            ));
        }
    }

    for (name, advisor) in &config.advisors {
        if !hosts.contains(&advisor.host) {
            findings.complaints.push(message!(
                "advisor-host-unknown",
                "advisor {advisor:?} names host {host:?}, which is not configured",
                advisor = name,
                host = &advisor.host,
            ));
        }
    }

    for (name, enumerator) in &config.enumerators {
        // Absent for a proxy enumerator; see the source loop above.
        if let Some(host) = &enumerator.host
            && !hosts.contains(host)
        {
            findings.complaints.push(message!(
                "enumerator-host-unknown",
                "enumerator {enumerator:?} names host {host:?}, which is not configured",
                enumerator = name,
                host = host,
            ));
        }
    }
}

/// Every `kind` must name a built-in or a declared extension.
///
/// This check exists because `kind` is a free string: the schema can no
/// longer reject `kind: nmp`, so that job moves here.  The message names the
/// alternatives, since a user who mistyped one needs to see the list.
fn check_kinds(config: &Config, probe: Probe, findings: &mut Findings) {
    let declared: BTreeSet<&String> = config.extensions.keys().collect();

    // Proxy kinds are source kinds too, and are the only ones that may
    // carry `proxy-to`. `check_proxies` polices that pairing; here they are
    // simply spellings a `kind` may have.
    for (label, source) in every_source(&config.sources) {
        check_kind(
            &declared,
            "source",
            &label,
            &source.kind,
            crate::repo::all_source_kinds(),
            findings,
        );
        check_options("source", &label, &source.options, findings);
        check_source_options(&label, source, findings);
        check_version_handler(&label, source, findings);
        check_names(&label, source, findings);
        check_omit("source", &label, &source.omit, findings);
        check_dependencies(&label, source, findings);
        check_host_path("source", &label, source.host_path.as_deref(), findings);
    }

    for (name, target) in &config.targets {
        check_kind(
            &declared,
            "target",
            name,
            &target.kind,
            crate::repo::target_kinds(),
            findings,
        );
        check_options("target", name, &target.options, findings);
        check_omit("target", name, &target.omit, findings);
        check_host_path("target", name, target.host_path.as_deref(), findings);
    }

    for (label, enumerator) in every_enumerator(&config.enumerators) {
        check_kind(
            &declared,
            "enumerator",
            &label,
            &enumerator.kind,
            crate::repo::enumerate::all_enumerator_kinds(),
            findings,
        );
        check_options("enumerator", &label, &enumerator.options, findings);
        check_login(config, &label, enumerator, findings);
        check_enumerator(config, &label, enumerator, findings);
        check_omit("enumerator", &label, &enumerator.omit, findings);
        check_host_path(
            "enumerator",
            &label,
            enumerator.host_path.as_deref(),
            findings,
        );
    }

    for (name, advisor) in &config.advisors {
        check_kind(
            &declared,
            "advisor",
            name,
            &advisor.kind,
            crate::advisory::kinds(),
            findings,
        );
        check_options("advisor", name, &advisor.options, findings);
    }

    if probe == Probe::Extensions {
        // Instantiating an extension means running a user-configured
        // program, which is why it is opt-in rather than the default for a
        // command whose job is to read files.
        findings.complaints.push(message!(
            "probe-extensions-unimplemented",
            "--probe-extensions is not implemented yet",
        ));
    }
}

/// Every enumerator a `enumerators` block contains, named or inline.
fn every_enumerator(
    enumerators: &std::collections::BTreeMap<String, EnumeratorConfig>,
) -> Vec<(String, &EnumeratorConfig)> {
    let mut out = Vec::new();

    for (name, enumerator) in enumerators {
        collect_enumerator(format!("{name:?}"), enumerator, 0, &mut out);
    }

    out
}

fn collect_enumerator<'c>(
    label: String,
    enumerator: &'c EnumeratorConfig,
    depth: usize,
    out: &mut Vec<(String, &'c EnumeratorConfig)>,
) {
    if depth > crate::repo::MAX_PROXY_DEPTH {
        return;
    }

    for (at, entry) in enumerator.proxy_to.iter().enumerate() {
        if let Some(inline) = entry.defined() {
            collect_enumerator(format!("{label} entry {at}"), inline, depth + 1, out);
        }
    }

    out.push((label, enumerator));
}

/// Every source a `sources` block contains, named or written inline under
/// a `proxy-to`.
///
/// Inline definitions appear nowhere else in the configuration, so a check
/// that iterates `config.sources` alone would never look at them -- and a
/// typo inside one would surface as a build failure rather than as a
/// finding.
fn every_source(
    sources: &std::collections::BTreeMap<String, SourceConfig>,
) -> Vec<(String, &SourceConfig)> {
    let mut out = Vec::new();

    for (name, source) in sources {
        collect_source(format!("{name:?}"), source, 0, &mut out);
    }

    out
}

fn collect_source<'c>(
    label: String,
    source: &'c SourceConfig,
    depth: usize,
    out: &mut Vec<(String, &'c SourceConfig)>,
) {
    // The builder reports going past this; stopping here keeps the two
    // from disagreeing about how deep is too deep.
    if depth > crate::repo::MAX_PROXY_DEPTH {
        return;
    }

    for (at, entry) in source.proxy_to.iter().enumerate() {
        if let Some(inline) = entry.defined() {
            collect_source(format!("{label} entry {at}"), inline, depth + 1, out);
        }
    }

    out.push((label, source));
}

/// What `proxy-to` means, and where it may appear.
///
/// Five rules the schema cannot express, because it validates one document
/// at a time and does not know which kinds are proxies:
///
/// - `proxy-to` only on a proxy kind, and a proxy kind only with it.
/// - No `host` on a proxy.
/// - A `ref` must name a configured source...
/// - ...and that source must not itself be a proxy, which is the whole of
///   the cycle prevention.
/// - Whatever arity and classifier rules the proxy itself imposes, which
///   only the proxy can answer -- so the sound ones are built and asked.
fn check_proxies(config: &Config, findings: &mut Findings) {
    let before = findings.complaints.len();
    let proxy_kinds = crate::repo::proxy_source_kinds();

    for (label, source) in every_source(&config.sources) {
        let is_proxy = crate::repo::is_proxy_kind(&source.kind);

        if !is_proxy {
            if !source.proxy_to.is_empty() {
                findings.complaints.push(message!(
                    "proxy-to-on-plain-source",
                    "source {source} has 'proxy-to' entries, but its kind {kind:?} is                      not a proxy. The proxy kinds are {kinds}",
                    source = &label,
                    kind = &source.kind,
                    kinds = proxy_kinds.join(", "),
                ));
            }

            continue;
        }

        if let Some(host) = &source.host {
            findings.complaints.push(message!(
                "proxy-names-a-host",
                "source {source} is a {kind} proxy and names host {host:?}. A proxy                  has no host of its own; its upstreams each name theirs. A proxy that                  genuinely needs one takes it from 'options' instead",
                source = &label,
                kind = &source.kind,
                host = host,
            ));
        }

        check_proxy_entries(config, &label, source, findings);
    }

    check_enumerator_proxies(config, findings);

    // Only ask the proxies themselves once the structure holds up.
    // Building an unsound configuration would report the same fault twice
    // in different words, and the words above are the more useful pair.
    if findings.complaints.len() == before {
        check_proxies_build(config, findings);
    }
}

/// The same five rules, on the `enumerators` collection.
///
/// Separate from the source pass rather than generic over both: the two
/// collections are different namespaces with different kind lists, and a
/// `ref` in one must never resolve against the other. Sharing the code
/// would mean parameterizing on exactly the things that must not be
/// confused.
fn check_enumerator_proxies(config: &Config, findings: &mut Findings) {
    let proxy_kinds = crate::repo::enumerate::proxy_enumerator_kinds();

    for (label, enumerator) in every_enumerator(&config.enumerators) {
        if !crate::repo::enumerate::is_proxy_enumerator_kind(&enumerator.kind) {
            if !enumerator.proxy_to.is_empty() {
                findings.complaints.push(message!(
                    "proxy-to-on-plain-enumerator",
                    "enumerator {enumerator} has 'proxy-to' entries, but its kind {kind:?} is                      not a proxy. The proxy enumerator kinds are {kinds}",
                    enumerator = &label,
                    kind = &enumerator.kind,
                    kinds = proxy_kinds.join(", "),
                ));
            }

            continue;
        }

        if let Some(host) = &enumerator.host {
            findings.complaints.push(message!(
                "proxy-enumerator-names-a-host",
                "enumerator {enumerator} is a {kind} proxy and names host {host:?}. A proxy                  has no host of its own; its upstreams each name theirs. A proxy that                  genuinely needs one takes it from 'options' instead",
                enumerator = &label,
                kind = &enumerator.kind,
                host = host,
            ));
        }

        for (at, entry) in enumerator.proxy_to.iter().enumerate() {
            let Some(name) = entry.referenced() else {
                continue;
            };

            // Deliberately the `enumerators` collection and nothing else. A
            // source of the same name is a different repository capability
            // and resolving against it would be silently wrong.
            let Some(referenced) = config.enumerators.get(name) else {
                findings.complaints.push(message!(
                    "proxy-enumerator-ref-unknown",
                    "enumerator {enumerator} entry {at} refers to enumerator {name:?}, which is                      not configured",
                    enumerator = &label,
                    at = at,
                    name = name,
                ));

                continue;
            };

            if crate::repo::enumerate::is_proxy_enumerator_kind(&referenced.kind) {
                findings.complaints.push(message!(
                    "proxy-enumerator-ref-is-a-proxy",
                    "enumerator {enumerator} entry {at} refers to enumerator {name:?}, which is                      itself a {kind} proxy. A 'ref' may only name a non-proxy enumerator,                      which is what keeps proxy configurations acyclic; write the inner                      proxy inline under 'enumerator' instead",
                    enumerator = &label,
                    at = at,
                    name = name,
                    kind = &referenced.kind,
                ));
            }
        }
    }
}

/// Each `proxy-to` entry must point at something, and never at a proxy.
fn check_proxy_entries(
    config: &Config,
    label: &str,
    source: &SourceConfig,
    findings: &mut Findings,
) {
    for (at, entry) in source.proxy_to.iter().enumerate() {
        let Some(name) = entry.referenced() else {
            continue;
        };

        let Some(referenced) = config.sources.get(name) else {
            findings.complaints.push(message!(
                "proxy-ref-unknown",
                "source {source} entry {at} refers to source {name:?}, which is not                  configured",
                source = label,
                at = at,
                name = name,
            ));

            continue;
        };

        if crate::repo::is_proxy_kind(&referenced.kind) {
            findings.complaints.push(message!(
                "proxy-ref-is-a-proxy",
                "source {source} entry {at} refers to source {name:?}, which is itself                  a {kind} proxy. A 'ref' may only name a non-proxy source, which is                  what keeps proxy configurations acyclic; write the inner proxy inline                  under 'source' instead",
                source = label,
                at = at,
                name = name,
                kind = &referenced.kind,
            ));
        }
    }
}

/// Refuse an enumerator whose kind would refuse its host or options, such
/// as `maven-html-index` pointed at Maven Central.
fn check_enumerator(
    config: &Config,
    label: &str,
    enumerator: &EnumeratorConfig,
    findings: &mut Findings,
) {
    // An unknown host is `check_references`'s to report, and a bad path
    // `check_host_path`'s.
    let Some(entry) = enumerator
        .host
        .as_deref()
        .and_then(|host| config.hosts.get(host))
    else {
        return;
    };

    let Ok(base_url) = crate::repo::under(&entry.url, enumerator.host_path.as_deref()) else {
        return;
    };

    let options = crate::ext::Options::new(enumerator.options.clone());

    if let Err(err) =
        crate::repo::enumerate::check_enumerator(&enumerator.kind, &base_url, &options)
    {
        findings.complaints.push(message!(
            "enumerator-refused-its-configuration",
            "enumerator {label}: {reason}",
            label = label,
            reason = &err,
        ));
    }
}

/// Build each configured proxy and report what it says about itself.
///
/// The arity and classifier rules are the proxy's own -- how many upstreams
/// it takes, whether their classifiers must be distinct, whether they have
/// to share an ecosystem -- and nothing outside it can enumerate them. So
/// they are collected by building it, which performs no I/O.
///
/// Extension kinds are skipped: `open_source` knows only the built-ins, so
/// asking would report every extension-backed source as unknown.
fn check_proxies_build(config: &Config, findings: &mut Findings) {
    let mut sources = crate::repo::Sources::new(config);

    // Unbound: this asks whether every source can be *constructed*, and
    // starting an HTTP client and a cache per host would be a side effect
    // of checking a file.
    let mut caps = crate::ext::Unbound::default();

    for (name, source) in &config.sources {
        if !crate::repo::is_proxy_kind(&source.kind) || !buildable(config, source) {
            continue;
        }

        if let Err(err) = sources.open(name, &mut caps) {
            findings.complaints.push(message!(
                "proxy-refused-its-configuration",
                "source {source:?}: {reason}",
                source = name,
                reason = &err,
            ));
        }
    }

    let mut enumerators = crate::repo::enumerate::Enumerators::new(config);

    for (name, enumerator) in &config.enumerators {
        if !crate::repo::enumerate::is_proxy_enumerator_kind(&enumerator.kind)
            || !enumerator_buildable(config, enumerator, &mut caps)
        {
            continue;
        }

        if let Err(err) = enumerators.open(name, &mut caps) {
            findings.complaints.push(message!(
                "proxy-enumerator-refused-its-configuration",
                "enumerator {enumerator:?}: {reason}",
                enumerator = name,
                reason = &err,
            ));
        }
    }
}

/// Whether every enumerator this one reaches is built in.  See [`buildable`].
fn enumerator_buildable(
    config: &Config,
    enumerator: &EnumeratorConfig,
    caps: &mut dyn crate::ext::Capabilities,
) -> bool {
    if crate::repo::enumerate::is_proxy_enumerator_kind(&enumerator.kind) {
        return enumerator
            .proxy_to
            .iter()
            .all(|entry| match &entry.upstream {
                crate::config::ProxyEnumeratorUpstream::Ref(name) => config
                    .enumerators
                    .get(name)
                    .is_some_and(|referenced| enumerator_buildable(config, referenced, caps)),

                crate::config::ProxyEnumeratorUpstream::Enumerator(inline) => {
                    enumerator_buildable(config, inline, caps)
                }
            });
    }

    // Unlike sources, an enumerator kind can refuse to open on its own
    // terms, such as `maven-html-index` on Central, so a proxy over one
    // would be reported as a fault in the proxy. Only the kinds that
    // actually open count as buildable.
    const BASE_URL: &str = "h://validate.invalid";

    let host = enumerator.host.as_deref().unwrap_or_default();
    let Ok(capability) = caps.host(host, BASE_URL) else {
        return false;
    };

    crate::repo::enumerate::open_enumerator(
        &enumerator.kind,
        BASE_URL,
        &crate::ext::Options::default(),
        capability,
    )
    .is_ok()
}

/// Whether every source this one reaches is built in.
///
/// A proxy over an extension-backed source cannot be built here, and
/// reporting that as a fault in the proxy would be wrong.
fn buildable(config: &Config, source: &SourceConfig) -> bool {
    if crate::repo::is_proxy_kind(&source.kind) {
        return source.proxy_to.iter().all(|entry| match &entry.upstream {
            crate::config::ProxyUpstream::Ref(name) => config
                .sources
                .get(name)
                .is_some_and(|referenced| buildable(config, referenced)),

            crate::config::ProxyUpstream::Source(inline) => buildable(config, inline),
        });
    }

    crate::repo::source_kinds().contains(&source.kind.as_str())
}

/// Report overrides that have already lapsed.
///
/// A warning rather than an error: an expired acknowledgement is not a
/// broken configuration, it is one that has quietly stopped doing anything.
/// Saying so is the whole reason dating them is offered -- an exception list
/// nobody prunes is one nobody dares prune, and the dates exist so this
/// check can name the dead entries instead of a person re-reading them all.
fn check_lapsed_overrides(path: &Path, policy: &QuarantinePolicy, findings: &mut Findings) {
    let now = chrono::Utc::now();

    for (at, rule) in policy.rules.iter().enumerate() {
        check_reachable(path, at, rule, findings);

        if rule.in_force(now) {
            continue;
        }

        findings.complaints.push(message!(
            "quarantine-override-lapsed",
            "{file} rule {at} for {purl} expired {when} and no longer applies; delete it, \
             or give it a new date if it is still wanted",
            file = &path.display(),
            at = at,
            purl = &rule.purl,
            when = &rule.expires,
        ));
    }
}

/// Note pinned keys whose expiry has passed.
///
/// Information rather than a complaint: unlike a lapsed override, a lapsed
/// key still verifies signatures made before its date, which is the normal
/// state of a retired PKI's key. Saying so lets a reader confirm the date
/// is the intended one.
fn check_lapsed_keys(config: &Config, ctx: &Ctx) {
    let now = chrono::Utc::now();

    for (name, key) in &config.signing_keys {
        if key.expires.in_force(now) {
            continue;
        }

        ctx.log().info(message!(
            "signing-key-lapsed",
            "signing key {name} expired {when}; only signatures made before then verify",
            name = name,
            when = &key.expires,
        ));
    }
}

/// Name each host that accepts plain HTTP.
///
/// A warning rather than a complaint: the configuration asked for it on
/// purpose, and the loader already refused every url that did not. Saying
/// so keeps the choice visible to whoever reviews the configuration.
fn note_insecure_hosts(config: &Config, ctx: &Ctx) {
    for name in crate::config::insecure_hosts(config) {
        ctx.log().warn(message!(
            "host-insecure-transport",
            "host {host} accepts plain http://, so its traffic is neither private nor \
             tamper-evident",
            host = name,
        ));
    }
}

/// Report a rule that cannot match anything.
///
/// A rule naming a version for an ecosystem this build cannot parse
/// matches nothing -- the range can only be read by that ecosystem, and
/// there is none. Without this the rule is *silently* inert, which is the
/// worst way for an exception to fail: the artifact keeps being held back
/// and the file says it should not be.
///
/// Only checked when the rule names a version. A versionless rule matches
/// on the name alone and works for an ecosystem this build has never heard
/// of, which is deliberate -- a user may run an extension that supplies one.
fn check_reachable(path: &Path, at: usize, rule: &QuarantineRule, findings: &mut Findings) {
    let Some(kind) = purl_ecosystem(&rule.purl) else {
        return;
    };

    if crate::ecosystem::open(kind).is_ok() {
        return;
    }

    findings.complaints.push(message!(
        "quarantine-override-unreachable",
        "{file} rule {at} names version range {range:?} for ecosystem {kind:?}, which this \
         build cannot read, so the rule matches nothing",
        file = &path.display(),
        at = at,
        range = crate::policy::version_of(&rule.purl).unwrap_or_default(),
        kind = kind,
    ));
}

/// The `pkg:<type>` of a purl, when it names a version to go with it.
fn purl_ecosystem(purl: &str) -> Option<&str> {
    crate::policy::version_of(purl)?;

    purl.strip_prefix("pkg:")?.split('/').next()
}

/// A `host-path` must be one that can be joined onto a host's url.
///
/// Checked here as well as where it is applied, so a typo is caught before
/// a run rather than when the source, target, or enumerator is first
/// opened, which for a long migration may be well into it.
fn check_host_path(what: &str, label: &str, path: Option<&str>, findings: &mut Findings) {
    let Some(path) = path else {
        return;
    };

    // Against a placeholder url: the join's rules are about the path, and
    // a host that does not resolve is already reported by
    // `check_references`.
    if let Err(detail) = crate::repo::under("https://host.invalid/", Some(path)) {
        findings.complaints.push(message!(
            "unusable-host-path",
            "{what} {label} has an unusable host-path: {detail}",
            what = what,
            label = label,
            detail = &detail,
        ));
    }
}

/// A source's `dependencies` must parse, or every run defaulting to it fails.
fn check_dependencies(label: &str, source: &crate::config::Source, findings: &mut Findings) {
    let Some(text) = &source.dependencies else {
        return;
    };

    let Err(reason) = SpiderSpec::parse(text) else {
        return;
    };

    findings.complaints.push(message!(
        "bad-source-dependencies",
        "source {label} dependencies: {reason}",
        label = label,
        reason = &reason,
    ));
}

/// An enumerator that needs a login must have a host that has one.
///
/// Reported here because the server refuses the walk outright, whatever the
/// repository allows anonymously; finding out on the first page of `find`
/// is finding out too late.
fn check_login(
    config: &Config,
    label: &str,
    enumerator: &EnumeratorConfig,
    findings: &mut Findings,
) {
    let Some(host) = enumerator.host.as_deref() else {
        return;
    };

    // An unknown host is `check_references`'s to report.
    let Some(entry) = config.hosts.get(host) else {
        return;
    };

    if entry.authentication.is_some() {
        return;
    }

    let options = crate::ext::Options::new(enumerator.options.clone());

    match crate::repo::enumerate::login(&enumerator.kind, &options) {
        Ok(crate::repo::enumerate::Login::Optional) => {}

        Ok(crate::repo::enumerate::Login::Required) => {
            findings.complaints.push(message!(
                "enumerator-needs-login",
                "enumerator {label}: {advice}",
                label = label,
                advice = &crate::repo::enumerate::login_advice(&enumerator.kind, host, &options),
            ));
        }

        Err(err) => findings.complaints.push(message!(
            "option-wrong-type",
            "enumerator {label}: {reason}",
            label = label,
            reason = &err,
        )),
    }
}

/// A `version-handler` must name a handler that exists, on a source kind
/// entitled to one.
///
/// Two checks, and the second is the one that matters. A registry adapter's
/// version scheme is not a preference: npm *is* semver and Maven *is*
/// `ComparableVersion`, so a configuration disagreeing is a configuration
/// that is wrong. Refusing it here is the difference between a mistake
/// somebody sees and one that quietly resolves the wrong artifact.
///
/// The first is belt and braces -- the schema enumerates the names, so a
/// file that reached here already matched one. It catches the schema and
/// the registry drifting apart, which is exactly what this command exists
/// to prevent.
/// Refuse an `omit` list no source, enumerator, or target could apply.
fn check_omit(
    collection: &str,
    label: &str,
    rules: &[crate::config::OmitRule],
    findings: &mut Findings,
) {
    if let Err(err) = crate::repo::Omit::parse(rules) {
        findings.complaints.push(message!(
            "omit-invalid",
            "{collection} {label}: {err}",
            collection = collection,
            label = label,
            err = &err,
        ));
    }
}

fn check_names(label: &str, source: &crate::config::Source, findings: &mut Findings) {
    if source.names.is_empty() {
        return;
    }

    // Refused rather than ignored: a mapping that silently did nothing
    // would copy under the source's own names.
    if !crate::repo::names_kinds().contains(&source.kind.as_str()) {
        findings.complaints.push(message!(
            "names-unsupported",
            "source {label} of kind {source_kind} sets names, but only these read \
             them: {accepts}",
            label = label,
            source_kind = &source.kind,
            accepts = &crate::repo::names_kinds().join(", "),
        ));

        return;
    }

    let options = crate::ext::Options::new(source.options.clone());

    let checked = crate::repo::NameMap::parse(&source.names)
        .and_then(|names| crate::repo::check_source_names(&source.kind, &options, &names));

    if let Err(err) = checked {
        findings.complaints.push(message!(
            "names-invalid",
            "source {label}: {err}",
            label = label,
            err = err,
        ));
    }
}

fn check_version_handler(label: &str, source: &crate::config::Source, findings: &mut Findings) {
    let Some(kind) = &source.version_handler else {
        return;
    };

    let options = crate::ext::Options::new(source.options.clone());

    if crate::repo::version_scheme(&source.kind, &options) == crate::repo::VersionScheme::Fixed {
        findings.complaints.push(message!(
            "version-handler-not-overridable",
            "source {label} of kind {source_kind} sets version-handler, but {source_kind} \
             decides its own version scheme; only these accept one: {accepts}",
            label = label,
            source_kind = &source.kind,
            accepts = &crate::repo::declared_version_kinds().join(", "),
        ));

        return;
    }

    if crate::version::open(kind).is_ok() {
        return;
    }

    findings.complaints.push(message!(
        "unknown-version-handler",
        "source {label} names the version handler {kind}, which is not one of: {known}",
        label = label,
        kind = kind,
        known = &crate::version::kinds().join(", "),
    ));
}

/// One `kind` must name a built-in or a declared extension.
fn check_kind(
    declared: &BTreeSet<&String>,
    collection: &str,
    name: &str,
    kind: &str,
    known: &[&str],
    findings: &mut Findings,
) {
    if known.contains(&kind) || declared.contains(&kind.to_owned()) {
        findings.resolved_kinds += 1;
        return;
    }

    findings.complaints.push(message!(
        "kind-unknown",
        "{collection} {name:?} has kind {kind:?}, which is neither built in \
         ({known}) nor an entry in `extensions`",
        collection = collection,
        name = name,
        kind = kind,
        known = known.join(", "),
    ));
}

/// A built-in kind's own options must let it open, such as the `github`
/// source's required `repositories`.
fn check_source_options(label: &str, source: &crate::config::Source, findings: &mut Findings) {
    let options = crate::ext::Options::new(source.options.clone());

    let Err(err) = crate::repo::check_source_options(&source.kind, &options) else {
        return;
    };

    findings.complaints.push(message!(
        "source-options-refused",
        "source {label} of kind {source_kind}: {reason}",
        label = label,
        source_kind = &source.kind,
        reason = &err,
    ));
}

/// The well-known options must be usable, whoever reads them later.
///
/// A repository-manager entry declares which repository it points at and
/// which ecosystem that repository holds.  Catching a misspelled ecosystem
/// here beats discovering it when the first artifact resolves against the
/// wrong version rules.
fn check_options(
    collection: &str,
    name: &str,
    options: &serde_json::Map<String, serde_json::Value>,
    findings: &mut Findings,
) {
    let options = crate::ext::Options::new(options.clone());

    let ecosystem = match options.ecosystem() {
        Ok(ecosystem) => ecosystem,

        Err(err) => {
            findings.complaints.push(message!(
                "option-wrong-type",
                "{collection} {name:?}: {reason}",
                collection = collection,
                name = name,
                reason = &err,
            ));

            return;
        }
    };

    if let Some(ecosystem) = ecosystem
        && crate::ecosystem::open(ecosystem.as_str()).is_err()
    {
        findings.complaints.push(message!(
            "option-ecosystem-unknown",
            "{collection} {name:?} declares ecosystem {ecosystem:?}, which is \
             neither built in ({known}) nor an entry in `extensions`",
            collection = collection,
            name = name,
            ecosystem = ecosystem.as_str(),
            known = crate::ecosystem::kinds().join(", "),
        ));
    }

    if let Err(err) = options.repository() {
        findings.complaints.push(message!(
            "option-wrong-type",
            "{collection} {name:?}: {reason}",
            collection = collection,
            name = name,
            reason = &err,
        ));
    }

    // A misspelled mapping is caught here rather than at the first request,
    // which for a migration is the difference between a message before
    // anything runs and one after a catalog walk has already started. The
    // mapping decides what an artifact *is*, so a typo that fell back to a
    // default would quietly produce a different set of artifacts.
    match options.string(MAPPING) {
        Err(err) => findings.complaints.push(message!(
            "option-wrong-type",
            "{collection} {name:?}: {reason}",
            collection = collection,
            name = name,
            reason = &err,
        )),

        Ok(Some(mapping)) => {
            if crate::repo::Mapping::parse(mapping).is_err() {
                findings.complaints.push(message!(
                    "option-mapping-unknown",
                    "{collection} {name:?} declares mapping {mapping:?}; the raw \
                     repository path mappings are {known}",
                    collection = collection,
                    name = name,
                    mapping = mapping,
                    known = &crate::repo::Mapping::names().join(", "),
                ));
            }
        }

        Ok(None) => {}
    }
}

/// How a raw repository's paths become coordinates.
///
/// Spelled the same by every raw source, enumerator, and target -- Nexus,
/// Artifactory, Artifact Keeper, and local directories -- and checked here
/// for each of them, since `check_options` runs on every entry.
const MAPPING: &str = "mapping";

/// Read every referenced policy file.
fn check_policies(config: &Config, findings: &mut Findings) {
    let paths = policy_paths(config);

    load_each(
        paths.licenses,
        LicensePolicy::load,
        |err| message!("license-policy-unusable", "{reason}", reason = err),
        |_, _, _| {},
        findings,
    );

    load_each(
        paths.securities,
        SecurityPolicy::load,
        |err| message!("security-policy-unusable", "{reason}", reason = err),
        |_, _, _| {},
        findings,
    );

    load_each(
        paths.quarantines,
        QuarantinePolicy::load,
        |err| message!("quarantine-policy-unusable", "{reason}", reason = err),
        check_lapsed_overrides,
        findings,
    );

    load_each(
        paths.signings,
        SigningPolicy::load,
        |err| message!("signing-policy-unusable", "{reason}", reason = err),
        |_, _, _| {},
        findings,
    );
}

/// Every referenced policy file, by kind: the setup's, then each host's.
#[derive(Default)]
struct PolicyPaths {
    licenses: Vec<PathBuf>,
    securities: Vec<PathBuf>,
    quarantines: Vec<PathBuf>,
    signings: Vec<PathBuf>,
}

impl PolicyPaths {
    /// Add one scope's policy files, those it names.
    fn add(
        &mut self,
        license: &Option<PathBuf>,
        security: &Option<PathBuf>,
        quarantine: &Option<PathBuf>,
        signing: &Option<PathBuf>,
    ) {
        self.licenses.extend(license.clone());
        self.securities.extend(security.clone());
        self.quarantines.extend(quarantine.clone());
        self.signings.extend(signing.clone());
    }
}

/// The policy files the setup and every host refer to.
fn policy_paths(config: &Config) -> PolicyPaths {
    let mut paths = PolicyPaths::default();
    let setup = &config.setup;

    paths.add(
        &setup.license_policy,
        &setup.security_policy,
        &setup.quarantine_policy,
        &setup.signing_policy,
    );

    for host in config.hosts.values() {
        paths.add(
            &host.license_policy,
            &host.security_policy,
            &host.quarantine_policy,
            &host.signing_policy,
        );
    }

    paths
}

/// Load each policy file, recording it when it loads and passes `check`,
/// and complaining with `unusable` when it does not load.
fn load_each<T>(
    paths: Vec<PathBuf>,
    load: impl Fn(&Path) -> Result<T>,
    unusable: impl Fn(&crate::core::error::Error) -> Message,
    check: impl Fn(&Path, &T, &mut Findings),
    findings: &mut Findings,
) {
    for path in paths {
        match load(&path) {
            Ok(policy) => {
                check(&path, &policy, findings);
                findings.policies.push(path);
            }

            Err(err) => findings.complaints.push(unusable(&err)),
        }
    }
}

/// Warn where a security policy's stance overrides `problem-policy`.
///
/// A warning rather than a complaint: the configuration works, and the
/// stance deciding is the documented answer. What would be wrong is the
/// user not knowing. Unloadable files are `check_policies`' to report.
fn check_stances(config: &Config, ctx: &Ctx) {
    let stated = config
        .problem_policy
        .get(&Code::VulnerabilityKnown)
        .copied();

    let paths = config.setup.security_policy.iter().chain(
        config
            .hosts
            .values()
            .filter_map(|host| host.security_policy.as_ref()),
    );

    let mut seen = BTreeSet::new();

    for path in paths {
        if !seen.insert(path) {
            continue;
        }

        let Ok(policy) = SecurityPolicy::load(path) else {
            continue;
        };

        if let Some(warning) = policy.stance_conflict(path, stated) {
            ctx.log().warn(warning);
        }
    }
}

/// Resolve every host credential, per the README.
///
/// AWS ones included, at one AWS call each: a wrong environment variable,
/// property file, or secret name fails here rather than on first use.
fn check_secrets(config: &Config, findings: &mut Findings) {
    for (name, host) in &config.hosts {
        let Some(auth) = &host.authentication else {
            continue;
        };

        for secret in auth.secrets() {
            match secret.resolve() {
                Ok(_) => findings.resolved_secrets += 1,
                Err(err) => findings.complaints.push(message!(
                    "secret-unresolvable",
                    "host {host:?}: {source}: {reason}",
                    host = name,
                    source = secret.describe(),
                    reason = &err,
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_schema_id;
    use crate::model::Cause;
    use std::fs;
    use std::path::Path;

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested {
            arg: "validate-config".into(),
        })
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("written");

        path
    }

    fn doc(body: &str) -> String {
        format!(r#"{{"$schema":"{}",{body}}}"#, config_schema_id())
    }

    /// Loads the example and its policies.  Relative paths resolve against
    /// the config's own directory, so this works from any working
    /// directory.
    #[test]
    fn shipped_example_validates() {
        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/configuration/config.yaml");

        let findings = run(&[example], Probe::NamesOnly, &ctx()).expect("loads");

        assert_eq!(findings.policies.len(), 4);

        // The example deliberately demonstrates an environment-variable
        // credential, which is not set in a test run.  Anything else is a
        // genuine defect in the example.
        let unexpected: Vec<String> = findings
            .complaints
            .iter()
            .map(Message::render)
            .filter(|complaint| !complaint.contains("NEXUS_TOKEN"))
            .collect();

        assert!(
            unexpected.is_empty(),
            "the shipped example must validate: {unexpected:?}"
        );
    }

    /// The credential above resolves once its variable exists, which is what
    /// proves the example itself is correct.
    #[test]
    fn shipped_example_is_clean_with_its_credential_set() {
        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/configuration/config.yaml");

        let config = ConfigLoader::new()
            .add_path(&example)
            .load()
            .expect("loads");

        let mut findings = Findings::default();
        check_references(&config, &mut findings);
        check_policies(&config, &mut findings);

        assert!(findings.is_ok(), "{:?}", findings.complaints);
    }

    /// The schema validates one document's shape; a host name is only
    /// meaningful against the merged whole, so this check has to live here.
    #[test]
    fn ref_host_dangling_caught() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""sources":{"s":{"host":"nowhere","kind":"maven"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(findings.complaints[0].render().contains("nowhere"));
    }

    /// A local directory validates without the directory existing, and a
    /// setting it cannot use is caught.
    #[test]
    fn local_dir_checked_unread() {
        let dir = tempfile::tempdir().expect("tempdir");

        let clean = write(
            dir.path(),
            "clean.json",
            &doc(r#""hosts":{"local":{"url":"file:///no/such/directory/"}},
                   "sources":{"s":{"host":"local","kind":"local-directory","host-path":"tools"}},
                   "targets":{"t":{"host":"local","kind":"local-directory"}},
                   "enumerators":{"e":{"host":"local","kind":"local-directory"}}"#),
        );

        let findings = run(&[clean], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);

        let retried = write(
            dir.path(),
            "retried.json",
            &doc(r#""hosts":{"local":{"url":"file:///srv/","retry":{"max-retries":3}}}"#),
        );

        let findings = run(&[retried], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.complaints[0].render().contains("retry"));
    }

    #[test]
    fn ref_enumerator_dangling_caught() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"host":"h","kind":"maven","enumerator":"ghost"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.complaints[0].render().contains("ghost"));
    }

    /// Every enumerator kind the tool can actually build must validate.
    ///
    /// The list `validate-config` checks against is easy to let drift from
    /// the one `enumerate::open_enumerator` implements, and a drift here refuses a
    /// configuration that would have run perfectly well -- the worst
    /// direction for a validator to be wrong in.
    #[test]
    fn every_built_in_enumerator_kind_validates() {
        for kind in crate::repo::enumerate::enumerator_kinds() {
            let dir = tempfile::tempdir().expect("tempdir");

            let path = write(
                dir.path(),
                "c.json",
                &doc(&format!(
                    // Signed in, since some kinds refuse an anonymous host.
                    r#""hosts":{{"h":{{"url":"https://e.test/","authentication":
                       {{"kind":"bearer","token":{{"kind":"text","value":"t"}}}}}}}},
                       "enumerators":{{"s":{{"host":"h","kind":"{kind}"}}}}"#
                )),
            );

            let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

            assert!(
                findings.is_ok(),
                "{kind} should validate: {:?}",
                findings
                    .complaints
                    .iter()
                    .map(|complaint| complaint.render())
                    .collect::<Vec<_>>()
            );
        }
    }

    /// A kind nothing implements is still refused, so the check above is
    /// not passing by accepting everything.
    #[test]
    fn enumerator_kind_unknown_still_refused() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "enumerators":{"s":{"host":"h","kind":"nonesuch"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(findings.complaints[0].render().contains("nonesuch"));
    }

    /// The most common configuration mistake there is, and the reason the
    /// README asks for secrets to be resolved here.
    #[test]
    fn secret_environment_unset_caught() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/","authentication":
                   {"kind":"bearer","token":
                   {"kind":"env","name":"ARTIFACT_COPY_DEFINITELY_UNSET"}}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(
            findings.complaints[0]
                .render()
                .contains("ARTIFACT_COPY_DEFINITELY_UNSET")
        );
    }

    /// A bearer-token host config reading `TOKEN` from the property file.
    fn property_file_doc(file: &Path) -> String {
        let file = serde_json::to_string(file).expect("path serializes");

        doc(&format!(
            r#""hosts":{{"h":{{"url":"https://e.test/","authentication":
               {{"kind":"bearer","token":
               {{"kind":"property-file","working-dir-path":{file},"key":"TOKEN"}}}}}}}}"#
        ))
    }

    #[test]
    fn secret_property_file_missing_caught() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = property_file_doc(&dir.path().join("absent.env"));
        let path = write(dir.path(), "c.json", &body);

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(findings.complaints[0].render().contains("absent.env"));
    }

    #[test]
    fn secret_property_file_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = write(dir.path(), "t.env", "TOKEN=x\n");
        let path = write(dir.path(), "c.json", &property_file_doc(&env));

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
        assert_eq!(findings.resolved_secrets, 1);
    }

    #[test]
    fn policy_unreadable_caught() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"license-policy":"/nonexistent/policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
    }

    /// The schema no longer enumerates kinds, so this check is the only
    /// thing standing between a typo and a confusing run-time failure.
    #[test]
    fn kind_misspelled_names_alternatives() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"ht://e.test/"}},
                   "sources":{"s":{"host":"h","kind":"nmp"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(findings.complaints[0].render().contains("nmp"));
        assert!(findings.complaints[0].render().contains("npm"));
    }

    /// The shape a repository-manager entry takes: one repository, one
    /// declared ecosystem.  Catching a misspelling here beats discovering it
    /// when the first artifact resolves against the wrong version rules.
    #[test]
    fn declared_ecosystem_must_be_one_that_exists() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"nexus":{"url":"h://nexus.test/"}},
                   "extensions":{"nexus3":{"kind":"executable",
                     "command":"/bin/true","arguments":[]}},
                   "sources":{"s":{"host":"nexus","kind":"nexus3","options":{
                     "repository":"maven-releases","ecosystem":"mavne"}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(findings.complaints[0].render().contains("mavne"));
        assert!(findings.complaints[0].render().contains("maven"));
    }

    /// The same entry, spelled correctly, is fine.
    #[test]
    fn repository_manager_entry_validates() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"nexus":{"url":"h://nexus.test/"}},
                   "extensions":{"nexus3":{"kind":"executable",
                     "command":"/bin/true","arguments":[]}},
                   "sources":{"s":{"host":"nexus","kind":"nexus3","options":{
                     "repository":"npm-private","ecosystem":"npm"}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
    }

    /// A wrong type is a mistake, not a setting to ignore.
    #[test]
    fn option_of_the_wrong_type_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"h://e.test/"}},
                   "sources":{"s":{"host":"h","kind":"npm",
                     "options":{"repository":42}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(
            findings.complaints[0]
                .render()
                .contains("should be a string")
        );
    }

    /// A kind naming a declared extension resolves, which is what makes a
    /// user-supplied source a first-class citizen.
    #[test]
    fn kind_naming_a_declared_extension_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"ht://e.test/"}},
                   "extensions":{"my-resolver":{"kind":"executable",
                     "command":"/bin/true","arguments":[]}},
                   "sources":{"s":{"host":"h","kind":"my-resolver"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
        assert_eq!(findings.resolved_kinds, 1);
    }

    #[test]
    fn complaints_reach_the_problem_sink() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""sources":{"s":{"host":"nowhere","kind":"maven"}}"#),
        );

        let ctx = ctx();
        run(&[path], Probe::NamesOnly, &ctx).expect("loads");

        assert_eq!(ctx.problems().counts()[&Code::ConfigInvalid], 1);
    }

    // -- Advisors ----------------------------------------------------------

    #[test]
    fn advisors_host_must_be_configured() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = r#""advisors":{"osv":{"kind":"osv-offline","host":"ghost"}}"#;
        let path = write(dir.path(), "c.json", &doc(body));

        let raised: Vec<String> = run(&[path], Probe::NamesOnly, &ctx())
            .expect("loads")
            .complaints
            .iter()
            .map(|complaint| complaint.id.clone())
            .collect();

        assert!(
            raised.contains(&"advisor-host-unknown".to_owned()),
            "{raised:?}"
        );
    }

    // -- Proxy sources ----------------------------------------------------

    const HOSTS: &str = r#""hosts":{"h":{"url":"https://e.test/"}}"#;

    /// The complaint ids raised for one `sources` block.
    fn ids(sources: &str) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = format!(r#"{HOSTS},"sources":{sources}"#);
        let path = write(dir.path(), "c.json", &doc(&body));

        run(&[path], Probe::NamesOnly, &ctx())
            .expect("loads")
            .complaints
            .iter()
            .map(|complaint| complaint.id.clone())
            .collect()
    }

    // -- Additional hosts --------------------------------------------------

    /// The complaint ids raised for one `hosts` block.
    fn host_ids(hosts: &str) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "c.json", &doc(&format!(r#""hosts":{hosts}"#)));

        run(&[path], Probe::NamesOnly, &ctx())
            .expect("loads")
            .complaints
            .iter()
            .map(|complaint| complaint.id.clone())
            .collect()
    }

    #[test]
    fn additional_hosts_must_be_configured() {
        let raised =
            host_ids(r#"{"h":{"url":"https://e.test/","additional-hosts":[{"host":"ghost"}]}}"#);

        assert!(
            raised.contains(&"additional-host-unknown".to_owned()),
            "{raised:?}"
        );
    }

    /// A hostname with a scheme or a path, or an entry naming both `host`
    /// and `hostname`, is refused when the file loads, before any check
    /// here runs.
    #[test]
    fn additional_host_shape_is_schema_checked() {
        for entry in [
            r#"{"hostname":"https://cdn.test/"}"#,
            r#"{"host":"h","hostname":"cdn.test"}"#,
            r#"{"hostname":"cdn.test","inherit-parent-authentication":true,
                "authentication":{"kind":"bearer","token":{"kind":"env","name":"T"}}}"#,
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let body = format!(
                r#""hosts":{{"h":{{"url":"https://e.test/","additional-hosts":[{entry}]}}}}"#
            );
            let path = write(dir.path(), "c.json", &doc(&body));

            assert!(run(&[path], Probe::NamesOnly, &ctx()).is_err(), "{entry}");
        }
    }

    #[test]
    fn additional_hosts_configured_raise_nothing() {
        let raised = host_ids(
            r#"{"h":{"url":"https://e.test/","additional-hosts":[
                  {"host":"h"},
                  {"hostname":"files.pythonhosted.org","inherit":true,
                   "inherit-parent-authentication":true}
               ]}}"#,
        );

        assert!(raised.is_empty(), "{raised:?}");
    }

    /// The whole point of the check list: a proxy configuration that is
    /// correct raises nothing.
    #[test]
    fn proxy_sound_raises_nothing() {
        let raised = ids(r#"{
                "primary":{"host":"h","kind":"npm"},
                "combined":{"kind":"proxy-failover","proxy-to":[
                    {"ref":"primary","classifier":"first"},
                    {"source":{"host":"h","kind":"npm"}}
                ]}
            }"#);

        assert!(raised.is_empty(), "{raised:?}");
    }

    /// A proxy kind is a source kind. Before `proxy-to` existed the list
    /// did not hold them, so this would have been reported as a typo.
    #[test]
    fn proxy_kind_not_unknown() {
        let raised = ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[{"ref":"a"}]},
                             "a":{"host":"h","kind":"npm"}}"#);

        assert!(!raised.contains(&"kind-unknown".to_owned()), "{raised:?}");
    }

    #[test]
    fn proxy_to_on_plain_source_reported() {
        let raised = ids(r#"{"a":{"host":"h","kind":"npm"},
                             "odd":{"kind":"npm","proxy-to":[{"ref":"a"}]}}"#);

        assert!(
            raised.contains(&"proxy-to-on-plain-source".to_owned()),
            "{raised:?}"
        );
    }

    /// The schema cannot catch this: it does not know which kinds are
    /// proxies, so a proxy kind with a host and no `proxy-to` parses.
    #[test]
    fn proxy_naming_host_reported() {
        let raised = ids(r#"{"p":{"host":"h","kind":"proxy-failover"}}"#);

        assert!(
            raised.contains(&"proxy-names-a-host".to_owned()),
            "{raised:?}"
        );
    }

    #[test]
    fn ref_proxy_dangling_reported() {
        let raised = ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[{"ref":"ghost"}]}}"#);

        assert!(
            raised.contains(&"proxy-ref-unknown".to_owned()),
            "{raised:?}"
        );
    }

    /// The cycle prevention, reported rather than discovered at build time.
    #[test]
    fn ref_naming_proxy_reported() {
        let raised = ids(r#"{
                "a":{"host":"h","kind":"npm"},
                "inner":{"kind":"proxy-failover","proxy-to":[{"ref":"a"}]},
                "outer":{"kind":"proxy-failover","proxy-to":[{"ref":"inner"}]}
            }"#);

        assert!(
            raised.contains(&"proxy-ref-is-a-proxy".to_owned()),
            "{raised:?}"
        );
    }

    /// An inline definition appears nowhere else in the configuration, so
    /// a check iterating `sources` alone would never look inside one.
    #[test]
    fn typo_in_inline_upstream_found() {
        let raised = ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[
                {"source":{"host":"h","kind":"nmp"}}
            ]}}"#);

        assert!(raised.contains(&"kind-unknown".to_owned()), "{raised:?}");
    }

    /// The rules only the proxy itself can state: how many upstreams it
    /// takes, and whether they have to be alternatives for anything.
    #[test]
    fn proxy_arity_rule_reported() {
        let raised = ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[]}}"#);

        assert!(
            raised.contains(&"proxy-refused-its-configuration".to_owned()),
            "{raised:?}"
        );
    }

    #[test]
    fn disjoint_upstream_ecosystems_are_reported() {
        let raised = ids(r#"{
                "js":{"host":"h","kind":"npm"},
                "jvm":{"host":"h","kind":"maven"},
                "both":{"kind":"proxy-failover","proxy-to":[{"ref":"js"},{"ref":"jvm"}]}
            }"#);

        assert!(
            raised.contains(&"proxy-refused-its-configuration".to_owned()),
            "{raised:?}"
        );
    }

    /// A structural fault is reported once, in the words that name it.
    /// Building an already-broken configuration would say the same thing
    /// again less usefully.
    #[test]
    fn structural_fault_is_not_also_reported_as_a_build_failure() {
        let raised = ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[{"ref":"ghost"}]}}"#);

        assert!(
            !raised.contains(&"proxy-refused-its-configuration".to_owned()),
            "{raised:?}"
        );
    }

    /// A proxy over an extension-backed source cannot be built here, and
    /// reporting that as a fault in the proxy would be wrong.
    #[test]
    fn proxy_over_extension_not_built() {
        let dir = tempfile::tempdir().expect("tempdir");

        let body = format!(
            r#"{HOSTS},
               "extensions":{{"custom":{{"kind":"executable",
                 "command":"/bin/true","arguments":[]}}}},
               "sources":{{
                   "ext":{{"host":"h","kind":"custom"}},
                   "p":{{"kind":"proxy-failover","proxy-to":[{{"ref":"ext"}}]}}
               }}"#
        );

        let path = write(dir.path(), "c.json", &doc(&body));
        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let raised: Vec<&str> = findings
            .complaints
            .iter()
            .map(|complaint| complaint.id.as_str())
            .collect();

        assert!(
            !raised.contains(&"proxy-refused-its-configuration"),
            "{raised:?}"
        );
    }

    // -- Proxy enumerators ---------------------------------------------------

    /// The complaint ids raised for one `enumerators` block.
    fn enumerator_ids(enumerators: &str) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = format!(r#"{HOSTS},"enumerators":{enumerators}"#);
        let path = write(dir.path(), "c.json", &doc(&body));

        run(&[path], Probe::NamesOnly, &ctx())
            .expect("loads")
            .complaints
            .iter()
            .map(|complaint| complaint.id.clone())
            .collect()
    }

    #[test]
    fn proxy_enumerator_sound_raises_nothing() {
        let raised = enumerator_ids(
            r#"{
                "primary":{"host":"h","kind":"pypi-simple"},
                "combined":{"kind":"proxy-failover","proxy-to":[
                    {"ref":"primary","classifier":"first"},
                    {"enumerator":{"host":"h","kind":"pypi-simple"}}
                ]}
            }"#,
        );

        assert!(raised.is_empty(), "{raised:?}");
    }

    #[test]
    fn proxy_enumerator_kind_not_unknown() {
        let raised = enumerator_ids(
            r#"{"a":{"host":"h","kind":"pypi-simple"},
                "p":{"kind":"proxy-failover","proxy-to":[{"ref":"a"}]}}"#,
        );

        assert!(!raised.contains(&"kind-unknown".to_owned()), "{raised:?}");
    }

    #[test]
    fn proxy_to_on_plain_enumerator_reported() {
        let raised = enumerator_ids(
            r#"{"a":{"host":"h","kind":"pypi-simple"},
                "odd":{"kind":"pypi-simple","proxy-to":[{"ref":"a"}]}}"#,
        );

        assert!(
            raised.contains(&"proxy-to-on-plain-enumerator".to_owned()),
            "{raised:?}"
        );
    }

    #[test]
    fn proxy_enumerator_naming_host_reported() {
        let raised = enumerator_ids(r#"{"p":{"host":"h","kind":"proxy-failover"}}"#);

        assert!(
            raised.contains(&"proxy-enumerator-names-a-host".to_owned()),
            "{raised:?}"
        );
    }

    #[test]
    fn ref_proxy_enumerator_dangling_reported() {
        let raised =
            enumerator_ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[{"ref":"ghost"}]}}"#);

        assert!(
            raised.contains(&"proxy-enumerator-ref-unknown".to_owned()),
            "{raised:?}"
        );
    }

    #[test]
    fn ref_enumerator_naming_proxy_reported() {
        let raised = enumerator_ids(
            r#"{
                "a":{"host":"h","kind":"pypi-simple"},
                "inner":{"kind":"proxy-failover","proxy-to":[{"ref":"a"}]},
                "outer":{"kind":"proxy-failover","proxy-to":[{"ref":"inner"}]}
            }"#,
        );

        assert!(
            raised.contains(&"proxy-enumerator-ref-is-a-proxy".to_owned()),
            "{raised:?}"
        );
    }

    /// The two collections are separate namespaces. An enumerator `ref` naming
    /// a source of the same name resolves against nothing, and reporting
    /// otherwise would be silently wrong.
    #[test]
    fn ref_enumerator_not_resolved_against_sources() {
        let dir = tempfile::tempdir().expect("tempdir");

        let body = format!(
            r#"{HOSTS},
               "sources":{{"shared":{{"host":"h","kind":"pypi"}}}},
               "enumerators":{{"p":{{"kind":"proxy-failover","proxy-to":[{{"ref":"shared"}}]}}}}"#
        );

        let path = write(dir.path(), "c.json", &doc(&body));
        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let raised: Vec<&str> = findings
            .complaints
            .iter()
            .map(|complaint| complaint.id.as_str())
            .collect();

        assert!(
            raised.contains(&"proxy-enumerator-ref-unknown"),
            "{raised:?}: a source is not an enumerator"
        );
    }

    #[test]
    fn typo_in_inline_upstream_enumerator_found() {
        let raised = enumerator_ids(
            r#"{"p":{"kind":"proxy-failover","proxy-to":[
                {"enumerator":{"host":"h","kind":"pypi-simpel"}}
            ]}}"#,
        );

        assert!(raised.contains(&"kind-unknown".to_owned()), "{raised:?}");
    }

    #[test]
    fn proxy_enumerator_arity_rule_reported() {
        let raised = enumerator_ids(r#"{"p":{"kind":"proxy-failover","proxy-to":[]}}"#);

        assert!(
            raised.contains(&"proxy-enumerator-refused-its-configuration".to_owned()),
            "{raised:?}"
        );
    }

    /// Three of the advertised enumerator kinds are not implemented yet, and
    /// a proxy over one of those is not a fault in the proxy.
    #[test]
    fn proxy_over_unimplemented_enumerator_not_built() {
        let raised = enumerator_ids(
            r#"{
                "index":{"host":"h","kind":"maven-html-index"},
                "p":{"kind":"proxy-failover","proxy-to":[{"ref":"index"}]}
            }"#,
        );

        assert!(
            !raised.contains(&"proxy-enumerator-refused-its-configuration".to_owned()),
            "{raised:?}"
        );
    }

    // -- Quarantine policy file -------------------------------------------

    fn quarantine_file(dir: &Path, body: &str) -> PathBuf {
        write(
            dir,
            "quarantine-policy.yaml",
            &format!(
                "$schema: {}\n{body}",
                crate::policy::QUARANTINE_POLICY_SCHEMA_ID
            ),
        )
    }

    /// The file is checked like its two siblings, so a broken one is caught
    /// before a run rather than during it.
    #[test]
    fn policy_quarantine_broken_reported() {
        let dir = tempfile::tempdir().expect("tempdir");

        quarantine_file(
            dir.path(),
            "rules:\n  - purl: \"pkg:npm/a\"\n    codes: [nonsense-code]\n    class: allowed\n    expires: never\n",
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"quarantine-policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let raised: Vec<&str> = findings
            .complaints
            .iter()
            .map(|complaint| complaint.id.as_str())
            .collect();

        assert!(raised.contains(&"quarantine-policy-unusable"), "{raised:?}");
    }

    /// A signing policy is checked like the other three: a key id where a
    /// fingerprint belongs is caught before a run.
    #[test]
    fn policy_signing_broken_reported() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("signing-policy.yaml"),
            format!(
                "$schema: {}\nrules:\n  - purl: pkg:maven/org.example/*\n    fingerprints: [\"{}\"]\n",
                crate::policy::SIGNING_POLICY_SCHEMA_ID,
                "z".repeat(40),
            ),
        )
        .expect("written");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"signing-policy":"signing-policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let raised: Vec<&str> = findings
            .complaints
            .iter()
            .map(|complaint| complaint.id.as_str())
            .collect();

        assert!(raised.contains(&"signing-policy-unusable"), "{raised:?}");
    }

    /// A lapsed override is not a broken configuration, it is one that has
    /// quietly stopped doing anything. Naming the dead entries is the whole
    /// reason dating them is offered.
    #[test]
    fn override_lapsed_reported() {
        let dir = tempfile::tempdir().expect("tempdir");

        quarantine_file(
            dir.path(),
            "rules:\n  - purl: \"pkg:npm/a\"\n    codes: [signature-missing]\n    class: allowed\n    expires: \"2020-01-01T00:00:00Z\"\n",
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"quarantine-policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");
        let lapsed: Vec<&Message> = findings
            .complaints
            .iter()
            .filter(|complaint| complaint.id == "quarantine-override-lapsed")
            .collect();

        assert_eq!(lapsed.len(), 1, "{:?}", findings.complaints);
        assert!(lapsed[0].render().contains("pkg:npm/a"), "{}", lapsed[0]);
    }

    /// An in-force override is silent, so the check is a list of things to
    /// prune rather than noise on every run.
    #[test]
    fn override_in_force_silent() {
        let dir = tempfile::tempdir().expect("tempdir");

        quarantine_file(
            dir.path(),
            "rules:\n  - purl: \"pkg:npm/a\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n",
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"quarantine-policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
        assert_eq!(findings.policies.len(), 1, "and it was read");
    }

    fn key_doc(expires: &str) -> String {
        doc(&format!(
            r#""signing-keys":{{"k":{{"scheme":"pgp","key-id":"ABCD","value":{{"kind":"text","value":"m"}},"expires":"{expires}"}}}}"#
        ))
    }

    fn lapsed_lines(expires: &str) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "c.json", &key_doc(expires));
        let (log, recorder) = crate::core::log::Log::recording();

        let findings = run(&[path], Probe::NamesOnly, &ctx().logging_with(log)).expect("loads");
        assert!(findings.is_ok(), "{:?}", findings.complaints);

        recorder
            .lines()
            .into_iter()
            .map(|(_, text)| text)
            .filter(|text| text.contains("expired"))
            .collect()
    }

    /// A lapsed key is noted, not complained about: it still verifies
    /// signatures made before its date.
    #[test]
    fn key_lapsed_noted() {
        let lines = lapsed_lines("2020-01-01T00:00:00Z");

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("k"), "{}", lines[0]);
    }

    #[test]
    fn key_in_force_silent() {
        assert!(lapsed_lines("never").is_empty());
    }

    // -- Host paths --------------------------------------------------------

    /// A target's `host-path` is applied by nothing yet, so this is the
    /// only thing that reads it. Without the check a typo would sit in a
    /// configuration until `copy` lands and then surprise somebody.
    #[test]
    fn host_path_target_checked() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://nexus.test/"}},
                   "targets":{"t":{"kind":"npm","host":"h","host-path":"../elsewhere"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let complaint = findings
            .complaints
            .iter()
            .map(ToString::to_string)
            .find(|text| text.contains("host-path"))
            .expect("refused");

        assert!(complaint.contains("target"), "{complaint}");
    }

    /// An enumerator's `host-path` follows the same rules as a source's.
    #[test]
    fn host_path_enumerator_checked() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://ak.test/"}},
                   "enumerators":{"e":{"kind":"pypi-simple","host":"h","host-path":"pypi/../other"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let complaint = findings
            .complaints
            .iter()
            .map(ToString::to_string)
            .find(|text| text.contains("host-path"))
            .expect("refused");

        assert!(complaint.contains("enumerator"), "{complaint}");
    }

    /// And a usable one passes, on both halves.
    #[test]
    fn host_path_usable_accepted_either_side() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://nexus.test/"}},
                   "sources":{"s":{"kind":"maven","host":"h","host-path":"repository/maven-public"}},
                   "targets":{"t":{"kind":"npm","host":"h","host-path":"repository/npm-hosted"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
    }

    /// The whole reason both halves exist: one server, read from one
    /// repository and written to another, with a single host entry.
    #[test]
    fn one_host_serves_a_source_and_a_target_on_one_manager() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"nexus":{"url":"https://nexus.test/"}},
                   "sources":{"upstream":{"kind":"maven","host":"nexus","host-path":"repository/maven-proxy"}},
                   "targets":{"mirror":{"kind":"npm","host":"nexus","host-path":"repository/npm-hosted"}}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        assert_eq!(config.hosts.len(), 1, "one entry for one server");
        assert_eq!(
            config.sources["upstream"].host_path.as_deref(),
            Some("repository/maven-proxy")
        );
        assert_eq!(
            config.targets["mirror"].host_path.as_deref(),
            Some("repository/npm-hosted")
        );
    }

    // -- Version handlers --------------------------------------------------

    /// The schema enumerates the handler names, so it has to be checked
    /// against the registry or a handler added in Rust becomes one nobody
    /// can configure -- and a name the schema accepts that the registry
    /// rejects is a configuration `validate-config` would pass and a run
    /// would refuse, which is the failure this command exists to prevent.
    #[test]
    fn schema_lists_every_version_handler() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schema/config.schema.json"))
                .expect("parses");

        let listed: Vec<&str> = schema["$defs"]["Source"]["properties"]["version-handler"]["enum"]
            .as_array()
            .expect("an enum of handler names")
            .iter()
            .map(|name| name.as_str().expect("a string"))
            .collect();

        assert_eq!(listed, crate::version::kinds());

        for name in listed {
            assert!(crate::version::open(name).is_ok(), "{name} should open");
        }
    }

    fn dependencies_doc(value: &str) -> String {
        doc(&format!(
            r#""hosts":{{"h":{{"url":"https://e.test/"}}}},
               "sources":{{"s":{{"kind":"npm","host":"h","dependencies":"{value}"}}}}"#
        ))
    }

    #[test]
    fn source_dependencies_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "c.json", &dependencies_doc("runtime+shallow"));

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
    }

    #[test]
    fn source_dependencies_bad_caught() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "c.json", &dependencies_doc("runtime+bogus"));

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(!findings.is_ok());
        assert!(findings.complaints[0].render().contains("bogus"));
    }

    #[test]
    fn version_handler_named_by_source() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"github","host":"h","version-handler":"semver",
                                   "options":{"repositories":["owner/*"]}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
    }

    /// Saying nothing keeps the ecosystem's own, which is what makes the
    /// key a pure addition to configurations written before it existed.
    /// Resolution reaches a usable handler, not just a validated string.
    #[test]
    fn version_handler_named_resolves_working() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"github","host":"h","version-handler":"semver",
                                   "options":{"repositories":["owner/*"]}}}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        let handler = config.sources["s"]
            .versions()
            .expect("resolves")
            .expect("named one");

        // node-semver, not tags: `^1.0` is a range to the first and an
        // exact tag name to the second, so this is the whole point of the
        // key in one assertion -- a repository whose tags happen to be
        // semver gets ranges instead of a refusal.
        assert_eq!(
            handler.version_spec("^1.0"),
            crate::model::VersionSpec::Range("^1.0".into())
        );
    }

    #[test]
    fn version_handler_optional_for_source() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"maven","host":"h"}}"#),
        );

        let config = ConfigLoader::new().add_path(&path).load().expect("loads");

        assert!(config.sources["s"].version_handler.is_none());
        assert!(config.sources["s"].versions().expect("resolves").is_none());
    }

    /// A registry adapter's version scheme is what the repository *is*,
    /// not a preference. A configuration disagreeing would resolve a
    /// plausible-looking wrong artifact rather than failing, so it is
    /// refused where somebody can see it.
    #[test]
    fn aql_enumerator_anonymous_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enumerator = |extra: &str| {
            doc(&format!(
                r#""hosts":{{"h":{{"url":"https://e.test/"}}}},
                   "enumerators":{{"e":{{"kind":"artifactory-oss","host":"h",
                   "options":{{"repository":"r","ecosystem":"maven"{extra}}}}}}}"#
            ))
        };

        let refused = write(dir.path(), "refused.json", &enumerator(""));
        let findings = run(&[refused], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(
            findings
                .complaints
                .iter()
                .any(|text| text.to_string().contains("needs a login")),
            "{:?}",
            findings.complaints
        );

        let attempted = write(
            dir.path(),
            "attempted.json",
            &enumerator(r#","anonymous":"attempt""#),
        );
        let findings = run(&[attempted], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(
            !findings
                .complaints
                .iter()
                .any(|text| text.to_string().contains("needs a login")),
            "{:?}",
            findings.complaints
        );
    }

    fn names_complaints(source: &str) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(&format!(
                r#""hosts":{{"h":{{"url":"https://e.test/"}}}},
                   "sources":{{"s":{source}}}"#
            )),
        );

        run(&[path], Probe::NamesOnly, &ctx())
            .expect("loads")
            .complaints
            .iter()
            .map(ToString::to_string)
            .filter(|text| text.contains("names"))
            .collect()
    }

    #[test]
    fn names_need_reading_kind() {
        let complaints = names_complaints(
            r#"{"kind":"npm","host":"h",
                "names":[{"from":{"name":"a"},"to":{"name":"b"}}]}"#,
        );

        assert_eq!(complaints.len(), 1, "{complaints:?}");
        assert!(complaints[0].contains("github"), "{complaints:?}");
    }

    #[test]
    fn names_malformed_refused() {
        let complaints = names_complaints(
            r#"{"kind":"github","host":"h","options":{"repositories":["o/*"]},
                "names":[{"from":{"name":"o/r","version":"v*"},"to":{"name":"t/r","version":"1"}}]}"#,
        );

        assert_eq!(complaints.len(), 1, "{complaints:?}");
    }

    #[test]
    fn names_must_be_readable() {
        let source = |allowed: &str| {
            format!(
                r#"{{"kind":"github","host":"h","options":{{"repositories":["{allowed}"]}},
                    "names":[{{"from":{{"name":"o/r"}},"to":{{"name":"t/r"}}}}]}}"#
            )
        };

        assert_eq!(names_complaints(&source("other/*")).len(), 1);
        assert!(names_complaints(&source("o/*")).is_empty());
    }

    #[test]
    fn omit_malformed_refused() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "targets":{"t":{"kind":"npm","host":"h","omit":[{"purl":"npm/x"}]}}"#),
        );

        // The schema catches it first; `check_omit` is the guard against
        // the two drifting apart.
        let err = run(&[path], Probe::NamesOnly, &ctx()).expect_err("refused");

        assert!(err.to_string().contains("omit"), "{err}");
    }

    #[test]
    fn maven_html_index_refuses_central() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(
                r#""hosts":{"central":{"url":"https://repo1.maven.org/maven2/"}},
                   "enumerators":{"e":{"kind":"maven-html-index","host":"central"}}"#,
            ),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(
            findings
                .complaints
                .iter()
                .any(|text| text.to_string().contains("Central")),
            "{:?}",
            findings.complaints
        );
    }

    #[test]
    fn version_scheme_fixed_kind_not_overridden() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"maven","host":"h","version-handler":"semver"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let complaint = findings
            .complaints
            .iter()
            .map(ToString::to_string)
            .find(|text| text.contains("version-handler"))
            .expect("refused");

        // The message says which kinds do accept one, because a user who
        // set it on the wrong source needs to know where it belongs.
        assert!(complaint.contains("github"), "{complaint}");
    }

    /// A github source without its repository list is refused.
    #[test]
    fn github_needs_repositories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://api.github.test/"}},
                   "sources":{"s":{"kind":"github","host":"h"}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(
            findings
                .complaints
                .iter()
                .any(|text| text.to_string().contains("repositories")),
            "{:?}",
            findings.complaints
        );
    }

    /// A raw source takes a handler only where its mapping reads a version.
    #[test]
    fn version_handler_raw_needs_name_version_file() {
        let complaints = |mapping: &str| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = write(
                dir.path(),
                "c.json",
                &doc(&format!(
                    r#""hosts":{{"h":{{"url":"https://e.test/"}}}},
                       "sources":{{"s":{{"kind":"nexus","host":"h","version-handler":"semver",
                                       "options":{{"repository":"r","ecosystem":"raw",
                                                  "mapping":"{mapping}"}}}}}}"#
                )),
            );

            run(&[path], Probe::NamesOnly, &ctx())
                .expect("loads")
                .complaints
                .iter()
                .map(ToString::to_string)
                .filter(|text| text.contains("version-handler"))
                .count()
        };

        assert_eq!(complaints("name-version-file"), 0);
        assert_eq!(complaints("directory"), 1);
        assert_eq!(complaints("as-is"), 1);
    }

    /// A misspelled mapping is caught before anything runs, not at the
    /// first request.
    ///
    /// The mapping decides what an artifact *is*, so a typo falling back to
    /// the default would quietly produce a different set of artifacts --
    /// which is not something a later error could undo.
    #[test]
    fn mapping_misspelled_refused_with_alternatives() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"nexus","host":"h",
                                   "options":{"repository":"r","ecosystem":"raw",
                                              "mapping":"regex"}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        let complaint = findings
            .complaints
            .iter()
            .map(ToString::to_string)
            .find(|text| text.contains("regex"))
            .expect("refused");

        // The alternatives are named, because somebody who guessed at the
        // spelling needs to learn the right one here rather than by
        // reading the source.
        assert!(complaint.contains("directory"), "{complaint}");
        assert!(complaint.contains("name-version-file"), "{complaint}");
    }

    /// And a correct one passes, so the check above is not merely refusing
    /// everything.
    #[test]
    fn mapping_declared_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"nexus","host":"h",
                                   "options":{"repository":"r","ecosystem":"raw",
                                              "mapping":"as-is"}}}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(
            !findings
                .complaints
                .iter()
                .any(|text| text.to_string().contains("mapping")),
            "{:?}",
            findings.complaints
        );
    }

    /// Every built-in registry adapter, not just the one above: each speaks
    /// an ecosystem that decides its ordering.
    #[test]
    fn every_registry_adapter_fixes_its_own_scheme() {
        use crate::repo::{VersionScheme, version_scheme};

        let none = crate::ext::Options::default();

        for kind in ["maven", "npm", "pypi"] {
            assert_eq!(version_scheme(kind, &none), VersionScheme::Fixed, "{kind}");
        }

        assert_eq!(version_scheme("github", &none), VersionScheme::Declared);

        // An unknown kind is fixed too, so an extension's source cannot be
        // handed a handler this tool would then not apply.
        assert_eq!(
            version_scheme("something-else", &none),
            VersionScheme::Fixed
        );
    }

    /// A closed set, so a typo is caught by the schema rather than becoming
    /// a setting that silently does nothing.
    #[test]
    fn version_handler_misspelled_refused() {
        let dir = tempfile::tempdir().expect("tempdir");

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""hosts":{"h":{"url":"https://e.test/"}},
                   "sources":{"s":{"kind":"github","host":"h","version-handler":"semvar",
                                   "options":{"repositories":["owner/*"]}}}"#),
        );

        let err = run(&[path], Probe::NamesOnly, &ctx()).expect_err("refused");

        assert!(err.to_string().contains("semvar"), "{err}");
    }

    /// A host may name its own, because an exception can reasonably depend
    /// on where the artifact came from.
    #[test]
    fn policy_quarantine_host_scoped_read() {
        let dir = tempfile::tempdir().expect("tempdir");

        quarantine_file(
            dir.path(),
            "rules:\n  - purl: \"pkg:npm/a\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n",
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(
                r#""hosts":{"h":{"url":"https://e.test/","quarantine-policy":"quarantine-policy.yaml"}}"#,
            ),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
        assert_eq!(findings.policies.len(), 1);
    }

    /// A rule naming a version for an ecosystem this build cannot read
    /// matches nothing, and saying so is the point: the artifact keeps
    /// being held back while the file says it should not be.
    #[test]
    fn override_unreachable_reported() {
        let dir = tempfile::tempdir().expect("tempdir");

        quarantine_file(
            dir.path(),
            "rules:\n  - purl: \"pkg:cargo/serde@<2\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n",
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"quarantine-policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");
        let raised: Vec<&str> = findings
            .complaints
            .iter()
            .map(|complaint| complaint.id.as_str())
            .collect();

        assert!(
            raised.contains(&"quarantine-override-unreachable"),
            "{raised:?}"
        );
    }

    /// A versionless rule matches on the name alone and works for an
    /// ecosystem this build has never heard of, because a user may run an
    /// extension that supplies one. Reporting it would be wrong.
    #[test]
    fn rule_versionless_unknown_ecosystem_silent() {
        let dir = tempfile::tempdir().expect("tempdir");

        quarantine_file(
            dir.path(),
            "rules:\n  - purl: \"pkg:cargo/serde\"\n    codes: [signature-missing]\n    class: allowed\n    expires: never\n",
        );

        let path = write(
            dir.path(),
            "c.json",
            &doc(r#""setup":{"quarantine-policy":"quarantine-policy.yaml"}"#),
        );

        let findings = run(&[path], Probe::NamesOnly, &ctx()).expect("loads");

        assert!(findings.is_ok(), "{:?}", findings.complaints);
    }
}
