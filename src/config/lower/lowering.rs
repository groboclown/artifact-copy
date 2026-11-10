//! One lowering pass: servers rendered first, then their repositories,
//! every problem collected rather than the first returned.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use handlebars::Handlebars;
use serde_json::{Map, Value};

use super::access::{Access, Collection, Role, access_text, parse_access};
use super::catalog::{Catalog, Kind, RepositoryKind, Template, Values};
use super::keys::{
    ACCESS, AUTHENTICATION, DEFAULT_REPOSITORY, HOST, INSECURE_TRANSPORT, KIND, NAME,
    OVERRIDE_TEMPLATE, REPOSITORIES, RETRY, SERVER, SERVER_KEYS, URL, VALUES,
};
use super::render::{merge_retry, overlay, server_context};
use super::{Anchor, Origins};
use crate::core::error::{Error, Result};

/// Whether a repository wrote its access or took its server's.
#[derive(Debug, Clone, Copy)]
enum Asked {
    Explicitly,
    ByDefault,
}

/// One repository's rendered template and what it asked for.
struct Rendering<'a> {
    repo: &'a Declared,
    rendered: &'a Map<String, Value>,
    requested: &'a BTreeSet<Access>,
    asked: Asked,
    dir: PathBuf,
    what: &'a str,
}

/// One repository as declared, with the server it belongs to.
pub(super) struct Declared {
    pub(super) alias: String,
    pub(super) server: String,
    pub(super) body: Map<String, Value>,
}

/// A server after its template rendered: what its repositories need.
pub(super) struct Lowered<'k> {
    pub(super) kind: &'k Kind,
    pub(super) kind_name: String,
    pub(super) context: Value,
    pub(super) values: Value,
    pub(super) access: BTreeSet<Access>,
    pub(super) default: Option<Map<String, Value>>,
}

/// One lowering pass's state.  Collects every problem rather than stopping
/// at the first, as schema validation does.
pub(super) struct Lowering<'o> {
    pub(super) renderer: Handlebars<'static>,
    pub(super) origins: &'o Origins,
    pub(super) anchor: Anchor,
    pub(super) problems: Vec<String>,
    pub(super) generated: BTreeMap<Collection, BTreeMap<String, (Value, String)>>,
}

impl Lowering<'_> {
    /// Every declared repository: nested under a server, or standalone
    /// naming one.
    pub(super) fn gather(
        &mut self,
        servers: &Map<String, Value>,
        standalone: Map<String, Value>,
    ) -> Vec<Declared> {
        let mut out = Vec::new();

        for (server, body) in servers {
            let nested = body.get(REPOSITORIES).and_then(Value::as_object);

            for (alias, repo) in nested.into_iter().flatten() {
                let Some(repo) = repo.as_object() else {
                    continue;
                };

                out.push(Declared {
                    alias: alias.clone(),
                    server: server.clone(),
                    body: repo.clone(),
                });
            }
        }

        for (alias, repo) in standalone {
            let Value::Object(mut repo) = repo else {
                continue;
            };

            let Some(Value::String(server)) = repo.remove(SERVER) else {
                self.problems
                    .push(format!("repository {alias:?} names no server"));
                continue;
            };

            out.push(Declared {
                alias,
                server,
                body: repo,
            });
        }

        out
    }

    /// Render one server's template and emit its host.
    pub(super) fn server<'k>(
        &mut self,
        catalog: &'k Catalog,
        alias: &str,
        body: &Value,
    ) -> Option<Lowered<'k>> {
        let body = body.as_object()?;
        let kind_name = body.get(KIND).and_then(Value::as_str).unwrap_or_default();

        let Some(kind) = catalog.get(kind_name) else {
            self.problems.push(format!(
                "server {alias:?} names kind {kind_name:?}, which no template defines; \
                 the kinds are {}",
                catalog.names().join(", "),
            ));
            return None;
        };

        let what = format!("server {alias:?}");
        let values = self.values(&kind.values, body.get(VALUES), &what)?;

        let context = server_context(alias, body);
        let scope = serde_json::json!({ "server": context, "values": values });
        let rendered = self.render(&kind.server, &scope, &what)?;

        self.only_keys(&rendered, &SERVER_KEYS, &kind.server, &what)?;

        let host = self.host(alias, body, &rendered, &what)?;
        let access = self.limits(&rendered, &what)?;

        self.emit(Collection::Hosts, alias, host, &what);

        let default = rendered
            .get(DEFAULT_REPOSITORY)
            .and_then(Value::as_object)
            .cloned();

        Some(Lowered {
            kind,
            kind_name: kind_name.to_owned(),
            context,
            values,
            access,
            default,
        })
    }

    /// The template's host block, with the user's url, credentials, and
    /// retry rules applied over it.
    fn host(
        &mut self,
        alias: &str,
        body: &Map<String, Value>,
        rendered: &Map<String, Value>,
        what: &str,
    ) -> Option<Value> {
        let template = match rendered.get(HOST) {
            Some(Value::Object(host)) => Value::Object(host.clone()),
            None => Value::Object(Map::new()),
            Some(_) => {
                self.problems
                    .push(format!("{what}: its template's 'host' is not a mapping"));
                return None;
            }
        };

        // Only the template's part: the user's own paths were anchored as
        // their file loaded, and anchoring twice doubles a relative base.
        let anchored = self.anchored(Collection::Hosts, alias, template, &self.server_dir(alias));
        let Value::Object(mut host) = anchored else {
            return None;
        };

        // Credentials belong to the user.  A template shipping them would
        // hand every user of that kind the same secret.
        if host.contains_key(AUTHENTICATION) {
            self.problems.push(format!(
                "{what}: its template declares authentication, which only a server may"
            ));
            return None;
        }

        if let Some(url) = body.get(URL) {
            host.insert(URL.to_owned(), url.clone());
        }

        if !host.contains_key(URL) {
            self.problems.push(format!(
                "server {alias:?} has no url, and its kind supplies none"
            ));
            return None;
        }

        if let Some(authentication) = body.get(AUTHENTICATION) {
            host.insert(AUTHENTICATION.to_owned(), authentication.clone());
        }

        // A user's kind may accept plain HTTP for a server it knows has no
        // TLS; the server entry still has the last word, either way.
        if let Some(insecure) = body.get(INSECURE_TRANSPORT) {
            host.insert(INSECURE_TRANSPORT.to_owned(), insecure.clone());
        }

        if let Some(retry) = merge_retry(host.remove(RETRY), body.get(RETRY)) {
            host.insert(RETRY.to_owned(), retry);
        }

        Some(Value::Object(host))
    }

    /// The access a server kind permits.  Absent means both.
    fn limits(&mut self, rendered: &Map<String, Value>, what: &str) -> Option<BTreeSet<Access>> {
        let Some(listed) = rendered.get(ACCESS) else {
            return Some(BTreeSet::from([Access::Read, Access::Write]));
        };

        let mut access = BTreeSet::new();

        for item in listed.as_array().into_iter().flatten() {
            match item.as_str().and_then(parse_access) {
                Some(more) => access.extend(more),
                None => {
                    self.problems.push(format!(
                        "{what}: its template's access lists {item}, which is not \
                         'read', 'write', or 'read-write'"
                    ));
                    return None;
                }
            }
        }

        Some(access)
    }

    /// Render one repository's template and emit its entries.
    pub(super) fn repository(
        &mut self,
        repo: &Declared,
        servers: &Map<String, Value>,
        lowered: &BTreeMap<String, Lowered<'_>>,
    ) {
        let what = format!("repository {:?}", repo.alias);

        let Some(server) = self.server_for(repo, servers, lowered, &what) else {
            return;
        };

        let Some((kind, repo_kind)) = self.kind_for(repo, server, &what) else {
            return;
        };

        let Some(values) = self.merged_values(repo, server, repo_kind, &what) else {
            return;
        };

        let Some(requested) = self.access(repo, server, &what) else {
            return;
        };

        let scope = scope_of(repo, server, kind, &requested, values);

        let Some(rendered) = self.render(&repo_kind.template, &scope, &what) else {
            return;
        };

        if self.roles(&rendered, repo_kind, &what).is_none() {
            return;
        }

        let rendering = self.rendering_of(repo, &rendered, &requested, &what);

        for role in Role::ALL {
            self.role(role, &rendering);
        }

        self.check_readable(&rendering);
    }

    /// The lowered server a repository belongs to.
    fn server_for<'l, 'k>(
        &mut self,
        repo: &Declared,
        servers: &Map<String, Value>,
        lowered: &'l BTreeMap<String, Lowered<'k>>,
        what: &str,
    ) -> Option<&'l Lowered<'k>> {
        if let Some(server) = lowered.get(&repo.server) {
            return Some(server);
        }

        // A server that failed has already said why.
        if !servers.contains_key(&repo.server) {
            self.problems.push(format!(
                "{what} names server {:?}, which is not configured",
                repo.server
            ));
        }

        None
    }

    /// The repository's kind name, and its template, when its server kind
    /// supports it.
    fn kind_for<'r, 's>(
        &mut self,
        repo: &'r Declared,
        server: &'s Lowered<'_>,
        what: &str,
    ) -> Option<(&'r str, &'s RepositoryKind)> {
        let kind = repo
            .body
            .get(KIND)
            .and_then(Value::as_str)
            .unwrap_or_default();

        if let Some(repo_kind) = server.kind.repositories.get(kind) {
            return Some((kind, repo_kind));
        }

        let supported: Vec<&str> = server
            .kind
            .repositories
            .keys()
            .map(String::as_str)
            .collect();

        self.problems.push(format!(
            "{what} has kind {kind:?}, which server kind {:?} does not support; \
             it supports {}",
            server.kind_name,
            supported.join(", "),
        ));

        None
    }

    /// The server's values, with the repository's own laid over them.
    fn merged_values(
        &mut self,
        repo: &Declared,
        server: &Lowered<'_>,
        repo_kind: &RepositoryKind,
        what: &str,
    ) -> Option<Value> {
        let own = self.values(&repo_kind.values, repo.body.get(VALUES), what)?;
        let mut values = server.values.clone();

        overlay(&mut values, own);

        Some(values)
    }

    /// What a repository's state records, for the checks after rendering.
    fn rendering_of<'a>(
        &self,
        repo: &'a Declared,
        rendered: &'a Map<String, Value>,
        requested: &'a BTreeSet<Access>,
        what: &'a str,
    ) -> Rendering<'a> {
        Rendering {
            repo,
            rendered,
            requested,
            asked: match repo.body.contains_key(ACCESS) {
                true => Asked::Explicitly,
                false => Asked::ByDefault,
            },
            dir: self.repository_dir(repo),
            what,
        }
    }

    /// Refuse an explicit read on a repository whose kind can read nothing.
    fn check_readable(&mut self, rendering: &Rendering<'_>) {
        let readable = [Role::Source, Role::Enumerator]
            .iter()
            .any(|role| rendering.rendered.contains_key(role.key()));

        if let (Asked::Explicitly, true, false) = (
            rendering.asked,
            rendering.requested.contains(&Access::Read),
            readable,
        ) {
            self.problems.push(format!(
                "{} asks for read access, and its kind has neither source nor enumerator",
                rendering.what
            ));
        }
    }

    /// A scope's values checked against its manifest, defaults filled in.
    fn values(&mut self, accepted: &Values, given: Option<&Value>, what: &str) -> Option<Value> {
        match accepted.apply(given) {
            Ok(values) => Some(values),
            Err(violations) => {
                for violation in violations {
                    self.problems.push(format!("{what}: {violation}"));
                }
                None
            }
        }
    }

    /// Refuse a rendered key the template has no business producing.
    fn only_keys(
        &mut self,
        rendered: &Map<String, Value>,
        allowed: &[&str],
        template: &Template,
        what: &str,
    ) -> Option<()> {
        let unknown: Vec<&str> = rendered
            .keys()
            .map(String::as_str)
            .filter(|key| !allowed.contains(key))
            .collect();

        if unknown.is_empty() {
            return Some(());
        }

        self.problems.push(format!(
            "{what}: template {} renders {}, which it may not; it may render {}",
            template.origin,
            unknown.join(", "),
            allowed.join(", "),
        ));

        None
    }

    /// The rendered roles must be exactly the ones the manifest declares.
    fn roles(
        &mut self,
        rendered: &Map<String, Value>,
        kind: &RepositoryKind,
        what: &str,
    ) -> Option<()> {
        let allowed: Vec<&str> = Role::ALL.iter().map(|role| role.key()).collect();

        self.only_keys(rendered, &allowed, &kind.template, what)?;

        let produced: BTreeSet<Role> = Role::ALL
            .into_iter()
            .filter(|role| rendered.contains_key(role.key()))
            .collect();

        if produced == kind.roles {
            return Some(());
        }

        let names = |roles: &BTreeSet<Role>| -> String {
            roles
                .iter()
                .map(|role| role.key())
                .collect::<Vec<_>>()
                .join(", ")
        };

        self.problems.push(format!(
            "{what}: template {} renders roles [{}], and its manifest declares [{}]",
            kind.template.origin,
            names(&produced),
            names(&kind.roles),
        ));

        None
    }

    /// The access a repository asks for, within what its server permits.
    fn access(
        &mut self,
        repo: &Declared,
        server: &Lowered<'_>,
        what: &str,
    ) -> Option<BTreeSet<Access>> {
        let Some(written) = repo.body.get(ACCESS) else {
            return Some(server.access.clone());
        };

        let Some(requested) = written.as_str().and_then(parse_access) else {
            self.problems.push(format!(
                "{what} has access {written}, which is not 'read', 'write', or 'read-write'"
            ));
            return None;
        };

        if !requested.is_subset(&server.access) {
            self.problems.push(format!(
                "{what} asks for {} access, and server kind {:?} permits only {}",
                access_text(&requested),
                server.kind_name,
                access_text(&server.access),
            ));
            return None;
        }

        Some(requested)
    }

    /// Emit one role's entry, if the repository's access wants it.
    fn role(&mut self, role: Role, rendering: &Rendering<'_>) {
        let Rendering {
            repo,
            rendered,
            requested,
            asked,
            dir,
            what,
        } = rendering;

        let user = repo.body.get(role.key());

        if !requested.contains(&role.access()) {
            if user.is_some() {
                self.problems.push(format!(
                    "{what} overrides its {} but its access is {}",
                    role.key(),
                    access_text(requested),
                ));
            }
            return;
        }

        let Some(block) = rendered.get(role.key()) else {
            // Asked for by name, so its absence is the user's to hear about.
            // Example: `access: write` on a kind with no target.
            if matches!((asked, role), (Asked::Explicitly, Role::Target)) {
                self.problems.push(format!(
                    "{what} asks for write access, and its kind has no target"
                ));
            }
            return;
        };

        let mut entry = self.anchored(role.collection(), &repo.alias, block.clone(), dir);

        if let Value::Object(fields) = &mut entry {
            fields
                .entry(HOST)
                .or_insert_with(|| Value::String(repo.server.clone()));
        }

        if let Some(user) = user {
            overlay(&mut entry, user.clone());
        }

        self.emit(role.collection(), &repo.alias, entry, what);
    }

    /// Render a template and parse its YAML.
    fn render(
        &mut self,
        template: &Template,
        scope: &Value,
        what: &str,
    ) -> Option<Map<String, Value>> {
        let text = match self.renderer.render_template(&template.source, scope) {
            Ok(text) => text,
            Err(err) => {
                self.problems.push(format!(
                    "{what}: template {} failed to render: {err}",
                    template.origin
                ));
                return None;
            }
        };

        let parsed: std::result::Result<Value, _> = serde_norway::from_str(&text);

        match parsed {
            Ok(Value::Object(fields)) => Some(fields),
            Ok(Value::Null) => Some(Map::new()),
            Ok(_) => {
                self.problems.push(format!(
                    "{what}: template {} does not render a mapping",
                    template.origin
                ));
                None
            }
            Err(err) => {
                self.problems.push(format!(
                    "{what}: template {} renders YAML that does not parse: {err}",
                    template.origin
                ));
                None
            }
        }
    }

    /// A template's entry with its relative paths taken against `dir`.
    fn anchored(&self, collection: Collection, name: &str, entry: Value, dir: &Path) -> Value {
        let mut wrapped = serde_json::json!({ collection.key(): { name: entry } });

        (self.anchor)(&mut wrapped, dir);

        wrapped[collection.key()][name].take()
    }

    /// Check and hold one generated entry.
    fn emit(&mut self, collection: Collection, name: &str, entry: Value, what: &str) {
        if let Err(detail) = collection.check(&entry) {
            self.problems.push(format!(
                "{what} generates an unusable {} {name:?}: {detail}",
                collection.singular()
            ));
            return;
        }

        self.generated
            .entry(collection)
            .or_default()
            .insert(name.to_owned(), (entry, what.to_owned()));
    }

    /// Add the generated entries, refusing a name declared directly unless
    /// that entry set `override-template`.
    pub(super) fn place(
        &mut self,
        root: &mut Map<String, Value>,
        overrides: &BTreeSet<(Collection, String)>,
    ) {
        for (collection, entries) in std::mem::take(&mut self.generated) {
            let slot = root
                .entry(collection.key())
                .or_insert_with(|| Value::Object(Map::new()));

            let Some(existing) = slot.as_object_mut() else {
                continue;
            };

            for (name, (entry, what)) in entries {
                if !existing.contains_key(&name) {
                    existing.insert(name, entry);
                    continue;
                }

                if overrides.contains(&(collection, name.clone())) {
                    continue;
                }

                self.problems.push(format!(
                    "{what} generates {} {name:?}, which is also declared directly; \
                     rename one, or set '{OVERRIDE_TEMPLATE}: true' on the direct entry",
                    collection.singular()
                ));
            }
        }
    }

    pub(super) fn finish(self) -> Result<()> {
        if self.problems.is_empty() {
            return Ok(());
        }

        Err(Error::Config(format!(
            "the servers and repositories cannot be lowered:\n  - {}",
            self.problems.join("\n  - ")
        )))
    }

    fn server_dir(&self, alias: &str) -> PathBuf {
        directory(self.origins.servers.get(alias))
    }

    /// A default repository has no declaration of its own, so it takes its
    /// server's file.
    fn repository_dir(&self, repo: &Declared) -> PathBuf {
        match self.origins.repositories.get(&repo.alias) {
            Some(file) => directory(Some(file)),
            None => self.server_dir(&repo.server),
        }
    }
}

/// The directory holding `file`; the working directory when unknown.
fn directory(file: Option<&PathBuf>) -> PathBuf {
    file.and_then(|file| file.parent())
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The template's scope for one repository.
fn scope_of(
    repo: &Declared,
    server: &Lowered<'_>,
    kind: &str,
    requested: &BTreeSet<Access>,
    values: Value,
) -> Value {
    let name = repo
        .body
        .get(NAME)
        .cloned()
        .unwrap_or_else(|| Value::String(repo.alias.clone()));

    serde_json::json!({
        "server": server.context,
        "repository": {
            "alias": repo.alias,
            "name": name,
            "kind": kind,
            "access": access_text(requested),
        },
        "values": values,
    })
}
