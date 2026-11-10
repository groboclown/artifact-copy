//! Reading a POM, and resolving it against its ancestors.
//!
//! A POM on its own rarely says what a project depends on. Three mechanisms
//! sit between the file and the answer, and all three have to be applied or
//! the result is confidently wrong:
//!
//! - **The parent chain.** `groupId` and `version` are routinely omitted and
//!   inherited; so are `<dependencies>`, `<properties>` and `<licenses>`.
//! - **Properties.** `${project.version}` and `${spring.version}` appear in
//!   version fields constantly, and an uninterpolated one is not a version.
//! - **`dependencyManagement`.** The usual pattern is a dependency with no
//!   version at all, and the version declared once in a parent.
//!
//! Everything here is **pure**: it takes POMs that have already been
//! fetched and returns the effective view. Walking the chain is the
//! source's job, because only the source may ask the host for a file.
//!
//! # What is not supported, and why it is reported
//!
//! Profiles that would change the dependency set are not applied; that is
//! left to a resolver that models the whole graph. What matters is that it
//! is not *silently* skipped: it is surfaced so the caller can raise a
//! problem, rather than descend into a dependency tree missing branches.
//!
//! # `scope=import` BOMs
//!
//! A BOM's management is merged beneath the importer's own, as Maven does:
//! the importer's entries win, then each BOM's in declaration order, the
//! first to manage a coordinate taking it. Fetching and expanding a BOM is
//! the source's job, so [`effective_with`] takes them already expanded,
//! keyed by [`bom_key`]; one it is not handed is reported unexpanded.
//!
//! References: [POM reference](https://maven.apache.org/pom.html).

use std::collections::{BTreeMap, BTreeSet};

use super::xml::{self, Node};
use crate::model::DepKind;

/// How many times a property may expand into another.
///
/// `${a}` may be `${b}`, which may be `${c}`. Ten is far past anything real
/// and stops a cyclic definition spinning.
const MAX_INTERPOLATION_DEPTH: usize = 10;

/// The `dependencyManagement` scope that imports a BOM.
const IMPORT_SCOPE: &str = "import";

/// Maven's default packaging, used when a POM declares none.
pub const DEFAULT_PACKAGING: &str = "jar";

/// Repairs for POMs that fold the group into the artifactId.
///
/// A handful of long-published artifacts carry an empty `<groupId>` and an
/// `<artifactId>` holding the whole dotted coordinate. They are on Central
/// and cannot be fixed there, so anything resolving real dependency graphs
/// has to know about them; dropping them instead would silently lose edges
/// from the graph.
///
/// Prefix rules: everything after the prefix is the artifactId.
const FOLDED_GROUP_PREFIXES: [&str; 2] = ["org.apache.felix.", "org.osgi."];

/// Exact artifactIds whose group is simply missing.
const FOLDED_EXACT: [(&str, &str); 1] = [("wagon-http-shared", "org.apache.maven.wagon")];

/// Recover a group and artifact from a dependency that declares no group.
///
/// Returns `None` when the coordinate cannot be repaired, which is the
/// common case and means the dependency is genuinely unusable.
fn repair_folded_coordinate(artifact_id: &str) -> Option<(String, String)> {
    for (name, group) in FOLDED_EXACT {
        if artifact_id == name {
            return Some((group.to_owned(), artifact_id.to_owned()));
        }
    }

    for prefix in FOLDED_GROUP_PREFIXES {
        if let Some(rest) = artifact_id.strip_prefix(prefix)
            && !rest.is_empty()
        {
            // The prefix carries a trailing dot so that it splits cleanly;
            // the group is the prefix without it.
            return Some((prefix.trim_end_matches('.').to_owned(), rest.to_owned()));
        }
    }

    None
}

/// One `<dependency>`, exactly as written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawDep {
    pub group_id: String,
    pub artifact_id: String,
    pub version: Option<String>,
    pub scope: Option<String>,
    pub optional: bool,
    pub packaging: Option<String>,
    pub classifier: Option<String>,
}

impl RawDep {
    /// What `dependencyManagement` keys on.
    ///
    /// Type and classifier are part of the key: a project may depend on both
    /// `lib` and `lib:test-jar:tests`, managed to different versions.
    fn key(&self) -> (String, String, String, String) {
        (
            self.group_id.clone(),
            self.artifact_id.clone(),
            self.packaging.clone().unwrap_or_else(|| "jar".to_owned()),
            self.classifier.clone().unwrap_or_default(),
        )
    }

    /// The dependency kind, or `None` when it contributes no artifact.
    ///
    /// `system` names a file on the building machine and `import` expands a
    /// BOM rather than adding an artifact; neither can be migrated.
    pub fn kind(&self) -> Option<DepKind> {
        // Checked before scope: an optional dependency is the weaker
        // obligation whatever its scope, and Maven will not pull it
        // transitively.
        if self.optional {
            return Some(DepKind::Optional);
        }

        match self.scope.as_deref().unwrap_or("compile") {
            "compile" | "runtime" => Some(DepKind::Runtime),

            // The closest analogue: present at build time, absent at
            // runtime. Maven has no `dev` of its own.
            "provided" => Some(DepKind::Dev),

            "test" => Some(DepKind::Test),

            "system" | "import" => None,

            // An unrecognized scope is treated as the default rather than
            // dropped, so a typo costs an over-fetch and not a missing
            // dependency.
            _ => Some(DepKind::Runtime),
        }
    }
}

/// A `<license>` entry, which in Maven is free text rather than SPDX.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LicenseRef {
    pub name: Option<String>,
    pub url: Option<String>,
}

/// A `<parent>` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentRef {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

/// One POM, as written, before any inheritance is applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pom {
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    pub packaging: Option<String>,
    pub parent: Option<ParentRef>,
    pub properties: BTreeMap<String, String>,
    pub licenses: Vec<LicenseRef>,
    pub dependencies: Vec<RawDep>,
    pub managed: Vec<RawDep>,

    /// Whether a `<profile>` a consumer could activate declares
    /// dependencies or manages them.
    ///
    /// Not merely whether profiles exist. A great many POMs carry a release
    /// or javadoc profile that touches only `<build>`, and stopping the
    /// spider on every one of those would be useless noise. This is true
    /// only when ignoring the profile could change the dependency set.
    pub profiles_affect_dependencies: bool,
}

impl Pom {
    /// The group this POM belongs to, inheriting from its parent.
    pub fn group_id(&self) -> Option<&str> {
        self.group_id
            .as_deref()
            .or(self.parent.as_ref().map(|p| p.group_id.as_str()))
    }

    /// The version of this POM, inheriting from its parent.
    pub fn version(&self) -> Option<&str> {
        self.version
            .as_deref()
            .or(self.parent.as_ref().map(|p| p.version.as_str()))
    }
}

/// Parse a POM document.
pub fn parse(document: &str) -> Result<Pom, String> {
    let root = xml::parse(document)?;

    if root.name != "project" {
        return Err(format!(
            "the root element is <{}>, not <project>",
            root.name
        ));
    }

    let parent = root.child("parent").and_then(|node| {
        Some(ParentRef {
            group_id: node.text_of("groupId")?.to_owned(),
            artifact_id: node.text_of("artifactId")?.to_owned(),
            version: node.text_of("version")?.to_owned(),
        })
    });

    Ok(Pom {
        group_id: root.text_of("groupId").map(str::to_owned),
        artifact_id: root.text_of("artifactId").map(str::to_owned),
        version: root.text_of("version").map(str::to_owned),
        packaging: root.text_of("packaging").map(str::to_owned),
        parent,
        properties: properties(&root),
        licenses: licenses(&root),
        dependencies: dependencies(root.child("dependencies")),
        managed: dependencies(root.at(&["dependencyManagement", "dependencies"])),
        profiles_affect_dependencies: profiles_affect_dependencies(&root),
    })
}

fn properties(root: &Node) -> BTreeMap<String, String> {
    root.child("properties")
        .map(|node| {
            node.children
                .iter()
                .map(|entry| (entry.name.clone(), entry.text.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn licenses(root: &Node) -> Vec<LicenseRef> {
    root.child("licenses")
        .map(|node| {
            node.children("license")
                .map(|entry| LicenseRef {
                    name: entry.text_of("name").map(str::to_owned),
                    url: entry.text_of("url").map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dependencies(container: Option<&Node>) -> Vec<RawDep> {
    let Some(container) = container else {
        return Vec::new();
    };

    container
        .children("dependency")
        .filter_map(|entry| {
            let artifact_id = entry.text_of("artifactId")?;

            // A missing group is usually fatal to the coordinate, but a few
            // published POMs fold it into the artifactId instead.
            let (group_id, artifact_id) = match entry.text_of("groupId") {
                Some(group) => (group.to_owned(), artifact_id.to_owned()),
                None => repair_folded_coordinate(artifact_id)?,
            };

            Some(RawDep {
                group_id,
                artifact_id,
                version: entry.text_of("version").map(str::to_owned),
                scope: entry.text_of("scope").map(str::to_owned),
                optional: entry.text_of("optional") == Some("true"),
                packaging: entry.text_of("type").map(str::to_owned),
                classifier: entry.text_of("classifier").map(str::to_owned),
            })
        })
        .collect()
}

/// Whether any profile could change which artifacts are needed.
fn profiles_affect_dependencies(root: &Node) -> bool {
    root.child("profiles")
        .map(|profiles| {
            profiles.children("profile").any(|profile| {
                let touches = profile.child("dependencies").is_some()
                    || profile.child("dependencyManagement").is_some();

                touches && activates(profile)
            })
        })
        .unwrap_or(false)
}

/// Marks a `<property>` activation as "when the property is absent".
const NEGATED_PROPERTY_PREFIX: &str = "!";

/// Whether a profile could activate while a consumer resolves the POM.
///
/// A profile with no `<activation>` needs `-P`, and one keyed on a property
/// needs `-Dname`; a consumer passes neither for an upstream POM. Maven ANDs
/// the conditions, so one such property keeps the whole profile off. A
/// negated `!name` is the opposite: active unless someone sets it.
fn activates(profile: &Node) -> bool {
    let Some(activation) = profile.child("activation") else {
        return false;
    };

    if activation.text_of("activeByDefault") == Some("true") {
        return true;
    }

    let mut conditions = activation
        .children
        .iter()
        .filter(|node| node.name != "activeByDefault")
        .peekable();

    // `<activeByDefault>false</activeByDefault>` alone never activates.
    if conditions.peek().is_none() {
        return false;
    }

    !conditions.any(|node| {
        node.name == "property"
            && !node
                .text_of("name")
                .is_some_and(|name| name.starts_with(NEGATED_PROPERTY_PREFIX))
    })
}

/// The resolved view of a POM and its ancestors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effective {
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    pub packaging: String,
    pub licenses: Vec<LicenseRef>,

    /// Dependencies with management applied and properties interpolated.
    pub dependencies: Vec<RawDep>,

    /// Property references that could not be resolved, by name.
    ///
    /// Collected rather than guessed at: a dependency whose version is
    /// still `${spring.version}` is not resolvable, and inventing one would
    /// migrate the wrong artifact.
    ///
    /// Kept apart from [`Effective::unresolved_coordinates`] because the two
    /// have different consequences: this one costs whichever dependency
    /// used it, that one costs the artifact itself.
    pub unresolved_properties: BTreeSet<String>,

    /// Property references the POM's **own** coordinates depend on and
    /// nothing in the chain defines.
    ///
    /// Non-empty means the POM cannot say what artifact it describes, so
    /// nothing read out of it can be trusted -- not the dependency list, not
    /// the licenses, not `${project.version}` anywhere below.
    pub unresolved_coordinates: BTreeSet<String>,

    /// `scope=import` BOMs that were not expanded, as coordinates.
    pub unexpanded_boms: BTreeSet<String>,

    /// Every `scope=import` BOM in the chain's management, interpolated, in
    /// the order Maven applies them.
    pub imports: Vec<RawDep>,

    /// The management in force, own entries first and then the imported
    /// BOMs': what a POM importing this one as a BOM receives.
    pub managed: Vec<RawDep>,

    /// The POM's own parent, which reading it needed.
    pub parent: Option<ParentRef>,

    /// Whether a profile could have changed the dependency set.
    pub profiles_affect_dependencies: bool,
}

/// BOMs already expanded: each one's [`Effective::managed`], keyed by
/// [`bom_key`].
pub type Imported = BTreeMap<String, Vec<RawDep>>;

/// How an import names the BOM it expands: `group:artifact:version`, with
/// `?` for a version the POM does not give.
pub fn bom_key(bom: &RawDep) -> String {
    format!(
        "{}:{}:{}",
        bom.group_id,
        bom.artifact_id,
        bom.version.as_deref().unwrap_or("?")
    )
}

/// Resolve a POM against its ancestors, with no BOM expanded.
///
/// `chain` runs child first: `chain[0]` is the POM being resolved and each
/// following entry is its parent.
pub fn effective(chain: &[Pom]) -> Effective {
    effective_with(chain, &Imported::new())
}

/// Resolve a POM against its ancestors and the BOMs it imports.
pub fn effective_with(chain: &[Pom], imported: &Imported) -> Effective {
    let Some(own) = chain.first() else {
        return Effective::default();
    };

    let properties = merged_properties(chain);
    let (coords, unresolved_coordinates) = own_coordinates(chain, &properties);

    let mut interp = Interpolation {
        properties: &properties,
        coords,
        unresolved: BTreeSet::new(),
    };

    let (mut management, imports) = managed_entries(chain, &mut interp);
    let unexpanded_boms = expand_boms(&mut management, &imports, imported);
    let dependencies = inherited_deps(chain, &management, &mut interp);

    // Packaging is **not** inherited. Every POM declares its own, and the
    // default is `jar` -- a module whose parent is a `pom` aggregator is
    // still a jar, and walking the chain for this would silently strip the
    // payload off every module of every multi-module build.
    let packaging = own
        .packaging
        .clone()
        .unwrap_or_else(|| DEFAULT_PACKAGING.to_owned());
    let packaging = interp.resolve(&packaging);

    let Interpolation {
        coords, unresolved, ..
    } = interp;

    Effective {
        group_id: coords.group_id,
        artifact_id: coords.artifact_id,
        version: coords.version,
        packaging,

        // Licenses are inherited whole, not merged: the nearest POM that
        // declares any wins, which is what Maven does.
        licenses: chain
            .iter()
            .find(|pom| !pom.licenses.is_empty())
            .map(|pom| pom.licenses.clone())
            .unwrap_or_default(),

        dependencies,
        unresolved_properties: unresolved,
        unresolved_coordinates,
        unexpanded_boms,
        imports,
        managed: management.ordered(),
        parent: own.parent.clone(),
        profiles_affect_dependencies: chain.iter().any(|pom| pom.profiles_affect_dependencies),
    }
}

/// Every property in the chain. Ancestors first, so a child's definition
/// overwrites its parent's.
fn merged_properties(chain: &[Pom]) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();

    for pom in chain.iter().rev() {
        properties.extend(pom.properties.clone());
    }

    properties
}

/// The POM's own coordinates, and the properties they name that nothing
/// defines.
///
/// Interpolated first and against the properties **alone**:
/// `${project.version}` cannot help define the version it names, and a
/// chain using `${revision}` for its version -- the CI-friendly-versions
/// pattern -- would otherwise be handed on verbatim as if it were a real
/// version string.
fn own_coordinates(
    chain: &[Pom],
    properties: &BTreeMap<String, String>,
) -> (Coords, BTreeSet<String>) {
    let mut unresolved = BTreeSet::new();
    let bare = Coords::default();

    let mut coordinate = |text: &str| interpolate(text, properties, &bare, &mut unresolved);

    let group_id = chain.iter().find_map(Pom::group_id).map(&mut coordinate);
    let version = chain.iter().find_map(Pom::version).map(&mut coordinate);
    let artifact_id = chain
        .first()
        .and_then(|own| own.artifact_id.as_deref())
        .map(&mut coordinate);

    // The coordinate properties, which are the ones actually used in the
    // wild -- `${project.version}` on a sibling module is near-universal.
    let coords = Coords {
        group_id,
        artifact_id,
        version,
    };

    (coords, unresolved)
}

/// The chain's management, and the `scope=import` BOMs it names.
///
/// Child first: the first definition of a coordinate wins, which is
/// Maven's nearest-wins rule. Kept in order as well, for a POM importing
/// this one as a BOM.
fn managed_entries(chain: &[Pom], interp: &mut Interpolation) -> (Management, Vec<RawDep>) {
    let mut management = Management::default();
    let mut imports = Vec::new();

    for pom in chain {
        for entry in &pom.managed {
            let entry = interp.dep(entry);

            if entry.scope.as_deref() == Some(IMPORT_SCOPE) {
                imports.push(entry);
                continue;
            }

            management.keep(entry);
        }
    }

    (management, imports)
}

/// Manage beneath the chain's own entries each BOM in `imports`, in order,
/// returning those not handed over.
///
/// One not handed over is recorded, so the caller can say why
/// dependencies lack versions.
fn expand_boms(
    management: &mut Management,
    imports: &[RawDep],
    imported: &Imported,
) -> BTreeSet<String> {
    let mut unexpanded = BTreeSet::new();

    for bom in imports {
        let Some(entries) = imported.get(&bom_key(bom)) else {
            unexpanded.insert(bom_key(bom));
            continue;
        };

        for entry in entries {
            management.keep(entry.clone());
        }
    }

    unexpanded
}

/// Declared dependencies with management applied, child first; a parent's
/// are inherited and a child redeclaring one replaces it.
fn inherited_deps(
    chain: &[Pom],
    management: &Management,
    interp: &mut Interpolation,
) -> Vec<RawDep> {
    let mut seen = BTreeSet::new();
    let mut dependencies = Vec::new();

    for pom in chain {
        for entry in &pom.dependencies {
            let mut entry = interp.dep(entry);

            if !seen.insert(entry.key()) {
                continue;
            }

            if let Some(managed) = management.by_key.get(&entry.key()) {
                // Management supplies only what the declaration omitted.
                if entry.version.is_none() {
                    entry.version = managed.version.clone();
                }

                if entry.scope.is_none() {
                    entry.scope = managed.scope.clone();
                }

                entry.optional = entry.optional || managed.optional;
            }

            dependencies.push(entry);
        }
    }

    dependencies
}

/// What `dependencyManagement` keys on; see [`RawDep::key`].
type ManagedKey = (String, String, String, String);

/// The management in force, and the order entries were first kept in.
#[derive(Default)]
struct Management {
    by_key: BTreeMap<ManagedKey, RawDep>,
    order: Vec<ManagedKey>,
}

impl Management {
    /// Keep `entry` unless a nearer definition manages its coordinate
    /// already.
    fn keep(&mut self, entry: RawDep) {
        if let std::collections::btree_map::Entry::Vacant(slot) = self.by_key.entry(entry.key()) {
            self.order.push(entry.key());
            slot.insert(entry);
        }
    }

    /// Every kept entry, in the order it was first kept.
    fn ordered(&self) -> Vec<RawDep> {
        self.order
            .iter()
            .filter_map(|key| self.by_key.get(key).cloned())
            .collect()
    }
}

/// Expanding references against the chain's properties and the POM's own
/// coordinates, collecting the names that do not resolve.
struct Interpolation<'a> {
    properties: &'a BTreeMap<String, String>,
    coords: Coords,
    unresolved: BTreeSet<String>,
}

impl Interpolation<'_> {
    fn resolve(&mut self, text: &str) -> String {
        interpolate(text, self.properties, &self.coords, &mut self.unresolved)
    }

    fn dep(&mut self, dep: &RawDep) -> RawDep {
        interpolate_dep(dep, &mut |text| self.resolve(text))
    }
}

/// The `project.*` properties.
#[derive(Default)]
struct Coords {
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
}

impl Coords {
    /// Resolve a coordinate property under any of its spellings.
    ///
    /// `${pom.version}` is the Maven 2 name and `${version}` the Maven 1
    /// one. Both are deprecated, both still appear in POMs on Central, and
    /// failing to resolve them would strand real dependencies.
    fn get(&self, name: &str) -> Option<&str> {
        let bare = name
            .strip_prefix("project.")
            .or_else(|| name.strip_prefix("pom."))
            .unwrap_or(name);

        match bare {
            "groupId" => self.group_id.as_deref(),
            "artifactId" => self.artifact_id.as_deref(),
            "version" => self.version.as_deref(),
            _ => None,
        }
    }
}

fn interpolate_dep(dep: &RawDep, resolve: &mut impl FnMut(&str) -> String) -> RawDep {
    RawDep {
        group_id: resolve(&dep.group_id),
        artifact_id: resolve(&dep.artifact_id),
        version: dep.version.as_deref().map(&mut *resolve),
        scope: dep.scope.as_deref().map(&mut *resolve),
        optional: dep.optional,
        packaging: dep.packaging.as_deref().map(&mut *resolve),
        classifier: dep.classifier.as_deref().map(&mut *resolve),
    }
}

/// Expand `${...}` references.
///
/// An unresolvable reference is **left verbatim** and its name recorded.
/// Dropping it would turn `${spring.version}` into an empty version and a
/// request for `spring-core-.jar`; substituting a guess would migrate the
/// wrong artifact. Leaving it visible lets the caller refuse to descend.
fn interpolate(
    text: &str,
    properties: &BTreeMap<String, String>,
    coords: &Coords,
    unresolved: &mut BTreeSet<String>,
) -> String {
    let mut current = text.to_owned();

    for _ in 0..MAX_INTERPOLATION_DEPTH {
        if !current.contains("${") {
            break;
        }

        let mut out = String::with_capacity(current.len());
        let mut rest = current.as_str();
        let mut expanded_any = false;

        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);

            let after = &rest[start + 2..];

            let Some(end) = after.find('}') else {
                // An unterminated `${` is text, not a reference.
                out.push_str(&rest[start..]);
                rest = "";
                break;
            };

            let name = &after[..end];

            match coords
                .get(name)
                .or_else(|| properties.get(name).map(String::as_str))
            {
                Some(value) => {
                    out.push_str(value);
                    expanded_any = true;
                }

                None => {
                    unresolved.insert(name.to_owned());
                    out.push_str(&rest[start..start + 2 + end + 1]);
                }
            }

            rest = &after[end + 1..];
        }

        out.push_str(rest);
        current = out;

        // Nothing expanded means every remaining reference is unresolvable,
        // so another pass would only loop.
        if !expanded_any {
            break;
        }
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pom(xml: &str) -> Pom {
        parse(xml).unwrap_or_else(|err| panic!("should parse: {err}"))
    }

    /// A child importing `org.example:bom:1.0`, managing `own` itself and
    /// depending on `own`, `shared`, and `deep` with no versions.
    const IMPORTING: &str = r#"<project>
         <groupId>org.example</groupId><artifactId>child</artifactId><version>1.0</version>
         <parent>
           <groupId>org.example</groupId><artifactId>parent</artifactId><version>2.0</version>
         </parent>
         <dependencyManagement><dependencies>
           <dependency>
             <groupId>org.example</groupId><artifactId>bom</artifactId>
             <version>1.0</version><type>pom</type><scope>import</scope>
           </dependency>
           <dependency>
             <groupId>org.example</groupId><artifactId>own</artifactId><version>9</version>
           </dependency>
         </dependencies></dependencyManagement>
         <dependencies>
           <dependency><groupId>org.example</groupId><artifactId>own</artifactId></dependency>
           <dependency><groupId>org.example</groupId><artifactId>shared</artifactId></dependency>
           <dependency><groupId>org.example</groupId><artifactId>deep</artifactId></dependency>
         </dependencies>
       </project>"#;

    fn managed(entries: &[(&str, &str)]) -> Vec<RawDep> {
        entries
            .iter()
            .map(|(artifact, version)| RawDep {
                group_id: "org.example".into(),
                artifact_id: (*artifact).into(),
                version: Some((*version).into()),
                scope: None,
                optional: false,
                packaging: None,
                classifier: None,
            })
            .collect()
    }

    /// An expanded BOM supplies the versions the importer leaves out; the
    /// importer's own management wins over it.
    #[test]
    fn bom_imported_supplies_versions() {
        let imported = Imported::from([(
            "org.example:bom:1.0".to_owned(),
            managed(&[("own", "1"), ("shared", "2"), ("deep", "3")]),
        )]);

        let resolved = effective_with(&[pom(IMPORTING)], &imported);

        assert_eq!(dep_named(&resolved, "own").version.as_deref(), Some("9"));
        assert_eq!(dep_named(&resolved, "shared").version.as_deref(), Some("2"));
        assert_eq!(dep_named(&resolved, "deep").version.as_deref(), Some("3"));
        assert!(resolved.unexpanded_boms.is_empty());
        assert_eq!(resolved.imports.len(), 1);
        assert_eq!(
            resolved
                .parent
                .as_ref()
                .map(|parent| parent.artifact_id.as_str()),
            Some("parent")
        );
    }

    /// The first BOM to manage a coordinate keeps it.
    #[test]
    fn bom_import_first_wins() {
        let two = pom(r#"<project>
             <artifactId>child</artifactId>
             <dependencyManagement><dependencies>
               <dependency><groupId>g</groupId><artifactId>first</artifactId>
                 <version>1</version><type>pom</type><scope>import</scope></dependency>
               <dependency><groupId>g</groupId><artifactId>second</artifactId>
                 <version>1</version><type>pom</type><scope>import</scope></dependency>
             </dependencies></dependencyManagement>
             <dependencies>
               <dependency><groupId>org.example</groupId><artifactId>shared</artifactId></dependency>
             </dependencies>
           </project>"#);

        let imported = Imported::from([
            ("g:first:1".to_owned(), managed(&[("shared", "1")])),
            ("g:second:1".to_owned(), managed(&[("shared", "2")])),
        ]);

        let resolved = effective_with(&[two], &imported);

        assert_eq!(dep_named(&resolved, "shared").version.as_deref(), Some("1"));
    }

    /// What a POM imported as a BOM hands on: its own management, then its
    /// imports'.
    #[test]
    fn management_lists_own_then_imported() {
        let imported = Imported::from([(
            "org.example:bom:1.0".to_owned(),
            managed(&[("own", "1"), ("shared", "2")]),
        )]);

        let resolved = effective_with(&[pom(IMPORTING)], &imported);
        let listed: Vec<(&str, Option<&str>)> = resolved
            .managed
            .iter()
            .map(|entry| (entry.artifact_id.as_str(), entry.version.as_deref()))
            .collect();

        assert_eq!(listed, [("own", Some("9")), ("shared", Some("2"))]);
    }

    fn dep_named<'e>(effective: &'e Effective, name: &str) -> &'e RawDep {
        effective
            .dependencies
            .iter()
            .find(|dep| dep.artifact_id == name)
            .unwrap_or_else(|| panic!("{name} is missing"))
    }

    const CHILD: &str = r#"
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <parent>
            <groupId>org.example</groupId>
            <artifactId>parent</artifactId>
            <version>2.0.0</version>
          </parent>
          <artifactId>child</artifactId>
          <properties>
            <guava.version>32.1.3-jre</guava.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>com.google.guava</groupId>
              <artifactId>guava</artifactId>
              <version>${guava.version}</version>
            </dependency>
            <dependency>
              <groupId>org.example</groupId>
              <artifactId>sibling</artifactId>
              <version>${project.version}</version>
            </dependency>
            <dependency>
              <groupId>org.slf4j</groupId>
              <artifactId>slf4j-api</artifactId>
            </dependency>
            <dependency>
              <groupId>junit</groupId>
              <artifactId>junit</artifactId>
              <version>4.13.2</version>
              <scope>test</scope>
            </dependency>
          </dependencies>
        </project>"#;

    const PARENT: &str = r#"
        <project>
          <groupId>org.example</groupId>
          <artifactId>parent</artifactId>
          <version>2.0.0</version>
          <packaging>pom</packaging>
          <licenses>
            <license>
              <name>Apache License, Version 2.0</name>
              <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
            </license>
          </licenses>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>org.slf4j</groupId>
                <artifactId>slf4j-api</artifactId>
                <version>2.0.9</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>org.inherited</groupId>
              <artifactId>from-parent</artifactId>
              <version>1.0</version>
            </dependency>
          </dependencies>
        </project>"#;

    fn resolved() -> Effective {
        effective(&[pom(CHILD), pom(PARENT)])
    }

    // -- Parsing ----------------------------------------------------------

    #[test]
    fn parse_parent_reference() {
        let parsed = pom(CHILD);
        let parent = parsed.parent.expect("declared");

        assert_eq!(parent.group_id, "org.example");
        assert_eq!(parent.artifact_id, "parent");
        assert_eq!(parent.version, "2.0.0");
    }

    /// A child routinely omits both, and they come from the parent.
    #[test]
    fn coordinates_missing_from_parent() {
        let parsed = pom(CHILD);

        assert_eq!(parsed.group_id, None);
        assert_eq!(parsed.group_id(), Some("org.example"));
        assert_eq!(parsed.version(), Some("2.0.0"));
    }

    #[test]
    fn parse_non_pom_refused() {
        assert!(parse("<metadata><version>1.0</version></metadata>").is_err());
        assert!(parse("not xml").is_err());
    }

    /// A dependency with no groupId or artifactId is not a dependency.
    /// Skipping it beats inventing an empty coordinate that then 404s.
    #[test]
    fn dependency_incomplete_skipped() {
        let parsed = pom(r#"<project>
                 <dependencies>
                   <dependency><groupId>g</groupId></dependency>
                   <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
                 </dependencies>
               </project>"#);

        assert_eq!(parsed.dependencies.len(), 1);
        assert_eq!(parsed.dependencies[0].artifact_id, "a");
    }

    // -- Inheritance ------------------------------------------------------

    #[test]
    fn coordinates_resolve_through_chain() {
        let resolved = resolved();

        assert_eq!(resolved.group_id.as_deref(), Some("org.example"));
        assert_eq!(resolved.artifact_id.as_deref(), Some("child"));
        assert_eq!(resolved.version.as_deref(), Some("2.0.0"));
    }

    /// Licenses are inherited whole. A child that declares none uses its
    /// parent's rather than reporting the artifact as unlicensed.
    #[test]
    fn licenses_inherited_from_parent() {
        let resolved = resolved();

        assert_eq!(resolved.licenses.len(), 1);
        assert_eq!(
            resolved.licenses[0].name.as_deref(),
            Some("Apache License, Version 2.0")
        );
    }

    #[test]
    fn licenses_child_override_parents_entirely() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <licenses><license><name>MIT</name></license></licenses>
               </project>"#);

        let resolved = effective(&[child, pom(PARENT)]);

        assert_eq!(resolved.licenses.len(), 1);
        assert_eq!(resolved.licenses[0].name.as_deref(), Some("MIT"));
    }

    #[test]
    fn dependencies_inherited_from_parent() {
        assert_eq!(
            dep_named(&resolved(), "from-parent").version.as_deref(),
            Some("1.0")
        );
    }

    /// The commonest shape in a multi-module build: no version on the
    /// dependency, one version in the parent's `dependencyManagement`.
    #[test]
    fn management_supplies_missing_version() {
        assert_eq!(
            dep_named(&resolved(), "slf4j-api").version.as_deref(),
            Some("2.0.9")
        );
    }

    /// Management fills gaps; it does not overrule what the child wrote.
    #[test]
    fn management_loses_to_declared_version() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency>
                     <groupId>org.slf4j</groupId>
                     <artifactId>slf4j-api</artifactId>
                     <version>1.7.36</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child, pom(PARENT)]);

        assert_eq!(
            dep_named(&resolved, "slf4j-api").version.as_deref(),
            Some("1.7.36")
        );
    }

    /// Management supplies a scope and `optional` the declaration omitted.
    #[test]
    fn management_supplies_scope_and_optional() {
        let resolved = effective(&[pom(r#"<project>
                 <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
                 <dependencyManagement><dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId><version>2</version>
                     <scope>test</scope><optional>true</optional>
                   </dependency>
                 </dependencies></dependencyManagement>
                 <dependencies>
                   <dependency><groupId>g</groupId><artifactId>lib</artifactId></dependency>
                 </dependencies>
               </project>"#)]);

        let lib = dep_named(&resolved, "lib");

        assert_eq!(lib.scope.as_deref(), Some("test"));
        assert!(lib.optional);
    }

    /// An own coordinate nothing defines is recorded apart from a
    /// dependency's unresolved property, and `${project.version}` cannot
    /// define the version it names.
    #[test]
    fn coordinates_unresolved_kept_apart() {
        let resolved = effective(&[pom(r#"<project>
                 <groupId>g</groupId><artifactId>a</artifactId>
                 <version>${revision}</version>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId>
                     <version>${lib.version}</version>
                   </dependency>
                 </dependencies>
               </project>"#)]);

        assert_eq!(resolved.version.as_deref(), Some("${revision}"));
        assert_eq!(
            resolved.unresolved_coordinates,
            BTreeSet::from(["revision".to_owned()])
        );
        assert_eq!(
            resolved.unresolved_properties,
            BTreeSet::from(["lib.version".to_owned()])
        );
    }

    /// Nearest wins: a child's own management overrides its parent's.
    #[test]
    fn management_nearest_entry_wins() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencyManagement><dependencies>
                   <dependency>
                     <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
                     <version>9.9.9</version>
                   </dependency>
                 </dependencies></dependencyManagement>
                 <dependencies>
                   <dependency>
                     <groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child, pom(PARENT)]);

        assert_eq!(
            dep_named(&resolved, "slf4j-api").version.as_deref(),
            Some("9.9.9")
        );
    }

    /// Management is keyed on type and classifier too: `lib` and
    /// `lib:test-jar:tests` are managed separately.
    #[test]
    fn management_distinguishes_classifier() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencyManagement><dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version>
                   </dependency>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId>
                     <type>test-jar</type><classifier>tests</classifier>
                     <version>2.0</version>
                   </dependency>
                 </dependencies></dependencyManagement>
                 <dependencies>
                   <dependency><groupId>g</groupId><artifactId>lib</artifactId></dependency>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId>
                     <type>test-jar</type><classifier>tests</classifier>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child]);

        let versions: Vec<Option<&str>> = resolved
            .dependencies
            .iter()
            .map(|dep| dep.version.as_deref())
            .collect();

        assert_eq!(versions, [Some("1.0"), Some("2.0")]);
    }

    // -- Properties -------------------------------------------------------

    #[test]
    fn property_interpolated() {
        assert_eq!(
            dep_named(&resolved(), "guava").version.as_deref(),
            Some("32.1.3-jre")
        );
    }

    /// `${project.version}` on a sibling module is near-universal, and it
    /// resolves through the parent chain rather than from `<properties>`.
    #[test]
    fn property_project_version_from_coordinates() {
        assert_eq!(
            dep_named(&resolved(), "sibling").version.as_deref(),
            Some("2.0.0")
        );
    }

    /// Both deprecated spellings still appear on Central.
    #[test]
    fn coordinates_legacy_spellings_resolve() {
        let child = pom(r#"<project>
                 <groupId>g</groupId><artifactId>a</artifactId><version>3.0</version>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>one</artifactId>
                     <version>${pom.version}</version>
                   </dependency>
                   <dependency>
                     <groupId>g</groupId><artifactId>two</artifactId>
                     <version>${version}</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child]);

        assert_eq!(dep_named(&resolved, "one").version.as_deref(), Some("3.0"));
        assert_eq!(dep_named(&resolved, "two").version.as_deref(), Some("3.0"));
        assert!(resolved.unresolved_properties.is_empty());
    }

    #[test]
    fn property_child_overrides_parents() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <properties><lib.version>2.0</lib.version></properties>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId>
                     <version>${lib.version}</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let parent = pom(r#"<project>
                 <groupId>g</groupId><artifactId>parent</artifactId><version>1.0</version>
                 <properties><lib.version>1.0</lib.version></properties>
               </project>"#);

        assert_eq!(
            dep_named(&effective(&[child, parent]), "lib")
                .version
                .as_deref(),
            Some("2.0")
        );
    }

    #[test]
    fn property_defined_by_another_resolves() {
        let child = pom(r#"<project>
                 <groupId>g</groupId><artifactId>a</artifactId><version>5.0</version>
                 <properties>
                   <base.version>${project.version}</base.version>
                   <lib.version>${base.version}</lib.version>
                 </properties>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId>
                     <version>${lib.version}</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        assert_eq!(
            dep_named(&effective(&[child]), "lib").version.as_deref(),
            Some("5.0")
        );
    }

    /// The critical failure mode. An unresolved property must be reported
    /// and left visible -- dropping it would build a request for
    /// `lib-.jar`, and guessing would migrate the wrong artifact.
    #[test]
    fn property_unresolvable_recorded_left_intact() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId>
                     <version>${env.SOME_VERSION}</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child]);

        assert!(resolved.unresolved_properties.contains("env.SOME_VERSION"));
        assert_eq!(
            dep_named(&resolved, "lib").version.as_deref(),
            Some("${env.SOME_VERSION}")
        );
    }

    /// A cyclic definition must terminate rather than spin.
    #[test]
    fn property_cycle_terminates() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <properties>
                   <a>${b}</a>
                   <b>${a}</b>
                 </properties>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId><version>${a}</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child]);

        assert!(resolved.dependencies[0].version.is_some());
    }

    #[test]
    fn property_unterminated_reference_left_as_text() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency>
                     <groupId>g</groupId><artifactId>lib</artifactId><version>${oops</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        assert_eq!(
            dep_named(&effective(&[child]), "lib").version.as_deref(),
            Some("${oops")
        );
    }

    // -- Scopes -----------------------------------------------------------

    #[test]
    fn scopes_map_onto_dependency_kinds() {
        let kind = |scope: Option<&str>, optional: bool| {
            RawDep {
                group_id: "g".into(),
                artifact_id: "a".into(),
                scope: scope.map(str::to_owned),
                optional,
                ..RawDep::default()
            }
            .kind()
        };

        assert_eq!(kind(None, false), Some(DepKind::Runtime));
        assert_eq!(kind(Some("compile"), false), Some(DepKind::Runtime));
        assert_eq!(kind(Some("runtime"), false), Some(DepKind::Runtime));
        assert_eq!(kind(Some("provided"), false), Some(DepKind::Dev));
        assert_eq!(kind(Some("test"), false), Some(DepKind::Test));

        // Neither yields an artifact this tool could fetch.
        assert_eq!(kind(Some("system"), false), None);
        assert_eq!(kind(Some("import"), false), None);

        // Optional outranks scope: Maven would not pull it transitively.
        assert_eq!(kind(Some("compile"), true), Some(DepKind::Optional));
        assert_eq!(kind(Some("test"), true), Some(DepKind::Optional));

        // A typo over-fetches rather than losing a dependency.
        assert_eq!(kind(Some("nonsense"), false), Some(DepKind::Runtime));
    }

    #[test]
    fn test_scope_survives_resolution() {
        assert_eq!(dep_named(&resolved(), "junit").kind(), Some(DepKind::Test));
    }

    // -- Unsupported features ---------------------------------------------

    /// An unexpanded BOM is why some dependencies have no version, so it is
    /// recorded rather than passed over -- otherwise the missing versions
    /// look like a bug in this tool.
    #[test]
    fn bom_import_recorded_not_applied() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencyManagement><dependencies>
                   <dependency>
                     <groupId>org.springframework.boot</groupId>
                     <artifactId>spring-boot-dependencies</artifactId>
                     <version>3.2.0</version>
                     <type>pom</type>
                     <scope>import</scope>
                   </dependency>
                 </dependencies></dependencyManagement>
               </project>"#);

        let resolved = effective(&[child]);

        assert!(
            resolved
                .unexpanded_boms
                .contains("org.springframework.boot:spring-boot-dependencies:3.2.0")
        );

        // And it is not mistaken for a dependency of its own.
        assert!(resolved.dependencies.is_empty());
    }

    /// A profile that only configures the build cannot change which
    /// artifacts are needed, and flagging those would stop the spider on a
    /// large fraction of Central for no reason.
    #[test]
    fn profile_flagged_only_when_touching_dependencies() {
        let build_only = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <profiles><profile>
                   <id>release</id>
                   <build><plugins><plugin><artifactId>gpg</artifactId></plugin></plugins></build>
                 </profile></profiles>
               </project>"#);

        assert!(!effective(&[build_only]).profiles_affect_dependencies);

        let with_deps = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <profiles><profile>
                   <id>jdk11</id>
                   <activation><jdk>11</jdk></activation>
                   <dependencies><dependency>
                     <groupId>g</groupId><artifactId>extra</artifactId><version>1.0</version>
                   </dependency></dependencies>
                 </profile></profiles>
               </project>"#);

        assert!(effective(&[with_deps]).profiles_affect_dependencies);
    }

    /// A dependency-bearing profile under the given `<activation>` markup.
    fn profiled(activation: &str) -> Pom {
        pom(&format!(
            r#"<project>
                 <artifactId>child</artifactId>
                 <profiles><profile>
                   <id>extra</id>
                   {activation}
                   <dependencies><dependency>
                     <groupId>g</groupId><artifactId>extra</artifactId><version>1.0</version>
                   </dependency></dependencies>
                 </profile></profiles>
               </project>"#
        ))
    }

    /// Like jersey's `sonar` profile: only `-P sonar` turns it on.
    #[test]
    fn profile_without_activation_ignored() {
        assert!(!effective(&[profiled("")]).profiles_affect_dependencies);
    }

    /// Like jersey's `moxy` profile: only `-Dmoxy` turns it on.
    #[test]
    fn profile_property_activation_ignored() {
        let moxy = profiled("<activation><property><name>moxy</name></property></activation>");

        assert!(!effective(&[moxy]).profiles_affect_dependencies);
    }

    #[test]
    fn profile_negated_property_flagged() {
        let absent = profiled("<activation><property><name>!moxy</name></property></activation>");

        assert!(effective(&[absent]).profiles_affect_dependencies);
    }

    #[test]
    fn profile_active_by_default_flagged() {
        let default = profiled("<activation><activeByDefault>true</activeByDefault></activation>");

        assert!(effective(&[default]).profiles_affect_dependencies);
    }

    #[test]
    fn profile_inactive_by_default_ignored() {
        let off = profiled("<activation><activeByDefault>false</activeByDefault></activation>");

        assert!(!effective(&[off]).profiles_affect_dependencies);
    }

    // -- Edges ------------------------------------------------------------

    // -- Coordinates published wrong --------------------------------------

    /// A handful of long-published POMs fold the whole dotted coordinate
    /// into `<artifactId>` and leave `<groupId>` empty. They are on Central
    /// and cannot be corrected there, so dropping them would silently lose
    /// edges from real dependency graphs.
    #[test]
    fn folded_group_recovered() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency>
                     <artifactId>org.apache.felix.framework</artifactId>
                     <version>1.0</version>
                   </dependency>
                   <dependency>
                     <artifactId>org.osgi.core</artifactId>
                     <version>2.0</version>
                   </dependency>
                   <dependency>
                     <artifactId>wagon-http-shared</artifactId>
                     <version>3.0</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child]);

        let found = |group: &str, artifact: &str| {
            resolved
                .dependencies
                .iter()
                .any(|dep| dep.group_id == group && dep.artifact_id == artifact)
        };

        assert!(
            found("org.apache.felix", "framework"),
            "{:?}",
            resolved.dependencies
        );
        assert!(found("org.osgi", "core"));

        // This one keeps its artifactId; only the group was missing.
        assert!(found("org.apache.maven.wagon", "wagon-http-shared"));
    }

    /// The repairs are a short, specific list, not a general "split on the
    /// last dot" rule -- which would mangle every ordinary artifactId that
    /// happens to contain one.
    #[test]
    fn folded_group_unrecognized_still_skipped() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency><artifactId>com.example.thing</artifactId></dependency>
                   <dependency><artifactId>commons-io</artifactId></dependency>
                 </dependencies>
               </project>"#);

        assert!(effective(&[child]).dependencies.is_empty());
    }

    /// The prefix alone is not a coordinate: `org.osgi.` with nothing after
    /// it names no artifact.
    #[test]
    fn folded_group_bare_prefix_not_repaired() {
        assert_eq!(repair_folded_coordinate("org.osgi."), None);
        assert_eq!(repair_folded_coordinate("org.apache.felix."), None);
        assert_eq!(repair_folded_coordinate("org.osgi"), None);
    }

    /// A declared group is always believed; the repairs apply only where
    /// one is genuinely absent.
    #[test]
    fn folded_group_declared_never_rewritten() {
        let child = pom(r#"<project>
                 <artifactId>child</artifactId>
                 <dependencies>
                   <dependency>
                     <groupId>com.example</groupId>
                     <artifactId>org.osgi.core</artifactId>
                     <version>1.0</version>
                   </dependency>
                 </dependencies>
               </project>"#);

        let resolved = effective(&[child]);

        assert_eq!(resolved.dependencies[0].group_id, "com.example");
        assert_eq!(resolved.dependencies[0].artifact_id, "org.osgi.core");
    }

    // -- Packaging --------------------------------------------------------

    /// Packaging is **not** inherited. A module whose parent is a `pom`
    /// aggregator is still a jar, and inheriting here would strip the
    /// payload off every module of every multi-module build.
    #[test]
    fn packaging_not_inherited_from_parent() {
        let child = pom("<project><artifactId>child</artifactId></project>");

        assert_eq!(effective(&[child, pom(PARENT)]).packaging, "jar");
        assert_eq!(effective(&[pom(PARENT)]).packaging, "pom");
    }

    #[test]
    fn packaging_defaults_to_jar() {
        let child = pom("<project><artifactId>a</artifactId></project>");

        assert_eq!(effective(&[child]).packaging, "jar");
    }

    #[test]
    fn packaging_declared_kept() {
        assert_eq!(effective(&[pom(PARENT)]).packaging, "pom");
    }

    #[test]
    fn empty_chain_resolves_to_nothing() {
        assert_eq!(effective(&[]), Effective::default());
    }

    #[test]
    fn dependencies_none_resolve_cleanly() {
        let resolved = effective(&[pom("<project><artifactId>a</artifactId></project>")]);

        assert!(resolved.dependencies.is_empty());
        assert!(resolved.unresolved_properties.is_empty());
        assert!(resolved.unexpanded_boms.is_empty());
    }
}
