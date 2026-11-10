//! A POM resolved against its parents and the BOMs it imports, and the
//! dependencies it then declares.
//!
//! References: [POM reference](https://maven.apache.org/pom.html).

use std::sync::Arc;

use super::pom::{self, DEFAULT_PACKAGING, Effective, Pom};
use super::sidecar::{self};
use super::{FetchedPom, MavenSource, POM_PACKAGING, is_safe_segment};
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ecosystem::maven::{CLASSIFIER_QUALIFIER, TYPE_QUALIFIER};
use crate::message;
use crate::model::{
    ArtifactId, DepKind, Dependency, EcosystemId, ResolvedArtifact, Version, VersionSpec,
};
use crate::net::{ByteLimit, Req};
use crate::version::VersionHandler;

/// How far a parent chain may be followed.
///
/// Real chains run to four or five. The cap exists because a POM that
/// names itself as its own parent would otherwise fetch forever.
const MAX_PARENT_DEPTH: usize = 16;

/// How deep BOM imports may nest: a BOM importing a BOM importing another.
///
/// Spring Boot's reaches three. Cycles are refused on their own; the cap
/// bounds the fetching for a chain that is merely long.
const MAX_BOM_DEPTH: usize = 8;

impl MavenSource {
    /// One POM, parsed.
    ///
    /// A `.pom` that is not a POM does **not** fail the artifact. Files get
    /// published wrong -- a `.pom` that is really a zip is a shape that
    /// exists on Central -- and the bytes are still perfectly copyable even
    /// when nothing can be read out of them. So a parse failure is reported
    /// and treated as an empty POM: the artifact keeps its files, and loses
    /// only the license and dependencies that were never readable anyway.
    ///
    /// A POM that cannot be *fetched* is a different matter and stays an
    /// error, because in the Maven layout that means the version is not
    /// there.
    pub(super) async fn pom(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
        ctx: &Ctx,
    ) -> Result<Arc<FetchedPom>> {
        let build = self
            .snapshot(group, artifact, version, ctx)
            .await?
            .value_for(version, None, POM_PACKAGING);
        let url = self.pom_url(group, artifact, version, &build);

        self.poms
            .get_or_try_init(&url, || async {
                let body = crate::ext::document(
                    &*self.host,
                    &Req::get(&url),
                    crate::ext::leaf(&url),
                    ByteLimit::METADATA,
                    ctx,
                )
                .await?;

                // Checked before it is parsed, not after. A POM that does
                // not match the checksum beside it should not have its
                // dependencies believed, and `checksum-mismatch` aborts the
                // run by default -- so reading it first would be acting on
                // bytes the next line is about to reject.
                let order = self.checksums.order();
                let id = ArtifactId::new(EcosystemId::maven(), Some(group), artifact);
                let pom_version = self.ecosystem.version(version);
                let subject = sidecar::Subject {
                    id: &id,
                    version: Some(&pom_version),
                };

                let sidecars = sidecar::check(
                    &url,
                    &body,
                    &order,
                    &*self.host,
                    &self.keyring(),
                    &subject,
                    ctx,
                )
                .await;

                self.checksums
                    .record(sidecars.digests.first().map(|digest| digest.alg));

                let text = String::from_utf8_lossy(&body);

                let parsed = pom::parse(&text).unwrap_or_else(|detail| {
                    ctx.report(
                        Code::MetadataMalformed,
                        message!(
                            "maven-pom-unreadable",
                            "{url} is not a readable POM ({reason}); its license and \
                             dependencies cannot be determined",
                            url = &url,
                            reason = &detail,
                        ),
                    );

                    Pom::default()
                });

                Ok(FetchedPom {
                    pom: parsed,
                    sidecars,
                })
            })
            .await
    }

    /// A POM resolved against its ancestors.
    ///
    /// The chain is fetched here because only the source may ask the host
    /// for a file; merging it is [`pom::effective`], which is pure.
    pub(super) async fn effective_pom(
        &self,
        id: &ArtifactId,
        version: &Version,
        ctx: &Ctx,
    ) -> Result<Effective> {
        let group = Self::group_of(id)?;
        let chain = self.chain(group, id.name(), version.text(), ctx).await?;

        // Resolved once to learn the BOMs it imports, and again with them
        // expanded. The POMs are cached, so the second pass is arithmetic.
        let imports = pom::effective(&chain).imports;
        let mut imported = pom::Imported::new();

        self.expand(&imports, &mut Vec::new(), &mut imported, ctx)
            .await;

        let effective = pom::effective_with(&chain, &imported);

        // The POM cannot say what artifact it describes, so nothing else in
        // it is worth reading: its dependency list, its licenses and every
        // `${project.version}` below are all relative to coordinates that
        // do not exist. Refused here rather than in each caller, because
        // both `resolve` and `deps` would otherwise have to remember to.
        if !effective.unresolved_coordinates.is_empty() {
            let properties = effective
                .unresolved_coordinates
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");

            ctx.report(
                Code::PomPropertyUnresolved,
                message!(
                    "maven-coordinates-unresolved",
                    "the POM for {purl} builds its own coordinates from {properties}, \
                     which nothing in its parent chain defines",
                    purl = id.purl_at(version.text()),
                    properties = &properties,
                ),
            );

            let build = self
                .snapshot(group, id.name(), version.text(), ctx)
                .await?
                .value_for(version.text(), None, POM_PACKAGING);

            return Err(Error::Malformed {
                what: "maven pom coordinates",
                url: self.pom_url(group, id.name(), version.text(), &build),
                detail: format!("unresolved {properties}"),
            });
        }

        Ok(effective)
    }

    /// Expand each BOM in `boms` into `imported`, its own imports first.
    ///
    /// A BOM's management is its effective one: its parents', and the BOMs
    /// it imports in turn. `path` holds the BOMs being expanded above this
    /// one, so a cycle stops rather than recursing; a BOM that cannot be
    /// read, or sits past [`MAX_BOM_DEPTH`], is left out, and the importer
    /// reports it unexpanded.
    fn expand<'a>(
        &'a self,
        boms: &'a [pom::RawDep],
        path: &'a mut Vec<String>,
        imported: &'a mut pom::Imported,
        ctx: &'a Ctx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            for bom in boms {
                let key = pom::bom_key(bom);

                let expandable = bom.version.as_deref().is_some_and(is_safe_segment)
                    && !imported.contains_key(&key)
                    && !path.contains(&key)
                    && path.len() < MAX_BOM_DEPTH;

                if !expandable {
                    continue;
                }

                let Some(version) = bom.version.as_deref() else {
                    continue;
                };

                let chain = match self
                    .chain(&bom.group_id, &bom.artifact_id, version, ctx)
                    .await
                {
                    Ok(chain) => chain,

                    Err(err) => {
                        ctx.report(
                            Code::DependencyUnresolved,
                            message!(
                                "maven-bom-unreadable",
                                "cannot read the bill of materials {artifact_name}: {reason}",
                                artifact_name = &key,
                                reason = &err,
                            ),
                        );

                        continue;
                    }
                };

                let nested = pom::effective(&chain).imports;

                path.push(key.clone());
                self.expand(&nested, path, imported, ctx).await;
                path.pop();

                let managed = pom::effective_with(&chain, imported).managed;

                imported.insert(key, managed);
            }
        })
    }

    /// A POM and its ancestors, child first.
    ///
    /// The POM itself must be fetched. A parent that cannot be is not
    /// fatal: the child's own dependencies are still worth reporting, and
    /// stopping there yields a partial answer whose gaps are then visible
    /// as unresolved properties and missing versions.
    async fn chain(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
        ctx: &Ctx,
    ) -> Result<Vec<Pom>> {
        let mut chain = vec![self.pom(group, artifact, version, ctx).await?.pom.clone()];

        for _ in 0..MAX_PARENT_DEPTH {
            let Some(parent) = chain.last().and_then(|pom| pom.parent.clone()) else {
                break;
            };

            let fetched = self
                .pom(&parent.group_id, &parent.artifact_id, &parent.version, ctx)
                .await;

            match fetched {
                Ok(fetched) => chain.push(fetched.pom.clone()),

                Err(err) => {
                    ctx.report(
                        Code::DependencyUnresolved,
                        message!(
                            "maven-parent-unreadable",
                            "cannot read the parent {purl1} of {purl}: {reason}",
                            purl = ArtifactId::new(EcosystemId::maven(), Some(group), artifact)
                                .purl_at(version),
                            purl1 = ArtifactId::new(
                                EcosystemId::maven(),
                                Some(&parent.group_id),
                                &parent.artifact_id,
                            )
                            .purl_at(&parent.version),
                            reason = &err,
                        ),
                    );

                    break;
                }
            }
        }

        Ok(chain)
    }

    /// What `artifact` depends on: the POMs its build reads first, then
    /// the dependencies its effective POM declares.
    ///
    /// Everything unsupported is reported before anything is returned.
    pub(super) async fn dependencies(
        &self,
        artifact: &ResolvedArtifact,
        ctx: &Ctx,
    ) -> Result<Vec<Dependency>> {
        let resolved = self
            .effective_pom(
                &artifact.id,
                crate::repo::version_required(&artifact.id, artifact.version.as_ref())?,
                ctx,
            )
            .await?;

        report_unsupported(artifact, &resolved, ctx);

        let mut out = build_dependencies(&resolved);

        out.extend(
            resolved
                .dependencies
                .iter()
                .filter_map(|dep| usable_dep(artifact, dep, ctx)),
        );

        Ok(out)
    }
}

/// Report what this tool does not apply, before anything is returned, so
/// a caller acting on the dependency list knows what is missing from it
/// rather than finding the gap later.
fn report_unsupported(artifact: &ResolvedArtifact, resolved: &Effective, ctx: &Ctx) {
    if resolved.profiles_affect_dependencies {
        ctx.report(
            Code::PomProfileUnsupported,
            message!(
                "maven-profile-affects-dependencies",
                "{purl} declares a profile that changes its dependencies, \
                 which this tool does not activate",
                purl = artifact.purl(),
            ),
        );
    }

    for bom in &resolved.unexpanded_boms {
        // The BOM is an `artifact_name`, not a `purl1`: the POM gives
        // only `group:artifact:version` text, whose version may be `?`
        // or an unresolved `${property}`, and no purl can be built from
        // that.
        ctx.report(
            Code::DependencyUnresolved,
            message!(
                "maven-bom-not-expanded",
                "{purl} imports the bill of materials {artifact_name}, which could \
                 not be expanded, so the versions it manages are unknown",
                purl = artifact.purl(),
                artifact_name = bom,
            ),
        );
    }
}

/// One declared dependency as a [`Dependency`], or `None` when it names
/// nothing that could be migrated.
fn usable_dep(artifact: &ResolvedArtifact, dep: &pom::RawDep, ctx: &Ctx) -> Option<Dependency> {
    // `system` and `import` contribute no artifact that could be
    // migrated, so they are skipped rather than reported.
    let kind = dep.kind()?;

    let Some(version) = &dep.version else {
        ctx.report(
            Code::DependencyUnresolved,
            message!(
                "maven-dependency-without-version",
                "{purl} depends on {purl1} with no version, and \
                 nothing in its parent chain manages one",
                purl = artifact.purl(),
                purl1 = dependency_id(dep).purl(),
            ),
        );

        return None;
    };

    // A property nothing defines is left verbatim by the resolver,
    // so a `${spring.version}` that reaches here is still literally
    // that. Descending on it would ask the repository for the
    // version `${spring.version}`; the whole point of leaving it
    // visible was so this could refuse instead.
    //
    // One dependency, not the artifact: the others in this POM are
    // unaffected, and the parent chain that would have defined the
    // property may simply not have loaded.
    if let Some(reference) = unresolved_reference(dep) {
        ctx.report(
            Code::DependencyUnresolved,
            message!(
                "maven-dependency-property-unresolved",
                "{purl} depends on {purl1} at {version}, which refers \
                 to {reference} -- nothing in its parent chain defines it",
                purl = artifact.purl(),
                purl1 = dependency_id(dep).purl(),
                version = version,
                reference = &reference,
            ),
        );

        return None;
    }

    Some(Dependency {
        id: dependency_id(dep),
        spec: match version.starts_with('[') || version.starts_with('(') {
            true => VersionSpec::Range(version.clone()),
            false => VersionSpec::Exact(version.clone()),
        },
        kind,
    })
}

/// The first `${...}` left standing in a dependency's coordinates.
///
/// Only the three that identify an artifact are checked. A `${...}` in a
/// scope or a classifier is a smaller problem and not one worth dropping a
/// dependency over -- it would be dropped from a set the caller can still
/// act on, which is the opposite of helpful.
fn unresolved_reference(dep: &pom::RawDep) -> Option<String> {
    [
        Some(dep.group_id.as_str()),
        Some(dep.artifact_id.as_str()),
        dep.version.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|text| {
        let start = text.find("${")?;
        let end = text[start..].find('}')?;

        Some(text[start..start + end + 1].to_owned())
    })
}

/// The POMs reading this one needed: its parent, and the BOMs it imports.
///
/// `build` dependencies, so any dependency walk copies them: a consumer's
/// build reads the parent and every imported BOM before it can resolve
/// anything else. A BOM whose version is unknown or unresolved is left
/// out; the importer already reports it unexpanded.
fn build_dependencies(resolved: &Effective) -> Vec<Dependency> {
    let parent = resolved.parent.iter().map(|parent| Dependency {
        id: ArtifactId::new(
            EcosystemId::maven(),
            Some(&parent.group_id),
            &parent.artifact_id,
        )
        .with_qualifier(TYPE_QUALIFIER, POM_PACKAGING),
        spec: VersionSpec::Exact(parent.version.clone()),
        kind: DepKind::Build,
    });

    let boms = resolved.imports.iter().filter_map(|bom| {
        let version = bom.version.as_ref()?;

        if unresolved_reference(bom).is_some() {
            return None;
        }

        Some(Dependency {
            id: dependency_id(&pom::RawDep {
                packaging: Some(POM_PACKAGING.to_owned()),
                ..bom.clone()
            }),
            spec: VersionSpec::Exact(version.clone()),
            kind: DepKind::Build,
        })
    });

    parent.chain(boms).collect()
}

/// Build a dependency's artifact identity, carrying type and classifier.
fn dependency_id(dep: &pom::RawDep) -> ArtifactId {
    let mut id = ArtifactId::new(EcosystemId::maven(), Some(&dep.group_id), &dep.artifact_id);

    if let Some(packaging) = &dep.packaging
        && packaging != DEFAULT_PACKAGING
    {
        id = id.with_qualifier(TYPE_QUALIFIER, packaging);
    }

    if let Some(classifier) = &dep.classifier {
        id = id.with_qualifier(CLASSIFIER_QUALIFIER, classifier);
    }

    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ctx::Ctx;
    use crate::core::problem::Action;
    use crate::ext::testing::Fixture;
    use crate::model::DepKind;
    use crate::net::FixtureClient;

    use crate::repo::maven::testing::*;
    use crate::version::VersionHandler;

    use crate::core::problem::Code;

    use crate::model::{Dependency, VersionSpec};

    use crate::repo::Source;
    use crate::repo::maven::MavenSource;

    async fn deps_of(f: &Fixture<MavenSource>, ctx: &Ctx) -> Vec<Dependency> {
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), ctx)
            .await
            .expect("read");

        f.subject.deps(&artifact, ctx).await.expect("read")
    }

    #[tokio::test]
    async fn dependencies_tagged_by_kind() {
        let f = fixture();
        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        let kind_of = |name: &str| {
            deps.iter()
                .find(|dep| dep.id.name() == name)
                .unwrap_or_else(|| panic!("{name} missing"))
                .kind
        };

        assert_eq!(kind_of("guava"), DepKind::Runtime);
        assert_eq!(kind_of("junit"), DepKind::Test);
    }

    /// The whole point of the parent chain: a property from the child and
    /// a managed version from the parent, both applied.
    #[tokio::test]
    async fn parent_resolves_properties_and_management() {
        let f = fixture();
        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        let spec_of = |name: &str| {
            deps.iter()
                .find(|dep| dep.id.name() == name)
                .unwrap_or_else(|| panic!("{name} missing"))
                .spec
                .clone()
        };

        assert_eq!(spec_of("guava"), VersionSpec::Exact("32.1.3-jre".into()));
        assert_eq!(spec_of("slf4j-api"), VersionSpec::Exact("2.0.9".into()));
    }

    /// A `system` dependency names a path on the building machine. There
    /// is no artifact to migrate, so it is skipped without a problem.
    #[tokio::test]
    async fn dependency_system_skipped_quietly() {
        let f = fixture();
        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        assert!(!deps.iter().any(|dep| dep.id.name() == "thing"));
        assert!(
            !ctx.problems()
                .counts()
                .contains_key(&Code::DependencyUnresolved)
        );
    }

    #[tokio::test]
    async fn parent_fetched_once_for_all_children() {
        let f = fixture();
        let ctx = ctx();

        deps_of(&f, &ctx).await;
        deps_of(&f, &ctx).await;

        assert_eq!(
            f.host
                .hits(&format!("{REPO}/org/example/parent/5.0/parent-5.0.pom")),
            1
        );
    }

    /// A dependency with no version anywhere cannot be fetched, and
    /// guessing one would migrate the wrong artifact.
    /// A bracketed version is a range, and a profile that changes the
    /// dependencies is reported while the rest are still returned.
    #[tokio::test]
    async fn dependency_ranges_and_profiles_read() {
        let ranged = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <dependencies>
                <dependency><groupId>g</groupId><artifactId>ranged</artifactId>
                  <version>[1.0,2.0)</version></dependency>
                <dependency><groupId>g</groupId><artifactId>exact</artifactId>
                  <version>1.5</version></dependency>
              </dependencies>
              <profiles><profile>
                <activation><activeByDefault>true</activeByDefault></activation>
                <dependencies>
                  <dependency><groupId>g</groupId><artifactId>extra</artifactId>
                    <version>1</version></dependency>
                </dependencies>
              </profile></profiles>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), ranged)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        let specs: Vec<(&str, &VersionSpec)> =
            deps.iter().map(|dep| (dep.id.name(), &dep.spec)).collect();

        assert_eq!(
            specs,
            [
                ("ranged", &VersionSpec::Range("[1.0,2.0)".to_owned())),
                ("exact", &VersionSpec::Exact("1.5".to_owned())),
            ]
        );
        assert_eq!(ctx.problems().counts()[&Code::PomProfileUnsupported], 1);
    }

    #[tokio::test]
    async fn dependency_unresolvable_version_reported() {
        let orphan = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <dependencies>
                <dependency><groupId>g</groupId><artifactId>mystery</artifactId></dependency>
              </dependencies>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), orphan)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        assert!(deps.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::DependencyUnresolved], 1);
    }

    /// An unresolved property costs whatever used it, and nothing more.
    /// Here it is one dependency's version, so that dependency is dropped
    /// and the sibling beside it is still returned.
    ///
    /// Dropped rather than returned verbatim: the resolver leaves
    /// `${nowhere.version}` in place deliberately so that this can refuse,
    /// and descending on it would ask the repository for a version by that
    /// literal name.
    #[tokio::test]
    async fn dependency_unresolved_property_dropped_alone() {
        let broken = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <dependencies>
                <dependency>
                  <groupId>g</groupId><artifactId>x</artifactId>
                  <version>${nowhere.version}</version>
                </dependency>
                <dependency>
                  <groupId>g</groupId><artifactId>fine</artifactId>
                  <version>2.0</version>
                </dependency>
              </dependencies>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), broken)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        assert_eq!(ctx.problems().counts()[&Code::DependencyUnresolved], 1);
        assert_eq!(deps.len(), 1, "the sibling dependency still stands");
        assert_eq!(deps[0].id.name(), "fine");

        // One edge of the graph, not the graph: nothing here justifies
        // dropping the artifact or abandoning its other dependencies.
        assert_eq!(ctx.problems().worst(), Some(Action::Warn));
    }

    /// The other half of the same code, and the opposite consequence: the
    /// POM cannot say what artifact it describes, so nothing read out of it
    /// is worth having.
    #[tokio::test]
    async fn pom_own_version_unresolved_refused() {
        let broken = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId>
              <version>${revision}</version>
              <dependencies>
                <dependency>
                  <groupId>g</groupId><artifactId>fine</artifactId>
                  <version>2.0</version>
                </dependency>
              </dependencies>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), broken)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        f.subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect_err("the coordinates do not resolve");

        assert_eq!(ctx.problems().counts()[&Code::PomPropertyUnresolved], 1);
        assert!(ctx.problems().worst().expect("reported").is_failure());
    }

    /// BOMs are fetched and expanded, nested ones too, and a cycle between
    /// them stops rather than recursing. Each imported BOM is a `build`
    /// dependency.
    #[tokio::test]
    async fn bom_imported_supplies_versions() {
        let importing = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <dependencyManagement><dependencies>
                <dependency>
                  <groupId>org.example</groupId><artifactId>bom</artifactId>
                  <version>1.0</version><type>pom</type><scope>import</scope>
                </dependency>
              </dependencies></dependencyManagement>
              <dependencies>
                <dependency><groupId>org.example</groupId><artifactId>shared</artifactId></dependency>
                <dependency><groupId>org.example</groupId><artifactId>deep</artifactId></dependency>
              </dependencies>
            </project>"#;

        // `bom` manages `shared` and imports `nested`, which manages `deep`
        // and imports `bom` back.
        let bom = r#"<project>
              <groupId>org.example</groupId><artifactId>bom</artifactId><version>1.0</version>
              <packaging>pom</packaging>
              <dependencyManagement><dependencies>
                <dependency>
                  <groupId>org.example</groupId><artifactId>nested</artifactId>
                  <version>1.0</version><type>pom</type><scope>import</scope>
                </dependency>
                <dependency>
                  <groupId>org.example</groupId><artifactId>shared</artifactId><version>2.0</version>
                </dependency>
              </dependencies></dependencyManagement>
            </project>"#;

        let nested = r#"<project>
              <groupId>org.example</groupId><artifactId>nested</artifactId><version>1.0</version>
              <packaging>pom</packaging>
              <dependencyManagement><dependencies>
                <dependency>
                  <groupId>org.example</groupId><artifactId>bom</artifactId>
                  <version>1.0</version><type>pom</type><scope>import</scope>
                </dependency>
                <dependency>
                  <groupId>org.example</groupId><artifactId>deep</artifactId><version>3.0</version>
                </dependency>
              </dependencies></dependencyManagement>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), importing)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), "")
                .with_body(format!("{REPO}/org/example/bom/1.0/bom-1.0.pom"), bom)
                .with_body(
                    format!("{REPO}/org/example/nested/1.0/nested-1.0.pom"),
                    nested,
                ),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        let version_of = |name: &str| {
            deps.iter()
                .find(|dep| dep.id.name() == name)
                .map(|dep| dep.spec.clone())
        };

        assert_eq!(version_of("shared"), Some(VersionSpec::Exact("2.0".into())));
        assert_eq!(version_of("deep"), Some(VersionSpec::Exact("3.0".into())));
        assert!(
            deps.iter()
                .any(|dep| dep.kind == DepKind::Build && dep.id.name() == "bom")
        );
        assert!(
            !ctx.problems()
                .counts()
                .contains_key(&Code::DependencyUnresolved)
        );
    }

    /// A parent POM is a `build` dependency.
    #[tokio::test]
    async fn parent_is_build_dependency() {
        let f = fixture();
        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        let parent = deps
            .iter()
            .find(|dep| dep.kind == DepKind::Build)
            .expect("the parent");

        assert_eq!(parent.id.name(), "parent");
        assert_eq!(parent.id.qualifier(TYPE_QUALIFIER), Some("pom"));
        assert_eq!(parent.spec, VersionSpec::Exact("5.0".into()));
    }

    /// A BOM that cannot be read is reported, and still named as a `build`
    /// dependency, since a consumer's build needs it all the same.
    #[tokio::test]
    async fn bom_unexpanded_reported() {
        let importing = r#"<project>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <dependencyManagement><dependencies>
                <dependency>
                  <groupId>org.springframework.boot</groupId>
                  <artifactId>spring-boot-dependencies</artifactId>
                  <version>3.2.0</version><type>pom</type><scope>import</scope>
                </dependency>
              </dependencies></dependencyManagement>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), importing)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        // At least one, for the reason the unreachable-parent test gives:
        // `metadata` and `deps` each walk the chain.
        assert!(ctx.problems().counts()[&Code::DependencyUnresolved] >= 1);
        assert!(
            deps.iter().any(
                |dep| dep.kind == DepKind::Build && dep.id.name() == "spring-boot-dependencies"
            )
        );
    }

    /// A missing parent yields a partial answer plus a problem, rather
    /// than losing the child's own dependencies entirely.
    #[tokio::test]
    async fn parent_unreachable_still_yields_child_dependencies() {
        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/maven-metadata.xml"), METADATA)
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), LIB_POM)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        // Guava's version came from a property in the child itself.
        assert!(deps.iter().any(|dep| dep.id.name() == "guava"));

        // slf4j-api's came from the parent's management, so it is now the
        // one that cannot be resolved -- and says so.
        assert!(!deps.iter().any(|dep| dep.id.name() == "slf4j-api"));
        assert!(ctx.problems().counts()[&Code::DependencyUnresolved] >= 1);
    }

    /// A parent is only ever a means to an end. When everything it would
    /// have supplied resolved anyway, its absence cost nothing, and the run
    /// says so without holding anything back.
    ///
    /// This is why the parent failure is reported at `warn` rather than
    /// weighed: if it *did* cost something, that something is reported at
    /// its own site and its own severity -- a dropped dependency, or a POM
    /// that can no longer name itself. Reporting the cause as well would be
    /// grading the same loss twice.
    #[tokio::test]
    async fn unreachable_parent_that_cost_nothing_is_only_reported() {
        let self_sufficient = r#"<project>
              <parent>
                <groupId>org.example</groupId><artifactId>missing</artifactId>
                <version>9.9</version>
              </parent>
              <groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>
              <properties><guava.version>32.0</guava.version></properties>
              <dependencies>
                <dependency>
                  <groupId>com.google.guava</groupId><artifactId>guava</artifactId>
                  <version>${guava.version}</version>
                </dependency>
              </dependencies>
            </project>"#;

        let f = fixture_from(
            FixtureClient::new()
                .with_body(format!("{DIR}/1.0/lib-1.0.pom"), self_sufficient)
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        let own: Vec<&Dependency> = deps
            .iter()
            .filter(|dep| dep.kind != DepKind::Build)
            .collect();

        assert_eq!(own.len(), 1, "the child stood on its own");

        // At least one, not exactly one: a failed parent fetch is not
        // cached the way a successful one is, so `metadata` and `deps` each
        // walk the chain and each say so. Filed under the double-report
        // defect in `TODO.md`; the claim under test is the action.
        assert!(ctx.problems().counts()[&Code::DependencyUnresolved] >= 1);

        // Reported, and the run carries on: nothing was actually lost.
        assert_eq!(ctx.problems().worst(), Some(Action::Warn));
    }

    /// A `.pom` that is really a zip exists on Central. The bytes are still
    /// copyable, so the artifact survives with its files intact and loses
    /// only what was never readable.
    #[tokio::test]
    async fn pom_unreadable_reported_and_survives() {
        let f = fixture_from(
            FixtureClient::new()
                .with_body(
                    format!("{DIR}/1.0/lib-1.0.pom"),
                    "PK\u{3}\u{4}\u{0}\u{0}binary",
                )
                .with_body(format!("{DIR}/1.0/lib-1.0.jar"), ""),
        );

        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("the artifact still resolves");

        // Still copyable -- which is the whole job.
        let names: Vec<&str> = artifact
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect();
        assert_eq!(names, ["lib-1.0.pom", "lib-1.0.jar"]);

        // But nothing was readable out of it, and that is said out loud.
        assert!(artifact.license.is_none());
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// A POM that names a dependency which does not exist is not an error
    /// here: inspection records the edge, and the missing artifact surfaces
    /// as a not-found when the spider follows it.
    #[tokio::test]
    async fn dependency_absent_still_reported_as_edge() {
        let f = fixture();
        let ctx = ctx();
        let deps = deps_of(&f, &ctx).await;

        // Nothing in the fixture publishes guava, and the edge stands.
        assert!(deps.iter().any(|dep| dep.id.name() == "guava"));
    }
}
