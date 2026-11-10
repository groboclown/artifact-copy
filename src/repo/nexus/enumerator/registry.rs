//! Reading a registry format's components: Maven, npm, and PyPI.

use crate::core::ctx::Ctx;
use crate::core::problem::Code;
use crate::message;
use crate::model::{ArtifactId, EcosystemId};
use crate::repo::enumerate::Found;

use super::NexusEnumerator;
use super::component::Component;

/// What ends an npm tarball's file name: `{name}-{version}.tgz`.
const NPM_TARBALL_SUFFIX: &str = ".tgz";

/// Nexus format names, which are not the purl types.
///
/// `maven2` is the one that actually differs; the others happen to
/// coincide, which is exactly the kind of coincidence that turns into a
/// bug when a sixth format is added and nobody notices the mapping was
/// implicit.
///
/// **Both `maven` and `maven2` are accepted.** Old Nexus servers use `maven2`,
/// and newer ones use `maven`.
fn ecosystem_of(format: &str) -> Option<EcosystemId> {
    match format {
        "maven" | "maven2" => Some(EcosystemId::maven()),
        "npm" => Some(EcosystemId::npm()),
        "pypi" => Some(EcosystemId::pypi()),
        "raw" => Some(EcosystemId::raw()),
        _ => None,
    }
}

/// The version an npm component's tarball names, if any asset is one.
///
/// `unicode-17.0.0/-/unicode-17.0.0-1.6.16.tgz` names `1.6.16`. `name` is
/// unscoped, as is the tarball's file name.
fn npm_version(component: &Component) -> Option<&str> {
    let prefix = format!("{}-", component.name);

    component
        .paths()
        .find_map(|path| {
            let file = path.rsplit('/').next()?;

            file.strip_prefix(prefix.as_str())?
                .strip_suffix(NPM_TARBALL_SUFFIX)
        })
        .filter(|version| !version.is_empty())
}

impl NexusEnumerator {
    /// A registry format's component as its artifact.
    pub(super) fn registry_found(&self, component: &Component, ctx: &Ctx) -> Option<Found> {
        // A component's own format is believed over the configured
        // ecosystem, because a group repository can aggregate several and
        // resolving a Maven coordinate against semver rules would produce a
        // plausible-looking wrong answer.
        if let Some(format) = &component.format
            && let Some(actual) = ecosystem_of(format)
            && actual != self.ecosystem
        {
            ctx.report(
                Code::MetadataMalformed,
                message!(
                    "nexus-unexpected-format",
                    "{repository} returned a {format} component while configured as \
                     {declared}; it is skipped",
                    repository = &self.repository,
                    format = format,
                    declared = &self.ecosystem,
                ),
            );

            return None;
        }

        let id = self.identify(component);
        let mut found = Found::new(id)
            .last_download(component.last_download())
            .files(self.listed(component));

        // An empty version is no version. Nexus sends `null` on one server
        // and `""` on another for the same absent field -- both measured --
        // and a `Version` whose text is empty would be written to the
        // report as a version that is blank rather than absent.
        if let Some(version) = self.version_of(component, ctx) {
            // Release status is the ecosystem's judgment, not this
            // enumerator's: `1.0-rc1` is a pre-release in Maven and
            // `31.1-jre` is not, and neither is knowable from the string
            // alone without Maven's rules.
            found = found.version(self.classify(&version));
        }

        Some(found)
    }

    /// The component's version, corrected from its npm tarball name.
    ///
    /// Nexus misreads a package named like a version: it lists
    /// `unicode-17.0.0-1.6.16.tgz` at `17.0.0-1.6.16` rather than `1.6.16`.
    /// The tarball is `{name}-{version}.tgz`, so it is believed instead.
    fn version_of(&self, component: &Component, ctx: &Ctx) -> Option<String> {
        let listed = component.version.as_deref().filter(|text| !text.is_empty());
        if self.ecosystem.as_str() != EcosystemId::NPM {
            return listed.map(str::to_owned);
        }

        let (Some(listed), Some(derived)) = (listed, npm_version(component)) else {
            return listed.map(str::to_owned);
        };
        if listed == derived {
            return Some(listed.to_owned());
        }

        ctx.report(
            Code::MetadataMalformed,
            message!(
                "nexus-npm-version-mismatch",
                "{repository} lists {name} at version {listed}, but its tarball \
                 names {derived}; the tarball is believed",
                repository = &self.repository,
                name = &component.name,
                listed = listed,
                derived = derived,
            ),
        );

        Some(derived.to_owned())
    }

    /// Build the coordinate, which is spelled differently per ecosystem.
    fn identify(&self, component: &Component) -> ArtifactId {
        let group = component.group.as_deref().filter(|text| !text.is_empty());

        match self.ecosystem.as_str() {
            // Nexus stores an npm scope in `group`, without its `@`.
            EcosystemId::NPM => {
                let scope = group.map(|scope| format!("@{}", scope.trim_start_matches('@')));

                ArtifactId::new(self.ecosystem.clone(), scope.as_deref(), &component.name)
            }

            // PyPI has no namespace at all; a group here would be noise.
            EcosystemId::PYPI => ArtifactId::new(self.ecosystem.clone(), None, &component.name),

            // Maven, and anything else that uses a namespace as written.
            // Raw never reaches here -- it is answered by `raw_id`, from
            // the asset path.
            _ => ArtifactId::new(self.ecosystem.clone(), group, &component.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::repo::nexus::enumerator::testing::*;

    /// Nexus stores an npm scope in `group`, without its `@`.
    #[tokio::test]
    async fn npm_scope_restored() {
        let body = r#"{"items": [
            {"format": "npm", "group": "angular", "name": "core", "version": "17.0.0"},
            {"format": "npm", "name": "lodash", "version": "4.17.21"}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "npm", &ctx).await;

        assert_eq!(page.found[0].id.purl(), "pkg:npm/%40angular/core");
        assert_eq!(page.found[1].id.purl(), "pkg:npm/lodash");
    }

    /// **Each version is its own artifact.** Nexus lists one component per
    /// npm version, and folding them by package gave one artifact ten
    /// tarballs, which npm cannot publish.
    #[tokio::test]
    async fn npm_versions_stay_apart() {
        let body = r#"{"items": [
            {"format": "npm", "group": "z", "name": "ui", "version": "1.0.0",
             "assets": [{"path": "@z/ui/-/ui-1.0.0.tgz",
                         "downloadUrl": "h://nexus.test/@z/ui/-/ui-1.0.0.tgz"}]},
            {"format": "npm", "group": "z", "name": "ui", "version": "1.0.1",
             "assets": [{"path": "@z/ui/-/ui-1.0.1.tgz",
                         "downloadUrl": "h://nexus.test/@z/ui/-/ui-1.0.1.tgz"}]}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "npm", &ctx).await;

        let found: Vec<(&str, Vec<&str>)> = page
            .found
            .iter()
            .map(|one| {
                let version = one.version.as_ref().expect("versioned").text();
                let files = one.files.iter().map(|file| file.name.as_str()).collect();

                (version, files)
            })
            .collect();

        assert_eq!(
            found,
            [
                ("1.0.0", vec!["ui-1.0.0.tgz"]),
                ("1.0.1", vec!["ui-1.0.1.tgz"])
            ]
        );
    }

    /// Nexus lists a package named like a version at `{suffix}-{version}`;
    /// the tarball name holds the real one.
    #[tokio::test]
    async fn npm_version_from_tarball() {
        let body = r#"{"items": [
            {"format": "npm", "group": "unicode", "name": "unicode-17.0.0",
             "version": "17.0.0-1.6.16",
             "assets": [{"path": "@unicode/unicode-17.0.0/-/unicode-17.0.0-1.6.16.tgz",
                         "downloadUrl": "h://nexus.test/@unicode/unicode-17.0.0/-/unicode-17.0.0-1.6.16.tgz"}]}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "npm", &ctx).await;

        assert_eq!(
            page.found[0].version.as_ref().expect("versioned").text(),
            "1.6.16"
        );
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// A version the tarball agrees with is taken without complaint.
    #[tokio::test]
    async fn npm_version_matching_silent() {
        let body = r#"{"items": [
            {"format": "npm", "group": "z", "name": "ui", "version": "1.0.0",
             "assets": [{"path": "@z/ui/-/ui-1.0.0.tgz",
                         "downloadUrl": "h://nexus.test/@z/ui/-/ui-1.0.0.tgz"}]}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "npm", &ctx).await;

        assert_eq!(
            page.found[0].version.as_ref().expect("versioned").text(),
            "1.0.0"
        );
        assert!(ctx.problems().counts().is_empty());
    }

    /// PyPI has no namespace, so a group would be noise in the purl.
    #[tokio::test]
    async fn pypi_has_no_namespace() {
        let body = r#"{"items": [
            {"format": "pypi", "group": "ignored", "name": "requests", "version": "2.31.0"}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "pypi", &ctx).await;

        assert_eq!(page.found[0].id.purl(), "pkg:pypi/requests");
    }

    /// A group repository can aggregate formats. Resolving a Maven
    /// coordinate against semver rules would give a plausible wrong answer,
    /// so a mismatch is skipped and named rather than guessed at.
    #[tokio::test]
    async fn format_other_skipped_reported() {
        let body = r#"{"items": [
            {"format": "npm", "name": "lodash", "version": "4.17.21"},
            {"format": "maven2", "group": "g", "name": "a", "version": "1.0"}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "maven", &ctx).await;

        assert_eq!(page.found.len(), 1);
        assert_eq!(page.found[0].id.name(), "a");
        assert_eq!(ctx.problems().counts()[&Code::MetadataMalformed], 1);
    }

    /// A format Nexus knows and this tool does not is left to the declared
    /// ecosystem rather than dropped: the coordinate may still be usable.
    ///
    /// `nuget` rather than `raw`, which this enumerator now reads: the example
    /// has to be a format the mapping genuinely does not know, or the test
    /// would pass for the wrong reason.
    #[tokio::test]
    async fn format_unrecognized_falls_back_to_declaration() {
        let body = r#"{"items": [
            {"format": "nuget", "group": "g", "name": "a", "version": "1.0"}
        ]}"#;

        let ctx = ctx();
        let (page, _) = walk_with(body, "maven", &ctx).await;

        assert_eq!(page.found.len(), 1);
    }

    #[test]
    fn format_names_map_to_purl_types() {
        // Maven is the one that differs; the rest coincide, which is the
        // kind of coincidence that becomes a bug when a format is added.
        assert_eq!(ecosystem_of("npm"), Some(EcosystemId::npm()));
        assert_eq!(ecosystem_of("pypi"), Some(EcosystemId::pypi()));
        assert_eq!(ecosystem_of("raw"), Some(EcosystemId::raw()));

        // Both Maven spellings, because both are in the field: older Nexus
        // servers say `maven2` and newer ones say `maven`. Reading only one
        // would skip every Maven component on half the servers there are.
        assert_eq!(ecosystem_of("maven2"), Some(EcosystemId::maven()));
        assert_eq!(ecosystem_of("maven"), Some(EcosystemId::maven()));

        // Still nothing: a format this tool cannot read a coordinate out
        // of is left to the declared ecosystem rather than guessed at.
        assert_eq!(ecosystem_of("nuget"), None);
    }
}
