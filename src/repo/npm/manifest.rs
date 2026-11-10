//! The version object an npm target publishes, and where it comes from.
//!
//! A registry stores the version object a publish sends and serves it back
//! as the packument, so it is what an installing client resolves
//! `dependencies`, `optionalDependencies`, `os`, `cpu`, and `bin` from.
//! Measured: Artifact Keeper and Nexus both store it as sent. A minimal
//! object installs the right bytes and none of their dependencies.
//!
//! So the origin's own manifest is sent, from the first of these that
//! answers:
//!
//! ```text
//!   registry  the version document the source staged beside the tarball
//!             ({registry}/{name}/{version}), checked against the tarball
//!   tarball   */package.json inside the staged tarball, read with caps
//!   minimal   name, version, license; reported as upload-metadata-incomplete
//! ```
//!
//! # What is never copied
//!
//! The origin's `dist` names its tarball and its keys: `tarball`,
//! `shasum`, and `integrity` are the target's to state, and `signatures`,
//! `npm-signature`, and `attestations` would fail verification against the
//! mirror. What describes the bytes, such as `fileCount`, stays.
//!
//! # What the registry assigned
//!
//! `_npmUser`, `_npmOperationalInternal`, `_resolved`, and the like are
//! written by the origin registry rather than by the publisher. Dropped by
//! default, since they describe the origin; `registry-fields: keep` keeps
//! them for a mirror that wants the origin's record. `_id`,
//! `_hasShrinkwrap`, `_nodeVersion`, and `_npmVersion` are the publisher's
//! and always stay.

use std::path::Path;

use serde_json::{Map, Value};

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::Code;
use crate::ext::Options;
use crate::message;
use crate::model::{DigestAlg, ResolvedArtifact};
use crate::net::ByteLimit;
use crate::repo::archive::{self, MAX_INFLATED, Wanted};

/// The option choosing [`RegistryFields`].
const REGISTRY_FIELDS_OPTION: &str = "registry-fields";

/// Keys the origin registry writes into a version object.
const REGISTRY_ASSIGNED: [&str; 8] = [
    "_npmUser",
    "_npmOperationalInternal",
    "_resolved",
    "_from",
    "_integrity",
    "_shasum",
    "_rev",
    "_attachments",
];

/// `dist` keys naming the origin's copy or vouching for it with the
/// origin's keys.
const ORIGIN_DIST: [&str; 6] = [
    "tarball",
    "shasum",
    "integrity",
    "signatures",
    "npm-signature",
    "attestations",
];

/// The `dist` key holding an SRI digest.
const INTEGRITY: &str = "integrity";

/// The `dist` key holding a hex sha1.
const SHASUM: &str = "shasum";

/// A version document. The README rides along, so well past a manifest.
const DOCUMENT_LIMIT: ByteLimit = ByteLimit::mib(16);

/// A tarball's `package.json`.
const PACKAGE_JSON_LIMIT: ByteLimit = ByteLimit::mib(1);

/// What an npm tarball is called in errors.
const TARBALL: &str = "npm tarball";

/// The one place a tarball's manifest may be: `package/package.json`, or
/// whatever single directory an old package used instead.
const TARBALL_WANTED: [Wanted; 1] = [Wanted {
    label: "top-level */package.json",
    matches: is_top_level_package_json,
}];

/// The manifest's file name inside its directory.
const PACKAGE_JSON: &str = "/package.json";

/// Scripts that make a registry flag `hasInstallScript`.
const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Whether registry-assigned keys travel with a copied manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistryFields {
    /// Drop them: they describe the origin registry, not the package.
    #[default]
    Drop,

    /// Keep them, for a mirror that wants the origin's record.
    Keep,
}

impl RegistryFields {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "drop" => Some(RegistryFields::Drop),
            "keep" => Some(RegistryFields::Keep),
            _ => None,
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["drop", "keep"]
    }

    /// Read from a target's options, defaulting to [`RegistryFields::Drop`].
    pub fn from_options(options: &Options) -> Result<Self> {
        let Some(named) = options.string(REGISTRY_FIELDS_OPTION)? else {
            return Ok(RegistryFields::default());
        };

        Self::parse(named).ok_or_else(|| {
            Error::Config(format!(
                "{REGISTRY_FIELDS_OPTION} is {named:?}, which is not one of: {known}",
                known = Self::names().join(", "),
            ))
        })
    }
}

/// Where a published manifest came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    Registry,
    Tarball,
    Minimal,
}

/// The version object to publish for `artifact`, less the target's `dist`
/// keys, from the first source in the module's order that answers.
///
/// `staged` is the version document the source staged, if it did. Never
/// fails: each fallback is logged, and the last is reported.
pub(super) fn manifest(
    artifact: &ResolvedArtifact,
    tarball: &Path,
    staged: Option<&Path>,
    fields: RegistryFields,
    ctx: &Ctx,
) -> (Map<String, Value>, Origin) {
    let purl = artifact.purl();

    let Some(staged) = staged else {
        ctx.log().debug(format_args!(
            "{purl}: the source staged no version document; reading the tarball's \
             package.json"
        ));

        return from_tarball_or_minimal(artifact, tarball, fields, &purl, ctx);
    };

    match from_registry(artifact, staged) {
        Ok(manifest) => return (cleaned(manifest, fields), Origin::Registry),

        Err(why) => ctx.log().warn(format_args!(
            "{purl}: the source's version document is not used ({why}); reading the \
             tarball's package.json instead"
        )),
    }

    from_tarball_or_minimal(artifact, tarball, fields, &purl, ctx)
}

/// The tarball's manifest, or the minimal one, reported.
fn from_tarball_or_minimal(
    artifact: &ResolvedArtifact,
    tarball: &Path,
    fields: RegistryFields,
    purl: &str,
    ctx: &Ctx,
) -> (Map<String, Value>, Origin) {
    match from_tarball(artifact, tarball) {
        Ok(manifest) => return (cleaned(manifest, fields), Origin::Tarball),

        Err(why) => ctx.log().warn(format_args!(
            "{purl}: the tarball's package.json is not used ({why})"
        )),
    }

    ctx.report(
        Code::UploadMetadataIncomplete,
        message!(
            "npm-manifest-minimal",
            "{purl} is published with only its name, version, and license: neither \
             the source nor the tarball gave a manifest, so its dependencies are not \
             served by the target",
            purl = purl,
        ),
    );

    (minimal(artifact), Origin::Minimal)
}

/// Name, version, and license: what a registry needs to accept a version.
pub(super) fn minimal(artifact: &ResolvedArtifact) -> Map<String, Value> {
    let mut manifest = Map::new();

    manifest.insert("name".into(), super::package_name(&artifact.id).into());
    manifest.insert("version".into(), version_text(artifact).into());
    manifest.insert("license".into(), artifact.license.clone().into());

    manifest
}

/// The source's version document, checked against the artifact.
fn from_registry(
    artifact: &ResolvedArtifact,
    staged: &Path,
) -> std::result::Result<Map<String, Value>, String> {
    let size = std::fs::metadata(staged)
        .map_err(|err| err.to_string())?
        .len();

    if size > DOCUMENT_LIMIT.get() {
        return Err(format!(
            "it is {size} bytes, more than {}",
            DOCUMENT_LIMIT.get()
        ));
    }

    let text = std::fs::read_to_string(staged).map_err(|err| err.to_string())?;
    let manifest = object(&text)?;

    identified(artifact, &manifest)?;
    matching(artifact, &manifest)?;

    Ok(manifest)
}

/// The tarball's `package.json`, with what a registry adds on publish.
fn from_tarball(
    artifact: &ResolvedArtifact,
    tarball: &Path,
) -> std::result::Result<Map<String, Value>, String> {
    let text = archive::tar_gz(
        tarball,
        TARBALL,
        &TARBALL_WANTED,
        PACKAGE_JSON_LIMIT,
        MAX_INFLATED,
    )
    .map_err(|err| err.to_string())?;
    let mut manifest = object(&text)?;

    identified(artifact, &manifest)?;

    let name = super::package_name(&artifact.id);
    let version = version_text(artifact);

    manifest
        .entry("_id")
        .or_insert_with(|| format!("{name}@{version}").into());

    let installs = manifest
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|scripts| INSTALL_SCRIPTS.iter().any(|key| scripts.contains_key(*key)));

    if installs {
        manifest.entry("hasInstallScript").or_insert(true.into());
    }

    Ok(manifest)
}

fn object(text: &str) -> std::result::Result<Map<String, Value>, String> {
    match serde_json::from_str(text) {
        Ok(Value::Object(manifest)) => Ok(manifest),
        Ok(_) => Err("it is not a JSON object".to_owned()),
        Err(err) => Err(format!("it is not JSON: {err}")),
    }
}

/// Refuse a manifest describing another package or version.
fn identified(
    artifact: &ResolvedArtifact,
    manifest: &Map<String, Value>,
) -> std::result::Result<(), String> {
    let name = super::package_name(&artifact.id);
    let version = version_text(artifact);

    let said = |key: &str| {
        manifest
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };

    if said("name") != name || said("version") != version {
        return Err(format!(
            "it describes {}@{}, not {name}@{version}",
            said("name"),
            said("version")
        ));
    }

    Ok(())
}

/// Refuse a document whose `dist` digests disagree with the tarball's.
fn matching(
    artifact: &ResolvedArtifact,
    manifest: &Map<String, Value>,
) -> std::result::Result<(), String> {
    let Some(dist) = manifest.get("dist").and_then(Value::as_object) else {
        return Ok(());
    };

    let claimed = dist
        .get(INTEGRITY)
        .and_then(Value::as_str)
        .and_then(crate::net::sig::sri_to_digest)
        .into_iter()
        .chain(
            dist.get(SHASUM)
                .and_then(Value::as_str)
                .map(|hex| crate::model::Digest::new(DigestAlg::Sha1, hex)),
        );

    let known = artifact.files.iter().flat_map(|file| &file.digests);

    for digest in claimed {
        let disagrees = known
            .clone()
            .any(|held| held.alg == digest.alg && held.hex != digest.hex);

        if disagrees {
            return Err(format!(
                "its {} digest is not the tarball's",
                digest.alg.as_str()
            ));
        }
    }

    Ok(())
}

/// `manifest` without the origin's `dist` keys, and without registry
/// fields unless kept.
fn cleaned(mut manifest: Map<String, Value>, fields: RegistryFields) -> Map<String, Value> {
    if fields == RegistryFields::Drop {
        for key in REGISTRY_ASSIGNED {
            manifest.remove(key);
        }
    }

    if let Some(Value::Object(dist)) = manifest.get_mut("dist") {
        for key in ORIGIN_DIST {
            dist.remove(key);
        }
    }

    manifest
}

fn version_text(artifact: &ResolvedArtifact) -> &str {
    artifact
        .version
        .as_ref()
        .map_or("", |version| version.text())
}

/// `package/package.json`, and not `package/node_modules/x/package.json`.
fn is_top_level_package_json(name: &str) -> bool {
    name.trim_start_matches("./")
        .strip_suffix(PACKAGE_JSON)
        .is_some_and(|directory| !directory.is_empty() && !directory.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactId, Cause, Digest, EcosystemId, FileRef, Release, Version};

    const SHA1: &str = "a55367ce349940a554fb70443d4109e7a26d8aeb";

    fn artifact() -> ResolvedArtifact {
        let mut file = FileRef::new("echo-1.0.0.tgz", "h://origin.test/echo-1.0.0.tgz");
        file.digests = vec![Digest::new(DigestAlg::Sha1, SHA1)];

        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::npm(), Some("@am-example"), "echo"),
            version: Some(Version::new("1.0.0", Release::General)),
            files: vec![file],
            license: Some("MIT".into()),
            published: None,
        }
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "echo".into() })
    }

    /// A version document as Nexus serves one.
    fn document(shasum: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "@am-example/echo",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": { "left-pad": "^1.3.0" },
            "engines": { "node": ">=18" },
            "_id": "@am-example/echo@1.0.0",
            "_npmUser": { "name": "am-publisher" },
            "dist": {
                "tarball": "h://origin.test/echo-1.0.0.tgz",
                "shasum": shasum,
                "fileCount": 3,
                "signatures": [{ "keyid": "k", "sig": "s" }],
            },
        })
    }

    fn staged(value: &serde_json::Value) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp");
        std::fs::write(file.path(), value.to_string()).expect("written");

        file
    }

    fn tarball(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp");
        let encoder = flate2::write::GzEncoder::new(
            file.reopen().expect("reopen"),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);

        for (name, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            builder
                .append_data(&mut header, name, *body)
                .expect("entry");
        }

        builder
            .into_inner()
            .expect("tar finished")
            .finish()
            .expect("gzip finished");

        file
    }

    fn empty_tarball() -> tempfile::NamedTempFile {
        tarball(&[("package/index.js", b"")])
    }

    #[test]
    fn registry_document_preferred() {
        let staged = staged(&document(SHA1));
        let (manifest, origin) = manifest(
            &artifact(),
            empty_tarball().path(),
            Some(staged.path()),
            RegistryFields::Drop,
            &ctx(),
        );

        assert_eq!(origin, Origin::Registry);
        assert_eq!(manifest["dependencies"]["left-pad"], "^1.3.0");
        assert_eq!(manifest["engines"]["node"], ">=18");
        assert_eq!(manifest["_id"], "@am-example/echo@1.0.0");

        // The origin's registry record and its dist claims are gone; what
        // describes the bytes stays.
        assert!(!manifest.contains_key("_npmUser"));
        assert_eq!(manifest["dist"], serde_json::json!({ "fileCount": 3 }));
    }

    #[test]
    fn registry_fields_may_be_kept() {
        let staged = staged(&document(SHA1));
        let (manifest, _) = manifest(
            &artifact(),
            empty_tarball().path(),
            Some(staged.path()),
            RegistryFields::Keep,
            &ctx(),
        );

        assert_eq!(manifest["_npmUser"]["name"], "am-publisher");
        assert!(
            !manifest["dist"]
                .as_object()
                .expect("dist")
                .contains_key("signatures")
        );
    }

    /// A document for other bytes is not this tarball's manifest.
    #[test]
    fn document_mismatched_falls_back_to_tarball() {
        let staged = staged(&document("0000000000000000000000000000000000000000"));
        let tarball = tarball(&[(
            "package/package.json",
            br#"{"name":"@am-example/echo","version":"1.0.0","scripts":{"postinstall":"x"}}"#,
        )]);

        let (manifest, origin) = manifest(
            &artifact(),
            tarball.path(),
            Some(staged.path()),
            RegistryFields::Drop,
            &ctx(),
        );

        assert_eq!(origin, Origin::Tarball);
        assert_eq!(manifest["_id"], "@am-example/echo@1.0.0");
        assert_eq!(manifest["hasInstallScript"], true);
    }

    #[test]
    fn document_other_package_refused() {
        let mut other = document(SHA1);
        other["version"] = "2.0.0".into();

        assert!(from_registry(&artifact(), staged(&other).path()).is_err());
    }

    /// An old package's directory need not be `package/`.
    #[test]
    fn tarball_directory_may_be_named_otherwise() {
        let tarball = tarball(&[
            (
                "node/package.json",
                br#"{"name":"@am-example/echo","version":"1.0.0"}"#,
            ),
            ("node/node_modules/x/package.json", br#"{"name":"x"}"#),
        ]);

        assert!(from_tarball(&artifact(), tarball.path()).is_ok());
    }

    #[test]
    fn tarball_two_manifests_refused() {
        let tarball = tarball(&[
            (
                "a/package.json",
                br#"{"name":"@am-example/echo","version":"1.0.0"}"#,
            ),
            (
                "b/package.json",
                br#"{"name":"@am-example/echo","version":"1.0.0"}"#,
            ),
        ]);

        assert!(from_tarball(&artifact(), tarball.path()).is_err());
    }

    #[test]
    fn nothing_readable_publishes_minimal_and_reports() {
        let ctx = ctx();
        let corrupt = tempfile::NamedTempFile::new().expect("temp");
        std::fs::write(corrupt.path(), b"not a tarball").expect("written");

        let (manifest, origin) = manifest(
            &artifact(),
            corrupt.path(),
            None,
            RegistryFields::Drop,
            &ctx,
        );

        assert_eq!(origin, Origin::Minimal);
        assert_eq!(manifest["name"], "@am-example/echo");
        assert_eq!(manifest["license"], "MIT");
        assert_eq!(ctx.problems().counts()[&Code::UploadMetadataIncomplete], 1);
    }

    #[test]
    fn registry_fields_option() {
        let options = |value: serde_json::Value| {
            crate::ext::testing::options(serde_json::json!({ REGISTRY_FIELDS_OPTION: value }))
        };

        assert_eq!(
            RegistryFields::from_options(&Options::default()).expect("default"),
            RegistryFields::Drop
        );
        assert_eq!(
            RegistryFields::from_options(&options("keep".into())).expect("keep"),
            RegistryFields::Keep
        );
        assert!(RegistryFields::from_options(&options("sometimes".into())).is_err());
    }
}
