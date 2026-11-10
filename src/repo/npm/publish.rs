//! Building an npm publish document.
//!
//! npm's publish endpoint takes a `PUT` of one JSON document describing the
//! package, the version being added, and the **tarball itself** -- base64
//! inside the JSON:
//!
//! ```text
//!   { "_id": "tuna", "name": "tuna",
//!     "dist-tags": { "latest": "1.2.0" },
//!     "versions": { "1.2.0": { ..., "dist": { "tarball": ..., "shasum": ... } } },
//!     "_attachments": { "tuna-1.2.0.tgz": { "data": "<base64>", ... } } }
//! ```
//!
//! # Why it is written to a file
//!
//! That document is bigger than the artifact: base64 costs a third on top.
//! Holding it as a `String` would mean a 400 MB allocation to publish a
//! 300 MB package, and the whole design exists to avoid exactly that -- see
//! [`Req::body`](crate::net::Req::body), which is documented as bounded by
//! construction precisely because uploads do not go through it.
//!
//! So this streams: a JSON prefix, then the tarball base64-encoded as it is
//! read, then the suffix. Memory stays at one buffer whatever the package
//! weighs. A temporary file holds the document until the upload finishes.
//!
//! # The version object is the manifest
//!
//! A registry stores the version object it is sent and serves it back as
//! the packument, so its `dependencies`, `engines`, and `bin` are what an
//! installing client sees. Which manifest is sent, and where it came from,
//! is [`super::manifest`]'s; this writes it with the target's own `dist`.

use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::core::error::{Error, Result};
use crate::model::{DigestAlg, ResolvedArtifact};

/// Digests an `integrity` may state, strongest first.
const INTEGRITY_ALGS: [DigestAlg; 2] = [DigestAlg::Sha512, DigestAlg::Sha256];

/// How much of the tarball is read at a time while encoding.
///
/// The one buffer this holds. Large enough that the syscall overhead is
/// irrelevant, small enough to be nothing next to a registry response.
const CHUNK: usize = 64 * 1024;

/// The dist-tag a published version is filed under.
///
/// npm requires at least one, and `latest` is what `npm publish` sets.
///
/// **Which version it names is decided by the caller**, not by the version
/// being published -- see [`NpmTarget::latest_after`](super::NpmTarget). A
/// registry takes the tag as given, so publishing each version under its
/// own would leave a mirror's `latest` on whichever upload finished last.
const DIST_TAG: &str = "latest";

/// Write the publish document for one artifact into a temporary file.
///
/// `tarball` is the payload, and `manifest` the version object to publish
/// for it, less any `dist` naming the origin's tarball. `latest` is what
/// the package's `latest` tag should name **after** this publish -- not
/// always the version being published, and `None` to send no `dist-tags`
/// at all. Returns the document, for the caller to upload; it is removed
/// when dropped.
pub(super) fn document(
    artifact: &ResolvedArtifact,
    tarball: &std::path::Path,
    tarball_url: &str,
    manifest: serde_json::Map<String, serde_json::Value>,
    latest: Option<&str>,
) -> Result<tempfile::NamedTempFile> {
    let name = super::package_name(&artifact.id);

    // An npm publish document is keyed by version at three levels, so there
    // is nothing to write without one. Refused rather than defaulted: a
    // `publish-lodash-.json` holding a `""` key would be accepted by the
    // registry and then be unfindable.
    let version = crate::repo::version_required(&artifact.id, artifact.version.as_ref())?.text();

    let into = crate::net::files::temporary()?;
    let path = into.path().to_path_buf();

    let source = std::fs::File::open(tarball).map_err(|source| Error::ReadFile {
        path: tarball.to_path_buf(),
        source,
    })?;

    let length = source
        .metadata()
        .map_err(|source| Error::ReadFile {
            path: tarball.to_path_buf(),
            source,
        })?
        .len();

    let mut out = std::io::BufWriter::new(into.reopen().map_err(|source| Error::WriteFile {
        path: path.clone(),
        source,
    })?);

    let attachment = format!("{name}-{version}.tgz");

    // The manifest's own `dist` keeps what describes the bytes, such as
    // `fileCount`; what names where they are and how to check them is the
    // target's.
    let mut entry = manifest;
    let dist = entry
        .entry("dist")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    // A digest the artifact does not carry is left out rather than sent
    // as `null`, which a registry stores and a client then has to read.
    if let serde_json::Value::Object(dist) = dist {
        dist.insert("tarball".into(), tarball_url.into());

        if let Some(shasum) = digest(artifact, DigestAlg::Sha1) {
            dist.insert("shasum".into(), shasum.into());
        }

        if let Some(integrity) = integrity(artifact) {
            dist.insert("integrity".into(), integrity.into());
        }
    }

    // Built as one value and serialized, because everything before the
    // tarball is small and getting the escaping right by hand is how a
    // publish document ends up subtly malformed.
    let mut prefix = serde_json::json!({
        "_id": name,
        "name": name,
        "versions": { version: entry },
    });

    // Added rather than always present: `dist-tags` is repository state,
    // and a publish that omits it leaves the target's own answer alone.
    if let Some(latest) = latest {
        prefix["dist-tags"] = serde_json::json!({ DIST_TAG: latest });
    }

    let mut prefix = serde_json::to_string(&prefix).map_err(|source| {
        Error::Config(format!("cannot build an npm publish document: {source}"))
    })?;

    // Spliced rather than serialized with the rest: the attachment's `data`
    // is the tarball, and serializing it would mean holding the encoded
    // copy in memory, which is the one thing this exists to avoid.
    prefix.pop();

    let written = write!(
        out,
        r#"{prefix},"_attachments":{{{}:{{"content_type":"application/octet-stream","length":{length},"data":""#,
        serde_json::Value::String(attachment)
    );

    written
        .and_then(|()| encode(source, &mut out))
        .and_then(|()| {
            out.write_all(br#""}}}"#)?;
            out.flush()
        })
        .map_err(|source| Error::WriteFile {
            path: path.clone(),
            source,
        })?;

    Ok(into)
}

/// Copy the tarball into the writer, base64-encoded.
///
/// Through [`base64::write::EncoderWriter`] rather than chunk-by-chunk by
/// hand: base64 encodes three bytes at a time, so a naive per-chunk encode
/// pads every chunk and produces a string no decoder accepts.
fn encode(mut source: std::fs::File, out: &mut impl Write) -> std::io::Result<()> {
    let mut encoder = base64::write::EncoderWriter::new(out, &BASE64);
    let mut buffer = vec![0u8; CHUNK];

    loop {
        let read = std::io::Read::read(&mut source, &mut buffer)?;

        if read == 0 {
            break;
        }

        encoder.write_all(&buffer[..read])?;
    }

    // Flushes the trailing partial group and its padding. Dropping the
    // encoder would do it too and swallow the error.
    encoder.finish()?;

    Ok(())
}

/// One digest of the artifact's payload, hex, if it declared one.
fn digest(artifact: &ResolvedArtifact, alg: DigestAlg) -> Option<String> {
    artifact
        .files
        .iter()
        .flat_map(|file| &file.digests)
        .find(|digest| digest.alg == alg)
        .map(|digest| digest.hex.clone())
}

/// The `integrity` string npm expects: `sha512-<base64 of the raw digest>`,
/// or `sha256-` for a tarball only that is known by, as one read from
/// Artifact Keeper is.
///
/// Rebuilt from the hex rather than carried, because a `Digest` is stored
/// hex everywhere else in this tool and one representation is enough.
fn integrity(artifact: &ResolvedArtifact) -> Option<String> {
    let (alg, hex) = INTEGRITY_ALGS
        .iter()
        .find_map(|alg| Some((*alg, digest(artifact, *alg)?)))?;

    let raw: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect();

    Some(format!("{}-{}", alg.as_str(), BASE64.encode(raw?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArtifactId, Digest, EcosystemId, FileRef, Release, Version};

    fn artifact(digests: Vec<Digest>) -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::npm(), Some("@acme"), "tuna"),
            version: Some(Version::new("1.2.0", Release::General)),
            files: vec![FileRef {
                name: "tuna-1.2.0.tgz".into(),
                url: "h://registry.test/tuna/-/tuna-1.2.0.tgz".into(),
                size: None,
                digests,
                signatures: Vec::new(),
                core_metadata: None,
            }],
            license: Some("MIT".into()),
            published: None,
        }
    }

    /// Write `bytes` as a tarball and build the document around it.
    fn built(bytes: &[u8], digests: Vec<Digest>) -> (tempfile::TempDir, serde_json::Value) {
        let dir = tempfile::tempdir().expect("tempdir");
        let tarball = dir.path().join("tuna-1.2.0.tgz");

        std::fs::write(&tarball, bytes).expect("written");

        let artifact = artifact(digests);
        let document = document(
            &artifact,
            &tarball,
            "h://mirror.test/@acme/tuna/-/tuna-1.2.0.tgz",
            super::super::manifest::minimal(&artifact),
            Some("1.2.0"),
        )
        .expect("built");

        let text = std::fs::read_to_string(document.path()).expect("readable");

        (dir, serde_json::from_str(&text).expect("valid JSON"))
    }

    /// The document is JSON, and the shape npm's endpoint expects.
    #[test]
    fn document_has_npm_shape() {
        let (_dir, doc) = built(b"tarball bytes", Vec::new());

        assert_eq!(doc["name"], "@acme/tuna");
        assert_eq!(doc["_id"], "@acme/tuna");
        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(doc["versions"]["1.2.0"]["version"], "1.2.0");
        assert_eq!(doc["versions"]["1.2.0"]["license"], "MIT");
        assert_eq!(
            doc["versions"]["1.2.0"]["dist"]["tarball"],
            "h://mirror.test/@acme/tuna/-/tuna-1.2.0.tgz"
        );
        assert_eq!(doc["_attachments"]["@acme/tuna-1.2.0.tgz"]["length"], 13);
    }

    /// The tarball survives the round trip. The attachment is spliced in
    /// rather than serialized, so this is the assertion that the splice is
    /// correct -- a document that parses but decodes to the wrong bytes
    /// would publish a corrupt package.
    #[test]
    fn tarball_round_trips_through_base64() {
        let payload = b"not really a tarball, but bytes all the same";
        let (_dir, doc) = built(payload, Vec::new());

        let data = doc["_attachments"]["@acme/tuna-1.2.0.tgz"]["data"]
            .as_str()
            .expect("a base64 string");

        assert_eq!(BASE64.decode(data).expect("decodes"), payload);
    }

    /// Encoding is streamed in 64 KiB chunks, and base64 works three bytes
    /// at a time -- so a payload that straddles chunk boundaries at a
    /// non-multiple of three is exactly where a naive per-chunk encode
    /// produces padding mid-string and a document nothing can decode.
    #[test]
    fn tarball_larger_than_chunk_still_decodes() {
        let payload: Vec<u8> = (0..(CHUNK * 2 + 7)).map(|at| (at % 251) as u8).collect();
        let (_dir, doc) = built(&payload, Vec::new());

        let data = doc["_attachments"]["@acme/tuna-1.2.0.tgz"]["data"]
            .as_str()
            .expect("a base64 string");

        assert_eq!(BASE64.decode(data).expect("decodes"), payload);
        assert_eq!(
            doc["_attachments"]["@acme/tuna-1.2.0.tgz"]["length"],
            payload.len()
        );
    }

    /// A tarball known only by sha256 still gets an `integrity`, and a
    /// digest it lacks is absent rather than `null`.
    #[test]
    fn integrity_falls_back_to_sha256() {
        let (_dir, doc) = built(
            b"x",
            vec![Digest {
                alg: DigestAlg::Sha256,
                hex: "ab".repeat(32),
            }],
        );
        let dist = &doc["versions"]["1.2.0"]["dist"];

        assert!(
            dist["integrity"]
                .as_str()
                .expect("integrity")
                .starts_with("sha256-")
        );
        assert!(dist.get("shasum").is_none());
    }

    /// npm reads integrity as `sha512-<base64 of the raw digest>`, not of
    /// the hex -- encoding the hex would be a string npm rejects.
    #[test]
    fn integrity_is_base64_of_raw_digest() {
        let hex = "ab".repeat(64);
        let (_dir, doc) = built(
            b"x",
            vec![
                Digest {
                    alg: DigestAlg::Sha512,
                    hex: hex.clone(),
                },
                Digest {
                    alg: DigestAlg::Sha1,
                    hex: "cd".repeat(20),
                },
            ],
        );

        let integrity = doc["versions"]["1.2.0"]["dist"]["integrity"]
            .as_str()
            .expect("an integrity string");

        let encoded = integrity
            .strip_prefix("sha512-")
            .expect("the sha512 prefix");

        assert_eq!(BASE64.decode(encoded).expect("decodes"), vec![0xab; 64]);
        assert_eq!(doc["versions"]["1.2.0"]["dist"]["shasum"], "cd".repeat(20));
    }

    /// A registry that declared no digests still gets a usable document;
    /// the fields are absent rather than empty strings, which npm would
    /// take as a claim that the digest *is* the empty string.
    #[test]
    fn digests_missing_absent_not_empty() {
        let (_dir, doc) = built(b"x", Vec::new());
        let dist = &doc["versions"]["1.2.0"]["dist"];

        assert!(dist["shasum"].is_null());
        assert!(dist["integrity"].is_null());
    }
}
