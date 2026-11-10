//! Artifact identity, the files that make one up, and how they are verified.

use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EcosystemId, Provenance, Version, VersionSpec};
use crate::core::error::Result;
use crate::internal::purl;

/// An artifact's identity, without a version.
///
/// Shaped to render as a purl, because that is how both policy files key
/// artifacts.  `namespace` is the Maven groupId or the npm scope; PyPI has
/// none.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId {
    ecosystem: EcosystemId,
    namespace: Option<String>,
    name: String,

    /// Purl qualifiers, sorted so the rendering is stable.  Maven uses
    /// `type` and `classifier`; PyPI uses `file_name`.
    qualifiers: Vec<(String, String)>,
}

impl ArtifactId {
    pub fn new(ecosystem: EcosystemId, namespace: Option<&str>, name: &str) -> Self {
        Self {
            ecosystem,
            namespace: namespace.map(str::to_owned),
            name: name.to_owned(),
            qualifiers: Vec::new(),
        }
    }

    /// Add a purl qualifier.  Replaces any existing value for the key.
    pub fn with_qualifier(mut self, key: &str, value: &str) -> Self {
        self.qualifiers.retain(|(k, _)| k != key);
        self.qualifiers.push((key.to_owned(), value.to_owned()));
        self.qualifiers.sort();

        self
    }

    pub fn ecosystem(&self) -> &EcosystemId {
        &self.ecosystem
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The purl qualifiers, in the sorted order the rendering uses.
    pub fn qualifiers(&self) -> &[(String, String)] {
        &self.qualifiers
    }

    pub fn qualifier(&self, key: &str) -> Option<&str> {
        self.qualifiers
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Versionless purl, e.g. `pkg:maven/org.apache.commons/commons-lang3`.
    pub fn purl(&self) -> String {
        purl::render(
            self.ecosystem.as_str(),
            self.namespace.as_deref(),
            &self.name,
            &self.qualifiers,
            None,
        )
    }

    /// Purl for one exact version.
    ///
    /// The version belongs between the name and the qualifiers --
    /// `pkg:type/ns/name@version?k=v` -- so this cannot be built by
    /// appending to [`ArtifactId::purl`], which has already emitted the
    /// qualifiers.
    pub fn purl_at(&self, version: &str) -> String {
        purl::render(
            self.ecosystem.as_str(),
            self.namespace.as_deref(),
            &self.name,
            &self.qualifiers,
            Some(version),
        )
    }

    /// Read a purl back into an identity and the version it carried.
    ///
    /// The inverse of [`ArtifactId::purl`] and [`ArtifactId::purl_at`], and
    /// it exists because a report database stores what those render: every
    /// question worth asking of an inventory is a question about one piece,
    /// and a row cannot be filtered on a piece it does not hold.
    ///
    /// **The version comes back separately**, because an `ArtifactId` holds
    /// none. A purl with no `@` answers `None`, which is the honest reading
    /// of a catalog that lists names only.
    pub fn parse(text: &str) -> Result<ParsedPurl> {
        let parts = purl::parse(text)?;

        let mut id = Self::new(
            EcosystemId::new(parts.ecosystem),
            parts.namespace.as_deref(),
            &parts.name,
        );

        for (key, value) in &parts.qualifiers {
            id = id.with_qualifier(key, value);
        }

        Ok(ParsedPurl {
            id,
            version: parts.version,
        })
    }
}

/// An [`ArtifactId`] read back out of a purl, and the version the purl
/// carried when it named one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPurl {
    pub id: ArtifactId,
    pub version: Option<String>,
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.purl())
    }
}

/// One artifact the user or the spider asked for.
#[derive(Debug, Clone)]
pub struct ArtifactRequest {
    pub id: ArtifactId,
    pub spec: VersionSpec,
    pub prov: Arc<Provenance>,
}

/// A checksum algorithm.
///
/// Ordered weakest to strongest so `max()` picks the best one a registry
/// offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlg {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl DigestAlg {
    /// Whether finding a second input with this digest is still infeasible.
    ///
    /// MD5 and SHA-1 are not: both have practical collisions, so a digest
    /// in either proves the bytes are *a* file somebody could have
    /// produced, not that they are the file that was published. They are
    /// still worth checking -- an accidental truncation trips them -- which
    /// is why they are recorded rather than ignored, and why
    /// `Verification` has a name for the difference.
    pub fn is_collision_resistant(self) -> bool {
        match self {
            DigestAlg::Md5 | DigestAlg::Sha1 => false,
            DigestAlg::Sha256 | DigestAlg::Sha512 => true,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DigestAlg::Md5 => "md5",
            DigestAlg::Sha1 => "sha1",
            DigestAlg::Sha256 => "sha256",
            DigestAlg::Sha512 => "sha512",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "md5" => Some(DigestAlg::Md5),
            "sha1" => Some(DigestAlg::Sha1),
            "sha256" => Some(DigestAlg::Sha256),
            "sha512" => Some(DigestAlg::Sha512),
            _ => None,
        }
    }

    /// Whether this is strong enough to rely on for integrity.
    ///
    /// MD5 and SHA-1 are both collision-broken; a file with only those is
    /// reported as weakly verified rather than treated as unverified.
    pub fn is_strong(self) -> bool {
        self >= DigestAlg::Sha256
    }
}

impl fmt::Display for DigestAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An expected checksum, lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    pub alg: DigestAlg,
    pub hex: String,
}

impl Digest {
    pub fn new(alg: DigestAlg, hex: impl Into<String>) -> Self {
        Self {
            alg,
            hex: hex.into().to_ascii_lowercase(),
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.alg, self.hex)
    }
}

/// How a signature was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigScheme {
    /// npm registry ECDSA P-256 over `{name}@{version}:{integrity}`.
    /// Verifiable from packument metadata alone, without the tarball.
    NpmEcdsa,

    /// Maven detached PGP in a sibling `.asc`.  Needs the payload.
    PgpDetached,

    /// PyPI PEP 740 attestation, at the provenance URL the index names.
    /// Verified once the file is staged; see `repo::pypi::attestation`.
    PypiAttestation,
}

/// A signature a registry declared for a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SigRef {
    pub scheme: SigScheme,

    /// Key identifier, where the scheme has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// The signature itself, or the URL it lives at for detached schemes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// One downloadable file belonging to an artifact.
#[derive(Debug, Clone)]
pub struct FileRef {
    pub name: String,
    pub url: String,
    pub size: Option<u64>,
    pub digests: Vec<Digest>,
    pub signatures: Vec<SigRef>,

    /// A core-metadata document beside this file, at `{url}.metadata`
    /// (PEP 658), with the digests the index published for it.
    ///
    /// `None` when the source says nothing of one. `Some` with no digests
    /// when it says one exists and gives no hash to check it against.
    pub core_metadata: Option<Vec<Digest>>,
}

impl FileRef {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            size: None,
            digests: Vec::new(),
            signatures: Vec::new(),
            core_metadata: None,
        }
    }

    /// The strongest digest declared, if any.
    pub fn best_digest(&self) -> Option<&Digest> {
        self.digests.iter().max_by_key(|d| d.alg)
    }

    /// Whether any declared digest is collision-resistant.
    pub fn has_strong_digest(&self) -> bool {
        self.digests.iter().any(|d| d.alg.is_strong())
    }
}

#[cfg(test)]
mod purl_tests {
    use super::*;

    /// The encoding rules live with the mechanics in
    /// [`crate::internal::purl`], and so do their tests. What is here is
    /// what an `ArtifactId` adds on top: that its pieces survive a round
    /// trip, and that one identity has exactly one rendering.
    fn round_trip(id: &ArtifactId, version: Option<&str>) {
        let rendered = match version {
            Some(version) => id.purl_at(version),
            None => id.purl(),
        };

        let back = ArtifactId::parse(&rendered).expect(&rendered);

        assert_eq!(&back.id, id, "{rendered}");
        assert_eq!(back.version.as_deref(), version, "{rendered}");
    }

    #[test]
    fn purl_rendered_comes_back() {
        let cases: Vec<ArtifactId> = vec![
            ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib"),
            ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
                .with_qualifier("type", "jar")
                .with_qualifier("classifier", "sources"),
            ArtifactId::new(EcosystemId::npm(), None, "lodash"),
            // An npm scope keeps its `@`, which the rendering escapes.
            ArtifactId::new(EcosystemId::npm(), Some("@angular"), "core"),
            ArtifactId::new(EcosystemId::pypi(), None, "requests")
                .with_qualifier("file_name", "requests-2.31.0-py3-none-any.whl"),
            // A namespace of several segments, whose separators are
            // structure rather than characters to escape.
            ArtifactId::new(
                EcosystemId::new("golang"),
                Some("github.com/someuser"),
                "pkg",
            ),
        ];

        for id in &cases {
            round_trip(id, None);
            round_trip(id, Some("1.2.3"));
            round_trip(id, Some("2.0.0-rc.1"));
        }
    }

    /// Qualifiers are sorted on the way in, so two orderings of one set are
    /// one identity rather than two.
    #[test]
    fn qualifier_order_does_not_matter() {
        let one = ArtifactId::parse("pkg:maven/g/a@1.0?type=jar&classifier=sources");
        let other = ArtifactId::parse("pkg:maven/g/a@1.0?classifier=sources&type=jar");

        assert_eq!(one.expect("one").id, other.expect("other").id);
    }

    /// One artifact has one rendering, which is what lets the rendering be
    /// a unique key in the report database. The specification says
    /// qualifier order carries no meaning, so sorting loses nothing.
    ///
    /// It is also the one published example that does not come back byte
    /// for byte, and the difference is the order alone.
    #[test]
    fn qualifiers_come_back_sorted() {
        let spec = "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1\
?repository_url=repo.spring.io%2Frelease&packaging=sources";

        let parsed = ArtifactId::parse(spec).expect("parsed");

        assert_eq!(
            parsed
                .id
                .purl_at(parsed.version.as_deref().expect("a version")),
            "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1\
?packaging=sources&repository_url=repo.spring.io%2Frelease"
        );

        assert_eq!(parsed.id.namespace(), Some("org.apache.xmlgraphics"));
        assert_eq!(parsed.id.name(), "batik-anim");
        assert_eq!(
            parsed.id.qualifiers(),
            [
                ("packaging".to_owned(), "sources".to_owned()),
                (
                    "repository_url".to_owned(),
                    "repo.spring.io/release".to_owned()
                ),
            ]
        );
    }

    /// An `ArtifactId` has nowhere to keep a subpath, so the refusal has to
    /// reach this far rather than being swallowed on the way.
    #[test]
    fn purl_subpath_refused() {
        let err = ArtifactId::parse("pkg:golang/google.golang.org/genproto#googleapis/api")
            .expect_err("refused");

        assert!(err.to_string().contains("subpath"), "{err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_maven_includes_sorted_qualifiers() {
        let id = ArtifactId::new(
            EcosystemId::maven(),
            Some("org.apache.xmlgraphics"),
            "batik-anim",
        )
        .with_qualifier("type", "zip")
        .with_qualifier("classifier", "dist");

        assert_eq!(
            id.purl(),
            "pkg:maven/org.apache.xmlgraphics/batik-anim?classifier=dist&type=zip"
        );
    }

    /// An npm scope reaches us as `@angular`; purl requires the `@` encoded.
    #[test]
    fn purl_npm_scope_percent_encoded() {
        let id = ArtifactId::new(EcosystemId::npm(), Some("@angular"), "animation");

        assert_eq!(id.purl(), "pkg:npm/%40angular/animation");
    }

    #[test]
    fn purl_pypi_has_no_namespace() {
        let id = ArtifactId::new(EcosystemId::pypi(), None, "requests");

        assert_eq!(id.purl(), "pkg:pypi/requests");
    }

    #[test]
    fn qualifier_replaced_not_duplicated() {
        let id = ArtifactId::new(EcosystemId::maven(), Some("g"), "a")
            .with_qualifier("type", "jar")
            .with_qualifier("type", "pom");

        assert_eq!(id.qualifier("type"), Some("pom"));
        assert_eq!(id.purl(), "pkg:maven/g/a?type=pom");
    }

    #[test]
    fn digest_best_prefers_strongest() {
        let mut file = FileRef::new("x.jar", "h://example.test/x.jar");
        file.digests = vec![
            Digest::new(DigestAlg::Md5, "AA"),
            Digest::new(DigestAlg::Sha256, "BB"),
            Digest::new(DigestAlg::Sha1, "CC"),
        ];

        assert_eq!(file.best_digest().unwrap().alg, DigestAlg::Sha256);
        assert!(file.has_strong_digest());
    }

    /// A 2012-era PyPI upload offers only md5: verifiable, but weakly.
    #[test]
    fn digest_md5_only_not_strong() {
        let mut file = FileRef::new("old.tar.gz", "h://example.test/old.tar.gz");
        file.digests = vec![Digest::new(DigestAlg::Md5, "AA")];

        assert!(!file.has_strong_digest());
        assert!(file.best_digest().is_some());
    }

    /// Purl orders the parts `name@version?qualifiers`.  Appending the
    /// version to a rendered id would put it after the `?`, which is
    /// malformed and would defeat any policy rule keyed on a version.
    #[test]
    fn purl_versioned_version_before_qualifiers() {
        let id = ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
            .with_qualifier("classifier", "sources")
            .with_qualifier("type", "jar");

        assert_eq!(
            id.purl_at("1.2.3"),
            "pkg:maven/org.example/lib@1.2.3?classifier=sources&type=jar"
        );
    }

    #[test]
    fn purl_versioned_without_qualifiers_plain() {
        let id = ArtifactId::new(EcosystemId::npm(), Some("@angular"), "core");

        assert_eq!(id.purl_at("17.0.0"), "pkg:npm/%40angular/core@17.0.0");
    }

    /// An artifact with no version renders the versionless purl, not one
    /// with an empty version.
    ///
    /// The two differ by a trailing `@`, and only the first survives a
    /// round trip: `purl::parse` reads an empty version back as `None`, so
    /// `pkg:raw/a@` re-renders as `pkg:raw/a`. Every purl comparison that
    /// decides a copy -- the transfer claim, the cache lookup, the target's
    /// `holds` query -- would then be comparing two spellings of one thing.
    #[test]
    fn purl_versionless_for_artifact_without_version() {
        let artifact = ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::new("raw"), None, "artifact1/1.0"),
            version: None,
            files: Vec::new(),
            license: None,
            published: None,
        };

        assert_eq!(artifact.purl(), "pkg:raw/artifact1%2F1.0");
        assert!(!artifact.purl().contains('@'));
        assert_eq!(artifact.version_text(), None);

        // And it is the same string the id alone renders, which is what
        // `ids::artifact` stores for such a row.
        assert_eq!(artifact.purl(), artifact.id.purl());
    }

    #[test]
    fn digest_hex_normalized_to_lower_case() {
        assert_eq!(Digest::new(DigestAlg::Sha256, "DEADBEEF").hex, "deadbeef");
    }
}

/// An artifact resolved to one exact version, with everything the report
/// needs about it.
#[derive(Debug, Clone)]
pub struct ResolvedArtifact {
    pub id: ArtifactId,

    /// `None` where the repository declares there are no versions.
    ///
    /// **Not a gap to be filled in.** A raw repository holds files under a
    /// path and says nothing else about them, so a directory has no version
    /// to resolve -- and every neighbouring type already says so:
    /// [`Found::version`](crate::repo::enumerate::Found), `Work::version`,
    /// `ArtifactRecord::version`, [`ParsedPurl::version`] and
    /// [`Coordinate::version`](crate::repo::Coordinate) are all optional,
    /// as is the `artifact.version` column. This was the one holdout.
    ///
    /// The alternative was a synthetic empty version, and it is worth
    /// saying why it was refused: `purl_at("")` renders a trailing `@`,
    /// which `purl::parse` then reads back as no version at all. The
    /// round trip breaks exactly where the transfer claim, the cache
    /// lookup and the target's `holds` query compare purls -- so a copy
    /// would re-fetch what it already held and never recognise what it had
    /// published.
    pub version: Option<Version>,

    pub files: Vec<FileRef>,

    /// License exactly as the ecosystem declared it, before policy
    /// evaluation.  Free text for Maven, an SPDX expression for npm,
    /// one of three competing fields for PyPI.
    pub license: Option<String>,

    pub published: Option<DateTime<Utc>>,
}

impl ResolvedArtifact {
    /// The purl for this exact version, which is how policies key artifacts.
    ///
    /// The versionless form when there is no version, rather than one with
    /// an empty version: the two render differently and only the first
    /// parses back to what it came from.
    pub fn purl(&self) -> String {
        match &self.version {
            Some(version) => self.id.purl_at(version.text()),
            None => self.id.purl(),
        }
    }

    /// The version as text, or `None` where there is none.
    ///
    /// Here so that reading a version does not mean an `unwrap` at every
    /// call site, and so that the absent case stays visible as `None`
    /// rather than becoming an empty string somebody then compares against.
    pub fn version_text(&self) -> Option<&str> {
        self.version.as_ref().map(Version::text)
    }
}
