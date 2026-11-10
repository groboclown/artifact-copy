//! VEX and SBOM documents, read as lock files.
//!
//! A VEX document says why a finding is acceptable for specific artifacts,
//! so it arrives the way the request for those artifacts does. Its
//! products, and a CycloneDX SBOM's components, become requests; its
//! statements suppress findings against them.
//!
//! ```text
//!   openvex.json   --> products              --> requests
//!                  '-> statements                       --> screening
//!   cyclonedx.json --> subject + components   --> requests
//!                  '-> vulnerabilities[].analysis       --> screening
//! ```
//!
//! References: [CycloneDX](https://cyclonedx.org/specification/overview/), [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;

use super::{Lock, LockFormat, LockHead, LockRead, read_capped};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::core::problem::Code;
use crate::message;
use crate::model::{ArtifactId, ArtifactRequest, Cause, Provenance, VersionSpec};
use crate::policy::{Statement, parse_vex};

/// The readers this crate ships for VEX and SBOM documents.
pub(super) fn readers() -> Vec<Arc<dyn Lock>> {
    vec![
        Arc::new(BomReader(Shape::OpenVex)),
        Arc::new(BomReader(Shape::CycloneDx)),
    ]
}

/// Which document a reader claims.
#[derive(Debug, Clone, Copy)]
enum Shape {
    OpenVex,
    CycloneDx,
}

/// The text near the top of a document that says which one it is: an
/// OpenVEX `@context` URL, a CycloneDX `bomFormat` value.
const OPENVEX_MARKER: &str = "openvex.dev";
const CYCLONEDX_MARKER: &str = "\"CycloneDX\"";
const CYCLONEDX_FORMAT_KEY: &str = "\"bomFormat\"";

/// No filename globs: these documents are named anything, so they are
/// claimed by content alone.
static OPENVEX_FORMATS: LazyLock<[LockFormat; 1]> = LazyLock::new(|| [format("openvex")]);
static CYCLONEDX_FORMATS: LazyLock<[LockFormat; 1]> = LazyLock::new(|| [format("cyclonedx")]);

fn format(name: &str) -> LockFormat {
    LockFormat {
        name: name.to_owned(),
        filenames: Vec::new(),
    }
}

struct BomReader(Shape);

#[async_trait]
impl Lock for BomReader {
    fn formats(&self) -> &[LockFormat] {
        match self.0 {
            Shape::OpenVex => &*OPENVEX_FORMATS,
            Shape::CycloneDx => &*CYCLONEDX_FORMATS,
        }
    }

    fn claims<'n, 'h>(&self, _name: &'n str, head: &LockHead<'h>) -> bool {
        let text = head.text();

        match self.0 {
            Shape::OpenVex => text.contains(OPENVEX_MARKER),
            Shape::CycloneDx => {
                text.contains(CYCLONEDX_FORMAT_KEY) && text.contains(CYCLONEDX_MARKER)
            }
        }
    }

    async fn read(&self, file: &Path, ctx: &Ctx) -> Result<LockRead> {
        let body = read_capped(file).await?;
        let source = file.display().to_string();
        let document = parse_vex(&body, &source)?;

        let mut requests = Requests::new(file);

        for purl in &document.components {
            requests.add(purl, &source, ctx);
        }

        let statements = document
            .statements
            .into_iter()
            .map(|statement| requests.adopt(statement, &source, ctx))
            .collect();

        Ok(LockRead {
            requests: requests.found,
            statements,
        })
    }

    fn attests(&self) -> bool {
        true
    }
}

/// The requests a document makes, each purl once.
struct Requests<'f> {
    file: &'f Path,
    seen: BTreeSet<String>,
    found: Vec<ArtifactRequest>,
}

impl<'f> Requests<'f> {
    fn new(file: &'f Path) -> Self {
        Self {
            file,
            seen: BTreeSet::new(),
            found: Vec::new(),
        }
    }

    /// Request `purl`, returning it as this crate renders it so a statement
    /// naming it matches the artifact screened: `pkg:npm/@a/b@1` and
    /// `pkg:npm/%40a/b@1` are one package.
    ///
    /// A product that is no purl names no ecosystem, so no source serves it;
    /// it is reported as foreign and kept as written.
    fn add(&mut self, purl: &str, source: &str, ctx: &Ctx) -> String {
        let Ok(parsed) = ArtifactId::parse(purl) else {
            ctx.report(
                Code::BomEcosystemForeign,
                message!(
                    "bom-product-not-purl",
                    "{source} names {product}, which is not a purl, so it is not requested",
                    source = source,
                    product = purl,
                ),
            );

            return purl.to_owned();
        };

        let (canonical, spec) = match &parsed.version {
            Some(version) => (
                parsed.id.purl_at(version),
                VersionSpec::Exact(version.clone()),
            ),
            None => (parsed.id.purl(), VersionSpec::Any),
        };

        if self.seen.insert(canonical.clone()) {
            self.found.push(ArtifactRequest {
                id: parsed.id,
                spec,
                prov: Arc::new(Provenance::root(Cause::LockFile {
                    path: PathBuf::from(self.file),
                    entry: canonical.clone(),
                })),
            });
        }

        canonical
    }

    /// Request each of a statement's products, and keep it naming them as
    /// requested.
    fn adopt(&mut self, mut statement: Statement, source: &str, ctx: &Ctx) -> Statement {
        statement.products = statement
            .products
            .iter()
            .map(|product| self.add(product, source, ctx))
            .collect();

        statement
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{LockSpec, Registry};

    const OPENVEX: &str = r#"{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [{
            "vulnerability": {"name": "CVE-1"},
            "products": [{"@id": "pkg:npm/%40scope/a@1"}, {"@id": "pkg:npm/b"}],
            "status": "fixed"
        }]
    }"#;

    const SBOM: &str = r#"{
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "a", "purl": "pkg:npm/a@1"},
            {"purl": "pkg:pypi/requests@2.0.0"}
        ],
        "vulnerabilities": [{"id": "CVE-2", "analysis": {"state": "resolved"},
                             "affects": [{"ref": "a"}]}]
    }"#;

    async fn read(name: &str, body: &str) -> (LockRead, Ctx) {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join(name);
        std::fs::write(&file, body).expect("written");

        let ctx = Ctx::for_test(Cause::Requested {
            arg: name.to_owned(),
        });
        let spec = LockSpec::parse(&file.display().to_string()).expect("parses");
        let reader = Registry::builtin()
            .resolve(&spec, name, &LockHead::of(body.as_bytes()))
            .expect("claimed");

        assert!(reader.attests());

        let found = reader.read(&file, &ctx).await.expect("reads");

        (found, ctx)
    }

    fn purls(found: &LockRead) -> Vec<String> {
        found
            .requests
            .iter()
            .map(|request| request.id.purl())
            .collect()
    }

    /// A versioned product asks for that version; a versionless one for any.
    #[tokio::test]
    async fn openvex_products_become_requests() {
        let (found, _) = read("triage.json", OPENVEX).await;

        assert_eq!(purls(&found), ["pkg:npm/%40scope/a", "pkg:npm/b"]);
        assert_eq!(found.requests[0].spec, VersionSpec::Exact("1".into()));
        assert_eq!(found.requests[1].spec, VersionSpec::Any);
        assert_eq!(found.statements.len(), 1);
    }

    /// A plain SBOM's components are requests, and a product named by both
    /// a component and a statement is requested once.
    #[tokio::test]
    async fn cyclonedx_components_become_requests() {
        let (found, _) = read("bom.json", SBOM).await;

        assert_eq!(purls(&found), ["pkg:npm/a", "pkg:pypi/requests"]);
        assert_eq!(found.statements[0].products, ["pkg:npm/a@1"]);
    }

    /// A statement about the document's subject names a requested
    /// artifact, so it can answer like any other.
    #[tokio::test]
    async fn subject_requested() {
        let (found, _) = read(
            "bom.json",
            r#"{"bomFormat": "CycloneDX",
                "metadata": {"component": {"bom-ref": "app", "purl": "pkg:npm/app@3"}},
                "components": [{"purl": "pkg:npm/a@1"}],
                "vulnerabilities": [{"id": "CVE-3", "analysis": {"state": "resolved"},
                                     "affects": [{"ref": "app"}]}]}"#,
        )
        .await;

        assert_eq!(purls(&found), ["pkg:npm/app", "pkg:npm/a"]);
        assert_eq!(found.statements[0].products, ["pkg:npm/app@3"]);
    }

    #[tokio::test]
    async fn product_not_purl_reported() {
        let (found, ctx) = read(
            "triage.json",
            r#"{"@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": "CVE-1",
                    "products": ["urn:example:image"], "status": "fixed"}]}"#,
        )
        .await;

        assert!(found.requests.is_empty());
        assert_eq!(ctx.problems().counts()[&Code::BomEcosystemForeign], 1);
    }

    /// An npm lock is still the npm reader's, not a document reader's.
    #[test]
    fn package_lock_not_claimed() {
        let head = LockHead::of(br#"{"lockfileVersion": 3}"#);

        for reader in readers() {
            assert!(!reader.claims("package-lock.json", &head));
        }
    }
}
