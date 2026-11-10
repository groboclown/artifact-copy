//! VEX and VDR documents, normalized to one statement type.
//!
//! A suppression carries a machine-readable justification rather than a
//! free-text reason, so an allowance survives audit.  Two input formats:
//! OpenVEX, whose products are already purls, and CycloneDX, which is what
//! most enterprise enumerators emit.  A CycloneDX document is an SBOM as
//! well as a VEX: its components are read too, and an `affects.ref` names
//! one of them by `bom-ref`.
//!
//! Read as lock files, since a document vouches for the artifacts it names;
//! see `crate::lock`.
//!
//! Only genuinely-cleared states suppress.  `under_investigation` is a
//! warning, and `affected` suppresses nothing at all -- a document saying "we
//! are exposed" must never read as an all-clear.
//!
//! References: [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md), [CycloneDX](https://cyclonedx.org/specification/overview/).

use std::collections::HashMap;

use serde::Deserialize;

use crate::core::error::{Error, Result};

/// What a VEX document says about one artifact and one advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Cleared: the advisory does not apply here.
    NotAffected,

    /// Cleared: already remediated.
    Fixed,

    /// Being triaged.  Downgrades the finding to a warning; does not clear it.
    UnderInvestigation,

    /// Exposed.  Suppresses nothing.
    Affected,
}

impl Status {
    /// Whether this status clears the finding.
    pub fn suppresses(self) -> bool {
        matches!(self, Status::NotAffected | Status::Fixed)
    }
}

/// One normalized statement, whatever format it arrived in.
#[derive(Debug, Clone)]
pub struct Statement {
    /// Advisory identifier: `CVE-...`, `GHSA-...`, `MAL-...`.
    pub vulnerability: String,

    /// Purls this applies to.  A statement with none applies to nothing,
    /// which is caught as dead policy rather than silently ignored.
    pub products: Vec<String>,

    pub status: Status,

    /// Required for `not_affected` -- an OpenVEX rule, enforced here so the
    /// mechanism cannot decay into a rubber stamp.
    pub justification: Option<String>,

    pub detail: Option<String>,

    /// Where this came from, for the report.
    pub source: String,
}

impl Statement {
    /// Whether this statement covers an artifact.
    ///
    /// A product without a version covers every version, matching how the
    /// license policy treats a versionless purl.
    pub fn covers(&self, purl: &str) -> bool {
        self.products.iter().any(|product| {
            product == purl
                || (!product.contains('@')
                    && purl.starts_with(product.as_str())
                    && purl[product.len()..].starts_with('@'))
        })
    }

    /// Whether this statement names an advisory, by id or alias.
    pub fn names(&self, id: &str, aliases: &[String]) -> bool {
        self.vulnerability.eq_ignore_ascii_case(id)
            || aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(&self.vulnerability))
    }

    /// Reject a clearance that gives no reason.
    fn validate(&self) -> Result<()> {
        if self.status == Status::NotAffected && self.justification.is_none() {
            return Err(unparsable(
                &self.source,
                format!(
                    "the not_affected statement for {} must carry a justification",
                    self.vulnerability
                ),
            ));
        }

        if self.products.is_empty() {
            return Err(unparsable(
                &self.source,
                format!("the statement for {} names no products", self.vulnerability),
            ));
        }

        Ok(())
    }
}

/// What one VEX or SBOM document holds.
#[derive(Debug, Clone, Default)]
pub struct Document {
    /// The VEX statements, normalized.
    pub statements: Vec<Statement>,

    /// The purl of every component a CycloneDX SBOM lists: its subject,
    /// `metadata.component`, then every entry of `components`, nested ones
    /// included. Empty for OpenVEX, which lists no components.
    pub components: Vec<String>,
}

/// Read a VEX or SBOM document, detecting its format from its content.
///
/// `source` names the document in statements and errors.
pub fn parse(body: &[u8], source: &str) -> Result<Document> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|err| unparsable(source, format!("not valid JSON: {err}")))?;

    // Detected by shape rather than by extension: both formats are `.json`
    // and users name them anything.
    let document = if value.get("@context").is_some() || value.get("statements").is_some() {
        parse_openvex(&value, source)?
    } else if value.get("bomFormat").is_some() || value.get("vulnerabilities").is_some() {
        parse_cyclonedx(&value, source)?
    } else {
        return Err(unparsable(
            source,
            "neither an OpenVEX document nor a CycloneDX SBOM or VEX".to_owned(),
        ));
    };

    for statement in &document.statements {
        statement.validate()?;
    }

    Ok(document)
}

fn unparsable(source: &str, detail: String) -> Error {
    Error::VexUnparsable {
        source_name: source.to_owned(),
        detail,
    }
}

// -- OpenVEX -------------------------------------------------------------

#[derive(Deserialize)]
struct OpenVex {
    #[serde(default)]
    statements: Vec<OpenVexStatement>,
}

#[derive(Deserialize)]
struct OpenVexStatement {
    vulnerability: OpenVexVuln,

    #[serde(default)]
    products: Vec<OpenVexProduct>,

    status: String,

    #[serde(default)]
    justification: Option<String>,

    #[serde(default)]
    impact_statement: Option<String>,
}

/// The spec allows either a bare string or an object with a `name`.
#[derive(Deserialize)]
#[serde(untagged)]
enum OpenVexVuln {
    Name(String),
    Object {
        #[serde(rename = "@id")]
        id: Option<String>,
        name: Option<String>,
    },
}

impl OpenVexVuln {
    fn id(&self) -> Option<String> {
        match self {
            OpenVexVuln::Name(name) => Some(name.clone()),
            OpenVexVuln::Object { id, name } => name.clone().or_else(|| id.clone()),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OpenVexProduct {
    Purl(String),
    Object {
        #[serde(rename = "@id")]
        id: Option<String>,
    },
}

impl OpenVexProduct {
    fn purl(&self) -> Option<String> {
        match self {
            OpenVexProduct::Purl(purl) => Some(purl.clone()),
            OpenVexProduct::Object { id } => id.clone(),
        }
    }
}

fn parse_openvex(value: &serde_json::Value, source: &str) -> Result<Document> {
    let document: OpenVex = serde_json::from_value(value.clone())
        .map_err(|err| unparsable(source, format!("not a usable OpenVEX document: {err}")))?;

    let mut statements = Vec::new();

    for statement in document.statements {
        let status = match statement.status.as_str() {
            "not_affected" => Status::NotAffected,
            "fixed" => Status::Fixed,
            "under_investigation" => Status::UnderInvestigation,
            "affected" => Status::Affected,
            other => {
                return Err(unparsable(
                    source,
                    format!("unknown OpenVEX status {other:?}"),
                ));
            }
        };

        let vulnerability = statement
            .vulnerability
            .id()
            .ok_or_else(|| unparsable(source, "a statement names no vulnerability".to_owned()))?;

        statements.push(Statement {
            vulnerability,
            products: statement.products.iter().filter_map(|p| p.purl()).collect(),
            status,
            justification: statement.justification,
            detail: statement.impact_statement,
            source: source.to_owned(),
        });
    }

    Ok(Document {
        statements,
        components: Vec::new(),
    })
}

// -- CycloneDX SBOM / VDR / VEX --------------------------------------------

#[derive(Deserialize)]
struct CycloneDx {
    #[serde(default)]
    metadata: Option<CycloneDxMetadata>,

    #[serde(default)]
    components: Vec<CycloneDxComponent>,

    #[serde(default)]
    vulnerabilities: Vec<CycloneDxVuln>,
}

#[derive(Deserialize)]
struct CycloneDxMetadata {
    #[serde(default)]
    component: Option<CycloneDxComponent>,
}

#[derive(Deserialize)]
struct CycloneDxComponent {
    #[serde(rename = "bom-ref", default)]
    bom_ref: Option<String>,

    #[serde(default)]
    purl: Option<String>,

    /// A component may nest others: an image holding packages, a package
    /// holding a vendored copy.
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Deserialize)]
struct CycloneDxVuln {
    #[serde(default)]
    id: Option<String>,

    #[serde(default)]
    analysis: Option<CycloneDxAnalysis>,

    #[serde(default)]
    affects: Vec<CycloneDxAffect>,
}

#[derive(Deserialize)]
struct CycloneDxAnalysis {
    #[serde(default)]
    state: Option<String>,

    #[serde(default)]
    justification: Option<String>,

    #[serde(default)]
    detail: Option<String>,
}

#[derive(Deserialize)]
struct CycloneDxAffect {
    #[serde(rename = "ref", default)]
    reference: Option<String>,
}

/// Every component under `components`, depth first, with its `bom-ref` and
/// `purl` collected.
///
/// ```text
///   image (bom-ref: img)
///     '-- lib (bom-ref: lib-1, purl: pkg:npm/lib@1)   -> refs[lib-1] = pkg:npm/lib@1
/// ```
fn walk_components(
    components: &[CycloneDxComponent],
    refs: &mut HashMap<String, String>,
    purls: &mut Vec<String>,
) {
    for component in components {
        if let Some(purl) = &component.purl {
            purls.push(purl.clone());

            if let Some(bom_ref) = &component.bom_ref {
                refs.insert(bom_ref.clone(), purl.clone());
            }
        }

        walk_components(&component.components, refs, purls);
    }
}

fn parse_cyclonedx(value: &serde_json::Value, source: &str) -> Result<Document> {
    let document: CycloneDx = serde_json::from_value(value.clone())
        .map_err(|err| unparsable(source, format!("not a usable CycloneDX document: {err}")))?;

    // The whole document, its subject included, rather than a descent
    // through the dependency graph from the subject.
    let subject = document.metadata.and_then(|metadata| metadata.component);
    let mut refs = HashMap::new();
    let mut components = Vec::new();

    walk_components(subject.as_slice(), &mut refs, &mut components);
    walk_components(&document.components, &mut refs, &mut components);

    let mut statements = Vec::new();

    for vuln in document.vulnerabilities {
        let Some(analysis) = vuln.analysis else {
            // A VDR entry with no analysis states a finding, not a
            // clearance.  Nothing to suppress.
            continue;
        };

        let Some(state) = analysis.state.as_deref() else {
            continue;
        };

        let status = match state {
            "not_affected" | "false_positive" => Status::NotAffected,
            "resolved" | "resolved_with_pedigree" => Status::Fixed,
            "in_triage" => Status::UnderInvestigation,
            "exploitable" => Status::Affected,
            other => {
                return Err(unparsable(
                    source,
                    format!("unknown CycloneDX analysis state {other:?}"),
                ));
            }
        };

        let vulnerability = vuln
            .id
            .ok_or_else(|| unparsable(source, "a vulnerability has no id".to_owned()))?;

        let mut products = Vec::new();

        for reference in vuln.affects.iter().filter_map(|a| a.reference.as_deref()) {
            products.push(product(reference, &refs, source, &vulnerability)?);
        }

        statements.push(Statement {
            vulnerability,
            products,
            status,
            // CycloneDX `false_positive` carries its reasoning in the state
            // itself, so accept it as the justification when none is given.
            justification: analysis
                .justification
                .or_else(|| (state == "false_positive").then(|| state.to_owned())),
            detail: analysis.detail,
            source: source.to_owned(),
        });
    }

    Ok(Document {
        statements,
        components,
    })
}

/// The purl an `affects.ref` names: a component's `bom-ref`, or a purl
/// written in place of one.
fn product(
    reference: &str,
    refs: &HashMap<String, String>,
    source: &str,
    vulnerability: &str,
) -> Result<String> {
    if let Some(purl) = refs.get(reference) {
        return Ok(purl.clone());
    }

    if reference.starts_with(PURL_SCHEME) {
        return Ok(reference.to_owned());
    }

    Err(unparsable(
        source,
        format!("{vulnerability} affects {reference:?}, which names no component with a purl"),
    ))
}

/// How every purl begins.
const PURL_SCHEME: &str = "pkg:";

#[cfg(test)]
mod tests {
    use super::*;

    fn load(body: &str) -> Result<Vec<Statement>> {
        parse(body.as_bytes(), "vex.json").map(|document| document.statements)
    }

    const OPENVEX: &str = r#"{
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [{
            "vulnerability": {"name": "CVE-2024-0001"},
            "products": [{"@id": "pkg:npm/lodash@4.17.20"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_present"
        }]
    }"#;

    const CYCLONEDX: &str = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "vulnerabilities": [{
            "id": "CVE-2024-0002",
            "analysis": {"state": "false_positive", "detail": "not reachable"},
            "affects": [{"ref": "pkg:maven/org.example/lib@1.0.0"}]
        }]
    }"#;

    #[test]
    fn openvex_parses_and_suppresses() {
        let statements = load(OPENVEX).expect("loads");

        assert_eq!(statements.len(), 1);
        assert!(statements[0].status.suppresses());
        assert!(statements[0].covers("pkg:npm/lodash@4.17.20"));
        assert!(statements[0].names("CVE-2024-0001", &[]));
    }

    #[test]
    fn cyclonedx_false_positive_suppresses() {
        let statements = load(CYCLONEDX).expect("loads");

        assert_eq!(statements.len(), 1);
        assert!(statements[0].status.suppresses());
        assert!(statements[0].covers("pkg:maven/org.example/lib@1.0.0"));
    }

    /// The format is detected from content, because both are `.json` and
    /// users name them whatever they like.
    #[test]
    fn format_detected_from_content() {
        assert_eq!(load(OPENVEX).unwrap()[0].vulnerability, "CVE-2024-0001");
        assert_eq!(load(CYCLONEDX).unwrap()[0].vulnerability, "CVE-2024-0002");
    }

    /// Being triaged is not an all-clear.
    #[test]
    fn status_under_investigation_does_not_suppress() {
        let body = r#"{"@context":"x","statements":[{
                "vulnerability":{"name":"CVE-1"},
                "products":[{"@id":"pkg:npm/a@1"}],
                "status":"under_investigation"}]}"#;

        let statements = load(body).expect("loads");

        assert_eq!(statements[0].status, Status::UnderInvestigation);
        assert!(!statements[0].status.suppresses());
    }

    /// A document saying "we are exposed" must never read as a clearance.
    #[test]
    fn status_affected_does_not_suppress() {
        let body = r#"{"@context":"x","statements":[{
                "vulnerability":{"name":"CVE-1"},
                "products":[{"@id":"pkg:npm/a@1"}],
                "status":"affected"}]}"#;

        assert!(!load(body).unwrap()[0].status.suppresses());
    }

    /// Without this the mechanism decays into a rubber stamp.
    #[test]
    fn status_not_affected_needs_justification() {
        let body = r#"{"@context":"x","statements":[{
                "vulnerability":{"name":"CVE-1"},
                "products":[{"@id":"pkg:npm/a@1"}],
                "status":"not_affected"}]}"#;

        let err = load(body).unwrap_err();

        assert!(err.to_string().contains("must carry a justification"));
    }

    #[test]
    fn statement_without_product_rejected() {
        let body = r#"{"@context":"x","statements":[{
                "vulnerability":{"name":"CVE-1"},
                "products":[],
                "status":"fixed"}]}"#;

        assert!(load(body).unwrap_err().to_string().contains("no products"));
    }

    /// A VDR entry that only records a finding is not a clearance.
    #[test]
    fn cyclonedx_without_analysis_yields_no_statement() {
        let body = r#"{"bomFormat":"CycloneDX","vulnerabilities":[
                {"id":"CVE-1","affects":[{"ref":"pkg:npm/a@1"}]}]}"#;

        assert!(load(body).unwrap().is_empty());
    }

    #[test]
    fn product_versionless_covers_every_version() {
        let statement = Statement {
            vulnerability: "CVE-1".into(),
            products: vec!["pkg:npm/lodash".into()],
            status: Status::Fixed,
            justification: None,
            detail: None,
            source: "t".into(),
        };

        assert!(statement.covers("pkg:npm/lodash@4.17.20"));
        assert!(!statement.covers("pkg:npm/lodash-es@4.17.20"));
    }

    #[test]
    fn statement_matched_by_alias() {
        let statement = Statement {
            vulnerability: "GHSA-aaaa-bbbb-cccc".into(),
            products: vec!["pkg:npm/a@1".into()],
            status: Status::Fixed,
            justification: None,
            detail: None,
            source: "t".into(),
        };

        assert!(statement.names("CVE-2024-9999", &["GHSA-aaaa-bbbb-cccc".into()]));
    }

    #[test]
    fn format_unknown_shape_rejected() {
        let body = r#"{"something": "else"}"#;

        assert!(load(body).is_err());
    }

    /// A CycloneDX `ref` is a `bom-ref`, resolved through the components,
    /// nested ones and the document's subject included.
    #[test]
    fn bom_ref_resolves_to_component() {
        let document = parse(
            br#"{"bomFormat":"CycloneDX",
                "metadata":{"component":{"bom-ref":"app","purl":"pkg:npm/app@1"}},
                "components":[{"bom-ref":"img","components":[
                    {"bom-ref":"lib-1","purl":"pkg:npm/lib@1"}]}],
                "vulnerabilities":[{"id":"CVE-1",
                    "analysis":{"state":"resolved"},
                    "affects":[{"ref":"lib-1"},{"ref":"app"}]}]}"#,
            "sbom.json",
        )
        .expect("parses");

        assert_eq!(
            document.statements[0].products,
            ["pkg:npm/lib@1", "pkg:npm/app@1"]
        );
    }

    /// The subject is evaluated with the rest of the document.
    #[test]
    fn components_listed_with_subject() {
        let document = parse(
            br#"{"bomFormat":"CycloneDX",
                "metadata":{"component":{"purl":"pkg:oci/app@sha256:1"}},
                "components":[{"purl":"pkg:npm/a@1","components":[
                    {"purl":"pkg:npm/b@2"}]}]}"#,
            "sbom.json",
        )
        .expect("parses");

        assert_eq!(
            document.components,
            ["pkg:oci/app@sha256:1", "pkg:npm/a@1", "pkg:npm/b@2"]
        );
        assert!(document.statements.is_empty());
    }

    #[test]
    fn bom_ref_without_component_unparsable() {
        let err = parse(
            br#"{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1",
                "analysis":{"state":"resolved"},"affects":[{"ref":"missing"}]}]}"#,
            "sbom.json",
        )
        .unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::VexUnparsable);
        assert!(err.to_string().contains("missing"));
    }
}
