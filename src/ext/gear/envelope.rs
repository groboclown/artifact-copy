//! One protocol message, typed, and checked against the schema.
//!
//! Every message crossing the gearing, in either direction, passes through
//! [`decode`] or [`encode`], so nothing reaches an extension or a point
//! adapter without satisfying `schema/extension-protocol.schema.json`.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{PROTOCOL_SCHEMA, PROTOCOL_VERSION, PointKind};
use crate::core::message::Message;
use crate::core::problem::Code;

/// The schema root, which describes the envelope itself.
const ENVELOPE: &str = "";

/// Who is speaking, and about what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Dir {
    Describe,
    Invoke,
    HostCall,
    HostResult,
    Result,
    Problem,
    Failed,
}

/// One message, as `schema/extension-protocol.schema.json` defines it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct Envelope {
    pub v: u32,
    pub id: String,
    pub dir: Dir,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub point: Option<PointKind>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

impl Envelope {
    fn bare(id: &str, dir: Dir) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.to_owned(),
            dir,
            point: None,
            op: None,
            input: None,
            output: None,
            code: None,
            message: None,
        }
    }

    /// Ask an extension what it is.
    pub fn describe(id: &str) -> Self {
        Self::bare(id, Dir::Describe)
    }

    /// Ask an extension to perform `op` on `point`.
    pub fn invoke(id: &str, point: PointKind, op: &str, input: Value) -> Self {
        Self {
            point: Some(point),
            op: Some(op.to_owned()),
            input: Some(input),
            ..Self::bare(id, Dir::Invoke)
        }
    }

    /// The host's answer to a host call.
    pub fn host_result(id: &str, output: Value) -> Self {
        Self {
            output: Some(output),
            ..Self::bare(id, Dir::HostResult)
        }
    }

    /// A failure the caller may act on, such as `artifact-not-found`.
    pub fn problem(id: &str, code: Code, message: Message) -> Self {
        Self {
            code: Some(code.as_str().to_owned()),
            message: Some(message),
            ..Self::bare(id, Dir::Problem)
        }
    }

    /// A refusal: the request could not be carried out at all.
    pub fn failed(id: &str, code: Code, message: Message) -> Self {
        Self {
            dir: Dir::Failed,
            ..Self::problem(id, code, message)
        }
    }

    /// The problem code this message carries, read leniently.
    ///
    /// An extension may name a code this build does not know; that reads
    /// as `metadata-malformed`, the code for an answer that cannot be used.
    pub fn problem_code(&self) -> Code {
        self.code
            .as_deref()
            .and_then(|code| serde_json::from_value(Value::String(code.to_owned())).ok())
            .unwrap_or(Code::MetadataMalformed)
    }

    /// What went wrong, for a person.
    pub fn explain(&self) -> String {
        match (&self.message, &self.code) {
            (Some(message), _) => message.render(),
            (None, Some(code)) => code.clone(),
            (None, None) => format!("{:?} with no explanation", self.dir),
        }
    }
}

/// Parse and validate one message.
pub(crate) fn decode(bytes: &[u8]) -> Result<Envelope, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|err| format!("not JSON: {err}"))?;

    check(ENVELOPE, &value)?;

    serde_json::from_value(value).map_err(|err| format!("not a message: {err}"))
}

/// Validate and serialize one message.
pub(crate) fn encode(envelope: &Envelope) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(envelope).map_err(|err| err.to_string())?;

    check(ENVELOPE, &value)?;

    serde_json::to_vec(&value).map_err(|err| err.to_string())
}

/// Validate `value` against one named definition, or the envelope for
/// [`ENVELOPE`].
///
/// Compiled once per definition and kept: a source invoked for every
/// artifact of a migration would otherwise compile the schema each time.
pub(crate) fn check(definition: &'static str, value: &Value) -> Result<(), String> {
    let validator = validator(definition);

    let problems: Vec<String> = validator
        .iter_errors(value)
        .map(|err| crate::internal::schema::violation("", &err))
        .collect();

    if problems.is_empty() {
        return Ok(());
    }

    let name = match definition {
        ENVELOPE => "message",
        other => other,
    };

    Err(format!("invalid {name}: {}", problems.join("; ")))
}

/// The compiled validator for one definition, leaked: there is one per
/// definition for the life of the process.
fn validator(definition: &'static str) -> &'static jsonschema::Validator {
    static VALIDATORS: OnceLock<Mutex<BTreeMap<&'static str, &'static jsonschema::Validator>>> =
        OnceLock::new();

    let mut held = VALIDATORS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    held.entry(definition)
        .or_insert_with(|| Box::leak(Box::new(compile(definition))))
}

/// Compile the protocol schema rooted at one definition.
fn compile(definition: &str) -> jsonschema::Validator {
    let mut document: Value =
        serde_json::from_str(PROTOCOL_SCHEMA).expect("the built-in schema parses");

    if definition != ENVELOPE {
        document = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("#/$defs/{definition}"),
            "$defs": document["$defs"],
        });
    }

    jsonschema::validator_for(&document).expect("the built-in schema compiles")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_round_trips() {
        let sent = Envelope::invoke("1", PointKind::Source, "versions", serde_json::json!({}));

        let bytes = encode(&sent).expect("valid");
        let back = decode(&bytes).expect("valid");

        assert_eq!(back.dir, Dir::Invoke);
        assert_eq!(back.op.as_deref(), Some("versions"));
    }

    #[test]
    fn field_unknown_rejected() {
        let bytes = br#"{"v": 1, "id": "1", "dir": "result", "extra": true}"#;

        assert!(decode(bytes).is_err());
    }

    #[test]
    fn code_unknown_reads_as_malformed() {
        let mut failed = Envelope::failed("1", Code::Unimplemented, Message::new("x"));
        failed.code = Some("no-such-code".into());

        assert_eq!(failed.problem_code(), Code::MetadataMalformed);
    }

    #[test]
    fn code_known_kept() {
        let failed = Envelope::failed("1", Code::ArtifactNotFound, Message::new("x"));

        assert_eq!(failed.problem_code(), Code::ArtifactNotFound);
    }

    #[test]
    fn definitions_check() {
        let good = serde_json::json!({"url": "h://host.test/", "max-bytes": 10});
        let bad = serde_json::json!({"url": "h://host.test/"});

        assert!(check("FetchInput", &good).is_ok());
        assert!(check("FetchInput", &bad).is_err());
    }
}
