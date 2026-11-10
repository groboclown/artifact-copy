//! The artifact-copy extension protocol, as a guest speaks it.
//!
//! One message in, one message out. Host calls go through [`Host`], so an
//! extension's logic runs natively in tests and through the WASM import in
//! production.

use serde::Deserialize;
use serde_json::{Value, json};

/// The protocol version this kit speaks.
pub const PROTOCOL_VERSION: u32 = 1;

pub const ARTIFACT_NOT_FOUND: &str = "artifact-not-found";
pub const METADATA_MALFORMED: &str = "metadata-malformed";
pub const UNIMPLEMENTED: &str = "unimplemented";

/// Why a request could not be answered.
#[derive(Debug)]
pub struct Failure {
    /// A problem code from the documented set.
    pub code: String,
    pub text: String,
}

impl Failure {
    pub fn new(code: &str, text: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            text: text.into(),
        }
    }

    pub fn not_found(text: impl Into<String>) -> Self {
        Self::new(ARTIFACT_NOT_FOUND, text)
    }

    pub fn malformed(text: impl Into<String>) -> Self {
        Self::new(METADATA_MALFORMED, text)
    }
}

/// What an extension may ask of the tool.
pub trait Host {
    /// A text body, at most `max_bytes` long.
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<String, Failure>;
}

/// One source extension: what it says about itself, and how it answers.
pub trait Source: Sync {
    /// The `Description` output, such as
    /// `{"protocol": 1, "points": ["source"], "ecosystems": [...]}`.
    fn describe(&self) -> Value;

    /// The output of operation `op`, such as `versions` or `metadata`.
    fn answer(&self, op: &str, input: Value, host: &dyn Host) -> Result<Value, Failure>;

    /// The message id a `failed` answer carries.
    fn failure_id(&self) -> &'static str;
}

#[derive(Deserialize)]
struct Request {
    id: String,
    dir: String,

    #[serde(default)]
    op: Option<String>,

    #[serde(default)]
    input: Option<Value>,
}

/// Answer one message.
pub fn handle(request: &[u8], source: &dyn Source, host: &dyn Host) -> Value {
    let request: Request = match serde_json::from_slice(request) {
        Ok(request) => request,
        Err(err) => return failed("0", source, &Failure::malformed(err.to_string())),
    };

    if request.dir == "describe" {
        return json!({
            "v": PROTOCOL_VERSION,
            "id": request.id,
            "dir": "describe",
            "output": source.describe(),
        });
    }

    let Some(op) = request.op.as_deref() else {
        let failure = Failure::new(UNIMPLEMENTED, "no operation");
        return failed(&request.id, source, &failure);
    };

    let input = request.input.clone().unwrap_or_default();

    match source.answer(op, input, host) {
        Ok(output) => {
            json!({"v": PROTOCOL_VERSION, "id": request.id, "dir": "result", "output": output})
        }
        Err(failure) => failed(&request.id, source, &failure),
    }
}

fn failed(id: &str, source: &dyn Source, failure: &Failure) -> Value {
    json!({
        "v": PROTOCOL_VERSION,
        "id": id,
        "dir": "failed",
        "code": failure.code,
        "message": {"id": source.failure_id(), "text": failure.text},
    })
}

/// The failure for an operation a source does not answer.
pub fn unimplemented(op: &str) -> Failure {
    Failure::new(UNIMPLEMENTED, format!("no operation {op:?}"))
}

/// Read a host call's answer: the body, or why there is none.
pub fn read_host_result(answer: &[u8]) -> Result<String, Failure> {
    let answer: Value =
        serde_json::from_slice(answer).map_err(|err| Failure::malformed(err.to_string()))?;

    if answer["dir"] == "host-result" {
        return answer["output"]["text"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Failure::malformed("the page is not text"));
    }

    let code = answer["code"].as_str().unwrap_or(METADATA_MALFORMED);
    let text = answer["message"]["text"]
        .as_str()
        .unwrap_or("the host call failed");

    Err(Failure::new(code, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoHost;

    impl Host for NoHost {
        fn fetch(&self, url: &str, _max_bytes: u64) -> Result<String, Failure> {
            Err(Failure::not_found(url))
        }
    }

    /// Answers `echo` with its input and fails everything else.
    struct Echo;

    impl Source for Echo {
        fn describe(&self) -> Value {
            json!({"protocol": PROTOCOL_VERSION, "points": ["source"]})
        }

        fn answer(&self, op: &str, input: Value, host: &dyn Host) -> Result<Value, Failure> {
            match op {
                "echo" => Ok(input),
                "fetch" => host.fetch("h://x/", 1).map(Value::from),
                other => Err(unimplemented(other)),
            }
        }

        fn failure_id(&self) -> &'static str {
            "echo-failed"
        }
    }

    #[test]
    fn describe_echoes_id() {
        let answer = handle(br#"{"v":1,"id":"9","dir":"describe"}"#, &Echo, &NoHost);

        assert_eq!(answer["id"], "9");
        assert_eq!(answer["output"]["points"][0], "source");
    }

    #[test]
    fn result_carries_output() {
        let request =
            br#"{"v":1,"id":"2","dir":"invoke","point":"source","op":"echo","input":{"a":1}}"#;

        let answer = handle(request, &Echo, &NoHost);

        assert_eq!(answer["dir"], "result");
        assert_eq!(answer["output"]["a"], 1);
    }

    #[test]
    fn unknown_op_fails() {
        let request = br#"{"v":1,"id":"3","dir":"invoke","point":"source","op":"deps","input":{}}"#;

        let answer = handle(request, &Echo, &NoHost);

        assert_eq!(answer["dir"], "failed");
        assert_eq!(answer["code"], UNIMPLEMENTED);
        assert_eq!(answer["message"]["id"], "echo-failed");
    }

    #[test]
    fn host_failure_keeps_code() {
        let request =
            br#"{"v":1,"id":"4","dir":"invoke","point":"source","op":"fetch","input":{}}"#;

        let answer = handle(request, &Echo, &NoHost);

        assert_eq!(answer["code"], ARTIFACT_NOT_FOUND);
    }

    #[test]
    fn host_result_reads() {
        let ok = br#"{"v":1,"id":"1","dir":"host-result","output":{"text":"page"}}"#;
        let gone = br#"{"v":1,"id":"1","dir":"problem","code":"artifact-not-found","message":{"id":"x","text":"404"}}"#;

        assert_eq!(read_host_result(ok).expect("text"), "page");
        assert_eq!(
            read_host_result(gone).expect_err("gone").code,
            ARTIFACT_NOT_FOUND
        );
    }
}
