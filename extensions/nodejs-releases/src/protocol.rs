//! What this extension says about itself, and which operations it answers.

use guest_kit::protocol::{PROTOCOL_VERSION, unimplemented};
use guest_kit::{Failure, Host, Source};
use serde_json::{Value, json};

use crate::releases;

/// NodeJS releases follow semver, so `nodejs@24` means the newest `24.x.y`.
const VERSION_SCHEME: &str = "semver";

/// The NodeJS releases source.
pub struct NodeJs;

impl Source for NodeJs {
    /// A raw source, ordered as semver.
    fn describe(&self) -> Value {
        json!({
            "protocol": PROTOCOL_VERSION,
            "points": ["source"],
            "ecosystems": [{"id": "raw", "purl-type": "raw", "osv-name": ""}],
            "version-scheme": VERSION_SCHEME,
        })
    }

    fn answer(&self, op: &str, input: Value, host: &dyn Host) -> Result<Value, Failure> {
        let input: releases::Input =
            serde_json::from_value(input).map_err(|err| Failure::malformed(err.to_string()))?;

        match op {
            "versions" => releases::versions(&input, host),
            "metadata" => releases::metadata(&input, host),
            other => Err(unimplemented(other)),
        }
    }

    fn failure_id(&self) -> &'static str {
        "nodejs-releases-failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guest_kit::protocol::{ARTIFACT_NOT_FOUND, UNIMPLEMENTED, handle};

    struct NoHost;

    impl Host for NoHost {
        fn fetch(&self, url: &str, _max_bytes: u64) -> Result<String, Failure> {
            Err(Failure::not_found(url))
        }
    }

    #[test]
    fn describe_declares_semver() {
        let answer = handle(br#"{"v":1,"id":"9","dir":"describe"}"#, &NodeJs, &NoHost);

        assert_eq!(answer["id"], "9");
        assert_eq!(answer["output"]["points"][0], "source");
        assert_eq!(answer["output"]["version-scheme"], VERSION_SCHEME);
    }

    #[test]
    fn unknown_op_fails() {
        let request = br#"{"v":1,"id":"3","dir":"invoke","point":"source","op":"deps","input":{"artifact":{"name":"nodejs"},"base-url":"h://x/","options":{}}}"#;

        let answer = handle(request, &NodeJs, &NoHost);

        assert_eq!(answer["dir"], "failed");
        assert_eq!(answer["code"], UNIMPLEMENTED);
    }

    #[test]
    fn host_failure_keeps_code() {
        let request = br#"{"v":1,"id":"4","dir":"invoke","point":"source","op":"versions","input":{"artifact":{"name":"nodejs"},"base-url":"h://x/","options":{}}}"#;

        let answer = handle(request, &NodeJs, &NoHost);

        assert_eq!(answer["code"], ARTIFACT_NOT_FOUND);
    }
}
