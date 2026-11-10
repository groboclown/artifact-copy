//! What this extension says about itself, and which operations it answers.

use guest_kit::protocol::{PROTOCOL_VERSION, unimplemented};
use guest_kit::{Failure, Host, Source};
use serde_json::{Value, json};

use crate::releases;

/// Tags such as `25.0.5.0.10` and `8.242.08.1-1` order as Maven versions.
const VERSION_SCHEME: &str = "maven";

/// The Amazon Corretto releases source.
pub struct Corretto;

impl Source for Corretto {
    /// A raw source, ordered as Maven versions.
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
        "corretto-releases-failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guest_kit::protocol::handle;

    struct NoHost;

    impl Host for NoHost {
        fn fetch(&self, url: &str, _max_bytes: u64) -> Result<String, Failure> {
            Err(Failure::not_found(url))
        }
    }

    #[test]
    fn describe_declares_maven() {
        let answer = handle(br#"{"v":1,"id":"9","dir":"describe"}"#, &Corretto, &NoHost);

        assert_eq!(answer["output"]["version-scheme"], VERSION_SCHEME);
        assert_eq!(answer["output"]["ecosystems"][0]["id"], "raw");
    }
}
