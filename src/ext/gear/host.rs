//! Carry out what an extension asks of the host.
//!
//! The extension names a capability and its input; this performs it through
//! the source's [`ExtHost`], so the host's constraints, credentials, and
//! caps apply exactly as they do to a built-in. A failure is answered, not
//! raised: the extension decides what a `404` means to it.
//!
//! ```text
//!   guest --host-call {op: fetch, input}--> answer --> ExtHost::fetch
//!   guest <--host-result {text|base64}----- answer <-- bytes
//!   guest <--problem {code: artifact-not-found}----- Error
//! ```

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;

use super::envelope::{self, Envelope};
use crate::core::ctx::Ctx;
use crate::core::problem::Code;
use crate::ext::ExtHost;
use crate::net::{ByteLimit, Req};

/// The host capability that returns a capped body in memory.
const FETCH_OP: &str = "fetch";

/// The most any one `fetch` may return, whatever the extension asks for.
///
/// An index page is kilobytes; a payload is never fetched by an
/// extension, since the host downloads files itself.
const MAX_FETCH_BYTES: ByteLimit = ByteLimit::mib(16);

/// What a host call needs from the invocation it happens during.
#[derive(Clone)]
pub(crate) struct Calling {
    pub host: Arc<dyn ExtHost>,
    pub ctx: Ctx,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct FetchInput {
    url: String,
    max_bytes: u64,
    accept: Option<String>,
}

/// Answer one host call.
///
/// `calling` is `None` while the extension describes itself, which is
/// before any source has handed it a host.
pub(crate) async fn answer(call: &Envelope, calling: Option<&Calling>) -> Envelope {
    let Some(calling) = calling else {
        return Envelope::failed(
            &call.id,
            Code::Unimplemented,
            crate::message!(
                "host-call-outside-invoke",
                "a host call is only answered during an invocation",
            ),
        );
    };

    match call.op.as_deref() {
        Some(FETCH_OP) => fetch(call, calling).await,

        other => {
            let op = other.unwrap_or_default();

            Envelope::failed(
                &call.id,
                Code::Unimplemented,
                crate::message!(
                    "host-op-unimplemented",
                    "the host capability {op:?} is not implemented",
                    op = op,
                ),
            )
        }
    }
}

/// Fetch a body, capped by the lower of the extension's limit and the host's.
async fn fetch(call: &Envelope, calling: &Calling) -> Envelope {
    let input = call.input.clone().unwrap_or_default();

    if let Err(detail) = envelope::check("FetchInput", &input) {
        return malformed(call, detail);
    }

    let input: FetchInput = match serde_json::from_value(input) {
        Ok(input) => input,
        Err(err) => return malformed(call, err.to_string()),
    };

    let cap = ByteLimit::bytes(input.max_bytes.min(MAX_FETCH_BYTES.get()));
    let mut req = Req::get(&input.url);

    if let Some(accept) = input.accept {
        req = req.accept(accept);
    }

    let body = match calling.host.fetch(&req, cap, &calling.ctx).await {
        Ok(body) => body,

        Err(err) => {
            let reason = err.to_string();

            return Envelope::problem(
                &call.id,
                err.code(),
                crate::message!("host-fetch-failed", "{reason}", reason = reason),
            );
        }
    };

    // Text where it is text, so an extension reading an index page need
    // not decode anything.
    let output = match std::str::from_utf8(&body) {
        Ok(text) => serde_json::json!({ "text": text }),
        Err(_) => serde_json::json!({ "base64": BASE64.encode(&body) }),
    };

    Envelope::host_result(&call.id, output)
}

/// The extension asked for something the protocol does not allow.
fn malformed(call: &Envelope, detail: String) -> Envelope {
    Envelope::failed(
        &call.id,
        Code::MetadataMalformed,
        crate::message!(
            "host-call-malformed",
            "malformed host call: {detail}",
            detail = detail,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::gear::PointKind;
    use crate::ext::gear::envelope::Dir;
    use crate::ext::testing::TestHost;
    use crate::net::fixture::{Canned, FixtureClient};

    fn calling(client: FixtureClient) -> Calling {
        Calling {
            host: Arc::new(TestHost::new(client)),
            ctx: Ctx::anonymous_for_test(),
        }
    }

    fn call(input: serde_json::Value) -> Envelope {
        Envelope {
            dir: Dir::HostCall,
            point: None,
            ..Envelope::invoke("7", PointKind::Source, FETCH_OP, input)
        }
    }

    #[tokio::test]
    async fn fetch_returns_text() {
        let client = FixtureClient::new().with("h://host.test/index", Canned::ok("hello"));
        let input = serde_json::json!({"url": "h://host.test/index", "max-bytes": 100});

        let answer = answer(&call(input), Some(&calling(client))).await;

        assert_eq!(answer.dir, Dir::HostResult);
        assert_eq!(answer.output.expect("output")["text"], "hello");
    }

    #[tokio::test]
    async fn fetch_returns_binary_as_base64() {
        let client =
            FixtureClient::new().with("h://host.test/bin", Canned::ok(vec![0xffu8, 0xfe, 0x00]));
        let input = serde_json::json!({"url": "h://host.test/bin", "max-bytes": 100});

        let answer = answer(&call(input), Some(&calling(client))).await;

        assert_eq!(answer.output.expect("output")["base64"], "//4A");
    }

    #[tokio::test]
    async fn fetch_missing_page_answers_problem() {
        let client = FixtureClient::new().with(
            "h://host.test/gone",
            Canned::status(http::StatusCode::NOT_FOUND),
        );
        let input = serde_json::json!({"url": "h://host.test/gone", "max-bytes": 100});

        let answer = answer(&call(input), Some(&calling(client))).await;

        assert_eq!(answer.dir, Dir::Problem);
        assert_eq!(answer.problem_code(), Code::ArtifactNotFound);
    }

    #[tokio::test]
    async fn fetch_without_limit_refused() {
        let input = serde_json::json!({"url": "h://host.test/index"});

        let answer = answer(&call(input), Some(&calling(FixtureClient::new()))).await;

        assert_eq!(answer.dir, Dir::Failed);
        assert_eq!(answer.problem_code(), Code::MetadataMalformed);
    }

    #[tokio::test]
    async fn op_unknown_unimplemented() {
        let mut head = call(serde_json::json!({}));
        head.op = Some("head".into());

        let answer = answer(&head, Some(&calling(FixtureClient::new()))).await;

        assert_eq!(answer.problem_code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn describe_gets_no_host() {
        let input = serde_json::json!({"url": "h://host.test/index", "max-bytes": 100});

        let answer = answer(&call(input), None).await;

        assert_eq!(answer.dir, Dir::Failed);
    }
}
