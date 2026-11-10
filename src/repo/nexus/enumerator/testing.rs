//! Fixtures shared by the Nexus enumerator's tests.

use std::sync::Arc;

use super::{COMPONENTS, NexusEnumerator};
use crate::core::ctx::Ctx;
use crate::ext::testing::{TestHost, options};
use crate::ext::{ExtHost, Options};
use crate::model::Cause;
use crate::net::FixtureClient;
use crate::repo::enumerate::{Enumerator, Page};

pub(super) const BASE: &str = "h://nexus.test";
pub(super) const REPO: &str = "maven-releases";

pub(super) fn url(cursor: Option<&str>) -> String {
    match cursor {
        None => format!("{BASE}/{COMPONENTS}?repository={REPO}"),
        Some(token) => {
            format!("{BASE}/{COMPONENTS}?repository={REPO}&continuationToken={token}")
        }
    }
}

pub(super) fn config(ecosystem: &str) -> Options {
    options(serde_json::json!({
        "repository": REPO,
        "ecosystem": ecosystem,
    }))
}

pub(super) fn enumerator(ecosystem: &str, host: Arc<dyn ExtHost>) -> NexusEnumerator {
    NexusEnumerator::open(BASE, &config(ecosystem), host).expect("opens")
}

pub(super) fn ctx() -> Ctx {
    Ctx::for_test(Cause::Enumerated {
        enumerator: "nexus".into(),
    })
}

pub(super) async fn walk_with(body: &str, ecosystem: &str, ctx: &Ctx) -> (Page, Arc<TestHost>) {
    let host = Arc::new(TestHost::new(
        FixtureClient::new().with_body(url(None), body.to_owned()),
    ));
    let page = enumerator(ecosystem, host.clone())
        .walk(None, ctx)
        .await
        .expect("walked");

    (page, host)
}
