//! Utilities for finding request provenance from a context.

use crate::core::ctx::Ctx;
use crate::core::message::Message;
use crate::model::Cause;

/// The provenance chain a record carries, leaf first.
pub fn provenance_chain(ctx: &Ctx) -> Vec<Message> {
    ctx.prov().chain().map(Cause::message).collect()
}
