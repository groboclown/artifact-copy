//! Shared internals, visible only inside this crate.
//!
//! The home for functionality that more than one module needs and none of
//! them owns -- where the alternative would be a second copy in an unrelated
//! subtree.
//!
//! Distinct from [`crate::core`], and the line between them is about
//! audience rather than about what the code does. `core` is what an
//! *embedder* works with: a `Ctx`, an `Error`, a `Problem`. What is here is
//! plumbing this crate happens to share, and nothing outside it should be
//! able to depend on -- so this module is `pub(crate)` and stays that way.
//!
//! Not a `util` bag. Something belongs here only when it has no natural
//! owner: a URL helper belongs in `net`, a version rule belongs in
//! `ecosystem`. The test is whether a reader would go looking for it
//! somewhere more specific first.

pub(crate) mod glob;
pub(crate) mod provenance;
pub(crate) mod purl;
pub(crate) mod schema;
