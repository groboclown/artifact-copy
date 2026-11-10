//! An artifact-copy source listing Amazon Corretto releases from GitHub.
//!
//! Answers `corretto-<major>@<tag>` as a raw artifact, such as
//! `corretto-25@25.0.5.0.10`. `versions` and `metadata` read the release
//! listing of `corretto/corretto-<major>` through the GitHub REST API, and
//! the files come from each release's Markdown download table. The `files`
//! option narrows the files by name pattern.
//!
//! Build with `cargo build --release --target wasm32-wasip1`.

// Only the WASM entry points call the logic; a native build is for tests.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]

mod protocol;
mod releases;
mod table;
mod tag;

guest_kit::export!(crate::protocol::Corretto);
