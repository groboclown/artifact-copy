//! An artifact-copy source listing NodeJS releases from nodejs.org/dist.
//!
//! Answers `nodejs@<version>` as a raw artifact: `versions` reads the dist
//! index, and `metadata` reads one release directory plus its
//! `SHASUMS256.txt`. The `files` option narrows the files by name pattern.
//!
//! Build with `cargo build --release --target wasm32-wasip1`.

// Only the WASM entry points call the logic; a native build is for tests.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]

mod links;
mod protocol;
mod releases;

guest_kit::export!(crate::protocol::NodeJs);
