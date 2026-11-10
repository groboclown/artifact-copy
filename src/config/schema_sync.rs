//! The committed schema lists the spellings of every closed enum the
//! configuration reads. Each test here checks one list against the Rust
//! enum, so a variant added on one side and not the other fails a test
//! rather than a user's configuration.
//!
//! The Rust side is read from serde itself: asked for an unknown variant,
//! a derived `Deserialize` refuses with every name it accepts
//! ("expected one of `a`, `b`"). That list is generated from the enum, so
//! it cannot drift the way a hand-written one would.

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{
    Authentication, Extension, LogLevel, OutputFormat, Payloads, SecretValue, SigningScheme,
    UnknownPublishTime,
};
use crate::core::problem::Class;

/// A spelling no enum accepts, to make serde list the ones it does.
const UNKNOWN: &str = "no-such-variant";

/// How an enum is written in a configuration.
enum Tagging {
    /// As a bare string: `level: info`.
    Plain,

    /// As an object whose `kind` names the variant: `{kind: env, ...}`.
    Kind,
}

/// The spellings serde accepts for `T`, sorted.
fn accepted<T: DeserializeOwned>(tagging: Tagging) -> Vec<String> {
    let probe = match tagging {
        Tagging::Plain => json!(UNKNOWN),
        Tagging::Kind => json!({ "kind": UNKNOWN }),
    };

    let Err(refusal) = serde_json::from_value::<T>(probe) else {
        panic!("{UNKNOWN} was accepted");
    };

    // Every name serde lists after "expected" is in backticks.
    let refusal = refusal.to_string();
    let (_, expected) = refusal
        .split_once("expected")
        .unwrap_or_else(|| panic!("no variant list in: {refusal}"));

    let mut names: Vec<String> = expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();

    names.sort_unstable();
    names
}

/// The committed configuration schema.
fn schema() -> Value {
    serde_json::from_str(include_str!("../../schema/config.schema.json")).expect("parses")
}

/// The spellings of a schema `enum` at `pointer`, sorted.
fn listed(pointer: &str) -> Vec<String> {
    let schema = schema();
    let entries = schema
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no enum at {pointer}"));

    sorted_strings(entries.iter())
}

/// The `kind` constants of a schema `oneOf` at `pointer`, sorted.
fn branches(pointer: &str) -> Vec<String> {
    let schema = schema();
    let entries = schema
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no oneOf at {pointer}"));

    sorted_strings(
        entries
            .iter()
            .map(|branch| &branch["properties"]["kind"]["const"]),
    )
}

fn sorted_strings<'a>(values: impl Iterator<Item = &'a Value>) -> Vec<String> {
    let mut names: Vec<String> = values
        .map(|value| value.as_str().expect("a string").to_owned())
        .collect();

    names.sort_unstable();
    names
}

#[test]
fn cache_payloads_match() {
    assert_eq!(
        accepted::<Payloads>(Tagging::Plain),
        listed("/properties/setup/properties/cache-payloads/enum")
    );
}

#[test]
fn log_level_matches() {
    assert_eq!(
        accepted::<LogLevel>(Tagging::Plain),
        listed("/properties/setup/properties/log/properties/level/enum")
    );
}

#[test]
fn output_format_matches() {
    assert_eq!(
        accepted::<OutputFormat>(Tagging::Plain),
        listed("/properties/setup/properties/log/properties/output-format/enum")
    );
}

#[test]
fn unknown_publish_time_matches() {
    assert_eq!(
        accepted::<UnknownPublishTime>(Tagging::Plain),
        listed("/$defs/UnknownPublishTime/enum")
    );
}

#[test]
fn signing_scheme_matches() {
    assert_eq!(
        accepted::<SigningScheme>(Tagging::Plain),
        listed("/$defs/SigningKey/properties/scheme/enum")
    );
}

#[test]
fn problem_class_matches() {
    assert_eq!(
        accepted::<Class>(Tagging::Plain),
        listed("/$defs/ProblemClass/enum")
    );
}

#[test]
fn extension_kind_matches() {
    assert_eq!(
        accepted::<Extension>(Tagging::Kind),
        branches("/$defs/Extension/oneOf")
    );
}

#[test]
fn authentication_kind_matches() {
    assert_eq!(
        accepted::<Authentication>(Tagging::Kind),
        branches("/$defs/Authentication/oneOf")
    );
}

#[test]
fn secret_kind_matches() {
    assert_eq!(
        accepted::<SecretValue>(Tagging::Kind),
        branches("/$defs/SecretValue/oneOf")
    );
}
