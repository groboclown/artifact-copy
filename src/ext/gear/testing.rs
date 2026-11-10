//! Guests for tests elsewhere in the crate, written in WAT, and a check
//! against the protocol schema.

use super::*;

/// Where the router guest keeps its fixed strings and its answers.
const PREFIX_AT: usize = 0;
const ID_NEEDLE_AT: usize = 32;
const QUOTE_AT: usize = 48;
const ROUTES_AT: usize = 1024;

/// The bytes every answer starts with, up to the echoed id.
const PREFIX: &str = r#"{"v":1,"id":""#;
const ID_NEEDLE: &str = r#""id":""#;

/// What a router answers when no route matches.
const FALLBACK: &str = r#"","dir":"failed","code":"unimplemented"}"#;

/// A guest answering each message by the first route whose needle the
/// message contains, echoing the message's id.
///
/// Each route is `(needle, rest)`, where `rest` is the answer after the
/// id, starting with `",`:
///
/// ```text
///   (r#""op":"versions""#, r#"","dir":"result","output":{"versions":[]}}"#)
/// ```
pub(crate) fn router(routes: &[(&str, &str)]) -> String {
    let mut data = String::new();
    let mut checks = String::new();
    let mut at = ROUTES_AT;

    let mut place = |text: &str, data: &mut String| -> (usize, usize) {
        let placed = (at, text.len());
        data.push_str(&format!("(data (i32.const {at}) \"{}\")\n", escape(text)));
        at += text.len();

        placed
    };

    let (fallback_at, fallback_len) = place(FALLBACK, &mut data);

    // Last route first, so the first matching route wins.
    for (needle, rest) in routes.iter().rev() {
        let (needle_at, needle_len) = place(needle, &mut data);
        let (rest_at, rest_len) = place(rest, &mut data);

        checks.push_str(&format!(
            "(if (i32.ge_s (call $find (local.get $p) (local.get $l) (i32.const {needle_at}) (i32.const {needle_len})) (i32.const 0))
                (then (local.set $rest (i32.const {rest_at})) (local.set $restl (i32.const {rest_len}))))\n"
        ));
    }

    let prefix_len = PREFIX.len();
    let id_needle_len = ID_NEEDLE.len();
    let heap_at = at.next_multiple_of(8);

    format!(
        r#"(module
  (import "artifact-copy" "host_call" (func $host_call (param i32 i32) (result i64)))
  (memory (export "memory") 4)
  (global $next (mut i32) (i32.const {heap_at}))
  (data (i32.const {PREFIX_AT}) "{prefix}")
  (data (i32.const {ID_NEEDLE_AT}) "{id_needle}")
  (data (i32.const {QUOTE_AT}) "\22")
  {data}
  (func $alloc (export "ac_alloc") (param $len i32) (result i32)
(local $at i32)
(local.set $at (global.get $next))
(global.set $next (i32.add (global.get $next) (local.get $len)))
(local.get $at))
  (func (export "ac_free") (param i32 i32))
  (func $find (param $h i32) (param $hl i32) (param $n i32) (param $nl i32) (result i32)
(local $i i32) (local $j i32)
(block $none
  (loop $outer
    (br_if $none (i32.gt_s (i32.add (local.get $i) (local.get $nl)) (local.get $hl)))
    (local.set $j (i32.const 0))
    (block $mismatch
      (loop $inner
        (if (i32.eq (local.get $j) (local.get $nl)) (then (return (local.get $i))))
        (br_if $mismatch
          (i32.ne
            (i32.load8_u (i32.add (local.get $h) (i32.add (local.get $i) (local.get $j))))
            (i32.load8_u (i32.add (local.get $n) (local.get $j)))))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $inner)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $outer)))
(i32.const -1))
  (func (export "ac_handle") (param $p i32) (param $l i32) (result i64)
(local $id i32) (local $idl i32) (local $rest i32) (local $restl i32) (local $out i32) (local $len i32)
(local.set $id
  (i32.add (local.get $p)
    (i32.add (call $find (local.get $p) (local.get $l) (i32.const {ID_NEEDLE_AT}) (i32.const {id_needle_len}))
             (i32.const {id_needle_len}))))
(local.set $idl
  (call $find (local.get $id) (i32.sub (i32.add (local.get $p) (local.get $l)) (local.get $id))
              (i32.const {QUOTE_AT}) (i32.const 1)))
(local.set $rest (i32.const {fallback_at}))
(local.set $restl (i32.const {fallback_len}))
{checks}
(local.set $len (i32.add (i32.const {prefix_len}) (i32.add (local.get $idl) (local.get $restl))))
(local.set $out (call $alloc (local.get $len)))
(memory.copy (local.get $out) (i32.const {PREFIX_AT}) (i32.const {prefix_len}))
(memory.copy (i32.add (local.get $out) (i32.const {prefix_len})) (local.get $id) (local.get $idl))
(memory.copy (i32.add (local.get $out) (i32.add (i32.const {prefix_len}) (local.get $idl)))
             (local.get $rest) (local.get $restl))
(i64.or (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
        (i64.extend_i32_u (local.get $len)))))"#,
        prefix = escape(PREFIX),
        id_needle = escape(ID_NEEDLE),
    )
}

/// The route answering `describe` for a raw source.
pub(crate) const DESCRIBE_RAW_SOURCE: (&str, &str) = (
    r#""dir":"describe""#,
    r#"","dir":"describe","output":{"protocol":1,"points":["source"],"ecosystems":[{"id":"raw","purl-type":"raw","osv-name":""}]}}"#,
);

/// Every byte as a WAT string escape.
fn escape(text: &str) -> String {
    text.bytes().map(|byte| format!("\\{byte:02x}")).collect()
}

/// Compile a WAT guest to its binary form.
pub(crate) fn binary(wat: &str) -> Vec<u8> {
    ::wat::parse_str(wat).expect("valid WAT")
}

/// Launch a WAT guest as `launch` would a module file.
pub(crate) fn launch_wat(wat: &str) -> Result<Gear> {
    start(wasm::Runtime::compile("test", &binary(wat))?)
}

/// Validate one value against a named definition in the protocol schema.
pub(crate) fn validate_against(definition: &str, value: &serde_json::Value) -> Vec<String> {
    let document: serde_json::Value =
        serde_json::from_str(PROTOCOL_SCHEMA).expect("the built-in schema parses");

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/$defs/{definition}"),
        "$defs": document["$defs"],
    });

    let validator = jsonschema::validator_for(&schema).expect("the definition compiles");

    validator
        .iter_errors(value)
        .map(|err| crate::internal::schema::violation("", &err))
        .collect()
}
