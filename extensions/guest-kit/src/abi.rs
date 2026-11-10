//! The WASM side of the guest ABI; see `src/ext/gear/wasm.rs` in the tool.
//!
//! ```text
//!   ac_alloc / ac_free   memory the host writes messages into, and frees answers from
//!   ac_handle            one message in, one answer out, as (ptr << 32) | len
//!   host_call            imported from "artifact-copy"
//! ```
//!
//! A message the host hands over belongs to the guest, which frees it; an
//! answer the guest hands back belongs to the host, which frees it.

use std::alloc::{Layout, alloc as raw_alloc, dealloc};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use crate::protocol::{self, Failure, Host, Source};

#[link(wasm_import_module = "artifact-copy")]
unsafe extern "C" {
    fn host_call(ptr: i32, len: i32) -> i64;
}

/// Correlation ids for host calls.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Host calls through the import.
struct WasmHost;

impl Host for WasmHost {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<String, Failure> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed).to_string();
        let call = json!({
            "v": protocol::PROTOCOL_VERSION,
            "id": id,
            "dir": "host-call",
            "op": "fetch",
            "input": {"url": url, "max-bytes": max_bytes},
        });
        let call = serde_json::to_vec(&call).map_err(|err| Failure::malformed(err.to_string()))?;

        // SAFETY: the host reads `len` bytes at `ptr`, which `call` holds
        // for the length of the call.
        let packed = unsafe { host_call(call.as_ptr() as i32, call.len() as i32) };

        let (ptr, len) = unpack(packed);
        let answer = take(ptr, len);

        protocol::read_host_result(&answer)
    }
}

/// Copy out, then free, a message the host placed in memory from `ac_alloc`.
fn take(ptr: usize, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }

    // SAFETY: the host wrote `len` bytes at `ptr`, allocated by `ac_alloc`.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec();

    // SAFETY: allocated by `ac_alloc` with this length, and no longer read.
    unsafe { free(ptr as i32, len as i32) };

    bytes
}

/// Hand `bytes` to the host in memory it will free with `ac_free`.
fn give(bytes: &[u8]) -> i64 {
    let ptr = alloc(bytes.len() as i32);

    if !bytes.is_empty() {
        // SAFETY: `alloc` returned `bytes.len()` writable bytes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len()) };
    }

    ((ptr as u32 as u64) << 32 | bytes.len() as u64) as i64
}

fn unpack(packed: i64) -> (usize, usize) {
    let packed = packed as u64;

    ((packed >> 32) as usize, packed as u32 as usize)
}

fn layout(len: i32) -> Layout {
    Layout::from_size_align(len as usize, 1).expect("a byte layout")
}

/// `ac_alloc`.
pub fn alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }

    // SAFETY: a non-zero size.
    unsafe { raw_alloc(layout(len)) as i32 }
}

/// `ac_free`.
///
/// # Safety
///
/// `ptr` and `len` must come from one [`alloc`] call, freed once.
pub unsafe fn free(ptr: i32, len: i32) {
    if len <= 0 {
        return;
    }

    // SAFETY: the caller's contract.
    unsafe { dealloc(ptr as *mut u8, layout(len)) };
}

/// `ac_handle`: one message for `source`.
pub fn handle(ptr: i32, len: i32, source: &dyn Source) -> i64 {
    let request = take(ptr as u32 as usize, len as u32 as usize);
    let answer = protocol::handle(&request, source, &WasmHost);
    let answer = serde_json::to_vec(&answer).unwrap_or_default();

    give(&answer)
}
