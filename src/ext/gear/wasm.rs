//! Run a WebAssembly core module as an extension.
//!
//! The module is compiled once; each message gets a fresh store and
//! instance, so nothing a call leaves behind reaches the next one. Within a
//! call the instance lives on across its host calls, which is what lets a
//! guest ask for a page and keep its place while the host fetches it.
//!
//! # Guest ABI
//!
//! ```text
//!   exports  memory
//!            ac_alloc(len: i32) -> ptr: i32
//!            ac_free(ptr: i32, len: i32)
//!            ac_handle(ptr: i32, len: i32) -> packed: i64
//!            _initialize()                      (optional, WASI reactor)
//!   imports  artifact-copy.host_call(ptr: i32, len: i32) -> packed: i64
//!
//!   packed = (ptr << 32) | len, a JSON message in guest memory
//! ```
//!
//! The host writes every message it hands over into memory it asked the
//! guest to allocate, and frees each answer it has read. WASI preview 1 is
//! linked so ordinary toolchains work, and grants nothing: no files, no
//! environment, no arguments, no network.

use std::path::Path;

use wasmtime::{
    Caller, Config, Engine, Instance, InstancePre, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::WasiP1Ctx;

use super::envelope::{self, Envelope};
use super::host::{self, Calling};
use crate::core::error::{Error, Result};
use crate::core::problem::Code;

/// The module name the host's imports live under.
const HOST_MODULE: &str = "artifact-copy";

const HOST_CALL: &str = "host_call";
const ALLOC: &str = "ac_alloc";
const FREE: &str = "ac_free";
const HANDLE: &str = "ac_handle";
const MEMORY: &str = "memory";

/// A WASI reactor's constructor, run once per instance before anything else.
const INITIALIZE: &str = "_initialize";

/// The most linear memory one instance may grow to.
const MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// The largest message either side may hand the other.
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// How much work one message may take, in wasmtime fuel (roughly one unit
/// per instruction). Generous for parsing an index page; a guest stuck in a
/// loop still ends.
const MAX_FUEL_PER_CALL: u64 = 50_000_000_000;

/// How often a running guest yields to the async runtime, in fuel, so one
/// long call cannot starve every other task on its thread.
const FUEL_YIELD_INTERVAL: u64 = 10_000_000;

/// What each store holds.
struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
    calling: Option<Calling>,
}

/// One compiled module, ready to instantiate.
pub(crate) struct Runtime {
    /// The configured extension name, for errors.
    name: String,
    engine: Engine,
    pre: InstancePre<State>,

    /// Fuel each message starts with; [`MAX_FUEL_PER_CALL`] outside tests.
    fuel: u64,
}

impl Runtime {
    /// Read and compile the module at `path`, and link it against the host.
    pub fn load(name: &str, path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|source| Error::ReadFile {
            path: path.to_owned(),
            source,
        })?;

        Self::compile(name, &bytes)
    }

    /// Compile a module from its binary form.
    pub fn compile(name: &str, bytes: &[u8]) -> Result<Self> {
        let unusable = |err: wasmtime::Error| {
            Error::Config(format!("extension {name:?} cannot be loaded: {err:#}"))
        };

        let mut config = Config::new();
        config.consume_fuel(true);

        let engine = Engine::new(&config).map_err(unusable)?;
        let module = Module::new(&engine, bytes).map_err(unusable)?;

        let mut linker: Linker<State> = Linker::new(&engine);
        wasmtime_wasi::p1::add_to_linker_async(&mut linker, |state| &mut state.wasi)
            .map_err(unusable)?;
        linker
            .func_wrap_async(HOST_MODULE, HOST_CALL, |caller, (ptr, len): (i32, i32)| {
                Box::new(host_call(caller, ptr, len))
            })
            .map_err(unusable)?;

        let pre = linker.instantiate_pre(&module).map_err(unusable)?;

        Ok(Self {
            name: name.to_owned(),
            engine,
            pre,
            fuel: MAX_FUEL_PER_CALL,
        })
    }

    /// Hand the guest one message and read its answer.
    ///
    /// `calling` is what host calls are served with; `None` refuses them.
    pub async fn handle(&self, request: &Envelope, calling: Option<Calling>) -> Result<Envelope> {
        self.exchange(request, calling)
            .await
            .map_err(|err| self.broken(format!("{err:#}")))
    }

    async fn exchange(
        &self,
        request: &Envelope,
        calling: Option<Calling>,
    ) -> wasmtime::Result<Envelope> {
        let mut store = self.store(calling)?;
        let instance = self.pre.instantiate_async(&mut store).await?;

        if let Some(init) = instance.get_func(&mut store, INITIALIZE) {
            init.typed::<(), ()>(&store)?
                .call_async(&mut store, ())
                .await?;
        }

        let bytes = envelope::encode(request).map_err(wasmtime::Error::msg)?;
        let (ptr, len) = give(&mut store, &instance, &bytes).await?;

        let handle = instance.get_typed_func::<(i32, i32), i64>(&mut store, HANDLE)?;
        let packed = handle.call_async(&mut store, (ptr, len)).await?;

        let memory = memory_of(&instance, &mut store)?;
        let answer = take(&mut store, &instance, memory, packed).await?;

        envelope::decode(&answer).map_err(wasmtime::Error::msg)
    }

    /// A store with the limits every call runs under.
    fn store(&self, calling: Option<Calling>) -> wasmtime::Result<Store<State>> {
        let state = State {
            wasi: WasiCtxBuilder::new().build_p1(),
            limits: StoreLimitsBuilder::new()
                .memory_size(MAX_MEMORY_BYTES)
                .build(),
            calling,
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(self.fuel)?;
        store.fuel_async_yield_interval(Some(FUEL_YIELD_INTERVAL))?;

        Ok(store)
    }

    /// The extension misbehaved: trapped, ran out of fuel or memory, or
    /// broke the ABI or the protocol.
    pub fn broken(&self, detail: String) -> Error {
        Error::Extension {
            extension: self.name.clone(),
            code: Code::MetadataMalformed,
            detail,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The `host_call` import: read the guest's request, answer it through the
/// host, and hand the answer back in guest memory.
async fn host_call(mut caller: Caller<'_, State>, ptr: i32, len: i32) -> wasmtime::Result<i64> {
    let memory = caller
        .get_export(MEMORY)
        .and_then(|export| export.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("the module exports no memory"))?;

    let bytes = read(&caller, memory, ptr, len)?;
    let call = envelope::decode(&bytes).map_err(wasmtime::Error::msg)?;
    let calling = caller.data().calling.clone();

    let answer = host::answer(&call, calling.as_ref()).await;
    let bytes = envelope::encode(&answer).map_err(wasmtime::Error::msg)?;

    let alloc = caller
        .get_export(ALLOC)
        .and_then(|export| export.into_func())
        .ok_or_else(|| wasmtime::Error::msg("the module exports no allocator"))?
        .typed::<i32, i32>(&caller)?;

    let len = message_len(bytes.len())?;
    let ptr = alloc.call_async(&mut caller, len).await?;
    memory.write(&mut caller, offset(ptr), &bytes)?;

    Ok(pack(ptr, len))
}

/// Copy `bytes` into memory the guest allocated for them.
async fn give(
    store: &mut Store<State>,
    instance: &Instance,
    bytes: &[u8],
) -> wasmtime::Result<(i32, i32)> {
    let alloc = instance.get_typed_func::<i32, i32>(&mut *store, ALLOC)?;
    let memory = memory_of(instance, &mut *store)?;

    let len = message_len(bytes.len())?;
    let ptr = alloc.call_async(&mut *store, len).await?;
    memory.write(&mut *store, offset(ptr), bytes)?;

    Ok((ptr, len))
}

/// Copy the guest's answer out of its memory, then let it free that memory.
async fn take(
    store: &mut Store<State>,
    instance: &Instance,
    memory: Memory,
    packed: i64,
) -> wasmtime::Result<Vec<u8>> {
    let (ptr, len) = unpack(packed);
    let bytes = read(&*store, memory, ptr, len)?;

    let free = instance.get_typed_func::<(i32, i32), ()>(&mut *store, FREE)?;
    free.call_async(&mut *store, (ptr, len)).await?;

    Ok(bytes)
}

fn memory_of(instance: &Instance, store: &mut Store<State>) -> wasmtime::Result<Memory> {
    instance
        .get_memory(store, MEMORY)
        .ok_or_else(|| wasmtime::Error::msg("the module exports no memory"))
}

/// Read one message the guest placed in its memory, refusing an oversized one
/// before copying it.
fn read(
    store: impl wasmtime::AsContext,
    memory: Memory,
    ptr: i32,
    len: i32,
) -> wasmtime::Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| wasmtime::Error::msg("negative message length"))?;

    if len > MAX_MESSAGE_BYTES {
        return Err(wasmtime::Error::msg(format!(
            "a {len} byte message exceeds the {MAX_MESSAGE_BYTES} byte limit"
        )));
    }

    let mut bytes = vec![0; len];
    memory.read(store, offset(ptr), &mut bytes)?;

    Ok(bytes)
}

fn message_len(len: usize) -> wasmtime::Result<i32> {
    if len > MAX_MESSAGE_BYTES {
        return Err(wasmtime::Error::msg(format!(
            "a {len} byte message exceeds the {MAX_MESSAGE_BYTES} byte limit"
        )));
    }

    i32::try_from(len).map_err(|_| wasmtime::Error::msg("message too large"))
}

/// A guest pointer as a memory offset. Guest pointers are unsigned 32-bit
/// values carried in an `i32`.
fn offset(ptr: i32) -> usize {
    ptr as u32 as usize
}

fn pack(ptr: i32, len: i32) -> i64 {
    ((ptr as u32 as u64) << 32 | len as u32 as u64) as i64
}

fn unpack(packed: i64) -> (i32, i32) {
    let packed = packed as u64;

    ((packed >> 32) as u32 as i32, packed as u32 as i32)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ext::gear::PointKind;
    use crate::ext::gear::envelope::Dir;

    /// A guest that answers every message with the JSON text it holds at
    /// offset 1024, and allocates with a bump pointer from offset 4096.
    ///
    /// `answer` is placed in a data segment; `body` replaces `ac_handle`'s
    /// body when a test needs another behavior.
    pub(crate) fn guest(answer: &str, handle_body: Option<&str>) -> String {
        let escaped: String = answer.bytes().map(|byte| format!("\\{byte:02x}")).collect();
        let len = answer.len();

        let body = handle_body.map(str::to_owned).unwrap_or_else(|| {
            format!("(i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {len}))")
        });

        format!(
            r#"(module
                (import "artifact-copy" "host_call" (func $host_call (param i32 i32) (result i64)))
                (memory (export "memory") 2)
                (global $next (mut i32) (i32.const 4096))
                (data (i32.const 1024) "{escaped}")
                (func (export "ac_alloc") (param $len i32) (result i32)
                    (local $at i32)
                    (local.set $at (global.get $next))
                    (global.set $next (i32.add (global.get $next) (local.get $len)))
                    (local.get $at))
                (func (export "ac_free") (param i32 i32))
                (func (export "ac_handle") (param $ptr i32) (param $len i32) (result i64)
                    {body}))"#
        )
    }

    pub(crate) fn runtime(wat: &str) -> Runtime {
        let bytes = ::wat::parse_str(wat).expect("valid WAT");

        Runtime::compile("test", &bytes).expect("compiles")
    }

    fn invoke() -> Envelope {
        Envelope::invoke("1", PointKind::Source, "versions", serde_json::json!({}))
    }

    #[tokio::test]
    async fn guest_answers() {
        let runtime = runtime(&guest(
            r#"{"v":1,"id":"1","dir":"result","output":{}}"#,
            None,
        ));

        let answer = runtime.handle(&invoke(), None).await.expect("answers");

        assert_eq!(answer.dir, Dir::Result);
    }

    #[tokio::test]
    async fn guest_invalid_answer_broken() {
        let runtime = runtime(&guest(r#"{"v":1,"dir":"result"}"#, None));

        let err = runtime.handle(&invoke(), None).await.expect_err("refused");

        assert_eq!(err.code(), Code::MetadataMalformed);
    }

    #[tokio::test]
    async fn guest_trap_broken() {
        let runtime = runtime(&guest("", Some("unreachable")));

        let err = runtime.handle(&invoke(), None).await.expect_err("trapped");

        assert!(matches!(err, Error::Extension { .. }), "{err}");
    }

    #[tokio::test]
    async fn guest_endless_loop_runs_out_of_fuel() {
        let mut runtime = runtime(&guest("", Some("(loop (br 0)) (i64.const 0)")));
        runtime.fuel = 1_000_000;

        let err = runtime.handle(&invoke(), None).await.expect_err("stopped");

        assert!(err.to_string().contains("fuel"), "{err}");
    }

    /// Answers only when the growth past the cap is refused.
    #[tokio::test]
    async fn guest_memory_growth_capped() {
        // 5000 pages of 64 KiB is about 312 MiB, past the cap.
        let answer = r#"{"v":1,"id":"1","dir":"result","output":{}}"#;
        let grow = format!(
            "(if (i32.ne (memory.grow (i32.const 5000)) (i32.const -1)) (then unreachable)) \
             (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {}))",
            answer.len()
        );
        let runtime = runtime(&guest(answer, Some(&grow)));

        runtime
            .handle(&invoke(), None)
            .await
            .expect("growth refused");
    }

    /// The guest forwards its host call's answer as its own.
    #[tokio::test]
    async fn guest_host_call_served() {
        let call = r#"{"v":1,"id":"2","dir":"host-call","op":"fetch","input":{"url":"h://host.test/a","max-bytes":10}}"#;
        let body = format!(
            "(call $host_call (i32.const 1024) (i32.const {}))",
            call.len()
        );
        let runtime = runtime(&guest(call, Some(&body)));

        let client = crate::net::fixture::FixtureClient::new()
            .with("h://host.test/a", crate::net::fixture::Canned::ok("page"));
        let calling = Calling {
            host: std::sync::Arc::new(crate::ext::testing::TestHost::new(client)),
            ctx: crate::core::ctx::Ctx::anonymous_for_test(),
        };

        let answer = runtime
            .handle(&invoke(), Some(calling))
            .await
            .expect("answers");

        assert_eq!(answer.dir, Dir::HostResult);
        assert_eq!(answer.output.expect("output")["text"], "page");
    }

    #[tokio::test]
    async fn guest_oversized_answer_refused() {
        let huge = format!(
            "(i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {}))",
            MAX_MESSAGE_BYTES + 1
        );
        let runtime = runtime(&guest("", Some(&huge)));

        let err = runtime.handle(&invoke(), None).await.expect_err("refused");

        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn compile_non_module_is_config_error() {
        let err = Runtime::compile("test", b"not wasm")
            .err()
            .expect("refused");

        assert!(matches!(err, Error::Config(_)), "{err}");
    }

    #[test]
    fn pack_round_trips_high_pointers() {
        let ptr = u32::MAX as i32;

        assert_eq!(unpack(pack(ptr, 7)), (ptr, 7));
    }
}
