# Writing Your Own Extension

An extension supplies a kind the tool does not build in. Today only a **WASM source** runs: a WebAssembly core module that tells the tool which versions of an artifact exist and which files each version holds. The tool downloads and verifies the files itself.

[`extensions/nodejs-releases`](../extensions/nodejs-releases/) and [`extensions/corretto-releases`](../extensions/corretto-releases/) are complete examples in Rust, built with `make build-extensions`. Both use [`extensions/guest-kit`](../extensions/guest-kit/), which implements the ABI and envelope below, so an extension supplies only a `guest_kit::Source` and `guest_kit::export!`.

## Configuring

```yaml
extensions:
  my-source:
    kind: wasm
    module: my_source.wasm      # relative to this configuration file

sources:
  mine:
    host: my-host               # every fetch must stay under this host
    kind: my-source
    options: {}                 # passed to the module as written
```

## What the module sees

The module can't reach the network, files, or the environment. It asks the tool for pages through one import, and the tool applies the host's constraints and credentials. The module never sees a credential.

Every message is one JSON document that validates against [`schema/extension-protocol.schema.json`](../schema/extension-protocol.schema.json):

| From the tool | The module answers |
|---|---|
| `{"dir": "describe"}` | `{"dir": "describe", "output": Description}` with `points: ["source"]`, exactly one built-in ecosystem, such as `raw`, and an optional `version-scheme` |
| `{"dir": "invoke", "op": "versions", "input": SourceVersionsInput}` | `{"dir": "result", "output": SourceVersionsOutput}` |
| `{"dir": "invoke", "op": "metadata", "input": SourceMetadataInput}` | `{"dir": "result", "output": SourceMetadataOutput}` |

`version-scheme` names how versions order: `semver`, `maven`, `pep440`, or `tags`. Without it, the ecosystem decides, and raw has no order. Under `semver`, a request `nodejs@24` means the newest `24.x.y`, while `nodejs@24.1.0` stays exact.

An answer echoes the request's `v` and `id`. A module that can't answer returns `{"dir": "failed", "code": "artifact-not-found", "message": {"id": "...", "text": "..."}}`, using a problem code such as `artifact-not-found` or `metadata-malformed`.

While it handles a message, the module may ask the tool for a page:

```json
{"v": 1, "id": "7", "dir": "host-call", "op": "fetch", "input": {"url": "https://nodejs.org/dist/", "max-bytes": 4194304}}
```

The answer is `{"dir": "host-result", "output": {"text": "..."}}`, or `{"base64": "..."}` for a body that isn't UTF-8. A failure, such as a `404`, comes back as `{"dir": "problem", "code": "artifact-not-found", ...}`. The tool caps `max-bytes` at 16 MiB.

## The ABI

| Export | Purpose |
|---|---|
| `memory` | Linear memory the tool reads and writes messages in. |
| `ac_alloc(len: i32) -> i32` | Memory for a message the tool hands over. The module owns it and frees it. |
| `ac_free(ptr: i32, len: i32)` | The tool frees an answer after reading it. |
| `ac_handle(ptr: i32, len: i32) -> i64` | Handle one message and return the answer as `(ptr << 32) \| len`. |
| `_initialize()` | Optional. Runs first, as for any WASI reactor. |

| Import | Purpose |
|---|---|
| `artifact-copy.host_call(ptr: i32, len: i32) -> i64` | Send a `host-call` and receive the answer as `(ptr << 32) \| len`, allocated with `ac_alloc`. |

Build for `wasm32-wasip1` as a `cdylib`. WASI is linked but grants nothing. Each message runs in a fresh instance, so the module can't keep state from one message to the next. Memory, work, and message size are capped. A module that exceeds a cap, traps, or answers outside the schema fails that request as `metadata-malformed`.
