# Extension Points and the Extension Mechanism

Throughout the code, there exist well defined places where a user can extend the functionality of this tool with their own custom code.  These interface with the *extension mechanism*.

## Extension Mechanism Sandbox

The extension mechanism provides a uniform approach to calling out to user code.  It runs under a few core principles:

* The extension will not perform network I/O.
* The extension has access only to a sandbox directory for file reads and writes.  The sandbox directory shouldn't be shared between extensions, and can't be depended upon to remain present between calls to the same extension.
* Calls into the extension are stateless (they don't expect one call to cause the extension to remember that state).

Because the extensions may run slow - the start time for JS based WASM can be in the order of minutes - the extension points should aim to batch as much of the communication to the extension as possible.

The explicit allowance for file access means that the interface uses this as a way to pass large objects, in particular downloaded URLs, to and from the extension.  A consequence of the "stateless" rule means that extensions can't rely on that sandbox directory keeping its contents from one call to the next.

## Extension Point

An extension point refers to a place in the code where the user's configuration options choose between different ways of performing the requested actions.  An extension point isn't directly the extension mechanism, but is a place for integration between a caller and the extension mechanism.

Each extension point may have a multitude of requirements that make interfacing with the extension mechanism difficult.  For example, a request to find dependencies of an artifact, for a Maven dependency, may involve reading in the chain of parent POM files to determine all the properties.  Pushing an artifact and its files to a repository may require first checking if the file exists there, and its checksums, to determine whether an upload means allow, skip because it exists, or report a mismatch error.

Because of these differences, the extension point implementation selection allows for:

* A built-in solution.  The tool directly knows how to perform the necessary action, and does it.
* The user to declare the extension module, and the module includes metadata information about how to interface with it.  The extension module is written for just one extension point, and so knows the expected gearing.  The extension module *requests* a gearing, but the tool determines the one actually used.

The list of extension points:

* Enumerator
* Source
* Target
* Advisory
* Lock file parsing

An *ecosystem* is not itself an extension point, in so much that it interfaces with an extension mechanism, but it is extensible insomuch as embedders can add their own, and it may be possible for an extension to define an ecosystem not present in the built-in collection.  Such an extension declares it in its metadata by supplying the constants the `Ecosystem` trait's typed methods return (id, purl type, OSV name, dependency kinds, companion documents), and the tool builds an ecosystem object from them; no gearing is involved.

A *host* defines an endpoint for a server technology.  By itself, it isn't an extension point.  Future refactoring will hide much of this information from the end-user, so that it will allow for choosing the Enumerator and Source implementation based on the host technology + the ecosystem of the repository.  The extensions may need to integrate this knowledge into their metadata.

## Extension Point / Mechanism Gearing

The two pieces of the mechanism and extension point meet at the *extension point gearing*.  The gearing works outside the extension mechanism sandbox, and so does not have the I/O limitations that the mechanism has.  The gearing has a set of allowed actions for the extension point, and can add additional protection layers around the extension mechanism, such as file copy vs. file links in the sandbox directory, or execution within a Linux landlock process.

All built-in extension point implementations avoid the gearing complexities.

### Built-ins

* A built-in is constructed with an `ExtHost`, and performs its own network I/O through it.  The host applies the URL constraints, attaches credentials, and caps sizes; the built-in holds no HTTP client.
* The host's *cache* is where downloads land, under `setup.cache-dir`, and it persists between runs.  It is not a sandbox: a built-in reads a cached file where it lies, and a target is handed the cached payload's path.  A built-in has no scratch directory; one that needs a file only for the length of a request uses a temporary file.
* The *sandbox* is an extension's scratch directory, and only a gearing creates one, usually as a temporary directory, and possibly one per thread when the gearing runs an extension in parallel.  The gearing stages into it what the extension needs, such as a copy of a cached payload.

### The Target gearing

A target extension cannot hold a lock or read the repository before it writes, so the Target gearing runs it in three phases: the extension states what it needs to know (ask), the gearing finds out, from the report or from the repository (answer), and the extension returns the operations to perform rather than performing them (prepare).  The question types for this live with the protocol types in `ext::gear`.  Built-in targets perform their own I/O and do not use these phases.

### Protecting the files a target is handed

A payload lives in the source's cache, and a target needs its bytes. **A built-in target is handed the cached file itself** and reads it in place, so the cache keeps its one copy; see [report-as-database.md](report-as-database.md#decisions). A target that wrote to that file would therefore write into the cache. No built-in target does -- `NpmTarget::publish` reads the tarball and writes a separate document beside it -- but a sandbox is documented as writable scratch, and an extension may legitimately use it as such.

So the protection comes in layers, from the one already built to the ones the gearing still needs:

1. **Read-only on disk.** A cached payload is made read-only after download, which turns the ordinary accident -- code opening the file for writing -- into a loud failure rather than a silent corruption. A mitigation, not a guarantee: code that unlinks the file and creates a new one in its place defeats it.
2. **Copy into the sandbox, never lend.** An out-of-process target is given its own copy in its own scratch directory by the Target gearing, never the cache's path or a link to it, so nothing it does to its copy reaches the cache. This is where copying belongs.
3. **Clear the flag on the copy.** `fs::copy` carries the read-only flag to the copy, so the gearing must clear it there (`ext::cache::writable`), or the extension cannot use its scratch directory as scratch.
4. **Linux landlock confinement**, so an extension process can reach its scratch directory and nothing else on disk.
5. **A sandbox per extension**, so one extension cannot read or alter what another was handed.

**A `copy` staging mode** would extend the second layer to built-in targets, for a user running one they have reason not to trust. It is accepted rather than designed out: copying every payload of every artifact of every migration is a large and certain cost against a small and hypothetical one, so it is a future option rather than the default.

## Extension Point Gearing Implementations

Initially, the project aims to support WASM modules and command-line tools as extension modules.  Both of these pose different problems that the gearing must aim to make simple, or at least possible.

### WASM

The WASM modules allow for the WASM code to gain a request/answer interface to the allowed set of actions.  Thus, they can remain stateful between call-outs.

Implemented for the Source point only, in `ext::gear` (mechanism) and `repo::extension` (point adapter).

```text
Sources::build_direct --kind names an extension--> gear::launch --compile, describe--> Gear
ExtensionSource::versions / metadata --> Gear::invoke --> fresh Store + Instance
                                             guest host_call --> gear::host --> ExtHost::fetch
ExtensionSource::download --> repo::download --> ExtHost   (never the module)
```

- **Lifecycle.** `launch` compiles the module once and asks it to `describe` itself, so a broken or incompatible module fails while the configuration is read. Each message then gets its own store and instance: stateful across the host calls of one invocation, stateless across invocations.
- **ABI.** The module exports `memory`, `ac_alloc(len) -> ptr`, `ac_free(ptr, len)`, and `ac_handle(ptr, len) -> packed`, and imports `artifact-copy.host_call(ptr, len) -> packed`, where `packed` is `(ptr << 32) | len`. Every message is one protocol envelope as JSON. A message the host hands over belongs to the guest; an answer the guest hands back is freed by the host. A WASI reactor's `_initialize` runs first when exported.
- **Grants.** WASI preview 1 is linked so ordinary toolchains work, with no files, environment, or arguments. The only way out is `host_call`, answered through the source's own `ExtHost`.
- **Limits.** Memory, fuel per message, and message size are capped by constants in `ext/gear/wasm.rs`, and a `fetch` body by `ext/gear/host.rs`. Breaking a limit, trapping, or answering outside the schema is `Error::Extension` with `metadata-malformed`; a `failed` answer keeps the extension's own code, so a proxy still falls through on `artifact-not-found`.
- **Versions.** A declared `version-scheme` becomes `ExtensionSource::version_handler`, so resolution orders and matches with it. Configuration can't override it: extension kinds stay `Fixed` for `repo::version_scheme`.
- **Validation.** Every envelope, in both directions, and each op's input or output is checked against `schema/extension-protocol.schema.json`.

`extensions/nodejs-releases` and `extensions/corretto-releases` are such modules, both built on the shared guest side in `extensions/guest-kit`.

### Streaming CLI

The CLI can use stdout to send requests to the gearing, and stdin to receive answers from the gearing.

### Separate Calls CLI

The CLI can process a request, then on exit send back a request for more information, or a final result.

### The Extension Protocol

See [`schema/extension-protocol.schema.json`](../../schema/extension-protocol.schema.json).
