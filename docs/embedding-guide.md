# Guide to Embedding the Migrator

How to use `artifact-copy` as a library from your own Rust program. The `artifact-copy` binary is itself a thin shell over this library ([`src/main.rs`](../src/main.rs)), so anything the command line does, a program can do.

An embedder does one of two things:

- **Drive a migration:** run `copy`, `inspect`, or `find` from your own program, with your own arguments, scheduling, and output.
- **Add a repository kind:** support a repository the tool does not build in.

The public API is what those two need, and nothing more; [`src/lib.rs`](../src/lib.rs) lists it and says why. Everything else is `pub(crate)`.


## Driving a migration

[`examples/embedder/copy.rs`](../examples/embedder/copy.rs) is a complete program that copies one artifact between two configured repositories, using [`migrate.yaml`](../examples/embedder/migrate.yaml) beside it. Run it with `cargo run --example embedder-copy`. It follows six steps.

### 1. Settings

A run reads a `config::Config`. Load it from files with `cli::ConfigLoader`, which finds, validates, and merges them exactly as the command line's `--config` does:

```rust
let config = ConfigLoader::new().add_path("migrate.yaml").load()?;
```

`Config` is also `serde::Deserialize`, so a program that keeps settings elsewhere can deserialize one directly. It then skips the schema validation `ConfigLoader` applies. The settings themselves are documented in [configuration-general.md](configuration-general.md) and the `configuration-*.md` files beside it.

### 2. The run's context

Every operation takes a `Ctx`. It carries why the run happened (its root `Cause`, which every artifact's provenance chain ends in), where problems go (`ProblemSink`), and where progress goes (`ProgressSink`; `NullSink` renders nothing):

```rust
let ctx = Ctx::new(
    Cause::Requested { arg: "nightly-migration".to_owned() },
    ProblemSink::new(),
    Arc::new(NullSink),
);
```

`ctx.cancel().cancel(reason)` stops a run cleanly, and `cancel_after` bounds it in time; the binary wires `cancel_on_interrupt` to Ctrl-C. `Ctx::logging_with` sends log lines to a `core::Log` of your own.

### 3. The session

`session::Session` turns the configuration into the live objects a run uses: hosts with their credentials and limits, sources, targets, enumerators, and advisors, each opened by its configured name.

```rust
let mut session = Session::open(&config, false)?;
```

The second argument is `--harden`. `Session::over` takes an `net::HttpClient` of your own instead of the built-in one.

### 4. The report

A command writes what it did to a `report::ReportWriter`. `report::open` builds one from a `ReportSpec` (a line report: JSON, YAML, or text), a `DbSpec` (a report database), or both. Write the header before the command runs:

```rust
let spec = ReportSpec::parse("json,run.jsonl").map_err(Error::Config)?;
let writer = report::open(Some(&spec), None).await?;
writer.write(&Record::Header(header("copy", &screening)))?;
```

The records are described in [reports.md](reports.md), and the database in [progress-db.md](progress-db.md).

### 5. The command

Each command in `commands` takes the session, what to do, where its results go, a progress node, and the context, and returns a `Summary`:

```rust
let outcome = copy::run(&mut session, &request, writer.as_ref(), &progress, &ctx).await;
```

| Command | Takes | Does |
| --- | --- | --- |
| `commands::copy::run` | `copy::Request`, a `ReportWriter` | Resolve, verify, screen, and publish to every target |
| `commands::inspect::run` | `inspect::Request`, a `spider::Visitor` | Resolve and walk dependencies, handing each artifact to the visitor |
| `commands::find::run` | an enumerator name, a `find::Span`, a `find::Sink` | Enumerate a repository's catalog into the sink |

Each also has a `describe` function that turns its `Summary` into log lines.

### 6. Closing the report

Write a `Record::Summary` **whatever the command returned**: a report without one reads as a run that did not finish. For a report database, also call `writer.state()` and its `complete(Completion::...)` to record how the run ended. Then `flush`.

`ctx.problems().worst()` is the worst `Action` any problem led to; the binary turns it into its exit code ([exit-codes.md](contributors/exit-codes.md)).

### What the command line adds

The binary does a few things around each command that the example leaves out. They are all reachable from the public API, and [`src/cli/subcmd.rs`](../src/cli/subcmd.rs) is the reference sequence:

- **Screening.** The example passes `screen: None` and writes `Screening::none()` into the header, so nothing is screened and the report says so. To screen as the binary does: `Screening::plan` over `session.advisors()`, open each with `session.advisor`, load each into an `advisory::Index` with `advisory::consult`, and pass both in `inspect::Request::screen`.
- **Bindings.** A report database records which repositories a run used. Call `writer.state()` and `bind` a `report::Binding` for the source and each target before the command runs.
- **Problems as they happen.** `ctx.problems().watched_by` takes a `core::problem::Watch`, which sees each problem when it is raised rather than only in the counts; the binary's writes each one to the report.


## Adding a repository kind

A configured `kind` names one of two things: a built-in kind, or an entry in the configuration's `extensions`.

**The built-in kinds are a closed list**, `repo::SERVERS`, by design. A program does not add to it. That leaves two routes.

### An extension

An extension runs out of process, as a WebAssembly module, and supplies a kind a configuration can name like any built-in one. Because a configuration can name it, every command reaches it through the session. This is the route for a kind that commands should use. [extensions.md](extensions.md) describes the protocol and points to two complete examples.

### A Rust implementation of a trait

A program can implement the extension-point traits directly:

| Trait | For |
| --- | --- |
| `repo::Source` | Reading a repository |
| `repo::Target` | Writing to one |
| `repo::enumerate::Enumerator` | Listing a repository's catalog |
| `advisory::Advisor` | Loading an advisory corpus |
| `ecosystem::Ecosystem` | A package ecosystem's rules |
| `version::VersionHandler` | Ordering versions |
| `lock::Lock` | Reading a lock file format |

The types those traits name are in `model`, `core`, and `ext`; an implementation fetches through the `ext::ExtHost` it is given, which enforces the host's constraints and credentials.

The built-in adapters share a few building blocks, and they are public so an adapter of your own behaves the same way:

| Item | For |
| --- | --- |
| `repo::download` | `Source::download`: fetch a file into the host's cache, checking its digests as it arrives, and hold it there |
| `repo::stage` | The same for bytes already in hand |
| `repo::version_required` | Refusing an artifact that names no version, for a repository whose artifacts have them |
| `repo::sole_ecosystem` | `Source::ecosystem` for an adapter that speaks one ecosystem |
| `repo::PageCap` | Reading `max-listing-rows`, so a paged listing stops on a server that never does |
| `repo::OverwriteGuard` | Reading `overwrite-guard`, so a target knows whether to check before writing |
| `repo::Companions`, `repo::Delivery`, `repo::Delivered` | What `Target::publish` is handed and reports |
| `repo::Trust` | What a source checks signatures against |

Such an implementation is yours to call, and to compose with the built-in ones: the built-in adapters (`MavenSource`, `NpmTarget`, `OsvOffline`, and the rest) and the proxies (`repo::Failover` over `repo::Upstreams`) are public, and `repo::open_source`, `open_target`, and `repo::enumerate::open_enumerator` open a built-in kind by name. A program that wants its own kinds selectable by name keeps its own table of them and falls back to those functions for the rest.

**What it cannot do is reach a command.** `copy`, `inspect`, and `find` open their sources and targets by configured name through the session, and a configured name resolves only to a built-in kind or an extension. To use a kind with a command, ship it as an extension.

`ext::testing` holds the fixtures the built-in adapters are tested with, such as `TestHost`, an `ExtHost` over canned HTTP responses that records what was asked.


## Stability

The crate is at `0.x`. Narrowing what is public is a breaking change, and exposing more is not, so the surface starts small: if you need an item that is `pub(crate)`, say what for.
