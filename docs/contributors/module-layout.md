# Module Layout

References: [PEP 508](https://peps.python.org/pep-0508/), [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

Why the modules sit where they do, and what a restructuring pass learned. The current layering rule itself lives in `src/lib.rs`; this is the reasoning behind it.

## What measuring found

**The large files were not large-logic files.** Across the fourteen biggest, 54% of lines were `#[cfg(test)]` and roughly 40% of what remained was doc comment. Real executable production code was about 3,700 lines of 13,540. The largest file by actual logic was `repo/maven.rs` at 388 code lines. `spider.rs`, the biggest overall at 1,726 lines, was 344 lines of logic and 1,106 lines of tests in one flat `mod tests`.

So most of "split the large files" is **test organization**, not logic decomposition. Only four files had a genuine production seam.

Two facts about reading the module graph:

- **Exclude doc-comment references.** They create phantom edges, and a naive grep invents two cycles that do not exist (`ecosystem -> repo` and `ext -> enumerate` appear only in prose).
- **`lib.rs` can be wrong about its own leaves.** `config` (in 4 / out 2) and `policy` (in 2 / out 4) were documented as leaves and are not. `progress` and `cancel` have fan-in 2 each, both `ctx` and `spider`, so they belong *under* the runtime cluster rather than beside it.

`config.rs` is the exemplar declaration file: 19 lines, 0 declarations, 4 re-exports.

## Do not merge these

Recorded so the decision is not re-litigated, because each *looks* like obvious duplication. `AGENTS.md`'s DRY rule warns against unifying things that merely look alike; these are the cases where that bites.

- **The four `walk()` implementations.** Their termination rules **contradict** each other. `repo/nexus/enumerator.rs` documents that an empty page is *not* the end, because the server filters after paging; `artifactory` and `pypi` both stop on a short page. A shared helper would have to reconcile incompatible stopping conditions, and getting it wrong silently truncates a catalog. Highest-risk merge available.
- **The `open_*` registries across collections.** Source, target, enumerator, proxy, and advisor openers have different signatures, and `lock::Registry` is not a match table at all but a precedence list with glob and head-peek detection. Within one collection the signature is uniform, which is why each repository server's descriptor carries its openers; see *Kinds sit with their server*.
- **`Description::builder()`.** Six fields, and each cluster fixes a different subset; a builder costs more than the literals save. Note also that `repo::Source` has no `describe()` at all -- a builder implying otherwise would paper over a real gap.
- **`impl Spider`.** `run`, `enqueue`, `process`, `descend_from`, and `children` are one pipeline sharing `Walk`, `Tally`, and the spider's own fields. Splitting it means inventing parameter structs, not moving items. Spreading its methods across files is a different thing and is done: `run` stays in `spider.rs`, one artifact's turn in `spider/walk.rs`, and the reports of a walk cut short in `spider/limits.rs`, all still `impl Spider`.
- **The nine `Walk { .. }` literals in `spider.rs`'s tests.** A `walk()` helper already covers the common case; the nine that remain are in tests that keep `visited`, `collector`, or `progress` afterwards, run two batches against one claim set, or pass `&Discard`. A second helper would take all four back as positional `&dyn` arguments -- and `visited` and `visitor` are adjacent and differ by one character. `Walk`'s own documentation says its fields are grouped "so that progress cannot be forgotten"; a positional helper reintroduces exactly that.

## `core` is for embedders; `internal` is for us

The glob matcher first went into `core`, which was wrong. `core` is the common functionality an outside user of the library works with -- `Ctx`, `Error`, `Problem` -- and nobody embedding this crate needs our glob matcher. It lives in `pub(crate) mod internal`, along with the rule for what earns a place there: **only things with no natural owner.** A URL helper belongs in `net`; a version rule belongs in `ecosystem`. The test is whether a reader would look somewhere more specific first.

By the same rule `net::url` and `net::files` are `pub(crate)`: they live in a public module, but an embedder supplying an `HttpClient` has no use for our percent-encoder or our `mkdir`.

`cache` is `pub(crate)` for the same reason -- every holder of a `Coalesced` is an adapter or the spider, and it was public by omission rather than by decision. `lib.rs` states the test for what ships: *could somebody outside this crate use it for anything?* A percent-encoder and an LRU of in-flight futures fail it.

## Two caches, two different rules

A **document** cache keyed by URL may evict whatever it likes, because a miss costs a re-fetch. A **claim** set keyed by coordinate may not, because forgetting a claim walks a subtree twice. `cache::Coalesced` is the first; `spider::visited` is the second. Every holder of a `Coalesced` names its capacity.

## Primitives that were genuinely identical

Four copies were folded, each to the module that owns the concern rather than to a `util` bag:

- `internal::glob` replaced `lock::glob` and `policy::license::glob_matches`, which were identical but for the name. It exposes `matches_purl` and `matches_file_name` over one matcher, so each call site names what it matches.
- `net::url::encode_unreserved` replaced the byte-identical `encode` in `enumerate/nexus` and `repo/github`. Named for the *character set*, not for "query" or "path", because the two callers encode different URL components and a component name would claim a rule it does not implement.
- `net::url::normalized_base` replaced seven copies of `base_url.trim_end_matches('/')`.
- `net::files::ensure_parent` replaced four copies of `create_dir_all` plus `Error::WriteFile`.

Two near-misses left alone deliberately. `model`'s `encode_segment` looks like a third copy of the URL encoder and is not -- it escapes the characters *purl* reserves, a different set for a different purpose. And `policy::license`'s trailing-slash trim is inside a larger license-URL normalizer, not the base-URL convention.

`internal::glob` documents the one thing a reader would otherwise get wrong: `*` crosses `/` on purpose, because purl rules like `pkg:maven/org.example/*` depend on it, whereas conventional filename globbing stops at a separator. The two names exist for that reason: a purl glob and a file glob are different questions, and the name says which one a caller asks. If file names ever need the conventional rule, only `matches_file_name` changes -- a boolean flag would push the decision out to the call sites, which is where it would get copied wrongly.

## `Call::fetch_json`, and the three sites that are not it

Six network fetch-then-parse copies became one method on `Call`. The helper takes the built `Req` and reads the URL *out of it*, rather than taking a URL alongside: every call site passed the same URL twice, once to build the request and once to name it in the error, and two of the six spelled the second copy differently.

**Three sites look like the pattern and are not**, each for a different reason:

- `repo/pypi/enumerator.rs` reads the **sandbox**, not the network. It calls `fetch_to_file` first and then `call.sandbox().read(..)`, because the index is verified in flight and is too large to want in memory twice.
- `repo/npm.rs`'s key-list fetch **deliberately swallows** the parse failure: a registry that publishes no signing keys is not an error. Routing it through `fetch_json` would build an `Error::Malformed` for the sole purpose of discarding it.
- `repo/pypi.rs`'s detail fetch does the same, returning `Ok(Vec::new())` for a package whose dependency metadata is dynamic.

## One module per document, not per adapter

Five serde blocks became **seven** modules, because two adapters were carrying two documents each:

| From | To | What it is |
| --- | --- | --- |
| `enumerate/nexus.rs` | `nexus/enumerator/component.rs` | the components endpoint |
| `enumerate/artifactory.rs` | `artifactory/row.rs` | AQL search results |
| `repo/github.rs` | `github/release.rs` | a release, from all three endpoints |
| `repo/npm.rs` | `npm/packument.rs` | the packument |
| `repo/npm.rs` | `npm/keys.rs` | `/-/npm/v1/keys` |
| `repo/pypi.rs` | `pypi/simple.rs` | the PEP 691 index |
| `repo/pypi.rs` | `pypi/detail.rs` | `/pypi/{name}/{version}/json` |

npm's key list is 22 lines and could have gone into `packument.rs` on size alone; it is a different endpoint returning a different document, and the file it earns is where the reason the source swallows its failures now lives.

The methods that moved with the types are the ones that answer *what the document said*, not what to do about it: `Component::last_download`, `Row::last_download`, `Row::property`, `ReleaseDoc::version` and `::published`, `VersionEntry::is_optional_peer`, `License::text`, `CoreMetadata::is_present`. `later_of`, which reconciles two rows' download times while folding, stayed with the fold in `artifactory/fold.rs` -- that is a decision about artifacts, not a reading of a row.

Cost worth knowing about: a field a parent reads has to become `pub(super)`, and most of them do. What stays private is a useful signal in itself -- each of `Component::assets`, `Row::stats`, `Row::properties`, and `VersionEntry::peer_meta` is read only by the moved method, which is why that method belonged with the type.

## Formats sit with the source; meaning sits with the ecosystem

`parse_version_list` moved to `repo/maven/metadata.rs` and the `Requires-Dist` reader to `repo/pypi/metadata.rs`, beside `pom.rs`.

The plan called the PyPI half "PEP 508 parsing" headed for `ecosystem/pypi.rs`. Reading it showed otherwise: it is an RFC 822 *document* reader that hands each line to `PyPi::parse_req`. What a requirement **means** is PEP 508 and belongs to the ecosystem; what a METADATA file **contains** is a format, and formats sit with the source. The adapter roots now contain no format-parsing functions at all.

One test worth having: the header is matched at the *start* of a line, because the sample contains `Summary: Requires-Dist: ...` as prose, which a `contains`-based reader would have turned into a phantom dependency.

## Test support that ships

- **`ext::testing::Fixture<T>`** replaces six copies of the same two-field struct. The field is `subject`, not `source` or `enumerator`, because it holds both and a name claiming one would be wrong half the time.
- **`ext::testing::options(Value)`** replaces four copies.
- **`Ctx::anonymous_for_test()`** replaces seven pieces of filler -- `"t"`, `"x"`, `"a"`, `"test"`. The point is not the six saved lines: a `Cause` spelled out at a call site now **means the test cares what it says**, and the ones that stayed (`"lodash"`, `"org.example:lib:1.0"`, `Cause::Enumerated { enumerator: "nexus" }`) are the ones where it does.

`Fixture::call<'h, 'c>`'s two lifetimes are the part worth having centralized. Elision cannot express the signature at all: with two elided input lifetimes Rust has no rule for which one the returned `Call` borrows from, so both are named because both are load-bearing, not for emphasis.

**`Ctx::anonymous_for_test` went into `core::ctx`, not `ext::testing`.** Putting it beside `TestHost` would have been the obvious place and would have created three new test-only `net -> ext` edges for something that has nothing to do with extensions.

No `#[cfg(test)]`-only `ecosystem <-> ext` edge remains. One used to: `ext.rs`'s `every_builtin_description_validates` checked a built-in ecosystem's `describe()` against the committed protocol schema, and both are gone.

## Lessons from doing the moves

- **A cycle can come from one import.** The only production cycle in the crate was `net/sig.rs` reaching up for `ext::Call` so `KeyStore` could fetch from a keyserver. Inverted with a one-method `net::Fetch` trait implemented for `Call` in `ext`.
- **Check `--help` after moving a `clap` type.** The report format enums derived `clap::ValueEnum`, which is what put `[possible values: ...]` in `--help`. Moving them to plain data silently dropped that line. The fix keeps the types plain and puts `impl ValueEnum` in `cli.rs` -- *how a value is spelled on a command line is presentation*, so it belongs in the presentation layer.
- **`core` shadows the built-in crate name.** Legal, and it caused no trouble because no file used a bare `core::` path, but crate-root re-exports must be written `pub use crate::core::...`, since a bare `use core::...` resolves to the *standard* `core`.
- **A blanket path rewrite gets two things wrong.** `$crate::message::...` inside the `message!` macro became `$super::message::...` and had to be restored to an absolute `$crate::core::message::...` -- a macro expands at its call site, so `super` there means something else entirely. And `src/main.rs` is a separate crate root, so its `artifact_copy::problem::...` paths were invisible to a `crate::`-based sweep.
- **Compare the test count before and after a carve.** Carving by line range lost a `#[tokio::test]` attribute because the range began at the `async fn` and the attribute sat on the line above. The compiler caught that one; a silently-skipped test would not have been caught at all.
- **A file's own banner comments are better evidence than a guess from outside.** `spider.rs`'s flat `mod tests` was split into the six modules its banners already named -- `edges`, `dedup`, `failure`, `plumbing`, `progress`, `stopping` -- where the plan had guessed three.
- **A move that alters a test expectation went further than a move.** Every behavior-preserving step held the test count constant, which is the check.

One bug fell out rather than a refactor: `validate-config` hand-maintained an enumerator-kind list omitting `nexus` and `artifactory`, so it refused configurations that would have run. Sources and targets already called `repo::source_kinds()`; enumerators did not. A test now walks every advertised kind so the list cannot drift again.

## Enumerators sit with their server

`enumerate` and the top-level `proxy` moved under `repo`, grouped by server technology rather than by extension point, so everything that speaks to one product is in one place:

```text
  repo/
    enumerate.rs            the Enumerator trait, open_enumerator, kinds
    enumerate/              Enumerators registry, Page, SampleSize
    manager.rs              what the manager enumerators share
    manager/source.rs       ManagedSource and Lister, what their sources share
    upstream.rs             Upstreams<T> and Proxied, shared by both proxies
    nexus.rs                the source, and the raw source
    nexus/asset.rs
    nexus/lister.rs
    nexus/enumerator.rs
    nexus/enumerator/component.rs
    artifactory.rs          the source and the Pro enumerator
    artifactory/fold.rs     rows into artifacts, for both enumerators
    artifactory/oss.rs      the OSS enumerator
    artifactory/lister.rs
    artifactory/row.rs
    artifact_keeper.rs      the source and the generic target
    artifact_keeper/enumerator.rs
    artifact_keeper/lister.rs
    artifact_keeper/listing.rs
    artifact_keeper/source.rs   the generic source
    maven/listing.rs        the version directory index, for file-listing
    pypi.rs                 the source
    pypi/enumerator.rs
    proxy.rs                the source proxies
    proxy/enumerator.rs     the enumerator proxies
```

The shared code is small -- `Coordinate`, `Mapping`, `pep503`, and `MAX_PROXY_DEPTH` -- so the move is about finding things, not about removing copies. It merges no `walk()`; see *Do not merge these*.

`component.rs` stays a child of the enumerator rather than a sibling of `asset.rs`, and `manager.rs` went to `repo` rather than `repo::enumerate`, so every `pub(super)` kept its old reach. `artifact_copy::enumerate` and `artifact_copy::proxy` are gone with no re-export; their items are at `repo::enumerate` and `repo::upstream`.

## Kinds sit with their server

Each server module under `repo` declares one `kind::Kinds`: the source, target, and enumerator kinds it offers, with the function that opens each and what `validate-config` asks of it (option check, `names`, version scheme, login, native ecosystem). `repo.rs` lists those descriptors once in `SERVERS`, and every kind list, check, and `open_*` reads that list. Adding a server is one module plus one line, and a kind cannot be advertised without opening, or open without being advertised.

Grouped by server rather than by extension point: the kind names a server offers differ per point (`nexus` source, `nexus-raw` target), and keeping what one product speaks in one place outweighs a list of every enumerator in one file. Proxies keep their own lists in `repo::proxy`, since they open from upstreams rather than from a URL; `all_source_kinds` and `all_enumerator_kinds` join the two for a message.

`SERVERS` is closed by design: an embedder does not register into it. A program with kinds of its own keeps its own table and falls back to `open_source`, `open_target`, and `open_enumerator`; a kind a configuration names is a built-in or an extension. See [embedding-guide.md](../embedding-guide.md).

## The CLI boundary

`cli` holds argument parsing, `cli::subcmd` (the sub-commands, reached only by `main`), and `cli::ConfigLoader` -- finding configuration files, validating them against the schema, and merging them. A guard test walks `src/` and fails if any production file below `cli` names `crate::cli`, so the boundary is enforced rather than remembered.

**The typed configuration stayed in `config`, and had to.** An earlier note read "as the configuration options also only come from the CLI execution, those belong under the CLI module" -- but they do not only come from there. `net` reads a retry plan and a TLS setting, `ext` reads constraints and credentials, `repo` reads a publish window, `session` reads all of it. Moving those types under `cli` would make the network layer depend on the argument parser, which is the layering violation `AGENTS.md` forbids and the one an embedder would feel first.

The split that does hold is by **question**:

| Question | Where | Why |
| --- | --- | --- |
| *Where do the settings come from* | `cli::ConfigLoader` | Only a command line asks. An embedder builds a `Config`. |
| *What are the settings* | `config` | Every layer below needs the answer. |

So "any transformation from configuration into data structures used for invocation belongs in the CLI module" holds for **files into a `Config`**, and not for `Config` into the live objects a run uses -- that is `session::Session`, which an embedder wants and which cannot reach up into `cli`.

`cli::subcmd` is named that rather than `cli::command`, since `cli::command` and `commands` differed by one letter while drawing an important line. `artifact-copy` is the one command a user runs, and these are its sub-commands.

## `commands` is what the tool can do

`commands` holds the bodies -- driven by a session and a context, reading no arguments and writing no output -- with `cli::subcmd` left holding only the dispatch: parsed arguments, name resolution, terminal output, exit code. One place for *what this tool can do*, separate from how a command line asks for it.

## Declaration-file discipline

For a module directory and its declaration file (`problem.rs` beside `problem/`), the file should contain only high-level helpers that unify disparate parts, and should import functionality rather than declare it. That way the top-level file reads as an overview of the module's public surface.

A type whose methods span several topics lives in its own child file, as each target and enumerator already does, and its other methods split into one `impl` block per topic file. Its fields are `pub(super)`, since the topic files are its siblings; a method only becomes `pub(super)` when a sibling calls it. The declaration file keeps the `open_*` functions and the `KINDS` that names them. `repo/maven.rs` is the worked example: `source.rs` holds `MavenSource` and its `Source` implementation, which delegates to `layout`, `versions`, `effective`, and `signatures`; each file's tests are the ones its code answers for, with the fixtures they share in `testing.rs`.

A module holding one type with one job stays whole: `repo/inventory.rs` is `InventorySource` and its `Source` implementation, with `combine.rs` its only separate topic. `lock.rs` split by registry concern rather than by type: `registry.rs` chooses a reader, `spec.rs` parses `--lock`, `read.rs` reads under the cap, and the declaration file keeps the `Lock` trait and the types its signatures name.
