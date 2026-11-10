# To do

Work that is left: missing functionality, known defects, decisions still open, and assumptions that need checking against a real system.

**Reasoning that is already settled is not here.** It lives in [docs/contributors](docs/contributors/README.md), one file per subsystem, and each item below links to the file that holds its background. Keeping the two apart is deliberate: an item here should be readable in a few lines, and the argument behind an awkward-looking constraint should still be findable a year later.

Ordering is roughly by dependency, not by priority.


## Priorities

Current priorities, which dictates the ordering of dependencies:

1. Bug fixes.
2. Missing functionality.
3. Refactor.


## Known defects

- **An embedder's lock reader never reaches a run.** `lock::Registry::prepend` is the only Rust-level registration hook, but `Session::locks()` builds a fresh `Registry::builtin()` (plus configured extensions) on every call, and `commands::inspect` uses that.


## Missing functionality

### Sources, targets, and enumerators

Background: [sources-and-targets.md](docs/contributors/sources-and-targets.md).

- **Ivy descriptors.** Spider `ivy.xml` files in an Ivy-typed repository for dependencies. The `ivy` server kind reads them as raw files today; see [sources-and-targets.md](docs/contributors/sources-and-targets.md#reading-an-artifactory-generic-repository).
- **GitHub releases** exists as a source and needs one change:

  - **Allow fetching the license** from the repository metadata, on request. It costs a request per artifact to learn something that is not necessarily a property of the release, since licenses can change across versions.
- **Name mappings beyond GitHub.** `repo::NameMap` is generic; the Nexus, Artifactory, and Artifact Keeper raw sources can apply it beside `Mapping::read`, and `repo::names_kinds` grows with them. An enumerator over a mapped source must yield the mapped names. See [sources-and-targets.md](docs/contributors/sources-and-targets.md#github-releases).
- **Name mapping patterns.** One literal name and one `*` per version today. Wildcards in names, and regular expressions, wait until a real layout needs them; either must stay reversible, since a request names the mapped side.
- **npm and PyPI repositories on `artifactory-pro`.** The server kind offers Maven only. The `artifactory` enumerator reads npm and PyPI coordinates from package properties nobody has confirmed (see *Uncertainties about external systems*), and the `artifactory` source's lister lists nothing for them, so the protocol source answers alone. Needs a Pro or JCR instance to measure. `artifactory-oss` does not offer those repository types.
- **Revisit what a failover proxy enumerator declares.** It inherits `depth` and `reports_last_download` from its first upstream, but may walk a later one that declares less, so the declaration can overstate what the walk yields. Candidates: the shallowest upstream, or the chosen upstream's declaration recorded per walk.
- **Which servers answer an npm changes feed.** `enumerate::native_kind` points an anonymous Artifactory npm repository at `npm-replicate`, but Artifactory, Nexus, and Verdaccio are not known to serve `_changes`. Measure them; if none does, the login advice should say there is no anonymous walk for npm there.
- **A merging proxy as an enumerator gets a generic `UnknownKind`.** [sources-and-targets.md](docs/contributors/sources-and-targets.md) settles that it has no enumerator; refuse it with a message pointing at the inspect, merge, and report-file workflow instead.
- **`Source::describe()`.** `repo::version_scheme` hard-codes which kinds take a `version-handler` ([repo.rs](src/repo.rs)); a source, extension included, should say so itself. See [versions.md](docs/contributors/versions.md).

### Lock files

The dispatcher, the npm readers, and the OpenVEX and CycloneDX (SBOM and VEX) readers exist. Still to add: `pylock.toml`, `requirements.txt`, `poetry.lock`, `uv.lock`, `pnpm-lock.yaml`, `gradle/verification-metadata.xml`, `gradle.lockfile`, `lib.gradle.toml`, and SBOM files in SPDX and other formats.

### Artifact filters

An SBOM names packages no source holds: its subject, and the project's own internal packages. Each reports `artifact-not-found`, and once *Exit code follows provenance* is built, fails the run, since an SBOM's packages count as requested. Add glob patterns over purls that remove artifacts from a run's requests:

- A global list, `forbid` only.
- Per repository, `forbid` to add to the global list, and `allow` to lift a global `forbid` for that repository.

Settle the relation to each entry's existing `omit` rules ([sources-and-targets.md](docs/contributors/sources-and-targets.md)), which are per entry, omit only, match by purl pattern rather than glob, and report `artifact-omitted` as a warning.

### Purl coordinates on the command line

A command-line coordinate is parsed only in the source's own syntax by `Ecosystem::parse_req`; no ecosystem accepts a purl. Accept `pkg:TYPE/...` beside the native syntax, and fail the command as a user error when `TYPE` is not one of the source's ecosystems. Today npm rejects a purl as a bad request, and raw takes `pkg:npm/x@1` as the path `pkg:npm/x` at version `1`.

Unlike a foreign product in an SBOM (`bom-ecosystem-foreign`, routine in a document generated from a container image), a foreign purl typed by the user is a mistake, so it stops the run rather than being recorded and skipped.

### The write path

Background: [write-path.md](docs/contributors/write-path.md).

- **The Target gearing: ask, answer, prepare.** A built-in target performs its own I/O through its host; an out-of-process one cannot, and cannot hold a lock, so its gearing runs it in three phases: the extension states what it needs to know, the gearing answers from the report or the repository, and the extension returns the operations to perform, each naming the file it carries, while the gearing does every read and write and holds any lock across them. See [extensions.md](docs/contributors/extensions.md#the-target-gearing).

  **The protocol cannot serve a target yet.** `schema/extension-protocol.schema.json` documents the host capabilities as `head`, `fetch`, and `fetch-to-file`, with no `send-file` or `send-form`; operations returned by the extension are the shape that fits it, since the extension answers with data and the gearing performs the I/O. The question types belong in `ext::gear`.

  **Per-file reporting.** A built-in target reports each file through `repo::Delivery`, which fills the report's upload `file_transfer` rows. A gearing must fill the same `Delivery` from the operations it performs. An operation carrying **no** files is real: writing `maven-metadata.xml` is one.

  **Two shapes left to design**, from the Maven target; see [write-path.md](docs/contributors/write-path.md#what-an-out-of-process-maven-target-would-need). A metadata merge is read-then-decide under a lock, which a gearing-held lock resolves. And both `artifact-keeper-generic` and `maven` read the stored file *after* a write is refused, which no phase covers.

- **Only npm, Maven, PyPI, an Artifact Keeper generic repository, an Artifactory generic repository, and a Nexus raw repository can be written to.** `target_kinds()` is deliberately shorter than `source_kinds()`, and `validate-config` refuses a target kind that cannot be written rather than accepting it and failing at the upload.
- **An older snapshot build in a target answers present.** Fixing it needs `Target::exists` to receive the build the source resolved. See [user-limits.md](docs/contributors/user-limits.md).

### Pull updates

A new command, which needs strong definition. It enumerates a target repository's artifacts; if an artifact has a download time within a specific time frame, defaulting to two weeks, the command finds the most recent version of that artifact in a source repository and copies it over. This follows the existing rules for publish window and GA-only releases.

It makes extensive use of the last-download capability, so enumerators must report early whether they support it. If they do not, the command fails fast.

### Merge inspection reports

To support merged repository walking, the tool needs a way to merge the reports 'inspect' creates. This has to settle which side's `LastDownload` survives when both reports hold a coordinate. It is also the second step of the workflow that replaces a merging proxy enumerator; see [sources-and-targets.md](docs/contributors/sources-and-targets.md).

### Exit code follows provenance

Background: [run-outcomes.md](docs/contributors/run-outcomes.md) and [exit-codes.md](docs/contributors/exit-codes.md).

The rule is settled and unbuilt: a run fails only if something the user named was not copied, plus codes whose severity fails the run however the artifact was reached (`malware-known`, the integrity codes). `cli::subcmd::run` returns only the worst `Action`, so a `skip-artifact` thirty dependencies deep exits 1 today. Left to build:

- `cli::subcmd::run` returning enough to judge provenance.
- Severity as a property of the code, probably on `core::problem::policy::Class`.
- Configuration overrides in both directions, as [exit-codes.md](docs/contributors/exit-codes.md) promises.

[quarantine.md](docs/contributors/quarantine.md) and `schema/config.schema.json` already describe the rule as built.

### Vulnerability score threshold

`vulnerability-known` is a flat `warn` "until a maximum-CVSS threshold exists" ([code.rs](src/core/problem/code.rs)); [quarantine.md](docs/contributors/quarantine.md) and [configuration.md](docs/contributors/configuration.md) assume one. Nothing reads an advisory's severity score.

### Configured but not applied

The configuration parses these fields, but nothing at run time reads them:

- `sources.*.enumerator`: `validate-config` checks the name; no command uses it.
- `targets.*.enumerator`: neither checked nor used.
- `caches`: parsed, path-anchored, and in the schema; only a test reads it. See [advisories.md](docs/contributors/advisories.md).
- `hosts.*.connect-timeout` and `hosts.*.request-timeout`: the client always uses `DEFAULT_CONNECT_TIMEOUT` and `DEFAULT_REQUEST_TIMEOUT` ([reqwest_client.rs](src/net/reqwest_client.rs)).

The configuration documentation currently reports that these are read but do nothing.  Once these are fixed, the docs should also update.

### Log instrumentation

Background: [logging.md](docs/contributors/logging.md).

The plumbing is built: `ctx.log()` reaches every layer, and the `report::Logged` tee logs every record and report state call. Few call sites log anything of their own yet. Add log lines where a user or developer needs them to follow a run: phase changes, resolution choices, HTTP requests and retries, cache hits, and skipped work, at the levels the event table in the background sets.

Some things, such as "ignore silently" items, should log at the "verbose" level.

### Logging configuration

Background: [logging.md](docs/contributors/logging.md).

`setup.log` is a placeholder: a level, an output format, and one file. What is left:

- Choosing a log stream (standard output or standard error) in the configuration, which only `--log-file` can do today.
- Detailed settings, such as a level per module or per destination. `tracing_subscriber::EnvFilter` directives, which `RUST_LOG` already accepts, are the likely basis; see *Per-module log filtering*.

### Per-module log filtering

Background: [logging.md](docs/contributors/logging.md).

Every log event has the target `artifact_copy::core::log`, because `tracing` fixes an event's target at its call site and all events pass through `core::log::Log`. A `RUST_LOG` directive such as `artifact_copy::net=debug` therefore matches nothing. Filtering by module needs the caller's module carried through `Log` (for example, a macro capturing `module_path!()`) and matched by a custom filter.

### Redact JSON error bodies, and reveal them under `--unsafe-debug`

Background: [logging.md](docs/contributors/logging.md).

`Error::HttpStatus::detail`: [excerpt.rs](src/net/excerpt.rs) replaces request credential values echoed in a text or small HTML body, and keeps a JSON body as sent, unscrubbed. Under `--unsafe-debug` it should show the original body; otherwise every kind, JSON included, should pass through the shared redaction.

### Command-line odds and ends

- `--probe-extensions` reports unimplemented.
- The arguments needed to assemble all the data into a report database seems extremely clunky.  Some of the arguments should imply other arguments.
- The configuration for "enumerator" overlaps the target and source.  There may be a way to make this simpler for the user, so they don't have to keep track of the migrator internals.  Probably a "repository-kind" on the source and "server-kind" on the host to imply the implementations used.
- The help screen contains many notes to the developers rather than end-user notes, and this should change up to reflect what end-users want.
- The `validate-config` command should send to stderr an okay message if everything's fine.
- **Output naming the target.** With several `--to` targets, output names each target; with one, most sites keep the earlier, target-free text. Simplify single-target output so it carries no extra verbosity. Sites that name a target (see [several-targets.md](docs/contributors/several-targets.md)):
  - `commands::copy::describe`: `copy-finished-at` names the target when there are several.
  - `report::text` artifact render: one line per destination under the outcome.
  - `report::logged::artifact_line`: per-destination list after the outcome; `Logged`'s claim and upload debug lines name the destination always.
  - `model::prov::Cause::message`, `Report` arm: `to target "x"` for one, `to targets a,b` for several.
  - `commands::inspect::Outstanding::nothing`: names the target or targets.
  - `report::record::ArtifactRecord::outcomes`: serialized in JSON and YAML only when there are several.
  - `cli::subcmd::copy::ends`: the repeated-target error.
- **Re-examine `find --as-target`.** Deferred decision. The new `--to` semantics don't apply very well to this sub-command.

### Extension gearing

- **Enforce `Constraints::max_files` and `max_sandbox_bytes`.** Both are declared and never checked. They limit an out-of-process extension's scratch directory, which only a gearing creates, so they are enforced there; built-ins have no scratch directory since the cache split.
- **Only a WASM source runs.** Every extension-backed target, enumerator, advisor, and lock format fails as `unimplemented`, as does every executable extension. Planned: the other points over WASM, a streaming command-line tool, and a separate-calls command-line tool. See [extensions.md](docs/contributors/extensions.md).
- **WASM host capabilities.** Only `fetch` is answered; `head` and `fetch-to-file` are refused as `unimplemented`, and no WASM extension has a sandbox directory yet.
- **NodeJS release signatures.** `extensions/nodejs-releases` takes sha256 digests from `SHASUMS256.txt` but does not check `SHASUMS256.txt.asc` against the NodeJS release keys.
- **Protection layers** between an extension and the files it is handed:
  - **Copy into the sandbox, never lend.** The gearing copies a cached payload into the extension's own scratch directory rather than linking it or handing over the cache's path, so nothing an extension does to its copy reaches the cache. Built-in targets are the exception: each is handed the cached file itself, which is read-only, so an accidental write fails loudly, but an unlink-and-replace still gets through. See [extensions.md](docs/contributors/extensions.md#protecting-the-files-a-target-is-handed).
  - **A `copy` staging mode**, extending the same copy to built-in targets, for a user running one they have reason not to trust. Not the default: paying for a copy of every payload of every migration, to forestall something no built-in target does, is the wrong trade.
  - **Clear the read-only flag on the copy.** `fs::copy` carries the cached payload's read-only flag to the copy, so the gearing must clear it there (`ext::cache::writable`), or the extension cannot use its scratch directory as scratch.
  - **Linux landlock confinement**, so an extension process can reach its scratch directory and nothing else on disk.
  - **A sandbox per extension**, so one extension cannot read or alter what another was handed.
- **An extension cannot declare an ecosystem.** Nothing builds an `Ecosystem` from an `EcosystemDesc`, and `Ecosystems::learn` takes only a built-in one. Its `osv_name` therefore never reaches the advisory index: every advisory about an extension ecosystem lands in `Index::untranslated`, and its artifacts are screened against nothing and report clean. Learn each extension's `osv_name` when the index is built. See [advisories.md](docs/contributors/advisories.md).
- **Host-technology knowledge in extension metadata**, once sources and enumerators are chosen from the host technology; see *Command-line odds and ends*.
- **An extension source's own `resolve` is bypassed under a `version-handler`.** `Bound` then runs the standard step-down loop; without one it forwards. Revisit when extension sources exist; see [versions.md](docs/contributors/versions.md).

### Integration tests with external systems

Set up integration tests against real running systems.  Currently, this only [manual executions](manual-integration-tests/README.md).

- **Test `200` can enumerate its target now.** It skips enumerating `maven-b` because the `artifactory` enumerator sends a sorted query OSS refuses; the server kind now generates an `artifactory-oss` enumerator, which works against the local server.
- **A Maven copy by coordinate from a plain `maven` source carries the POM and the main payload only.** The `nexus`, `artifactory`, and `artifact-keeper` sources add the files their server lists, a `maven` source with `file-listing: html-index` (which `maven-central` sets) adds what its directory index lists, and a copy fed by an artifact enumeration carries every listed file. Only a `maven` source on a host with no autoindex, left at `file-listing: none`, still sees only what `MavenSource::files_of` names. See [user-limits.md](docs/contributors/user-limits.md).
- **Raw mappings other than `directory` are untested live.** Every test uses `directory`. Add `as-is` and `name-version-file` runs against Nexus and Artifact Keeper, and an Artifact Keeper generic source. Artifactory is covered by `112` (`directory`) and `113` (`name-version-file`).
- **A target that holds an artifact's payload is not asked about its other files.** `Target::exists` answers per artifact, so a version copied before artifact enumerations listed files, or copied part-way, is skipped as present and never gains its `.module` or classifier files. Test `200` has to start from an empty `maven-b` for this reason.

## Refactoring

Background on what has already been restructured, and on what must **not** be merged, is in [module-layout.md](docs/contributors/module-layout.md).

### Follow the "general to specific" flow

As a general flow, the code should follow a flow where the "top" level represents the general usage or high level view of the operation, then progressive "drilling in" allows for seeing the details.  This isn't a hard rule, but a general guideline to make the code easier to read, and to help minimize developer or library consumer head space.

Breaking apart long functions remains. Done: maintainer touch points ([adding-a-kind.md](docs/contributors/adding-a-kind.md)), the declaration-file splits ([module-layout.md](docs/contributors/module-layout.md#declaration-file-discipline)), and narrowing the public surface ([embedding-guide.md](docs/embedding-guide.md)), apart from the report state below.

Rules for every sub-task:

- One behavior-preserving move per commit. Compare the test count before and after (`cargo test -- --list`); a changed expectation means the commit went beyond a move.
- A declaration file holds, in order: `mod` lines, re-exports, entrypoint functions, unifying types.
- Name child files by topic, reusing sibling names already in use: `source.rs`, `target.rs`, `enumerator.rs`, `lister.rs`.
- Move an `impl` block without its struct when possible; that avoids field visibility changes.
- A private item may become `pub(super)` when it moves into a child file of the same module. Anything wider needs approval.
- Tests follow the code into the child file that receives the items they test. Setup or assertions that tests in several child files share moves into a test fixture or helper (as `ext::testing::Fixture` and `repo/maven/testing.rs` do), in the same commit as the split.
- Name each step function for its step (`refuse_draft`, `check_window`). Add a parameter struct only when a step needs more than about five values; prefer methods on an existing state type.
- Respect *Do not merge these* in [module-layout.md](docs/contributors/module-layout.md): a `walk()` stopping rule stays visible in the parent loop.
- Record each settled decision in the matching `docs/contributors` file, not here.

#### Separate internal from embedder concerns

An *embedder* needs enough access to construct a configuration to execute and to add new extension point interfaces to it. Everything else should narrow to `pub(crate)` or `pub(super)` in place, where the item already lives, as `net::url` and `net::files` were. `internal` keeps its rule: only things with no natural owner.

In a few cases, such as shared artifact server logic, an embedder may want to reuse some of it. Choose carefully: exposing it makes it harder to pull back later, since that becomes a major version change rather than an incremental exposure.

- **Report state.** `report::sink` stays public whole: `ReportWriter::state()` and `query()` return `ReportState` and `ReportQuery`, whose methods name every database and walk type. Narrowing it means splitting the crate's own state access out of `ReportWriter`, a redesign rather than a narrowing.

### Scan for dead code

Some initial ideas may have been abandoned along the way. By the time the primary features are complete there should be no dead wood left.

## Possible new features and optimizations

- **One request per version on Artifactory Pro.** The `artifactory` source's lister asks for folder info and then each file, because the storage API's `?list&deep=1` is Pro only. With a Pro server and a login, `?list` or an AQL query on the version's path answers in one request.
- **Read Artifactory's checksum headers.** A `HEAD` on a stored file answers `X-Checksum-Sha1`, `X-Checksum-Sha256`, and `X-Checksum-Md5` (measured on 6.9.1), and `MavenSource::published` already sends that `HEAD` for `Last-Modified`. Reading the headers would give a Maven payload declared digests without fetching its sidecars.
- **Read an advisory corpus from a directory, not only an archive.** `from_file` on either advisor reads a zip, which covers a downloaded snapshot and anything `git archive` or GitHub's download button produces. A working `git clone` of `ossf/malicious-packages` is a directory tree, and somebody who mirrors the feed that way should be able to point at it. It needs its own traversal rather than a variant of the zip reader: the caps in `advisory::archive` translate, but walking a user-named directory has to decide what to do about symlinks, which the zip path never faces because nothing is ever opened for writing. Until then, zipping the clone works.
- **Honor PGP revocation reasons.** Every revocation refuses today; `key-retired` could keep signatures made before the revocation. See [verification.md](docs/contributors/verification.md).
- **Fetch Sigstore TUF metadata through a configured host**, so proxy, TLS, and allow-list settings apply; until then, `setup.sigstore-trusted-root`. See [user-limits.md](docs/contributors/user-limits.md).
- **Progress timers instead of just counts.** Some operations make more sense with a time-passed counter than a processed count, and with a percentage it may even estimate the time remaining.
- **Reuse of keep-alive connections.** Pool open connections where the host allows it. This may already happen through `reqwest`, in which case it comes for free.
- **DRY and large function splits.** Aim to follow DRY, but only for shared functionality that also shares a purpose -- an overzealous unification causes later bugs when requirements change for one caller and not the other. Larger functions should use decomposition to separate logic flow from tactical detail.
- **Add report-based enumerators** passed through the command-line arguments.  This allows using an existing source but set the enumerator as an already pulled "find" or "inspect" report.  A directory as a source or target is the `local-directory` server kind; see [sources-and-targets.md](docs/contributors/sources-and-targets.md#a-local-directory).
- **Allow configuration overrides** through CLI arguments.  Much lower priority.  Part of the advantage of a file-based configuration comes from the accountability and history that a file provides.  Additionally, the logic behind turning a JSON-like config structure into argument key/values doesn't have a good solution.
- **Grow `scripts/explore-report-db.py` past its first pass.** It takes phrases that return summary reports; see *Not in the initial version* in [report-as-database.md](docs/contributors/report-as-database.md#not-in-the-initial-version).

## Found by checking the local servers

Work that follows from probing the manual-integration servers and public services on 2026-09-29. The measurements live in [server-behaviors.md](docs/contributors/server-behaviors.md).

### Nexus does not rebuild `maven-metadata.xml` or serve checksums it was not given

- Find out whether Nexus rebuilds on upload with other settings, or only through its "Rebuild Maven repository metadata" task; then document per server which `metadata` mode a Maven target needs, and consider warning when `metadata: server` targets a Nexus host. `write-path.md`'s "a repository manager rebuilds it from what it holds" is wrong for Nexus as configured here.
- A file not stored by `MavenTarget` has no `.sha1`, so `already_holds` and `overwrite-guard: check` read a large one as absent (write) or unconfirmable (refused). Fall back to Nexus's asset API.
- The `nexus` source reads Maven versions from the search API rather than `maven-metadata.xml`, so reading is unaffected; only a target is.

### Artifactory serves `.sha1` and `.md5` only when the uploader supplied them

- `already_holds` and `overwrite-guard: check` compare a large file through `.sha1`. On Artifactory, try `.sha256` first, or read the storage API.
- `MavenTarget` could send `X-Checksum-Sha1`, `X-Checksum-Sha256`, and `X-Checksum-Md5` with each `PUT`, so the stored file serves every sidecar a client may ask for, whichever sidecars `checksums` writes.

### Artifactory's `Last-Modified` is whatever the uploader said

- The `artifactory` source takes the later of the storage API's `created` and `lastModified`, so a backdated claim cannot make a file look older than its upload. A plain `maven` source pointed at Artifactory still reads the uploader's `Last-Modified`.
- A Maven target could send the source's publish time as `X-Artifactory-Last-Modified`, so a mirror preserves it; today a copy carries the copy time.

### Nexus's `search/assets` wildcards match more than a glob

- `name-version-file` sends a `*`. Filter its results client-side against the intended pattern, and check whether any mapping can produce a pattern Nexus refuses.

### The manual-integration servers differ from their README

- Nexus has anonymous access **off** (`security/anonymous` answers `enabled: false`), so the "`a` allows anonymous reads" rule does not hold for Nexus's raw, maven, and npm `-a` repositories; `.env` sets `ANONYMOUS_FORMAT=pypi`.
- Nexus's Maven repositories use `writePolicy: ALLOW`, which accepts a redeploy with 201; so does Artifactory OSS as admin. Nothing in the stack exercises the refused-rewrite path (400 or 409). Configure one Maven repository with `ALLOW_ONCE` so it is tested.
- Nexus's `.env` cannot be sourced: `NEXUS_FORMATS` is unquoted and holds spaces.
- Tests `010` and `020` had not run: Nexus `raw-a`, `pypi-a`, and every npm repository were empty.

### `ossf/malicious-packages` has an `unmergable` tree

- Decide whether `osv/unmergable/` records should load.


## Uncertainties about external systems

Assumptions this code makes about services it does not control, not yet confirmed against a running instance. None is a known bug. Each is a place where the first report from a real deployment should be believed over the code.

Where one of these is wrong the failure is visible rather than silent -- each is noted with how it shows up -- because a wrong answer about somebody else's repository is far worse than a loud refusal.

| Assumption | Where | If it is wrong |
| --- | --- | --- |
| Artifactory sets `npm.name`, `npm.version`, `pypi.name`, `pypi.version` as package properties | `enumerate::artifactory` | Every file reports `artifactory-missing-package-properties` and is skipped. **Cannot be checked locally:** the OSS image offers only Generic and Maven repositories (`/api/repositories`). Needs a Pro or JCR instance. |
| Nexus stores an npm scope in `group` without its `@` | `enumerate::nexus` | Scoped packages get the wrong purl -- `pkg:npm/angular/core` instead of `pkg:npm/%40angular/core`. **Not yet checked:** every local npm repository was empty; publishing one scoped package to `npm-a` would settle it. |
| Nexus omits `lastDownloaded` on servers too old to record it | `enumerate::nexus` | The `Never`/`Unknown` distinction collapses. 3.96.3 sends an explicit `null` for a never-downloaded asset, as the code expects; an old server is still untested. |
| The Artifactory server's clock is not ahead of this tool's | `repo::artifactory::oss` | The OSS walk ends at the tool's start time, compared against the server's `created`; a server clock running ahead leaves the newest uploads for the next walk. Concurrent uploads during a walk are unmeasured. |
| Artifact Keeper's npm and PyPI format routes serve a Remote's cached path as listed, and the catalog lists PyPI files as `simple/{project}/{file}` | `repo::artifact_keeper::cache` | Under `mode: proxy` or `proxy-cache`, cached files fail to download, or the enumerator skips them as unreadable paths. Read from the server's source; **not yet checked** against a running Remote repository. |
| Artifact Keeper stores npm under `{name}/{version}/` and PyPI under `{normalized}/{version}/`, and `path_prefix` matches the stored path | `repo::artifact_keeper::lister`, `enumerator` | The source adds no server digests, or the enumerator skips every file as an unreadable path. Read from the server's source; **not yet checked:** the local npm and PyPI repositories are empty. |
| Artifactory's storage API sends `children` for every folder, even an empty one, and never for a file | `repo::artifactory::storage` | A folder reads as a file, or a file as a folder, and a generic artifact resolves as absent. **Not yet checked:** the local server's `generic-a` is not in `server-config.d`. |
| Artifactory refuses a rewrite with 403 for an account without overwrite permission, and verifies `X-Checksum-Sha256` on a deploy | `repo::artifactory::target` | Under `overwrite-guard: server`, a refused rewrite fails instead of being compared; a corrupted transfer is stored. **Unmeasured:** the local server is used as admin, which overwrites. |
| Artifact Keeper's upload takes a raw path in a non-generic repository | `repo::artifact_keeper` | `artifact-keeper-generic` pointed at a Maven or npm repository fails, or stores a file its format handler misreads. **Unmeasured:** the backend's upload route checks no format. |
| A Nexus browse row's time is UTC on every server, spelled as Java's `Date::toString` | `repo::nexus::browse` | Another zone leaves a file's publish time unknown, so a publish window refuses it. Measured `Z` on 3.96.3. |
| An Artifact Keeper generic repository lists files as Nexus raw does | `repo::artifact_keeper::source` | Generic artifacts resolve as absent. **Not yet checked:** the local server has no generic repository. |
| A Maven repository refusing a redeploy answers 400 (Nexus `ALLOW_ONCE`) or 409, and not another status | `repo::maven::target` | A refused rewrite fails instead of being compared. **Unmeasured:** both local servers accept redeploys (Nexus `writePolicy: ALLOW`, Artifactory OSS as admin, both 201 and replacing the bytes); see *The manual-integration servers differ from their README*. |
| Nexus's `%2A` and `*` behave alike in every query parameter the code sends | `repo::nexus` | `name-version-file` resolution returns empty or over-matches. Confirmed for `group=`; the other parameters are unmeasured. |
| A refused Nexus components upload (400 under `writePolicy: ALLOW_ONCE`) writes none of its group, and `raw.directory=/` names the repository root | `repo::nexus::target` | A partly written group lists its written files as already present and resends the rest, which then fail as refused; a root-level file lands elsewhere or is refused. **Unmeasured:** the local `raw-b` uses `writePolicy: ALLOW`, and only directory uploads were tried. |


## Extensions

- **Corretto signatures.** `extensions/corretto-releases` lists each `.sig` file but does not check it against the Corretto signing key.
- **Duplicate YAML keys pass silently.** A configuration file with two top-level `hosts:` keys keeps only the last, and `validate-config` reports nothing.


## Far distant future ideas

### Merging databases

This would be a new Python script.

### Auto-detecting a repository's ecosystem

From the server, deferred as "a later convenience" by [sources-and-targets.md](docs/contributors/sources-and-targets.md).  This will require some lookup and alterations to the configuration lowering, and leads to many potential problems.

### Allow for configuration, not code, for repository quirks

Repositories such as Maven Central store files with known issues - bad formatted file uploads, incorrect checksums, wrong dependency declarations.  Rather than putting this into code, the configuration should allow for "fixing up" these errors to prevent the tool from stopping on known problems.

Examples:

- Maven Central
  - [org.slf4j:slf4j-log4j12@1.0.1 POM file](https://repo1.maven.org/maven2/org/slf4j/slf4j-log4j12/1.0.1/slf4j-log4j12-1.0.1.pom) does not match the sha1 checksum published beside it.
  - [A few POM files](src/repo/maven/pom.rs) have known bad group+artifact links.

The configuration should be *source based*, meaning "when the given source has this value, replace with that value during evaluation".

This requires some thought.  Things like the bad checksum can belong in the quarantine rules, but that's limited to just "allow the bad checksum".  "Fixing" the bad references is something else.
