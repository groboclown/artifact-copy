# Artifact Copy

A tool to inspect artifacts and copy them from one repository to another, including following dependencies.  It has added security measures for [quarantining](#the-quarantine-policy) artifacts.

Reading from a repository can optionally store the results in a sqlite database.  This allows for performing [analysis](#explore-the-database) after an execution.

It supports [JFrog Artifactory](docs/configuration-artifactory.md), [Sonatype Nexus](docs/configuration-nexus.md), and [Artifact Keeper](docs/configuration-artifact-keeper.md) repository servers out of the box.  It supports [PyPI](docs/configuration-pypi.md), [Maven](docs/configuration-maven2.md), and [NPM](docs/configuration-npm.md) standard pull and publish mechanisms.  It can also read from [GitHub repository releases](docs/configuration-low-level.md).


## Security

You are responsible for the servers you configure; the tool is responsible for doing no harm with what it downloads.  It never runs an artifact, bounds what it reads, checks digests and signatures, and screens against advisories when configured.  TLS is verified by default, and a plain `http://` url is refused unless its host sets `insecure-transport: true`.  See [Security Assumptions](docs/security.md) for what the tool guards against and what it assumes.

## Usage

### General flags

```
--config=CONFIG       Add the configuration file or directory to the
                      configuration collection.  You may pass multiple of
                      these to extend the configuration, but note that
                      the *earlier* settings override later ones.  See
                      the configuration section below for details.

--quiet               Log errors only, and show no progress (level `error`).

--verbose             Log each artifact as it is handled (level `info`).

--debug               Log the actions taken within each artifact
                      (level `debug`).

--tracing             Log everything (level `trace`).  Secrets stay
                      redacted unless --unsafe-debug is also given.

--unsafe-debug        Debug *all* data, secrets included (level `debug`,
                      or `trace` with --tracing).
                      WARNING: this has the potential to output sensitive
                      information, such as passwords.  Do not use in
                      any environment where this could leak information.

--log-file=FILE       Append log lines to FILE, or write them to standard
                      output with `-`.  Defaults to `setup.log`'s file,
                      then standard error.
```

Of the level flags, **the first one given wins**: `--quiet --debug` logs at `error`.  `--unsafe-debug` reveals secrets wherever it appears, even when an earlier flag set the level.  Without a level flag, the level comes from `RUST_LOG`, then the configuration's `setup.log.level`, then `warn`.  See [Logging](docs/configuration-general.md#logging).


### Screening

`copy`, `inspect` and `find` take two more flags, which apply to screening artifacts for known vulnerabilities and known malware:

```
--no-advisories       Skip vulnerability and malware screening for this run.

--refresh-advisories  Refresh the advisory corpus even if the cached copy
                      is still fresh.
```

Screening happens only when the configuration names an `advisors` entry.  When it does, and no corpus answers, the run reports `advisory-source-unavailable` and stops with an error.  Unlike unreachable source
repositories, a source being down costs you the artifacts it holds, which you will notice, while screening being down costs you a *wrong answer* - a run that copies everything and reports nothing looks exactly like a clean run.  The tool would rather refuse to answer.

You have two ways to say you accept that risk:

* Run with the CLI argument `--no-advisories` for one run to record the issue in the report's header rather than reported as a problem.
- Add the value to the `problem-policy` section in the configuration to say it as a standing decision: 
  ```json
  {"problem-policy": {"advisory-source-unavailable": "allowed"}}
  ```

Either way the report's `corpus-age` header field records that nothing was consulted, so a report produced this way cannot later be mistaken for a screened one.  See [Reading Reports](docs/reports.md) for how to read it. 


### Problems

Everything that goes wrong, or is worth saying, is a problem with a **code**, such as `publish-too-recent` or `checksum-mismatch`.  The code decides what the run does: carry on, skip the artifact, or stop.  Each problem's message carries a stable **message id** with named arguments, so a tool reading a report matches on the id rather than on English text.  [Problem codes](docs/reports.md#problem-codes) lists every code with its default handling, and [Message ids](docs/reports.md#message-ids) describes the message shape.

The configuration's `problem-policy` changes a code's handling for every artifact; see [Problem policy](docs/configuration-general.md#problem-policy).


### The quarantine policy

The file named by `setup.quarantine-policy` holds per-artifact exceptions to `problem-policy`, each with a justification and an expiry, in either direction: excuse one artifact, or hold one to a stricter rule.  The first rule matching both the artifact and the code wins.  It follows a [schema](schema/quarantine-policy.schema.json); see the [example](examples/configuration/quarantine-policy.yaml).

```yaml
$schema: https://github.com/groboclown/artifact-copy/schema/quarantine-policy.schema.json
rules:
  - purl: pkg:pypi/urllib3@2.5.1
    codes: [publish-too-recent]
    class: soft
    justification: Emergency security fix needed before the publish window elapses.
    expires: "2027-01-31T00:00:00Z"
```

A rule naming `publish-too-recent` **excuses the publish window** for that artifact, so a patched release can be taken before the window has run without shortening it for everything.  It excuses only the window: a pre-release still needs `--pre-release`.

Both `allowed` and `soft` take the artifact, and differ afterwards:

| Class | The artifact | Flagged in the report's `quarantine` list | Under `--harden` |
| --- | --- | --- | --- |
| `allowed` | taken | no | still taken |
| `soft` | taken | yes | held back |

`--harden` (or `setup.harden-quarantine`) makes every `soft` reservation hold its artifact back for one run.  `soft` is usually the one wanted, since the exception stays visible for audit; `allowed` holds even in a hardened run.


### Copy a subset of artifacts from a source to a target

```
artifact-copy copy
  --from=REPOSITORY --to=REPOSITORY [--to=REPOSITORY ...]
  [--pre-release]
  [--dependencies=SPIDER]
  [--lock=FILE ...]
  [--to-report=[TYPE,]FILE]
  [--db=FILE [--from-db] [--refresh=PART,...]]
  [--] [ARTIFACT ...]
```

Copy each listed ARTIFACT request from the `--from` repository (the SOURCE) to the `--to` repository (the TARGET).  Each names a repository in the configuration, and the two must allow for compatible artifacts.

Repeat `--to` to copy to several targets in one run.  Each artifact is downloaded and checked once, then published to each target in the order given.  One target failing does not stop the others, and a payload stays cached until every target has taken it.  Naming a target twice is refused.

`--source=SOURCE` and `--target=TARGET` name a low-level source and target instead, for advanced use.

The ARTIFACT request must conform to the repository kind's format rules.  If the request includes a non-exact version, then the SOURCE will use its own rules to determine the exact version accessed.  This will always choose the *highest* matching version.  If you pass the `--pre-release` flag, then this will include alpha, beta, release candidate, and other non-official versions in its search; without this flag, the tool will attempt to only select general availability releases.

Some repositories allow for declaring a collection of dependencies for each artifact.  You may pass the `--dependencies=SPIDER` setting to override the SOURCE configuration's `dependencies` setting, which takes the same syntax.  Without the flag, or with `--dependencies=default`, the SOURCE setting applies; a SOURCE without one follows no dependencies.  The kinds are `runtime`, `dev`, `test`, `optional`, `peer`, and `build`, and ecosystems differ in which they publish: `test` is Maven only, `peer` is npm only, PyPI publishes neither `dev` nor `test`, and `build` - a Maven parent POM or imported BOM - joins any walk.  Asking for a kind an ecosystem lacks stops the run.  See [Dependencies](docs/configuration-server.md#dependencies) for the table.  You can use `+` to join multiple of these together, or `all` to mean the union of all the dependencies.  You can also add `shallow` to the list to mean only pull the first level dependencies, and not spider through all of them.

Instead of (or in addition to) passing in a list of artifacts, you can pass one or more `--lock=FILE` to have the enumerator examine the repository specific lock-file for artifacts.  The format is detected from the file's name and content; `--lock=FORMAT,FILE` names it outright.  The formats are `package-lock` (`package-lock.json`, `npm-shrinkwrap.json`), `yarn` (`yarn.lock`), `openvex`, and `cyclonedx`, and an extension may add more.  The repository enumerator may need to do something similar to find dependencies, so this will re-use that logic.  Note that the command-line requested `--lock=FILE` will not obey the `SPIDER` setting - the tool will pull *every* dependency in that lock file, and will only cause the `SPIDER` setting to take effect with those top-level artifacts' dependencies.

A `--lock=FILE` may also name a VEX or SBOM document: OpenVEX, or CycloneDX, which is both an SBOM and a VEX.  Every package the document names becomes a requested artifact.  A package in an ecosystem the SOURCE does not serve, such as an operating system package in an SBOM generated from a container image, is left out and reported as `bom-ecosystem-foreign`, which `--verbose` shows.  The document's VEX statements apply to the whole run: a `not_affected` or `fixed` statement clears the vulnerability finding before any problem is raised, so it bypasses the vulnerability rules in `problem-policy` and the quarantine policy for that artifact; `under_investigation` lowers the finding to a warning, and `affected` clears nothing.  A statement that cleared nothing is reported as `vex-unmatched`, which under `--no-advisories` is every statement about a resolved package, and an advisory the document says nothing about, against a package it covers, as `vex-incomplete`.  These documents are recognized by their content, whatever their name; `--lock=openvex,FILE` and `--lock=cyclonedx,FILE` name the format outright.  SPDX and other SBOM formats are not read yet.

This command writes the same report the [`inspect`](#inspect-artifacts-from-a-repository) sub-command writes, in the same formats and to the same places - standard output unless `--to-report` or `--db` names a file.  It lists **every** artifact the run reached, not only the ones it took, and each carries what became of it: `copied`, `already present`, or the reason it was not copied.  There are three such reasons, and they are kept apart because they call for different responses: `refused` means a rule decided against an artifact that was otherwise fine, `unresolved` means the request matched nothing, and `failed` means the copy itself did not succeed and re-running may well take it.  A report listing only what was copied would answer what the target now holds, which the target answers better; what only the run can say is why something it reached did not get there.

A refusal also prunes: the tool does not follow the dependencies of an artifact it would not copy, and does not fetch its payload.

With several targets, each artifact's record also says what became of it at each target, and its overall outcome is the worst of them: `failed`, then `refused`, then `copied`, then `already present`.  A refusal from a rule about the artifact, such as its license or an advisory, applies to every target.

Note: this command considers each requested artifact as independent, and will not attempt to select inter-compatible versions.  This includes the lock file scan and dependency scan.  Therefore, note that this may end up pulling in revisions that a version evaluation tool would not use.

With `--db=FILE`, the run is also kept in a [report database](#the-report-database) that accumulates across runs, which is what lets a copy resume: a long running [`find`](#find-all-artifacts-in-a-source-or-target-repository) or [`inspect`](#inspect-artifacts-from-a-repository) fills it in, and a later copy works through what is left.  `copy` accepts `--refresh=source`, `target`, `payloads`, `spider`, and `all`.

A downloaded payload stays in the cache after it is published, so a later run does not fetch it again.  Set `setup.cache-payloads` to `discard` when that is the wrong trade - a migration of a large repository would otherwise grow a second copy of it on local disk.

Pass `--from-db` to copy what the `--db` database says is outstanding instead of naming artifacts.  The database is then the manifest: a version the source gained since the artifact enumeration is not copied, so a migration split across several runs stays reproducible.  Each artifact's files come from the database rather than being asked of the source again, and anything the database does not hold falls back to the source.  An artifact that has already reached this target is skipped, whichever source or run put it there.  A `find` feeds it when run with `--from` naming the same repository.  See [The Report Database](docs/progress-db.md#example-a-resumable-migration) for a long copy that recovers without retrying every artifact.

### Inspect artifacts from a repository

```
artifact-copy inspect --from=REPOSITORY [--pre-release] [--dependencies=SPIDER] [--lock=FILE ...] [--to-report=[TYPE,]FILE] [--db=FILE [--from-db] [--refresh=PART,...]] [ARTIFACT ...]
```

Inspect the artifacts in the configured repository (the SOURCE) that match the requested lock file and/or artifact requests.  It uses the same rules as the `copy` sub-command, but, rather than copying them to a target repository, will instead generate a report in the given report FORMAT.

`--source=SOURCE` names a low-level source instead, for advanced use.

The repository is read through its **source**, not its enumerator: inspection resolves each request into a full record - its files, their checksums, the declared license, the publish time - and every one of those is something only a source can answer.  An enumerator enumerates a catalog and is what [`find`](#find-all-artifacts-in-a-source-or-target-repository) takes.

Pass `--from-db` to inspect what the `--db` database says the source holds, instead of naming artifacts.  Each artifact's files, license and publish time come from the database where it has them, so replaying an inspection that already resolved everything costs no requests.  Naming artifacts or a lock file alongside it is refused, because the two say different things.  To feed it from a `find`, run that with `--from` naming the same repository.

Without `--dependencies`, the SOURCE configuration's `dependencies` setting decides, as with `copy`.  Every artifact named by a `--lock=FILE` is taken whatever that setting says; it governs which *edges* are followed, not whether a named artifact is wanted.

The report goes where `--to-report=[TYPE,]FILE` says, and to standard output as text when neither it nor `--db` is given.  A FILE of `-` is standard output, so `--to-report=json,-` writes JSON there.  TYPE defaults to `text`.  It always opens with a header record and closes with a summary, and the summary is written even when the run fails - a report without one means the run did not finish.

* `json` output in a JSON format, one record per line.  The one format meant for other tools to ingest; see [Reading Reports](docs/reports.md).
* `yaml` output in a YAML format, for people to read.
* `text` output in a friendly human format.  Essentially, the same as YAML, but without the quotes and character escaping.

Each of the line formats has an appending twin - `json-append`, `yaml-append`, and `text-append` - which adds this run's records after the ones already in the file instead of replacing them.  The plain spellings replace.

`inspect` accepts `--refresh=source`, `spider`, and `all`.

### The report database

`--db=FILE` keeps a run in a SQLite database, beside or instead of the `--to-report` line report.  The two serve different readers: a line report lets an outside tool follow a run, and the database is this tool's cache and resume state.  `copy`, `inspect`, and `find` take it.  Without `--to-report`, a run given `--db` writes no line report.

Without `--db`, `copy` and `inspect` keep a temporary database for the run under the cache directory (`setup.cache-dir`), so a dependency walk queues on disk rather than in memory, and remove it when the run ends.  It changes nothing about the report: the text still goes to standard output.  Nothing in it outlives the run, so it neither resumes a walk nor answers a later one.  `--db=-` keeps no database at all; the walk then queues in memory, up to `setup.maximum-in-memory-queued-dependencies`, and `--from-db` and `--refresh` are refused.  `find` keeps none, since an enumeration holds nothing that grows.

Each run is added to whatever the file already holds.  **The database is a cache**: what an earlier run learned is used rather than asked again.  `--refresh=PART,...` asks the server for a part instead, and still records the answer.  PART is one of:

* `source` - versions, files, license, and publish time a source was already asked for.
* `target` - whether a target already holds an artifact.
* `payloads` - bytes an earlier run fetched.
* `enumeration` - where an interrupted `find` stopped; without it, the walk continues from there.
* `spider` - where an interrupted dependency walk of `inspect` or `copy` stopped; without it, a walk of the same source under the same `--dependencies` continues from there.
* `all` - every part, and the database file is replaced first.

`--refresh` takes a comma separated list and may be repeated.  A part a command does not use is refused.  The `--from-db` flag takes a command's work from the database rather than from named artifacts.

See [The Report Database](docs/progress-db.md) for its schema, `scripts/explore-report-db.py` for inspecting it, and maintenance.

### Find all artifacts in a source or target repository

```
artifact-copy find --from=REPOSITORY [--to-report=[TYPE,]FILE] [--db=FILE [--refresh=PART,...] [--rescan-all]] [--sample-size=SIZE]
artifact-copy find --enumerator=ENUMERATOR [--as-target=TARGET | --as-source=SOURCE] [--to-report=[TYPE,]FILE] [--db=FILE [--refresh=PART,...] [--rescan-all]] [--sample-size=SIZE]
```

`--from` walks the repository's enumerator and records what it finds as the contents of the same repository's source, so a later `inspect --from-db` or `copy --from-db` reads its work from the database.  `--enumerator` names a low-level enumerator instead, for advanced use, and files what it finds under the enumerator unless `--as-target` or `--as-source` says otherwise.

Searches the entire repository for all stored artifacts.  Uses the same format options as the [`inspect`](#inspect-artifacts-from-a-repository) sub-command, and writes the same kind of report.

**An inventory, not a resolution.**  An enumerator reports what a repository *holds*: the artifact, its version where the catalog lists one, and when the repository last served it.  The files, their checksums, the declared license and the publish time are a SOURCE's answers and cost a request each, so a walk of a million artifacts would become a million requests on top of the few hundred the walk itself takes.  `copy --from-db` falls back to the source for what an inventory lacks, so an inventory is enough to feed it.

That is also why this sub-command has no `--pre-release` and no `--dependencies`: neither means anything without resolution.

Some catalogs list names only - PyPI's simple index and npm's replication feed both do - and a record then carries no version at all rather than an invented one.

**Do not enumerate Maven Central.**  Its terms forbid downloading all or large portions of it, and its index is deprecated and rate limited, so the `maven-central` kind has no enumerator.  Copy what your builds need instead.  See [Public Repositories](docs/configuration-public.md#being-a-good-citizen).

With `--enumerator`: if the repository whose artifacts you are enumerating is also a configured publish target, pass `--as-target=TARGET` to record what the artifact enumeration finds as that target's contents.  A later `copy` then asks the database what the target already holds instead of asking the target once per artifact.  The equivalence is your assertion: the tool records what the artifact enumeration saw, and never that one repository is another.

Likewise, if the repository whose artifacts you are enumerating is also a configured source, pass `--as-source=SOURCE` to record what the artifact enumeration finds as that source's contents.  That is what a later `inspect --from-db` or `copy --from-db` reads its work from; without it, the artifact enumeration is filed under the enumerator and neither of them sees it.  The two flags cannot be combined.

With `--db`, a walk that was interrupted continues from its last page rather than the beginning.  A walk recorded under a different enumerator kind is refused; `--refresh=enumeration` walks from the start instead.  `find` accepts `--refresh=enumeration` and `all`.

With `--db`, a walk after one that reached the end of the catalog lists only what was modified since that walk *started*, where the enumerator can ask the server for that: `artifactory` and `artifactory-oss`, which filter on Artifactory's `modified` time, so a redeployed file is listed again.  Every other enumerator walks the whole catalog and says so in the log.  The run ends by logging how many artifacts were found and since when, which tells you whether another pass is needed.  `--rescan-all` walks the whole catalog anyway; a sampled walk always does.  An interrupted walk resumes as it started, narrowed or not, and is refused beside `--rescan-all` when it was narrowed; `--refresh=enumeration` drops it.  A narrowed walk lists changes, not the catalog, so `inspect --from-db` and `copy --from-db` still rely on the last full walk to know everything the source holds.

This can limit the artifact enumeration to a sample size.  You can specify a number of artifacts or a percentage of artifacts (denoted by adding a `%` after the number, like `--sample-size=35%`).  If the repository enumerator does not report a total artifact count, then this enumerates the first SIZE artifacts, and errors if you specify a percentage

### Validate the configuration

```
artifact-copy validate-config
```

Validate the configuration files.  This performs a full inspection, including resolving every configured secret, AWS ones included, and reading linked license files.

## Configuration files

You may specify a configuration from one or more files, or from a directory containing a set of configuration files.  They follow a [schema](schema/config.schema.json), and load *first wins*: with `--config=a.yaml --config=b.yaml`, a setting in `a.yaml` beats the same setting in `b.yaml`.  A directory loads its `*.yaml` and `*.json` files (not sub-directories) alphabetically.  This prevents a script from tacking on an extra configuration file to weaken rules.

The [user guide](docs/README.md) covers every setting.  Start with [general settings](docs/configuration-general.md), which include the security-relevant ones.

### Servers and repositories

Describe each server by its technology, and list its repositories.  The tool generates the hosts, sources, targets, and enumerators they imply, each repository's under the repository's name, which is what `--from` and `--to` take.

```yaml
servers:
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: basic
      username: { kind: env, name: NEXUS_USER }
      password: { kind: env, name: NEXUS_PASSWORD }
    repositories:
      nexus-maven:
        name: maven-releases     # the repository's name on the server
        kind: maven2
        access: read             # read, write, or read-write
  pypi-org:
    kind: public-pypi.org        # one read-only repository, named pypi-org
```

* Settings every server shares, such as authentication and retry: [shared settings](docs/configuration-server.md).
* Per server kind: [Nexus](docs/configuration-nexus.md), [Artifactory](docs/configuration-artifactory.md), [Artifact Keeper](docs/configuration-artifact-keeper.md), [local directory](docs/configuration-local-directory.md), and [public repositories](docs/configuration-public.md).
* Per repository type: [Maven](docs/configuration-maven2.md), [npm](docs/configuration-npm.md), [PyPI](docs/configuration-pypi.md), and [raw](docs/configuration-raw.md).
* The low-level `hosts`, `sources`, `targets`, and `enumerators` sections: [low-level configuration](docs/configuration-low-level.md).
* Your own server kinds: [Writing Your Own Server Kind](docs/custom-server-kinds.md).

### Adding support for new sources and targets

In addition to the built-in systems, you can [add your own custom extension](docs/extensions.md).  Currently, this is limited to a WASM extension.  You can find two examples in the [extensions](extensions) directory.

## Supporting Scripts

Along with the `artifact-copy` tool, the [scripts](scripts) directory contains some tools to help you review the generated database files.

### Explore the Database

```
scripts/explore-report-db.py DB_FILE
```

This script provides an interactive tool to look through the data in the database file.  It's a simple layer on top of low-level SQL to read through the database.

Rather than running interactively, you can also pass commands through `stdin` to automate the generation of reports.


### Compare Artifacts

```
scripts/diff-report-db.py LEFT_DB RIGHT_DB --left=NAME [--left-role=ROLE] --right=NAME [--right-role=ROLE] [--zero-size-known] [--output=FILE]
```

Compare what two repositories hold, as [report databases](#the-report-database) recorded them.  Each side is a repository name in its database; both databases may be the same file.  `--left-role` and `--right-role` (`source`, `target`, or `enumerator`) pick one when a name has several roles.

The comparison goes only as deep as both sides recorded, per artifact: packages always; versions when both sides list versions of the package; files when both sides list files of the artifact; a file's size when both sides know it; and its digests under each algorithm both sides recorded.  A name-only inventory against a full inspection therefore reports packages and nothing below them.  Some inspectors record a size of 0 to mean unknown, so 0 is not compared unless `--zero-size-known` is given.

Writes one JSON object per difference, one per line, to standard output or `--output`:

```
{"level": "version", "change": "right-only", "purl": "pkg:maven/g/a", "version": "1.2"}
{"level": "size", "change": "differs", "purl": "pkg:maven/g/a", "version": "1.2", "file": "a-1.2.jar", "left": 10, "right": 12}
```

`level` is `package`, `version`, `file`, `size`, or `digest`; `change` is `left-only`, `right-only`, or `differs`.  A digest difference also carries `algorithm`, with each side's digests as a list.



## License

This tool was released under the [MIT license](LICENSE).
