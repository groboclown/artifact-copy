# Reading Reports

References: [CycloneDX](https://cyclonedx.org/specification/overview/).

Use the `json` format (`--to-report=json,FILE`) when another tool will process the records.  It is the one format meant to be ingested: [`JSONL`](https://en.wikipedia.org/wiki/JSONL), one JSON record per line, validated by [`schema/report.schema.json`](../schema/report.schema.json).  `yaml` and `text` are for people to read, and their layout may change.  artifact-copy itself never reads a line report back; a later run reads what it needs from the [report database](progress-db.md).

This allows for tools like `grep` to quickly scan them for specific messages, and using stream tools to parse the JSON while the tool runs.  This format also makes it pretty trivial to transform to a JSON array.

Each line format has an appending twin - `json-append`, `yaml-append`, `text-append` - which adds a run's records to a file rather than replacing it.

A report database, given by `--db=FILE`, is a database rather than a stream.  It holds the same four records this document describes, in the order they were written, and it accumulates them across runs: `--db=FILE` adds a run to whatever the file already holds, and `--refresh=all` starts a fresh one.  A run may write both a database and a `--to-report` line report.

Beside the records it stores their pieces, so an artifact can be found by ecosystem, namespace, name, version, or a single purl qualifier without matching text against a rendered purl.  The schema is [`schema/report-db.sql`](../schema/report-db.sql), which the tool applies verbatim.

See [The Report Database](progress-db.md) for reading and maintaining it.

## Format

Every record carries a `record` key naming its kind, so a reader that meets a kind it does not know can skip the line rather than fail the file.  There are four: `header`, `artifact`, `problem` and `summary`.

[`schema/report.schema.json`](../schema/report.schema.json) validates one line: any record this version writes, and nothing else, so a field or problem code it does not list is from a different version.

A report opens with a header and closes with a summary.  The summary is written even when the run failed, so its absence means something stronger than "nothing went wrong": it means the run did not finish, and whatever the report does contain is a prefix rather than an answer.

While the output for the reports are in JSONL, which means the records live on a single line of text, and use newlines to separate the records, for the purposes of clarity the examples express the JSON record in a friendly to read manner.

## The header, and why `corpus-age` is the field to read first

```json
{
    "record": "header",
    "created":"2026-09-18T15:47:29Z",
    "tool-version":"0.1.0",
    "command":"inspect",
    "corpus-age":{}
}
```

`corpus-age` says what the run screened against for known vulnerabilities and known malware.  **It is always present, even when empty**.  A clean report means nothing without knowing whether anything was actually consulted to produce it.  A run that copies everything and reports no findings looks identical to a genuinely clean run unless this field tells the two apart.  An empty object means no advisor was configured, so nothing was screened and nothing was claimed.  Otherwise there is one entry per configured advisor:

| Entry | Means |
| --- | --- |
| `{"consulted":{"modified":"..."}}` | Screened against this corpus, last updated at that time. |
| `"skipped-by-request"` | Configured, and `--no-advisories` turned it off for this run. |
| `{"unavailable":{"why":"..."}}` | Configured, not skipped, and still not consulted. |

An `unavailable` entry is always accompanied by an `advisory-source-unavailable` problem record, which **aborts the run by default**.  See [screening](../README.md#screening) for how to change that.

## Files, and who named them

Each file of an artifact record carries an `origin`:

| `origin` | Means |
| --- | --- |
| `"listed"` | A `find` artifact enumeration saw it in the repository's catalog.  Nothing resolved it and nothing fetched it. |
| `"resolved"` | A resolution named it: the source's own answer, or that answer combined with an artifact enumeration's listing.  The default when the field is absent. |

A `find` record now lists the files a catalog holds.  A later `inspect` or `copy` against the same report combines those with what the source resolves: files only the catalog lists (a Maven `-sources.jar` or Gradle `.module`, which the Maven layout gives a source no way to find) join the artifact, and their digests are checked when the bytes are fetched.  When the catalog and the source disagree about a file's digest or size, the artifact is refused with `listing-mismatch`, which is `skip-artifact` by default.

## Provenance

Artifact and problem records carry `provenance`: why the run looked at the artifact, leaf first. Each link is a message, like a problem's, so a tool reads its kind and pieces without parsing the English:

```json
{"id": "cause-dependency", "args": {"purl": "pkg:npm/app@1.0.0", "kind": "runtime", "release": "general"}, "text": "runtime dependency of pkg:npm/app@1.0.0"}
```

| `id` | `args` |
| --- | --- |
| `cause-requested` | `arg`: the request as typed. |
| `cause-lock-file` | `path`, and `entry`: the lock file's own name for the artifact. |
| `cause-dependency` | `purl`: the parent, at the version it resolved to; `kind`: the dependency kind; `release`: `general` or `pre-release`, present with a version. |
| `cause-enumerated` | `enumerator`. |
| `cause-report` | `path`: the report database used as a work list; `purl`: the entry it listed; `source`; `destination`, for `copy --from-db`; `run`: the run that last recorded the entry, when known. |

## Advisories

Each artifact record lists the advisories that named it under `advisories`:

```json
{"id": "MAL-2024-1", "advisor": "ossf", "kind": "malware", "match": "affected"}
```

| Field | Means |
| --- | --- |
| `advisor` | The configured advisor whose corpus supplied the record.  When several carry it, the first in configuration order. |
| `kind` | `"malware"` for a `MAL-` record, otherwise `"vulnerability"`. |
| `match` | `"affected"` when the version falls in the advisory's affected set.  `"version-unusable"` when the advisory names the package but lists no version that can be compared with this one, such as commit-hash ranges only. |
| `suppressed-by` | The VEX statement that cleared it.  A suppressed advisory is recorded and raises no problem, so no `problem-policy` entry or quarantine rule ever sees it. |

An unsuppressed advisory also appears as a problem record: `malware-known` (`skip-artifact`, hard quarantine), `vulnerability-known` (`warn`, or at least `skip-artifact` under `vulnerabilities: forbid` unless a quarantine rule names the artifact), `vulnerability-under-investigation` (`warn`), or `advisory-version-unusable` (`skip-artifact`, hard quarantine).  `problem-policy` and the quarantine policy change these the way they change any other code.  A VEX document given with `--lock` adds `vex-incomplete` (`warn`) for a vulnerability found against a package the document covers and does not mention, `bom-ecosystem-foreign` (`ignore`) for each package it names in an ecosystem the source does not serve, and `vex-unparsable` (`abort`) for a document that cannot be used.  `inspect` and `copy` screen every resolved artifact with a version; `find` screens every listing with a version.

## Several targets

A `copy` with more than one `--to` adds `outcomes` to each artifact record: what became of the artifact at each target, in `--to` order.  `outcome` stays, as the worst of them -- `failed`, then `refused`, then `copied`, then `already-present` -- so a reader of one-target reports needs no change.  A one-target copy writes no `outcomes`.

```json
{
    "record": "artifact",
    "purl": "pkg:npm/tuna",
    "version": "1.0.0",
    "outcome": {"action": "copied", "verification": "verified"},
    "outcomes": [
        {"destination": "mirror", "outcome": {"action": "copied", "verification": "verified"}},
        {"destination": "backup", "outcome": {"action": "already-present"}}
    ]
}
```

## The summary

```json
{
    "record": "summary",
    "artifacts": 1,
    "counts": {
        "signature-missing": 1
    },
    "worst-action": "warn",
    "unmatched-suppressions": []
}
```

`artifacts` counts artifact records.  `counts` and `quarantined` count problems rather than artifacts, so one artifact tripping two rules adds two; count artifacts from the artifact records, where an artifact is a thing that exists.  `worst-action` is the strongest action anything in the run took, and is what the exit code follows from.

### `unmatched-suppressions`

VEX (Vulnerability Exploitability eXchange) and VDR (Vulnerability Disclosure Report) documents are given with `--lock`, as OpenVEX or CycloneDX; a CycloneDX document is both an SBOM and a VEX.  The packages a document names are the run's request, and its statements clear findings against them.

VEX statements this run showed to be dead policy, each as `document#advisory` - the document to edit and the statement in it.  They also appear as `vex-unmatched` problem records, which are warnings by default, so the counts and this list agree.

A statement is asked once a package it covers resolves and is screened, and **a statement asked that cleared nothing is stale**: the advisory was withdrawn, its affected range moved, or the statement was never needed.  A statement about a package the source does not hold was never asked; that package is reported as `artifact-not-found` instead, which is what an artifact filter would answer.  Under `--no-advisories`, every statement about a resolved package is listed: the package is still screened, against no advisories, so nothing can answer.  A statement naming only packages in an ecosystem the source does not serve is no part of the run, and is not listed.  Two documents clearing the same advisory for the same package both count as answering.

## Problem codes

Every problem record carries a `code`, from the closed set below. The code decides what the run does; `problem-policy` and the quarantine policy may change that for a code marked per-artifact. See [Problem policy](configuration-general.md#problem-policy).

- **Action** is what the run does by default: `ignore` and `warn` carry on, `stop-spider` keeps the artifact and stops following its dependencies, `skip-artifact` leaves the artifact out, and `abort` stops the run.
- **Quarantine** is the default reservation class: `soft` takes the artifact and flags it, `hard` holds it back for review.
- **Per artifact** says whether `problem-policy` and the quarantine policy may name the code. A fault in the run's own input or environment always takes its default.

| Code | Action | Quarantine | Per artifact | Meaning |
| --- | --- | --- | --- | --- |
| `config-invalid` | `abort` | - | no | The configuration does not hold together. |
| `config-unreadable` | `abort` | - | no | A configuration file cannot be read or parsed. |
| `file-unreadable` | `abort` | - | no | A file the run was given cannot be read. |
| `file-unwritable` | `abort` | - | no | A file the run tried to write could not be written: a full disk, a read-only mount. |
| `cache-file-missing` | `warn` | - | no | The report says a payload is cached and it is not there, so it is fetched again. |
| `cache-entry-expired` | `ignore` | - | no | A cached file passed its retention or freshness and was fetched again. |
| `cache-entry-stale` | `warn` | - | no | A cached document passed its freshness and could not be refreshed, so the stale copy was used. |
| `cache-entry-evicted` | `ignore` | - | no | A cached file was removed to keep a cache under its size cap. |
| `report-unusable` | `abort` | - | no | The report store failed. |
| `checksum-mismatch` | `abort` | - | yes | The bytes do not match a declared digest. |
| `size-mismatch` | `abort` | - | yes | The bytes do not match the declared size. |
| `signature-invalid` | `abort` | - | yes | A signature does not verify against the key that made it. |
| `signature-key-revoked` | `skip-artifact` | `hard` | yes | The signing key's holder has revoked it. |
| `signature-key-expired` | `warn` | `soft` | yes | The signing key had expired before the signature was made. |
| `signature-missing` | `warn` | `soft` | yes | No signature to check. |
| `signature-key-unvouched` | `warn` | `soft` | yes | The signature verifies, but the signing policy does not let its key vouch for this artifact. |
| `artifact-not-found` | `skip-artifact` | - | yes | The source does not hold the artifact. |
| `version-unresolvable` | `skip-artifact` | - | yes | No version matches the request and the run's criteria. |
| `host-unreachable` | `skip-artifact` | - | yes | No answer from the host. |
| `request-rejected` | `skip-artifact` | - | yes | The host refused the request: a 4xx other than 404, 408, and 429. |
| `secondary-file-rejected` | `skip-artifact` | - | yes | A target refused one secondary file of an artifact and took the rest. |
| `download-too-large` | `skip-artifact` | - | yes | A download passed its size limit. |
| `metadata-malformed` | `skip-artifact` | - | yes | The source's metadata for the artifact cannot be read. |
| `license-forbidden` | `skip-artifact` | - | yes | The license policy forbids the artifact's license. |
| `license-unknown` | `warn` | - | yes | The artifact declares no license the policy can judge. |
| `license-unmatched` | `warn` | - | yes | The license policy has no rule for the artifact's license. |
| `malware-known` | `skip-artifact` | `hard` | yes | An advisory names the artifact as malware. |
| `vulnerability-known` | `warn` | - | yes | An advisory names a vulnerability affecting this version. |
| `vulnerability-under-investigation` | `warn` | - | yes | A VEX statement says a vulnerability is under investigation. |
| `advisory-version-unusable` | `skip-artifact` | `hard` | yes | An advisory names the package, and whether this version is affected cannot be decided. |
| `advisory-source-stale` | `warn` | - | yes | An advisory corpus is older than configured. |
| `advisory-source-unavailable` | `abort` | - | yes | Screening was configured and no corpus answered. |
| `vex-unparsable` | `abort` | - | yes | A VEX document cannot be read, or states something its format forbids. |
| `vex-unmatched` | `warn` | - | yes | A VEX statement cleared nothing. |
| `vex-incomplete` | `warn` | - | yes | A VEX document covers the artifact and says nothing about an advisory against it. |
| `bom-ecosystem-foreign` | `ignore` | - | yes | An SBOM or VEX document names a package in an ecosystem the source does not serve. |
| `publish-too-recent` | `skip-artifact` | `hard` | yes | The version is inside the publish window, or its publish time is unknown. |
| `dependency-unresolved` | `warn` | - | yes | One dependency could not be resolved; the others are kept. |
| `dependency-metadata-dynamic` | `warn` | - | yes | The dependency list is computed at build time, so it cannot be read. |
| `pom-profile-unsupported` | `stop-spider` | - | yes | A POM uses a profile this tool does not activate, so its dependencies are not followed. |
| `pom-property-unresolved` | `skip-artifact` | - | yes | A POM names itself through a property that does not resolve. |
| `lock-unrecognized` | `abort` | - | no | No reader claims a `--lock` file. |
| `lock-format-unknown` | `abort` | - | no | `--lock=FORMAT,FILE` names a format no reader has. |
| `lock-malformed` | `abort` | - | no | A `--lock` file cannot be read in its format. |
| `enumeration-unsupported` | `abort` | - | no | The repository has no enumerator. |
| `sample-percent-unsupported` | `abort` | - | no | `--sample-size` is a percentage and the enumerator cannot count its catalog. |
| `listing-mismatch` | `skip-artifact` | - | yes | The catalog and the source disagree about a file's bytes. |
| `upload-metadata-incomplete` | `warn` | - | yes | The target took the bytes but serves less about them than the origin did. |
| `distribution-type-unsupported` | `warn` | - | yes | A file of the version was left behind: the target cannot take its type, or no version can be read from its name. |
| `file-omitted` | `ignore` | - | yes | An `omit` rule left a file out of an artifact. |
| `artifact-omitted` | `warn` | - | yes | An `omit` rule left an artifact out. |
| `unimplemented` | `abort` | - | no | The run reached something this version does not do yet. |
| `aborted` | `abort` | - | no | The run was stopped. |

## Message ids

A problem's `message`, and each provenance entry, is an `id`, named `args`, and an English `text`:

```json
{"id": "publish-too-recent", "args": {"purl": "pkg:npm/tuna@1.2.0"}, "text": "..."}
```

Match on `id` and read `args`; the `text` is a fallback for display and may change wording between versions. One code may carry several ids, each a different diagnosis: `publish-too-recent` and `publish-time-unknown` share a code, since the run acts on both the same way, and call for different fixes - wait, versus set `unknown-publish-time: allow`.
