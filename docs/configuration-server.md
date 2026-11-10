# Shared Server Settings

References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

Settings every server kind accepts, and settings shared by its repositories. The per-server and per-repository guides link here rather than repeat them. The [schema](../schema/config.schema.json) is the authority; this guide explains it.

## Servers

A `servers` entry describes one server by its technology. Its key (the alias) names the host it generates.

```yaml
servers:
  nexus:                         # the alias
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: bearer
      token: { kind: env, name: NEXUS_TOKEN }
    retry:
      max-retries: 5
    values:
      maximum-concurrent-downloads: 8
    repositories:
      nexus-maven:
        name: maven-releases
        kind: maven2
```

| Field | Required | Meaning |
| --- | --- | --- |
| `kind` | yes | The server technology. Built-in: `nexus3`, `artifactory-pro`, `artifactory-oss`, `artifact-keeper`, `local-directory`, `maven-central`, `npmjs`, and `public-pypi.org`. `setup.server-kinds-dir` adds more; see [Writing Your Own Server Kind](custom-server-kinds.md). |
| `url` | for most kinds | The server's root url. Replaces any url the kind supplies. The [public kinds](configuration-public.md) supply one. |
| `authentication` | no | Credentials sent with every request. See [Authentication](#authentication). |
| `insecure-transport` | no | Accept an `http://` url. Default `false`, which refuses one. See [Transport security](configuration-general.md#transport-security). |
| `retry` | no | Retry rules merged over the kind's own. See [Retry](#retry). |
| `values` | no | Settings the kind's templates read. See [Server values](#server-values). |
| `repositories` | no | The server's repositories, keyed by alias. See [Repositories](#repositories). |

`$comment` and `$comments` are accepted on every entry and ignored.

## Authentication

A server takes one `authentication` block. The tool never sends it to an [additional host](configuration-low-level.md#additional-hosts) unless that entry asks for it, and never sends it to a [mirror](configuration-low-level.md#mirrors).

Basic login:

```yaml
authentication:
  kind: basic
  username: { kind: env, name: REPO_USER }
  password: { kind: env, name: REPO_PASSWORD }
```

Bearer token:

```yaml
authentication:
  kind: bearer
  token: { kind: env, name: REPO_TOKEN }
  header: Authorization          # default
  prefix: "Bearer "              # default
```

`header` and `prefix` let a bearer block send other token headers, such as `X-JFrog-Art-Api` with an empty prefix. Both forms send credentials as given, so use them only over `https`.

### Secret values

Each credential is a secret value: a reference to where the value lives.

| `kind` | Fields | Reads |
| --- | --- | --- |
| `text` | `value` | The value inline. Avoid it outside of tests. |
| `env` | `name` | An environment variable. |
| `aws-secret` | `name`, optional `region`, `profile` | An AWS Secrets Manager string secret. |
| `aws-secret-key` | `name`, `key`, optional `region`, `profile` | One key of a JSON AWS Secrets Manager secret. A number or boolean becomes its JSON text. |
| `property-file` | `key`, and `config-relative-path` or `working-dir-path` | One `KEY=value` entry of a `.env`-style file. |

AWS secrets use the AWS default credential chain unless `region` or `profile` says otherwise.

A `property-file` reads only the file. Unlike ordinary `.env` tooling, the process environment never overrides it or fills a missing key, and the file has no `${OTHER}` interpolation. A missing file or key is an error. The last definition of a key wins. The file accepts an optional leading `export `, `#` and `!` comments, and matching quotes around a value.

`validate-config` resolves every secret, AWS ones included. See [Secrets](configuration-general.md#secrets) for security guidance.

## Retry

`retry` says when and how a failed request repeats. It holds a base policy, plus per-status and transport-error rules. A rule inherits every field it does not state from the base policy.

| Field | Default | Meaning |
| --- | --- | --- |
| `retry` | `true` | Whether to retry at all. In an `on-status` or `on-transport-error` rule, it switches one status off, `500: {retry: false}`, or back on. At the base, `false` turns off every retry a rule does not switch back on, the default statuses and transport errors included; `true` retries nothing beyond the listed statuses. |
| `max-retries` | `3` | Attempts after the first, from 0 to 100. |
| `initial-delay` | `1` second | Wait before the first retry. |
| `maximum-delay` | `30` seconds | Ceiling on a computed delay. A wait the server states is not clamped to it. |
| `maximum-total-retry-seconds` | `300` seconds | Time budget across all retries. A wait that would exceed it gives up instead. |
| `exponential-back-off` | `true` | Double the delay each attempt. |
| `incremental-delay` | none | Add this much to the delay each attempt. Wins over `exponential-back-off`. |
| `honor-retry-after` | `true` | Let a wait the server states replace the computed delay. |
| `on-status` | none | Rules keyed by an exact status (`504`) or a class (`5xx`). |
| `on-transport-error` | retried | A rule for a failure before any status arrived: a refused connection, a DNS failure, a TLS handshake error. |
| `use-default-statuses` | `true` | Whether 408, 429, 500, 502, 503, and 504 retry without being listed. |

Delays take a [duration](#units).

### Choosing the rule

For a failed status, the first match wins:

1. An exact code in `on-status`, such as `503`.
2. A class in `on-status`, such as `5xx`.
3. A default status (408, 429, 500, 502, 503, 504), retried under the base policy, while `use-default-statuses` is true and the base does not say `retry: false`.

Any other status does not retry. A 401 or 404 fails at once, so a wrong token or a missing artifact shows up without a wait. A status listed in `on-status` retries unless its rule, or the base, says `retry: false`.

A `5xx` rule therefore covers 500, 502, 503, and 504 as well, and `5xx: {retry: false}` stops them. Set `use-default-statuses: false` to list exactly which statuses retry, for a server whose codes do not follow the HTTP registry.

### Stated waits

With `honor-retry-after`, the tool reads the wait from `Retry-After`, then `RateLimit-Reset` (seconds), then `X-RateLimit-Reset` (epoch seconds) when `X-RateLimit-Remaining` is 0. A stated wait past `maximum-total-retry-seconds` gives up, and the error names when to retry. GitHub reports an exhausted limit as 403, which retries only where `on-status` lists it.

### Merging with the server kind

A server kind's template may set retry rules, such as Maven Central's `429: {honor-retry-after: true}`. The server's `retry` merges over them: an `on-status` rule adds a status, or replaces the kind's rule for the same status.

### Example

Wait out a restarting gateway, keep everything else brisk, and never retry a 500:

```yaml
retry:
  max-retries: 3
  initial-delay: 1 sec
  on-status:
    504:
      max-retries: 10
      initial-delay: 30 sec
      maximum-delay: 5 min
      maximum-total-retry-seconds: 1 hr
    500:
      retry: false
```

## Server values

`values` passes settings to the server kind's templates. Each kind declares the values it accepts; an unknown value is an error. These host values are shared across kinds:

| Value | Meaning | Server kinds |
| --- | --- | --- |
| `connect-timeout` | How long to wait for a connection. | every kind except `local-directory` |
| `request-timeout` | How long to wait for a whole request. | every kind except `local-directory` |
| `maximum-concurrent-downloads` | The most downloads from this server at once, 1 to 100. | every kind except `local-directory` and `maven-central`, which stays at 1 |
| `maximum-concurrent-uploads` | The most uploads to this server at once, 1 to 100. | `nexus3`, `artifactory-pro`, `artifactory-oss`, and `artifact-keeper` |

Timeouts take a [duration](#units). A value left out keeps the host's default.

The concurrency caps count every request to the server at once, from every repository on it: each read (`GET` or `HEAD`) takes a download slot and each write an upload slot, held through the request's retries. Left out, a server has no cap of its own.

**Timeouts not yet applied.** The configuration accepts and validates `connect-timeout` and `request-timeout`, but every request uses a 30 second connect timeout and a 300 second request timeout. See *Configured but not applied* in [TODO.md](../TODO.md).

```yaml
values:
  connect-timeout: 30
  request-timeout: 5 min
  maximum-concurrent-downloads: 8
  maximum-concurrent-uploads: 2
```

Kind-specific server values, such as `local-directory`'s `symlinks`, live in that kind's guide.

## Repositories

A repository is one repository on a server. Its alias names the source, target, and enumerator it generates, which is what `--from` and `--to` take.

Declare it under its server, or in the top-level `repositories` collection naming its server. The second form lets a repository live in another file.

```yaml
servers:
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    repositories:
      nexus-maven:
        name: maven-releases
        kind: maven2
        access: read

repositories:
  nexus-npm:
    server: nexus
    kind: npm
```

| Field | Required | Meaning |
| --- | --- | --- |
| `kind` | yes | The repository kind, as its server technology names it: `maven2` on Nexus, `maven` on Artifactory. Each server guide lists its kinds. |
| `name` | no | The repository's name on the server. Absent means the alias. |
| `access` | no | `read`, `write`, or `read-write`. See [Access](#access). |
| `values` | no | Settings the repository template reads, laid over the server's `values`. |
| `source`, `target`, `enumerator` | no | Settings deep-merged over what the template generates. See [Overrides](#overrides). |
| `server` | top-level only | The server alias. Required in the top-level collection, and forbidden under a server's own `repositories`. |

### Access

`access` picks what the repository generates:

| `access` | Generates |
| --- | --- |
| `read` | source and enumerator |
| `write` | target |
| `read-write` | source, target, and enumerator |
| absent | everything the server kind permits and its template provides |

A [public server](configuration-public.md) permits `read` only. Asking for more than the kind permits is an error.

### Overrides

The `source`, `target`, and `enumerator` blocks deep-merge over the generated entries, the user winning. Mappings merge by key; anything else, a list included, is replaced whole. Each block takes the fields of the matching [low-level entry](configuration-low-level.md).

```yaml
repositories:
  central-mirror:
    server: nexus
    kind: maven2
    source:
      dependencies: runtime
      minimum-publish-time: 7 days
      options:
        checksums: [sha256, sha1]
```

The settings below are the ones most often overridden.

#### Dependencies

`source.dependencies` says which dependencies `copy` and `inspect` follow when `--dependencies` is absent or `default`. It takes the flag's syntax: dependency kinds joined with `+`, or `all`, plus `shallow` for the first level only, or `none`. Absent means `none`, so a copy with neither this key nor `--dependencies` copies only what it was asked for. Every walk logs at `info`, shown by `--verbose`, which dependencies it follows and what decided it.

| Ecosystem | Dependency kinds |
| --- | --- |
| Maven | `runtime`, `dev`, `test`, `optional`, `build` |
| npm | `runtime`, `dev`, `optional`, `peer` |
| PyPI | `runtime`, `optional` |
| raw | none |

Asking for a kind the ecosystem lacks is an error. Maven's `build` (parent POMs and imported BOMs) is followed whenever any dependency is. See the repository type guides for how each maps onto its ecosystem.

**A kind is all or nothing.** There is no way to follow only some of a kind, such as the optional dependencies for Windows, or one named extra. Conditions written into a package are not evaluated:

| Ecosystem | Condition | What the tool does |
| --- | --- | --- |
| PyPI | `extra == "name"` marker | The dependency is `optional`, whichever extra names it. |
| PyPI | Any other marker, such as `sys_platform == "win32"` or `python_version < "3.10"` | Ignored: the dependency is `runtime` and followed on every platform. |
| npm | `optionalDependencies`, and peers marked optional in `peerDependenciesMeta` | `optional`; a package's `os` and `cpu` fields do not narrow them, so every platform's binary package is followed. |
| Maven | `<optional>true</optional>` | `optional`. |
| Maven | A profile that changes dependencies, such as one activated by operating system | Never activated. The artifact is reported as `pom-profile-unsupported` and its dependencies are not followed further. |

A walk therefore copies a superset of what any one platform installs. To leave out what you do not want, name the artifacts with an [omit](#omit) rule.

#### Publish time

`source.minimum-publish-time` refuses an artifact published more recently than this [duration](#units), reported as `publish-too-recent`. It keeps a freshly published, possibly malicious, release out until the ecosystem has had time to notice.

`source.unknown-publish-time` decides what happens when the repository reports no publish time and a window is set: `refuse` (the default) or `allow`. It overrides `setup.unknown-publish-time`. Use `allow` only for a repository known not to report publish times.

#### Omit

`omit` (on a source, target, or enumerator) leaves files or whole artifacts out, on top of the ecosystem's built-in omissions (checksum sidecars, and for Maven `maven-metadata.xml` and `_remote.repositories`).

```yaml
source:
  omit:
    - files: "*.sha256"                              # every artifact
    - purl: "pkg:maven/org.example/internal-*"       # whole artifacts
    - purl: "pkg:maven/org.example/lib@[1.0,1.2)"    # both
      files: "*-javadoc.jar"
```

`purl` is a glob over the name, optionally with `@` and a version range in the ecosystem's syntax. `files` is a file name glob with `*` and `?`.

| On | Effect |
| --- | --- |
| a source | An omitted file is never fetched; an omitted artifact never resolves. |
| an enumerator | It is not recorded. |
| a target | It is fetched and verified, but never uploaded, for a target that refuses a repository's own checksum files. |

An omitted file reports `file-omitted` (ignored by default) and an omitted artifact `artifact-omitted` (a warning). Rules only omit more; nothing restores a built-in omission.

#### Cache

A source or enumerator takes its own cache limits, laid over the `setup` defaults described in [Cache](configuration-general.md#cache).

| Field | Meaning |
| --- | --- |
| `cache-retention` | How long a cached file stays after its last use. A [lifetime](#units); `forever` lifts a `setup` limit. |
| `cache-freshness` | A list of `{files, fresh-for}` rules: how long after its fetch a cached file matching `files` may be used. Tried before `setup.cache-freshness` and the built-in rules. Setting it replaces any rules the server kind supplies. |
| `cache-size` | The most this repository's cache folder may hold, such as `5 GiB`, within `setup.cache-size`. |

```yaml
source:
  cache-freshness:
    - files: "maven-metadata.xml*"
      fresh-for: 15 minutes
```

### Shared repository values

Several repository kinds accept the same `values`. The kind's guide says which, and with what default.

| Value | Meaning |
| --- | --- |
| `mapping` | How raw paths become artifacts: `directory`, `as-is`, or `name-version-file`. See [Mapping](configuration-raw.md#mapping). |
| `overwrite-guard` | Who keeps a written path from being replaced. `server` relies on the server refusing a rewrite; `check` compares what the target holds before writing, one request per file. |
| `max-listing-rows` | The most rows one paged listing reads before giving up, a guard against a server that never stops paging. Raise it for a repository holding years of builds. |
| `last-download` | Where last-download times come from: `unknown`, or `stats`, at one request per file. |
| `legacy-dists` | PyPI only. See [Legacy distributions](configuration-pypi.md#legacy-distributions). |
| `anonymous` | Artifactory OSS only. See [Enumerating anonymously](configuration-artifactory.md#enumerating-anonymously). |

## Units

| Type | Form | Examples |
| --- | --- | --- |
| Duration | A number of seconds, or an integer and a unit: `ms`, `sec`, `min`, `hr`, `day`, singular or plural, spelled out or not. `_` separates digits. Up to one year. | `30`, `500 ms`, `5 min`, `24 hours`, `1_000 seconds` |
| Lifetime | A duration, or `forever`. | `30 days`, `forever` |
| Byte size | A count of bytes, or an integer and a unit: `b`, `kb`, `kib` or `k`, `mb`, `mib` or `m`, `gb`, `gib` or `g`. `kb` is 1000 bytes, `kib` 1024. | `1048576`, `50 MiB`, `20 GiB` |
