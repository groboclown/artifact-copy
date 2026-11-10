# Artifact Keeper

Server kind `artifact-keeper` covers [Artifact Keeper](https://artifactkeeper.com/docs/), an open source, self-hosted artifact registry. The tool reads each repository through its format's protocol and the Artifact Keeper REST API's artifact listing, which adds digests, sizes, and publish times. [artifact-keeper-api.md](contributors/artifact-keeper-api.md) records the endpoints the tool uses.

## Server

```yaml
servers:
  keeper:
    kind: artifact-keeper
    url: https://keeper.example.com/
    authentication:
      kind: bearer
      token: { kind: env, name: KEEPER_TOKEN }
```

- `url` is the server root. Repositories live under `{format}/{name}`, such as `maven/libs`.
- `authentication`, `retry`, and the host `values` (`connect-timeout`, `request-timeout`, `maximum-concurrent-downloads`, `maximum-concurrent-uploads`) follow [Shared settings](configuration-server.md). The kind adds no retry rules of its own.

## Repositories

| `kind` | Format | Guide |
| --- | --- | --- |
| `maven` | Maven 2 | [Maven](configuration-maven2.md) |
| `npm` | npm | [npm](configuration-npm.md) |
| `pypi` | PyPI | [PyPI](configuration-pypi.md) |
| `generic` | raw, or any format read as files | [Raw](configuration-raw.md) |

Each supports `access: read`, `write`, or `read-write`. See [Repositories](configuration-server.md#repositories) for `name`, `access`, and override blocks.

```yaml
servers:
  keeper:
    kind: artifact-keeper
    url: https://keeper.example.com/
    repositories:
      libs:
        kind: maven
        values:
          last-download: stats
      npm-hosted:
        kind: npm
      pypi-hosted:
        kind: pypi
        values:
          legacy-dists: skip
```

### Repository values

| Value | Kinds | Default | Meaning |
| --- | --- | --- | --- |
| `max-listing-rows` | all | `20000` | See [Shared repository values](configuration-server.md#shared-repository-values). |
| `last-download` | all | `unknown` | `stats` records each file's last download in `find` results, at one request per file. Refused with `mode: proxy` or `proxy-cache`. |
| `mode` | all | `hosted` | `proxy` or `proxy-cache` for a Remote (proxy) repository. See [Proxy repositories](#proxy-repositories). |
| `legacy-dists` | `pypi` | `error` | See [Legacy distributions](configuration-pypi.md#legacy-distributions). |
| `mapping` | `generic` | `directory` | See [Mapping](configuration-raw.md#mapping). |
| `overwrite-guard` | `generic` | `server` | See [Overwrite guard](configuration-raw.md#overwrite-guard). `check` for a repository with versioning enabled, unless a copy should replace what it holds. |

## Proxy repositories

An Artifact Keeper **Remote** repository pulls from an upstream and caches what it serves. Read through its format's protocol, it answers with the upstream's versions and files, and fetching one it has not cached pulls it through the upstream. To read **what the repository has cached** instead, set `mode`:

| `mode` | Versions and files | Metadata, dependencies, license | Requests to the upstream |
| --- | --- | --- | --- |
| `hosted` (default) | the protocol's | the protocol's | any the protocol makes |
| `proxy` | the cache's | the protocol's | only for metadata the cache has let expire |
| `proxy-cache` | the cache's | none | none |

```yaml
servers:
  keeper:
    kind: artifact-keeper
    url: https://keeper.example.com/
    repositories:
      pypi-remote:
        kind: pypi
        values:
          mode: proxy-cache
      maven-remote:
        kind: maven
        values:
          mode: proxy
```

- **`proxy`** keeps the protocol for what the files say, so dependencies, licenses, signatures, and PEP 658 metadata are all there, and lets the cache decide which versions exist and which of a version's files to copy. A file the protocol names and the cache does not hold is left out. A version with no cached file is not found.
- **`proxy-cache`** reads the cache alone, through the REST API's artifact listing: versions, files, SHA-256 digests, sizes, and the time each file was cached as its publish time. An artifact has **no dependencies and no license**, so following dependencies reaches no further than the artifacts asked for, and a license policy has no declared license to judge.
- The enumerator walks the cache under either mode. `last-download: stats` is refused, because cached files carry no download statistics.
- Cached files are downloaded through the format's route (`maven/{name}`, `npm/{name}`, `pypi/{name}`), which serves them from the cache and applies the repository's scan-on-proxy policy.
- Point a proxy mode at a **Remote** repository only. A hosted repository's npm and PyPI files are stored in another layout, so a proxy mode finds none of them.
- A **Virtual** repository caches nothing itself: its Remote members do. Configure each Remote member as its own repository.
- A `generic` repository has no protocol, so its source and enumerator read the listing under every mode; `mode` changes nothing for it except that `last-download: stats` is refused.

## Server behavior to know

Measured against Artifact Keeper 1.9; see [server-behaviors.md](contributors/server-behaviors.md#artifact-keeper-2026-10-05).

- **Maven metadata is rebuilt on upload**, so the `maven` target leaves it to the server.
- **A rewrite is refused** with 409, which the default overwrite guard relies on. A `generic` repository with versioning enabled accepts it instead, keeping the old bytes as a revision labeled with the artifact's version (read from the server's source, not measured).
- **npm `dist` is rewritten**: `integrity` becomes the server's own sha256 of the tarball, and `shasum` is dropped.
- **The npm version route** answers only `@scope/name/1.0.0`, not `%2f` or `%40` spellings.
- **A missing repository** answers 404 `Repository not found`.

## Low-level details

The server generates one [host](configuration-low-level.md#hosts) named for its alias, carrying `url`, `authentication`, `retry`, and the host values. Each repository generates:

| `kind` | [Source](configuration-low-level.md#source-kinds) | [Target](configuration-low-level.md#target-kinds) | [Enumerator](configuration-low-level.md#enumerator-kinds) |
| --- | --- | --- | --- |
| `maven` | `artifact-keeper`, `ecosystem: maven` | `maven` at `maven/{name}` | `artifact-keeper`, `ecosystem: maven` |
| `npm` | `artifact-keeper`, `ecosystem: npm` | `npm` at `npm/{name}` | `artifact-keeper`, `ecosystem: npm` |
| `pypi` | `artifact-keeper`, `ecosystem: pypi` | `pypi` at `pypi/{name}`, with `legacy-dists` | `artifact-keeper`, `ecosystem: pypi` |
| `generic` | `artifact-keeper`, `ecosystem: raw`, with `mapping` | `artifact-keeper-generic`, with `mapping` | `artifact-keeper`, `ecosystem: raw`, with `mapping` |

Every source and enumerator sets `options.repository` to the repository's `name`. Sources pass `max-listing-rows`; enumerators pass `last-download`. Both pass `mode` when it is set. The templates live in [server-kinds/artifact-keeper/](../server-kinds/artifact-keeper/).
