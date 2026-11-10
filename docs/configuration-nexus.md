# Nexus

Server kind `nexus3` covers [Sonatype Nexus Repository 3](https://help.sonatype.com/en/sonatype-nexus-repository.html), Community and Pro. The tool reads each repository through its format's protocol and through the [Nexus REST API](https://help.sonatype.com/en/rest-apis.html), which adds the digests, sizes, and publish times the server computed. It writes through each format's own upload protocol.

## Server

```yaml
servers:
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: basic
      username: { kind: env, name: NEXUS_USER }
      password: { kind: env, name: NEXUS_PASSWORD }
```

- `url` is the server root, not a repository url. Repositories live under `repository/{name}`; the REST API sits at the root.
- `authentication` is usually a `basic` login. See [Authentication](configuration-server.md#authentication).
- `retry` and the host `values` (`connect-timeout`, `request-timeout`, `maximum-concurrent-downloads`, `maximum-concurrent-uploads`) follow [Shared settings](configuration-server.md#server-values). The kind adds no retry rules of its own.

A repository without anonymous access answers 401 to a read without credentials, so configure them even for a read-only repository.

## Repositories

| `kind` | Format | Guide |
| --- | --- | --- |
| `maven2` | Maven 2 | [Maven](configuration-maven2.md) |
| `npm` | npm | [npm](configuration-npm.md) |
| `pypi` | PyPI | [PyPI](configuration-pypi.md) |
| `raw` | raw, or any format read as files | [Raw](configuration-raw.md) |

Each supports `access: read`, `write`, or `read-write`. See [Repositories](configuration-server.md#repositories) for `name`, `access`, and override blocks.

```yaml
servers:
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    repositories:
      maven-releases:
        kind: maven2
      npm-hosted:
        kind: npm
        access: write
      pypi-hosted:
        kind: pypi
        values:
          legacy-dists: skip
      tools:
        kind: raw
        values:
          mapping: name-version-file
```

### Repository values

| Value | Kinds | Default | Meaning |
| --- | --- | --- | --- |
| `max-listing-rows` | all | `10000` | See [Shared repository values](configuration-server.md#shared-repository-values). |
| `legacy-dists` | `pypi` | `error` | See [Legacy distributions](configuration-pypi.md#legacy-distributions). |
| `mapping` | `raw` | `directory` | See [Mapping](configuration-raw.md#mapping). |
| `overwrite-guard` | `raw` | `server` | Set `check` for a repository with `writePolicy: ALLOW`. See [Overwrite guard](configuration-raw.md#overwrite-guard). |
| `upload-group-size` | `raw` | `50 MiB` | See [Raw repository values](configuration-raw.md#repository-values). |

## Server behavior to know

Measured against Nexus 3.96; see [server-behaviors.md](contributors/server-behaviors.md#nexus).

- **Maven metadata is not rebuilt on upload.** A version copied into a hosted Maven repository does not resolve by range or `LATEST` until `maven-metadata.xml` lists it, and Nexus generates no checksum sidecars. The `maven2` kind therefore writes both: `metadata: merge`, and the default `checksums`.
- **A rewrite is refused** under `writePolicy: ALLOW_ONCE` (400), which the default `overwrite-guard: server` relies on. Under `ALLOW`, Nexus replaces silently; use `check`.
- **A PyPI component holds two assets**, the wheel and its PEP 658 `.whl.metadata`.
- **A raw write to another format** uses one PUT per file. A Maven repository accepts Maven-layout paths only; npm and PyPI repositories refuse.

## Low-level details

The server generates one [host](configuration-low-level.md#hosts) named for its alias, carrying `url`, `authentication`, `retry`, and the host values. Each repository generates:

| `kind` | [Source](configuration-low-level.md#source-kinds) | [Target](configuration-low-level.md#target-kinds) | [Enumerator](configuration-low-level.md#enumerator-kinds) |
| --- | --- | --- | --- |
| `maven2` | `nexus`, `ecosystem: maven` | `maven` at `repository/{name}`, `metadata: merge` | `nexus`, `ecosystem: maven` |
| `npm` | `nexus`, `ecosystem: npm` | `npm` at `repository/{name}` | `nexus`, `ecosystem: npm` |
| `pypi` | `nexus`, `ecosystem: pypi` | `pypi` at `repository/{name}`, with `legacy-dists` | `nexus`, `ecosystem: pypi` |
| `raw` | `nexus`, `ecosystem: raw`, with `mapping` | `nexus-raw`, with `mapping`, `overwrite-guard`, `upload-group-size` | `nexus`, `ecosystem: raw`, with `mapping` |

Every source and enumerator sets `options.repository` to the repository's `name`; sources also pass `max-listing-rows`. The templates live in [server-kinds/nexus3/](../server-kinds/nexus3/).
