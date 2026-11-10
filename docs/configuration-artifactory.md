# Artifactory

Two server kinds cover [JFrog Artifactory](https://docs.jfrog.com/artifactory/docs/repository-management-overview): `artifactory-pro` for licensed editions and `artifactory-oss` for the open source edition. The tool reads each repository through its format's protocol and the storage API, which adds the checksums, sizes, and times the server recorded. It enumerates through the [Artifactory Query Language](https://docs.jfrog.com/artifactory/docs/artifactory-query-language) (AQL).

## Choosing the kind

| | `artifactory-pro` | `artifactory-oss` |
| --- | --- | --- |
| Enumeration | Sorted AQL pages. | AQL paged by upload-time window, because OSS refuses sorted AQL. |
| Maven redeploy | Left to the server. | `overwrite-guard: check`, because OSS as admin overwrites a redeploy and reports success. |
| `anonymous` value | not accepted | accepted |

Use `artifactory-oss` for an OSS server: `artifactory-pro` enumeration fails there.

## Server

```yaml
servers:
  artifactory:
    kind: artifactory-pro
    url: https://artifactory.example.com/artifactory/
    authentication:
      kind: bearer
      token: { kind: env, name: ARTIFACTORY_TOKEN }
```

- `url` ends in `/artifactory/`. Repositories live under `{name}`.
- `retry` and the host `values` (`connect-timeout`, `request-timeout`, `maximum-concurrent-downloads`, `maximum-concurrent-uploads`) follow [Shared settings](configuration-server.md#server-values). The kinds add no retry rules of their own.

### Authentication

**Enumeration needs credentials**, even on a repository that allows anonymous reads: Artifactory refuses AQL to anonymous users. `validate-config` reports a server without `authentication`. Each form below works with an access token; see [Authentication](configuration-server.md#authentication).

Access token as a bearer token:

```yaml
authentication:
  kind: bearer
  token: { kind: env, name: ARTIFACTORY_TOKEN }
```

Access token as the password of a basic login:

```yaml
authentication:
  kind: basic
  username: { kind: env, name: ARTIFACTORY_USER }
  password: { kind: env, name: ARTIFACTORY_TOKEN }
```

API key, which JFrog deprecated and newer releases refuse:

```yaml
authentication:
  kind: bearer
  token: { kind: env, name: ARTIFACTORY_API_KEY }
  header: X-JFrog-Art-Api
  prefix: ""
```

### Enumerating anonymously

On `artifactory-oss`, the repository value `anonymous: attempt` sends AQL without credentials, for a release that allows anonymous AQL. Absent, a server without `authentication` is refused before the walk. Without either, enumerate through the format's own protocol with a hand-written [enumerator](configuration-low-level.md#enumerator-kinds), such as `maven-html-index`.

## Repositories

| `kind` | Format | Access | Guide |
| --- | --- | --- | --- |
| `maven` | Maven 2 | read-write | [Maven](configuration-maven2.md) |
| `generic` | raw | read-write | [Raw](configuration-raw.md) |
| `ivy` | Ivy, read as raw files | read only | [Raw](configuration-raw.md) |

The built-in kinds have no npm or PyPI repository kind. See [Repositories](configuration-server.md#repositories) for `name`, `access`, and override blocks.

```yaml
servers:
  artifactory:
    kind: artifactory-oss
    url: https://artifactory.example.com/artifactory/
    authentication:
      kind: bearer
      token: { kind: env, name: ARTIFACTORY_TOKEN }
    repositories:
      libs-release:
        kind: maven
      tools:
        kind: generic
        values:
          mapping: name-version-file
      ivy-legacy:
        kind: ivy
```

### Repository values

| Value | Kinds | Default | Meaning |
| --- | --- | --- | --- |
| `mapping` | `generic`, `ivy` | `directory`; `name-version-file` on `ivy` | See [Mapping](configuration-raw.md#mapping). |
| `overwrite-guard` | `generic` | `check` | Artifactory replaces a path silently for an account allowed to overwrite. See [Overwrite guard](configuration-raw.md#overwrite-guard). |
| `anonymous` | OSS `maven`, `generic`, `ivy` | refuse | See [Enumerating anonymously](#enumerating-anonymously). |

## Server behavior to know

Measured against Artifactory OSS 7.161; see [server-behaviors.md](contributors/server-behaviors.md#artifactory).

- **`.sha1` and `.md5` exist only when the uploader sent them.** The `maven` target writes them by default.
- **`Last-Modified` is the uploader's claim**, not the server's upload time, so a Maven publish time read from it is only as good as whoever uploaded.
- **A redeploy keeps `created`** and moves `lastModified`.
- **OSS lists a folder's files one request per file**, since its deep listing is Pro only.
- **Maven metadata** is generated once a version's POM is uploaded.

With `--db`, a `find` after a complete walk lists only what changed since that walk started, filtered on Artifactory's `modified` time.

## Low-level details

The server generates one [host](configuration-low-level.md#hosts) named for its alias, carrying `url`, `authentication`, `retry`, and the host values. Each repository generates:

| `kind` | [Source](configuration-low-level.md#source-kinds) | [Target](configuration-low-level.md#target-kinds) | [Enumerator](configuration-low-level.md#enumerator-kinds) |
| --- | --- | --- | --- |
| `maven` | `artifactory`, `ecosystem: maven` | `maven` at `{name}`; `overwrite-guard: check` on OSS | `artifactory` (Pro) or `artifactory-oss`, `ecosystem: maven` |
| `generic` | `artifactory`, `ecosystem: raw`, with `mapping` | `artifactory-generic`, with `mapping`, `overwrite-guard` | `artifactory` or `artifactory-oss`, `ecosystem: raw`, with `mapping` |
| `ivy` | `artifactory`, `ecosystem: raw`, with `mapping` | none | `artifactory` or `artifactory-oss`, `ecosystem: raw`, with `mapping` |

Every entry sets `options.repository` to the repository's `name`; OSS enumerators also pass `anonymous`. The templates live in [server-kinds/artifactory-pro/](../server-kinds/artifactory-pro/) and [server-kinds/artifactory-oss/](../server-kinds/artifactory-oss/).
