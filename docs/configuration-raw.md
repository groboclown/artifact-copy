# Raw Repositories

A raw repository stores plain files at paths, with no package format: no metadata index, no dependency declarations, and no version convention. Products name it differently: Nexus calls it raw, Artifactory and Artifact Keeper generic. The tool also reads any other repository as raw files, and an Artifactory Ivy repository as raw only.

Because the files carry no artifact identity, a [mapping](#mapping) says how paths become artifacts.

## References

No formal specification exists. The closest definitions are each product's own:

- [Nexus raw repositories](https://help.sonatype.com/en/raw-repositories.html).
- [Artifactory repository management](https://docs.jfrog.com/artifactory/docs/repository-management-overview), which covers generic repositories.
- [Apache Ivy files](https://ant.apache.org/ivy/history/latest-milestone/ivyfile.html), for the Ivy layout. The tool reads `ivy.xml` as a file, never for dependencies.

## Repository kind by server

| Server kind | Repository `kind` | Access | Guide |
| --- | --- | --- | --- |
| `nexus3` | `raw` | read-write | [Nexus](configuration-nexus.md) |
| `artifactory-pro`, `artifactory-oss` | `generic` | read-write | [Artifactory](configuration-artifactory.md) |
| `artifactory-pro`, `artifactory-oss` | `ivy` | read only | [Artifactory](configuration-artifactory.md) |
| `artifact-keeper` | `generic` | read-write | [Artifact Keeper](configuration-artifact-keeper.md) |
| `local-directory` | `generic` | read-write | [Local Directory](configuration-local-directory.md) |

On Nexus and Artifact Keeper, a `raw` or `generic` repository entry may point at a repository of any format, reading it as plain files. Writing that way issues one plain upload per file, which the format may refuse: Nexus accepts a Maven-layout path in a Maven repository and refuses npm, PyPI, and other paths.

## Mapping

`mapping` (a repository value) decides how a path becomes an artifact.

| `mapping` | Artifact | Version | `tools/acme/cli/1.2.0/cli.tar.gz` |
| --- | --- | --- | --- |
| `directory` | the directory holding the file | none | artifact `tools/acme/cli/1.2.0`, file `cli.tar.gz` |
| `as-is` | the file itself | none | artifact `tools/acme/cli/1.2.0/cli.tar.gz` |
| `name-version-file` | everything before the last two segments | the second to last segment | artifact `tools/acme/cli`, version `1.2.0`, file `cli.tar.gz` |

- `directory` is the default, except on `ivy`. Each directory is its own artifact: `a/b` and `a/b/c` are two. A file at the repository root is its own artifact.
- `as-is` suits a repository of unrelated files, such as a backup dump.
- `name-version-file` is the default on `ivy`. A path with fewer than three segments does not fit and is reported. Only this mapping has versions, so only it accepts a [version handler](#versions).

### Requests

A request is a path, or `path@version` under `name-version-file`. The last `@` separates the version.

```text
tools/acme/cli/1.2.0
tools/acme/cli@1.2.0
```

### Versions

Under `name-version-file`, the version is text the publisher chose, so the default refuses to order versions or resolve a range. A `source.version-handler` override names the convention the repository follows: `semver`, `maven`, `pep440`, or `tags` (no ordering).

```yaml
repositories:
  tools:
    server: nexus
    kind: raw
    values:
      mapping: name-version-file
    source:
      version-handler: semver
```

## Repository values

| Value | Kinds | Default | Meaning |
| --- | --- | --- | --- |
| `mapping` | all | `directory`; `name-version-file` on `ivy` | See [Mapping](#mapping). |
| `overwrite-guard` | Nexus `raw` | `server` | See below. |
| | Artifactory `generic` | `check` | |
| | `local-directory` `generic` | `check` | |
| | Artifact Keeper `generic` | `server` | |
| `upload-group-size` | Nexus `raw` | `50 MiB` | The most one upload request carries, as a [byte size](configuration-server.md#units). A larger file goes alone. |
| `max-listing-rows` | Nexus `raw`, Artifact Keeper `generic` | 10000 on Nexus, 20000 on Artifact Keeper | See [Shared repository values](configuration-server.md#shared-repository-values). |
| `last-download` | Artifact Keeper `generic` | `unknown` | See [Shared repository values](configuration-server.md#shared-repository-values). |
| `anonymous` | Artifactory OSS `generic`, `ivy` | refuse | See [Enumerating anonymously](configuration-artifactory.md#enumerating-anonymously). |

### Overwrite guard

`overwrite-guard` decides who keeps a written path from being replaced.

- `server` sends the file and relies on the server refusing a rewrite, then compares what it holds. Right for Nexus under `writePolicy: ALLOW_ONCE`.
- `check` compares what the target holds before writing, one request per file. Different bytes refuse the artifact with nothing written; identical files are skipped. Right for a server that overwrites silently: Nexus under `writePolicy: ALLOW`, Artifactory for an account with overwrite permission, or an Artifact Keeper repository with versioning enabled.

## Dependencies

Raw files declare none, so [dependencies](configuration-server.md#dependencies) do not apply.

## Example

```yaml
servers:
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: bearer
      token: { kind: env, name: NEXUS_TOKEN }
    repositories:
      nexus-tools:
        name: tools
        kind: raw
        values:
          mapping: name-version-file
          overwrite-guard: check
  backup:
    kind: local-directory
    url: file:///srv/backup/
    repositories:
      backup-tools:
        name: tools
        kind: generic
        values:
          mapping: name-version-file
```

```text
artifact-copy find --from=nexus-tools --db=tools.db
artifact-copy copy --from=nexus-tools --to=backup-tools --db=tools.db --from-db
```

## Low-level details

A raw repository generates:

| Server kind | [Source](configuration-low-level.md#source-kinds) | [Target](configuration-low-level.md#target-kinds) | [Enumerator](configuration-low-level.md#enumerator-kinds) |
| --- | --- | --- | --- |
| `nexus3` | `nexus`, `ecosystem: raw` | `nexus-raw` | `nexus`, `ecosystem: raw` |
| `artifactory-pro` | `artifactory`, `ecosystem: raw` | `artifactory-generic` (not for `ivy`) | `artifactory`, `ecosystem: raw` |
| `artifactory-oss` | `artifactory`, `ecosystem: raw` | `artifactory-generic` (not for `ivy`) | `artifactory-oss`, `ecosystem: raw` |
| `artifact-keeper` | `artifact-keeper`, `ecosystem: raw` | `artifact-keeper-generic` | `artifact-keeper`, `ecosystem: raw` |
| `local-directory` | `local-directory` | `local-directory` | `local-directory` |

Each passes `mapping` and the other repository values through as `options`.
