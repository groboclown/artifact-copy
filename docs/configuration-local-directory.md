# Local Directory

Server kind `local-directory` reads and writes raw files in a directory on this machine, for making a backup of a repository or restoring one. An emulated server answers the tool's requests, so the directory behaves like any other raw repository.

## References

A local directory follows no protocol. Its files are laid out by the repository's [mapping](configuration-raw.md#mapping), the same rules every raw repository follows.

## Server

```yaml
servers:
  backup:
    kind: local-directory
    url: file:///srv/backup/
    values:
      symlinks: within-root
```

- `url` is a `file://` url naming the directory.
- It takes no `authentication` and no `retry`. Its low-level host rejects `tls-verify`, `connect-timeout`, `request-timeout`, `retry`, `authentication`, and `additional-hosts`.

### Symlinks

The server value `symlinks` decides how a symbolic link inside the directory is treated.

| Value | Effect |
| --- | --- |
| `as-file` | The default. Copy the link as a file holding its target text. |
| `follow` | Follow it anywhere. |
| `skip` | Leave it out. |
| `within-root` | Follow it only while it stays inside the directory. |

**Security:** `follow` lets a link inside the directory read any file this process can, and publish it. Prefer `as-file` or `within-root` for a directory you did not create.

## Repositories

| `kind` | Format | Guide |
| --- | --- | --- |
| `generic` | raw | [Raw](configuration-raw.md) |

Each repository is a sub-directory of the server's directory, named by the repository's `name`. A repository named `/` is the directory itself.

```yaml
servers:
  backup:
    kind: local-directory
    url: file:///srv/backup/
    repositories:
      backup-tools:
        name: tools                # /srv/backup/tools
        kind: generic
        values:
          mapping: name-version-file
      backup-all:
        name: /                    # /srv/backup
        kind: generic
```

### Repository values

| Value | Default | Meaning |
| --- | --- | --- |
| `mapping` | `directory` | See [Mapping](configuration-raw.md#mapping). |
| `overwrite-guard` | `check` | `check` compares every file before writing any. A file is never replaced either way. See [Overwrite guard](configuration-raw.md#overwrite-guard). |

Nothing read is ever written to, and a written file is never replaced. See [Repositories](configuration-server.md#repositories) for `name`, `access`, and override blocks.

## Example

Back up a Nexus raw repository, then restore it to another server:

```text
artifact-copy find --from=nexus-tools --db=tools.db
artifact-copy copy --from=nexus-tools --to=backup-tools --db=tools.db --from-db
artifact-copy copy --from=backup-tools --to=keeper-tools tools/acme/cli@1.2.0
```

## Low-level details

The server generates one [host](configuration-low-level.md#hosts) named for its alias, with `url` and `options.symlinks`. Each `generic` repository generates:

| Role | Kind | Options |
| --- | --- | --- |
| [source](configuration-low-level.md#source-kinds) | `local-directory` | `mapping` |
| [target](configuration-low-level.md#target-kinds) | `local-directory` | `mapping`, `overwrite-guard` |
| [enumerator](configuration-low-level.md#enumerator-kinds) | `local-directory` | `mapping` |

Each sets `host-path` to the repository's `name`, except a repository named `/`, which takes none. The enumerator lists files without hashing them. The templates live in [server-kinds/local-directory/](../server-kinds/local-directory/); [local-directory.svg](contributors/local-directory.svg) draws the design.
