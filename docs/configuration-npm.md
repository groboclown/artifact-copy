# npm Registries

An npm registry serves JavaScript packages. Each package has a packument: one JSON document listing every version, its `dist` tarball url and integrity hash, its dependencies, and its dist-tags such as `latest`. The tarball holds the package and its `package.json`.

## References

npm publishes no formal registry specification. The closest are:

- [Registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md): the packument and version documents.
- [package.json](https://docs.npmjs.com/cli/configuring-npm/package-json): dependency fields.
- [node-semver](https://github.com/npm/node-semver): version ordering and range syntax.
- [Registry signatures](https://docs.npmjs.com/about-registry-signatures): the ECDSA signatures checked against [signing keys](configuration-general.md#signing-keys).

## Repository kind by server

| Server kind | Repository `kind` | Guide |
| --- | --- | --- |
| `nexus3` | `npm` | [Nexus](configuration-nexus.md) |
| `artifact-keeper` | `npm` | [Artifact Keeper](configuration-artifact-keeper.md) |
| `npmjs` | its default repository | [Public repositories](configuration-public.md#npm) |

The built-in Artifactory kinds have no npm repository kind.

## Requests

A request is `[@scope/]name[@range]`, with a node-semver range:

```text
lodash
lodash@^4.17.0
@types/node@20.11.5
```

A range or a missing version selects the highest match. Without `--pre-release`, prerelease versions such as `5.0.0-rc.1` are skipped. `--lock=package-lock.json` requests every package the lock file names.

## Dependencies

| `package.json` | [Kind](configuration-server.md#dependencies) |
| --- | --- |
| `dependencies` | `runtime` |
| `devDependencies` | `dev` |
| `optionalDependencies` | `optional` |
| `peerDependencies` | `peer` |

## Target options

These go in a repository's `target.options` override.

### `dist-tags`

Whether a publish sets the package's `latest` tag. npm requires none of these, so the right choice depends on what the mirror is for.

| Value | Effect |
| --- | --- |
| `never` | The default. Send no dist-tags; the target's operator owns them. A package new to the mirror then has no `latest`, so `npm install NAME` fails until someone runs `npm dist-tag`. The failure is visible and one command fixes it. |
| `on-create` | Set `latest` when creating the package, and never move it. Several versions of a new package copied in one run upload concurrently, so the tag lands on whichever went first, possibly the oldest. |
| `highest` | Keep `latest` on the highest version the mirror holds. This overrules a publisher who pinned `latest` lower after a bad release. |

### `registry-fields`

Whether a copied manifest keeps the keys its origin registry added (`_npmUser`, `_npmOperationalInternal`, `_resolved`, `_from`, `_integrity`, `_shasum`, `_rev`, `_attachments`): `drop` (the default) or `keep`.

The published manifest is the origin's version document when the source serves one, else the tarball's `package.json`.

## Example

```yaml
servers:
  npmjs:
    kind: npmjs
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: bearer
      token: { kind: env, name: NEXUS_TOKEN }
    repositories:
      npm-hosted:
        kind: npm
        access: write
        target:
          options:
            dist-tags: on-create
```

```text
artifact-copy copy --from=npmjs --to=npm-hosted lodash@^4.17.0
```

See [Shared settings](configuration-server.md) for [dependencies](configuration-server.md#dependencies), [publish time](configuration-server.md#publish-time), [omit](configuration-server.md#omit), and [cache](configuration-server.md#cache) settings.

## Low-level details

An npm repository generates:

| Role | Kind | Notes |
| --- | --- | --- |
| [source](configuration-low-level.md#source-kinds) | `nexus` or `artifact-keeper` with `ecosystem: npm` on a repository manager; `npm` on npmjs | |
| [target](configuration-low-level.md#target-kinds) | `npm` | `host-path` is `repository/{name}` on Nexus, `npm/{name}` on Artifact Keeper. |
| [enumerator](configuration-low-level.md#enumerator-kinds) | the repository manager's own, with `ecosystem: npm` | npmjs has none; a hand-written `npm-replicate` enumerator walks a replication feed. |

Cached packuments stay fresh for an hour unless a [freshness rule](configuration-server.md#cache) says otherwise.
