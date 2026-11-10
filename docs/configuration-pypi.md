# PyPI Repositories

References: [Sigstore](https://docs.sigstore.dev/).

A PyPI-style repository, or Python package index, serves Python distributions: wheels and source distributions (sdists). Its simple API lists each project's files with their hashes; a file's core metadata, including its dependencies, is served beside it or read from inside it. Uploads use a separate form-post API.

## References

- [Simple repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/): the living specification, built from [PEP 503](https://peps.python.org/pep-0503/) (HTML), [PEP 691](https://peps.python.org/pep-0691/) (JSON), and [PEP 658](https://peps.python.org/pep-0658/) (metadata files).
- [Version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/): version ordering and ranges, from [PEP 440](https://peps.python.org/pep-0440/).
- [Index hosted attestations](https://packaging.python.org/en/latest/specifications/index-hosted-attestations/): provenance, from [PEP 740](https://peps.python.org/pep-0740/).
- [PyPI upload API](https://docs.pypi.org/api/upload/): the closest thing to an upload specification.

## Repository kind by server

| Server kind | Repository `kind` | Guide |
| --- | --- | --- |
| `nexus3` | `pypi` | [Nexus](configuration-nexus.md) |
| `artifact-keeper` | `pypi` | [Artifact Keeper](configuration-artifact-keeper.md) |
| `public-pypi.org` | its default repository | [Public repositories](configuration-public.md#pypi) |

The built-in Artifactory kinds have no PyPI repository kind.

## Requests

A request is a PEP 508 requirement: a project name, optional extras, and an optional version specifier.

```text
requests
requests>=2.31,<3
requests[socks]==2.32.3
```

Names are normalized, so `Requests` and `requests` are the same project. Extras do not change the identity; they select which optional dependencies apply. A range or a missing version selects the highest match. Without `--pre-release`, pre-releases and `.dev` versions are skipped.

## Dependencies

| Core metadata | [Kind](configuration-server.md#dependencies) |
| --- | --- |
| `Requires-Dist` | `runtime` |
| `Requires-Dist` with an `extra == "..."` marker | `optional` |

PyPI publishes no development or test dependency distinction.

## Target options

These go in a repository's `target.options` override, except `legacy-dists`, which is a repository value on Nexus and Artifact Keeper.

### Legacy distributions

`legacy-dists` decides what happens to a distribution that is neither a wheel nor an sdist (`.egg`, `.exe`, `.msi`), which pypi.org no longer accepts and an older server may.

| Value | Effect |
| --- | --- |
| `error` | The default. Refuse the artifact before any of it uploads. |
| `skip` | Upload the wheels and sdists, and report each file left behind as `distribution-type-unsupported`. |
| `guess` | Upload it under the file type its extension suggests, and let the server decide. |

```yaml
repositories:
  pypi-hosted:
    server: nexus
    kind: pypi
    values:
      legacy-dists: skip
```

### `attestations`

Whether a file's PEP 740 attestations travel with it.

| Value | Effect |
| --- | --- |
| `forward` | The default. Fetch the provenance the source's index names and send its attestations in the upload. Nexus and Artifact Keeper accept them and keep nothing. |
| `drop` | Send none. |

Attestations are checked against Sigstore's trusted root; see [Sigstore](configuration-general.md#sigstore).

### `upload-path`

Where uploads are posted, relative to the target's `host-path` and defaulting to it. Nexus and Artifact Keeper take uploads at the index root. Set it for an index with a separate upload endpoint. `.` and `..` are refused.

## Example

```yaml
servers:
  pypi-org:
    kind: public-pypi.org
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: basic
      username: { kind: env, name: NEXUS_USER }
      password: { kind: env, name: NEXUS_PASSWORD }
    repositories:
      pypi-hosted:
        kind: pypi
        access: write
```

```text
artifact-copy copy --from=pypi-org --to=pypi-hosted "requests>=2.31,<3"
```

See [Shared settings](configuration-server.md) for [dependencies](configuration-server.md#dependencies), [publish time](configuration-server.md#publish-time), [omit](configuration-server.md#omit), and [cache](configuration-server.md#cache) settings.

## Low-level details

A PyPI repository generates:

| Role | Kind | Notes |
| --- | --- | --- |
| [source](configuration-low-level.md#source-kinds) | `nexus` or `artifact-keeper` with `ecosystem: pypi` on a repository manager; `pypi` on pypi.org | |
| [target](configuration-low-level.md#target-kinds) | `pypi` | `host-path` is `repository/{name}` on Nexus, `pypi/{name}` on Artifact Keeper. `legacy-dists` comes from the repository value. |
| [enumerator](configuration-low-level.md#enumerator-kinds) | the repository manager's own, with `ecosystem: pypi`; `pypi-simple` on pypi.org | |

Cached simple pages and JSON detail documents stay fresh for an hour, and the `pypi-simple` project index a day, unless a [freshness rule](configuration-server.md#cache) says otherwise.
