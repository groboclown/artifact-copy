# Low-Level Configuration

The `servers` and `repositories` sections generate four kinds of low-level entries: hosts, sources, targets, and enumerators. Most configurations never write these directly. Read this guide to understand what a server kind generates, to tune a generated entry through a repository's [override blocks](configuration-server.md#overrides), or to describe a repository no server kind covers.

The [schema](../schema/config.schema.json) is the authority.

## Concepts

```text
servers:                          generated
  nexus:  ----------------------> hosts.nexus            (url, credentials, retry)
    repositories:
      libs:  -------------------> sources.libs           (resolves and reads artifacts)
                             +--> targets.libs           (writes artifacts)
                             +--> enumerators.libs       (lists what the repository holds)
```

| Entry | Answers | Used by |
| --- | --- | --- |
| [Host](#hosts) | Where a server is, and how to talk to it: url, TLS, credentials, retry, connection limits, policy overrides. | every other entry |
| [Source](#sources) | What versions an artifact has, which files a version holds, their checksums, license, and publish time; and the bytes. | `--from` on `copy` and `inspect` |
| [Target](#targets) | Whether a repository holds an artifact, and how to publish one. | `--to` on `copy` |
| [Enumerator](#enumerators) | Every artifact a repository holds: a catalog walk, not a resolution. | `--from` on `find` |

Resolution and enumeration are separate because a repository can do one and not the other: Maven Central answers the Maven protocol and must not be enumerated.

Each server generates one host, named for its alias. Each repository generates the source, target, and enumerator its `access` and the kind's template allow, named for the repository's alias. `--source`, `--target`, and `--enumerator` name a low-level entry directly.

## Generated and hand-written entries

Hand-written `hosts`, `sources`, `targets`, and `enumerators` sit beside generated ones. A hand-written entry with a generated entry's name is an error, unless it sets `override-template: true`, in which case it replaces the generated entry whole.

Prefer a repository's `source`, `target`, and `enumerator` override blocks: they deep-merge over the generated entry and keep the rest. Use `override-template` only to replace an entry outright.

## Hosts

```yaml
hosts:
  internal:
    url: https://nexus.example.com/
    authentication:
      kind: bearer
      token: { kind: env, name: NEXUS_TOKEN }
    retry:
      on-status:
        500: { retry: false }
```

| Field | Meaning |
| --- | --- |
| `url` | Required. The root every entry on this host joins its `host-path` onto. |
| `tls-verify` | Default `true`. See [Transport security](configuration-general.md#transport-security). |
| `insecure-transport` | Default `false`. Required for an `http://` url, mirror, or keyserver. See [Transport security](configuration-general.md#transport-security). |
| `connect-timeout`, `request-timeout` | [Durations](configuration-server.md#units). Not yet applied; see [Server values](configuration-server.md#server-values). |
| `maximum-concurrent-downloads`, `maximum-concurrent-uploads` | 1 to 100. The most reads and writes in flight to this host at once, across every entry on it. Left out, no cap. See [Server values](configuration-server.md#server-values). |
| `retry` | See [Retry](configuration-server.md#retry). |
| `authentication` | See [Authentication](configuration-server.md#authentication). |
| `additional-hosts` | See [Additional hosts](#additional-hosts). |
| `mirrors` | See [Mirrors](#mirrors). |
| `license-policy`, `security-policy`, `quarantine-policy`, `signing-policy` | Override the `setup` policy files for this host's artifacts. See [Policy files](configuration-general.md#policy-files). |
| `signing-keys` | Names from the top-level `signing-keys`. Replaces the registry's key endpoint for this host. See [Signing keys](configuration-general.md#signing-keys). |
| `keyservers` | Overrides `setup.keyservers` for this host. |
| `options` | Only a `file://` host takes any: `symlinks`. See [Local Directory](configuration-local-directory.md#symlinks). |
| `override-template` | See [Generated and hand-written entries](#generated-and-hand-written-entries). |

A server's `url`, `authentication`, `retry`, and host `values` become its host's fields.

### Additional hosts

`additional-hosts` lists other hosts this host's reads may reach by a link or a redirect: pypi.org lists files on `files.pythonhosted.org`, and github.com redirects archives to `codeload.github.com`. A read never leaves the host otherwise. Nothing is ever written to an additional host, and the list is not transitive.

| Field | Meaning |
| --- | --- |
| `hostname` | A bare hostname, reached over https with the default TLS setting and retry, and no credentials. |
| `host` | A `hosts` entry, reached with its own url, TLS setting, retry, and credentials. |
| `inherit` | Use the owning host's TLS setting and retry instead. Never its credentials. |
| `inherit-parent-authentication` | Send the owning host's credentials too. |
| `authentication` | Credentials for this host alone. |

Each entry takes exactly one of `hostname` and `host`, and at most one of `inherit-parent-authentication` and `authentication`.

A read through a `host` entry counts against that host's `maximum-concurrent-downloads`, shared with the host's own entries. A `hostname` entry has no cap.

### Mirrors

`mirrors` lists copies of this host, asked first for each file read. A read under the host's url goes to each mirror in order, with the url rewritten, then to the host itself. A mirror that lacks the file, is unreachable, or redirects hands the read to the next; any other failure, such as a digest mismatch, is the answer. URLs, caches, and proxies still see the host's own urls.

```yaml
hosts:
  central:
    url: https://repo1.maven.org/maven2/
    mirrors:
      - url: https://maven-central.storage-download.googleapis.com/maven2/
        skip: ["*/"]
```

| Field | Meaning |
| --- | --- |
| `url` | Required. Replaces the host's url: `.../maven2/a/b/1/b-1.jar` becomes `https://maven-central.storage-download.googleapis.com/maven2/a/b/1/b-1.jar`. |
| `skip` | Paths below the host's url never asked of this mirror, with `*` and `?` wildcards. `*/` sends directory indexes straight to the host. |

Mirrors are anonymous: the host's credentials never reach them. They use the host's TLS setting and retry, but not its concurrency cap: a mirror read takes no slot. Writes never go to a mirror. A `HEAD` request goes to one only when it asks whether a file exists; a `HEAD` read for its headers stays with the host, because a mirror's `Last-Modified` is when it copied the file, not when it was published. A `file://` host takes no mirrors.

## Sources

```yaml
sources:
  central:
    kind: maven
    host: central
    dependencies: runtime
    minimum-publish-time: 3 days
```

| Field | Meaning |
| --- | --- |
| `kind` | The implementation. See [Source kinds](#source-kinds). |
| `host` | The host it reads from. Required, except for a proxy, which forbids it. |
| `host-path` | Where under the host's url the repository lives, such as `repository/npm-group`. The source cannot read outside it. `.` and `..` are refused. |
| `options` | Settings the kind reads. Two keys mean the same everywhere: `repository` (which repository on the host) and `ecosystem` (`maven`, `npm`, `pypi`, or `raw`). |
| `dependencies` | See [Dependencies](configuration-server.md#dependencies). |
| `minimum-publish-time`, `unknown-publish-time` | See [Publish time](configuration-server.md#publish-time). |
| `omit` | See [Omit](configuration-server.md#omit). |
| `cache-retention`, `cache-freshness`, `cache-size` | See [Cache](configuration-server.md#cache). |
| `version-handler` | `maven`, `pep440`, `semver`, or `tags`. Only for a kind with no ecosystem ordering: `github`, or a raw source with `mapping: name-version-file`. Refused elsewhere. |
| `names` | `github` only: rules mapping a repository name and tag pattern to an artifact name and version, such as tag `v*` to version `*`. |
| `proxy-to` | A proxy's upstreams. See [Proxies](#proxies). |
| `enumerator` | Accepted and checked, but not yet used. |

### Source kinds

| Kind | Reads | Options |
| --- | --- | --- |
| `maven` | The Maven repository protocol on any server. | `file-listing`, `version-discovery`, `checksums`. See [Maven options](configuration-maven2.md#source-options). |
| `npm` | The npm registry protocol. | none |
| `pypi` | The PyPI simple and JSON APIs. | none |
| `nexus` | A Nexus 3 repository: the ecosystem protocol plus the REST API's digests, sizes, and publish times. | `repository`, `ecosystem`, `max-listing-rows` (default 10000), and for `ecosystem: raw`, `mapping`. |
| `artifactory` | An Artifactory repository, with the storage API. | `repository`, `ecosystem`, and for `raw`, `mapping`. |
| `artifact-keeper` | An Artifact Keeper repository, with its artifact listing. | `repository`, `ecosystem`, `max-listing-rows` (default 20000), `mode` (`hosted`, `proxy`, or `proxy-cache`; see [Proxy repositories](configuration-artifact-keeper.md#proxy-repositories)), and for `raw`, `mapping`. |
| `local-directory` | Raw files on this machine, through a `file://` host. | `mapping` |
| `github` | GitHub release assets. | `repositories` (required: `owner/repo` or `owner/pattern`), `max-listing-rows` (default 10000). |
| `proxy-failover`, `proxy-merge` | Other sources. See [Proxies](#proxies). | none |

`nexus`, `artifactory`, and `artifact-keeper` take no `host-path`: they find the repository by `options.repository`. Any other kind names an [extension](configuration-general.md#extensions).

### Proxies

A proxy source stands in front of other sources, in order. It has no host.

```yaml
sources:
  combined:
    kind: proxy-failover
    proxy-to:
      - ref: internal-maven      # a non-proxy entry in 'sources'
      - source:                  # described in place; may itself be a proxy
          kind: maven
          host: central
```

- `proxy-failover` asks each upstream in turn, moving on only when one reports `artifact-not-found` or `host-unreachable`. Use it for a hot standby, or for nested subsets.
- `proxy-merge` unions every upstream's version list. Use it for a release repository beside a snapshot repository.

A `ref` must name a source that is not a proxy. Each entry may carry a `classifier`, which no built-in proxy reads. The proxy's own `dependencies` governs the whole walk.

## Targets

```yaml
targets:
  internal:
    kind: maven
    host: internal
    host-path: repository/maven-releases
    options:
      metadata: merge
```

| Field | Meaning |
| --- | --- |
| `kind` | The implementation. See [Target kinds](#target-kinds). |
| `host` | Required. The host it writes to. |
| `host-path` | Where under the host's url it writes. `.` and `..` are refused. |
| `options` | Settings the kind reads. |
| `omit` | See [Omit](configuration-server.md#omit). |
| `enumerator` | Accepted, but not yet used. |

### Target kinds

| Kind | Writes | Options |
| --- | --- | --- |
| `maven` | The Maven repository protocol. | `checksums`, `metadata`, `overwrite-guard`. See [Maven target options](configuration-maven2.md#target-options). |
| `npm` | The npm publish protocol. | `dist-tags`, `registry-fields`. See [npm target options](configuration-npm.md#target-options). |
| `pypi` | The PyPI upload protocol. | `upload-path`, `legacy-dists`, `attestations`. See [PyPI target options](configuration-pypi.md#target-options). |
| `nexus-raw` | A Nexus repository as raw files. | `repository`, `mapping`, `overwrite-guard` (default `server`), `upload-group-size` (default `50 MiB`), `max-listing-rows`. |
| `artifactory-generic` | An Artifactory generic repository. | `repository`, `mapping`, `overwrite-guard` (default `check`). |
| `artifact-keeper-generic` | An Artifact Keeper repository as raw files. | `repository`, `mapping`, `overwrite-guard` (default `server`), `max-listing-rows`. |
| `local-directory` | Raw files on this machine. | `mapping`, `overwrite-guard` (default `check`). |

See [Raw Repositories](configuration-raw.md) for `mapping` and `overwrite-guard`.

## Enumerators

```yaml
enumerators:
  pypi-all:
    kind: pypi-simple
    host: pypi
```

| Field | Meaning |
| --- | --- |
| `kind` | The implementation. See [Enumerator kinds](#enumerator-kinds). |
| `host` | The host it walks. Required, except for a proxy, which forbids it. |
| `host-path` | Where under the host's url its catalog lives. Absent for a repository manager, whose catalog is a REST API at the server root. |
| `options` | Settings the kind reads. |
| `omit` | See [Omit](configuration-server.md#omit). |
| `cache-retention`, `cache-freshness`, `cache-size` | See [Cache](configuration-server.md#cache). |
| `proxy-to` | `proxy-failover` only, naming enumerators. A walk uses the first upstream that can start; it never merges catalogs. |

### Enumerator kinds

| Kind | Walks | Options |
| --- | --- | --- |
| `maven-html-index` | Directory-autoindex HTML in Maven layout, on any server. Lists every version a directory holds. Never point it at Maven Central, whose terms forbid enumeration. | `page-size` (versions per page, default 100) |
| `pypi-simple` | The PEP 691 index: every project in one response. Names only. | none |
| `npm-replicate` | A CouchDB changes feed for names, reading each packument from `registry`. | `registry` (default: the feed's own url), `page-size` (default 100) |
| `nexus` | The Nexus REST API. | `repository`, `ecosystem`, and for `raw`, `mapping` |
| `artifactory` | Artifactory Pro, through sorted AQL. Needs a login. | `repository`, `ecosystem`, `mapping`, `anonymous` |
| `artifactory-oss` | Artifactory OSS, through AQL paged by upload time. Needs a login. | `repository`, `ecosystem`, `mapping`, `anonymous` |
| `artifact-keeper` | The Artifact Keeper artifact listing. | `repository`, `ecosystem`, `mapping`, `last-download`, `mode` |
| `local-directory` | A directory on this machine, without hashing what it lists. | `mapping` |

`anonymous`: `refuse` (the default) refuses a host without `authentication` before the walk; `attempt` sends the queries anyway, for a release that allows anonymous AQL. `last-download`: `unknown` (the default) reports no usage; `stats` asks for each file's last download, at one request per file.
