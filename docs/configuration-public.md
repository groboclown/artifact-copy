# Public Repositories

References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

Three server kinds read the public registries: `maven-central`, `npmjs`, and `public-pypi.org`. Each supplies its own url, is read only, and has one repository, named for the server's alias.

```yaml
servers:
  central:
    kind: maven-central
  npmjs:
    kind: npmjs
  pypi-org:
    kind: public-pypi.org
```

`--from=central`, `--from=npmjs`, and `--from=pypi-org` then name them. To publish to a public registry, use its native tools.

## Being a good citizen

Public registries are shared infrastructure, run for free or at a vendor's expense. Each publishes terms of use, and each can throttle or block a client that strains it. The tool's defaults follow their guidance; keep them.

- **Read their terms.** You, not the tool, agree to them.
- **Do not clone a public registry.** Maven Central's terms forbid downloading all or large portions of it, so `maven-central` has no enumerator. Copy what your builds need, not the catalog.
- **Cache.** Keep `setup.cache-dir` between runs, and leave `cache-payloads: reuse`, so a repeated run asks again only for what changed. The [built-in freshness rules](configuration-general.md#cache) keep index documents for an hour; do not shorten them without reason.
- **Use a report database** (`--db`) for long migrations, so a resumed run does not repeat finished work.
- **Back off.** Keep `exponential-back-off` and `honor-retry-after` on in [retry](configuration-server.md#retry), and do not raise `max-retries` or shorten delays against a public host.
- **Limit concurrency.** Keep `maximum-concurrent-downloads` low. `maven-central` fixes it at 1.
- **Identify yourself.** Every request sends `User-Agent: artifact-copy/{version} (+https://github.com/groboclown/artifact-copy)`, as Sonatype and PyPI ask.
- **Prefer a proxy.** If your organization runs a repository manager that proxies these registries, read through it instead.

## Maven Central

`maven-central` reads `https://repo1.maven.org/maven2/`, and reads files from Google's copy of Central first.

- One download at a time, fixed; `maximum-concurrent-downloads` is not accepted.
- A 429 waits as long as Central's `Retry-After` says.
- No enumerator, per Central's terms. Do not point a hand-written `maven-html-index` enumerator at it either.
- Its source reads directory indexes (`file-listing: html-index`, `version-discovery: html-index`), because Central's `maven-metadata.xml` can be stale. That costs a request per version and per artifact; an exact release version skips the artifact index, confirmed by its POM instead. See [Maven source options](configuration-maven2.md#source-options).
- Cached `maven-metadata.xml` stays fresh for a day rather than an hour, since Central is append-only.
- Files come from the [mirrors](configuration-low-level.md#mirrors) in the `mirrors` value first, which spares Central's rate limit. The default is [Google's GCS copy](https://storage-download.googleapis.com/maven-central/index.html), `https://maven-central.storage-download.googleapis.com/maven2/`. That copy has no directory indexes, so indexes go straight to Central. `HEAD` requests that read publish times also go to Central; those that only check a file exists, such as for an `.asc`, go to the mirrors first.

Server values: `connect-timeout`, `request-timeout`, and `mirrors`. See [Server values](configuration-server.md#server-values). `mirrors` is a list of urls, at most 10, and `[]` reads Central alone. Google also serves `https://maven-central-eu.storage-download.googleapis.com/maven2/` and `https://maven-central-asia.storage-download.googleapis.com/maven2/`.

```yaml
servers:
  central:
    kind: maven-central
    values:
      mirrors:
        - https://maven-central-eu.storage-download.googleapis.com/maven2/
```

Terms and guidance:

- [Sonatype Central Terms of Service](https://central.sonatype.org/terms.html): forbids scraping or mirroring, excessive requests or bandwidth, and evading abuse detection.
- [Rate limiting (429) guidance](https://central.sonatype.org/faq/429-error/) and [guidance for tooling providers](https://central.sonatype.org/faq/429-tooling-provider/): identify the tool, cache, and back off.
- [Maven Central Index](https://central.sonatype.org/faq/429-maven-index/): the full index is deprecated and rate limited.

## npm

`npmjs` reads `https://registry.npmjs.org/`.

- No enumerator yet. A hand-written `npm-replicate` [enumerator](configuration-low-level.md#enumerator-kinds) walks a replication feed, which npm's policy prefers to crawling.
- Registry signatures are checked against npm's published keys, or against [pinned keys](configuration-general.md#signing-keys).

Server values: `connect-timeout`, `request-timeout`, `maximum-concurrent-downloads`. See [Server values](configuration-server.md#server-values).

Terms and guidance:

- [npm Open Source Terms](https://docs.npmjs.com/policies/open-source-terms): replication through the public APIs is allowed; an unreasonable volume of requests is not, and five million requests in a month is never reasonable.
- [Replication and crawler policy](https://docs.npmjs.com/policies/crawlers): replicate rather than crawl; a crawler stays at 1 request per second or less.
- [Registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

## PyPI

`public-pypi.org` reads `https://pypi.org/`, and follows file links to `files.pythonhosted.org`.

- Its enumerator reads the PEP 691 simple index: every project name in one response.
- A copy to a PyPI target forwards each file's PEP 740 attestations by default; see [attestations](configuration-pypi.md#attestations).

Server values: `connect-timeout`, `request-timeout`, `maximum-concurrent-downloads`. See [Server values](configuration-server.md#server-values).

Terms and guidance:

- [PyPI Terms of Use](https://policies.python.org/pypi.org/Terms-of-Use/) and [Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/): no undue burden or excessive automated bulk activity; PyPI may throttle or suspend.
- [PyPI API guidance](https://docs.pypi.org/api/): set a unique `User-Agent`, avoid bursts of thousands of requests in minutes, and run your own mirror or cache to download many packages.

## Low-level details

Each server generates a [host](configuration-low-level.md#hosts) named for its alias, and its default repository generates:

| Server kind | Host | [Source](configuration-low-level.md#source-kinds) | [Enumerator](configuration-low-level.md#enumerator-kinds) |
| --- | --- | --- | --- |
| `maven-central` | `https://repo1.maven.org/maven2/`, `maximum-concurrent-downloads: 1`, retry `429: {honor-retry-after: true}`, a mirror per `mirrors` value with `skip: ["*/"]` | `maven`, with `file-listing` and `version-discovery` set to `html-index`, and a 24 hour `maven-metadata.xml*` freshness rule | none |
| `npmjs` | `https://registry.npmjs.org/` | `npm` | none |
| `public-pypi.org` | `https://pypi.org/`, additional host `files.pythonhosted.org` | `pypi` | `pypi-simple` |

None generates a target. The templates live in [server-kinds/](../server-kinds/).
