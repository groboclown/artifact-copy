# Measured Server Behaviors

References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

What real servers did when probed, so the next reader does not re-derive it. Measured on 2026-09-29 against the manual-integration servers (Nexus 3.96.3-01 Community, Artifactory OSS 7.161.26) and the public services named below; entries marked (2026-10-05) were measured later, against the same servers and Artifact Keeper 1.9. Work that follows from these lives in [TODO.md](../../TODO.md) under *Found by checking the local servers*.


## Nexus

### Maven metadata and checksums are not generated

A POM uploaded to the hosted `maven-c` got no `org/probe/p/maven-metadata.xml` (404, still 404 twenty seconds later), and its `.sha1`, `.md5`, `.sha256`, and `.sha512` all answered 404. So under `metadata: server`, a version copied into Nexus does not resolve by range or `LATEST` until something rebuilds the index. A file stored by anything other than `MavenTarget`, which writes its own sidecars, has no checksum sidecar. The asset API reports `checksum.sha1` for every asset.

### `search/assets` wildcards match more than a glob

`*` crosses `/`, and `%2A` arrives as `*`. Once a pattern holds a wildcard, Nexus matches as though a trailing `*` were appended: `/nx-artifact1/*.0` matches group `/nx-artifact1/2.0/sub`. It refuses with 400 a leading wildcard, a pattern like `/*/sub` (a special character then a wildcard), and a trailing wildcard after fewer than three characters. Without a wildcard the match is exact and case-sensitive.

### `search/assets?group=`

Exact, case-sensitive, and not a prefix. Without the leading `/` it answers an empty page.

### Raw repositories

- One component holds one asset, and the component id equals the asset id.
- `version` is `""` on 3.96.3 (another server sent `null`; both read as absent), `name` is the asset path with a leading `/`, and `group` is `/` plus the directory.
- A root file stored by `PUT`, or by the component upload API with `raw.directory=/`, has `group` `/`, and `search/assets?group=/` finds it.
- `blobCreated` is the first upload and survives a rewrite; `lastModified` and `blobUpdated` follow every write. So `blobCreated` is the publish time, as `repo::nexus` reads it.
- `uploader` is `null` for raw uploads.

### `lastDownloaded`

An explicit `null` until the first download, then ISO 8601 with milliseconds. Repeat downloads within seconds do not move it.

### Object keys

No repeated keys in component or asset objects.

### `search` (2026-10-05)

`/service/rest/v1/search` returns components with their assets, each asset carrying `checksum`, `fileSize`, `downloadUrl`, and `blobCreated`. It filters by `maven.groupId`, `maven.artifactId`, and `maven.baseVersion`, or by `group`, `name`, and `version`. `name=ech` matches nothing and `name=ech*` matches `echo`: exact unless a `*` makes it a glob. `maven.baseVersion` selects a snapshot's timestamped builds together.

A PyPI component holds the wheel and its PEP 658 `.whl.metadata` as two assets.

### Any repository read as raw (2026-10-06)

- `search/assets?group=/{folder}` finds a folder only in a raw repository; in `maven-a`, `group=/example/lib/echo/1.0` answered nothing while `group=example.lib` (the groupId) answered every asset.
- `q` matches component keywords, not paths. A Maven file uploaded at `/am/probe/rawview/1.0/rawview-1.0.txt` was found by `q=rawview` and `q=am.probe` but never by `q=/am/probe/rawview/1.0/*`, even though `q=/example/lib/echo/1.0/*` found an older Maven component's files.
- `service/rest/repository/browse/{repository}/{folder}/` is an HTML page for every format: one table row per file, linked by its absolute download URL, with last modified (`Mon Oct 05 16:14:59 Z 2026`) and size; a sub-folder links relatively as `{name}/`. A file path with a trailing `/` answers 404, as a missing folder does; without one it answers 303.
- `GET /v1/repositories/{name}` answers `format` (`maven2`, `raw`) for the reader and publisher accounts, and 401 anonymously.
- `PUT /repository/{name}/{path}` answered 201 on raw and on Maven for a Maven-layout path (`am/probe/rawview/1.0/rawview-1.0.txt`); Maven refused any other path with 400 "Invalid mavenPath for a Maven 2 repository", npm and cargo with 400, PyPI with 404. Every probe file was deleted afterwards.


## Artifactory

### `.sha1` and `.md5` exist only when the uploader supplied them

After a plain `PUT`, `p-1.0.pom.sha1` and `.md5` answered 404 ("Checksum not found") while `.sha256` answered 200. Artifactory serves the checksums the client sent (`X-Checksum-Sha1`, or an uploaded sidecar) plus its own SHA-256. The storage API's `checksums` holds all three regardless.

### `Last-Modified` is whatever the uploader said

Both `X-Artifactory-Last-Modified: <epoch ms>` and a plain `Last-Modified` request header set the stored `lastModified` and the served `Last-Modified`; `created` stays at server time. A plain `PUT` gives the upload time. So `MavenSource::published`, which reads `Last-Modified`, reads the uploader's claim.

### `gavc` search returns nothing

`/api/search/gavc` answers `{"results":[]}` for every query, anonymous or admin, with or without `v=` and `repos=`. Nothing uses it. Use `api/search/artifact` instead (a substring match: `echo-1.0.jar` also finds `noecho-1.0.jar`), or AQL with a login.

### AQL

- Unsorted `.offset().limit()` pages reproduce the unpaged order (creation order) across page sizes and repeated runs.
- OSS refuses `.sort(...)` ("Sorting is not supported by AQL in the open source version"), even with the sorted fields included.
- (2026-10-05) A range on one field is two clauses: `"$and":[{"created":{"$gte":A}},{"created":{"$lt":B}}]`. The single-object form `"created":{"$gte":A,"$lt":B}` is a syntax error. `$lt` excludes a file created exactly at `B`.
- (2026-10-05) `.limit(N)` without a sort is accepted.
- `.include(...)` accepts `size`, `actual_sha1`, `actual_md5`, `sha256`, `created`, and `modified`. `stat.downloaded` comes back nested as `stats[].downloaded`.
- Rows hold no repeated keys.

### Anonymous APIs

Folder info, file info, `?stats`, HTML indexes, and `api/search/artifact` work. AQL is 403 ("Only non-anonymous users are allowed to access AQL queries", also on 6.9.1), even on a repository that allows anonymous reads; `creation`, `dates`, and `usage` are 401; `?list&deep=1` is 403.

### Storage API (2026-10-05)

- `?list&deep=1&listFolders=0` is Pro only: OSS answers 400 even as admin. Listing a folder's files on OSS takes folder info (`children`, names only) and then one file-info request per file.
- File info holds `size` (a number sent as a string), `checksums` (sha1, md5, sha256, computed), `originalChecksums` (the uploader's), `downloadUri`, `created`, and `lastModified`.
- A redeploy keeps `created` and moves `lastModified`: the overwritten `echo-1.0.jar` showed `created` 2026-09-29 and `lastModified` 2026-10-05. `latestVersion`, `versions`, and repository configuration are Pro only. The storage API's `?stats` gives `lastDownloaded` in epoch milliseconds.

### Maven metadata

Artifactory generates `maven-metadata.xml` for a coordinate once its POM is uploaded, not for jars alone.

### Ivy repositories (2026-10-06)

An OSS `ivy` repository (`ivy-a`, created by `configure.sh`) accepted `PUT`s at `ja-ivy/module/1.0/module-1.0.jar` and `ja-ivy/module/1.0/ivy-1.0.xml`, paths outside its `ivy-default` layout (`[org]/[module]/[baseRev]/[type]s/...`). The storage API and AQL answered for it exactly as for a generic repository: `inspect` resolved both files with md5, sha1, and sha256, and `find` walked `ja-ivy/module` at `1.0`.


## Artifact Keeper (2026-10-05)

Measured against the local 1.9 server; the REST reference is [artifact-keeper-api.md](artifact-keeper-api.md).

- The artifact list of a hosted Maven repository sends `has_more`, `next_cursor`, and `created_at`, and `download_count` 0 for a never-downloaded file.
- `/api/v1/artifacts/{id}/stats` answers `last_downloaded: null` for a never-downloaded file.
- `maven-metadata.xml` is rebuilt on upload.
- A repository that does not exist answers 404 `{"code":"NOT_FOUND","message":"Repository not found"}`. The local server has no generic repositories, so `generic-a` answers that.
- (2026-10-06) `artifacts?path_prefix=` lists `maven-a`'s files by stored path (`example/lib/noecho/1.0/noecho-1.0.jar`), as it would a generic repository's, so the raw source and enumerator read any format. The backend's `PUT /api/v1/repositories/{key}/artifacts/*path` (`authorize_generic_upload`) checks no format; a raw write to another format is unmeasured.

## npm publish (2026-10-08)

Measured by publishing `@am-example/echo@1.0.0` with npm 12.2.0 (`030` and `031`), then copying it between the two servers (`240`).

- **Both store the published version object as sent** and serve it back: `dependencies`, `engines`, `gitHead`, `_id`, `_nodeVersion`, and `_npmVersion` all came back from each.
- **Artifact Keeper rewrites `dist`**: `integrity` becomes its own sha256 of the tarball and `shasum` is dropped. Nexus keeps the publisher's sha512 `integrity` and `shasum`.
- **The version route** `/{name}/{version}`: Nexus answers `@scope%2fname/1.0.0` and `@scope/name/1.0.0` alike. Artifact Keeper answers only `@scope/name/1.0.0` -- 400 for `%2f`, 404 for `%40`. Both answer the packument under either spelling.
- **Nexus stores `null` as given**: a publish sending `"shasum": null` is served back with it. An `integrity` of `sha256-...` is stored, and npm 12 accepts it when fetching the tarball.
- Nexus's `npm-a` answers 401 to an anonymous read, as its other `-a` repositories do (see *The manual-integration servers differ from their README* in [TODO.md](../../TODO.md)).

## Public services

### npm replication feed

`https://replicate.npmjs.com/_changes?include_docs=true` answers 400, as does `include_docs=false`. Without the parameter it returns ids and revisions only.

### npm keys

`/-/npm/v1/keys` lists `keyid`, `keytype`, `scheme`, `key` (base64 SPKI), and `expires`, which is `null` or a timestamp. A retired key stays listed with its expiry.

### Maven Central Index

The full `nexus-maven-repository-index.gz` is 3.3 GB and answered 429 to a ranged request from both Central hosts ("the Index changes every 2 weeks and is largely a deprecated artifact"). The incremental chunks are served, and one decoded as the `IndexDataReader` format (version byte 1, then a timestamp matching `.properties`), not Lucene.

### HKP keyservers

keys.openpgp.org and keyserver.ubuntu.com answer `/pks/lookup?op=get&options=mr&search=0x<fingerprint>` with an armored key, and a miss with 404 whose body differs by server. Read the status, not the body.

### OSV

`{base}/{Maven,PyPI,npm}/all.zip` exist, each entry a root-level `<ID>.json` whose `id` matches its name.

### `ossf/malicious-packages`

Records live at `osv/malicious/<ecosystem>/<package>/<ID>.json` and `osv/withdrawn/...`, with a third directory, `osv/unmergable/`.
