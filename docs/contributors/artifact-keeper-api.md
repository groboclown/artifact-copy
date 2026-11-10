# Artifact Keeper REST API

Reference for the endpoints the `artifact-keeper` enumerator, the `artifact-keeper` source, and the `artifact-keeper-generic` target use. Read from the product's source and checked against the local 1.9 server on 2026-10-05; where the two disagree, the running server wins.

The backend source sits in [GitHub](https://github.com/artifact-keeper/artifact-keeper/tree/main/backend). The API handlers for repositories, for any ecosystem, currently live in [backend/src/api/handlers/repositories.rs](https://github.com/artifact-keeper/artifact-keeper/blob/main/backend/src/api/handlers/repositories.rs).

Routes use Python f-string notation and apply to all repositories regardless of ecosystem.

## Access

- Every route below accepts no credentials (a public repository), Basic with a username and password, or a bearer token. Basic does **not** accept an API token as its password on `/api/v1`.
- A presented credential that is invalid answers 401; it does not fall back to anonymous.
- A private repository the caller may not read answers **404, not 403**: the server hides whether it exists. An error naming a 404 has to say "missing, or not visible to these credentials".

## Single file

- **Download**: GET `{base_url}/api/v1/repositories/{repository}/download/{path}` -- public repositories do not require authentication. Accepts the stored path and, for npm, the URL-shaped path. The enumerator and the listers use this route for every format of a hosted repository; a Remote's cached files go through the format route instead (see *A Remote repository's cache*).
- **Existence check**: HEAD `{base_url}/api/v1/repositories/{repository}/download/{path}` -- public repositories do not require authentication.
- **Upload**: PUT `{base_url}/api/v1/repositories/{repository}/artifacts/{path}` -- **requires authentication even on a public repository**, and a user granted `write`: measured against 1.9, anonymous answers 401 and a read-only account 403. Answers 201 with the stored artifact's JSON. See *Writing a path* below for what a second upload does.
- **Metadata**: GET `{base_url}/api/v1/repositories/{repository}/artifacts/{path}` -- one stored artifact as JSON, in the same shape as a listing item, including `checksum_sha256`.
- **Upload with path**: POST `{base_url}/api/v1/repositories/{repository}/artifacts/{path}` -- multi-part upload with a `file` field containing the data, writing to the artifact at `path` in `repository`. Requires authentication.

## Multiple files

- **Upload**: POST `{base_url}/api/v1/repositories/{repository}/artifacts`, requiring authentication. The artifact path is built from the optional `path` form field combined with the uploaded file's filename:
  - missing or empty `path` -- the path is just the filename
  - `path` ending in `/` -- the path becomes `<path><filename>`, treating it as a directory prefix
  - otherwise the `path` value is used verbatim as the full artifact path

## Writing a path

Measured against a running 1.9 server, and read from `upload_artifact` in the handler source:

- **A path is written once.** A second PUT to it answers **409** `"Artifact version already exists and is immutable"` -- **whether or not the bytes are the same**. Re-sending is not idempotent, so a writer that may run twice has to read the stored checksum to tell a file it already delivered from a conflict.
- **Except on a versioned repository.** A Generic or Mlmodel repository with `versioning_enabled` (`GET .../repositories/{key}` answers it) accepts the second PUT with 201: different bytes become the head and the old ones a revision under `GET .../versions/{path}`; identical bytes record no revision. An `x-artifact-version` header labels the revision; without it the label is the path's guessed version. Read from `enforce_path_immutability`, `versioning_applies`, and `persist_generic_staged_upload`, not measured.
- **Declared checksums are verified.** `x-checksum-sha256`, `x-checksum-sha1` and `x-checksum-md5` request headers are each checked against the digests computed while the body streams in; a mismatch answers 400 with both values in the message.
- **The path must not start with `/`.** A leading separator (`artifacts//a/b.txt`) is refused with 400; paths are validated against traversal, null bytes and backslashes as well. Listed paths carry no leading separator either.
- **The publishing account cannot delete.** `DELETE .../artifacts/{path}` answers 403 for a user granted only `write`; an administrator's delete answers 200 and leaves a tombstone, which the server consults before accepting different bytes at a released path again.
- **`name` and `version` are guessed from the path** as `{name}/{version}/{file...}` for every format except npm, exactly as the listing's are.

## Where each format is stored

The stored path is the server's own layout, not the URL a client fetches. Coordinates are read from it; the listing's `name` and `version` are not trusted.

| Format | Stored path | Listed as |
| --- | --- | --- |
| maven | `org/example/lib/1.0/lib-1.0.jar` | the same |
| npm | `@scope/name/1.0.0/name-1.0.0.tgz` | `@scope/name/-/name-1.0.0.tgz`, the tarball URL shape |
| pypi | `{normalized}/{version}/{file}` | the same; a remote repository's cache lists `simple/{project}/{file}` |
| generic | whatever the uploader chose | the same |

The server rebuilds `maven-metadata.xml` on upload (measured: `lastUpdated` followed the upload), so the Maven protocol's version list is current.

## Repository information

- **Current storage usage**: GET `{base_url}/api/v1/repositories/{repository}/storage` -- public repositories do not require authentication. Returns JSON with:
  - `repository_key` -- the internal key of the repository, UUID-like
  - `logical_bytes` -- number of bytes stored
  - `blob_count` -- number of artifact files stored, including metadata such as `maven-meta.xml`
  - `dedup_scope` -- how the repository decides to remove duplicate blobs to shrink storage
  - `computed_at` -- when this report was constructed

## Artifact file list

GET `{base_url}/api/v1/repositories/{repository}/artifacts?per_page={per_page}` returns one page as a JSON document, **sorted by stored path**. `per_page` defaults to 20 and is clamped to 1..100.

Query parameters:

- `cursor` -- the `next_cursor` of the previous page. A keyset position (base64url of `[last_path, ""]`), stable while files are added. `page` is ignored while a cursor is present.
- `page` -- page number, counting from 1. Offset paging; use the cursor instead.
- `path_prefix` -- a **literal starts-with match** on the stored path (an escaped `LIKE`, so `%` and `_` match themselves): `a/b` reaches `a/b/...`, and `a/bc/...` too. A trailing `/` keeps `1.0/` from reaching `1.0.1/`.
- `count=exact` -- makes `pagination.total` exact. Not used: 1.9.1 reported a lower bound.
- `group_by=maven_component` -- groups by GAV, but loads at most 10,000 files and groups them in memory, so it truncates above that. Not used.

Response:

- `items` -- array of artifact file information, each a dictionary:
  - `id` -- a UUID; the stats endpoint takes it
  - `repository_key` -- internal key of the repository
  - `path` -- the stored path, rewritten for npm; see *Where each format is stored*
  - `name` and `version` -- the server's *guess*, populated under the assumption that a path takes the form `{name}/{version}/{filename}`. **Do not rely on these for any ecosystem.**
  - `size_bytes` -- number of bytes of the artifact
  - `checksum_sha256` -- the only digest listed
  - `content_type` -- a guess at the file's content type
  - `download_count` -- always present, 0 when never downloaded
  - `created_at` -- when the server stored the file. A path is written once, so this is the age of the bytes.
  - `uploaded_by`, `uploaded_by_username` -- the uploader
  - `analyzable` -- whether the server can analyze the artifact for quarantine issues
  - `quarantine_status`, `quarantine_until` -- why the server restricts downloading it
- `has_more` -- whether another page follows. Authoritative: the server fetches one row past the page.
- `next_cursor` -- present when `has_more` is true.
- `pagination` -- `page`, `per_page`, `total`, `total_pages`. As of 1.9.1 `total` held `1 + (per_page * page)` while `has_more` was true.

**A remote repository's legacy listing sends neither `has_more` nor `next_cursor`**, only `pagination`. The enumerator falls back to page numbers there, and treats a page carrying none of the three as an error rather than the end of the walk.

## A Remote repository's cache

A Remote (proxy) repository records nothing in the `artifacts` table. Its listing is answered from the `proxy_cache_artifacts` catalog instead (backend `list_remote_cached_from_catalog`), or for a cache older than the catalog, from the storage backend (`list_remote_cached_artifacts`). The query parameters and paging are the same as a hosted listing's, except the legacy fallback above. The tool reads it under `mode: proxy` or `mode: proxy-cache`.

- **Paths are the ones a client fetched**, not the hosted storage layout:

  | Format | Cached path |
  | --- | --- |
  | maven | `org/example/lib/1.0/lib-1.0.jar`, as hosted |
  | npm | `@scope/name/-/name-1.0.0.tgz` |
  | pypi | `simple/{normalized}/{file}`, plus PEP 658 `{file}.metadata` beside a distribution |
  | generic | the upstream's path |

- **Metadata rows are left out**: index pages (a path ending in `/` or the cached index basename), and for npm every path without a `/-/` segment, which is a packument (`proxy_catalog::not_cached_metadata_sql`).
- `id` is synthetic: the first 16 bytes of the SHA-256 of `proxy-cache/{repository}/{path}`. It has no `artifacts` row, so the stats endpoint has nothing for it, and the source and enumerator refuse `last-download: stats` with a proxy mode.
- `created_at` and `cache_cached_at` are when the file was cached, not when it was published upstream. `checksum_sha256` is empty and `size_bytes` 0 on a placeholder row still waiting for its download to finish.
- `download_count` counts proxied downloads (`proxy_download_statistics`). No last-download time is listed.
- **Cached files are fetched through the format route**, `{base_url}/{format}/{repository}/{path}`: `maven/{repository}/{path}`, `npm/{repository}/{path}` (the scope's `@` literal; the route answers no `%40`), and `pypi/{repository}/simple/{project}/{file}`. These routes serve the cache through the repository's scan gate. The generic download route refuses a Remote miss on a repository that scans on proxy (backend #4442), so it is used only for raw files. A cached file that has expired is fetched from the upstream again by either route.
- **A Virtual repository caches nothing itself.** Its listing combines its members' `artifacts` rows, so it shows what hosted members hold and none of what Remote members have cached. Read each Remote member on its own.

## Download statistics

GET `{base_url}/api/v1/artifacts/{id}/stats` answers `{"artifact_id", "download_count", "first_downloaded", "last_downloaded"}`, the last two `null` until the first recorded download (measured).

- This is the only source of a last-download time, and it costs one request per file, so the enumerator asks only under `last-download: stats`.
- A HEAD is not recorded, and neither is a proxied pass-through.
- Events are recorded best-effort and can be dropped when the server's dispatcher queue overflows, so `null` reads as `Never`, approximately.
- A remote repository's cached rows carry a synthetic id with no stats behind it. With a proxy mode the enumerator refuses `last-download: stats`. Without one it reads a 404 as `Unknown`.

## No date filter

Neither the artifact list nor the package list takes a date. `/api/v1/search/advanced` parses `created_after` and `created_before` and then ignores them, so an "uploaded since" walk has to filter `created_at` itself.
