# The Write Path

References: [PEP 658](https://peps.python.org/pep-0658/), [PEP 740](https://peps.python.org/pep-0740/), [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md), [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

Targets, uploads, and `copy`.

## The upload capabilities

`ExtHost` had `head`, `fetch`, and a download into its cache -- all reads -- so no target could publish anything. There are now two that write, and which one an adapter wants depends on the registry's protocol:

| | For | Body |
| --- | --- | --- |
| `ExtHost::send_file` | a whole document, `PUT` or `POST` | one file, streamed |
| `ExtHost::send_form` | `multipart/form-data`, `curl -F` style | fields plus streamed files (`net::FormPart`) |

Both take a **file path** rather than a `String`: npm's publish document wraps the tarball in base64, so it is a third *larger* than the artifact, and PyPI's upload sends the distribution beside its metadata. `Req::body` stays documented as bounded by construction. A payload is sent from where the source cached it; a document a target builds for one request -- npm's publish document, a Maven checksum sidecar -- goes to a temporary file.

`send_form` is on the host rather than in each adapter because the framing, the boundary, and the escaping are identical everywhere -- three hand-rolled copies would be three chances to get one subtly wrong -- and because an adapter that built its own body would still have to hand it here to be sent, so it would gain nothing but the bugs.

A form goes through the allow-list and picks up the host's credentials exactly as a fetch does. An upload is the request where that matters most, and a test pins both.

## The npm target

`repo::NpmTarget` implements `Target`: `exists` asks the version document rather than the packument (a packument for a popular package is megabytes and this is asked once per artifact), and `publish` sends one `PUT` of npm's publish document.

`repo::npm::publish` streams that document -- JSON prefix, tarball encoded through `base64::write::EncoderWriter` as it is read, suffix -- so memory is one 64 KiB buffer whatever the package weighs. A test with a payload straddling chunk boundaries at a non-multiple of three pins the encoding, which is where a naive per-chunk encode produces padding mid-string.

### The version object is the origin's manifest

A registry stores the version object a publish sends and serves it back as the packument, so its `dependencies`, `optionalDependencies`, `os`, `cpu`, `bin`, and `engines` are what an installing client resolves from. Artifact Keeper and Nexus both store it as sent (measured; see [server-behaviors.md](server-behaviors.md#npm-publish-2026-10-08)), so a minimal object installs the right bytes and none of their dependencies -- and an npm source pointed at that mirror reports none either.

`repo::npm::manifest` sends the origin's own, from the first of three that answers:

| Tier | From | Checked |
| --- | --- | --- |
| registry | the version document, `{registry}/{name}/{version}`, staged as the `PackageManifest` companion | name, version, and `dist` digests against the tarball's |
| tarball | `*/package.json` in the staged tarball, through `repo::archive`'s caps | name and version; `_id` and `hasInstallScript` added as a registry would |
| minimal | name, version, license | reported as `upload-metadata-incomplete` |

The companion is named by the source rather than advertised on the file: `Source::companion` defaults to what a file advertises (PyPI's PEP 658 and PEP 740 documents) and `NpmSource` answers `PackageManifest` itself, keeping a scope's `@` and `/` literal, since Artifact Keeper refuses either escaped on this route. Wrappers and proxies forward it, and `InventorySource` asks its live source, so a `--from-db` copy needs nothing recorded. A 404 stages nothing and the tarball answers.

**Never copied:** the origin's `dist.tarball`, `shasum`, and `integrity`, which the target states for its own copy, and `signatures`, `npm-signature`, and `attestations`, which would not verify against the mirror. `integrity` is sha512 when the tarball's digest is known, else sha256 -- a tarball read from Artifact Keeper is known only by that -- and a digest the tarball lacks is left out rather than sent as `null`, which Nexus stores as given.

**Registry-assigned keys** (`_npmUser`, `_npmOperationalInternal`, `_resolved`, `_from`, `_integrity`, `_shasum`, `_rev`, `_attachments`) describe the origin rather than the package and are dropped by default; the target option `registry-fields: keep` keeps them. `_id`, `_hasShrinkwrap`, `_nodeVersion`, and `_npmVersion` are the publisher's and always stay.

**Not reproduced by the tarball tier:** the README and `directories.bin` expansion `npm publish` does on the client.

## The Maven target

`repo::maven::MavenTarget` writes the directory tree `MavenSource` reads: each file is a `PUT` into its version directory, under the name the source gave it. A snapshot's files already carry the build timestamp the source resolved, so the target invents no name. Every file gets a checksum sidecar per `checksums` entry, hashed from the staged bytes; a `.asc` gets none, for the reason in [verification.md](verification.md#sidecar-depth-stays-at-one-by-decision).

**`exists` asks about the payload, not the POM**, because classifier artifacts share one POM. The payload's extension is the POM's packaging, so the target's own POM is read first and the payload is then asked with a `HEAD` -- two requests for a present version, one for an absent one. A snapshot is looked up by the build the target's own version index names, so a target holding an older build answers *present*.

**A refused rewrite is a question, not a failure.** Nexus answers 400 to a redeploy and Artifact Keeper 409; either is answered by comparing the stored file with the staged one, by bytes for a file up to 64 KiB and through the target's `.sha1` above that. Same bytes are a delivery that already happened; different bytes, or a large file with no `.sha1` to compare, are `Error::Integrity`. A refusal over a path that holds nothing -- the `.sha1` absent and a `HEAD` of the file answering 404 -- is not a rewrite at all but the server refusing the path, such as a Nexus answering 400 to a name outside its Maven layout, and it stands as the server gave it (`request-rejected`).

**A rejected secondary file does not stop the rest.** The POM and the payload its packaging names are the artifact's primary files, named as the source names them (`maven::payload_shape`); every other file is one a directory listing added, and the version directory is all that places it -- Central's `groovy/2.4.0` holds `groovy-all-2.4.0-groovydoc.jar`. A secondary file the target rejects, or whose name it cannot take (not a usable path segment, the repository's own index, or not starting with the artifactId), is reported as `secondary-file-rejected`, a failure by default and configurable like any artifact code, recorded as skipped, and the remaining files are published; a file refused by name is never sent. A rejected primary file fails the artifact.

**Not every server refuses.** Artifactory OSS, as admin, overwrites a path with different bytes and answers 201. `overwrite-guard: check` makes the same comparison before anything is sent: every file of the artifact is compared first, one request each, and different bytes under any of them refuse the artifact with nothing written. A path answering 404, or a large file with no `.sha1`, is written; one already holding the same bytes is skipped along with its checksums. `server`, the default, leaves it to the server's refusal and costs nothing.

**`maven-metadata.xml` is the server's unless configured otherwise.** Under `metadata: server` nothing is written, because a repository manager rebuilds it from what it holds. Under `metadata: merge` the target reads its own document, adds the version, and writes it back, plus a snapshot's version-level document derived from the published file names. Only the `<versioning>` element of the artifact-level document is replaced; everything else -- a plugin prefix, a vendor element, an attribute -- stays byte for byte, and a result that does not read back as the versions written is refused rather than stored. `<latest>` and `<release>` name the highest version by Maven's ordering rather than the last one copied -- the `dist-tags` argument below, applied to Maven.

### Snapshots and their builds

The Maven layout names only a snapshot's latest build, so `MavenSource` resolves that one. A catalog lists every build: Artifactory's rows fold every timestamped file under the `-SNAPSHOT` directory into one artifact, and Nexus, which lists each build as a component with a timestamped version, has the version mapped back to its snapshot (`ecosystem::maven::snapshot_of`) so its builds fold the same way. A copy fed from such an artifact enumeration therefore carries every build's files, and the target publishes them all under their own names. The version-level document names the newest build of each file, and the newest build overall as `<snapshot>`, whatever order the files arrived in.

### What an out-of-process Maven target would need

A built-in target performs its own I/O, so none of this constrains `MavenTarget`. It is what the Target gearing has to offer an out-of-process one, which answers in ask, answer, prepare phases (see [extensions.md](extensions.md#the-target-gearing)). Most of the target fits them without strain: every file write and every checksum write is an operation it could return rather than perform, each naming the file it carries, and the metadata writes are operations carrying none.

Two parts do not fit:

- **The metadata merge is read-then-decide.** The document written depends on the document read, and the two must not interleave with another publish of the same coordinate. `MavenTarget` holds a striped in-process lock across the pair, as `NpmTarget` does -- state an out-of-process extension could not hold. In the gearing it becomes a question (*what does the index say?*) answered by the gearing, with the lock held by the gearing across the answer and the write.
- **The conflict check happens after a write fails.** Like Artifact Keeper's 409 handling, the comparison is a read that exists only because a write was refused. No phase of ask, answer, prepare runs after a write; either the gearing learns to hand a refused operation back with the target's contents, or the extension asks about each file rather than each artifact.

## The PyPI target

`repo::pypi::PyPiTarget` uploads each distribution with one multipart `POST` to the upload API twine speaks: `:action=file_upload`, `protocol_version=1`, the name, version, `filetype`, `pyversion`, `md5_digest` and `sha256_digest`, the core metadata, and `content`. `upload-path` names where the form goes, relative to `host-path` and defaulting to it, since Nexus and Artifact Keeper take uploads at the index root.

**The metadata is the point.** An index serves `Requires-Python`, the summary and the rest back to pip from what the *upload* said, not from the distribution. A wheel uploaded with only its name and version installs, and a pip on the wrong interpreter picks it. So each upload repeats the origin's core metadata, from the first of:

1. the PEP 658 document beside the file on the source;
2. the distribution's own document: a wheel's `METADATA`, read by `repo::pypi::wheel` under caps on the entry count, on the entry's declared size before decompressing, and on the bytes actually read (so an archive that lies about its size is still stopped); or an sdist's top-level `PKG-INFO`, read by `repo::pypi::sdist` from a `.zip` under the same caps, and from a `.tar.gz` under caps on the entry count, the entry's declared size, and the bytes inflated in all -- a tar has no central directory, so confirming there is exactly one `PKG-INFO` means inflating the whole stream. A document that breaks a cap, is missing, or appears twice fails the upload;
3. nothing: the fields the filename gives, reported as `upload-metadata-incomplete` (warn). A `.tar.bz2` or `.tar.xz` sdist without a sidecar lands here.

Header `Foo-Bar` travels as field `foo_bar`, repeats repeated, with the plurals twine uses (`classifiers`, `project_urls`, `license_files`), and a body after the headers as `description`.

### The core metadata is the source's to download

The PEP 658 document lives on the **source's** host, and a target reaches only its own. So `upload` has the source download it: the PyPI ecosystem declares `Companion::CoreMetadata` in `Ecosystem::companions`, and for each file whose `FileRef.core_metadata` says a document exists -- set by `PyPiSource` from the index's `core-metadata` field -- `upload` calls `Source::download` for `{url}.metadata`, checked in flight against the digests the index published (a mismatch fails as `checksum-mismatch`, like any payload). The document reaches `PyPiTarget::publish` in `repo::Companions`, by path. A 404 leaves the file without one and the target falls back.

Declared by the ecosystem rather than asked by the target, because which documents belong to a file is an ecosystem rule: an npm file claiming one costs no request, and a test pins that. A target may still decline a declared companion through `Target::declines`, so a document it would ignore costs no request either.

A copy fed from a report fetches the same documents: the report records `FileRef.core_metadata` and `FileRef.signatures` on `repository_file` (schema version 5), and `InventorySource` gives them back.

### Attestations travel as a companion

PEP 740 names each file's provenance object in the index (`provenance` in JSON, `data-provenance` in HTML). `PyPiSource` records it as a `SigRef` of scheme `pypi-attestation`; `upload` fetches it through the source as `Companion::Provenance` (the index publishes no digest for the object itself), hands it to `PyPiSource::verify` to check its attestations (see [verification.md](verification.md#attestations-are-verified-once-the-file-is-staged)), and `PyPiTarget` flattens every bundle's attestations into the upload's `attestations` field. `attestations: forward` is the default. `drop` sends none; the source still fetches the provenance once, to check it, because checking is the source's business and forwarding the target's.

Nexus 3 and Artifact Keeper accept the field and serve no provenance back, so on them forwarding costs one request per file for nothing kept. pypi.org refuses the field unless the upload itself comes through Trusted Publishing under the same identity, which is what `drop` is for.

### A filename is uploaded once

PyPI and Nexus refuse a second upload of a filename with 400; some servers use 409. Either is answered by reading the target's own simple index: the same sha256 is a delivery that already happened, a different one is `Error::Integrity`. A 400 for a file the index does not list was not a conflict, and the server's own refusal is returned as the failure.

`exists` asks the same index: PEP 700's `versions` where the index has it, any listed file of the version where it predates that. The project name is PEP 503 normalized.

### Legacy distributions

`.egg`, `.exe`, `.msi` and the like cannot be uploaded to PyPI any more, and are real on old mirrors -- and on old servers that still take them. `legacy-dists` is therefore the user's call: `error` (the default) refuses the artifact before any of it is sent, `skip` uploads the rest and reports each file left behind as `distribution-type-unsupported` (warn), and `guess` sends the `filetype` the extension suggests. A signature, a checksum sidecar, or a `.metadata` document travelling with a distribution is never uploaded as one.

## The Nexus raw target

`repo::nexus::NexusRawTarget` (`nexus-raw`) places each file by its `mapping`, refusing a path that does not read back as the artifact, exactly as `artifact-keeper-generic` does. It uploads through the components API rather than one `PUT` per file: `POST service/rest/v1/components?repository={name}` with `raw.directory` and `raw.assetN` / `raw.assetN.filename` pairs. One request carries one directory and at most `upload-group-size` (default `50 MiB`, any unit `ByteSize` reads); a group closes when the next file would pass the cap, in source order with no packing, and a larger file goes alone.

`writePolicy: ALLOW_ONCE` refuses a rewrite with 400 and `ALLOW` replaces it silently, so `overwrite-guard` applies as for Maven. Under `server` a refused group is answered by listing the directory through `search/assets`: the same sha256 (sha1 where none is listed) is already delivered, different bytes are `Error::Integrity`, and files still absent are sent once more. Under `check` the listing comes first, so different bytes refuse the artifact with nothing written.

**A repository of another format takes one `PUT /repository/{name}/{path}` per file.** The components API takes only that format's own fields, with which Nexus places the file itself, so a mapping's path is not one it would keep. The target asks `GET /v1/repositories/{name}` for the format once, before its first upload. Maven takes a Maven-layout path and refuses any other with 400; npm, cargo, and PyPI refuse every one (measured; see [server-behaviors.md](server-behaviors.md)), and the refusal stands. A 400 is also `ALLOW_ONCE` refusing a rewrite, so it is answered by finding the file on the browse page: absent, the refusal stands; a different size is a conflict; the same size is downloaded and hashed, since the page lists no digest.

## The Artifactory generic target

`repo::artifactory` (`artifactory-generic`) places each file by its `mapping`, refusing a path that does not read back as the artifact, as `artifact-keeper-generic` does, and deploys it with one `PUT {repository}/{path}` carrying `X-Checksum-Sha256` from the staged bytes, plus SHA-1 and MD5 where the source declared them. Artifactory serves only the sidecars it was given a checksum for (see [server-behaviors.md](server-behaviors.md)).

**`overwrite-guard` defaults to `check` here**, unlike every other target: Artifactory OSS as admin replaces a path with different bytes and answers 201, so the default that trusts the server would let a copy rewrite the target's history. Every file is looked up through the storage API before any is sent; the same SHA-256 is already delivered, and different bytes, or a folder, refuse the artifact with nothing written. `server` skips the lookups, for an account without overwrite permission, and answers a 403 by the same comparison; a 403 over an absent path is an account that may not deploy at all, and fails as sent.

`exists` reuses the raw source's lookup without fetching each file's info.

## Per-file results

`Target::publish` fills a `repo::Delivery` as it goes: `start` before sending a file, `finish` with `Uploaded`, `AlreadyPresent`, or `Skipped`. A failure leaves the files it was sending pending, and `copy` records those as `failed`, so the report's upload `file_transfer` rows say which files of a half-published artifact the target already has. A request carrying no file of the artifact, such as `maven-metadata.xml` or a checksum sidecar, is not recorded.

## The source's cache, handed to the target

`commands::upload` asks `ConfiguredTarget::holds` whether the target already has the version -- the report first, then `Target::exists` -- then has the **source** download each file through its own host into that host's cache, verified in flight, and hands the target the cached files' paths.

Downloading through the target's host instead would need its constraints widened to cover the source's -- the change that lets one host's credentials reach another. A built-in target reads the cached file where it lies, so nothing is copied and the cache keeps its one copy for the next run; `payloads: discard` deletes it after a successful publish. An out-of-process target would be given its own scratch directory by its gearing, which is where copying belongs.

`Session::target` builds the target with a host confined to its own `host-path` prefix exactly as a source is. `repo::under` does the join, and `Hosts::under` confines a capability to a prefix rather than to a host.

## `copy` is `inspect` with a different visitor

`commands::copy` *is* `inspect::run` with an uploading `Visitor` instead of a reporting one. Sharing the walk rather than repeating it is what keeps `README.md`'s claim that "inspect uses the same rules as copy" true -- a second implementation would drift, and the drift would show as a `inspect` promising artifacts `copy` then did not take.

The target is opened **before** the walk, so a misconfigured one fails without a byte fetched; a test asserts the source was never consulted. Artifacts already present are counted apart from those published, because a re-run over a mostly-copied repository is the ordinary case and "0 published" alone cannot be told from doing nothing -- and they are excluded from the run's verification, since an artifact that was never fetched saying `NotAttempted` would report a re-run as *less* verified than the run that did the work.

Upload failures are graded rather than fatal. One artifact the target rejects no longer discards the run and the report with it; an `abort`-classed error -- a checksum mismatch, a cache that cannot be written -- still unwinds.

## `copy` optionally keeps track of tasks performed for restart

In order to perform a migration of one repository to another, the user can use essentially `find` as input to the `copy` command.  Because this migration can cover a much larger scope than a usual copy (thousands of artifacts versus dozens), the user can encounter issues that abort the process which requires them to continue where they left off (network interruption, resource timeouts, etc).

So that a rerun does not start over from the beginning of the input list, `copy` records what it copied and what it skipped in the report database, and a later `copy` reads that back rather than trying those artifacts again.

A full migration is:

1. `find --from=SOURCE --db=FILE` records every artifact the source holds.
2. `copy --from=SOURCE --to=TARGET --db=FILE --from-db` works through what has not reached the target, claiming each artifact in `artifact_transfer` before network work.
3. If the copy aborts, the user reruns the same command. Terminal transfers are skipped, and a claim left `in-progress` by a run that is over is reclaimed.

Only the database resumes. A line report is a stream for outside tools, and `copy --from-db` without `--db` fails with one message.

With several `--to` targets, `copy` fetches and verifies each artifact once and publishes it to each target in turn, each with its own claim; see [several-targets.md](several-targets.md). `--from-db` then works through what has not reached **every** target, and the dependency walk is keyed on the sorted target set, so a rerun with other targets starts a new walk.

`find` must also resume, and continuing where the enumerator last retrieved values has two candidate approaches:
    - Rerun the page operation from the start until it reaches the desired page.  Experiments with Nexus shows that Maven repositories take about 2 seconds to return per page.  If the repository contains 1 million artifacts, then that will mean each restart takes hours to get to the right place.
    - Keep track of the last page query position.  Not all servers use the same page request method - some use a "next page" token, others use a page number (boutique per server).  Additionally, servers may not guarantee that reusing an old page token will work.

The second is built: `repository_enumeration` keeps the cursor beside the enumerator kind that issued it, and a cursor recorded under another kind is refused rather than reused. See [report-as-database.md](report-as-database.md#what-the-database-finder-needs-up-front).

[The Report Database](../progress-db.md) is the user-facing guide: schema pointers, `scripts/explore-report-db.py`, maintenance, and hand edits.

### Two things wiring the report turned up

Building `copy`'s report found that **the restriction it was meant to report did not exist**. `Action::SkipArtifact` was computed by the policy tables and never branched on, and `Action::StopSpider` had no consumer anywhere -- not one line of production code or test. Only `Abort` changed control flow. So a `hard` quarantine rule recorded a problem and the artifact was copied anyway, and the report's reason column would have had nothing to put in it. Both are now honored: a refusal skips the upload and prunes the subtree, and `stop-spider` prunes without dropping the artifact.

**`stop-spider` is checked after the dependency read, not before the visit.** Its only producer is `pom-profile-unsupported`, reported inside `MavenSource::deps`, which runs after the visitor has already been handed the artifact. A check placed before the visit would always find nothing and would read as though it worked.

**A latent bug had to be fixed first.** `repo::resolve` narrows with `Ctx::for_artifact` *inside* the publish-window step-down loop, and `for_artifact` inherits the reservation list -- so a `publish-too-recent` about a **rejected** candidate landed in the list the **accepted** version later read. It only mislabeled `ArtifactRecord.quarantine`, which nothing branched on, so it went unnoticed. Wiring `SkipArtifact` up naively would have turned it into a refusal to copy artifacts that resolved cleanly, up to `MAX_STEP_DOWN` of them per artifact. Reservations are now keyed by the subject they were decided under; provenance could not discriminate, being identical across candidates.

Behavior change worth calling out: a run that previously exited 1 *and copied* the artifact now exits 1 *and does not*. The exit code is unchanged, because `SkipArtifact` already reached it through `ProblemSink::worst`.

### What the report does not cover

Stated so it is not mistaken for a promise: a record is written for every artifact that reached *resolution*. Children discarded by the depth limit, the frontier abandoned when a run stops, and the cancellation race produce counts only. An artifact reached twice gets one line, deliberately.

## `dist-tags`, and why the default asserts nothing

`latest` is a setting, and the default asserts nothing. The first two attempts were both wrong, and the reason is worth keeping.

The starting point -- publish each version under its own `latest` -- leaves a mirror pointing at whichever upload finished last, and copying several versions of one package is *ordinary* for npm rather than an edge case: a lock file names them, a user names them, and two different-looking ranges (`abc@>6`, `abc@>2`) may resolve to two versions.

The second attempt, `latest` = highest version the target holds, fixed the ordering and **invented a meaning**. `latest` is a publisher's editorial choice, not the maximum: `npm dist-tag add foo@1.9.5 latest` after a bad 2.0 is routine, so "correcting" it every time a copy touches the package is a silent override.

**The real objection is one this codebase had already made.** `dist-tags` is repository state -- the same shape as `maven-metadata.xml`, which `repo::maven` refuses to copy because doing so "would overwrite the target's true index with a claim about a *different* repository". Writing a computed `latest` is that mistake in another registry's vocabulary.

It is a setting rather than a flat refusal because of one disanalogy: a target **regenerates** `maven-metadata.xml`, so not copying it costs nothing, while nothing regenerates `dist-tags` -- a mirror with none may not answer `npm install NAME` at all. `DistTags` is `never` (default), `on-create`, or `highest`.

**The default is the safest, not the most convenient.** Asserting nothing fails *visibly* and an operator fixes it with one command; every other mode can write a tag that is wrong and looks right. `on-create` is not the default for the same reason the whole problem existed: several versions of a new package are created concurrently, so "the version that created it" may be the oldest.

Also worth knowing: npm publishes **no specification** requiring a publish to set `dist-tags`. The `npm` CLI always sends it, which is not the same thing, and this was treated as a requirement for two rounds before being checked.

An earlier note claimed npm requires a dist-tag, that a mirror filled in arbitrary order ends with `latest` on whatever was copied last, and that **copying in ascending version order** is what makes the result right. All three are wrong, and the note is recorded here only so the reasoning is not repeated: ordering the copy would fix the symptom by making the tool assert something it has no basis for.
