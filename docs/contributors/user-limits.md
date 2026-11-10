# Decisions That Limit Users

References: [PEP 658](https://peps.python.org/pep-0658/), [PEP 740](https://peps.python.org/pep-0740/), [TUF](https://theupdateframework.github.io/specification/latest/), [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

Each row is a decision that stops a user from doing something, where it lives in code, and what an option would look like. The reasoning stays in the linked file; this one exists so a future request for an option can find the decision quickly and weigh it.

Add a row whenever a change makes such a decision. The list was audited against the contributor documentation and the code on 2026-11-09; a decision no document states is not listed, since a row points at the reasoning.

## Spider

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Under `--db=-`, the dependency queue holds at most `setup.maximum-in-memory-queued-dependencies` (default `DEFAULT_QUEUE_LIMIT_TASKS`) and prunes past it | `commands::spider::MemoryFrontier` | Walking a graph wider than the cap without a report database | A command-line override for one run | [report-as-database.md](report-as-database.md#dependency-walks) |

## Maven

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Without an artifact enumeration, a snapshot copies its latest build only | `repo::maven::MavenSource::snapshot`, `metadata::Snapshot::value_for` | Migrating a snapshot's older timestamped builds by coordinate, or from a Maven layout with no catalog | A source option enumerating builds, for repositories with a listing API | [write-path.md](write-path.md#snapshots-and-their-builds) |
| The payload's `.asc` is always probed | `repo::maven::MavenSource::signature_files` | Avoiding one `HEAD` per artifact on a repository known to hold no signatures | A source option `signatures: probe \| skip` | [verification.md](verification.md#signatures-are-copied-and-checked-once-the-payload-is-staged) |
| No checksum is written beside a `.asc` | `repo::maven::target::MavenTarget::publish` | Serving `.asc.sha1` to a client that insists on one | Apply the target's `checksums` to signatures too | [verification.md](verification.md#sidecar-depth-stays-at-one-by-decision) |
| Sidecars stop at one level when reading | `repo::maven::sidecar` | Checking `.pom.asc.sha1` or `.pom.sha1.asc` | None planned; the decision argues it buys nothing | [verification.md](verification.md#sidecar-depth-stays-at-one-by-decision) |
| A source's `maven-metadata.xml` is never copied | `repo::maven::is_repository_managed`, `MavenTarget::check_name` | Copying an index verbatim | None planned; `metadata: merge` writes the target's own | [write-path.md](write-path.md#the-maven-target) |
| `metadata: merge` refuses an index whose `<versioning>` it cannot find cleanly | `repo::maven::metadata::merge_versions` | Merging into a document with the tag inside a comment or CDATA | Splice on the parsed document's positions rather than on the text | [write-path.md](write-path.md#the-maven-target) |
| A snapshot's version-level index is rendered from the published names | `repo::maven::metadata::render_snapshot` | Keeping anything but the builds in a target's version-level `maven-metadata.xml` | Splice as the artifact-level merge does | [write-path.md](write-path.md#snapshots-and-their-builds) |
| `<latest>` and `<release>` are the highest version | `repo::maven::metadata::merge_versions` | Keeping a publisher's chosen `release` | A `latest` setting shaped like npm's `dist-tags` | [write-path.md](write-path.md#dist-tags-and-why-the-default-asserts-nothing) |
| Only 400 and 409 read as "already written" | `repo::maven::target::ALREADY_WRITTEN` | Confirming a delivery on a server that refuses a redeploy another way | A target option naming the statuses | [write-path.md](write-path.md#the-maven-target) |
| A large file already written is confirmed only through the target's `.sha1` | `repo::maven::target::MavenTarget::already_holds` | Resuming onto a target that publishes no checksums | Fall back to downloading the stored file | [write-path.md](write-path.md#the-maven-target) |
| The payload's extension is the POM's packaging | `repo::maven::MavenSource::files_of`, `MavenTarget::exists` | Packaging whose file extension differs, such as `bundle` or `maven-plugin` | A packaging-to-extension table, per source | [write-path.md](write-path.md#the-maven-target) |
| A target holding an older snapshot build answers present | `repo::maven::target::MavenTarget::exists` | Refreshing a snapshot the target already has a build of | Compare the build the source resolved, once `Target::exists` is given it | [write-path.md](write-path.md#the-maven-target) |
| A target holding the payload answers present, whatever else it lacks | `repo::maven::target::MavenTarget::exists`, `commands::upload::run` | Adding a `.module` or classifier file to a version a target already holds | Ask per file rather than per artifact | [write-path.md](write-path.md#what-an-out-of-process-maven-target-would-need) |
| A request with no artifact enumeration through a plain `maven` source copies the POM and payload only | `repo::maven::MavenSource::files_of` | Copying classifier files or `.module` with `inspect` or `copy` by coordinate from a repository no `nexus`, `artifactory`, or `artifact-keeper` source fronts, and whose `maven` source does not set `file-listing: html-index` | Read Gradle's `.module` when the POM carries its marker, or probe named classifiers | [sources-and-targets.md](sources-and-targets.md#an-artifact-enumerations-file-listing-combined-with-a-resolution) |

## PyPI

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A `.tar.bz2` or `.tar.xz` sdist without a PEP 658 document uploads filename fields only | `repo::pypi::sdist::metadata` | Carrying such an sdist's `Requires-Python` and summary to the target | Read `PKG-INFO` through bzip2 and xz decoders, under the tar caps | [write-path.md](write-path.md#the-pypi-target) |
| A `.tar.gz` sdist inflating past 1 GiB fails the upload | `repo::pypi::sdist::MAX_INFLATED` | Copying a very large sdist without a PEP 658 document | A configurable cap | [write-path.md](write-path.md#the-pypi-target) |
| Uploads go under `host-path` | `repo::pypi::target::upload_url` | Publishing to an index with a separate upload host, such as `upload.pypi.org` | An upload host of its own, with its own credentials | [write-path.md](write-path.md#the-pypi-target) |
| A PEP 740 publisher kind other than GitHub, GitLab, and Google is not identity-checked | `repo::pypi::attestation::signed_by` | Confirming an ActiveState-published file came from its publisher | An identity rule per kind, as `pypi-attestations` adds them | [verification.md](verification.md#attestations-are-verified-once-the-file-is-staged) |
| The Sigstore TUF fetch bypasses the configured hosts | `net::sig::sigstore::SigstoreRoot` | Routing it through a proxy, TLS setting, or allow-list | Fetch TUF metadata through a configured host; until then, `setup.sigstore-trusted-root` | [verification.md](verification.md#attestations-are-verified-once-the-file-is-staged) |
| `inspect` does not verify PEP 740 attestations | `repo::pypi::PyPiSource::verify` | Learning an attestation is bad before a copy | Fetch and check provenance at resolution, one request per file | [verification.md](verification.md#attestations-are-verified-once-the-file-is-staged) |
| A legacy distribution's `pyversion` is guessed from its name | `repo::pypi::target::classify` | Exact interpreter tags for `.exe`/`.msi` under `legacy-dists: guess` | Read the tag from the distribution | [write-path.md](write-path.md#legacy-distributions) |
| `pypi-simple` lists project names only, with no version and last download always unknown | `repo::pypi::enumerator::PyPiEnumerator` | Choosing artifacts by disuse, or recording versions, from a walk of a PEP 691 index | None planned; the index carries neither, and an invented version would be worse than none | [wiring.md](wiring.md#inspect-and-find) |

## Hosts

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| An additional `hostname` is reached over `https` only | `session::anonymous_prefix` | Reading from a plain-http host without declaring it | None needed: a `{host: name}` entry states its own scheme | [wiring.md](wiring.md#additional-hosts-a-second-host-a-hosts-reads-may-reach) |
| Additional hosts serve reads only | `ext::HostedExt::route` | A target publishing files to a second host | Route writes too | [wiring.md](wiring.md#additional-hosts-a-second-host-a-hosts-reads-may-reach) |
| A write follows a redirect only inside its prefix, and only for 307 or 308 | `ext::HostedExt::next` | A registry redirecting uploads to another host | Name the upload host as the target's own host | [wiring.md](wiring.md#redirects) |

## Enumerator listings

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A file only the source names is never a mismatch | `repo::inventory::combine` | Catching a source that names a file its catalog lacks, before the fetch fails | Record when a listing was complete, per artifact | [sources-and-targets.md](sources-and-targets.md#the-combination-rule) |
| A URL is never compared | `repo::inventory::combine` | Noticing a catalog that serves a file from somewhere unexpected | A setting that treats a host difference as a mismatch | [sources-and-targets.md](sources-and-targets.md#the-combination-rule) |
| A listing alone is never copied | `repo::InventorySource::metadata` | Copying from a report when the source cannot resolve the artifact | None planned; the source's checks would be skipped | [sources-and-targets.md](sources-and-targets.md#the-combination-rule) |
| Raw listings are unfiltered | `ecosystem::joins_listing` | Leaving a raw repository's `.sha1` files behind | A per-source filter; see the filter proxy enumerator in `TODO.md` | [sources-and-targets.md](sources-and-targets.md#what-a-listing-holds) |

## Local directories

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Under `symlinks: as-file`, the default, a link is copied as a file holding its target text | `net::emulate::fs::Root::open`, `Root::link` | Restoring a link as a link | A target that writes a link back, for a source that says one is | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |
| Under `symlinks: within-root`, a link resolving outside the directory is skipped and reported | `net::emulate::fs::Root::link` | Reading a file a link points to elsewhere | `symlinks: follow` | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |
| The generic listing is not paged, and the enumerator lists the whole repository for each page | `net::emulate::generic::answer`, `repo::local_dir::enumerator` | Walking a very large directory without holding its listing in memory | A cursor carrying the last path returned | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |
| Last download is always unknown | `repo::local_dir::LocalDirEnumerator` | Choosing artifacts by disuse in a directory | Read access times, where the filesystem records them reliably | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |
| A file's modification time stands for its publish time | `net::emulate::generic::Item::modified` | A publish window that ignores a later `touch` or copy | None planned; a directory records nothing closer | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |
| A name that is not UTF-8 is skipped and reported | `net::emulate::fs::Root::descend` | Copying such a file | Carry the name percent-encoded through the listing | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |
| A `file://` host refuses `tls-verify`, timeouts, `retry`, `authentication`, and `additional-hosts` | `session::local_settings` | Nothing a directory can use | None planned | [sources-and-targets.md](sources-and-targets.md#a-local-directory) |

## npm

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| The origin's `dist.signatures`, `npm-signature`, and `attestations` are stripped from a published manifest | `repo::npm::manifest::cleaned`, `repo::npm::manifest::ORIGIN_DIST` | Carrying a package's registry signatures or provenance attestations to a mirror | None planned; they would not verify against the mirror | [write-path.md](write-path.md#the-version-object-is-the-origins-manifest) |
| A publish only ever sets `latest`, and the source's other `dist-tags` are never carried | `repo::npm::publish::DIST_TAG`, `repo::npm::target::NpmTarget::latest_after` | Carrying `next`, `beta`, or a publisher's pinned `latest` from the origin to a mirror | None planned; `dist-tags` is the target's state, as `maven-metadata.xml` is | [write-path.md](write-path.md#dist-tags-and-why-the-default-asserts-nothing) |
| The tarball tier does not reproduce the README or the `directories.bin` expansion `npm publish` does | `repo::npm::manifest::from_tarball` | A mirror serving the README and expanded `bin` when the source staged no version document | Reproduce `npm publish`'s client-side steps in the tarball tier | [write-path.md](write-path.md#the-version-object-is-the-origins-manifest) |
| A registry key's expiry is judged against the clock, so a signature made before the key expired reads as untrusted | `net::sig::npm::verify_npm` | Verifying an older version signed by a key that has since been retired | None planned; `dist.signatures` carry no creation time | [verification.md](verification.md#keys-expiry-and-revocation) |

## GitHub releases

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A source only; there is no target | `repo::github::KINDS` | Publishing copied artifacts as GitHub release assets | None planned; a release is created by a project's own process | [sources-and-targets.md](sources-and-targets.md#github-releases) |
| `repositories` is required, and an entry may not put `*` in the owner | `repo::github::allowed::Allowed::read`, `repo::github::allowed::entry` | Reading any public repository without listing it, or trusting every owner a pattern matches | None planned; trust is granted per owner | [sources-and-targets.md](sources-and-targets.md#github-releases) |
| A release is a raw artifact, so only a raw target accepts it | `repo::github::source::GitHubSource::ecosystem` | Copying a release's jar or wheel into a Maven, npm, or PyPI target | A mapping from release assets to another ecosystem's coordinates | [sources-and-targets.md](sources-and-targets.md#github-releases) |
| A request more than one `names` rule admits is refused, not settled by rule order | `repo::github::source::GitHubSource::sourced` | Overlapping rules where the first one listed wins | None planned; which repository a release comes from is not to be guessed | [sources-and-targets.md](sources-and-targets.md#github-releases) |
| Without a `version-handler`, a range is refused | `repo::github::source::GitHubSource::chosen_release` | Asking for `^1.0` against a repository's tags | None needed: `version-handler` declares the tags' order | [sources-and-targets.md](sources-and-targets.md#github-releases) |
| Without a `version-handler`, a release inside the publish window is refused, not stepped down to an older tag | `repo::github::source::check_window` | Taking the newest release outside the window when the latest is too recent | None needed: under `version-handler` the standard step-down loop runs | [resolution.md](resolution.md#the-github-override-had-to-narrow-first) |

## Extensions

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A WASM module gets WASI with no files, environment, or arguments; its only way out is `host_call` | `ext::gear::wasm::Runtime::store` | An extension reading its own data file, a token from the environment, or arguments | None planned; this is the sandbox | [extensions.md](extensions.md#wasm) |
| Each message runs in a fresh store and instance | `ext::gear::wasm::Runtime::exchange` | An extension caching what it fetched from one `versions` or `metadata` call to the next | None planned; calls are stateless by principle | [extensions.md](extensions.md#extension-mechanism-sandbox) |
| Memory (256 MiB), fuel per message, message size (32 MiB), and a `fetch` body (16 MiB) are fixed | `ext::gear::wasm::MAX_MEMORY_BYTES`, `MAX_FUEL_PER_CALL`, `MAX_MESSAGE_BYTES`, `ext::gear::host::MAX_FETCH_BYTES` | An extension reading a larger index document, or needing more memory or work | A per-extension setting raising the caps | [extensions.md](extensions.md#wasm) |
| An extension source's version scheme is the one it declares | `repo::scheme::version_scheme` | Setting `version-handler` on an extension kind | None planned; a refused setting is visible, an ignored one is not | [extensions.md](extensions.md#wasm) |

## Raw repositories

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A raw target takes raw artifacts only | `repo::sole_ecosystem`, called by each raw target's `ecosystem` | Copying a Maven, npm, or PyPI artifact into a generic or raw repository | A declared layout per ecosystem, configured on the target | [sources-and-targets.md](sources-and-targets.md#raw-and-generic-repositories) |
| A file whose path does not read back as its artifact refuses the whole artifact before anything is written | `repo::artifact_keeper::target::ArtifactKeeperGenericTarget::path_for`, `repo::nexus::target::NexusRawTarget::place`, `repo::artifactory::target::ArtifactoryGenericTarget::path_for` | Writing a file name holding a separator, a `name-version-file` artifact with no version, or several `as-is` files onto one path | None planned; the next enumeration would file the copy under another artifact | [sources-and-targets.md](sources-and-targets.md#writing-an-artifact-keeper-generic-repository) |
| A path holding different bytes is refused, never deleted to make room; under `overwrite-guard: server`, a server that overwrites decides | `repo::OverwriteGuard`, `repo::artifact_keeper::target::ArtifactKeeperGenericTarget::conflict`, `repo::nexus::target::conflict` | Refreshing a raw file whose bytes changed at the source, such as a republished "latest", on a server that refuses rewrites | A versioned Artifact Keeper repository, or an overwriting server, under `overwrite-guard: server` | [sources-and-targets.md](sources-and-targets.md#a-path-is-written-once) |
| A raw target answers present when any file of the artifact is there | `repo::artifact_keeper::ArtifactKeeperGenericTarget::exists`, `repo::nexus::NexusRawTarget::exists`, `repo::artifactory::target::ArtifactoryGenericTarget::exists` | Completing a half-written directory without the report's transfer claims | Compare against the source's file list once `Target::exists` is given the artifact | [sources-and-targets.md](sources-and-targets.md#asking-whether-an-artifact-is-there) |

## Repository managers

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Server files the protocol source does not name are added only for a whole Maven release | `repo::manager::source::unnamed` | Carrying a snapshot's classifier files, or a server's extra npm or PyPI assets, through a `nexus`, `artifactory`, or `artifact-keeper` source | None planned; the protocol source chose the snapshot build and lists every distribution | [sources-and-targets.md](sources-and-targets.md#repository-manager-sources) |
| A repeated Nexus asset field other than `lastDownloaded` fails the components page | `repo::nexus::enumerator::component::Asset` | Walking a Nexus that repeats another key with `find` | The same folding for the next quirk, once it is seen | [sources-and-targets.md](sources-and-targets.md#nexus-repeats-lastdownloaded) |

## Copy and publish

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Several targets are published in sequence, in `--to` order, for each artifact | `commands::copy::Copying::publish_legs` | Publishing one artifact to several targets at once | Concurrent publishing per artifact, under a memory bound | [several-targets.md](several-targets.md#decisions) |
| Configured `omit` rules only omit more | `repo::Omit::file` | Copying a checksum sidecar or Maven's `_remote.repositories` as an ordinary file | None planned; a target writes those for itself | [sources-and-targets.md](sources-and-targets.md#omitting-files-and-artifacts) |
| An omission removes files and never stops a source from reading a document | `repo::omit::source::OmittingSource::metadata` | Stopping the Maven source from fetching a POM or `maven-metadata.xml` by omitting it | None planned; omission decides what an artifact has, not what is read | [sources-and-targets.md](sources-and-targets.md#omitting-files-and-artifacts) |

## Proxies

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A proxy moves to the next upstream only on `artifact-not-found` or `host-unreachable` | `repo::proxy::is_answerable_elsewhere` | Falling back to a mirror when the primary serves malformed metadata or bad bytes | None planned; falling through would hide a broken primary | [sources-and-targets.md](sources-and-targets.md#what-proxy-failover-settles-that-the-next-proxy-should-reconsider-rather-than-copy) |
| Each answer from `proxy-failover` may come from a different upstream | `repo::proxy::Failover` | Guaranteeing that one artifact's versions and files come from one upstream | A different proxy design; not a cache added to this one | [sources-and-targets.md](sources-and-targets.md#what-proxy-failover-settles-that-the-next-proxy-should-reconsider-rather-than-copy) |
| A failover enumerator moves to the next upstream only before the first page | `repo::proxy::enumerator::Failover::page` | Finishing a walk from a standby after the primary fails partway | None planned; restarting would report the catalog twice | [sources-and-targets.md](sources-and-targets.md#two-rules-the-enumerator-side-needs-and-the-source-side-does-not) |
| Failover is the only proxy enumerator | `repo::proxy::enumerator::proxy_enumerator_kinds` | Walking the union of two repositories' catalogs in one `find` | None planned; join two reports and use the joined report | [sources-and-targets.md](sources-and-targets.md#merging-belongs-on-the-source-side) |
| A `ref` in `proxy-to` may not name another proxy | `repo::sources::Sources::referenced` | Sharing one named proxy between proxies by reference | None needed: write the inner proxy inline under `source` | [sources-and-targets.md](sources-and-targets.md#configuration) |
| Proxy kinds are built-in only | `repo::proxy::proxy_source_kinds`, `repo::proxy::enumerator::proxy_enumerator_kinds` | An extension kind configured as a proxy | None planned; an embedder can compose proxies in code | [sources-and-targets.md](sources-and-targets.md#configuration) |

## Versions and resolution

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Resolution steps down through at most 8 candidates looking for one outside the publish window | `repo::resolve::MAX_STEP_DOWN` | Resolving the newest acceptable version when more than 8 recent releases are inside the window or lack a publish time | A per-source or command-line step-down limit | [resolution.md](resolution.md#the-publish-window-cannot-be-applied-at-selection-time) |
| `version-handler` is refused on a source kind whose ecosystem fixes the ordering | `cli::subcmd::validate_config::check_version_handler`, `repo::version_scheme` | Overriding how npm, Maven, or PyPI versions sort | None planned; a disagreeing setting is wrong, and ignoring it would be worse | [versions.md](versions.md#only-a-repository-whose-contents-decide-may-declare-one) |
| Version handlers are a closed set: `semver`, `maven`, `pep440`, `tags` | `version::open` | A custom version ordering through configuration or an extension | None planned; an embedder supplies an `Ecosystem` | [versions.md](versions.md#what-it-buys) |
| Pre-releases are admitted only by `--pre-release`, never by a source's configuration or a quarantine rule | `repo::Criteria::pre_release`, `repo::criteria_for` | Letting pre-releases in for one source, or one artifact such as `2.15.0-rc1` | None planned; it is a statement about the request | [resolution.md](resolution.md#what-it-does-not-excuse) |
| `publish-too-recent` and `publish-time-unknown` share a code, so a rule excusing one excuses both | `core::problem::Code::PublishTooRecent` | Excusing a too-recent window while still refusing an unknown publish time | Split the code, as `signature-invalid` was; not warranted while the action is the same | [resolution.md](resolution.md#what-it-does-not-excuse) |
| A proxy's own publish window applies; its upstreams' windows are never consulted | `repo::criteria_for` | Keeping a stricter upstream window when reading through a proxy | None planned; a test pins it | [resolution.md](resolution.md#how-the-criteria-are-assembled) |

## Dependencies

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| `build` joins any walk that follows anything | `commands::spider::SpiderSpec::resolve` | Following `runtime` alone without parent POMs and imported BOMs | None planned; a consumer's build needs them | [resolution.md](resolution.md#maven-parents-and-imported-boms) |
| A dependency kind is followed whole; conditions in a package (PyPI markers other than `extra`, npm `os` and `cpu`, Maven profiles) are not evaluated | `commands::spider::SpiderSpec::resolve`, `repo::pypi::metadata::dependency` | Following only one platform's optional dependencies, or one named extra | None planned; an `omit` rule leaves out what is not wanted | [configuration-server.md](../configuration-server.md#dependencies) |
| Asking for a kind an ecosystem lacks stops the run | `commands::spider::Spider::wanted_kinds` | `--dependencies=runtime+test` against a manager serving npm beside Maven | Narrow to the kinds each ecosystem has | [configuration-server.md](../configuration-server.md#dependencies) |

## Screening

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Malware is recognized only by a `MAL-` prefix on the id or an alias | `advisory::osv::Advisory::is_malware` | Treating another feed's malware advisories as `malware-known` rather than `vulnerability-known` | A per-advisor list of malware id prefixes | [advisories.md](advisories.md#the-record-shape) |
| A corpus archive is capped per entry (16 MiB), in total (4 GiB), and in entries (4,000,000), and reaching a cap fails the load | `advisory::archive::ENTRY_LIMIT`, `CORPUS_LIMIT`, `ENTRY_COUNT_LIMIT` | Screening against a corpus that grows past a cap | Configurable caps, per advisor | [advisories.md](advisories.md#reading-an-archive) |
| A supplied corpus (`path`) must be a zip, and a missing file fails rather than falling back to the network | `advisory::archive::local`, `OsvOffline::from_file`, `OssfMalicious::from_file` | Pointing an advisor at a `git clone`, or using `path` as a preferred copy with a download fallback | Read a directory tree; no fallback is planned | [advisories.md](advisories.md#a-corpus-the-user-supplies) |
| VEX statements arrive only as `--lock` documents; the security policy holds only the `malware` and `vulnerabilities` stances | `policy::security::SecurityPolicy`, `lock::bom::BomReader` | A lasting suppression for one artifact in configuration, and suppressions in `find`, which takes no `--lock` | None planned; request-scoped statements are what make staleness detectable | [advisories.md](advisories.md#vex-documents-belong-with-the-lock-files) |
| A CycloneDX document is read whole: the subject and every component become requests | `lock::bom::BomReader::read` | Using an SBOM for its VEX statements without requesting its subject and internal packages | Artifact filters; see *Artifact filters* in `TODO.md` | [advisories.md](advisories.md#vex-documents-belong-with-the-lock-files) |

## Policies

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A host's own license or signing policy replaces `setup`'s rather than layering on it | `session::Session::licenses_for`, `repo::sources::Sources::signing` | Adding a few host-specific rules on top of the organization-wide policy without copying it | None planned; half a policy from each file is a decision nobody wrote | [licensing.md](licensing.md#per-source-not-per-run) |
| A quarantine rule must name its codes; nothing covers every code for an artifact | `policy::quarantine::Rule::codes` | Acknowledging an artifact wholesale in one entry | None planned; excusing a missing signature should not also excuse a malware finding | [quarantine.md](quarantine.md#user-configuration) |

## Signatures

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Any revocation disqualifies a PGP key; the revocation reason is not read | `net::sig::pgp::untrustworthy` | Accepting signatures made before a `key-retired` revocation | Compare each signature's time against the revocation's, by reason code | [verification.md](verification.md#keys-expiry-and-revocation) |
| A key fetched from a keyserver vouches for nothing until a signing-policy rule names its fingerprint | `policy::signing::SigningPolicy::vouches` | Getting verified signatures from keyservers alone, without a signing policy | None planned; a keyserver supplies material, not trust | [verification.md](verification.md#which-key-may-vouch-for-what) |
| The signing policy covers Maven's detached PGP signatures only | `repo::maven::sidecar::vouched` | Limiting which npm registry keys or PyPI publishers may vouch for an artifact | Signing-policy rules for npm keys and attestation identities | [verification.md](verification.md#which-key-may-vouch-for-what) |
| A keyserver is reached anonymously, with default TLS and retry | `session::Hosts::keyserving` | An authenticated keyserver, one with a private CA, or custom retry or timeouts | Keyserver settings shaped like a host's | [verification.md](verification.md#keys-expiry-and-revocation) |

## Transport and retry

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A plain `http://` url is refused at load unless its host sets `insecure-transport`, and always in `setup.keyservers` | `config::transport::refused` | Plain HTTP without an explicit opt-in, and a plain-HTTP keyserver in `setup` | None planned for hosts; list such a keyserver under a host that sets `insecure-transport` | [configuration-general.md](../configuration-general.md#transport-security) |
| A status no rule names never retries | `net::retry::plan::Plan::rule_for` | Retrying a 401 or 404 by default | Name the status in `on-status` | [configuration-server.md](../configuration-server.md#choosing-the-rule) |

## Configuration and logging

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| Configuration files merge first-wins, key by key; a list is taken whole from the first file that has it | `cli::config::merge_first_wins` | A later file adding to an earlier file's list, or splitting `setup.log` between files using different path keys | None planned | [logging.md](logging.md#known-limits) |
| The first level flag on the command line wins | `cli::logging::first_flag` | Overriding an earlier `--quiet` from an alias or wrapper with a later `--verbose` | Last flag wins | [logging.md](logging.md#levels) |
| `--log-file=-` is refused when the report also goes to standard output | `cli::logging::Arguments::read` | Sending log lines and the report to one standard output | None planned; mixed lines would parse as neither | [logging.md](logging.md#destination-and-format) |

## Reports and cache

| Decision | Code | What it prevents | Possible option | Background |
| --- | --- | --- | --- | --- |
| A sampled `find` never sets `reached_end`, so it never dates an inventory | `report::sink::Enumeration::reached_end`, `report::db::enumeration::last_complete` | Using a sampled walk to narrow the next `find` by date | None planned; it would lose artifacts quietly | [report-as-database.md](report-as-database.md#what-the-database-finder-needs-up-front) |
| A report-fed run takes versions from the inventory, never ones the repository gained since | `repo::InventorySource::versions` | A `--from-db` copy picking up newly published versions | None planned; run `find` again | [report-as-database.md](report-as-database.md#what-the-database-finder-needs-up-front) |
| Dependencies are never answered from the report database | `repo::InventorySource::deps` | Following dependencies from a report alone | Store forward dependency edges | [report-as-database.md](report-as-database.md#what-the-database-finder-needs-up-front) |
| A cached payload is reused only when a declared digest proves it | `repo::download::cached` | Reusing a cached file for which the source declares no digest | None planned; complete is not current | [report-as-database.md](report-as-database.md#decisions) |
| A size cap never evicts a file the run still holds, so a run can stay over its cap | `ext::cache::Cache::trim`, `ext::cache::Budget::trim` | Enforcing `cache-size` as a hard disk limit during a large run | None planned; a held file is still needed | [report-as-database.md](report-as-database.md#decisions) |
