# Security Assumptions

What artifact-copy protects against, and what it leaves to you.

## The split

**You are responsible for the servers you configure.** The tool copies what a source serves and believes what its metadata says, within the checks below. It cannot tell a compromised repository manager from a healthy one that serves the same bytes, and it does not try.

**The tool is responsible for doing no harm with what it downloads.** It reads artifacts as data, never runs them, bounds every read, and refuses to pass on bytes that fail their checks.

## What the tool guards against

- **Tampered bytes.** Each file is checked against the digests its source declares; a mismatch stops the run (`checksum-mismatch`, `size-mismatch`). A `problem-policy` entry or a quarantine rule can lower these codes, even to `allowed`, so review those files for such entries. A file checked only against MD5 or SHA-1 is recorded as `weak-digest-only` in the report. Signatures are verified where the ecosystem has them: see [Signing keys](configuration-general.md#signing-keys).
- **Known-bad artifacts.** With an advisor configured, artifacts are screened for known malware and vulnerabilities, and a screening outage stops the run rather than passing everything as clean. See [Screening](../README.md#screening).
- **Too-new releases.** A publish window holds back versions younger than you allow, the usual window for a compromised release to be found. See [Publish time](configuration-server.md#publish-time).
- **Credentials leaking to other hosts.** Requests never follow a redirect on their own: each hop is checked against the hosts the configuration allows, and a host's credentials go only to that host, unless an `additional-hosts` entry says `inherit-parent-authentication`. Mirrors are always asked anonymously. A source is confined to its own repository's path, not the whole server.
- **Hostile archives.** Reading metadata out of a wheel, sdist, or npm tarball, or loading an advisory corpus, is capped in entries and inflated size, so a decompression bomb fails as malformed rather than filling memory or disk. Every response read into memory, such as an index or a metadata document, is capped as it streams, whatever its `Content-Length` claims (`download-too-large`). Payloads stream to disk.
- **Writing outside a local directory.** The `local-directory` target refuses a path with an empty, `.`, or `..` segment, and never replaces an existing file.
- **Silent overwrites.** A written path is not replaced; see `overwrite-guard` in [Raw repositories](configuration-raw.md#overwrite-guard).
- **Extensions.** A WASM extension runs with no WASI capabilities, a fresh instance per message, and capped memory and work. It names files; the tool downloads and checks them. See [Extensions](extensions.md).
- **Secrets in logs.** Secrets are redacted in every log level except `--unsafe-debug`, which logs everything; never use it where its output could leak.
- **A configuration file weakening another.** Configuration loads first-wins, so a file added later cannot override a setting an earlier one made. See [Loading configuration files](configuration-general.md#loading-configuration-files).

## What the tool assumes

- **The configured servers are the ones you meant.** TLS verification is on by default and proves you reached the named host, not that the host is trustworthy.
- **Plain HTTP is a decision.** An `http://` url is refused unless its host sets `insecure-transport: true` (a server entry, or a server kind you write, may set it for the host it generates; the built-in kinds never do). Over plain HTTP, anything on the network path sees every credential sent and can supply every checksum and signature the tool then checks against, so set it only on a network you trust. `validate-config` names each host that sets it. A keyserver in `setup.keyservers` has no host to opt in on, so plain HTTP is always refused there.
- **`tls-verify: false` is a decision too.** It accepts any certificate, with the same consequence as plain HTTP. Use it only for a private mirror with a self-signed certificate. See [Transport security](configuration-general.md#transport-security).
- **The machine running the tool is trusted.** The cache directory holds downloaded payloads, and the report database records what was copied and why. Secrets are read from the environment, files, or AWS at run time; protect those as you would the credentials themselves.
- **Policy files are reviewed.** License, security, quarantine, and signing policies decide what is copied. A quarantine rule can wave an artifact through; keep those files under review like code.
- **Copied artifacts are not made safe.** Screening finds what advisories already know. An artifact the tool copies is as trustworthy as its source and the advisories it was checked against, and no more.
