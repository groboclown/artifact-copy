# General Settings

References: [OSV schema](https://ossf.github.io/osv-schema/), [Sigstore](https://docs.sigstore.dev/), [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

Settings that apply whatever servers a configuration names: how files load, the `setup` section, the policy files, advisory screening, signing keys, and problem handling. Several of these decide what the tool trusts, so read the security notes before changing them.

The [schema](../schema/config.schema.json) is the authority. [examples/configuration/](../examples/configuration/) holds a worked example of every section.

## Loading configuration files

`--config=PATH` adds a file, or a directory whose `*.yaml` and `*.json` files (not sub-directories) load alphabetically. Repeat it to add more.

Every file must begin by naming the schema, exactly as written here; loading refuses a file without it. The examples in these guides leave the line out for brevity.

```yaml
$schema: https://github.com/groboclown/artifact-copy/schema/config.schema.json
```

**The first setting wins.** With `--config=a.yaml --config=b.yaml`, a `setup.log.level` in `a.yaml` beats the one in `b.yaml`. A wrapper script therefore cannot append a file that weakens a rule set earlier: put the file holding your organization's rules first.

`artifact-copy validate-config` loads everything, resolves every secret and kind, and reads every linked policy file, reporting all problems at once.

## Paths

A key that names a file says how a relative path resolves.

| Key | Relative to |
| --- | --- |
| `config-relative-path` | The directory holding the configuration file that declares it. |
| `working-dir-path` | The current working directory, following the `.env` convention. |
| `command` (extensions) | Neither: the operating system resolves it, so a bare `python3` comes from `PATH`. |

A path-bearing object takes one of `config-relative-path` and `working-dir-path`, never both. A plain path setting, such as `setup.cache-dir` or a policy file, is configuration-relative. Name an absolute path to pin any of them.

## Setup

`setup` holds run-wide defaults.

```yaml
setup:
  cache-dir: .cache/artifact-copy
  cache-retention: 30 days
  cache-size: 20 GiB
  log:
    level: info
    config-relative-path: artifact-copy.log
  thread-pool-size: 8
  license-policy: license-policy.yaml
  security-policy: security-policy.yaml
  quarantine-policy: quarantine-policy.yaml
  signing-policy: signing-policy.yaml
```

| Field | Default | Meaning |
| --- | --- | --- |
| `cache-dir` | `artifact-copy` under the system temporary directory | Where fetched files, advisory corpora, and temporary report databases live. |
| `cache-payloads` | `reuse` | `reuse` keeps a payload after it reaches every target; `discard` removes it, so a large migration does not keep a second copy on disk. |
| `cache-retention`, `cache-freshness`, `cache-size` | see [Cache](#cache) | Cache limits. |
| `log` | `warn` to standard error | See [Logging](#logging). |
| `thread-pool-size` | | Worker threads, 1 to 100. Host connection pools are separate. Accepted, but not yet read by a run. |
| `maximum-in-memory-download` | `64 MiB` | The largest response body held in memory, as a [byte size](configuration-server.md#units). Larger bodies stream to disk. |
| `maximum-in-memory-queued-dependencies` | `100000` | How many discovered dependencies a walk under `--db=-` holds before it prunes the rest and reports `spider-queue-full`. Other walks queue on disk. |
| `unknown-publish-time` | `refuse` | The default for every source. See [Publish time](configuration-server.md#publish-time). |
| `license-policy`, `security-policy`, `quarantine-policy`, `signing-policy` | none | Policy files. See [Policy files](#policy-files). |
| `harden-quarantine` | `false` | Make every soft quarantine hold its artifact back. `--harden` sets it for one run. |
| `keyservers` | empty | See [Signing keys](#signing-keys). |
| `sigstore-trusted-root` | fetched | See [Sigstore](#sigstore). |
| `server-kinds-dir` | none | A directory of custom server kinds. See [Writing Your Own Server Kind](custom-server-kinds.md). |

### Cache

A cached file has two age limits and an optional size cap.

- `cache-retention`: how long a file stays after its last use. Absent is forever.
- `cache-freshness`: how long after its fetch a file may be used before it is fetched again, as a list of `{files, fresh-for}` rules matched by file name. The first matching rule wins.
- `cache-size`: the most the whole cache directory may hold. Past it, the least recently used files go first, reported as `cache-entry-evicted`. A payload not yet published is never removed.

```yaml
setup:
  cache-retention: 30 days
  cache-freshness:
    - files: "maven-metadata.xml*"
      fresh-for: 15 minutes
  cache-size: 20 GiB
```

Freshness rules apply in this order: the source's or enumerator's own, then `setup`'s, then the built-in rules. The built-in rules keep inventory documents (`maven-metadata.xml*`, `index.html`, `packument.json`, `simple.html`, `detail.json`) an hour, `simple-index.json` a day, and every other file forever. An expired file is fetched again and reported as `cache-entry-expired`.

Each source and enumerator may set its own limits; see [Cache overrides](configuration-server.md#cache). `scripts/db-maintenance.py prune-cache` deletes files past their retention, and with `--max-size` shrinks a cache no run is using.

### Logging

`setup.log` sets the defaults for where and how a run logs:

```yaml
setup:
  log:
    level: info
    output-format: plain
    config-relative-path: logs/artifact-copy.log
```

| Field | Meaning |
| --- | --- |
| `level` | `trace`, `debug`, `info`, `warn` (the default), `error`, or `off`. |
| `output-format` | `ansi` (color and progress bars on a terminal), `plain`, or `json-stream` (one JSON object per line). |
| `config-relative-path` or `working-dir-path` | A file log lines are appended to, relative to the configuration file or to the working directory. Absent means standard error. |

The command line wins over the configuration:

- **Level:** the first level flag given (`--quiet`, `--verbose`, `--debug`, `--tracing`, `--unsafe-debug`), then `RUST_LOG`, then `level`, then `warn`. An unparsable `RUST_LOG` is ignored.
- **Destination:** `--log-file=FILE`, then this file, then standard error. `--log-file=-` writes to standard output, and is refused when the report goes there too. A stream can be chosen only on the command line.

Progress bars show for `ansi` output on a terminal at `warn` or more verbose; `--quiet`, `plain`, and `json-stream` show none.

`validate-config` does not apply `setup.log`; it checks the configuration rather than running with it.

**Splitting `setup.log` across files can fail.** Configuration files merge first-wins key by key, so a `config-relative-path` from one file and a `working-dir-path` from another both survive, and loading refuses the result. Keep `setup.log`'s file in one configuration file.

**Security:** `--unsafe-debug` logs everything, credentials included. Never use it where the output could leak.

### Sigstore

`sigstore-trusted-root` names a Sigstore `trusted_root.json` that PEP 740 attestations are checked against. Absent, the tool fetches Sigstore's current root from its TUF repository on first use and caches it. Set it for an air-gapped run, or one that must not reach Sigstore.

## Policy files

Configuration says what the rules are; policy files say which artifacts are exceptions. Keeping exceptions apart lets each one be reviewed on its own, carry a justification, and change on its own cadence.

| File | Decides | Schema | Example |
| --- | --- | --- | --- |
| License | Which licenses pass, and per-artifact license overrides. | [license-policy.schema.json](../schema/license-policy.schema.json) | [license-policy.yaml](../examples/configuration/license-policy.yaml) |
| Security | The organization-wide `malware` (`forbid`, the default, or `report`) and `vulnerabilities` (`report`, the default, or `forbid`) stances. | [security-policy.schema.json](../schema/security-policy.schema.json) | [security-policy.yaml](../examples/configuration/security-policy.yaml) |
| Quarantine | Per-artifact overrides of a problem code's class, in either direction, with a justification and expiry. | [quarantine-policy.schema.json](../schema/quarantine-policy.schema.json) | [quarantine-policy.yaml](../examples/configuration/quarantine-policy.yaml) |
| Signing | Which PGP keys vouch for which artifacts. | [signing-policy.schema.json](../schema/signing-policy.schema.json) | [signing-policy.yaml](../examples/configuration/signing-policy.yaml) |

Name each in `setup`. A [low-level host](configuration-low-level.md#hosts) may override any of them for its own artifacts, for a rule that applies to a public registry and not an internal one. Keep such overrides rare.

The security policy holds no per-artifact allowances. Those are VEX statements, passed with the request through `--lock`; see the main [readme](../README.md).

## Problem policy

`problem-policy` sets how each problem code is handled, for every artifact a run touches.

```yaml
problem-policy:
  signature-key-unvouched: hard
  signature-key-expired: allowed
  advisory-source-stale: soft
```

| Class | Effect |
| --- | --- |
| `allowed` | Record it and carry on. |
| `soft` | Take the artifact and flag it for review. |
| `hard` | Hold the artifact back, reviewably. |
| `failure` | Not up for review; it fails. |

A code left out keeps its built-in class. Codes are a closed set, so the schema catches a misspelling. Only codes about an artifact may be named: a fault in the run's own input, such as a configuration that will not load, always fails. Per-artifact exceptions belong in the quarantine policy, not here. The schema's `problem-policy` lists every code.

## Advisors

An `advisors` entry names a corpus of known vulnerabilities and malware. Each downloads its corpus once, caches it, and answers lookups locally. Screening happens only when at least one advisor is configured.

```yaml
advisors:
  osv:
    kind: osv-offline
    host: osv-bucket
    ttl: 12 hours
    ecosystems: [maven, pypi, npm]
  ossf:
    kind: ossf-malicious
    host: github-web
    ttl: 6 hours
```

| Field | Meaning |
| --- | --- |
| `kind` | `osv-offline` reads OSV's per-ecosystem `all.zip`, which covers vulnerabilities and the malware records OSV ingests. `ossf-malicious` reads the `ossf/malicious-packages` repository directly, because OSV ingestion can lag. Any other value names an extension. |
| `host` | A host to fetch from; its url replaces the published location, so a mirror is a host entry. OSV publishes at `https://osv-vulnerabilities.storage.googleapis.com/`. `ossf-malicious` reads `https://github.com/`, whose host must list `codeload.github.com` under `additional-hosts`. |
| `path` | A zip on disk to read instead of fetching, for an air-gapped run. A missing file fails rather than falling back to the network. |
| `ttl` | How long a cached corpus stays usable before a refresh. |
| `ecosystems` | Which ecosystems to screen. Empty means all. |
| `options` | `ossf-malicious` reads `repository` (default `ossf/malicious-packages`) and `branch` (default `main`). |

**Security:** when no corpus answers, the run reports `advisory-source-unavailable` and stops. A screening outage would otherwise look exactly like a clean run. `--no-advisories` or `problem-policy: {advisory-source-unavailable: allowed}` accepts that risk, and the report's `corpus-age` header records it. See [Reading Reports](reports.md).

## Signing keys

`signing-keys` pins public keys in configuration instead of fetching them from a registry. A [low-level host](configuration-low-level.md#hosts) names the keys its signatures are checked against; naming any replaces the registry's own key endpoint for that host. A key declared but never named grants no trust.

```yaml
signing-keys:
  npmjs-2022:
    scheme: npm-ecdsa
    key-id: SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA
    citation-url: https://docs.npmjs.com/about-registry-signatures
    expires: never
    value: { kind: env, name: NPM_SIGNING_KEY }
```

| Field | Meaning |
| --- | --- |
| `scheme` | `npm-ecdsa` or `pgp`. |
| `key-id` | The identifier a signature names: an npm `keyid`, or a PGP key id or fingerprint. |
| `value` | The public key, as a [secret value](configuration-server.md#secret-values). |
| `citation-url` | Where the key came from, for a reviewer. Never fetched. |
| `expires` | An RFC 3339 timestamp, or `never`, written out. A signature made later is reported. `validate-config` reports lapsed keys. |

`setup.keyservers` lists HKP keyservers to ask for PGP keys not pinned here, such as `https://keys.openpgp.org`. **It is empty by default, so nothing is fetched**: a key looked up to check a signature proves only that whoever holds it signed, not that it is the right key. A host may override the list. A fetched key vouches only where the signing policy names it.

## Transport security

Every network host verifies TLS certificates by default. A [low-level host](configuration-low-level.md#hosts) may set `tls-verify: false` for a private mirror with a self-signed certificate, on a network you trust. Without verification, anything that can intercept the connection can supply every checksum and signature the tool reads.

A plain `http://` url is refused when the configuration loads unless its host sets `insecure-transport: true`, which also covers the host's mirrors and keyservers. A server entry takes the same key and passes it to the host it generates. A [server kind you write](custom-server-kinds.md) may set it on its host, and the server entry's value replaces the kind's; no built-in kind sets it. `setup.keyservers` has no host to opt in on, so `http://` is always refused there. `validate-config` warns about each host that sets it. See [Security Assumptions](security.md).

## Secrets

Credentials are [secret values](configuration-server.md#secret-values): references to an environment variable, AWS Secrets Manager, or a property file.

- Prefer `env` or `aws-secret` over `text`, which puts the credential in the file.
- A `property-file` reads only its file, never the process environment, so the resolved value does not depend on whoever launched the run.
- Give each credential the least access its role needs: a `read` repository needs no write permission.

## Extensions

An `extensions` entry names a WASM module or an executable that supplies a source, target, enumerator, or advisor kind the tool does not build in. A configuration names it in `kind` exactly as it would a built-in. An entry takes `kind: wasm` and a `module` path, relative to the configuration file, or `kind: executable`, a `command`, and its `arguments`. Only a WASM source runs so far; every other extension is refused as `unimplemented`. See [Writing Your Own Extension](extensions.md) and the schema's `Extension` definition.

```yaml
extensions:
  nodejs-releases:
    kind: wasm
    module: extensions/nodejs_releases.wasm

sources:
  node:
    host: nodejs-org            # url: https://nodejs.org/dist/
    kind: nodejs-releases
    options:
      files: ["node-v*-linux-x64.tar.gz"]
```

The bundled extensions read a `files` option: name patterns with `*` and `?`, where a `!` pattern drops what it matches. Patterns apply in order and the last match decides, as in `.gitignore`; with no include pattern, every name not excluded is kept. `["amazon-corretto-*-linux-x64.tar.gz", "!*-alpine-*"]` keeps the Linux tarball and drops the Alpine one.

A WASM source reaches the network only through its source's `host`, under that host's constraints and credentials, and is granted no files or environment.

**Security:** an extension runs with the tool's own permissions and sees the data passed to it. Configure only extensions you trust.
