# References

The external definitions this tool implements or reads, each listed once. Code and documentation that rely on one cite it by link; this page is the index. Where a machine-readable definition may be redistributed, a pinned copy is in [`external/`](../external/README.md).

The license column is the license of the definition itself, where its publisher states one. "Not stated" means the publisher's repository declares none; consult the publisher before copying from it.

## Python packaging

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [PEP 440](https://peps.python.org/pep-0440/), now [Version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/) | final | Version ordering and specifiers: `src/version/pep440.rs` | Public domain (PEP) |
| [PEP 503](https://peps.python.org/pep-0503/), now [Simple repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/) | final | The HTML simple index and name normalization: `src/repo/pypi/pep503.rs` | Public domain (PEP) |
| [PEP 508](https://peps.python.org/pep-0508/), now [Dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) | final | `Requires-Dist` and markers: `src/repo/pypi/metadata.rs` | Public domain (PEP) |
| [PEP 566](https://peps.python.org/pep-0566/), now [Core metadata](https://packaging.python.org/en/latest/specifications/core-metadata/) | current | `METADATA` and `PKG-INFO` fields: `src/repo/pypi/metadata.rs`, `src/repo/pypi/core_metadata.rs` | Public domain (PEP) |
| [PEP 625](https://peps.python.org/pep-0625/) | final | Source distribution file names: `src/repo/pypi/sdist.rs` | Public domain (PEP) |
| [PEP 639](https://peps.python.org/pep-0639/) | final | `license_expression` from the JSON API: `src/repo/pypi/detail.rs` | Public domain (PEP) |
| [PEP 658](https://peps.python.org/pep-0658/) and [PEP 714](https://peps.python.org/pep-0714/) | final | Core metadata served beside a file: `src/repo/pypi/simple.rs` | Public domain (PEP) |
| [PEP 691](https://peps.python.org/pep-0691/) | final | The JSON simple index: `src/repo/pypi/simple.rs` | Public domain (PEP) |
| [PEP 700](https://peps.python.org/pep-0700/) | final | `versions`, `size`, and `upload-time` in the simple index | Public domain (PEP) |
| [PEP 735](https://peps.python.org/pep-0735/) | final | Dependency groups, which never reach an index and are not read: `src/ecosystem/pypi.rs` | Public domain (PEP) |
| [PEP 740](https://peps.python.org/pep-0740/), now [Index-hosted attestations](https://packaging.python.org/en/latest/specifications/index-hosted-attestations/) | final | Provenance and attestations: `src/repo/pypi/attestation.rs` | Public domain (PEP) |
| [PyPI upload API](https://docs.pypi.org/api/upload/) | current | The legacy upload form: `src/repo/pypi/target.rs` | Not stated |

## npm

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md) | current | Packuments, version documents, and publish: `src/repo/npm/` | Not stated |
| [package.json](https://docs.npmjs.com/cli/configuring-npm/package-json) | current | Manifest fields: `src/repo/npm/` | Not stated |
| [package-lock.json](https://docs.npmjs.com/cli/configuring-npm/package-lock-json) and [yarn.lock](https://classic.yarnpkg.com/lang/en/docs/yarn-lock/) | current | `--lock` readers: `src/lock/npm.rs` | Not stated |
| [Registry signatures](https://docs.npmjs.com/about-registry-signatures) | current | ECDSA signatures: `src/net/sig/npm.rs` | Not stated |
| [node-semver](https://github.com/npm/node-semver) | current | Range syntax and ordering: `src/version/` | ISC |

## Maven

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [Repository layout](https://maven.apache.org/repositories/layout.html) | current | Paths of artifacts: `src/repo/maven/` | Not stated |
| [Repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html) | 1.1.0 (`modelVersion`) | `maven-metadata.xml`: `src/repo/maven/metadata.rs` | Not stated |
| [POM reference](https://maven.apache.org/pom.html) | 4.0.0 | Dependencies, parents, and imports: `src/repo/maven/effective.rs` | Not stated |
| [ComparableVersion](https://maven.apache.org/ref/current/maven-artifact/apidocs/org/apache/maven/artifact/versioning/ComparableVersion.html) | current | Version ordering: `src/version/` | Not stated |
| [Ivy file](https://ant.apache.org/ivy/history/latest-milestone/ivyfile.html) | current | Artifactory `ivy` repositories, read as files: `src/repo/artifactory/raw.rs` | Not stated |

## Repository managers

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [Nexus REST APIs](https://help.sonatype.com/en/rest-apis.html) | 3.96.3 and 3.98.0 Community, measured | `src/repo/nexus/`; generated locally by `scripts/fetch-external.sh --nexus-url` | Sonatype EULA |
| [Artifactory repository management](https://docs.jfrog.com/artifactory/docs/repository-management-overview) and [AQL](https://docs.jfrog.com/artifactory/docs/artifactory-query-language) | OSS 7.161.26, measured | `src/repo/artifactory/` | Not stated |
| [Artifact Keeper](https://artifactkeeper.com/docs/) | 1.9 measured; OpenAPI from 1.11.12 | `src/repo/artifact_keeper/`; OpenAPI in [`external/artifact-keeper/`](../external/artifact-keeper/) | MIT |

## Advisories and SBOMs

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [OSV schema](https://ossf.github.io/osv-schema/) | current | Advisory records: `src/advisory/osv.rs`; schema in [`external/osv/`](../external/osv/) | Apache-2.0 |
| [OSSF malicious packages](https://github.com/ossf/malicious-packages) | current | Malware corpus: `src/advisory/ossf_malicious.rs` | Apache-2.0 |
| [GitHub advisory database](https://github.com/github/advisory-database) | current | `GHSA` identifiers in OSV records | CC-BY-4.0 |
| [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | v0.2.0 | VEX statements: `src/policy/vex.rs`, `src/lock/bom.rs`; schema in [`external/openvex/`](../external/openvex/) | CC0-1.0 |
| [CycloneDX](https://cyclonedx.org/specification/overview/) | JSON; 1.6 schema copied | SBOM and VEX documents: `src/lock/bom.rs`, `src/policy/vex.rs`; schema in [`external/cyclonedx/`](../external/cyclonedx/) | Apache-2.0 |
| [CVSS](https://www.first.org/cvss/) | current | OSV `severity` scores, which are not yet read | Not stated |

## Identifiers and licenses

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [Package URL](https://github.com/package-url/purl-spec) | current | Every artifact identifier: `src/internal/purl.rs` | Not stated |
| [SPDX license expressions](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/) and the [license list](https://spdx.org/licenses/) | 2.3 | License policy: `src/policy/license.rs` | Not stated |
| [Semantic Versioning](https://semver.org/) | 2.0.0 | npm and generic version ordering: `src/version/` | Not stated |

## Signatures

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [OpenPGP, RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) | RFC 9580 | Detached signatures: `src/net/sig/` | IETF Trust |
| [Sigstore](https://docs.sigstore.dev/) and its [protobuf specs](https://github.com/sigstore/protobuf-specs) | current | PEP 740 attestations: `src/net/sig/sigstore.rs` | Apache-2.0 (specs) |
| [The Update Framework](https://theupdateframework.github.io/specification/latest/) | current | Sigstore's trusted root, fetched through TUF: `src/net/sig/sigstore.rs` | Not stated |

## Protocols and formats

| Definition | Version | Used for | License |
| --- | --- | --- | --- |
| [RFC 9110, HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110) | RFC 9110 | Status codes and `Retry-After`: `src/net/retry/plan.rs` | IETF Trust |
| [RateLimit headers draft](https://ietf-wg-httpapi.github.io/ratelimit-headers/draft-ietf-httpapi-ratelimit-headers.html) | draft | `RateLimit-Reset`: `src/net/retry/plan.rs` | IETF Trust |
| [RFC 3986, URI syntax](https://www.rfc-editor.org/rfc/rfc3986) | RFC 3986 | Percent-encoding: `src/net/url.rs` | IETF Trust |
| [RFC 3339, timestamps](https://www.rfc-editor.org/rfc/rfc3339) | RFC 3339 | Times in reports and indexes | IETF Trust |
| [RFC 822, message format](https://www.rfc-editor.org/rfc/rfc822) | RFC 822 | The header syntax of Python core metadata | IETF Trust |
| [JSON Schema](https://json-schema.org/draft/2020-12/schema) | 2020-12 | The files under `schema/` | Not stated |
| [JSON Lines](https://en.wikipedia.org/wiki/JSONL) | - | `json-stream` reports | - |
