# External Definitions

Machine-readable definitions of the formats and APIs this tool reads, copied from their publishers under their own licenses. Each directory holds the upstream `LICENSE`. Nothing here is built or loaded by the tool; it is reference for whoever changes the code that reads these formats.

[`build-scripts/fetch-external.sh`](../build-scripts/fetch-external.sh) downloads every file at the commit pinned in it. To move to a newer upstream, change the commit there and run it. The full bibliography, including specifications with no machine-readable form, is [docs/references.md](../docs/references.md).

| Directory | Definition | Upstream | License | Read by |
| --- | --- | --- | --- | --- |
| `osv/` | OSV schema | [ossf/osv-schema](https://github.com/ossf/osv-schema) `validation/schema.json` | Apache-2.0 | `src/advisory/osv.rs`, `src/advisory/osv_offline.rs`, `src/advisory/ossf_malicious.rs` |
| `openvex/` | OpenVEX JSON schema | [openvex/spec](https://github.com/openvex/spec) `openvex_json_schema.json` | CC0-1.0 | `src/policy/vex.rs`, `src/lock/bom.rs` |
| `cyclonedx/` | CycloneDX 1.6 JSON schema, with the SPDX and JSF schemas it references | [CycloneDX/specification](https://github.com/CycloneDX/specification) `schema/` | Apache-2.0 | `src/policy/vex.rs`, `src/lock/bom.rs` |
| `artifact-keeper/` | Artifact Keeper REST API, OpenAPI 3.1 | [artifact-keeper/artifact-keeper-api](https://github.com/artifact-keeper/artifact-keeper-api) `openapi.json` | MIT | `src/repo/artifact_keeper/` |

## Not committed

- **Nexus 3 REST API.** Sonatype publishes no file to pin; a server generates it at `/service/rest/swagger.json`, and Nexus Community Edition is distributed under Sonatype's EULA, so the document is not committed. `scripts/fetch-external.sh --nexus-url=URL` writes it to `external/nexus/`, which `.gitignore` excludes. Read by `src/repo/nexus/`.
- **Artifactory REST API** and the **npm registry API** publish no redistributable machine-readable definition. See [docs/references.md](../docs/references.md) for their documentation.
