# Maven 2 Repositories

A Maven 2 repository stores artifacts in the layout Apache Maven defines: `group/as/path/artifact/version/artifact-version[-classifier].ext`, with a `maven-metadata.xml` per artifact listing its versions, a POM per version declaring its dependencies, and checksum and signature sidecars. Gradle, sbt, and other JVM build tools read the same layout.

## References

- [Repository layout](https://maven.apache.org/repositories/layout.html): the path rules.
- [Repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html): the `maven-metadata.xml` format.
- [POM reference](https://maven.apache.org/pom.html): dependencies, scopes, parents, and imported BOMs.
- [ComparableVersion](https://maven.apache.org/ref/current/maven-artifact/apidocs/org/apache/maven/artifact/versioning/ComparableVersion.html): how versions order.
- [Version range syntax](https://maven.apache.org/enforcer/enforcer-rules/versionRanges.html): the bracketed ranges a request may use.

## Repository kind by server

| Server kind | Repository `kind` | Guide |
| --- | --- | --- |
| `nexus3` | `maven2` | [Nexus](configuration-nexus.md) |
| `artifactory-pro`, `artifactory-oss` | `maven` | [Artifactory](configuration-artifactory.md) |
| `artifact-keeper` | `maven` | [Artifact Keeper](configuration-artifact-keeper.md) |
| `maven-central` | its default repository | [Public repositories](configuration-public.md#maven-central) |

## Requests

A request is `group:artifact[:version]`, or `group:artifact:packaging[:classifier]:version`, the order `mvn dependency:get` takes. The version may be exact or a range:

```text
org.apache.commons:commons-lang3:3.14.0
org.apache.commons:commons-lang3:[3.12,3.15)
com.google.guava:guava
```

A range or a missing version selects the highest match. Without `--pre-release`, alpha, beta, milestone, release candidate, and snapshot versions are skipped.

## Dependencies

A POM dependency's scope decides its [dependency kind](configuration-server.md#dependencies):

| POM | Kind |
| --- | --- |
| `compile`, `runtime`, or no scope | `runtime` |
| `provided` | `dev` |
| `test` | `test` |
| `<optional>true</optional>`, any scope | `optional` |
| `system`, `import` | not followed |
| parent POM, imported BOM | `build`, followed whenever any kind is |

## Source options

These go in a repository's `source.options` override. The [Maven Central](configuration-public.md#maven-central) kind sets the first two to `html-index`.

| Option | Default | Meaning |
| --- | --- | --- |
| `file-listing` | `none` | `html-index` also reads each resolved version's directory index, one request per version, to find files the POM does not name: classifiers such as `-sources` and `-javadoc`, Gradle's `.module`, and SBOMs. For a server with a directory autoindex. |
| `version-discovery` | `probe` | How versions missing from a stale `maven-metadata.xml` are found. Under every value but `metadata`, an exact release version is confirmed by fetching its POM before any list is read; the POM is reused, so this costs no extra request, and a mirror can serve it. `probe` also confirms an exact version the list lacks with a HEAD of its POM. `html-index` joins the artifact directory index, one request per artifact. `both` does both. `metadata` trusts the metadata alone. |
| `checksums` | learned | Sidecars to probe beside a POM, in order, stopping at the first found. Absent, the source probes `sha512`, `sha256`, `sha1`, and `md5` for its first 8 POMs, then only what it found. An empty list probes none. |

The `nexus`, `artifactory`, and `artifact-keeper` sources generated for repository managers list every file a version holds through the product's API, so they need neither `file-listing` nor `version-discovery`.

## Target options

These go in a repository's `target.options` override.

| Option | Default | Meaning |
| --- | --- | --- |
| `checksums` | `[sha1, md5]` | Sidecars written beside each file, computed from the copied bytes. An empty list writes none. Signature files get none. |
| `metadata` | `server` | Who keeps `maven-metadata.xml`. `server` writes nothing, for a server that rebuilds it on upload. `merge` reads the target's document, adds the version, and writes it back, keeping the rest. |
| `overwrite-guard` | `server` | `server` relies on the server refusing a rewrite. `check` compares what the target holds first, one request per file, for a server that overwrites and reports success. |

Nexus does not rebuild `maven-metadata.xml` on upload, so the `nexus3` kind sets `metadata: merge`. Artifactory OSS overwrites a redeploy as admin, so `artifactory-oss` sets `overwrite-guard: check`.

## Example

```yaml
servers:
  nexus:
    kind: nexus3
    url: https://nexus.example.com/
    authentication:
      kind: basic
      username: { kind: env, name: NEXUS_USER }
      password: { kind: env, name: NEXUS_PASSWORD }
    repositories:
      maven-releases:
        kind: maven2
        source:
          dependencies: runtime
          minimum-publish-time: 7 days
        target:
          options:
            checksums: [sha256, sha1]
```

See [Shared settings](configuration-server.md) for `dependencies`, `minimum-publish-time`, [omit](configuration-server.md#omit), and [cache](configuration-server.md#cache) settings.

## Low-level details

A Maven repository generates:

| Role | Kind | Notes |
| --- | --- | --- |
| [source](configuration-low-level.md#source-kinds) | `nexus`, `artifactory`, or `artifact-keeper` with `ecosystem: maven` on a repository manager; `maven` on Maven Central | |
| [target](configuration-low-level.md#target-kinds) | `maven` | `host-path` is `repository/{name}` on Nexus, `{name}` on Artifactory, `maven/{name}` on Artifact Keeper. |
| [enumerator](configuration-low-level.md#enumerator-kinds) | the repository manager's own, with `ecosystem: maven` | Maven Central has none. |

A hand-written `maven` source or `maven-html-index` enumerator reaches any server that serves the layout, such as a static file server.

The built-in omissions leave out checksum sidecars, `maven-metadata.xml`, and `_remote.repositories`. Cached `maven-metadata.xml` and directory indexes stay fresh for an hour unless a [freshness rule](configuration-server.md#cache) says otherwise.
