# Setup Details

The `docker-compose.yml` file will start up Artifact Keeper and its database, then run another container to configure the server to add NPM, Python, Maven, OCI (docker), Conan, and generic repositories.  Each format gets three repositories, named `{format}-a`, `{format}-b`, and `{format}-c`.

```
../sctl.sh start artifact-keeper
../sctl.sh watch artifact-keeper
```

## Cut down to the backend

The upstream getting-started compose runs eleven services; this runs two, plus the configuration container.

| Dropped | Why it is safe to drop |
| --- | --- |
| `web`, `caddy` | The UI and its reverse proxy.  Nothing here drives a browser, and the backend is reached directly instead. |
| `opensearch` | Full-text search for the UI.  `OPENSEARCH_URL` is optional in the backend's config, so leaving it unset disables the feature. |
| `trivy`, `openscap` | Vulnerability and compliance scanners.  Same story - unset their URLs and the integrations never register. |
| `dependency-track` | Already opt-in upstream behind a profile, and it costs about 4 GiB of RAM. |
| `pg-certs` | Generated self-signed certificates for Postgres TLS.  This connects with `sslmode=disable` instead. |
| `scan-workspace-init` | Contains a volume shared with the enumerators.  With no enumerators there is no shared volume. |

`sslmode=disable` is the one place this is **less** secure than upstream, but note that both ends are containers on one private compose network, and the certificate machinery is a third service and a volume to maintain for a throwaway rig.

## No password dance

Unlike the other two servers, nothing here has to replace a bootstrap password.  The compose file sets `ADMIN_PASSWORD`, and the backend then creates the administrator with it and leaves `must_change_password` clear, so the API is usable the moment it is up.  Without that variable the backend generates a password into its storage volume and locks every endpoint behind a setup guard until someone reads it out.

The publishing and read-only accounts are created with explicit passwords for the same reason: a user the server generates a password for is flagged `must_change_password`, and the tool would then authenticate as an account that cannot do anything yet.

## Anonymous access

The cleanest of the three models.  A repository simply carries `allow_anonymous_access`, and the server-wide `AK_GUEST_ACCESS_ENABLED` decides whether any of them are honored - where Nexus needs a privilege inside a role assigned to a built-in user, and Artifactory needs a permission target plus a global switch.

Anonymous access is **on** for every `-a` repository.  The `-b` and `-c` repositories need a user.

The configuration reads `ARTIFACT_KEEPER_FORMATS`, `ARTIFACT_KEEPER_PORT`, and `ARTIFACT_KEEPER_VERSION` from the server's `.env`.

## What the tool can and cannot use

The `docker` and `conan` repositories exist even though the tool can't use them yet.

There is also no Artifact Keeper enumerator kind (yet), so `find` against npm or Maven has nothing to walk.  The PyPI repositories, though, walk using the PEP 503 index this backend serves, and `server-config.d` wires them up.
