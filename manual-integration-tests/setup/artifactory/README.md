# Setup Details

The `docker-compose.yml` file will start up the OSS edition of Artifactory and its dependent services, then run another container to configure the server to add generic and Maven repositories.

```
../sctl.sh start artifactory
../sctl.sh watch artifactory
```

Artifactory is slower to start than Nexus - three to five minutes on a first run, while it builds its embedded database.  The configure container waits for it, and is safe to re-run.

The server runs on embedded Derby, which current images allow only with `shared.database.allowNonPostgresql`.  The compose file sets that, and everything else JFrog's `config.sh` would write, so that script is not needed.

Before Artifactory starts, the `access-config` container copies [`access.config.import.yml`](access.config.import.yml) into the data volume.  It lets the admin password create an access token, and opens the Access permissions API to that token.  `configure.sh` needs both.

The default configuration creates three repositories per format, named `{format}-a`, `{format}-b`, and `{format}-c`:

* `maven-*` - Maven2 compatible repositories.
* `generic-*` - generic repositories.
* `ivy-*` - Ivy repositories, which the tool reads as raw files laid out name/version/file.

Copy tests write into `maven-b`, kept apart from `maven-a` so a copy cannot collide with what the publish tests put there.

The OSS edition serves Maven (with Gradle, Ivy and SBT sharing its layout) and generic repositories, and nothing else.  npm, PyPI and Go are Pro features, which is why they are not here.  Current images create such a repository without complaint when you add one to `ARTIFACTORY_FORMATS`; whether they serve it is untested.

The tool reads `generic-*` as raw repositories (source, target, and enumerator) and `ivy-*` as raw repositories it only reads (source and enumerator).  A server created before `ivy` joined `ARTIFACTORY_FORMATS` gains the Ivy repositories by running `configure.sh` again; it skips repositories that exist.

## Anonymous access

Anonymous access is **on** for every `-a` repository.  The `-b` and `-c` repositories need the admin account.

There is no publishing or read-only account.  The OSS edition refuses user management over REST, even to an admin token, so the tool reads and publishes as admin.

This allows for testing out anonymous-capable reads vs. authenticated reads.

Artifactory expresses this differently from Nexus.  There is a global "allow anonymous access" switch in the configuration descriptor, and separately one permission target per `-a` repository naming the `anonymous` user.  The configuration sets the permission first and the switch second, so there is no window in which anonymous holds more than intended.

To control the repository configuration, the [`configure.sh`](configure.sh) script reads from the server's `.env`: `ARTIFACTORY_FORMATS`, `ARTIFACTORY_PORT`, and `ARTIFACTORY_VERSION`.

## If a re-run is refused

Artifactory works out which password is live by trying one.  If neither the configured nor the out-of-the-box password is accepted, the `.env` has been regenerated against a server that still holds the old one.  The fix is to discard the server's data:

```
docker compose -f setup/artifactory/docker-compose.yml down -v
```
