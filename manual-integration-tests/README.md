# Manual Integration Tests

This directory contains methods for constructing locally running artifact stores to test out the application.

## Setting Up

The setup uses several `docker-compose.yml` files to create different artifact servers.  They use open source and trial versions with minimal, insecure configurations.  Never consider these ready for production.  They exist here as a way to test out the application's capabilities using contained instances.

To run these, you'll need either `docker` or `podman` installed along with a compatible docker-compose tool, plus `openssl` to generate the passwords.

Start, check the status, and stop a server with [`setup/sctl.sh`](setup/sctl.sh) rather than by calling compose directly:

```
./setup/sctl.sh start all
./setup/sctl.sh stop nexus
./setup/sctl.sh status all
./setup/sctl.sh logs artifactory
./setup/sctl.sh stop all
```

These control a set of services:

* [Nexus](nexus/README.md) - Nexus OSS running on port 8081.  Note that, before you can publish here, you must first [accept](setup/nexus/accept-eula.sh) the EULA.
* [Artifactory](artifactory/README.md) - JFrog Artifactory OSS running on port 8082.
* [Artifact Keeper](artifact-keeper/README.md) - Artifact Keeper running on port 8083.

### Server Secrets

The `setup/sctl.sh` script constructs a `.env` file per server.  This holds three `openssl`-generated passwords and only exists for your local environment (the [`.gitignore`](../.gitignore) file excludes it).

The file contains secrets for an admin account, a publishing account, and a read-only account, plus settings from the server's `env.defaults`.

If you need to rotate credentials, delete the `.env` *and* the server's data volume.  The passwords only regenerate if the `.env` file doesn't exist.  Additionally, they are baked into the server's own database the first time it is configured, so rewriting the file makes for mis-matching credentials.

## Initial Population

In order to keep these examples self-contained without needing to copy resources off the internet, is directory includes the [publish](publish/README.md) directory that allows pushing out to these local servers.

## Connecting

If you use the defaults for the compose above, you can add the [`server-config.d`](server-config.d/) directory path as a `--config` argument, and it will add new hosts + repositories.

That directory declares hosts, sources, targets and enumerators only - it carries no `setup` section, so pass it alongside a base configuration that does.  Each host reads its password straight out of its own server's generated `.env` with a `property-file` secret.

```shell
artifact-copy \
  --config local-base-config.yaml \
  --config manual-integration-tests/server-config.d \
  find --from=nexus-local-npm-a
```

(assuming you ran it from the project root)

Take note that, inside those configuration files, references to the `.env` files are relative to your working directory, while all other path values are relative to the configuration file's location.  Additionally, you will only see an error for a missing `.env` file on first use.

The provided server config files describe each server under `servers`, and each of its repositories becomes a source, a target, and an enumerator under one name (see [Servers and repositories](../README.md#servers-and-repositories)).  A server carries one credential, so the anonymous reads use the low-level `hosts`, `sources`, and `enumerators` sections instead:

| Server or host | Authenticates as | Used by |
| --- | --- | --- |
| `nexus-local` (server) | `am-publisher` | every repository but the `pypi-a` source and enumerator |
| `nexus-local-anonymous` (host) | nothing | the `pypi-a` source and enumerator |
| `artifactory-local` (server) | `admin` | `maven-auth-a` (read only), `maven-b`, `maven-c`, and `maven-b-guarded` (write only), plus the `maven-a` target |
| `artifactory-local-anonymous` (host) | nothing | the `maven-a` source and enumerator |
| `ak-local` (server) | `am-publisher` | every repository but the `npm-a` source; `npm-auth-a` reads only |
| `ak-local-anonymous` (host) | nothing | the `npm-a` source |

The low-level targets for the anonymous repositories write through the host their server generates, so writes always authenticate.  The anonymous hosts exist to be used rather than for completeness: each reaches only the `-a` repositories its server leaves open, and pointing one at a `-b` repository is the quickest check that the credentials on the servers are doing anything at all.

Reads use the publishing account, not `am-reader`, because a server has one credential and the tests write into the repositories they read.

## Repositories

In order to [test out](tests/README.md) the large amount of functionality provided by the `artifact-copy` tool, this constructs a set of repositories that allow for showcasing the copies.

Each server creates three repositories per format, named `{format}-a`, `{format}-b`, and `{format}-c`:

* `a` allows anonymous reads.  The publish, inspect, and find tests (0XX and 1XX) use it.
* `b` requires the read account (Artifactory: admin).  The copy tests (2XX) copy from an `a` repository into it.
* `c` requires the read account (Artifactory: admin).  Reserved for full repository copy tests.

The `server-config.d` entries follow the same naming: `nexus-local-maven-a` reads Nexus's `maven-a`.

| Server | Formats | Publishing |
| --- | --- | --- |
| Nexus | `raw`, `npm`, `pypi`, `maven`, `cargo` | `am-publisher` |
| Artifactory | `maven`, `generic` (raw) | `admin` |
| Artifact Keeper | `npm`, `pypi`, `maven`, `docker` (OCI), `conan`, `generic` (raw) | `am-publisher` |
