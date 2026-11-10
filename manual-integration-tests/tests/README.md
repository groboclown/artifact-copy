# Some scripted tests

## Setup

These tests expect the full [server stack](../setup/) to be running before the scripts start:

```shell
./sctl.sh start all
```

These scripts expect some environment variables to reflect where to find the repositories, with defaults to the default values.  The scripts pick these up in the [`fixtures/env-loader.sh`](fixtures/env-loader.sh) script.

## Running

The tests all start with a number (0-9), and they're written under the expectations that:

* They run in numerical order (`009` runs before `900`).
* The server stack starts out empty.
* The scripts live in the same layout as the repository originally had them.  That's because they reach out to the `../setup` and `../publish` directories.

The number groups also pick which of each server's [three repositories per format](../README.md#repositories) a test touches:

* 0XX (publish) and 1XX (find and inspect) use the anonymous `a` repositories.
* 2XX (copy) copy from an `a` repository into a `b` repository.

The npm publishes (`030`, `031`) run `npm publish` itself, with a temporary `.npmrc` holding the publish user, so each server stores what a real publish sends.
* No test uses the `c` repositories yet; they are reserved for full repository copy tests.

The "000-publish-*" scripts run the [publish](../publish/) actions.  If you don't have an environment that allows for running these, then you'll need to manually execute those scripts with the provided `Dockerfile`.

If you need to point to a different host or port number, then set these values:

* `DEFAULT_SERVER_HOSTNAME` - default for the other values if they aren't set; if this isn't set, then it defaults to localhost.
* `NEXUS_HOSTNAME`
* `ARTIFACTORY_HOSTNAME`
* `ARTIFACT_KEEPER_HOSTNAME`
* `NEXUS_PORT` - defaults to 8081
* `ARTIFACTORY_PORT` - defaults to 8082
* `ARTIFACT_KEEPER_PORT` - defaults to 8083
* `NEXUS_HOST` - defaults to `${NEXUS_HOSTNAME}:${NEXUS_PORT}`
* `ARTIFACTORY_HOST` - defaults to `${ARTIFACTORY_HOSTNAME}:${ARTIFACTORY_PORT}`
* `ARTIFACT_KEEPER_HOST` - defaults to `${ARTIFACT_KEEPER_HOSTNAME}:${ARTIFACT_KEEPER_PORT}`
* `PUBLISH_USER` - defaults to `am-publisher`
