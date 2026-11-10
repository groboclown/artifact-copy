# Server Population

In order to aid in the integration test, this directory constructs artifacts from source to use in pushing to the repositories.

Each of these tests contains a trivial 'echo' library.  You should only push these to the local repositories, because they have no reason to live in anything real.

## Publish Through Docker

You can use the provided [`Dockerfile`](Dockerfile) to publish the sample libraries into the local servers.  This allows you to perform the publish without needing to locally install the different developer tools at the required versions.

First build the image:

```shell
docker build -t local-am/publish .
```

(that assigns a local label `local-am/publish` to the image, which you can change to whatever you prefer)

Then build and publish:

```shell
docker run --rm -t -v $(pwd)/../setup:/setup local-am/publish 
```

You may need to have this image run in the same network as the services, which means adding a `--network NETWORK_NAME` to the invocation, or use a host network.  Doing so may also require you to pass extra environment variables to replace the host names:

* Nexus host: `-e NEXUS_HOST=am-nexus`
* Artifactory host: `-e ARTIFACTORY_HOST=am-artifactory`
* Artifact Keeper host: `-e AK_HOST=am-ak-backend`
