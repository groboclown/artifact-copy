#!/bin/sh

# Runs the "publish/maven-*" builds to publish into the Artifactory server.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

for project_dir in "${PUBLISH_DIR}"/maven-* ; do
    cd "${project_dir}"
    echo "systemProp.REPO_URL=http://${ARTIFACTORY_HOST}/artifactory/maven-a" > gradle.properties
    # Admin: the OSS edition has no publishing account.
    export PUBLISH_USER="${ADMIN_USER}"
    export PUBLISH_PASSWORD="${ARTIFACTORY_ADMIN_PASSWORD}"
    ./gradlew publish
done
