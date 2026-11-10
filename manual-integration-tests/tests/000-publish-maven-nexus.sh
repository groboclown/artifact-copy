#!/bin/sh

# Runs the "publish/maven-echo-v1" build to publish into the Nexus server.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

cd "${PUBLISH_DIR}/maven-echo-v1"
echo "systemProp.REPO_URL=http://${NEXUS_HOST}/repository/maven-a" > gradle.properties
# PUBLISH_USER should already be set.
export PUBLISH_USER
export PUBLISH_PASSWORD="${NEXUS_PUBLISH_PASSWORD}"
./gradlew publish
