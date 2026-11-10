#!/bin/sh

# Runs the "publish/maven-noecho" build to publish into the Artifact Keeper server.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

cd "${PUBLISH_DIR}/maven-noecho"
echo "systemProp.REPO_URL=http://${ARTIFACT_KEEPER_HOST}/maven/maven-a" > gradle.properties
# PUBLISH_USER should already be set.
export PUBLISH_USER
export PUBLISH_PASSWORD="${ARTIFACT_KEEPER_PUBLISH_PASSWORD}"
./gradlew publish
