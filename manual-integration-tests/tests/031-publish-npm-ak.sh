#!/bin/sh

# Publishes "publish/npm-echo" into Artifact Keeper's npm-a repository with
# npm itself, so the stored version document is what a real publish writes.
#
# A second run fails: npm-a refuses a re-publish of the same version.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/npm-publish.sh"

REGISTRY="http://${ARTIFACT_KEEPER_HOST}/npm/npm-a/"

>&2 echo "Publishing @am-example/echo to ${REGISTRY}"
npm_publish "${REGISTRY}" "${PUBLISH_USER}" "${ARTIFACT_KEEPER_PUBLISH_PASSWORD}"
