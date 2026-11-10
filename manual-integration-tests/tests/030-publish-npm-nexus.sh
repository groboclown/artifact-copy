#!/bin/sh

# Publishes "publish/npm-echo" into Nexus's npm-a repository with npm
# itself, so the stored version document is what a real publish writes.
#
# A second run fails: npm-a refuses a re-publish of the same version.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/npm-publish.sh"

REGISTRY="http://${NEXUS_HOST}/repository/npm-a/"

>&2 echo "Publishing @am-example/echo to ${REGISTRY}"
npm_publish "${REGISTRY}" "${PUBLISH_USER}" "${NEXUS_PUBLISH_PASSWORD}"
