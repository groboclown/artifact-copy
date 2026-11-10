#!/bin/sh

# Performs Nexus-native API call to publish artifacts into the raw repository.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

>&2 echo "Publishing to repository/raw-a/nx-artifact1/1.0"
curl -sSfL \
    "http://${NEXUS_HOST}/service/rest/v1/components?repository=raw-a" \
    -u "${PUBLISH_USER}:${NEXUS_PUBLISH_PASSWORD}" \
    -X POST \
    -F "raw.directory=nx-artifact1/1.0" \
    -F "raw.asset1=@${TEST_HOME}/fixtures/test-artifact-1.txt" \
    -F "raw.asset1.filename=a1.txt" \
    -F "raw.asset2=@${TEST_HOME}/fixtures/test-artifact-2.txt" \
    -F "raw.asset2.filename=a2.txt"
echo

>&2 echo "Publishing to repository/raw-a/nx-artifact3"
curl -sSfL \
    "http://${NEXUS_HOST}/service/rest/v1/components?repository=raw-a" \
    -u "${PUBLISH_USER}:${NEXUS_PUBLISH_PASSWORD}" \
    -X POST \
    -F "raw.directory=nx-artifact3" \
    -F "raw.asset1=@${TEST_HOME}/fixtures/test-artifact-3.txt" \
    -F "raw.asset1.filename=versionless.txt"
echo
