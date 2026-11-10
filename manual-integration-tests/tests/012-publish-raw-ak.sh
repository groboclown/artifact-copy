#!/bin/sh

# Performs Artifact Keeper-native API call to publish artifacts into the generic repository.
#
# A second run fails: the server answers 409 to any re-upload of a path.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

REPO_URL="http://${ARTIFACT_KEEPER_HOST}/api/v1/repositories/generic-a/artifacts"
CREDENTIALS="${PUBLISH_USER}:${ARTIFACT_KEEPER_PUBLISH_PASSWORD}"

>&2 echo "Publishing to generic-a/ak-artifact1/1.0"
curl -sSfL \
    "${REPO_URL}/ak-artifact1/1.0/a1.txt" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-1.txt"
echo
curl -sSfL \
    "${REPO_URL}/ak-artifact1/1.0/a2.txt" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-2.txt"
echo


>&2 echo "Publishing to generic-a/ak-artifact3"
curl -sSfL \
    "${REPO_URL}/ak-artifact3/versionless.txt" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-3.txt"
echo
