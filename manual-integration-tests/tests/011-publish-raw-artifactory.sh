#!/bin/sh

# Performs Artifactory-native API call to publish artifacts into the generic repository.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

REPO_URL="http://${ARTIFACTORY_HOST}/artifactory/generic-a"
# Admin: the OSS edition has no publishing account.
CREDENTIALS="${ADMIN_USER}:${ARTIFACTORY_ADMIN_PASSWORD}"

>&2 echo "Publishing to generic-a/ja-artifact1/1.0"
curl -sSfL \
    "${REPO_URL}/ja-artifact1/1.0/a1.txt" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-1.txt"
echo
curl -sSfL \
    "${REPO_URL}/ja-artifact1/1.0/a2.txt" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-2.txt"
echo


>&2 echo "Publishing to generic-a/ja-artifact3"
curl -sSfL \
    "${REPO_URL}/ja-artifact3/versionless.txt" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-3.txt"
echo
