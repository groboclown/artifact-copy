#!/bin/sh

# Performs Artifactory-native API calls to publish one module into the Ivy
# repository, laid out name/version/file as the tool reads it.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

REPO_URL="http://${ARTIFACTORY_HOST}/artifactory/ivy-a"
# Admin: the OSS edition has no publishing account.
CREDENTIALS="${ADMIN_USER}:${ARTIFACTORY_ADMIN_PASSWORD}"

>&2 echo "Publishing to ivy-a/ja-ivy/module/1.0"
curl -sSfL \
    "${REPO_URL}/ja-ivy/module/1.0/module-1.0.jar" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-1.txt"
echo
curl -sSfL \
    "${REPO_URL}/ja-ivy/module/1.0/ivy-1.0.xml" \
    -u "${CREDENTIALS}" \
    -T "${TEST_HOME}/fixtures/test-artifact-2.txt"
echo
