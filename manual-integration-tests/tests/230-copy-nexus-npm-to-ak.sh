#!/bin/sh

# Copies @am-example/echo from the Nexus `npm-a` repository into the
# Artifact Keeper `npm-b` one.
#
# Needs `030-publish-npm-nexus.sh` to have run first.
#
# The interesting part is the version document Artifact Keeper serves
# afterwards: it keeps whatever the publish sent, so `dependencies` and
# `engines` there mean the copy carried the origin's manifest.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"

>&2 echo "------ Copying @am-example/echo@1.0.0 into ak-local-npm-b"
run_am \
    copy --from=nexus-local-npm-a --to=ak-local-npm-b \
    "@am-example/echo@1.0.0"

>&2 echo
>&2 echo "What ak-local-npm-b now serves for @am-example/echo@1.0.0:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    "http://${ARTIFACT_KEEPER_HOST}/npm/npm-b/@am-example/echo/1.0.0"
>&2 echo

>&2 echo
>&2 echo "Expected: 'dependencies' with left-pad and 'engines' with node, as"
>&2 echo "published to Nexus, and a 'dist' naming ak-local-npm-b's tarball."
