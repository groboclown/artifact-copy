#!/bin/sh

# Copies one pinned scoped package from the real registry.npmjs.org
# into Artifact Keeper.
#
# **Needs internet access.**  The scope exercises the `%2f` encoding of
# the packument URL.
#
# Run it twice.  The second run finds the version already present and
# uploads nothing.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"

PACKAGE="@babel/plugin-transform-arrow-functions"
VERSION="7.16.7"

>&2 echo "------ Copying ${PACKAGE}@${VERSION} from npmjs into ak-local-npm-b"
run_am \
    copy --from=npmjs --to=ak-local-npm-b "${PACKAGE}@${VERSION}"

>&2 echo
>&2 echo "What the npm-b index now lists for ${PACKAGE}:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    "http://${ARTIFACT_KEEPER_HOST}/npm/npm-b/${PACKAGE}" | \
    jq -r '.versions|keys|.[]'
>&2 echo

>&2 echo
>&2 echo "Expected: ${VERSION}"
