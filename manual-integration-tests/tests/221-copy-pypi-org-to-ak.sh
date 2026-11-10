#!/bin/sh

# Copies one pinned package from the real pypi.org into Artifact Keeper.
#
# **Needs internet access.**  pypi.org lists its files on a second host,
# `files.pythonhosted.org`, so this is the test that the host's
# `additional-hosts` lets it fetch them: without it every file is
# refused as outside what the source may fetch.
#
# Run it twice.  The second run finds the version already present and
# uploads nothing.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"

PACKAGE="six"
VERSION="1.17.0"

>&2 echo "------ Copying ${PACKAGE}==${VERSION} from pypi-org into ak-local-pypi-b"
run_am \
    copy --from=pypi-org --to=ak-local-pypi-b "${PACKAGE}==${VERSION}"

>&2 echo
>&2 echo "What the pypi-b index now lists for ${PACKAGE}:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "http://${ARTIFACT_KEEPER_HOST}/pypi/pypi-b/simple/${PACKAGE}/"
>&2 echo

>&2 echo
>&2 echo "Expected: ${VERSION} with a wheel and an sdist, each with the"
>&2 echo "'requires-python' pypi.org states for them."
