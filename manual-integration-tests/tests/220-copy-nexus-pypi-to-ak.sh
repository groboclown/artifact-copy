#!/bin/sh

# Copies the Nexus `pypi-a` repository into the Artifact Keeper `pypi-b` one.
#
# Needs `020-publish-pypi-nexus.sh` to have run first, so `pypi-a`
# holds `am-python-echo` 1.0 as a wheel and an sdist.
#
# Run it twice.  The second run is the interesting one: the target's index
# lists the version, so the copy uploads nothing.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"

REPORT="${TEST_OUT}/nexus-pypi-to-ak-pypi.db"
rm -f "${REPORT}"

>&2 echo "------ Running find against nexus-local-pypi-a"
run_am \
    find --from=nexus-local-pypi-a \
    --db="${REPORT}"

>&2 echo "------ Copying what the report holds into ak-local-pypi-b"
run_am \
    copy --from=nexus-local-pypi-a --to=ak-local-pypi-b --from-db \
    --db="${REPORT}"

>&2 echo
>&2 echo "What the pypi-b index now lists for am-python-echo:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "http://${ARTIFACT_KEEPER_HOST}/pypi/pypi-b/simple/am-python-echo/"
>&2 echo

>&2 echo
>&2 echo "Expected: version 1.0, with a wheel and an sdist, and 'requires-python'"
>&2 echo "set to '>=3.9' on each file -- the core metadata the upload carried."
