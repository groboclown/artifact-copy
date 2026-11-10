#!/bin/sh

# Copies the Nexus `raw-a` repository into the Artifact Keeper `generic-b` one.
#
# Needs `010` to have published first.  Both sides use the directory
# mapping, so every file should land at the path it had in Nexus:
# `nx-artifact1/1.0/a1.txt`, `nx-artifact1/1.0/a2.txt` and
# `nx-artifact3/versionless.txt`.
#
# Run it twice.  The second run is the interesting one: the report says
# everything was delivered, and Artifact Keeper refuses to rewrite a path
# even with the same bytes, so a copy that did not know either would fail.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"

REPORT="${TEST_OUT}/nexus-raw-to-ak-generic.db"
rm -f "${REPORT}"

>&2 echo "------ Running find against nexus-local-raw-a"
run_am \
    find --from=nexus-local-raw-a \
    --db="${REPORT}"

>&2 echo "------ Copying what the report holds into ak-local-generic-b"
run_am \
    copy --from=nexus-local-raw-a --to=ak-local-generic-b --from-db \
    --db="${REPORT}"

>&2 echo
>&2 echo "What the generic repository now holds:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    "http://${ARTIFACT_KEEPER_HOST}/api/v1/repositories/generic-b/artifacts?per_page=100" \
    | grep -o '"path":"[^"]*"' | sort

>&2 echo
>&2 echo "Expected:"
# Copied artifacts from 010.  `012` publishes into `generic-a`, not here.
>&2 echo '  "path":"nx-artifact1/1.0/a1.txt"'
>&2 echo '  "path":"nx-artifact1/1.0/a2.txt"'
>&2 echo '  "path":"nx-artifact3/versionless.txt"'
