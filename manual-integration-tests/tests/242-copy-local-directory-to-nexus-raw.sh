#!/bin/sh

# Copies the local directory `a` into the Nexus `raw-c` repository: a
# backup restored.
#
# Needs `240` to have filled the directory first.  Every file should land
# at the path it had there.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"
. "${TEST_HOME}/fixtures/local-directory.sh"

REPORT="${TEST_OUT}/local-directory-to-nexus-raw.db"
rm -f "${REPORT}" 2>/dev/null || true

>&2 echo "------ Running find against local-dir-a"
run_am \
    find --from=local-dir-a \
    --db="${REPORT}" \
    --config="${LOCAL_DIR_CONFIG}"

>&2 echo "------ Copying what the report holds into nexus-local-raw-c"
run_am \
    copy --from=local-dir-a --to=nexus-local-raw-c --from-db \
    --db="${REPORT}" \
    --config="${LOCAL_DIR_CONFIG}"

>&2 echo
>&2 echo "What raw-c now holds:"
curl -sSf -u "${READONLY_USER}:${NEXUS_READONLY_PASSWORD}" \
    "http://${NEXUS_HOST}/service/rest/v1/assets?repository=raw-c" \
    | grep -o '"path" *: *"[^"]*"' | sort

>&2 echo
>&2 echo "Expected:"
>&2 echo '  "path" : "nx-artifact1/1.0/a1.txt"'
>&2 echo '  "path" : "nx-artifact1/1.0/a2.txt"'
>&2 echo '  "path" : "nx-artifact3/versionless.txt"'
