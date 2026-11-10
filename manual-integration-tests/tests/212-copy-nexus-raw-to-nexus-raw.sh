#!/bin/sh

# Copies the Nexus `raw-a` repository into the Nexus `raw-b` one, through
# the `nexus-raw` target.
#
# Needs `010` to have published first.  Both sides use the directory
# mapping, so every file should land at the path it had in `raw-a`:
# `nx-artifact1/1.0/a1.txt`, `nx-artifact1/1.0/a2.txt` and
# `nx-artifact3/versionless.txt`.
#
# Run it twice.  The second run copies nothing; the report already says
# each file reached `raw-b`.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"

REPORT="${TEST_OUT}/nexus-raw-to-nexus-raw.db"
rm -f "${REPORT}"

>&2 echo "------ Running find against nexus-local-raw-a"
run_am \
    find --from=nexus-local-raw-a \
    --db="${REPORT}"

>&2 echo "------ Copying what the report holds into nexus-local-raw-b"
run_am \
    copy --from=nexus-local-raw-a --to=nexus-local-raw-b --from-db \
    --db="${REPORT}"

>&2 echo
>&2 echo "What the raw repository now holds:"
curl -sSf -u "${PUBLISH_USER}:${NEXUS_PUBLISH_PASSWORD}" \
    "http://${NEXUS_HOST}/service/rest/v1/search/assets?repository=raw-b" \
    | grep -o '"path" : "[^"]*"' | sort

>&2 echo
>&2 echo "Expected:"
>&2 echo '  "path" : "/nx-artifact1/1.0/a1.txt"'
>&2 echo '  "path" : "/nx-artifact1/1.0/a2.txt"'
>&2 echo '  "path" : "/nx-artifact3/versionless.txt"'

>&2 echo
>&2 echo "Per-file uploads the report recorded:"
sqlite3 "${REPORT}" \
    "SELECT direction, state, COUNT(*) FROM file_transfer GROUP BY 1, 2"
