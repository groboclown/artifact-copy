#!/bin/sh

# Copies the Nexus `raw-a` repository into the local directory `a`.
#
# Needs `010` to have published first.  Both sides use the directory
# mapping, so every file should land at the path it had in Nexus:
# `nx-artifact1/1.0/a1.txt`, `nx-artifact1/1.0/a2.txt` and
# `nx-artifact3/versionless.txt`.
#
# Run it twice.  The second run copies nothing; the report already says
# each file reached the directory.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"
. "${TEST_HOME}/fixtures/local-directory.sh"

REPORT="${TEST_OUT}/nexus-raw-to-local-directory.db"
rm -f "${REPORT}" 2>/dev/null || true

>&2 echo "------ Running find against nexus-local-raw-a"
run_am \
    find --from=nexus-local-raw-a \
    --db="${REPORT}" \
    --config="${LOCAL_DIR_CONFIG}"

>&2 echo "------ Copying what the report holds into local-dir-a"
run_am \
    copy --from=nexus-local-raw-a --to=local-dir-a --from-db \
    --db="${REPORT}" \
    --config="${LOCAL_DIR_CONFIG}"

>&2 echo
>&2 echo "What the directory now holds:"
( cd "${LOCAL_DIR}/a" && find . -type f | sort )

>&2 echo
>&2 echo "Expected:"
>&2 echo "  ./nx-artifact1/1.0/a1.txt"
>&2 echo "  ./nx-artifact1/1.0/a2.txt"
>&2 echo "  ./nx-artifact3/versionless.txt"
