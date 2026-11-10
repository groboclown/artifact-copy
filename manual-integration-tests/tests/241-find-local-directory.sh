#!/bin/sh

# Walks the local directory `a` and records what it holds.
#
# Needs `240` to have filled it first.  The directory mapping makes two
# artifacts of three files, each file listed with its size and no digest:
# a walk does not hash what it lists.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"
. "${TEST_HOME}/fixtures/local-directory.sh"

REPORT="${TEST_OUT}/local-directory-find.db"
rm -f "${REPORT}" 2>/dev/null || true

>&2 echo "------ Walking local-dir-a into ${REPORT}"
run_am \
    find --from=local-dir-a \
    --db="${REPORT}" \
    --config="${LOCAL_DIR_CONFIG}"

>&2 echo
>&2 echo "What the walk recorded:"
sqlite3 "${REPORT}" \
    "SELECT a.purl, f.name, f.size_bytes
       FROM repository_file f
       JOIN repository_artifact ra ON ra.repository_artifact_id = f.repository_artifact_id
       JOIN artifact a ON a.artifact_id = ra.artifact_id
      ORDER BY a.purl, f.name;"

>&2 echo
>&2 echo "Expected: two artifacts, three files --"
>&2 echo "  pkg:raw/nx-artifact1%2F1.0|a1.txt|..."
>&2 echo "  pkg:raw/nx-artifact1%2F1.0|a2.txt|..."
>&2 echo "  pkg:raw/nx-artifact3|versionless.txt|..."
