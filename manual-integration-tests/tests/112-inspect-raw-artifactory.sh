#!/bin/sh

# Resolves one generic artifact through the storage API.
#
# Run 011 first.  `ja-artifact1/1.0` holds two files under the directory
# mapping, which has no version.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

REPO_ROOT=$( cd "${TEST_HOME}/../.." && pwd )
REPORT="${TEST_HOME}/raw-artifactory-inspect.sqlite"

rm -f "${REPORT}"

>&2 echo "Resolving ja-artifact1/1.0 from generic-a"
cd "${REPO_ROOT}"
cargo run --quiet -- \
    --config manual-integration-tests/server-config.d \
    inspect \
    --from artifactory-local-generic-a \
    --db "${REPORT}" \
    ja-artifact1/1.0

if command -v sqlite3 >/dev/null 2>&1 ; then
  >&2 echo
  >&2 echo "Files it found, with the digest a copy would verify against:"
  sqlite3 "${REPORT}" \
      "SELECT f.name, d.algorithm, d.hex
        FROM repository_file f
        JOIN repository_artifact ra
          ON ra.repository_artifact_id = f.repository_artifact_id
        LEFT JOIN repository_file_digest d ON d.repository_file_id = f.repository_file_id
        ORDER BY f.name, d.algorithm;"

  >&2 echo
  >&2 echo "Expected: a1.txt and a2.txt, each with md5, sha1 and sha256."
  >&2 echo
  >&2 echo "You may want to remove the temporary file ${REPORT}"
else
  >&2 echo "You can inspect the report database file ${REPORT} for the inspection results."
fi
