#!/bin/sh

# Walks the Nexus raw repository and records what it holds.
#
# The shape this test exists for: `010` publishes three files into two
# directories, and the directory mapping makes those two artifacts.  Three
# components in, two artifacts out, and no files -- an enumerator reports what a
# repository *has*, and what each thing *is* costs a request the walk does
# not pay.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

REPO_ROOT=$( cd "${TEST_HOME}/../.." && pwd )
REPORT="${TEST_HOME}/raw-nexus.sqlite"

rm -f "${REPORT}"

>&2 echo "Walking raw-a into ${REPORT}"
cd "${REPO_ROOT}"
cargo run --quiet -- \
    --config manual-integration-tests/server-config.d \
    find \
    --from nexus-local-raw-a \
    --db "${REPORT}"

>&2 echo
>&2 echo "What the walk recorded:"
sqlite3 "${REPORT}" \
    "SELECT purl, COALESCE(version, '(none)') FROM artifact ORDER BY purl;"

>&2 echo
>&2 echo "Expected: two artifacts, neither with a version --"
>&2 echo "  pkg:raw/nx-artifact1%2F1.0"
>&2 echo "  pkg:raw/nx-artifact3"
