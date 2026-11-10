#!/bin/sh

# Checks `overwrite-guard: check` against Artifactory OSS, which as admin
# overwrites a path with different bytes and answers 201.
#
# Needs `200` to have copied `echo` 1.0 into `maven-b` first.
#
# The target's `exists` answers "present" whenever the payload is there,
# so the guard is only reached when the jar is missing.  This sets that
# up by hand:
#
#   1. The POM in `maven-b` is replaced with different bytes, and the jar
#      is deleted.  A copy through the guarded target must refuse, and
#      write nothing: the POM keeps the altered bytes, the jar stays gone.
#   2. The original POM is put back.  The guarded copy must now skip the
#      POM, whose bytes match, and write only the jar.
#
# Both steps leave `maven-b` as `200` left it, so the test can be rerun.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"

COORDINATE="example.lib:echo:1.0"
SOURCE_DIR="http://${NEXUS_HOST}/repository/maven-a/example/lib/echo/1.0"
TARGET_DIR="http://${ARTIFACTORY_HOST}/artifactory/maven-b/example/lib/echo/1.0"
ADMIN="${ADMIN_USER}:${ARTIFACTORY_ADMIN_PASSWORD}"

ORIGINAL_POM="${TEST_OUT}/201-echo-1.0.pom"
ALTERED_POM="${TEST_OUT}/201-echo-1.0-altered.pom"
HELD_POM="${TEST_OUT}/201-echo-1.0-held.pom"

# The HTTP status of a target path.
status() {
    curl -s -o /dev/null -w '%{http_code}' -u "${ADMIN}" "${TARGET_DIR}/$1"
}

# Fail the test with a message.
fail() {
    >&2 echo "FAILED: $1"
    exit 1
}

>&2 echo "------ Fetching the source POM"
curl -sSf -u "${READONLY_USER}:${NEXUS_READONLY_PASSWORD}" \
    "${SOURCE_DIR}/echo-1.0.pom" -o "${ORIGINAL_POM}"

# Still a readable POM with the same packaging, so `exists` reads it as
# before; only its bytes differ.
cp "${ORIGINAL_POM}" "${ALTERED_POM}"
echo "<!-- altered by 201 -->" >> "${ALTERED_POM}"

>&2 echo "------ Step 1: different POM bytes stored, jar missing"
curl -sSf -o /dev/null -u "${ADMIN}" -X PUT \
    --data-binary "@${ALTERED_POM}" "${TARGET_DIR}/echo-1.0.pom"
curl -s -o /dev/null -u "${ADMIN}" -X DELETE "${TARGET_DIR}/echo-1.0.jar"

test "$( status echo-1.0.jar )" = "404" || fail "the jar was not deleted"

if run_am copy --from=nexus-local-maven-a \
    --to=artifactory-local-maven-b-guarded "${COORDINATE}"
then
    fail "the guarded copy succeeded over different bytes"
fi

curl -sSf -u "${ADMIN}" "${TARGET_DIR}/echo-1.0.pom" -o "${HELD_POM}"
cmp -s "${HELD_POM}" "${ALTERED_POM}" || fail "the stored POM was overwritten"
test "$( status echo-1.0.jar )" = "404" || fail "the jar was written after a refusal"

>&2 echo "  refused, and nothing was written"

>&2 echo "------ Step 2: original POM restored, jar still missing"
curl -sSf -o /dev/null -u "${ADMIN}" -X PUT \
    --data-binary "@${ORIGINAL_POM}" "${TARGET_DIR}/echo-1.0.pom"

run_am copy --from=nexus-local-maven-a \
    --to=artifactory-local-maven-b-guarded "${COORDINATE}"

curl -sSf -u "${ADMIN}" "${TARGET_DIR}/echo-1.0.pom" -o "${HELD_POM}"
cmp -s "${HELD_POM}" "${ORIGINAL_POM}" || fail "the stored POM changed"
test "$( status echo-1.0.jar )" = "200" || fail "the jar was not written"
test "$( status echo-1.0.jar.sha1 )" = "200" || fail "the jar's checksum is missing"

>&2 echo "  the POM was left alone and the jar was written"

>&2 echo
>&2 echo "Passed."
