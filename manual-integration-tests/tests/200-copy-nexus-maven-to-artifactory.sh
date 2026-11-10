#!/bin/sh

# Copies the Nexus `maven-a` repository into the Artifactory `maven-b` one.
#
# Needs `000` to have published first.  The target is `maven-b` rather
# than `maven-a`, which `001` fills with its own build of the same
# coordinate: a copy onto that would meet different bytes at the same path.
#
# No artifact enumeration of the target: the OSS edition refuses the
# sorted AQL the artifactory enumerator sends (see TODO.md), so the copy
# asks the target itself whether each artifact is there.
#
# Run it twice.  The second run is the interesting one: the target answers
# that it already holds everything, so the copy publishes nothing.
#
# A target left holding an earlier copy of `echo` answers "present" and
# gets nothing new, even files it lacks; clear `maven-b` first to see a
# full copy.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}"

REPORT="${TEST_OUT}/nexus-to-artifactory-maven.db"
rm -f "${REPORT}"

>&2 echo "------ Running find against nexus-local-maven-a"
run_am \
    find --from=nexus-local-maven-a \
    --db="${REPORT}"

>&2 echo "------ Copying what the report holds into artifactory-local-maven-b"
run_am \
    copy --from=nexus-local-maven-a --to=artifactory-local-maven-b --from-db \
    --db="${REPORT}"

>&2 echo
>&2 echo "What the maven-b repository now holds:"
for path in \
    example/lib/echo/maven-metadata.xml \
    example/lib/echo/1.0/echo-1.0.pom \
    example/lib/echo/1.0/echo-1.0.pom.sha1 \
    example/lib/echo/1.0/echo-1.0.jar \
    example/lib/echo/1.0/echo-1.0.jar.sha1 \
    example/lib/echo/1.0/echo-1.0.module \
    example/lib/echo/1.0/echo-1.0-sources.jar
do
    status="$( curl -s -o /dev/null -w '%{http_code}' \
        -u "${ADMIN_USER}:${ARTIFACTORY_ADMIN_PASSWORD}" \
        "http://${ARTIFACTORY_HOST}/artifactory/maven-b/${path}" )"
    >&2 echo "  ${status} ${path}"
done

>&2 echo
>&2 echo "Expected: 200 for all.  The .module and the sources jar reach the"
>&2 echo "copy only because the Nexus artifact enumeration listed them; the Maven layout alone"
>&2 echo "names neither."
