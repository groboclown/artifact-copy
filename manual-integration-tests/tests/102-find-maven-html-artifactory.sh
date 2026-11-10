#!/bin/sh

# Walk Artifactory's anonymous Maven repository through its directory
# index, with the maven-html-index enumerator.  Run 001 first so maven-a
# holds something.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}" || exit 1

>&2 echo "------ Running find against artifactory-local-maven-a's directory index"
run_am \
    find --enumerator artifactory-local-maven-a --as-source artifactory-local-maven-a
