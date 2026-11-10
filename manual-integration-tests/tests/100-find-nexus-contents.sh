#!/bin/sh

# Connect to the Nexus server with the command and list out the repository
# contents.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}" || exit 1

>&2 echo "------ Running find against nexus-local-raw-a"
run_am \
    find --from nexus-local-raw-a

>&2 echo
>&2 echo "------ Running find against nexus-local-maven-a"
run_am \
    find --from nexus-local-maven-a
