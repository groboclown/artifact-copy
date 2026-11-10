#!/bin/sh

# Connect to the Nexus server with the command and list all the repository
# files.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"
mkdir -p "${TEST_OUT}" || exit 1

>&2 echo "------ Running inspect against nexus-local-raw-a"
run_am \
    inspect --from nexus-local-raw-a nx-artifact1/1.0 nx-artifact3

>&2 echo
>&2 echo "------ Running inspect against nexus-local-maven-a"
run_am \
    inspect --from nexus-local-maven-a example.lib:echo:1.0
