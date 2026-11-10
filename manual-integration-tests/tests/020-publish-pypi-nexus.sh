#!/bin/sh

# Runs the "publish/pypi-echo" build to publish into the Nexus server.
#
# The project's Makefile builds a `.venv` beside it and installs `build`
# and `twine` there. `PYTHON` picks the interpreter that creates it.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"

PYTHON="${PYTHON:-python3}"

cd "${PUBLISH_DIR}/pypi-echo"

# A clean build, so a stale distribution from an earlier version is not
# uploaded beside this one.
rm -rf dist

# twine reads its credentials from the environment rather than prompting.
# PUBLISH_USER should already be set.
export TWINE_USERNAME="${PUBLISH_USER}"
export TWINE_PASSWORD="${NEXUS_PUBLISH_PASSWORD}"

make publish PYTHON="${PYTHON}" PYPI_UPLOAD_URL="http://${NEXUS_HOST}/repository/pypi-a/"
