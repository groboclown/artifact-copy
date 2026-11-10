# A "sourced" file, not a stand-alone script.

# Writes a configuration declaring a `local-directory` server over
# "${TEST_OUT}/local-dir", whose repositories `local-dir-a` and
# `local-dir-b` are its sub-directories `a` and `b`.
#
# Written at run time rather than kept in `server-config.d`: a file:// url
# is absolute, and this checkout's location is not known in advance.
#
# This requires the calling script to first run:
#    TEST_HOME=$( cd $( dirname "$0" ) && pwd )
#    . "${TEST_HOME}/fixtures/env-loader.sh"
test -d "${TEST_HOME}" || exit 1

LOCAL_DIR="${TEST_OUT}/local-dir"
LOCAL_DIR_CONFIG="${TEST_OUT}/local-directory.yaml"

mkdir -p "${LOCAL_DIR}"
LOCAL_DIR="$( cd "${LOCAL_DIR}" && pwd )"

cat > "${LOCAL_DIR_CONFIG}" <<CONFIG
\$schema: https://github.com/groboclown/artifact-copy/schema/config.schema.json

servers:
  local-dir:
    kind: local-directory
    url: file://${LOCAL_DIR}/
    repositories:
      local-dir-a:
        name: a
        kind: generic
      local-dir-b:
        name: b
        kind: generic
CONFIG
