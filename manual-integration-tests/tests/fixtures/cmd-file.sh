# A "sourced" file, not a stand-alone script.

# Use these commonly with:
# "${DEBUG_EXEC}" --config="${BASE_CONFIG_FILE}" --config="${CONFIG_DIR}"
# Or use this to ensure you're running with the latest binary,
# and automatically pass in the above config settings; they are
# passed in last so you can override them with arguments.
# run_am some-option another-value

# This requires the calling script to first run:
#    TEST_HOME=$( cd $( dirname "$0" ) && pwd )
#    . "${TEST_HOME}/fixtures/env-loader.sh"
test -d "${TEST_HOME}" || exit 1
DEBUG_EXEC_DIR="${PROJECT_HOME}/target/debug"
DEBUG_EXEC="${DEBUG_EXEC_DIR}/artifact-copy"

run_am() {
  time cargo run --manifest-path "${PROJECT_HOME}/Cargo.toml" -- "$@" --config="${BASE_CONFIG_FILE}" --config="${CONFIG_DIR}"
}

if [ ! -f "${DEBUG_EXEC}" ] ; then
  ( cd "${PROJECT_HOME}" && cargo build ) || exit 1
fi
if [ ! -x "${DEBUG_EXEC}" ] ; then
  >&2 echo "The artifact-monitor executable was not built correctly (${DEBUG_EXEC})"
  exit 1
fi

CONFIG_DIR="$( cd "${TEST_HOME}/../server-config.d" && pwd )" || exit 1
BASE_CONFIG_FILE="${TEST_HOME}/fixtures/simple-base-config.yaml"

