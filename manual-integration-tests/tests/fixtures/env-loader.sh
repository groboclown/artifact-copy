# A "sourced" file, not a stand-alone script.

# This requires the calling script to first run:
#    TEST_HOME=$( cd $( dirname "$0" ) && pwd )
#    . "${TEST_HOME}/fixtures/env-loader.sh"
test -d "${TEST_HOME}" || exit 1

PROJECT_HOME="${TEST_HOME}/../.."
TEST_OUT="${PROJECT_HOME}/local-test-out"

PUBLISH_DIR="${TEST_HOME}/../publish"

NEXUS_HOME="${TEST_HOME}/../setup/nexus"
ARTIFACTORY_HOME="${TEST_HOME}/../setup/artifactory"
ARTIFACT_KEEPER_HOME="${TEST_HOME}/../setup/artifact-keeper"

# Ensure the environments are what we expect.
test -f "${ARTIFACT_KEEPER_HOME}/.env" || exit 1
test -f "${ARTIFACTORY_HOME}/.env" || exit 1
test -f "${NEXUS_HOME}/.env" || exit 1


DEFAULT_SERVER_HOSTNAME="${DEFAULT_SERVER_HOSTNAME:-127.0.0.1}"
NEXUS_HOSTNAME="${NEXUS_HOSTNAME:-${DEFAULT_SERVER_HOSTNAME}}"
ARTIFACTORY_HOSTNAME="${ARTIFACTORY_HOSTNAME:-${DEFAULT_SERVER_HOSTNAME}}"
ARTIFACT_KEEPER_HOSTNAME="${ARTIFACT_KEEPER_HOSTNAME:-${DEFAULT_SERVER_HOSTNAME}}"
NEXUS_PORT="${NEXUS_PORT:-8081}"
ARTIFACTORY_PORT="${ARTIFACTORY_PORT:-8082}"
ARTIFACT_KEEPER_PORT="${ARTIFACT_KEEPER_PORT:-8083}"
NEXUS_HOST="${NEXUS_HOST:-${NEXUS_HOSTNAME}:${NEXUS_PORT}}"
ARTIFACTORY_HOST="${ARTIFACTORY_HOST:-${ARTIFACTORY_HOSTNAME}:${ARTIFACTORY_PORT}}"
ARTIFACT_KEEPER_HOST="${ARTIFACT_KEEPER_HOST:-${ARTIFACT_KEEPER_HOSTNAME}:${ARTIFACT_KEEPER_PORT}}"
PUBLISH_USER="${PUBLISH_USER:-am-publisher}"
READONLY_USER="${READONLY_USER:-am-reader}"
ADMIN_USER="${ADMIN_USER:-admin}"

NEXUS_READONLY_PASSWORD="$( grep -E '^READONLY_PASSWORD=' "${NEXUS_HOME}/.env" | cut -f 2 -d = )" || exit 1
NEXUS_PUBLISH_PASSWORD="$( grep -E '^PUBLISH_PASSWORD=' "${NEXUS_HOME}/.env" | cut -f 2 -d = )" || exit 1
NEXUS_ADMIN_PASSWORD="$( grep -E '^ADMIN_PASSWORD=' "${NEXUS_HOME}/.env" | cut -f 2 -d = )" || exit 1

# Admin only: the OSS edition refuses user management over REST.
ARTIFACTORY_ADMIN_PASSWORD="$( grep -E '^ADMIN_PASSWORD=' "${ARTIFACTORY_HOME}/.env" | cut -f 2 -d = )" || exit 1

ARTIFACT_KEEPER_READONLY_PASSWORD="$( grep -E '^READONLY_PASSWORD=' "${ARTIFACT_KEEPER_HOME}/.env" | cut -f 2 -d = )" || exit 1
ARTIFACT_KEEPER_PUBLISH_PASSWORD="$( grep -E '^PUBLISH_PASSWORD=' "${ARTIFACT_KEEPER_HOME}/.env" | cut -f 2 -d = )" || exit 1
