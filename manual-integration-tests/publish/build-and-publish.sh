#!/bin/sh

SERVER_SETTINGS_DIR="${SERVER_SETTINGS_DIR:-../setup}"
SERVER_SETTINGS_DIR="$( cd "${SERVER_SETTINGS_DIR}" && pwd )" || exit 1

cd "$( dirname "$0" )" || exit 1

if [ -z "$1" ] || [ "$1" = "-h" ] || [ "$1" = "--help" ] ; then
    echo "Usage: $0 <maven|npm|pypi> [nexus|artifactory|artifact-keeper]"
    exit 1
fi
project="$1"
target="$2"

NEXUS_HOST="${NEXUS_HOST:-127.0.0.1:8081}"
ARTIFACTORY_HOST="${ARTIFACTORY_HOST:-127.0.0.1:8082}"
AK_HOST="${AK_HOST:-127.0.0.1:8083}"
PUBLISH_USER="${PUBLISH_USER:-am-publisher}"


case "${project}" in
    maven)
        if [ -z "${target}" ] ; then
            target=artifactory
        fi
        case "${target}" in
            nexus)
                REPO="${REPO:-http://${NEXUS_HOST}/repository/maven-a}"
                ;;
            artifactory)
                REPO="${REPO:-http://${ARTIFACTORY_HOST}/artifactory/maven-a}"
                ;;
            artifact-keeper)
                REPO="${REPO:-http://${AK_HOST}/maven/maven-a}"
                ;;
            *)
                >&2 echo "No such server available for ${project}: ${target}"
                exit 1
        esac
        PUBLISH_PASSWORD="$( grep PUBLISH_PASSWORD= "${SERVER_SETTINGS_DIR}/${target}/.env" | cut -f 2 -d = )"
        export PUBLISH_USER
        export PUBLISH_PASSWORD
        cd maven-echo-v1 || exit 1
        echo "systemProp.REPO_URL=${REPO}" > gradle.properties
        ./gradlew --no-daemon build publish || exit 1
        ;;
    npm)
        if [ -z "${target}" ] ; then
            target=nexus
        fi
        case "${target}" in
            nexus)
                REPO="${REPO:-http://${NEXUS_HOST}/repository/npm-a}"
                ;;
            artifact-keeper)
                REPO="${REPO:-http://${AK_HOST}/npm/npm-a}"
                ;;
            *)
                # OSS Artifactory doesn't support NPM other than through
                # the 'generic' repository.
                >&2 echo "No such server available for ${project}: ${target}"
                exit 1
        esac
        PUBLISH_PASSWORD="$( grep PUBLISH_PASSWORD= "${SERVER_SETTINGS_DIR}/${target}/.env" | cut -f 2 -d = )"
        cd npm-echo || exit 1
        echo "registry = ${REPO}" > .npmrc
        echo "_auth = $( echo -n "${PUBLISH_USER}:${PUBLISH_PASSWORD}" | base64 )" >> .npmrc
        echo "email = publisher@am.example" >> .npmrc
        echo "always-auth = true" >> .npmrc
        npm publish "--registry=${REPO}" || exit 1
        ;;
    pypi)
        if [ -z "${target}" ] ; then
            target=nexus
        fi
        case "${target}" in
            nexus)
                REPO="${REPO:-http://${NEXUS_HOST}/repository/pypi-a}"
                ;;
            artifact-keeper)
                REPO="${REPO:-http://${AK_HOST}/pypi/pypi-a}"
                ;;
            *)
                # OSS Artifactory doesn't support PyPI other than through
                # the 'generic' repository.
                >&2 echo "No such server available for ${project}: ${target}"
                exit 1
        esac
        PUBLISH_PASSWORD="$( grep PUBLISH_PASSWORD= "${SERVER_SETTINGS_DIR}/${target}/.env" | cut -f 2 -d = )"
        export PUBLISH_PASSWORD
        cd pypi-echo || exit 1
        test -d .venv || python3 -m venv .venv || exit 1
        .venv/bin/pip install -e || exit 1
        .venv/bin/python3 -m build || exit 1
        .venv/bin/python3 -m twine upload --repository-url "${REPO}" dist/* || exit 1
        ;;
    *)
        >&2 echo "No such publish script available for '$1'"
        exit 1
        ;;
esac
