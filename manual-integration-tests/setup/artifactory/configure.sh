#!/bin/sh
#
# Configure a freshly started Artifactory for artifact-copy's manual
# tests.
#
# Runs inside the compose cluster, against the REST API over the compose
# network.  It is safe to run more than once: every step checks the state it
# is about to create, so a re-run on an already-configured server changes
# nothing and still exits 0.
#
# What it does, in order:
#
#   1. waits for Artifactory to answer its ping endpoint;
#   2. replaces the out-of-the-box administrator password;
#   3. creates an admin access token, which the Access service requires;
#   4. creates three local repositories (a, b, c) per requested format;
#   5. grants anonymous read of each "a" repository, and turns anonymous
#      access on.
#
# No publishing or read-only user.  The OSS edition refuses user management
# over REST, even to an admin token, so the tool authenticates as admin.
#
# The Access calls work only because `access.config.import.yml` beside this
# script opens them to Basic-created tokens and admin tokens.
#
# Anonymous access is ON and reaches exactly the "a" repository of each
# format.  A server anyone can read everywhere cannot tell a working
# credential from one the tool never sends, and a server nobody can read
# anonymously never exercises the unauthenticated path.  One open
# repository beside two closed ones tests both.
#
# # This is a separate program from the Nexus one, on purpose
#
# The two products differ in nearly every call made here - Artifactory
# creates repositories with PUT and a package type, keeps users in a
# separate Access service, and expresses authorization as permission
# targets rather than as roles holding privileges.  Sharing a script would
# mean a wrapper per call with nothing left in common underneath.

set -eu

ARTIFACTORY_URL="${ARTIFACTORY_URL:-http://artifactory:8082}"

# Everything the repository manager serves hangs off this prefix; the Access
# service, which owns users, does not.  Both are behind the same router.
REST="${ARTIFACTORY_URL}/artifactory/api"
ACCESS="${ARTIFACTORY_URL}/access/api"

ADMIN_USER="${ARTIFACTORY_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"

# What Artifactory ships with, and what this replaces on a first run.
BOOTSTRAP_PASSWORD="${ARTIFACTORY_BOOTSTRAP_PASSWORD:-password}"

FORMATS="${ARTIFACTORY_FORMATS:-maven generic ivy}"
WAIT_SECONDS="${WAIT_SECONDS:-900}"

# Each format gets one repository per letter; the "a" one is anonymous.
# Tests read and publish "a", copy "a" into "b", and leave "c" for full
# repository copies.
REPO_LETTERS="a b c"
ANONYMOUS_LETTER="a"

# Prefix of the per-format permission targets this script owns
# (`am-anonymous-maven`).  Prefixed so they are obviously not Artifactory's
# own.
ANONYMOUS_PERMISSION_PREFIX="am-anonymous"

# Lifetime of the admin token.  Long enough for one run, short enough that a
# leaked log line is soon worthless.
TOKEN_EXPIRY_SECONDS=3600

BODY="/tmp/artifactory-response"

# How many steps could not be completed.  Collected rather than failing at
# the first, so one unsupported format still reports the others.
failures=0

# The password authentication currently uses.  Decided once, in main.
PASSWORD=""

# The admin token for the Access service, which refuses Basic.  Set once,
# in main, after the password.
TOKEN=""

log() {
    echo "[configure] $*"
}

fail() {
    echo "[configure] ERROR: $*" >&2
}

# Wait until Artifactory answers.
#
# `/artifactory/api/system/ping` returns 200 only once the repository
# manager is serving, which is well after the port opens - Artifactory
# builds its database on a first start and answers 503 throughout.
wait_for_artifactory() {
    waited=0

    log "waiting for ${ARTIFACTORY_URL} (up to ${WAIT_SECONDS}s)"

    while [ "${waited}" -lt "${WAIT_SECONDS}" ]; do
        status="$(curl -sS -o /dev/null -w '%{http_code}' \
            "${REST}/system/ping" 2>/dev/null || echo 000)"

        if [ "${status}" = "200" ]; then
            log "artifactory is up after ${waited}s"
            return 0
        fi

        sleep 5
        waited=$((waited + 5))
    done

    fail "artifactory did not become ready within ${WAIT_SECONDS}s"
    fail "check 'docker compose logs artifactory'"

    return 1
}

# GET a url, leaving the body in $BODY and echoing the status code.
api_get() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        "$1" || echo "000"
}

# Send JSON to a url with the given method.
api_json() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        -H 'Content-Type: application/json' \
        -X "$1" --data-binary "$3" \
        "$2" || echo "000"
}

# Send to the Access service with the admin token.  The data is optional.
access_call() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -H "Authorization: Bearer ${TOKEN}" \
        -H 'Content-Type: application/json' \
        -X "$1" ${3:+--data-binary "$3"} \
        "$2" || echo "000"
}

# Whether a set of credentials is accepted.
#
# Used to tell a first run from a later one.  Artifactory keeps no
# equivalent of Nexus's bootstrap password file, so the only way to know
# which password is live is to try one.
credentials_work() {
    candidate="$1"

    status="$(curl -sS -o /dev/null -w '%{http_code}' \
        -u "${ADMIN_USER}:${candidate}" \
        "${REST}/system/version" 2>/dev/null || echo 000)"

    [ "${status}" = "200" ]
}

# Replace the out-of-the-box administrator password.
#
# Skipped when the configured password already works, which is what makes a
# re-run harmless.
set_admin_password() {
    if credentials_work "${ADMIN_PASSWORD}"; then
        log "admin password is already the configured one"
        PASSWORD="${ADMIN_PASSWORD}"

        return 0
    fi

    if ! credentials_work "${BOOTSTRAP_PASSWORD}"; then
        fail "neither the configured nor the bootstrap admin password is"
        fail "  accepted.  If this server was configured with a different"
        fail "  .env, delete the cluster's volume and start again:"
        fail "    docker compose down -v"

        return 1
    fi

    log "setting the admin password"

    PASSWORD="${BOOTSTRAP_PASSWORD}"

    # Older versions of Artifactory just have 'newPassword'.
    status="$(api_json POST "${REST}/security/users/authorization/changePassword" \
        "$(printf '{"userName":"%s","oldPassword":"%s","newPassword1":"%s","newPassword2":"%s"}' \
            "${ADMIN_USER}" "${BOOTSTRAP_PASSWORD}" "${ADMIN_PASSWORD}" "${ADMIN_PASSWORD}")")"

    if [ "${status}" != "200" ]; then
        fail "could not set the admin password (HTTP ${status})"
        cat "${BODY}" >&2 || true

        return 1
    fi

    # Everything after this authenticates with the new password.
    PASSWORD="${ADMIN_PASSWORD}"

    log "admin password is now the configured one"
}

# The repository key this script uses for a format and letter, e.g.
# `maven-a`.
#
# Kept in one place because `server-config.d` has to agree with it, and two
# lists of names drift.
repo_name() {
    echo "$1-$2"
}

# Merge a YAML patch into the configuration descriptor.
#
# The descriptor is XML, and rewriting XML without a parser is how a server
# ends up unbootable.  Artifactory accepts a YAML patch of just the fields
# in question instead, and current OSS images serve this where they refuse
# the repository and permission APIs as Pro-only.
config_patch() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        -H 'Content-Type: application/yaml' \
        -X PATCH \
        --data-binary "$1" \
        "${REST}/system/configuration" || echo "000"
}

# Create one local repository, if it is not already there.
#
# Checked against the repository list, because `GET /repositories/{key}`
# is Pro-only on current OSS images.  Created through the descriptor for the
# same reason.  The patch accepts any package type, npm included, so this
# no longer detects a format the edition does not license.
create_repo() {
    format="$1"
    name="$(repo_name "${format}" "$2")"

    if [ "$(api_get "${REST}/repositories")" = "200" ] \
        && grep -q "\"key\"[[:space:]]*:[[:space:]]*\"${name}\"" "${BODY}"; then
        log "${name} (${format}) already exists"
        return 0
    fi

    log "creating ${name} (${format})"

    status="$(config_patch "$(printf 'localRepositories:\n  %s:\n    type: %s\n' \
        "${name}" "${format}")")"

    if [ "${status}" != "200" ]; then
        fail "could not create ${name} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi

    log "created ${name}"
}

# Create the admin token the Access service requires.
#
# Created with Basic, which Access allows only with `token.allow-basic-auth`
# from `access.config.import.yml`.  Parsed with sed, as there is no jq here.
fetch_token() {
    status="$(curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        -X POST \
        -d 'scope=applied-permissions/admin' \
        -d "expires_in=${TOKEN_EXPIRY_SECONDS}" \
        "${ACCESS}/v1/tokens" || echo "000")"

    if [ "${status}" != "200" ]; then
        fail "could not create an admin token (HTTP ${status})"
        fail "  Access needs token.allow-basic-auth; see access.config.import.yml."
        cat "${BODY}" >&2 || true

        return 1
    fi

    TOKEN="$(tr -d '\n' < "${BODY}" \
        | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

    if [ -z "${TOKEN}" ]; then
        fail "the token response held no access_token"

        return 1
    fi
}

# Create or replace a permission target granting one user a set of actions
# on one repository.
#
# The Access v1 permissions API, open to an admin token only with
# `permissions.allow-admin-access-to-permissions-v1-api`.  Actions are
# single letters: `r` read, `w` deploy, `d` delete, `n` annotate, `m`
# manage.
#
# The `_artifact` suffix and the `custom_data` string copy what Artifactory
# writes for its own targets, e.g. `Anything_artifact`.  The service id is
# required.  PUT replaces an existing target and answers 404 for a missing
# one, which POST then creates.
create_permission() {
    name="$1"
    repository="$2"
    user="$3"
    actions="$4"

    log "granting ${user} [${actions}] on ${repository}"

    status="$(access_call GET "${ACCESS}/v1/system/service_id")"

    if [ "${status}" != "200" ]; then
        fail "could not read the Access service id (HTTP ${status})"
        failures=$((failures + 1))

        return 1
    fi

    service_id="$(cat "${BODY}")"

    body="$(printf '{"name":"%s_artifact","display_name":"%s","resource_type":"repo","service_id":"%s","custom_data":"{\\"permissionIdentifier\\":\\"%s\\",\\"excludePattern\\":\\"\\",\\"repoKeys\\":[\\"%s\\"],\\"includePattern\\":\\"**\\"}","actions":{"users":{"%s":[%s]},"groups":{}}}' \
        "${name}" "${name}" "${service_id}" "${name}" "${repository}" "${user}" "${actions}")"

    status="$(access_call PUT "${ACCESS}/v1/permissions/${name}_artifact" "${body}")"

    if [ "${status}" = "404" ]; then
        status="$(access_call POST "${ACCESS}/v1/permissions" "${body}")"
    fi

    if [ "${status}" != "200" ] && [ "${status}" != "201" ]; then
        fail "could not create permission ${name} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi
}

# Switch anonymous access on or off.
set_anonymous() {
    enabled="$1"

    status="$(config_patch "$(printf 'security:\n  anonAccessEnabled: %s\n' "${enabled}")")"

    if [ "${status}" != "200" ]; then
        fail "could not set anonymous access to ${enabled} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi
}

# Give anonymous read of each format's "a" repository, then turn it on.
#
# In that order.  Enabling first would leave a window, however short, in
# which anonymous holds whatever Artifactory grants it by default.
open_anonymous_repos() {
    # One target per repository: each names exactly one, which is what
    # keeps the grant from spreading.
    for format in ${FORMATS}; do
        create_permission "${ANONYMOUS_PERMISSION_PREFIX}-${format}" \
            "$(repo_name "${format}" "${ANONYMOUS_LETTER}")" \
            anonymous '"r"' || return 1
    done

    log "enabling anonymous access (*-${ANONYMOUS_LETTER} only)"

    set_anonymous true || return 1
}

# Refuse to start without the tools, rather than mistaking one for a server
# that will not answer.
#
# A missing `curl` is indistinguishable from a dead server once the wait
# loop starts: every probe reports 000 either way, and the run ends after
# WAIT_SECONDS blaming the server. That is exactly what an `apk add` which
# quietly installed nothing looked like. The configuration now runs on an
# image that already carries what it needs, and this makes the day that
# stops being true say so in one line.
require_tools() {
    missing=""

    for tool in curl sed tr grep; do
        command -v "${tool}" >/dev/null 2>&1 || missing="${missing} ${tool}"
    done

    if [ -n "${missing}" ]; then
        fail "this image is missing:${missing}"
        fail "  Nothing here installs packages at run time, so the image named"
        fail "  by the 'configure' service has to carry them already."

        return 1
    fi
}

main() {
    require_tools || exit 1
    wait_for_artifactory || exit 1

    set_admin_password || exit 1
    fetch_token || exit 1

    # Repositories first: a permission target naming one cannot be created
    # before it exists, and the anonymous grants below name them.
    for format in ${FORMATS}; do
        for letter in ${REPO_LETTERS}; do
            create_repo "${format}" "${letter}" || true
        done
    done

    open_anonymous_repos || true

    echo
    log "repositories now on this server:"

    if [ "$(api_get "${REST}/repositories")" = "200" ]; then
        # No jq in this image, so the keys are pulled out with sed rather
        # than parsed.  Whitespace-tolerant, because how a server spaces its
        # JSON is not something it promises.  It is a log line, not a
        # contract.
        tr ',' '\n' < "${BODY}" \
            | sed -n 's/.*"key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/  \1/p' \
            || true
    fi

    echo

    if [ "${failures}" -ne 0 ]; then
        fail "${failures} step(s) failed"
        exit 1
    fi

    log "done.  Artifactory is at ${ARTIFACTORY_URL}"
    log "  admin:     ${ADMIN_USER}"
    log "  anonymous: read of every *-${ANONYMOUS_LETTER} repository"

    log ""
    log "The admin password is in setup/artifactory/.env, which the tool reads"
    log "directly.  Nothing needs exporting; run from the repository root:"
    log "  artifact-copy --config manual-integration-tests/server-config.d ..."
}

main "$@"
