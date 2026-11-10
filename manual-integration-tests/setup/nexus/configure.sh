#!/bin/sh
#
# Configure a freshly started Nexus for artifact-copy's manual tests.
#
# Runs inside the compose cluster, against the REST API over the compose
# network.  It is safe to run more than once: every step checks the state it
# is about to create, so a re-run on an already-configured server changes
# nothing and still exits 0.
#
# What it does, in order:
#
#   1. waits for Nexus to answer its status endpoint;
#   2. takes the generated bootstrap password and sets the one in `.env`;
#   3. creates three hosted repositories (a, b, c) per requested format;
#   4. creates a publishing role and a read-only role, and a user for each;
#   5. narrows anonymous access to the "a" repositories, and turns it on.
#
# Anonymous access is ON and reaches exactly the "a" repository of each
# format.  That split is the point.  A server anyone can read everywhere
# cannot tell a working credential from one the tool never sends, and a
# server nobody can read anonymously cannot test the unauthenticated path
# at all.  One open repository beside two closed ones tests both, and a
# source pointed at the wrong one fails loudly.
#
# It never creates proxy repositories.  A proxy would make this cluster
# fetch from the public registries the moment anything asked it a question,
# which is a surprising thing for a local test server to do.

set -eu

NEXUS_URL="${NEXUS_URL:-http://nexus:8081}"
ADMIN_USER="${NEXUS_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"

PUBLISH_USER="${PUBLISH_USER:-am-publisher}"
PUBLISH_PASSWORD="${PUBLISH_PASSWORD:?PUBLISH_PASSWORD is required}"

READONLY_USER="${READONLY_USER:-am-reader}"
READONLY_PASSWORD="${READONLY_PASSWORD:?READONLY_PASSWORD is required}"

# Roles this script owns.  Prefixed so they are obviously not Nexus's own.
PUBLISH_ROLE="am-publish"
READONLY_ROLE="am-readonly"

FORMATS="${NEXUS_FORMATS:-raw npm pypi maven cargo}"
WAIT_SECONDS="${WAIT_SECONDS:-300}"

# Each format gets one repository per letter; the "a" one is anonymous.
# Tests read and publish "a", copy "a" into "b", and leave "c" for full
# repository copies.
REPO_LETTERS="a b c"
ANONYMOUS_LETTER="a"

# The role carrying the anonymous grants, and the prefix of the per-format
# privileges it holds (`am-anonymous-read-pypi`).
ANONYMOUS_ROLE="am-anonymous"
ANONYMOUS_PRIVILEGE_PREFIX="am-anonymous-read"

# Written by Nexus on a first start, and deleted once the password changes.
# Its absence is therefore how this tells a first run from a later one.
BOOTSTRAP_FILE="${BOOTSTRAP_FILE:-/nexus-data/admin.password}"

# The blob store every stock Nexus already has.  Creating our own would add
# a step that buys nothing for a scratch server.
BLOB_STORE="default"

BODY="/tmp/nexus-response"

# How many repositories could not be created.  Collected rather than
# failing at the first, so one unsupported format still reports the others.
failures=0

log() {
    echo "[configure] $*"
}

fail() {
    echo "[configure] ERROR: $*" >&2
}

# The password to authenticate with right now.
#
# On a first run that is the generated one in the data volume; afterwards
# the password this script already set.  Getting this wrong is the usual
# reason a re-run appears to hang on authentication, so it is decided once
# and printed.
current_password() {
    if [ -r "${BOOTSTRAP_FILE}" ]; then
        tr -d ' \t\r\n' < "${BOOTSTRAP_FILE}"
    else
        printf '%s' "${ADMIN_PASSWORD}"
    fi
}

# Wait until Nexus serves its status endpoint.
#
# `/service/rest/v1/status` answers 200 only once the repository manager is
# actually up, which is later than the port opening - connecting too early
# gets a 503 from a server that is still unpacking itself.
wait_for_nexus() {
    waited=0

    log "waiting for ${NEXUS_URL} (up to ${WAIT_SECONDS}s)"

    while [ "${waited}" -lt "${WAIT_SECONDS}" ]; do
        status="$(curl -sS -o /dev/null -w '%{http_code}' \
            "${NEXUS_URL}/service/rest/v1/status" 2>/dev/null || echo 000)"

        if [ "${status}" = "200" ]; then
            log "nexus is up after ${waited}s"
            return 0
        fi

        sleep 5
        waited=$((waited + 5))
    done

    fail "nexus did not become ready within ${WAIT_SECONDS}s"
    fail "check 'docker compose logs nexus'"

    return 1
}

# GET a path, leaving the body in $BODY and echoing the status code.
api_get() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        "${NEXUS_URL}$1" || echo "000"
}

# POST JSON to a path, leaving the body in $BODY and echoing the status code.
api_post_json() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        -H 'Content-Type: application/json' \
        -X POST --data-binary "$2" \
        "${NEXUS_URL}$1" || echo "000"
}

# PUT JSON to a path, leaving the body in $BODY and echoing the status code.
api_put_json() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        -H 'Content-Type: application/json' \
        -X PUT --data-binary "$2" \
        "${NEXUS_URL}$1" || echo "000"
}

# Replace the generated password with the known one.
#
# Nexus takes the new password as a text/plain body rather than as JSON,
# which is unlike every other endpoint here.
set_admin_password() {
    if [ ! -r "${BOOTSTRAP_FILE}" ]; then
        log "admin password already set (no ${BOOTSTRAP_FILE})"
        return 0
    fi

    log "setting the admin password"

    status="$(curl -sS -o "${BODY}" -w '%{http_code}' \
        -u "${ADMIN_USER}:${PASSWORD}" \
        -H 'Content-Type: text/plain' \
        -X PUT --data-binary "${ADMIN_PASSWORD}" \
        "${NEXUS_URL}/service/rest/v1/security/users/${ADMIN_USER}/change-password")"

    if [ "${status}" != "204" ]; then
        fail "could not set the admin password (HTTP ${status})"
        cat "${BODY}" >&2 || true

        return 1
    fi

    # Everything after this authenticates with the new password.
    PASSWORD="${ADMIN_PASSWORD}"

    log "admin password is now the configured one"
}

# Switch anonymous access on or off.
set_anonymous() {
    enabled="$1"

    status="$(api_put_json /service/rest/v1/security/anonymous \
        "$(printf '{"enabled":%s,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' \
            "${enabled}")")"

    if [ "${status}" != "200" ]; then
        fail "could not set anonymous access to ${enabled} (HTTP ${status})"
        cat "${BODY}" >&2 || true

        failures=$((failures + 1))

        return 1
    fi
}

# Create the read+browse privilege for one repository.
#
# Named per repository rather than using Nexus's wildcards, which is the
# whole point here: the wildcard privileges the other roles use would give
# anonymous every repository on the server.
create_read_privilege() {
    name="$1"
    format="$2"
    repository="$3"

    status="$(api_get "/service/rest/v1/security/privileges/${name}")"

    if [ "${status}" = "200" ]; then
        log "privilege ${name} already exists"
        return 0
    fi

    log "creating privilege ${name} (${format}:${repository})"

    status="$(api_post_json /service/rest/v1/security/privileges/repository-view \
        "$(printf '{"name":"%s","description":"Anonymous read of %s","actions":["BROWSE","READ"],"format":"%s","repository":"%s"}' \
            "${name}" "${repository}" "${format}" "${repository}")")"

    if [ "${status}" != "200" ] && [ "${status}" != "201" ]; then
        fail "could not create privilege ${name} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi
}

# Point the built-in `anonymous` user at one role and nothing else.
#
# Nexus ships it holding `nx-anonymous`, which carries wildcard read over
# every repository.  Replacing its roles is what narrows it; the built-in
# role itself cannot be edited.
#
# The whole user object is written rather than patched because there is no
# JSON parser in this image, and these are the fields a stock Nexus ships.
set_anonymous_roles() {
    role="$1"

    log "restricting the anonymous user to ${role}"

    status="$(api_put_json /service/rest/v1/security/users/anonymous \
        "$(printf '{"userId":"anonymous","firstName":"Anonymous","lastName":"User","emailAddress":"anonymous@example.org","source":"default","status":"active","roles":["%s"]}' \
            "${role}")")"

    if [ "${status}" != "200" ] && [ "${status}" != "204" ]; then
        fail "could not set the anonymous user's roles (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi
}

# Give anonymous read of each format's "a" repository, then turn it on.
#
# In that order.  Enabling first would leave a window, however short, where
# anonymous still holds the stock wildcard read over everything.
open_anonymous_repos() {
    # A JSON list body of privilege names: `"p1","p2"`.
    privileges=""

    for format in ${FORMATS}; do
        name="${ANONYMOUS_PRIVILEGE_PREFIX}-${format}"

        create_read_privilege "${name}" "${format}" \
            "$(repo_name "${format}" "${ANONYMOUS_LETTER}")" || return 1

        privileges="${privileges:+${privileges},}\"${name}\""
    done

    create_role "${ANONYMOUS_ROLE}" \
        "Anonymous read of the ${ANONYMOUS_LETTER} repositories only" \
        "${privileges}" || return 1

    set_anonymous_roles "${ANONYMOUS_ROLE}" || return 1

    log "enabling anonymous access (*-${ANONYMOUS_LETTER} only)"

    set_anonymous true || return 1
}

# Create a role granting a set of built-in privileges.
#
# The privileges are Nexus's own wildcard ones rather than per-repository
# grants: this server's repositories come and go with NEXUS_FORMATS, and a
# role naming them individually would need editing every time that changed.
create_role() {
    id="$1"
    description="$2"
    privileges="$3"

    status="$(api_get "/service/rest/v1/security/roles/${id}")"

    if [ "${status}" = "200" ]; then
        log "role ${id} already exists"
        return 0
    fi

    log "creating role ${id}"

    status="$(api_post_json /service/rest/v1/security/roles \
        "$(printf '{"id":"%s","name":"%s","description":"%s","privileges":[%s],"roles":[]}' \
            "${id}" "${id}" "${description}" "${privileges}")")"

    if [ "${status}" != "200" ] && [ "${status}" != "201" ]; then
        fail "could not create role ${id} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi
}

# Create a user holding one role.
#
# Idempotent by checking first: the create endpoint answers 400 rather than
# 409 for a duplicate, which is indistinguishable from a rejected password.
create_user() {
    user_id="$1"
    role="$2"
    password="$3"

    status="$(api_get "/service/rest/v1/security/users?userId=${user_id}")"

    # The search endpoint answers 200 with an empty list when there is no
    # such user, so the status alone does not settle it.  Whitespace-
    # tolerant, because how a server spaces its JSON is not something it
    # promises and a false "not found" here re-creates an existing user.
    if [ "${status}" = "200" ] \
        && grep -Eq "\"userId\"[[:space:]]*:[[:space:]]*\"${user_id}\"" "${BODY}"; then
        log "user ${user_id} already exists"
        return 0
    fi

    log "creating user ${user_id}"

    status="$(api_post_json /service/rest/v1/security/users \
        "$(printf '{"userId":"%s","firstName":"%s","lastName":"user","emailAddress":"%s@example.invalid","password":"%s","status":"active","roles":["%s"]}' \
            "${user_id}" "${user_id}" "${user_id}" "${password}" "${role}")")"

    if [ "${status}" != "200" ] && [ "${status}" != "201" ]; then
        fail "could not create user ${user_id} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))
    fi
}

# The two accounts the tool authenticates as.
#
# Separate on purpose: a source and an enumerator should work with the
# read-only account, and if they ever need the publishing one that is a bug
# worth seeing here rather than in somebody's registry.
create_accounts() {
    # `|| true` because these report their own failures into the counter,
    # and `set -e` would otherwise stop at the first one - losing the
    # report of everything after it.
    create_role "${READONLY_ROLE}" \
        "Read and browse every repository" \
        '"nx-repository-view-*-*-read","nx-repository-view-*-*-browse"' || true

    create_role "${PUBLISH_ROLE}" \
        "Read, browse and write every repository" \
        '"nx-repository-view-*-*-*"' || true

    create_user "${READONLY_USER}" "${READONLY_ROLE}" "${READONLY_PASSWORD}"
    create_user "${PUBLISH_USER}" "${PUBLISH_ROLE}" "${PUBLISH_PASSWORD}"
}

# The repository name this script uses for a format and letter, e.g.
# `maven-a`.
#
# Kept in one place because `server-config.d` has to agree with it, and two
# lists of names drift.
repo_name() {
    echo "$1-$2"
}

# The creation payload for a format.
#
# Maven needs two policies that have no sensible default for a test server:
# RELEASE because snapshots have their own resolution rules, and STRICT so a
# badly-laid-out upload is refused here rather than confusing the tool.
repo_payload() {
    format="$1"
    name="$2"

    storage="\"storage\":{\"blobStoreName\":\"${BLOB_STORE}\",\"strictContentTypeValidation\":true,\"writePolicy\":\"ALLOW\"}"

    case "${format}" in
        maven)
            printf '{"name":"%s","online":true,%s,"maven":{"versionPolicy":"RELEASE","layoutPolicy":"STRICT","contentDisposition":"INLINE"}}' \
                "${name}" "${storage}"
            ;;
        *)
            printf '{"name":"%s","online":true,%s}' "${name}" "${storage}"
            ;;
    esac
}

# Create one hosted repository, if it is not already there.
create_repo() {
    format="$1"
    name="$(repo_name "${format}" "$2")"

    status="$(api_get "/service/rest/v1/repositories/${name}")"

    if [ "${status}" = "200" ]; then
        log "${name} (${format}) already exists"
        return 0
    fi

    log "creating ${name} (${format})"

    status="$(api_post_json "/service/rest/v1/repositories/${format}/hosted" \
        "$(repo_payload "${format}" "${name}")")"

    case "${status}" in
        201)
            log "created ${name}"
            ;;
        404)
            # The endpoint itself is missing, which means this Nexus does
            # not know the format.  Said plainly, because the alternative
            # reading - "the server is broken" - sends you looking in the
            # wrong place entirely.
            fail "this Nexus does not support the '${format}' format."
            fail "  Cargo in particular needs a recent release; set"
            fail "  NEXUS_VERSION to a newer tag, or drop the format from"
            fail "  NEXUS_FORMATS."
            failures=$((failures + 1))
            ;;
        *)
            fail "could not create ${name} (HTTP ${status})"
            cat "${BODY}" >&2 || true
            failures=$((failures + 1))
            ;;
    esac
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
    wait_for_nexus || exit 1

    PASSWORD="$(current_password)"

    set_admin_password || exit 1

    # Repositories first: a privilege naming one cannot be created before it
    # exists, and the anonymous grants below name them.
    for format in ${FORMATS}; do
        for letter in ${REPO_LETTERS}; do
            create_repo "${format}" "${letter}"
        done
    done

    create_accounts
    open_anonymous_repos || true

    echo
    log "repositories now on this server:"

    if [ "$(api_get /service/rest/v1/repositories)" = "200" ]; then
        # No jq in this image, so the names are pulled out with sed rather
        # than parsed.  Names only, and tolerant of whitespace: matching a
        # pair of adjacent fields would depend on the order Nexus happens
        # to serialize them in, which is not something it promises.  It is
        # a log line, not a contract.
        tr ',' '\n' < "${BODY}" \
            | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/  \1/p' \
            || true
    fi

    echo

    if [ "${failures}" -ne 0 ]; then
        fail "${failures} step(s) failed"
        exit 1
    fi

    log "done.  Nexus is at ${NEXUS_URL}"
    log "  admin:     ${ADMIN_USER}"
    log "  publish:   ${PUBLISH_USER}"
    log "  read-only: ${READONLY_USER}"
    log "  anonymous: read of every *-${ANONYMOUS_LETTER} repository"
    log ""
    log "The passwords are in setup/nexus/.env, which the tool reads directly."
    log "Nothing needs exporting; run from the repository root:"
    log "  artifact-copy --config manual-integration-tests/server-config.d ..."
    log "The EULA still needs accepting (see manual-integration-tests/setup/nexus/accept-eula.sh)."
}

main "$@"
