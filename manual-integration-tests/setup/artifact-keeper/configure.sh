#!/bin/sh
#
# Configure a freshly started Artifact Keeper for artifact-copy's manual
# tests.
#
# Runs inside the compose cluster, against the REST API over the compose
# network.  It is safe to run more than once: every step checks the state it
# is about to create, so a re-run on an already-configured server changes
# nothing and still exits 0.
#
# What it does, in order:
#
#   1. waits for the backend to answer its liveness endpoint;
#   2. logs in as the administrator and holds the bearer token;
#   3. creates three local repositories (a, b, c) per requested format,
#      opening each "a" one to anonymous read;
#   4. creates a publishing user and a read-only user;
#   5. grants each of them the matching actions on every repository.
#
# # No password-change dance
#
# Unlike the other two servers here, nothing needs to replace a bootstrap
# password.  The compose file sets `ADMIN_PASSWORD`, and the backend then
# creates the administrator with that password and leaves
# `must_change_password` clear, so the API is open for business as soon as
# it is up.  Without that variable it would generate a password into its
# storage volume and lock every endpoint behind a setup guard until someone
# read it out.
#
# # Anonymous access is a property of the repository
#
# The cleanest of the three models.  Nexus needs a privilege in a role
# assigned to a built-in user, and Artifactory needs a permission target
# plus a global switch; here a repository simply carries
# `allow_anonymous_access`, and the server-wide `AK_GUEST_ACCESS_ENABLED`
# decides whether any of them are honored.  Each format's "a" repository
# gets it and the rest do not, for the reason the other two files give: a
# server anyone can read everywhere cannot tell a working credential from
# one the tool never sends, and a server nobody can read anonymously never
# exercises the unauthenticated path.
#
# # No jq, and nothing installed at runtime
#
# The API answers with the UUID of each thing it creates and wants that UUID
# back when granting a permission on it, so this does have to read JSON.
#
# So this runs on an image that already carries what it needs, exactly as
# the Nexus and Artifactory scripts do, and reads JSON with `sed`.
#
# Reading JSON with `sed` is only safe under conditions this script meets
# and a general tool would not:
#
#   - Every value it *sends* is one it generated or that is fixed here --
#     hex passwords, repository keys built from a format name -- so no
#     escaping is at stake.
#   - Every value it *reads* is an opaque token or a UUID, neither of which
#     can contain a quote.
#   - The one list it searches is flat, so splitting on `{` puts each
#     record in its own chunk and a field cannot be attributed to the wrong
#     one.
#
# The extraction is checked against the live API rather than assumed.

set -eu

BASE="${ARTIFACT_KEEPER_URL:-http://backend:8080}"
API="${BASE}/api/v1"

ADMIN_USER="${ARTIFACT_KEEPER_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"

PUBLISH_USER="${PUBLISH_USER:-am-publisher}"
PUBLISH_PASSWORD="${PUBLISH_PASSWORD:?PUBLISH_PASSWORD is required}"

READONLY_USER="${READONLY_USER:-am-reader}"
READONLY_PASSWORD="${READONLY_PASSWORD:?READONLY_PASSWORD is required}"

FORMATS="${ARTIFACT_KEEPER_FORMATS:-npm pypi maven docker conan generic}"
WAIT_SECONDS="${WAIT_SECONDS:-600}"

# Each format gets one repository per letter; the "a" one is anonymous.
# Tests read and publish "a", copy "a" into "b", and leave "c" for full
# repository copies.
REPO_LETTERS="a b c"
ANONYMOUS_LETTER="a"

BODY="/tmp/ak-response"

# How many steps could not be completed.  Collected rather than failing at
# the first, so one unsupported format still reports the others.
failures=0

# Filled in by `log_in`.
TOKEN=""

log() {
    echo "[configure] $*"
}

fail() {
    echo "[configure] ERROR: $*" >&2
}

# Wait until the backend is live.
#
# `/livez` is unauthenticated and answers only once the router is serving.
wait_for_backend() {
    waited=0

    log "waiting for ${BASE} (up to ${WAIT_SECONDS}s)"

    while [ "${waited}" -lt "${WAIT_SECONDS}" ]; do
        echo "Trying ${BASE}/livez"
        status="$(curl -sS -o /dev/null -w '%{http_code}' \
            "${BASE}/livez" 2>/dev/null || echo 000)"

        if [ "${status}" = "200" ]; then
            log "artifact keeper is up after ${waited}s"
            return 0
        fi
        echo "Failed connection with ${status}"

        sleep 3
        waited=$((waited + 3))
    done

    fail "the backend did not become ready within ${WAIT_SECONDS}s"
    fail "check 'docker compose logs backend'"

    return 1
}

# The value of a string field, from a JSON object in $BODY.
#
# Whitespace-tolerant around the colon, because how a server spaces its
# JSON is not something it promises. First match wins, which is what a
# single-object response wants.
field() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "${BODY}" \
        | head -n 1
}

# GET a path under /api/v1, leaving the body in $BODY, echoing the status.
api_get() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -H "Authorization: Bearer ${TOKEN}" \
        "${API}$1" || echo "000"
}

# Send JSON to a path under /api/v1 with the given method.
api_json() {
    curl -sS -o "${BODY}" -w '%{http_code}' \
        -H "Authorization: Bearer ${TOKEN}" \
        -H 'Content-Type: application/json' \
        -X "$1" --data-binary "$3" \
        "${API}$2" || echo "000"
}

# Exchange the admin password for a bearer token.
log_in() {
    log "logging in as ${ADMIN_USER}"

    status="$(curl -sS -o "${BODY}" -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        -X POST --data-binary "$(printf '{"username":"%s","password":"%s"}' \
            "${ADMIN_USER}" "${ADMIN_PASSWORD}")" \
        "${API}/auth/login" || echo "000")"

    if [ "${status}" != "200" ]; then
        fail "could not log in as ${ADMIN_USER} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        fail ""
        fail "  If this server was configured with a different .env, delete"
        fail "  the cluster's volumes and start again:"
        fail "    docker compose down -v"

        return 1
    fi

    TOKEN="$(field access_token)"

    if [ -z "${TOKEN}" ]; then
        # A login that succeeds without a token means the account needs
        # something else first - TOTP enrolment, or a password change. Said
        # plainly, because "empty token" on its own reads as a bug here.
        fail "logged in but no access token was issued."
        fail "  The admin account is probably mid-setup (a forced password"
        fail "  change, or 2FA enrolment).  Response:"
        cat "${BODY}" >&2 || true

        return 1
    fi

    log "authenticated"
}

# The repository key this script uses for a format and letter, e.g.
# `maven-a`.
#
# Kept in one place because `server-config.d` has to agree with it, and two
# lists of names drift.
repo_name() {
    echo "$1-$2"
}

# Whether repositories with this letter are open to anonymous read.
is_anonymous_letter() {
    [ "$1" = "${ANONYMOUS_LETTER}" ]
}

# Create one local repository, if it is not already there.
create_repo() {
    format="$1"
    letter="$2"
    name="$(repo_name "${format}" "${letter}")"

    if [ "$(api_get "/repositories/${name}")" = "200" ]; then
        log "${name} (${format}) already exists"
        return 0
    fi

    if is_anonymous_letter "${letter}"; then
        anonymous=true
        log "creating ${name} (${format}), open to anonymous read"
    else
        anonymous=false
        log "creating ${name} (${format})"
    fi

    status="$(api_json POST /repositories "$(printf \
        '{"key":"%s","name":"%s","description":"%s","format":"%s","repo_type":"local","allow_anonymous_access":%s}' \
        "${name}" "${name}" "artifact-copy manual integration tests" \
        "${format}" "${anonymous}")")"

    case "${status}" in
        200|201)
            log "created ${name}"
            ;;
        400|422)
            # The likeliest cause by far is a format this build does not
            # know, so the message says which knob to turn rather than
            # leaving a bare validation error to be interpreted.
            fail "refused to create ${name} (HTTP ${status})."
            fail "  '${format}' may not be a format this build serves; check"
            fail "  ARTIFACT_KEEPER_FORMATS.  Response:"
            cat "${BODY}" >&2 || true
            failures=$((failures + 1))
            ;;
        *)
            fail "could not create ${name} (HTTP ${status})"
            cat "${BODY}" >&2 || true
            failures=$((failures + 1))
            ;;
    esac
}

# The id of a repository, by key.
repo_id() {
    if [ "$(api_get "/repositories/$1")" != "200" ]; then
        return 1
    fi

    field id
}

# The id of a user, by username.
#
# Looked up through the list endpoint because there is no get-by-name: the
# id is what a permission grant needs, and it is only ever learned this way.
user_id() {
    wanted="$1"

    if [ "$(api_get "/users?per_page=200")" != "200" ]; then
        return 1
    fi

    # Split on `{` so each user record is its own chunk, then take the id
    # out of the chunk that carries the username. A flat record cannot
    # split, so an id can never be attributed to the wrong user -- and a
    # paging envelope around the list changes nothing, because the envelope
    # is not a chunk that carries a username.
    tr '{' '\n' < "${BODY}" \
        | grep "\"username\"[[:space:]]*:[[:space:]]*\"${wanted}\"" \
        | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1
}

# Create a user, if it is not already there.
#
# The password is passed explicitly, which matters: a user the server
# generates a password for is flagged `must_change_password`, and the tool
# would then authenticate as an account that cannot do anything yet.
create_user() {
    username="$1"
    password="$2"

    existing="$(user_id "${username}" || true)"

    if [ -n "${existing}" ]; then
        log "user ${username} already exists"
        return 0
    fi

    log "creating user ${username}"

    status="$(api_json POST /users "$(printf \
        '{"username":"%s","email":"%s@example.invalid","password":"%s","display_name":"%s","is_admin":false}' \
        "${username}" "${username}" "${password}" "${username}")")"

    if [ "${status}" != "200" ] && [ "${status}" != "201" ]; then
        fail "could not create user ${username} (HTTP ${status})"
        cat "${BODY}" >&2 || true
        failures=$((failures + 1))

        return 1
    fi
}

# Grant one user a set of actions on one repository.
grant() {
    principal="$1"
    repository="$2"
    actions="$3"

    status="$(api_json POST /permissions "$(printf \
        '{"principal_type":"user","principal_id":"%s","target_type":"repository","target_id":"%s","actions":[%s]}' \
        "${principal}" "${repository}" "${actions}")")"

    case "${status}" in
        # 409 is "already granted", which is the ordinary answer on a re-run
        # and not a problem.
        200|201|409) return 0 ;;
        *)
            fail "could not grant [${actions}] on ${repository} (HTTP ${status})"
            cat "${BODY}" >&2 || true
            failures=$((failures + 1))

            return 1
            ;;
    esac
}

# The two accounts the tool authenticates as, and what they may do.
#
# Separate on purpose: a source and an enumerator should work with the read-only
# account, and if either ever needs the publishing one that is a bug worth
# seeing here rather than in somebody's registry.
create_accounts() {
    create_user "${READONLY_USER}" "${READONLY_PASSWORD}" || true
    create_user "${PUBLISH_USER}" "${PUBLISH_PASSWORD}" || true

    reader="$(user_id "${READONLY_USER}" || true)"
    publisher="$(user_id "${PUBLISH_USER}" || true)"

    if [ -z "${reader}" ] || [ -z "${publisher}" ]; then
        fail "could not resolve the new users' ids; skipping grants"
        failures=$((failures + 1))

        return 1
    fi

    for format in ${FORMATS}; do
        for letter in ${REPO_LETTERS}; do
            name="$(repo_name "${format}" "${letter}")"
            id="$(repo_id "${name}" || true)"

            if [ -z "${id}" ]; then
                # Already reported by create_repo; not counted twice.
                continue
            fi

            log "granting on ${name}"

            grant "${reader}" "${id}" '"read"' || true
            grant "${publisher}" "${id}" '"read","write","deploy"' || true
        done
    done
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
    wait_for_backend || exit 1
    log_in || exit 1

    for format in ${FORMATS}; do
        for letter in ${REPO_LETTERS}; do
            create_repo "${format}" "${letter}"
        done
    done

    create_accounts

    echo
    log "repositories now on this server:"

    if [ "$(api_get "/repositories?per_page=200")" = "200" ]; then
        # One chunk per repository, for the reason `user_id` gives.
        tr '{' '\n' < "${BODY}" \
            | grep '"key"' \
            | sed -n 's/.*"key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/  \1/p' \
            | sort -u || true
    fi

    echo

    if [ "${failures}" -ne 0 ]; then
        fail "${failures} step(s) failed"
        exit 1
    fi

    log "done.  Artifact Keeper is at ${BASE}"
    log "  admin:     ${ADMIN_USER}"
    log "  publish:   ${PUBLISH_USER}"
    log "  read-only: ${READONLY_USER}"
    log "  anonymous: read of every *-${ANONYMOUS_LETTER} repository"

    log ""
    log "The passwords are in setup/artifact-keeper/.env, which the tool reads"
    log "directly.  Nothing needs exporting; run from the repository root:"
    log "  artifact-copy --config manual-integration-tests/server-config.d ..."
}

main "$@"
