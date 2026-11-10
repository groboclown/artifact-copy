#!/bin/sh

cd $( dirname "$0" ) || exit 1

DEFAULT_SERVER_HOSTNAME="${DEFAULT_SERVER_HOSTNAME:-127.0.0.1}"
NEXUS_HOSTNAME="${NEXUS_HOSTNAME:-${DEFAULT_SERVER_HOSTNAME}}"
NEXUS_PORT="${NEXUS_PORT:-8081}"
NEXUS_HOST="${NEXUS_HOST:-${NEXUS_HOSTNAME}:${NEXUS_PORT}}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="$( grep -E "^ADMIN_PASSWORD=" .env | cut -f 2 -d = )" || exit 1

tmpf="$( mktemp )"
if ! \
    curl -sf -o "${tmpf}" "http://${NEXUS_HOST}/service/rest/v1/system/eula" \
    -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
; then
    >&2 echo "Server not running?"
    exit 1
fi

accepted=$( jq .accepted < "${tmpf}" )
if [ "${accepted}" = "true" ] ; then
    rm "${tmpf}"
    echo "Somebody already accepted the EULA.  Nothing else to do."
    exit 0
fi
jq -r .disclaimer < "${tmpf}"

read -p "Do you accept the terms of this EULA? [y/N] " yn
if [ "${yn}" = "y" ] || [ "${yn}" = "Y" ] ; then
    echo "Accepted."
    tmpf2="$( mktemp )"
    jq '.accepted=true' < "${tmpf}" > "${tmpf2}"
    rm "${tmpf}"

    curl -sf -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
        -H 'Content-Type: application/json' \
        -X POST http://${NEXUS_HOST}/service/rest/v1/system/eula \
        -d @"${tmpf2}"
    rm "${tmpf2}"
else
    rm "${tmpf}"
    echo "Did not accept license."
    exit 22
fi
