#!/usr/bin/env bash
# Download the external definitions under external/, pinned to the commits
# recorded below, so a refresh is a deliberate edit of one line.
#
# Usage: scripts/fetch-external.sh [--nexus-url=URL]
#
# --nexus-url fetches Nexus 3's OpenAPI document from a running server
# (`{URL}/service/rest/swagger.json`); Sonatype publishes no file to pin.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXTERNAL="$ROOT/external"
RAW="https://raw.githubusercontent.com"

# Upstream repository, pinned commit, and the license file's name there.
OSV_REPO="ossf/osv-schema"
OSV_COMMIT="7e336cc6dabe2f414d8e65f1955d1f1aa4b17d39"

OPENVEX_REPO="openvex/spec"
OPENVEX_COMMIT="93139bd2c65390b504e47f82f11c50451289f93a"

CYCLONEDX_REPO="CycloneDX/specification"
CYCLONEDX_COMMIT="6470e34ef83f915868ece48934cff52e10c9eb49"

AK_API_REPO="artifact-keeper/artifact-keeper-api"
AK_API_COMMIT="bfae595a6832e39c0d8d7f495d481e638de336dd"

NEXUS_URL=""

for arg in "$@"; do
    case "$arg" in
        --nexus-url=*) NEXUS_URL="${arg#--nexus-url=}" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# fetch REPO COMMIT PATH DEST: one file from a pinned commit.
fetch() {
    local repo="$1" commit="$2" path="$3" dest="$4"

    mkdir -p "$(dirname "$dest")"
    curl -fsSL "$RAW/$repo/$commit/$path" -o "$dest"
    echo "fetched $repo@${commit:0:12} $path"
}

fetch "$OSV_REPO" "$OSV_COMMIT" validation/schema.json "$EXTERNAL/osv/schema.json"
fetch "$OSV_REPO" "$OSV_COMMIT" LICENSE "$EXTERNAL/osv/LICENSE"

fetch "$OPENVEX_REPO" "$OPENVEX_COMMIT" openvex_json_schema.json "$EXTERNAL/openvex/openvex_json_schema.json"
fetch "$OPENVEX_REPO" "$OPENVEX_COMMIT" LICENSE "$EXTERNAL/openvex/LICENSE"

# bom-1.6 references the SPDX and JSF schemas beside it.
for file in bom-1.6.schema.json spdx.schema.json jsf-0.82.schema.json; do
    fetch "$CYCLONEDX_REPO" "$CYCLONEDX_COMMIT" "schema/$file" "$EXTERNAL/cyclonedx/$file"
done
fetch "$CYCLONEDX_REPO" "$CYCLONEDX_COMMIT" LICENSE "$EXTERNAL/cyclonedx/LICENSE"

fetch "$AK_API_REPO" "$AK_API_COMMIT" openapi.json "$EXTERNAL/artifact-keeper/openapi.json"
fetch "$AK_API_REPO" "$AK_API_COMMIT" LICENSE "$EXTERNAL/artifact-keeper/LICENSE"

if [ -n "$NEXUS_URL" ]; then
    mkdir -p "$EXTERNAL/nexus"
    curl -fsSL "${NEXUS_URL%/}/service/rest/swagger.json" -o "$EXTERNAL/nexus/swagger.json"
    echo "fetched $NEXUS_URL swagger.json"
fi
