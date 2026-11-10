#!/bin/sh

# Copies one pinned NodeJS release from the real nodejs.org into the
# Artifact Keeper `generic-c` repository.
#
# **Needs internet access**, and the WASM extension built first with
# `make build-extensions`.  The `nodejs-org` source lists only the Linux
# x64 tarball, so the copy is one file, checked against the sha256 that
# the release's `SHASUMS256.txt` states.
#
# Run it twice.  The second run finds the version already present and
# uploads nothing.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"

VERSION="24.1.0"

>&2 echo "------ Copying nodejs@${VERSION} from nodejs-org into ak-local-generic-c"
run_am \
    copy --from=nodejs-org --to=ak-local-generic-c "nodejs@${VERSION}"

>&2 echo
>&2 echo "What the generic repository now holds:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    "http://${ARTIFACT_KEEPER_HOST}/api/v1/repositories/generic-c/artifacts?per_page=100" \
    | grep -o '"path":"[^"]*"' | sort

>&2 echo
>&2 echo "Expected:"
>&2 echo "  \"path\":\"nodejs/${VERSION}/node-v${VERSION}-linux-x64.tar.gz\""
