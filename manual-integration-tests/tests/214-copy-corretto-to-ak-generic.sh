#!/bin/sh

# Copies one pinned Amazon Corretto release from GitHub into the Artifact
# Keeper `generic-c` repository.
#
# **Needs internet access**, and the WASM extension built first with
# `make build-extensions`.  Anonymous GitHub API access allows 60 requests
# an hour.
#
# 25.0.1.9.1 is a Linux-only release, so its Windows build is carried from
# 25.0.1.8.1: the copy holds files of two builds under one version.
#
# Run it twice.  The second run finds the version already present and
# uploads nothing.

set -e
TEST_HOME=$( cd $( dirname "$0" ) && pwd )
. "${TEST_HOME}/fixtures/env-loader.sh"
. "${TEST_HOME}/fixtures/cmd-file.sh"

VERSION="25.0.1.9.1"
CARRIED="25.0.1.8.1"

>&2 echo "------ Copying corretto-25@${VERSION} from corretto into ak-local-generic-c"
run_am \
    copy --from=corretto --to=ak-local-generic-c "corretto-25@${VERSION}"

>&2 echo
>&2 echo "What the generic repository now holds:"
curl -sSf -u "${READONLY_USER}:${ARTIFACT_KEEPER_READONLY_PASSWORD}" \
    "http://${ARTIFACT_KEEPER_HOST}/api/v1/repositories/generic-c/artifacts?per_page=100" \
    | grep -o '"path":"corretto-25/[^"]*"' | sort

>&2 echo
>&2 echo "Expected:"
>&2 echo "  \"path\":\"corretto-25/${VERSION}/amazon-corretto-${CARRIED}-windows-x64-jdk.zip\""
>&2 echo "  \"path\":\"corretto-25/${VERSION}/amazon-corretto-${VERSION}-linux-x64.tar.gz\""
