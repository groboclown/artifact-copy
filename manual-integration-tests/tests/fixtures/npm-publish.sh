# A "sourced" file, not a stand-alone script.

# Publish the "publish/npm-echo" package with npm.
#
# Usage: npm_publish REGISTRY_URL USER PASSWORD
#
# npm reads credentials from a user config keyed by the registry's URL
# without its scheme, so a temporary one is written and removed after.
#
# This requires the calling script to first run:
#    TEST_HOME=$( cd $( dirname "$0" ) && pwd )
#    . "${TEST_HOME}/fixtures/env-loader.sh"
test -d "${TEST_HOME}" || exit 1

npm_publish() {
  registry="${1%/}/"
  auth="$( printf '%s:%s' "$2" "$3" | base64 | tr -d '\n' )"
  npmrc="$( mktemp )"

  printf '//%s:_auth=%s\n' "${registry#*://}" "${auth}" > "${npmrc}"

  ( cd "${PUBLISH_DIR}/npm-echo" && npm publish --registry="${registry}" --userconfig="${npmrc}" )
  status=$?

  rm -f "${npmrc}"
  return ${status}
}
