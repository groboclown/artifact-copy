#!/bin/sh

if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ -z "$1" ] ; then
  echo "Usage: $0 PLATFORM_TRIPLE ..."
  echo "Use 'current' as the PLATFORM_TRIPLE to refer to the current target."
  exit 1
fi

exec_name="artifact-copy"
extensions="corretto-releases nodejs-releases"
here="$( cd "$( dirname "$0" )" && pwd )" || exit 1
root="$( cd "${here}/.." && pwd )" || exit 1
version=$( grep 'version = "' "${root}/Cargo.toml" | head -n 1 | cut -f 2 -d '"' )

for platform in "$@" ; do
    platform_dir="${root}/target/${platform}/release"

    if [ "${platform}" = "current" ] ; then
        platform=$( rustc -vV | sed -n 's|host: ||p' ) || exit 1
        platform_dir="${root}/target/release"
    fi

    target_dir="${root}/target/install-${platform}.d"
    target_file="${root}/target/${exec_name}-${version}_${platform}.tar.gz"

    if [ ! -d "${platform_dir}" ] ; then
        >&2 echo "Could not find ${platform_dir} ; did you build it?"
        exit 1
    fi

    exec_file="${platform_dir}/${exec_name}"
    if [ ! -f "${exec_file}" ] ; then
        exec_file="${exec_file}.exe"
        if [ ! -f "${exec_file}" ] ; then
            >&2 echo "Executable ${exec_name} not found in ${platform_dir} ; did you build it?"
            exit 1
        fi
    fi

    test -d "${target_dir}" && rm -r "${target_dir}"
    mkdir -p "${target_dir}" || exit 1

    # The tarball construction.

    cp "${exec_file}" "${target_dir}/." || exit 1
    cp -R \
        "${root}/docs" \
        "${root}/examples" \
        "${root}/schema" \
        "${root}/README.md" \
        "${root}/LICENSE" \
        "${target_dir}/." || exit 1

    mkdir -p "${target_dir}/extensions"
    for ext in ${extensions} ; do
        # Use '*' for the name, because the build turns '-' to '_'.
        cp "${root}/extensions/${ext}/target/wasm32-wasip1/release/"*.wasm "${target_dir}/extensions/." || exit 1
    done

    # Clean up extra things that don't need to be there.
    rm -r "${target_dir}/docs/contributors"

    ( cd "${target_dir}" && tar zcf "${target_file}" * )
done
