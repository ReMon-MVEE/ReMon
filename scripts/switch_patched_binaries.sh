#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# Check the number of parameters
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters. Expected the requested libc version."
    exit 1
else
    version="$1"
fi

case "$version" in
    "ubuntu18")
        glib_version_suffix="0.4002.0"
        libc_version_suffix="2.27.9000"
        libgomp_version_suffix="4.5"
        libstdcpp_version_suffix="6.0.24"
        ;;

    "ubuntu20")
        glib_version_suffix="0.6400.2"
        libc_version_suffix="2.31"
        libgomp_version_suffix="5.0"
        libstdcpp_version_suffix="6.0.28"
        ;;

    *)
        echo "Invalid version specified!"
        echo "$version"
        exit 2
        ;;
esac

MVEE_ROOT="$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd ))"
ARCH=$(${MVEE_ROOT}/build_scripts/getmakearch.rb | grep ^ARCH | cut -d':' -f2 | tr -d '\n')

cd ${MVEE_ROOT}/patched_binaries/gnomelibs/${ARCH}/
ln -nsf libgio-2.0.so.${glib_version_suffix} libgio-2.0.so.0
ln -nsf libglib-2.0.so.${glib_version_suffix} libglib-2.0.so.0
ln -nsf libgmodule-2.0.so.${glib_version_suffix} libgmodule-2.0.so.0
ln -nsf libgobject-2.0.so.${glib_version_suffix} libgobject-2.0.so.0
ln -nsf libgthread-2.0.so.${glib_version_suffix} libgthread-2.0.so.0

cd ${MVEE_ROOT}/patched_binaries/libc/${ARCH}/
ln -nsf ld-${libc_version_suffix}.so ld-linux.so
ln -nsf libc-${libc_version_suffix}.so libc.so.6
ln -nsf libdl-${libc_version_suffix}.so libdl.so.2
ln -nsf libm-${libc_version_suffix}.so libm.so.6
ln -nsf libpthread-${libc_version_suffix}.so libpthread.so.0
ln -nsf libresolv-${libc_version_suffix}.so libresolv.so.2
ln -nsf librt-${libc_version_suffix}.so librt.so.1
ln -nsf libutil-${libc_version_suffix}.so libutil.so.1

cd ${MVEE_ROOT}/patched_binaries/libgomp/${ARCH}/
ln -nsf libgomp.so.${libgomp_version_suffix} libgomp.so.1.0.0

cd ${MVEE_ROOT}/patched_binaries/libstdc++/${ARCH}/
ln -nsf libstdc++.so.${libstdcpp_version_suffix} libstdc++.so.6
