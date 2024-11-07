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
    "ubuntu24")
        glib_version_suffix="not_implemented"
        libc_version_suffix="2.39"
        libgomp_version_suffix="not_implemented"
        libstdcpp_version_suffix="not_implemented"
        ;;

    *)
        echo "Invalid version specified!"
        echo "$version"
        exit 2
        ;;
esac

MVEE_ROOT="$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd ))"
ARCH=$(${MVEE_ROOT}/build_scripts/getmakearch.rb | grep ^ARCH | cut -d':' -f2 | tr -d '\n')

switch_library_version ()
{
	SOURCE=$1
	DEST=$2

	if [ -f $SOURCE ]
	then
		ln -nsf $SOURCE $DEST
	else
		rm $DEST
	fi
}

cd ${MVEE_ROOT}/patched_binaries/gnomelibs/${ARCH}/
switch_library_version libgio-2.0.so.${glib_version_suffix} libgio-2.0.so.0
switch_library_version libglib-2.0.so.${glib_version_suffix} libglib-2.0.so.0
switch_library_version libgmodule-2.0.so.${glib_version_suffix} libgmodule-2.0.so.0
switch_library_version libgobject-2.0.so.${glib_version_suffix} libgobject-2.0.so.0
switch_library_version libgthread-2.0.so.${glib_version_suffix} libgthread-2.0.so.0

cd ${MVEE_ROOT}/patched_binaries/libc/${ARCH}/
switch_library_version ld-${libc_version_suffix}.so ld-linux.so
switch_library_version libc-${libc_version_suffix}.so libc.so.6
switch_library_version libdl-${libc_version_suffix}.so libdl.so.2
switch_library_version libm-${libc_version_suffix}.so libm.so.6
switch_library_version libpthread-${libc_version_suffix}.so libpthread.so.0
switch_library_version libresolv-${libc_version_suffix}.so libresolv.so.2
switch_library_version librt-${libc_version_suffix}.so librt.so.1
switch_library_version libutil-${libc_version_suffix}.so libutil.so.1

cd ${MVEE_ROOT}/patched_binaries/libgomp/${ARCH}/
switch_library_version libgomp.so.${libgomp_version_suffix} libgomp.so.1.0.0

cd ${MVEE_ROOT}/patched_binaries/libstdc++/${ARCH}/
switch_library_version libstdc++.so.${libstdcpp_version_suffix} libstdc++.so.6
