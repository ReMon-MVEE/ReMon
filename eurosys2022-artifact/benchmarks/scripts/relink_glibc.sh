#!/bin/bash

__home_dir="$(readlink -f $(dirname ${BASH_SOURCE})/../../)"
cd "$__home_dir/../patched_binaries/libc/amd64/"


case "$1" in
  stripped)
    echo " > setting a stripped version of our libc, burst accesses are not wrapped"
    ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/stripped/"* \
      "$__home_dir/../patched_binaries/libc/amd64"
    break
    ;;
  default)
    echo " > setting the default version of our libc, burst accesses are wrapped"
    ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* \
      "$__home_dir/../patched_binaries/libc/amd64"
    break
    ;;
  *)
    echo " > unrecognized option $1, setting default version of our libc, burst accesses are wrapped, instead"
    ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* \
      "$__home_dir/../patched_binaries/libc/amd64"
    break
    ;;
esac
