#!/bin/bash
set -e


cd "$(readlink -f $(dirname ${BASH_SOURCE})/../fontconfig/)"


. ../config.sh
__llvm_bin_dir="$__llvm_dir/bin/"
if [ ! -d "$__llvm_bin_dir" ]
then
  echo " > please set llvm bin directory path to valid path"
  echo " > current: $__llvm_bin_dir"
  exit 1
fi

__current_dir=$(pwd)

while test $# -gt 0
do
  case $1 in
    --install)
      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      make clean || :
      make distclean || :
      ./configure
      sudo make -j"$(nproc)" install
      sudo ldconfig
      shift
      ;;

    --default)
      __prefix="$(pwd)/../out/fontconfig/default"
      mkdir -p "$__prefix"

      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      make clean || :
      make distclean || :
      ./configure --prefix="$__prefix"
      make -j"$(nproc)"
      mkdir -p "$__prefix/etc/"
      ln -fs /etc/fonts/ "$__prefix/etc/"
      cp "$__current_dir/src/.libs/libfontconfig.so" "$__prefix/libfontconfig.so.1"
      shift
      ;;

    --wrapped)
      __prefix="$(pwd)/../out/fontconfig/wrapped"
      mkdir -p "$__prefix"

      if [ ! -e "$__current_dir/non-instrumented.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                 \
            "$__current_dir/../instrumenting/fontconfig.shm.in" \
            "non-instrumented.shm"
      fi

      export CC="$__llvm_bin_dir/clang -g -O3 -fshm_support=$__current_dir/non-instrumented.shm"
      export CXX="$__llvm_bin_dir/clang++ -g -O3 -fshm_support=$__current_dir/non-instrumented.shm"

      make clean || :
      make distclean || :
      ./configure --prefix="$__prefix"
      make -j"$(nproc)"
      mkdir -p "$__prefix/etc/"
      ln -fs /etc/fonts/ "$__prefix/etc/"
      cp "$__current_dir/src/.libs/libfontconfig.so" "$__prefix/libfontconfig.so.1"
      shift
      ;;

    *)
      echo " > unrecognised option $1"
      exit 1
  esac
done

