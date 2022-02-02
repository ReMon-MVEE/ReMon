#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../apache/)"

. ../config.sh
__llvm_bin_dir="$__llvm_dir/bin/"
if [ ! -d "$__llvm_bin_dir" ]
then
  echo " > please set llvm bin directory path to valid path"
  echo " > current: $__llvm_bin_dir"
  exit 1
fi

__current_dir=$(pwd)

# Common flags: Wrap atomics
export CFLAGS="-g -O3 -fatomicize"

while test $# -gt 0
do
  case $1 in
    --base)
      __prefix="$__current_dir/../out/apache/base"

      export CC="$__llvm_bin_dir/clang -g -O#"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"
      export CFLAGS="-g -O3"

      make distclean
      ./configure --prefix=${__prefix} --with-included-apr --with-mpm=worker
      make -j"$(nproc)"
      make install

      ln -fs "$__current_dir/docs/conf/httpd.conf" "$__prefix/conf/"

      shift
      ;;

    --default)
      __prefix="$__current_dir/../out/apache/default"

      export CC="$__llvm_bin_dir/clang $CFLAGS"
      export CXX="$__llvm_bin_dir/clang++ $CFLAGS"

      make distclean
      ./configure --prefix=${__prefix} --with-included-apr --with-mpm=worker
      make -j"$(nproc)"
      make install

      ln -fs "$__current_dir/docs/conf/httpd.conf" "$__prefix/conf/"

      shift
      ;;

    --wrapped)
      __prefix="$__current_dir/../out/apache/wrapped"

      if [ ! -e "$__current_dir/non-instrumented.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                       \
            "$__current_dir/../instrumenting/apache.shm.in" \
            "non-instrumented.shm"
      fi

      export CC="$__llvm_bin_dir/clang $CFLAGS -fshm_support=$__current_dir/non-instrumented.shm"
      export CXX="$__llvm_bin_dir/clang++ $CFLAGS -fshm_support=$__current_dir/non-instrumented.shm"

      make distclean
      ./configure --prefix=${__prefix} --with-included-apr --with-mpm=worker
      make -j"$(nproc)"
      make install

      ln -fs "$__current_dir/docs/conf/httpd.conf" "$__prefix/conf/"
      
      shift
      ;;
    *)
      echo " > unrecognised option $1"
      exit 1
  esac
done

