#!/bin/bash
set -e


cd "$(readlink -f $(dirname ${BASH_SOURCE})/../pulseaudio/)"


. ../config.sh
__llvm_bin_dir="$__llvm_dir/bin/"
if [ ! -d "$__llvm_bin_dir" ]
then
  echo " > please set llvm bin directory path to valid path"
  echo " > current: $__llvm_bin_dir"
  exit 1
fi

__current_dir=$(pwd)

DEB_HOST_MULTIARCH=x86_64-linux-gnu
DEB_VERSION_UPSTREAM=meh

export CFLAGS="-g -O3"
export CXXFLAGS="-g -O3"
export LDLAGS="-g -O3"

do_make ()
{
  mkdir -p "$__prefix"
  make clean || :
  make distclean || :
  ./configure --enable-x11 --disable-hal-compat                             \
    --prefix="$__prefix"                                                    \
    --libdir=${__prefix}/lib/${DEB_HOST_MULTIARCH}                          \
    --with-module-dir=${__prefix}/lib/pulse-${DEB_VERSION_UPSTREAM}/modules \
    --disable-esound                                                        \
    --enable-gsettings                                                      \
    --disable-gconf
  make -j"$(nproc)"
  cp "$__current_dir/src/.libs/libpulse.so.0.23.0" "$__prefix/libpulse.so.0"
  cp "$__current_dir/src/.libs/libpulsecommon-14.2.so" "$__prefix/libpulsecommon-14.2.so"
}

while test $# -gt 0
do
  case $1 in
    --install)
      ln -fs "$__current_dir/../patches/pulseaudio/a/src/pulsecore/memblock.c" "$__current_dir/src/pulsecore/memblock.c"

      export CC="$__llvm_bin_dir/clang"
      export CXX="$__llvm_bin_dir/clang++"

      make clean || :
      make distclean || :
      ./configure --enable-x11 --disable-hal-compat                             \
        --disable-esound                                                        \
        --enable-gsettings                                                      \
        --disable-gconf
      sudo make -j"$(nproc)" install
      sudo ldconfig

      shift
      ;;

    --system-patched)
      ln -fs "$__current_dir/../patches/pulseaudio/b/src/pulsecore/memblock.c" "$__current_dir/src/pulsecore/memblock.c"

      export CC="$__llvm_bin_dir/clang"
      export CXX="$__llvm_bin_dir/clang++"

      make clean
      make distclean
      ./configure --enable-x11 --disable-hal-compat                             \
        --disable-esound                                                        \
        --enable-gsettings                                                      \
        --disable-gconf
      sudo make -j"$(nproc)" install
      sudo ldconfig

      shift
      ;;

    --default)
      __prefix="$__current_dir/../out/pulseaudio/default"
      mkdir -p "$__prefix"

      ln -fs "$__current_dir/../patches/pulseaudio/a/src/pulsecore/memblock.c" "$__current_dir/src/pulsecore/memblock.c"

      export CC="$__llvm_bin_dir/clang"
      export CXX="$__llvm_bin_dir/clang++"
      
      do_make

      shift
      ;;

    --wrapped)
      __prefix="$__current_dir/../out/pulseaudio/wrapped"
      mkdir -p "$__prefix"

      if [ ! -e "$__current_dir/non-instrumented.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                 \
            "$__current_dir/../instrumenting/pulseaudio.shm.in" \
            "non-instrumented.shm"
      fi

      ln -fs "$__current_dir/../patches/pulseaudio/a/src/pulsecore/memblock.c" "$__current_dir/src/pulsecore/memblock.c"

      export CC="$__llvm_bin_dir/clang -fshm_support=$__current_dir/non-instrumented.shm"
      export CXX="$__llvm_bin_dir/clang++ -fshm_support=$__current_dir/non-instrumented.shm"
      
      do_make

      shift
      ;;

    --default-patched)
      __prefix="$__current_dir/../out/pulseaudio/default_patched"
      mkdir -p "$__prefix"

      ln -fs "$__current_dir/../patches/pulseaudio/b/src/pulsecore/memblock.c" "$__current_dir/src/pulsecore/memblock.c"

      export CC="$__llvm_bin_dir/clang"
      export CXX="$__llvm_bin_dir/clang++"
      
      do_make

      shift
      ;;

    --wrapped-patched)
      __prefix="$__current_dir/../out/pulseaudio/wrapped_patched"
      mkdir -p "$__prefix"

      if [ ! -e "$__current_dir/non-instrumented-patched.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                         \
            "$__current_dir/../instrumenting/pulseaudio-patched.shm.in" \
            "non-instrumented.shm"
      fi

      ln -fs "$__current_dir/../patches/pulseaudio/b/src/pulsecore/memblock.c" "$__current_dir/src/pulsecore/memblock.c"

      export CC="$__llvm_bin_dir/clang -fshm_support=$__current_dir/non-instrumented-patched.shm"
      export CXX="$__llvm_bin_dir/clang++ -fshm_support=$__current_dir/non-instrumented-patched.shm"
      
      do_make

      shift
      ;;

    *)
      echo " > unrecognised option $1"
      exit 1
  esac
done

