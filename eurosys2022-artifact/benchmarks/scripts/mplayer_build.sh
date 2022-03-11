#!/bin/bash
set -e


cd "$(readlink -f $(dirname ${BASH_SOURCE})/../mplayer/)"


# sudo apt install libpulse-dev libxv-dev libxext-dev libx11-dev libfreetype6-dev libfontconfig-dev

. ../config.sh
__llvm_bin_dir="$__llvm_dir/bin/"
if [ ! -d "$__llvm_bin_dir" ]
then
  echo " > please set llvm bin directory path to valid path"
  echo " > current: $__llvm_bin_dir"
  exit 1
fi

__current_dir=$(pwd)

do_make ()
{
  make clean || :
  make distclean || :
  ./configure --prefix=$__prefix --enable-debug $__disable --enable-xv --enable-pulse --yasm=''
  make -j"$(nproc)" install
}

while test $# -gt 0
do
  case $1 in
    --default)
      __prefix="$__current_dir/../out/mplayer/default"
      __disable=""
      ln -s "$__current_dir/../patches/mplayer/a/sub/osd.c" -f "$__current_dir/sub/osd.c"

      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      do_make

      shift
      ;;

    --wrapped)
      __prefix="$__current_dir/../out/mplayer/wrapped"
      __disable=""
      ln -s "$__current_dir/../patches/mplayer/a/sub/osd.c" -f "$__current_dir/sub/osd.c"

      if [ ! -e "$__current_dir/non-instrumented.shm" ]
      then
        ../scripts/generate_non_instrumented.sh              \
            "$__current_dir/../instrumenting/mplayer.shm.in" \
            "non-instrumented.shm"
      fi

      export CC="$__llvm_bin_dir/clang -g -O3 -fshm_support=$__current_dir/non-instrumented.shm"
      export CXX="$__llvm_bin_dir/clang++ -g -O3 -fshm_support=$__current_dir/non-instrumented.shm"

      do_make

      shift
      ;;

   --default-no-fast-memcpy)
      __prefix="$__current_dir/../out/mplayer/default_no_fast_memcpy"
      __disable="--disable-fastmemcpy"
      ln -s "$__current_dir/../patches/mplayer/a/sub/osd.c" -f "$__current_dir/sub/osd.c"

      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      do_make
      
      shift
      ;;

    --wrapped-no-fast-memcpy)
      __prefix="$__current_dir/../out/mplayer/wrapped_no_fast_memcpy"
      __disable="--disable-fastmemcpy"
      ln -s "$__current_dir/../patches/mplayer/a/sub/osd.c" -f "$__current_dir/sub/osd.c"

      if [ ! -e "./non-instrumented-no-fast-memcpy.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                             \
            "$__current_dir/../instrumenting/mplayer-no-fast-memcpy.shm.in" \
            "non-instrumented-no-fast-memcpy.shm"
      fi

      export CC="$__llvm_bin_dir/clang -g -O3 -fshm_support=./non-instrumented-no-fast-memcpy.shm"
      export CXX="$__llvm_bin_dir/clang++ -g -O3 -fshm_support=./non-instrumented-no-fast-memcpy.shm"

      do_make

      shift
      ;;

   --dyninst)
      __prefix="$__current_dir/../out/mplayer/default_no_fast_memcpy"
      __disable="--disable-fastmemcpy"
      ln -s "$__current_dir/../patches/mplayer/a/sub/osd.c" -f "$__current_dir/sub/osd.c"

      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      if [[ ! -e "$__current_dir/../out/mplayer/default_no_fast_memcpy/bin/mplayer" ]]
      then
        do_make
      else
        ./configure --prefix=$__prefix --enable-debug $__disable --enable-xv --enable-pulse --yasm=''
      fi

      if [[ ! -e "$__current_dir/../instrumenting/mplayer_no_fast_memcpy.dyninst" ]]
      then
        echo " > dyninst input file $__current_dir/../instrumenting/mplayer_no_fast_memcpy.dyninst not found"
        echo " > we will start mplayer now, please allow a few frames of subtitles to render before closing with ctrl+C"

        $__current_dir/../scripts/run.sh --video "$__current_dir/../input/video/1080p30.webm"            \
          --subs "$__current_dir/../input/subs.srt" --wrapped-pulseaudio --wrapped-fontconfig --debug -- \
          mplayer default_no_fast_memcpy
        
        grep mplayer "$__current_dir/../../../MVEE/bin/Debug/Logs/non-instrumented.csv" | cut '-d;' -f4 > \
          "$__current_dir/../instrumenting/mplayer_no_fast_memcpy.dyninst"
      fi

      
      export DYNINST_INSTALL="$__current_dir/../../../deps/dyninst/build/../install"
      export DYNINSTAPI_RT_LIB="${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so"
      export LD_LIBRARY_PATH="${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH"

      cd "$__current_dir/../../../dyninst_shm/"
      ./bartTestInstrumenter "$__current_dir/../out/mplayer/default_no_fast_memcpy/bin/mplayer" \
        "$__current_dir/../instrumenting/mplayer_no_fast_memcpy.dyninst"
      __prefix="$__current_dir/../out/mplayer/dyninst/bin"
      mkdir -p "$__prefix"
      mv ./InterestingProgram-rewritten "$__prefix/mplayer"

      shift
      ;;

   --default-osd-fixed)
      __prefix="$__current_dir/../out/mplayer/default_osd_fixed"
      __disable=""
      ln -s "$__current_dir/../patches/mplayer/b/sub/osd.c" -f "$__current_dir/sub/osd.c"

      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      do_make
      
      shift
      ;;

    --wrapped-osd-fixed)
      __prefix="$__current_dir/../out/mplayer/wrapped_osd_fixed"
      __disable=""
      ln -s "$__current_dir/../patches/mplayer/b/sub/osd.c" -f "$__current_dir/sub/osd.c"
      
      if [ ! -e "$__current_dir/non-instrumented-osd-fixed.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                        \
            "$__current_dir/../instrumenting/mplayer-osd-fixed.shm.in" \
            "non-instrumented-osd-fixed.shm"
      fi

      export CC="$__llvm_bin_dir/clang -g -O3 -fshm_support=$__current_dir/non-instrumented-osd-fixed.shm"
      export CXX="$__llvm_bin_dir/clang++ -g -O3 -fshm_support=$__current_dir/non-instrumented-osd-fixed.shm"

      do_make

      shift
      ;;

   --default-full)
      __prefix="$__current_dir/../out/mplayer/default_full"
      __disable="--disable-fastmemcpy"
      ln -s "$__current_dir/../patches/mplayer/b/sub/osd.c" -f "$__current_dir/sub/osd.c"

      export CC="$__llvm_bin_dir/clang -g -O3"
      export CXX="$__llvm_bin_dir/clang++ -g -O3"

      do_make
      
      shift
      ;;

    --wrapped-full)
      __prefix="$__current_dir/../out/mplayer/wrapped_full"
      __disable="--disable-fastmemcpy"
      ln -s "$__current_dir/../patches/mplayer/b/sub/osd.c" -f "$__current_dir/sub/osd.c"

      if [ ! -e "$__current_dir/non-instrumented-full.shm" ]
      then
        ../scripts/generate_non_instrumented.sh                   \
            "$__current_dir/../instrumenting/mplayer-full.shm.in" \
            "non-instrumented-full.shm"
      fi

      export CC="$__llvm_bin_dir/clang -g -O3 -fshm_support=$__current_dir/non-instrumented-full.shm"
      export CXX="$__llvm_bin_dir/clang++ -g -O3 -fshm_support=$__current_dir/non-instrumented-full.shm"

      do_make

      shift
      ;;
    *)
      echo " > unrecognised option $1"
      exit 1
  esac
done

