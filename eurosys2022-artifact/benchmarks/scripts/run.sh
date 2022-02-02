#!/bin/bash
set -e

__home_dir=$(readlink -f $(dirname ${BASH_SOURCE})/../../)

__native=0
__ipmon=0
__mplayer_options="-benchmark -osdlevel 0 -vo xv -quiet"
__benchmark=""
__version=""
__build="Release"
__variants="2"
__video=""
__ld_preload=""

while test $# -gt 0
do
  case $1 in
    --native)
      __native=1
      shift
      ;;
    --ipmon)
      __ipmon=1
      shift
      ;;
    --debug)
      __build="Debug"
      shift
      ;;
    --variants)
      shift
      __variants="$1"
      shift
      ;;
    --wrapped-pulseaudio)
      ln -fs "$__home_dir/benchmarks/out/pulseaudio/wrapped/"* "$__home_dir/../patched_binaries/gnomelibs/amd64/"
      __ld_preload="$__ld_preload:$__home_dir/benchmarks/out/pulseaudio/wrapped/libpulse.so.0"
      __ld_preload="$__ld_preload:$__home_dir/benchmarks/out/pulseaudio/wrapped/libpulsecommon-14.2.so"
      shift
      ;;
    --default-pulseaudio)
      ln -fs "$__home_dir/benchmarks/out/pulseaudio/default/"* "$__home_dir/../patched_binaries/gnomelibs/amd64/"
      __ld_preload="$__ld_preload:$__home_dir/benchmarks/out/pulseaudio/default/libpulse.so.0"
      __ld_preload="$__ld_preload:$__home_dir/benchmarks/out/pulseaudio/default/libpulsecommon-14.2.so"
      shift
      ;;
    --wrapped-fontconfig)
      ln -fs "$__home_dir/benchmarks/out/fontconfig/wrapped/libfontconfig.so.1" \
        "$__home_dir/../patched_binaries/gnomelibs/amd64/"
      __ld_preload="$__ld_preload:$__home_dir/benchmarks/out/fontconfig/wrapped/libfontconfig.so.1"
      shift
      ;;
    --default-fontconfig)
      ln -fs "$__home_dir/benchmarks/out/fontconfig/default/libfontconfig.so.1" \
        "$__home_dir/../patched_binaries/gnomelibs/amd64/"
      __ld_preload="$__ld_preload:$__home_dir/benchmarks/out/fontconfig/default/libfontconfig.so.1"
      shift
      ;;
    --unwrapped-bursts)
      ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/stripped/"* \
        "$__home_dir/../patched_binaries/libc/amd64"
      shift
      ;;
    --wrapped-bursts)
      ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* \
        "$__home_dir/../patched_binaries/libc/amd64"
      shift
      ;;
    --subs)
      shift
      __mplayer_options="$__mplayer_options -sub $1"
      shift
      ;;
    --framedrop)
      __mplayer_options="$__mplayer_options -framedrop"
      shift
      ;;
    --maxfps)
      __mplayer_options="$__mplayer_options -nosound"
      shift
      ;;
    --video)
      shift
      __mplayer_options="$__mplayer_options $1"
      shift
      ;;
    --)
      shift
      __benchmark="$1"
      shift
      __version="$1"
      shift
      break
      ;;
    *)
      echo " > unrecoginsed option $1"
      shift
      ;;
  esac
done


export LD_PRELOAD="$__ld_preload"


echo "$__benchmark"
echo "$__version"
if [[ ! -n "$__benchmark" ]]
then
  echo " > somehow no benchmark given"
  exit 2
fi
if [[ ! -e "$__home_dir/benchmarks/out/$__benchmark/" ]] && [[ "$__benchmark" != "microbenchmark" ]]
then
  echo " > benchmark $__benchmark not currently available, did you build it?"
  exit 2
fi

if [[ ! -n "$__version" ]] && [[ "$__benchmark" != "microbenchmark" ]]
then
  echo " > somehow no version given"
  exit 2
fi
if [[ ! -e "$__home_dir/benchmarks/out/$__benchmark/$__version" ]] && [[ "$__benchmark" != "microbenchmark" ]]
then
  echo " > $__version version of $__benchmark not currently available, did you build it?"
  exit 2
fi



__run=""
case "$__benchmark" in
  nginx)
    echo " > running nginx"
    __run="$__home_dir/benchmarks/out/nginx/$__version/sbin/nginx"
    ;;
  apache)
    echo " > running apache"
    __run="$__home_dir/benchmarks/out/apache/$__version/bin/httpd start"
    ;;
  mplayer)
    echo " > running apache"
    __run="$__home_dir/benchmarks/out/mplayer/$__version/bin/mplayer $__mplayer_options"
    ;;
  microbenchmark)
    echo " > running apache"
    __run="$__home_dir/benchmarks/microbenchmark/memcpy"
    ;;
  *)
    echo " > unrecoginsed benchmark $__benchmark"
    shift
    ;;
esac


if [[ "$__version" == *"dyninst"* ]]
then
  echo " > hello there"
  export DYNINST_INSTALL=$__home_dir/../deps/dyninst/build/../install 
  export DYNINSTAPI_RT_LIB=${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so
  export LD_LIBRARY_PATH=${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH
fi


if [[ "$__native" == 1 ]]
then
  echo " > using native execution"
  echo " > executing command: $__run"

  $__run
else
  echo " > using $__build version of ReMon"

  if [[ "$__ipmon" == 1 ]]
  then
    echo " > enabling ipmon for this run"
    ln -fs "$__home_dir/benchmarks/conf/MVEE-ipmon.ini" "$__home_dir/../MVEE/bin/$__build/MVEE.ini"
    ln -fs "$__home_dir/../IP-MON/libipmon-$__benchmark.so" "$__home_dir/../IP-MON/libipmon.so"
  else
    echo " > disabling ipmon for this run"
    ln -fs "$__home_dir/benchmarks/conf/MVEE.ini" "$__home_dir/../MVEE/bin/$__build/MVEE.ini"
  fi

  cd "$__home_dir/../MVEE/bin/$__build/"
  echo " > executing command: ./mvee -N $__variants -- $__run"
  ./mvee -N "$__variants" -- "$__run"
  ln -fs "$__home_dir/../IP-MON/libipmon-default.so" "$__home_dir/../IP-MON/libipmon.so"

fi

ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* "$__home_dir/../patched_binaries/libc/amd64"