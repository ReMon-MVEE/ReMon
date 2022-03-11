#!/bin/bash
set -e

__home_dir=$(readlink -f $(dirname ${BASH_SOURCE})/../../)

__native=0
__ipmon=1
__mplayer_options="-benchmark -osdlevel 0 -vo xv -quiet"
__benchmark=""
__version=""
__build="Release"
__variants="2"
__video=""

while test $# -gt 0
do
  case $1 in
    --native)
      __native=1
      shift
      ;;
    --variants)
      shift
      __variants="$1"
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
    --)
      shift
      __version="$1"
      shift
      __mplayer_options="$__mplayer_options $1"
      shift
      if test $# -gt 0
      then
        __mplayer_options="$__mplayer_options -sub $1"
        shift
      fi
      break
      ;;
    *)
      echo " > unrecoginsed option $1"
      shift
      ;;
  esac
done


ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* \
  "$__home_dir/../patched_binaries/libc/amd64"
export LD_PRELOAD="$__ld_preload"


if [[ ! -e "$__home_dir/benchmarks/out/mplayer/" ]]
then
  echo " > mplayer not currently available, did you build it?"
  exit 2
fi

if [[ ! -n "$__version" ]]
then
  echo " > somehow no version given"
  exit 2
fi
if [[ ! -e "$__home_dir/benchmarks/out/mplayer/$__version" ]]
then
  echo " > $__version version of mplayer not currently available, did you build it?"
  exit 2
fi

export DYNINST_INSTALL=$__home_dir/../deps/dyninst/build/../install 
export DYNINSTAPI_RT_LIB=${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH


LD_PRELOAD="$__home_dir/benchmarks/out/fontconfig/default/libfontconfig.so.1:$__home_dir/benchmarks/out/pulseaudio/default/libpulsecommon-14.2.so:$__home_dir/benchmarks/out/pulseaudio/default/libpulse.so.0"
ln -fs "$__home_dir/benchmarks/out/pulseaudio/wrapped/"* "$__home_dir/../patched_binaries/gnomelibs/amd64/"
ln -fs "$__home_dir/benchmarks/out/fontconfig/wrapped/libfontconfig.so.1" \
  "$__home_dir/../patched_binaries/gnomelibs/amd64/"
ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* "$__home_dir/../patched_binaries/libc/amd64"

__run="$__home_dir/benchmarks/out/mplayer/$__version/bin/mplayer $__mplayer_options"

if [[ "$__native" == 1 ]]
then
  echo " > using native execution"
  echo " > executing command: $__run"

  $__run
else
  if [[ "$__ipmon" == 1 ]]
  then
    echo " > enabling ipmon for this run"
    ln -fs "$__home_dir/benchmarks/conf/MVEE-ipmon.ini" "$__home_dir/../MVEE/bin/Release/MVEE.ini"
    ln -fs "$__home_dir/../IP-MON/libipmon-mplayer.so" "$__home_dir/../IP-MON/libipmon.so"
  else
    echo " > disabling ipmon for this run"
    ln -fs "$__home_dir/benchmarks/conf/MVEE.ini" "$__home_dir/../MVEE/bin/Release/MVEE.ini"
  fi

  cd "$__home_dir/../MVEE/bin/Release/"
  echo " > executing command: ./mvee -N $__variants -- $__run"
  ./mvee -N "$__variants" -- "$__run"
  ln -fs "$__home_dir/../IP-MON/libipmon-default.so" "$__home_dir/../IP-MON/libipmon.so"

fi
