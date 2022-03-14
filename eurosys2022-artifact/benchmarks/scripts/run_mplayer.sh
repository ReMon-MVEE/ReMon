#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../../../)"


rm ./eurosys2022-artifact/benchmarks/results/mplayer/* || :


# Optional for when you want to enable IP-MON, has no effect when kernel is not IP-MON enabled.
cd IP-MON/
ln -fs libipmon-mplayer.so libipmon.so
cd ../


__root_dir=$(pwd)

# Set dyninst variables
export DYNINST_INSTALL="$__root_dir/deps/dyninst/build/../install"
export DYNINSTAPI_RT_LIB="${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so"
ln -fs "${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so" \
  "$__root_dir/eurosys2022-artifact/../patched_binaries/gnomelibs/amd64/"
export LD_LIBRARY_PATH="${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH"


# Set environment to use correct .so for every run
LD_PRELOAD="$__root_dir/eurosys2022-artifact/benchmarks/out/fontconfig/base/libfontconfig.so.1:$__root_dir/eurosys2022-artifact/benchmarks/out/pulseaudio/base/libpulsecommon-14.2.so:$__root_dir/eurosys2022-artifact/benchmarks/out/pulseaudio/base/libpulse.so.0:$LD_PRELOAD"
ln -fs "$__root_dir/eurosys2022-artifact/benchmarks/out/pulseaudio/wrapped/"* \
  "$__root_dir/eurosys2022-artifact/../patched_binaries/gnomelibs/amd64/"
ln -fs "$__root_dir/eurosys2022-artifact/benchmarks/out/fontconfig/wrapped/libfontconfig.so.1" \
  "$__root_dir/eurosys2022-artifact/../patched_binaries/gnomelibs/amd64/"
ln -fs "$__root_dir/eurosys2022-artifact/../deps/ReMon-glibc/build/built-versions/normal/"* \
  "$__root_dir/eurosys2022-artifact/../patched_binaries/libc/amd64"


cd MVEE/bin/Release/
sed -i "s/\"use_ipmon\" : false/\"use_ipmon\" : true/g" ./MVEE.ini

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p30-framedrop || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p30-framedrop   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 30 fps framedrop test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p30-framedrop
  echo "   > [$__i/5] mvee 10 second 1080p 30 fps framedrop test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p30-framedrop
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p60-framedrop || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p60-framedrop   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 60 fps framedrop test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p60-framedrop
  echo "   > [$__i/5] mvee 10 second 1080p 60 fps framedrop test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p60-framedrop
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p90-framedrop || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p90-framedrop   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 90 fps framedrop test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p90-framedrop
  echo "   > [$__i/5] mvee 10 second 1080p 90 fps framedrop test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p90-framedrop
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p120-framedrop || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p120-framedrop   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 120 fps framedrop test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p120-framedrop
  echo "   > [$__i/5] mvee 10 second 1080p 120 fps framedrop test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4                     \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p120-framedrop
done



rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p30-framedrop-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p30-framedrop-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 30 fps framedrop test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p30-framedrop-subs
  echo "   > [$__i/5] mvee 10 second 1080p 30 fps framedrop test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p30-framedrop-subs
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p60-framedrop-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p60-framedrop-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 60 fps framedrop test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p60-framedrop-subs
  echo "   > [$__i/5] mvee 10 second 1080p 60 fps framedrop test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p60-framedrop-subs
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p90-framedrop-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p90-framedrop-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 90 fps framedrop test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p90-framedrop-subs
  echo "   > [$__i/5] mvee 10 second 1080p 90 fps framedrop test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p90-framedrop-subs
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p120-framedrop-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p120-framedrop-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p 120 fps framedrop test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p120-framedrop-subs
  echo "   > [$__i/5] mvee 10 second 1080p 120 fps framedrop test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4                     \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p120-framedrop-subs
done



rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pwebm-maxfps || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pwebm-maxfps   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p webm max fps test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pwebm-maxfps
  echo "   > [$__i/5] mvee 10 second 1080p webm max fps test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm                     \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pwebm-maxfps
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pmp4-maxfps || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pmp4-maxfps || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p mp4 max fps test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pmp4-maxfps
  echo "   > [$__i/5] mvee 10 second 1080p mp4 max fps test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pmp4-maxfps
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pwebm-maxfps || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pwebm-maxfps   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1440p webm max fps test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pwebm-maxfps
  echo "   > [$__i/5] mvee 10 second 1440p webm max fps test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm                     \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pwebm-maxfps
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pmp4-maxfps || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pmp4-maxfps   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1440p mp4 max fps test, without subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pmp4-maxfps
  echo "   > [$__i/5] mvee 10 second 1440p mp4 max fps test, without subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pmp4-maxfps
done


rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pwebm-maxfps-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pwebm-maxfps-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p webm max fps test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pwebm-maxfps-subs
  echo "   > [$__i/5] mvee 10 second 1080p webm max fps test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm                     \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pwebm-maxfps-subs
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pmp4-maxfps-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pmp4-maxfps-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1080p mp4 max fps test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pmp4-maxfps-subs
  echo "   > [$__i/5] mvee 10 second 1080p mp4 max fps test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pmp4-maxfps-subs
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pwebm-maxfps-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pwebm-maxfps-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1440p webm max fps test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pwebm-maxfps-subs
  echo "   > [$__i/5] mvee 10 second 1440p webm max fps test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm                     \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pwebm-maxfps-subs
done

rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pmp4-maxfps-subs || :
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pmp4-maxfps-subs   || :
for __i in {1..5}
do
  echo "   > [$__i/5] native 10 second 1440p mp4 max fps test, with subtitles"
  ../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt           \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4       \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pmp4-maxfps-subs
  echo "   > [$__i/5] mvee 10 second 1440p mp4 max fps test, with subtitles"
  ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
    -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
    -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                          \
    ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4                      \
    >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pmp4-maxfps-subs
done


# Output result.
../../../eurosys2022-artifact/benchmarks/scripts/process_mplayer.sh