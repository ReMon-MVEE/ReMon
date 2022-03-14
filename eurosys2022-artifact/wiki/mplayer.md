# MPlayer

Time required: ~45 minutes. Start from the repo's root directory.

**Note**: There is a known synchronization issue that might cause the MVEE to not shut down after the benchmark has
finished. If not new window appears while running the automatic script or no new terminal prompt appears while runin
manual commands, it is safe to crl+c to shut down the MVEE.

## Automatic

### Native

```bash
./eurosys2022-artifact/benchmarks/scripts/run_mplayer.sh
```

### Running in docker

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh runx11 ./eurosys2022-artifact/benchmarks/scripts/run_mplayer.sh
```

**Method 2**: running docker command manually:

```bash
x11docker --hostdisplay --hostipc --gpu --pulseaudio --interactive   \
  --user=RETAIN --network --clipboard --cap-default                  \
  --workdir=/home/eval/artifact --                                   \
  --cap-add SYS_PTRACE -ti -v "$(pwd):/home/eval/artifact/" --       \
  shmvee:ae ./eurosys2022-artifact/benchmarks/scripts/run_mplayer.sh
```

## Manual

## Step 0 - docker entrance

**Optional!** Skip if you are running the experiments natively.

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh runx11
```

**Method 2**: running docker command manually:

```bash
x11docker --hostdisplay --hostipc --gpu --pulseaudio --interactive \
  --user=RETAIN --network --clipboard --cap-default                \
  --workdir=/home/eval/artifact --                                 \
  --cap-add SYS_PTRACE -ti -v ./:/home/eval/artifact/ --           \
  shmvee:ae bash
```

## Step 1 - setting up the output for automatic processing

```bash
# Clear files containing output.
rm ../../../eurosys2022-artifact/benchmarks/results/mplayer/*
```

## Step 2 - setting up the MVEE

```bash
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
```

## Step 2 - running the experiments

```bash
# native 10 second 1080p 30 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p30-framedrop
# native 10 second 1080p 60 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p60-framedrop
# native 10 second 1080p 90 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p90-framedrop
# native 10 second 1080p 120 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p120-framedrop


# mvee 10 second 1080p 30 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p30-framedrop
# mvee 10 second 1080p 60 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p60-framedrop
# mvee 10 second 1080p 90 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p90-framedrop
# mvee 10 second 1080p 120 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p120-framedrop


# native 10 second 1080p 30 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p30-framedrop-subs
# native 10 second 1080p 60 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p60-framedrop-subs
# native 10 second 1080p 90 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p90-framedrop-subs
# native 10 second 1080p 120 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                        \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080p120-framedrop-subs


# mvee 10 second 1080p 30 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p30-framedrop-subs
# mvee 10 second 1080p 60 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p60-framedrop-subs
# mvee 10 second 1080p 90 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p90-framedrop-subs
# mvee 10 second 1080p 120 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -framedrop                                       \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080p120-framedrop-subs



# native 10 second 1080p webm max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pwebm-maxfps
# native 10 second 1080p mp4 max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pmp4-maxfps
# native 10 second 1440p webm max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pwebm-maxfps
# native 10 second 1440p mp4 max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pmp4-maxfps


# mvee 10 second 1080p webm max fps test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pwebm-maxfps
# mvee 10 second 1080p mp4 max fps test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pmp4-maxfps
# mvee 10 second 1440p webm max fps test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pwebm-maxfps
# mvee 10 second 1440p mp4 max fps test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pmp4-maxfps


# native 10 second 1080p webm max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pwebm-maxfps-subs
# native 10 second 1080p mp4 max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1080pmp4-maxfps-subs
# native 10 second 1440p webm max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pwebm-maxfps-subs
# native 10 second 1440p mp4 max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                          \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt          \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/native-10s-1440pmp4-maxfps-subs


# mvee 10 second 1080p webm max fps test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pwebm-maxfps-subs
# mvee 10 second 1080p mp4 max fps test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1080pmp4-maxfps-subs
# mvee 10 second 1440p webm max fps test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pwebm-maxfps-subs
# mvee 10 second 1440p mp4 max fps test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer \
  -benchmark -osdlevel 0 -vo xv -quiet -nosound                                         \
   -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt                         \
  ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4       \
  >> ../../../eurosys2022-artifact/benchmarks/results/mplayer/mvee-10s-1440pmp4-maxfps-subs
```

## Step 3 - automatic processing

This will output the average of the runs for each experiment. This does not have to be run inside the docker container,
but works either way. Run this from the repo's root.

```bash
./eurosys2022-artifact/benchmarks/scripts/process_mplayer.sh
```