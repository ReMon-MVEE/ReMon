# Running the experiments

All command listings start from the repository's root.

## microbenchmark

```bash
# prints out: "> size: time in ns"

# # Optional for when you want to enable IP-MON
# cd IP-MON/
# ln -fs libipmon-default.so libipmon.so
# cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true


# native run, do this 10 times
../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy

# wrapped bursts, do this 10 times
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh default
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy

# non-wrapped bursts, do this 10 times
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh stripped
# optionally enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy

# make sure the correct libc version is used for later experiments
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh default
```

## nginx

Open two terminal windows: one to run nginx from and one to run wrk from. Ideally, the one running wrk is opened on a
separate machine connected via a dedicated gigabit ethernet link, to replicate our evaluation setup.

wrk command: `wrk -d 10s -t 1 -c 10 --timeout 10s http:/127.0.0.1:8080`. If you are using separate machines to
benchmark nginx, the ip is the ip on the dedicated link for the machine running nginx.

```bash
# # Optional for when you want to enable IP-MON
# cd IP-MON/
# ln -fs libipmon-nginx.so libipmon.so
# cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true


# native run, 1 worker, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf and set "workers: " to 1 if it would not be set to 1
../../../eurosys2022-artifact/benchmarks/out/nginx/base/sbin/nginx
# run the wrk command in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/nginx/base/sbin/nginx -s stop

# non-insturmented shm accesses run, 1 worker, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf and set "workers: " to 1 if it would not be set to 1
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/default/sbin/nginx
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# insturmented shm accesses run, 1 worker, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf and set "workers: " to 1 if it would not be set to 1
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/wrapped/sbin/nginx
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE


# native run, 2 workers, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf and set "workers: " to 2 if it would not be set to 2
../../../eurosys2022-artifact/benchmarks/out/nginx/base/sbin/nginx
# run the wrk command in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/nginx/base/sbin/nginx -s stop

# non-insturmented shm accesses run, 2 workers, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf and set "workers: " to 2 if it would not be set to 2
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/default/sbin/nginx
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# insturmented shm accesses run, 2 workers, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf and set "workers: " to 2 if it would not be set to 2
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/wrapped/sbin/nginx
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE
```

## apache

Open two terminal windows: one to run apache from and one to run wrk from. Ideally, the one running wrk is opened on a
separate machine connected via a dedicated gigabit ethernet link, to replicate our evaluation setup.

wrk command: `wrk -d 10s -t 1 -c 10 --timeout 10s http:/127.0.0.1:8080`. If you are using separate machines to
benchmark apache, the ip is the ip on the dedicated link for the machine running apache.

```bash
# # Optional for when you want to enable IP-MON
# cd IP-MON/
# ln -fs libipmon-apache.so libipmon.so
# cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true


# native run, 1 worker, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/out/apache/base/docroot/conf/httpd.conf and set "workers: " to 1 if it would not be set to 1
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl start
# run the wrk command in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl stop

# non-insturmented shm accesses run, 1 worker, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/out/apache/default/docroot/conf/httpd.conf and set "workers: " to 1 if it would not be set to 1
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/default/bin/apachectl start
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# insturmented shm accesses run, 1 worker, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/docroot/conf/httpd.conf and set "workers: " to 1 if it would not be set to 1
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/bin/apachectl start
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE


# native run, 2 workers, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/out/apache/base/docroot/conf/httpd.conf and set "workers: " to 2 if it would not be set to 2
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl start
# run the wrk command in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl stop

# non-insturmented shm accesses run, 2 workers, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/out/apache/default/docroot/conf/httpd.conf and set "workers: " to 2 if it would not be set to 2
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/default/bin/apachectl start
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# insturmented shm accesses run, 2 workers, do this 5 times
# edit  ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/docroot/conf/httpd.conf and set "workers: " to 2 if it would not be set to 2
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/bin/apachectl start
# run the wrk command in the other terminal and wait for the results
# crtl+c to terminate the MVEE
```

## MPlayer

```bash
# # Optional for when you want to enable IP-MON
# cd IP-MON/
# ln -fs libipmon-mplayer.so libipmon.so
# cd ../


__root_dir=$(pwd)

# Set dyninst variables
export DYNINST_INSTALL="$__root_dir/deps/dyninst/build/../install"
export DYNINSTAPI_RT_LIB="${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so"
export LD_LIBRARY_PATH="${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH"


# Set environment to use correct .so for every run
LD_PRELOAD="$__root_dir/eurosys2022-artifact/benchmarks/out/fontconfig/base/libfontconfig.so.1:$__root_dir/eurosys2022-artifact/benchmarks/out/pulseaudio/base/libpulsecommon-14.2.so:$__root_dir/eurosys2022-artifact/benchmarks/out/pulseaudio/base/libpulse.so.0"
ln -fs "$__root_dir/eurosys2022-artifact/benchmarks/out/pulseaudio/wrapped/"* "$__root_dir/eurosys2022-artifact/../patched_binaries/gnomelibs/amd64/"
ln -fs "$__root_dir/eurosys2022-artifact/benchmarks/out/fontconfig/wrapped/libfontconfig.so.1" \
  "$__root_dir/eurosys2022-artifact/../patched_binaries/gnomelibs/amd64/"
ln -fs "$__root_dir/eurosys2022-artifact/../deps/ReMon-glibc/build/built-versions/normal/"* "$__root_dir/eurosys2022-artifact/../patched_binaries/libc/amd64"


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true


# native 10 second 1080p 30 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4
# native 10 second 1080p 60 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4
# native 10 second 1080p 90 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4
# native 10 second 1080p 120 fps framedrop test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4


# mvee 10 second 1080p 30 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4
# mvee 10 second 1080p 60 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4
# mvee 10 second 1080p 90 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4
# mvee 10 second 1080p 120 fps framedrop test, without subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4


# native 10 second 1080p 30 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# native 10 second 1080p 60 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# native 10 second 1080p 90 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# native 10 second 1080p 120 fps framedrop test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt


# mvee 10 second 1080p 30 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p30.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# mvee 10 second 1080p 60 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# mvee 10 second 1080p 90 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p90.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# mvee 10 second 1080p 120 fps framedrop test, with subtitles, do this 5 times
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/mplayer/dyninst/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -framedrop ../../../eurosys2022-artifact/benchmarks/input/video/1080p120.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt



# native 10 second 1080p webm max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm
# native 10 second 1080p mp4 max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4
# native 10 second 1440p webm max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm
# native 10 second 1440p mp4 max fps test, without subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4


# mvee 10 second 1080p webm max fps test, without subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm
# mvee 10 second 1080p mp4 max fps test, without subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4
# mvee 10 second 1440p webm max fps test, without subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm
# mvee 10 second 1440p mp4 max fps test, without subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4


# native 10 second 1080p webm max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# native 10 second 1080p mp4 max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# native 10 second 1440p webm max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# native 10 second 1440p mp4 max fps test, with subtitles, do this 5 times
../../../eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt


# mvee 10 second 1080p webm max fps test, with subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.webm -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# mvee 10 second 1080p mp4 max fps test, with subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1080p60.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# mvee 10 second 1440p webm max fps test, with subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.webm -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
# mvee 10 second 1440p mp4 max fps test, with subtitles, do this 5 times
./mvee -N 2 -- /eurosys2022-artifact/benchmarks/out/mplayer/default/bin/mplayer -benchmark -osdlevel 0 -vo xv -quiet -nosound ../../../eurosys2022-artifact/benchmarks/input/video/1440p60.mp4 -sub ../../../eurosys2022-artifact/benchmarks/input/subs.srt
```
