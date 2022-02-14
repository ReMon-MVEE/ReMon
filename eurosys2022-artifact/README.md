# Sharing is Caring: Secure and Efficient Shared Memory Support for MVEEs


**Artifact Appendix correction:** you cannot change the apache configuration by changing only one file. You need to
change the conf in /wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/out/apache/<version>/conf/httpd.conf for
each version separately.

## System

All benchmarks were originally run on a system running Ubuntu 18.04 LTS, equipped with a 6-core AMD Ryzen 5 5600x CPU,
Nvidia 2060 GPU, and 16GB of RAM. For our experiments we disabled hyper-threading and turbo-boost.

As a rule of thumb we suggest counting one core for the monitor and n additional cores for every process that would be
started by the application being run. With n representing the configured number of variants.

---

## Setup

While we suggest running the experiments in a native Ubuntu 18.04 machine, we do provide a docker image that can be used
instead. This docker image is set up to contain a user _eval_ with password _artifactdocker_, so that it functions as
any regular ubuntu system would and our MVEE does not run with root privileges. Additionally, if you want to run
mplayer, a graphical application, using the docker container, you will need x11docker. Download and install instructions
can be found at https://github.com/mviereck/x11docker#installation.

To benchmark the servers, we used wrk. This tool can be cloned from https://github.com/wg/wrk. Even if you run the
benchmarks using docker, wrk does not need to run inside the docker container. To reproduce our results, run the web
server on one system and the wrk benchmark on a second system, connecting both through a direct gigabit ethernet
connection.

---

## Bootstrapping

ReMon and all benchmarks we provide can be set up by simply running the `bootstrap.sh` script. This script will:

1. Bootstrap ReMon and its dependencies (this includes the LLVM used by ReMon that we also extended)
2. Set up the different IP-MON builds to be used with different benchmarks
3. Download ReMon's custom glibc that we also extended
4. Build glibc
5. Set up dyninst
6. Download all benchmarks
7. Bootstrap all benchmarks (applying patches where necessary)
8. Optionally build all varieties of all benchmarks

Item 5 is only performed when the environment variable `BUILDALL` is set to 1.

This script requires only a little interaction at the start, but runs fully autonomously otherwise.

---

## Docker Setup

Docker can be set up either by using the `docker_control.sh` script or fully manually. We advice the former, but provide
instructions for both.

### Script Aided Setup

```bash
git clone https://github.com/ReMon-MVEE/ReMon.git
cd ReMon/eurosys2022-artifact/
./docker_control.sh build
# Will prompt eval user password when starting and once more later, this password is artifactdocker
./docker_control.sh bootstrap
./docker_control.sh build-all
```

### Manual Docker Setup

```bash
git clone https://github.com/ReMon-MVEE/ReMon.git
cd ReMon/
export REMON_HOME=$PWD

cd eurosys2022-artifact/

docker build . -t shmvee:ae

# Will prompt eval user password when starting and once more later, this password is artifactdocker
# Replace BUILDALL=1 with BUILDALL=0 to not build all benchmarks immediately
docker run                                                                                   \
    -v "$REMON_HOME":"/home/eval/artifact/" --workdir="/home/eval/artifact/" \
    --env BUILDALL=1 --name artifact -it shmvee:ae                                           \
    ./bootstrap.sh
docker commit artifact shmvee:ae
docker rm artifact
```

---

## Running Docker

Docker can be run in two configurations: normally and using x11docker. The first suffices for running normal terminal
applications, but the second is necessary to run graphical applications. Although, x11docker can also be used to run the
terminal applications. We describe how to start both manually and using the `docker_control.sh` script.

### Script Aided Start

normal docker: `./docker_control.sh run`

x11docker: `./docker_control.sh runx11`

### Manual Start

normal docker: 

```bash
docker run -v "/wherever/you/cloned/remon/":"/home/eval/artifact/" \
    --security-opt seccomp=unconfined                              \
    --workdir="/home/eval/artifact/" -p 8080:8080 -it              \
    shmvee:ae bash
```

x11docker: 

```bash
x11docker --hostdisplay --hostipc --gpu --pulseaudio --interactive                                   \
    --user=RETAIN --network --clipboard --cap-default --                                             \
    --cap-add SYS_PTRACE -ti -v "/wherever/you/cloned/remon/":"/home/eval/artifact/" -p 8080:8080 -- \
    shmvee:ae bash
```

---

## Kernel Setup

To run ReMon at its full potential, a small kernel patch is required. We override ReMon's kernel patch with a rolled
back version for 5.3.0. Note that this patch should work just fine on a 5.4.0 kernel if you're running Ubuntu 20.04 LTS,
but we suggest using 18.04 LTS and a 5.3.0 kernel for reproducibility. We provide a method of setting up the kernel here
that will install it as a separate package, next to your default kernel, instead of overwriting it. This allows you to
select what kernel to use at boot time via the _Advanced Options For Ubuntu_ option. The IP-MON kernel is only tested on
Ubuntu kernel source, running it in other distros is not guaranteed to work. However, installing the kernel as mentioned
below will have little to no impact on your experience.

To show the grub boot menu go to /etc/default/grub and add/change: GRUB_TIMEOUT_STYLE=menu and GRUB_TIMEOUT=10. After
saving the changes execute `sudo update-grub`.

```bash
cd /wherever/you/want/to/download/the/kernel

sudo apt-get update
sudo apt-get install linux-source-5.3.0
tar jxf /usr/src/linux-source-5.3.0/linux-source-5.3.0.tar.bz2
# Alternatively: obtain linux 5.3.0 of 5.4.0 kernel source elsewhere, not guaranteed to work.

cd linux-source-5.3.0
patch -p1 < /wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/patches/linux-5.3.0-full-ipmon.patch
make menuconfig 
# while you're in the config menu, you might want to bump the kernel tick rate up to 1000Hz
# you can do so by navigating to "Processor type and features" > "Timer Frequency"
./scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYS

make -j$(nproc) deb-pkg LOCALVERSION=-ipmon
sudo dpkg -i ../linux-headers*.deb ../linux-image*.deb ../linux-libc-dev*.deb
```

---

## Benchmark Setup

If you simply want to build all benchmarks at once, run the `eurosys2022-artifact/benchmarks/scripts/build_all.sh`. The
rest of this section explains how to build the individual benchmarks and what the different benchmark versions are.

Every benchmark ships with a `build.sh` script that allows for easy configuration and building. These files can be found
in eurosys2022-artifact/benchmarks/scripts and all follow the form `<benchmark>_build.sh`. Which specific version
should be built can be chosen by passing the required arguments. Additionally, you can pass several configuration
arguments at once and the script will configure and build them sequentially. The final output is written to
eurosys2022-artifact/benchmarks/out/ in their relevant directory.

Note that the mplayer dyninst rewritten version does not build automatically. 

### Nginx

Version 1.18.0 downloaded from http://nginx.org/download/nginx-1.18.0.tar.gz. A small patch has to be applied to make
the code compatible with ReMon's -fatomicize LLVM pass, five lines changed
(eurosys2022-artifact/benchmarks/patches/nginx.patch). Our `eurosys2022-artifact/bootstrap.sh` will overwrite nginx'
default configuration and index.html file to the correct ones for benchmarking.

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --base                   | Vanilla build with ReMon-supplied LLVM, meant to run natively.                            |
| --default                | Build with ReMon-supplied LLVM, compiled with ReMon's -fatomicize option to function      |
|                          | correctly when running under ReMon, after applying a patch to force nginx to use Sys V    |
|                          | shared memory.                                                                            |
| --wrapped                | build with ReMon-supplied , after applying a patch to force nginx to use Sys V shared     |
|                          | memory and wrapping instructions that might access shared                                 |
|                          | memory using our compiler pass.                                                           |
| --base-anon              | Vanilla build with ReMon-supplied LLVM, allowing nginx to use anonymous shared memory,    |
|                          | meant to run natively.                                                                    |
| --default-anon           | Build with ReMon-supplied LLVM, allowing nginx to use anonymous shared memory.            |
| --wrapped-anon           | build with ReMon-supplied LLVM, allowing nginx to use anonymous shared memory and         |
|                          | wrapping instructions that might access shared memory using our compiler pass.            |

### Apache

Version 2.4.46 downloaded from https://github.com/apache/httpd.git. Additionally, we use a local apr and apr-util with
apache. Apr is version 1.7.0 and downloaded from https://dlcdn.apache.org//apr/apr-1.7.0.tar.gz. Apr-util is version
1.6.1 and downloaded from https://dlcdn.apache.org//apr/apr-util-1.6.1.tar.gz. A small patch has to be applied to make
the code compatible with ReMon's LLVM pass, nine lines changed (benchmarks/patches/apache.patch). Our
`eurosys2022-artifact/bootstrap.sh` will overwrite apache's default configuration and index.html file to the correct
ones for benchmarking.

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --base                   | Vanilla build with ReMon-supplied LLVM, meant to run natively.                            |
| --default                | Build with ReMon-supplied LLVM, compiled with ReMon's -fatomicize option to function      |
|                          | correctly when running under ReMon.                                                       |
| --wrapped                | Build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |

### Mplayer

Version 1.4 downloaded from http://www.mplayerhq.hu/MPlayer/releases/MPlayer-1.4.tar.xz.

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --default                | Vanilla build with ReMon-supplied LLVM.                                                   |
| --wrapped                | build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |
| --default-no-fast-memcpy | build with ReMon-supplied LLVM, after configuring the build to use glibc's memcpy instead |
|                          | of its own assembly implementation.                                                       |
| --wrapped-no-fast-memcpy | build with ReMon-supplied LLVM, after configuring the build to use glibc's memcpy instead |
|                          |of its own assembly implementation and wrapping instructions that might access shared      |
|                          | memory with our compiler pass.                                                            |
| --dyninst-no-fast-memcpy | Will rewrite the --default-no-fast-memcpy binary using dyninst.                           |
| --default-osd-fixed      | build with ReMon-supplied LLVM, after patching the code to use a C-coded for rendering    |
|                          | its on-screen display instead of the assembly implementation.                             |
| --wrapped-osd-fixed      | build with ReMon-supplied LLVM, after patching the code to use a C-coded for rendering    |
|                          | its on-screen display instead of the assembly implementation and wrapping instructions    |
|                          | that might access shared memory with our compiler pass.                                   |
| --default-full           | build with ReMon-supplied LLVM, after applying both the no-fast-memcpy and osd-fixed      |
|                          | changes.                                                                                  |
| --wrapped-full           | build with ReMon-supplied LLVM, after applying both the no-fast-memcpy and osd-fixed      |
|                          | changes, and wrapping instructions that might access shared memory with our compiler      |
|                          | pass.                                                                                     |

You will need to run `eurosys2022-artifact/benchmarks/scripts/mplayer_build.sh --dyninst-no-fast-memcpy` manually. Since
this requires some dynamic analysis, an mplayer instance will pop up. Allow a few frames with subtitles to render and
then close the window, it might take a few seconds for the window to close. After this, the benchmark version will be
automatically rewritten to eurosys2022-artifact/benchmarks/out/mplayer_dyninst_no_fast_memcpy/bin/mplayer.
dyninst_shm/README.md provides more information on this process.

### Pulseaudio

Version 14.2 downloaded from git://anongit.freedesktop.org/pulseaudio/pulseaudio.

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --default                | Vanilla build with ReMon-supplied LLVM.                                                   |
| --wrapped                | build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |
| --install                | Install the vanilla build on the system, for more accurate comparison. Note that this     |
|                          | makes very little difference and might not be worth it.                                   |

### Fontconfig

Version 2.13.1 downloaded from https://gitlab.freedesktop.org/fontconfig/fontconfig.git.

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --default                | Vanilla build with ReMon-supplied LLVM,                                                   |
| --wrapped                | build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |
| --install                | Install the vanilla build on the system, for more accurate comparison. Note that this     |
|                          | makes very little difference and might not be worth it.                                   |

### Microbenchmark

Copies a buffer of a certain size into shared memory for a certain amount of times in a tight loop. Can be configured by
changing the definition of `SIZES_ARRAY` and `SHM_TEST_COUNT` respectively. Make sure to update `MAX_DATA_SIZE`
accordingly with changes to `SIZES_ARRAY`!

---

## Running Benchmarks

If results at any point seem rather low, make sure you are configured correctly.

- If you're using IP-MON, check MVEE.ini that IP-MON is enabled. 
- Check patched_binaries/libc/amd46 that the normal/ .so files are symlinked, not the stripped/ ones (unless intended)

Note that any dyninst rewritten binary run requires the following environment variables to be defined. Although `run.sh`
will set this up for you.

```bash
export DYNINST_INSTALL=/wherever/you/cloned/remon/dyninst/build/../install 
export DYNINSTAPI_RT_LIB=${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH
```

### Script Aided

All benchmarks can be run using `eurosys2022-artifact/benchmarks/scripts/run.sh <options> -- <benchmark> <version>`. 

- **Benchmark** here can be any of the benchmarking applications mentioned earlier, and corresponds with one of the
folders in eurosys2022-artifact/benchmarks/out/.
- **Version** represents what configure option is used, as mentioned in the previous section, and corresponds with a
folder in eurosys2022-artifact/benchmarks/out/<benchmark>. These folders are generally the configure options with '-'
replaced with '_'.
- **Options** are mentioned in the table below.

| Option                    | Meaning                                                                                  |
| :------------------------ | :--------------------------------------------------------------------------------------- |
| --native                  | Runs selected benchmark natively, instead of running it under ReMon.                     |
| --ipmon                   | Run ReMon with IP-MON enabled                                                            |
| --debug                   | Run Debug version of ReMon.                                                              |
| --variants <N>            | Configures ReMon to use N variants.                                                      |
| --wrapped-pulseaudio      | Configure ReMon to load the wrapped versions of pulseaudio. Note: the same binary will   |
|                           | also be loaded by the native execution by making use of LD_PRELOAD.                      |
| --default-pulseaudio      | Configure ReMon to load the default versions of pulseaudio. Note: the same binary will   |
|                           | also be loaded by the native execution by making use of LD_PRELOAD.                      |
| --wrapped-fontconfig      | Configure ReMon to load the wrapped versions of fontconfig. Note: the same binary will   |
|                           | also be loaded by the native execution by making use of LD_PRELOAD.                      |
| --default-fontconfig      | Configure ReMon to load the default versions of fontconfig. Note: the same binary will   |
|                           | also be loaded by the native execution by making use of LD_PRELOAD.                      |
| --video </path/to/video>  | Only affects mplayer. Play video at path/to/video using mplayer.                         |
| --subs </path/to/sub.srt> | Only affects mplayer. Load subtitle file at path/to/sub.srt.                             |
| --framedrop               | Only affects mplayer. Configure mplayer to show statistics on dropped frames.            |
| --maxfps                  | Only affects mplayer. Configure mplayer to disable sound and render video frames as fast |
|                           | as possible.                                                                             |

### Nginx

Optionally: start by starting the docker container.

1. `cd /wherever/you/cloned/remon/GHUMVEE/bin/Release/`.
2. Start nginx: `./mvee -N <numvariant> -- /wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/out/nginx/<option>/sbin/nginx`.
3. From a different terminal (or, ideally, a different host) run `wrk -d 10s -t 1 -c 10 --timeout 10s http://localhost:8080/`.
4. Stop nginx via ctrl+c in the first terminal.

Step 1 and 2 can be replace by using the `run.sh` script mentioned earlier.

To alter the amount of worker processes, change `worker_processes` in
/wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf. This file is symlinked to all
versions, so this change is propagated to all versions.

Our config of nginx enables some rate limiting features to force shared memory usage. Thus, these values should always
be chose so that they don't actually limit the server's throughput. The current configuration should be okay, even when
benchmarking over loopback, but should you see requests/second got above 250 000, maybe double `rate` in the
`limit_req_zone` line and `burst` in the `limit_req` line in the config once more. Also make sure that the amount of
connections your benchmarking client opens does not exceed `limit_conn addr`, currently configured at 25.

### Apache

Optionally: start with starting the docker container.

1. `cd /wherever/you/cloned/remon/GHUMVEE/bin/Release/`.
2. Start apache: `./mvee -N <numvariant> -- /wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/out/apache/<option>/bin/httpd start`.
3. From a different terminal (or, ideally, a different host) run `wrk -d 10s -t 1 -c 10 --timeout 10s http://localhost:8080/`.
4. Stop apache via ctrl+c in the first terminal.

Step 1 and 2 can be replace by using the `run.sh` script mentioned earlier.

To alter the amount of worker processes, change `ServerLimit` in
/wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/apache/docs/conf/httpd.conf. This file is symlinked to all
versions, so this change is propagated to all versions.

### Mplayer

Optionally: start with starting the x11docker container.

Manually:
1. `cd /wherever/you/cloned/remon/GHUMVEE/bin/Release/`.
2. Start mplayer: `./mvee -N <numvariant> -- /wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/out/mplayer/<option>/bin/mplayer -benchmark -vo xv -osd-level 0 -quiet <video input>`.

Step 1 and 2 can be replace by using the `run.sh` script mentioned earlier.

Options to add to the mplayer command:
| -nosound                 | Disables sound output, making mplayer render frames as fast as it can. Shows maximum      |
|                          | reachable fps.                                                                            |
| -framedrop               | Skip the displaying of some frames to keep audio and video in sync. Shows frame drop      |
|                          | rate.                                                                                     |
| -sub </path/to/subs.srt> | Shows subtitle on screen that is rendered for 10 seconds.                                 |

### Microbenchmark

Optionally: start with starting the docker container.

1. `cd /wherever/you/cloned/remon/GHUMVEE/bin/Release/`.
2. `./mvee -N <numvariant> -- /wherever/you/cloned/remon/eurosys2022-artifact/benchmarks/microbenchmark/memcpy`.

---
