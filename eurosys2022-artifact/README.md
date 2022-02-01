# Sharing is Caring: Secure and Efficient Shared Memory Support for MVEEs

## System

All benchmarks were originally run on a system running Ubuntu 18.04 LTS, equipped with a 6-core AMD Ryzen 5 5600x CPU,
Nvidia 2060 GPU and 16GB of RAM. For our experiments we disabled hyper-threading and turbo-boost.

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
benchmarks using docker, wrk does not need to run inside the docker container.

---

## Bootstrapping

ReMon and all benchmarks we provide can be set up by simply running the `bootstrap.sh` script. This script will:

1. Download ReMon
2. Bootstrap ReMon and its dependencies (this includes the LLVM used by ReMon that we also extended)
3. Download ReMon's custom glibc that we also extended
4. Build glibc
5. Download all benchmarks
6. Bootstrap all benchmarks (applying patches where necessary)
7. Optionally build all varieties of all benchmarks

Item 5 is only performed when the environment variable `BUILDALL` is set to 1.

**Note that bootstrapping requires some minimal user interaction to continue a few times.**

---

## Docker Setup

Docker can be set up either by using the `docker_control.sh` script or fully manually. We advice the former, but provide
instructions for both.

### Script Aided Setup

```bash
./docker_control.sh build
./docker_control.sh bootstrap
./docker_control.sh build-all
```

### Manual Docker Setup

```bash
docker build . -t shmvee:ae

# Replace BUILDALL=0 with BUILDALL=1 to build all benchmarks immediately
docker run                                                                               \
    -v "/wherever/this/repo/is/":"/home/eval/artifact/" --workdir="/home/eval/artifact/" \
    --env BUILDALL=0 --name artifact -it shmvee:ae                                       \
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
docker run -v "/wherever/this/repo/is/":"/home/eval/artifact/" \
    --workdir="/home/eval/artifact/" -p 8080:8080 -it          \
    shmvee:ae bash
```

x11docker: 

```bash
x11docker --hostdisplay --hostipc --gpu --pulseaudio --interactive                               \
    --user=RETAIN --network --clipboard --cap-default --                                         \
    --cap-add SYS_PTRACE -ti -v "/wherever/this/repo/is/":"/home/eval/artifact/" -p 8080:8080 -- \
    shmvee:ae bash
```

---

## Kernel Setup

To run ReMon at its full potential a small kernel patch is required. The patch itself is part of ReMon and instructions
to install it are also mentioned in ReMon's README. We provide a more general explanation on kernel setup here. Not that
even though we use the 5.4.0 patch for IP-MON, this patch still works on the 5.3.0 kernel.

```bash
cd /wherever/you/want/to/download/the/kernel

# Maybe do git download instead for this?
sudo apt-get update
sudo apt-get install linux-source-5.3.0
tar jxf /usr/src/linux-source-5.3.0/linux-source-5.3.0.tar.bz2

cd linux-source-5.3.0
patch -p1 < /path/to/ReMon/patches/linux-5.4.0-full-ipmon.patch
make menuconfig 
# while you're in the config menu, you might want to bump the kernel tick rate up to 1000Hz
# you can do so by navigating to "Processor type and features" > "Timer Frequency"
./scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYS

make -j$(nproc) deb-pkg LOCALVERSION=-ipmon
sudo dpkg -i ../linux-headers*.deb ../linux-image*.deb ../linux-libc-dev*.deb
```

This installs the IPMON enabled kernel as a separate kernel option in the grub boot menu. Allowing you to easily switch
between it and your regular kernel.

---

## Benchmark Setup

If you simply want to build all benchmarks at once, run the `benchmarks/scripts/build_all.sh`. The rest of this section
explains how to build the individual benchmarks and what the different benchmark versions are.

Every benchmark ships with `build.sh` file that allows for easy configuration and building. These files can be found in
`benchmarks/scripts` and all follow the form `<benchmark>_build.sh`. **TODO: make them call directory agnostic**. Which
specific version should be built can be chosen by passing the required arguments. Additionally, you can pass several
configuration arguments at once and the script will configure and build them sequentially. The final output is written
to `benchmarks/out/` in their relevant directory.

### Nginx

Version 1.18.0 downloaded from http://nginx.org/download/nginx-1.18.0.tar.gz. A small patch has to be applied to make
the code compatible with ReMon's LLVM pass, five lines changed (benchmarks/patches/nginx.patch).

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --base                   | Vanilla build with ReMon-supplied LLVM.                                                   |
| --default                | Build with ReMon-supplied LLVM, compiled with ReMon's -fatomicize option to function      |
|                          | correctly when running under ReMon, after applying a patch to force nginx to use Sys V    |
|                          | shared memory.                                                                            |
| --wrapped                | build with ReMon-supplied , after applying a patch to force nginx to use Sys V shared     |
|                          | memory and wrapping instructions that might access shared                                 |
|                          | memory using our compiler pass.                                                           |
| --base-anon              | Vanilla build with ReMon-supplied LLVM, allowing nginx to use anonymous shared memory.    |
| --default-anon           | Build with ReMon-supplied LLVM, allowing nginx to use anonymous shared memory.            |
| --wrapped-anon           | build with ReMon-supplied LLVM, allowing nginx to use anonymous shared memory and         |
|                          | wrapping instructions that might access shared memory using our compiler pass.            |

### Apache

Version 2.4.46 downloaded from https://github.com/apache/httpd.git. A small patch has to be applied to make the code
compatible with ReMon's LLVM pass, nine lines changed (benchmarks/patches/apache.patch). Additionally, we use a local
apr and apr-util with apache. Apr is version 1.7.0 and downloaded from https://dlcdn.apache.org//apr/apr-1.7.0.tar.gz.
Apr-util is version 1.6.1 and downloaded from https://dlcdn.apache.org//apr/apr-util-1.6.1.tar.gz.

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --base                   | Vanilla build with ReMon-supplied LLVM.                                                   |
| --default                | Build with ReMon-supplied LLVM, compiled with ReMon's -fatomicize option to function      |
|                          | correctly when running under ReMon.                                                       |
| --wrapped                | Build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |

### Mplayer

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

### Pulseaudio

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --default                | Vanilla build with ReMon-supplied LLVM.                                                   |
| --wrapped                | build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |
| --install                | Install the vanilla build on the system, for more accurate comparison. Note that this     |
|                          | makes very little difference and might not be worth it.                                   |

### Fontconfig

| Configure Option         | Meaning                                                                                   |
| :----------------------- | :---------------------------------------------------------------------------------------- |
| --default                | Vanilla build with ReMon-supplied LLVM, **TODO: install on system**.                      |
| --wrapped                | build with ReMon-supplied LLVM, after wrapping instructions that might access shared      |
|                          | memory using our compiler pass.                                                           |
| --install                | Install the vanilla build on the system, for more accurate comparison. Note that this     |
|                          | makes very little difference and might not be worth it.                                   |

### Microbenchmark

**TODO: add this**

---

## Running Benchmarks

### Script Aided

All benchmarks can be run using `benchmarks/scripts/run.sh <options> -- <benchmark> <version>`. 

- **Benchmark** here can be either one of the benchmarking applications mentioned here, and corresponds with one of the
folders in benchmarks/out/.
- **Version** represents what configure option is used, as mentioned in the previous section, and corresponds with a
folder in benchmarks/out/<benchmark>. These folders are generally the configure options with '-' replaced with '_'.
- **Options** are mentioned in the table below.

| Option                    | Meaning                                                                                  |
| :------------------------ | :--------------------------------------------------------------------------------------- |
| --ipmon                   | Run ReMon with IP-MON enabled                                                            |
| --debug                   | Run Debug version of ReMon. **Warning:** needs to be compiled.                           |
| --variants <N>            | Configures ReMon to use N variants.                                                      |
| --native                  | Runs selected benchmark natively, instead of running it under ReMon.                     |
| --subs </path/to/sub.srt> | Only affects mplayer. Load subtitle file at path/to/sub.srt.                             |
| --framedrop               | Only affects mplayer. Configure mplayer to show statistics on dropped frames.            |
| --maxfps                  | Only affects mplayer. Configure mplayer to disable sound and render video frames as fast |
|                           | as possible.                                                                             |
| --video </path/to/video>  | Only affects mplayer. Play video at path/to/video using mplayer.                         |

### Nginx

Optionally: start with starting the docker container.

1. `cd /wherever/this/repo/is/remon/GHUMVEE/bin/Release/`.
2. Start nginx: `./mvee -N <numvariant> -- /wherever/this/repo/is/benchmarks/out/nginx/<option>/sbin/nginx`.
3. From a different terminal (or, ideally, a different host) run `wrk -d 10s -t 1 -c 10 --timeout 10s http://localhost:8080/`.
4. Stop nginx via ctrl+c in the first terminal.

### Apache

Optionally: start with starting the docker container.

1. `cd /wherever/this/repo/is/remon/GHUMVEE/bin/Release/`.
2. Start apache: `./mvee -N <numvariant> -- /wherever/this/repo/is/benchmarks/out/apache/<option>/bin/httpd start`.
3. From a different terminal (or, ideally, a different host) run `wrk -d 10s -t 1 -c 10 --timeout 10s http://localhost:8080/`.
4. Stop apache via ctrl+c in the first terminal.

### Mplayer

Optionally: start with starting the x11docker container.

Manually:
1. `cd /wherever/this/repo/is/remon/GHUMVEE/bin/Release/`.
2. Start mplayer: `./mvee -N <numvariant> -- /wherever/this/repo/is/benchmarks/out/mplayer/<option>/bin/mplayer `
   `-benchmark -vo xv -osd-level 0 -quiet <video input>`.

Options to add to the mplayer command:
| -nosound                 | Disables sound output, making mplayer render frames as fast as it can. Shows maximum      |
|                          | reachable fps.                                                                            |
| -framedrop               | Skip the displaying of some frames to keep audio and video in sync. Shows frame drop      |
|                          | rate.                                                                                     |
| -sub </path/to/subs.srt> | Shows subtitle on screen that is rendered for 10 seconds.                                 |


**TODO: script to run this**

### Microbenchmark

**TODO: add this**
