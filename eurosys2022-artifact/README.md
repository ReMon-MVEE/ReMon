# Eurosys 2022 Artifact

This artifact relates to the "Sharing is Caring: Secure and Efficient Shared Memory Support for MVEEs" paper submitted
to Eurosys 2022. All bash snippets in the steps below are assumed to start from the repository root.

## System

All benchmarks were originally run on a system running Ubuntu 18.04 LTS, equipped with a 6-core AMD Ryzen 5 5600x CPU,
Nvidia 2060 GPU, and 16GB of RAM. For our experiments we disabled hyper-threading and turbo-boost.

As a rule of thumb we suggest counting one core for the monitor and n additional cores for every process that would be
started by the application being run. With n representing the configured number of variants.

## Prerequisites

For more reproducible results turn off hyper threading and turbo boost. The method for this might depend on your system.
General Intel way:

```bash
echo "1"   | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
echo "off" | sudo tee /sys/devices/system/cpu/smt/control
```

## Setup

While we suggest running the experiments in a native Ubuntu 18.04 machine, we do provide a docker image that can be used
instead.

To run MPlayer, a graphical application, in the docker container, download and install x11docker from
https://github.com/mviereck/x11docker.

To benchmark the servers download and install wrk from https://github.com/wg/wrk. Even if you run the benchmarks using
docker, wrk does **not** need to run inside the docker container. To reproduce our results, run the web server on one
system and the wrk benchmark on a second system, connecting both through a dedicated gigabit ethernet connection.

## Optional IP-MON setup

To run ReMon at its full potential, a small kernel patch is required. We override ReMon's kernel patch with a rolled
back version for 5.3.0. Note that this patch should work just fine on a 5.4.0 kernel if you're running Ubuntu 20.04 LTS,
but we suggest using 18.04 LTS and a 5.3.0 kernel for reproducibility. We provide a method of setting up the kernel here
that will install it as a separate package, next to your default kernel, instead of overwriting it. This allows you to
select what kernel to use at boot time via the _Advanced Options For Ubuntu_ option. The IP-MON kernel is only tested on
Ubuntu kernel source, running it in other distros is not guaranteed to work. However, installing the kernel as mentioned
below will have little to no impact on your experience.

To show the grub boot menu go to /etc/default/grub and add/change: `GRUB_TIMEOUT_STYLE=menu` and `GRUB_TIMEOUT=10`.
After saving the changes execute `sudo update-grub`.

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

## Docker instructions

When prompted for a user password inside the container
- Docker container user: eval
- Docker container password: artifactdocker

### Step 0 - setting up the container

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh build
```

**Method 2**: running docker command manually:

```bash
docker build -t shmvee:ae ./eurosys2022-artifact/
```

### Step 1 - bootstrap

**Method 1**: using the included docker bash script

```bash
# This is necessary as running this in docker might fail.
sudo sysctl -w kernel.yama.ptrace_scope=0

./eurosys2022-artifact/docker_control.sh bootstrap
```

**Method 2**: running docker command manually:

```bash
# This is necessary as running this in docker might fail.
sudo sysctl -w kernel.yama.ptrace_scope=0

docker run                                                                                 \
    -v "$(pwd):/home/eval/artifact/" --workdir="/home/eval/artifact/eurosys2022-artifact/" \
    --env BUILDALL=1 --name artifact -it shmvee:ae                                         \
    ./bootstrap.sh
docker commit artifact shmvee:ae
docker rm artifact
```

### Step 2 - run experiments

**Microbenchmark**: follow instructions in eurosys2022-artifact/wiki/microbenchmark.md

**Nginx**: follow instructions in eurosys2022-artifact/wiki/nginx.md

**Apache**: follow instructions in eurosys2022-artifact/wiki/apaches.md

**MPlayer**: follow instructions in eurosys2022-artifact/wiki/mplayer.md

## Native execution instructions

### Step 1 - bootstrap

```bash
BUILDALL=1 ./eurosys2022-artifact/bootstrap.sh
```

### Step 2 - run experiments

**Microbenchmark**: follow instructions in eurosys2022-artifact/wiki/microbenchmark.md

**Nginx**: follow instructions in eurosys2022-artifact/wiki/nginx.md

**Apache**: follow instructions in eurosys2022-artifact/wiki/apaches.md

**MPlayer**: follow instructions in eurosys2022-artifact/wiki/mplayer.md