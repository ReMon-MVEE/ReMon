# ReMon

## Introduction
This repository hosts **ReMon**, a secure and efficient Multi-Variant Execution Environment for x86 Linux programs. ReMon consists of two main components:
- The GHent University Multi-Variant Execution Environment (**GHUMVEE**). **GHUMVEE** is a full-fledged ptrace-based MVEE. It supports over 200 system calls and it is capable of running a wide variety of realistic programs.
- The In-Process MONitor (**IP-MON**). **IP-MON** is a highly efficient user-space monitor that can replicate ~70 distinct system calls without reporting them to GHUMVEE. Contrary to GHUMVEE, **IP-MON** is not a full MVEE. It can merely be used to augment GHUMVEE and to enhance its performance.

**GHUMVEE** supports both the AMD64 and the i386 architectures, though the latter has not been maintained for quite some time. **IP-MON** supports only the AMD64 architecture.

The current version of **IP-MON** takes quite a lot of manual effort to set up. Unless you **_REALLY_** need maximum performance, I would recommend using **_only_** GHUMVEE, and not IP-MON.

## ReMon Prerequisites
You will need:
- A GNU/Linux distribution based on Debian. I **_strongly_** recommend Ubuntu 14.04 x64.
- Ruby
- gcc (version 4.8 or later recommended)
- LLVM/Clang with C++14 support (version 3.6 or later recommended)
- The musl C library (get it at git://git.musl-libc.org/musl or install directly using `sudo apt-get install musl-tools`)
- Several development packages (see below)

The following command installs all of the required packages:
`sudo apt-get install ruby gcc g++ clang libselinux-dev musl-tools libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libisl-dev libcloog-isl-dev libconfig-dev libcap-dev`

## GHUMVEE Instructions

### Building GHUMVEE

Building GHUMVEE is really easy. Just navigate to ReMon's root folder and type `make -f makefile.release`.
This will build an optimized and statically linked version of the GHUMVEE binary.

Alternatively, you can also use these build configurations:
- `Release-syms`: link-time optimized version of GHUMVEE (with symbol tables intact). Suitable for people who want to debug the Release build for some obscure reason. Build using `make -f makefile.release-with-syms`.
- `Debug`: unoptimized version of GHUMVEE. This builds really fast and is suitable for people who want to debug GHUMVEE. Build using `make -f makefile.debug`.
- `Debug-sanitize`: unoptimized version of GHUMVEE with address-sanitizer enabled. Might be useful to debug memory corruption bugs. Build using `make -f make.debug-sanitize`

You will find the compiled GHUMVEE binary in the MVEE/bin/<your configuration>/ folder.
 
### Configuring GHUMVEE

GHUMVEE contains a number of configurable options and features. Features that severely impact GHUMVEE's performance generally must be configured at compile time by editing the /path/to/ReMon/MVEE/Inc/MVEE_build_config.h file. Don't forget to recompile GHUMVEE after editing this file.

Features/options with minimal performance impact can be configured by editing the MVEE.ini file in the output folder for your selected GHUMVEE build type (i.e. /path/to/ReMon/MVEE/bin/Release/ or /path/to/ReMon/MVEE/bin/Debug/).

The main feature that you might want to use is **debug logging**. Debugging logging can be enabled by disabling the `MVEE_BENCHMARK` feature in /path/to/ReMon/MVEE/Inc/MVEE_build_config.h. 

### Configuring the kernel (AMD64 systems only)

On x64, the vsyscall and vDSO need to be disabled or hidden because they contain a shared read-only page with timing info.  The kernel periodically updates this timing information so that user-space programs do not neccessarily have to go into the kernel to perform calls like sys_gettimeofday. From an MVEE's perspective however, they are a problematic source of inconsistencies (we cannot easily intercept reads from the vDSO/vsyscall pages so different variants might read different timing values and might diverge because of it).

**GHUMVEE** contains a loader-tool that is transparently injected and that will hide the vDSO. However, the vsyscall page can only be hidden if your kernel is configured to use native vsyscall pages (this used to be the default setting, but it no longer is). To enable native vsyscall pages, use the following commands:

```
sudo vi /etc/default/grub
# find the line that says GRUB_CMDLINE_LINUX_DEFAULT and add vsyscall=native to it
sudo update-grub
sudo reboot
```

### Running GHUMVEE

Depending on which build type you selected, you'll find GHUMVEE in either /path/to/ReMon/MVEE/bin/Release/ or /path/to/ReMon/MVEE/bin/Debug/. Navigate to this folder and you'll find the MVEE executable.

You can launch the MVEE in two modes:
- Legacy Mode: Use `./MVEE [Builtin Configuration Number (see MVEE_config.cpp)] [Number of Variants] [MVEE Options]`.
- RAVEN Mode: Use `./MVEE -s [Variant Set (default: default)] -f [Config File (default: MVEE.ini)] [MVEE Options] -- [Additional Program Args]`

To see a full list of supported option, just launch the MVEE using `./MVEE`.
The config file format is (mostly) compatible with RAVEN. 
A full overview of RAVEN's options is available in `RAVEN-config.pdf`.

**NOTES:** 
- The `--` is mandatory in RAVEN mode, even if no program args are passed.
- The default config file is set up to launch two variants of `/bin/bash -c` by default. Thus, if you were to launch ReMon like this: `./MVEE -- "echo test"`, this would end up executing `/bin/bash -c echo test`.
 
### Shutting GHUMVEE down

The easiest way to shut GHUMVEE down is to use CTRL+C. This will kill all of the variants and safely terminate the MVEE.

Alternatively, you might want to use the **MVEE_backtrace** tool in /path/to/ReMon/Utilities/MVEE_backtrace/ to shut the MVEE down. As the name suggests, the **MVEE_backtrace** tool will force GHUMVEE to generate stack traces for all of the variants it's currently monitoring. Keep in mind, however, that **MVEE_backtrace** will only work if you compile GHUMVEE with debug logging **_enabled_**.

## IP-MON Instructions

To fully unleash the power of **ReMon**, you will also need to compile and enable **IP-MON**. Do keep in mind, however, that **IP-MON** is not nearly as mature as **GHUMVEE**. It _should_ work, but it takes quite some effort to get it up and running, and there might still be bugs.

If you're not looking to maximize performance, then please skip this entire section. Debugging divergences is **_MUCH_** easier if you just use **GHUMVEE** without **IP-MON**.

### Building IP-MON

To build IP-MON itself, navigate to /path/to/ReMon/IP-MON and type `./comp.sh`.

### Building the IP-MON kernel

**IP-MON** requires some kernel modifications to run. **ReMon** ships with the necessary kernel patch for Linux 4.40. To build and install the custom kernel, use the following commands:

```
cd /wherever/you/want/to/download/the/kernel
apt-get source linux
cd linux-<insert version number here>
patch -p1 < /path/to/ReMon/patches/linux-4.4.0-full-ipmon.patch
make menuconfig 
# while you're in the config menu, you might want to bump the kernel tick rate up to 1000Hz
# you can do so by navigating to "Processor type and features" > "Timer Frequency"
make -j 8
sudo make modules_install
sudo make install
``` 

### Configuring the IP-MON policy

The **IP-MON** syscall policy must be selected at the source level. You can do so by editing the /path/to/ReMon/IP-MON/MVEE_ipmon.h file. Here, you can edit the definition of `CURRENT_POLICY` to select your policy.

### Enabling IP-MON

To enable **IP-MON**, simply edit the MVEE.ini file in the output folder of your selected GHUMVEE build type and set the `use_ipmon` option to 1.

### Running IP-MON

You cannot run **IP-MON** directly. GHUMVEE will automatically load and run **IP-MON** when you enable it using the `use_ipmon` option described above.

### Older IP-MON version

Although we no longer support the version of IP-MON we presented at USENIX ATC, you can still find its source code in this repository in the IP-MON-atc folder.

## Further Tinkering

### Building GHUMVEE-ready glibc and libpthreads libraries

To run multi-threaded variants, we need a glibc and libpthreads that can replicate any synchronization decisions made by the master variant to the slave variants. You can read all about this in my paper called "Multi-Variant Execution of Parallel Programs".

**GHUMVEE** ships with prebuilt versions of glibc and libpthreads. These prebuilt versions are loaded into the variants' address spaces automagically. **If you're not planning to do anything crazy, these prebuilt versions will suffice and you can skip the rest of this section.**

Some people might want to build their own GHUMVEE-ready versions of glibc and libpthreads. They can do so as follows:

```
# get the official source
wget http://ftp.gnu.org/gnu/glibc/glibc-2.19.tar.xz
tar xJf glibc-2.19.tar.xz

# apply the latest wall of clocks patch. You need this patch to support multi-threaded programs
cd glibc-2.19
patch -p1 < /path/to/ReMon/MVEE/patches/glibc-2.19-official-amd64-woc.patch

# apply the IP-MON patch
patch -p1 < /path/to/ReMon/MVEE/patches/glibc-2.19-ipmon.patch

# build
mkdir build-tree
cd build-tree
cp /path/to/ReMon/MVEE/scripts/stijn-configure-libc.sh .
./stijn-configure-libc.sh
make -j 8

# install the libraries into $HOME/glibc-build
make install
```

The current version of ReMon will load the glibc and libpthreads in the /path/to/ReMon/MVEE/patched_binaries/libc/amd64/ folder into each of the variants' address spaces. You should set up symlinks in this folder so ReMon loads the **IP-MON**-compatible glibc/libpthreads:

```
cd /path/to/ReMon/MVEE/patched_binaries/libc/amd64/
unlink libc.so.6
unlink libpthread.so.0
ln -s ~/glibc-build/lib/libc-2.19.so libc.so.6
ln -s ~/glibc-build/lib/libpthread-2.19.so libpthread.so.0
```

### Building GHUMVEE-ready versions of libstdc++ and libgomp

In addition to GHUMVEE-ready versions of glibc and libpthreads, some multi-threaded variants might also require GHUMVEE-ready versions of libstdc++ and libgomp. Once again, GHUMVEE ships with prebuilt versions of these libraries so if you're not planning to do anything crazy, **you can skip the rest of this section **.

If, for whatever reason, you want to build your own GHUMVEE-versions of these libraries, then use the following commands:
```
# download the gcc sources
apt-get source gcc-<latestversion>
cd gcc-<latestversion>
tar xJf gcc-*
cd gcc-<version>

# copy the mvee_atomic.h header to the gcc sources folder
cp /path/to/ReMon/scripts/mvee_atomic.h .

# patch libstdc++
patch -p1 < /path/to/ReMon/patches/libstdc++.<yourver>.patch

# patch libgomp
cd libgomp/config
rm -rf linux bsd mingw32 osf
mv posix linux
mkdir posix
cp linux/time.c posix
cd ../../
patch -p1 < /path/to/ReMon/patches/libgomp.<yourver>.patch

# make
./configure --enable-languages=c,c++
make -j 8

# The build will fail, due to the unresolved references to mvee symbols. 
# Whenever the build fails, go to the directory that contains the module that failed to link, 
# and edit its Makefile to allow unresolved references to mvee symbols:
sed -i 's/\(.*LDFLAGS = .*\)/\1 -Wl,--unresolved-symbols=ignore-all/' Makefile

# Then resume make until the next error. This cannot be done up front 
# because this will propagate into the sub-package's LDFLAGS that are 
# also used when running configure (which results in configure reporting 
# that all possible functions it checks for are available, because none 
# of them produce a link error anymore).
# There is probably some cleaner, more automated way, but this suffices for now.

# "install" the libs
cp <arch>-pc-linux-gnu/libgomp/.libs/libgomp.so.1.0.0 /path/to/ReMon/patched_binaries/<i386|amd64>/libgomp/
cp <arch>-pc-linux-gnu/libstdc++-v3/src/.libs/libstdc++.so.6.0.<ver> /path/to/ReMon/patched_binaries/<i386|amd64>/libstdc++/
```

## Known Issues

- GCC emits code with ad-hoc synchronization to initialize local static variables.  If these local statics get initialized in a multi-threaded context, this can cause mismatches (e.g. in PARSEC's raytrace benchmarks). This ad-hoc synchronization code can be eliminated using the `-fno-threadsafe-statics` compiler flag.

## Further Reading

Here are some of the publications that build on or use ReMon:

[Taming Parallelism in a Multi-Variant Execution Environment](http://www.ics.uci.edu/~stijnv/Papers/eurosys17-parallelism.pdf)
Stijn Volckaert, Bart Coppens, Bjorn De Sutter, Koen De Bosschere, Per Larsen, and Michael Franz.
In 12th European Conference on Computer Systems (EuroSys'17). ACM, 2017.
To appear.

[Secure and Efficient Application Monitoring and Replication](http://www.ics.uci.edu/~stijnv/Papers/atc16-remon.pdf)
Stijn Volckaert, Bart Coppens, Alexios Voulimeneas, Andrei Homescu, Per Larsen, Bjorn De Sutter, and Michael Franz.
In 2016 USENIX Annual Technical Conference (ATC'16), pages 167-179. USENIX, 2016.

[Advanced Techniques for Multi-Variant Execution](http://www.ics.uci.edu/~stijnv/Papers/thesis.pdf)
Stijn Volckaert.
PhD dissertation, Ghent University, 2015.

[Cloning your Gadgets: Complete ROP Attack Immunity with Multi-Variant Execution](http://www.ics.uci.edu/~stijnv/Papers/tdsc15-gadgets.pdf)
Stijn Volckaert, Bart Coppens, and Bjorn De Sutter.
In IEEE Transactions on Dependable and Secure Computing (TDSC) (Volume 13, Issue 4, July-Aug 2016).

[GHUMVEE: Efficient, effective, and flexible replication](http://www.ics.uci.edu/~stijnv/Papers/fps12-ghumvee.pdf)
Stijn Volckaert, Bjorn De Sutter, Tim De Baets, and Koen De Bosschere.
In 5th International Symposium on Foundations and Practice of Security (FPS'12), pages 261-277. Springer, 2013.

## License

The **IP-MON** component is available under the licensing terms in `IPMONLICENSE.txt`.
This license applies to the following files:
- `patches/linux-3.13-ipmon.patch`
- `patches/linux-3.13-full-ipmon.patch`
- `patches/linux-4.4.0-full-ipmon.patch`
- The entire `IP-MON` and `IP-MON-atc` folders

Some of the files in the `exploits/BROP` folder were downloaded from [this website](http://www.scs.stanford.edu/brop/). The licensing terms for these files are unknown.

Unless otherwise specified, all other files in the repository are available under the licensing terms in `GHUMVEELICENSE.txt`.
