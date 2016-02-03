===============================================================================  
              _____ _    _ _    _ __  ____      ________ ______ 
             / ____| |  | | |  | |  \/  \ \    / /  ____|  ____|
            | |  __| |__| | |  | | \  / |\ \  / /| |__  | |__   
            | | |_ |  __  | |  | | |\/| | \ \/ / |  __| |  __|  
            | |__| | |  | | |__| | |  | |  \  /  | |____| |____ 
             \_____|_|  |_|\____/|_|  |_|   \/   |______|______|

            GHent University Multi-Variant Execution Environment
        (c) 2010-2016 Stijn Volckaert <stijn.volckaert@elis.ugent.be>
=============================================================================== 

Last Update: 27 JANUARI 2016

0) Disclaimer:
--------------

This is my initial attempt at writing some high-level documentation for GHUMVEE.
GHUMVEE has for the most part been a solo project and since I've never had any
immediate plans to share the code, I have never had to write high-level
documentation either. The code itself however should be well documented.

1) Introduction:
----------------

GHUMVEE is a Multi-Variant Execution System for x86 systems. Theoretically, we
support both the AMD64 and the i386 architectures, however, the latter has not
been maintained for quite a long time. 

Besides GHUMVEE, this package also contains the UTCB. The UTCB is a user-space
monitor that can replicate about 70 system calls without reporting them to
the ptracer. We described the UTCB in a paper called "Free Unlimited Calling:
Relaxed Multi-Variant Execution". We are revising this paper at the time of
this writing. In the paper, the UTCB is referred to as "IP-MON", and the
combination of IP-MON and GHUMVEE is called "ReMon".
                                                     
2) Prerequisites
----------------

!!! TL;DR: Install Ubuntu 14.04 x64 and the following packages:
!!! sudo apt-get install ruby libselinux-dev musl-tools clang libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libisl-dev libcloog-isl-dev

To build and run GHUMVEE you need:

* A GNU/Linux installation derived from a recent Debian. I _strongly_ recommend
Ubuntu since that's the only distro I've ever used during development.

Right now I am using Ubuntu 14.04 x64 myself. In the past I've also used the i386
versions of Ubuntu 11.04, 12.04, 12.10 and 13.04.

* Ruby

* A recent gcc compiler (4.8+ recommended)

* LLVM/Clang (3.6+ recommended)

* The musl C library (git clone git://git.musl-libc.org/musl or sudo apt-get install musl-tools)

* To run non-trivial (i.e. multi-threaded programs) in GHUMVEE, you'll also need
GHUMVEE-enabled versions of the libc, libpthreads, libstdc++ and (for OpenMP)
libgomp libraries. I have included several prebuilt versions of these libraries
so chances are that you won't need to build them yourselves. If you DO need to build
them yourself for whatever reason, then please read Sections 5 and 6.

* To minimize the latency on system calls you might want to rebuild the kernel as
well.  The default tick rate for Ubuntu kernels is 250Hz. The latency is however
significantly lower with a tickrate of 1000Hz. To get the kernel sources, use
"apt-get source linux".

3) When do you need to build your own libc/libpthreads/libstdc++/libgomp?
-------------------------------------------------------------------------

The SVN version of GHUMVEE includes prebuilt versions of all of these libraries.
These prebuilt versions suffice to run GHUMVEE and to replicate most parallel programs.
There are only 2 reasons why you might want to recompile these libraries yourself:

* If you want to use ReMon, you NEED to build your own libc/libpthreads. Please refer 
to section 5 for details. You do NOT NEED to build your own libstdc++ or libgomp
for ReMon!

* If you want to implement your own synchronization replication agents, you
also need to build your own libc/libpthreads. If you choose to change the interface
to the synchronization replication agents, you will also have to build 
libstdc++/libgomp (refer to section 6).

* Otherwise, please use the prebuilt versions of the standard libraries and skip 
sections 5 and 6 below.


4) IMPORTANT NOTE FOR X64 SYSTEMS
---------------------------------

On x64, the vsyscall and vDSO need to be disabled or hidden because they contain
a shared read-only page with timing info.  The kernel periodically updates this
timing information so that user-space programs do not neccessarily have to go
into the kernel to perform calls like sys_gettimeofday. From an MVEE's
perspective however, they are a problematic source of inconsistencies (we cannot
easily intercept reads from the vDSO/vsyscall pages so different replicas might
read different timing values and might diverge because of it).
GHUMVEE contains a loader-tool that is transparently injected and that will hide the
vDSO. However, the vsyscall page might have to be hidden manually by adding
"vsyscall=native" to your kernel commandline. To do so, do the following:

sudo vi /etc/default/grub
# find the line that says GRUB_CMDLINE_LINUX_DEFAULT and add vsyscall=native to it
sudo update-grub
sudo reboot

The loader tool itself is described in section 8.

5) Building GHUMVEE-ready glibc and libpthreads libraries
---------------------------------------------------------

!!! REMINDER: YOU PROBABLY DON'T NEED TO DO THIS. PLEASE REFER TO SECTION 3 FOR EXTRA INFORMATION !!!

To run multi-threaded replicas, we need a glibc and libpthreads that replicate any
synchronization decisions from the master to the slave replicas. You can read all 
about this in my paper titled:

"Replicatable Determinism for Parallel Programs"

... which you'll find on http://ghumvee.elis.ugent.be

You also have to build your own version of libc/libpthreads if you want to use ReMon.

You can build libc/libpthreads as follows:

# get the official source
$ wget http://ftp.gnu.org/gnu/glibc/glibc-2.19.tar.xz
$ tar xJf glibc-2.19.tar.xz

# apply the latest wall of clocks patch. You need this patch to support multi-threaded programs
$ cd glibc-2.19
$ patch -p1 < ~/MVEE/patches/glibc-2.19-official-amd64-woc.patch

# if you want to use ReMon, you also need to apply the following patch:
$ patch -p1 < ~/MVEE/patches/glibc-2.19-utcb.patch

# build
$ mkdir build-tree
$ cd build-tree
$ cp ~/MVEE/scripts/stijn-configure-libc.sh .
$ ./stijn-configure-libc.sh
$ make -j 8

# install the libraries into $HOME/glibc-build
$ make install

The current version of GHUMVEE will look for libc and libpthreads in the 
MVEE/patched_binaries/libc/amd64/ folder. You should set up some symlinks there:

$ cd ~/MVEE/patched_binaries/libc/amd64/
$ unlink libc.so.6
$ unlink libpthread.so.0
$ ln -s ~/glibc-build/lib/libc-2.19.so libc.so.6
$ ln -s ~/glibc-build/lib/libpthread-2.19.so libpthread.so.0

6) Building a GHUMVEE-ready libstdc++ and libgomp
-------------------------------------------------

!!! REMINDER: YOU PROBABLY DON'T NEED TO DO THIS. PLEASE REFER TO SECTION 3 FOR EXTRA INFORMATION !!!

!!! Make sure that you have the following packages installed: !!!
!!! libgmp-dev libmpfr-dev libmpc-dev libisl-dev libcloog-isl-dev !!!

Most multi-threaded C++ programs (and especially the C++11 ones with atomics)
need a GHUMVEE-enabled libstdc++. While you're at it, you can also build libgomp
from the gcc sources.  Libgomp is the base library for OpenMP programs. The
libraries can be built as follows:

apt-get source gcc-<latestversion>
cd gcc-<latestversion>
tar xJf gcc-*
cd gcc-<version>

# copy the mvee_atomic.h header
cp /path-to-GHUMVEE/scripts/mvee_atomic.h .

# patch libstdc++
patch -p1 < /path-to-GHUMVEE/patches/libstdc++.<yourver>.patch

# patch libgomp
cd libgomp/config
rm -rf linux bsd mingw32 osf
mv posix linux
mkdir posix
cp linux/time.c posix
cd ../../
patch -p1 < /path-to-GHUMVEE/patches/libgomp.<yourver>.patch

# make
./configure --enable-languages=c,c++
make -j 8

# The build will fail, due to the unresolved references to mvee symbols. Whenever the build fails, go to the directory with the failed linking,
# and edit its Makefile to allow unresolved references to mvee symbols:
sed -i 's/\(.*LDFLAGS = .*\)/\1 -Wl,--unresolved-symbols=ignore-all/' Makefile

# Then resume make until the next error. This cannot be done upfront because this will propagate into the sub-package's LDFLAGS that are also used when running configure (which results in configure reporting that all possible functions it checks for are available, because none of them produce a link error anymore).
# There is probably some cleaner, more automated way, but this suffices for now.

# "install" the libs
cp <arch>-pc-linux-gnu/libgomp/.libs/libgomp.so.1.0.0 ~/MVEE/patched_binaries/<i386|amd64>/libgomp/
cp <arch>-pc-linux-gnu/libstdc++-v3/src/.libs/libstdc++.so.6.0.<ver> ~/MVEE/patched_binaries/<i386|amd64>/libstdc++/

7) Building a GHUMVEE-ready kernel
----------------------------------

You NEED to build a custom kernel if you want to use ReMon. If you do not 
want to use ReMon, then building a custom kernel is optional but recommended.
You can build the kernel as follows:

apt-get source linux
cd linux-<version>

# optional: patch kernel for ReMon here. use patches/linux-3.13-utcb.patch
patch -p1 < ~/MVEE/patches/linux-3.13-utcb.patch

make menuconfig
# go to processor type and features
# scroll down to timer frequency
# select 1000Hz
# exit
make -j 8
sudo make modules_install
sudo make install
sudo reboot

8) Building GHUMVEE itself
--------------------------

You will need to install the following packages first:
  musl-tools libelf-dev libdwarf-dev libconfig-dev libcap-dev

Simply run make in the MVEE root directory:
make -j 8

You also need the MVEE LD Loader but this should be built automatically by make!

9) (Optional) Building the UTCB/IP-MON
--------------------------------------

!!! Make sure that you have Ruby and LLVM/Clang installed
!!! Please also verify that you can run clang

cd ~/MVEE/UTCB
./comp.sh

NOTE: You will see some errors the first time you build the UTCB.
It is safe to ignore these.

10) Playing around with GHUMVEE
-------------------------------

You'll find the GHUMVEE binary in MVEE/MVEE/bin/Release. There are currently two
ways to invoke GHUMVEE:

> The EASY way:

./MVEE <number of variants> -- <some command>

e.g.:

./MVEE 2 -- ls -al

> The AWESOME way:

./MVEE <demo number> <number of variants>

You'll find the list of demos in MVEE_demos.cpp

---

To use ReMon, you need to enable the UTCB. You can do this by enabling the "use_utcb" 
option in MVEE.ini.

---

GHUMVEE has a lot of cool debugging features. You can configure all of them
in MVEE/MVEE/Inc/MVEE_config.h. I won't bother explaining what any of the features
do since they are thoroughly documented in the source code.

---

You can also configure a bunch of options in MVEE/MVEE/bin/Release/MVEE.ini
Once again, this file is thoroughly documented.

---

If whatever program you're running in GHUMVEE deadlocks, you can use the
MVEE/MVEE_backtrace tool to shut down the MVEE and force it to generate call
stack traces for each of the replicas.

11) Playing around with the UTCB/IP-MON
---------------------------------------

You can select the UTCB policy by editing the MVEE/UTCB/MVEE_utcb.h file.
Remember to recompile by running comp.sh after editing this file!

In the file, scroll down to the "Policy control" section. The CURRENT_POLICY
preprocessor definition defines which policy will be used.

The different options are described in the "Free Unlimited Calling" paper.

12) KNOWN ISSUES
----------------

* GCC emits code with ad-hoc synchronization to initialize local static
variables.  If these local statics get initialized in a multi-threaded context,
this can cause mismatches (e.g. in PARSEC's raytrace benchmarks). This ad-hoc
synchronization code can be eliminated using -fno-threadsafe-statics.
