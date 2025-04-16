#!/bin/bash
set -e
cd $(readlink -f $(dirname ${BASH_SOURCE}))
ln -fs $(readlink -f ./ReMon-glibc/build-tree/elf/ld-linux-x86-64.so.2) ../patched_binaries/libc/amd64/ld-linux.so # ld-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/libc.so) ../patched_binaries/libc/amd64/libc.so.6 # libc-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/dlfcn/libdl.so) ../patched_binaries/libc/amd64/libdl.so.2 # libdl-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/math/libm.so) ../patched_binaries/libc/amd64/libm.so.6 # libm-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/nptl/libpthread.so) ../patched_binaries/libc/amd64/libpthread.so.0 # libpthread-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/resolv/libresolv.so) ../patched_binaries/libc/amd64/libresolv.so.2 # libresolv-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/rt/librt.so) ../patched_binaries/libc/amd64/librt.so.1 # librt-2.31.so
ln -fs $(readlink -f ./ReMon-glibc/build-tree/login/libutil.so) ../patched_binaries/libc/amd64/libutil.so.1 # libutil-2.31.so
