#!/bin/bash

__home_dir="$(readlink -f $(dirname ${BASH_SOURCE}))"
cd "$__home_dir"

sudo apt install -y libpulse-dev libxv-dev libxext-dev libx11-dev libx11-xcb-dev libxtst-dev libfreetype6-dev    \
        libfontconfig-dev gperf libpcre3-dev libexpat1-dev autopoint libtool libtool-bin libsndfile1-dev gettext \
        libssl-dev python libice-dev libsm-dev uuid-dev gcc binutils libiberty-dev

## ReMon Setup #########################################################################################################
cd ../
./bootstrap.sh
cd ./build/
make -j$(nproc)
make debug
make -j$(nproc)

sudo apt install -y clang
cd ../IP-MON
ruby ./generate_headers.rb

cp "$__home_dir/benchmarks/patches/IP-MON/"* "$__home_dir/../IP-MON/"

./comp.sh
mv ./libipmon.so ./libipmon-default.so

patch -p 2 -d ./ < ../eurosys2022-artifact/benchmarks/patches/ipmon-nginx.patch
./comp.sh
mv ./libipmon.so ./libipmon-nginx.so
patch -R -p 2 -d ./ < ../eurosys2022-artifact/benchmarks/patches/ipmon-nginx.patch

patch -p 2 -d ./ < ../eurosys2022-artifact/benchmarks/patches/ipmon-apache.patch
./comp.sh
mv ./libipmon.so ./libipmon-apache.so
patch -R -p 2 -d ./ < ../eurosys2022-artifact/benchmarks/patches/ipmon-apache.patch

patch -p 2 -d ./ < ../eurosys2022-artifact/benchmarks/patches/ipmon-mplayer.patch
./comp.sh
mv ./libipmon.so ./libipmon-mplayer.so
patch -R -p 2 -d ./ < ../eurosys2022-artifact/benchmarks/patches/ipmon-mplayer.patch

ln -fs ./libipmon-default.so ./libipmon.so
## ReMon Setup #########################################################################################################


## glibc Setup #########################################################################################################
cd "$__home_dir/../deps/"
if [ ! -d "./ReMon-glibc/" ]
then
    git clone https://github.com/ReMon-MVEE/ReMon-glibc.git
    cd "./ReMon-glibc/"
    mkdir "./build/"
    cd "./build/"
    mkdir "built-versions/"
    mkdir "built-versions/normal/"
    mkdir "built-versions/stripped/"

    # really dangerous config for u. Never, EVER, do make install with this.
    CFLAGS="-O2 -fno-builtin" ../configure --enable-stackguard-randomization --enable-obsolete-rpc --enable-pt_chown \
        --with-selinux --enable-lock-elision=no --enable-addons=nptl --prefix=/ --sysconfdir=/etc/

    git checkout 6da144e6c531e478771704a17efc1d47f55d625a
    make -j$(nproc)
    cp "./elf/ld.so"             "./built-versions/normal/"
    cp "./libc.so.6"             "./built-versions/normal/"
    cp "./dlfcn/libdl.so.2"      "./built-versions/normal/"
    cp "./math/libm.so.6"        "./built-versions/normal/"
    cp "./nptl/libpthread.so.0"  "./built-versions/normal/"
    cp "./resolv/libresolv.so.2" "./built-versions/normal/"
    cp "./rt/librt.so.1"         "./built-versions/normal/"
    cp "./login/libutil.so.1"    "./built-versions/normal/"

    patch -d ../ -p 1 < "$__home_dir/benchmarks/patches/ReMon-glibc-stripped.patch"
    make clean
    make -j$(nproc)
    cp "./elf/ld.so"             "./built-versions/stripped/"
    cp "./libc.so.6"             "./built-versions/stripped/"
    cp "./dlfcn/libdl.so.2"      "./built-versions/stripped/"
    cp "./math/libm.so.6"        "./built-versions/stripped/"
    cp "./nptl/libpthread.so.0"  "./built-versions/stripped/"
    cp "./resolv/libresolv.so.2" "./built-versions/stripped/"
    cp "./rt/librt.so.1"         "./built-versions/stripped/"
    cp "./login/libutil.so.1"    "./built-versions/stripped/"

    git checkout 6da144e6c531e478771704a17efc1d47f55d625a ../

    ln -fs "$__home_dir/../deps/ReMon-glibc/build/built-versions/normal/"* \
		"$__home_dir/../patched_binaries/libc/amd64"
fi
## glibc Setup #########################################################################################################


## dyninst Setup #######################################################################################################
cd "$__home_dir/../deps/"

if [ ! -d "./dyninst/" ]
then
    git clone https://github.com/dyninst/dyninst dyninst
    cd ./dyninst/
    git checkout 7e8b26128506496344fd44fc13dd77c1fa1ec334

    mkdir ./build/
    mkdir ./install/
    cd ./build/
    cmake .. -DCMAKE_INSTALL_PREFIX="$__home_dir/../deps/dyninst/build/../install"
    make -j$(nproc) # This downloads external stuff, including boost!
    make install

    export DYNINST_INSTALL="$__home_dir/../deps/dyninst/build/../install"

    cd "$__home_dir/../dyninst_shm"
    cmake .
    make -j$(nproc)
fi
## dyninst Setup #######################################################################################################


## Benchmark Setup #####################################################################################################
cd "$__home_dir/benchmarks/"

if [ ! -d "./pulseaudio/" ]
then
    git clone --depth 1 -b v14.2 git://anongit.freedesktop.org/pulseaudio/pulseaudio pulseaudio
    cd ./pulseaudio/
    NOCONFIGURE=1 ./bootstrap.sh
    cd ../
fi

if [ ! -d "./fontconfig/" ]
then
    git clone --depth 1 -b 2.13.1 https://gitlab.freedesktop.org/fontconfig/fontconfig.git fontconfig
    cd ./fontconfig/
    NOCONFIGURE=1 ./autogen.sh
    cd ../
fi

if [ ! -d "./nginx/" ]
then
    wget http://nginx.org/download/nginx-1.18.0.tar.gz
    tar -xf nginx-1.18.0.tar.gz
    mv nginx-1.18.0 nginx
    patch -d ./nginx/ -p 2 < ./patches/nginx.patch
    cp "$__home_dir/benchmarks/conf/nginx.conf" "$__home_dir/benchmarks/nginx/conf/"
    cp "$__home_dir/benchmarks/input/index.html" "$__home_dir/benchmarks/nginx/html/"
fi

if [ ! -d "./apache/" ]
then
    git clone --depth 1 -b 2.4.46 https://github.com/apache/httpd.git apache
    cd ./apache/srclib/
    wget https://dlcdn.apache.org//apr/apr-1.7.0.tar.gz
    tar -xf ./apr-1.7.0.tar.gz
    mv ./apr-1.7.0/ ./apr/
    wget https://dlcdn.apache.org//apr/apr-util-1.6.1.tar.gz
    tar -xf ./apr-util-1.6.1.tar.gz
    mv ./apr-util-1.6.1/ apr-util/
    cd ../
    cp "$__home_dir/benchmarks/conf/httpd.conf.in" "$__home_dir/benchmarks/apache/docs/conf/"
    cp "$__home_dir/benchmarks/input/index.html" "$__home_dir/benchmarks/apache/docs/docroot/"
    ./buildconf
    cd ../
    patch -p 2 -d ./apache/ < ./patches/apache.patch
fi

if [ ! -d "./mplayer/" ]
then
    wget http://www.mplayerhq.hu/MPlayer/releases/MPlayer-1.4.tar.xz
    tar -xf ./MPlayer-1.4.tar.xz
    mv ./MPlayer-1.4/ ./mplayer/
fi

cd ./microbenchmark
make
cd ../

echo "__llvm_dir=\"$__home_dir/../deps/llvm/build-tree/\"" > ./config.sh
if [[ "$BUILDALL" == 1 ]]
then
    ./scripts/build_all.sh
fi

# TODD check without yasm
## Benchmark Setup #####################################################################################################
