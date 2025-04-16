#!/bin/bash
set -e

cd $(readlink -f $(dirname ${BASH_SOURCE}))

sudo apt install openssh-server
mkdir ~/.ssh || true
touch ~/.ssh/config || true

## kernel
if [[ ! $(uname -r | grep -e "-ipmon-pmvee") ]]
then 
    mkdir kernel/ || true
    cd kernel/
    sudo apt-get update
    sudo apt-get install linux-source-5.4.0
    tar jxf /usr/src/linux-source-5.4.0/linux-source-5.4.0.tar.bz2
    cd linux-source-5.4.0
    patch -p1 < ../../../patches/linux-5.4.0-full-ipmon-pmvee.patch
    make menuconfig 
    # while you're in the config menu, you might want to bump the kernel tick rate up to 1000Hz
    # you can do so by navigating to "Processor type and features" > "Timer Frequency"
    ./scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYS
    ./scripts/config --disable SYSTEM_REVOCATION_KEYS
    make -j$(nproc) deb-pkg LOCALVERSION=-ipmon-pmvee
    sudo dpkg -i ../linux-headers*.deb ../linux-image*.deb ../linux-libc-dev*.deb
    cd ../../
fi
## kernel

## kernel check
if [[ ! $(uname -r | grep -e "-ipmon-pmvee") ]]
then 
    echo "FORTDIVIDE requires our custom kernel patch to be applied."
    if [[ $(grep -e "-ipmon-pmvee" /boot/grub/grub.cfg) ]]
    then
        echo "It appears you do have to correct kernel installed on this system, please reboot to it"
    else
        echo "You do not appear to have the correct kernel installed on this system, perhaps something went wrong compiling and installing it."
    fi
    exit 1    
fi
## kernel check

## top level remon
cd ../

./bootstrap.sh
cd build/
patch -p 2 -d ../IP-MON < ../eurosp2025/patches/pmvee-ipmon-nginx.patch
make block-shm && make benchmark && make -j 1>/dev/null
mv ../IP-MON/libipmon.so ../IP-MON/libipmon-nginx.so
patch -R -p 2 -d ../IP-MON < ../eurosp2025/patches/pmvee-ipmon-nginx.patch
make block-shm && make benchmark && make -j 1>/dev/null
mv ../IP-MON/libipmon.so ../IP-MON/libipmon-default.so
make enable-ipmon-pmvee && make block-shm && make benchmark && make -j 1>/dev/null
mv ../IP-MON/libipmon.so ../IP-MON/libipmon-pmvee.so
ln -fs $(readlink -f ../IP-MON/libipmon-pmvee.so) ../IP-MON/libipmon.so
cd ../

cd eurosp2025/
## top level remon

## fortdivide changes to ReMon build and config
## fortdivide changes to ReMon build and config

## fortdivide changes to ReMon libc build and config
if [ ! -e ReMon-glibc ]
then
    git clone https://github.com/ReMon-MVEE/ReMon-glibc.git
    cd ReMon-glibc/
    mkdir build-tree
    patch -d ./ -p 1 < ../patches/ReMon-glibc.patch
    cd build-tree
    CFLAGS="-g -O2 -fno-builtin -Wno-alloca-larger-than -ggdb -fno-omit-frame-pointer" ../configure --enable-stackguard-randomization --enable-obsolete-rpc --enable-pt_chown --with-selinux --enable-lock-elision=no --enable-addons=nptl --prefix=/usr/ --sysconfdir=/etc/
    make -j
    # ln -fs $(readlink -f ./) ../../../patched_binaries/libc/amd64/
    cd ../../
fi
./fortdivide-libc.sh
## fortdivide changes to ReMon libc build and config

## nginx
if [ ! -e nginx-1.23.3 ]
then
    git clone https://github.com/nginx/nginx.git nginx-1.23.3
    cd nginx-1.23.3
    git checkout release-1.23.3
    patch -d ./ -p 2 < ../patches/nginx-1.23.3.patch
    ln -fs ../build_scripts/nginx-1.23.3-build.sh ./
    ./auto/configure
    cd ../
fi
## nginx

## lighttpd
if [ ! -e lighttpd-1.4.60 ]
then
    git clone https://git.lighttpd.net/lighttpd/lighttpd1.4.git lighttpd-1.4.60
    cd lighttpd-1.4.60
    ./autogen.sh
    git checkout lighttpd-1.4.60
    patch -d ./ -p 2 < ../patches/lighttpd-1.4.60.patch
    ln -fs ../build_scripts/lighttpd-1.4.60-build.sh ./
    cd ../
fi
## lighttpd

## final benchmark setup
sed -r -i "s.##benchmark_location##.$(readlink -f ./).g" ./pmvee_config/nginx-1.23.3/*
sed -r -i "s.##benchmark_location##.$(readlink -f ./).g" ./pmvee_config/lighttpd-1.4.60/*
sed -r -i "s.##benchmark_location##.$(readlink -f ./).g" ./microbenchmarks/mapping_count/mapping_count.json
sed -r -i "s.##benchmark_location##.$(readlink -f ./).g" ../PMVEE/scripts/get_libc_line.sh
sed -r -i "s.##fortdivide_location##.$(readlink -f ../).g" ./benchmarking.sh
sed -r -i "s.##fortdivide_location##.$(readlink -f ../).g" ./pmvee_config/MVEE.ini.patch
sed -r -i "s.##fortdivide_location##.$(readlink -f ../).g" ../PMVEE/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py

cd ../
patch -d ./ -p 1 < eurosp2025/pmvee_config/MVEE.ini.patch

cd ./PMVEE/allocator/
make
cd ../
make lib
make module-install
cd ../eurosp2025

echo "" >> ~/.ssh/config
echo "Host fortdivide-benchmark" >> ~/.ssh/config
echo "    Hostname localhost" >> ~/.ssh/config
echo "    User $USER" >> ~/.ssh/config
## final benchmark setup