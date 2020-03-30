#!/bin/bash
set -e

ORIG_PWD=$(pwd)

mkdir -p deps

# Install the necessary ubuntu packages
if [ -e /usr/bin/apt ]
then
    sudo apt install ruby gcc g++ libselinux-dev musl-tools libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libconfig-dev libcap-dev cmake bison flex git texinfo texi2html zlib1g-dev libunwind8 libunwind8-dev liblzma5 liblzma-dev automake
fi

# Download & Install binutils
if [ ! -e deps/binutils ]
then
    wget ftp://sourceware.org/pub/binutils/snapshots/binutils-2.30.90.tar.xz
    tar xJf binutils-2.30.90.tar.xz
    mv binutils-2.30.90 deps/binutils
    #	git clone git://sourceware.org/git/binutils-gdb.git deps/binutils
fi
if [ ! -e deps/binutils/build-tree ]
then
    mkdir -p deps/binutils/build-tree
    cd deps/binutils/build-tree
    ../configure --enable-plugins --enable-gold --disable-werror
    make -j `getconf _NPROCESSORS_ONLN`
    cd ../../../
fi

# Download & Install ReMon LLVM
if [ ! -e deps/llvm ]
then
    git clone https://github.com/csl-ugent/ReMon-llvm-project.git deps/llvm
fi
if [ ! -e deps/llvm/build-tree ]
then
    mkdir -p deps/llvm/build-tree
    cd deps/llvm/build-tree
    cmake -DLLVM_TARGETS_TO_BUILD="X86;ARM" -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=$ORIG_PWD/deps/binutils/include -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" ../llvm/
    make -j `getconf _NPROCESSORS_ONLN`
    cd ../../../
fi

# Download & Build libelf
if [ ! -e deps/libelf ]
then
    wget https://fossies.org/linux/misc/old/libelf-0.8.13.tar.gz
    tar xzf libelf-0.8.13.tar.gz -C deps
    rm libelf-0.8.13.tar.gz
    cd deps
    mv libelf-0.8.13 libelf
    cd libelf
    ./configure
    make -j `getconf _NPROCESSORS_ONLN`
    cd ../../
fi

# Download & Build libdwarf
if [ ! -e deps/libdwarf ]
then
    #	git clone git://git.code.sf.net/p/libdwarf/code deps/libdwarf
    git clone https://github.com/tomhughes/libdwarf.git deps/libdwarf
    cd deps/libdwarf
    ./configure
    make -j `getconf _NPROCESSORS_ONLN`
    cd ../../
fi

# Download & Build libjson
if [ ! -e deps/jsoncpp ]
then
    git clone https://github.com/open-source-parsers/jsoncpp.git deps/jsoncpp
    cd deps/jsoncpp
    git checkout 6a15ca64429e1ce6d2fff915ff14ce1c2a96975c
    git reset --hard
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_COMPILER=$ORIG_PWD/deps/llvm/build-tree/bin/clang++ -DCMAKE_CXX_FLAGS=-O3 ..
    make -j `getconf _NPROCESSORS_ONLN`
    cd ../../../
fi

# Download & Build musl
if [ ! -e deps/musl ]
then
    wget http://www.musl-libc.org/releases/musl-1.1.19.tar.gz
    tar xzf musl-1.1.19.tar.gz
    mv musl-1.1.19 deps/musl
    #	git clone git://git.musl-libc.org/musl deps/musl
    cd deps/musl
    ./configure --prefix=$ORIG_PWD/deps/musl-install --exec-prefix=$ORIG_PWD/deps/musl-install
    make -j `getconf _NPROCESSORS_ONLN`
    make install
    cd ../../
fi

# All done!
printf "\033[0;32mReMon's dependencies are now installed!\033[0m\n"

# Set the version for the patched libc
$ORIG_PWD/scripts/switch_patched_binaries.sh ubuntu18

# setting up build directory

# variables ============================================================================================================
   BUILD_PWD=$(pwd)
   BUILD_CXX=${BUILD_PWD}"/deps/llvm/build-tree/bin/clang++"
BUILD_LINKER=${BUILD_PWD}"/deps/binutils/build-tree/gold/ld-new"
    BUILD_AR=${BUILD_PWD}"/deps/binutils/build-tree/binutils/ar"
BUILD_RANLIB=${BUILD_PWD}"/deps/binutils/build-tree/binutils/ranlib"
# ======================================================================================================================


# setup cmake ==========================================================================================================
if [ ! -e $BUILD_PWD"/build" ]
then
  mkdir $BUILD_PWD"/build"
fi

cd $BUILD_PWD"/build"
cmake -DCMAKE_CXX_COMPILER=$BUILD_CXX                      \
            -DCMAKE_LINKER=$BUILD_LINKER                   \
                -DCMAKE_AR=$BUILD_AR                       \
            -DCMAKE_RANLIB=$BUILD_RANLIB                   \
      ..
# ======================================================================================================================