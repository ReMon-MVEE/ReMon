#!/bin/bash
set -e

ORIG_PWD=$(pwd)

# Install the necessary ubuntu packages
sudo apt-get install ruby gcc g++ libselinux-dev musl-tools libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libisl-dev libcloog-isl-dev libconfig-dev libcap-dev cmake bison flex git texinfo texi2html binutils-dev

# Download & Install binutils
if [ ! -e deps/binutils ]
then
	git clone git://sourceware.org/git/binutils-gdb.git deps/binutils
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
	git clone https://github.com/stijn-volckaert/ReMon-llvm.git deps/llvm
fi
if [ ! -e deps/llvm/tools/clang ]
then
	git clone https://github.com/stijn-volckaert/ReMon-clang.git deps/llvm/tools/clang
fi
if [ ! -e deps/llvm/projects/compiler-rt ]
then 
	git clone https://github.com/stijn-volckaert/ReMon-compiler-rt.git deps/llvm/projects/compiler-rt
fi
if [ ! -e deps/llvm/build-tree ]
then
	mkdir -p deps/llvm/build-tree
	cd deps/llvm/build-tree
	cmake -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=$ORIG_PWD/deps/binutils/include ..
	make -j `getconf _NPROCESSORS_ONLN`
	cd ../../../
fi

# Download & Build libelf
if [ ! -e deps/libelf ]
then
	wget http://www.mr511.de/software/libelf-0.8.13.tar.gz
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
	git clone git://git.code.sf.net/p/libdwarf/code deps/libdwarf
	cd deps/libdwarf
	./configure
	make dd
	cd ../../
fi

# Download & Build libjson
if [ ! -e deps/jsoncpp ]
then
	git clone https://github.com/open-source-parsers/jsoncpp.git deps/jsoncpp
	cd deps/jsoncpp
	mkdir build
	cd build
	cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_COMPILER=$ORIG_PWD/deps/llvm/build-tree/bin/clang++ -DCMAKE_CXX_FLAGS=-O3 ..
	make -j `getconf _NPROCESSORS_ONLN`
	cd ../../../
fi

# All done!
printf "\033[0;32mReMon's dependencies are now installed!\033[0m\n"

