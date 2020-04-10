FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive

# Install the required packages
RUN \
    apt-get update && \
    # Required to build dependencies
    apt-get install -y gcc g++ cmake bison flex python texinfo texi2html automake zlib1g-dev \
    # Required to build MVEE
    ruby libselinux-dev musl-tools libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libconfig-dev libcap-dev libunwind8 libunwind8-dev liblzma5 liblzma-dev

################################################################################################################################################################
###################################################################### Build dependencies ######################################################################
################################################################################################################################################################

# Install binutils
COPY deps/binutils /tmp/binutils/
RUN \
    mkdir -p /opt/deps/binutils/build-tree && \
    cd /opt/deps/binutils/build-tree && \
    /tmp/binutils/configure --enable-plugins --enable-gold --disable-werror && \
    make -j `getconf _NPROCESSORS_ONLN`

# Build musl
COPY deps/musl /tmp/musl/
RUN \
    cd /tmp/musl && \
    /tmp/musl/configure --prefix=/opt/deps/musl-install --exec-prefix=/opt/deps/musl-install && \
    make -j `getconf _NPROCESSORS_ONLN` install

# Build libjson
COPY deps/jsoncpp /tmp/jsoncpp/
RUN \
    mkdir -p /opt/deps/jsoncpp/build && \
    cd /opt/deps/jsoncpp/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_FLAGS=-O3 \
    -DCMAKE_INSTALL_INCLUDEDIR=include/jsoncpp -DCMAKE_INSTALL_PREFIX=/usr/ /tmp/jsoncpp && \
    make -j `getconf _NPROCESSORS_ONLN` install

# Install ReMon LLVM
COPY deps/llvm /tmp/llvm/
RUN \
    mkdir -p /build/llvm/ && \
    cd /build/llvm/ && \
    cmake -DLLVM_TARGETS_TO_BUILD="X86;ARM" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/deps/llvm/build-tree/ -DLLVM_BINUTILS_INCDIR=/tmp/binutils/include /tmp/llvm/ && \
    make -j `getconf _NPROCESSORS_ONLN` install

# Cleanup
RUN rm -rf /tmp/*

# Set environment variable in container, so when building MVEE we know all dependencies can be found in /usr
ENV MVEE_DEPS_PRESENT_IN_SYSTEM yes

################################################################################################################################################################
########################################################################## Extra stuff #########################################################################
################################################################################################################################################################

# Enable deb-src
RUN sed -i 's/^#\sdeb-src/deb-src/' /etc/apt/sources.list

# Install extra applications to run in MVEE, or tools to build those applications
RUN \
    apt-get update && \
    apt-get install -y vim less strace sudo

# Make sure normal users have plenty of rights to /opt
RUN chmod 777 /opt

WORKDIR /projects
