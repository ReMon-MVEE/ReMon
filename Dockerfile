FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

# Install the required packages
RUN \
    apt-get update && \
    # Required to build dependencies
    apt-get install -y gcc g++ cmake bison flex python texinfo texi2html automake zlib1g-dev ccache \
    # Required to build MVEE
    ruby libselinux-dev musl-tools libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libconfig-dev libcap-dev libunwind8 libunwind8-dev liblzma5 liblzma-dev libjsoncpp-dev

################################################################################################################################################################
###################################################################### Build dependencies ######################################################################
################################################################################################################################################################

# Install binutils
COPY deps/binutils /opt/source/binutils/
RUN \
    mkdir -p /opt/deps/binutils/build-tree && \
    cd /opt/deps/binutils/build-tree && \
    /opt/source/binutils/configure --enable-plugins --enable-gold --disable-werror && \
    make -j `getconf _NPROCESSORS_ONLN`

# Install ReMon LLVM
COPY deps/llvm /opt/source/llvm/
RUN \
    mkdir -p /build/llvm/ && \
    cd /build/llvm/ && \
    cmake -DLLVM_TARGETS_TO_BUILD="X86;ARM" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/deps/llvm/build-tree/ -DLLVM_BINUTILS_INCDIR=/opt/source/binutils/include -DLLVM_CCACHE_BUILD=OFF \
    -DLLVM_CCACHE_DIR=/build/ccache/ -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" /opt/source/llvm/llvm/ && \
    make -j `getconf _NPROCESSORS_ONLN` install

# Cleanup
RUN rm -rf /opt/source/*

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
