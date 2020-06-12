#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# This script can be invoked in the following modes:
# - 'download'      => downloads the dependencies for the MVEE
# - 'build'         => builds the dependencies in a Ubuntu 18.04 docker
# - 'run' (default) => runs the docker, in which you can build and use the MVEE
# - 'dev'           => runs the docker in development mode (all sources are mounted to re-compile)

IMAGE=remon
BUILD_DIR=$PWD/build
DEPS_DIR=$PWD/deps
SHARED_PROJECTS_DIR=$PWD/ext

build_docker() {
    if ! command -v docker &> /dev/null; then
        echo "No docker installed!"
        exit 1
    fi

    docker build . -t $IMAGE
}

download_deps() {
    mkdir -p deps

    # download binutils
    if [ ! -e deps/binutils ]
    then
        wget ftp://sourceware.org/pub/binutils/snapshots/binutils-2.30.90.tar.xz
        tar xJf binutils-2.30.90.tar.xz
        mv binutils-2.30.90 deps/binutils
        #	git clone git://sourceware.org/git/binutils-gdb.git deps/binutils
        rm binutils-2.30.90.tar.xz
    fi

    # download remon llvm
    if [ ! -e deps/llvm ]
    then
        git clone https://github.com/stijn-volckaert/remon-llvm.git deps/llvm
    fi
    if [ ! -e deps/llvm/tools/clang ]
    then
        git clone https://github.com/stijn-volckaert/remon-clang.git deps/llvm/tools/clang
    fi
    if [ ! -e deps/llvm/projects/compiler-rt ]
    then
        git clone https://github.com/stijn-volckaert/remon-compiler-rt.git deps/llvm/projects/compiler-rt
    fi

    # download libjson
    if [ ! -e deps/jsoncpp ]
    then
        git clone https://github.com/open-source-parsers/jsoncpp.git deps/jsoncpp
        cd deps/jsoncpp
        git reset --hard 6a15ca64429e1ce6d2fff915ff14ce1c2a96975c
        cd -
    fi

    # Set the version for the patched libc
    ./scripts/switch_patched_binaries.sh ubuntu18
}

run_docker() {
    if ! command -v x11docker &> /dev/null; then
        echo "No x11docker installed! Download at https://github.com/mviereck/x11docker"
        exit 1
    fi

    # Make these folders here. If docker makes them for us, they will be root-owned...
    mkdir -p $BUILD_DIR
    mkdir -p $SHARED_PROJECTS_DIR

    # This script adds numerous volumes to the container:
    # - the repository, containing all the code
    # - a persistent home folder. This is provided by x11docker, and can contain your config files and bash history (across docker runs!)
    # - a shared 'projects' folder, where you can place applications to build and/or run in the MVEE, as well as their data.
    # - the 'build' data volume. This named volume can be used to incrementally build LLVM (or other applications) in.
    VOLUMES="--volume $PWD:/opt/repo --volume $SHARED_PROJECTS_DIR:/projects --volume build:/build"

    # In development mode, we also mount the source code of the dependencies
    if [ "$#" -eq 1 ]; then
        VOLUMES="$VOLUMES --volume $DEPS_DIR:/opt/source"
    fi

    # The following command consists of:
    # 1st line: the x11docker invocation and its options (allow for sudo/su, with default password 'x11docker')
    # 2nd line: the docker options (allow ptracing and mount volumes)
    # 3rd line: the actual docker image and the command to run in it
    x11docker --gpu --pulseaudio --interactive --home --sudouser -- \
        --cap-add SYS_PTRACE -ti $VOLUMES -- \
        $IMAGE bash
}

# Check the number of parameters
if [ "$#" -ne 1 ]; then
    echo "No mode specified, trying to just run the docker."
    mode="run"
else
    mode="$1"
fi

case "$mode" in
    build)
        build_docker
        ;;

    download)
        download_deps
        ;;

    run)
        run_docker
        ;;

    dev)
        run_docker 1
        ;;

    *)
        echo "Invalid mode specified!"
        exit 2
        ;;
esac
