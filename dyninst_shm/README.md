# General

The code in this directory contains code snippets from Dyninst (in dyninst-internals.cpp), which is LGPL>=2.1

# Build instructions

## Build Dyninst

First, get Dyninst as follows:

    cd /projects
    git clone https://github.com/dyninst/dyninst dyninst-git
    cd dyninst-git
    git checkout 7e8b26128506496344fd44fc13dd77c1fa1ec334
    sudo apt-get install libiberty-dev

Then build Dyninst as follows

    mkdir build
    mkdir install
    cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=${PWD}/../install 
    make # This downloads external stuff, including boost!
    make install

## Build this plugin

    export DYNINST_INSTALL=/projects/dyninst-git/build/../install 
    cd /opt/repo/dyninst_shm
    cmake .
    make

# Using this plugin

Suppose you want to rewrite `/projects/blah/mplayer` and you have the `non-instrumented-mplayer.csv` file, then first prepare the latter file as follows to keep only the instructions in the specific binary (`mplayer`) that we want to rewrite:

    grep mplayer non-instrumented-mplayer.csv | cut '-d;' -f4 > mplayer.dyninst

Then we need to set some paths:

    export DYNINST_INSTALL=/projects/dyninst-git/build/../install 
    export DYNINSTAPI_RT_LIB=${DYNINST_INSTALL}/lib/libdyninstAPI_RT.so
    export LD_LIBRARY_PATH=${DYNINST_INSTALL}/lib/:$LD_LIBRARY_PATH

And then finally, we can rewrite the binary as follows:

    ./bartTestInstrumenter /projects/blah/mplayer mplayer.dyninst

This will write the rewritten file to `InterestingProgram-rewritten`
