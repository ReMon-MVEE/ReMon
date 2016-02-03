#!/bin/sh
gcc -g -O3 -c gcclibs_interposer.c
gcc -shared -o gcclibs_interposer.so gcclibs_interposer.o -ldl -lrt
cp gcclibs_interposer.so ../../interposer_binaries
