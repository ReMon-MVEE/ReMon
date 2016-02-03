#!/bin/sh
gcc -ggdb -c -std=gnu99 rand_interposer.c
g++ -shared -o rand_interposer.so rand_interposer.o --version-script=Versions -ldl -lrt
cp rand_interposer.so ../../interposer_binaries
