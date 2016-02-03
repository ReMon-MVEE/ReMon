#!/bin/sh
gcc -g -fno-stack-protector -fPIC -c libc_interposer.c
g++ -shared -o libc_interposer.so libc_interposer.o -ldl -lrt
cp libc_interposer.so ../../interposer_binaries/
