#!/bin/sh
g++ -O3 -I/usr/lib/jvm/java-1.7.0-openjdk-i386/include/ -c openjdk_interposer.c -ggdb
#g++ -ggdb -I/usr/lib/jvm/java-6-openjdk/include/ -c openjdk_interposer.c
g++ -shared -o openjdk_interposer.so openjdk_interposer.o -ldl -lrt
cp openjdk_interposer.so ../../interposer_binaries/
