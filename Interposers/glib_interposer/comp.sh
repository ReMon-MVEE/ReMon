#!/bin/sh
g++ -ggdb `pkg-config --cflags glib-2.0` -c glib_interposer.cpp
g++ -shared -o glib_interposer.so glib_interposer.o -ldl -lrt
cp glib_interposer.so ../../interposer_binaries/
