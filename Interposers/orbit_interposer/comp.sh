#!/bin/sh
g++ -fPIC -c `orbit2-config --cflags` orbit_interposer.cpp
g++ -shared -o orbit_interposer.so orbit_interposer.o -ldl -lc
cp orbit_interposer.so ../../interposer_binaries/
