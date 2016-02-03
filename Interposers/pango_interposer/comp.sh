#!/bin/sh
g++ -g `pkg-config --cflags pango freetype2` -c pango_interposer.cpp
g++ -shared -o pango_interposer.so pango_interposer.o -ldl -lrt
cp pango_interposer.so ../../interposer_binaries
