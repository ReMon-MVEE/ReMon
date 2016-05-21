#!/bin/sh
g++ -ggdb -c libreoffice_uno_interposer.c
g++ -shared -o libreoffice_uno_interposer.so libreoffice_uno_interposer.o -ldl -lrt
cp libreoffice_uno_interposer.so ../../interposer_binaries/
