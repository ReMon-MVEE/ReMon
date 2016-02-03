#!/bin/sh
gcc -g -m32 -O3 -std=c99 -c mvee_lazy_hooker.c
gcc -g -m32 -O3 -c hde32.c
gcc -g -m32 -O3 -c LinuxDetours.c
gcc -g -m32 -O3 -c MVEE_interposer_base_shared.c
gcc -flto -shared -O3 -o mvee_lazy_hooker.so mvee_lazy_hooker.o hde32.o LinuxDetours.o MVEE_interposer_base_shared.o -ldl -lrt -lc -lpthread
cp mvee_lazy_hooker.so ../interposer_binaries
