nasm -f elf routines32.s -o routines32.o
gcc -mtune=pentium routines32.o TestApp12.c -O6 -o TestApp12
