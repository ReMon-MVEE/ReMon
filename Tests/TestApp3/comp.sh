# gcc -c -O3 -fwhole-program -fstack-protector-all -o TestApp3.o.1 TestApp3.c

# gcc -pthread -o TestApp3.1 TestApp3.o.1

# gcc -c -o TestApp3.o.2 TestApp3.c
# gcc -pthread -o TestApp3.2 TestApp3.o.2

# cp TestApp3.2 TestApp3

g++ -pthread -O2 -ggdb -fno-omit-frame-pointer -o TestApp3 TestApp3.cpp
