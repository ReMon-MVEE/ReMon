gcc -c -O3 -fwhole-program -fstack-protector-all -o TestApp3.o.1 TestApp3.c
# g++ -c -O -o TestApp3.o.1 TestApp3.cpp
# g++ -c -fauto-inc-dec -fcprop-registers -fdce -fdefer-pop -fdse -fguess-branch-probability -fif-conversion2 -fif-conversion -finline-small-functions -fipa-pure-const -fipa-reference -fmerge-constants -fsplit-wide-types -ftree-builtin-call-dce -ftree-ccp -ftree-ch -ftree-copyrename -ftree-dce -ftree-dominator-opts -ftree-dse -ftree-fre -ftree-sra -ftree-ter -funit-at-a-time -fomit-frame-pointer -o TestApp3.o.1 TestApp3.cpp
gcc -lpthread -o TestApp3.1 TestApp3.o.1

gcc -c -o TestApp3.o.2 TestApp3.c
gcc -lpthread -o TestApp3.2 TestApp3.o.2

# cp TestApp3.2 TestApp3
