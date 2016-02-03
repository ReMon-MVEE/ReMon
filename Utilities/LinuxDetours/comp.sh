g++ -g -c LinuxDetours.c
g++ -g -c hde32.c
g++ -shared -o LinuxDetours.so LinuxDetours.o hde32.o
cp LinuxDetours.so ../MVEE/bin/Release/
cp LinuxDetours.so ../MVEE/bin/Debug/
rm *.o
