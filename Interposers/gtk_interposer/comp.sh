g++ -c -g `pkg-config --cflags glib-2.0` gtk_interposer.cpp -o gtk_interposer.o
g++ -shared -o gtk_interposer.so gtk_interposer.o -ldl -lrt
cp gtk_interposer.so ../../interposer_binaries/
rm *.o
