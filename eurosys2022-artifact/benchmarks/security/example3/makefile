CC=../../../../deps/llvm/build-tree/bin/clang++


all: external protected

clean:
	rm -rf bin/

bin:
	mkdir bin

external: external.cpp definitions.h bin
	$(CC) -pie -fPIE -lrt -lpthread -I./ -o ./bin/external external.cpp

protected: protected.cpp definitions.h bin
	$(CC) -pie -fPIE -lrt -lpthread -I./ -o ./bin/protected protected.cpp
