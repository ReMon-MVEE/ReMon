CC=../../../../deps/llvm/build-tree/bin/clang++


all: external protected wrapped

clean:
	rm -rf bin/

bin:
	mkdir bin

external: external.cpp definitions.h bin
	$(CC) -g -pie -fPIE -lrt -lpthread -I./ \
	      -o ./bin/external external.cpp

protected: protected.cpp definitions.h bin
	$(CC) -g -pie -fPIE -lrt -lpthread -I./ \
	      -o ./bin/protected protected.cpp

wrapped: protected.cpp definitions.h bin
	../../scripts/generate_non_instrumented.sh non-instrumented.shm.in non-instrumented.shm
	$(CC) -g -pie -fPIE -lrt -lpthread -I./               \
		  -fshm_support=$(shell pwd)/non-instrumented.shm \
	      -o ./bin/wrapped protected.cpp
