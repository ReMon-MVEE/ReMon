CC=../../../../deps/llvm/build-tree/bin/clang++


all: external protected wrapped

clean:
	rm -rf bin/

bin:
	mkdir bin

external: external.cpp definitions.h bin
	$(CC) -g -pie -fPIE -lrt -lpthread -I./ -o ./bin/external external.cpp

protected: protected.cpp definitions.h bin
	$(CC) -g -pie -fPIE -lrt -lpthread -I./ \
	      -o ./bin/protected protected.cpp
	$(CC) -g -pie -fPIE -lrt -lpthread -I./   \
		  -DENCRYPTION_KEY=0x8765432187654321 \
		  -o ./bin/protected_2 protected.cpp
	sed -i 's/".*variant-B": {.*/"variant-B": { "exec": { "alias": [ "$(shell pwd | sed 's/\//\\\//g')\/bin\/protected=$(shell pwd | sed 's/\//\\\//g')\/bin\/protected_2" ] } } }/g' ../../../../MVEE/bin/Debug/MVEE.ini
	sed -i 's/".*variant-B": {.*/"variant-B": { "exec": { "alias": [ "$(shell pwd | sed 's/\//\\\//g')\/bin\/protected=$(shell pwd | sed 's/\//\\\//g')\/bin\/protected_2" ] } } }/g' ../../../../MVEE/bin/Release/MVEE.ini

wrapped: protected.cpp definitions.h bin
	../set_aliases.sh
	../../scripts/generate_non_instrumented.sh non-instrumented.shm.in non-instrumented.shm
	$(CC) -g -pie -fPIE -lrt -lpthread -I./               \
		  -fshm_support=$(shell pwd)/non-instrumented.shm \
	      -o ./bin/wrapped protected.cpp
	$(CC) -g -pie -fPIE -lrt -lpthread -I./               \
	      -DENCRYPTION_KEY=0x8765432187654321             \
		  -fshm_support=$(shell pwd)/non-instrumented.shm \
		  -o ./bin/wrapped_2 protected.cpp
