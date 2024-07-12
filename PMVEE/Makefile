obj-m += pmvee_kernel_module.o

all: module-install lib

clean: module-clean lib-clean

lib-static-debug:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -c -fPIC -g -O3 -o PMVEE.o PMVEE.c
	ar r libpmvee.a PMVEE.o

lib-static:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -c -fPIC -O3 -o PMVEE.o PMVEE.c
	ar r libpmvee.a PMVEE.o

lib:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -DPMVEE_PRELOAD -shared -ldl -fPIC -O3 -lc -o libpmvee.preload.so PMVEE.c
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -shared -fPIC -O3 -lc -o libpmvee.so PMVEE.c
	ln -fs $(shell readlink -f ./libpmvee.so) ../patched_binaries/gnomelibs/amd64/libpmvee.so

lib-scanning:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -DPMVEE_HEAP_SCANNING -DPMVEE_PRELOAD -shared -ldl -fPIC -O3 -lc -o libpmvee.preload.so PMVEE.c
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -DPMVEE_HEAP_SCANNING -shared -fPIC -O3 -lc -o libpmvee.so PMVEE.c
	ln -fs $(shell readlink -f ./libpmvee.so) ../patched_binaries/gnomelibs/amd64/libpmvee.so

lib-debug:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -DPMVEE_PRELOAD -shared -ldl -fPIC -g -O3 -o libpmvee.preload.so PMVEE.c
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -shared -fPIC -g -O3 -o libpmvee.so PMVEE.c
	ln -fs $(shell readlink -f ./libpmvee.so) ../patched_binaries/gnomelibs/amd64/libpmvee.so

lib-test: debug
	clang lookuptest.c -o lookuptest -L. -lpmvee
	gdb --args ./lookuptest

lib-clean:
	rm PMVEE.o
	rm libpmvee.a

module-debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

module-clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

module-uninstall:
	sudo rmmod pmvee_kernel_module || true

module-install: module-uninstall module
	sudo insmod pmvee_kernel_module.ko
