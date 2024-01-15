obj-m += pmvee_kernel_module.o

all: module lib

clean: module-clean lib-clean

lib-debug:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -c -fPIC -g -O3 -o PMVEE.o PMVEE.c
	ar r libpmvee.a PMVEE.o

lib:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -c -fPIC -O3 -o PMVEE.o PMVEE.c
	ar r libpmvee.a PMVEE.o

lib-shared:
	clang -DPMVEE_LEADER -DPMVEE_COPY_STATE -shared -fPIC -O3 -o libpmvee.so PMVEE.c

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
