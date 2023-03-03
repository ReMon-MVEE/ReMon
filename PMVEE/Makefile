obj-m += pmvee_kernel_module.o

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

uninstall:
	sudo rmmod pmvee_kernel_module || true

install: uninstall all
	sudo insmod pmvee_kernel_module.ko
