To run qemu variants, simply download and build QEMU as follows:

$ git clone git://git.qemu-project.org/qemu.git
$ cd qemu
$ ./configure --target-list=i386-linux-user,x86_64-linux-user,arm-linux-user,aarch64-linux-user
$ make -j 8
