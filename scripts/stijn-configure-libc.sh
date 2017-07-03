rm -rf $HOME/glibc-build/etc
mkdir -p $HOME/glibc-build/etc
cp /etc/ld.so.conf.d/x86_64-linux-gnu.conf $HOME/glibc-build/etc/ld.so.conf
../configure --host=x86_64-linux-gnu --build=x86_64-linux-gnu --prefix=/usr --enable-stackguard-randomization --enable-obsolete-rpc --enable-pt_chown --with-selinux --enable-lock-elision=no --enable-addons=nptl --prefix=$HOME/glibc-build
