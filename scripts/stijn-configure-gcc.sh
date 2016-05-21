../configure --enable-lto --enable-languages=c,c++ \
  --enable-multiarch --enable-shared --enable-threads=posix \
  --program-suffix=-4.8 --with-gmp=/usr/local/lib --with-mpc=/usr/lib \
  --with-mpfr=/usr/lib --without-included-gettext --with-system-zlib \
  --with-tune=generic --with-stage1-ldflags=-L$HOME/glibc-build/lib/ \
  --with-boot-ldflags=-L$HOME/glibc-build/lib/ \
  --prefix=$HOME/gcc-build
