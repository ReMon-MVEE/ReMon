gcc -L../patched_binaries/libc/i386/ -fPIC -shared -O3 -o libclang_rt.sync-i386.so libsync.cpp
cp libclang_rt.sync-i386.so ../patched_binaries/libc/i386/
