gcc -L../patched_binaries/libc/amd64/ -fPIC -shared -O3 -o libclang_rt.sync-x86_64.so libsync.cpp
cp libclang_rt.sync-x86_64.so ../patched_binaries/libc/amd64/
