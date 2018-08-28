gcc -L../patched_binaries/libc/arm/ -fPIC -shared -O3 -o libclang_rt.sync-arm.so libsync.cpp
cp libclang_rt.sync-arm.so ../patched_binaries/libc/arm/
