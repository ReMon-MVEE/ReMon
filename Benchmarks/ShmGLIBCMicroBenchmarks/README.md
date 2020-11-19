# Compile options

## memcpy

gcc -o benchmark main.cpp -lstdc++ -DSHM_MICRO_MEMCPY

## memmove

gcc -o benchmark main.cpp -lstdc++ -DSHM_MICRO_MEMMOVE

## memset

gcc -o benchmark main.cpp -lstdc++ -DSHM_MICRO_MEMSET