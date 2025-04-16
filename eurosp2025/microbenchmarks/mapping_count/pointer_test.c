#include "lib/stubs.h"

#ifdef PMVEE_LEADER

#define PMVEE_STATE_COPY_POINTER(__pointer)                      \
*(void**)(__pmvee_zone + *__pmvee_args_size) = (void*)__pointer; \
*__pmvee_args_size+=sizeof(void*); // printf(">%ld", sizeof(void*));fflush(stdout);

#endif

#ifdef PMVEE_FOLLOWER

#define PMVEE_STATE_COPY_POINTER(__pointer)                      \
__pointer = *(void**)(__pmvee_zone + *__pmvee_args_size);        \
*__pmvee_args_size+=sizeof(void*);
#endif

void** pointer_data = (void**) 0;
int* pointer_count = (int*) 0x42;

void pointer_test_migration(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    for (int pointer_i = 0; pointer_i < *pointer_count; pointer_i++)
    {
        PMVEE_STATE_COPY_POINTER(pointer_data[pointer_i]);
    }
}