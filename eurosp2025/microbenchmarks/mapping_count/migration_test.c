#include "lib/stubs.h"

void** migration_data = (void**) 0;
int* migration_count = (int*) 0x42;

void migration_test_copy(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    for (int migration_i = 0; migration_i < *migration_count; migration_i++)
    {
        PMVEE_STATE_COPY_POINTER(migration_data[migration_i]);
    }
}