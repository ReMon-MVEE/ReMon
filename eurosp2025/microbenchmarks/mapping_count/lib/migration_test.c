#include "stubs.h"

void __attribute__ ((noinline)) migration_test()
{

#if   defined(PMVEE_LEADER)
    size_t __pmvee_args_size = 0;
    char* __pmvee_zone = get_pmvee_copy();
    void* full_state_copy_start = (void*) (__pmvee_zone + __pmvee_args_size);
    migration_test_copy(__pmvee_zone, &__pmvee_args_size, &migration_test);
    void* state_copy_start = __pmvee_copy_state_leader(__pmvee_zone, &__pmvee_args_size, &migration_test);
    void* state_copy_end = (void*)(__pmvee_zone + __pmvee_args_size);
    PMVEE_ENTER(3, PMVEE_GET_ZONE, full_state_copy_start, state_copy_start, state_copy_end);
    __pmvee_real_migration_test();
    PMVEE_EXIT;
    clear_pointer_lookup();
#elif defined(PMVEE_FOLLOWER)
    size_t __pmvee_args_size = 0;
    PMVEE_ENTER(3, PMVEE_GET_ZONE)
    migration_test_copy(__pmvee_zone, &__pmvee_args_size, &migration_test);
    __pmvee_copy_state_follower(__pmvee_zone, &__pmvee_args_size, &migration_test);
    __pmvee_real_migration_test();
    PMVEE_EXIT;
    printf("should not be reched by follower\n");fflush(stdout);
#else
#endif
}
