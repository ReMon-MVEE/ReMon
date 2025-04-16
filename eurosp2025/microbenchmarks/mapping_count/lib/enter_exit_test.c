#include "stubs.h"

void __attribute__ ((noinline)) enter_exit_test()
{

#if   defined(PMVEE_LEADER)
    PMVEE_ENTER(1, PMVEE_VOID_ZONE, 0, 0, 0);
    __pmvee_real_enter_exit_test();
    PMVEE_EXIT;
    clear_pointer_lookup();
#elif defined(PMVEE_FOLLOWER)
    PMVEE_ENTER(1, PMVEE_VOID_ZONE)
    __pmvee_real_enter_exit_test();
    PMVEE_EXIT;
    printf("should not be reched by follower\n");fflush(stdout);
#else
#endif
}
