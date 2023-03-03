#ifdef PMVEE_LEADER
#include "PMVEE.h"

char* get_pmvee_zone()
{
    if (!pmvee_zone)
    {
        pmvee_zone = mmap(NULL, PMVEE_ZONE_DEFAULT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pmvee_zone == MAP_FAILED)
        {
            printf(" > could not map pmvee_zone... for some reason. (%d)", errno);
            exit(-1);
        }
    }

    return pmvee_zone;
}
#endif

#ifdef PMVEE_FOLLOWER
#include "PMVEE.h"

char* get_pmvee_zone()
{
    printf(" > You are a lowly follower. You should not be calling this function.");
    exit(-1);
    return pmvee_zone;
}
#endif