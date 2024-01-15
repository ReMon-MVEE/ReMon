#ifdef PMVEE_LEADER
#include <stdio.h>
#include <unistd.h>
#include "PMVEE.h"

char* base = (char*) 0;
char* pmvee_copy = (char*) 0;

#define debugf(...) ; // printf(__VA_ARGS__);fflush(stdout);

char* get_pmvee_copy()
{
    if (!pmvee_copy)
    {
        pmvee_copy = mmap(NULL, PMVEE_COPY_DEFAULT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pmvee_copy == MAP_FAILED)
        {
            debugf(" > could not map pmvee_copy... for some reason. (%d)", errno);
            exit(-1);
        }
        base = (char*)syscall(__NR_pmvee_switch, PMVEE_REGION_REQUEST);
        debugf(" > b-%p\n", (void*)base);
    }

    return pmvee_copy;
}


__pmvee_dict_t* pmvee_dict      = (__pmvee_dict_t*) 0;
__pmvee_dict_t* pmvee_dict_head = (__pmvee_dict_t*) 0;
__pmvee_dict_t* pmvee_dict_tail = (__pmvee_dict_t*) 0;

int lookup_pointer(void* original, void** new)
{
    if (!pmvee_dict)
    {
        pmvee_dict = mmap(NULL, PMVEE_DICT_DEFAULT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pmvee_dict == MAP_FAILED)
        {
            debugf(" > could not map pmvee_dict... for some reason. (%d)\n", errno);
            exit(-1);
        }

        size_t offset = 0;
        while (offset < PMVEE_DICT_DEFAULT_SIZE / sizeof(__pmvee_dict_t))
        {
            (pmvee_dict + offset)->prev = pmvee_dict + (offset - 1);
            (pmvee_dict + offset)->from = (void*) 0x00;
            (pmvee_dict + offset)->to   = (void*) 0x00;
            (pmvee_dict + offset)->next = pmvee_dict + (offset + 1);
            offset++;
        }
        pmvee_dict->prev                = (void*)  0;
        (pmvee_dict + offset - 1)->next = (void*) -1;
        pmvee_dict_head = pmvee_dict;
        pmvee_dict_tail = pmvee_dict;
    }

    debugf(" > [ %p ; %p )\n", base, base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE);
    if ((char*)original >= base && original <= (void*)((unsigned long)base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE))
    {
        debugf(" > returning %p\n", original);
        *new = original;
        return 0;
    }

    debugf(" > translating %p...", original);
    __pmvee_dict_t* pmvee_dict_i = (__pmvee_dict_t*) pmvee_dict_head;
    while (pmvee_dict_i != pmvee_dict_tail)
    {
        if (pmvee_dict_i->from == original)
        {
            *new = pmvee_dict_i->to;
            debugf(" > found %p!", *new);
            return 0;
        }
        pmvee_dict_i = pmvee_dict_i->next;
    }

    pmvee_dict_tail    =  pmvee_dict_i->next;
    pmvee_dict_i->from =  original;
    pmvee_dict_i->to   = *new;
    debugf(" > added %p -> %p!\n", original, *new);
    return 1;
}
#endif

#ifdef PMVEE_FOLLOWER

#endif


static struct __pmvee_state_copies_t __pmvee_state_copies =
{
    (int)-1,
    {},
    (int)-1,
    {}
};
static void (*__pmvee_copy_libc_state_leader) (char*, size_t*) = NULL;
void* __pmvee_copy_state_leader(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    if (!__pmvee_copy_libc_state_leader)
    {
        __asm("syscall;"
                : "=a" (__pmvee_copy_libc_state_leader)
                : "a" (__NR_pmvee_switch), "D" (PMVEE_LIBC_REQUEST)
                : "rcx", "r8", "r9", "r10", "r11");
    }
    if (__pmvee_state_copies.copy_count == (int)-1)
    {
        __asm("syscall;"
                :
                : "a" (__NR_pmvee_switch), "D" (PMVEE_HANDLER_REQUEST), "S" (&__pmvee_state_copies)
                : "rcx", "r8", "r9", "r10", "r11");
    }

    __pmvee_copy_libc_state_leader(__pmvee_zone, __pmvee_args_size);
    for (int i = 0; i < __pmvee_state_copies.migration_count; i++)
        __pmvee_state_copies.__pmvee_state_migrations[i](__pmvee_zone, __pmvee_args_size, origin);
    void* return_val = (void*)(__pmvee_zone + *__pmvee_args_size);
    for (int i = 0; i < __pmvee_state_copies.copy_count; i++)
        __pmvee_state_copies.__pmvee_state_copies[i](__pmvee_zone, __pmvee_args_size, origin);

    return return_val;
}

static void (*__pmvee_copy_libc_state_follower) (char*, size_t*) = NULL;
void __pmvee_copy_state_follower(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    if (!__pmvee_copy_libc_state_follower)
    {
        __asm("syscall;"
                : "=a" (__pmvee_copy_libc_state_follower)
                : "a" (__NR_pmvee_switch), "D" (PMVEE_LIBC_REQUEST)
                : "rcx", "r8", "r9", "r10", "r11");
    }
    if (__pmvee_state_copies.copy_count == (int)-1)
    {
        __asm("syscall;"
                :
                : "a" (__NR_pmvee_switch), "D" (PMVEE_HANDLER_REQUEST), "S" (&__pmvee_state_copies)
                : "rcx", "r8", "r9", "r10", "r11");
    }

    __pmvee_copy_libc_state_follower(__pmvee_zone, __pmvee_args_size);
    for (int i = 0; i < __pmvee_state_copies.migration_count; i++)
        __pmvee_state_copies.__pmvee_state_migrations[i](__pmvee_zone, __pmvee_args_size, origin);
    for (int i = 0; i < __pmvee_state_copies.copy_count; i++)
        __pmvee_state_copies.__pmvee_state_copies[i](__pmvee_zone, __pmvee_args_size, origin);
}
