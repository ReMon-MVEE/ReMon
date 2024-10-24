#define _GNU_SOURCE
#include <dlfcn.h>

#ifdef PMVEE_LEADER
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "PMVEE.h"
#include <string.h>


static char* __pmvee_base = (char*) 0;
static char* __pmvee_zone_base = (char*) 0;
static unsigned long __pmvee_copy_size = 0;
static char* __pmvee_communication = (char*) 0;

#define debugf(...) ; // printf(__VA_ARGS__);fflush(stdout);

char* get_pmvee_copy()
{
    if (!__pmvee_base)
        __pmvee_base = (char*)syscall(__NR_pmvee_switch, PMVEE_REGION_REQUEST);

    if (!__pmvee_communication)
        __pmvee_communication = (char*) syscall(__NR_pmvee_switch, PMVEE_COMMUNICATION_REQUEST, 0, 0);
    if (__pmvee_communication == MAP_FAILED)
        sleep(120);

    return __pmvee_communication;
}


#if 0
void __pmvee_copy_all(size_t size)
{
    memcpy(__pmvee_zone_base, __pmvee_communication, size);
}
#endif


__pmvee_dict_t* pmvee_dict      = (__pmvee_dict_t*) 0;
__pmvee_dict_t* pmvee_dict_head = (__pmvee_dict_t*) 0;
__pmvee_dict_t* pmvee_dict_tail = (__pmvee_dict_t*) 0;

int lookup_pointer(void* original, void** new, unsigned long size)
{
    debugf(" > [ %p ; %p )\n", __pmvee_base, __pmvee_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE);
    if ((char*)original >= __pmvee_base && original <= (void*)((unsigned long)__pmvee_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE))
    {
        debugf(" > returning %p\n", original);
        *new = original;
        return 0;
    }

    if (!pmvee_dict)
    {
        pmvee_dict = (__pmvee_dict_t*)syscall(__NR_pmvee_switch, PMVEE_DICT_REQUEST); // mmap((void*)12, PMVEE_DICT_DEFAULT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

    if (!__pmvee_zone_base)
    {
        __pmvee_zone_base = (char*)syscall(__NR_pmvee_switch, PMVEE_ZONE_REQUEST);
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

    *new = ((char*)__pmvee_zone_base) + __pmvee_copy_size;
    __pmvee_copy_size += size;

    pmvee_dict_tail    =  pmvee_dict_i->next;
    pmvee_dict_i->from =  original;
    pmvee_dict_i->to   = *new;
    debugf(" > added %p -> %p!\n", original, *new);
    return 1;
}

char* add_to_zone(int size)
{
    if (!__pmvee_zone_base)
    {
        __pmvee_zone_base = (char*)syscall(__NR_pmvee_switch, PMVEE_ZONE_REQUEST);
    }
    char* new = ((char*)__pmvee_zone_base) + __pmvee_copy_size;
    __pmvee_copy_size += size;
    return new;
}

void clear_pointer_lookup()
{
    if (!pmvee_dict)
        return;

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
    __pmvee_copy_size = 0;
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
static struct pmvee_migration_info_t* __pmvee_migration_info = 0;
static struct pmvee_mappings_t* simple_mappings = 0;


static void __attribute__ ((noinline)) __pmvee_migrate_data_leader(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    unsigned long migration_index = 0;
    for (int i = 0; i < __pmvee_migration_info->migration_count; i++)
    {
        void* source = (void*)__pmvee_migration_info->info[migration_index++];
        unsigned long size = __pmvee_migration_info->info[migration_index++];
        // *(char**)(__pmvee_zone + *__pmvee_args_size) = add_to_zone(size);
        // memcpy(*(char**)(__pmvee_zone + *__pmvee_args_size), (char*)source, size);
        // *__pmvee_args_size+=sizeof(char*);
        memcpy((__pmvee_zone + *__pmvee_args_size), source, size);
        *__pmvee_args_size+=size;
        // printf(" > value: %ld\n", size);fflush(stdout);
    }
}

static void __attribute__((noinline)) __pmvee_migrate_pointers_leader(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    unsigned long pointer_index = 2 * __pmvee_migration_info->migration_count;
    for (int i = 0; i < __pmvee_migration_info->pointer_count; i++)
    {
        void** source = (void**)(__pmvee_migration_info->info[pointer_index++]);
        *(void**)(__pmvee_zone + *__pmvee_args_size) = *source;
        *__pmvee_args_size+=sizeof(void*);
        // printf(" > pointer\n");fflush(stdout);
    }
}

static void __attribute__((noinline)) __pmvee_migrate_pointers_scan_leader(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    int mapping_start_i = 0;
    *(unsigned long*)(__pmvee_zone + *__pmvee_args_size) = PMVEE_SCANNINGG_START;
    *__pmvee_args_size+=sizeof(unsigned long);

    while (mapping_start_i < simple_mappings->mapping_count && simple_mappings->mappings[mapping_start_i].end <= __pmvee_base)
    {
        mapping_start_i++;
    }

    for (int mapping_i = mapping_start_i; mapping_i < simple_mappings->mapping_count; mapping_i++)
    {
        if (simple_mappings->mappings[mapping_i].start >= (__pmvee_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE))
            break;
        if (!(simple_mappings->mappings[mapping_i].prot & PROT_WRITE))
            continue;

        for (unsigned long* mapping_pt = (unsigned long*)simple_mappings->mappings[mapping_i].start;
                mapping_pt < (unsigned long*)simple_mappings->mappings[mapping_i].end; mapping_pt++)
        {
            if ((*mapping_pt) >= (unsigned long)__pmvee_base && (*mapping_pt) < (unsigned long)(__pmvee_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE))
                continue;
            for (int check_i = 0; check_i < simple_mappings->mapping_count; check_i++)
            {
                if ((unsigned long) simple_mappings->mappings[check_i].start <= (*mapping_pt) &&
                        (unsigned long) simple_mappings->mappings[check_i].end > (*mapping_pt))
                {
                    void* to_write = (void*)mapping_pt;
                    // __asm("movq %%rbx, %%r8; addq %%rcx, %%r8; movq %%rax, (%%r8);" :: "a" (to_write), "b" (__pmvee_zone), "c" (*__pmvee_args_size) : "r8");
                    *(void**)(__pmvee_zone + *__pmvee_args_size) = to_write;
                    *__pmvee_args_size+=sizeof(void*);
                    to_write = (void*)*mapping_pt;
                    *(void**)(__pmvee_zone + *__pmvee_args_size) = to_write;
                    *__pmvee_args_size+=sizeof(void*);
                    // printf(" > pointer target\n");fflush(stdout);
                    // printf(" > pointer\n");fflush(stdout);
                }
            }
        }
    }
    *(void**)(__pmvee_zone + *__pmvee_args_size) = (void*)0;
    *__pmvee_args_size+=sizeof(void*);
}

static void (*__pmvee_copy_libc_state_leader_stub) (char*, size_t*) = NULL;
void* __attribute__ ((noinline)) __pmvee_copy_state_leader(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    if (!__pmvee_base)
        __pmvee_base = (char*)syscall(__NR_pmvee_switch, PMVEE_REGION_REQUEST);
    if (!__pmvee_copy_libc_state_leader_stub)
    {
        __asm("syscall;"
                : "=a" (__pmvee_copy_libc_state_leader_stub)
                : "a" (__NR_pmvee_switch), "D" (PMVEE_LIBC_REQUEST)
                : "rsi", "rcx", "r8", "r9", "r10", "r11", "r12", "memory", "cc");
    }
    if (__pmvee_state_copies.copy_count == (int)-1)
    {
        __asm("syscall;"
                :
                : "a" (__NR_pmvee_switch), "D" (PMVEE_HANDLER_REQUEST), "S" (&__pmvee_state_copies)
                : "rcx", "r8", "r9", "r10", "r11", "r12", "memory", "cc");
    }

    if (!__pmvee_migration_info)
        __pmvee_migration_info = (struct pmvee_migration_info_t*) syscall(__NR_pmvee_switch, PMVEE_MIGRATION_INFO_REQUEST, 0, 0);

    if (!simple_mappings)
        simple_mappings = (struct pmvee_mappings_t*) syscall(__NR_pmvee_switch, PMVEE_MAPPINGS_REQUEST, 0, 0);

    __pmvee_copy_libc_state_leader_stub(__pmvee_zone, __pmvee_args_size);
    __pmvee_migrate_data_leader(__pmvee_zone, __pmvee_args_size, origin);
    for (int i = 0; i < __pmvee_state_copies.migration_count; i++)
        __pmvee_state_copies.__pmvee_state_migrations[i](__pmvee_zone, __pmvee_args_size, origin);
    void* return_val = (void*)(__pmvee_zone + *__pmvee_args_size);
    // printf(" > pointers\n");fflush(stdout);
    __pmvee_migrate_pointers_leader(__pmvee_zone, __pmvee_args_size, origin);
    #ifdef PMVEE_HEAP_SCANNING
    __pmvee_migrate_pointers_scan_leader(__pmvee_zone, __pmvee_args_size, origin);
    #endif
    for (int i = 0; i < __pmvee_state_copies.copy_count; i++)
        __pmvee_state_copies.__pmvee_state_copies[i](__pmvee_zone, __pmvee_args_size, origin);

    // printf(" > done\n\n");fflush(stdout);
    // __pmvee_copy_size = 0;
    return return_val;
}


static void __pmvee_migrate_data_follower(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    unsigned long migration_index = 0;
    for (int i = 0; i < __pmvee_migration_info->migration_count; i++)
    {
        void* destination = (void*)__pmvee_migration_info->info[migration_index++];
        unsigned long size = __pmvee_migration_info->info[migration_index++];
        // memcpy((char*)destination, *(char**)(__pmvee_zone + *__pmvee_args_size), size);
        // *__pmvee_args_size+=sizeof(char*);
        memcpy(destination, (__pmvee_zone + *__pmvee_args_size), size);
        *__pmvee_args_size+=size;
    }
}

static void __attribute__ ((noinline)) __pmvee_migrate_pointers_follower(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    unsigned long pointer_index = 2 * __pmvee_migration_info->migration_count;
    for (int i = 0; i < __pmvee_migration_info->pointer_count; i++)
    {
        *(void**)(__pmvee_migration_info->info[pointer_index++]) = *(void**)(__pmvee_zone  + *__pmvee_args_size);
        *__pmvee_args_size+=sizeof(void*);
    }
}

static void __attribute__((noinline)) __pmvee_migrate_pointers_scan_follower(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    if ((*(unsigned long*)(__pmvee_zone + *__pmvee_args_size)) == PMVEE_SCANNINGG_START)
    {
        *__pmvee_args_size+=sizeof(unsigned long);
        while (*(void**)(__pmvee_zone + *__pmvee_args_size))
        {
            void** destination = *(void**)(__pmvee_zone + *__pmvee_args_size);
            *__pmvee_args_size+=sizeof(void*);
            *destination = *(void**)(__pmvee_zone + *__pmvee_args_size);
            *__pmvee_args_size+=sizeof(void*);
        }
        *__pmvee_args_size+=sizeof(void*);
    }
}

static void (*__pmvee_copy_libc_state_follower_stub) (char*, size_t*) = NULL;
void __attribute__ ((noinline)) __pmvee_copy_state_follower(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin)
{
    if (!__pmvee_copy_libc_state_follower_stub)
    {
        __asm("syscall;"
                : "=a" (__pmvee_copy_libc_state_follower_stub)
                : "a" (__NR_pmvee_switch), "D" (PMVEE_LIBC_REQUEST)
                : "rsi", "rcx", "r8", "r9", "r10", "r11", "r12", "memory", "cc");
    }
    if (__pmvee_state_copies.copy_count == (int)-1)
    {
        __asm("syscall;"
                :
                : "a" (__NR_pmvee_switch), "D" (PMVEE_HANDLER_REQUEST), "S" (&__pmvee_state_copies)
                : "rcx", "r8", "r9", "r10", "r11", "r12", "memory", "cc");
    }

    if (!__pmvee_migration_info)
    {
        __asm("syscall;"
                : "=a" (__pmvee_migration_info)
                : "a" (__NR_pmvee_switch), "D" (PMVEE_MIGRATION_INFO_REQUEST)
                : "rsi", "rcx", "r8", "r9", "r10", "r11", "r12", "memory", "cc");
    }
    
    // if (!__pmvee_zone_base)
    // {
    //     __pmvee_zone_base = (char*)syscall(__NR_pmvee_switch, PMVEE_ZONE_REQUEST);
    // }

    __pmvee_copy_libc_state_follower_stub(__pmvee_zone, __pmvee_args_size);
    __pmvee_migrate_data_follower(__pmvee_zone, __pmvee_args_size, origin);
    for (int i = 0; i < __pmvee_state_copies.migration_count; i++)
        __pmvee_state_copies.__pmvee_state_migrations[i](__pmvee_zone, __pmvee_args_size, origin);
    __pmvee_migrate_pointers_follower(__pmvee_zone, __pmvee_args_size, origin);
    #ifdef PMVEE_HEAP_SCANNING
    __pmvee_migrate_pointers_scan_follower(__pmvee_zone, __pmvee_args_size, origin);
    #endif
    for (int i = 0; i < __pmvee_state_copies.copy_count; i++)
        __pmvee_state_copies.__pmvee_state_copies[i](__pmvee_zone, __pmvee_args_size, origin);
        
    // __pmvee_copy_size = 0;
}

#ifdef PMVEE_PRELOAD
void* (*real_malloc) (size_t) = NULL;
void* (*real_realloc) (void *, size_t) = NULL;
void (*real_free) (void*) = NULL;

void* mmapped = NULL;
size_t mmapped_size = 0;

static void* temp_malloc(size_t size)
{
    mmapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mmapped;
}

static void* temp_realloc(void* ptr, size_t size)
{
    _exit(12);
    return (void*)0x00;
}

static void temp_free(void* ptr)
{
    if (ptr != mmapped)
        _exit(1);
    munmap(mmapped, mmapped_size);
}

void* malloc(size_t size)
{
    if (!real_malloc)
    {
        real_malloc = &temp_malloc;
        real_realloc = &temp_realloc;
        real_free = &temp_free;
        void* real_malloc_temp = dlsym(RTLD_NEXT, "malloc");
        void* real_realloc_temp = dlsym(RTLD_NEXT, "__libc_realloc");
        void* real_free_temp = dlsym(RTLD_NEXT, "free");
        real_malloc = real_malloc_temp;
        real_realloc = real_realloc_temp;
        real_free = real_free_temp;
    }
    return real_malloc(size);
}


void free(void* ptr)
{
    if (!real_free)
    {
        if (real_malloc)
            _exit(-1);
        
        real_malloc = &temp_malloc;
        real_realloc = &temp_realloc;
        real_free = &temp_free;
        void* real_malloc_temp = dlsym(RTLD_NEXT, "malloc");
        void* real_realloc_temp = dlsym(RTLD_NEXT, "realloc");
        void* real_free_temp = dlsym(RTLD_NEXT, "free");
        real_malloc = real_malloc_temp;
        real_realloc = real_realloc_temp;
        real_free = real_free_temp;
    }
    if (__pmvee_base)
        debugf("free called on %p, %sin __pmvee_base\n", ptr, (ptr >= (void*)__pmvee_base && ptr < (void*)(__pmvee_base + PMVEE_COPY_DEFAULT_SIZE)) ? "" : "not ");
    if (__pmvee_base && ptr >= (void*)__pmvee_base &&
            (ptr) < (void*)(__pmvee_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE))
    {
        return;
    }
    return;
    real_free(ptr);
}

void* realloc(void *ptr, size_t new_size)
{
    if (!real_realloc)
        _exit(12);

    // printf(" > __pmvee_zone_base: %p", __pmvee_zone_base);fflush(stdout);
    // printf(" > ptr: %p (%s)\n", ptr, __pmvee_zone_base && ptr >= (void*)__pmvee_zone_base &&
    //         (ptr + new_size) < (void*)(__pmvee_zone_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE) ? "true":"false");
    // printf(" > end: %p", __pmvee_zone_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE);fflush(stdout);
    if (__pmvee_base && ptr >= (void*)__pmvee_base &&
            (ptr + new_size) < (void*)(__pmvee_base + PMVEE_ZONE_ONE_DEFAULT_SIZE + PMVEE_ZONE_TWO_DEFAULT_SIZE))
    {
        _exit(42);
        return ptr;
    }
    return real_realloc(ptr, new_size);
}
#endif