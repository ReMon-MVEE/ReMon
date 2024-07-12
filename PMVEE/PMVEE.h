#ifndef PMVEE_H
#define PMVEE_H



// =====================================================================================================================
// Some constants.
#define PMVEE_CONFIG_REMOVE_PERMISSIONS
#define PMVEE_FLAGS_REMOVE_PERMISSIONS  0b01
#define PMVEE_FLAGS_DUP_EXEC            0b10
#define PMVEE_REGION_REQUEST            0x001
#define PMVEE_LIBC_REQUEST              0x002
#define PMVEE_LIBC_SET                  0x004
#define PMVEE_HANDLER_REQUEST           0x008
#define PMVEE_PRINT_BACKTRACE           0x010
#define PMVEE_DIFF_MEMORY               0x020
#define PMVEE_COMMUNICATION_REQUEST     0x040
#define PMVEE_MIGRATION_INFO_REQUEST    0x080
#define PMVEE_MAPPINGS_REQUEST          0x100
#define PMVEE_ZONE_REQUEST              0x200

#define PMVEE_SCANNINGG_START           0x6969696969696969l

#define PMVEE_COPY_COUNT                64

#define MAP_PMVEE 0x2000000

#define PMVEE_ZONE_ONE_DEFAULT_SIZE 0xe0000000l
#define PMVEE_ZONE_TWO_DEFAULT_SIZE 0xe0000000l
#define PMVEE_COPY_DEFAULT_SIZE     0x4000 * 8
#define PMVEE_DICT_DEFAULT_SIZE     0x4000 * 8

#define PMVEE_COMMUNICATION_SIZE    PMVEE_COPY_DEFAULT_SIZE
#define PMVEE_SIMPLE_MAPPINGS_SIZE  PMVEE_COPY_DEFAULT_SIZE
#define PMVEE_ZONE_DEFAULT_SIZE     PMVEE_COPY_DEFAULT_SIZE


#ifdef IPMON_PMVEE_HANDLING
#define IS_MULTI_EXEC           (multi_exec->multi)
#define PARENT_MULTI_EXEC       (parent_monitor->multi_exec->multi)
#define SET_MULTI_EXEC(__multi) (multi_exec->multi = __multi)
#else
#define IS_MULTI_EXEC           (multi_exec)
#define PARENT_MULTI_EXEC       (parent_monitor->multi_exec)
#define SET_MULTI_EXEC(__multi) (multi_exec = __multi)
#endif
// =====================================================================================================================


struct pmvee_mappings_info_t
{
    char* start;
    char* end;
    unsigned long prot;
};
#ifndef __cplusplus
struct pmvee_mappings_t
{
    unsigned long mapping_count;
    struct pmvee_mappings_info_t mappings[];
};
#endif

// =====================================================================================================================
// Define these if they aren't yet, just in case people compile this on machines that do not have the kernel patch.
#ifndef __NR_pmvee_switch
#define __NR_pmvee_switch 509
#endif
#ifndef __NR_pmvee_check
#define __NR_pmvee_check 510
#endif
// =====================================================================================================================


// =====================================================================================================================
// This one can be generally defined, as it is basically "single-variant enter".
#define PMVEE_EXIT __asm__("mov %%rsp, %%rdi; syscall;" : : "a" (__NR_pmvee_check ) : "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory", "cc" );
// =====================================================================================================================

struct __pmvee_state_copies_t
{
    int migration_count;
    void (*__pmvee_state_migrations[PMVEE_COPY_COUNT]) (char*, size_t*, void*);
    int copy_count;
    void (*__pmvee_state_copies[PMVEE_COPY_COUNT]) (char*, size_t*, void*);
};

// =====================================================================================================================
// Needed for leader and follower compilation.
#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#ifdef PMVEE_LIBC_COPY
static void (*__pmvee_copy_libc_state_leader) (char*, size_t*);
static void (*__pmvee_copy_libc_state_follower) (char*, size_t*);
#endif


#ifdef PMVEE_COPY_STATE
static struct __pmvee_state_copies_t __pmvee_state_copies;
struct pmvee_migration_info_t
{
    unsigned long migration_count;
    unsigned long pointer_count;
    unsigned long info[];
};
static struct pmvee_migration_info_t* __pmvee_migration_info;
static struct pmvee_mappings_t* simple_mappings;
#endif

struct __pmvee_FILE_copy_t
{
    /* The following pointers correspond to the C++ streambuf protocol. */
    char *_IO_read_ptr;	/* Current read pointer */
    char *_IO_read_end;	/* End of get area. */
    char *_IO_read_base;	/* Start of putback+get area. */
    char *_IO_write_base;	/* Start of put area. */
    char *_IO_write_ptr;	/* Current put pointer. */
    char *_IO_write_end;	/* End of put area. */
    char *_IO_buf_base;	/* Start of reserve area. */
    char *_IO_buf_end;	/* End of reserve area. */

    /* The following fields are used to support backing up and undo. */
    char *_IO_save_base; /* Pointer to start of non-current get area. */
    char *_IO_backup_base;  /* Pointer to first valid character of backup area */
    char *_IO_save_end; /* Pointer to end of non-current get area. */
};

void __pmvee_register_state_copy(void (*)(char*, size_t*, void*));
void* __pmvee_copy_state_leader(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin);
void __pmvee_copy_state_follower(char* __pmvee_zone, size_t* __pmvee_args_size, void* origin);


#ifdef PMVEE_LEADER


#define PMVEE_STATE_COPY_NULL                        \
*(void**)(__pmvee_zone + *__pmvee_args_size) = NULL; \
*__pmvee_args_size+=sizeof(void*); // printf(">%ld", sizeof(void*));fflush(stdout);

#define PMVEE_STATE_COPY_POINTER(__pointer)                      \
*(void**)(__pmvee_zone + *__pmvee_args_size) = (void*)__pointer; \
*__pmvee_args_size+=sizeof(void*); // printf(">%ld", sizeof(void*));fflush(stdout);

#define PMVEE_STATE_COPY_POINTER_POINTER(__pointer)                \
*(void**)(__pmvee_zone + *__pmvee_args_size) = (void*)__pointer;   \
*__pmvee_args_size+=sizeof(void*);                                 \
/* printf(">1-%ld", sizeof(void*));fflush(stdout); */              \
*(void**)(__pmvee_zone + *__pmvee_args_size) = *(void**)__pointer; \
*__pmvee_args_size+=sizeof(void*); // printf(">2-%ld", sizeof(void*));fflush(stdout);

#define PMVEE_STATE_COPY_STRUCT(__data, __struct)         \
*(__struct*)(__pmvee_zone + *__pmvee_args_size) = __data; \
*__pmvee_args_size+=sizeof(__struct); // printf(">%ld", sizeof(__struct));fflush(stdout);

#define PMVEE_STATE_COPY_REGION(__data, __size)                     \
memcpy((void*)(__pmvee_zone + *__pmvee_args_size), __data, __size); \
*__pmvee_args_size+=__size; // printf(">%ld", __size);fflush(stdout);

#define PMVEE_STATE_COPY_POINTER_OFFSET(__data_from, __data_to, __type_cast)                                     \
*(size_t*)(__pmvee_zone + *__pmvee_args_size) = (size_t)((unsigned long)__data_to - (unsigned long)__data_from); \
*__pmvee_args_size+=sizeof(size_t); // printf(">%ld", sizeof(size_t));fflush(stdout);


#endif

#ifdef PMVEE_FOLLOWER


#define PMVEE_STATE_COPY_NULL \
*__pmvee_args_size+=sizeof(void*);

#define PMVEE_STATE_COPY_POINTER(__pointer)                      \
__pointer = *(void**)(__pmvee_zone + *__pmvee_args_size);        \
*__pmvee_args_size+=sizeof(void*);

#define PMVEE_STATE_COPY_POINTER_POINTER                                     \
{                                                                            \
    void* __temp__pointer = *(void**)(__pmvee_zone + *__pmvee_args_size);    \
    *__pmvee_args_size+=sizeof(void*);                                       \
    *(void**)__temp__pointer = *(void**)(__pmvee_zone + *__pmvee_args_size); \
    *__pmvee_args_size+=sizeof(void*);                                       \
}

#define PMVEE_STATE_COPY_STRUCT(__data, __struct)         \
__data = *(__struct*)(__pmvee_zone + *__pmvee_args_size); \
*__pmvee_args_size+=sizeof(__struct);

#define PMVEE_STATE_COPY_REGION(__data, __size)                     \
memcpy(__data, (void*)(__pmvee_zone + *__pmvee_args_size), __size); \
*__pmvee_args_size+=__size;

#define PMVEE_STATE_COPY_POINTER_OFFSET(__data_from, __data_to, __type_cast)            \
__data_to = (__type_cast) (((unsigned long)__data_from) + *(size_t*)(__pmvee_zone + *__pmvee_args_size)) ; \
*__pmvee_args_size+=sizeof(size_t);
#endif


#endif
// =====================================================================================================================


// =====================================================================================================================
// Defines relating to leader compilation.
#ifdef PMVEE_LEADER
struct __pmvee_dict_s
{
    struct __pmvee_dict_s* prev;
    void* from;
    void* to;
    struct __pmvee_dict_s* next;
};
typedef struct __pmvee_dict_s __pmvee_dict_t;
extern __pmvee_dict_t* pmvee_dict;
extern __pmvee_dict_t* pmvee_dict_head;
extern __pmvee_dict_t* pmvee_dict_tail;
extern int lookup_pointer(void* original, void** new, unsigned long size);
extern void clear_pointer_lookup();

extern char* get_pmvee_copy();
extern void __pmvee_copy_all(size_t size);

// Leader enter into multi-exec.
#define PMVEE_GET_ZONE "D" (__pmvee_zone)
#define PMVEE_VOID_ZONE "D" ((unsigned long)-1)
#define PMVEE_ENTER(x, y, __full_start, __start, __end)    \
__asm (                                                    \
    "movq %[end], %%r10; leaq (%%rip), %%r9; add $12, %%r9; movl %[index], %%r8d; syscall;" : \
    :                                                      \
    "a" (__NR_pmvee_switch),                               \
    y ,                                                    \
    [index] "i" ( x ),                                     \
    "S" ((unsigned long) __full_start),                    \
    "d" ((unsigned long) __start),                         \
    [end] "R" ((unsigned long) __end) :                    \
    "rcx", "r8", "r9", "r10", "r11", "memory", "cc");


// For people that might want to quickly manually write void function wrappers with 0-7 arguments.
#define PMVEE_CALL_0ARG(__x, __name)       \
void __pmvee_real##__name();               \
void __name()                              \
{                                          \
    PMVEE_ENTER(__x, PMVEE_VOID_ZONE);     \
    __pmvee_real##__name();                \
    PMVEE_EXIT                             \
}                                          \
void __pmvee_real##__name()


#define PMVEE_CALL_1ARG(__x, __name, __type1, __arg1) \
void __pmvee_real##__name(__type1 __arg1);            \
void __name(__type1 __arg1)                           \
{                                                     \
    char* __pmvee_zone = get_pmvee_zone();            \
    *(__type1*) (__pmvee_zone) = __arg1;              \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);        \
    __pmvee_real##__name(__arg1);                     \
    PMVEE_EXIT                                        \
}                                                     \
void __pmvee_real##__name(__type1 __arg1)


#define PMVEE_CALL_2ARGS(__x, __name, __type1, __arg1, __type2, __arg2)         \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2);                      \
void __name(__type1 __arg1, __type2 __arg2)                                     \
{                                                                               \
    char* __pmvee_zone = get_pmvee_zone();                                      \
    size_t __pmvee_args_size = 0;                                               \
    *(__type1*) (__pmvee_zone)                                        = __arg1; \
    *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))) = __arg2; \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);                                  \
    __pmvee_real##__name(__arg1, __arg2);                                       \
    PMVEE_EXIT                                                                  \
}                                                                               \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2)


#define PMVEE_CALL_3ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3) \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3);      \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3)                     \
{                                                                               \
    char* __pmvee_zone = get_pmvee_zone();                                      \
    size_t __pmvee_args_size = 0;                                               \
    *(__type1*) (__pmvee_zone)                                        = __arg1; \
    *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))) = __arg2; \
    *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))) = __arg3; \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);                                  \
    __pmvee_real##__name(__arg1, __arg2, __arg3);                               \
    PMVEE_EXIT                                                                  \
}                                                                               \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3)


#define PMVEE_CALL_4ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4) \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3,       \
        __type4 __arg4);                                                        \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4)     \
{                                                                               \
    char* __pmvee_zone = get_pmvee_zone();                                      \
    size_t __pmvee_args_size = 0;                                               \
    *(__type1*) (__pmvee_zone)                                        = __arg1; \
    *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))) = __arg2; \
    *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))) = __arg3; \
    *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))) = __arg4; \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);                                  \
    __pmvee_real##__name(__arg1, __arg2, __arg3, __arg4);                       \
    PMVEE_EXIT                                                                  \
}                                                                               \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4)


#define PMVEE_CALL_5ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4, __type5, __arg5)  \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3,       \
        __type4 __arg4, __type5 __arg5);                                        \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,     \
        __type5 __arg5)                                                         \
{                                                                               \
    char* __pmvee_zone = get_pmvee_zone();                                      \
    size_t __pmvee_args_size = 0;                                               \
    *(__type1*) (__pmvee_zone)                                       =  __arg1; \
    *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))) = __arg2; \
    *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))) = __arg3; \
    *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))) = __arg4; \
    *(__type5*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type4))) = __arg5; \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);                                  \
    __pmvee_real##__name(__arg1, __arg2, __arg3, __arg4, __arg5);               \
    PMVEE_EXIT                                                                  \
}                                                                               \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4, __type5 __arg5)


#define PMVEE_CALL_6ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4, __type5, __arg5, __type6, __arg6)  \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3,       \
        __type4 __arg4, __type5 __arg5, __type6 __arg6);                        \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,     \
        __type5 __arg5, __type6 __arg6)                                         \
{                                                                               \
    char* __pmvee_zone = get_pmvee_zone();                                      \
    size_t __pmvee_args_size = 0;                                               \
    *(__type1*) (__pmvee_zone)                                        = __arg1; \
    *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))) = __arg2; \
    *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))) = __arg3; \
    *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))) = __arg4; \
    *(__type5*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type4))) = __arg5; \
    *(__type6*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type5))) = __arg6; \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);                                  \
    __pmvee_real##__name(__arg1, __arg2, __arg3, __arg4, __arg5, __arg6);       \
    PMVEE_EXIT                                                                  \
}                                                                               \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3,       \
        __type4 __arg4, __type5 __arg5, __type6 __arg6)


#define PMVEE_CALL_7ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4, __type5, __arg5, __type6, __arg6, __type7, __arg7)  \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3,         \
        __type4 __arg4, __type5 __arg5, __type6 __arg6, __type7 __arg7);          \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,       \
        __type5 __arg5, __type6 __arg6, __type7 __arg7)                           \
{                                                                                 \
    char* __pmvee_zone = get_pmvee_zone();                                        \
    size_t __pmvee_args_size = 0;                                                 \
    *(__type1*) (__pmvee_zone)                                        = __arg1;   \
    *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))) = __arg2;   \
    *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))) = __arg3;   \
    *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))) = __arg4;   \
    *(__type5*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type4))) = __arg5;   \
    *(__type6*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type5))) = __arg6;   \
    *(__type7*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type6))) = __arg7;   \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE, 0, 0, 0);                                    \
    __pmvee_real##__name(__arg1, __arg2, __arg3, __arg4, __arg5, __arg6, __arg7); \
    PMVEE_EXIT                                                                    \
}                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3,         \
        __type4 __arg4, __type5 __arg5, __type6 __arg6, __type7 __arg7)
#endif
// =====================================================================================================================


// =====================================================================================================================
// Defines relating to follower compilation.
#ifdef PMVEE_FOLLOWER


// Follower enter into multi-exec.
#define PMVEE_GET_ZONE "=a" (__pmvee_zone), "=D" (__pmvee_args_size)
#define PMVEE_VOID_ZONE
#define PMVEE_ENTER(x, y)                      \
char* __pmvee_zone = (char*)0;                 \
__asm__(                                       \
    "movl %[index], %%r8d; syscall;"           \
    : y                                        \
    : "a" (__NR_pmvee_switch), "D" (-1), [index] "i" (x) \
    : "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory", "cc");


// For people that might want to quickly manually write void function wrappers with 0-7 arguments.
#define PMVEE_CALL_0ARG(__x, __name)            \
void __pmvee_real##__name(;                     \
void __name()                                   \
{                                               \
    PMVEE_ENTER(__x, PMVEE_VOID_ZONE);          \
    __pmvee_real##__name();                     \
    PMVEE_EXIT                                  \
}                                               \
void __pmvee_real##__name()


#define PMVEE_CALL_1ARG(__x, __name, __type1, __arg1)      \
void __pmvee_real##__name(__type1 __arg1);                 \
void __name(__type1 __arg1)                                \
{                                                          \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                      \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone); \
    __pmvee_real##__name(__pmvee_##__arg1);                \
    PMVEE_EXIT                                             \
}                                                          \
void __pmvee_real##__name(__type1 __arg1)


#define PMVEE_CALL_2ARGS(__x, __name, __type1, __arg1, __type2, __arg2)                           \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2);                                        \
void __name(__type1 __arg1, __type2 __arg2)                                                       \
{                                                                                                 \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                                                             \
    size_t __pmvee_args_size = 0;                                                                 \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone);                                        \
    __type2 __pmvee_##__arg2 = *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))); \
    __pmvee_real##__name(__pmvee_##__arg1, __pmvee_##__arg2);                                     \
    PMVEE_EXIT                                                                                    \
}                                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2)


#define PMVEE_CALL_3ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3)          \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3);                        \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3)                                       \
{                                                                                                 \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                                                             \
    size_t __pmvee_args_size = 0;                                                                 \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone);                                        \
    __type2 __pmvee_##__arg2 = *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))); \
    __type3 __pmvee_##__arg3 = *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))); \
    __pmvee_real##__name(__pmvee_##__arg1, __pmvee_##__arg2, __pmvee_##__arg3);                   \
    PMVEE_EXIT                                                                                    \
}                                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3)


#define PMVEE_CALL_4ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4) \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4);        \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4)                       \
{                                                                                                 \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                                                             \
    size_t __pmvee_args_size = 0;                                                                 \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone);                                        \
    __type2 __pmvee_##__arg2 = *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))); \
    __type3 __pmvee_##__arg3 = *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))); \
    __type4 __pmvee_##__arg4 = *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))); \
    __pmvee_real##__name(__pmvee_##__arg1, __pmvee_##__arg2, __pmvee_##__arg3, __pmvee_##__arg4); \
    PMVEE_EXIT                                                                                    \
}                                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4)


#define PMVEE_CALL_5ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4, __type5, __arg5) \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,         \
        __type5 __arg5);                                                                          \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4, __type5 __arg5)       \
{                                                                                                 \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                                                             \
    size_t __pmvee_args_size = 0;                                                                 \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone);                                        \
    __type2 __pmvee_##__arg2 = *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))); \
    __type3 __pmvee_##__arg3 = *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))); \
    __type4 __pmvee_##__arg4 = *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))); \
    __type5 __pmvee_##__arg5 = *(__type5*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type4))); \
    __pmvee_real##__name(__pmvee_##__arg1, __pmvee_##__arg2, __pmvee_##__arg3, __pmvee_##__arg4,  \
            __pmvee_##__arg5);                                                                    \
    PMVEE_EXIT                                                                                    \
}                                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4, __type5 __arg5)


#define PMVEE_CALL_6ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4, __type5, __arg5, __type6, __arg6) \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,         \
        __type5 __arg5, __type6 __arg6);                                                          \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4, __type5 __arg5,       \
        __type6 __arg6)                                                                           \
{                                                                                                 \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                                                             \
    size_t __pmvee_args_size = 0;                                                                 \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone);                                        \
    __type2 __pmvee_##__arg2 = *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))); \
    __type3 __pmvee_##__arg3 = *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))); \
    __type4 __pmvee_##__arg4 = *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))); \
    __type5 __pmvee_##__arg5 = *(__type5*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type4))); \
    __type6 __pmvee_##__arg6 = *(__type6*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type5))); \
    __pmvee_real##__name(__pmvee_##__arg1, __pmvee_##__arg2, __pmvee_##__arg3, __pmvee_##__arg4,  \
            __pmvee_##__arg5, __pmvee_##__arg6);                                                  \
    PMVEE_EXIT                                                                                    \
}                                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,         \
        __type5 __arg5, __type6 __arg6)


#define PMVEE_CALL_7ARGS(__x, __name, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4, __type5, __arg5, __type6, __arg6, __type7, __arg7)  \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,         \
        __type5 __arg5, __type6 __arg6, __type7 __arg7);                                          \
void __name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4, __type5 __arg5,       \
        __type6 __arg6, __type7 __arg7)                                                           \
{                                                                                                 \
    PMVEE_ENTER(__x, PMVEE_GET_ZONE);                                                             \
    size_t __pmvee_args_size = 0;                                                                 \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone);                                        \
    __type2 __pmvee_##__arg2 = *(__type2*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type1))); \
    __type3 __pmvee_##__arg3 = *(__type3*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type2))); \
    __type4 __pmvee_##__arg4 = *(__type4*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type3))); \
    __type5 __pmvee_##__arg5 = *(__type5*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type4))); \
    __type6 __pmvee_##__arg6 = *(__type6*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type5))); \
    __type7 __pmvee_##__arg7 = *(__type7*) (__pmvee_zone + (__pmvee_args_size+=sizeof(__type6))); \
    __pmvee_real##__name(__pmvee_##__arg1, __pmvee_##__arg2, __pmvee_##__arg3, __pmvee_##__arg4,  \
            __pmvee_##__arg5, __pmvee_##__arg6, __pmvee_##__arg7);                                \
    PMVEE_EXIT                                                                                    \
}                                                                                                 \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2, __type3 __arg3, __type4 __arg4,         \
        __type5 __arg5, __type6 __arg6, __type7 __arg7)
#endif
// =====================================================================================================================


#endif
