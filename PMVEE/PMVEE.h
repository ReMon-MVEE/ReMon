#ifndef PMVEE_H
#define PMVEE_H


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>


// =====================================================================================================================
// Some constants.
#define PMVEE_CONFIG_REMOVE_PERMISSIONS
#define PMVEE_FLAGS_REMOVE_PERMISSIONS  0b01
#define PMVEE_FLAGS_DUP_EXEC            0b10


#define PMVEE_ZONE_DEFAULT_SIZE 0x1000 * 1
// =====================================================================================================================


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
#define PMVEE_EXIT __asm__("syscall;" : : "a" (__NR_pmvee_check ), "D" (-1)         : "rsi", "rdx", "r10");
// =====================================================================================================================


// =====================================================================================================================
// Needed for leader and follower compilation.
#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
static char* pmvee_zone = (char*) 0;
char* get_pmvee_zone();
#endif
// =====================================================================================================================


// =====================================================================================================================
// Defines relating to leader compilation.
#ifdef PMVEE_LEADER

// Leader enter into multi-exec.
#define PMVEE_ENTER(x) __asm__("movl %2, %%r8d; syscall;" : : "a" (__NR_pmvee_switch), "D" (__pmvee_zone), "i" (x): "rsi", "rdx", "r10", "r8");


// For people that might want to quickly manually write void function wrappers with 0-7 arguments.
#define PMVEE_CALL_0ARG(__x, __name)       \
void __pmvee_real##__name();               \
void __name()                              \
{                                          \
    char* __pmvee_zone = get_pmvee_zone(); \
    PMVEE_ENTER(__x);                      \
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
    PMVEE_ENTER(__x);                                 \
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
    PMVEE_ENTER(__x);                                                           \
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
    PMVEE_ENTER(__x);                                                           \
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
    PMVEE_ENTER(__x);                                                           \
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
    PMVEE_ENTER(__x);                                                           \
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
    PMVEE_ENTER(__x);                                                           \
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
    PMVEE_ENTER(__x);                                                             \
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
#define PMVEE_ENTER(x) char* __pmvee_zone; __asm__("movl %3, %%r8d; syscall;" : "=a" (__pmvee_zone) : "a" (__NR_pmvee_switch), "D" (0), "i" (x): "rsi", "rdx", "r10", "r8");


// For people that might want to quickly manually write void function wrappers with 0-7 arguments.
#define PMVEE_CALL_1ARG(__x, __name) \
void __pmvee_real##__name(;          \
void __name()                        \
{                                    \
    PMVEE_ENTER(__x);                \
    __pmvee_real##__name();          \
    PMVEE_EXIT                       \
}                                    \
void __pmvee_real##__name()


#define PMVEE_CALL_1ARG(__x, __name, __type1, __arg1)      \
void __pmvee_real##__name(__type1 __arg1);                 \
void __name(__type1 __arg1)                                \
{                                                          \
    PMVEE_ENTER(__x);                                      \
    __type1 __pmvee_##__arg1 = *(__type1*) (__pmvee_zone); \
    __pmvee_real##__name(__pmvee_##__arg1);                \
    PMVEE_EXIT                                             \
}                                                          \
void __pmvee_real##__name(__type1 __arg1)


#define PMVEE_CALL_2ARGS(__x, __name, __type1, __arg1, __type2, __arg2)                           \
void __pmvee_real##__name(__type1 __arg1, __type2 __arg2);                                        \
void __name(__type1 __arg1, __type2 __arg2)                                                       \
{                                                                                                 \
    PMVEE_ENTER(__x);                                                                             \
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
    PMVEE_ENTER(__x);                                                                             \
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
    PMVEE_ENTER(__x);                                                                             \
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
    PMVEE_ENTER(__x);                                                                             \
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
    PMVEE_ENTER(__x);                                                                             \
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
    PMVEE_ENTER(__x);                                                                             \
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
