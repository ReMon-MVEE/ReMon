/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include "MVEE_interposer_base_shared.h"

/*-----------------------------------------------------------------------------
    Global vars - local
-----------------------------------------------------------------------------*/
static struct mvee_interposer_buffer_info _buffer_info;
static unsigned char                      _buffer_initialized = 0;

//
// We only want to record the result of the OUTER function call
// If we do not use this flag, if the master_variant were to
// call interposed function B from within interposed function A,
// it would record the result of function B and then the result
// of function A. The slave variants are only waiting for the
// result of the outer function though (A in this case)!
// In the event of nested calls, the slave variant's control flow
// would start to divert from the intended control flow!!
//
static __thread int                       outer_func          = 1;

/*-----------------------------------------------------------------------------
    External symbols that should be accessible to the interposers
-----------------------------------------------------------------------------*/
#ifdef __cplusplus
extern "C"
{
#endif
// these are exported by the MVEE (e)glibc
int  mvee_should_sync                      (void);
void mvee_write_lock_result_prepare        (void);
void mvee_write_lock_result_write          (int);
void mvee_write_lock_result_adjust_pos     (void);
void mvee_write_lock_result_finish         (void);
void mvee_read_lock_result_wait            (int*);
void mvee_read_lock_result_wake            (void);
#ifdef __cplusplus
}
#endif

/*-----------------------------------------------------------------------------
    Magic Constants
-----------------------------------------------------------------------------*/
#define SLAVES_DONT_CALL_ORIGINAL_FUNCTION 0
#define SLAVES_CALL_ORIGINAL_FUNCTION      1
#define SLAVES_DONT_CHECK_RESULT           0
#define SLAVES_CHECK_RESULT                1
#define WITHOUT_STACK_LOGGING              0
#define WITH_STACK_LOGGING                 1
#define EXECUTE_WITH_LOCK                  0 // i.e. lock, execute, log, unlock
#define EXECUTE_BEFORE_LOCK                1 // i.e. execute, lock, log, unlock
#define EXECUTE_AFTER_LOCK                 2 // i.e. lock, log, unlock, execute
#define EXECUTE_ATOMIC_PREOP               3 // master: lock, execute, log - slave: wait, execute
#define EXECUTE_ATOMIC_POSTOP              4 // master: unlock - slave: wake

/*-----------------------------------------------------------------------------
    Magic Casting Macros
-----------------------------------------------------------------------------*/
//
// Used to declare the result. Built-in types only. If your interposer uses
// custom types, define the appropriate DECL macros prior to including this header
//
#define DECL_void(type, a)      int a  = 0;
#define DECL_generic(type, a)   type a = 0;
#define DECL_char(type, a)      DECL_generic(type, a)
#define DECL_uchar(type, a)     DECL_generic(type, a)
#define DECL_short(type, a)     DECL_generic(type, a)
#define DECL_ushort(type, a)    DECL_generic(type, a)
#define DECL_int(type, a)       DECL_generic(type, a)
#define DECL_uint(type, a)      DECL_generic(type, a)
#define DECL_longlong(type, a)  DECL_generic(type, a)
#define DECL_ulonglong(type, a) DECL_generic(type, a)

//
// Used to assign the result. As for the DECL macros, if you're using custom
// types, declare the appropriate ASN macro first
//
#define ASN_void(a)
#define ASN_generic(a)          a      =
#define ASN_char(a)             ASN_generic(a)
#define ASN_uchar(a)            ASN_generic(a)
#define ASN_short(a)            ASN_generic(a)
#define ASN_ushort(a)           ASN_generic(a)
#define ASN_int(a)              ASN_generic(a)
#define ASN_uint(a)             ASN_generic(a)
#define ASN_longlong(a)         ASN_generic(a)
#define ASN_ulonglong(a)        ASN_generic(a)

/*-----------------------------------------------------------------------------
    DO_SYNC_CHECK_BUFFER - this is dangerous! The buffer MUST be initialized
    in a single-threaded context to ensure consistency
-----------------------------------------------------------------------------*/
#define DO_SYNC_CHECK_BUFFER(buffer_type, use_eip_buffer, stack_depth) \
                                                                       \
    if (!mvee_interposer_masterthread_id)                              \
        mvee_interposer_thread_init();                                 \
                                                                       \
    if (!_buffer_initialized)                                          \
    {                                                                  \
        _buffer_initialized = 1;                                       \
        mvee_interposer_init_buffer(&_buffer_info, buffer_type,        \
                                    use_eip_buffer, stack_depth);      \
    }

/*-----------------------------------------------------------------------------
    DO_SYNC - constructs an execution ordering wrapper around a function.
    See Wiki/Article/... for details.

    @param resulttype			- return type of the original function. If
    the	return type is void, use the DO_SYNC_VOID macro instead.
    @param orig_func			- pointer to the original function (use
    dlsym(RTLD_NEXT, "orig_func"))
  @param argnames				- names of the arguments to pass to the
    original function, surrounded by parantheses. (e.g.: (mutex, private))
  @param buffer_type			- type of the buffer in which the results
    should be written/read. See MVEE/Inc/MVEE_fake_syscall.h.
  @param slave_should_execute	- if true, the slave variants will also execute
    the original function but the result of the call will be discarded.
    If the wrapped function has no side effects (e.g.: locking functions),
    then this can be safely set to false.
  @param check_slave_result	- if slave_should_execute == true and this is
    also set to true, the wrapper will log a warning if the slave result
    does not match the master result.
  @param exec_type			- when is the original function executed relative
    to the lock, log, unlock sequence
  @param use_eip_buffer		- if set to true, all variants will also log
    a partial callstack for every operation they perform. This partial
    callstack is logged into an "eip queue" associated with the main
    shared queue.
  @param stack_depth			- ignored if use_eip_buffer is false. This is
    the number of callees in every partial callstack.
-----------------------------------------------------------------------------*/
#define DO_SYNC(resulttype, orig_func, orig_func_args,                                 \
                buffer_type, slave_should_execute, check_slave_result,                 \
                exec_type, use_eip_buffer, stack_depth)                                \
                                                                                       \
    int was_outer;                                                                     \
    DECL_ ## resulttype(resulttype, result);                                           \
                                                                                       \
    if (!mvee_should_sync())                                                           \
    {                                                                                  \
        ASN_ ## resulttype(result) orig_func orig_func_args;                           \
        return;                                                                        \
    }                                                                                  \
                                                                                       \
    /* make sure the queue(s) are set up properly first! */                            \
    if (exec_type < EXECUTE_ATOMIC_PREOP)                                              \
    {                                                                                  \
        DO_SYNC_CHECK_BUFFER(buffer_type, use_eip_buffer, stack_depth);                \
    }                                                                                  \
                                                                                       \
    /* See the comment above! */                                                       \
    was_outer  = outer_func;                                                           \
    outer_func = 0;                                                                    \
                                                                                       \
    if (was_outer)                                                                     \
    {                                                                                  \
        /* master variant functionality */                                             \
        if (mvee_interposer_variantnum == 0)                                             \
        {                                                                              \
            /* if we execute during the lock, log, unlock region, we must be */        \
            /* dealing with an atomic function. As such, we should also grab */        \
            /* the libc lock to ensure proper ordering relative to other */            \
            /* locking functions */                                                    \
            if (exec_type == EXECUTE_WITH_LOCK)                                        \
            {                                                                          \
                mvee_write_lock_result_prepare();                                      \
                mvee_interposer_write_lock_acquire(&_buffer_info);                     \
                /* execute the original function and assign the result */              \
                ASN_ ## resulttype(result) orig_func orig_func_args;                   \
                mvee_interposer_write_data(&_buffer_info, sizeof(result), &result);    \
                mvee_interposer_write_lock_release(&_buffer_info);                     \
                mvee_write_lock_result_finish();                                       \
            }                                                                          \
            /* this is the default exec type for most interposers */                   \
            else if (exec_type == EXECUTE_BEFORE_LOCK)                                 \
            {                                                                          \
                ASN_ ## resulttype(result) orig_func orig_func_args;                   \
                mvee_interposer_write_lock_acquire(&_buffer_info);                     \
                mvee_interposer_write_data(&_buffer_info, sizeof(result), &result);    \
                mvee_interposer_write_lock_release(&_buffer_info);                     \
            }                                                                          \
            /* I don't think anyone will ever need this exec type... */                \
            else if (exec_type == EXECUTE_AFTER_LOCK)                                  \
            {                                                                          \
                mvee_interposer_write_lock_acquire(&_buffer_info);                     \
                /* this will write 0 into the buffer */                                \
                mvee_interposer_write_data(&_buffer_info, sizeof(result), &result);    \
                mvee_interposer_write_lock_release(&_buffer_info);                     \
                ASN_ ## resulttype(result) orig_func orig_func_args;                   \
            }                                                                          \
            else if (exec_type == EXECUTE_ATOMIC_PREOP)                                \
            {                                                                          \
                mvee_write_lock_result_prepare();                                      \
                ASN_ ## resulttype(result) orig_func orig_func_args;                   \
                mvee_write_lock_result_write(0);                                       \
            }                                                                          \
            else if (exec_type == EXECUTE_ATOMIC_POSTOP)                               \
            {                                                                          \
                mvee_write_lock_result_adjust_pos();                                   \
                mvee_write_lock_result_finish();                                       \
            }                                                                          \
        }                                                                              \
        else                                                                           \
        {                                                                              \
            /* the slave functionality is much simpler... */                           \
            /* atomic funcs: wait for the 0 to appear in the glibc buffer first */     \
            if (exec_type == EXECUTE_WITH_LOCK                                         \
                || exec_type == EXECUTE_ATOMIC_PREOP)                                  \
                mvee_read_lock_result_wait(NULL);                                      \
                                                                                       \
            /* now wait for the result from our own buffer */                          \
            if (exec_type < EXECUTE_ATOMIC_PREOP)                                      \
                mvee_interposer_read_data(&_buffer_info, sizeof(result), &result);     \
                                                                                       \
            /* optionally, execute the original func from within the slave */          \
            if (slave_should_execute == SLAVES_CALL_ORIGINAL_FUNCTION)                 \
            {                                                                          \
                DECL_ ## resulttype(resulttype, slaveresult);                          \
                ASN_ ## resulttype(result) orig_func orig_func_args;                   \
                                                                                       \
                /* for error checking, check if the result matches the master */       \
                /* result... */                                                        \
                if (check_slave_result == SLAVES_CHECK_RESULT)                         \
                {                                                                      \
                    if (slaveresult != result)                                         \
                        syscall(__NR_gettid, 1337, 10000001, 52, slaveresult, result); \
                }                                                                      \
            }                                                                          \
                                                                                       \
            /* handle queue rollover */                                                \
            if (exec_type < EXECUTE_ATOMIC_PREOP)                                      \
                mvee_interposer_read_wake(&_buffer_info);                              \
                                                                                       \
            if (exec_type == EXECUTE_WITH_LOCK                                         \
                || exec_type == EXECUTE_ATOMIC_POSTOP)                                 \
                mvee_read_lock_result_wake();                                          \
        }                                                                              \
    }                                                                                  \
    else                                                                               \
    {                                                                                  \
        /* if it's an inner function, the result does not need to be recorded */       \
        if (mvee_interposer_variantnum == 0 || slave_should_execute)                     \
            ASN_ ## resulttype(result) orig_func orig_func_args;                       \
    }                                                                                  \
    outer_func = was_outer;

/*-----------------------------------------------------------------------------
    Detour macros
-----------------------------------------------------------------------------*/
#define INTERPOSER_DETOUR_HOOK(hooklib, hookfunc, use_debug_syms) \
    mvee_register_hook_func(#hookfunc, #hooklib, (void*)hookfunc ## _hook, (void*)__ ## hookfunc, 1, 1, use_debug_syms, NULL)

#define INTERPOSER_DETOUR_GENERATE_HOOKFUNC(rettype, orig_func_name, args) \
    rettype __ ## orig_func_name args {                                    \
        asm ("nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             "nop\n\t"                                                     \
             );                                                            \
    }                                                                      \
    rettype orig_func_name ## _hook args
