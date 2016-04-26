/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include "../../MVEE/Inc/MVEE_fake_syscall.h"
#include "../../MVEE/Inc/MVEE_interposer_base.h"
#include "../../Utilities/mvee_lazy_hooker/mvee_lazy_hooker.h"

/*-----------------------------------------------------------------------------
    mvee_atomic_preop
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, mvee_atomic_preop, (int op))
{
    DO_SYNC(void,                           /* return type for the original func */
        __mvee_atomic_preop,                /* pointer to the trampoline */
        (op),                               /* arguments to original func */
        MVEE_GCCLIBS_BUFFER,                /* identifier constant for the buffer */
        SLAVES_DONT_CALL_ORIGINAL_FUNCTION, /* whether or not slaves should call the function */
        SLAVES_DONT_CHECK_RESULT,           /* whether or not slaves should check if their result matches the master's result */
        EXECUTE_ATOMIC_PREOP,
        WITHOUT_STACK_LOGGING,              /* debugging feature: should we log a partial callstack for each invocation of the hook? */
        4);                                 /* debugging feature: depth of the callstack */
}

/*-----------------------------------------------------------------------------
    mvee_atomic_postop
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, mvee_atomic_postop, ())
{
    DO_SYNC(void,                           /* return type for the original func */
        __mvee_atomic_postop,               /* pointer to the trampoline */
        (),                                 /* arguments to original func */
        MVEE_GCCLIBS_BUFFER,                /* identifier constant for the buffer */
        SLAVES_DONT_CALL_ORIGINAL_FUNCTION, /* whether or not slaves should call the function */
        SLAVES_DONT_CHECK_RESULT,           /* whether or not slaves should check if their result matches the master's result */
        EXECUTE_ATOMIC_POSTOP,
        WITHOUT_STACK_LOGGING,              /* debugging feature: should we log a partial callstack for each invocation of the hook? */
        4);                                 /* debugging feature: depth of the callstack */
}

/*-----------------------------------------------------------------------------
    gcclibs_interposer initialization
-----------------------------------------------------------------------------*/
static void __attribute__((constructor)) init()
{
    INTERPOSER_DETOUR_HOOK(libgomp.so.1.0.0, mvee_atomic_preop, 0);
    INTERPOSER_DETOUR_HOOK(libgomp.so.1.0.0, mvee_atomic_postop, 0);
    INTERPOSER_DETOUR_HOOK(libstdc++.so.6.0.17, mvee_atomic_preop, 0);
    INTERPOSER_DETOUR_HOOK(libstdc++.so.6.0.17, mvee_atomic_postop, 0);
}
