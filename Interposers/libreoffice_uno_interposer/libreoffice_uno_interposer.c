/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdio.h>
#include "libreoffice_uno_interposer.h"

/*-----------------------------------------------------------------------------
    write_uno_operation
-----------------------------------------------------------------------------*/
void write_uno_operation(int pos, unsigned int result)
{
    *(volatile unsigned int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    is_mythread_uno_operation
-----------------------------------------------------------------------------*/
int is_mythread_uno_operation(int pos)
{
    volatile int op = *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos);
    return op == masterthread_id;
}

/*-----------------------------------------------------------------------------
    read_uno_operation
-----------------------------------------------------------------------------*/
void read_uno_operation(int pos, unsigned int* result)
{
    volatile unsigned int op = *(volatile unsigned int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = op;
}

/*-----------------------------------------------------------------------------
    osl_incrementInterlockedCount
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(unsigned int, osl_incrementInterlockedCount, (unsigned int* pCount))
{
  DO_SYNC_ATOMIC(unsigned int, osl_incrementInterlockedCount, __osl_incrementInterlockedCount, (pCount), MVEE_UNO_HASH_BUFFER, 2*sizeof(int), write_uno_operation, read_uno_operation, is_mythread_uno_operation, 1, 1, 1, 1, 2);
    //printf("osl_incrementInterlockedCount - %d - %d\n", result, *pCount);
    /*int frame_pointer;
    asm("movl %%ebp, %0;" : "=r"(frame_pointer)::);
    syscall(__NR_gettid, 1337, 10000001, 50, result, *pCount, frame_pointer);*/
    return result;
}

/*-----------------------------------------------------------------------------
    osl_decrementInterlockedCount
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(unsigned int, osl_decrementInterlockedCount, (unsigned int* pCount))
{
  DO_SYNC_ATOMIC(unsigned int, osl_decrementInterlockedCount, __osl_decrementInterlockedCount, (pCount), MVEE_UNO_HASH_BUFFER, 2*sizeof(int), write_uno_operation, read_uno_operation, is_mythread_uno_operation, 1, 1, 1, 1, 2);
    //printf("osl_decrementInterlockedCount - %d - %d\n", result, *pCount);
    /*int frame_pointer;
    asm("movl %%ebp, %0;" : "=r"(frame_pointer)::);
    syscall(__NR_gettid, 1337, 10000001, 51, result, *pCount, frame_pointer);*/
    return result;
}

/*-----------------------------------------------------------------------------
    osl_getThreadHash
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(unsigned int, osl_getThreadHash, (pthread_t hThread))
{
  DO_SYNC(unsigned int, osl_getThreadHash, __osl_getThreadHash, (hThread), MVEE_UNO_HASH_BUFFER, 2*sizeof(int), write_uno_operation, read_uno_operation, is_mythread_uno_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    rtl_generic_hash
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(unsigned int, rtl_generic_hash, (void* p))
{
  DO_SYNC(unsigned int, rtl_generic_hash, __rtl_generic_hash, (p), MVEE_UNO_HASH_BUFFER, 2*sizeof(int), write_uno_operation, read_uno_operation, is_mythread_uno_operation, 1, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    rtl_generic_less_than
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(unsigned int, rtl_generic_less_than, (void* left, void* right))
{
  DO_SYNC(unsigned int, rtl_generic_less_than, __rtl_generic_less_than, (left, right), MVEE_UNO_HASH_BUFFER, 2*sizeof(int), write_uno_operation, read_uno_operation, is_mythread_uno_operation, 1, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    init
-----------------------------------------------------------------------------*/
void __attribute__((constructor)) init()
{
    printf("Registering LIBUNO Hooks ...\n");

    INTERPOSER_DETOUR_HOOK(*, osl_getThreadHash, 0);
    INTERPOSER_DETOUR_HOOK(*, osl_decrementInterlockedCount, 0);
    INTERPOSER_DETOUR_HOOK(*, osl_incrementInterlockedCount, 0);
    INTERPOSER_DETOUR_HOOK(*, rtl_generic_hash, 0);
    INTERPOSER_DETOUR_HOOK(*, rtl_generic_less_than, 0);
}
