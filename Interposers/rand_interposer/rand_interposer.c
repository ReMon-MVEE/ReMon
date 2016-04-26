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
#include "rand_interposer.h"

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
pthread_mutex_t rand_lock = PTHREAD_MUTEX_INITIALIZER;
void (*orig_rand)(unsigned int) = NULL;

/*-----------------------------------------------------------------------------
    write_rand_operation
-----------------------------------------------------------------------------*/
void write_rand_operation(int pos, unsigned int result)
{
    *(volatile unsigned int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    is_mythread_rand_operation
-----------------------------------------------------------------------------*/
int is_mythread_rand_operation(int pos)
{
    volatile int op = *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos);
    return op == masterthread_id;
}

/*-----------------------------------------------------------------------------
    read_rand_operation
-----------------------------------------------------------------------------*/
void read_rand_operation(int pos, unsigned int* result)
{
    volatile unsigned int op = *(volatile unsigned int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = op;
}

/*-----------------------------------------------------------------------------
    arg_to_ret
-----------------------------------------------------------------------------*/
unsigned int arg_to_ret(unsigned int arg)
{
    return arg;
}

/*-----------------------------------------------------------------------------
    srand
-----------------------------------------------------------------------------*/
void srand(unsigned int seed)
{
    if (!orig_rand)
        orig_rand = (void (*)(unsigned int))dlsym(RTLD_NEXT, "srand");
    pthread_mutex_lock(&rand_lock);
    DO_SYNC(unsigned int, arg_to_ret, arg_to_ret, (seed), MVEE_RAND_BUFFER, 2*sizeof(int), write_rand_operation, read_rand_operation, is_mythread_rand_operation, 0, 0, 1, 1, 2);
    printf("interposer_initializing_rand: %d\n", result);
    orig_rand(result);
    pthread_mutex_unlock(&rand_lock);
}
