/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly synchronizes all
    PIDs among the children and takes care of all the possible places where a
    PID is returned. During execution of this program in the MVEE, no
    mismatches should occur.
=============================================================================*/

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <asm/unistd_32.h>

// internal pthread structs/defines, see nptl/descr.h
// these are usually opaque for programs, but we need them for testing

typedef struct list_head
{
  void *next;
  void *prev;
} list_t;

#ifndef TCB_ALIGNMENT
# define TCB_ALIGNMENT	sizeof (double)
#endif

/* Thread descriptor data structure.  */
struct pthread
{
  union
  {
    struct
    {
      int multiple_threads;
      int gscope_flag;
    } header;

    /* This extra padding has no special purpose, and this structure layout
       is private and subject to change without affecting the official ABI.
       We just have it here in case it might be convenient for some
       implementation-specific instrumentation hack or suchlike.  */
    void *__padding[24];
  };

  /* This descriptor's link on the `stack_used' or `__stack_user' list.  */
  list_t list;

  /* Thread ID - which is also a 'is this thread descriptor (and
     therefore stack) used' flag.  */
  pid_t tid;

  /* Process ID - thread group ID in kernel speak.  */
  pid_t pid;
} __attribute ((aligned (TCB_ALIGNMENT)));

int gettid()
{
    return syscall(__NR_gettid);
}

void* thread_func(void* param)
{
    printf("PID 2: %d\n", getpid());
    printf("TID 2: %d\n", gettid());
    printf("TID 2 from thread descriptor: %d\n", ((pthread*)pthread_self())->tid);
    return NULL;
}

int main(int argc, char** argv)
{
    printf("PID: %d\n", getpid());
    printf("PID from set_tid_address: %ld\n", syscall(__NR_set_tid_address, NULL));
    printf("PID from thread descriptor: %d\n", ((pthread*)pthread_self())->pid);
    printf("TID from thread descriptor: %d\n", ((pthread*)pthread_self())->tid);
    pthread_t thread;
    pthread_create( &thread, NULL, thread_func, NULL );
    pthread_join( thread, NULL );
    return 0;
}
