/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    Copy of the original TestApp3, but now the threads are created with clone
    instead of pthread_create, to verify if clone can be used in combination
    with pthread.
=============================================================================*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sched.h>
#include <pthread.h>

#define MAXTHREADS 5

// 64kB stack
#define STACK_SIZE 1024*64

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

int* nums;
int counter = 0;

static unsigned long next = 1;
/* RAND_MAX assumed to be 32767 */
int myrand(void)
{
    next = next * 1103515245 + 12345;
    return((unsigned)(next/65536) % 32768);
}
void mysrand(unsigned seed)
{
    next = seed;
}

int thread_func(void* param)
{
    int sleeptime;
    int num;
    int max;

    //max = 0x7FFFFFFF;
    //max = 0x0001FFFF;
    max = 20000;

    for (int i = 0; i < max; ++i)
    {
        for (int j = 0; j < max; ++j)
        {
            int tmp = i << j;
        }
    }

    //printf( "Thread %d Initializing...\n", *(int*)param);
    mysrand( *(int*)param );

    //printf( "Thread %d taking lock 1...\n", *(int*)param);
    pthread_mutex_lock( &mutex1 );
    sleeptime = myrand() % 5000;
    //printf( "Thread %d releasing lock 1...\n", *(int*)param);
    pthread_mutex_unlock( &mutex1 );

    //printf( "Thread %d sleeping...\n", *(int*)param);
    sleep(sleeptime / 1000);

    //printf( "Thread %d taking lock 2...\n", *(int*)param);
    pthread_mutex_lock( &mutex2 );
    num = myrand();
    //printf( "Thread %d releasing lock 2...\n", *(int*)param);
    pthread_mutex_unlock( &mutex2 );

    //printf( "Thread %d taking lock 1...\n", *(int*)param);
    pthread_mutex_lock( &mutex1 );
    counter += num;
    //printf( "Thread %d releasing lock 1...\n", *(int*)param);
    pthread_mutex_unlock( &mutex1 );

    //printf( "Thread %d RETURN\n", *(int*)param);
    return 0;
}

int main(int argc, char** argv)
{
    printf("Initializing TestApp3\n");
    int i = 0;
    //pthread_t threads[MAXTHREADS];
    int threads[MAXTHREADS];
    nums = new int[MAXTHREADS];
    void* child_stack;

    for (i = 0; i < MAXTHREADS; ++i)
    {
        printf("Creating Thread %d...\n",i);
        nums[i] = i;
        //pthread_create( &threads[i], NULL, thread_func, &nums[i] );
        child_stack = malloc(STACK_SIZE);
        threads[i] = clone(&thread_func, (char*)child_stack + STACK_SIZE, CLONE_VM, &nums[i]);
        if ( threads[i] == -1 )
        {
             perror( "clone" );
             exit( 2 );
        }
    }

    for (i = 0; i < MAXTHREADS; ++i)
    {
        printf("Joining Thread %d...\n",i);
        //pthread_join( threads[i], NULL );
        if (waitpid(threads[i], NULL, __WCLONE) == -1)
        {
             perror( "waitpid" );
             exit( 3 );
        }
    }

    printf("Counter: %d\n", counter);

    return 0;
}
