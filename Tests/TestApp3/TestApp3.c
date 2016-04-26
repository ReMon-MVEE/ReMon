/*=============================================================================
    This is a pointless program that calculates some random number. The result
    of the calculation depends on the order in which the threads are scheduled.
    Therefore, this is a nondeterministic calculation, but, because the monitor
    correctly synchronises pthread_mutex_lock and pthread_mutex_unlock, all
    variants will return the same results!

    printf is just a wrapper around vfprintf (glibc/stdio-common/vfprintf.c).
    after formatting the output buffer, vfprintf locks the output file stream.
    In printf's case, the output file steam is stdout. To prevent multiple
    threads in the same process from printing to stdout simultaneously, the
    stream is locked using an lll_lock (= futex based). This might cause dead-
    locks if printf calls are not synchronised.
=============================================================================*/
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define MAXTHREADS 2

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

int nums[MAXTHREADS];
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
  printf("mysrand: %d\n", seed);
    next = seed;
}

void* thread_func(void* param)
{
    int sleeptime;
    int num;
    int max;
    int i, j, tmp;

    //max = 0x7FFFFFFF;
    //max = 0x0001FFFF;
    max = 2000;

    for (i = 0; i < max; ++i)
    {
        for (j = 0; j < max; ++j)
        {
            tmp = i << j;
        }
    }

    //printf( "Thread %d Initializing...\n", *(int*)param);

    //printf( "Thread %d taking lock 1...\n", *(int*)param);
    pthread_mutex_lock( &mutex1 );
    sleeptime = myrand() % 5000;
    //printf( "Thread %d releasing lock 1...\n", *(int*)param);
    pthread_mutex_unlock( &mutex1 );

    //printf( "Thread %d sleeping...\n", *(int*)param);
    printf("sleeping: %lf\n", sleeptime/1000);
    //    syscall(224, 1337, 10000001, 72);
    sleep(sleeptime / 1000);
    //    syscall(224, 1337, 10000001, 73);

    //printf( "Thread %d taking lock 2...\n", *(int*)param);
    //    pthread_mutex_lock( &mutex2 );
    //    num = myrand();
    //printf( "Thread %d releasing lock 2...\n", *(int*)param);
    //    pthread_mutex_unlock( &mutex2 );

    //printf( "Thread %d taking lock 1...\n", *(int*)param);
    //    pthread_mutex_lock( &mutex1 );
    //    counter += num;
    //printf( "Thread %d releasing lock 1...\n", *(int*)param);
    //    pthread_mutex_unlock( &mutex1 );

    //printf( "Thread %d RETURN\n", *(int*)param);
    return NULL;
}

int main(int argc, char** argv)
{
    int i = 0;
    printf("Initializing TestApp3\n");
    pthread_t threads[MAXTHREADS];
    /*nums = new int[MAXTHREADS];*/

    mysrand(1);
    for (i = 0; i < MAXTHREADS; ++i)
    {
        printf("Creating Thread %d...\n",i);
        nums[i] = i;
        pthread_create( &threads[i], NULL, thread_func, &nums[i] );
    }

    for (i = 0; i < MAXTHREADS; ++i)
    {
        printf("Joining Thread %d...\n",i);
        pthread_join( threads[i], NULL );
    }

    printf("Counter: %d\n", counter);

    /*
    for (i = 0; i < 10; ++i)
      sleep(1);
    */

    return 0;
}
