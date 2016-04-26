#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define MAXTHREADS 100

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

int* nums;
int counter = 0;

static unsigned long __thread next = 1;
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

void* thread_func(void* param)
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

printf( "Thread %d Initializing...\n", *(int*)param);
    mysrand( *(int*)param );

printf( "Thread %d taking lock 1...\n", *(int*)param);
    pthread_mutex_lock( &mutex1 );
    sleeptime = myrand() % 5000;
printf( "Thread %d releasing lock 1...\n", *(int*)param);
    pthread_mutex_unlock( &mutex1 );

printf( "Thread %d sleeping... %u seconds...\n", *(int*)param, sleeptime / 1000);
    sleep(sleeptime / 1000);

printf( "Thread %d taking lock 2...\n", *(int*)param);
    pthread_mutex_lock( &mutex2 );
    num = myrand();
printf( "Thread %d releasing lock 2...\n", *(int*)param);
    pthread_mutex_unlock( &mutex2 );

printf( "Thread %d taking lock 1...\n", *(int*)param);
    pthread_mutex_lock( &mutex1 );
    counter += num;
printf( "Thread %d releasing lock 1...\n", *(int*)param);
    pthread_mutex_unlock( &mutex1 );

printf( "Thread %d RETURN\n", *(int*)param);
    return NULL;
}

int main(int argc, char** argv)
{
    printf("Initializing TestApp3\n");
    int i = 0;
    pthread_t threads[MAXTHREADS];
    nums = new int[MAXTHREADS];

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

    pause();

    return 0;
}
