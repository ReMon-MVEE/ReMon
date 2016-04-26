#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

#define NUM_ITERATIONS 1000000

int main()
{
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int i;
    for (i = 0; i < NUM_ITERATIONS; ++i)
    {
        pthread_mutex_lock(&mutex);
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}
