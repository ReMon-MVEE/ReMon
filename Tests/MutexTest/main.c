/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if recursive mutexes are correctly
    identified. It can also be used to check if the monitor intercepts all
    mutex locking functions.
=============================================================================*/

#define _GNU_SOURCE 1

#include <stdio.h>
#include <pthread.h>
#include <errno.h>

/*-----------------------------------------------------------------------------
    Define for determining if a mutex is recursive, see nptl/pthreadP.h
-----------------------------------------------------------------------------*/
#define PTHREAD_MUTEX_TYPE(m) \
  ((m)->__data.__kind & 127)

int mutex_is_recursive(pthread_mutex_t *mutex)
{
    return (PTHREAD_MUTEX_TYPE(mutex) == PTHREAD_MUTEX_RECURSIVE_NP);
}

char *mutex_is_recursive_str(pthread_mutex_t *mutex)
{
    if (mutex_is_recursive(mutex))
        return "yes";
    else
        return "no";
}

int main(int argc, char** argv)
{
    pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex2;
    pthread_mutex_t mutex3 = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
    pthread_mutex_t mutex4;
    pthread_mutexattr_t attr;
    pthread_mutex_init(&mutex1, NULL);
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mutex4, &attr);
    pthread_mutexattr_destroy(&attr);
    printf("Mutex 1 recursive: %s\n", mutex_is_recursive_str(&mutex1));
    printf("Mutex 2 recursive: %s\n", mutex_is_recursive_str(&mutex2));
    printf("Mutex 3 recursive: %s\n", mutex_is_recursive_str(&mutex3));
    printf("Mutex 4 recursive: %s\n", mutex_is_recursive_str(&mutex4));

    printf("Locking (normal)...\n");
    // test if pthread_mutex_lock works correctly
    pthread_mutex_lock(&mutex1);
    if (pthread_mutex_trylock(&mutex1) == EBUSY)
        printf("ok\n");
    else
        printf("mutex not locked!\n"); // should not occur
    pthread_mutex_unlock(&mutex1);

    printf("Locking (alias)...\n");
    // test if __pthread_mutex_lock (note the __ prefix) works correctly
    __pthread_mutex_lock(&mutex1);
    if (pthread_mutex_trylock(&mutex1) == EBUSY)
        printf("ok\n");
    else
        printf("mutex not locked!\n"); // should not occur
    __pthread_mutex_unlock(&mutex1);

    return 0;
}
