/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly handles a
    setuid-related call and resulting SETXID signal while another thread is
    wating on a mutex or condition variable. During execution of this
    program in the MVEE, no mismatches or deadlocks should occur.

    No real solution for delivering signals to waiting threads was found, but
    all setuid-related functions are cancelled out (see libc_interposer), to
    prevent the SETXID signal from happening.
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <pthread.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

void* blocking_thread_func(void* param)
{
    pthread_mutex_lock(&mutex);
    struct timespec abstime;
    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_sec += 3;
    printf("Waiting for 3 seconds...\n");
    pthread_cond_timedwait(&condition, &mutex, &abstime);
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void* setxid_thread_func(void* param)
{
    if (seteuid(getuid()) == 0)
        printf("success\n");
    else
        perror("seteuid");
    return NULL;
}

int main()
{
    pthread_t blocking_thread, setxid_thread;
    //pthread_mutex_lock(&mutex);
    pthread_create(&blocking_thread, NULL, blocking_thread_func, NULL);
    pthread_create(&setxid_thread, NULL, setxid_thread_func, NULL);
    pthread_join(setxid_thread, NULL);
    //pthread_mutex_unlock(&mutex);
    //pthread_cond_signal(&condition);
    pthread_join(blocking_thread, NULL);
    printf("done\n");
    return 0;
}
