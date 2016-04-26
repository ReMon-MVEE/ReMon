/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly handles rdtsc
    instructions executed by the children and if it synchronizes the result of
    these instructions among the children. During execution of this program in
    the MVEE, no mismatches or deadlocks should occur.

    The monitor should also prevent the children from re-enabling rdtsc through
    a prctl call.
=============================================================================*/

#include <stdio.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define NUM_THREADS 5

void sig_handler(int sig, siginfo_t *siginfo, void *context)
{
  printf("SIGSEGV occurred\n");
  printf("Errno: %d\n", siginfo->si_errno);
  printf("Code: 0x%08X\n", siginfo->si_code);
  printf("Address: 0x%08X\n", (int)siginfo->si_addr);
  exit(1);
}

__inline__ uint64_t rdtsc() {
  uint32_t lo, hi;
  /* We cannot use "=A", since this would use %rax on x86_64 */
  __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
  return (uint64_t)hi << 32 | lo;
}

void* thread_func(void* param)
{
    printf("TSC from thread: %llu\n", rdtsc());
    return NULL;
}

void* thread_func2(void* param)
{
    struct timespec ts;
    while (1)
    {
        rdtsc();
        ts.tv_sec = 0;
        ts.tv_nsec = (random() % 100) * 1000000;
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    pthread_t thread;
    int i;
    pthread_t threads[NUM_THREADS];

    // try to re-enable rdtsc
    if (prctl(PR_SET_TSC, PR_TSC_ENABLE, 0, 0, 0) == -1)
        perror("Enabling TSC failed"); // this error should occur in the MVEE

    //   struct sigaction action;
    //   action.sa_sigaction = sig_handler;
    //   sigemptyset(&action.sa_mask);
    //   action.sa_flags = SA_SIGINFO;
    //   sigaction(SIGSEGV, &action, NULL);

    printf("TSC: %llu\n", rdtsc());

    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);
    printf("Testing rdtsc handling multithread robustness...\n");
    for (i = 0; i < NUM_THREADS; ++i)
        pthread_create(&threads[i], NULL, thread_func2, NULL);
    while (1)
    {
        printf("ping\n");
        sleep(1);
    }
    return 0;
}
