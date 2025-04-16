#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>

#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
#include "PMVEE.h"
#endif


#define ITERATIONS 10000
#define FOLLOWER_VARIANTS 1


#define PMVEE_EMPTY_ENTER \
__asm("xor %%r10, %%r10; xor %%r8, %%r8; xor %%r9, %%r9; movl %[id], %%r8d; syscall;" :: "a" (__NR_pmvee_switch), "D" (own_pid), "S" (own_pid), "d" (0), [id] "i" (3): "rcx", "r10", "r8", "r9", "r11", "memory", "cc");

#define PMVEE_EMPTY_EXIT \
__asm("xor %%r10, %%r10; xor %%r8, %%r8; xor %%r9, %%r9; syscall;" :: "a" (__NR_pmvee_check), "D" (own_pid), "S" (own_pid), "d" (0) : "rcx", "r10", "r8", "r9", "r11", "memory", "cc");


long int time_empty;
long int time_getpid;

void* mp_start = 0;
unsigned long mp_size = 0;


#ifdef NATIVE_RUNNING

#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
#error illigal compilation setup
#endif

#define RANDOM_BASE NULL

#define START_MEASURING        { spawn_followers(); enter_exit_test(); barrier_wait(); gettimeofday(&start, NULL); }
#define START_MEASURING_NO_PRE { spawn_followers(); barrier_wait(); gettimeofday(&start, NULL); }
#define END_MEASURING          { barrier_wait(); gettimeofday(&end, NULL); unalive_followers(); }
#define SET_INITIAL            { enter_exit_test_initial(); }

#define RUN_ENTER_EXIT_LOOP(__core, __time)  \
{                                            \
    spawn_followers();                       \
    if (am_leader)                           \
    {                                        \
        barrier_wait();                      \
    }                                        \
    else                                     \
    {                                        \
        { __core; };                         \
        gettimeofday(&start, NULL);          \
        for (int i = 0; i < ITERATIONS; i++) \
        {                                    \
            __core;                          \
        }                                    \
        gettimeofday(&end, NULL);            \
        barrier->time = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec); \
        barrier_wait();                      \
        exit(0);                             \
    }                                        \
    __time = barrier->time;                  \
}


#define RUN_ENTER_EXIT_LOOP_SYNC(__core, __time)  \
{                                            \
    spawn_followers();                       \
    if (am_leader)                           \
    {                                        \
        { __core; };                         \
        for (int i = 0; i < ITERATIONS; i++) \
        {                                    \
            __core                           \
        }                                    \
    }                                        \
    else                                     \
    {                                        \
        { __core; };                         \
        gettimeofday(&start, NULL);          \
        for (int i = 0; i < ITERATIONS; i++) \
        {                                    \
            { __core; }                      \
        }                                    \
        gettimeofday(&end, NULL);            \
        barrier->time = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec); \
        barrier_wait();                      \
        exit(0);                             \
    }                                        \
    barrier_wait();                          \
    __time = barrier->time;                  \
}


pid_t leader_pid = 0;
pid_t own_pid = 0;
pid_t am_leader = 0;
int followers = 0;
int id = 0;


struct barrier_t
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int waiting[FOLLOWER_VARIANTS + 1];
    long int time;
    
};
struct barrier_t* barrier = (struct barrier_t*)0;

static void barrier_wait() {
    pthread_mutex_lock(&barrier->mutex);

    barrier->waiting[id] = 1;
    int i;
    for (i = 0; i < FOLLOWER_VARIANTS + 1; i++)
        if (!barrier->waiting[i])
            break;
    if (i == (FOLLOWER_VARIANTS + 1))
    {
        for (i = 0; i < FOLLOWER_VARIANTS + 1; i++)
            barrier->waiting[i] = 0;
        pthread_cond_broadcast(&barrier->cond);
    }
    else while (barrier->waiting[id])
        pthread_cond_wait(&barrier->cond, &barrier->mutex);

    pthread_mutex_unlock(&barrier->mutex);
}

static void single_barrier_wait(struct barrier_t* to_wait) {
    pthread_mutex_lock(&to_wait->mutex);

    to_wait->waiting[0] = 1;
    int i;
    for (i = 0; i < 1; i++)
        if (!to_wait->waiting[i])
            break;
    if (i == (1))
    {
        for (i = 0; i < 1; i++)
            to_wait->waiting[i] = 0;
        pthread_cond_broadcast(&to_wait->cond);
    }
    else while (to_wait->waiting[id])
        pthread_cond_wait(&to_wait->cond, &to_wait->mutex);

    pthread_mutex_unlock(&to_wait->mutex);
}

static struct barrier_t* barrier_init(int followers)
{
    struct barrier_t* init = (struct barrier_t*) mmap(0, sizeof(struct barrier_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (init == MAP_FAILED)
    {
        printf("Failed to map barrier.\n");
        _exit(1);
    }
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if(pthread_mutex_init(&init->mutex, &attr))
    {
        printf("Failed to initialise mutex\n");
        _exit(1);
    }
    pthread_condattr_t psharedc;
    (void) pthread_condattr_init(&psharedc);
    (void) pthread_condattr_setpshared(&psharedc, PTHREAD_PROCESS_SHARED);
    if(pthread_cond_init(&init->cond, &psharedc))
    {
        printf("Failed to initialise cond\n");
        _exit(1);
    }
    for (int i = 0; i < followers + 1; i++)
        init->waiting[i] = 0;

    return init;
}

static void spawn_followers()
{
    leader_pid = getpid();
    if ((am_leader = fork()) == -1)
    {
        printf("Failed to fork.\n");
        _exit(1);
    }
    id = am_leader ? 0 : 1;
    followers++;
    own_pid = getpid();
}

static void unalive_followers()
{
    if (!am_leader)
        exit(0);
    else
        followers = 0;
}

void __attribute__ ((noinline)) enter_exit_test()
{
    asm("movq %%rcx, %%r10; xor %%r8, %%r8; xor %%r9, %%r9; syscall;" :: "a" (__NR_pmvee_switch), "D" (leader_pid), "S" (own_pid), "d" (mp_start), "c" ((unsigned long) mp_size) : "r10", "r8", "r9", "r11", "memory", "cc");
    asm("movq %%rcx, %%r10; xor %%r8, %%r8; xor %%r9, %%r9; syscall;" :: "a" (__NR_pmvee_check), "D" (leader_pid), "S" (own_pid), "d" (mp_start), "c" ((unsigned long) mp_size) : "r10", "r8", "r9", "r11", "memory", "cc");
}


void __attribute__ ((noinline)) enter_exit_test_sync()
{
    barrier_wait();
    __asm("movq %%rcx, %%r10; xor %%r8, %%r8; xor %%r9, %%r9; syscall;" :: "a" (__NR_pmvee_switch), "D" (leader_pid), "S" (own_pid), "d" (mp_start), "c" ((unsigned long) mp_size) : "r10", "r8", "r9", "r11", "memory", "cc");
    barrier_wait();
    barrier_wait();
    __asm("movq %%rcx, %%r10; xor %%r8, %%r8; xor %%r9, %%r9; syscall;" :: "a" (__NR_pmvee_check), "D" (leader_pid), "S" (own_pid), "d" (mp_start), "c" ((unsigned long) mp_size) : "r10", "r8", "r9", "r11", "memory", "cc");
    barrier_wait();
}
#else
#define RANDOM_BASE NULL

#define RUN_ENTER_EXIT_LOOP(__core, __time) \
{                                        \
    { __core; };                         \
    gettimeofday(&start, NULL);          \
    for (int i = 0; i < ITERATIONS; i++) \
    {                                    \
        __core;                          \
    }                                    \
    gettimeofday(&end, NULL);            \
    __time = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec); \
}

#define START_MEASURING { enter_exit_test(); gettimeofday(&start, NULL); }
#define START_MEASURING_NO_PRE { gettimeofday(&start, NULL); }
#define END_MEASURING   { gettimeofday(&end, NULL); }

void __attribute__ ((noinline)) enter_exit_test()
#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
;
void __attribute__ ((noinline)) __pmvee_real_enter_exit_test()
#endif
{
    __asm("nop;" ::: "cc");
}
#endif



void __attribute__ ((noinline)) base_line_tests()
#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
;
void __attribute__ ((noinline)) __pmvee_real_base_line_tests()
#endif
{
    struct timeval start, end;
    time_empty = 0;
    time_getpid = 0;

    START_MEASURING_NO_PRE
    for (int i = 0; i < ITERATIONS; i++)
        __asm("nop;" ::: "cc");
    END_MEASURING
    time_empty = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec);

    START_MEASURING_NO_PRE
    for (int i = 0; i < ITERATIONS; i++)
        __asm("movq %0, %%rax; syscall;" :: "i" (__NR_getpid) : "rax", "rcx", "r11", "memory", "cc");
    END_MEASURING
    time_getpid = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec);
}


int own_pid;
void __attribute__ ((noinline)) enter_exit_direct()
{
    PMVEE_EMPTY_ENTER
    PMVEE_EMPTY_EXIT
}


int clone_test(void* args)
{
    return 0;
}


int native_main()
{
#ifdef NATIVE_RUNNING
    own_pid = getpid();
    leader_pid = getpid();

    struct timeval start, end;
    long int time_taken;

    
    barrier = (struct barrier_t*) mmap(0, sizeof(struct barrier_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (barrier == MAP_FAILED)
    {
        printf("Failed to map barrier.\n");
        _exit(1);
    }
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if(pthread_mutex_init(&barrier->mutex, &attr))
    {
        printf("Failed to initialise mutex\n");
        _exit(1);
    }
    pthread_condattr_t psharedc;
    (void) pthread_condattr_init(&psharedc);
    (void) pthread_condattr_setpshared(&psharedc, PTHREAD_PROCESS_SHARED);
    if(pthread_cond_init(&barrier->cond, &psharedc))
    {
        printf("Failed to initialise cond\n");
        _exit(1);
    }
    for (int i = 0; i < FOLLOWER_VARIANTS + 1; i++)
        barrier->waiting[i] = 0;


    base_line_tests();
    printf(">[native measuring] > time elapsed: %ld us for %d iterations\n",
            time_empty,
            ITERATIONS);fflush(stdout);
    printf(">[native getpid] > time elapsed: %ld us for %d iterations\n",
            time_getpid,
            ITERATIONS);fflush(stdout);

    struct barrier_t* bench_barrier = barrier_init(0);
    RUN_ENTER_EXIT_LOOP({single_barrier_wait(bench_barrier);}, time_taken)
    printf(">[single barrier] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    RUN_ENTER_EXIT_LOOP_SYNC({barrier_wait();}, time_taken)
    printf(">[barrier sync] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);

    RUN_ENTER_EXIT_LOOP({__asm("syscall;" :: "a" (__NR_getpid) : "rcx", "r11", "memory", "cc");}, time_taken)
    printf(">[getpid sanity check] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    RUN_ENTER_EXIT_LOOP_SYNC({barrier_wait(); __asm("syscall;" :: "a" (__NR_getpid) : "rcx", "r11", "memory", "cc");barrier_wait();}, time_taken)
    printf(">[getpid sync] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);


    RUN_ENTER_EXIT_LOOP(enter_exit_test();, time_taken)
    printf(">[native enter exit] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    RUN_ENTER_EXIT_LOOP_SYNC(enter_exit_test_sync();, time_taken)
    printf(">[native enter exit sync] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);


    RUN_ENTER_EXIT_LOOP({int new_pid = fork(); if (new_pid) {kill(new_pid, SIGKILL);} else { while(1) wait(&new_pid);}}, time_taken)
    printf(">[fork and kill child] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    RUN_ENTER_EXIT_LOOP({int new_pid = fork(); if (!new_pid) {kill(getpid(), SIGKILL);}}, time_taken)
    printf(">[fork and kill self] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
            
    char* stack = ((char*)malloc(1024*1024))+1024*1024;
    RUN_ENTER_EXIT_LOOP({ int new_pid = clone(clone_test, stack, SIGCHLD, 0); }, time_taken)
    printf(">[clone and kill self] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);

#endif
    return 0;
}


int pmvee_main()
{
    struct timeval start, end;
    long int time_taken;

#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
    __pmvee_real_base_line_tests();
    printf(">[SVX measuring] > time elapsed: %ld us for %d iterations\n",
            time_empty,
            ITERATIONS);fflush(stdout);
    printf(">[SVX getpid] > time elapsed: %ld us for %d iterations\n",
            time_getpid,
            ITERATIONS);fflush(stdout);
#endif
            
    base_line_tests();
    printf(">[MVX measuring] > time elapsed: %ld us for %d iterations\n",
            time_empty,
            ITERATIONS);fflush(stdout);
    printf(">[MVX getpid] > time elapsed: %ld us for %d iterations\n",
            time_getpid,
            ITERATIONS);fflush(stdout);

    RUN_ENTER_EXIT_LOOP(enter_exit_test();, time_taken)
    printf(">[MVX enter exit] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);

    RUN_ENTER_EXIT_LOOP(enter_exit_direct();, time_taken)
    printf(">[MVX enter exit direct] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);

    return 0;
}


int main(int argc, char** argv)
{
    #ifdef NATIVE_RUNNING
    native_main();
    #elif defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
    PMVEE_EXIT;
    pmvee_main();
    #endif

    return 0;
}