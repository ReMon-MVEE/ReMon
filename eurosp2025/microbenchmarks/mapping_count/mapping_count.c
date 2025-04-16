#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>

#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
#include "PMVEE.h"
#endif


#define MAX_POINTERS 8192
int pointer_count_global = 0;
int migration_count_global = 0;
extern int* pointer_count;
extern int* migration_count;
extern void** pointer_data;
extern void** migration_data;

#define ITERATIONS 10000
#define FOLLOWER_VARIANTS 1


long int time_empty;
long int time_getpid;

void* mp_start;
unsigned long mp_size;

int data_migration = 0;
void** data;


#ifdef FULL_NATIVE_RUNNING

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
            __core                           \
        }                                    \
        gettimeofday(&end, NULL);            \
        barrier->time = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec); \
        barrier_wait();                      \
        exit(0);                             \
    }                                        \
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
    syscall(__NR_pmvee_switch, leader_pid, own_pid, mp_start, mp_size, 0, 0);
    syscall(__NR_pmvee_check, leader_pid, own_pid, mp_start, mp_size, 0, 0);
}
#elif defined(FULL_NATIVE_RUNNING_SYNC)
#define RANDOM_BASE NULL

#define START_MEASURING { spawn_followers(); enter_exit_test(); barrier_wait(); gettimeofday(&start, NULL); }
#define START_MEASURING_NO_PRE { spawn_followers(); barrier_wait(); gettimeofday(&start, NULL); }
#define END_MEASURING   { barrier_wait(); gettimeofday(&end, NULL); unalive_followers(); }
#define SET_INITIAL     { enter_exit_test_initial(); }

#define RUN_ENTER_EXIT_LOOP(__core, __time)  \
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
            __core                           \
        }                                    \
        gettimeofday(&end, NULL);            \
        barrier->time = ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec); \
        exit(0);                             \
    }                                        \
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
    barrier_wait();
    syscall(__NR_pmvee_switch, leader_pid, own_pid, mp_start, mp_size, 0, 0);
    barrier_wait();
    syscall(__NR_pmvee_check, leader_pid, own_pid, mp_start, mp_size, 0, 0);
    barrier_wait();
}
#else
#define RANDOM_BASE NULL

pid_t leader_pid = 0;
pid_t own_pid = 0;

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

void __attribute__ ((noinline)) pointer_test()
#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
;
void __attribute__ ((noinline)) __pmvee_real_pointer_test()
#endif
{
    __asm("nop;" ::: "cc");
}

void __attribute__ ((noinline)) migration_test()
#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
;
void __attribute__ ((noinline)) __pmvee_real_migration_test()
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


void __attribute__ ((noinline)) enter_exit_only()
{
    syscall(__NR_pmvee_switch, own_pid, own_pid, 0, 0, 0, 0);
    syscall(__NR_pmvee_check, own_pid, own_pid, 0, 0, 0, 0);
}


int main(int argc, char** argv)
{
    #if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
    pointer_count = &pointer_count_global;
    migration_count = &migration_count_global;
    migration_data = (void**) mmap(0, MAX_POINTERS * sizeof(void*), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int data_i = 0; data_i < MAX_POINTERS; data_i++)
        migration_data[data_i] = &main;
    pointer_data = (void**) mmap(0, MAX_POINTERS * sizeof(void*), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int data_i = 0; data_i < MAX_POINTERS; data_i++)
        pointer_data[data_i] = &main;

    PMVEE_EXIT;
    #endif

    struct timeval start, end;
    long int time_taken;

    leader_pid = getpid();
    own_pid = getpid();

    #if defined(FULL_NATIVE_RUNNING) || defined(FULL_NATIVE_RUNNING_SYNC)


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
    #endif

    #if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
    __pmvee_real_base_line_tests();
    printf(">[single-variant measuring] > time elapsed: %ld us for %d iterations\n",
            time_empty,
            ITERATIONS);fflush(stdout);
    printf(">[single-variant get pid] > time elapsed: %ld us for %d iterations\n",
            time_getpid,
            ITERATIONS);fflush(stdout);
    #endif

    base_line_tests();
    printf(">[multi-variant measuring] > time elapsed: %ld us for %d iterations\n",
            time_empty,
            ITERATIONS);fflush(stdout);
    printf(">[multi-variant get pid] > time elapsed: %ld us for %d iterations\n",
            time_getpid,
            ITERATIONS);fflush(stdout);

#if defined(PMVEE_LEADER) || defined(PMVEE_FOLLOWER)
    START_MEASURING
    for (int i = 0; i < ITERATIONS; i++)
        __pmvee_real_enter_exit_test();
    END_MEASURING
    printf(">[single-variant enter-exit] > time elapsed: %ld us for %d iterations\n",
            ((end.tv_sec - start.tv_sec) * 1000000) + (end.tv_usec - start.tv_usec),
            ITERATIONS);fflush(stdout);

    int migration_sizes[] = { 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };
    for (int migration_size_i = 0; migration_size_i < sizeof(migration_sizes)/sizeof(int); migration_size_i++)
    {
        pointer_count_global = migration_sizes[migration_size_i];
        migration_count_global = migration_sizes[migration_size_i];
        RUN_ENTER_EXIT_LOOP(migration_test();, time_taken)
        printf(">[migration %d] > time elapsed: %ld us for %d iterations\n",
                migration_sizes[migration_size_i],
                time_taken,
                ITERATIONS);fflush(stdout);
        RUN_ENTER_EXIT_LOOP(pointer_test();, time_taken)
        printf(">[pointer migration %d] > time elapsed: %ld us for %d iterations\n",
                migration_sizes[migration_size_i],
                time_taken,
                ITERATIONS);fflush(stdout);
    }
#endif


    int mapping_sizes[] = { 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000 }; // , 0x100000, 0x400000, 0x1000000 };
    int test_sizes[] = { 0, 1, 5, 10, 20, 50, 100, 200 }; // , 500, 1000 };
    // for (int mapping_size_i = 0xffffffff; mapping_size_i < sizeof(mapping_sizes)/sizeof(int); mapping_size_i++)
    for (int mapping_size_i = 0; mapping_size_i < sizeof(mapping_sizes)/sizeof(int); mapping_size_i++)
    {
        for (int test_i = 0; test_i < sizeof(test_sizes)/sizeof(int); test_i++)
        {
            mp_size = mapping_sizes[mapping_size_i] * test_sizes[test_i];
            mp_start = 0;
            if (mp_size)
            {
                mp_start = mmap(RANDOM_BASE, mp_size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | 0x2000000, -1, 0);
                if (mp_start == MAP_FAILED)
                {
                    printf(" Could not set up mappings. errno: %d\n", errno);
                    return -1;
                }
            }

            unsigned long mapping_count = 0;
            while (mapping_count < test_sizes[test_i])
            {
                if (mmap(mp_start + (mapping_count * mapping_sizes[mapping_size_i]), mapping_sizes[mapping_size_i], mapping_count % 2 ? PROT_WRITE : (PROT_READ | PROT_WRITE), MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | 0x2000000, -1, 0) == MAP_FAILED)
                {
                    printf(" Could not create mappings. errno: %d\n", errno);
                    return -1;
                }
                for (int i = 0; i < mapping_sizes[mapping_size_i]; i+=4096)
                    *(unsigned long*)((mp_start + (mapping_count * mapping_sizes[mapping_size_i])) + i) = mapping_count;
                mapping_count++;
            }

            RUN_ENTER_EXIT_LOOP(enter_exit_test();, time_taken)
            printf(">[0x%x mapping count %d] > time elapsed: %ld us for %d iterations\n",
                    mapping_sizes[mapping_size_i],
                    test_sizes[test_i],
                    time_taken,
                    ITERATIONS);fflush(stdout);

            if (mp_size)
                munmap(mp_start, mp_size);
        }
    }

/*
0x000070b92f0fa000-0x000070b92eb1d000 PROT_NONE
0x000070b92f329000-0x000070b92f0fa000 PROT_READ | PROT_WRITE
0x000070b92f35a000-0x000070b92f329000 PROT_NONE
0x000070b92f35b000-0x000070b92f35a000 PROT_READ | PROT_WRITE
0x000070b92f38a000-0x000070b92f35b000 PROT_NONE
0x000070b92f38c000-0x000070b92f38a000 PROT_READ | PROT_WRITE
0x000070b92f3ba000-0x000070b92f38c000 PROT_NONE
0x000070b92f3bb000-0x000070b92f3ba000 PROT_READ | PROT_WRITE
0x000070b92f3ea000-0x000070b92f3bb000 PROT_NONE
0x000070b92f3eb000-0x000070b92f3ea000 PROT_READ | PROT_WRITE
0x000070b92f41a000-0x000070b92f3eb000 PROT_NONE
0x000070b92f41b000-0x000070b92f41a000 PROT_READ | PROT_WRITE
0x000070b92f44a000-0x000070b92f41b000 PROT_NONE
0x000070b92f44b000-0x000070b92f44a000 PROT_READ | PROT_WRITE
0x000070b92f47a000-0x000070b92f44b000 PROT_NONE
0x000070b92f47b000-0x000070b92f47a000 PROT_READ | PROT_WRITE
0x000070b92f4aa000-0x000070b92f47b000 PROT_NONE
0x000070b92f4ab000-0x000070b92f4aa000 PROT_READ | PROT_WRITE
0x000070b92f4da000-0x000070b92f4ab000 PROT_NONE
0x000070b92f4db000-0x000070b92f4da000 PROT_READ | PROT_WRITE
0x000070b92f50a000-0x000070b92f4db000 PROT_NONE
0x000070b92f50b000-0x000070b92f50a000 PROT_READ | PROT_WRITE
0x000070b92f53a000-0x000070b92f50b000 PROT_NONE
0x000070b92f53b000-0x000070b92f53a000 PROT_READ | PROT_WRITE
0x000070b92f59a000-0x000070b92f53b000 PROT_NONE
0x000070b92f59b000-0x000070b92f59a000 PROT_READ | PROT_WRITE
0x000070b92f62a000-0x000070b92f59b000 PROT_NONE
0x000070b92f62b000-0x000070b92f62a000 PROT_READ | PROT_WRITE
0x000070b92f65a000-0x000070b92f62b000 PROT_NONE
0x000070b92f65b000-0x000070b92f65a000 PROT_READ | PROT_WRITE
0x000070b92f68a000-0x000070b92f65b000 PROT_NONE
0x000070b92f68b000-0x000070b92f68a000 PROT_READ | PROT_WRITE
0x000070b92f71a000-0x000070b92f68b000 PROT_NONE
0x000070b92f71b000-0x000070b92f71a000 PROT_READ | PROT_WRITE
0x000070b92f7aa000-0x000070b92f71b000 PROT_NONE
0x000070b92f7ab000-0x000070b92f7aa000 PROT_READ | PROT_WRITE
0x000070b92f7da000-0x000070b92f7ab000 PROT_NONE
0x000070b92f7db000-0x000070b92f7da000 PROT_READ | PROT_WRITE
0x000070b92f80a000-0x000070b92f7db000 PROT_NONE
0x000070b92f80b000-0x000070b92f80a000 PROT_READ | PROT_WRITE
0x000070b92f89a000-0x000070b92f80b000 PROT_NONE
0x000070b92f89b000-0x000070b92f89a000 PROT_READ | PROT_WRITE
0x000070b92f8fa000-0x000070b92f89b000 PROT_NONE
0x000070b92f8fb000-0x000070b92f8fa000 PROT_READ | PROT_WRITE
0x000070b9311c7000-0x000070b92f8fb000 PROT_NONE
0x000070b93250e000-0x000070b9311c7000 PROT_NONE
0x000070b93250f000-0x000070b93250e000 PROT_READ | PROT_WRITE
0x000070b933753000-0x000070b93250f000 PROT_NONE
0x000070b933754000-0x000070b933753000 PROT_READ | PROT_WRITE
0x000070b933755000-0x000070b933754000 PROT_NONE
0x000070b933756000-0x000070b933755000 PROT_READ | PROT_WRITE
0x000070b933757000-0x000070b933756000 PROT_NONE
0x000070b933758000-0x000070b933757000 PROT_READ | PROT_WRITE
0x000070b933759000-0x000070b933758000 PROT_NONE
0x000070b93375a000-0x000070b933759000 PROT_READ | PROT_WRITE
0x000070b93375b000-0x000070b93375a000 PROT_NONE
0x000070b93375c000-0x000070b93375b000 PROT_READ | PROT_WRITE
0x000070b93375d000-0x000070b93375c000 PROT_NONE
0x000070b93375e000-0x000070b93375d000 PROT_READ | PROT_WRITE
0x000070b93375f000-0x000070b93375e000 PROT_NONE
0x000070b933760000-0x000070b93375f000 PROT_READ | PROT_WRITE
0x000070b933761000-0x000070b933760000 PROT_NONE
0x000070b933762000-0x000070b933761000 PROT_READ | PROT_WRITE
0x000070b933763000-0x000070b933762000 PROT_NONE
0x000070b933764000-0x000070b933763000 PROT_READ | PROT_WRITE
0x000070b933765000-0x000070b933764000 PROT_NONE
0x000070b933766000-0x000070b933765000 PROT_READ | PROT_WRITE
0x000070b933767000-0x000070b933766000 PROT_NONE
0x000070b933768000-0x000070b933767000 PROT_READ | PROT_WRITE
0x000070b933769000-0x000070b933768000 PROT_NONE
0x000070b93376a000-0x000070b933769000 PROT_READ | PROT_WRITE
0x000070b93376b000-0x000070b93376a000 PROT_NONE
0x000070b93376c000-0x000070b93376b000 PROT_READ | PROT_WRITE
0x000070b93376d000-0x000070b93376c000 PROT_NONE
0x000070b93376e000-0x000070b93376d000 PROT_READ | PROT_WRITE
0x000070b93376f000-0x000070b93376e000 PROT_NONE
0x000070b933770000-0x000070b93376f000 PROT_READ | PROT_WRITE
0x000070b933771000-0x000070b933770000 PROT_NONE
0x000070b933772000-0x000070b933771000 PROT_READ | PROT_WRITE
0x000070b933773000-0x000070b933772000 PROT_NONE
0x000070b933774000-0x000070b933773000 PROT_READ | PROT_WRITE
0x000070b933775000-0x000070b933774000 PROT_NONE
0x000070b933776000-0x000070b933775000 PROT_READ | PROT_WRITE
0x000070b933777000-0x000070b933776000 PROT_NONE
0x000070b933778000-0x000070b933777000 PROT_READ | PROT_WRITE
0x000070b933779000-0x000070b933778000 PROT_NONE
0x000070b93377a000-0x000070b933779000 PROT_READ | PROT_WRITE
0x000070b93377b000-0x000070b93377a000 PROT_NONE
0x000070b93377c000-0x000070b93377b000 PROT_READ | PROT_WRITE
0x000070b93377d000-0x000070b93377c000 PROT_NONE
0x000070b93377e000-0x000070b93377d000 PROT_READ | PROT_WRITE
0x000070b93377f000-0x000070b93377e000 PROT_NONE
0x000070b933780000-0x000070b93377f000 PROT_READ | PROT_WRITE
0x000070b933781000-0x000070b933780000 PROT_NONE
0x000070b933782000-0x000070b933781000 PROT_READ | PROT_WRITE
0x000070b933783000-0x000070b933782000 PROT_NONE
0x000070b933784000-0x000070b933783000 PROT_READ | PROT_WRITE
0x000070b933785000-0x000070b933784000 PROT_NONE
0x000070b933786000-0x000070b933785000 PROT_READ | PROT_WRITE
0x000070b933787000-0x000070b933786000 PROT_NONE
0x000070b933788000-0x000070b933787000 PROT_READ | PROT_WRITE
0x000070b933789000-0x000070b933788000 PROT_NONE
0x000070b93378a000-0x000070b933789000 PROT_READ | PROT_WRITE
0x000070b93378b000-0x000070b93378a000 PROT_NONE
0x000070b93378c000-0x000070b93378b000 PROT_READ | PROT_WRITE
0x000070b934404000-0x000070b93378c000 PROT_NONE
0x000070b934405000-0x000070b934404000 PROT_READ | PROT_WRITE
0x000070b934406000-0x000070b934405000 PROT_NONE
0x000070b934407000-0x000070b934406000 PROT_READ | PROT_WRITE
0x000070b934408000-0x000070b934407000 PROT_NONE
0x000070b934409000-0x000070b934408000 PROT_READ | PROT_WRITE
0x000070b935650000-0x000070b934409000 PROT_NONE
0x000070b935651000-0x000070b935650000 PROT_READ | PROT_WRITE
0x000070b9361da000-0x000070b935651000 PROT_NONE
0x000070b9361db000-0x000070b9361da000 PROT_READ | PROT_WRITE
0x000070b9375c3000-0x000070b9361db000 PROT_NONE
0x000070b9375c4000-0x000070b9375c3000 PROT_READ | PROT_WRITE
0x000070b9386d9000-0x000070b9375c4000 PROT_NONE
0x000070b9386da000-0x000070b9386d9000 PROT_READ | PROT_WRITE
0x000070b9392a4000-0x000070b9386da000 PROT_NONE
0x000070b9392a6000-0x000070b9392a4000 PROT_READ | PROT_WRITE
0x000070b93a6e8000-0x000070b9392a6000 PROT_NONE
0x000070b93a6ea000-0x000070b93a6e8000 PROT_READ | PROT_WRITE
0x000070b93b280000-0x000070b93a6ea000 PROT_NONE
0x000070b93b283000-0x000070b93b280000 PROT_READ | PROT_WRITE
0x000070b93c1e5000-0x000070b93b283000 PROT_NONE
0x000070b93c1e8000-0x000070b93c1e5000 PROT_READ | PROT_WRITE
0x000070b93e3a8000-0x000070b93c1e8000 PROT_NONE
0x000070b93e3ad000-0x000070b93e3a8000 PROT_READ | PROT_WRITE
0x000070b94186c000-0x000070b93e3ad000 PROT_NONE
0x000070b941874000-0x000070b94186c000 PROT_READ | PROT_WRITE
0x000070b94265e000-0x000070b941874000 PROT_NONE
0x000070b942668000-0x000070b94265e000 PROT_READ | PROT_WRITE
0x000070b943424000-0x000070b942668000 PROT_NONE
0x000070b943430000-0x000070b943424000 PROT_READ | PROT_WRITE
0x000070b9462b4000-0x000070b943430000 PROT_NONE
0x000070b9462b9000-0x000070b9462b4000 PROT_READ | PROT_WRITE
0x000070b949508000-0x000070b9462b9000 PROT_NONE
0x000070b949510000-0x000070b949508000 PROT_READ | PROT_WRITE
0x000070b94a807000-0x000070b949510000 PROT_NONE
0x000070b94a80c000-0x000070b94a807000 PROT_READ | PROT_WRITE
0x000070b94b5c7000-0x000070b94a80c000 PROT_NONE
0x000070b94b5cd000-0x000070b94b5c7000 PROT_READ | PROT_WRITE
0x000070b94e882000-0x000070b94b5cd000 PROT_NONE
0x000070b94e88c000-0x000070b94e882000 PROT_READ | PROT_WRITE
0x000070b94e896000-0x000070b94e88c000 PROT_NONE
0x000070b94e8a0000-0x000070b94e896000 PROT_READ | PROT_WRITE
0x000070b94e8aa000-0x000070b94e8a0000 PROT_NONE
0x000070b94e8b4000-0x000070b94e8aa000 PROT_READ | PROT_WRITE
0x000070b950769000-0x000070b94e8b4000 PROT_NONE
0x000070b950777000-0x000070b950769000 PROT_READ | PROT_WRITE
0x000070b9b51c7000-0x000070b950777000 PROT_NONE
0x000070b9b51ce000-0x000070b9b51c7000 PROT_NONE
0x000070b9b51e2000-0x000070b9b51ce000 PROT_READ | PROT_WRITE
0x000070b9b51e9000-0x000070b9b51e2000 PROT_NONE
0x000070b9b51ea000-0x000070b9b51e9000 PROT_NONE
0x000070b9b51ed000-0x000070b9b51ea000 PROT_NONE
0x000070b9b51ee000-0x000070b9b51ed000 PROT_NONE
0x000070b9b51ef000-0x000070b9b51ee000 PROT_NONE
0x000070b9b51f3000-0x000070b9b51ef000 PROT_READ | PROT_WRITE
0x000070b9b51f4000-0x000070b9b51f3000 PROT_NONE
0x000070b9b51f6000-0x000070b9b51f4000 PROT_NONE
0x000070b9b51fa000-0x000070b9b51f6000 PROT_READ | PROT_WRITE
0x000070b9b51fc000-0x000070b9b51fa000 PROT_NONE
0x000070b9b51fd000-0x000070b9b51fc000 PROT_NONE
0x000070b9b5201000-0x000070b9b51fd000 PROT_NONE
0x000070b9b5202000-0x000070b9b5201000 PROT_NONE
0x000070b9b5203000-0x000070b9b5202000 PROT_NONE
0x000070b9b5207000-0x000070b9b5203000 PROT_READ | PROT_WRITE
0x000070b9b5208000-0x000070b9b5207000 PROT_NONE
0x000070b9b520a000-0x000070b9b5208000 PROT_NONE
0x000070b9b520e000-0x000070b9b520a000 PROT_READ | PROT_WRITE
0x000070b9b5210000-0x000070b9b520e000 PROT_NONE
0x000070b9b5212000-0x000070b9b5210000 PROT_NONE
0x000070b9b5216000-0x000070b9b5212000 PROT_READ | PROT_WRITE
0x000070b9b5218000-0x000070b9b5216000 PROT_NONE
0x000070b9b521a000-0x000070b9b5218000 PROT_NONE
0x000070b9b521e000-0x000070b9b521a000 PROT_READ | PROT_WRITE
0x000070b9b5220000-0x000070b9b521e000 PROT_NONE
0x000070b9b5282000-0x000070b9b5220000 PROT_NONE
0x000070b9b52a4000-0x000070b9b5282000 PROT_NONE
0x000070b9b52be000-0x000070b9b52a4000 PROT_NONE
0x000070b9b52de000-0x000070b9b52be000 PROT_READ | PROT_WRITE
0x000070b9b52e8000-0x000070b9b52de000 PROT_NONE
*/
    unsigned long hardened_sizes[] =
    {
        0x000070b92f0fa000-0x000070b92eb1d000, 0x000070b92f329000-0x000070b92f0fa000, 0x000070b92f35a000-0x000070b92f329000, 0x000070b92f35b000-0x000070b92f35a000, 0x000070b92f38a000-0x000070b92f35b000, 0x000070b92f38c000-0x000070b92f38a000, 0x000070b92f3ba000-0x000070b92f38c000, 0x000070b92f3bb000-0x000070b92f3ba000, 0x000070b92f3ea000-0x000070b92f3bb000, 0x000070b92f3eb000-0x000070b92f3ea000, 0x000070b92f41a000-0x000070b92f3eb000, 0x000070b92f41b000-0x000070b92f41a000, 0x000070b92f44a000-0x000070b92f41b000, 0x000070b92f44b000-0x000070b92f44a000, 0x000070b92f47a000-0x000070b92f44b000, 0x000070b92f47b000-0x000070b92f47a000, 0x000070b92f4aa000-0x000070b92f47b000, 0x000070b92f4ab000-0x000070b92f4aa000, 0x000070b92f4da000-0x000070b92f4ab000, 0x000070b92f4db000-0x000070b92f4da000, 0x000070b92f50a000-0x000070b92f4db000, 0x000070b92f50b000-0x000070b92f50a000, 0x000070b92f53a000-0x000070b92f50b000, 0x000070b92f53b000-0x000070b92f53a000, 0x000070b92f59a000-0x000070b92f53b000, 0x000070b92f59b000-0x000070b92f59a000, 0x000070b92f62a000-0x000070b92f59b000, 0x000070b92f62b000-0x000070b92f62a000, 0x000070b92f65a000-0x000070b92f62b000, 0x000070b92f65b000-0x000070b92f65a000, 0x000070b92f68a000-0x000070b92f65b000, 0x000070b92f68b000-0x000070b92f68a000, 0x000070b92f71a000-0x000070b92f68b000, 0x000070b92f71b000-0x000070b92f71a000, 0x000070b92f7aa000-0x000070b92f71b000, 0x000070b92f7ab000-0x000070b92f7aa000, 0x000070b92f7da000-0x000070b92f7ab000, 0x000070b92f7db000-0x000070b92f7da000, 0x000070b92f80a000-0x000070b92f7db000, 0x000070b92f80b000-0x000070b92f80a000, 0x000070b92f89a000-0x000070b92f80b000, 0x000070b92f89b000-0x000070b92f89a000, 0x000070b92f8fa000-0x000070b92f89b000, 0x000070b92f8fb000-0x000070b92f8fa000, 0x000070b9311c7000-0x000070b92f8fb000, 0x000070b93250e000-0x000070b9311c7000, 0x000070b93250f000-0x000070b93250e000, 0x000070b933753000-0x000070b93250f000, 0x000070b933754000-0x000070b933753000, 0x000070b933755000-0x000070b933754000, 0x000070b933756000-0x000070b933755000, 0x000070b933757000-0x000070b933756000, 0x000070b933758000-0x000070b933757000, 0x000070b933759000-0x000070b933758000, 0x000070b93375a000-0x000070b933759000, 0x000070b93375b000-0x000070b93375a000, 0x000070b93375c000-0x000070b93375b000, 0x000070b93375d000-0x000070b93375c000, 0x000070b93375e000-0x000070b93375d000, 0x000070b93375f000-0x000070b93375e000, 0x000070b933760000-0x000070b93375f000, 0x000070b933761000-0x000070b933760000, 0x000070b933762000-0x000070b933761000, 0x000070b933763000-0x000070b933762000, 0x000070b933764000-0x000070b933763000, 0x000070b933765000-0x000070b933764000, 0x000070b933766000-0x000070b933765000, 0x000070b933767000-0x000070b933766000, 0x000070b933768000-0x000070b933767000, 0x000070b933769000-0x000070b933768000, 0x000070b93376a000-0x000070b933769000, 0x000070b93376b000-0x000070b93376a000, 0x000070b93376c000-0x000070b93376b000, 0x000070b93376d000-0x000070b93376c000, 0x000070b93376e000-0x000070b93376d000, 0x000070b93376f000-0x000070b93376e000, 0x000070b933770000-0x000070b93376f000, 0x000070b933771000-0x000070b933770000, 0x000070b933772000-0x000070b933771000, 0x000070b933773000-0x000070b933772000, 0x000070b933774000-0x000070b933773000, 0x000070b933775000-0x000070b933774000, 0x000070b933776000-0x000070b933775000, 0x000070b933777000-0x000070b933776000, 0x000070b933778000-0x000070b933777000, 0x000070b933779000-0x000070b933778000, 0x000070b93377a000-0x000070b933779000, 0x000070b93377b000-0x000070b93377a000, 0x000070b93377c000-0x000070b93377b000, 0x000070b93377d000-0x000070b93377c000, 0x000070b93377e000-0x000070b93377d000, 0x000070b93377f000-0x000070b93377e000, 0x000070b933780000-0x000070b93377f000, 0x000070b933781000-0x000070b933780000, 0x000070b933782000-0x000070b933781000, 0x000070b933783000-0x000070b933782000, 0x000070b933784000-0x000070b933783000, 0x000070b933785000-0x000070b933784000, 0x000070b933786000-0x000070b933785000, 0x000070b933787000-0x000070b933786000, 0x000070b933788000-0x000070b933787000, 0x000070b933789000-0x000070b933788000, 0x000070b93378a000-0x000070b933789000, 0x000070b93378b000-0x000070b93378a000, 0x000070b93378c000-0x000070b93378b000, 0x000070b934404000-0x000070b93378c000, 0x000070b934405000-0x000070b934404000, 0x000070b934406000-0x000070b934405000, 0x000070b934407000-0x000070b934406000, 0x000070b934408000-0x000070b934407000, 0x000070b934409000-0x000070b934408000, 0x000070b935650000-0x000070b934409000, 0x000070b935651000-0x000070b935650000, 0x000070b9361da000-0x000070b935651000, 0x000070b9361db000-0x000070b9361da000, 0x000070b9375c3000-0x000070b9361db000, 0x000070b9375c4000-0x000070b9375c3000, 0x000070b9386d9000-0x000070b9375c4000, 0x000070b9386da000-0x000070b9386d9000, 0x000070b9392a4000-0x000070b9386da000, 0x000070b9392a6000-0x000070b9392a4000, 0x000070b93a6e8000-0x000070b9392a6000, 0x000070b93a6ea000-0x000070b93a6e8000, 0x000070b93b280000-0x000070b93a6ea000, 0x000070b93b283000-0x000070b93b280000, 0x000070b93c1e5000-0x000070b93b283000, 0x000070b93c1e8000-0x000070b93c1e5000, 0x000070b93e3a8000-0x000070b93c1e8000, 0x000070b93e3ad000-0x000070b93e3a8000, 0x000070b94186c000-0x000070b93e3ad000, 0x000070b941874000-0x000070b94186c000, 0x000070b94265e000-0x000070b941874000, 0x000070b942668000-0x000070b94265e000, 0x000070b943424000-0x000070b942668000, 0x000070b943430000-0x000070b943424000, 0x000070b9462b4000-0x000070b943430000, 0x000070b9462b9000-0x000070b9462b4000, 0x000070b949508000-0x000070b9462b9000, 0x000070b949510000-0x000070b949508000, 0x000070b94a807000-0x000070b949510000, 0x000070b94a80c000-0x000070b94a807000, 0x000070b94b5c7000-0x000070b94a80c000, 0x000070b94b5cd000-0x000070b94b5c7000, 0x000070b94e882000-0x000070b94b5cd000, 0x000070b94e88c000-0x000070b94e882000, 0x000070b94e896000-0x000070b94e88c000, 0x000070b94e8a0000-0x000070b94e896000, 0x000070b94e8aa000-0x000070b94e8a0000, 0x000070b94e8b4000-0x000070b94e8aa000, 0x000070b950769000-0x000070b94e8b4000, 0x000070b950777000-0x000070b950769000, 0x000070b9b51c7000-0x000070b950777000, 0x000070b9b51ce000-0x000070b9b51c7000, 0x000070b9b51e2000-0x000070b9b51ce000, 0x000070b9b51e9000-0x000070b9b51e2000, 0x000070b9b51ea000-0x000070b9b51e9000, 0x000070b9b51ed000-0x000070b9b51ea000, 0x000070b9b51ee000-0x000070b9b51ed000, 0x000070b9b51ef000-0x000070b9b51ee000, 0x000070b9b51f3000-0x000070b9b51ef000, 0x000070b9b51f4000-0x000070b9b51f3000, 0x000070b9b51f6000-0x000070b9b51f4000, 0x000070b9b51fa000-0x000070b9b51f6000, 0x000070b9b51fc000-0x000070b9b51fa000, 0x000070b9b51fd000-0x000070b9b51fc000, 0x000070b9b5201000-0x000070b9b51fd000, 0x000070b9b5202000-0x000070b9b5201000, 0x000070b9b5203000-0x000070b9b5202000, 0x000070b9b5207000-0x000070b9b5203000, 0x000070b9b5208000-0x000070b9b5207000, 0x000070b9b520a000-0x000070b9b5208000, 0x000070b9b520e000-0x000070b9b520a000, 0x000070b9b5210000-0x000070b9b520e000, 0x000070b9b5212000-0x000070b9b5210000, 0x000070b9b5216000-0x000070b9b5212000, 0x000070b9b5218000-0x000070b9b5216000, 0x000070b9b521a000-0x000070b9b5218000, 0x000070b9b521e000-0x000070b9b521a000, 0x000070b9b5220000-0x000070b9b521e000, 0x000070b9b5282000-0x000070b9b5220000, 0x000070b9b52a4000-0x000070b9b5282000, 0x000070b9b52be000-0x000070b9b52a4000, 0x000070b9b52de000-0x000070b9b52be000, 0x000070b9b52e8000-0x000070b9b52de000
    };
    unsigned long hardened_protections[] = 
    {
        PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_NONE, PROT_READ | PROT_WRITE, PROT_NONE
    };
    void* hardened_mappings[sizeof(hardened_sizes)/sizeof(unsigned long)] = { (void*)0 };

    // int hardened_mappings[] = { 4096, 13344768, 2289664, 200704, 4096, 192512, 8192, 188416, 4096, 192512, 4096, 192512, 4096, 192512, 4096, 192512, 4096, 192512, 4096, 192512, 4096, 192512, 4096, 192512, 4096, 389120, 4096, 585728, 4096, 192512, 4096, 192512, 4096, 585728, 4096, 585728, 4096, 192512, 4096, 192512, 4096, 585728, 4096, 389120, 4096, 50659328, 4096, 19001344, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096, 19050496, 4096, 4096, 4096, 4096, 4096, 18075648, 4096, 15065088, 4096, 13672448, 4096, 18841600, 4096, 18481152, 8192, 11132928, 8192, 16916480, 12288, 21184512, 12288, 31055872, 20480, 48185344, 32768, 23642112, 40960, 12165120, 49152, 55746560, 20480, 43220992, 32768, 21635072, 20480, 18161664, 24576, 44240896, 40960, 40960, 40960, 40960, 40960, 39280640, 57344, 1687597056, 81920, 45056, 12288, 12288, 16384, 28672, 16384, 12288, 16384, 8192, 16384, 12288, 16384, 12288, 16384, 12288, 16384, 143360, 262144, 118784, 32768, 98304, 32768, 20480, 98304, 20480, 1310720, 1310720 };

    for (int hardened_i = 0; hardened_i < sizeof(hardened_sizes)/sizeof(unsigned long); hardened_i++)
        mp_size += hardened_sizes[hardened_i];
    mp_start = mmap(RANDOM_BASE, mp_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | 0x2000000, -1, 0);
    if (mp_start == MAP_FAILED)
    {
        printf(" Could not set up hardened mappings. errno: %d\n", errno);
        return -1;
    }

    mp_size = 0;
    for (int hardened_i = 0; hardened_i < sizeof(hardened_sizes)/sizeof(unsigned long); hardened_i++)
    {
        hardened_mappings[hardened_i] = mmap(mp_start + mp_size, hardened_sizes[hardened_i], hardened_protections[hardened_i], MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | 0x2000000, -1, 0);
        if (hardened_mappings[hardened_i] == MAP_FAILED)
        {
            printf(" Could not complete nginx mappings, failed on %d. errno: %d\n", hardened_i, errno);
            return -1;
        }
        mp_size += hardened_sizes[hardened_i];
        if (hardened_protections[hardened_i] & PROT_WRITE)
            for (int i = 0; i < hardened_sizes[hardened_i]; i+=4096)
                *(unsigned long*)(hardened_mappings[hardened_i] + i) = hardened_i;
    }
    
    RUN_ENTER_EXIT_LOOP(enter_exit_test();, time_taken)
    printf(">[nginx mappings hardened heap] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    if (mp_size)
        munmap(mp_start, mp_size);

/*
0x000046bd8cc7b000-0x000046bd8cc17000 PROT_READ | PROT_WRITE
0x000046bd8ccb6000-0x000046bd8cc7b000 PROT_READ | PROT_WRITE
0x000046bd8cdb6000-0x000046bd8ccb6000 PROT_READ | PROT_WRITE
0x000046bd8cdd6000-0x000046bd8cdb6000 PROT_READ | PROT_WRITE
*/
    unsigned long libc_sizes[] =
    {
        0x000046bd8cc7b000-0x000046bd8cc17000, 0x000046bd8ccb6000-0x000046bd8cc7b000, 0x000046bd8cdb6000-0x000046bd8ccb6000, 0x000046bd8cdd6000-0x000046bd8cdb6000
    };
    unsigned long libc_protections[] =
    {
        PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE
    };
    void* libc_mappings[sizeof(libc_sizes)/sizeof(unsigned long)] = { (void*)0 };

    mp_size = 0;
    for (int libc_i = 0; libc_i < sizeof(libc_sizes)/sizeof(unsigned long); libc_i++)
        mp_size += libc_sizes[libc_i];
    void* mp_start = mmap(RANDOM_BASE, mp_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | 0x2000000, -1, 0);
    if (mp_start == MAP_FAILED)
    {
        printf(" Could not set up libc mappings, size: %lx. errno: %d\n", mp_size, errno);
        return -1;
    }

    mp_size = 0;
    for (int libc_i = 0; libc_i < sizeof(libc_sizes)/sizeof(unsigned long); libc_i++)
    {
        libc_mappings[libc_i] = mmap(mp_start + mp_size, libc_sizes[libc_i], libc_protections[libc_i], MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | 0x2000000, -1, 0);
        if (libc_mappings[libc_i] == MAP_FAILED)
        {
            printf(" Could not complete libc mappings. errno: %d\n", errno);
            return -1;
        }
        mp_size+= libc_sizes[libc_i];
        if (libc_protections[libc_i] & PROT_WRITE)
            for (int i = 0; i < libc_sizes[libc_i]; i+=4096)
                *(unsigned long*)(libc_mappings[libc_i] + i) = libc_i;
    }

    RUN_ENTER_EXIT_LOOP(enter_exit_test();, time_taken)
    printf(">[libc mappings libc heap] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    if (mp_size)
        munmap(mp_start, mp_size);

    /*
    0x0000021ff28ba000-0x0000021ff28ad000 PROT_READ | PROT_WRITE
    0x0000021ff28c7000-0x0000021ff28ba000 PROT_READ | PROT_WRITE
    0x0000021ff28d4000-0x0000021ff28c7000 PROT_READ | PROT_WRITE
    0x0000021ff28e1000-0x0000021ff28d4000 PROT_READ | PROT_WRITE
    0x0000021ff28ee000-0x0000021ff28e1000 PROT_READ | PROT_WRITE
    0x0000021ff28fb000-0x0000021ff28ee000 PROT_READ | PROT_WRITE
    0x0000021ff2908000-0x0000021ff28fb000 PROT_READ | PROT_WRITE
    0x0000021ff2915000-0x0000021ff2908000 PROT_READ | PROT_WRITE
    0x0000021ff2922000-0x0000021ff2915000 PROT_READ | PROT_WRITE
    0x0000021ff295d000-0x0000021ff2922000 PROT_READ | PROT_WRITE
    0x0000021ff2976000-0x0000021ff295d000 PROT_READ | PROT_WRITE
    0x0000021ff298f000-0x0000021ff2976000 PROT_READ | PROT_WRITE
    0x0000021ff29af000-0x0000021ff298f000 PROT_READ | PROT_WRITE
    0x0000021ff29bc000-0x0000021ff29af000 PROT_READ | PROT_WRITE
    0x0000021ff29c9000-0x0000021ff29bc000 PROT_READ | PROT_WRITE
    */
    unsigned long pmvee_sizes[] = 
    {
        0x0000021ff28ba000-0x0000021ff28ad000,
        0x0000021ff28c7000-0x0000021ff28ba000,
        0x0000021ff28d4000-0x0000021ff28c7000,
        0x0000021ff28e1000-0x0000021ff28d4000,
        0x0000021ff28ee000-0x0000021ff28e1000,
        0x0000021ff28fb000-0x0000021ff28ee000,
        0x0000021ff2908000-0x0000021ff28fb000,
        0x0000021ff2915000-0x0000021ff2908000,
        0x0000021ff2922000-0x0000021ff2915000,
        0x0000021ff295d000-0x0000021ff2922000,
        0x0000021ff2976000-0x0000021ff295d000,
        0x0000021ff298f000-0x0000021ff2976000,
        0x0000021ff29af000-0x0000021ff298f000,
        0x0000021ff29bc000-0x0000021ff29af000,
        0x0000021ff29c9000-0x0000021ff29bc000
    };
    unsigned long pmvee_protections[] =
    {
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE,
        PROT_READ | PROT_WRITE
    };
    void* pmvee_mappings[sizeof(pmvee_sizes)/sizeof(unsigned long)] = { (void*)0 };

    mp_size = 0;
    for (int pmvee_i = 0; pmvee_i < sizeof(pmvee_sizes)/sizeof(unsigned long); pmvee_i++)
        mp_size += pmvee_sizes[pmvee_i];
    mp_start = mmap(RANDOM_BASE, mp_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | 0x2000000, -1, 0);
    if (mp_start == MAP_FAILED)
    {
        printf(" Could not set up pmvee mappings, size: %lx. errno: %d\n", mp_size, errno);
        return -1;
    }

    mp_size = 0;
    for (int pmvee_i = 0; pmvee_i < sizeof(pmvee_sizes)/sizeof(unsigned long); pmvee_i++)
    {
        pmvee_mappings[pmvee_i] = mmap(mp_start + mp_size, pmvee_sizes[pmvee_i], pmvee_protections[pmvee_i], MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | 0x2000000, -1, 0);
        if (pmvee_mappings[pmvee_i] == MAP_FAILED)
        {
            printf(" Could not complete pmvee mappings, failed on %d. errno: %d\n", pmvee_i, errno);
            return -1;
        }
        mp_size+= pmvee_sizes[pmvee_i];
        if (pmvee_protections[pmvee_i] & PROT_WRITE)
            for (int i = 0; i < pmvee_sizes[pmvee_i]; i+=4096)
                *(unsigned long*)(pmvee_mappings[pmvee_i] + i) = pmvee_i;
    }

    RUN_ENTER_EXIT_LOOP(enter_exit_test();, time_taken)
    printf(">[nginx mappings pmvee heap] > time elapsed: %ld us for %d iterations\n",
            time_taken,
            ITERATIONS);fflush(stdout);
    if (mp_size)
        munmap(mp_start, mp_size);

    return 0;
}
