#include <chrono>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>
#include <string.h>
#include <stdio.h>
#include <cstdarg>


#ifndef TEST_COUNT
  #define TEST_COUNT                        10000000
#endif


#define logf                                logging::log
#ifndef LOG_FILE
  #define LOG_FILE                          "./shm_micros.out"
#endif
namespace logging
{
    static FILE*
            log_file;

    void        log                                         (const char* format, ...)
    {
        va_list va;
        va_start(va, format);
        printf(" > ");
        vfprintf(stdout, format, va);
        printf("\n");
        va_end(va);

#ifdef LOG_FILE
        if (logging::log_file)
        {
            va_list file_va;
            va_start(file_va, format);
            fprintf(logging::log_file, " > ");
            vfprintf(logging::log_file, format, file_va);
            printf("\n");
            va_end(file_va);
        }
#endif
    }
}


#ifdef SHM_MICRO_MEMCPY
#define TEST(__to, __from, __size, __which)                                                                            \
result = 0;                                                                                                            \
auto start = std::chrono::high_resolution_clock::now();                                                                \
for (int iteration = 0; iteration < TEST_COUNT; iteration++)                                                           \
    memcpy(__to, __from, __size);                                                                                      \
auto end = std::chrono::high_resolution_clock::now();                                                                  \
result = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();                                    \
logf("result for %s: %d bytes: %fns / memcpy", __which, __size, result / TEST_COUNT);
#elif defined(SHM_MICRO_MEMMOVE)
#define TEST(__to, __from, __size, __which)                                                                            \
result = 0;                                                                                                            \
auto start = std::chrono::high_resolution_clock::now();                                                                \
for (int iteration = 0; iteration < TEST_COUNT; iteration++)                                                           \
    memmove(__to, __from, __size);                                                                                     \
auto end = std::chrono::high_resolution_clock::now();                                                                  \
result = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();                                    \
logf("result for %s: %d bytes: %fns / memmove", __which, __size, result / TEST_COUNT);
#elif defined(SHM_MICRO_MEMSET)
#define TEST(__to, __from, __size, __which)                                                                            \
result = 0;                                                                                                            \
auto start = std::chrono::high_resolution_clock::now();                                                                \
for (int iteration = 0; iteration < TEST_COUNT; iteration++)                                                           \
    memset(__to, __from, __size);                                                                                      \
auto end = std::chrono::high_resolution_clock::now();                                                                  \
result = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();                                    \
logf("result for %s: %d bytes: %fns / memset", __which, __size, result / TEST_COUNT);
#else
#error "either SHM_MICRO_MEMCPY, SHM_MICRO_MEMMOVE, or SHM_MICRO_MEMCPY should be defined"
#endif


#define TEST_SIZE                         4096 * 16
static int SIZES_ARRAY[] = {
    1,
    2,
    4,
    8,
    32,
    64,
    128,
    512,
    1024,
    2048,
    4096,
    4096 * 2,
    4096 * 4,
    4096 * 8,
    4096 * 16,
};
static int SIZES_ARRAY_SIZE = sizeof(SIZES_ARRAY) / sizeof(int);


int main()
{
    logf("setting up mappings...");
    int first_memfd_shared = memfd_create("shared test", 0);
    if (first_memfd_shared < 0)
    {
        logf("failed to create memfd for first shared mapping");
        return -1;
    }
    if (ftruncate(first_memfd_shared, TEST_SIZE) < 0)
    {
        logf("failed to truncate memfd for first shared mapping");
        return -1;
    }
    void* first_shared_mapping = mmap(nullptr, TEST_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                                first_memfd_shared, 0);
    if (first_shared_mapping == MAP_FAILED)
    {
        logf("failed to set up first shared mapping");
        return -1;
    }
    close(first_memfd_shared);
    logf("first shared mapping set up!");

#ifndef SHM_MICRO_MEMSET
    int second_memfd_shared = memfd_create("shared test", 0);
    if (second_memfd_shared < 0)
    {
        logf("failed to create memfd for second shared mapping");
        return -1;
    }
    if (ftruncate(second_memfd_shared, TEST_SIZE) < 0)
    {
        logf("failed to truncate memfd for second shared mapping");
        return -1;
    }
    void* second_shared_mapping = mmap(nullptr, TEST_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                                second_memfd_shared, 0);
    if (second_shared_mapping == MAP_FAILED)
    {
        logf("failed to set up second shared mapping");
        return -1;
    }
    close(second_memfd_shared);
    logf("second shared mapping set up!");
#endif

    void* first_private_mapping = mmap(nullptr, TEST_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,-1, 0);
    if (first_private_mapping == MAP_FAILED)
    {
        logf("failed to set up private mapping");
        return -1;
    }
    logf("first private mapping set up!");

#ifndef SHM_MICRO_MEMSET
    void* second_private_mapping = mmap(nullptr, TEST_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,-1, 0);
    if (second_private_mapping == MAP_FAILED)
    {
        logf("failed to set up private mapping");
        return -1;
    }
    logf("private mapping set up!");
#endif

    logf("mappings set up!");


    logf("starting micro benchmark...");
    logf("iterations:%d", TEST_COUNT);
    float result = 0;

#ifdef SHM_MICRO_MEMSET
    for (int size = 0; size < SIZES_ARRAY_SIZE; size++)
    {
        TEST(first_shared_mapping, 0xff, SIZES_ARRAY[size], "to shared")
    }

    for (int size = 0; size < SIZES_ARRAY_SIZE; size++)
    {
        TEST(first_private_mapping, 0xff, SIZES_ARRAY[size], "to private")
    }
#else
    for (int size = 0; size < SIZES_ARRAY_SIZE; size++)
    {
        memset(first_shared_mapping, 0x11, TEST_SIZE);
        memset(second_private_mapping, 0x44, TEST_SIZE);

        TEST(first_shared_mapping, second_private_mapping, SIZES_ARRAY[size], "private to shared")
    }

    for (int size = 0; size < SIZES_ARRAY_SIZE; size++)
    {
        memset(second_shared_mapping, 0x22, TEST_SIZE);
        memset(first_private_mapping, 0x33, TEST_SIZE);

        TEST(first_private_mapping, second_shared_mapping, SIZES_ARRAY[size], "shared to private")
    }

    for (int size = 0; size < SIZES_ARRAY_SIZE; size++)
    {
        memset(first_shared_mapping, 0x11, TEST_SIZE);
        memset(second_shared_mapping, 0x22, TEST_SIZE);

        TEST(first_shared_mapping, second_shared_mapping, SIZES_ARRAY[size], "shared to shared")
    }

    for (int size = 0; size < SIZES_ARRAY_SIZE; size++)
    {
        memset(first_private_mapping, 0x33, TEST_SIZE);
        memset(second_private_mapping, 0x44, TEST_SIZE);

        TEST(first_private_mapping, second_private_mapping, SIZES_ARRAY[size], "private to private")
    }
#endif

    return 0;
}