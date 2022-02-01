#include <chrono>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>


#define MAX_DATA_SIZE     4096*16
#define SHM_TEST_COUNT    100000
static unsigned long long SIZES_ARRAY[] = 
{
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    1024,
    2048,
    4096,
    4096*2,
    4096*4,
    4096*8,
    4096*16,
};
static int SIZES_ARRAY_SIZE = sizeof(SIZES_ARRAY) / sizeof(unsigned long long);

__uint8_t* input_data;
__uint8_t* output_data;

#define ERROR(__error, __message)                                   \
if (__error)                                                        \
{                                                                   \
    printf(" > benchmark terminated: %s - %d\n", __message, errno); \
    exit(1);                                                        \
}

int main()
{
    // data setup ------------------------------------------------------------------------------------------------------
    input_data = (__uint8_t*)mmap(nullptr, MAX_DATA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ERROR(input_data == MAP_FAILED, "failed to allocate input data")
    for (int i = 0; i < MAX_DATA_SIZE; i++)
        input_data[i] = i&0xff;

    output_data = (__uint8_t*)mmap(nullptr, MAX_DATA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ERROR(output_data == MAP_FAILED, "failed to allocate output data")
    // data setup ------------------------------------------------------------------------------------------------------

    // shm benchmark setup ---------------------------------------------------------------------------------------------
    int shmid = shmget(IPC_PRIVATE, MAX_DATA_SIZE, IPC_CREAT | 0666);
    ERROR(shmid == -1, "failed to set up SysV IPC")
    void* shm_addr = shmat(shmid, nullptr, 0);
    ERROR(shm_addr == MAP_FAILED, "failed to map up SysV IPC")
    // shm benchmark setup ---------------------------------------------------------------------------------------------
    for (int size_i = 0; size_i < SIZES_ARRAY_SIZE; size_i++)
    {
        unsigned long long size = SIZES_ARRAY[size_i];
        
        auto start = std::chrono::high_resolution_clock::now();
        for (int cnt_i = 0; cnt_i < SHM_TEST_COUNT; cnt_i++)
            memcpy(shm_addr, input_data, size);
        auto end = std::chrono::high_resolution_clock::now();
        float result = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        printf("\t> %llu: %f ns\n", size, result / SHM_TEST_COUNT);
    }
    return 0;
}