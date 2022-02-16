#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "definitions.h"


struct shm_t* shm_ptr = nullptr;
unsigned long long ROP_CHAIN[] = { 0, 0, 0, 0, 0, 0, 0, 5, 20, 30, 34, 38, 46 };


void example()
{
    // wait for pointer to be written
    printf(" > Waiting on MVEE protected.");
    if (sem_wait(&shm_ptr->sem2) == -1)
    {
        printf(" > External part could not wait on semaphore 2. - errno: %d\n", errno);
        return;
    }

    // set up rop chain
    printf(" > Setting up ROP chain.\n");
    unsigned long long base_ptr = (unsigned long)shm_ptr->chain[0];
    for (int rop_i = 0; rop_i < MVEE_CHAIN_SIZE; rop_i++)
        shm_ptr->chain[rop_i] = (void*) (base_ptr + ROP_CHAIN[rop_i]);
    shm_ptr->chain_size = MVEE_CHAIN_SIZE;
        
    // launch rop
    printf(" > Notifying MVEE protected.\n");
    if (sem_post(&shm_ptr->sem1) == -1)
    {
        printf(" > External part could not post on semaphore 1. - errno: %d\n", errno);
        return;
    }
}

int main ()
{    
    // set up shared memory
    // https://man7.org/linux/man-pages/man3/shm_open.3.html
    int shm_fd = shm_open(MVEE_SHM_NAME, O_RDWR, S_IRUSR | S_IWUSR);
    if (shm_fd == -1)
    {
        printf(" > External part could not acquire shared memory fd. - errno: %d\n", errno);
        return errno;
    }

    shm_ptr = (struct shm_t*) 
            mmap(nullptr, sizeof(struct shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED)
    {
        printf(" > External part could not mmap shared memory. - errno: %d\n", errno);
        return errno;
    }

    example();

    // clean up shared memory
    shm_unlink(MVEE_SHM_NAME);
    munmap(shm_ptr, sizeof(struct shm_t));


    printf(" > External part finished. \n");
    return 0;
}