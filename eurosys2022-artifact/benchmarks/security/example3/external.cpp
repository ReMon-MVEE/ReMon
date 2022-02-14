#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "definitions.h"


struct shm_t* shm_ptr;


void example()
{
    // wait for pointer to be written
    printf(" > Waiting on MVEE protected.\n");
    if (sem_wait(&shm_ptr->sem2) == -1)
    {
        printf(" > External part could not wait on semaphore 1. - errno: %d\n", errno);
        return;
    }

    // update pointer in shared memory
    printf(" > Updating pointer in shared memory.\n");
    *(unsigned long*)&shm_ptr->ptr += MVEE_EXTERNAL_PUBLIC_PRIVATE_OFFSET;

    // allow pointer to be consumed
    printf(" > Notifying external.\n");
    if (sem_post(&shm_ptr->sem1) == -1)
    {
        printf(" > External part could not post on semaphore 2. - errno: %d\n", errno);
        return;
    }
}


int main()
{    // set up shared memory
    // https://man7.org/linux/man-pages/man3/shm_open.3.html
    int shm_fd = shm_open(MVEE_SHM_NAME, O_RDWR, S_IRUSR | S_IWUSR);
    if (shm_fd == -1)
    {
        printf(" > External part could not acquire shared memory fd. - errno: %d\n", errno);
        return errno;
    }

    shm_ptr = (struct shm_t*) mmap(nullptr, sizeof(struct shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED)
    {
        printf(" > External part could not mmap shared memory. - errno: %d\n", errno);
        shm_unlink(MVEE_SHM_NAME);
        return errno;
    }

    example();

    // clean up shared memory
    shm_unlink(MVEE_SHM_NAME);
    munmap(shm_ptr, sizeof(struct shm_t));


    printf(" > External part finished.\n");
    return 0;
}