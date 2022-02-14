#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "definitions.h"


struct shm_t* shm_ptr = nullptr;


void public_disclosure ()
{
    printf(" > What you say.\n");
}


void private_disclosure ()
{
    printf(" > What you think.\n");
}


void example()
{
    // write our pointer to shared memory
    printf(" > writing pointer to shared memory.\n");
    shm_ptr->ptr = &public_disclosure;

    // allow external to change pointer
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

    // consume pointer
    printf(" > Consuming pointer from shared memory.\n");
    shm_ptr->ptr();
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

    shm_ptr = (struct shm_t*) 
            mmap(nullptr, sizeof(struct shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED)
    {
        printf(" > MVEE protected part could not mmap shared memory. - errno: %d\n", errno);
        return errno;
    }
    memset(&shm_ptr->ptr, 0, sizeof(void*));
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


    printf(" > MVEE protexted part finished. \n");
    return 0;
}