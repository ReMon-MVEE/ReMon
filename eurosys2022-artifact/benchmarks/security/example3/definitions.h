#ifndef MVEE_DEFINITIONS_H
#define MVEE_DEFINITIONS_H

#define MVEE_SHM_NAME                       "mvee_shm_security_test_3"
#define MVEE_EXTERNAL_PUBLIC_PRIVATE_OFFSET 32

#include <semaphore.h>
struct shm_t
{
    void  (*ptr) ();
    sem_t sem1;
    sem_t sem2;
};

#endif