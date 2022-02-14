#ifndef MVEE_DEFINITIONS_H
#define MVEE_DEFINITIONS_H

#define MVEE_SHM_NAME   "mvee_shm_security_test_4"
#define MVEE_CHAIN_SIZE 5 + 2 + 7

#include <semaphore.h>
struct shm_t
{
    void*  chain[MVEE_CHAIN_SIZE];
    size_t chain_size;
    sem_t  sem1;
    sem_t  sem2;
};

#endif