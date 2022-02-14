#ifndef MVEE_DEFINITIONS_H
#define MVEE_DEFINITIONS_H

#define MVEE_SHM_NAME         "mvee_shm_security_test_2"
#define MVEE_BUFFER_SIZE      1024
#define MVEE_SHM_MESSAGE_SIZE MVEE_BUFFER_SIZE * 2
#define PUBLIC_CONTENT        "Everyone can know this"
#define PRIVATE_CONTENT       "This should be hidden"

#ifndef ENCRYPTION_KEY
#define ENCRYPTION_KEY 0x1234567812345678
#endif
#ifndef LEAKED_KEY
#define LEAKED_KEY 0x1234567812345678
#endif

#include <semaphore.h>
struct shm_t
{
    char          message[MVEE_SHM_MESSAGE_SIZE];
    unsigned long message_length;
    sem_t         sem1;
    sem_t         sem2;
};

#endif