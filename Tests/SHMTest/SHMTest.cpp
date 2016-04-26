/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor prevents the children from
    using System V Shared Memory (shmget/shmat/shmctl).

    It can also be used to test if the monitor prevents the children from making
    the injected memcpy code writeable again. To do so, execute this program in
    the MVEE. When the program asks for the memcpy address, get this address
    from the MVEE log file and enter it. The subsequent mprotect call should
    fail.
=============================================================================*/

#include <iostream>
#include <stdio.h>
#include <sys/shm.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
    int shmid;
    std::cout << "Enter shmid:";
    std::cin >> shmid;
    void* address = shmat(shmid, NULL, 0);
    if (address == (void*)-1)
        printf("shmat failed: %d (%s)\n", errno, strerror(errno));
    else
    {
        printf("shmat succeeded: 0x%08X\n", address);
        shmdt(address);
    }
    if (shmctl(shmid, IPC_RMID, NULL) == -1)
        printf("shmctl failed: %d (%s)\n", errno, strerror(errno));
    else
    {
        printf("shmctl succeeded: 0x%08X\n", address);
        shmdt(address);
    }
    std::cout << "Enter memcpy address:";
    std::cin >> std::hex >> address;
    if (mprotect((void*)((int)address - 4096), 4097, PROT_WRITE) == 0)
        std::cout << "mprotect succeeded." << std::endl;
    else
        std::cout << "mprotect failed." << std::endl;

    std::cout << "Done." << std::endl;
}
