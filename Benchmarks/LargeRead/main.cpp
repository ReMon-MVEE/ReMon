/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program reads a file of 1.25 MB into memory and can be used to
    benchmark the reading/writing of child buffers by the monitor.
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#define FILESIZE    1280 * 1024

void* thread_func(void* param)
{
    int fd = (int)param;
    void* data = malloc(FILESIZE);
    if (read(fd, data, FILESIZE) == -1)
        printf("fail: %d (%s)\n", errno, strerror(errno));
    free(data);
    return NULL;
}

int main(int argc, char** argv)
{
    int fd = open("testfile", 0);
    if (fd == -1)
        printf("fail: %d (%s)\n", errno, strerror(errno));
    void* data = malloc(FILESIZE);
    if (read(fd, data, FILESIZE) == -1)
        printf("fail: %d (%s)\n", errno, strerror(errno));
//    pthread_t thread;
//    pthread_create(&thread, NULL, thread_func, (void*)fd);
//    pthread_join(thread, NULL);
    free(data);
    fsync(fd);
    close(fd);
}
