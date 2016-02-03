/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2014 Stijn Volckaert, Ghent University 
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

/*=============================================================================
    This program creates a new thread and calls system() in that thread to
    execute ls. It can be used to test if the monitor correctly handles forks/
    executing other programs.
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void* thread_func(void* param)
{
    system("ls");
    return NULL;
}

int main(int argc, char *argv[])
{
    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);
    return 0;
}
