/*
 * Multi Variant Execution Environment PoC
 * Copyright (C) 2010 Stijn Volckaert <stijnv@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define MAXTHREADS 10

int* nums;

void* thread_func(void* param)
{
  //    int max = 0x3FFF;
  int max = 0x3FF;
    for (int i = 0; i < max; ++i)
    {
        for (int j = 0; j < max; ++j)
        {
            *(int*)nums = i*j;
        }
    }
    return NULL;
}

int main(int argc, char** argv)
{
    printf("Initializing TestApp13\n");
    int i = 0;
    pthread_t threads[MAXTHREADS];
    nums = new int[MAXTHREADS];

    for (i = 0; i < MAXTHREADS; ++i)
    {
        printf("Creating Thread %d...\n",i);
        nums[i] = i;
        pthread_create( &threads[i], NULL, thread_func, &nums[i] );
    }

    for (i = 0; i < MAXTHREADS; ++i)
    {
        printf("Joining Thread %d...\n",i);
        pthread_join( threads[i], NULL );
    }

    printf("ALL DONE!\n");

    return 0;
}
