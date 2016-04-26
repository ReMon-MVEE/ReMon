/*
 * bandwidth 0.22, a benchmark to estimate memory transfer bandwidth.
 * Copyright (C) 2005-2010 by Zack T Smith.
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

/*=============================================================================
    This is a simple memory bandwidth test. The test sequentially reads out a
    64MB buffer and discards the results. The reading code is SSE2 enhanced.

    Source: Zack Smith (fbui@comcast.net)
    http://home.comcast.net/~fbui/bandwidth.html
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

extern int ReaderSSE2 (void *ptr, unsigned long, unsigned long);
extern int RandomReaderSSE2 (unsigned long **ptr, unsigned long, unsigned long);

double
do_read (unsigned long size, int random, int loops)
{
	unsigned long long total_count = 0;
	unsigned long t0, diff=0;
	unsigned char *chunk;
	unsigned char *chunk0;
	unsigned long tmp;
	unsigned long **chunk_ptrs = NULL;

	if (size & 255)
		error ("do_read(): chunk size is not multiple of 256.");

	//-------------------------------------------------
	chunk0 = chunk = malloc (size+32);
	if (!chunk)
		error ("Out of memory");

	memset (chunk, 0, size);

	tmp = (unsigned long) chunk;
	if (tmp & 15) {
		tmp -= (tmp & 15);
		tmp += 16;
		chunk = (unsigned char*) tmp;
	}

	//----------------------------------------
	// Set up random pointers to chunks.
	//
	if (random) {
		int tmp = size/256;
		chunk_ptrs = (unsigned long**) malloc (sizeof (unsigned long*) * tmp);
		if (!chunk_ptrs)
			error ("Out of memory.");

		//----------------------------------------
		// Store pointers to all chunks into array.
		//
		int i;
		for (i = 0; i < tmp; i++) {
			chunk_ptrs [i] = (unsigned long*) (chunk + 256 * i);
		}

		//----------------------------------------
		// Randomize the array of chunk pointers.
		//
		int k = 100;
		while (k--) {
			for (i = 0; i < tmp; i++) {
				int j = rand() % tmp;
				if (i != j) {
					unsigned long *ptr = chunk_ptrs [i];
					chunk_ptrs [i] = chunk_ptrs [j];
					chunk_ptrs [j] = ptr;
				}
			}
		}
	}

        struct timeval tv;
        double starttime, endtime;
        gettimeofday(&tv, NULL);
        starttime = tv.tv_sec + tv.tv_usec / 1000000.0;

	if (random)
		RandomReaderSSE2 (chunk_ptrs, size/256, loops);
	else
		ReaderSSE2 (chunk, size, loops);

        gettimeofday(&tv, NULL);
        endtime = tv.tv_sec + tv.tv_usec /  1000000.0;

	free (chunk0);

	if (chunk_ptrs)
		free (chunk_ptrs);

	return endtime - starttime;
}

int main(int argc, char** argv)
{
    int bufsize = 64*1024*1024;
    int loops;
    double duration;
    int random = 0;

    if (argc > 1 && atoi(argv[1]) == 1)
    {
        random = 1;
        loops = 1000;
    }
    else
    {
        loops = 1000;
    }

    duration = do_read(bufsize, random, loops);

    if (random)
        printf("Done! Memory Bandwidth = %f MB/sec (Random Reading)\n", bufsize / 1024 / 1024 / (duration) * loops);
    else
        printf("Done! Memory Bandwidth = %f MB/sec (Sequential Reading)\n", bufsize / 1024 / 1024 / (duration) * loops);

    return 0;
}
