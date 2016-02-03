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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include "md5.h"

FILE* testfile;

int main(int argc, char** argv)
{
    testfile = fopen("testfile.txt", "w+");

    for (int i = 0; i < 10*1024; ++i)
        fprintf(testfile, "%10d: Testing 123...\n", i);

    fclose(testfile);


    struct stat filestats;
    md5_context context;
    stat("testfile.txt", &filestats);

    printf("TestFile.txt - Size: %d bytes\n", (int)filestats.st_size);

    testfile = fopen("testfile.txt", "rb+");
    fseek(testfile, 0L, SEEK_SET);

    md5_starts(&context);
    int bytesread = 0;
    unsigned char buf[512];
    while (bytesread < (int)filestats.st_size)
    {
        int pos = ftell(testfile);
	int toread = (int)filestats.st_size - pos > 512 ? 512 : (int)filestats.st_size - pos;
//printf("pos: %d - toread: %d - bytesread: %d\n", pos, toread, bytesread);
        int read = fread(buf, sizeof(unsigned char), toread, testfile);

	if (read == -1)
		exit(1);
	bytesread += read;
        md5_update(&context, buf, toread*sizeof(unsigned char));
    }

    unsigned char hash[16];
    md5_finish(&context, hash);

    char hashstr[33];
    hashstr[32] = '\0';
    for (int i = 0; i < 16; ++i)
        sprintf(hashstr + i * 2, "%02X", hash[i]);

    printf("Hash: %s\n", hashstr);

    fclose(testfile);





    return 0;
}
