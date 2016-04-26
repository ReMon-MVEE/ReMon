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
