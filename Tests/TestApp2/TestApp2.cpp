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


//struct stat {
//    dev_t     st_dev;     /* ID of device containing file */
//    ino_t     st_ino;     /* inode number */
//    mode_t    st_mode;    /* protection */
//    nlink_t   st_nlink;   /* number of hard links */
//    uid_t     st_uid;     /* user ID of owner */
//    gid_t     st_gid;     /* group ID of owner */
//    dev_t     st_rdev;    /* device ID (if special file) */
//    off_t     st_size;    /* total size, in bytes */
//    blksize_t st_blksize; /* blocksize for filesystem I/O */
//    blkcnt_t  st_blocks;  /* number of blocks allocated */
//    time_t    st_atime;   /* time of last access */
//    time_t    st_mtime;   /* time of last modification */
//    time_t    st_ctime;   /* time of last status change */
//};

static unsigned long next = 1;
/* RAND_MAX assumed to be 32767 */
int myrand(void) {
    next = next * 1103515245 + 12345;
    return((unsigned)(next/65536) % 32768);
}
void mysrand(unsigned seed) {
    printf("Init RNG Seed: %d\n", seed);
    next = seed;
}


int main(int argc, char** argv)
{
  /*    testfile = fopen("testfile.txt", "rw+");

    for (int i = 0; i < 10240000; ++i)
        fprintf(testfile, "%05d: Testing 123...\n", i);

	fclose(testfile);*/


    struct stat filestats;
    md5_context context;
    stat("testfile.txt", &filestats);

    printf("TestFile.txt - Size: %d bytes\n", (int)filestats.st_size);

    testfile = fopen("testfile.txt", "rwb");

    struct timeval tv;
    gettimeofday(&tv, NULL);
    mysrand(tv.tv_usec);

    md5_starts(&context);
    int tmp;
    int j;
    for (int i = 0; i < 1000; ++i)
    {
        //j = (int) ((int)filestats.st_size / sizeof(int) * (rand() / (RAND_MAX + 1.0)));

        //printf("Rand() = %d\n", myrand());

        j = myrand() * (unsigned int)filestats.st_size / 32767;

        fseek(testfile, j, SEEK_SET);

        fread(&tmp, 1, sizeof(int), testfile);
        md5_update(&context, (unsigned char*)&tmp, sizeof(int));
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
