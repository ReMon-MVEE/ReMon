/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly initializes stat
    struct buffers passed to the stat function, to prevent mismatches caused by
    uninitialized padding (see libc_interposer.cpp). During execution of this
    program in the MVEE, no mismatches should occur.
=============================================================================*/

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

// prints the contents of memory in hex and ascii.
// starts at the location of the pointer "start"
// prints "length" bytes of memory.
// source: http://mypieceoftheinter.net/archives/1749
void Print_Memory(const unsigned char * start, unsigned int length)
{
    //create row, col, and i.  Set i to 0
    int row, col, i = 0;
    //iterate through the rows, which will be 16 bytes of memory wide
    for(row = 0; (i + 1) < length; row++)
    {
        //print hex representation
        for(col = 0; col<16; col++)
        {
            //calculate the current index
            i = row*16+col;
            //divides a row of 16 into two columns of 8
            if(col==8)
                printf(" ");
            //print the hex value if the current index is in range.
            if(i<length)
                printf("%02X", start[i]);
            //print a blank if the current index is past the end
            else
                printf("  ");
            //print a space to keep the values separate
            printf(" ");
        }
        //create a vertial seperator between hex and ascii representations
        printf(" ");
        //print ascii representation
        for(col = 0; col<16; col++)
        {
            //calculate the current index
            i = row*16+col;
            //divides a row of 16 into two coumns of 8
            if(col==8)
                printf("  ");
            //print the value if it is in range
            if(i<length)
            {
                //print the ascii value if applicable
                if(start[i]>0x20 && start[i]<0x7F)  //A-Z
                    printf("%c", start[i]);
                //print a period if the value is not printable
                else
                    printf(".");
            }
            //nothing else to print, so break out of this for loop
            else
                break;
        }
        //create a new row
        printf("\n");
    }
}

int
main(int argc, char *argv[])
{
    struct stat sb;

    if (argc != 2) {
	fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if (stat(argv[1], &sb) == -1) {
	perror("stat");
	exit(EXIT_FAILURE);
    }

    printf("File type:                ");

    switch (sb.st_mode & S_IFMT) {
    case S_IFBLK:  printf("block device\n");            break;
    case S_IFCHR:  printf("character device\n");        break;
    case S_IFDIR:  printf("directory\n");               break;
    case S_IFIFO:  printf("FIFO/pipe\n");               break;
    case S_IFLNK:  printf("symlink\n");                 break;
    case S_IFREG:  printf("regular file\n");            break;
    case S_IFSOCK: printf("socket\n");                  break;
    default:       printf("unknown?\n");                break;
    }

    printf("I-node number:            %ld\n", (long) sb.st_ino);

    printf("Mode:                     %lo (octal)\n",
	    (unsigned long) sb.st_mode);

    printf("Link count:               %ld\n", (long) sb.st_nlink);
    printf("Ownership:                UID=%ld   GID=%ld\n",
	    (long) sb.st_uid, (long) sb.st_gid);

    printf("Preferred I/O block size: %ld bytes\n",
	    (long) sb.st_blksize);
    printf("File size:                %lld bytes\n",
	    (long long) sb.st_size);
    printf("Blocks allocated:         %lld\n",
	    (long long) sb.st_blocks);

    printf("Last status change:       %s", ctime(&sb.st_ctime));
    printf("Last file access:         %s", ctime(&sb.st_atime));
    printf("Last file modification:   %s", ctime(&sb.st_mtime));

    Print_Memory((unsigned char*)&sb, sizeof(struct stat));

    exit(EXIT_SUCCESS);
}