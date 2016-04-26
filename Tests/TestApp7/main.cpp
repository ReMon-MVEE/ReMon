/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <asm/unistd_32.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static unsigned long next = 1;
/* RAND_MAX assumed to be 32767 */
int myrand(void)
{
    next = next * 1103515245 + 12345;
    return((unsigned)(next/65536) % 32768);
}
void mysrand(unsigned seed)
{
    next = seed;
}

// arg struct for old_mmap syscall, see linux/syscalls.h
struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

int main (int argc, char *argv[])
{
printf("bleh\n");
    // try to map a shared memory page with the old mmap syscall
    struct mmap_arg_struct args = { 0 };
    args.addr = NULL;
    args.fd = -1;
    args.flags = MAP_SHARED | MAP_ANONYMOUS;
    args.len = 4096;
    args.offset = 0;
    args.prot = PROT_READ | PROT_WRITE;
    int res = syscall(__NR_mmap, &args);
    char* bleh;
//    printf("old_mmap result: 0x%08X\n", res);
    if ((void*)res == MAP_FAILED)
    perror("old_mmap");

printf("mmap success\n");
printf("trying to write\n");
bleh = (char*)res;
    bleh[0] = bleh[1000] = '\0';

printf("write success");

    if (res > -1 || res < -4095)
    {
      if (munmap ((void*)res, 4096) == -1)
        perror ("munmap");
    }

printf("testing sysv\n");
int shm_id = shmget(IPC_PRIVATE, 128*4096, IPC_CREAT | S_IRUSR | S_IWUSR);
char* blablabla = (char*)shmat(shm_id, NULL, 0);
blablabla[564] = blablabla[0] = '\0';
printf("done!\n");

    // try to map a shared memory page with the regular mmap
    res = (int)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
//    printf("mmap2 result: 0x%08X\n", res);
    if ((void*)res == MAP_FAILED)
    perror("mmap2");

bleh = (char*)res;
bleh[0] = bleh[1] = '\0';
printf("mmap 2 success\n");

    if (res > -1 || res < -4095)
    {
      if (munmap ((void*)res, 4096) == -1)
        perror ("munmap");
    }


    // try to map a file shared
    struct stat sb;
    off_t len;
    char *p;
    int fd;

    fd = open ("/home/stijn/thesistim/TestApp7/bin/Debug/mmaptest", O_RDWR);
    if (fd == -1) {
          perror ("open");
          return 1;
    }

    if (fstat (fd, &sb) == -1) {
          perror ("fstat");
          return 1;
    }

    if (!S_ISREG (sb.st_mode)) {
          fprintf (stderr, "%s is not a file\n", argv[1]);
          return 1;
    }

printf("mmaping fd: %d - size: %d\n", fd, sb.st_size);

    p = (char*)mmap (NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
          perror ("mmap");
          return 1;
    }

    if (close (fd) == -1) {
          perror ("close");
          return 1;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    mysrand(tv.tv_usec);

    char temp = myrand();

    for (len = 0; len < sb.st_size; len++)
          p[len] = temp;

    if (munmap (p, sb.st_size) == -1) {
          perror ("munmap");
          return 1;
    }

    printf("LAWL\n");

    return 0;
}
