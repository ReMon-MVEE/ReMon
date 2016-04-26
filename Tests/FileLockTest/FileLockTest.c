/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly handles file
    locks (fcntl with F_SETLK/F_GETLK). During execution of this program in
    the MVEE, no mismatches should occur.
=============================================================================*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define LOCKFILE "mylock"

int main(int argc, char *argv[])
{
  int fd;
  struct flock lock;

  fd = open(LOCKFILE, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR);
  if (fd < 0)
  {
    perror("open");
    exit(1);
  }

  lock.l_type = F_WRLCK;     /* F_RDLCK, F_WRLCK, F_UNLCK */
  lock.l_start = 1;  /* byte offset relative to l_whence */
  lock.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
  lock.l_len = 1;       /* #bytes (0 means to EOF) */
  if (fcntl(fd, F_SETLKW, &lock) < 0)
  {
    perror("fcntl 1");
    close(fd);
    exit(1);
  }

  if (fcntl(fd, F_GETLK, &lock) < 0)
  {
    perror("fcntl 2");
    close(fd);
    exit(1);
  }
  if (lock.l_type != F_UNLCK)
    printf("lock is already owned by process %d\n", lock.l_pid);
  else
    printf("lock ok\n");

  close(fd);
  //unlink(LOCKFILE);
}