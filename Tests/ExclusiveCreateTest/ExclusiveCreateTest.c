/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly handles exclusive
    file creates (O_CREAT and O_EXCL). During execution of this program in the
    MVEE, no mismatches should occur.
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SUBDIR "Subdir"
#define FILENAME "test.txt"

int main(int argc, char *argv[])
{
  int fd, dir_fd;
  //chdir(SUBDIR);
  // use fchdir for extra difficulty
  dir_fd = open(SUBDIR, O_RDONLY, S_IRWXU);
  if (dir_fd > -1)
  {
    fchdir(dir_fd);
    close(dir_fd);
  }
  else
    perror("opening dir");
  unlink(FILENAME);
  fd = open(FILENAME, O_RDONLY | O_CREAT | O_EXCL, S_IRWXU);
  if (fd == -1)
    perror("1st create error");
  else
    close(fd);
  fd = open(FILENAME, O_RDONLY | O_CREAT | O_EXCL, S_IRWXU);
  if (fd == -1)
    perror("2nd create error");
  else
    close(fd);
  return 0;
}