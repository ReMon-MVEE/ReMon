/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program creates a fork and executes ls in that fork. It can be used to
    test if the monitor correctly handles forks/executing other programs.
=============================================================================*/

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define BUFSIZE 100

int
main(int argc, char *argv[])
{
  int childpid, status;
  childpid = fork();
  if (childpid == 0)
  {
    execl("/bin/ls", "ls", NULL);
  }
  else
  {
    waitpid(childpid, &status, 0);
    printf("Done\n");
  }
  return 0;
}
