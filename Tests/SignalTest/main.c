/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly delivers signals
    to the children, and correctly handles segfaults in signal handlers. In the
    MVEE, the first segfault will occur and will be printed out, but the signal
    handler should still be executed and the second segfault should also occur
    and should be printed out as well.
=============================================================================*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

void sig_handler(int sig)
{
  printf("In signal handler\n");
  char *p = 0;
  *p = 'c';
  exit(1);
}

int main(int argc, char *argv[])
{
  signal(SIGSEGV, sig_handler);
  char *p = 0;
  *p = 'c';
}