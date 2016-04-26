/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  struct timespec time;
  clock_gettime(CLOCK_MONOTONIC, &time);
  printf("Seconds: %d\n", time.tv_sec);
  printf("Nanoseconds: %d\n", time.tv_nsec);
  return 0;
}
