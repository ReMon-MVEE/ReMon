/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2014 Stijn Volckaert, Ghent University 
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
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
