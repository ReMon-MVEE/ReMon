/*=============================================================================
    Linux Detours v1.0 - (c) 2011 Stijn Volckaert (svolckae@elis.ugent.be)

    Revision History:
        * Created by Stijn Volckaert
=============================================================================*/

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "LinuxDetours.h"
#include <sys/time.h>
#include <dlfcn.h>
#include <stdio.h>

/*-----------------------------------------------------------------------------
    Trampolines
-----------------------------------------------------------------------------*/
int gettimeofday_trampoline(struct timeval *tv, struct timezone *tz)
{
  GENERATE_TRAMPOLINE;
}

/*-----------------------------------------------------------------------------
    gettimeofday_hook - calls the original function through the trampoline
-----------------------------------------------------------------------------*/
int gettimeofday_hook(struct timeval *tv, struct timezone *tz)
{
  printf("gettimeofday_hook!\n");
  return gettimeofday_trampoline(tv, tz);
}

/*-----------------------------------------------------------------------------
    gettimeofday_hook2 - replaces the original function completely
-----------------------------------------------------------------------------*/
int gettimeofday_hook2(struct timeval *tv, struct timezone *tz)
{
  printf("gettimeofday_hook2!\n");
  tv->tv_sec = 0;
  return 0;
}

/*-----------------------------------------------------------------------------
    main - Just a simple test program!
-----------------------------------------------------------------------------*/
int main(int argc, char** argv)
{
  void* pLibc = dlopen("libc.so.6", RTLD_NOW);
  void* pGetTimeOfDay = dlsym(pLibc, "gettimeofday");
  struct timeval tv;

  gettimeofday(&tv, 0);
  printf("timeofday: %d sec\n", tv.tv_sec);
  sleep(2);

  DetourFunctionWithTrampoline(pGetTimeOfDay, gettimeofday_hook, gettimeofday_trampoline);

  gettimeofday(&tv, 0);
  printf("timeofday: %d sec\n", tv.tv_sec);
  sleep(2);

  DetourRemove(pGetTimeOfDay);

  gettimeofday(&tv, 0);
  printf("timeofday: %d sec\n", tv.tv_sec);
  sleep(2);

  DetourFunctionWithTrampoline(pGetTimeOfDay, gettimeofday_hook2, gettimeofday_trampoline);

  gettimeofday(&tv, 0);
  printf("timeofday: %d sec\n", tv.tv_sec);
  sleep(2);

  DetourRemove(pGetTimeOfDay);

  gettimeofday(&tv, 0);
  printf("timeofday: %d sec\n", tv.tv_sec);
  return 0;
}
