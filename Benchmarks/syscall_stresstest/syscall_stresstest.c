#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <asm/unistd_64.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

// #define TEST_UTCB

#ifdef TEST_UTCB
#include "/home/stijn/MVEE/UTCB/MVEE_utcb.h"
#endif

//#define NUMTHREADS 100
//#define NUMCALLS   (unsigned long long)(1 * 1000 * 1000)
#define NUMCALLS (unsigned long long)(5 * 1000 * 1000)

pthread_barrier_t barrier;
pthread_t threads[NUMTHREADS];
pid_t pid;



void* thread_func(void* param)
{
  long tmp;
  struct timeval tv;
  struct timezone tz;

  //  pthread_barrier_wait(&barrier);
  //  printf("utcb key: 0x%08x\n", *(volatile int __attribute__((address_space(256)))*)NULL);

  for (unsigned int i = 0; i < NUMCALLS; ++i)
    {
#ifdef TEST_UTCB
      tmp = utcb_syscall(__NR_getpid);
#else
      tmp = syscall(__NR_getpid);
#endif
    }

#ifdef TEST_UTCB
  int ret = utcb_syscall(__NR_gettimeofday, &tv, &tz);
#else
  int ret = gettimeofday(&tv, &tz);
#endif

  //printf("gettimeofday ret: %d - time: %ld.%ld - timezone: %d\n", ret, tv.tv_sec, tv.tv_usec, tz.tz_minuteswest);

  pid = tmp;
  return 0;
}

int main(int argc, char** argv)
{
  //  pthread_barrier_init(&barrier, NULL, NUMTHREADS);

  printf("syscall stresstest - %d threads - %llu calls for each thread\n", NUMTHREADS, NUMCALLS);

  if (NUMTHREADS > 1)
    {

      for (int i = 0; i < NUMTHREADS; ++i)
	pthread_create(&threads[i], NULL, thread_func, NULL);

      for (int i = 0; i < NUMTHREADS; ++i)
	pthread_join(threads[i], NULL);

    }
  else
    {
      thread_func(NULL);
    }

  printf("All done! PID: %d %ld (%s)\n", pid, syscall(__NR_getpid), strerror(errno));

  return 0;
}
