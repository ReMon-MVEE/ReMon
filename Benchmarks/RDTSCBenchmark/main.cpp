#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(int argc, char** argv)
{
  long final = 0;
  unsigned int lower, upper;
  int max = 95;

  int pid = fork();

  if (pid == 0)
    {

  for (int i = 0; i < 500000; ++i)
    {
      for (int x = 0; x < max; ++x)
	{
          for (int j = 0; j < max; ++j)
            {
              int tmp = x << j;
            }
	}

      asm volatile("rdtsc\n" : "=a"(lower), "=d"(upper));
      final += lower;
      final += upper;
    }

  printf("final = %d\n", final);
    }
  else
    {
      int status;
      int bla = waitpid(pid, &status, 0);
      printf("bla = %d\n", bla);
    }
}
