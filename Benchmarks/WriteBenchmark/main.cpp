#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char** argv)
{
  char* buffer = NULL;
  int fd = open( "testfile.txt", O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
  int alloc_size = atoi(argv[1]);
  int max = atoi(argv[2]);

  printf("file open. fd: %d\n", fd);

  buffer = (char*)malloc(alloc_size);

  for (int i = 0; i < 500000; ++i)
    {
      for (int x = 0; x < max; ++x)
	{
	  for (int j = 0; j < max; ++j)
	    {
	      int tmp = x << j;
	    }
	}

      syscall(__NR_write, fd, buffer, alloc_size);
    }

  syscall(__NR_close, fd);
}
