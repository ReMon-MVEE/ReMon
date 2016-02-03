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
	int fd = syscall(__NR_open, "testfile.txt", O_RDONLY);
	int alloc_size = atoi(argv[1]);

	buffer = (char*)malloc(alloc_size);

	for (int i = 0; i < 10000; ++i)
	{
		syscall(__NR_lseek, fd, 0, 0, 0, SEEK_SET);
		syscall(__NR_read, fd, buffer, alloc_size);
	}

	syscall(__NR_close, fd);
}
