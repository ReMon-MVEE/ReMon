#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char** argv)
{
	char* buffer = NULL;
	int alloc_size;
	int allocs_remaining = 20000;
	struct stat st;

//	printf("string benchmark\n");

	alloc_size = atoi(argv[1]);
	buffer = (char*)malloc(alloc_size);
	memset(buffer, 50, alloc_size);
	buffer[alloc_size-1] = '\0';

//	printf("alloc size: %d\n", alloc_size);

	while (allocs_remaining-- > 0)
		fopen(buffer, "r");

//	printf("all done!\n");
	return 0;
}
