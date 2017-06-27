#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <asm/unistd_64.h>
#include <stdlib.h>

#define ESC_XCHECKS_OFF -42
#define ESC_XCHECKS_ON  -43

struct syscall_info
{
	long syscalls_to_ignore;
	long syscall_nums[3];
};

int main(int argc, char** argv) 
{
	struct syscall_info info;
	char buf[4096];
	char file[4096];

	char* root = getenv("MVEEROOT");
	if (root)
		sprintf(file, "%s/Tests/SyscallCheckToggling/TestFile", root);
	else
		sprintf(file, "TestFile");

	info.syscalls_to_ignore = 3;
	info.syscall_nums[0] = __NR_open;
	info.syscall_nums[1] = __NR_read;
	info.syscall_nums[2] = __NR_write;

	syscall(__NR_write, ESC_XCHECKS_OFF, &info, sizeof(struct syscall_info));
	int fd = open(file, O_RDONLY);
	int bytes = read(fd, buf, 4096);
	if (bytes > 0)
		write(fileno(stdout), buf, strlen(buf));
	syscall(__NR_write, ESC_XCHECKS_ON, NULL, 0);

	printf("Hello World!\n");

	return 0;
}
