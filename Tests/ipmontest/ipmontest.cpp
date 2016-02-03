#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd_64.h>
#include <sys/mman.h>

#define IPMON_RB_BASE 0x00007ffffefff000
#define IPMON_RB_SIZE 16 * 1024 * 1024

void reveal()
{
	long ret = syscall(318, 0);
	printf("sys_ipmon_rbcontrol(IPMON_RB_REVEAL) result: %ld (%s)\n",
		   ret, strerror(-ret));
}

void probe()
{
	unsigned char* rb = (unsigned char*)0x00007ffffefff000;
	*rb = 1;
}

void do_mprotect()
{
	long ret = mprotect((void*)IPMON_RB_BASE, IPMON_RB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);

	printf("Attempt 0 - mprotect whole buffer - return: %ld (%s)\n",
		   ret, strerror(-ret));

	ret = mprotect((void*)IPMON_RB_BASE, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

	printf("Attempt 1 - mprotect first page only - return %ld (%s)\n",
		   ret, strerror(-ret));

	ret = mprotect((void*)(IPMON_RB_BASE + 4096), 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

	printf("Attempt 2 - mprotect second page only - return %ld (%s)\n",
		   ret, strerror(-ret));
}

void do_munmap()
{
	long ret = munmap((void*)IPMON_RB_BASE, IPMON_RB_SIZE);

	printf("Attempt 0 - munmap whole buffer - return: %ld (%s)\n",
		   ret, strerror(-ret));

	ret = munmap((void*)IPMON_RB_BASE, 4096);

	printf("Attempt 1 - munmap first page only - return: %ld (%s)\n",
		   ret, strerror(-ret));
}

void do_syscalltest()
{
	for (int i = 0; i < 1000000; ++i)
		syscall(__NR_gettid);
}

void do_shorttest_a()
{
	for (int i = 0; i < 5; ++i)
	{
		__asm__ __volatile__ ("movq $0, (0)");
		long ret = syscall(__NR_gettid,1,2,3,4,5,6);
		printf("ret %d - %ld\n", i, ret);
	}
}


void do_shorttest_b()
{
	for (int i = 0; i < 5; ++i)
	{
		long ret = syscall(__NR_gettid,1,2,3,4,5,6);
		__asm__ __volatile__ ("movq $0, (0)");
		printf("ret %d - %ld\n", i, ret);
	}
}


void do_shorttest_c()
{
	for (int i = 0; i < 5; ++i)
	{
		long ret = syscall(__NR_gettid,1,2,3,4,5,6);
		printf("ret %d - %ld\n", i, ret);
	}
}


int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Syntax: %s <test num>\n", argv[0]);
		return -1;
	}

	long num = strtol(argv[1], NULL, 10);

	switch(num)
	{
	case 0:
		printf("Trying to write into IP-MON rb buffer from outside IP-MON. Expecting failure.\n");
		probe();
		break;
	case 1:
		printf("Trying to reveal IP-MON rb buffer from outside IP-MON. Expecting failure.\n");
		reveal();
		printf("> Now trying to write into rb buffer. Expecting failure\n");
		probe();
		break;
	case 2:
		printf("Trying to mprotect IP-MON rb buffer from outside IP-MON. Expecting failure.\n");
		do_mprotect();
		break;
	case 3:
		printf("Trying to munmap IP-MON rb buffer from outside IP-MON. Expecting failure.\n");
		do_munmap();
		break;
	case 4:
		printf("Executing 1M sys_gettid calls.\n");
		do_syscalltest();
		break;
	case 5:
//		printf("Short self-test - crash before syscall\n");
		do_shorttest_a();
		break;
	case 6:
//		printf("Short self-test - crash after syscall\n");
		do_shorttest_b();
		break;
	case 7:
		printf("Short self-test - no crash\n");
		do_shorttest_c();
		break;
	}


	return 0;
}
