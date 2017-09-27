#include "../../MVEE/Inc/arch/amd64/MVEE_private_arch.h" // for MVEE_FAKE_SYSCALL_BASE
#include "../../MVEE/Inc/MVEE_fake_syscall.h"            // for MVEE_ENABLE_XCHECKS
#include <unistd.h>
#include <string.h>
#include <asm/unistd.h>

void my_write(const char* str)
{
	syscall(__NR_write, 2, str, strlen(str) + 1);
}

int main(int argc, char** argv)
{
	my_write("This write is not xchecked - I am variant 2\n");
	my_write("This write is not xchecked either - I am variant 2\n");
	syscall(MVEE_ENABLE_XCHECKS);
	my_write("This write is xchecked\n");

	return 0;
}
