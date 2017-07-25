#include "../../libclevrbuf/api.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	unsigned long checksum = 0;

	rb_init();
	srand(time(0));

	for (int i = 0; i < 1000000; ++i)
	{
		unsigned long elem = rand();
		checksum ^= elem;

		rb_xcheck(elem);
	}

	// triggers divergence with ASLR
	rb_xcheck((unsigned long)&checksum);

	printf("Calculated checksum: %lu\n", checksum);
	return 0;
}
