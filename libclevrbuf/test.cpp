#include "librbuf.h"

#define ITEMS 1000000
#define SLAVES 8

unsigned short my_variant = 0;

void do_master_test(struct rbuf* buf)
{
	srand(0);
	int hash = 0;

	printf("Producing %d elements in master\n", ITEMS);

	for (int i = 0; i < ITEMS; ++i)
	{
		int elem = rand();
		hash = hash ^ elem;
		rbuf_push<int>(buf, elem);
	}

	printf("All items pushed - hash: %d\n", hash);
}

void do_slave_test(struct rbuf* buf)
{
	srand(0);
	int hash = 0;

	printf("Cross-checking %d elements in slave %d\n", ITEMS, my_variant);

	for (int i = 0; i < ITEMS; ++i)
	{
		int expected_elem = rand(), actual_elem;
		rbuf_peek<int>(buf, my_variant - 1, actual_elem, expected_elem);
		hash = hash ^ actual_elem;

		if (expected_elem != actual_elem)
		{
			printf("CROSS-CHECK FAIL - SLAVE: %d - ITEM NUM: %d - EXPECTED VALUE: %d - ACTUAL VALUE: %d\n",
				   my_variant - 1, i, expected_elem, actual_elem);			
		}
	}

	printf("All items cross-checked - hash: %d\n", hash);
}

int main(int argc, char** argv)
{
	struct rbuf* buf = rbuf_init<int>(4096, SLAVES + 1);

	if (!buf)
		return -1;

	for (int i = 0; i < SLAVES; ++i)
	{
		if (fork() == 0)
		{
			my_variant = i + 1;		
			do_slave_test(buf);
			exit(0);
			return 0;
		}
	}

	do_master_test(buf);
	exit(0);
	return 0;
}

