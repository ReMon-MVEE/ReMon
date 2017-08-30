#include "librbuf.h"
#include "api.h"

__thread struct rbuf* buf = nullptr;
int my_variant_num = 0;

extern "C" void rb_init()
{
	buf = rbuf_init<unsigned long>(4096, 0, false);
	syscall(MVEE_GET_THREAD_NUM, &my_variant_num);
}

extern "C" void rb_xcheck(unsigned long item)
{
	if (my_variant_num == 0)
	{
		rbuf_push<unsigned long>(buf, item);
	}
	else
	{
		unsigned long master_item = item;
		rbuf_peek<unsigned long>(buf, my_variant_num - 1, master_item);

		if (master_item != item)
			*(volatile unsigned long*) 0 = 0xDEADBEEF;
	}
}
