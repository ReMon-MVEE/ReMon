#include "librbuf.h"
#include "api.h"

enum class CrossCheckType : char
{
	ITEM,
	TERMINATOR,
};

#pragma pack(push, 1)
struct CrossCheck
{
	// FIXME: this structure takes 9 bytes
	// do we want the size aligned to 8 bytes (for a total of 16)???
	unsigned long item;
	CrossCheckType type;

	bool operator==(const CrossCheck &other) const
	{
		return item == other.item && type == other.type;
	}

	bool operator!=(const CrossCheck &other) const
	{
		return !(*this == other);
	}
};
#pragma pack(pop)
static_assert(sizeof(CrossCheck) == 9);

__thread struct rbuf* buf = nullptr;
int my_variant_num = 0;

static inline void xcheck_internal(CrossCheck &xcheck)
{
	if (my_variant_num == 0)
	{
		rbuf_push<CrossCheck>(buf, xcheck);
	}
	else
	{
		CrossCheck master_xcheck = xcheck;
		rbuf_peek<CrossCheck>(buf, my_variant_num - 1, master_xcheck);

		if (master_xcheck != xcheck)
			*(volatile unsigned long*) 0 = 0xDEADBEEF;
	}
}

#ifdef EXPLICIT_RB_INIT
extern "C" void rb_init()
#else
__attribute__((constructor))
static void rb_init()
#endif
{
	buf = rbuf_init<CrossCheck>(4096, 0);
	syscall(MVEE_GET_THREAD_NUM, &my_variant_num);
	// we only wanted cross-checks for rbuf_init(),
	// disable them now
	syscall(MVEE_DISABLE_XCHECKS, NULL);
}

#ifdef EXPLICIT_RB_FINI
extern "C" void rb_fini()
#else
__attribute__((destructor))
static void rb_fini()
#endif
{
	// Add a cross-check for program termination
	CrossCheck xcheck = { 0, CrossCheckType::TERMINATOR };
	xcheck_internal(xcheck);
}

extern "C" void rb_xcheck(unsigned long item)
{
	CrossCheck xcheck = { item, CrossCheckType::ITEM };
	xcheck_internal(xcheck);
}
