#include "librbuf.h"
#include "api.h"

#include <cstddef>
#include <cstdint>

enum CrossCheckType : uint8_t
{
	TERMINATOR,

	// For client-provided tags, add their tag value to this
	FIRST_CLIENT_TAG,

	UNKNOWN_TAG = FIRST_CLIENT_TAG,
	FUNCTION_ENTRY_TAG,
	FUNCTION_EXIT_TAG,
};

#pragma pack(push, 1)
struct CrossCheck
{
	// FIXME: this structure takes 9 bytes
	// do we want the size aligned to 8 bytes (for a total of 16)???
	uint64_t item;
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

static __thread struct rbuf* buf = nullptr;
static int my_variant_num = 0;
static uint64_t first_func_xcheck = 0;
static bool seen_first_func = false;

#ifdef EXPLICIT_RB_INIT
extern "C"
#else
static inline
#endif
void rb_init()
{
	if (buf != nullptr)
		return;

	// if we started with cross-checks disabled, enable them now
	syscall(MVEE_ENABLE_XCHECKS, NULL);
	buf = rbuf_init<CrossCheck>(4096, 0);
	syscall(MVEE_GET_THREAD_NUM, &my_variant_num);
#ifdef UNSYNCED_SYSCALLS
	// we only wanted cross-checks for rbuf_init(),
	// disable them now
	syscall(MVEE_DISABLE_XCHECKS, NULL);
#endif
}

#ifdef EXPLICIT_RB_FINI
extern "C" void rb_fini();
#else
static void rb_fini();
#endif

static inline void xcheck_internal(CrossCheck &xcheck)
{
	if (buf == nullptr)
		rb_init();

	if (my_variant_num == 0)
	{
		rbuf_push<CrossCheck>(buf, xcheck);
	}
	else
	{
		CrossCheck master_xcheck = xcheck;
		rbuf_peek<CrossCheck>(buf, my_variant_num - 1, master_xcheck, xcheck);

		if (master_xcheck != xcheck)
		{
//			*(volatile uint64_t*) 0 = xcheck.item;
			__sync_synchronize();
			asm volatile("mov %0, %%rax\n\t"
						 "xor %%rbx, %%rbx\n\t"
						 "mov %%rax, (%%rbx)" :: "g"(xcheck.item) : "rax", "rbx");
		}
	}

	if (!seen_first_func &&
		xcheck.type == FUNCTION_ENTRY_TAG) {
		seen_first_func = true;
		first_func_xcheck = xcheck.item;
	}
	if (seen_first_func &&
		xcheck.type == FUNCTION_EXIT_TAG &&
		xcheck.item == first_func_xcheck) {
		// The first cross-checked function just returned,
		// so wrap everything up
		rb_fini();
	}
}

#ifdef EXPLICIT_RB_FINI
extern "C" void rb_fini()
#else
static void rb_fini()
#endif
{
	if (buf == nullptr)
		return;

	// Add a cross-check for program termination
	CrossCheck xcheck = { 0, CrossCheckType::TERMINATOR };
	xcheck_internal(xcheck);
	syscall(MVEE_DISABLE_XCHECKS, NULL);
}

extern "C" void rb_xcheck(uint8_t tag, uint64_t val)
{
	auto xcheck_tag = static_cast<CrossCheckType>(CrossCheckType::FIRST_CLIENT_TAG + tag);
	CrossCheck xcheck{ val, xcheck_tag };
	xcheck_internal(xcheck);
}
