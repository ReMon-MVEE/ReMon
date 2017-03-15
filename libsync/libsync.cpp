extern "C" unsigned char mvee_atomic_preop(unsigned char, void*);
extern "C" void mvee_atomic_postop(unsigned char);

extern "C" unsigned char mvee_atomic_preop_trampoline(unsigned char type, void* variable)
{
//	*(volatile int*)0=0;
	return mvee_atomic_preop(type, variable);
}

extern "C" void mvee_atomic_postop_trampoline(unsigned char preop_result)
{
	mvee_atomic_postop(preop_result);
}
