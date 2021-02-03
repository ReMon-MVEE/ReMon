struct mvee_shm_op_ret {
  unsigned long val;
  bool cmp;
};

extern "C" unsigned char mvee_atomic_preop(unsigned char, void*);
extern "C" void mvee_atomic_postop(unsigned char);
extern "C" mvee_shm_op_ret mvee_shm_op(unsigned char id, void* address, unsigned long size, unsigned long value, unsigned long cmp);

extern "C" unsigned char mvee_atomic_preop_trampoline(unsigned char type, void* variable)
{
//	*(volatile int*)0=0;
	return mvee_atomic_preop(type, variable);
}

extern "C" void mvee_atomic_postop_trampoline(unsigned char preop_result)
{
	mvee_atomic_postop(preop_result);
}

extern "C" mvee_shm_op_ret mvee_shm_op_trampoline(unsigned char id, void* address, unsigned long size, unsigned long value, unsigned long cmp)
{
  return mvee_shm_op(id, address, size, value, cmp);
}
