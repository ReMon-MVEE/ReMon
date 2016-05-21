/* supported atomic ops */
enum mvee_atomic_ops {
  mvee_atomic_load_n,
  mvee_atomic_load,
  mvee_atomic_store_n,
  mvee_atomic_store,
  mvee_atomic_exchange_n,
  mvee_atomic_exchange,
  mvee_atomic_compare_exchange_n,
  mvee_atomic_compare_exchange,
  mvee_atomic_add_fetch,
  mvee_atomic_sub_fetch,
  mvee_atomic_and_fetch,
  mvee_atomic_xor_fetch,
  mvee_atomic_or_fetch,
  mvee_atomic_nand_fetch,
  mvee_atomic_fetch_add,
  mvee_atomic_fetch_sub,
  mvee_atomic_fetch_and,
  mvee_atomic_fetch_xor,
  mvee_atomic_fetch_or,
  mvee_atomic_fetch_nand,
  mvee_atomic_test_and_set,
  mvee_atomic_clear,
  mvee_atomic_always_lock_free,
  mvee_atomic_is_lock_free,
  mvee_sync_fetch_and_add,
  mvee_sync_fetch_and_sub,
  mvee_sync_fetch_and_or,
  mvee_sync_fetch_and_and,
  mvee_sync_fetch_and_xor,
  mvee_sync_fetch_and_nand,
  mvee_sync_add_and_fetch,
  mvee_sync_sub_and_fetch,
  mvee_sync_or_and_fetch,
  mvee_sync_and_and_fetch,
  mvee_sync_xor_and_fetch,
  mvee_sync_nand_and_fetch,
  mvee_sync_bool_compare_and_swap,
  mvee_sync_val_compare_and_swap,
  mvee_sync_lock_test_and_set,
  mvee_sync_lock_release,
  mvee_atomic_ops_max
};
 
/* interceptable functions */
#ifdef __cplusplus
extern "C" {
#endif
unsigned char mvee_atomic_preop(unsigned short op, void* word_ptr);
void mvee_atomic_postop(unsigned char __preop_result);
#ifdef __cplusplus
}
#endif
 
/* call macros to the original intrinsics */
#define orig_atomic_load_n(ptr, memmodel) __atomic_load_n(ptr, memmodel)
#define orig_atomic_load(ptr, ret, memmodel) __atomic_load(ptr, ret, memmodel)
#define orig_atomic_store_n(ptr, val, memmodel) __atomic_store_n(ptr, val, memmodel)
#define orig_atomic_store(ptr, val, memmodel) __atomic_store(ptr, val, memmodel)
#define orig_atomic_exchange_n(ptr, val, memmodel) __atomic_exchange_n(ptr, val, memmodel)
#define orig_atomic_exchange(ptr, val, ret, memmodel) __atomic_exchange(ptr, val, ret, memmodel)
#define orig_atomic_compare_exchange_n(ptr, expected, desired, weak, success_memmodel, failure_memmodel) __atomic_compare_exchange_n(ptr, expected, desired, weak, success_memmodel, failure_memmodel)
#define orig_atomic_compare_exchange(ptr, expected, desired, weak, success_memmodel, failure_memmodel) __atomic_compare_exchange(ptr, expected, desired, weak, success_memmodel, failure_memmodel)
#define orig_atomic_add_fetch(ptr, val, memmodel) __atomic_add_fetch(ptr, val, memmodel)
#define orig_atomic_sub_fetch(ptr, val, memmodel) __atomic_sub_fetch(ptr, val, memmodel)
#define orig_atomic_and_fetch(ptr, val, memmodel) __atomic_and_fetch(ptr, val, memmodel)
#define orig_atomic_xor_fetch(ptr, val, memmodel) __atomic_xor_fetch(ptr, val, memmodel)
#define orig_atomic_or_fetch(ptr, val, memmodel) __atomic_or_fetch(ptr, val, memmodel)
#define orig_atomic_nand_fetch(ptr, val, memmodel) __atomic_nand_fetch(ptr, val, memmodel)
#define orig_atomic_fetch_add(ptr, val, memmodel) __atomic_fetch_add(ptr, val, memmodel)
#define orig_atomic_fetch_sub(ptr, val, memmodel) __atomic_fetch_sub(ptr, val, memmodel)
#define orig_atomic_fetch_and(ptr, val, memmodel) __atomic_fetch_and(ptr, val, memmodel)
#define orig_atomic_fetch_xor(ptr, val, memmodel) __atomic_fetch_xor(ptr, val, memmodel)
#define orig_atomic_fetch_or(ptr, val, memmodel) __atomic_fetch_or(ptr, val, memmodel)
#define orig_atomic_fetch_nand(ptr, val, memmodel) __atomic_fetch_nand(ptr, val, memmodel)
#define orig_atomic_test_and_set(ptr, memmodel) __atomic_test_and_set(ptr, memmodel)
#define orig_atomic_clear(ptr, memmodel) __atomic_clear(ptr, memmodel)
#define orig_atomic_always_lock_free(size, ptr) __atomic_always_lock_free(size, ptr)
#define orig_atomic_is_lock_free(size, ptr) __atomic_is_lock_free(size, ptr)
#define orig_sync_fetch_and_add(ptr,  value, ...) __sync_fetch_and_add(ptr,  value, ##__VA_ARGS__)
#define orig_sync_fetch_and_sub(ptr,  value, ...) __sync_fetch_and_sub(ptr,  value, ##__VA_ARGS__)
#define orig_sync_fetch_and_or(ptr,  value, ...) __sync_fetch_and_or(ptr,  value, ##__VA_ARGS__)
#define orig_sync_fetch_and_and(ptr,  value, ...) __sync_fetch_and_and(ptr,  value, ##__VA_ARGS__)
#define orig_sync_fetch_and_xor(ptr,  value, ...) __sync_fetch_and_xor(ptr,  value, ##__VA_ARGS__)
#define orig_sync_fetch_and_nand(ptr,  value, ...) __sync_fetch_and_nand(ptr,  value, ##__VA_ARGS__)
#define orig_sync_add_and_fetch(ptr,  value, ...) __sync_add_and_fetch(ptr,  value, ##__VA_ARGS__)
#define orig_sync_sub_and_fetch(ptr,  value, ...) __sync_sub_and_fetch(ptr,  value, ##__VA_ARGS__)
#define orig_sync_or_and_fetch(ptr,  value, ...) __sync_or_and_fetch(ptr,  value, ##__VA_ARGS__)
#define orig_sync_and_and_fetch(ptr,  value, ...) __sync_and_and_fetch(ptr,  value, ##__VA_ARGS__)
#define orig_sync_xor_and_fetch(ptr,  value, ...) __sync_xor_and_fetch(ptr,  value, ##__VA_ARGS__)
#define orig_sync_nand_and_fetch(ptr,  value, ...) __sync_nand_and_fetch(ptr,  value, ##__VA_ARGS__)
#define orig_sync__compare_and_swap(ptr,  oldval,  newval, ...) __sync__compare_and_swap(ptr,  oldval,  newval, ##__VA_ARGS__)
#define orig_sync_val_compare_and_swap(ptr,  oldval,  newval, ...) __sync_val_compare_and_swap(ptr,  oldval,  newval, ##__VA_ARGS__)
#define orig_sync_lock_test_and_set(ptr,  value, ...) __sync_lock_test_and_set(ptr,  value, ##__VA_ARGS__)
#define orig_sync_lock_release(ptr, ...) __sync_lock_release(ptr, ##__VA_ARGS__)
 
/* mvee wrappers */
#define  __atomic_load_n(ptr, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_load_n,(void*) (unsigned long)ptr); __ret = orig_atomic_load_n(ptr, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_load(ptr, ret, memmodel) ({ unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_load,(void*) (unsigned long)ptr); orig_atomic_load(ptr, ret, memmodel); mvee_atomic_postop(__preop_result); })
#define  __atomic_store_n(ptr, val, memmodel) ({ unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_store_n,(void*) (unsigned long)ptr); orig_atomic_store_n(ptr, val, memmodel); mvee_atomic_postop(__preop_result); })
#define  __atomic_store(ptr, val, memmodel) ({ unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_store,(void*) (unsigned long)ptr); orig_atomic_store(ptr, val, memmodel); mvee_atomic_postop(__preop_result); })
#define  __atomic_exchange_n(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_exchange_n,(void*) (unsigned long)ptr); __ret = orig_atomic_exchange_n(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_exchange(ptr, val, ret, memmodel) ({ unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_exchange,(void*) (unsigned long)ptr); orig_atomic_exchange(ptr, val, ret, memmodel); mvee_atomic_postop(__preop_result); })
#define  __atomic_compare_exchange_n(ptr, expected, desired, weak, success_memmodel, failure_memmodel) ({ bool __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_compare_exchange_n,(void*) (unsigned long)ptr); __ret = orig_atomic_compare_exchange_n(ptr, expected, desired, weak, success_memmodel, failure_memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_compare_exchange(ptr, expected, desired, weak, success_memmodel, failure_memmodel) ({ bool __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_compare_exchange,(void*) (unsigned long)ptr); __ret = orig_atomic_compare_exchange(ptr, expected, desired, weak, success_memmodel, failure_memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_add_fetch(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_add_fetch,(void*) (unsigned long)ptr); __ret = orig_atomic_add_fetch(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_sub_fetch(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_sub_fetch,(void*) (unsigned long)ptr); __ret = orig_atomic_sub_fetch(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_and_fetch(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_and_fetch,(void*) (unsigned long)ptr); __ret = orig_atomic_and_fetch(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_xor_fetch(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_xor_fetch,(void*) (unsigned long)ptr); __ret = orig_atomic_xor_fetch(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_or_fetch(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_or_fetch,(void*) (unsigned long)ptr); __ret = orig_atomic_or_fetch(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_nand_fetch(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_nand_fetch,(void*) (unsigned long)ptr); __ret = orig_atomic_nand_fetch(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_fetch_add(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_fetch_add,(void*) (unsigned long)ptr); __ret = orig_atomic_fetch_add(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_fetch_sub(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_fetch_sub,(void*) (unsigned long)ptr); __ret = orig_atomic_fetch_sub(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_fetch_and(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_fetch_and,(void*) (unsigned long)ptr); __ret = orig_atomic_fetch_and(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_fetch_xor(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_fetch_xor,(void*) (unsigned long)ptr); __ret = orig_atomic_fetch_xor(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_fetch_or(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_fetch_or,(void*) (unsigned long)ptr); __ret = orig_atomic_fetch_or(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_fetch_nand(ptr, val, memmodel) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_fetch_nand,(void*) (unsigned long)ptr); __ret = orig_atomic_fetch_nand(ptr, val, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_test_and_set(ptr, memmodel) ({ bool __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_test_and_set,(void*) (unsigned long)ptr); __ret = orig_atomic_test_and_set(ptr, memmodel); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_clear(ptr, memmodel) ({ unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_clear,(void*) (unsigned long)ptr); orig_atomic_clear(ptr, memmodel); mvee_atomic_postop(__preop_result); })
#define  __atomic_always_lock_free(size, ptr) ({ bool __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_always_lock_free,(void*) (unsigned long)ptr); __ret = orig_atomic_always_lock_free(size, ptr); mvee_atomic_postop(__preop_result); __ret; })
#define  __atomic_is_lock_free(size, ptr) ({ bool __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_atomic_is_lock_free,(void*) (unsigned long)ptr); __ret = orig_atomic_is_lock_free(size, ptr); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_fetch_and_add(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_fetch_and_add,(void*) (unsigned long)ptr); __ret = orig_sync_fetch_and_add(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_fetch_and_sub(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_fetch_and_sub,(void*) (unsigned long)ptr); __ret = orig_sync_fetch_and_sub(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_fetch_and_or(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_fetch_and_or,(void*) (unsigned long)ptr); __ret = orig_sync_fetch_and_or(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_fetch_and_and(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_fetch_and_and,(void*) (unsigned long)ptr); __ret = orig_sync_fetch_and_and(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_fetch_and_xor(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_fetch_and_xor,(void*) (unsigned long)ptr); __ret = orig_sync_fetch_and_xor(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_fetch_and_nand(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_fetch_and_nand,(void*) (unsigned long)ptr); __ret = orig_sync_fetch_and_nand(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_add_and_fetch(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_add_and_fetch,(void*) (unsigned long)ptr); __ret = orig_sync_add_and_fetch(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_sub_and_fetch(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_sub_and_fetch,(void*) (unsigned long)ptr); __ret = orig_sync_sub_and_fetch(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_or_and_fetch(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_or_and_fetch,(void*) (unsigned long)ptr); __ret = orig_sync_or_and_fetch(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_and_and_fetch(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_and_and_fetch,(void*) (unsigned long)ptr); __ret = orig_sync_and_and_fetch(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_xor_and_fetch(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_xor_and_fetch,(void*) (unsigned long)ptr); __ret = orig_sync_xor_and_fetch(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_nand_and_fetch(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_nand_and_fetch,(void*) (unsigned long)ptr); __ret = orig_sync_nand_and_fetch(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync__compare_and_swap(ptr, oldval, newval, ...) ({ bool __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_bool_compare_and_swap,(void*) (unsigned long)ptr); __ret = orig_sync__compare_and_swap(ptr, oldval, newval, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_val_compare_and_swap(ptr, oldval, newval, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_val_compare_and_swap,(void*) (unsigned long)ptr); __ret = orig_sync_val_compare_and_swap(ptr, oldval, newval, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_lock_test_and_set(ptr, value, ...) ({ typeof(*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee_sync_lock_test_and_set,(void*) (unsigned long)ptr); __ret = orig_sync_lock_test_and_set(ptr, value, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); __ret; })
#define  __sync_lock_release(ptr, ...) ({ unsigned char __preop_result = mvee_atomic_preop(mvee_sync_lock_release,(void*) (unsigned long)ptr); orig_sync_lock_release(ptr, ##__VA_ARGS__); mvee_atomic_postop(__preop_result); })
