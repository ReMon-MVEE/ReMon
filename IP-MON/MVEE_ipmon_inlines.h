#ifndef IPMON_INLINES_H_
#define IPMON_INLINES_H_

/*
 * Most of these inline assembly functions has different variants:
 * - one variant has a pointer argument that points to local memory (i.e., not into the RB) and thus can leak
 * - one variant has a pointer argument that points into the RB and should not leak. 
 *   Thus, this argument is now an *offset* into the RB, through the RB_REGISTER register.
 * 
 * These functions (only those currently used in IP-MON are implemented) have different names, depending on their arguments:
 * - local pointers get _ptr as a suffix to their name;
 * - RB offset-using functions get _offset.
 * Functions with two pointer arguments get a combined suffix, e.g., memcmp_offset_ptr. The pointer-variants are the 'original' ones,
 * i.e., those copied from an external source.
 * 
 * NOTE: some functions return one of their arguments, for example, memcpy returns a pointer to dst. By definition, memcpy_offset_ptr CANNOT
 * return (i.e., leak) the dst pointer, and hence such functions return VOID instead!
 */

/*
 * The inline assembly functions we used in our USENIX ATC 2016 paper were stripped from this file
 * because they are based on 3rd party code that either had no license or that had a BSD-incompatible license.
 * 
 * We used the following 3rd party functions (NOTE: some of these may no longer be available):
 * http://kam.mff.cuni.cz/~ondra/benchmark_string/core2/strlen_profile/variant/strlen_revised.s
 * http://kam.mff.cuni.cz/~ondra/benchmark_string/core2/memcpy_profile/variant/memcpy-sse2-unaligned.s
 * http://kam.mff.cuni.cz/~ondra/benchmark_string/core2/memcmp_profile/variant/memcmp_new.s
 * glibc 2.19's memset
 * 
 * The current functions in this file cannot be inlined and may therefore leak the RB pointer!
 */

#include <stdlib.h>

/*-----------------------------------------------------------------------------
    strlen
-----------------------------------------------------------------------------*/
size_t ipmon_strlen_ptr(const char* str)
{
	return strlen(str);
}

/*-----------------------------------------------------------------------------
    memcpy
-----------------------------------------------------------------------------*/
void* ipmon_memcpy_ptr_ptr(void* destination, const void* source, size_t num)
{
	return memcpy(destination, source, num);
}

// source offset is an offset into the RB
void* ipmon_memcpy_ptr_offset(void* destination, unsigned long source_offset, size_t num)
{
	void* actual_source;
	asm volatile("leaq (%%" RB_REGISTER ", %[source_offset]), %%rsi\n\t"
				 "movq %%rsi, %[actual_source]" :
				 [actual_source] "=r"(actual_source) :
				 [source_offset] "r"(source_offset) :
				 "%rsi");
	return memcpy(destination, actual_source, num);
}

// NOTE: returns void rather than void* !
void ipmon_memcpy_offset_ptr(unsigned long destination_offset, const void* source, size_t num)
{
	void* actual_destination;
	asm volatile("leaq (%%" RB_REGISTER ", %[destination_offset]), %%rdi\n\t"
				 "movq %%rdi, %[actual_destination]" :
				 [actual_destination] "=r"(actual_destination) :
				 [destination_offset] "r"(destination_offset) :
				 "%rdi");
	memcpy(actual_destination, source, num);
}

/*-----------------------------------------------------------------------------
    memcmp
-----------------------------------------------------------------------------*/

int ipmon_memcmp_ptr_ptr(const void* ptr1, const void* ptr2, size_t num)
{
	return memcmp(ptr1, ptr2, num);
}

int ipmon_memcmp_ptr_offset(const void* ptr1, unsigned long ptr2_offset, size_t num)
{
	void* actual_ptr2;
	asm volatile("leaq (%%" RB_REGISTER ", %[ptr2_offset]), %%rsi\n\t"
				 "movq %%rsi, %[actual_ptr2]" :
				 [actual_ptr2] "=r"(actual_ptr2) :
				 [ptr2_offset] "r"(ptr2_offset) :
				 "%rsi");
	return memcmp(ptr1, actual_ptr2, num);
}

int ipmon_memcmp_offset_ptr(unsigned long ptr1_offset, const void * ptr2, size_t num)
{
	void* actual_ptr1;
	asm volatile("leaq (%%" RB_REGISTER ", %[ptr1_offset]), %%rdi\n\t"
				 "movq %%rdi, %[actual_ptr1]" :
				 [actual_ptr1] "=r"(actual_ptr1) :
				 [ptr1_offset] "r"(ptr1_offset) :
				 "%rdi");
	return memcmp(actual_ptr1, ptr2, num);
}

/*-----------------------------------------------------------------------------
    memset
-----------------------------------------------------------------------------*/
void ipmon_memset_ptr(void* ptr, int value, size_t num)
{
	memset(ptr, value, num);
}

void ipmon_memset_offset(unsigned long offset, int value, size_t num)
{
	void* actual_ptr;
	asm volatile("leaq (%%" RB_REGISTER ", %[offset]), %%rdi\n\t"
				 "movq %%rdi, %[actual_ptr]" :
				 [actual_ptr] "=r"(actual_ptr) :
				 [offset] "r"(offset) :
				 "%rdi");
	memset(actual_ptr, value, num);
}


#endif /* IPMON_INLINES_H_ */
