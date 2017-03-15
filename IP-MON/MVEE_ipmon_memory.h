/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in IPMONLICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "../MVEE/Inc/MVEE_fake_syscall.h"
#include <sys/types.h>
#include <errno.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <alloca.h>
#include <string.h>

/*-----------------------------------------------------------------------------
    IP-MON Helper functions for argument/return size calculation

	These are specialized routines that calculate the size a data struture might
	occupy in the Replication Buffer.

	Note that we often have both a _layout_len and a _len function. The
	_layout_len function calculates the size we need to store information about
	the layout of the data struture. This is used in PRECALL handlers to
	determine if all variants passed an equivalent data structure to the
	syscall.

	The _len calculates the size we need to store the full data structure,
	including its data.
-----------------------------------------------------------------------------*/
STATIC INLINE size_t ipmon_iovec_bytes(const struct iovec* iov, int iovcnt)
{
	size_t result = 0;

	for (int i = 0; i < iovcnt; ++i)
		result += iov[i].iov_len;

	return result;
}

STATIC INLINE int ipmon_iovec_elems(const struct iovec* iov, size_t bytes)
{
	int elems = 0;

	// see how many elements we need 
	while (bytes != 0)
		bytes -= MIN(bytes, iov[elems++].iov_len);

	return elems;
}

STATIC INLINE size_t ipmon_iovec_layout_len(const struct iovec* iov, int iovcnt)
{
	return iovcnt * sizeof(unsigned long);
}

STATIC INLINE size_t ipmon_iovec_len(const struct iovec* iov, int iovcnt)
{
	size_t result = 0;

	for (int i = 0; i < iovcnt; ++i)
		result += iov[i].iov_len;

	return result;
}

STATIC INLINE size_t ipmon_msg_layout_len(const struct msghdr* hdr, int iovcnt)
{
	return sizeof(struct msghdr) + ipmon_iovec_len(hdr->msg_iov, iovcnt);
}

STATIC INLINE size_t ipmon_msg_len(const struct msghdr* hdr, int iovcnt)
{
	size_t result = sizeof(struct msghdr);

	result += hdr->msg_namelen;
	result += ipmon_iovec_len(hdr->msg_iov, iovcnt);
	result += hdr->msg_controllen;

	return result;
}

STATIC INLINE size_t ipmon_mmsg_layout_len(const struct mmsghdr* hdr, unsigned int vlen)
{
	size_t result = 0;

	for (int i = 0; i < vlen; ++i)
	{
		result += ipmon_msg_layout_len(&hdr->msg_hdr, hdr->msg_hdr.msg_iovlen);
		hdr ++;
	}

	return result;
}

STATIC INLINE size_t ipmon_mmsg_len(const struct mmsghdr* hdr, unsigned int vlen)
{
	size_t result = vlen * sizeof(unsigned int);

	for (int i = 0; i < vlen; ++i)
	{
		result += ipmon_msg_len(&hdr->msg_hdr, hdr->msg_hdr.msg_iovlen);
		hdr ++;
	}

	return result;
}

/*-----------------------------------------------------------------------------
    IP-MON serialization functions
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_iovec_layout_get_serialized_size(struct iovec* iov, int* alloc_size, int cnt)
{
	*alloc_size = cnt * sizeof(unsigned long);
}

STATIC INLINE void ipmon_msg_layout_get_serialized_size(struct msghdr* hdr, int* alloc_size, int cnt)
{
	ipmon_iovec_layout_get_serialized_size(hdr->msg_iov, alloc_size, cnt);
	*alloc_size += sizeof(struct msghdr);
}

STATIC INLINE void ipmon_mmsg_layout_get_serialized_size(struct mmsghdr* hdr, int* alloc_size, int vlen)
{
	int tmp_alloc;
	
	*alloc_size = 0;
	for (int i = 0; i < vlen; ++i)
	{
		ipmon_msg_layout_get_serialized_size(&hdr->msg_hdr, &tmp_alloc, hdr->msg_hdr.msg_iovlen);
		*alloc_size += tmp_alloc;
		hdr++;
	}	
}

STATIC INLINE void ipmon_iovec_get_serialized_size(struct iovec* iov, int* alloc_size, int* elems, size_t bytes_copied)
{
	*elems = ipmon_iovec_elems(iov, bytes_copied);
	*alloc_size = bytes_copied;
}

STATIC INLINE void ipmon_msg_get_serialized_size(struct msghdr* hdr, int* alloc_size, int* elems, size_t bytes_copied)
{
	*elems = ipmon_iovec_elems(hdr->msg_iov, bytes_copied);
	*alloc_size  = sizeof(struct msghdr) + bytes_copied;
	*alloc_size += hdr->msg_namelen + hdr->msg_controllen;
}

STATIC INLINE void ipmon_mmsg_get_serialized_size(struct mmsghdr* hdr, int* alloc_size, size_t messages_sent)
{
	int tmp_elems, tmp_alloc_size;

	*alloc_size = 0;

	for (int i = 0; i < messages_sent; ++i)
	{
		ipmon_msg_get_serialized_size(&hdr->msg_hdr, &tmp_alloc_size, &tmp_elems, hdr->msg_len);
		*alloc_size += tmp_alloc_size + sizeof(unsigned int);
		hdr++;
	}
}

STATIC INLINE int ipmon_iovec_layout_serialize(void* dst, struct iovec* src, int elems)
{
	for (int i = 0; i < elems; ++i)
		((unsigned long*)dst)[i] = src[i].iov_len;	

	return elems * sizeof(unsigned long);
}

STATIC INLINE int ipmon_msg_layout_serialize(void* dst, struct msghdr* hdr, int elems)
{
	struct msghdr* target = (struct msghdr*)dst;
	memset(target, 0, sizeof(struct msghdr));

	target->msg_iovlen = hdr->msg_iovlen;
	target->msg_namelen = hdr->msg_namelen;
	target->msg_controllen = hdr->msg_controllen;
	target->msg_flags = hdr->msg_flags;

    return sizeof(struct msghdr) + 
		ipmon_iovec_layout_serialize((void*)((unsigned long)target + sizeof(struct msghdr)),
								hdr->msg_iov,
								hdr->msg_iovlen);
}

STATIC INLINE int ipmon_mmsg_layout_serialize(void* dst, struct mmsghdr* hdr, int vlen)
{
	int offset = 0;

	for (int i = 0; i < vlen; ++i)
	{
		offset += ipmon_msg_layout_serialize((void*)((unsigned long)dst + offset),
											&hdr->msg_hdr,
											hdr->msg_hdr.msg_iovlen);
		hdr++;
	}

	return offset;
}

STATIC INLINE int ipmon_iovec_serialize(void* dst, struct iovec* src, int elems, size_t bytes_copied)
{
	// serialize iov data
	int offset = 0;
	int to_copy;
	int bytes_remaining = bytes_copied;
	for (int i = 0; i < elems; ++i)
	{
		to_copy = MIN(src[i].iov_len, bytes_remaining);

		if (to_copy > 0)
		{
			memcpy((void*)((unsigned long)dst + offset),
				   src[i].iov_base,
				   to_copy);

			bytes_remaining -= to_copy;
			offset += to_copy;
		}
	}		

	return offset;
}

STATIC INLINE int ipmon_msg_serialize(void* dst, struct msghdr* src, int elems, size_t bytes_copied)
{
	// serialize the header itself
	struct msghdr* target = (struct msghdr*)dst;
	memset(target, 0, sizeof(struct msghdr));

	target->msg_iovlen = src->msg_iovlen;
	target->msg_namelen = src->msg_namelen;
	target->msg_controllen = src->msg_controllen;
	target->msg_flags = src->msg_flags;

	// serialize the name
	if (src->msg_namelen)
		memcpy((void*)((unsigned long)target + sizeof(struct msghdr)), src->msg_name, src->msg_namelen);

	// serialize control messages (THIS SUCKS!)
	int offset = sizeof(struct msghdr) + src->msg_namelen;

	// there might be uninitialized shit between the messages. Get rid of it...
	if (src->msg_controllen)
	{
		memcpy((void*)((unsigned long)target + offset), src->msg_control, src->msg_controllen);

		struct cmsghdr* cmsg = CMSG_FIRSTHDR(src);
		struct cmsghdr* next;
		while(cmsg)
		{
			next = CMSG_NXTHDR(src, cmsg);

			if ((unsigned long)next > (unsigned long)cmsg + cmsg->cmsg_len)
			{
				memset((void*)((unsigned long)target + offset + cmsg->cmsg_len),
					   0,
					   (unsigned long)next - ((unsigned long)cmsg + cmsg->cmsg_len));
			}

			offset += (unsigned long)next - (unsigned long)cmsg;
			cmsg = next;
		}

		offset = src->msg_namelen + src->msg_controllen  + sizeof(struct msghdr);
	}

	// serialize the io vector
	return offset + ipmon_iovec_serialize((void*)((unsigned long)target + offset),
						 src->msg_iov,
						 elems,
						 bytes_copied);
}

STATIC INLINE int ipmon_mmsg_serialize(void* dst, struct mmsghdr* src, int msgs_sent)
{
	int offset = 0;
	int elems;

	for (int i = 0; i < msgs_sent; ++i)
	{
		*(unsigned int*)((unsigned long)dst + offset) = src->msg_len;
		offset += sizeof(unsigned int);

		elems = ipmon_iovec_elems(src->msg_hdr.msg_iov, src->msg_len);

		offset += ipmon_msg_serialize((void*)((unsigned long)dst + offset),
									 &src->msg_hdr,
									 elems,
									 src->msg_len);

		src++;
	}

	return offset;
}

STATIC INLINE int ipmon_iovec_deserialize(struct iovec* dst, void* src, int elems, size_t bytes_copied)
{
	int offset = 0;
	int to_copy;
	int bytes_remaining = bytes_copied;
	for (int i = 0; i < elems; ++i)
	{
		to_copy = MIN(dst[i].iov_len, bytes_remaining);

		if (to_copy > 0)
		{
			memcpy(dst[i].iov_base,
				   (void*)((unsigned long)src + offset),
				   to_copy);

			bytes_remaining -= to_copy;
			offset += to_copy; 
		}  
	}

	return offset;
}

STATIC INLINE int ipmon_msg_deserialize(struct msghdr* dst, void* src, int elems, size_t bytes_copied)
{
	struct msghdr* hdr = (struct msghdr*)src;

	dst->msg_namelen = hdr->msg_namelen;
	dst->msg_controllen = hdr->msg_controllen;
	dst->msg_flags = hdr->msg_flags;

	if (hdr->msg_namelen)
		memcpy(dst->msg_name, (void*)((unsigned long)src + sizeof(struct msghdr)), hdr->msg_namelen);
	if (hdr->msg_controllen)
		memcpy(dst->msg_control, (void*)((unsigned long)src + sizeof(struct msghdr) + hdr->msg_namelen), hdr->msg_controllen);

	int offset = sizeof(struct msghdr) + hdr->msg_namelen + hdr->msg_controllen;
	
	return offset + ipmon_iovec_deserialize(
		dst->msg_iov,
		(void*)((unsigned long)src + offset),
		elems,
		bytes_copied);						   
}

STATIC INLINE int ipmon_mmsg_deserialize(struct mmsghdr* dst, void* src, int msgs_sent)
{
	int offset = 0;

	for (int i = 0; i < msgs_sent; ++i)
	{	
		int bytes_from_current_msg = *(unsigned int*)((unsigned long)src + offset);
		int elems_from_current_msg = ipmon_iovec_elems(dst->msg_hdr.msg_iov, bytes_from_current_msg);

		dst[i].msg_len = bytes_from_current_msg;

		offset += sizeof(unsigned int);
		offset += ipmon_msg_deserialize(&dst->msg_hdr,
									   (void*)((unsigned long)src + offset),
									   elems_from_current_msg,
									   bytes_from_current_msg);

		dst++;
	}

	return offset;
}

/*-----------------------------------------------------------------------------
    IP-MON memcmp functions - One of the structures is read from the buffer,
    whereas the other is read straight from the application memory.
-----------------------------------------------------------------------------*/
STATIC INLINE int ipmon_ptrcmp(struct ipmon_syscall_data* data, const void* ptr2, size_t sz)
{
	long _ptr1 = *(long*) data->data;
	long _ptr2 = *(long*) ptr2;

	if ((_ptr1 | _ptr2) && (!_ptr1 || !_ptr2))
		return 1;

	return 0;
}

STATIC INLINE int ipmon_wordcmp(struct ipmon_syscall_data* data, const void* ptr, size_t sz)
{
	long word1 = *(long*) data->data;
	long word2 = *(long*) ptr;

	if (word1 != word2)
		return 2;

	return 0;
}

STATIC INLINE int ipmon_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t sz)
{
	return memcmp(data->data, ptr, sz);
}

STATIC INLINE int ipmon_iovec_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t bytes)
{	
	struct iovec* iov = (struct iovec*)ptr;

	int elems, alloc_size;
	ipmon_iovec_get_serialized_size(iov, &alloc_size, &elems, bytes);
	void* tmp = alloca(alloc_size);
	ipmon_iovec_serialize(tmp, iov, elems, bytes);

	return ipmon_cmp(data, tmp, alloc_size);
}

STATIC INLINE int ipmon_iovec_layout_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t iovcnt)
{
	struct iovec* iov = (struct iovec*)ptr;

	int alloc_size;
	ipmon_iovec_layout_get_serialized_size(iov, &alloc_size, iovcnt);
	void* tmp = alloca(alloc_size);
	ipmon_iovec_layout_serialize(tmp, iov, iovcnt);

	return ipmon_cmp(data, tmp, alloc_size);
}

STATIC INLINE int ipmon_msg_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t bytes)
{
	struct msghdr* hdr = (struct msghdr*)ptr;

	int elems, alloc_size;
	ipmon_msg_get_serialized_size(hdr, &alloc_size, &elems, bytes);
	void* tmp = alloca(alloc_size);
	ipmon_msg_serialize(tmp, hdr, elems, bytes);

	return ipmon_cmp(data, tmp, alloc_size);
}

STATIC INLINE int ipmon_msg_layout_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t dummy)
{
	struct msghdr* hdr = (struct msghdr*)ptr;

	int alloc_size;
	ipmon_msg_layout_get_serialized_size(hdr, &alloc_size, hdr->msg_iovlen);
	void* tmp = alloca(alloc_size);
	ipmon_msg_layout_serialize(tmp, hdr, hdr->msg_iovlen);

	return ipmon_cmp(data, tmp, alloc_size);
}

STATIC INLINE int ipmon_mmsg_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t msgs_to_compare)
{
	struct mmsghdr* hdr = (struct mmsghdr*)ptr;

	int alloc_size;
	ipmon_mmsg_get_serialized_size(hdr, &alloc_size, msgs_to_compare);
	void* tmp = alloca(alloc_size);
	ipmon_mmsg_serialize(tmp, hdr, msgs_to_compare);

	return ipmon_cmp(data, tmp, alloc_size);
}

STATIC INLINE int ipmon_mmsg_layout_cmp(struct ipmon_syscall_data* data, const void* ptr, size_t len)
{
	struct mmsghdr* hdr = (struct mmsghdr*)ptr;

	int alloc_size;
	ipmon_mmsg_layout_get_serialized_size(hdr, &alloc_size, len);
	void* tmp = alloca(alloc_size);
	ipmon_mmsg_layout_serialize(tmp, hdr, len);

	return ipmon_cmp(data, tmp, alloc_size);
}

/*-----------------------------------------------------------------------------
    IP-MON generic replication/checking functions
-----------------------------------------------------------------------------*/

/* function to check if two pointers are equivalent (<=> both either NULL or not-NULL) */

STATIC INLINE void ipmon_wordcpy_to(struct ipmon_syscall_data* dst, void* src, size_t sz)
{
	*(long*)dst->data = *(long*)src;
}

STATIC INLINE void ipmon_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t sz)
{
	memcpy(dst->data, src, sz);
}

STATIC INLINE void ipmon_wordcpy_from(void* dst, struct ipmon_syscall_data* src, size_t sz)
{
	*(long*)dst = *(long*)src->data;
}

STATIC INLINE void ipmon_cpy_from(void* dst, struct ipmon_syscall_data* src, size_t sz)
{
	memcpy(dst, src->data, sz);
}

/*-----------------------------------------------------------------------------
    IP-MON I/O vector copying. We intentionally serialize I/O vectors in a format
	that allows us to compare them directly
-----------------------------------------------------------------------------*/

STATIC INLINE void ipmon_iovec_layout_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t cnt)
{
	struct iovec* iov = (struct iovec*)src;

	int alloc_size;
	ipmon_iovec_layout_get_serialized_size(iov, &alloc_size, cnt);
	void* data = alloca(alloc_size);
	ipmon_iovec_layout_serialize(data, iov, cnt);

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_iovec_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t bytes_copied)
{
	struct iovec* iov = (struct iovec*)src;

	int elems, alloc_size;
	ipmon_iovec_get_serialized_size(iov, &alloc_size, &elems, bytes_copied);	
	void* data = alloca(alloc_size);
	ipmon_iovec_serialize(data, iov, elems, bytes_copied);

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_iovec_cpy_from(void* dst, struct ipmon_syscall_data* src, size_t bytes_copied)
{
	struct iovec* iov = (struct iovec*)dst;

	int elems = ipmon_iovec_elems(iov, bytes_copied);
	int alloc_size = src->len;
	void* data = alloca(alloc_size);
	ipmon_cpy_from(data, src, alloc_size);

	ipmon_iovec_deserialize(iov, data, elems, bytes_copied);
}

/*-----------------------------------------------------------------------------
    IP-MON Message Copying
-----------------------------------------------------------------------------*/

STATIC INLINE void ipmon_msg_layout_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t cnt)
{
	struct msghdr* hdr = (struct msghdr*)src;

	int alloc_size;
	ipmon_msg_layout_get_serialized_size(hdr, &alloc_size, cnt);
	void* data = alloca(alloc_size);
	ipmon_msg_layout_serialize(data, hdr, cnt);

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_msg_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t bytes_copied)
{
	struct msghdr* hdr = (struct msghdr*)src;

	int elems, alloc_size;
	ipmon_msg_get_serialized_size(hdr, &alloc_size, &elems, bytes_copied);	
	void* data = alloca(alloc_size);
	ipmon_msg_serialize(data, hdr, elems, bytes_copied);

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_msg_cpy_from(void* dst, struct ipmon_syscall_data* src, size_t bytes_copied)
{
	struct msghdr* hdr = (struct msghdr*)dst;

	int elems = ipmon_iovec_elems(hdr->msg_iov, bytes_copied);
	int alloc_size = src->len;
	void* data = alloca(alloc_size);
	ipmon_cpy_from(data, src, alloc_size);

	ipmon_msg_deserialize(hdr, data, elems, bytes_copied);
}

/*-----------------------------------------------------------------------------
    IP-MON Message Vector Copying
-----------------------------------------------------------------------------*/

STATIC INLINE void ipmon_mmsg_layout_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t cnt)
{
	struct mmsghdr* hdr = (struct mmsghdr*)src;

	int alloc_size;
	ipmon_mmsg_layout_get_serialized_size(hdr, &alloc_size, cnt);
	void* data = alloca(alloc_size);
	memset(data, 0, alloc_size);
	ipmon_mmsg_layout_serialize(data, hdr, cnt);

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_mmsg_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t msgs_copied)
{
	struct mmsghdr* hdr = (struct mmsghdr*)src;

	int alloc_size;
	ipmon_mmsg_get_serialized_size(hdr, &alloc_size, msgs_copied);	
	void* data = alloca(alloc_size);
	ipmon_mmsg_serialize(data, hdr, msgs_copied);

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_mmsg_cpy_from(void* dst, struct ipmon_syscall_data* src, size_t msgs_copied)
{
	struct mmsghdr* hdr = (struct mmsghdr*)dst;

	int alloc_size = src->len;
	void* data = alloca(alloc_size);
	ipmon_cpy_from(data, src, alloc_size);

	ipmon_mmsg_deserialize(hdr, data, msgs_copied);
}

STATIC INLINE void ipmon_mmsg_lens_cpy_to(struct ipmon_syscall_data* dst, void* src, size_t msgs_copied)
{
	struct mmsghdr* hdr = (struct mmsghdr*)src;

	int alloc_size = msgs_copied * sizeof(unsigned int);
	void* data = alloca(alloc_size);
	for (int i = 0; i < msgs_copied; ++i)
	{
		((unsigned int*)data)[i] = hdr->msg_len;
		hdr++;
	}

	ipmon_cpy_to(dst, data, alloc_size);
}

STATIC INLINE void ipmon_mmsg_lens_cpy_from(void* dst, struct ipmon_syscall_data* src, size_t msgs_copied)
{
	struct mmsghdr* hdr = (struct mmsghdr*)dst;

	int alloc_size = msgs_copied * sizeof(unsigned int);
	void* data = alloca(alloc_size);
	ipmon_cpy_from(data, src, alloc_size);

	for (int i = 0; i < msgs_copied; ++i)
	{
		hdr->msg_len = ((unsigned int*)data)[i];
		hdr++;
	}
}

/*-----------------------------------------------------------------------------
    IP-MON generic replication/checking functions
-----------------------------------------------------------------------------*/

STATIC INLINE struct ipmon_syscall_data* ipmon_get_data_at (struct ipmon_syscall_entry* entry, unsigned int data_offset)
{
	return (struct ipmon_syscall_data*)((unsigned long)entry + data_offset);
}

// Called from the PRECALL handlers
//
// The master copies <sz> bytes from <ptr> into the IP-MON buffer
// as the <num>'th argument for the ipmon_syscall_entry at <entry_offset>
// Copying is done using the <cpy> function
//
// The slaves compare the <num>'th argument of the ipmon_syscall_entry at <entry_offset>
// with their own argument at <ptr>.
// The comparison is done using cmpfunc <cmp>
#define ipmon_check(__entry, __num, __ptr, __size_in_buffer, __size_for_cpyfunc, __cpy, __cmp) \
	{																	\
		unsigned long __arg_offset = sizeof(struct ipmon_syscall_entry); \
		struct ipmon_syscall_data* __arg = ipmon_get_data_at(__entry, __arg_offset); \
																		\
		/* skip to the argument we're checking. - We start counting at 1 */ \
		for (unsigned char __i = 1; __i < __num; ++__i)					\
		{																\
			__arg_offset += __arg->len;									\
			__arg = ipmon_get_data_at(__entry, __arg_offset);			\
		}																\
																		\
		/* The master records the length and then copies the data*/		\
		if (ipmon_variant_num == 0)										\
		{																\
			__arg->len = DATASIZE(__size_in_buffer);					\
			__cpy(__arg, __ptr, __size_for_cpyfunc);					\
		}																\
		else															\
		{																\
			int __ret;													\
																		\
			/* check if the size matches */								\
			if (DATASIZE(__size_in_buffer) != __arg->len)				\
				ipmon_arg_verify_failed(__entry->syscall_no, -__num, __size_in_buffer); \
																		\
			/* check if the data matches */								\
			if ((__ret = __cmp(__arg, __ptr, __size_for_cpyfunc)))		\
				ipmon_arg_verify_failed(__entry->syscall_no, __num, (unsigned long)__ptr); \
		}																\
	}																	

// Called from the POSTCALL handlers
//
// The master copies its data to the IP-MON buffer
// as the <num>'th return value in the ipmon_syscall_entry at offset <entry_offset>
// Copying is done using the <to_cpy> function
//
// The slaves copy the data back from the IP-MON buffer
// to their own return value at <ptr>
// Copying is done using the <from_cpy> function
#define ipmon_replicate(__entry, __num, __ptr, __size_in_buffer, __size_for_cpyfunc, __to_cpy, __from_cpy) \
	{																	\
		/*return data entries directly follow the argument data entries */ \
		unsigned long __ret_offset = __entry->syscall_args_size + sizeof(struct ipmon_syscall_entry); \
		struct ipmon_syscall_data* __ret = ipmon_get_data_at(__entry, __ret_offset); \
																		\
		/* skip to the return value we're replicating - Again, we start counting at 1 */ \
		for (unsigned char __i = 1; __i < __num; ++__i)					\
		{																\
			__ret_offset += __ret->len;									\
			__ret = ipmon_get_data_at(__entry, __ret_offset);			\
		}																\
																		\
		if (ipmon_variant_num == 0)										\
		{																\
			__ret->len = DATASIZE(__size_in_buffer);					\
			__to_cpy(__ret, __ptr, __size_for_cpyfunc);					\
		}																\
		else															\
		{																\
			__from_cpy(__ptr, __ret, __size_for_cpyfunc);				\
		}																\
	}																	\

/*-----------------------------------------------------------------------------
    IP-MON Counting Macros
-----------------------------------------------------------------------------*/
#define ARG										\
	args_size

#define RET										\
	ret_size

#define DATASIZE(sz)							\
	ROUND_UP(sizeof(unsigned long) + sz, 8)

#define COUNTREG(cnt_ptr)						\
	*cnt_ptr += DATASIZE(sizeof(unsigned long))

#define COUNTBUFFER(cnt_ptr, buf_ptr, buf_sz)	\
	if (buf_ptr) *cnt_ptr += DATASIZE(buf_sz)

#define COUNTSTRING(cnt_ptr, str)						\
	if (str) *cnt_ptr += DATASIZE(strlen((char*)str))

#define COUNTIOVEC(cnt_ptr, vec, cnt)									\
	if (vec && cnt > 0)													\
	{																	\
		*cnt_ptr += DATASIZE(ipmon_iovec_len((const struct iovec*)vec, cnt)); \
	}

#define COUNTIOVECLAYOUT(cnt_ptr, vec, cnt)								\
	if (vec && cnt > 0)													\
	{																	\
		*cnt_ptr += DATASIZE(ipmon_iovec_layout_len((const struct iovec*)vec, cnt));	\
	}

#define COUNTMSG(cnt_ptr, hdr)											\
	if (hdr)															\
	{																	\
		const struct msghdr* tmp = (const struct msghdr*)hdr;			\
		*cnt_ptr += DATASIZE(ipmon_msg_len(tmp, tmp->msg_iovlen));		\
	}

#define COUNTMSGLAYOUT(cnt_ptr, hdr)									\
	if (hdr)															\
	{																	\
		const struct msghdr* tmp = (const struct msghdr*)hdr;			\
		*cnt_ptr += DATASIZE(ipmon_msg_layout_len(tmp, tmp->msg_iovlen)); \
	}

#define COUNTMMSG(cnt_ptr, hdr, vlen)									\
	if (hdr)															\
	{																	\
		const struct mmsghdr* tmp = (const struct mmsghdr*)hdr;			\
		*cnt_ptr += DATASIZE(ipmon_mmsg_len(tmp, vlen));					\
	}

#define COUNTMMSGLAYOUT(cnt_ptr, hdr, vlen)								\
	if (hdr)															\
	{																	\
		const struct mmsghdr* tmp = (const struct mmsghdr*)hdr;			\
		*cnt_ptr += DATASIZE(ipmon_mmsg_layout_len(tmp, vlen));			\
	}


/*-----------------------------------------------------------------------------
    IPMON Checking Macros - those memcmp/memcpy functions MUST BE INLINED!!!!

	We have to discuss how we do this!
-----------------------------------------------------------------------------*/
// Compare two registers
#define CHECKREG(arg)													\
	{																	\
		int num = ++order;												\
		ipmon_check(entry, num, &arg, sizeof(unsigned long), sizeof(unsigned long), ipmon_wordcpy_to, ipmon_wordcmp); \
	}

// Checks whether two pointers are either both null or both non-null
#define CHECKPOINTER(arg)												\
	{																	\
		int num = ++order;												\
		ipmon_check(entry, num, &arg, sizeof(unsigned long), sizeof(unsigned long), ipmon_wordcpy_to, ipmon_ptrcmp); \
	}

// Compare two strings
#define CHECKSTRING(arg)												\
	if (arg)															\
	{																	\
		size_t len = strlen((char*) arg);								\
		int num = ++order;												\
		ipmon_check(entry, num, (void*)arg, len, len, ipmon_cpy_to, ipmon_cmp); \
	}

// Compare two fixed sized buffers
#define CHECKBUFFER(buffer, len)										\
	 if (buffer)											            \
	 {																	\
		 int num = ++order;												\
		 ipmon_check(entry, num, (void*)buffer, len, len, ipmon_cpy_to, ipmon_cmp); \
	 }

// Compare two I/O vectors
#define CHECKIOVEC(vec, cnt)											\
	if (vec && cnt > 0)													\
	{																	\
		size_t size_in_buffer = ipmon_iovec_len((struct iovec*)vec, cnt); \
		int num = ++order;												\
		ipmon_check(entry, num, (void*)vec, size_in_buffer, cnt, ipmon_iovec_cpy_to, ipmon_iovec_cmp); \
	}

// Compare two I/O vector layouts
#define CHECKIOVECLAYOUT(vec, cnt)										\
	if (vec && cnt > 0)													\
	{																	\
		size_t size_in_buffer = ipmon_iovec_layout_len((struct iovec*)vec, cnt); \
		int num = ++order;												\
		ipmon_check(entry, num, (void*)vec, size_in_buffer, cnt, ipmon_iovec_layout_cpy_to, ipmon_iovec_layout_cmp); \
	}

// Compare two Messages
#define CHECKMSG(vec)													\
	if (vec)															\
	{																	\
		const struct msghdr* msg = (const struct msghdr*)vec;			\
		size_t size_in_buffer   = ipmon_msg_len(msg, msg->msg_iovlen);	\
		size_t size_for_cpyfunc = ipmon_iovec_bytes(msg->msg_iov, msg->msg_iovlen); \
		int num = ++order;												\
		ipmon_check(entry, num, (void*)vec, size_in_buffer, size_for_cpyfunc, ipmon_msg_cpy_to, ipmon_msg_cmp); \
	}

// Compare two Message layouts
#define CHECKMSGLAYOUT(vec)												\
	if (vec)															\
	{																	\
		const struct msghdr* msg = (const struct msghdr*)vec;			\
		size_t size_in_buffer   = ipmon_msg_layout_len(msg, msg->msg_iovlen); \
		size_t size_for_cpyfunc = msg->msg_iovlen;						\
		int num = ++order;												\
		ipmon_check(entry, num, (void*)vec, size_in_buffer, size_for_cpyfunc, ipmon_msg_layout_cpy_to, ipmon_msg_layout_cmp); \
	}

// Compare two Message Vectors
#define CHECKMMSG(vec, vlen)											\
	if (vec)															\
	{																	\
		const struct mmsghdr* hdr = (const struct mmsghdr*)vec;			\
		size_t size_in_buffer = ipmon_mmsg_len(hdr, vlen);				\
		int num = ++order;												\
		ipmon_check(entry, num, (void*)vec, size_in_buffer, vlen, ipmon_mmsg_cpy_to, ipmon_mmsg_cmp); \
	}

// Compare two Message Vector layouts
#define CHECKMMSGLAYOUT(vec, vlen)										\
	if (vec)															\
	{																	\
		const struct mmsghdr* hdr = (const struct mmsghdr*)vec;			\
		size_t size_in_buffer = ipmon_mmsg_layout_len(hdr, vlen);		\
		int num = ++order;												\
		ipmon_check(entry, num, (void*)vec, size_in_buffer, vlen, ipmon_mmsg_layout_cpy_to, ipmon_mmsg_layout_cmp); \
	}

// Compare two Sockaddrs
#define CHECKSOCKADDR(_addr, addrlen)									\
	if (_addr && addrlen > 0)											\
	{																	\
		struct sockaddr* addr = (struct sockaddr*)_addr;				\
		char textaddr[1024];											\
																		\
		switch(addr->sa_family)											\
		{																\
			case AF_INET:												\
			case AF_INET6:												\
			{															\
				inet_ntop(addr->sa_family, &((struct sockaddr_in*)addr)->sin_addr, textaddr, 1024);	\
				break;													\
			}															\
			case AF_FILE:												\
			{															\
				strncpy(textaddr, ((struct sockaddr_un*)addr)->sun_path, 1024);	\
				break;													\
			}															\
			default:													\
			{															\
				sprintf(textaddr, "Fam: %d", addr->sa_family);			\
				break;													\
			}															\
		}																\
		CHECKSTRING(textaddr);											\
	}

// Replicate a buffer
#define REPLICATEBUFFER(buffer, len)									\
	if (success && buffer && len > 0)									\
	{																	\
		int num = ++order;												\
		ipmon_replicate(entry, num, (void*)buffer, len, len, ipmon_cpy_to, ipmon_cpy_from);	\
	}

// Replicate an I/O vector
#define REPLICATEIOVEC(vec, bytes)										\
	if (success && vec && bytes > 0)									\
	{																	\
		struct iovec* iov = (struct iovec*)vec;							\
		int actual_elems_copied = ipmon_iovec_elems(iov, bytes);			\
		size_t size_in_buffer = ipmon_iovec_len(iov, actual_elems_copied); \
		int num = ++order;												\
		ipmon_replicate(entry, num, (void*)vec, actual_elems_copied, bytes, ipmon_iovec_cpy_to, ipmon_iovec_cpy_from); \
	}

// Replicate a Message 
#define REPLICATEMSG(vec, bytes)										\
	if (success && vec)													\
	{																	\
		const struct msghdr* hdr = (const struct msghdr*)vec;			\
		int actual_elems_copied = ipmon_iovec_elems(hdr->msg_iov, bytes); \
		size_t size_in_buffer = ipmon_msg_len(hdr, actual_elems_copied); \
		int num = ++order;												\
		ipmon_replicate(entry, num, (void*)vec, size_in_buffer, bytes, ipmon_msg_cpy_to, ipmon_msg_cpy_from); \
	}

// Replicate a Message Vector
#define REPLICATEMMSG(vec, msgs_sent)									\
	if (success && vec)													\
	{																	\
		const struct mmsghdr* hdr = (const struct mmsghdr*)vec;			\
		size_t size_in_buffer = ipmon_mmsg_len(hdr, msgs_sent);			\
		int num = ++order;												\
		ipmon_replicate(entry, num, (void*)vec, size_in_buffer, msgs_sent, ipmon_mmsg_cpy_to, ipmon_mmsg_cpy_from); \
	}

#define REPLICATEMMSGLENS(vec, msgs_sent)								\
	{																	\
		size_t size_in_buffer = msgs_sent * sizeof(unsigned int);		\
		int num = ++order;												\
		ipmon_replicate(entry, num, (void*)vec, size_in_buffer, msgs_sent, ipmon_mmsg_lens_cpy_to, ipmon_mmsg_lens_cpy_from); \
	}
