/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in IPMONLICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <alloca.h>
#include <stddef.h>
#include "MVEE_ipmon.h"
#include "MVEE_ipmon_inlines.h"
#include "MVEE_ipmon_memory.h"
#include "../MVEE/Inc/MVEE_fake_syscall.h"

//#define IPMON_DEBUG

/*-----------------------------------------------------------------------------
    Replication buffer needs complete hiding, these functions access it
-----------------------------------------------------------------------------*/

/* TODO: offsetof for these as well */
#define IPMON_RB_OFFSET_NUMVARIANTS          "0"
#define IPMON_RB_OFFSET_USABLE_SIZE          "4"
#define IPMON_RB_OFFSET_HAVE_PENDING_SIGNALS "8"

#define GENERATE_GET_RB(type, name, offset)   		\
STATIC INLINE type rb_ ## name()              		\
{                                             		\
	type output;                              		\
	__asm__ volatile (                    		    \
		"mov " offset "(%%" RB_REGISTER "), %0; "   \
		: "=r"(output) : "r"(output):);				\
	return output;                  	          	\
}

GENERATE_GET_RB(int, numvariants, IPMON_RB_OFFSET_NUMVARIANTS)                     /* rb_numvariants */
GENERATE_GET_RB(int, usable_size, IPMON_RB_OFFSET_USABLE_SIZE)                     /* rb_usable_size */
GENERATE_GET_RB(long, have_pending_signals, IPMON_RB_OFFSET_HAVE_PENDING_SIGNALS)  /* rb_have_pending_signals */

STATIC INLINE unsigned long variant_offset(unsigned int variant)
{
	return 64 + variant*sizeof(ipmon_variant_info);
}

#define GENERATE_GET_VARIANT(name) \
STATIC INLINE unsigned int variant_info_ ## name(unsigned int variant) 								\
{																									\
	int output;																						\
	unsigned long offset = variant_offset(variant) + offsetof( struct ipmon_variant_info, name );	\
																									\
	__asm__ volatile (																				\
		"mov (%%" RB_REGISTER ", %1), %0	; "														\
		: "=r"(output) : "r"(offset), "r"(output));						\
	return output;																					\
}

GENERATE_GET_VARIANT(pos)    /* variant_info_pos */
GENERATE_GET_VARIANT(status) /* variant_info_status */

#define GENERATE_SET_VARIANT(name) \
STATIC INLINE void variant_info_ ## name ## _set(unsigned int variant, int new_value)				\
{																									\
	unsigned long offset = variant_offset(variant) + offsetof( struct ipmon_variant_info, name );	\
																									\
	__asm__ volatile (																				\
		"mov %1, (%%" RB_REGISTER ", %0); "															\
		:: "r"(offset), "r"(new_value));															\
}

GENERATE_SET_VARIANT(pos)    /* variant_info_pos_set */
GENERATE_SET_VARIANT(status) /* variant_info_status_set */

/* These take offsets relative to the RB base address */
#define GENERATE_SYSCALL_ENTRY_GET(type, member)								\
STATIC INLINE type syscall_entry_ ## member(unsigned long entry_offset)			\
{																				\
	type output;																\
	entry_offset += offsetof( struct ipmon_syscall_entry, syscall_ ## member );	\
	__asm__ volatile (															\
		"mov (%%" RB_REGISTER ", %1), %0"										\
		: "=r"(output) : "r"(entry_offset), "r"(output));				\
	return output;																\
}

#define GENERATE_SYSCALL_ENTRY_SET(type, member)												\
STATIC INLINE void syscall_entry_ ## member ## _set(unsigned long entry_offset, type new_value)	\
{																								\
	entry_offset += offsetof( struct ipmon_syscall_entry, syscall_ ## member );					\
	__asm__ volatile (																			\
		"mov %0, (%%" RB_REGISTER ", %1)"														\
		:: "r"(new_value), "r"(entry_offset));													\
}

#define GENERATE_SYSCALL_ACCESSORS(type, member)	\
	GENERATE_SYSCALL_ENTRY_GET(type, member)		\
	GENERATE_SYSCALL_ENTRY_SET(type, member)

GENERATE_SYSCALL_ACCESSORS(unsigned int,  no) /* syscall_entry_no, syscall_entry_no_set */
GENERATE_SYSCALL_ACCESSORS(unsigned char, checked) /* syscall_entry_checked, syscall_entry_checked_set */
GENERATE_SYSCALL_ACCESSORS(unsigned char, is_mastercall) /* syscall_entry_is_mastercall, syscall_entry_is_mastercall_set */
GENERATE_SYSCALL_ACCESSORS(unsigned char, is_blocking) /* syscall_entry_is_blocking, syscall_entry_is_blocking_set */
// hand-written accesses: struct ipmon_condvar syscall_results_available;                // 8    - optimized condition variable. Does not support consecutive wait operations
// hand-written accesses: struct ipmon_barrier syscall_lockstep_barrier;                 // 12   - used for lock-stepping
GENERATE_SYSCALL_ACCESSORS(unsigned int,  entry_size) /* syscall_entry_entry_size, syscall_entry_entry_size_set */
GENERATE_SYSCALL_ACCESSORS(unsigned int,  args_size) /* syscall_entry_args_size, syscall_entry_args_size_set */
GENERATE_SYSCALL_ACCESSORS(long,          return_value) /* syscall_entry_return_value, syscall_entry_return_value_set */

STATIC INLINE unsigned long syscall_data_len(unsigned long entry_offset)
{
	entry_offset += offsetof(struct ipmon_syscall_data, len);

	unsigned long output;
	__asm__ volatile (
		"mov (%%" RB_REGISTER ",%1), %0; "
		: "=r"(output) : "r"(entry_offset), "r"(output));
	return output;
}

STATIC INLINE unsigned long syscall_data_len_set(unsigned long entry_offset, unsigned long new_value)
{
	entry_offset += offsetof(struct ipmon_syscall_data, len);

	unsigned long output;
	__asm__ volatile (
		"mov %1, (%%" RB_REGISTER ",%0); "
		:: "r"(entry_offset), "r"(new_value));
}

/*-----------------------------------------------------------------------------
    ipmon_current_entry_offset - the pos we store in RB->variant_info is
    relative to the start of the syscall_entry array.
    The entry offset is relative to the start of the RB
-----------------------------------------------------------------------------*/
STATIC INLINE
unsigned long ipmon_current_entry_offset()
{
	return offsetof(struct ipmon_buffer, variant_info) +
			sizeof(struct ipmon_variant_info) * rb_numvariants() +
			variant_info_pos(ipmon_variant_num);
}

// TODO:
	// struct ipmon_syscall_data syscall_args[]             // 32   - These are not fixed size
	// struct ipmon_syscall_data syscall_returns[]

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
//
// Retard check - is the loaded glibc compatible with IP-MON or not?
//
unsigned char            ipmon_initialized       = 0;
unsigned char            ipmon_libc_compatible   = 0;
unsigned char            ipmon_kernel_compatible = 0;
unsigned char            ipmon_variant_num       = 0;

//
// Mask of syscalls that may be handled by IP-MON and bypass the ptracer
// Note that mask and kernelmask may differ because we might request
// that certain calls (e.g. sys_futex) be allowed to bypass the ptracer
// even if we want to dispatch them as checked calls in IP-MON.
// 
IPMON_MASK(mask);
IPMON_MASK(kernelmask);

//
// epoll support
//
unsigned long ipmon_epoll_map[MAX_FDS][MAX_FDS];
int           ipmon_epoll_map_spinlock = 1;
volatile int* ipmon_epoll_map_lock_ptr = &ipmon_epoll_map_spinlock;

/*-----------------------------------------------------------------------------
    IP-MON debugging
-----------------------------------------------------------------------------*/
#ifdef IPMON_DEBUG
void ipmon_log(const char* msg, long v) {
	char buf[150]; /* TODO */
	sprintf(buf, "IPMON DEBUG: %s = %ld\n", msg, v);
	ipmon_checked_syscall(__NR_write, 1, buf, strlen(buf) + 1, 0, 0, 0);
}
void sigill_debug(long a, long b, long c, long d) {
	__asm__ volatile ("mov %0, %%rax ; mov %1, %%rbx; mov %2, %%rcx ; mov %3, %%rdx ; ud2" :: "r"(a), "r"(b), "r"(c), "r"(d));
}
#else
#define ipmon_log(msg, v) /* nothing */
#endif

/*-----------------------------------------------------------------------------
    IP-MON shared memory regions
-----------------------------------------------------------------------------*/
// This is the buffer we're using to replicate syscalls
//__thread long                 ipmon_replication_buffer_id = -1;
//__thread struct ipmon_buffer* ipmon_replication_buffer    = NULL;

// This buffer contains information about the file types for each fd
long           ipmon_reg_file_map_id       = -1;
char*          ipmon_reg_file_map          = NULL;

/*-----------------------------------------------------------------------------
    ipmon_arg_verify_failed - Just crash the variant. It's super user friendly!
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_arg_verify_failed(void* ptr)
{
	*(volatile unsigned int*)((unsigned long)0x1000000000000000 | ((unsigned long)ptr)) = 0;
                             // 0000000000000000
}

/*-----------------------------------------------------------------------------
    IP-MON epoll support
-----------------------------------------------------------------------------*/
#define atomic_decrement_and_test(mem)					\
	({ unsigned char __result;							\
	__asm __volatile ("lock decl %0; sete %1"			\
					  : "=m" (*mem), "=qm" (__result)	\
					  : "m" (*mem));					\
	__result; })

STATIC INLINE void ipmon_epoll_lock()
{
	while (1)
	{
		if (atomic_decrement_and_test(ipmon_epoll_map_lock_ptr))
			return;

		while (*ipmon_epoll_map_lock_ptr <= 0)
			cpu_relax();
	}
}

STATIC INLINE void ipmon_epoll_unlock()
{
	gcc_barrier();
	*ipmon_epoll_map_lock_ptr = 1;
}

STATIC INLINE void ipmon_epoll_set_ptr_for_fd(int epoll_fd, int fd, unsigned long ptr)
{
	ipmon_epoll_map[epoll_fd][fd] = ptr;
}

STATIC INLINE unsigned long ipmon_epoll_get_ptr_for_fd(int epoll_fd, int fd)
{
	return ipmon_epoll_map[epoll_fd][fd];
}

STATIC INLINE int ipmon_epoll_get_fd_for_ptr(int epoll_fd, unsigned long ptr)
{
	// optimization
	if (ptr < 4096)
		return ptr;

	for (int i = 0; i < MAX_FDS; ++i)
		if (ipmon_epoll_map[epoll_fd][i] == ptr)
			return i;

	return 0;
}

/*-----------------------------------------------------------------------------
    Keeping track of blocking/non-blocking system calls
-----------------------------------------------------------------------------*/
STATIC INLINE char ipmon_get_file_type(unsigned long fd)
{
	if (fd > 4096)
		return 0;

	return ipmon_reg_file_map[fd];
}

/*-----------------------------------------------------------------------------
    ipmon_can_read
-----------------------------------------------------------------------------*/
STATIC INLINE bool ipmon_can_read(long fd)
{
#if CURRENT_POLICY >= SOCKET_RO_POLICY
	return true;
#elif CURRENT_POLICY >= NONSOCKET_RO_POLICY
	char type = ipmon_get_file_type(fd) & (~MVEE_BLOCKING_FD);

	if (type != FT_SOCKET_NON_BLOCKING)
		return true;
	return false;
#else
	return false;
#endif
}


/*-----------------------------------------------------------------------------
    ipmon_can_write
-----------------------------------------------------------------------------*/
STATIC INLINE bool ipmon_can_write(long fd)
{
#if CURRENT_POLICY >= SOCKET_RW_POLICY
	return true;
#elif CURRENT_POLICY >= NONSOCKET_RW_POLICY
	char type = ipmon_get_file_type(fd) & (~MVEE_BLOCKING_FD);

	if (type != FT_SOCKET_NON_BLOCKING)
		return true;
	return false;
#else
	return false;
#endif
}

/*-----------------------------------------------------------------------------
    uname - (struct utsname* buf)
-----------------------------------------------------------------------------*/
UNSYNCED(uname);

/*-----------------------------------------------------------------------------
    getpriority - (int which, int who)
-----------------------------------------------------------------------------*/
CALCSIZE(getpriority)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(getpriority)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    nanosleep - (const struct timespec* req, struct timespec* rem)
-----------------------------------------------------------------------------*/
CALCSIZE(nanosleep)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG1, sizeof(struct timespec));
	COUNTBUFFER(RET, ARG2, sizeof(struct timespec));
}

PRECALL(nanosleep)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKBUFFER(ARG1, sizeof(struct timespec));
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

POSTCALL(nanosleep)
{
	REPLICATEBUFFER(ARG2, sizeof(struct timespec));
	return order;
}

/*-----------------------------------------------------------------------------
    getrusage - (int who, struct rusage* usage)
-----------------------------------------------------------------------------*/
CALCSIZE(getrusage)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct rusage));
}

PRECALL(getrusage)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(getrusage)
{
	REPLICATEBUFFER(ARG2, sizeof(struct rusage));
	return order;
}

/*-----------------------------------------------------------------------------
    sysinfo - (struct sysinfo* info)
-----------------------------------------------------------------------------*/
CALCSIZE(sysinfo)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(struct sysinfo));
}

PRECALL(sysinfo)
{
	CHECKPOINTER(ARG1);
	return IPMON_MASTERCALL;
}

POSTCALL(sysinfo)
{
	REPLICATEBUFFER(ARG1, sizeof(struct sysinfo));
	return order;
}

/*-----------------------------------------------------------------------------
    times - (struct tms* buf)
-----------------------------------------------------------------------------*/
CALCSIZE(times)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(struct tms));
}

PRECALL(times)
{
	CHECKPOINTER(ARG1);
	return IPMON_MASTERCALL;
}

POSTCALL(times)
{
	REPLICATEBUFFER(ARG1, sizeof(struct tms));
	return order;
}

/*-----------------------------------------------------------------------------
    capget - (cap_user_header_t header, cap_user_data_t dataptr)
-----------------------------------------------------------------------------*/
CALCSIZE(capget)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG1, sizeof(__user_cap_header_struct));
	COUNTBUFFER(RET, ARG1, sizeof(__user_cap_header_struct));
	COUNTBUFFER(RET, ARG2, sizeof(__user_cap_data_struct) * 2);
}

PRECALL(capget)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKBUFFER(ARG1, sizeof(__user_cap_header_struct));
	return IPMON_MASTERCALL;
}

POSTCALL(capget)
{
	REPLICATEBUFFER(ARG1, sizeof(__user_cap_header_struct));
	REPLICATEBUFFER(ARG2, sizeof(__user_cap_data_struct) * 2);
	return order;
}

/*-----------------------------------------------------------------------------
    getitimer - (int which, struct itimerval* curr_value)
-----------------------------------------------------------------------------*/
CALCSIZE(getitimer)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct itimerval));
}

PRECALL(getitimer)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(getitimer)
{
	REPLICATEBUFFER(ARG2, sizeof(struct itimerval));
	return order;
}

/*-----------------------------------------------------------------------------
    int futex(int *uaddr, int op, int val, const struct timespec *timeout,
          int *uaddr2, int val3);
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(futex)
{
	if (ARG2 == MVEE_FUTEX_WAIT_TID)
		return true;
	return false;
}

CALCSIZE(futex)
{
	COUNTREG(ARG);
}

PRECALL(futex)
{
	CHECKREG(ARG2);
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

/*-----------------------------------------------------------------------------
    gettimeofday -
-----------------------------------------------------------------------------*/
CALCSIZE(gettimeofday)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(struct timeval));
	COUNTBUFFER(RET, ARG2, sizeof(struct timezone));
}

PRECALL(gettimeofday)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(gettimeofday)
{
	REPLICATEBUFFER(ARG1, sizeof(struct timeval));
	REPLICATEBUFFER(ARG2, sizeof(struct timezone));
	return order;
}

/*-----------------------------------------------------------------------------
    time - (time_t*)
-----------------------------------------------------------------------------*/
CALCSIZE(time)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(time_t));
}

PRECALL(time)
{
	CHECKPOINTER(ARG1);
	return IPMON_MASTERCALL;
}

POSTCALL(time)
{
	REPLICATEBUFFER(ARG1, sizeof(time_t));
	return order;
}

/*-----------------------------------------------------------------------------
    clock_gettime - int, struct timespec*
-----------------------------------------------------------------------------*/
CALCSIZE(clock_gettime)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct timespec));
}

PRECALL(clock_gettime)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(clock_gettime)
{
	REPLICATEBUFFER(ARG2, sizeof(struct timespec));
	return order;
}

/*-----------------------------------------------------------------------------
    getpid
-----------------------------------------------------------------------------*/
PRECALL(getpid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    getegid
-----------------------------------------------------------------------------*/
PRECALL(getegid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    geteuid
-----------------------------------------------------------------------------*/
PRECALL(geteuid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    getgid
-----------------------------------------------------------------------------*/
PRECALL(getgid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    getpgrp
-----------------------------------------------------------------------------*/
PRECALL(getpgrp)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    getppid
-----------------------------------------------------------------------------*/
PRECALL(getppid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    gettid
-----------------------------------------------------------------------------*/
PRECALL(gettid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    getuid
-----------------------------------------------------------------------------*/
PRECALL(getuid)
{
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    sched_yield - this is never dangerous BUT our synchronization replication
    algorithm heavily depends on this syscall

    => should be super fast!
-----------------------------------------------------------------------------*/
UNSYNCED(sched_yield)

/*-----------------------------------------------------------------------------
    getcwd - char *buffer, unsigned long size
-----------------------------------------------------------------------------*/
CALCSIZE(getcwd)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(getcwd)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	return IPMON_NORMAL_CALL;
}

/*-----------------------------------------------------------------------------
    access - (const char* pathname, int mode)
-----------------------------------------------------------------------------*/
CALCSIZE(access)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
}

PRECALL(access)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	CHECKSTRING(ARG1);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    faccessat - (int dirfd, const char *pathname, int mode)
-----------------------------------------------------------------------------*/
CALCSIZE(faccessat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
}

PRECALL(faccessat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKSTRING(ARG2);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    int stat(const char *path, struct stat *buf);
    int fstat(int fd, struct stat *buf);
    int lstat(const char *path, struct stat *buf); 
-----------------------------------------------------------------------------*/
CALCSIZE(stat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTBUFFER(RET, ARG2, sizeof(struct stat));
}

PRECALL(stat)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKSTRING(ARG1);
	return IPMON_MASTERCALL;
}

POSTCALL(stat)
{
	REPLICATEBUFFER(ARG2, sizeof(struct stat));
	return order;
}

CALCSIZE(lstat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTBUFFER(RET, ARG2, sizeof(struct stat));
}

PRECALL(lstat)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKSTRING(ARG1);
	return IPMON_MASTERCALL;
}

POSTCALL(lstat)
{
	REPLICATEBUFFER(ARG2, sizeof(struct stat));
	return order;
}

CALCSIZE(fstat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct stat));
}

PRECALL(fstat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(fstat)
{
	REPLICATEBUFFER(ARG2, sizeof(struct stat));
	return order;
}

/*-----------------------------------------------------------------------------
    newfstatat - (int dfd, char *filename, struct stat *buf, int flag)
-----------------------------------------------------------------------------*/
CALCSIZE(newfstatat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, sizeof(struct stat));
}

PRECALL(newfstatat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(newfstatat)
{
	REPLICATEBUFFER(ARG3, sizeof(struct stat));
	return order;
}

/*-----------------------------------------------------------------------------
    getdents - (unsigned int fd, struct linux_dirent* dirp, unsigned int count)
-----------------------------------------------------------------------------*/
CALCSIZE(getdents)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(getdents)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	return IPMON_MASTERCALL;
}

POSTCALL(getdents)
{
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    readlink - (const char *path, char *buf, size_t bufsiz)
-----------------------------------------------------------------------------*/
CALCSIZE(readlink)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(readlink)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKSTRING(ARG1);
	return IPMON_MASTERCALL;
}

POSTCALL(readlink)
{
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    readlinkat - (int dirfd, const char *path, char *buf, size_t bufsiz)
-----------------------------------------------------------------------------*/
CALCSIZE(readlinkat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(readlinkat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(readlinkat)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    getxattr/lgetxattr - (const char *path, const char *name,
                 void *value, size_t size)
	fgetxattr - (int fd, const char *name,
                 void *value, size_t size)
-----------------------------------------------------------------------------*/
CALCSIZE(getxattr)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(getxattr)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG1);
	CHECKSTRING(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(getxattr)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

CALCSIZE(lgetxattr)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(lgetxattr)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG1);
	CHECKSTRING(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(lgetxattr)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

CALCSIZE(fgetxattr)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);	
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(fgetxattr)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(fgetxattr)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    lseek - (int fd, off_t offset, int whence)
-----------------------------------------------------------------------------*/
CALCSIZE(lseek)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(lseek)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    alarm - (unsigned int seconds)
-----------------------------------------------------------------------------*/
CALCSIZE(alarm)
{
	COUNTREG(ARG);
}

PRECALL(alarm)
{
	CHECKREG(ARG1);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    setitimer - (int which, const struct itimerval* new_value, struct itimerval* old_value)
-----------------------------------------------------------------------------*/
CALCSIZE(setitimer)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, sizeof(struct itimerval));
	COUNTBUFFER(RET, ARG3, sizeof(struct itimerval));
}

PRECALL(setitimer)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKBUFFER(ARG2, sizeof(struct itimerval));
	return IPMON_MASTERCALL;
}

POSTCALL(setitimer)
{
	REPLICATEBUFFER(ARG3, sizeof(struct itimerval));
	return order;
}

/*-----------------------------------------------------------------------------
    timerfd_gettime - (int ufd, struct itimerspec* otmr)
-----------------------------------------------------------------------------*/
CALCSIZE(timerfd_gettime)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct itimerspec));
}

PRECALL(timerfd_gettime)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_MASTERCALL;
}

POSTCALL(timerfd_gettime)
{
	REPLICATEBUFFER(ARG2, sizeof(struct itimerspec));
	return order;
}

/*-----------------------------------------------------------------------------
    madvise - void* addr, size_t length, int advice

    The only potentially dangerous variant of this call is where
    advice == MADV_REMOVE. That doesn't affect us however since MADV_REMOVE
    only affects MAP_SHARED regions with PROT_WRITE access, which we do not
    allow in GHUMVEE
-----------------------------------------------------------------------------*/
UNSYNCED(madvise)

/*-----------------------------------------------------------------------------
    fadvise64 - (int fd, loff_t offset, loff_t len, int advice)
-----------------------------------------------------------------------------*/
CALCSIZE(fadvise64)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(fadvise64)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    read - int fd, void* buf, size_t count
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(read)
{
	// check whether our current policy allows
	// us to dispatch read calls on this file
	// as unchecked calls
	return !ipmon_can_read(ARG1);
}

CALCSIZE(read)
{
	// reserve space for 3 register arguments
	// one buffer whose maximum size is in argument 3 of this syscall
	COUNTREG(ARG); 
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(read)
{
	// compare the system call arguments
	// dispatch this as a call that only
	// the master actually invokes
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(read)
{
	// replicate the results
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    pread64 - (int fd, void *buf, size_t count, off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(pread64)
{
	return !ipmon_can_read(ARG1);
}

CALCSIZE(pread64)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(pread64)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(pread64)
{
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    readv - (int fd, const struct iovec *iov, int iovcnt)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(readv)
{
	return !ipmon_can_read(ARG1);
}

CALCSIZE(readv)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVECLAYOUT(ARG, ARG2, ARG3);
	COUNTIOVEC(RET, ARG2, ARG3);
}

PRECALL(readv)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKIOVECLAYOUT(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(readv)
{
	REPLICATEIOVEC(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    preadv - (int fd, const struct iovec *iov, int iovcnt, off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(preadv)
{
	return !ipmon_can_read(ARG1);
}

CALCSIZE(preadv)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVECLAYOUT(ARG, ARG2, ARG3);
	COUNTIOVEC(RET, ARG2, ARG3);
}

PRECALL(preadv)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKIOVECLAYOUT(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(preadv)
{
	REPLICATEIOVEC(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    poll - struct pollfd *fds, nfds_t nfds, int timeout
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(poll)
{
	for (int i = 0; i < ARG2; ++i)
		if (!ipmon_can_read(((struct pollfd*)ARG1)[i].fd))
			return true;

	return false;
}

CALCSIZE(poll)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG1, (sizeof(struct pollfd) * ARG2));
	COUNTBUFFER(RET, ARG1, (sizeof(struct pollfd) * ARG2)); // buffer is input and can be modified by the syscall
}

PRECALL(poll)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKBUFFER(ARG1, (sizeof(struct pollfd) * ARG2));
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(poll)
{
	REPLICATEBUFFER(ARG1, (sizeof(struct pollfd) * ARG2));
	return order;
}

/*-----------------------------------------------------------------------------
    select - (int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(select)
{
	for (int i = 0; i < ARG1; ++i)
	{
		if ((ARG2 && FD_ISSET(i, (fd_set*)ARG2)) ||
			(ARG3 && FD_ISSET(i, (fd_set*)ARG3)) ||
			(ARG4 && FD_ISSET(i, (fd_set*)ARG4)))
		{
			if (!ipmon_can_read(i))
				return true;
		}
	}

	return false;
}

CALCSIZE(select)
{
	// some bastards don't pass a full fd set to the
	// kernel because they assume that the kernel
	// won't touch the non-interesting bits anyway
	unsigned long set_size = ROUND_UP(ARG1 + 1, sizeof(unsigned long));
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, set_size);
	COUNTBUFFER(RET, ARG2, set_size);
	COUNTBUFFER(ARG, ARG3, set_size);
	COUNTBUFFER(RET, ARG3, set_size);
	COUNTBUFFER(ARG, ARG4, set_size);
	COUNTBUFFER(RET, ARG4, set_size);
	COUNTBUFFER(ARG, ARG5, sizeof(struct timeval));
	COUNTBUFFER(RET, ARG5, sizeof(struct timeval));
}

PRECALL(select)
{
	unsigned long set_size = ROUND_UP(ARG1 + 1, sizeof(unsigned long));
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKPOINTER(ARG4);
	CHECKPOINTER(ARG5);
	CHECKBUFFER(ARG2, set_size);
	CHECKBUFFER(ARG3, set_size);
	CHECKBUFFER(ARG4, set_size);
	CHECKBUFFER(ARG5, sizeof(struct timeval));
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;	
}

POSTCALL(select)
{
	unsigned long set_size = ROUND_UP(ARG1 + 1, sizeof(unsigned long));
	REPLICATEBUFFER(ARG2, set_size);
	REPLICATEBUFFER(ARG3, set_size);
	REPLICATEBUFFER(ARG4, set_size);
	REPLICATEBUFFER(ARG5, sizeof(struct timeval));
	return order;
}

/*-----------------------------------------------------------------------------
    timerfd_settime - (int fd, int flags,
                    const struct itimerspec *new_value,
                    struct itimerspec *old_value);
-----------------------------------------------------------------------------*/
CALCSIZE(timerfd_settime)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(struct itimerspec));
	COUNTBUFFER(RET, ARG4, sizeof(struct itimerspec));
}

PRECALL(timerfd_settime)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKPOINTER(ARG3);
	CHECKPOINTER(ARG4);
	CHECKBUFFER(ARG3, sizeof(struct itimerspec));
	return IPMON_MASTERCALL;
}

POSTCALL(timerfd_settime)
{
	REPLICATEBUFFER(ARG4, sizeof(struct itimerspec));
	return order;
}

/*-----------------------------------------------------------------------------
    sync - 
-----------------------------------------------------------------------------*/
PRECALL(sync)
{
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

/*-----------------------------------------------------------------------------
    fsync - (int fd)
	fdatasync - (int fd)
	syncfs - (int fd)
-----------------------------------------------------------------------------*/
CALCSIZE(fsync)
{
	COUNTREG(ARG);
}

PRECALL(fsync)
{
	CHECKREG(ARG1);
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

CALCSIZE(fdatasync)
{
	COUNTREG(ARG);
}

PRECALL(fdatasync)
{
	CHECKREG(ARG1);
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

CALCSIZE(syncfs)
{
	COUNTREG(ARG);
}

PRECALL(syncfs)
{
	CHECKREG(ARG1);
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

/*-----------------------------------------------------------------------------
    write - int fd, const void* buf, size_t count
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(write)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(write)
{
	COUNTREG(ARG); // arg1
	COUNTREG(ARG); // arg2
	COUNTREG(ARG); // arg3
	COUNTBUFFER(ARG, ARG2, ARG3);
}

PRECALL(write)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
//	ipmon_arg_verify_failed((void*)ARG2);
	CHECKBUFFER(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    pwrite - (int fd, const void *buf, size_t count, off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(pwrite64)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(pwrite64)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, ARG3);
}

PRECALL(pwrite64)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKBUFFER(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    writev - (int fd, const struct iovec *iov, int iovcnt)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(writev)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(writev)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVEC(ARG, ARG2, ARG3);
}

PRECALL(writev)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKIOVEC(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    pwritev - (int fd, const struct iovec *iov, int iovcnt,
                off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(pwritev)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(pwritev)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVEC(ARG, ARG2, ARG3);
}

PRECALL(pwritev)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKIOVEC(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    recvfrom - (int sockfd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
-----------------------------------------------------------------------------*/
CALCSIZE(recvfrom)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
	if (ARG6 && *(socklen_t*)ARG6 > 0)
		COUNTBUFFER(RET, ARG5, *(socklen_t*)ARG6);
}

PRECALL(recvfrom)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	CHECKPOINTER(ARG6);
	CHECKBUFFER(ARG6, sizeof(socklen_t));
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(recvfrom)
{
	REPLICATEBUFFER(ARG2, ret);
	REPLICATEBUFFER(ARG6, sizeof(socklen_t));
	REPLICATEBUFFER(ARG5, *(socklen_t*)ARG6);
	return order;
}

/*-----------------------------------------------------------------------------
    recvmsg - (int fd, struct msghdr* msg, int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(recvmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMSGLAYOUT(ARG, ARG2);
	COUNTMSG(RET, ARG2);
}

PRECALL(recvmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKMSGLAYOUT(ARG2);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(recvmsg)
{
	REPLICATEMSG(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    recvmmsg - (int fd, struct mmsghdr* msgvec, unsigned int vlen, 
	unsigned int flags, struct timespec* timeout)
-----------------------------------------------------------------------------*/
CALCSIZE(recvmmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMMSGLAYOUT(ARG, ARG2, ARG3);
	COUNTBUFFER(ARG, ARG5, sizeof(struct timespec));
	COUNTMMSG(RET, ARG2, ARG3);
}

PRECALL(recvmmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	CHECKMMSGLAYOUT(ARG2, ARG3);
	CHECKBUFFER(ARG5, sizeof(struct timespec));
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(recvmmsg)
{
	REPLICATEMMSG(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    getsockname - (int fd, struct sockaddr __user * usockaddr,                                                   
	int __user * usockaddr_len)
-----------------------------------------------------------------------------*/
CALCSIZE(getsockname)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(int));
	COUNTBUFFER(RET, ARG2, *(int*)ARG3);
	COUNTBUFFER(RET, ARG3, sizeof(int));
}

PRECALL(getsockname)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKBUFFER(ARG3, sizeof(int));
	return IPMON_MASTERCALL;
}

POSTCALL(getsockname)
{
	// tricky business!!! getsockname returns a truncated result
	// if the call was unsucessful
	success = true; // hack
	int oldsize = *(int*)ARG3;
	REPLICATEBUFFER(ARG3, sizeof(int));
	REPLICATEBUFFER(ARG2, MIN(*(int*)ARG3, oldsize));
	return order;
}

/*-----------------------------------------------------------------------------
    getpeername - (int fd, struct sockaddr __user * usockaddr,                                                   
	int __user * usockaddr_len)   
-----------------------------------------------------------------------------*/
CALCSIZE(getpeername)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(int));
	COUNTBUFFER(RET, ARG2, *(int*)ARG3);
	COUNTBUFFER(RET, ARG3, sizeof(int));
}

PRECALL(getpeername)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKBUFFER(ARG3, sizeof(int));
	return IPMON_MASTERCALL;
}

POSTCALL(getpeername)
{
	// same hack as above to deal with truncated results
	success = true; // hack
	int oldsize = *(int*)ARG3;
	REPLICATEBUFFER(ARG3, sizeof(int));
	REPLICATEBUFFER(ARG2, MIN(*(int*)ARG3, oldsize));
	return order;
}

/*-----------------------------------------------------------------------------
    getsockopt - (int fd, int level, int optname,                                                                
	char __user * optval, int __user * optlen) 
-----------------------------------------------------------------------------*/
CALCSIZE(getsockopt)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG5, sizeof(int));
	COUNTBUFFER(RET, ARG4, *(int*)ARG5);
	COUNTBUFFER(RET, ARG5, sizeof(int));
}

PRECALL(getsockopt)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	CHECKPOINTER(ARG5);
	CHECKBUFFER(ARG5, sizeof(int));
	return IPMON_MASTERCALL;
}

POSTCALL(getsockopt)
{
	int oldsize = *(int*)ARG5;
	REPLICATEBUFFER(ARG5, sizeof(int));
	REPLICATEBUFFER(ARG4, MIN(oldsize, *(int*)ARG5));
	return order;
}

/*-----------------------------------------------------------------------------
    sendto - (int fd, void __user * buff, size_t len,                                                             
	unsigned int flags, struct sockaddr __user * addr, int addr_len)
-----------------------------------------------------------------------------*/
CALCSIZE(sendto)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, ARG3);
	COUNTBUFFER(ARG, ARG5, ARG6);
}

PRECALL(sendto)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	CHECKREG(ARG6);
	CHECKBUFFER(ARG2, ARG3);
	CHECKBUFFER(ARG5, ARG6);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    sendmsg - (int fd, struct msghdr __user * msg, unsigned int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(sendmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMSG(ARG, ARG2);
}

PRECALL(sendmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKMSG(ARG2);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    sendmmsg - (int fd, struct mmsghdr __user * mmsg,                                                            
	unsigned int vlen, unsigned int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(sendmmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMMSG(ARG, ARG2, ARG3);
	COUNTBUFFER(RET, ARG2, ARG3 * sizeof(unsigned int));
}

PRECALL(sendmmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);

	// hack set msg_len so we can use the same handlers we're using for recvmmsg
	if (ARG2 && ARG3 > 0)
	{
		struct mmsghdr* hdr = (struct mmsghdr*)ARG2;
		for (int i; i < ARG3; ++i)
		{
			hdr->msg_len = ipmon_iovec_bytes(hdr->msg_hdr.msg_iov, hdr->msg_hdr.msg_iovlen);
			hdr ++;
		}
	}
	
	CHECKMMSG(ARG2, ARG3);
	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(sendmmsg)
{
	// must replicate lens here
	REPLICATEMMSGLENS(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    sendfile - (int out_fd, int in_fd, off_t __user * offset, size_t count)
-----------------------------------------------------------------------------*/
CALCSIZE(sendfile)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(off_t));
}

PRECALL(sendfile)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKBUFFER(ARG3, sizeof(off_t));

	// tricky business! this may block on in_fd OR out_fd

	return IPMON_MASTERCALL | IPMON_MAYBE_BLOCKING(ARG1) | IPMON_MAYBE_BLOCKING(ARG2);
}

/*-----------------------------------------------------------------------------
    epoll_wait - (int epfd, struct epoll_event __user* events, int maxevents, int timeout)
-----------------------------------------------------------------------------*/
CALCSIZE(epoll_wait)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct epoll_event) * ARG3);
}

PRECALL(epoll_wait)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	return IPMON_MASTERCALL | IPMON_BLOCKING_CALL;
}

POSTCALL(epoll_wait)
{
	// epoll events contain pointers. Therefore, this will completely break
	// when combined with diversity!!!
	if (success && ret > 0)
	{
		// in the master, map ptrs onto fds before replicating
		if (ipmon_variant_num == 0)
		{
			struct epoll_event* events = (struct epoll_event*)alloca(ret * sizeof(struct epoll_event));
			ipmon_memcpy_ptr_ptr(events, (void*)ARG2, ret * sizeof(struct epoll_event));
		
			for (int i = 0; i < ret; ++i)
				events[i].data.u32 = ipmon_epoll_get_fd_for_ptr(ARG1, (unsigned long)events[i].data.ptr);

			REPLICATEBUFFER(events, ret * sizeof(struct epoll_event));
		}
        // in the slaves, map fds onto ptrs after replicating
		else
		{
			struct epoll_event* events = (struct epoll_event*)ARG2;

			REPLICATEBUFFER(ARG2, ret * sizeof(struct epoll_event));

			for (int i = 0; i < ret; ++i)
				events[i].data.ptr = (void*)ipmon_epoll_get_ptr_for_fd(ARG1, (int)events[i].data.u32);
		}	
	}
	return order;
}

/*-----------------------------------------------------------------------------
    epoll_ctl - (int epfd, int op, int fd, struct epoll_event *event)

	See comment above. This won't work when combined with diversity!!!
-----------------------------------------------------------------------------*/
CALCSIZE(epoll_ctl)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(epoll_ctl)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	ipmon_epoll_lock();
	return IPMON_MASTERCALL;
}

POSTCALL(epoll_ctl)
{
	if (success)
	{
		struct epoll_event* event = (struct epoll_event*)ARG4;
		switch(ARG2)
		{
    		case EPOLL_CTL_ADD:
    		case EPOLL_CTL_MOD:
				ipmon_epoll_set_ptr_for_fd(ARG1, ARG3, (unsigned long)event->data.ptr);
				break;
    		case EPOLL_CTL_DEL:
				ipmon_epoll_set_ptr_for_fd(ARG1, ARG3, 0);
				break;
		}
	}
	ipmon_epoll_unlock();
	return order;
}

/*-----------------------------------------------------------------------------
    shutdown - (int sockfd, int how)
-----------------------------------------------------------------------------*/
CALCSIZE(shutdown)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(shutdown)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    setsockopt - (int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen)
-----------------------------------------------------------------------------*/
CALCSIZE(setsockopt)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG4, ARG5);
}

PRECALL(setsockopt)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	CHECKREG(ARG5);
	CHECKBUFFER(ARG4, ARG5);
	return IPMON_MASTERCALL;
}

/*-----------------------------------------------------------------------------
    ioctl - (int fd, unsigned long request, ...)

	ioctl supports many getter calls which we could allow
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(ioctl)
{
	if (ARG2 == FIONREAD)
		return false;
	return true;
}

CALCSIZE(ioctl)
{
	COUNTREG(ARG);
	COUNTREG(ARG);

	switch(ARG2)
	{
	    case FIONREAD:
			COUNTREG(ARG);
			COUNTBUFFER(RET, ARG3, sizeof(int));
			break;
	}
}

PRECALL(ioctl)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);

	switch(ARG2)
	{
    	case FIONREAD:
			CHECKPOINTER(ARG3);
			break;
	}

	return IPMON_MASTERCALL;
}

POSTCALL(ioctl)
{
	switch(ARG2)
	{
    	case FIONREAD:
			REPLICATEBUFFER(ARG3, sizeof(int));
			break;
	}

	return order;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_maybe_checked - allows a system call handler to decide whether
    or not a specific invocation should be reported to the monitor
-----------------------------------------------------------------------------*/
STATIC INLINE bool ipmon_syscall_maybe_checked(struct ipmon_syscall_args& args, unsigned long syscall_no)
{
	switch(syscall_no)
	{
#include "MVEE_ipmon_maybe_checked.h"
	}
	return false;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_is_unsynced
-----------------------------------------------------------------------------*/
STATIC INLINE unsigned char ipmon_syscall_is_unsynced(struct ipmon_syscall_args& args, unsigned long syscall_no)
{
	switch(syscall_no)
	{
#include "MVEE_ipmon_is_unsynced.h"
	}
	return 0;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_calcsize
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_syscall_calcsize(struct ipmon_syscall_args& args, unsigned long syscall_no, unsigned int* ARG, unsigned int* RET)
{
	switch(syscall_no)
	{
#include "MVEE_ipmon_calcsize.h"
	}
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_precall - does argument logging in the master, argument
    verification in the slaves and determines whether or not the call is a
    mastercall
-----------------------------------------------------------------------------*/
STATIC INLINE unsigned char ipmon_syscall_precall(struct ipmon_syscall_args& args, unsigned long entry_offset)
{
	switch(syscall_entry_no(entry_offset))
	{
#include "MVEE_ipmon_precall.h"
	}

	return 0;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_postcall - does return logging in the master and return
    replication in the slaves.  Returns the number of ipmon_syscall_data
    elements used in the buffer for replicating the results
-----------------------------------------------------------------------------*/
STATIC INLINE int ipmon_syscall_postcall(struct ipmon_syscall_args& args, unsigned long entry_offset)
{
	long ret = syscall_entry_return_value(entry_offset);
	bool success = (ret >= 0 || ret < -4096);
	int nr_elements = 0;

	switch(syscall_entry_no(entry_offset))
	{
#include "MVEE_ipmon_postcall.h"
	}

	return nr_elements;
}


/*-----------------------------------------------------------------------------
    ipmon_barrier_wait - Super optimized spin-futex barrier. 
	
	NOTE: This is a slightly altered version of pool_barrier_wait2 on 
	locklessinc.com.

	TODO: Check License?

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_barrier_wait(struct ipmon_barrier* barrier)
{
	unsigned short old_seq = __atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST);
	unsigned char count    = __atomic_add_fetch(&barrier->count, 1, __ATOMIC_SEQ_CST);

	// we're not the last thread to reach the barrier
	if (count < rb_numvariants())
	{
		old_seq |= 1;

		// We optimize for the case where the variants are in sync
		// (i.e. we don't have to wait too long at the barrier)
		for (int i = 0; i < 10000; ++i)
		{
			if (__atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST) != old_seq)
				return;
			
			cpu_relax();
		}

		while ((__atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST) | 1) == old_seq)
		{
			// set the waiters flag
			*(volatile unsigned char*)&barrier->seq = 1;

			// and wait for seq to change
			ipmon_unchecked_syscall(__NR_futex, (unsigned long)&barrier->hack, FUTEX_WAIT, old_seq, (unsigned long)NULL, (unsigned long)NULL, 0);
		}
	}
	// last thread, wake everyone
	else
	{
		// This xchg will clear the least significant byte of seq, increment the
		// 3 most significant bytes of seq as if it was a 3 byte integer, and
		// reset the count field to zero
		if (__atomic_exchange_n(&barrier->hack, (old_seq | 1) + 255, __ATOMIC_SEQ_CST) & 1)
		{
			// if the least significant byte was 1, we need to FUTEX_WAKE
			ipmon_unchecked_syscall(__NR_futex, (unsigned long)&barrier->hack, FUTEX_WAKE, INT_MAX, (unsigned long)NULL, (unsigned long)NULL, 0);
		}
	}
}

/*-----------------------------------------------------------------------------
    ipmon_cond_wait - super optimized cv that can only be used once!

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_cond_wait(struct ipmon_condvar* cv)
{
#ifndef IPMON_USE_FUTEXES_FOR_CONDVAR
	int i = 0;
	while (!__atomic_load_n(&cv->signaled, __ATOMIC_SEQ_CST))
	{
		cpu_relax();
						
		if (i++ > IPMON_YIELD_THRESHOLD)
		{
			i = 0;
			ipmon_unchecked_syscall(__NR_sched_yield);
		}
	}
#else
	// We expect to see 1
	for (int i = 0; i < 10000; ++i)
	{
		if (__atomic_load_n(&cv->signaled, __ATOMIC_SEQ_CST))
			return;

		cpu_relax();
	}

	// futex_wait while not signaled
	while ((__atomic_load_n(&cv->hack, __ATOMIC_SEQ_CST) | 1) == 1)
	{
		__atomic_store_n(&cv->have_waiters, 1, __ATOMIC_SEQ_CST);

		// and wait for everything to change
		ipmon_unchecked_syscall(__NR_futex, (unsigned long)&cv->hack, FUTEX_WAIT, 1, (unsigned long)NULL, (unsigned long)NULL, 0);
	}
#endif
}

/*-----------------------------------------------------------------------------
    ipmon_cond_broadcast - 

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_cond_broadcast(struct ipmon_condvar* cv)
{
#ifndef IPMON_USE_FUTEXES_FOR_CONDVAR
	__atomic_store_n(&cv->signaled, 1, __ATOMIC_SEQ_CST);
#else
	// atomically set signaled to 1 and clear the have_waiters flag
	if (__atomic_exchange_n(&cv->hack, 0x00000100, __ATOMIC_SEQ_CST) & 1)
	{
		// have_waiters was set. We must wake some threads
		ipmon_unchecked_syscall(__NR_futex, (unsigned long)&cv->hack, FUTEX_WAKE, INT_MAX, (unsigned long)NULL, (unsigned long)NULL, 0);
	}
#endif
}


/*-----------------------------------------------------------------------------
    ipmon_sync_on_syscall_entrance - Called just before we invoke the original
	syscall. This would be the place where we implement lock-stepping.

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_sync_on_syscall_entrance(unsigned long entry_offset)
{
#ifdef IPMON_DO_LOCKSTEP
	ipmon_barrier_wait(&entry->syscall_lockstep_barrier);
#endif
}

/*-----------------------------------------------------------------------------
    ipmon_sync_on_syscall_exit - Called just before we leave IP-MON. This
	is where we can do lock-stepping at the syscall exit. This is called
	AFTER the results have been copied into the local slave memory!

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_sync_on_syscall_exit(unsigned long entry_offset)
{
#ifdef IPMON_DO_LOCKSTEP
	ipmon_barrier_wait(&entry->syscall_lockstep_barrier);
#endif
}

/*-----------------------------------------------------------------------------
    ipmon_do_syscall_wake - Called by the master to inform the slaves about
	the availability of the syscall results. 
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_do_syscall_wake(unsigned long entry_offset)
{
	// TODO: LEAKS!
	struct ipmon_condvar* condvar = (struct ipmon_condvar*)(entry_offset + offsetof(struct ipmon_syscall_entry, syscall_results_available));

	__asm__ volatile (
		"addq %%" RB_REGISTER ", %0;"
		: "+r"(condvar) : "r"(condvar));

	ipmon_cond_broadcast(condvar);
}

/*-----------------------------------------------------------------------------
    ipmon_do_syscall_wait - Called by the slaves to wait for the syscall results
    to become available. 
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_do_syscall_wait(unsigned long entry_offset)
{
	// TODO: LEAKS!
	struct ipmon_condvar* condvar = (struct ipmon_condvar*)(entry_offset + offsetof(struct ipmon_syscall_entry, syscall_results_available));

	__asm__ volatile (
		"addq %%" RB_REGISTER ", %0;"
		:"+r"(condvar) : "r"(condvar));

	ipmon_cond_wait(condvar);
}

/*-----------------------------------------------------------------------------
    ipmon_should_restart_call - We might see the ERESTART errors (which are
	normally never returned to user space) because GHUMVEE explicitly 
	forced an interrupted unchecked call to return to user space.
	
	Normally, interrupted calls would automatically restart after the signal
	that interrupts them has been handled by the ptracer.

	In our case, however, we want to restart the unchecked call as a checked
	call. This gives GHUMVEE the opportunity to deliver the interrupting signal
-----------------------------------------------------------------------------*/
STATIC INLINE bool ipmon_should_restart_call(long ret)
{
	// check for ERESTART* errors
	if (ret <= -512	&& ret >= -516)
		return true;
	return false;
}

/*-----------------------------------------------------------------------------
    ipmon_flush_buffer - called at a syscall entry when there's not enough
    room to log the next syscall info
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_flush_buffer()
{
	variant_info_status_set(ipmon_variant_num, IPMON_STATUS_FLUSHING);
	ipmon_checked_syscall(MVEE_FLUSH_SHARED_BUFFER, MVEE_IPMON_BUFFER);
}

/*-----------------------------------------------------------------------------
    ipmon_wait_for_next_syscall - called only by slaves. Spins on the master's
	pos variable until it is bigger than the local variant's pos
-----------------------------------------------------------------------------*/
STATIC INLINE unsigned char ipmon_wait_for_next_syscall()
{
	unsigned int i = 0;
	unsigned char result = 0;

	while (1)
	{
		unsigned int master_pos = variant_info_pos(0);
		unsigned int our_pos    = variant_info_pos(ipmon_variant_num);

		if (master_pos > our_pos)
			return result;

		// Maybe the master is just flushing the buffer?
		if (master_pos == our_pos && 
			(variant_info_status(0) & IPMON_STATUS_FLUSHING))
		{
			// The above check is racy. We need to check again if we really
			// caught up with the master the master might indeed be flushing
			// right now but it might have changed its offset since the time we
			// read it!!!
			master_pos = variant_info_pos(0);
			if (master_pos == our_pos)
			{
				ipmon_flush_buffer();
				result = 1;
				continue;
			}
		}

		if (i++ > IPMON_YIELD_THRESHOLD)
		{
			i = 0;
			ipmon_unchecked_syscall(__NR_sched_yield);
		}
		else
		{
			cpu_relax();
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
    ipmon_prepare_syscall - 

    Determines how a syscall should be handled. There are several scenarios:

    1) if syscall is not in the list of possibly unchecked syscalls,
    this function will just return straight away

    2) if the syscall is in the list, then the master replica will determine
    whether or not the syscall metadata will fit in the IPMON buffer.

    If not, we will just store minimal info about the syscall and tell
    the caller that the syscall SHOULD be checked.

    If the metadata fits in the buffer, then the policy will be applied
-----------------------------------------------------------------------------*/
STATIC INLINE unsigned char ipmon_prepare_syscall (struct ipmon_syscall_args& args, unsigned long syscall_no)
{
	// Prepare the syscall here. The master needs to ensure that there's room to
	// write the syscall info
	unsigned char result;
	unsigned long entry_offset = ipmon_current_entry_offset();
	args.entry_offset = entry_offset;

	// Check whether we're the master or slave
	if (ipmon_variant_num == 0)
	{
		unsigned int args_size = 0, ret_size = 0, entry_size;
		unsigned char checked_call = 0;

		ipmon_syscall_calcsize(args, syscall_no, &args_size, &ret_size);

		entry_size = ROUND_UP(sizeof(struct ipmon_syscall_entry) + args_size + ret_size, sizeof(unsigned long));

		if (rb_have_pending_signals() || entry_size > rb_usable_size())
			checked_call = 1;

		// If the call is checked, there is no need to reserve any room for the
		// arguments and returns
		if (checked_call)
		{
			args_size = ret_size = 0;
			entry_size = ROUND_UP(sizeof(struct ipmon_syscall_entry), sizeof(unsigned long));
		}

		// If the entry size (which can be just sizeof(ipmon_syscall_entry) when
		// it is a checked call, would exceed the buffer, flush
		if (entry_size > rb_usable_size() - variant_info_pos(ipmon_variant_num))
		{
			ipmon_flush_buffer();
			entry_offset = ipmon_current_entry_offset();
			args.entry_offset = entry_offset;
		}

		// OK. We have room to write the entry now
		syscall_entry_no_set(entry_offset, (int)syscall_no);
		syscall_entry_checked_set(entry_offset, checked_call);
		syscall_entry_entry_size_set(entry_offset, entry_size);
		syscall_entry_args_size_set(entry_offset, args_size);

		if (!checked_call)
		{
			char call_type = ipmon_syscall_precall(args, entry_offset);
			if (call_type & IPMON_MASTERCALL)
				syscall_entry_is_mastercall_set(entry_offset, 1);
			if (call_type & IPMON_BLOCKING_CALL)
				syscall_entry_is_blocking_set(entry_offset, 1);
		}

		// Update the variant's current in-buffer position here.  NOTE: We will
		// adjust this later, once we know the real size occupied by the return
		// values.
		//
		// We update the position here already to ease debugging in GHUMVEE
		variant_info_pos_set(0,
							 variant_info_pos(0) +
								(syscall_entry_is_mastercall(entry_offset) ?
									sizeof(struct ipmon_syscall_entry)
									: syscall_entry_entry_size(entry_offset)));

		// All relevant pre-syscall information has been logged into the buffer
		// This is where we could sync with the slave variants to implement
		// lock-stepping
		ipmon_sync_on_syscall_entrance(entry_offset);

		if (checked_call)
			return IPMON_EXEC_NO_IPMON;

		return IPMON_EXEC_IPMON;
	} 
	else 
	{ 
        // wait until we see a valid syscall entry that we haven't replicated
        // yet
		if (ipmon_wait_for_next_syscall())
		{
			entry_offset = ipmon_current_entry_offset();
			args.entry_offset = entry_offset;
		}

		// Update our position in the replication buffer
		variant_info_pos_set(ipmon_variant_num,
							 variant_info_pos(ipmon_variant_num) +
								(syscall_entry_is_mastercall(entry_offset) ?
									sizeof(struct ipmon_syscall_entry)
									: syscall_entry_entry_size(entry_offset)));

		if (syscall_entry_checked(entry_offset))
			return IPMON_EXEC_NO_IPMON;

		// Sanity Check 1: Compare the master's syscall number with ours
		if ((int)syscall_no != syscall_entry_no(entry_offset)) {
			ipmon_arg_verify_failed((void*)(long) syscall_entry_no(entry_offset));
		}

		// Sanity Check 2: Compare all syscall arguments
		ipmon_syscall_precall(args, entry_offset);

		// We could sync with the master here to implement lock-stepping
		ipmon_sync_on_syscall_entrance(entry_offset);

		if (!syscall_entry_is_mastercall(entry_offset))
			return IPMON_EXEC_IPMON;

		// for master calls, we don't want the slaves to even enter the kernel
		return IPMON_EXEC_NOEXEC;
	}

	return IPMON_EXEC_NO_IPMON;
}

/*-----------------------------------------------------------------------------
    ipmon_finish_syscall - this gets called in the following contexts:

    * by the master if the call was unchecked
    * by the slave if the call was unchecked
    * by the slave if the call was noexec
-----------------------------------------------------------------------------*/
STATIC INLINE long ipmon_finish_syscall (struct ipmon_syscall_args& args, long ret)
{
	unsigned long entry_offset = args.entry_offset;

	// This will happen for unsynced calls!
	if (entry_offset == 0) /* invalid offset in RB */
		return ret;

	// We don't have to do anything for normal calls either
	if (! syscall_entry_is_mastercall(entry_offset))
		return ret;

	if (ipmon_variant_num == 0)
	{
		unsigned int nr_ret_elements = 0;
		unsigned long true_ret_size  = 0;

		syscall_entry_return_value_set(entry_offset, ret);
		gcc_barrier();

		// We might have to restart the call if it was interrupted by a signal
		if (!ipmon_should_restart_call(ret))
		{
			nr_ret_elements = ipmon_syscall_postcall(args, entry_offset);

			// Recalculate the size of the return values			
			for (unsigned int i = 0; i < nr_ret_elements; i++)				
			{
				// our current position is the start of the return values
				true_ret_size += syscall_data_len(entry_offset + 
												  syscall_entry_args_size(entry_offset) + 
												  true_ret_size + 
												  sizeof(struct ipmon_syscall_entry) /* sizeof by BART */);
			}

			// we need word-size alignment on all ipmon_syscall_entries
			// because they contain variables that must be updated atomically
			syscall_entry_entry_size_set(entry_offset,
				ROUND_UP(sizeof(struct ipmon_syscall_entry) + syscall_entry_args_size(entry_offset) + true_ret_size, sizeof(long)));

			// Update our position in the buffer once more
			variant_info_pos_set(0,
								 variant_info_pos(0) + syscall_entry_args_size(entry_offset) + true_ret_size);
		}

		// Tell the slaves that the syscall results are available
		ipmon_do_syscall_wake(entry_offset);

		// We could sync with the slaves here to implement full lock-stepping
		ipmon_sync_on_syscall_exit(entry_offset);
	}
	else
	{
		// Wait until the master has written the results
		ipmon_do_syscall_wait(entry_offset);

		ret = syscall_entry_return_value(entry_offset);

		if (!ipmon_should_restart_call(ret))
		{
			// Replicate the results
			ipmon_syscall_postcall(args, entry_offset);

			// And update our position in the buffer because the master might have
			// changed the entry size.
			variant_info_pos_set(ipmon_variant_num,
								 variant_info_pos(ipmon_variant_num) + syscall_entry_entry_size(entry_offset) - sizeof(struct ipmon_syscall_entry));
		}

		// We could sync with the master here
		ipmon_sync_on_syscall_exit(entry_offset);
	}

	return ret;
}

/*-----------------------------------------------------------------------------
    ipmon_is_unchecked_syscall
-----------------------------------------------------------------------------*/
STATIC INLINE unsigned char ipmon_is_unchecked_syscall(unsigned char* mask, unsigned long syscall_no)
{
	unsigned long no_to_byte, bit_in_byte;

	/* This is not very concise but the compiler will optimize it anyway... */
	if (syscall_no > ROUND_UP(__NR_syscalls, 8))
		return 0;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (mask[no_to_byte] & (1 << (7 - bit_in_byte)))
		return 1;
	return 0;
}

/*-----------------------------------------------------------------------------
    ipmon_set_unchecked_syscall
-----------------------------------------------------------------------------*/
STATIC INLINE void ipmon_set_unchecked_syscall(unsigned char* mask, unsigned long syscall_no, unsigned char unchecked)
{
	unsigned long no_to_byte, bit_in_byte;

	if (syscall_no > ROUND_UP(__NR_syscalls, 8))
		return;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (unchecked)
		mask[no_to_byte] |= (1 << (7 - bit_in_byte));
	else
		mask[no_to_byte] &= ~(1 << (7 - bit_in_byte));
}

/*-----------------------------------------------------------------------------
    ipmon_enclave_entrypoint - This is where we land after the enclave entrypoint has
	set up our arguments for us. (This is injected by the diablo.py script in the final assembly file)
-----------------------------------------------------------------------------*/
extern "C" long ipmon_enclave_entrypoint
(
	unsigned long syscall_no,
	unsigned long arg1,
	unsigned long arg2,
	unsigned long arg3,
	unsigned long arg4,
	unsigned long arg5,
	unsigned long arg6
)
{
	long result;
	struct ipmon_syscall_args args;
	args.arg1 = arg1;
	args.arg2 = arg2;
	args.arg3 = arg3;
	args.arg4 = arg4;
	args.arg5 = arg5;
	args.arg6 = arg6;
	args.entry_offset = 0;

	// If the syscall is not registered as a possibly unchecked syscall,
	// then we can skip the policy checks and replication logic altogether.
	//
	// Do note that even if we did decide to let the call through,
	// the kernel would refuse to dispatch it as an unchecked call anyway!
	if (!ipmon_is_unchecked_syscall(mask, syscall_no)
		|| ipmon_syscall_maybe_checked(args, syscall_no))
		return ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);

	// Certain syscalls are always harmless and should bypass both the ptracer
	// and the IP-MON's replication logic. Examples of such calls are
	// sys_sched_yield and sys_madvise
	if (ipmon_syscall_is_unsynced(args, syscall_no))
	{
		if (rb_have_pending_signals())
			syscall_no = (unsigned long)-1;

		result = ipmon_unchecked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);

		if (ipmon_should_restart_call(result))
			result = ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);		

		return result;
	}

	// OK. At this point we know that the syscall could possibly bypass
	// the ptracer and that it does have to go through the policy and
	// replication manager.
	//
	// We invoke the policy manager here first through ipmon_prepare_syscall.
	// The policy manager will then tell us what to do with it.
	switch(ipmon_prepare_syscall(args, syscall_no))
	{
		// This is a possible outcome for the master replica.  For
		// IPMON_EXEC_IPMON, the master replica should log its syscall
		// arguments, perform an unchecked call and log the syscall results.
		case IPMON_EXEC_IPMON:
		{
			if (rb_have_pending_signals())
				syscall_no = (unsigned long)-1;

			result = ipmon_unchecked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);

			long ret = ipmon_finish_syscall(args, result);

			if (ipmon_should_restart_call(result))
				return ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);

			return ret;
		}
		// This is a possible outcome for the slave replica.
		// Generally, whenever the policy manager decides that the master's
		// disposition is IPMON_EXEC_IPMON, the slave's disposition will
		// be IPMON_EXEC_NOEXEC.
		//
		// IPMON_EXEC_NOEXEC means that we should not invoke the original
		// syscall but we SHOULD pick up the results from the IPMON buffer
		case IPMON_EXEC_NOEXEC:
		{
			long ret = ipmon_finish_syscall(args, 0);

			if (ipmon_should_restart_call(ret))
				ret = ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);

			return ret;
		}
		// Finally, the policy manager could decide that the syscall
		// does have to be reported to the ptracer.
		default:
			break;
	}

	return ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
}

/*-----------------------------------------------------------------------------
    ipmon_rb_probe - 
-----------------------------------------------------------------------------*/
/*
void ipmon_rb_probe()
{
	// Test if we can access the replication buffer
	RB->padding[0] = 0;
}
*/

/*-----------------------------------------------------------------------------
    ipmon_register_thread - IP-MON registration is thread-local now!
-----------------------------------------------------------------------------*/
void ipmon_register_thread()
{
	void* RB = (void*)ipmon_checked_syscall(__NR_shmat, 
											ipmon_checked_syscall(MVEE_GET_SHARED_BUFFER,
																  0,
																  MVEE_IPMON_BUFFER,
																  (unsigned long)NULL,
																  (unsigned long)NULL,
																  (unsigned long)NULL,
																  (unsigned long)NULL), 
											(unsigned long)NULL,
											0);

	/* TODO STIJN: Is the passing around of RB needed here? */
	if (!RB)
	{
		printf("ERROR: IP-MON registration failed. Could not attach to Replication Buffer\n");
		exit(-1);
		return;
	}

	//printf("Replication buffer mapped @ 0x%016lx\n", ipmon_replication_buffer);

	// Attach to the regfile map. This one is process-wide but might still be mapped after forking! 
	long mvee_regfile_id = ipmon_checked_syscall(MVEE_GET_SHARED_BUFFER,
												 0,
												 MVEE_IPMON_REG_FILE_MAP,
											     (unsigned long)NULL,
												 (unsigned long)NULL,
												 (unsigned long)NULL,
												 (unsigned long)NULL);
	if (mvee_regfile_id != ipmon_reg_file_map_id)
	{
		ipmon_reg_file_map_id = mvee_regfile_id;
		ipmon_reg_file_map    = (char*)ipmon_checked_syscall(__NR_shmat, mvee_regfile_id, (unsigned long)NULL, 0);

		if (!ipmon_reg_file_map)
		{
			printf("ERROR: IP-MON registration failed. Could not attach to File Map\n");
			exit(-1);
			return;
		}
	}

	// This syscall returns the thread number within the variant set and can
	// optonally also set the variant number
	ipmon_checked_syscall(MVEE_GET_THREAD_NUM, (unsigned long)&ipmon_variant_num);

	// Register IP-MON
	long ret = ipmon_checked_syscall(__NR_prctl, 
									 PR_REGISTER_IPMON, 
									 (unsigned long)kernelmask, 
									 ROUND_UP(__NR_syscalls, 8) / 8, 
									 (unsigned long)RB, 
									 (unsigned long)ipmon_enclave_entrypoint
		);

	RB = NULL;

	// TODO: There used to be a race here and it might still be there.
	// Registration may in fact fail because the calling thread
	// is being transferred from one ptracer to the other.
	if (ret < 0 && ret > -4096)
	{
		printf("ERROR: IP-MON registration failed. sys_prctl(PR_REGISTER_IPMON) returned: %ld (%s)\n", ret, strerror(-ret));
		exit(-1);
		return;
	}
}

/*-----------------------------------------------------------------------------
    is_ipmon_libc_compatible - Check if the currently loaded glibc exports an
    ipmon_syscall symbol to find out whether or not it is compatible with
    IP-MON.
-----------------------------------------------------------------------------*/
STATIC INLINE
unsigned char is_ipmon_libc_compatible()
{
	if (!ipmon_initialized)
	{
		void* libc = dlopen("libc.so.6", RTLD_LAZY);
		if (libc && dlsym(libc, "ipmon_syscall"))
			ipmon_libc_compatible = 1;
	}
	return ipmon_libc_compatible;
}

/*-----------------------------------------------------------------------------
    is_ipmon_kernel_compatible - Check if the currently loaded kernel supports
	the sys_ipmon_return syscall
-----------------------------------------------------------------------------*/
STATIC INLINE
unsigned char is_ipmon_kernel_compatible()
{
	if (!ipmon_initialized)
	{
		// this call returns -EFAULT if called from outside the 
		// enclave
		if (ipmon_checked_syscall(__NR_ipmon_invoke) == -ENOIPMON)
			ipmon_kernel_compatible = 1;
	}
	return ipmon_kernel_compatible;
}

/*-----------------------------------------------------------------------------
    init - Initialize IP-MON and check for compatible glibc
-----------------------------------------------------------------------------*/
void __attribute__((constructor)) init()
{
	// We don't want to recalculate the syscall mask if we've already registered
	// an IP-MON for this process.
	if (ipmon_initialized && 
/*		is_ipmon_libc_compatible() && */
		is_ipmon_kernel_compatible())
	{
		ipmon_register_thread();
		return;
	}

/*
	if (!is_ipmon_libc_compatible())
	{
		printf("WARNING: IP-MON has been activated through the use_ipmon setting in MVEE.ini,\n");
		printf("WARNING: but we could not detect an IP-MON-compatible glibc.\n");
		printf("WARNING:\n");
		printf("WARNING: Common causes include:\n");
		printf("WARNING: * You have set use_system_libc to 1 in MVEE.ini and are therefore not\n");
		printf("WARNING: loading the glibc binary from MVEE/prebuilt_binaries/libc/arch/.");
		printf("WARNING:\n");
		printf("WARNING: * You have not built an IP-MON-compatible glibc. Please refer to\n");
		printf("WARNING: MVEE/README.txt for instructions\n");
		return;
	}
*/

	if (!is_ipmon_kernel_compatible())
	{
		printf("WARNING: IP-MON has been activated through the use_ipmon setting in MVEE.ini,\n");
		printf("WARNING: but we could not detect an IP-MON-compatible kernel.\n");
		printf("WARNING:\n");
		printf("WARNING: Please refer to MVEE/README.txt for instruction on how to build an\n");
		printf("WARNING: IP-MON compatible kernel.\n");
		return;
	}

	ipmon_initialized = true;
	IPMON_MASK_CLEAR(mask);
	IPMON_MASK_SET(mask, __NR_ipmon_invoke);

#if CURRENT_POLICY >= BASE_POLICY
	IPMON_MASK_SET(mask, __NR_getegid);
	IPMON_MASK_SET(mask, __NR_geteuid);
	IPMON_MASK_SET(mask, __NR_getgid);
	IPMON_MASK_SET(mask, __NR_getpgrp);
	IPMON_MASK_SET(mask, __NR_getppid);
	IPMON_MASK_SET(mask, __NR_gettid);
	IPMON_MASK_SET(mask, __NR_getuid);
	IPMON_MASK_SET(mask, __NR_getpid);
	IPMON_MASK_SET(mask, __NR_gettimeofday);
	IPMON_MASK_SET(mask, __NR_time);
	IPMON_MASK_SET(mask, __NR_clock_gettime);
	IPMON_MASK_SET(mask, __NR_sched_yield);
	IPMON_MASK_SET(mask, __NR_getcwd);
	IPMON_MASK_SET(mask, __NR_uname);
	IPMON_MASK_SET(mask, __NR_getpriority);
	IPMON_MASK_SET(mask, __NR_nanosleep);
	IPMON_MASK_SET(mask, __NR_getrusage);
	IPMON_MASK_SET(mask, __NR_sysinfo);
    IPMON_MASK_SET(mask, __NR_times);
	IPMON_MASK_SET(mask, __NR_capget);
	IPMON_MASK_SET(mask, __NR_getitimer);

# if CURRENT_POLICY >= NONSOCKET_RO_POLICY
	// unconditionally allow
	IPMON_MASK_SET(mask, __NR_access);
	IPMON_MASK_SET(mask, __NR_faccessat);
	IPMON_MASK_SET(mask, __NR_stat);
	IPMON_MASK_SET(mask, __NR_lstat);
	IPMON_MASK_SET(mask, __NR_fstat);
	IPMON_MASK_SET(mask, __NR_newfstatat);
	IPMON_MASK_SET(mask, __NR_getdents);
	IPMON_MASK_SET(mask, __NR_readlink);
	IPMON_MASK_SET(mask, __NR_readlinkat);
	IPMON_MASK_SET(mask, __NR_getxattr);
	IPMON_MASK_SET(mask, __NR_lgetxattr);
	IPMON_MASK_SET(mask, __NR_fgetxattr);
	IPMON_MASK_SET(mask, __NR_lseek);
	IPMON_MASK_SET(mask, __NR_alarm);
	IPMON_MASK_SET(mask, __NR_setitimer);
	IPMON_MASK_SET(mask, __NR_timerfd_gettime);
	IPMON_MASK_SET(mask, __NR_madvise);
	IPMON_MASK_SET(mask, __NR_fadvise64);

	// conditionally allow
	IPMON_MASK_SET(mask, __NR_read);
	IPMON_MASK_SET(mask, __NR_readv);
	IPMON_MASK_SET(mask, __NR_pread64);
	IPMON_MASK_SET(mask, __NR_preadv);
	IPMON_MASK_SET(mask, __NR_select);
	IPMON_MASK_SET(mask, __NR_poll); 
	IPMON_MASK_SET(mask, __NR_ioctl);
# if defined(IPMON_SUPPORT_FUTEX) || defined(IPMON_USE_FUTEXES_FOR_BLOCKING_CALLS)
	IPMON_MASK_SET(mask, __NR_futex);
# endif

#  if CURRENT_POLICY >= NONSOCKET_RW_POLICY
    // unconditionally allow
	IPMON_MASK_SET(mask, __NR_timerfd_settime);
	IPMON_MASK_SET(mask, __NR_sync);
	IPMON_MASK_SET(mask, __NR_fsync);
	IPMON_MASK_SET(mask, __NR_fdatasync);
	IPMON_MASK_SET(mask, __NR_syncfs);

	// conditionally allow
	IPMON_MASK_SET(mask, __NR_write);
	IPMON_MASK_SET(mask, __NR_writev);
	IPMON_MASK_SET(mask, __NR_pwrite64); 
	IPMON_MASK_SET(mask, __NR_pwritev); 

#   if CURRENT_POLICY >= SOCKET_RO_POLICY
	// unconditionally allow
	IPMON_MASK_SET(mask, __NR_recvfrom);
	IPMON_MASK_SET(mask, __NR_recvmsg);
	IPMON_MASK_SET(mask, __NR_recvmmsg);
	IPMON_MASK_SET(mask, __NR_getsockname);
	IPMON_MASK_SET(mask, __NR_getpeername);
	IPMON_MASK_SET(mask, __NR_getsockopt);

#    if CURRENT_POLICY >= SOCKET_RW_POLICY
	// unconditionally allow
	IPMON_MASK_SET(mask, __NR_sendto);
	IPMON_MASK_SET(mask, __NR_sendmsg);
	IPMON_MASK_SET(mask, __NR_sendmmsg);
	IPMON_MASK_SET(mask, __NR_sendfile);
	IPMON_MASK_SET(mask, __NR_shutdown);
	IPMON_MASK_SET(mask, __NR_setsockopt);
#     ifdef IPMON_SUPPORT_EPOLL
	IPMON_MASK_SET(mask, __NR_epoll_wait); // we can only support epoll_wait if we also see epoll_ctl coming in
	IPMON_MASK_SET(mask, __NR_epoll_ctl);
#     endif

#    endif  // >= SOCKET_RW
#   endif   // >= SOCKET_RO
#  endif    // >= NONSOCKET_RW
# endif     // >= NONSOCKET_RO
#endif      // >= BASE

	ipmon_memcpy_ptr_ptr(&kernelmask, &mask, sizeof(mask));

// explicitly disable it here because we might have enabled it
// during registration if we're using futexes internally
// for blocking calls
#ifndef IPMON_SUPPORT_FUTEX
    IPMON_MASK_UNSET(mask, __NR_futex);
#endif

	ipmon_register_thread();
}
