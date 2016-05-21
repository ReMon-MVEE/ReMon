/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in IPMONLICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <unistd.h>
#include <asm/unistd_64.h>

/*-----------------------------------------------------------------------------
    Hax0r
-----------------------------------------------------------------------------*/
#ifdef __cplusplus
extern "C" {
#endif

/*-----------------------------------------------------------------------------
    Policy control
-----------------------------------------------------------------------------*/
//#define IPMON_DO_LOCKSTEP
#define IPMON_USE_FUTEXES_FOR_CONDVAR
#define IPMON_SUPPORT_FUTEX
#define IPMON_SUPPORT_EPOLL

// don't do anything
#define USELESS_POLICY       0 

// Allow all read-only calls that do not operate 
// on file descriptors and that do not access the file system
#define BASE_POLICY          1

// BASE_POLICY + allow read-only calls on regular 
// files, pipes, special files and the file system.
// Also allow write-calls on process-local vars
#define NONSOCKET_RO_POLICY  2

// NONSOCKET_RO_POLICY + allow write calls on regular
// files, pipes and special files.
#define NONSOCKET_RW_POLICY  3

// NONSOCKET_RW_POLICY + allow read-only calls on sockets
#define SOCKET_RO_POLICY     4

// SOCKET_RO_POLICY + allow write calls on sockets
#define SOCKET_RW_POLICY     5

#define CURRENT_POLICY       SOCKET_RO_POLICY

/*-----------------------------------------------------------------------------
    Definitions and Generic Macros
-----------------------------------------------------------------------------*/
#ifndef __NR_syscalls
#define __NR_syscalls 319
#endif

#define __NR_ipmon_invoke 318
#define __NR_ipmon_return 319

#ifndef ROUND_UP
#define ROUND_UP(x, multiple) ( (((long)(x)) + multiple - 1) & (~(multiple - 1)) )
#endif

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

#define cpu_relax() asm volatile("rep; nop" ::: "memory")
#define gcc_barrier() asm volatile("" ::: "memory")

#define RB_REGISTER "r13"


#define CACHE_LINE_SIZE 64
#define MVEE_FUTEX_WAIT_TID                30
#define MAX_FDS  4096
#define PR_REGISTER_IPMON 		0xb00b135
#define ENOIPMON 256
#define RB ipmon_replication_buffer
#define IPMON_STATUS_FLUSHING 1
#define IPMON_YIELD_THRESHOLD 10000
#define IPMON_NOT_LEAVING_ENCLAVE 2 
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define INT_MAX 0x7fffffff

typedef unsigned long rb_pointer;

#define STATIC static
#define INLINE inline __attribute__((always_inline))
//#define INLINE inline
// #define STATIC
// #define INLINE

/*-----------------------------------------------------------------------------
    System Call Handler Macros
-----------------------------------------------------------------------------*/
//
// When defined, the syscall will always be dispatched as unchecked and will not
// be subject to any replication. This is useful for calls that are completely
// harmless and that do not return mutable results (e.g. sys_sched_yield)
//
#define UNSYNCED(a)      \
	STATIC INLINE unsigned char ipmon_handle_##a##_is_unsynced   () { return 1; }

//
// This can be defined for syscalls that may or may not be dispatched as
// unchecked, based on the syscall arguments. Might be useful for stuff
// like sys_read.
//
#define MAYBE_CHECKED(a) \
	STATIC INLINE bool          ipmon_handle_##a##_maybe_checked (struct ipmon_syscall_args& args)

//
// Calculates the size the syscall args and return values may occupy in the
// replication buffer. This calculates the worst-case size.  The effective size
// of the return values will be updated when the syscall returns.
//
#define CALCSIZE(a)      \
	STATIC INLINE void          ipmon_handle_##a##_calcsize      (struct ipmon_syscall_args& args, unsigned int* args_size, unsigned int* ret_size)

//
// Handles the pre-syscall logic. In the master variant, this is where the
// syscall args are logged. In the slave variants, this is where the syscall
// args are compared with the logged values.
//
#define PRECALL(a)       \
	STATIC INLINE unsigned long ipmon_handle_##a##_precall       (struct ipmon_syscall_args& args, unsigned long entry_offset, unsigned char order=0)

//
// Handles the post-syscall logic. In the master variant, this is where the
// syscall results are logged. In the slave variants, this is where we replicate
// the master's results.
//
#define POSTCALL(a)      \
	STATIC INLINE unsigned int  ipmon_handle_##a##_postcall      (struct ipmon_syscall_args& args, unsigned long entry_offset, long ret, bool success, unsigned char order=0)

// 
// Convenience Macros used in the syscall handlers
//
#define ARG1 args.arg1
#define ARG2 args.arg2
#define ARG3 args.arg3
#define ARG4 args.arg4
#define ARG5 args.arg5
#define ARG6 args.arg6

//
// Possible ways to complete a system call
//
#define IPMON_EXEC_NO_IPMON  0 // Do not use IP-MON to execute the syscall.
#define IPMON_EXEC_NOEXEC    1 // Do not execute the syscall but do invoke IP-MON for return value replication
#define IPMON_EXEC_IPMON     2 // Execute the syscall and if we're the master, also store return values

//
// Possible system call types for IPMON_EXEC_IPMON
//
#define IPMON_MASTERCALL     1 // Only the master should invoke the original syscall
#define IPMON_NORMAL_CALL    2 // All variants invoke the original syscall
#define IPMON_UNSYNCED_CALL  4 // All variants invoke the original syscall. No lock-stepping neccessary
#define IPMON_BLOCKING_CALL  8 // The call is expected to block. This is not a distinct call type. It is ORed with one of the above call types.

#define IPMON_MAYBE_BLOCKING(fd) ((ipmon_get_file_type(fd) & MVEE_BLOCKING_FD) ? IPMON_BLOCKING_CALL : 0)

/*-----------------------------------------------------------------------------
    MVEE File Mapping Definitions
-----------------------------------------------------------------------------*/
#define MVEE_BLOCKING_FD  (16)

enum FileType
{
    FT_UNKNOWN = 0,
    FT_REGULAR = 1,
    FT_PIPE_NON_BLOCKING = 2,
    FT_SOCKET_NON_BLOCKING = 3,
    FT_POLL_NON_BLOCKING = 4,
    FT_SPECIAL = 5,
    FT_PIPE_BLOCKING = 18,    // 16 | 2
    FT_SOCKET_BLOCKING = 19,  // 16 | 3
    FT_POLL_BLOCKING = 20,    // 16 | 4
};

/*-----------------------------------------------------------------------------
    IP-MON Mask Macros
-----------------------------------------------------------------------------*/
#define IPMON_MASK(mask) 				    unsigned char mask[ROUND_UP(__NR_syscalls, 8) / 8]
#define IPMON_MASK_CLEAR(mask) 			    ipmon_memset_ptr(mask, 0, ROUND_UP(__NR_syscalls, 8) / 8)
#define IPMON_MASK_SET(mask, syscall) 	    ipmon_set_unchecked_syscall(mask, syscall, 1)
#define IPMON_MASK_UNSET(mask, syscall)     ipmon_set_unchecked_syscall(mask, syscall, 0)
#define IPMON_MASK_ISSET(mask, syscall) 	ipmon_is_unchecked_syscall(mask, syscall)

/*-----------------------------------------------------------------------------
    IP-MON Data Structures
-----------------------------------------------------------------------------*/
//
// 
//
struct ipmon_barrier
{
	union
	{
		struct
		{
			unsigned short seq;
			unsigned char count;
			unsigned char padding;
		};
		unsigned int hack;
	};
};

//
//
//
struct ipmon_condvar
{
	union
	{
		struct
		{
			unsigned char have_waiters;
			unsigned char signaled;
			unsigned char padding[2];
		};
		unsigned int hack;
	};
};

//
// This structure could use some compression. We're using larger data types than we should be
//
struct ipmon_syscall_entry
{
	unsigned int  syscall_no;								// 0	- syscall no, see unistd.h
    unsigned char syscall_checked;							// 4	- if set to 1, the syscall must be reported to the ptracer and we don't perform user-space arg verification and return replication
	unsigned char syscall_is_mastercall;					// 5	- if set to 1, only the master may execute the call. The slaves just get the same result
	unsigned char syscall_is_blocking;                      // 6    - if set to 1, the master is expecting the syscall to block for some time and the slave should use a futex call on the return_valid field to wait for the result
	unsigned char padding;                                  // 7    - 
	struct ipmon_condvar
                  syscall_results_available;                // 8    - optimized condition variable. Does not support consecutive wait operations
	struct ipmon_barrier
                  syscall_lockstep_barrier;                 // 12   - used for lock-stepping
	unsigned int  syscall_entry_size;						// 16	- size of the entire entry, including syscall args and returns
	unsigned int  syscall_args_size;						// 20	- size of the arguments array only
	long          syscall_return_value;						// 24	- value returned through register rax
	// struct ipmon_syscall_data syscall_args[]             // 32   - These are not fixed size
	// struct ipmon_syscall_data syscall_returns[]
};

// we want to align this on a 4-byte boundary!
struct ipmon_syscall_data
{
	unsigned long 	len;
	unsigned char 	data[1];
};


struct ipmon_variant_info
{
	unsigned int  pos;                                      // This starts at zero and is relative to the end of the variant_info array in the RB
	unsigned int  status;
	unsigned char padding[64 - 2 * sizeof(unsigned int)];
};

struct ipmon_buffer
{
	// Cacheline 0
	int           numvariants;                        // 00-04: number of variants we're running with
	int           usable_size;                        // 04-08: size that is usable for syscall entries
	unsigned long have_pending_signals;
	unsigned char padding[64 - sizeof(unsigned long) - sizeof(int)*2];

	// Cachelines 1-n
	struct ipmon_variant_info variant_info[1];

	// And the actual syscall data
//	struct ipmon_syscall_entry ipmon_syscall_entry[1];
};

// This is the syscall metadata which we pass around to the various handler functions
// TODO: This structure could use a more appropriate name
struct ipmon_syscall_args
{
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
	unsigned long arg6;

	unsigned long entry_offset; /* offset wrt base of RB => 0 is invalid */
};

/*-----------------------------------------------------------------------------
    asm functions called from C
-----------------------------------------------------------------------------*/
long ipmon_checked_syscall   (unsigned long syscall_no, ...);
long ipmon_unchecked_syscall (unsigned long syscall_no, ...);
/*-----------------------------------------------------------------------------

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
extern unsigned char ipmon_variant_num;

/*-----------------------------------------------------------------------------
    Hax0r
-----------------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
