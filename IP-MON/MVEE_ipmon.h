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
    RB Pointer Handling
-----------------------------------------------------------------------------*/
//
// Bart: if this is defined, the enclave entrypoint will _explicitly_ pass the
// RB pointer to the ipmon_enclave C function as the first argument
//
// If this is _NOT_ defined, then the enclave entrypoint will just keep
// the RB pointer in register R11
//
#define IPMON_PASS_RB_POINTER_EXPLICITLY

/*-----------------------------------------------------------------------------
    Policy control
-----------------------------------------------------------------------------*/
// Does the flush locally, avoiding context switches to GHUMVEE
#define IPMON_FLUSH_LOCAL

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

// Allow all supported calls
#define FULL_SYSCALLS        6

#define CURRENT_POLICY       FULL_SYSCALLS

/*-----------------------------------------------------------------------------
    Definitions and Generic Macros
-----------------------------------------------------------------------------*/
#ifndef __NR_syscalls
#define __NR_syscalls 317
#endif

#define __NR_ipmon_invoke 511

#ifndef ROUND_UP
#define ROUND_UP(x, multiple) ( (((long)(x)) + multiple - 1) & (~(multiple - 1)) )
#endif

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

#define cpu_relax() asm volatile("rep; nop" ::: "memory")
#define gcc_barrier() asm volatile("" ::: "memory")


#define CACHE_LINE_SIZE 64
#define MVEE_FUTEX_WAIT_TID                30
#define MAX_FDS  4096
#define PR_REGISTER_IPMON 		0xb00b135
#define ENOIPMON 256
///#define RB ipmon_replication_buffer
#define IPMON_STATUS_FLUSHING 1
#define IPMON_YIELD_THRESHOLD 10000
#define IPMON_NOT_LEAVING_ENCLAVE 2 
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define INT_MAX 0x7fffffff
#define ENTRY_ALIGNMENT sizeof(unsigned long)

#define O_FILEFLAGSMASK                    (O_LARGEFILE | O_RSYNC | O_DSYNC | O_NOATIME | O_DIRECT | O_ASYNC | O_FSYNC | O_SYNC | O_NDELAY | O_NONBLOCK | O_APPEND | O_TRUNC | O_NOCTTY | O_EXCL | O_CREAT | O_ACCMODE)
#define S_FILEMODEMASK                     (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)


typedef unsigned long rb_pointer;

//#define STATIC static
//#define INLINE inline
#define STATIC
#define INLINE

#define MVEE_FAKE_SYSCALL_BASE 0x6FFFFFFF // needed for fake syscalls

/*
 * PKU Syscalls
 */
#ifndef SYS_mprotect_key
#define SYS_mprotect_key 329//__NR_pkey_mprotect
#define SYS_pkey_alloc   330//__NR_pkey_alloc
#define SYS_pkey_free    331//__NR_pkey_free
#endif

#define pkey_mprotect(ptr, size, flags, pkey)   \
  syscall(SYS_mprotect_key, ptr, size, flags, pkey)

#define pkey_free(pkey)                         \
  syscall(SYS_pkey_free, pkey)

/*-----------------------------------------------------------------------------
    System Call Handler Macros
-----------------------------------------------------------------------------*/
//
// When defined, the syscall will always be dispatched as unchecked and will not
// be subject to any replication. This is useful for calls that are completely
// harmless and that do not return mutable results (e.g. sys_sched_yield)
//
#define UNSYNCED(a)      \
	unsigned char ipmon_handle_##a##_is_unsynced   () { return 1; }

//
// This can be defined for syscalls that may or may not be dispatched as
// unchecked, based on the syscall arguments. Might be useful for stuff
// like sys_read.
//
#define MAYBE_CHECKED(a) \
	bool          ipmon_handle_##a##_maybe_checked (struct ipmon_syscall_args& args)

//
// Calculates the size the syscall args and return values may occupy in the
// replication buffer. This calculates the worst-case size.  The effective size
// of the return values will be updated when the syscall returns.
//
#define CALCSIZE(a)      \
	void          ipmon_handle_##a##_calcsize      (struct ipmon_syscall_args& args, unsigned int* args_size, unsigned int* ret_size)

//
// Handles the pre-syscall logic. In the master variant, this is where the
// syscall args are logged. In the slave variants, this is where the syscall
// args are compared with the logged values.
//
// NOTE: This handler returns a system call type. Only the type returned
// in the master matters, however. The slave variants will simply use the
// same type the master logged into the RB.
//
#define PRECALL(a)       \
	unsigned short ipmon_handle_##a##_precall       (struct ipmon_syscall_args& args, struct ipmon_syscall_entry* entry, unsigned char order=0)

//
// Handles the post-syscall logic. In the master variant, this is where the
// syscall results are logged. In the slave variants, this is where we replicate
// the master's results.
//
#define POSTCALL(a)      \
	unsigned int  ipmon_handle_##a##_postcall      (struct ipmon_syscall_args& args, struct ipmon_syscall_entry* entry, long ret, long realret, bool success, unsigned char order=0)

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
// Who should execute the syscall?
//
#define IPMON_EXEC_NO_IPMON  1 // Do not use IP-MON to execute the syscall - Route to CP-MON instead
#define IPMON_EXEC_NOEXEC    2 // Abort the syscall but possibly use IP-MON for return value replication
#define IPMON_EXEC_MASTER    4 // The master executes the syscall. The slaves no not.
#define IPMON_EXEC_ALL       8 // All variants execute the syscall

//
// Possible ways to handle replication
//
#define IPMON_REPLICATE_MASTER 16 // The master results are replicated to the slaves

//
// Extra modifiers
//
#define IPMON_UNSYNCED_CALL  32  // No lock-stepping for this call
#define IPMON_BLOCKING_CALL  64  // The call is expected to block. This is not a distinct call type. It is ORed with one of the above call types.
#define IPMON_ORDER_CALL     128 // All ordered calls must execute in the same order in all variants
#define IPMON_LOCKSTEP_CALL  256 // 

//
// Signal Handling
//
#define IPMON_WAIT_FOR_SIGNAL_CALL 512 // Don't actually execute the call. Just wait for a signal delivery isntead

#define IPMON_MAYBE_BLOCKING(fd) ((ipmon_get_file_type(fd) & MVEE_BLOCKING_FD) ? IPMON_BLOCKING_CALL : 0)
#define IPMON_MAYBE_DISPATCH_MASTER(fd)							\
	if (ipmon_variant_num == 0)									\
	{															\
		char file_type = ipmon_get_file_type(fd);				\
		if (file_type & FT_MASTER_FILE)							\
			return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;	\
	}															\
	else														\
	{															\
		fd = ipmon_get_slave_fd(fd);							\
	}															\
	return IPMON_EXEC_ALL | IPMON_REPLICATE_MASTER;


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
	FT_MASTER_FILE = 32
};

/*-----------------------------------------------------------------------------
    IP-MON Mask Macros
-----------------------------------------------------------------------------*/
#define IPMON_MASK(mask) 				    unsigned char mask[ROUND_UP(__NR_syscalls, 8) / 8]
#define IPMON_MASK_CLEAR(mask) 			    memset(mask, 0, ROUND_UP(__NR_syscalls, 8) / 8)
#define IPMON_MASK_SET(mask, syscall) 	    ipmon_set_unchecked_syscall(mask, syscall, 1)
#define IPMON_MASK_UNSET(mask, syscall)     ipmon_set_unchecked_syscall(mask, syscall, 0)
#define IPMON_MASK_ISSET(mask, syscall) 	ipmon_is_unchecked_syscall(mask, syscall)

/*-----------------------------------------------------------------------------
    IP-MON Data Structures
-----------------------------------------------------------------------------*/
//
// Optimized non-pthreads barriers
//
struct ipmon_barrier
{
	union
	{
		struct
		{
			unsigned short seq;
			unsigned short count;
		};
		unsigned int hack;
	};
};

//
// Optimized non-pthreads condition variables
// NOTE: The way we implement these currently does not allow for condvar reuse.
// Once the cond var gets signaled, noone can wait on it again
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
// Optimized non-pthreads condition variables
//
struct ipmon_mutex
{
	union
	{
		struct
		{
			unsigned char locked;
			unsigned char contended;
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
	unsigned short syscall_no;								// 0	- We use this for integrity checking only so we don't mind that this does not capture pseudo-calls correctly
    unsigned short syscall_type; 							// 2	- bitwise or mask of call types above
	unsigned int   syscall_order;                           // 4    - Logical clock value for order-sensitive syscalls
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
	unsigned long have_pending_signals;               // 1 = signals are pending - 2 = in signal handler	
	struct ipmon_barrier pre_flush_barrier;
	struct ipmon_barrier post_flush_barrier;
	unsigned long flush_count;
	unsigned char padding[64 - 2*sizeof(unsigned long) - sizeof(int)*2 - sizeof(struct ipmon_barrier) * 2];

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

	struct ipmon_syscall_entry* entry;
};

/*-----------------------------------------------------------------------------
  kernel_termios is not compatible with termios (doh!)
-----------------------------------------------------------------------------*/
#define __KERNEL_NCCS 19
struct __kernel_termios
{
    tcflag_t c_iflag;             /* input mode flags */
    tcflag_t c_oflag;             /* output mode flags */
    tcflag_t c_cflag;             /* control mode flags */
    tcflag_t c_lflag;             /* local mode flags */
    cc_t     c_line;              /* line discipline */
    cc_t     c_cc[__KERNEL_NCCS]; /* control characters */
};

/*-----------------------------------------------------------------------------
    asm functions called from C
-----------------------------------------------------------------------------*/
long ipmon_checked_syscall	 (unsigned long syscall_no, ...);
long ipmon_unchecked_syscall (unsigned long syscall_no, ...);

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
