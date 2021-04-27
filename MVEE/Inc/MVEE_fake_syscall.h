/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_FAKE_SYSCALL_H_INCLUDED
#define MVEE_FAKE_SYSCALL_H_INCLUDED

/*-----------------------------------------------------------------------------
 Enumerations
 -----------------------------------------------------------------------------*/
#ifndef MVEE_FAKE_SYSCALL_DEFINES_ONLY
enum mvee_shared_buffer_types
{
    MVEE_PTHREAD_LOCK_BUFFER,      /* 0 */
    MVEE_GTK_HASH_BUFFER,          /* 1 */
    MVEE_ORBIT_REQUEST_BUFFER,     /* 2 */
    MVEE_LIBC_LOCK_BUFFER,         /* 3 */
    MVEE_GLIB_HASH_BUFFER,         /* 4 */
    MVEE_PANGO_HASH_BUFFER,        /* 5 */
    MVEE_REALLOC_BUFFER,           /* 6 */
    MVEE_UNO_HASH_BUFFER,          /* 7 */
    MVEE_RAND_BUFFER,              /* 8 */
    MVEE_LIBC_LOCK_EIP_BUFFER,     /* 9 - !!!DEPRECATED!!!: Now merged with the normal MVEE_LIBC_LOCK_LOCK_BUFFER!!! */
    MVEE_JDK_ATOMIC_BUFFER,        /* 10 */
    MVEE_LIBC_MALLOC_DEBUG_BUFFER, /* 11 */
    MVEE_GCCLIBS_BUFFER,           /* 12 */
    MVEE_LIBC_ATOMIC_BUFFER,       /* 13 */
    MVEE_OLD_MAX_SHM_TYPES,        /* 14 */
    MVEE_UTCB_BUFFER,              /* 15 - !!!DEPRECATED in favor of MVEE_IPMON_BUFFER!!! */
    MVEE_LIBC_LOCK_BUFFER_PARTIAL, /* 16 */
	MVEE_LIBC_ATOMIC_BUFFER_HIDDEN,/* 17 - !!!DEPRECATED!!! */
	MVEE_LIBC_HIDDEN_BUFFER_ARRAY, /* 18 - !!!DEPRECATED!!! */
	MVEE_UTCB_REG_FILE_MAP,        /* 19 - !!!DEPRECATED in favor of MVEE_IPMON_REG_FILE_MAP!!! */
	MVEE_IPMON_BUFFER,             /* 20 */
	MVEE_IPMON_REG_FILE_MAP,       /* 21 */
	MVEE_RING_BUFFER,              /* 22 */
	MVEE_SHM_BUFFER,               /* 23 */
    MVEE_MAX_SHM_TYPES             /* 24 */
};
#endif

/*-----------------------------------------------------------------------------
 Constants
 -----------------------------------------------------------------------------*/

#define MVEE_RDTSC_FAKE_SYSCALL  MVEE_FAKE_SYSCALL_BASE + 1

//
// MVEE_GET_MASTERTHREAD_ID: Fetches the id of the master variant's equivalent
// of the calling thread. Also sets a bool if the calling thread is IN the master
// variant.
//
// usage:
// bool im_the_master_variant;
// int masterthread_id = syscall(MVEE_GET_MASTERTHREAD_ID, &im_the_master_variant);
//
#define MVEE_GET_MASTERTHREAD_ID MVEE_FAKE_SYSCALL_BASE + 3

//
// MVEE_GET_SHARED_BUFFER: Fetches the id of the shared buffer of the specified type.
// The shared buffer is allocated if needed. There can be 1 shared buffer of each type
// (at most).
//
// As of 01/10/2012, every shared buffer can have an eip buffer associated with it.
// An eip buffer can be used to log partial callstacks for every variant.
//
// usage:
// int shared_buffer_id, shared_buffer_size;
// void* shared_buffer_ptr;
// int eip_buffer = 0;
// int stack_depth = 3;
// int shared_buffer_slot_size = 2*sizeof(int);
// shared_buffer_id = syscall(MVEE_GET_SHARED_BUFFER, eip_buffer, MVEE_PTHREAD_LOCK_BUFFER, &shared_buffer_size, shared_buffer_slot_size, stack_depth);
// if (shared_buffer_id != -1)
//     shared_buffer_ptr = shmat(shared_buffer_id, NULL, 0);
//
//
// parameters for the syscall:
// @param eip_buffer		: when set to 0, request the normal buffer. When
//		set to 1, request an eip buffer associated with the normal buffer.
// @param buffer_type		: buffer identifier. See above for a full list.
// @param buffer_size		: ptr to a word-sized variable in which to store
//		the size of the newly allocated buffer
// @param slot_size			: size (in bytes) of 1 buffer slot
// @param stack_depth		: ignored if eip_buffer == 0, contains the nr of
//		callstack elements in each slot (for every variant)
//
#define MVEE_GET_SHARED_BUFFER         MVEE_FAKE_SYSCALL_BASE + 4

//
// MVEE_FLUSH_SHARED_BUFFER: Used to sync the buffer flush (setting pos back to 0)
//
#define MVEE_FLUSH_SHARED_BUFFER       MVEE_FAKE_SYSCALL_BASE + 5

//
// MVEE_SET_INFINITE_LOOP_PTR: Used to identify the infinite loop function
// which is used for both thread transfering and signal delivery.
// See eglibc-<ver>/csu/libc-start.c (function mvee_inifinite_loop)
// for details
//
#define MVEE_SET_INFINITE_LOOP_PTR     MVEE_FAKE_SYSCALL_BASE + 6

//
// MVEE_TOGGLESYNC: Used to temporarily toggle synchronization of the specified syscall
// only allowed for certain call types! This is used to support functions like
// pthread_cond_timedwait
//
#define MVEE_TOGGLESYNC                MVEE_FAKE_SYSCALL_BASE + 7

//
// MVEE_SET_SHARED_BUFFER_POS_PTR: Passes a pointer to the current shared
// buffer position to the monitor
//
// !!!DEPRECATED!!!: This was used by an old version of the shared buffer-
// based interposers
#define MVEE_SET_SHARED_BUFFER_POS_PTR MVEE_FAKE_SYSCALL_BASE + 8

//
// MVEE_RUNS_UNDER_MVEE_CONTROL: Can be used to check if the program runs
// under MVEE control
//
#define MVEE_RUNS_UNDER_MVEE_CONTROL   MVEE_FAKE_SYSCALL_BASE + 9

//
// MVEE_GET_THREAD_NUM: Fetches the monitorid of the monitorthread responsible
// for monitoring the caller and also returns the variantnum of the caller
//
#define MVEE_GET_THREAD_NUM            MVEE_FAKE_SYSCALL_BASE + 10

//
// MVEE_RESOLVE_SYMBOL: resolves a symbol using debugging syms
//
#define MVEE_RESOLVE_SYMBOL            MVEE_FAKE_SYSCALL_BASE + 11

//
// MVEE_SET_SYNC_PRIMITIVES_PTR: passes a pointer to a bitmask that keeps
// track of which high-level sync primitives an application uses
//
#define MVEE_SET_SYNC_PRIMITIVES_PTR   MVEE_FAKE_SYSCALL_BASE + 12

//
// MVEE_ALL_HEAPS_ALIGNED: Checks if the variants' newly allocated heaps are
// aligned to the desired boundary. If any variant has a non-aligned heap, this
// syscall will return 0.  If all variants have aligned heaps, the call returns
// 1. If the call returns 0, the variants are expected to unmap the newly mapped
// heap and fall back to a slower aligned allocation method.
//
#define MVEE_ALL_HEAPS_ALIGNED         MVEE_FAKE_SYSCALL_BASE + 13

//
// MVEE_INVOKE_LD: transfer control to ld-linux
//
#define MVEE_INVOKE_LD                 MVEE_FAKE_SYSCALL_BASE + 16

//
// MVEE_GET_VIRTUALIZED_ARGV0: Writes the argv[0] value for the master variant
// into the buffer.
// Returns 0 if successful
//
// Syntax: 
//    syscall(MVEE_GET_VIRTUALIZED_ARGV0, old_argv0, virtualized_argv0_buf, virtualized_argv0_buf_sz)
// With:
//    - old_argv0 is a pointer to the original argv[0] string
//    - virtualized_argv0_buf is where the mvee should write the virtualized string
//    - virtualized_argv0_buf_sz is the size of the aforementioned buffer
//
#define MVEE_GET_VIRTUALIZED_ARGV0     MVEE_FAKE_SYSCALL_BASE + 17

//
// MVEE_ENABLE_XCHECKS: re-enables crosschecking for fastforwarding variants.
// Only works if variants.global.settings.xchecks_initially_enabled is false.
//
#define MVEE_ENABLE_XCHECKS            MVEE_FAKE_SYSCALL_BASE + 18

//
// MVEE_DISABLE_XCHECKS: turns crosschecking back off. Only works if
// variants.global.settings.xchecks_initially_enabled is false.
//
#define MVEE_DISABLE_XCHECKS           MVEE_FAKE_SYSCALL_BASE + 19

//
// MVEE_GET_LEADER_SHM_TAG: returns the shared-memory tag for the leader.
//
#define MVEE_GET_LEADER_SHM_TAG        MVEE_FAKE_SYSCALL_BASE + 20

//
// MVEE_RESET_ATFORK: registers a variable to be reset at fork-time (in the child)
//
#define MVEE_RESET_ATFORK              MVEE_FAKE_SYSCALL_BASE + 21

//
// MVEE Semaphore emulation calls. One weakness of our synchronization agents is
// that they capture synchronization operations on virtual addresses.  This does
// not work for inter-process semaphores because one and the same semaphore can
// be at virtual address A in one process and virtual address B in the other
// (even though A and B would map to the same physical address).  In this case,
// our synchronization agents would be unable to truly capture the order in
// which operations on that semaphore happen.
//
// As a workaround, we have the MVEE perform semaphore operations on behalf of
// the variants.
//
#define MVEE_SEM_CLOSE                 MVEE_FAKE_SYSCALL_BASE + 30
#define MVEE_SEM_GETVALUE              MVEE_FAKE_SYSCALL_BASE + 31
#define MVEE_SEM_INIT                  MVEE_FAKE_SYSCALL_BASE + 32
#define MVEE_SEM_OPEN                  MVEE_FAKE_SYSCALL_BASE + 33
#define MVEE_SEM_POST                  MVEE_FAKE_SYSCALL_BASE + 34
#define MVEE_SEM_UNLINK                MVEE_FAKE_SYSCALL_BASE + 35
#define MVEE_SEM_WAIT                  MVEE_FAKE_SYSCALL_BASE + 36
#define MVEE_SEM_TIMEDWAIT             MVEE_FAKE_SYSCALL_BASE + 37
#define MVEE_SEM_TRYWAIT               MVEE_FAKE_SYSCALL_BASE + 38

//
// MVEE_IPMON_INVOKE: This is an actual syscall we add to the kernel.
// The only time it is invoked directly is when IP-MON checks if it
// runs on top of an IP-MON compatible kernel
//
#define MVEE_IPMON_INVOKE              511

#endif // MVEE_FAKE_SYSCALL_H_INCLUDED
