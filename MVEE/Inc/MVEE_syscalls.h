/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

// *****************************************************************************
// GHUMVEE supports two synchronization mechanisms for system calls: 
//
// * Lock-step synchronization (or "synced" execution in GHUMVEE-speak) -> the
// variants are stopped at every syscall entrance and exit and may not resume
// until all other variants have reached the same point, in an equivalent state.
// We generally do not allow variants to diverge when executing in lock-step
// mode. The few cases where "benign" divergences may happen are handled in the
// monitor::call_is_known_false_positive function.
//
// * Loose synchronization (or "unsynced" execution in GHUMVEE-speak) -> in
// certain cases, the variants may execute syscalls freely, without being
// stopped. When executing an "unsynced" syscall, we allow the variant that
// executes the call to diverge from the other variants.
//
// *****************************************************************************
// In lock-step mode, there are three ways to dispatch a system call:
//
// * Mastercall dispatch -> Only the master variant executes the original
// syscall, while the slave variants execute a dummy syscall (sys_getpid). When
// the syscall returns, GHUMVEE copies the master's results to the slaves'
// address spaces. We mostly use mastercall dispatch for I/O-related system
// calls (e.g. sys_write).
//
// * Normal dispatch -> All variants execute the original syscall and GHUMVEE
// does not copy the master's results to the slaves' address spaces when the
// syscall returns. This is the default dispatching method.
//
// * Fork dispatch -> Only used for sys_clone, sys_fork and sys_vfork. This is
// similar to normal dispatch, but GHUMVEE does some extra post-call handling
// to set up the newly created threads/processes.
//
// *****************************************************************************
// GHUMVEE implements syscall support using the system call handlers (in
// MVEE_syscalls_handlers.cpp). Every syscall handler function must have the
// following signature:
//   long monitor::<syscall name>_<handler function type>(int variantnum)
//
// When compiling GHUMVEE, the generate_syscall_tables.rb script will parse the
// MVEE_syscalls_handlers.cpp file to build function pointer tables containing
// the function handlers for each syscall. The high-level syscall dispatching
// functions in MVEE_syscalls.cpp use these tables to invoke the appropriate
// handler functions for each syscall. Depending on the syscall execution mode,
// MVEE_syscalls.cpp will pass -1 as the value for variantnum (in case of a
// synced syscall) or a positive value (in case of an unsynced syscall). 
//
// *****************************************************************************
// GHUMVEE can run in DEBUG mode or in BENCHMARK mode. In DEBUG mode, GHUMVEE
// will create log files in the MVEE/bin/<build type>/Logs folder. These log
// files contain strace-like output.
//
// In BENCHMARK mode, GHUMVEE disables all logging.
//
// BENCHMARK mode can be enabled by defining the MVEE_BENCHMARK preprocessor
// flag in MVEE/Inc/MVEE_config.h.
//
// *****************************************************************************
// There are _SIX_ types of syscall handlers:
//
// 1) get_call_type handler (Optional):
// ------------------------------------
//
// Called for                : all syscalls
// Called in BENCHMARK mode  : YES
// variants[x].callnum valid : NO
// variants[x].regs valid    : NO
//
// GHUMVEE calls this handler to determine the synchronization mode for the
// corresponding syscall. If the function returns MVEE_CALL_TYPE_UNSYNCED, then
// the syscall invocation will not be subject to lock-stepping. If the function
// returns anything else, or if no get_call_type handler exists for the syscall,
// then the syscall _WILL_ be subject to lock-stepping.
//
// 2) log_args handler (Optional):
// -------------------------------
//
// Called for                : all syscalls
// Called in BENCHMARK mode  : NO
// variants[x].callnum valid : NO
// variants[x].regs valid    : NO
//
// GHUMVEE calls this handler at the entrance of a syscall. The handler logs
// the system call arguments for the syscall being executed. The return value
// of the log_args handler is ignored.
//
// 3) precall handler (Required):
// ------------------------------
//
// Called for                : synced syscalls only
// Called in BENCHMARK mode  : YES
// variants[x].callnum valid : YES
// variants[x].regs valid    : YES
//
// These handlers are used to detect system call argument divergences and to
// control the dispatching mode. precall handlers are NOT optional. If the
// variants execute a syscall for which no precall handler exists, then GHUMVEE
// will consider this to be a divergence and it will shut down the MVEE.
//
// 4) call handler (Optional):
// ---------------------------
//
// Called for                : all syscalls
// Called in BENCHMARK mode  : YES
// variants[x].callnum valid : YES
// variants[x].regs valid    : YES
//
// These handlers can be used to overwrite system call arguments and/or to force
// syscalls to return immediately (possibly while returning an error). Call
// handlers are called _JUST_ before the variants are resumed from the syscall
// entry site. The main reason why we have these handlers is to be able to deny
// syscalls without signalling a divergence.
//
// 5) log_return handler (Optional):
// ---------------------------------
//
// Called for                : all syscalls
// Called in BENCHMARK mode  : NO
// variants[x].callnum valid : YES
// variants[x].regs valid    : YES
//
// Similar to the log_args handlers, these handler functions log the syscall
// results for the corresponding system call.
// 
// 6) postcall handler (Optional):
// -------------------------------
//
// Called for                : all syscalls
// Called in BENCHMARK mode  : YES
// variants[x].callnum valid : NO
// variants[x].regs valid    : YES
//
// The main purpose of these handler functions is to copy the syscall results
// from the master to the slaves' address spaces. We generally only do this for
// mastercalls. Optionally, the postcall handler can request that the variant(s)
// are not resumed from the syscall exit site.
//
// *****************************************************************************
#ifndef MVEE_SYSCALLS_H_INCLUDED
#define MVEE_SYSCALLS_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "MVEE_config.h"

/*-----------------------------------------------------------------------------
    Syscall Handler Definitions
-----------------------------------------------------------------------------*/
// Types of system call handlers
#define MVEE_GET_CALL_TYPE                0
#define MVEE_HANDLE_PRECALL               1
#define MVEE_HANDLE_CALL                  2
#define MVEE_HANDLE_POSTCALL              3

// Types of system call loggers
#define MVEE_LOG_ARGS                     0
#define MVEE_LOG_RETURN                   1

// Possible return values of the GET_CALL_TYPE system call handler
#define MVEE_CALL_TYPE_UNKNOWN            0
#define MVEE_CALL_TYPE_UNSYNCED           1
#define MVEE_CALL_TYPE_NORMAL             2

// Possible return values of the PRECALL system call handler
#define MVEE_PRECALL_ARGS_MATCH           0x0001                    // All variants have equivalent syscall arguments
#define MVEE_PRECALL_ARGS_MISMATCH(a)     (0x0002 | (a << 6))       // A mismatch was detected in syscall argument nr. <a>
#define MVEE_PRECALL_CALL_DENY            0x0004                    // The variants have diverged. NOTE: We could technically allow a call, despite having an argument mismatch!
#define MVEE_PRECALL_CALL_DISPATCH_NORMAL 0x0008                    // Dispatch as a normal syscall
#define MVEE_PRECALL_CALL_DISPATCH_FORK   0x0010                    // Dispatch as a fork-like syscall
#define MVEE_PRECALL_CALL_DISPATCH_MASTER 0x0020                    // Dispatch as a mastercall
#define MVEE_PRECALL_MISMATCHING_ARG(precall_flags) \
	((precall_flags & (~0x3F)) >> 6)

// Possible return values of the CALL system call handler
#define MVEE_CALL_ALLOW                   0x0001                    // Allow the variant(s) to be resumed from the syscall entry site, without modifying their syscall number or arguments
#define MVEE_CALL_DENY                    0x0002                    // Allow the variant(s) to be resumed from the syscall entry site, but replace their syscall number by __NR_getpid
#define MVEE_CALL_HANDLED_UNSYNCED_CALL   0x0004                    // Debugging aid
#define MVEE_CALL_ERROR                   0x0004                    
#define MVEE_CALL_VALUE                   0x0008
#define MVEE_CALL_RETURN_ERROR(a) (0x0004 | (a << 6))               // Used in conjunction with MVEE_CALL_DENY. Return error <a> from the denied syscall (this is equivalent to MVEE_CALL_RETURN_VALUE(-a))
#define MVEE_CALL_RETURN_VALUE(a) (0x0008 | (a << 6))               // Used in conjunction with MVEE_CALL_DENY. Return value <a> from the denied syscall
#define MVEE_CALL_RETURN_EXTENDED_VALUE   0x0010                    // Used in conjunction with MVEE_CALL_DENY. Return value <variants[].extended_value> from the denied syscall (we need this for word-sized return values)

// Possible return values of the POSTCALL system call handler
#define MVEE_POSTCALL_RESUME              0x0000                    // Default return value for postcall handlers. Resume the variant(s) from the syscall exit site
#define MVEE_POSTCALL_DONTRESUME          0x0001                    // Don't resume the variant(s) from the syscall exit site (used for sigreturn and friends)
#define MVEE_POSTCALL_HANDLED_UNSYNCED_CALL 0x0002

#define MVEE_HANDLER_DONTHAVE             (&monitor::handle_donthave)
#define MVEE_HANDLER_DONTNEED             (&monitor::handle_dontneed)

// Types of locks a system call handler might need - these are managed from MVEE/Src/MVEE_syscalls.cpp
#define MVEE_SYSLOCK_MMAN                 (1 << 0)                  // syscall needs mman lock
#define MVEE_SYSLOCK_SHM                  (1 << 1)                  // syscall needs shm lock
#define MVEE_SYSLOCK_FD                   (1 << 2)                  // syscall needs fd lock
#define MVEE_SYSLOCK_SIG                  (1 << 3)                  // syscall needs sighand lock
#define MVEE_SYSLOCK_FULL                 (1 << 4)                  // syslocks need to be held accross the call
#define MVEE_SYSLOCK_PRECALL              (1 << 5)                  // syslocks need to be held before the call only
#define MVEE_SYSLOCK_POSTCALL             (1 << 6)                  // syslocks need to be held after the call only

#endif // MVEE_SYSCALLS_H_INCLUDED
