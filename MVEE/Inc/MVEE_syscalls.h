/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

/*
    Notes on syscall handlers:

    - There are 6 types of handers:
        1. The get_call_type handler: if registered, this handler is called
        at EVERY syscall entrance. This handler determines whether or
        not a call should be synced.

        If not registered, the monitor assumes that the call is synced.

        2. The log_args handler: if registered, and if the monitor is compiled
        with MVEE_BENCHMARK defined, the log_args handler will log the system
        call arguments into the logfile.

        This handler can also be called by the error loggers (e.g. for a
        syscall number mismatch), even if MVEE_BENCHMARK is not defined.

        3. The precall handler: if registered, the handler is called at every
        syscall-entrance synchronization point. At the time of calling,
        childs[x].callnum and childs[x].regs are valid. This handler determines
        whether or not the call arguments match and how the call should be
        dispatched (normal vs master vs fork). The monitor is responsible for
        actually dispatching the call.

        If a call is denied by the precall handler, the monitor will shut down.

        WARNING: PRECALL HANDLERS ARE ___NOT___ CALLED FOR UNSYNCED CALLS!!!

        4. The call handler: if registered, the handler is called just prior
        to dispatching a call (either synced or unsynced). This handler can be
        used to manipulate the syscall arguments or to deny a dispatch (without
        having the monitor shut down). The handler does not perform the actual
        dispatch.

        5. The log return handler: if registered, and if the monitor is compiled
        with MVEE_BENCHMARK defined, the log_return handler will log the system
        call return value to the log file.

        6. The postcall handler: if registered, the handler is called when the
        call has returned. If the call was unsynced, the postcall handler is
        called immediately after the monitor sees the syscall exit. If the call
        was synced, the postcall handler is called at the syscall-exit
        synchronization point. At the time of calling, childs[x].callnum is no
        longer valid (but childs[x].prevcallnum is). Childs[x].regs IS still valid.
        If the call was synced, the succeeded flag is valid as well.

        These handlers are used to read syscall returns and sync them in case of
        a mastercall. Mastercall postcall handlers do not need to sync the EAX
        value. The monitor will do that. They DO need to sync return buffers.

  UPDATE: 16/12/2014
  I've split the handler table into log handlers and call handlers.
  Log handlers are only used if the MVEE is not compiled with MVEE_BENCHMARK.

*/

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
#define MVEE_PRECALL_ARGS_MATCH           0x0001                    // These two are a bit redundant...
#define MVEE_PRECALL_ARGS_MISMATCH        0x0002                    //
#define MVEE_PRECALL_CALL_DENY            0x0004
#define MVEE_PRECALL_CALL_DISPATCH_NORMAL 0x0008
#define MVEE_PRECALL_CALL_DISPATCH_FORK   0x0010
#define MVEE_PRECALL_CALL_DISPATCH_MASTER 0x0020

// Possible return values of the CALL system call handler
#define MVEE_CALL_ALLOW                   0x0001
#define MVEE_CALL_DENY                    0x0002
#define MVEE_CALL_ERROR                   0x0004
#define MVEE_CALL_VALUE                   0x0008
#define MVEE_CALL_RETURN_ERROR(a) (0x0004 | (a << 6))
#define MVEE_CALL_RETURN_VALUE(a) (0x0008 | (a << 6))
#define MVEE_CALL_RETURN_EXTENDED_VALUE   0x0010

// Possible return values of the POSTCALL system call handler
#define MVEE_POSTCALL_RESUME              0x0000
#define MVEE_POSTCALL_DONTRESUME          0x0001

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
