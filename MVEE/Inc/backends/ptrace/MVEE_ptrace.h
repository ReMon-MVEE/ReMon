/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_PTRACE_H_INCLUDED
#define MVEE_PTRACE_H_INCLUDED

/*-----------------------------------------------------------------------------
  Includes
-----------------------------------------------------------------------------*/
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <unistd.h>
#include "MVEE_build_config.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
  Definitions
-----------------------------------------------------------------------------*/
#ifndef PTRACE_GETSIGMASK
  #define PTRACE_GETSIGMASK (__ptrace_request)0x420a // new since Linux 3.11
#endif

#ifndef PTRACE_SETSIGMASK
  #define PTRACE_SETSIGMASK (__ptrace_request)0x420b // new since Linux 3.11
#endif

#ifndef SIGSYSTRAP
  #define SIGSYSTRAP (SIGTRAP | 0x80)
#endif

/*-----------------------------------------------------------------------------
    Constants
-----------------------------------------------------------------------------*/
#define PROCESS_VM_WRITEV     0x4222
#define PROCESS_VM_READV      0x4223

enum StopReason
{
    STOP_NOTSTOPPED,
	STOP_SYSCALL,
	STOP_SIGNAL,
	STOP_EXECVE,
	STOP_FORK,
	STOP_EXIT,
	STOP_KILLED
};

/*-----------------------------------------------------------------------------
  Interaction
-----------------------------------------------------------------------------*/
namespace interaction
{
    // *************************************************************************
    // Structures
    // *************************************************************************
	struct mvee_wait_status
	{
        // process that is reporting a stop
		pid_t pid; 
        StopReason reason;
        unsigned long data;
	};

	// *************************************************************************
    // Process Control
    // *************************************************************************

	// 
	// Resume the specified variant and make sure it gets stopped at its next
	// syscall entry/exit.
	// 
	// If pending_signal_to_be_delivered is not 0, then the signal with that
	// signal number will be delivered to the variant, provided that it is 
	// already in the variant's pending list.
	//
	// NOTE: signal delivery through ptrace is NOT synchronous. The variant
	// might run uncontrolably for a while before the signal handler associated
	// with the signal is invoked. To prevent this from happening, you
	// could/should move the instruction pointer to an infinite loop BEFORE
	// resuming the variant.
	//
	static bool resume_until_syscall (pid_t variantpid, int pending_signal_to_be_delivered=0)
	{
        if (ptrace(PTRACE_SYSCALL, variantpid, 0, (void*) (long) pending_signal_to_be_delivered) == 0)
			return true;
		return false;
	}

	// 
	// Resume the specified variant and do not request that it be stopped at 
	// its next syscall entry/exit.
	//
	// 
	// If pending_signal_to_be_delivered is not 0, then the signal with that
	// signal number will be delivered to the variant, provided that it is 
	// already in the variant's pending list.
	//
	// NOTE: signal delivery through ptrace is NOT synchronous. The variant
	// might run uncontrolably for a while before the signal handler associated
	// with the signal is invoked. To prevent this from happening, you
	// could/should move the instruction pointer to an infinite loop BEFORE
	// resuming the variant.
	//
	static bool resume (pid_t variantpid, int pending_signal_to_be_delivered=0)
	{
        if (ptrace(PTRACE_CONT, variantpid, 0, (void*) (long) pending_signal_to_be_delivered) == 0)
            return true;
        return false;
	}

    //
    // Place the specified variant under the calling monitor's supervision 
    //
	static bool attach (pid_t variantpid)
	{
        if (ptrace(PTRACE_ATTACH, variantpid, 0, NULL) == 0)
            return true;
        return false;
    }

	//
	// Detach the monitor from the specified variant. Note that this will result
	// in a SIGCONT signal being sent to the variant in case of ptrace.
	// 
	static bool detach (pid_t variantpid)
	{
		if (ptrace(PTRACE_DETACH, variantpid, 0, NULL) == 0)
			return true;
		return false;
	}

    //
    // Send a signal to a specific thread
    //
    static bool signal (pid_t variantpid, pid_t varianttgid, int signal)
	{		
		if (syscall(__NR_tgkill, varianttgid, variantpid, signal) == 0)
			return true;
		return false;
	}

	//
    // Kills an entire thread group
    //
    static bool kill_group (pid_t variantpid)
	{
		return signal(variantpid, variantpid, SIGKILL);
	}

    //
    // Kills a specific thread
    //
	static bool kill (pid_t variantpid, pid_t varianttgid)
	{
		return signal(variantpid, varianttgid, SIGKILL);
	}

	//
	// To be called when the variant is attached to its designated tracer
	// thread.  This configures ptrace so we receive notifications for all of
	// the events we care about.
	//
	static bool setoptions (pid_t variantpid)
	{
		if (ptrace(PTRACE_SETOPTIONS, variantpid, 0, 
				   (void*)(PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
						   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
						   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) == 0)
			return true;
		return false;
	}

	//
	// Place the calling process under the supervision of its parent process.
	// Specifically, this sets the parent process as the ptracer of the calling
	// process.  Note that this does not stop the process in case of ptrace.
	//
	static bool accept_tracing()
	{
		if (ptrace(PTRACE_TRACEME, 0, 0, NULL) == 0)
			return true;
		return false;
	}

    //
    // Poll process status if @pid == -1, we wait for ANY child process if @pid
    // > 0, we wait for that specific process/thread
	//
	// The contents of the mvee_wait_status struct depend on event that caused
	// the process to change state.
	//
	// These are the possible values for <status.reason> upon successful return of
	// this function:
	//
	// + STOP_NOTSTOPPED: a non-blocking wait was requested and no thread has
	// changed state. <status.pid> is 0.
	//
	// + STOP_SYSCALL: a syscall entry or exit event caused the thread to change
	// state. <status.pid> is the pid of the thread that entered/returned from a
	// syscall.
	//
	// + STOP_FORK: a process/thread created a new child using fork, vfork or
	// clone.  <status.pid> is the pid of the process/thread that
	// forked. <status.data> is the pid of the child process/thread.
	//
	// + STOP_EXECVE: a process has successfully replaced its core image through
	// execve. <status.pid> is the pid of the process that has completed the
	// execve call.
	//
	// + STOP_EXIT: a thread has terminated through sys_exit or sys_exit_group.
	// <status.pid> is the pid of the terminated thread. <status.data> is the
	// exit code of the terminated thread.
	// 
	// + STOP_KILLED: a thread was killed by a signal. <status.pid> is the pid
	// of the terminated thread. <status.data> is the signal that caused its
	// termination.
	//
	// + STOP_SIGNAL: a signal was sent to a thread. <status.pid> is the thread
	// the signal was sent to. <status.data> is the signal that was sent.
    //
    static bool wait (pid_t pid, struct mvee_wait_status& status, bool wait_for_specific_thread_only=true, bool non_blocking=false, bool wait_for_non_traced_children=true)
	{
        int ret, flags = 0;

        if (wait_for_specific_thread_only)
            flags |= __WALL | __WNOTHREAD;
        if (non_blocking)
            flags |= WNOHANG;
        if (wait_for_non_traced_children)
            flags |= WUNTRACED;

		status.reason = STOP_NOTSTOPPED;
		status.data = SIGSTOP;
        status.pid = waitpid(pid, &ret, flags);

        if (status.pid == 0 && non_blocking)
		{
			status.reason = STOP_NOTSTOPPED;
		}
		else if (status.pid == -1)
		{
			status.reason = STOP_NOTSTOPPED;
			return false;
		}
		else
		{
			if (WIFSTOPPED(ret))
			{
				status.data = WSTOPSIG(ret);

				switch (status.data)
				{
					case SIGSYSTRAP:
					{
						status.reason = STOP_SYSCALL;
						break;
					}
					case SIGTRAP:
					{
						int event = ((ret & 0x000F0000) >> 16);
						if (event == PTRACE_EVENT_FORK || 
							event == PTRACE_EVENT_VFORK ||
							event == PTRACE_EVENT_CLONE)
						{
							status.reason = STOP_FORK;
							if (ptrace(PTRACE_GETEVENTMSG,
									   status.pid, 0, &status.data) == 0)
							{
								status.data = status.data & 0xFFFFFFFF;
							}
							else
							{
								return false;
							}
						}
						else if (event == PTRACE_EVENT_EXEC)
						{
							status.reason = STOP_EXECVE;
						}
						break;
					}
					default:
					{
						status.reason = STOP_SIGNAL;
						break;
					}
				}
			}
			else if (WIFEXITED(ret))
			{
				status.reason = STOP_EXIT;
				status.data = WEXITSTATUS(ret);
			}
			else if (WIFSIGNALED(ret))
			{
				status.reason = STOP_KILLED;
				status.data = WTERMSIG(ret);
			}
		}		

		return true;
    }

	//
	// Suspend the variant by sending it a SIGSTOP signal. We need the thread group id
	// for this as other threads in the group may also accept the SIGSTOP signal if
	// we don't use sys_tgkill
	//
	static bool suspend (pid_t variantpid, pid_t varianttgid)
	{
		return signal(variantpid, varianttgid, SIGSTOP);
	}

	//
	// Checks if the variant is suspended by attempting to read one of its registers
	// If the call fails, that means the variant is either dead, or not suspended
	//
	static bool is_suspended (pid_t variantpid)
	{
		if (ptrace(PTRACE_PEEKUSER, variantpid, 0, NULL) == -1)
			return false;
		return true;
	}

	// *************************************************************************
    // Read/write primitives
    // *************************************************************************

	//
	// Read a single memory word (i.e., 8 bytes on 64-bit or 4 bytes on 32-bit)
	// 
	static bool read_memory_word (pid_t variantpid, void* addr, long& out_value)
	{
		errno = 0;
#ifdef MVEE_GENERATE_EXTRA_STATS
		if (!mvee::in_logging_handler)
			mvee::log_ptrace_op(1, PTRACE_PEEKDATA, sizeof(long));
#endif
		long tmp = ptrace(PTRACE_PEEKDATA, variantpid, (unsigned long) addr, NULL);
		if (tmp == -1 && errno != 0)
			return false;
		out_value = tmp;
		return true;
	}

    //
    // Write a single memory word
    //
	static bool write_memory_word (pid_t variantpid, void* addr, long in_value)
	{
		if (ptrace(PTRACE_POKEDATA, variantpid, (unsigned long) addr, (void*) in_value) == -1)
			return false;
		return true;
	}

    // 
    // Read an arbitrary amount of data from the variant's virtual memory
    // 
    //
    static bool read_memory (pid_t variantpid, void* variant_addr, long data_len, void* monitor_buffer)
    {
        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base  = (void*)monitor_buffer;
        local[0].iov_len   = data_len;
        remote[0].iov_base = (void*)variant_addr;
        remote[0].iov_len  = data_len;

        ssize_t nread = process_vm_readv(variantpid, local, 1, remote, 1, 0);
        if (nread != data_len)
            warnf("interaction::read_memory failed. tried to read %d bytes - actually read %d bytes\n", 
				  data_len, nread);

#ifdef MVEE_GENERATE_EXTRA_STATS
        if (!mvee::in_logging_handler)
            mvee::log_ptrace_op(1, PROCESS_VM_READV, nread);
#endif

        return nread;
    }

    //
    // Write an arbitrary amount of data into the variant's virtual memory
    //
    static bool write_memory (pid_t variantpid, void* variant_addr, long data_len, void* monitor_buffer)
    {
        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base  = (void*)monitor_buffer;
        local[0].iov_len   = data_len;
        remote[0].iov_base = (void*)variant_addr;
        remote[0].iov_len  = data_len;

        ssize_t nwritten = process_vm_writev(variantpid, local, 1, remote, 1, 0);
        if (nwritten != data_len)
            warnf("interaction::write_memory failed. tried to write %d bytes - actually wrote %d bytes\n", 
				  data_len, nwritten);

#ifdef MVEE_GENERATE_EXTRA_STATS
        if (!mvee::in_logging_handler)
            mvee::log_ptrace_op(1, PROCESS_VM_WRITEV, nwritten);
#endif

        return nwritten;
    }

    //
    // Read all of the variant's general purpose registers into a
    // user_regs_struct
    //
	static bool read_all_regs (pid_t variantpid, user_regs_struct* regs)
	{
		if (ptrace(PTRACE_GETREGS, variantpid, 0, regs) == 0)
			return true;
		return false;
	}

    // 
    // Copy an entire user_regs_struct into the variant's general purpose
    // register context
    //
	static bool write_all_regs (pid_t variantpid, user_regs_struct* regs)
	{
		if (ptrace(PTRACE_SETREGS, variantpid, 0, regs) == 0)
			return true;
		return false;
	}

	// 
	// Read a specific register from the variant's register context.
	// @reg_offset must be an offset into the user struct (see
	// /usr/include/arch/sys/user.h) Typically, you can calculate the register
	// offset by taking the register number from /usr/include/arch/sys/reg.h and
	// multiplying it by the word size for the architecture.
	//
	static bool read_specific_reg (pid_t variantpid, int reg_offset, unsigned long& out_value)
	{
		errno = 0;
		long out = ptrace(PTRACE_PEEKUSER, variantpid, reg_offset, NULL);
		
		if (out == -1 && errno)
			return false;
		out_value = (unsigned long) out;
		return true;
	}

	// 
	// Overwrite a specific register in the variant's register context.
	// @reg_offset must be an offset into the user struct (see
	// /usr/include/arch/sys/user.h) Typically, you can calculate the register
	// offset by taking the register number from /usr/include/arch/sys/reg.h and
	// multiplying it by the word size for the architecture.
	//
	static bool write_specific_reg (pid_t variantpid, int reg_offset, unsigned long in_value)
	{
		if (ptrace(PTRACE_POKEUSER, variantpid, reg_offset, (void*) in_value) == -1)
			return false;
		return true;
	}

	//
	// Fetch the syscall number. To be used at a syscall entry site
	//
	static bool fetch_syscall_no (pid_t variantpid, unsigned long& syscall_no)
	{
		return read_specific_reg (variantpid, SYSCALL_NO_REG_OFFSET, syscall_no);
	}

	//
	// Overwrites the syscall number. To be used at a syscall entry site
	//
	static bool write_syscall_no (pid_t variantpid, unsigned long new_syscall_no)
	{
		return write_specific_reg (variantpid, SYSCALL_NO_REG_OFFSET, new_syscall_no);
	}

	// 
	// Reads the variant's instruction pointer
	//
	static bool fetch_ip (pid_t variantpid, unsigned long& ip)
	{
		return read_specific_reg(variantpid, IP_REG_OFFSET, ip);
	}

	//
	// Overwrites the variant's instruction pointer
	//
	static bool write_ip (pid_t variantpid, unsigned long ip)
	{
		return write_specific_reg(variantpid, IP_REG_OFFSET, ip);
	}

	//
	// Reads the syscall return value
	//
	static bool fetch_syscall_return (pid_t variantpid, unsigned long& syscall_return)
	{
		return read_specific_reg(variantpid, SYSCALL_RETURN_REG_OFFSET, syscall_return);
	}

	//
	// Overwrite the syscall return
	//
	static bool write_syscall_return (pid_t variantpid, unsigned long new_syscall_return)
	{
		return write_specific_reg(variantpid, SYSCALL_RETURN_REG_OFFSET, new_syscall_return);
	}

	//
	// Set the syscall no for the next syscall
	//
	static bool write_next_syscall_no (pid_t variantpid, unsigned long next_syscall_no)
	{
		return write_specific_reg(variantpid, SYSCALL_NEXT_REG_OFFSET, next_syscall_no);
	}

	// *************************************************************************
    // Signal Handling
    // *************************************************************************
	
	// 
	// Get information about the signal that stopped this variant
	//
	static bool get_signal_info (pid_t variantpid, siginfo_t* info)
	{
		if (ptrace(PTRACE_GETSIGINFO, variantpid, 0, info) == -1)
			return false;
		return true;
	}

    //
    // Set information about the signal that stopped this variant
    //
	static bool set_signal_info (pid_t variantpid, siginfo_t* info)
	{
        if (ptrace(PTRACE_SETSIGINFO, variantpid, 0, info) == -1)
			return false;
		return true;
	}
}



#endif
