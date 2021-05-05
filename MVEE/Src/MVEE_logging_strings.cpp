/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/eventfd.h>
#include <sys/xattr.h>
#include <sys/un.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <linux/net.h>
#include <linux/futex.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <string.h>
#include <signal.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <linux/dqblk_xfs.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_logging.h"
#include "MVEE_syscall_string_table.h"
#include "MVEE_macros.h"
#include "MVEE_shm.h"
#include "MVEE_signals.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_memory.h"
#include "MVEE_filedesc.h"
#include "MVEE_interaction.h"
#include <linux/quota.h>
#ifdef MVEE_ARCH_HAS_ARCH_PRCTL
#include <asm/prctl.h>
#endif
#include <sys/random.h>

/*-----------------------------------------------------------------------------
    Flag Check Macro
-----------------------------------------------------------------------------*/
#define TEST_FLAG(flags, flag, str)                                         \
    if ((flags & flag) || (flags == flag) || ((flag == 0) && !(flags & 1))) \
    {                                                                       \
        if (str != "")                                                      \
            str += " | ";                                                   \
        str += #flag;                                                       \
    }

#define DEF_CASE(a) \
	case a:			\
	result = #a;	\
	break;

/*-----------------------------------------------------------------------------
    getTextualState
-----------------------------------------------------------------------------*/
const char* getTextualState(unsigned int state)
{
    const char* result = "UNKNOWN";

    switch(state)
    {
        DEF_CASE(STATE_WAITING_ATTACH);
        DEF_CASE(STATE_WAITING_RESUME);
        DEF_CASE(STATE_NORMAL);
        DEF_CASE(STATE_IN_SYSCALL);
        DEF_CASE(STATE_IN_MASTERCALL);
        DEF_CASE(STATE_IN_FORKCALL);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSig
-----------------------------------------------------------------------------*/
const char* getTextualSig(unsigned int sig)
{
    const char* result = "UNKNOWN";

    switch(sig)
    {
        DEF_CASE(SIGALRM)
        DEF_CASE(SIGHUP)
        DEF_CASE(SIGINT)
        DEF_CASE(SIGKILL)
        DEF_CASE(SIGPIPE)
        DEF_CASE(SIGPOLL)
        DEF_CASE(SIGPROF)
        DEF_CASE(SIGTERM)
        DEF_CASE(SIGUSR1)
        DEF_CASE(SIGUSR2)
        DEF_CASE(SIGVTALRM)
//        DEF_CASE(STKFLT) - Undefined on linux
        DEF_CASE(SIGPWR)
        DEF_CASE(SIGWINCH)
        DEF_CASE(SIGCHLD)
        DEF_CASE(SIGURG)
        DEF_CASE(SIGTSTP)
        DEF_CASE(SIGTTIN)
        DEF_CASE(SIGTTOU)
        DEF_CASE(SIGSTOP)
        DEF_CASE(SIGCONT)
        DEF_CASE(SIGABRT)
        DEF_CASE(SIGFPE)
        DEF_CASE(SIGILL)
        DEF_CASE(SIGQUIT)
        DEF_CASE(SIGSEGV)
#if SIGTRAP != SIGSYSTRAP
        DEF_CASE(SIGSYSTRAP)
#endif
        DEF_CASE(SIGTRAP)
        DEF_CASE(SIGSYS)
//        DEF_CASE(SIGEMT) - Undefined on linux
        DEF_CASE(SIGBUS)
        DEF_CASE(SIGXCPU)
        DEF_CASE(SIGXFSZ)
        DEF_CASE(SIGCANCEL)
        DEF_CASE(SIGSETXID)
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigHow
-----------------------------------------------------------------------------*/
const char* getTextualSigHow(int how)
{
    const char* result = "SIG_???";

    switch(how)
    {
        DEF_CASE(SIG_BLOCK);
        DEF_CASE(SIG_UNBLOCK);
        DEF_CASE(SIG_SETMASK);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualPtraceRequest
-----------------------------------------------------------------------------*/
const char* getTextualPtraceRequest(unsigned int request)
{
    const char* result = "PTRACE_UNKNOWN";

    switch(request)
    {
        DEF_CASE(PTRACE_TRACEME);
        DEF_CASE(PTRACE_PEEKTEXT);
        DEF_CASE(PTRACE_PEEKDATA);
        DEF_CASE(PTRACE_PEEKUSER);
        DEF_CASE(PTRACE_POKETEXT);
        DEF_CASE(PTRACE_POKEDATA);
        DEF_CASE(PTRACE_POKEUSER);
        DEF_CASE(PTRACE_CONT);
        DEF_CASE(PTRACE_KILL);
        DEF_CASE(PTRACE_SINGLESTEP);
        DEF_CASE(PTRACE_ATTACH);
        DEF_CASE(PTRACE_DETACH);
        DEF_CASE(PTRACE_SYSCALL);
        DEF_CASE(PTRACE_SETOPTIONS);
        DEF_CASE(PTRACE_GETREGS);
        DEF_CASE(PTRACE_SETREGS);
        DEF_CASE(PTRACE_GETEVENTMSG);
        DEF_CASE(PTRACE_GETSIGINFO);
        DEF_CASE(PTRACE_SETSIGINFO);
        DEF_CASE(PROCESS_VM_READV);
        DEF_CASE(PROCESS_VM_WRITEV);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSyscall
-----------------------------------------------------------------------------*/
const char* getTextualSyscall(long int syscallnum)
{
    const char* result = "sys_unknown";

    if (syscallnum < 0)
        result = "EXIT";
    else if (syscallnum < MAX_CALLS)
        result = mvee_syscall_string_table[syscallnum];
    else
    {
        // fake syscall numbers defined by monitor
        switch (syscallnum)
        {
            DEF_CASE(NO_CALL);
            DEF_CASE(MVEE_RDTSC_FAKE_SYSCALL);
            DEF_CASE(MVEE_GET_MASTERTHREAD_ID);
            DEF_CASE(MVEE_GET_SHARED_BUFFER);
            DEF_CASE(MVEE_FLUSH_SHARED_BUFFER);
            DEF_CASE(MVEE_SET_INFINITE_LOOP_PTR);
            DEF_CASE(MVEE_TOGGLESYNC);
            DEF_CASE(MVEE_SET_SHARED_BUFFER_POS_PTR);
            DEF_CASE(MVEE_RUNS_UNDER_MVEE_CONTROL);
            DEF_CASE(MVEE_GET_THREAD_NUM);
            DEF_CASE(MVEE_RESOLVE_SYMBOL);
            DEF_CASE(MVEE_SET_SYNC_PRIMITIVES_PTR);
            DEF_CASE(MVEE_ALL_HEAPS_ALIGNED);
            DEF_CASE(MVEE_INVOKE_LD);
			DEF_CASE(MVEE_IPMON_INVOKE);
			DEF_CASE(MVEE_GET_VIRTUALIZED_ARGV0);
			DEF_CASE(MVEE_ENABLE_XCHECKS);
			DEF_CASE(MVEE_GET_LEADER_SHM_TAG);
			DEF_CASE(MVEE_RESET_ATFORK);
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketCall
-----------------------------------------------------------------------------*/
const char* getTextualSocketCall(long int sockcallnum)
{
    const char* result = "UNKNOWN";

    switch(sockcallnum)
    {
        DEF_CASE(SYS_SOCKET);
        DEF_CASE(SYS_BIND);
        DEF_CASE(SYS_CONNECT);
        DEF_CASE(SYS_LISTEN);
        DEF_CASE(SYS_ACCEPT);
        DEF_CASE(SYS_GETSOCKNAME);
        DEF_CASE(SYS_GETPEERNAME);
        DEF_CASE(SYS_SOCKETPAIR);
        DEF_CASE(SYS_SEND);
        DEF_CASE(SYS_SENDTO);
        DEF_CASE(SYS_RECV);
        DEF_CASE(SYS_RECVFROM);
        DEF_CASE(SYS_SHUTDOWN);
        DEF_CASE(SYS_SETSOCKOPT);
        DEF_CASE(SYS_GETSOCKOPT);
        DEF_CASE(SYS_SENDMSG);
        DEF_CASE(SYS_RECVMSG);
        DEF_CASE(SYS_ACCEPT4);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketFamily
-----------------------------------------------------------------------------*/
const char* getTextualSocketFamily(long int family)
{
    const char* result = "UNKNOWN";

    switch(family)
    {
        DEF_CASE(AF_UNSPEC);
        DEF_CASE(AF_LOCAL);
        //DEF_CASE(AF_UNIX);
        //DEF_CASE(AF_FILE);
        DEF_CASE(AF_INET);
        DEF_CASE(AF_AX25);
        DEF_CASE(AF_IPX);
        DEF_CASE(AF_APPLETALK);
        DEF_CASE(AF_NETROM);
        DEF_CASE(AF_BRIDGE);
        DEF_CASE(AF_ATMPVC);
        DEF_CASE(AF_X25);
        DEF_CASE(AF_INET6);
        DEF_CASE(AF_ROSE);
        DEF_CASE(AF_DECnet);
        DEF_CASE(AF_NETBEUI);
        DEF_CASE(AF_SECURITY);
        DEF_CASE(AF_KEY);
        DEF_CASE(AF_NETLINK);
        //DEF_CASE(AF_ROUTE);
        DEF_CASE(AF_PACKET);
        DEF_CASE(AF_ASH);
        DEF_CASE(AF_ECONET);
        DEF_CASE(AF_ATMSVC);
        DEF_CASE(AF_RDS);
        DEF_CASE(AF_SNA);
        DEF_CASE(AF_IRDA);
        DEF_CASE(AF_PPPOX);
        DEF_CASE(AF_WANPIPE);
        DEF_CASE(AF_LLC);
        DEF_CASE(AF_CAN);
        DEF_CASE(AF_TIPC);
        DEF_CASE(AF_BLUETOOTH);
        DEF_CASE(AF_IUCV);
        DEF_CASE(AF_RXRPC);
        DEF_CASE(AF_ISDN);
        DEF_CASE(AF_PHONET);
        DEF_CASE(AF_IEEE802154);
        DEF_CASE(AF_CAIF);
        DEF_CASE(AF_ALG);
        DEF_CASE(AF_NFC);
        DEF_CASE(AF_VSOCK);
        DEF_CASE(AF_MAX);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketProtocol
-----------------------------------------------------------------------------*/
const char* getTextualSocketProtocol(long int proto)
{
    const char* result = "UNKNOWN";

    switch(proto)
    {
        DEF_CASE(PF_UNSPEC);
        DEF_CASE(PF_LOCAL);
        DEF_CASE(PF_INET);
        DEF_CASE(PF_AX25);
        DEF_CASE(PF_IPX);
        DEF_CASE(PF_APPLETALK);
        DEF_CASE(PF_NETROM);
        DEF_CASE(PF_BRIDGE);
        DEF_CASE(PF_ATMPVC);
        DEF_CASE(PF_X25);
        DEF_CASE(PF_INET6);
        DEF_CASE(PF_ROSE);
        DEF_CASE(PF_DECnet);
        DEF_CASE(PF_NETBEUI);
        DEF_CASE(PF_SECURITY);
        DEF_CASE(PF_KEY);
        DEF_CASE(PF_NETLINK);
        DEF_CASE(PF_PACKET);
        DEF_CASE(PF_ASH);
        DEF_CASE(PF_ECONET);
        DEF_CASE(PF_ATMSVC);
        DEF_CASE(PF_RDS);
        DEF_CASE(PF_SNA);
        DEF_CASE(PF_IRDA);
        DEF_CASE(PF_PPPOX);
        DEF_CASE(PF_WANPIPE);
        DEF_CASE(PF_LLC);
        DEF_CASE(PF_CAN);
        DEF_CASE(PF_TIPC);
        DEF_CASE(PF_BLUETOOTH);
        DEF_CASE(PF_IUCV);
        DEF_CASE(PF_RXRPC);
        DEF_CASE(PF_ISDN);
        DEF_CASE(PF_PHONET);
        DEF_CASE(PF_IEEE802154);
        DEF_CASE(PF_CAIF);
        DEF_CASE(PF_ALG);
        DEF_CASE(PF_NFC);
        DEF_CASE(PF_VSOCK);
        DEF_CASE(PF_MAX);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketProtocol
-----------------------------------------------------------------------------*/
const char* getTextualSocketShutdownHow(long int how)
{
    const char* result = "UNKNOWN";

    switch(how)
    {
        DEF_CASE(SHUT_WR);
        DEF_CASE(SHUT_RDWR);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSEGVCode
-----------------------------------------------------------------------------*/
const char* getTextualSEGVCode(int code)
{
    const char* result = "(unknown)";

    switch (code)
    {
        DEF_CASE(SI_USER);
        DEF_CASE(SI_KERNEL);
        DEF_CASE(SI_QUEUE);
        DEF_CASE(SI_TIMER);
        DEF_CASE(SI_MESGQ);
        DEF_CASE(SI_ASYNCIO);
        DEF_CASE(SI_SIGIO);
        DEF_CASE(SI_TKILL);
        DEF_CASE(SEGV_MAPERR);
        DEF_CASE(SEGV_ACCERR);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFcntlCmd
-----------------------------------------------------------------------------*/
const char* getTextualFcntlCmd(int cmd)
{
    const char* result = "(unknown)";

    switch (cmd)
    {
        DEF_CASE(F_DUPFD);
        DEF_CASE(F_GETFD);
        DEF_CASE(F_SETFD);
        DEF_CASE(F_GETFL);
        DEF_CASE(F_SETFL);
        DEF_CASE(F_GETLK);
        DEF_CASE(F_SETLK);
        DEF_CASE(F_SETLKW);
        //DEF_CASE(F_GETLK64);
        //DEF_CASE(F_SETLK64);
        //DEF_CASE(F_SETLKW64);
        DEF_CASE(F_SETOWN);
        DEF_CASE(F_GETOWN);
        DEF_CASE(F_SETSIG);
        DEF_CASE(F_GETSIG);
        DEF_CASE(F_SETLEASE);
        DEF_CASE(F_GETLEASE);
        DEF_CASE(F_NOTIFY);
    }

    return result;
}

/*-----------------------------------------------------------------------------
  getTextualFlockType
-----------------------------------------------------------------------------*/
const char* getTextualFlockType(unsigned int type)
{
    const char* result = "(unknown)";

    switch (type)
    {
        DEF_CASE(LOCK_SH);
        DEF_CASE(LOCK_EX);
        DEF_CASE(LOCK_UN);
    }

    return result;
}


/*-----------------------------------------------------------------------------
    getTextualKernelError
-----------------------------------------------------------------------------*/
const char* getTextualKernelError (int err)
{
    const char* result = "(unknown)";

    switch (err)
    {
        DEF_CASE(ERESTARTSYS);
        DEF_CASE(ERESTARTNOINTR);
        DEF_CASE(ERESTARTNOHAND);
        DEF_CASE(ENOIOCTLCMD);
        DEF_CASE(ERESTART_RESTARTBLOCK);
        DEF_CASE(EBADHANDLE);
        DEF_CASE(ENOTSYNC);
        DEF_CASE(EBADCOOKIE);
        DEF_CASE(ENOTSUPP);
        DEF_CASE(ETOOSMALL);
        DEF_CASE(ESERVERFAULT);
        DEF_CASE(EBADTYPE);
        DEF_CASE(EJUKEBOX);
        DEF_CASE(EIOCBQUEUED);
        DEF_CASE(EIOCBRETRY);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualProcmaskRequest
-----------------------------------------------------------------------------*/
const char* getTextualProcmaskRequest(int how)
{
    const char* result = "(unknown)";

    switch(how)
    {
        DEF_CASE(SIG_BLOCK);
        DEF_CASE(SIG_UNBLOCK);
        DEF_CASE(SIG_SETMASK);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFutexOp
-----------------------------------------------------------------------------*/
const char* getTextualFutexOp(int op)
{
    const char* result = "(unknown)";

    switch(op)
    {
        DEF_CASE(FUTEX_WAIT);
        DEF_CASE(FUTEX_WAKE);
        DEF_CASE(FUTEX_FD);
        DEF_CASE(FUTEX_REQUEUE);
        DEF_CASE(FUTEX_CMP_REQUEUE);
        DEF_CASE(FUTEX_WAKE_OP);
        DEF_CASE(FUTEX_LOCK_PI);
        DEF_CASE(FUTEX_UNLOCK_PI);
        DEF_CASE(FUTEX_TRYLOCK_PI);
        DEF_CASE(FUTEX_WAIT_BITSET);
        DEF_CASE(FUTEX_WAKE_BITSET);
        DEF_CASE(FUTEX_WAIT_REQUEUE_PI);
        DEF_CASE(FUTEX_CMP_REQUEUE_PI);
        DEF_CASE(FUTEX_WAIT_PRIVATE);
        DEF_CASE(FUTEX_WAKE_PRIVATE);
        DEF_CASE(FUTEX_REQUEUE_PRIVATE);
        DEF_CASE(FUTEX_CMP_REQUEUE_PRIVATE);
        DEF_CASE(FUTEX_WAKE_OP_PRIVATE);
        DEF_CASE(FUTEX_LOCK_PI_PRIVATE);
        DEF_CASE(FUTEX_UNLOCK_PI_PRIVATE);
        DEF_CASE(FUTEX_TRYLOCK_PI_PRIVATE);
        DEF_CASE(FUTEX_WAIT_BITSET_PRIVATE);
        DEF_CASE(FUTEX_WAKE_BITSET_PRIVATE);
        DEF_CASE(FUTEX_WAIT_REQUEUE_PI_PRIVATE);
        DEF_CASE(FUTEX_CMP_REQUEUE_PI_PRIVATE);
        DEF_CASE(MVEE_FUTEX_WAIT_TID);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualAtomicType
-----------------------------------------------------------------------------*/
const char* getTextualAtomicType(int atomic_type)
{
    const char* result = "(unknown)";

#define DEF_EXTENDED_ATOMIC(a)			\
    case a + __MVEE_BASE_ATOMICS_MAX__: \
        result = #a;                    \
        break;

    switch(atomic_type)
    {
        DEF_CASE(ATOMIC_FORCED_READ);
        DEF_CASE(ATOMIC_LOAD);
        DEF_CASE(ATOMIC_LOAD_MAX);
        DEF_CASE(CATOMIC_AND);
        DEF_CASE(CATOMIC_OR);
        DEF_CASE(CATOMIC_EXCHANGE_AND_ADD);
        DEF_CASE(CATOMIC_ADD);
        DEF_CASE(CATOMIC_INCREMENT);
        DEF_CASE(CATOMIC_DECREMENT);
        DEF_CASE(CATOMIC_MAX);
        DEF_CASE(ATOMIC_COMPARE_AND_EXCHANGE_VAL);
        DEF_CASE(ATOMIC_COMPARE_AND_EXCHANGE_BOOL);
        DEF_CASE(ATOMIC_EXCHANGE);
        DEF_CASE(ATOMIC_EXCHANGE_AND_ADD);
        DEF_CASE(ATOMIC_INCREMENT_AND_TEST);
        DEF_CASE(ATOMIC_DECREMENT_AND_TEST);
		DEF_CASE(ATOMIC_ADD_NEGATIVE);
        DEF_CASE(ATOMIC_ADD_ZERO);
        DEF_CASE(ATOMIC_ADD);
		DEF_CASE(ATOMIC_OR);
		DEF_CASE(ATOMIC_OR_VAL);
        DEF_CASE(ATOMIC_INCREMENT);
        DEF_CASE(ATOMIC_DECREMENT);
        DEF_CASE(ATOMIC_BIT_TEST_SET);
        DEF_CASE(ATOMIC_BIT_SET);
        DEF_CASE(ATOMIC_AND);
		DEF_CASE(ATOMIC_AND_VAL);
        DEF_CASE(ATOMIC_STORE);
		DEF_CASE(ATOMIC_MIN);
        DEF_CASE(ATOMIC_MAX);
        DEF_CASE(ATOMIC_DECREMENT_IF_POSITIVE);
		DEF_CASE(ATOMIC_FETCH_ADD);
		DEF_CASE(ATOMIC_FETCH_AND);
		DEF_CASE(ATOMIC_FETCH_OR);
		DEF_CASE(ATOMIC_FETCH_XOR);
        DEF_CASE(__THREAD_ATOMIC_CMPXCHG_VAL);
        DEF_CASE(__THREAD_ATOMIC_AND);
        DEF_CASE(__THREAD_ATOMIC_BIT_SET);
        DEF_CASE(___UNKNOWN_LOCK_TYPE___);

        DEF_EXTENDED_ATOMIC(mvee_atomic_load_n);
        DEF_EXTENDED_ATOMIC(mvee_atomic_load);
        DEF_EXTENDED_ATOMIC(mvee_atomic_store_n);
        DEF_EXTENDED_ATOMIC(mvee_atomic_store);
        DEF_EXTENDED_ATOMIC(mvee_atomic_exchange_n);
        DEF_EXTENDED_ATOMIC(mvee_atomic_exchange);
        DEF_EXTENDED_ATOMIC(mvee_atomic_compare_exchange_n);
        DEF_EXTENDED_ATOMIC(mvee_atomic_compare_exchange);
        DEF_EXTENDED_ATOMIC(mvee_atomic_add_fetch);
        DEF_EXTENDED_ATOMIC(mvee_atomic_sub_fetch);
        DEF_EXTENDED_ATOMIC(mvee_atomic_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_atomic_xor_fetch);
        DEF_EXTENDED_ATOMIC(mvee_atomic_or_fetch);
        DEF_EXTENDED_ATOMIC(mvee_atomic_nand_fetch);
        DEF_EXTENDED_ATOMIC(mvee_atomic_fetch_add);
        DEF_EXTENDED_ATOMIC(mvee_atomic_fetch_sub);
        DEF_EXTENDED_ATOMIC(mvee_atomic_fetch_and);
        DEF_EXTENDED_ATOMIC(mvee_atomic_fetch_xor);
        DEF_EXTENDED_ATOMIC(mvee_atomic_fetch_or);
        DEF_EXTENDED_ATOMIC(mvee_atomic_fetch_nand);
        DEF_EXTENDED_ATOMIC(mvee_atomic_test_and_set);
        DEF_EXTENDED_ATOMIC(mvee_atomic_clear);
        DEF_EXTENDED_ATOMIC(mvee_atomic_always_lock_free);
        DEF_EXTENDED_ATOMIC(mvee_atomic_is_lock_free);
        DEF_EXTENDED_ATOMIC(mvee_sync_fetch_and_add);
        DEF_EXTENDED_ATOMIC(mvee_sync_fetch_and_sub);
        DEF_EXTENDED_ATOMIC(mvee_sync_fetch_and_or);
        DEF_EXTENDED_ATOMIC(mvee_sync_fetch_and_and);
        DEF_EXTENDED_ATOMIC(mvee_sync_fetch_and_xor);
        DEF_EXTENDED_ATOMIC(mvee_sync_fetch_and_nand);
        DEF_EXTENDED_ATOMIC(mvee_sync_add_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_sync_sub_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_sync_or_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_sync_and_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_sync_xor_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_sync_nand_and_fetch);
        DEF_EXTENDED_ATOMIC(mvee_sync_bool_compare_and_swap);
        DEF_EXTENDED_ATOMIC(mvee_sync_val_compare_and_swap);
        DEF_EXTENDED_ATOMIC(mvee_sync_lock_test_and_set);
        DEF_EXTENDED_ATOMIC(mvee_sync_lock_release);
        DEF_EXTENDED_ATOMIC(mvee_atomic_ops_max);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualBreakpointType
-----------------------------------------------------------------------------*/
const char* getTextualBreakpointType(int bp_type)
{
    const char* result = "(unknown)";

    switch(bp_type)
    {
        DEF_CASE(MVEE_BP_EXEC_ONLY);
        DEF_CASE(MVEE_BP_WRITE_ONLY);
        DEF_CASE(MVEE_BP_READ_WRITE);
        DEF_CASE(MVEE_BP_READ_WRITE_NO_FETCH);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualBufferType
-----------------------------------------------------------------------------*/
const char* getTextualBufferType(int buffer_type)
{
    const char* result = "(unknown)";

    switch(buffer_type)
    {
        DEF_CASE(MVEE_PTHREAD_LOCK_BUFFER);
        DEF_CASE(MVEE_GTK_HASH_BUFFER);
        DEF_CASE(MVEE_ORBIT_REQUEST_BUFFER);
        DEF_CASE(MVEE_LIBC_LOCK_BUFFER);
        DEF_CASE(MVEE_GLIB_HASH_BUFFER);
        DEF_CASE(MVEE_PANGO_HASH_BUFFER);
        DEF_CASE(MVEE_REALLOC_BUFFER);
        DEF_CASE(MVEE_UNO_HASH_BUFFER);
        DEF_CASE(MVEE_RAND_BUFFER);
//		DEF_CASE(MVEE_LIBC_LOCK_EIP_BUFFER);
        DEF_CASE(MVEE_JDK_ATOMIC_BUFFER);
        DEF_CASE(MVEE_LIBC_MALLOC_DEBUG_BUFFER);
        DEF_CASE(MVEE_GCCLIBS_BUFFER);
        DEF_CASE(MVEE_LIBC_ATOMIC_BUFFER);
        DEF_CASE(MVEE_UTCB_BUFFER);
        DEF_CASE(MVEE_LIBC_LOCK_BUFFER_PARTIAL);
        DEF_CASE(MVEE_LIBC_ATOMIC_BUFFER_HIDDEN);
		DEF_CASE(MVEE_LIBC_HIDDEN_BUFFER_ARRAY);
		DEF_CASE(MVEE_UTCB_REG_FILE_MAP);
        DEF_CASE(MVEE_IPMON_BUFFER);
        DEF_CASE(MVEE_IPMON_REG_FILE_MAP);
		DEF_CASE(MVEE_RING_BUFFER);
		DEF_CASE(MVEE_SHM_BUFFER);
        DEF_CASE(MVEE_LIBC_VARIANTWIDE_ATOMIC_BUFFER);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualRlimitType
-----------------------------------------------------------------------------*/
const char* getTextualRlimitType(int rlimit_type)
{
    const char* result = "(unknown)";

    switch(rlimit_type)
    {
        DEF_CASE(RLIMIT_AS);
        DEF_CASE(RLIMIT_CORE);
        DEF_CASE(RLIMIT_CPU);
        DEF_CASE(RLIMIT_DATA);
        DEF_CASE(RLIMIT_FSIZE);
        DEF_CASE(RLIMIT_LOCKS);
        DEF_CASE(RLIMIT_MEMLOCK);
        DEF_CASE(RLIMIT_MSGQUEUE);
        DEF_CASE(RLIMIT_NICE);
        DEF_CASE(RLIMIT_NOFILE);
        DEF_CASE(RLIMIT_NPROC);
        DEF_CASE(RLIMIT_RSS);
        DEF_CASE(RLIMIT_RTPRIO);
        DEF_CASE(RLIMIT_RTTIME);
        DEF_CASE(RLIMIT_SIGPENDING);
        DEF_CASE(RLIMIT_STACK);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualAllocType
-----------------------------------------------------------------------------*/
const char* getTextualAllocType(int alloc_type)
{
    const char* result = "(unknown)";

    switch(alloc_type)
    {
        DEF_CASE(LIBC_MALLOC);
        DEF_CASE(LIBC_FREE);
        DEF_CASE(LIBC_REALLOC);
        DEF_CASE(LIBC_MEMALIGN);
        DEF_CASE(LIBC_CALLOC);
        DEF_CASE(MALLOC_TRIM);
        DEF_CASE(HEAP_TRIM);
        DEF_CASE(MALLOC_CONSOLIDATE);
        DEF_CASE(ARENA_GET2);
        DEF_CASE(_INT_MALLOC);
        DEF_CASE(_INT_FREE);
        DEF_CASE(_INT_REALLOC);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualAllocResult
-----------------------------------------------------------------------------*/
const char* getTextualAllocResult(int alloc_type, int alloc_result)
{
    const char* op_result = "???";

    switch(alloc_type)
    {
        case LIBC_MALLOC:
            if (alloc_result == 0)
                op_result = "Malloc failed - no suitable arena found";
            else if (alloc_result == 1)
                op_result = "Initial malloc failed - retrying from other arena";
            else if (alloc_result == 2)
                op_result = "Initial malloc success";
            else if (alloc_result == 3)
                op_result = "Malloc success";
            break;
        case LIBC_FREE:
            if (alloc_result == 0)
                op_result = "Freeing mmaped chunk";
            else if (alloc_result == 1)
                op_result = "Freeing regular chunk";
            break;
        case LIBC_REALLOC:
            if (alloc_result == 0)
                op_result = "Realloc success - mmapped chunk was sufficiently large";
            else if (alloc_result == 1)
                op_result = "Realloc failed - couldn't mmap new block";
            else if (alloc_result == 2)
                op_result = "Realloc success - mmapped new block";
            else if (alloc_result == 3)
                op_result = "Realloc - attempting realloc within same arena";
            else if (alloc_result == 4)
                op_result = "Initial realloc failed - attempting to realloc in other arena";
            else if (alloc_result == 5)
                op_result = "Realloc result";
            break;
        case LIBC_MEMALIGN:
            if (alloc_result == 0)
                op_result = "Align request";
            else if (alloc_result == 1)
                op_result = "Align result";
            break;
        case LIBC_CALLOC:
            if (alloc_result == 0)
                op_result = "Calloc request";
            else if (alloc_result == 1)
                op_result = "Couldn't find arena for initial calloc";
            else if (alloc_result == 2)
                op_result = "Initial calloc failed - retrying from other arena";
            else if (alloc_result == 3)
                op_result = "Calloc success - mmapped chunk";
            else if (alloc_result == 4)
                op_result = "Calloc result";
            break;
        case MALLOC_TRIM:
            if (alloc_result == 0)
                op_result = "Trimmed secondary arena";
            else if (alloc_result == 1)
                op_result = "Trimmed main arena";
            break;
        case MALLOC_CONSOLIDATE:
            if (alloc_result == 0)
                op_result = "Consolidation complete. size = nr of chunks consolidated";
            break;
        case ARENA_GET2:
            if (alloc_result == 0)
                op_result = "arena_get request - found a free arena";
            else if (alloc_result == 1)
                op_result = "arena_get request - didn't find a free arena";
            else if (alloc_result == 2)
                op_result = "adjusted narenas_limit";
            else if (alloc_result == 3)
                op_result = "Initialized new arena";
            else if (alloc_result == 4)
                op_result = "Reused old arena";
            break;
        case _INT_MALLOC:
            if (alloc_result == 0)
                op_result = "Internal Malloc - normalized size";
            else if (alloc_result == 1)
                op_result = "Internal Malloc - fastbin possible";
            else if (alloc_result == 2)
                op_result = "Internal Malloc - found victim in fastbin";
            else if (alloc_result == 3)
                op_result = "Internal Malloc - didn't find victim in fastbin";
            else if (alloc_result == 4)
                op_result = "Internal Malloc - smallbin possible";
            else if (alloc_result == 5)
                op_result = "Internal Malloc - no victim found - initiating malloc consolidation";
            else if (alloc_result == 6)
                op_result = "Internal Malloc - victim found in smallbin";
            else if (alloc_result == 7)
                op_result = "Internal Malloc - need to look in largebins";
            else if (alloc_result == 8)
                op_result = "Internal Malloc - arena still has fast chunks - initiating malloc consolidation";
            else if (alloc_result == 9)
                op_result = "Internal Malloc - found unsorted chunk in smallbin range";
            else if (alloc_result == 10)
                op_result = "Internal Malloc - found exact fit in unsorted chunk list";
            else if (alloc_result == 11)
                op_result = "Internal Malloc - no fit found in unsorted chunk list after MAX_ITERS iterations";
            else if (alloc_result == 12)
                op_result = "Internal Malloc - post-consolidation - finding smallest fit in largebin";
            else if (alloc_result == 13)
                op_result = "Internal Malloc - post-consolidation - found smallest fit";
            else if (alloc_result == 14)
                op_result = "Internal Malloc - post-consolidation - iterating through all bins";
            else if (alloc_result == 15)
                op_result = "Internal Malloc - post-consolidation - found smallest fit";
            else if (alloc_result == 16)
                op_result = "Internal Malloc - using top chunk";
            else if (alloc_result == 17)
                op_result = "Internal Malloc - consolidating fastchunks and retrying";
            else if (alloc_result == 18)
                op_result = "Internal Malloc - using sysmalloc";
            else if (alloc_result == 19)
                op_result = "Internal Malloc - fwd";
            else if (alloc_result == 20)
                op_result = "Internal Malloc - bck";

            break;
        case _INT_FREE:
            if (alloc_result == 0)
                op_result = "Internal Free - inserting in fastbins";
            else if (alloc_result == 1)
                op_result = "Internal Free - fastbin index calculated";
            else if (alloc_result == 2)
                op_result = "Internal Free - non-fastbin insertion + consolidation";
            else if (alloc_result == 3)
                op_result = "Internal Free - consolidating backwards";
            else if (alloc_result == 4)
                op_result = "Internal Free - consolidating into top";
            else if (alloc_result == 5)
                op_result = "Internal Free - fastbin consolidation threshold exceeded - initiating consolidation & trim";
            else if (alloc_result == 6)
                op_result = "Internal Free - releasing mmapped chunk";
            break;

        case HEAP_TRIM:
            if (alloc_result == 0)
                op_result = "heap trim - entrance";
            else if (alloc_result == 1)
                op_result = "heap trim - iteration for top chunk";
            else if (alloc_result == 2)
                op_result = "heap trim - can't delete heap";
            else if (alloc_result == 3)
                op_result = "heap trim - extra < pagesz";
            else if (alloc_result == 4)
                op_result = "heap trim - shrink failed";
            else if (alloc_result == 5)
                op_result = "heap trim - trim succeeded";
            break;
        case _INT_REALLOC:
            if (alloc_result == 0)
                op_result = "internal realloc - expanding into top";
            else if (alloc_result == 1)
                op_result = "internal realloc - expanding into next chunk";
            else if (alloc_result == 2)
                op_result = "internal realloc - alloc/copy/free";
            else if (alloc_result == 3)
                op_result = "internal realloc - realloced into next";
            else if (alloc_result == 4)
                op_result = "internal realloc - realloced into new chunk";
            else if (alloc_result == 5)
                op_result = "internal realloc - cleanup small chunk";
            else if (alloc_result == 6)
                op_result = "internal realloc - cleanup big chunk";
            break;
    }

    return op_result;
}

/*-----------------------------------------------------------------------------
    getTextualDWARFConstant
-----------------------------------------------------------------------------*/
const char* getTextualDWARFConstant(int constant)
{
    const char* result = "(unknown)";

    switch(constant)
    {
        DEF_CASE(DW_EXPR_OFFSET);
        DEF_CASE(DW_EXPR_VAL_OFFSET);
        DEF_CASE(DW_EXPR_EXPRESSION);
        DEF_CASE(DW_EXPR_VAL_EXPRESSION);
        DEF_CASE(DW_FRAME_SAME_VAL);
        DEF_CASE(DW_FRAME_UNDEFINED_VAL);
        DEF_CASE(DW_FRAME_CFA_COL3);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualDWARFOp
-----------------------------------------------------------------------------*/
const char* getTextualDWARFOp (int op)
{
    const char* result = "(unknown)";

    switch(op)
    {
        DEF_CASE(DW_OP_addr);
        DEF_CASE(DW_OP_deref);
        DEF_CASE(DW_OP_const1u);
        DEF_CASE(DW_OP_const1s);
        DEF_CASE(DW_OP_const2u);
        DEF_CASE(DW_OP_const2s);
        DEF_CASE(DW_OP_const4u);
        DEF_CASE(DW_OP_const4s);
        DEF_CASE(DW_OP_const8u);
        DEF_CASE(DW_OP_const8s);
        DEF_CASE(DW_OP_constu);
        DEF_CASE(DW_OP_consts);
        DEF_CASE(DW_OP_dup);
        DEF_CASE(DW_OP_drop);
        DEF_CASE(DW_OP_over);
        DEF_CASE(DW_OP_pick);
        DEF_CASE(DW_OP_swap);
        DEF_CASE(DW_OP_rot);
        DEF_CASE(DW_OP_xderef);
        DEF_CASE(DW_OP_abs);
        DEF_CASE(DW_OP_and);
        DEF_CASE(DW_OP_div);
        DEF_CASE(DW_OP_minus);
        DEF_CASE(DW_OP_mod);
        DEF_CASE(DW_OP_mul);
        DEF_CASE(DW_OP_neg);
        DEF_CASE(DW_OP_not);
        DEF_CASE(DW_OP_or);
        DEF_CASE(DW_OP_plus);
        DEF_CASE(DW_OP_plus_uconst);
        DEF_CASE(DW_OP_shl);
        DEF_CASE(DW_OP_shr);
        DEF_CASE(DW_OP_shra);
        DEF_CASE(DW_OP_xor);
        DEF_CASE(DW_OP_bra);
        DEF_CASE(DW_OP_eq);
        DEF_CASE(DW_OP_ge);
        DEF_CASE(DW_OP_gt);
        DEF_CASE(DW_OP_le);
        DEF_CASE(DW_OP_lt);
        DEF_CASE(DW_OP_ne);
        DEF_CASE(DW_OP_skip);
        DEF_CASE(DW_OP_lit0);
        DEF_CASE(DW_OP_lit1);
        DEF_CASE(DW_OP_lit2);
        DEF_CASE(DW_OP_lit3);
        DEF_CASE(DW_OP_lit4);
        DEF_CASE(DW_OP_lit5);
        DEF_CASE(DW_OP_lit6);
        DEF_CASE(DW_OP_lit7);
        DEF_CASE(DW_OP_lit8);
        DEF_CASE(DW_OP_lit9);
        DEF_CASE(DW_OP_lit10);
        DEF_CASE(DW_OP_lit11);
        DEF_CASE(DW_OP_lit12);
        DEF_CASE(DW_OP_lit13);
        DEF_CASE(DW_OP_lit14);
        DEF_CASE(DW_OP_lit15);
        DEF_CASE(DW_OP_lit16);
        DEF_CASE(DW_OP_lit17);
        DEF_CASE(DW_OP_lit18);
        DEF_CASE(DW_OP_lit19);
        DEF_CASE(DW_OP_lit20);
        DEF_CASE(DW_OP_lit21);
        DEF_CASE(DW_OP_lit22);
        DEF_CASE(DW_OP_lit23);
        DEF_CASE(DW_OP_lit24);
        DEF_CASE(DW_OP_lit25);
        DEF_CASE(DW_OP_lit26);
        DEF_CASE(DW_OP_lit27);
        DEF_CASE(DW_OP_lit28);
        DEF_CASE(DW_OP_lit29);
        DEF_CASE(DW_OP_lit30);
        DEF_CASE(DW_OP_lit31);
        DEF_CASE(DW_OP_reg0);
        DEF_CASE(DW_OP_reg1);
        DEF_CASE(DW_OP_reg2);
        DEF_CASE(DW_OP_reg3);
        DEF_CASE(DW_OP_reg4);
        DEF_CASE(DW_OP_reg5);
        DEF_CASE(DW_OP_reg6);
        DEF_CASE(DW_OP_reg7);
        DEF_CASE(DW_OP_reg8);
        DEF_CASE(DW_OP_reg9);
        DEF_CASE(DW_OP_reg10);
        DEF_CASE(DW_OP_reg11);
        DEF_CASE(DW_OP_reg12);
        DEF_CASE(DW_OP_reg13);
        DEF_CASE(DW_OP_reg14);
        DEF_CASE(DW_OP_reg15);
        DEF_CASE(DW_OP_reg16);
        DEF_CASE(DW_OP_reg17);
        DEF_CASE(DW_OP_reg18);
        DEF_CASE(DW_OP_reg19);
        DEF_CASE(DW_OP_reg20);
        DEF_CASE(DW_OP_reg21);
        DEF_CASE(DW_OP_reg22);
        DEF_CASE(DW_OP_reg23);
        DEF_CASE(DW_OP_reg24);
        DEF_CASE(DW_OP_reg25);
        DEF_CASE(DW_OP_reg26);
        DEF_CASE(DW_OP_reg27);
        DEF_CASE(DW_OP_reg28);
        DEF_CASE(DW_OP_reg29);
        DEF_CASE(DW_OP_reg30);
        DEF_CASE(DW_OP_reg31);
        DEF_CASE(DW_OP_breg0);
        DEF_CASE(DW_OP_breg1);
        DEF_CASE(DW_OP_breg2);
        DEF_CASE(DW_OP_breg3);
        DEF_CASE(DW_OP_breg4);
        DEF_CASE(DW_OP_breg5);
        DEF_CASE(DW_OP_breg6);
        DEF_CASE(DW_OP_breg7);
        DEF_CASE(DW_OP_breg8);
        DEF_CASE(DW_OP_breg9);
        DEF_CASE(DW_OP_breg10);
        DEF_CASE(DW_OP_breg11);
        DEF_CASE(DW_OP_breg12);
        DEF_CASE(DW_OP_breg13);
        DEF_CASE(DW_OP_breg14);
        DEF_CASE(DW_OP_breg15);
        DEF_CASE(DW_OP_breg16);
        DEF_CASE(DW_OP_breg17);
        DEF_CASE(DW_OP_breg18);
        DEF_CASE(DW_OP_breg19);
        DEF_CASE(DW_OP_breg20);
        DEF_CASE(DW_OP_breg21);
        DEF_CASE(DW_OP_breg22);
        DEF_CASE(DW_OP_breg23);
        DEF_CASE(DW_OP_breg24);
        DEF_CASE(DW_OP_breg25);
        DEF_CASE(DW_OP_breg26);
        DEF_CASE(DW_OP_breg27);
        DEF_CASE(DW_OP_breg28);
        DEF_CASE(DW_OP_breg29);
        DEF_CASE(DW_OP_breg30);
        DEF_CASE(DW_OP_breg31);
        DEF_CASE(DW_OP_regx);
        DEF_CASE(DW_OP_fbreg);
        DEF_CASE(DW_OP_bregx);
        DEF_CASE(DW_OP_piece);
        DEF_CASE(DW_OP_deref_size);
        DEF_CASE(DW_OP_xderef_size);
        DEF_CASE(DW_OP_nop);
        DEF_CASE(DW_OP_push_object_address);
        DEF_CASE(DW_OP_call2);
        DEF_CASE(DW_OP_call4);
        DEF_CASE(DW_OP_call_ref);
        DEF_CASE(DW_OP_form_tls_address);
        DEF_CASE(DW_OP_call_frame_cfa);
        DEF_CASE(DW_OP_bit_piece);
        DEF_CASE(DW_OP_implicit_value);
        DEF_CASE(DW_OP_stack_value);
        DEF_CASE(DW_OP_GNU_push_tls_address);
        //DEF_CASE(DW_OP_lo_user);
        DEF_CASE(DW_OP_GNU_uninit);
        DEF_CASE(DW_OP_GNU_encoded_addr);
        DEF_CASE(DW_OP_GNU_implicit_pointer);
        DEF_CASE(DW_OP_GNU_entry_value);
        //DEF_CASE(DW_OP_HP_unknown);
        DEF_CASE(DW_OP_HP_is_value);
        DEF_CASE(DW_OP_HP_fltconst4);
        DEF_CASE(DW_OP_HP_fltconst8);
        DEF_CASE(DW_OP_HP_mod_range);
        DEF_CASE(DW_OP_HP_unmod_range);
        DEF_CASE(DW_OP_HP_tls);
        DEF_CASE(DW_OP_INTEL_bit_piece);
        //DEF_CASE(DW_OP_APPLE_uninit);
        DEF_CASE(DW_OP_PGI_omp_thread_num);
        DEF_CASE(DW_OP_hi_user);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualEpollFlags
-----------------------------------------------------------------------------*/
const char* getTextualEpollFlags(int flags)
{
    if (flags == EPOLL_CLOEXEC)
        return "EPOLL_CLOEXEC";
    else
        return "";
}

/*-----------------------------------------------------------------------------
    getTextualEpollOp
-----------------------------------------------------------------------------*/
const char* getTextualEpollOp(int op)
{
    const char* result = "(unknown)";

    switch(op)
    {
        DEF_CASE(EPOLL_CTL_ADD);
        DEF_CASE(EPOLL_CTL_MOD);
        DEF_CASE(EPOLL_CTL_DEL);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualEventFdFlags
-----------------------------------------------------------------------------*/
const char* getTextualEventFdFlags(int flags)
{
    const char* result = "(unknown)";

    switch(flags)
    {
        DEF_CASE(EFD_CLOEXEC);
        DEF_CASE(EFD_NONBLOCK);
        DEF_CASE(EFD_SEMAPHORE);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualXattrFlags
-----------------------------------------------------------------------------*/
const char* getTextualXattrFlags(int flags)
{
    const char* result = "(unknown)";

    switch(flags)
    {
        DEF_CASE(XATTR_CREATE);
        DEF_CASE(XATTR_REPLACE);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualTimerType
-----------------------------------------------------------------------------*/
const char* getTextualTimerType(int type)
{
    const char* result = "(unknown)";

    switch(type)
    {
        DEF_CASE(CLOCK_REALTIME);
        DEF_CASE(CLOCK_MONOTONIC);
		DEF_CASE(CLOCK_REALTIME_COARSE);
		DEF_CASE(CLOCK_MONOTONIC_COARSE);
		DEF_CASE(CLOCK_MONOTONIC_RAW);
		DEF_CASE(CLOCK_BOOTTIME);
		DEF_CASE(CLOCK_PROCESS_CPUTIME_ID);
		DEF_CASE(CLOCK_THREAD_CPUTIME_ID);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSyslogAction
-----------------------------------------------------------------------------*/
const char* getTextualSyslogAction(int action)
{
    const char* result = "(unknown)";

    switch(action)
    {
        DEF_CASE(SYSLOG_ACTION_CLOSE);
        DEF_CASE(SYSLOG_ACTION_OPEN);
        DEF_CASE(SYSLOG_ACTION_READ);
        DEF_CASE(SYSLOG_ACTION_READ_ALL);
        DEF_CASE(SYSLOG_ACTION_READ_CLEAR);
        DEF_CASE(SYSLOG_ACTION_CLEAR);
        DEF_CASE(SYSLOG_ACTION_CONSOLE_OFF);
        DEF_CASE(SYSLOG_ACTION_CONSOLE_ON);
        DEF_CASE(SYSLOG_ACTION_CONSOLE_LEVEL);
        DEF_CASE(SYSLOG_ACTION_SIZE_UNREAD);
        DEF_CASE(SYSLOG_ACTION_SIZE_BUFFER);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFileType
-----------------------------------------------------------------------------*/
const char* getTextualFileType(int type)
{
    const char* result = "(unknown)";

    switch(type)
    {
		DEF_CASE(FT_UNKNOWN);
		DEF_CASE(FT_REGULAR);
		DEF_CASE(FT_PIPE_BLOCKING);
		DEF_CASE(FT_PIPE_NON_BLOCKING);
		DEF_CASE(FT_SOCKET_BLOCKING);
		DEF_CASE(FT_SOCKET_NON_BLOCKING);
		DEF_CASE(FT_POLL_BLOCKING);
		DEF_CASE(FT_POLL_NON_BLOCKING);
		DEF_CASE(FT_SPECIAL);
		DEF_CASE(FT_MEMFD);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualRAVENCall
-----------------------------------------------------------------------------*/
const char* getTextualRAVENCall(int call)
{
	const char* result = "ESC_UNKNOWN";

	switch(call)
	{
		DEF_CASE(ESC_XCHECK);
		DEF_CASE(ESC_XCHECK_VALUES_ONLY);
		DEF_CASE(ESC_FUTEX_HACK);
		DEF_CASE(ESC_ENTER_LOCK);
//		DEF_CASE(ESC_LEAVE_UNLOCK);
		DEF_CASE(ESC_LEAVE_LOCK);
		DEF_CASE(ESC_XCHECKS_OFF);
		DEF_CASE(ESC_XCHECKS_ON);
		DEF_CASE(ESC_XCHECKS_OFF_LOCAL);
		DEF_CASE(ESC_XCHECKS_ON_LOCAL);
		DEF_CASE(ESC_VARIANT_INIT_SYNC);
		DEF_CASE(ESC_VARIANT_REACTIVATE);
		DEF_CASE(ESC_ENABLE_SYSCALL_CHECKS);
		DEF_CASE(ESC_EXECVE_FAILURE);
		DEF_CASE(ESC_RINGBUFF_INIT);
		DEF_CASE(ESC_RINGBUFF_DESTROY);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualErrno
-----------------------------------------------------------------------------*/
const char* getTextualErrno(int err)
{
	const char* result = "Unknown Error";

	switch (err)
	{
		DEF_CASE(ENOIPMON);
		default:
			result = strerror(err);
			break;
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualIntervalTimerType
-----------------------------------------------------------------------------*/
const char* getTextualIntervalTimerType(int which)
{
	const char* result = "Unknown Timer Type";

	switch (which)
	{
		DEF_CASE(ITIMER_REAL);
		DEF_CASE(ITIMER_VIRTUAL);
		DEF_CASE(ITIMER_PROF);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualArchPrctl
-----------------------------------------------------------------------------*/
const char* getTextualArchPrctl(int code)
{
	const char* result = "UNKNOWN";

#ifdef MVEE_ARCH_HAS_ARCH_PRCTL
	switch (code)
	{
		DEF_CASE(ARCH_SET_FS);
		DEF_CASE(ARCH_GET_FS);
		DEF_CASE(ARCH_SET_GS);
		DEF_CASE(ARCH_GET_GS);
	}
#endif

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualRusageWho
-----------------------------------------------------------------------------*/
const char* getTextualRusageWho(int who)
{
	const char* result = "UNKNOWN";

	switch (who)
	{
		DEF_CASE(RUSAGE_SELF);
		DEF_CASE(RUSAGE_CHILDREN);
		DEF_CASE(RUSAGE_THREAD);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualQuotactlType
-----------------------------------------------------------------------------*/
const char* getTextualQuotactlType(int type)
{
	const char* result = "UNKNOWN";

	switch (type)
	{
		DEF_CASE(USRQUOTA);
		DEF_CASE(GRPQUOTA);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualQuotactlCmd
-----------------------------------------------------------------------------*/
const char* getTextualQuotactlCmd(int cmd)
{
	const char* result = "Q_UNKNOWN";

	switch (cmd)
	{
		DEF_CASE(Q_QUOTAON);
		DEF_CASE(Q_QUOTAOFF);
		DEF_CASE(Q_GETQUOTA);
		DEF_CASE(Q_SETQUOTA);
		DEF_CASE(Q_GETINFO);
		DEF_CASE(Q_SETINFO);
		DEF_CASE(Q_GETFMT);
		DEF_CASE(Q_SYNC);
#ifdef Q_GETSTATS
		DEF_CASE(Q_GETSTATS);
#endif
		DEF_CASE(Q_XQUOTAON);
		DEF_CASE(Q_XQUOTAOFF);
		DEF_CASE(Q_XGETQUOTA);
		DEF_CASE(Q_XSETQLIM);
		DEF_CASE(Q_XGETQSTAT);
		DEF_CASE(Q_XQUOTARM);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualQuotactlFmt
-----------------------------------------------------------------------------*/
const char* getTextualQuotactlFmt(unsigned long fmt)
{
	const char* result = "QFMT_UNKNOWN";

	switch (fmt)
	{
		DEF_CASE(QFMT_VFS_OLD);
		DEF_CASE(QFMT_VFS_V0);
		DEF_CASE(QFMT_VFS_V1);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualPriorityWhich
-----------------------------------------------------------------------------*/
const char* getTextualPriorityWhich(int which)
{
	const char* result = "PRIO_UNKNOWN";

	switch (which)
	{
		DEF_CASE(PRIO_PROCESS);
		DEF_CASE(PRIO_PGRP);
		DEF_CASE(PRIO_USER);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualSchedulingPolicy
-----------------------------------------------------------------------------*/
const char* getTextualSchedulingPolicy(int policy)
{
	const char* result = "SCHED_UNKNOWN";

	switch (policy)
	{
		DEF_CASE(SCHED_OTHER);
		DEF_CASE(SCHED_BATCH);
		DEF_CASE(SCHED_IDLE);
		DEF_CASE(SCHED_FIFO);
		DEF_CASE(SCHED_RR);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualInotifyFlags
-----------------------------------------------------------------------------*/
const char* getTextualInotifyFlags(int flags)
{
	const char* result = "IN_UNKNOWN";

	switch (flags)
	{
		DEF_CASE(IN_NONBLOCK);
		DEF_CASE(IN_CLOEXEC);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualMremapFlags
-----------------------------------------------------------------------------*/
const char* getTextualMremapFlags(int flags)
{
	const char* result = "<none>";

	switch (flags)
	{
		DEF_CASE(MREMAP_MAYMOVE);
		DEF_CASE(MREMAP_FIXED);
	}

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualTimerFlags
-----------------------------------------------------------------------------*/
std::string getTextualTimerFlags(int flags)
{
    std::string result;

    TEST_FLAG(flags, TFD_NONBLOCK     , result);
    TEST_FLAG(flags, TFD_CLOEXEC      , result);
    TEST_FLAG(flags, TFD_TIMER_ABSTIME, result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualWaitEventType
-----------------------------------------------------------------------------*/
std::string getTextualWaitEventType(int status)
{
    std::string result;

    if (WIFEXITED(status))
    {
        result = "EXIT";
    }
    else if (WIFSTOPPED(status))
    {
        result  = "STOP - ";
        result += getTextualSig(WSTOPSIG(status));
    }
    else
    {
        result  = "SIG - ";
        result += getTextualSig(WSTOPSIG(status));
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFileFlags
-----------------------------------------------------------------------------*/
std::string getTextualFileFlags(int flags)
{
    std::string result;

    TEST_FLAG(flags, O_RDONLY,    result);
    TEST_FLAG(flags, O_WRONLY,    result);
    TEST_FLAG(flags, O_RDWR,      result);
    TEST_FLAG(flags, O_APPEND,    result);
    TEST_FLAG(flags, O_ASYNC,     result);
    TEST_FLAG(flags, O_CREAT,     result);
    TEST_FLAG(flags, O_DIRECT,    result);
    TEST_FLAG(flags, O_DIRECTORY, result);
    TEST_FLAG(flags, O_EXCL,      result);
    TEST_FLAG(flags, O_LARGEFILE, result);
    TEST_FLAG(flags, O_NOATIME,   result);
    TEST_FLAG(flags, O_NOCTTY,    result);
    TEST_FLAG(flags, O_NOFOLLOW,  result);
    TEST_FLAG(flags, O_NONBLOCK,  result);
    TEST_FLAG(flags, O_SYNC,      result);
    TEST_FLAG(flags, O_TRUNC,     result);
    TEST_FLAG(flags, O_CLOEXEC,   result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFileMode
-----------------------------------------------------------------------------*/
std::string getTextualFileMode(int mode)
{
    std::string result;

	// Permissions
    TEST_FLAG(mode, S_IRUSR, result);
    TEST_FLAG(mode, S_IWUSR, result);
    TEST_FLAG(mode, S_IXUSR, result);
    TEST_FLAG(mode, S_IRGRP, result);
    TEST_FLAG(mode, S_IWGRP, result);
    TEST_FLAG(mode, S_IXGRP, result);
    TEST_FLAG(mode, S_IROTH, result);
    TEST_FLAG(mode, S_IWOTH, result);
    TEST_FLAG(mode, S_IXOTH, result);

	// File Types
    TEST_FLAG(mode, S_IFMT, result);
    TEST_FLAG(mode, S_IFDIR, result);
    TEST_FLAG(mode, S_IFCHR, result);
    TEST_FLAG(mode, S_IFBLK, result);
    TEST_FLAG(mode, S_IFREG, result);
    TEST_FLAG(mode, S_IFIFO, result);
    TEST_FLAG(mode, S_IFLNK, result);
    TEST_FLAG(mode, S_IFSOCK, result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualAccessMode
-----------------------------------------------------------------------------*/
std::string getTextualAccessMode(int mode)
{
    std::string result;

    TEST_FLAG(mode, R_OK, result);
    TEST_FLAG(mode, W_OK, result);
    TEST_FLAG(mode, X_OK, result);
    TEST_FLAG(mode, F_OK, result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualProtectionFlags
-----------------------------------------------------------------------------*/
std::string getTextualProtectionFlags(int mode)
{
    std::string result;

    TEST_FLAG(mode, PROT_EXEC,      result);
    TEST_FLAG(mode, PROT_READ,      result);
    TEST_FLAG(mode, PROT_WRITE,     result);
    TEST_FLAG(mode, PROT_NONE,      result);
    TEST_FLAG(mode, PROT_GROWSDOWN, result);
    TEST_FLAG(mode, PROT_GROWSUP,   result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualCloneFlags
-----------------------------------------------------------------------------*/
std::string getTextualCloneFlags(unsigned int flags)
{
    std::string result;

    TEST_FLAG(flags, CLONE_CHILD_CLEARTID, result);
    TEST_FLAG(flags, CLONE_CHILD_SETTID,   result);
    TEST_FLAG(flags, CLONE_FILES,          result);
    TEST_FLAG(flags, CLONE_FS,             result);
    TEST_FLAG(flags, CLONE_IO,             result);
    TEST_FLAG(flags, CLONE_NEWIPC,         result);
    TEST_FLAG(flags, CLONE_NEWNET,         result);
    TEST_FLAG(flags, CLONE_NEWNS,          result);
    TEST_FLAG(flags, CLONE_NEWPID,         result);
    TEST_FLAG(flags, CLONE_NEWUTS,         result);
    TEST_FLAG(flags, CLONE_PARENT,         result);
    TEST_FLAG(flags, CLONE_PARENT_SETTID,  result);
    //    TEST_FLAG(flags, CLONE_PID           , result);
    TEST_FLAG(flags, CLONE_PTRACE,         result);
    TEST_FLAG(flags, CLONE_SETTLS,         result);
    TEST_FLAG(flags, CLONE_SIGHAND,        result);
    //    TEST_FLAG(flags, CLONE_STOPPED       , result);
    TEST_FLAG(flags, CLONE_SYSVSEM,        result);
    TEST_FLAG(flags, CLONE_THREAD,         result);
    TEST_FLAG(flags, CLONE_UNTRACED,       result);
    TEST_FLAG(flags, CLONE_VFORK,          result);
    TEST_FLAG(flags, CLONE_VM,             result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualMapType
-----------------------------------------------------------------------------*/
std::string getTextualMapType(int mode)
{
    std::string result;

    TEST_FLAG(mode, MAP_SHARED,         result);
    TEST_FLAG(mode, MAP_PRIVATE,        result);
    TEST_FLAG(mode, MAP_FIXED,          result);
    TEST_FLAG(mode, MAP_ANONYMOUS,      result);
//    TEST_FLAG(mode, MAP_32BIT      , result);
    TEST_FLAG(mode, MAP_GROWSDOWN,      result);
    TEST_FLAG(mode, MAP_DENYWRITE,      result);
    TEST_FLAG(mode, MAP_EXECUTABLE,     result);
    TEST_FLAG(mode, MAP_LOCKED,         result);
    TEST_FLAG(mode, MAP_NORESERVE,      result);
    TEST_FLAG(mode, MAP_POPULATE,       result);
    TEST_FLAG(mode, MAP_NONBLOCK,       result);
    TEST_FLAG(mode, MAP_STACK,          result);
    TEST_FLAG(mode, MAP_MVEE_WASSHARED, result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigset
-----------------------------------------------------------------------------*/
std::string getTextualSigSet(sigset_t set)
{
    std::string result;

    for (int i = 1; i < SIGRTMAX+1; ++i)
    {
        if (sigismember(&set, i))
        {
            if (result != "")
                result += " | ";
            result += getTextualSig(i);
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualPollRequest -
-----------------------------------------------------------------------------*/
std::string getTextualPollRequest(int events)
{
    std::string result;

    TEST_FLAG(events, POLLIN,     result);
    TEST_FLAG(events, POLLPRI,    result);
    TEST_FLAG(events, POLLOUT,    result);
    TEST_FLAG(events, POLLRDNORM, result);
    TEST_FLAG(events, POLLRDBAND, result);
    TEST_FLAG(events, POLLWRNORM, result);
    TEST_FLAG(events, POLLWRBAND, result);
    TEST_FLAG(events, POLLMSG,    result);
    TEST_FLAG(events, POLLREMOVE, result);
    TEST_FLAG(events, POLLRDHUP,  result);
    TEST_FLAG(events, POLLERR,    result);
    TEST_FLAG(events, POLLHUP,    result);
    TEST_FLAG(events, POLLNVAL,   result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualMSyncFlags -
-----------------------------------------------------------------------------*/
std::string getTextualMSyncFlags (int flags)
{
    std::string result;

    TEST_FLAG(flags, MS_ASYNC,      result);
    TEST_FLAG(flags, MS_SYNC,       result);
    TEST_FLAG(flags, MS_INVALIDATE, result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketType
-----------------------------------------------------------------------------*/
std::string getTextualSocketType(long int type)
{
    std::string result;

    TEST_FLAG(type, SOCK_STREAM,    result);
    TEST_FLAG(type, SOCK_DGRAM,     result);
    TEST_FLAG(type, SOCK_SEQPACKET, result);
    TEST_FLAG(type, SOCK_RAW,       result);
    TEST_FLAG(type, SOCK_RDM,       result);
    TEST_FLAG(type, SOCK_PACKET,    result);
    TEST_FLAG(type, SOCK_NONBLOCK,  result);
    TEST_FLAG(type, SOCK_CLOEXEC,   result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketAddr
-----------------------------------------------------------------------------*/
std::string getTextualSocketAddr(struct sockaddr* addr)
{
	std::stringstream ss;
    std::string result = "";

    switch(addr->sa_family)
    {
        case AF_INET:
		{
            char tmp[50];
            inet_ntop(addr->sa_family, &((struct sockaddr_in*)addr)->sin_addr, tmp, 50);
			ss << "clientsock:ipv4:" << std::string(tmp);
            break;
        }

        case AF_INET6:
        {
            char tmp[50];
            inet_ntop(addr->sa_family, &((struct sockaddr_in*)addr)->sin_addr, tmp, 50);
			ss << "clientsock:ipv6:" << std::string(tmp);
            break;
        }
//      case AF_FILE:
//		case AF_UNIX:
		case AF_LOCAL:
		{
			ss << "domainsock:" << std::string(((struct sockaddr_un*)addr)->sun_path);
			result = ss.str();
			break;
		}
        default:
        {
            result  = "<couldn't resolve socket addr - family: ";
            result += getTextualSocketFamily(addr->sa_family);
            result += ">";
            break;
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketMsgFlags
-----------------------------------------------------------------------------*/
std::string getTextualSocketMsgFlags(long int flags)
{
    std::string result;

    TEST_FLAG(flags, MSG_CONFIRM,   result);
    TEST_FLAG(flags, MSG_DONTROUTE, result);
    TEST_FLAG(flags, MSG_DONTWAIT,  result);
    TEST_FLAG(flags, MSG_EOR,       result);
    TEST_FLAG(flags, MSG_MORE,      result);
    TEST_FLAG(flags, MSG_NOSIGNAL,  result);
    TEST_FLAG(flags, MSG_OOB,       result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualCPUSet
-----------------------------------------------------------------------------*/
std::string getTextualCPUSet (cpu_set_t* mask)
{
    std::string result;

    for (unsigned int i = 0; i < sizeof(cpu_set_t) * 8; ++i)
    {
        if (CPU_ISSET(i, mask))
        {
            if (result != "")
                result += " | ";
            result += "CPU ";
            result += std::to_string(i);
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualUserId
-----------------------------------------------------------------------------*/
std::string getTextualUserId (int uid)
{
    if (uid == -1)
        return std::string("<unchanged>");

    char        cmd[200];
    sprintf(cmd, "cat /etc/passwd | cut -d':' -f1,3 | grep \":%d\" | cut -d':' -f1", uid);
    std::string result = mvee::log_read_from_proc_pipe(cmd, NULL);
    if (result != "")
    {
        int len = result.length();
        for (int i = 1; i < 5; ++i)
            if (len - i > 0 && (result[len - i] == 10 || result[len - i] == 13))
                result[len - i] = 0;
    }
    return result;
}

/*-----------------------------------------------------------------------------
    getTextualGroupId
-----------------------------------------------------------------------------*/
std::string getTextualGroupId (int gid)
{
    if (gid == -1)
        return std::string("<unchanged>");

    char        cmd[200];
    sprintf(cmd, "cat /etc/group | grep \":%d:\" | cut -d':' -f1", gid);
    std::string result = mvee::log_read_from_proc_pipe(cmd, NULL);
    if (result != "")
    {
        int len = result.length();
        for (int i = 1; i < 5; ++i)
            if (len - i > 0 && (result[len - i] == 10 || result[len - i] == 13))
                result[len - i] = 0;
    }
    return result;
}

/*-----------------------------------------------------------------------------
    getTextualGroups
-----------------------------------------------------------------------------*/
std::string getTextualGroups (int cnt, gid_t* gids)
{
    std::string tmp = "[";

    for (int i = 0; i < cnt; ++i)
    {
        if (tmp.length() > 1)
            tmp += ", ";
        tmp += std::to_string(gids[i]);
        tmp += " = ";
        tmp += getTextualGroupId(gids[i]);
    }

    tmp += "]";
    return tmp;
}

/*-----------------------------------------------------------------------------
    getTextualEpollEvents
-----------------------------------------------------------------------------*/
std::string getTextualEpollEvents(unsigned int events)
{
    std::string result;

    TEST_FLAG(events, EPOLLIN,      result);
    TEST_FLAG(events, EPOLLOUT,     result);
    TEST_FLAG(events, EPOLLRDHUP,   result);
    TEST_FLAG(events, EPOLLERR,     result);
    TEST_FLAG(events, EPOLLHUP,     result);
    TEST_FLAG(events, EPOLLET,      result);
    TEST_FLAG(events, EPOLLONESHOT, result);
    TEST_FLAG(events, EPOLLWAKEUP,  result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigactionFlags
-----------------------------------------------------------------------------*/
std::string getTextualSigactionFlags(unsigned int flags)
{
    std::string result;

    TEST_FLAG(flags, SA_NOCLDSTOP, result);
    TEST_FLAG(flags, SA_NOCLDWAIT, result);
    TEST_FLAG(flags, SA_NODEFER,   result);
    TEST_FLAG(flags, SA_ONSTACK,   result);
    TEST_FLAG(flags, SA_RESETHAND, result);
    TEST_FLAG(flags, SA_RESTART,   result);
    TEST_FLAG(flags, SA_SIGINFO,   result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualPerfFlags
-----------------------------------------------------------------------------*/
std::string getTextualPerfFlags(unsigned long flags)
{
    std::string result;

#ifdef PERF_FLAG_FD_CLOEXEC
    TEST_FLAG(flags, PERF_FLAG_FD_CLOEXEC,  result);
#endif
    TEST_FLAG(flags, PERF_FLAG_FD_NO_GROUP, result);
    TEST_FLAG(flags, PERF_FLAG_FD_OUTPUT,   result);
    TEST_FLAG(flags, PERF_FLAG_PID_CGROUP,  result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualShmFlags
-----------------------------------------------------------------------------*/
std::string getTextualShmFlags(unsigned long flags)
{
    std::string result;

    TEST_FLAG(flags, SHM_RDONLY, result);
    TEST_FLAG(flags, SHM_RND   , result);
    TEST_FLAG(flags, SHM_REMAP , result);
    TEST_FLAG(flags, SHM_EXEC  , result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualShmctlFlags
-----------------------------------------------------------------------------*/
std::string getTextualShmctlFlags(unsigned long cmd)
{
    std::string result;

    switch(cmd)
    {
        DEF_CASE(IPC_STAT)
        DEF_CASE(IPC_SET)
        DEF_CASE(IPC_RMID)
        DEF_CASE(IPC_INFO)
        DEF_CASE(SHM_INFO)
        DEF_CASE(SHM_STAT)
        // DEF_CASE(SHM_STAT_ANY)
        DEF_CASE(SHM_LOCK)
        DEF_CASE(SHM_UNLOCK)
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualInotifyMask
-----------------------------------------------------------------------------*/
std::string getTextualInotifyMask(unsigned long mask)
{
	std::string result;

	if ((mask & IN_ALL_EVENTS) == IN_ALL_EVENTS)
	{
		TEST_FLAG(mask, IN_ALL_EVENTS    , result);
	}
	else
	{
		TEST_FLAG(mask, IN_ACCESS        , result);
		TEST_FLAG(mask, IN_ATTRIB        , result);
		TEST_FLAG(mask, IN_CLOSE_WRITE   , result);
		TEST_FLAG(mask, IN_CLOSE_NOWRITE , result);
		TEST_FLAG(mask, IN_CREATE        , result);
		TEST_FLAG(mask, IN_DELETE        , result);
		TEST_FLAG(mask, IN_DELETE_SELF   , result);
		TEST_FLAG(mask, IN_MODIFY        , result);
		TEST_FLAG(mask, IN_MOVE_SELF     , result);
		TEST_FLAG(mask, IN_MOVED_FROM    , result);
		TEST_FLAG(mask, IN_MOVED_TO      , result);
		TEST_FLAG(mask, IN_OPEN          , result);
	}

	TEST_FLAG(mask, IN_DONT_FOLLOW       , result);
	TEST_FLAG(mask, IN_EXCL_UNLINK       , result);
	TEST_FLAG(mask, IN_MASK_ADD          , result);
	TEST_FLAG(mask, IN_ONESHOT           , result);
	TEST_FLAG(mask, IN_ONLYDIR           , result);
	TEST_FLAG(mask, IN_IGNORED           , result);
	TEST_FLAG(mask, IN_ISDIR             , result);
	TEST_FLAG(mask, IN_Q_OVERFLOW        , result);
	TEST_FLAG(mask, IN_UNMOUNT           , result);

	return result;
}

/*-----------------------------------------------------------------------------
    getTextualUnlinkFlags
-----------------------------------------------------------------------------*/
std::string getTextualUnlinkFlags (int flags)
{
	std::string result;

	TEST_FLAG(flags, AT_REMOVEDIR, result);

	return result;	
}

/*-----------------------------------------------------------------------------
    getTextualLinkFlags
-----------------------------------------------------------------------------*/
std::string getTextualLinkFlags (int flags)
{
	std::string result;

	TEST_FLAG(flags, AT_EMPTY_PATH     , result);
	TEST_FLAG(flags, AT_SYMLINK_FOLLOW , result);

	return result;	
}

/*-----------------------------------------------------------------------------
    getTextualChmodFlags
-----------------------------------------------------------------------------*/
std::string getTextualChmodFlags (int flags)
{
	std::string result;

	TEST_FLAG(flags, AT_SYMLINK_FOLLOW , result);

	return result;	
}

/*-----------------------------------------------------------------------------
    getTextualMVEEWaitStatus
-----------------------------------------------------------------------------*/
std::string getTextualMVEEWaitStatus (interaction::mvee_wait_status& status)
{
	std::stringstream ss;

	ss << "[PID: " << status.pid << ", reason: ";

	switch (status.reason)
	{
		case STOP_NOTSTOPPED: 
			ss << "STOP_NOTSTOPPED";
			break;
		case STOP_SYSCALL:
			ss << "STOP_SYSCALL";
			break;
		case STOP_SIGNAL:
			ss << "STOP_SIGNAL";
			break;
		case STOP_EXECVE:
			ss << "STOP_EXECVE";
			break;
		case STOP_FORK:
			ss << "STOP_FORK";
			break;
		case STOP_EXIT:
			ss << "STOP_EXIT";
			break;
		case STOP_KILLED:
			ss << "STOP_KILLED";
			break;
	}

	ss << ", sig: " << getTextualSig(status.data) << "]";
	return ss.str();
}

/*-----------------------------------------------------------------------------
    getTextualIpcShmKey
-----------------------------------------------------------------------------*/
std::string getTextualIpcShmKey (key_t key)
{
	std::stringstream ss;

	if (key == IPC_PRIVATE)
		ss << "IPC_PRIVATE";
	else
		ss << key;

	return ss.str();
}

/*-----------------------------------------------------------------------------
    getTextualIpcShmFlags
-----------------------------------------------------------------------------*/
std::string getTextualIpcShmFlags (int shmflg)
{
	// The 9 least significant bits of the shmflg argument specify a permission
	// mode similar to the mode argument of sys_open
    std::string result = getTextualFileMode(shmflg & 0x1FF);

	// In addition to the permission mode, sys_shmget accepts these
    TEST_FLAG(shmflg, IPC_CREAT     , result);
    TEST_FLAG(shmflg, IPC_EXCL      , result);
	TEST_FLAG(shmflg, SHM_HUGETLB   , result);
	TEST_FLAG(shmflg, SHM_NORESERVE , result);
#ifdef SHM_HUGE_2MB
	TEST_FLAG(shmflg, SHM_HUGE_2MB  , result);
#endif
#ifdef SHM_HUGE_1GB
	TEST_FLAG(shmflg, SHM_HUGE_1GB  , result);
#endif

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFallocateFlags
-----------------------------------------------------------------------------*/
std::string getTextualFallocateFlags (int mode)
{
    std::string result;

    TEST_FLAG(mode, FALLOC_FL_KEEP_SIZE      , result);
    TEST_FLAG(mode, FALLOC_FL_PUNCH_HOLE     , result);
#ifdef FALLOC_FL_COLLAPSE_RANGE
    TEST_FLAG(mode, FALLOC_FL_COLLAPSE_RANGE , result);
#endif
#ifdef FALLOC_FL_ZERO_RANGE
    TEST_FLAG(mode, FALLOC_FL_ZERO_RANGE     , result);
#endif

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualRandFlags
-----------------------------------------------------------------------------*/
std::string getTextualRandFlags (unsigned int mode)
{
    std::string result;

    TEST_FLAG(mode, GRND_RANDOM   , result);
    TEST_FLAG(mode, GRND_NONBLOCK , result);

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualMemfdFlags
-----------------------------------------------------------------------------*/
std::string getTextualMemfdFlags (unsigned int flags)
{
    std::string result;

    TEST_FLAG(flags, MFD_CLOEXEC       , result);
    TEST_FLAG(flags, MFD_ALLOW_SEALING , result);
    TEST_FLAG(flags, MFD_HUGETLB       , result);
#ifdef SHM_HUGE_2MB
    TEST_FLAG(flags, MFD_HUGE_2MB      , result);
#endif
#ifdef SHM_HUGE_1GB
    TEST_FLAG(flags, MFD_HUGE_1GB      , result);
#endif

    return result;
}
