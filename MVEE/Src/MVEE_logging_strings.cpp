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
#include <sys/shm.h>
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

/*-----------------------------------------------------------------------------
    getTextualState
-----------------------------------------------------------------------------*/
const char* getTextualState(unsigned int dwState)
{
    const char* result = "UNKNOWN";

#define DEF_STATE(a) \
    case a:          \
        result = #a; \
        break;

    switch(dwState)
    {
        DEF_STATE(STATE_WAITING_ATTACH);
        DEF_STATE(STATE_WAITING_RESUME);
        DEF_STATE(STATE_NORMAL);
        DEF_STATE(STATE_IN_SYSCALL);
        DEF_STATE(STATE_IN_MASTERCALL);
        DEF_STATE(STATE_IN_FORKCALL);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSig
-----------------------------------------------------------------------------*/
const char* getTextualSig(unsigned int dwSignal)
{
    const char* result = "UNKNOWN";

#define DEF_SIGNAL(a) case a: \
        result = #a;          \
        break;                \

    switch(dwSignal)
    {
        DEF_SIGNAL(SIGALRM)
        DEF_SIGNAL(SIGHUP)
        DEF_SIGNAL(SIGINT)
        DEF_SIGNAL(SIGKILL)
        DEF_SIGNAL(SIGPIPE)
        DEF_SIGNAL(SIGPOLL)
        DEF_SIGNAL(SIGPROF)
        DEF_SIGNAL(SIGTERM)
        DEF_SIGNAL(SIGUSR1)
        DEF_SIGNAL(SIGUSR2)
        DEF_SIGNAL(SIGVTALRM)
//        DEF_SIGNAL(STKFLT) - Undefined on linux
        DEF_SIGNAL(SIGPWR)
        DEF_SIGNAL(SIGWINCH)
        DEF_SIGNAL(SIGCHLD)
        DEF_SIGNAL(SIGURG)
        DEF_SIGNAL(SIGTSTP)
        DEF_SIGNAL(SIGTTIN)
        DEF_SIGNAL(SIGTTOU)
        DEF_SIGNAL(SIGSTOP)
        DEF_SIGNAL(SIGCONT)
        DEF_SIGNAL(SIGABRT)
        DEF_SIGNAL(SIGFPE)
        DEF_SIGNAL(SIGILL)
        DEF_SIGNAL(SIGQUIT)
        DEF_SIGNAL(SIGSEGV)
#if SIGTRAP != SIGSYSTRAP
        DEF_SIGNAL(SIGSYSTRAP)
#endif
        DEF_SIGNAL(SIGTRAP)
        DEF_SIGNAL(SIGSYS)
//        DEF_SIGNAL(SIGEMT) - Undefined on linux
        DEF_SIGNAL(SIGBUS)
        DEF_SIGNAL(SIGXCPU)
        DEF_SIGNAL(SIGXFSZ)
        DEF_SIGNAL(SIGCANCEL)
        DEF_SIGNAL(SIGSETXID)
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSigHow
-----------------------------------------------------------------------------*/
const char* getTextualSigHow(int how)
{
    const char* result = "SIG_???";

#define DEF_HOW(a) case a: \
        result = #a;       \
        break;             \

    switch(how)
    {
        DEF_HOW(SIG_BLOCK);
        DEF_HOW(SIG_UNBLOCK);
        DEF_HOW(SIG_SETMASK);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualRequest
-----------------------------------------------------------------------------*/
const char* getTextualRequest(unsigned int dwRequest)
{
    const char* result = "PTRACE_UNKNOWN";

#define DEF_REQUEST(a) \
    case a:            \
        result = #a;   \
        break;

    switch(dwRequest)
    {
        DEF_REQUEST(PTRACE_TRACEME);
        DEF_REQUEST(PTRACE_PEEKTEXT);
        DEF_REQUEST(PTRACE_PEEKDATA);
        DEF_REQUEST(PTRACE_PEEKUSER);
        DEF_REQUEST(PTRACE_POKETEXT);
        DEF_REQUEST(PTRACE_POKEDATA);
        DEF_REQUEST(PTRACE_POKEUSER);
        DEF_REQUEST(PTRACE_CONT);
        DEF_REQUEST(PTRACE_KILL);
        DEF_REQUEST(PTRACE_SINGLESTEP);
        DEF_REQUEST(PTRACE_ATTACH);
        DEF_REQUEST(PTRACE_DETACH);
        DEF_REQUEST(PTRACE_SYSCALL);
        DEF_REQUEST(PTRACE_SETOPTIONS);
        DEF_REQUEST(PTRACE_GETREGS);
        DEF_REQUEST(PTRACE_SETREGS);
        DEF_REQUEST(PTRACE_GETEVENTMSG);
        DEF_REQUEST(PTRACE_GETSIGINFO);
        DEF_REQUEST(PTRACE_SETSIGINFO);
        DEF_REQUEST(PTRACE_EXT_COPYMEM);
        DEF_REQUEST(PTRACE_EXT_COPYSTRING);
        DEF_REQUEST(PROCESS_VM_READV);
        DEF_REQUEST(PROCESS_VM_WRITEV);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSyscall
-----------------------------------------------------------------------------*/
const char* getTextualSyscall(long int syscallnum)
{
    const char* result = "(unknown)";

#define DEF_SYSCALL(a) \
    case a:            \
        result = #a;   \
        break;

    if (syscallnum < 0)
        result = "EXIT";
    else if (syscallnum < MAX_CALLS)
        result = mvee_syscall_string_table[syscallnum];
    else
    {
        // fake syscall numbers defined by monitor
        switch (syscallnum)
        {
            DEF_SYSCALL(NO_CALL);
            DEF_SYSCALL(MVEE_RDTSC_FAKE_SYSCALL);
            DEF_SYSCALL(MVEE_GET_MASTERTHREAD_ID);
            DEF_SYSCALL(MVEE_GET_SHARED_BUFFER);
            DEF_SYSCALL(MVEE_FLUSH_SHARED_BUFFER);
            DEF_SYSCALL(MVEE_SET_INFINITE_LOOP_PTR);
            DEF_SYSCALL(MVEE_TOGGLESYNC);
            DEF_SYSCALL(MVEE_SET_SHARED_BUFFER_POS_PTR);
            DEF_SYSCALL(MVEE_RUNS_UNDER_MVEE_CONTROL);
            DEF_SYSCALL(MVEE_GET_THREAD_NUM);
            DEF_SYSCALL(MVEE_RESOLVE_SYMBOL);
            DEF_SYSCALL(MVEE_SET_SYNC_PRIMITIVES_PTR);
            DEF_SYSCALL(MVEE_ALL_HEAPS_ALIGNED);
            DEF_SYSCALL(MVEE_INVOKE_LD);
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

#define DEF_SOCKETCALL(a) \
    case a:               \
        result = #a;      \
        break;

    switch(sockcallnum)
    {
        DEF_SOCKETCALL(SYS_SOCKET);
        DEF_SOCKETCALL(SYS_BIND);
        DEF_SOCKETCALL(SYS_CONNECT);
        DEF_SOCKETCALL(SYS_LISTEN);
        DEF_SOCKETCALL(SYS_ACCEPT);
        DEF_SOCKETCALL(SYS_GETSOCKNAME);
        DEF_SOCKETCALL(SYS_GETPEERNAME);
        DEF_SOCKETCALL(SYS_SOCKETPAIR);
        DEF_SOCKETCALL(SYS_SEND);
        DEF_SOCKETCALL(SYS_SENDTO);
        DEF_SOCKETCALL(SYS_RECV);
        DEF_SOCKETCALL(SYS_RECVFROM);
        DEF_SOCKETCALL(SYS_SHUTDOWN);
        DEF_SOCKETCALL(SYS_SETSOCKOPT);
        DEF_SOCKETCALL(SYS_GETSOCKOPT);
        DEF_SOCKETCALL(SYS_SENDMSG);
        DEF_SOCKETCALL(SYS_RECVMSG);
        DEF_SOCKETCALL(SYS_ACCEPT4);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketFamily
-----------------------------------------------------------------------------*/
const char* getTextualSocketFamily(long int family)
{
    const char* result = "UNKNOWN";

#define DEF_SOCKETFAMILY(a) \
    case a:                 \
        result = #a;        \
        break;

    switch(family)
    {
        DEF_SOCKETFAMILY(AF_UNSPEC);
        DEF_SOCKETFAMILY(AF_LOCAL);
        //DEF_SOCKETFAMILY(AF_UNIX);
        //DEF_SOCKETFAMILY(AF_FILE);
        DEF_SOCKETFAMILY(AF_INET);
        DEF_SOCKETFAMILY(AF_AX25);
        DEF_SOCKETFAMILY(AF_IPX);
        DEF_SOCKETFAMILY(AF_APPLETALK);
        DEF_SOCKETFAMILY(AF_NETROM);
        DEF_SOCKETFAMILY(AF_BRIDGE);
        DEF_SOCKETFAMILY(AF_ATMPVC);
        DEF_SOCKETFAMILY(AF_X25);
        DEF_SOCKETFAMILY(AF_INET6);
        DEF_SOCKETFAMILY(AF_ROSE);
        DEF_SOCKETFAMILY(AF_DECnet);
        DEF_SOCKETFAMILY(AF_NETBEUI);
        DEF_SOCKETFAMILY(AF_SECURITY);
        DEF_SOCKETFAMILY(AF_KEY);
        DEF_SOCKETFAMILY(AF_NETLINK);
        //DEF_SOCKETFAMILY(AF_ROUTE);
        DEF_SOCKETFAMILY(AF_PACKET);
        DEF_SOCKETFAMILY(AF_ASH);
        DEF_SOCKETFAMILY(AF_ECONET);
        DEF_SOCKETFAMILY(AF_ATMSVC);
        DEF_SOCKETFAMILY(AF_RDS);
        DEF_SOCKETFAMILY(AF_SNA);
        DEF_SOCKETFAMILY(AF_IRDA);
        DEF_SOCKETFAMILY(AF_PPPOX);
        DEF_SOCKETFAMILY(AF_WANPIPE);
        DEF_SOCKETFAMILY(AF_LLC);
        DEF_SOCKETFAMILY(AF_CAN);
        DEF_SOCKETFAMILY(AF_TIPC);
        DEF_SOCKETFAMILY(AF_BLUETOOTH);
        DEF_SOCKETFAMILY(AF_IUCV);
        DEF_SOCKETFAMILY(AF_RXRPC);
        DEF_SOCKETFAMILY(AF_ISDN);
        DEF_SOCKETFAMILY(AF_PHONET);
        DEF_SOCKETFAMILY(AF_IEEE802154);
        DEF_SOCKETFAMILY(AF_CAIF);
        DEF_SOCKETFAMILY(AF_ALG);
        DEF_SOCKETFAMILY(AF_NFC);
        DEF_SOCKETFAMILY(AF_VSOCK);
        DEF_SOCKETFAMILY(AF_MAX);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketProtocol
-----------------------------------------------------------------------------*/
const char* getTextualSocketProtocol(long int proto)
{
    const char* result = "UNKNOWN";

#define DEF_SOCKETPROTOCOL(a) \
    case a:                   \
        result = #a;          \
        break;

    switch(proto)
    {
        DEF_SOCKETPROTOCOL(PF_UNSPEC);
        DEF_SOCKETPROTOCOL(PF_LOCAL);
        DEF_SOCKETPROTOCOL(PF_INET);
        DEF_SOCKETPROTOCOL(PF_AX25);
        DEF_SOCKETPROTOCOL(PF_IPX);
        DEF_SOCKETPROTOCOL(PF_APPLETALK);
        DEF_SOCKETPROTOCOL(PF_NETROM);
        DEF_SOCKETPROTOCOL(PF_BRIDGE);
        DEF_SOCKETPROTOCOL(PF_ATMPVC);
        DEF_SOCKETPROTOCOL(PF_X25);
        DEF_SOCKETPROTOCOL(PF_INET6);
        DEF_SOCKETPROTOCOL(PF_ROSE);
        DEF_SOCKETPROTOCOL(PF_DECnet);
        DEF_SOCKETPROTOCOL(PF_NETBEUI);
        DEF_SOCKETPROTOCOL(PF_SECURITY);
        DEF_SOCKETPROTOCOL(PF_KEY);
        DEF_SOCKETPROTOCOL(PF_NETLINK);
        DEF_SOCKETPROTOCOL(PF_PACKET);
        DEF_SOCKETPROTOCOL(PF_ASH);
        DEF_SOCKETPROTOCOL(PF_ECONET);
        DEF_SOCKETPROTOCOL(PF_ATMSVC);
        DEF_SOCKETPROTOCOL(PF_RDS);
        DEF_SOCKETPROTOCOL(PF_SNA);
        DEF_SOCKETPROTOCOL(PF_IRDA);
        DEF_SOCKETPROTOCOL(PF_PPPOX);
        DEF_SOCKETPROTOCOL(PF_WANPIPE);
        DEF_SOCKETPROTOCOL(PF_LLC);
        DEF_SOCKETPROTOCOL(PF_CAN);
        DEF_SOCKETPROTOCOL(PF_TIPC);
        DEF_SOCKETPROTOCOL(PF_BLUETOOTH);
        DEF_SOCKETPROTOCOL(PF_IUCV);
        DEF_SOCKETPROTOCOL(PF_RXRPC);
        DEF_SOCKETPROTOCOL(PF_ISDN);
        DEF_SOCKETPROTOCOL(PF_PHONET);
        DEF_SOCKETPROTOCOL(PF_IEEE802154);
        DEF_SOCKETPROTOCOL(PF_CAIF);
        DEF_SOCKETPROTOCOL(PF_ALG);
        DEF_SOCKETPROTOCOL(PF_NFC);
        DEF_SOCKETPROTOCOL(PF_VSOCK);
        DEF_SOCKETPROTOCOL(PF_MAX);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSocketProtocol
-----------------------------------------------------------------------------*/
const char* getTextualSocketShutdownHow(long int how)
{
    const char* result = "UNKNOWN";

#define DEF_SOCKETSHUTDOWNHOW(a) \
    case a:                      \
        result = #a;             \
        break;

    switch(how)
    {
        DEF_SOCKETSHUTDOWNHOW(SHUT_WR);
        DEF_SOCKETSHUTDOWNHOW(SHUT_RDWR);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSEGVCode
-----------------------------------------------------------------------------*/
const char* getTextualSEGVCode(int code)
{
    const char* result = "(unknown)";

#define DEF_SEGVCODE(a) \
    case a:             \
        result = #a;    \
        break;

    switch (code)
    {
        DEF_SEGVCODE(SI_USER);
        DEF_SEGVCODE(SI_KERNEL);
        DEF_SEGVCODE(SI_QUEUE);
        DEF_SEGVCODE(SI_TIMER);
        DEF_SEGVCODE(SI_MESGQ);
        DEF_SEGVCODE(SI_ASYNCIO);
        DEF_SEGVCODE(SI_SIGIO);
        DEF_SEGVCODE(SI_TKILL);
        DEF_SEGVCODE(SEGV_MAPERR);
        DEF_SEGVCODE(SEGV_ACCERR);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFcntlCmd
-----------------------------------------------------------------------------*/
const char* getTextualFcntlCmd(int cmd)
{
    const char* result = "(unknown)";

#define DEF_FCNTLCMD(a) \
    case a:             \
        result = #a;    \
        break;

    switch (cmd)
    {
        DEF_FCNTLCMD(F_DUPFD);
        DEF_FCNTLCMD(F_GETFD);
        DEF_FCNTLCMD(F_SETFD);
        DEF_FCNTLCMD(F_GETFL);
        DEF_FCNTLCMD(F_SETFL);
        DEF_FCNTLCMD(F_GETLK);
        DEF_FCNTLCMD(F_SETLK);
        DEF_FCNTLCMD(F_SETLKW);
        //DEF_FCNTLCMD(F_GETLK64);
        //DEF_FCNTLCMD(F_SETLK64);
        //DEF_FCNTLCMD(F_SETLKW64);
        DEF_FCNTLCMD(F_SETOWN);
        DEF_FCNTLCMD(F_GETOWN);
        DEF_FCNTLCMD(F_SETSIG);
        DEF_FCNTLCMD(F_GETSIG);
        DEF_FCNTLCMD(F_SETLEASE);
        DEF_FCNTLCMD(F_GETLEASE);
        DEF_FCNTLCMD(F_NOTIFY);
    }

    return result;
}

/*-----------------------------------------------------------------------------
  getTextualFlockType
-----------------------------------------------------------------------------*/
const char* getTextualFlockType(unsigned int type)
{
    const char* result = "(unknown)";

#define DEF_FLOCKTYPE(a) \
    case a:              \
        result = #a;     \
        break;

    switch (type)
    {
        DEF_FLOCKTYPE(LOCK_SH);
        DEF_FLOCKTYPE(LOCK_EX);
        DEF_FLOCKTYPE(LOCK_UN);
    }

    return result;
}


/*-----------------------------------------------------------------------------
    getTextualKernelError
-----------------------------------------------------------------------------*/
const char* getTextualKernelError (int err)
{
    const char* result = "(unknown)";

#define DEF_KERNEL_ERROR(a) \
    case a:                 \
        result = #a;        \
        break;

    switch (err)
    {
        DEF_KERNEL_ERROR(ERESTARTSYS);
        DEF_KERNEL_ERROR(ERESTARTNOINTR);
        DEF_KERNEL_ERROR(ERESTARTNOHAND);
        DEF_KERNEL_ERROR(ENOIOCTLCMD);
        DEF_KERNEL_ERROR(ERESTART_RESTARTBLOCK);
        DEF_KERNEL_ERROR(EBADHANDLE);
        DEF_KERNEL_ERROR(ENOTSYNC);
        DEF_KERNEL_ERROR(EBADCOOKIE);
        DEF_KERNEL_ERROR(ENOTSUPP);
        DEF_KERNEL_ERROR(ETOOSMALL);
        DEF_KERNEL_ERROR(ESERVERFAULT);
        DEF_KERNEL_ERROR(EBADTYPE);
        DEF_KERNEL_ERROR(EJUKEBOX);
        DEF_KERNEL_ERROR(EIOCBQUEUED);
        DEF_KERNEL_ERROR(EIOCBRETRY);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualProcmaskRequest
-----------------------------------------------------------------------------*/
const char* getTextualProcmaskRequest(int how)
{
    const char* result = "(unknown)";

#define DEF_PROCMASKHOW(a) \
    case a:                \
        result = #a;       \
        break;

    switch(how)
    {
        DEF_PROCMASKHOW(SIG_BLOCK);
        DEF_PROCMASKHOW(SIG_UNBLOCK);
        DEF_PROCMASKHOW(SIG_SETMASK);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFutexOp
-----------------------------------------------------------------------------*/
const char* getTextualFutexOp(int op)
{
    const char* result = "(unknown)";

#define DEF_FUTEX_OP(a) \
    case a:             \
        result = #a;    \
        break;

    switch(op)
    {
        DEF_FUTEX_OP(FUTEX_WAIT);
        DEF_FUTEX_OP(FUTEX_WAKE);
        DEF_FUTEX_OP(FUTEX_FD);
        DEF_FUTEX_OP(FUTEX_REQUEUE);
        DEF_FUTEX_OP(FUTEX_CMP_REQUEUE);
        DEF_FUTEX_OP(FUTEX_WAKE_OP);
        DEF_FUTEX_OP(FUTEX_LOCK_PI);
        DEF_FUTEX_OP(FUTEX_UNLOCK_PI);
        DEF_FUTEX_OP(FUTEX_TRYLOCK_PI);
        DEF_FUTEX_OP(FUTEX_WAIT_BITSET);
        DEF_FUTEX_OP(FUTEX_WAKE_BITSET);
        DEF_FUTEX_OP(FUTEX_WAIT_REQUEUE_PI);
        DEF_FUTEX_OP(FUTEX_CMP_REQUEUE_PI);
        DEF_FUTEX_OP(FUTEX_WAIT_PRIVATE);
        DEF_FUTEX_OP(FUTEX_WAKE_PRIVATE);
        DEF_FUTEX_OP(FUTEX_REQUEUE_PRIVATE);
        DEF_FUTEX_OP(FUTEX_CMP_REQUEUE_PRIVATE);
        DEF_FUTEX_OP(FUTEX_WAKE_OP_PRIVATE);
        DEF_FUTEX_OP(FUTEX_LOCK_PI_PRIVATE);
        DEF_FUTEX_OP(FUTEX_UNLOCK_PI_PRIVATE);
        DEF_FUTEX_OP(FUTEX_TRYLOCK_PI_PRIVATE);
        DEF_FUTEX_OP(FUTEX_WAIT_BITSET_PRIVATE);
        DEF_FUTEX_OP(FUTEX_WAKE_BITSET_PRIVATE);
        DEF_FUTEX_OP(FUTEX_WAIT_REQUEUE_PI_PRIVATE);
        DEF_FUTEX_OP(FUTEX_CMP_REQUEUE_PI_PRIVATE);
        DEF_FUTEX_OP(MVEE_FUTEX_WAIT_TID);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualAtomicType
-----------------------------------------------------------------------------*/
const char* getTextualAtomicType(int atomic_type)
{
    const char* result = "(unknown)";

  #define DEF_BASE_ATOMIC(a) \
    case a:                  \
        result = #a;         \
        break;
  #define DEF_EXTENDED_ATOMIC(a)        \
    case a + __MVEE_BASE_ATOMICS_MAX__: \
        result = #a;                    \
        break;

    switch(atomic_type)
    {
        DEF_BASE_ATOMIC(ATOMIC_FORCED_READ);
        DEF_BASE_ATOMIC(ATOMIC_LOAD);
        DEF_BASE_ATOMIC(ATOMIC_LOAD_MAX);
        DEF_BASE_ATOMIC(CATOMIC_COMPARE_AND_EXCHANGE_VAL_ACQ);
        DEF_BASE_ATOMIC(CATOMIC_COMPARE_AND_EXCHANGE_BOOL_ACQ);
        DEF_BASE_ATOMIC(CATOMIC_AND);
        DEF_BASE_ATOMIC(CATOMIC_OR);
        DEF_BASE_ATOMIC(CATOMIC_EXCHANGE_AND_ADD);
        DEF_BASE_ATOMIC(CATOMIC_ADD);
        DEF_BASE_ATOMIC(CATOMIC_INCREMENT);
        DEF_BASE_ATOMIC(CATOMIC_DECREMENT);
        DEF_BASE_ATOMIC(CATOMIC_MAX);
        DEF_BASE_ATOMIC(ATOMIC_COMPARE_AND_EXCHANGE_VAL_ACQ);
        DEF_BASE_ATOMIC(ATOMIC_COMPARE_AND_EXCHANGE_BOOL_ACQ);
        DEF_BASE_ATOMIC(ATOMIC_EXCHANGE_ACQ);
        DEF_BASE_ATOMIC(ATOMIC_EXCHANGE_AND_ADD);
        DEF_BASE_ATOMIC(ATOMIC_INCREMENT_AND_TEST);
        DEF_BASE_ATOMIC(ATOMIC_DECREMENT_AND_TEST);
        DEF_BASE_ATOMIC(ATOMIC_ADD_ZERO);
        DEF_BASE_ATOMIC(ATOMIC_ADD);
        DEF_BASE_ATOMIC(ATOMIC_INCREMENT);
        DEF_BASE_ATOMIC(ATOMIC_DECREMENT);
        DEF_BASE_ATOMIC(ATOMIC_BIT_TEST_SET);
        DEF_BASE_ATOMIC(ATOMIC_BIT_SET);
        DEF_BASE_ATOMIC(ATOMIC_AND);
        DEF_BASE_ATOMIC(ATOMIC_STORE);
        DEF_BASE_ATOMIC(ATOMIC_MAX);
        DEF_BASE_ATOMIC(ATOMIC_DECREMENT_IF_POSITIVE);
        DEF_BASE_ATOMIC(__THREAD_ATOMIC_CMPXCHG_VAL);
        DEF_BASE_ATOMIC(__THREAD_ATOMIC_AND);
        DEF_BASE_ATOMIC(__THREAD_ATOMIC_BIT_SET);
        DEF_BASE_ATOMIC(___UNKNOWN_LOCK_TYPE___);
        //DEF_BASE_ATOMIC(__MVEE_BASE_ATOMICS_MAX__);

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

  #define DEF_BP_TYPE(a) \
    case a:              \
        result = #a;     \
        break;

    switch(bp_type)
    {
        DEF_BP_TYPE(MVEE_BP_EXEC_ONLY);
        DEF_BP_TYPE(MVEE_BP_WRITE_ONLY);
        DEF_BP_TYPE(MVEE_BP_READ_WRITE);
        DEF_BP_TYPE(MVEE_BP_READ_WRITE_NO_FETCH);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualBufferType
-----------------------------------------------------------------------------*/
const char* getTextualBufferType(int buffer_type)
{
    const char* result = "(unknown)";

  #define DEF_BUFFER_TYPE(a) \
    case a:                  \
        result = #a;         \
        break;

    switch(buffer_type)
    {
        DEF_BUFFER_TYPE(MVEE_PTHREAD_LOCK_BUFFER);
        DEF_BUFFER_TYPE(MVEE_GTK_HASH_BUFFER);
        DEF_BUFFER_TYPE(MVEE_ORBIT_REQUEST_BUFFER);
        DEF_BUFFER_TYPE(MVEE_LIBC_LOCK_BUFFER);
        DEF_BUFFER_TYPE(MVEE_GLIB_HASH_BUFFER);
        DEF_BUFFER_TYPE(MVEE_PANGO_HASH_BUFFER);
        DEF_BUFFER_TYPE(MVEE_REALLOC_BUFFER);
        DEF_BUFFER_TYPE(MVEE_UNO_HASH_BUFFER);
        DEF_BUFFER_TYPE(MVEE_RAND_BUFFER);
//		DEF_BUFFER_TYPE(MVEE_LIBC_LOCK_EIP_BUFFER);
        DEF_BUFFER_TYPE(MVEE_JDK_ATOMIC_BUFFER);
        DEF_BUFFER_TYPE(MVEE_LIBC_MALLOC_DEBUG_BUFFER);
        DEF_BUFFER_TYPE(MVEE_GCCLIBS_BUFFER);
        DEF_BUFFER_TYPE(MVEE_LIBC_ATOMIC_BUFFER);
        DEF_BUFFER_TYPE(MVEE_UTCB_BUFFER);
        DEF_BUFFER_TYPE(MVEE_LIBC_LOCK_BUFFER_PARTIAL);
        DEF_BUFFER_TYPE(MVEE_LIBC_ATOMIC_BUFFER_HIDDEN);
		DEF_BUFFER_TYPE(MVEE_LIBC_HIDDEN_BUFFER_ARRAY);
		DEF_BUFFER_TYPE(MVEE_UTCB_REG_FILE_MAP);
        DEF_BUFFER_TYPE(MVEE_IPMON_BUFFER);
        DEF_BUFFER_TYPE(MVEE_IPMON_REG_FILE_MAP);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualRlimitType
-----------------------------------------------------------------------------*/
const char* getTextualRlimitType(int rlimit_type)
{
    const char* result = "(unknown)";

    #define DEF_RLIMIT_TYPE(a) \
    case a:                    \
        result = #a;           \
        break;

    switch(rlimit_type)
    {
        DEF_RLIMIT_TYPE(RLIMIT_AS);
        DEF_RLIMIT_TYPE(RLIMIT_CORE);
        DEF_RLIMIT_TYPE(RLIMIT_CPU);
        DEF_RLIMIT_TYPE(RLIMIT_DATA);
        DEF_RLIMIT_TYPE(RLIMIT_FSIZE);
        DEF_RLIMIT_TYPE(RLIMIT_LOCKS);
        DEF_RLIMIT_TYPE(RLIMIT_MEMLOCK);
        DEF_RLIMIT_TYPE(RLIMIT_MSGQUEUE);
        DEF_RLIMIT_TYPE(RLIMIT_NICE);
        DEF_RLIMIT_TYPE(RLIMIT_NOFILE);
        DEF_RLIMIT_TYPE(RLIMIT_NPROC);
        DEF_RLIMIT_TYPE(RLIMIT_RSS);
        DEF_RLIMIT_TYPE(RLIMIT_RTPRIO);
        DEF_RLIMIT_TYPE(RLIMIT_RTTIME);
        DEF_RLIMIT_TYPE(RLIMIT_SIGPENDING);
        DEF_RLIMIT_TYPE(RLIMIT_STACK);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualAllocType
-----------------------------------------------------------------------------*/
const char* getTextualAllocType(int alloc_type)
{
    const char* result = "(unknown)";

    #define DEF_ALLOC_TYPE(a) \
    case a:                   \
        result = #a;          \
        break;

    switch(alloc_type)
    {
        DEF_ALLOC_TYPE(LIBC_MALLOC);
        DEF_ALLOC_TYPE(LIBC_FREE);
        DEF_ALLOC_TYPE(LIBC_REALLOC);
        DEF_ALLOC_TYPE(LIBC_MEMALIGN);
        DEF_ALLOC_TYPE(LIBC_CALLOC);
        DEF_ALLOC_TYPE(MALLOC_TRIM);
        DEF_ALLOC_TYPE(HEAP_TRIM);
        DEF_ALLOC_TYPE(MALLOC_CONSOLIDATE);
        DEF_ALLOC_TYPE(ARENA_GET2);
        DEF_ALLOC_TYPE(_INT_MALLOC);
        DEF_ALLOC_TYPE(_INT_FREE);
        DEF_ALLOC_TYPE(_INT_REALLOC);
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

  #define DEF_CONST(a) \
    case a:            \
        result = #a;   \
        break;

    switch(constant)
    {
        DEF_CONST(DW_EXPR_OFFSET);
        DEF_CONST(DW_EXPR_VAL_OFFSET);
        DEF_CONST(DW_EXPR_EXPRESSION);
        DEF_CONST(DW_EXPR_VAL_EXPRESSION);
        DEF_CONST(DW_FRAME_SAME_VAL);
        DEF_CONST(DW_FRAME_UNDEFINED_VAL);
        DEF_CONST(DW_FRAME_CFA_COL3);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualDWARFOp
-----------------------------------------------------------------------------*/
const char* getTextualDWARFOp (int op)
{
    const char* result = "(unknown)";

  #define DEF_OP(a)  \
    case a:          \
        result = #a; \
        break;

    switch(op)
    {
        DEF_OP(DW_OP_addr);
        DEF_OP(DW_OP_deref);
        DEF_OP(DW_OP_const1u);
        DEF_OP(DW_OP_const1s);
        DEF_OP(DW_OP_const2u);
        DEF_OP(DW_OP_const2s);
        DEF_OP(DW_OP_const4u);
        DEF_OP(DW_OP_const4s);
        DEF_OP(DW_OP_const8u);
        DEF_OP(DW_OP_const8s);
        DEF_OP(DW_OP_constu);
        DEF_OP(DW_OP_consts);
        DEF_OP(DW_OP_dup);
        DEF_OP(DW_OP_drop);
        DEF_OP(DW_OP_over);
        DEF_OP(DW_OP_pick);
        DEF_OP(DW_OP_swap);
        DEF_OP(DW_OP_rot);
        DEF_OP(DW_OP_xderef);
        DEF_OP(DW_OP_abs);
        DEF_OP(DW_OP_and);
        DEF_OP(DW_OP_div);
        DEF_OP(DW_OP_minus);
        DEF_OP(DW_OP_mod);
        DEF_OP(DW_OP_mul);
        DEF_OP(DW_OP_neg);
        DEF_OP(DW_OP_not);
        DEF_OP(DW_OP_or);
        DEF_OP(DW_OP_plus);
        DEF_OP(DW_OP_plus_uconst);
        DEF_OP(DW_OP_shl);
        DEF_OP(DW_OP_shr);
        DEF_OP(DW_OP_shra);
        DEF_OP(DW_OP_xor);
        DEF_OP(DW_OP_bra);
        DEF_OP(DW_OP_eq);
        DEF_OP(DW_OP_ge);
        DEF_OP(DW_OP_gt);
        DEF_OP(DW_OP_le);
        DEF_OP(DW_OP_lt);
        DEF_OP(DW_OP_ne);
        DEF_OP(DW_OP_skip);
        DEF_OP(DW_OP_lit0);
        DEF_OP(DW_OP_lit1);
        DEF_OP(DW_OP_lit2);
        DEF_OP(DW_OP_lit3);
        DEF_OP(DW_OP_lit4);
        DEF_OP(DW_OP_lit5);
        DEF_OP(DW_OP_lit6);
        DEF_OP(DW_OP_lit7);
        DEF_OP(DW_OP_lit8);
        DEF_OP(DW_OP_lit9);
        DEF_OP(DW_OP_lit10);
        DEF_OP(DW_OP_lit11);
        DEF_OP(DW_OP_lit12);
        DEF_OP(DW_OP_lit13);
        DEF_OP(DW_OP_lit14);
        DEF_OP(DW_OP_lit15);
        DEF_OP(DW_OP_lit16);
        DEF_OP(DW_OP_lit17);
        DEF_OP(DW_OP_lit18);
        DEF_OP(DW_OP_lit19);
        DEF_OP(DW_OP_lit20);
        DEF_OP(DW_OP_lit21);
        DEF_OP(DW_OP_lit22);
        DEF_OP(DW_OP_lit23);
        DEF_OP(DW_OP_lit24);
        DEF_OP(DW_OP_lit25);
        DEF_OP(DW_OP_lit26);
        DEF_OP(DW_OP_lit27);
        DEF_OP(DW_OP_lit28);
        DEF_OP(DW_OP_lit29);
        DEF_OP(DW_OP_lit30);
        DEF_OP(DW_OP_lit31);
        DEF_OP(DW_OP_reg0);
        DEF_OP(DW_OP_reg1);
        DEF_OP(DW_OP_reg2);
        DEF_OP(DW_OP_reg3);
        DEF_OP(DW_OP_reg4);
        DEF_OP(DW_OP_reg5);
        DEF_OP(DW_OP_reg6);
        DEF_OP(DW_OP_reg7);
        DEF_OP(DW_OP_reg8);
        DEF_OP(DW_OP_reg9);
        DEF_OP(DW_OP_reg10);
        DEF_OP(DW_OP_reg11);
        DEF_OP(DW_OP_reg12);
        DEF_OP(DW_OP_reg13);
        DEF_OP(DW_OP_reg14);
        DEF_OP(DW_OP_reg15);
        DEF_OP(DW_OP_reg16);
        DEF_OP(DW_OP_reg17);
        DEF_OP(DW_OP_reg18);
        DEF_OP(DW_OP_reg19);
        DEF_OP(DW_OP_reg20);
        DEF_OP(DW_OP_reg21);
        DEF_OP(DW_OP_reg22);
        DEF_OP(DW_OP_reg23);
        DEF_OP(DW_OP_reg24);
        DEF_OP(DW_OP_reg25);
        DEF_OP(DW_OP_reg26);
        DEF_OP(DW_OP_reg27);
        DEF_OP(DW_OP_reg28);
        DEF_OP(DW_OP_reg29);
        DEF_OP(DW_OP_reg30);
        DEF_OP(DW_OP_reg31);
        DEF_OP(DW_OP_breg0);
        DEF_OP(DW_OP_breg1);
        DEF_OP(DW_OP_breg2);
        DEF_OP(DW_OP_breg3);
        DEF_OP(DW_OP_breg4);
        DEF_OP(DW_OP_breg5);
        DEF_OP(DW_OP_breg6);
        DEF_OP(DW_OP_breg7);
        DEF_OP(DW_OP_breg8);
        DEF_OP(DW_OP_breg9);
        DEF_OP(DW_OP_breg10);
        DEF_OP(DW_OP_breg11);
        DEF_OP(DW_OP_breg12);
        DEF_OP(DW_OP_breg13);
        DEF_OP(DW_OP_breg14);
        DEF_OP(DW_OP_breg15);
        DEF_OP(DW_OP_breg16);
        DEF_OP(DW_OP_breg17);
        DEF_OP(DW_OP_breg18);
        DEF_OP(DW_OP_breg19);
        DEF_OP(DW_OP_breg20);
        DEF_OP(DW_OP_breg21);
        DEF_OP(DW_OP_breg22);
        DEF_OP(DW_OP_breg23);
        DEF_OP(DW_OP_breg24);
        DEF_OP(DW_OP_breg25);
        DEF_OP(DW_OP_breg26);
        DEF_OP(DW_OP_breg27);
        DEF_OP(DW_OP_breg28);
        DEF_OP(DW_OP_breg29);
        DEF_OP(DW_OP_breg30);
        DEF_OP(DW_OP_breg31);
        DEF_OP(DW_OP_regx);
        DEF_OP(DW_OP_fbreg);
        DEF_OP(DW_OP_bregx);
        DEF_OP(DW_OP_piece);
        DEF_OP(DW_OP_deref_size);
        DEF_OP(DW_OP_xderef_size);
        DEF_OP(DW_OP_nop);
        DEF_OP(DW_OP_push_object_address);
        DEF_OP(DW_OP_call2);
        DEF_OP(DW_OP_call4);
        DEF_OP(DW_OP_call_ref);
        DEF_OP(DW_OP_form_tls_address);
        DEF_OP(DW_OP_call_frame_cfa);
        DEF_OP(DW_OP_bit_piece);
        DEF_OP(DW_OP_implicit_value);
        DEF_OP(DW_OP_stack_value);
        DEF_OP(DW_OP_GNU_push_tls_address);
        //DEF_OP(DW_OP_lo_user);
        DEF_OP(DW_OP_GNU_uninit);
        DEF_OP(DW_OP_GNU_encoded_addr);
        DEF_OP(DW_OP_GNU_implicit_pointer);
        DEF_OP(DW_OP_GNU_entry_value);
        //DEF_OP(DW_OP_HP_unknown);
        DEF_OP(DW_OP_HP_is_value);
        DEF_OP(DW_OP_HP_fltconst4);
        DEF_OP(DW_OP_HP_fltconst8);
        DEF_OP(DW_OP_HP_mod_range);
        DEF_OP(DW_OP_HP_unmod_range);
        DEF_OP(DW_OP_HP_tls);
        DEF_OP(DW_OP_INTEL_bit_piece);
        //DEF_OP(DW_OP_APPLE_uninit);
        DEF_OP(DW_OP_PGI_omp_thread_num);
        DEF_OP(DW_OP_hi_user);
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

#define DEF_OP(a)    \
    case a:          \
        result = #a; \
        break;

    switch(op)
    {
        DEF_OP(EPOLL_CTL_ADD);
        DEF_OP(EPOLL_CTL_MOD);
        DEF_OP(EPOLL_CTL_DEL);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualEventFdFlags
-----------------------------------------------------------------------------*/
const char* getTextualEventFdFlags(int flags)
{
    const char* result = "(unknown)";

#define DEF_EFD(a)   \
    case a:          \
        result = #a; \
        break;

    switch(flags)
    {
        DEF_EFD(EFD_CLOEXEC);
        DEF_EFD(EFD_NONBLOCK);
        DEF_EFD(EFD_SEMAPHORE);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualXattrFlags
-----------------------------------------------------------------------------*/
const char* getTextualXattrFlags(int flags)
{
    const char* result = "(unknown)";

#define DEF_XATTRFLAG(a) \
    case a:              \
        result = #a;     \
        break;

    switch(flags)
    {
        DEF_XATTRFLAG(XATTR_CREATE);
        DEF_XATTRFLAG(XATTR_REPLACE);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualTimerType
-----------------------------------------------------------------------------*/
const char* getTextualTimerType(int type)
{
    const char* result = "(unknown)";

#define DEF_TIMERTYPE(a) \
    case a:              \
        result = #a;     \
        break;

    switch(type)
    {
        DEF_TIMERTYPE(CLOCK_REALTIME);
        DEF_TIMERTYPE(CLOCK_MONOTONIC);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualSyslogAction
-----------------------------------------------------------------------------*/
const char* getTextualSyslogAction(int action)
{
    const char* result = "(unknown)";

#define DEF_ACTION(a) \
    case a:           \
        result = #a;  \
        break;

    switch(action)
    {
        DEF_ACTION(SYSLOG_ACTION_CLOSE);
        DEF_ACTION(SYSLOG_ACTION_OPEN);
        DEF_ACTION(SYSLOG_ACTION_READ);
        DEF_ACTION(SYSLOG_ACTION_READ_ALL);
        DEF_ACTION(SYSLOG_ACTION_READ_CLEAR);
        DEF_ACTION(SYSLOG_ACTION_CLEAR);
        DEF_ACTION(SYSLOG_ACTION_CONSOLE_OFF);
        DEF_ACTION(SYSLOG_ACTION_CONSOLE_ON);
        DEF_ACTION(SYSLOG_ACTION_CONSOLE_LEVEL);
        DEF_ACTION(SYSLOG_ACTION_SIZE_UNREAD);
        DEF_ACTION(SYSLOG_ACTION_SIZE_BUFFER);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualFileType
-----------------------------------------------------------------------------*/
const char* getTextualFileType(int type)
{
    const char* result = "(unknown)";

#define DEF_TYPE(a) \
    case a:           \
        result = #a;  \
        break;

    switch(type)
    {
		DEF_TYPE(FT_UNKNOWN);
		DEF_TYPE(FT_REGULAR);
		DEF_TYPE(FT_PIPE_BLOCKING);
		DEF_TYPE(FT_PIPE_NON_BLOCKING);
		DEF_TYPE(FT_SOCKET_BLOCKING);
		DEF_TYPE(FT_SOCKET_NON_BLOCKING);
		DEF_TYPE(FT_POLL_BLOCKING);
		DEF_TYPE(FT_POLL_NON_BLOCKING);
		DEF_TYPE(FT_SPECIAL);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    getTextualTimerFlags
-----------------------------------------------------------------------------*/
std::string getTextualTimerFlags(int flags)
{
    std::string result;

    TEST_FLAG(flags, TFD_NONBLOCK, result);
    TEST_FLAG(flags, TFD_CLOEXEC,  result);

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

    TEST_FLAG(mode, S_IRUSR, result);
    TEST_FLAG(mode, S_IWUSR, result);
    TEST_FLAG(mode, S_IXUSR, result);
    TEST_FLAG(mode, S_IRGRP, result);
    TEST_FLAG(mode, S_IWGRP, result);
    TEST_FLAG(mode, S_IXGRP, result);
    TEST_FLAG(mode, S_IROTH, result);
    TEST_FLAG(mode, S_IWOTH, result);
    TEST_FLAG(mode, S_IXOTH, result);

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
    std::string result = "";

    switch(addr->sa_family)
    {
        case AF_INET:
        case AF_INET6:
        {
            char tmp[50];
            inet_ntop(addr->sa_family, &((struct sockaddr_in*)addr)->sin_addr, tmp, 50);
            result = std::string(tmp);
            break;
        }
        case AF_FILE:
        {
            result = std::string(((struct sockaddr_un*)addr)->sun_path);
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
