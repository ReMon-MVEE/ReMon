/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/* ------------------------> SIGNALS FUCKING SUCK!!! <----------------------

   GHUMVEE can deliver signal in one of three ways:
   1) if the signal is synchronous (i.e. a direct consequence of the control
   flow), the signal is delivered right away at the "signal-delivery-stop"
   point (cfr. ptrace man page).

   2) if the signal is asynchronous, GHUMVEE will always deny the delivery of
   the initial signal at the "signal-delivery-stop" point by using
   ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

   The kernel will discard the pending signal because we use NULL as the 4th
   argument here. GHUMVEE does however cache _all_ of the signal's information.
   It then waits for a rendez-vous point.

   2.1) if the first rendez-vous point is the return site of an interrupted
   sys_[rt_]sigsuspend call, GHUMVEE will first restart the call and at the NEXT
   rendez-vous point (i.e. the entry site of the restarted call), GHUMVEE
   will send the signal using sys_tgkill. The sigsuspend call will then
   once again be interrupted, but this time we DO want to inject the signal
   so GHUMVEE will inject the signal using:
   ptrace(PTRACE_SYSCALL, pid, NULL, sig);

   We do ofcourse have to adjust the sender PID of the signal before the final
   injection.

   2.2) if the first rendez-vous point is the entry of any other syscall,
   we make a backup of the variants's contexts, skip the syscall by replacing
   the syscall no by __NR_getpid an then transfer the control to the infinte
   loop function in GHUMVEE's eglibc.

   While in the infinite loop, we can let the variants run freely while we
   send the signal using sys_tgkill and inject it when the variants are in
   signal-delivery-stop.

Consequently, when we see the sys_[rt_]sigreturn, our course of action depends
on how the signal was delivered:

   1) If the signal was synchronous, we must not alter the context at all.

   2) If the signal was delivered at the sigsuspend entry site, we must not
   alter the context but we do have to ensure that we invoke the sigsuspend
   POSTCALL handler on the first syscall-stop event after the sigreturn dispatch.

   3) If the signal was asynchronous and not delivered at the sigsuspend entry
   site, we must dispatch the sigreturn call and restore the initial context.
 */

#include <signal.h>
#include <string.h>
#include "MVEE.h"
#include "MVEE_signals.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_syscalls.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
    sighand_table class
-----------------------------------------------------------------------------*/
void sighand_table::init()
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&sighand_lock, &attr);
}

sighand_table::sighand_table()
{
    init();
    memset(&action_table, 0, sizeof(struct sigaction) * (_NSIG - 1));
}

sighand_table::sighand_table(const sighand_table& parent)
{
    init();
    for (int i = 0; i < _NSIG-1; ++i)
        memcpy(&action_table[i], &parent.action_table[i], sizeof(struct sigaction));
}

/*-----------------------------------------------------------------------------
    grab_lock
-----------------------------------------------------------------------------*/
void sighand_table::grab_lock()
{
    pthread_mutex_lock(&sighand_lock);
}

/*-----------------------------------------------------------------------------
    release_lock
-----------------------------------------------------------------------------*/
void sighand_table::release_lock()
{
    pthread_mutex_unlock(&sighand_lock);
}

/*-----------------------------------------------------------------------------
    full_release_lock
-----------------------------------------------------------------------------*/
void sighand_table::full_release_lock()
{
    while (sighand_lock.__data.__owner == syscall(__NR_gettid))
        release_lock();
}

/*-----------------------------------------------------------------------------
    is_control_flow_signal - Returns true if the given signal is a
    synchronous signal that was probably caused by the normal control flow of
    the variants themselves.
-----------------------------------------------------------------------------*/
bool sighand_table::is_control_flow_signal(int sig)
{
    switch (sig)
    {
        case SIGILL:
        case SIGABRT:
        case SIGFPE:
        case SIGSEGV:
        case SIGPIPE:
        case SIGBUS:
        case SIGSYS:
        case SIGSETXID:
            return true;
    }
    return false;
}

/*-----------------------------------------------------------------------------
    is_default_ignored_signal - check if the default action for the specified
    signal is SIG_IGN
-----------------------------------------------------------------------------*/
bool sighand_table::is_default_ignored_signal (int signo)
{
    if (signo == SIGCHLD
        || signo == SIGWINCH
        || signo == SIGURG
        || signo == SIGCLD)
        return true;
    return false;
}

/*-----------------------------------------------------------------------------
    reset - resets dispositions of handled signals
-----------------------------------------------------------------------------*/
void sighand_table::reset()
{
    for (int i = 0; i < _NSIG-1; ++i)
    {
        if (action_table[i].sa_handler
            && action_table[i].sa_handler != SIG_IGN)
        {
            action_table[i].sa_handler = SIG_DFL;
        }
    }
}

/*-----------------------------------------------------------------------------
    set_sigaction - Set a new sigaction for the specified signal

    @param signum     Signal number
-----------------------------------------------------------------------------*/
void sighand_table::set_sigaction(int signum, struct sigaction* action)
{
    debugf("sighandler changed for sig: %s\n", getTextualSig(signum));
    mvee::log_sigaction(action);

    if (signum >= 0 && signum < _NSIG-1)
        memcpy(&action_table[signum], action, sizeof(struct sigaction));
}
