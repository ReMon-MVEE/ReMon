/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_LOGGING_H_INCLUDED
#define MVEE_LOGGING_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sched.h>
#include <string>
#include "MVEE_build_config.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Logging Prototypes
-----------------------------------------------------------------------------*/
#define LOCALLOGNAME         "%s/Logs/MVEE_%d.log"
#define LOGDIR               "./Logs/"
#define LOGNAME              "./Logs/MVEE.log"
#define NON_INSTRUMENTED_LOGNAME                                                                                       \
                             "./Logs/non-instrumented.csv"
#define PTRACE_LOGNAME       "./Logs/MVEE_ptrace.log"
#define DATATRANSFER_LOGNAME "./Logs/MVEE_datatransfer.log"
#define LOCKSTATS_LOGNAME    "./Logs/MVEE_lockstats.log"
#define SIG_LOGNAME          "./Logs/MVEE_sig.log"

/*-----------------------------------------------------------------------------
    Logging String Helpers
-----------------------------------------------------------------------------*/
//
// Functions for converting numeric identifiers to text
//
const char* getTextualState             (unsigned int dwState);
const char* getTextualSig               (unsigned int dwSignal);
const char* getTextualSigHow            (int how);
const char* getTextualPtraceRequest     (unsigned int dwRequest);
const char* getTextualProcmaskRequest   (int how);
const char* getTextualSyscall           (long int syscallnum);
const char* getTextualSocketCall        (long int sockcallnum);
const char* getTextualSocketFamily      (long int family);
const char* getTextualSocketProtocol    (long int proto);
const char* getTextualSocketShutdownHow (long int how);
const char* getTextualSEGVCode          (int code);
const char* getTextualFcntlCmd          (int cmd);
const char* getTextualFlockType         (unsigned int type);
const char* getTextualKernelError       (int err);
const char* getTextualFutexOp           (int op);
const char* getTextualAtomicType        (int lock_type);
const char* getTextualBreakpointType    (int bp_type);
const char* getTextualBufferType        (int buffer_type);
const char* getTextualRlimitType        (int rlimit);
const char* getTextualAllocType         (int alloc_type);
const char* getTextualAllocResult       (int alloc_type, int alloc_result);
const char* getTextualDWARFReg          (int reg);
const char* getTextualDWARFOp           (int op);
const char* getTextualDWARFConstant     (int constant);
const char* getTextualEpollFlags        (int flags);
const char* getTextualEpollOp           (int op);
const char* getTextualEventFdFlags      (int flags);
const char* getTextualXattrFlags        (int flags);
const char* getTextualTimerType         (int type);
const char* getTextualSyslogAction      (int action);
const char* getTextualFileType          (int type);
const char* getTextualRAVENCall         (int fd);
const char* getTextualErrno             (int err);
const char* getTextualIntervalTimerType (int which);
const char* getTextualArchPrctl         (int code);
const char* getTextualRusageWho         (int who);
const char* getTextualQuotactlType      (int type);
const char* getTextualQuotactlCmd       (int cmd);
const char* getTextualQuotactlFmt       (unsigned long fmt);
const char* getTextualPriorityWhich     (int which);
const char* getTextualSchedulingPolicy  (int policy);
const char* getTextualInotifyFlags      (int flags);
const char* getTextualMremapFlags       (int flags);
std::string getTextualTimerFlags        (int flags);
std::string getTextualWaitEventType     (int status);
std::string getTextualEpollEvents       (unsigned int events);
std::string getTextualFileFlags         (int flags);
std::string getTextualFileMode          (int mode);
std::string getTextualAccessMode        (int mode);
std::string getTextualProtectionFlags   (int mode);
std::string getTextualCloneFlags        (unsigned int flags);
std::string getTextualMapType           (int mode);
std::string getTextualSigSet            (sigset_t set);
std::string getTextualPollRequest       (int events);
std::string getTextualMSyncFlags        (int flags);
std::string getTextualCPUSet            (cpu_set_t* set);
std::string getTextualSocketType        (long int type);
std::string getTextualSocketAddr        (struct sockaddr* addr);
std::string getTextualSocketMsgFlags    (long int flags);
std::string getTextualGroupId           (int gid);
std::string getTextualUserId            (int uid);
std::string getTextualGroups            (int cnt, gid_t* gids);
std::string getTextualSigactionFlags    (unsigned int flags);
std::string getTextualPerfFlags         (unsigned long flags);
std::string getTextualShmFlags          (unsigned long flags);
std::string getTextualShmctlFlags       (unsigned long cmd)
std::string getTextualInotifyMask       (unsigned long mask);
std::string getTextualUnlinkFlags       (int flags);
std::string getTextualLinkFlags         (int flags);
std::string getTextualChmodFlags        (int flags);
std::string getTextualMVEEWaitStatus    (interaction::mvee_wait_status& status);
std::string getTextualIpcShmKey         (key_t key);
std::string getTextualIpcShmFlags       (int shmflg);
std::string getTextualFallocateFlags    (int mode);
std::string getTextualRandFlags         (unsigned int mode);
std::string getTextualMemfdFlags        (unsigned int flags);

#endif // MVEE_LOGGING_H_INCLUDED
