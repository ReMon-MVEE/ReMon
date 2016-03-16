/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

#ifndef MVEE_PRIVATE_H_INCLUDED
#define MVEE_PRIVATE_H_INCLUDED

/*-----------------------------------------------------------------------------
  Includes
-----------------------------------------------------------------------------*/
#include <sys/user.h>
#include <stddef.h>
#include <stdio.h>
#include <signal.h>
#include <memory>
#include <vector>
#include <deque>
#include "MVEE_config.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
    Typedefs
-----------------------------------------------------------------------------*/
typedef long (monitor:: *mvee_syscall_handler)(int);

/*-----------------------------------------------------------------------------
  Constants
-----------------------------------------------------------------------------*/
#define O_FILEFLAGSMASK                    (O_LARGEFILE | O_RSYNC | O_DSYNC | O_NOATIME | O_DIRECT | O_ASYNC | O_FSYNC | O_SYNC | O_NDELAY | O_NONBLOCK | O_APPEND | O_TRUNC | O_NOCTTY | O_EXCL | O_CREAT | O_ACCMODE)
#define S_FILEMODEMASK                     (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)
#define MAP_MVEE_WASSHARED                 0x800000
#define MVEE_FUTEX_WAIT_TID                30
#define PR_REGISTER_IPMON                  0xb00b135

#define NO_MVEE_SCHEDULING                 0                        // mvee won't pin any threads
#define MVEE_CLEVER_SCHEDULING             1 

#ifndef PTRACE_GETSIGMASK
 #define PTRACE_GETSIGMASK                 (__ptrace_request)0x420a // new since Linux 3.11
#endif
#ifndef PTRACE_SETSIGMASK
 #define PTRACE_SETSIGMASK                 (__ptrace_request)0x420b // new since Linux 3.11
#endif

/*-----------------------------------------------------------------------------
  Enumerations
-----------------------------------------------------------------------------*/
enum MonitorState
{
    STATE_WAITING_ATTACH,                                           // Waiting to attach to the newly created childs
    STATE_WAITING_RESUME,                                           // We use PTRACE_O_TRACE[FORK|VFORK|CLONE] so new childs are started with SIGSTOP
    STATE_NORMAL,                                                   // Normal operation
    STATE_IN_SYSCALL,                                               // Waiting for syscall to return
    STATE_IN_FORKCALL,                                              // Waiting for forkcall to return
    STATE_IN_MASTERCALL                                             // Waiting for mastercall to return
};

enum ArgType
{
    ARG_CSTRING,
    ARG_STRING,
    ARG_BUFFER,
};

/*-----------------------------------------------------------------------------
  Classes
-----------------------------------------------------------------------------*/
//
// Forward decls
//
class resolved_instruction;
class dwarf_info;
class mmap_addr2line_proc;
class mvee_dwarf_context;
class mmap_region_info;
class mmap_table;
class _shm_info;
class shm_table;
class fd_info;
class fd_table;
class sighand_table;
class writeback_info;

struct hidden_buffer_array_entry
{
	void*         hidden_buffer_address;
	unsigned long hidden_buffer_size;
	char          padding[64 - sizeof(void*) - sizeof(unsigned long)];
};

class mvee_pending_signal
{
public:
    // could also be read from sig_info
    unsigned short sig_no;
    // keeps track of which childs have received the signal (signals originating
    // from within the process need to be received by EVERY child before they can be delivered)
    unsigned short sig_recv_mask;
    // exact copy of the siginfo_t the child would have received natively
    siginfo_t      sig_info;
};

class child_arg
{
public:
    ArgType     type;
    void*       buf;
    char*       cstr;
    std::string str;
    bool        valid;

    child_arg();
    ~child_arg();
    void reset();
    void set_buf(void* b);
    void set_cstr(char* c);
    void set_str(std::string& s);
};

// might have to optimize the layout even further for better cache performance
// the user_regs struct is quite large, especially on AMD64...
class childstate
{
public:
	VariantArch   arch;                                             // 
    pid_t         childpid;                                         // Process ID of this child
    long          prevcallnum;                                      // Previous system call executed by the child. Set when the call returns.
    long          callnum;                                          // System call number being executed by this child.
    int           call_flags;                                       // Result of the call handler
    struct user_regs_struct
                  regs;                                             // Arguments for the syscall are copied into the childstate just before entering the call
    child_arg     args[7];                                          // Cached arguments
    long          return_value;                                     // Return of the current syscall. Retrieved using PTRACE_PEEKUSER
    long          extended_value;                                   // Extended value to be returned through the EAX register.

    unsigned char call_type;                                        // Type of the current system call, i.e. synced/unsynced/unknown
    bool          call_dispatched;                                  // has the current call been dispatched yet?
    bool          regs_valid;                                       // Are the regs up to date?
    bool          return_valid;                                     // Is the return value up to date?
    bool          restarted_syscall;                                // Did we restart the current syscall? Might happen if a signal has arrived while the child was in the middle of a blocking syscall
    bool          restarting_syscall;
    bool          child_terminated;                                 // Was the child terminated?
    bool          child_pending;                                    // child is waiting to be resumed just after fork/vfork/clone
    bool          child_attached;                                   // has the target monitor attached to this child yet?
    bool          child_resumed;                                    // child is waiting for a resume after attach
    bool          current_signal_ready;

    // ptmalloc2 heap allocation hacks
    //
    // The new_heap function in eglibc-2.x/malloc/arena.c will either extend
    // an existing heap or allocate a new HEAP_MAX_SIZE sized heap.
    // In the latter case, ptmalloc requires that the new heap is not only
    // HEAP_MAX_SIZE bytes large but it must also be aligned to a
    // HEAP_MAX_SIZE boundary. Since mmap2 is unable to satify such requirements,
    // ptmalloc will always allocate a block of HEAP_MAX_SIZE * 2 bytes. It will
    // then unmap the region below the HEAP_MAX_SIZE boundary (if any) and unmap
    // the region beyond the next HEAP_MAX_SIZE boundary.
    //
    // With ASLR enabled, some variants might have a lower region while some
    // may not. Moreover, we should assume that the size of the upper region
    // will be different for every variant.
    //
    unsigned long last_lower_region_start;
    unsigned long last_lower_region_size;
    unsigned long last_upper_region_start;
    unsigned long last_upper_region_size;
    unsigned long last_mmap_result;

	// IP-MON information
	mmap_region_info* ipmon_region;

	// Hidden buffer support
	int           hidden_buffer_array_id;                           // SysV shm id for the hidden buffer array
	unsigned long hidden_buffer_array_base;                         // base address at which the hidden buffer array is mapped in this child
	void*         hidden_buffer_array;                              // pointer to the monitor mapped version of the hidden buffer array

    // somehow, the sigset gets corrupted across sigprocmask calls...
    sigset_t      last_sigset;

    // Occasionally used vars...
    pid_t         childtgid;                                        // Thread Group ID of this child
    pid_t         pendingpid;                                       // Process ID of the newly created process/thread
    unsigned long infinite_loop_ptr;                                // pointer to the sys_pause loop
    unsigned long should_sync_ptr;                                  // pointer to the should_sync flag
    long          callnumbackup;                                    // Backup of the syscall num. Made when the monitor is delivering a signal
    struct user_regs_struct
                  regsbackup;                                       // Backup of the registers. Made when the monitor is delivering a signal
    unsigned long hw_bps[4];                                        // currently set hardware breakpoints
    unsigned char hw_bps_type[4];                                   // type of hw bp. 0 = exec only, 1 = write only, 2 = I/O read/write, 3 = data read/write but no instr fetches
    void*         tid_address[2];                                   // optional pointers to the thread id
    size_t        orig_controllen;                                  // for recvmsg
#ifdef __NR_socketcall
    unsigned long orig_arg1;                                        // for sys_socketcall
#endif
#ifdef MVEE_CHECK_SYNC_PRIMITIVES
    int           sync_primitives_bitmask;                          // copied over from the child using sync_primitives_ptr
    void*         sync_primitives_ptr;                              //
#endif
#ifdef MVEE_ALLOW_PERF
    std::string   perf_out;                                         //
#endif

    childstate();
};

//
// Per-monitor state
//
class monitor
{
public:
    //
    // Public interface for the MVEE logger
    //
    bool is_logging_enabled                  ();
    bool is_group_shutting_down              ();
    void log_monitor_state_short             (int err);

    //
    // Public interface for the MVEE monitor management
    //
    void  signal_shutdown                     ();
    void  signal_registration                 ();
    std::vector<pid_t>
          getpids                             ();
    void  join_thread                         ();
    pid_t get_mastertgid                      ();
    void  set_should_check_multithread_state  ();

	// 
	// Scheduling support
	// 
	int   get_master_core                     ();

    //
    // Public variables for the MVEE logger
    //
    FILE* monitor_log;                                              // we now have each monitor log to the global log (MVEE.log) as well as its own log (MVEE_<id>.log)
    int   monitorid;                                                // Identifier for this set of equivalent forked processes

    //
    // System Call Handlers
    //
    long handle_donthave                     (int childnum);
    long handle_dontneed                     (int childnum);
    #include "MVEE_syscall_handler_prototypes.h"

    //
    // Constructors
    //
    monitor(std::vector<pid_t>& pids, std::vector<VariantArch>& archs);
    monitor(monitor* parent_monitor, bool shares_fd_table=false, bool shares_mmap_table=false, bool shares_sighand_table=false, bool shares_tgid=false);
    ~monitor();

private:

    //
    // Main monitor thread
    //
    static void* thread                              (void* param);

    //
    // System call support (these are all in MVEE_syscalls_support.cpp)
    // These functions mostly support the MVEE<->variant datatransfers
    //
    void             call_check_regs                     (int childnum);
    bool             call_check_result                   (long int result);
    bool             call_postcall_all_syscalls_succeeded();
    long             call_postcall_get_child_result      (int childnum);
    void             call_postcall_set_child_result      (int childnum, unsigned long result);
    std::vector<unsigned long>
                     call_postcall_get_result_vector     ();
    bool             call_compare_child_strings          (std::vector<unsigned long>& stringptrs, size_t maxlength=0);
    bool             call_compare_child_buffers          (std::vector<unsigned long>& bufferptrs, size_t size);
    bool             call_compare_wait_pids              (std::vector<pid_t>& pids);
    bool             call_compare_signal_handlers        (std::vector<unsigned long>& handlers);
    bool             call_compare_sigactions             (std::vector<unsigned long>& handlers, std::vector<unsigned long>& sa_flags);
    bool             call_compare_sigsets                (sigset_t* set1, sigset_t* set2);
    unsigned char    call_compare_pointers               (std::vector<unsigned long>& pointers);
    bool             call_compare_io_vectors             (std::vector<unsigned long>& addresses, size_t len, bool layout_only=false);
    bool             call_compare_msgvectors             (std::vector<unsigned long>& addresses, bool layout_only=false);
	bool             call_compare_fd_sets                (std::vector<unsigned long>& addresses, int nfds);
    std::string      call_serialize_io_vector            (int childnum, struct iovec* vec, unsigned int vecsz);
    std::string      call_serialize_msgvector            (int childnum, struct msghdr* msg);
    std::string      call_serialize_io_buffer            (int childnum, unsigned long buf, unsigned long buflen);
    void             call_replicate_io_vector            (std::vector<unsigned long>& addresses, long bytes_copied);
    void             call_replicate_msgvector            (std::vector<unsigned long>& addresses, long bytes_sent);
    void             call_replicate_mmsgvector           (std::vector<unsigned long>& addresses, int vlen);
    void             call_replicate_mmsgvectorlens       (std::vector<unsigned long>& addresses, int sent, int attempted);
    void             call_replicate_buffer               (std::vector<unsigned long>& addresses, int size);
    sigset_t         call_get_sigset                     (int childnum, unsigned long sigset_ptr, bool is_old_call);
    struct sigaction call_get_sigaction                  (int childnum, unsigned long sigaction_ptr, bool is_old_call);
    struct sockaddr* call_get_sockaddr                   (int childnum, unsigned long ptr, socklen_t addr_len);

    //
    // Specific Syscall handlers (these are all in MVEE_syscalls_handlers.cpp)
    //
    bool        handle_is_known_false_positive      (const char* program_name, long callnum, long* precall_flags);
    long        handle_check_open_call              (const std::string& full_path, int* flags, int mode);
    void        handle_execve_get_args              (int childnum);
    static bool handle_munmap_precall_callback      (mmap_table* table, std::vector<mmap_region_info*>& infos, void* mon);

    //
    // Generic Syscall handlers (these are in MVEE_syscalls.cpp)
    //
    unsigned char call_is_known_false_positive        (long* precall_flags);
    void          call_resume_all                     ();
    void          call_resume_fake_syscall            ();
    unsigned char call_precall_get_call_type          (int childnum, long callnum);
    long          call_precall                        ();
    long          call_call_dispatch_unsynced         (int childnum);
    long          call_call_dispatch                  ();
    long          call_postcall_return_unsynced       (int childnum);
    long          call_postcall_return                ();
    void          call_shift_args                     (int childnum, int cnt);
    void          call_grab_locks                     (unsigned char syslocks);
    void          call_release_locks                  (unsigned char syslocks);
    void          call_grab_syslocks                  (int childnum, unsigned long callnum, unsigned char which);
    void          call_release_syslocks               (int childnum, unsigned long callnum, unsigned char which);
    void          call_wait_all                       ();
    void          call_execute_synced_call            (bool at_syscall_exit, unsigned long callnum, std::vector<std::deque<unsigned long> >& call_args);

    //
    // Event handling
    //
    void handle_signal_event                 (int index, int status);
    bool handle_rdtsc_event                  (int index);
    void handle_trap_event                   (int index);
    void handle_fork_event                   (int index, int event);
    void handle_syscall_entrance_event       (int index);
    void handle_syscall_exit_event           (int index);
    void handle_syscall_event                (int index);
    void handle_exit_event                   (int index);
    void handle_attach_event                 (int index, int status);
    void handle_resume_event                 (int index);
    void handle_detach_event                 (pid_t childpid, int status);
    void handle_event                        (pid_t childpid, int status);

    //
    // Signal specific event handling
    //
    std::vector<mvee_pending_signal>::iterator discard_pending_signal              (std::vector<mvee_pending_signal>::iterator& it);
    void                                       handle_sig_delivery_stop            (int index, int status);
    bool                                       sig_prepare_delivery                ();
	bool                                       sig_handle_sigchld_race             (std::vector<mvee_pending_signal>::iterator it);
    void                                       sig_finish_delivery                 ();
    void                                       sig_return_from_sighandler          ();
    void                                       sig_restart_syscall                 (int childnum);
    void                                       sig_restart_partially_interrupted_syscall();
	void                                       sig_set_pending_signals             (bool pending_signals);
	bool                                       in_ipmon                            (int childnum, unsigned long ip);
	bool                                       in_ipmon_syscall                    (int childnum, unsigned long ip);

    //
    // Hardware breakpoint support
    //
    void hwbp_refresh_regs              (int childnum);
    bool hwbp_set_watch                 (int childnum, unsigned long addr, unsigned char bp_type);
    bool hwbp_unset_watch               (int childnum, unsigned long addr);

    //
    // Logging/Backtracing functions
    //
    void log_init                        ();
    void log_fini                        ();
    void log_child_backtrace             (int childnum, int max_depth=0, int calculate_file_offsets=0, int is_segfault=0);
    void log_caller_info                 (int childnum, int level, unsigned long address, int calculate_file_offsets=0, void (*logfunc)(const char*, ...)=NULL);
    void log_monitor_state               (void (*logfunc)(const char* format, ...)=NULL);
    void log_monitor_state_live          ();
    void log_backtraces                  ();
    void log_dump_queues                 (shm_table* shm_table);
    void log_unhandled_sig               (int status, int index);
    void log_call_mismatch               (int index1, int index2);
    void log_callargs_mismatch           ();
    void log_segfault                    (int childnum);
    void log_hw_bp_event                 (int childnum, siginfo_t* sig);
    void log_ipmon_state                 ();
	void log_calculate_clock_spread      ();
	void log_stack(int childnum);

    //
    // Initializing new children
    //
    int         init_ptrace_options             (int childnum);
    void        init_child                      (int childnum, pid_t childpid, pid_t childtgid, VariantArch arch);
    bool        restart_child                   (int childnum);
    static void serialize_and_relocate_arr      (std::deque<char*>& arr, char*& serialized, char**& relocated, unsigned long target_address);
    std::deque<char*>
                get_original_argv               ();

    //
    // Monitor startup/shutdown
    //
    void shutdown                            (bool success);
    void await_pending_transfers         ();
    void init();
	void schedule_threads();

    //
    // Functions for dynamic toggling of the synchronization replication algorithm
    //
    void enable_sync                     ();
    void disable_sync                    ();
    bool is_program_multithreaded        ();
    void check_multithread_state         ();

	// 
	// Hidden buffer support
	//
	void register_hidden_buffer          (int buffer_id, _shm_info* info, std::vector<unsigned long>& addresses);

    //
    // Debugging support
    //
    void update_sync_primitives          ();

    //
    // Syscall handler tables
    //
    static const mvee_syscall_handler syscall_handler_table[MAX_CALLS][4];
    static const mvee_syscall_handler syscall_logger_table[MAX_CALLS][2];

    //
    // Variables
    //
    pthread_t                         monitor_thread;
    pthread_mutex_t                   monitor_lock;
    pthread_cond_t                    monitor_cond;

    bool                              created_by_vfork;
    bool                              should_check_multithread_state;
    bool                              should_shutdown;        // set by the management thread
    bool                              call_succeeded;         // Set by the postcall handler when a synced call has succeeded
    bool                              in_new_heap_allocation; // are we inside the new_heap function in ptmalloc/arena.c ?
    bool                              monitor_registered;
    bool                              monitor_terminating;
    bool                              have_pending_signals;
    bool                              ipmon_initialized;

    int                               parentmonitorid;        // monitorid of the monitor that created this monitor...
    MonitorState                      state;                  //
    std::shared_ptr<fd_table>
                                      set_fd_table;           // File descriptor table for this thread set. Might be shared with a parent thread set
    std::shared_ptr<mmap_table>
                                      set_mmap_table;         // Mmap table for this thread set. Might be shared with a parent thread set
    std::shared_ptr<shm_table>
                                      set_shm_table;          // Shared memory segments table for this thread set. Usually shared with a parent thread set...
    std::shared_ptr<sighand_table>
                                      set_sighand_table;      //
    std::vector<writeback_info>
                                      writeback_infos;        // temporary buffers for munmap
    std::vector<pid_t>                local_detachlist;       // pids of childs that we haven't detached from yet...
    std::vector<pid_t>                unknown_childs;         // pids of childs we've received events from but don't know yet
    _shm_info*                        atomic_buffer;          // thread-local atomic buffer
    std::vector<void*>                atomic_counters;
    std::vector<void*>                atomic_queue_pos;
	bool                              atomic_buffer_hidden;   // should we hide the pointer to the atomic buffer in the hidden buffer array?

    _shm_info*                        ipmon_buffer;

    // Signal info
    unsigned short                    current_signal;         // signal no for the signal we're currently delivering
    unsigned short                    current_signal_sent;    //
    siginfo_t*                        current_signal_info;    // siginfo for the signal we're currently delivering
    std::vector<mvee_pending_signal>
                                      pending_signals;
    std::vector<childstate>
                                      childs;                 // State for all child processes being traced by this monitor
#ifdef MVEE_ALLOW_PERF
    bool                              perf;                   // is this monitor tracking the perf process
#endif

    pid_t                             monitor_tid;

    // set of signals which are currently blocked for this thread set.
    // Blocked signals are added to the pending queue and must be delivered
    // when and if the signal is every unblocked. Duplicates must be discarded
    sigset_t                          blocked_signals;
    // previous set of signals which were blocked. this is used for calls
    // that temporarily replace the signal mask (e.g. sigsuspend)
    sigset_t                          old_blocked_signals;

	int master_core;
};

class detachedchild
{
public:
    pid_t         childpid;                                   //
    monitor*      new_monitor;                                //
    int           parentmonitorid;                            // id of the monitor this child was detached from
    int           parent_has_detached;                        //
    struct user_regs_struct
                  original_regs;                              // original contents of the registers
    unsigned long transfer_func;                              // pointer to the sys_pause loop
    void*         tid_address[2];                             // set if we should tell the child what its thread id is (e.g. if the child was created by clone(CLONE_CHILD_SETTID)
};

// Passed to sys_ptrace through the data field
struct pt_copymem
{
    pid_t         source_pid;                                 // PID of the source process
    unsigned long source_va;                                  // Virtual Address of the source buffer
    pid_t         dest_pid;                                   // PID of the destination process
    unsigned long dest_va;                                    // Virtual Address of the destination buffer
    unsigned long copy_size;                                  //
};

// Passed to sys_ptrace through the data field
struct pt_copystring
{
    unsigned long source_va;                                  // Virtual Address of the source string
    unsigned long dest_buffer_va;                             // Virtual Address of the destination buffer
    unsigned long dest_buffer_size;                           // Size of the destination buffer - if the source string doesn't fit in here, an error is returned
    unsigned long out_string_size;                            // The kernel will write the string size here
};

// If our glibc is compiled with MVEE_DEBUG_MALLOC, slave replicae will pass an mvee_malloc_error
// struct to the monitor whenever they detect a divergence in malloc behavior
struct mvee_malloc_error
{
    int   alloc_type;                                         // type of allocation. See mvee_libc_alloc_types enum
    int   msg;                                                // message identifier. See getTextualAllocResult function in MVEE_logging_strings.cpp
    long  chunksize;                                          // size of the allocated chunk
    void* ar_ptr;                                             // pointer to the arena we're operating in
    void* chunk_ptr;                                          // pointer to the allocated chunk
};

struct ipmon_barrier
{
	union
	{
		struct
		{
			unsigned short seq;
			unsigned char count;         // nr of variants that have reached the barrier
			unsigned char padding;
		} s;
		unsigned int hack;
	} u;
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
		} s;
		unsigned int hack; 
	} u;
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

struct ipmon_syscall_data
{
	unsigned long len;
	unsigned char data[1];
};

struct ipmon_variant_info
{
	unsigned int  pos;
	unsigned int  status;
	unsigned char padding[64 - 2 * sizeof(unsigned int)];
};

struct ipmon_buffer
{
	// Cacheline 0
	int           ipmon_numvariants;                        // 00-04: number of variants we're running with
	unsigned int  ipmon_usable_size;                        // 04-08: size that is usable for syscall entries
	unsigned long ipmon_have_pending_signals;
	unsigned char ipmon_padding0[64 - sizeof(unsigned long) - sizeof(int)*2];

	// Cachelines 1-n
	struct ipmon_variant_info ipmon_variant_info[1];

	// And the actual syscall data
//	struct ipmon_syscall_entry ipmon_syscall_entry[1];
};


/*-----------------------------------------------------------------------------
  Definitions
-----------------------------------------------------------------------------*/
//
// Signal number for traps caused by syscalls (requires PTRACE_O_TRACESYSGOOD)
//
#define SIGSYSTRAP                  (SIGTRAP | 0x80)

/*-----------------------------------------------------------------------------
  HW breakpoint types
-----------------------------------------------------------------------------*/
#define MVEE_BP_EXEC_ONLY           0
#define MVEE_BP_WRITE_ONLY          1
#define MVEE_BP_READ_WRITE          2
#define MVEE_BP_READ_WRITE_NO_FETCH 3

/*-----------------------------------------------------------------------------
  Trap codes
-----------------------------------------------------------------------------*/
#define MVEE_TRAP_BRKPT             (1)                       /* process breakpoint */
#define MVEE_TRAP_TRACE             (2)                       /* process trace trap */
#define MVEE_TRAP_BRANCH            (3)                       /* process taken branch trap */
#define MVEE_TRAP_HWBKPT            (4)                       /* hardware breakpoint/watchpoint */

/*-----------------------------------------------------------------------------
  Kernel Errors
-----------------------------------------------------------------------------*/
#define ERESTARTSYS                 512
#define ERESTARTNOINTR              513
#define ERESTARTNOHAND              514                       /* restart if no handler.. */
#define ENOIOCTLCMD                 515                       /* No ioctl command */
#define ERESTART_RESTARTBLOCK       516                       /* restart by calling sys_restart_syscall */

/* Defined for the NFSv3 protocol */
#define EBADHANDLE                  521                       /* Illegal NFS file handle */
#define ENOTSYNC                    522                       /* Update synchronization mismatch */
#define EBADCOOKIE                  523                       /* Cookie is stale */
#define ENOTSUPP                    524                       /* Operation is not supported */
#define ETOOSMALL                   525                       /* Buffer or request is too small */
#define ESERVERFAULT                526                       /* An untranslatable error occurred */
#define EBADTYPE                    527                       /* Type not supported by server */
#define EJUKEBOX                    528                       /* Request initiated, but will not complete before timeout */
#define EIOCBQUEUED                 529                       /* iocb queued, will get completion event */
#define EIOCBRETRY                  530                       /* iocb queued, will trigger a retry */

/*-----------------------------------------------------------------------------
    Kernel Syslog actions
-----------------------------------------------------------------------------*/
/* Close the log.  Currently a NOP. */
#define SYSLOG_ACTION_CLOSE         0
/* Open the log. Currently a NOP. */
#define SYSLOG_ACTION_OPEN          1
/* Read from the log. */
#define SYSLOG_ACTION_READ          2
/* Read all messages remaining in the ring buffer. */
#define SYSLOG_ACTION_READ_ALL      3
/* Read and clear all messages remaining in the ring buffer */
#define SYSLOG_ACTION_READ_CLEAR    4
/* Clear ring buffer. */
#define SYSLOG_ACTION_CLEAR         5
/* Disable printk's to console */
#define SYSLOG_ACTION_CONSOLE_OFF   6
/* Enable printk's to console */
#define SYSLOG_ACTION_CONSOLE_ON    7
/* Set level of messages printed to console */
#define SYSLOG_ACTION_CONSOLE_LEVEL 8
/* Return number of unread characters in the log buffer */
#define SYSLOG_ACTION_SIZE_UNREAD   9
/* Return size of the log buffer */
#define SYSLOG_ACTION_SIZE_BUFFER   10

#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

union mvee_word
{
    unsigned long  _ulong;
    long           _long;
    unsigned int   _uint;
    int            _int;
    unsigned short _ushort;
    short          _short;
    unsigned char  _uchar;
    char           _char;
    pid_t          _pid;
};

#endif // MVEE_PRIVATE_H_INCLUDED
