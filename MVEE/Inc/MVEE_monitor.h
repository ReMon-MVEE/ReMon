/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
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
#include <fcntl.h>
#include <memory>
#include <vector>
#include <deque>
#include <sstream>
#include "shared_mem_handling.h"
#include "MVEE_build_config.h"
#include "MVEE_private_arch.h"
#include "MVEE_interaction.h"
#include "MVEE_filedesc.h"
#ifdef MVEE_ARCH_USE_LIBUNWIND
#define UNW_REMOTE_ONLY
#include "libunwind-ptrace.h"
#endif

/*-----------------------------------------------------------------------------
    Typedefs
-----------------------------------------------------------------------------*/
typedef long (monitor:: *mvee_syscall_handler)(int);
typedef void (monitor:: *mvee_syscall_logger)(int);

/*-----------------------------------------------------------------------------
  Constants
-----------------------------------------------------------------------------*/
#define O_FILEFLAGSMASK                    (O_LARGEFILE | O_RSYNC | O_DSYNC | O_NOATIME | O_DIRECT | O_ASYNC | O_FSYNC | O_SYNC | O_NDELAY | O_NONBLOCK | O_APPEND | O_TRUNC | O_NOCTTY | O_EXCL | O_CREAT | O_ACCMODE)
#define S_FILEMODEMASK                     (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)
#define MAP_MVEE_WASSHARED                 0x800000
#define MVEE_FUTEX_WAIT_TID                30
#define PR_REGISTER_IPMON                  0xb00b135
#define ENOIPMON                           256

#define NO_MVEE_SCHEDULING                 0                        // mvee won't pin any threads
#define MVEE_CLEVER_SCHEDULING             1 

/*-----------------------------------------------------------------------------
  Enumerations
-----------------------------------------------------------------------------*/
enum MonitorState
{
    STATE_WAITING_ATTACH, // Waiting to attach to the newly created variants
    STATE_WAITING_RESUME, // Waiting for variants to be ready for resume
    STATE_NORMAL,         // Normal operation - variants are running and not executing a syscall
    STATE_IN_SYSCALL,     // Waiting for syscall to return
    STATE_IN_FORKCALL,    // Waiting for forkcall to return
    STATE_IN_MASTERCALL   // Waiting for mastercall to return
};

/*-----------------------------------------------------------------------------
  RAVEN Compatibility
-----------------------------------------------------------------------------*/
#define ESC_XCHECK          -1
#define ESC_XCHECK_VALUES_ONLY      -2
#define ESC_FUTEX_HACK          -10
#define ESC_ENTER_LOCK          -11
//#define ESC_LEAVE_UNLOCK        -12
#define ESC_LEAVE_LOCK          -12
#define ESC_XCHECKS_OFF         -42
#define ESC_XCHECKS_ON          -43
#define ESC_XCHECKS_OFF_LOCAL       -44
#define ESC_XCHECKS_ON_LOCAL        -45
#define ESC_VARIANT_INIT_SYNC       -100
#define ESC_VARIANT_REACTIVATE      -101 // CRIU depends on this one; please don't change it                       
#define ESC_ENABLE_SYSCALL_CHECKS   -200
#define ESC_EXECVE_FAILURE      -210
#define ESC_RINGBUFF_INIT       -300 // Ring Buffer initialization                                                 
#define ESC_RINGBUFF_DESTROY        -301 // Ring Buffer destruction        

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

struct raven_syscall_info
{
	long max_unchecked_syscalls;
	long unchecked_syscalls[1];
};

class mvee_pending_signal
{
public:
    // could also be read from sig_info
    unsigned short sig_no;
    // keeps track of which variants have received the signal (signals
    // originating from within the process need to be received by EVERY variant
    // before they can be delivered)
    unsigned short sig_recv_mask;
    // exact copy of the siginfo_t the variant would have received natively
    siginfo_t      sig_info;
};

class overwritten_syscall_arg
{
public:
	int   syscall_arg_num; // 1 to 6
	long  arg_old_value;   // old value in the register. may be a pointer
	bool  restore_data;    // true if we also have to restore memory contents
	void* data_loc;        // location of the data that needs to be restored
	void* data_content;    // content of the data
	long  data_len;        //

	overwritten_syscall_arg();
	~overwritten_syscall_arg();
};

// might have to optimize the layout even further for better cache performance
// the user_regs struct is quite large, especially on AMD64...
class variantstate
{
public:
    pid_t         variantpid;                                       // Process ID of this variant
    long          prevcallnum;                                      // Previous system call executed by the variant. Set when the call returns.
    long          callnum;                                          // System call number being executed by this variant.
    int           call_flags;                                       // Result of the call handler
    PTRACE_REGS   regs;                                             // Arguments for the syscall are copied into the variantstate just before entering the call
    PTRACE_FPREGS fpregs;                                           // Arguments for the syscall are copied into the variantstate just before entering the call
    long          return_value;                                     // Return of the current syscall.
    long          extended_value;                                   // Extended value to be returned through the EAX register.

    unsigned char call_type;                                        // Type of the current system call, i.e. synced/unsynced/unknown
    bool          call_dispatched;                                  // has the current call been dispatched yet?
    bool          regs_valid;                                       // Are the regs up to date?
    bool          fpregs_valid;                                     // Are the fpregs up to date?
    bool          return_valid;                                     // Is the return value up to date?
    bool          restarted_syscall;                                // Did we restart the current syscall? Might happen if a signal has arrived while the variant was in the middle of a blocking syscall
    bool          restarting_syscall;
    bool          variant_terminated;                               // Was the variant terminated?
    bool          variant_pending;                                  // variant is waiting to be resumed just after fork/vfork/clone
    bool          variant_attached;                                 // has the target monitor attached to this variant yet?
    bool          variant_resumed;                                  // variant is waiting for a resume after attach
    bool          current_signal_ready;
	bool          fast_forwarding;                                  // If set to true, we are dispatching all syscalls as unsynced until the variants explicitly enable xchecks through syscall(MVEE_ENABLE_XCHECKS)
	bool          have_overwritten_args;                            // Do we have any overwritten syscall args that need to be restored?

#ifdef MVEE_ARCH_USE_LIBUNWIND
	unw_addr_space_t unwind_as;
	struct UPT_info* unwind_info;
#endif

	// 
	// RAVEN syscall check toggling support.
	//
	// Variants can call sys_write(ESC_XCHECKS_OFF, syscall_info,
	// syscall_info_size) to temporarily disable syscall checking for a set of
	// syscalls specified in the @syscall_info struct.
	//
	// sys_write(ESC_XCHECKS_ON, NULL, 0) turns syscall checking back on.
	//
	// The @syscall_info struct has the following layout:
	//
	// struct syscall_info {
	//    long max_unchecked_syscalls;
	//    long unchecked_syscalls[];
	// };
	//
	// The @syscall_info_size argument contains the size of the syscall_info
	// struct (in bytes). If the syscall_info.unchecked_syscalls[] array
	// contains 5 elements, then @syscall_info_size should be (5 + 1) *
	// sizeof(long).
	//
	// After issuing this syscall, the MVEE will temporarily disable
	// cross-checking for the issuing variant. In GHUMVEE-speak, this means that
	// we will temporarily dispatch the issuing variant's syscalls as unsynced
	// calls.
	//
	// We expect to see only the syscalls in syscall_info.unchecked_syscalls[]
	// while checking is disabled. We also expect to see no more than
	// syscall_info.max_unchecked_syscalls syscalls while checking is
	// disabled.
	//
	// Two conditions can trigger divergence while checking is disabled: 
	// * We see a syscall that is not in the syscall_info.unchecked_syscalls[]
	// list.
	// * We see more than syscall_info.max_unchecked_syscalls while checking
	// is disabled.
	// 
	bool          syscall_checking_disabled;
	long          max_unchecked_syscalls;
	SYSCALL_MASK(unchecked_syscalls);
	

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

    // somehow, the sigset gets corrupted across sigprocmask calls...
    sigset_t      last_sigset;

    // Occasionally used vars...
    pid_t         varianttgid;                                      // Thread Group ID of this variant
    pid_t         pendingpid;                                       // Process ID of the newly created process/thread
    unsigned long infinite_loop_ptr;                                // pointer to the sys_pause loop
    unsigned long should_sync_ptr;                                  // pointer to the should_sync flag
    long          callnumbackup;                                    // Backup of the syscall num. Made when the monitor is delivering a signal
    PTRACE_REGS   regsbackup;                                       // Backup of the registers. Made when the monitor is delivering a signal
    unsigned long hw_bps[4];                                        // currently set hardware breakpoints
    unsigned char hw_bps_type[4];                                   // type of hw bp. 0 = exec only, 1 = write only, 2 = I/O read/write, 3 = data read/write but no instr fetches
    void*         tid_address[2];                                   // optional pointers to the thread id
    size_t        orig_controllen;                                  // for recvmsg
#ifdef __NR_socketcall
    unsigned long orig_arg1;                                        // for sys_socketcall
#endif
#ifdef MVEE_CHECK_SYNC_PRIMITIVES
    int           sync_primitives_bitmask;                          // copied over from the variant's address space using sync_primitives_ptr
    void*         sync_primitives_ptr;                              //
#endif
    std::string   perf_out;                                         // Output of the perf program
	Json::Value*  config;                                           // Variant-specific config

	std::vector<overwritten_syscall_arg>
       	  	      overwritten_args;

    // shared mem ------------------------------------------------------------------------------------------------------
    instruction_intent
                  instruction;
    int           variant_num;
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    void*         syscall_pointer;
#endif
    unsigned long shm_tag;                                          // Tag for shared memory pages
    std::vector<std::pair<unsigned long, size_t>> reset_atfork;     // Variables to reset in forked children
    struct iovec* replaced_iovec;
    // -----------------------------------------------------------------------------------------------------------------

    variantstate();
	~variantstate();
};


//
// This class represents the monitors that monitor the variants.  Unless
// otherwise noted, all of member functions are implemented in MVEE_monitor.cpp
//
class monitor
{
    friend class shm_handling;
	friend class mvee;
    friend class instruction_intent_emulation;
    friend class instruction_intent;
    friend class replay_buffer;
    friend class acquire_shm_protected_memory_for_access;

#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    friend class instruction_tracing;
#endif
public:

	// *************************************************************************
    // Public interface for the MVEE logger
    // *************************************************************************

	//
    // Returns true if the logf function should log to this monitor's monitor
    // log
	//
    bool is_logging_enabled                  ();

	//
	// Returns true if this monitor's variants are shutting down
	//
    bool is_group_shutting_down              ();

	//
	// Implemented in MVEE_logging.cpp. Logs basic information about this
	// monitor and the variants it's monitoring.
	//
    void log_monitor_state_short             (int err);

	// *************************************************************************
    // Public interface for the MVEE monitor management - These functions are
	// available to the main mvee process
	// *************************************************************************

	//
	// Wakes up the monitor and sets its should_shutdown flag
	//
    void  signal_shutdown                     ();

	//
	// Wakes up the monitor and sets its monitor_registered flag, indicating
	// that it can begin executing the main monitor loop
	//
    void  signal_registration                 ();

	//
	// Get the process ids of the variant threads monitored by this monitor
	//
    std::vector<pid_t>
          getpids                             ();

	//
	// Calls pthread_join on the specified monitor's pthread_t object
	//
    void  join_thread                         ();

	//
	// Get the Task Group ID of the master variant monitored by this monitor
	//
    pid_t get_mastertgid                      ();

	//
	// Sets the should_check_multithread_state flag for this monitor, indicating
	// that it should check if it's still monitoring a multi-threaded process
	// upon the next opportunity. We use this mechanism to dynamically
	// enable/disable the synchronization agents in the variants
	//
    void  set_should_check_multithread_state  ();

	// *************************************************************************
	// Scheduling support
	// *************************************************************************

	//
	// Returns the logical CPU core id of the core to which the master variant
	// thread was assigned (if any)
	//
	int   get_master_core                     ();

	// *************************************************************************
    // Public variables for the MVEE logger
	// *************************************************************************

    // File handle for this monitor's local log file (i.e. MVEE_<monitorid>.log)
    FILE* monitor_log;

    // Unique identifier for this
    int   monitorid;

	// *************************************************************************
    // System Call Handlers
	// *************************************************************************

	//
	// Dummy functions called when we don't have a handler for a specific
	// syscall
	//
    long handle_donthave                     (int variantnum);
    long handle_dontneed                     (int variantnum);
	void log_donthave                        (int variantnum);
	void log_dontneed                        (int variantnum);

	//
	// Syscall handler logging helper
	//
	std::string      call_get_variant_pidstr (int variantnum);

	//
	// Include an automatically generated syscall handler table. All of these
	// handler functions are implemented in MVEE_syscalls_handlers.cpp
	//
    #include "MVEE_syscall_handler_prototypes.h"

	// *************************************************************************
    // Constructors/Destructors
	// *************************************************************************

	//
	// Constructor used for the primary monitor thread (i.e. the one that attaches
	// to the initial variant processes)
	//
    monitor(std::vector<pid_t>& pids);

	//
	// Constructor used for the secondary monitor threads (i.e. the monitor threads
	// that attach to descendants of the initial variant processes)
	//
    monitor(monitor* parent_monitor, bool shares_fd_table=false, bool shares_mmap_table=false, bool shares_sighand_table=false, bool shares_tgid=false);
    ~monitor();

    // *************************************************************************
    // shared memory debugging stuff
    // *************************************************************************


#ifdef MVEE_SHM_INSTRUCTION_ACCESS_DEBUGGING
#define SET_INSTRUCTION_SRC_PTR(__src_ptr, __src, __cast)                                                              \
relevant_monitor.set_instruction_src_ptr(variant->variant_num, (unsigned long) __src_ptr, *(__cast*) __src);
#define SET_INSTRUCTION_DST_PTR(__dst_ptr, __dst, __cast)                                                              \
relevant_monitor.set_instruction_dst_ptr(variant->variant_num, (unsigned long) __dst_ptr, *(__cast*) __dst);
#define SET_INSTRUCTION_SRC_REG(__src, __cast)                                                                         \
relevant_monitor.set_instruction_src_reg(variant->variant_num, *(__cast*) __src);
#define SET_INSTRUCTION_DST_REG(__dst, __cast)                                                                         \
relevant_monitor.set_instruction_dst_reg(variant->variant_num, *(__cast*) __dst);
    void             add_instruction                     (int variant_num, instruction_intent* intent);
    void             print_instruction_list              ();
    void             set_instruction_src_ptr             (int variant_num, unsigned long src_ptr, unsigned long src);
    void             set_instruction_dst_ptr             (int variant_num, unsigned long dst_str, unsigned long dst);
    void             set_instruction_src_reg             (int variant_num, unsigned long src);
    void             set_instruction_dst_reg             (int variant_num, unsigned long dst);
#endif
private:

	// *************************************************************************
    // Main monitor thread function - This runs the main monitoring loop
	// *************************************************************************
    static void* thread                                  (void* param);

	// *************************************************************************
    // System call support (these are all in MVEE_syscalls_support.cpp)
    // These functions mostly support the MVEE<->variant datatransfers
	// *************************************************************************

	// inline templates here
	#include "MVEE_syscalls_support_templates.h"

	// 
	// Check if our cached regs variable is still up to date for variant
	// @variantnum, possibly refreshing it if necessary 
	//
    void             call_check_regs                     (int variantnum);

	//
	// Check if our cached fpregs variable is still up to date for variant
	// @variantnum, possibly refreshing it if necessary
	//
    void             call_check_fpregs                   (int variantnum);

	// 
	// Returns true if the specified syscall result indicates an error
	//
    bool             call_check_result                   (long int result);

	//
	// Returns true if none of the variants's syscalls returned errors
	//
    bool             call_postcall_all_syscalls_succeeded();

	// 
	// Returns the syscall result for variant @variantnum
	//
    long             call_postcall_get_variant_result      (int variantnum);

	// 
	// Overwrite the syscall result for variant @variantnum
	//
    void             call_postcall_set_variant_result      (int variantnum, unsigned long result);

	//
	// Returns a vector containing the syscall results for all variants
	//
    std::vector<unsigned long>
                     call_postcall_get_result_vector     ();

	//
	// Resolves path names, determines if the syscall opened an unsynced file or not
	// returns true on success, false on failure
	// resolved_paths, and unsynced_access are modified by this func
	//
	bool             call_resolve_open_paths             (std::vector<unsigned long>& fds,
														  std::vector<unsigned long>& path_ptrs,
														  std::vector<std::string>& resolved_paths,
														  bool& unsynced_access,
														  unsigned long open_at_fd=AT_FDCWD);											 

	//
	// Comparison functions. These are pretty self-explanatory.  They generally
	// accept a pointer to a data structure for each variant. If the data
	// matches, the comparison function returns true.
	// 
    bool             call_compare_variant_strings        (std::vector<const char*>& stringptrs, size_t maxlength=0);
    bool             call_compare_variant_buffers        (std::vector<const unsigned char*>& bufferptrs, size_t size);
    bool             call_compare_wait_pids              (std::vector<pid_t>& pids);
    bool             call_compare_signal_handlers        (std::vector<unsigned long>& handlers);
    bool             call_compare_sigactions             (std::vector<unsigned long>& handlers, std::vector<unsigned long>& sa_flags);
    bool             call_compare_sigsets                (sigset_t* set1, sigset_t* set2);
    unsigned char    call_compare_pointers               (std::vector<void*>& pointers);
    bool             call_compare_io_vectors             (std::vector<struct iovec*>& addresses, size_t len, bool layout_only=false);
    bool             call_compare_msgvectors             (std::vector<struct msghdr*>& addresses, bool layout_only=false);
	bool             call_compare_mmsgvectors            (std::vector<struct mmsghdr*>& addresses, int vlen, bool layout_only=false);
	bool             call_compare_fd_sets                (std::vector<fd_set*>& addresses, int nfds);

	//
	// Serialization Functions. These are helper functions for the syscall
	// logging handlers in MVEE_syscall_handlers.cpp
	// 
    std::string      call_serialize_io_vector            (int variantnum, struct iovec* vec, unsigned int vecsz);
    std::string      call_serialize_msgvector            (int variantnum, struct msghdr* msg);
    std::string      call_serialize_io_buffer            (int variantnum, const unsigned char* buf, unsigned long buflen);
	// 
	// Replication functions. These accept a pointer to a data structure for
	// each variant. The data structure is deep copied from the address space of
	// the master variant to the address spaces of the slaves
	//
    void             call_replicate_io_vector            (std::vector<struct iovec*>& addresses, long bytes_copied);
    void             call_replicate_msgvector            (std::vector<struct msghdr*>& addresses, long bytes_sent);
    void             call_replicate_mmsgvector           (std::vector<struct mmsghdr*>& addresses, int vlen);
    void             call_replicate_mmsgvectorlens       (std::vector<struct mmsghdr*>& addresses, int sent, int attempted);
    void             call_replicate_buffer               (std::vector<const unsigned char*>& addresses, int size);
	void             call_replicate_ifconfs              (std::vector<struct ifconf*>& addresses);

	//
	// getter functions. These accept pointers to a specific data structure and
	// do a deep copy to a local data structure.
	//
    sigset_t         call_get_sigset                     (int variantnum, void* sigset_ptr, bool is_old_call);
    struct sigaction call_get_sigaction                  (int variantnum, void* sigaction_ptr, bool is_old_call);
    struct sockaddr* call_get_sockaddr                   (int variantnum, struct sockaddr* ptr, __socklen_t addr_len);
	std::set<int>    call_get_fd_set_from_domain_msgvector  (struct msghdr* address);
	std::set<int>    call_get_fd_set_from_domain_mmsgvector (struct mmsghdr* address, int vlen);	

	//
	// Argument overwriting support. Mainly used for aliasing
	//
	void             call_overwrite_arg_value            (int variantnum, int argnum, long new_value, bool needs_restore);
	void             call_overwrite_arg_data             (int variantnum, int argnum, unsigned old_len, void* data, unsigned len, bool needs_restore);
	void             call_restore_args                   (int variantnum);

	// *************************************************************************
    // Specific Syscall handlers (these are all in MVEE_syscalls_handlers.cpp)
	// *************************************************************************

	// 
    // False positive handling. This is called when a syscall argument mismatch
	// is detected when executing program @program_name. Based on the
	// @precall_flags, we can see which argument caused the mismatch detection.
	// If this function returns true, we ignore the mismatch
	//
    bool        handle_is_known_false_positive      (const char* program_name, long callnum, long* precall_flags);

	//
	// Returns true if we should allow open/openat calls to open file @fullpath
	//
    long        handle_check_open_call              (const std::string& full_path, int flags, int mode);

	// 
	// Fetching the arguments for an execve call is complicated and slow.
	// We therefore use a specialized function that caches the results.
	// 
    void        handle_execve_get_args              (int variantnum);

	// 
	// callback function for the iterator function that iterates over regions
	// that were unmapped by the preceding sys_munmap call.  This function
	// handles writebacks of memory regions that _WERE_ MAP_SHARED, but that
	// were changed by the MVEE to MAP_PRIVATE. Please refer to the original
	// GHUMVEE paper for details.
	//
    static bool handle_munmap_precall_callback      (mmap_table* table, std::vector<mmap_region_info*>& infos, void* mon);

	// *************************************************************************
    // Generic Syscall handlers (these are in MVEE_syscalls.cpp) - This is the
    // main interface for the general monitor logic implemented in
    // MVEE_monitor.cpp
	// *************************************************************************

	// 
	// Check if the syscall arguments mismatch we detected is a known benign
	// divergence. This is a wrapper around handle_is_known_false_positive
	// (described above)
	// 
    unsigned char call_is_known_false_positive        (long* precall_flags);

	//
	// Resume a single variant
	// 
	void          call_resume                         (int variantnum);

	// 
	// Resume all variants
	//
    void          call_resume_all                     ();

	// 
	// Replace the syscall number for a single variant with __NR_getpid and then
	// resume it. This forces the variant to execute sys_getpid instead of
	// the call it was about to execute
	// 
	void         call_resume_fake_syscall             (int variantnum);


	// 
	// Replace the syscall number for all variants with __NR_getpid and then
	// resume them. This forces all variants to execute sys_getpid instead of
	// the call they were about to execute
	// 
    void          call_resume_fake_syscall_all        ();

	//
	// The syscall that has just returned for this variant was denied in the 
	// CALL handler. This means that the syscall number was replaced by __NR_getpid
	// and that GHUMVEE will provide the syscall return value.
	// This function will write that return value based on the information
	// provided by the CALL handler
	//
	void          call_write_denied_syscall_return    (int variantnum);

	// 
	// Determines if syscall @callnum should be executed in lockstep for variant
	// @variantnum
	// 
	// For standard syscalls, this is a wrapper around the get_call_type handle
	// functions for the syscall that is currently being executed by variant
	// @variantnum
	//
    unsigned char call_precall_get_call_type          (int variantnum, long callnum);

	//
	// Calls the argument logging function for the specified syscall (if any)
	// A default logging function is called if no specialized logger
	// exists in MVEE_syscall_handlers.cpp
	//
	void          call_precall_log_args               (int variantnum, long callnum);

	//
	// Calls the PRECALL handler for the current syscall. This is only done
	// if the syscall is synced (i.e., lockstepped). The PRECALL handler
	// reads the call arguments and asserts that they are equivalent
	// 
    long          call_precall                        ();

	//
	// Runs the late precall handling (i.e. overwriting syscall results if
	// necessary) for syscalls that are not subject to lockstepping
	// 
	// For standard syscalls, this is a wrapper around the call handler function
	// for the syscall that is currently being executed by variant @variantnum
	// 
    long          call_call_dispatch_unsynced         (int variantnum);

	//
	// Runs the late precall handling (i.e. overwriting syscall results if
	// necessary) for syscalls that are subject to lockstepping
	// 
	// For standard syscalls, this is a wrapper around the call handler function
	// for the syscall that is currently being executed by the variants
	// 
    long          call_call_dispatch                  ();

	//
	// Calls the return logging function for the specified syscall (if any)
	// A default logging function is called if no specialized logger exists
	// in MVEE_syscalls_handlers.cpp
	//
	void         call_postcall_log_return             (int variantnum);

	//
	// Runs the postcall handling for syscalls that are not subject to
	// lockstepping
	// 
	// For standard syscalls, this is a wrapper around the postcall handler
	// function for the syscall that is currently being executed by variant
	// @variantnum
	// 
    long          call_postcall_return_unsynced       (int variantnum);

	//
	// Runs the postcall handling for syscalls that are subject to lockstepping
	// 
	// For standard syscalls, this is a wrapper around the postcall handler
	// function for the syscall that is currently being executed by the variants
	// 
    long          call_postcall_return                ();

	//
	// Shifts the syscall arguments for variant @variantnum by @cnt arguments.
	//
	// Example: shifting the arguments by 1 would cause ARG2 to be copied into
	// ARG1, ARG3 into ARG2, ...  
	//
	// We use this so we can use this on 32-bit for multiplexed calls such as
	// sys_ipc and sys_socketcall.
	//
	// Note: We only shift our locally cached copies of the syscall arguments,
	// not the actual in-process arguments
	// 
    void          call_shift_args                     (int variantnum, int cnt);

	// 
	// Locks the specified set of locks. We use these locks to prevent
	// related syscall from being executed simultaneously
	//
    void          call_grab_locks                     (unsigned char syslocks);

	// 
	// Releases the specified set of locks.
	// 
    void          call_release_locks                  (unsigned char syslocks);

	// 
	// Helper functions for syslock locking
	//
    void          call_grab_syslocks                  (int variantnum, unsigned long callnum, unsigned char which);
    void          call_release_syslocks               (int variantnum, unsigned long callnum, unsigned char which);

	//
	// Wait for all variants to be stopped
	//
    void          call_wait_all                       ();

	//
	// Injects a syscall into the variants. This function, which should only be
	// called when the variants are all suspended, overwrites the
	// syscall number and syscall arguments for all variants. It then resumes
	// them, and waits for the syscalls to return.
	// 
    void          call_execute_synced_call            (bool at_syscall_exit, unsigned long callnum, std::vector<std::deque<unsigned long> >& call_args);

	// *************************************************************************
    // Event handling - This is all of the non-syscall related event handling
	// These functions are implemented in MVEE_monitor.cpp
	// *************************************************************************

	//
	// Processes a signal delivery to variant @index. 
	//
    void handle_signal_event                 (int index, interaction::mvee_wait_status& status);

	//
	// Process a SIGTRAP signal, possibly resulting from the execution of an
	// RDTSC instruction. We disassemble the faulting instruction to verify
	// this. If the faulting instruction is indeed RDTSC, we ensure that
	// all variants get consistent results and return true.
	//
#ifdef MVEE_ARCH_HAS_RDTSC
    bool handle_rdtsc_event                  (int index);
#endif

	// 
	// Generic SIGTRAP handling. 
	//
    void handle_trap_event                   (int index);

	// 
	// Processes the creation of a new task by variant @index
	//
    void handle_fork_event                   (int index, interaction::mvee_wait_status& status);

	//
	// Processes the entrance into a syscall by variant @index. This function
	// only implements the really high-level syscall handling logic and relies
	// on the generic syscall handler functions in MVEE_syscalls.cpp to handle
	// the specifics.
	//
    void handle_syscall_entrance_event       (int index);

	// 
	// Processes the return from a syscall @index. This function only implements
	// the really high-level syscall handling logic and relies on the generic
	// syscall handler functions in MVEE_syscalls.cpp to handle the specifics.
	//
    void handle_syscall_exit_event           (int index);

	//
	// Processes a SIGSYSTRAP signal. This function figures out if the signal
	// was caused by a syscall entrance or exit and delegates to one of the
	// above functions accordingly
	//
    void handle_syscall_event                (int index);

	// 
	// Processes the death of variant @index.
	//
    void handle_exit_event                   (int index);

	//
	// Processes the first SIGSTOP we see from variant @index, which we have not
	// attached to yet
	//
    void handle_attach_event                 (int index);

	//
	// Processes the second SIGSTOP we see from variant @index. This second
	// SIGSTOP is caused by our attach operation.
	//
    void handle_resume_event                 (int index);

	//
	// Handles an event from a variant we are not currently attached to
	//
    void handle_detach_event                 (int variantpid);

	// 
	// Entrypoint for all event handling
	//
    void handle_event                        (interaction::mvee_wait_status& status);

	// *************************************************************************
    // Signal specific event handling
	// *************************************************************************

	//
	// Removes the specified signal from this monitor's pending_signals list,
	// preventing future delivery of said signal to the variants
	//
    std::vector<mvee_pending_signal>::iterator discard_pending_signal              (std::vector<mvee_pending_signal>::iterator& it);
	
	//
	// Checks if we have pending signals
	//
	bool                                       have_pending_signals                ();

	//
	// Checks if the variants are in a signal handler
    //
	bool                                       in_signal_handler                   ();

	//
	// Entrypoint for all signal related events. This handles all variant
	// interruptions due to signal deliveries.  The wait4 status is given in
	// @status. The function returns false if the variant was terminated due to
	// the signal delivery (this can happen for example if the interrupting
	// signal is a SIGKILL)
	// 
    void                                       handle_sig_delivery_stop            (int index, int status);

	// 
	// Inspects the pending_signals list and possibly initiates the delivery
	// of one of the pending signals to the variants. Returns true if a signal
	// delivery was initiated
	//
    bool                                       sig_prepare_delivery                ();

	//
	// Handles the delivery of a SIGCHLD signal that was delivered while we were
	// executing a mastercall. Returns true if the mastercall was successfully
	// restarted
	//
	bool                                       sig_handle_sigchld_race             (std::vector<mvee_pending_signal>::iterator it);

	//
	// Finishes the delivery of a signal whose delivery was initiated in a
	// preceding sig_prepare_delivery call
	//
    void                                       sig_finish_delivery                 ();

	//
	// Handles the execution of sys_rt_sigreturn calls. This call is executed
	// when the the execution of a signal handler finishes. This function should
	// restore the original register context for each variant and resume them
	//
    void                                       sig_return_from_sighandler          ();

	//
	// Handle ERESTART_* errors resulting from signal deliveries during blocking
	// syscalls.
	//
    void                                       sig_restart_syscall                 (int variantnum);
    void                                       sig_restart_partially_interrupted_syscall();

	// 
	// Set the have_pending_signals flag, indicating that the sig_prepare_delivery
	// function might have to initiate a signal delivery
	//
	void                                       sig_set_pending_signals             (bool pending_signals, bool signal_handler);

	// 
	// Returns true if variant @variantnum's instruction pointer points to the
	// IP-MON executable code
	//
	bool                                       in_ipmon                            (int variantnum, unsigned long ip);

	//
	// Returns true if variant @variantnum's instruction pointer points to a
	// syscall instruction inside IP-MON's executable code
	//
	bool                                       in_ipmon_syscall                    (int variantnum, unsigned long ip);

	// *************************************************************************
    // Hardware breakpoint support
	// *************************************************************************

	// 
	// Update variant @variantnum's debug registers after we have set or unset a
	// hardware breakpoint
	// 
    void hwbp_refresh_regs              (int variantnum);

	//
	// Set or remove a hardware breakpoint at address @addr in variant
	// @variantnum. Refer to MVEE_monitor.h for a list of possible breakpoint
	// types
	//
    bool hwbp_set_watch                 (int variantnum, unsigned long addr, unsigned char bp_type);
    bool hwbp_unset_watch               (int variantnum, unsigned long addr);

	// *************************************************************************
    // Logging/Backtracing functions - These are implemented in MVEE_logging.cpp
	// *************************************************************************

	// 
	// Opens the monitor-local log file (i.e. MVEE_<monitorid>.log)
	//
    void log_init                        ();

	// 
	// Closes the monitor-local log file (i.e. MVEE_<monitorid>.log)
	//
    void log_fini                        ();

	//
	// Logs the instruction trace in json format, should only be called when running an instruction trace.
	//
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    void log_instruction_trace           ();
#endif

	//
	// Logs a stack trace for variant @variantnum
	//
    void log_variant_backtrace             (int variantnum, int max_depth=0, int calculate_file_offsets=0, int is_segfault=0);

	// 
	// Logs source line information for the instruction found at address
	// @address in variant @variantnum
	// 
    void log_caller_info                 (int variantnum, int level, unsigned long address, int calculate_file_offsets=0, void (*logfunc)(const char*, ...)=NULL);

	//
	// Log the extended state of this monitor and its variants
	//
    void log_monitor_state               (void (*logfunc)(const char* format, ...)=NULL);

	//
	// Log stack traces for all variants
	//
    void log_backtraces                  ();

	// 
	// Log the contents of all known shared memory segments attached by the
	// variants. Among other things, we use this to visualize the contents
	// of the synchronization buffers
	//
    void log_dump_queues                 (shm_table* shm_table);

	//
	// Error Logging Functions
	//
    void log_unhandled_sig               (int status, int index);
    void log_call_mismatch               (int index1, int index2);
    void log_callargs_mismatch           ();
    void log_segfault                    (int variantnum);
    void log_hw_bp_event                 (int variantnum, siginfo_t* sig);

	//
	// Visualizes the contents of IP-MON's Replication Buffer
	//
    void log_ipmon_state                 ();
	bool log_ipmon_entry                 (struct ipmon_buffer* buffer, struct ipmon_syscall_entry* entry, void (*logfunc)(const char* format, ...));
	struct ipmon_syscall_data* 
		get_ipmon_data                   (struct ipmon_syscall_entry* entry, unsigned long start_offset, unsigned long end_offset, int data_num);
	struct ipmon_syscall_data* 
		get_ipmon_arg                    (struct ipmon_syscall_entry* entry, int arg_num);
	struct ipmon_syscall_data* 
		get_ipmon_ret                    (struct ipmon_syscall_entry* entry, int ret_num);

	//
	// Calculates statistics for the synchronization operations in the
	// synchronization buffers attached to the variants
	// 
	void log_calculate_clock_spread      ();
	
	//
	// Log the contents of the stack around the current stack pointer in variant
	// @variantnum
	//
	void log_stack                       (int variantnum);

	//
	// Dump the cross-check buffer for libclevrbuf
	//
	unsigned long long get_clevrbuf_value(unsigned long value_pos);
	void log_clevrbuf_state              (int variantnum);

	//
	// Write messages into the mismatch info stream.  These messages may or may
	// not be printed to stdout/log files later, depending on whether or not the
	// mismatch was flagged as a benign divergence
	//
	void cache_mismatch_info             (const char* format, ...);

	// 
	// dump the mismatch stream to stdout/log files
	//
	void dump_mismatch_info              ();

	// 
	// reset the mismatch info stream
	//
	void flush_mismatch_info             ();

	// *************************************************************************
    // Variant Initialization
	// *************************************************************************   

	//
	// Initialize the variantstate struct for variant @variantnum
	//
    void        init_variant                    (int variantnum, pid_t variantpid, pid_t varianttgid);

	//
	// Restart variant @variantnum to its initial state by injecting a sys_execve
	// call with the original arguments
	//
    bool        restart_variant                 (int variantnum);

	//
	// Writes new execve arguments to inject the
	// MVEE_LD_Loader/interpreter/library path/...
	//
	void        rewrite_execve_args             (int variantnum, bool write_to_stack=true, bool rewrite_envp=false);

	//
	// Serializes a deque by writing a raw serialized buffer and a raw pointer
	// array containing pointers to the elements in the serialized buffer.
	// The pointers are relocated because we assume that the serialized buffer
	// will be written at @target_address
	//
    static void serialize_and_relocate_arr      (std::deque<char*>& arr, char*& serialized, char**& relocated, unsigned long target_address);

	//
	// Get the original execve arguments array for the specified variant
	//
    std::deque<char*>
                get_original_argv               (int variantnum);

	// *************************************************************************
    // Monitor startup/shutdown
	// *************************************************************************    

	//
	// Shut down the current monitor thread. This frees all of the resources
	// allocated by this monitor and possibly kills any variants that are still
	// active. If necessary, the shutdown function also generates backtraces.
	// Finally, the shutdown function will signal the mvee garbage collection
	// thread by calling mvee::unregister_monitor, and it will then simply wait
	// to be garbage collected.
	//
    void shutdown                            (bool success);

	//
	// Handle any incoming events from variants we have detached from, but are
	// not attached to other monitor threads yet.
	//
    void await_pending_transfers         ();

	//
	// Initialize all of our variables to their default values
	//
    void init();

	//
	// Pin our variant threads to the most suitable logical CPU cores
	// 
	void schedule_threads();

    //
    // Functions for dynamic toggling of the synchronization replication algorithm
    //
    void enable_sync                     ();
    void disable_sync                    ();
    bool is_program_multithreaded        ();
    void check_multithread_state         ();

    //
    // Debugging support
    //
    void update_sync_primitives          ();

    //
    // Syscall handler tables
    //
    static const mvee_syscall_handler syscall_handler_table [MAX_CALLS][4];
    static const mvee_syscall_logger  syscall_logger_table  [MAX_CALLS][2];

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
    bool                              ipmon_initialized;
	bool                              ipmon_mmap_handling;
	bool                              ipmon_fd_handling;
    bool                              aliased_open;           // 


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
    std::vector<pid_t>                local_detachlist;       // pids of variants that we haven't detached from yet...
    std::vector<pid_t>                unknown_variants;       // pids of variants we've received events from but don't know yet
    _shm_info*                        atomic_buffer;          // thread-local atomic buffer
    std::vector<void*>                atomic_counters;
    std::vector<void*>                atomic_queue_pos;
    static std::vector<std::unique_ptr<_shm_info>>     atomic_variantwide_buffer;

    _shm_info*                        ipmon_buffer;
	_shm_info*                        ring_buffer;
    _shm_info*                        shm_buffer;          // shared memory buffer

    // Signal info
    unsigned short                    current_signal;         // signal no for the signal we're currently delivering
    unsigned short                    current_signal_sent;    //
    siginfo_t*                        current_signal_info;    // siginfo for the signal we're currently delivering
    std::vector<mvee_pending_signal>
                                      pending_signals;
    std::vector<variantstate>
                                      variants;               // State for all variant processes being traced by this monitor
    bool                              perf;                   // is this monitor tracking the perf process
    pid_t                             monitor_tid;

    // set of signals which are currently blocked for this thread set.
    // Blocked signals are added to the pending queue and must be delivered
    // when and if the signal is every unblocked. Duplicates must be discarded
	std::vector<sigset_t>             blocked_signals;
    // previous set of signals which were blocked. this is used for calls
    // that temporarily replace the signal mask (e.g. sigsuspend)
	std::vector<sigset_t>             old_blocked_signals;

	unsigned long                     last_mmap_requested_size;
	unsigned long                     last_mmap_requested_alignment;

	int master_core;

	std::stringstream mismatch_info;                          // cached mismatch info

    // shared memory ===================================================================================================
    replay_buffer                     buffer;

    int                               shm_setup_state;
    shared_monitor_map_info*          current_shadow;

#ifdef MVEE_SHM_INSTRUCTION_ACCESS_DEBUGGING
    struct instruction_info_t
    {
        uint8_t instruction [15];
        unsigned long size;
        unsigned long instruction_pointer;
        unsigned long faulting_address;
        unsigned long src_ptr;
        bool src_reg;
        unsigned long dst_ptr;
        bool dst_reg;
        unsigned long src;
        unsigned long dst;
    };
    std::vector<std::vector<instruction_info_t>> instruction_list;
#endif
    // shared memory ===================================================================================================
};

struct detachedvariant
{
    pid_t         variantpid;                                 //
    monitor*      new_monitor;                                // monitor the variant should be transferred to
    int           parentmonitorid;                            // id of the monitor this variant was detached from
    int           parent_has_detached;                        // set to true when the original monitor, under whose control this variant was spawned, has detached
    PTRACE_REGS   original_regs;                              // original contents of the registers
    unsigned long transfer_func;                              // pointer to the sys_pause loop
    void*         tid_address[2];                             // set if we should tell the variant what its thread id is (e.g. if the variant was created by clone(CLONE_CHILD_SETTID)
	unsigned long should_sync_ptr;
};

// If our glibc is compiled with MVEE_DEBUG_MALLOC, slave variants will pass an mvee_malloc_error
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
			unsigned short count;         // nr of variants that have reached the barrier
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
	int           ipmon_usable_size;                        // 04-08: size that is usable for syscall entries
	unsigned long ipmon_have_pending_signals;
	struct ipmon_barrier pre_flush_barrier;
	struct ipmon_barrier post_flush_barrier;
	unsigned long flush_count;
	unsigned char ipmon_padding[64 - 2*sizeof(unsigned long) - sizeof(int)*2 - sizeof(struct ipmon_barrier) * 2];

	// Cachelines 1-n
	struct ipmon_variant_info ipmon_variant_info[1];

	// And the actual syscall data
//	struct ipmon_syscall_entry ipmon_syscall_entry[1];
};

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
#define IPMON_UNSYNCED_CALL  32 // No lock-stepping for this call
#define IPMON_BLOCKING_CALL  64 // The call is expected to block. This is not a distinct call type. It is ORed with one of the above call types.
#define IPMON_WAIT_FOR_SIGNAL_CALL 512

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
#include "MVEE_exceptions.h"


#endif // MVEE_PRIVATE_H_INCLUDED
