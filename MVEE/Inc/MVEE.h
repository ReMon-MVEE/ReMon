/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_H_
#define MVEE_H_

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <stddef.h>
#include <stdio.h>
#include <pthread.h>
#include <memory>
#include <map>
#include <vector>
#include <string>
#include <deque>
#include <set>
#include "MVEE_config.h"

/*-----------------------------------------------------------------------------
    Forward Declarations
-----------------------------------------------------------------------------*/
struct config_t;
struct config_setting_t;
class monitor;
class detachedvariant;
class mmap_addr2line_proc;
class dwarf_info;
class shm_table;
class mmap_table;

//
// Convenience class for locking a mutex
//
class MutexLock
{
private:
    pthread_mutex_t *mutex;
public:
    MutexLock(pthread_mutex_t *_mutex)
    {
        mutex = _mutex;
        pthread_mutex_lock(mutex);
    }

    ~MutexLock()
    {
        pthread_mutex_unlock(mutex);
    }
};

long mvee_wrap_ptrace                 (unsigned short request, pid_t pid, unsigned long addr, void *data, int allow_even_if_shutting_down=0);

/*-----------------------------------------------------------------------------
    Constants
-----------------------------------------------------------------------------*/
#include "MVEE_numcalls.h" // defines MAX_CALLS
#define NO_CALL   0x01000000

/*-----------------------------------------------------------------------------
    GHUMVEE Config File Configuration - refer to the default MVEE.ini for
    documentation.
-----------------------------------------------------------------------------*/
struct mvee_config
{
	unsigned char mvee_use_ipmon;
    unsigned char mvee_hide_vdso;
    unsigned char mvee_intercept_tsc;
    unsigned char mvee_use_dcl;
    unsigned char mvee_allow_setaffinity;
    unsigned char mvee_use_system_libc;
    unsigned char mvee_use_system_libgomp;
    unsigned char mvee_use_system_libstdcpp;
    unsigned char mvee_use_system_libgfortran;
    unsigned char mvee_use_system_gnomelibs;
    const char*   mvee_root_path;
    const char*   mvee_libc_path;
    const char*   mvee_libgomp_path;
    const char*   mvee_libstdcpp_path;
    const char*   mvee_libgfortran_path;
    const char*   mvee_gnomelibs_path;
	const char*   mvee_spec2006_path;
	const char*   mvee_parsec2_path;
	const char*   mvee_parsec3_path;
    config_t*     config;
};

//
// This represents the global state of the MVEE.
//
class mvee
{
public:

    // *************************************************************************
    // Logging Functions - These are implemented in MVEE_logging.cpp
    // *************************************************************************

	// 
    // Log a message to the log files. This function is disabled if the
    // MVEE_BENCHMARK preprocessor option is set.
	// 
    static void        logf                        (const char* format, ...);

	// 
	// Log a message to stdout and to the log files. Even with MVEE_BENCHMARK
	// enabled, the message is still printed to stdout.
    //
    static void        warnf                       (const char* format, ...);

	//
	// Log the specified ptrace operation to the ptrace log file.
	//
    static void        log_ptrace_op               (int op_type, int op_subtype, int bytes);

	//
	// Print synchronization statistics to the lockstats file. The statistics
	// are gathered from the shared synchronization buffer referred to by
	// @shm_table.
	//
    static void        log_dump_locking_stats      (monitor* mon, mmap_table* mmap_table, shm_table* shm_table);

	//
	// Create a process by executing the command specified by @proc and return
	// its output.
	//
    static std::string log_read_from_proc_pipe     (const char* proc, size_t* output_length);

	//
	// Convert the buffer specified by @hexbuffer to hex string format
	//
    static std::string log_do_hex_dump             (const void* hexbuffer, int buffer_size);

	// 
	// Helper function to log register contents.
	// 
    static void        log_register                (const char* register_name, unsigned long* register_ptr, void (*logfunc)(const char*, ...));

	//
	// Helper function to log DWARF2 rules.
	//
    static void        log_dwarf_rule              (unsigned int reg_num, void* _rule);

	//
	// Helper function to log sigaction structures.
	//
    static void        log_sigaction               (struct sigaction* action);

    // *************************************************************************
    // MVEE Initialization/Shutdown - Implemented in MVEE.cpp
    // *************************************************************************
	
	//
	// Start the monitor and mvee::numvariants variants.  This is the default
	// mode for the MVEE
    //
    static void start_monitored             ();

	// 
	// Start mvee::numvariants variants that run natively.  We do not monitor
	// the variants in this mode
	//
    static void start_unmonitored           ();

	// 
	// Adds a variant to a list of processes that may need to be forcibly killed
	// upon MVEE shutdown
	// 
    static void shutdown_add_to_kill_list   (pid_t kill_pid);

	// 
	// Reads the MVEE configuration from MVEE.ini, possibly creating the file in
	// the process.
    //
    static void init_config                 ();

	// 
	// Parse a commandline option for the MVEE
	//
    static void process_opt                 (char* opt);

	//
	// Asynchronously request a shutdown of the entire MVEE
	//
    static void request_shutdown            (bool should_backtrace);

    // *************************************************************************
    // Monitor Management - Implemented in MVEE.cpp
    // *************************************************************************

	//
	// Safely store the specified set of variant pids in the
	// mvee::variant_pid_mapping map.
	//
    static void                                 register_variants           (std::vector<pid_t>& pids);

	//
	// Safely store the specified monitor in the mvee::monitor_id_mapping map
	// and activate the monitor through monitor::signal_registration
    //
    static void                                 register_monitor            (monitor* mon);

	//
	// Remove the specified monitor from the mvee::monitor_id_mapping map and
	// add it to the garbage collection list.
	//
	// This function also shuts down the MVEE when the last running monitor
	// unregisters.
    //
    static void                                 unregister_monitor          (monitor* mon);

	// 
	// Returns true if the MVEE is monitoring variants that consist of multiple
	// processes (i.e. tasks that have different tgids.
	//
    static bool                                 is_multiprocess             ();

	// 
	// Returns the set of logical CPU cores that are currently being used by
	// running variants.
	//
	static std::set<int>                        get_unavailable_cores       (int* most_recent_core);

	// 
	// Get the next available monitor identifier.
	//
    static int                                  get_next_monitorid          ();

	//
	// Returns true if backtraces have been requested for variants that are
	// shutting down.
	// 
    static bool                                 get_should_generate_backtraces();

	// 
	// Tell all monitors to check if their variants are multithreaded.
	// We use this to enable/disable the synchronization agents.
	//
    static void                                 set_should_check_multithread_state (int monitorid);

	//
    // Add the specified variant to the mvee::detachlist vector. A newly created
	// monitor can look through this list to fetch information about the
	// variants it should attach to.
	//
    static void                                 add_detached_variant        (detachedvariant* variant);

	// 
    // Returns true if the mvee::detachlist vector contains information about 
	// variants that have been detached from the specified monitor
	//
    static bool                                 have_detached_variants      (monitor* mon);
	
	// 
	// Removes the specified variant from the mvee::detachlist vector.
	// Returns the detachedvariant struct for the removed variant.
	//
    static detachedvariant*                     remove_detached_variant     (pid_t variantpid);

	// 
	// Returns true if the mvee::detachlist vecotr contains information
	// about variants to which the specified monitor should attach
	//
    static int                                  have_pending_variants       (monitor* mon);

    // 
	// Returns a smart pointer to the mmap_addr2line_proc structure for the
	// specified ELF binary.
	//
    static std::shared_ptr<mmap_addr2line_proc> get_addr2line_proc(const std::string& file_name);

	// 
	// Returns a smart pointer to the dwarf_info structure for the specified ELF
	// binary.
	// 
    static std::shared_ptr<dwarf_info>          get_dwarf_info(const std::string& file_name);

    //
    // Initializes a table of locks that should be locked for each syscall
    // executed by the variants. This function is implemented in
    // MVEE_syscalls_handlers.cpp.
    //
    static void init_syslocks               ();

	//
	// Returns a vector containing the pids of the slave variants that
	// correspond with the specified master variant
	//
    static bool map_master_to_slave_pids    (pid_t master_pid, std::vector<pid_t>& slave_pids);

    // *************************************************************************
    // OS/Environment configuration
    // *************************************************************************

	//
	// Returns the name of the folder from which we started the MVEE.
	//
    static std::string   os_get_orig_working_dir     ();

	// 
	// Returns the name of the root directory for the MVEE. This is the
	// directory that contains the MVEE, MVEE_LD_Loader, patched_binaries,
	// ... subdirectories
	// 
    static std::string   os_get_mvee_root_dir        ();

	// 
	// Reads the default maximum size of user-mode stacks using ulimit -s
	//
    static unsigned long os_get_stack_limit          ();

	// 
	// Get the number of logical CPU cores through sysconf
	//
    static int           os_get_num_cores            ();

	// 
	// Get the number of physical CPU sockets (not cores!) through /proc/cpuinfo
	//
    static int           os_get_num_physical_cpus    ();

	// 
	// Check and possibly change the kernel.yama.ptrace_scope setting through
	// sysctl. This is a temporary fix for the problem described in
	// https://lkml.org/lkml/2014/12/24/196
	//
    static void          os_check_ptrace_scope       ();

	// 
	// Check the vsyscall setting on the kernel command line. Warn the user
	// if vsyscall is not set to native
	//
    static void          os_check_kernel_cmdline     ();

	// 
	// Update the kernel.shmmax and kernel.shmall settings so we can allocate
	// additional shared memory pages through the SYSV ipc API
	//
    static bool          os_try_update_shmmax        ();

	// 
	// Get the monitor process id
	//
    static pid_t         os_getpid                   ();

	// 
	// Get the monitor thread id
	//
    static pid_t         os_gettid                   ();

	// 
	// Get the full path to the default ELF interpreter on the host machine
	// 
    static std::string   os_get_interp               ();

	// 
	// Determine the name of the interpreter to be used to execute @file
	// and add it to the @add_to_list deque.
	//
	// We do this by: 
	//
	// 1) Adding no interpreter at all if the file is an ELF file for the
	// host platform
	//
	// 2) checking the first line of the file to see if it starts with a
	// hashbang (#!). If it does, we add the interpreter specified by the
	// hashbang line.
	//
	// 3) looking at the file extension. We currently support .sh and .rb files
	// 
    static bool          os_add_interp_for_file      (std::deque<char*>& add_to_list, std::string& file);

	// 
	// Cache the interpreter name for the specified file
	//
    static void          os_register_interp          (std::string& file, const char* interp);

	// 
	// Get the full path for the MVEE_LD_Loader to be used on the host platform
	//
    static std::string   os_get_mvee_ld_loader       ();

	// 
	// Resets the environment variables we may have set earlier
	// 
    static void          os_reset_envp               ();

	//
	// Helper function to allocate a block of shared memory through the SYSV ipc
	// API
	//
	static bool          os_alloc_sysv_sharedmem     (unsigned long alloc_size, int* id_ptr, int* size_ptr, void** ptr_ptr);

	//
	// Uses objdump to get the RPATH for the specified ELF @binary. If there is
	// an RPATH, then we convert it to a full pathname
	//
	static std::string   os_get_rpath                (std::string& binary);

	//
	// Identifies the (relative) entry point address for the specified ELF @binary
	//
	static unsigned long os_get_entry_point_address  (std::string& binary);

	//
	// Normalizes @path by handling relative paths, double slashes, etc.
	//
	static std::string   os_normalize_path_name      (std::string path);

    // *************************************************************************
    // Miscellaneous Support Functions
    // *************************************************************************

	//
	// Tokenizes a string
	// 
    static std::deque<std::string> strsplit(const std::string& s, char delim);

	// 
	// Returns true if the searchstring ends with the specified suffix
	//
    static bool                    str_ends_with(std::string& search_in_str, const char* suffix);

	//
	// Valgrind-friendly version of strdup
	//
    static char*                   strdup(const char* orig);

	// 
	// Returns true if the string contains only printable characters
	//
    static bool                    is_printable_string(char* str, int len);

	// 
	// Convert an "old" integer-style sigset to a "new" sigset_t-style sigset
	//
    static sigset_t                old_sigset_to_new_sigset(unsigned long old_sigset);

    //
    // Access to global state - This lock protects the public variables that may
    // be modified at run-time
    //
    static void lock                        ();
    static void unlock                      ();
    
    // *************************************************************************
    // Monitor/Demo settings and properties. All of these are initialized during
    // monitor startup and not modified afterwards. It is therefore safe to read
    // these without holding the mvee lock 
	// *************************************************************************

    // set to true if we're running a native benchmark
    static bool                     no_monitoring;

    // command line arguments passed to the demo
    static std::vector<std::string> demo_args;

    // number of the demo we're running (cfr. MVEE_demos.cpp)
    static int                      demo_num;

    // Set to true if we're tracking performance counters for this demo
#ifdef MVEE_ALLOW_PERF
    static bool                     use_perf;
#endif

    // Number of variants we're running
    static int                      numvariants;

    // (optional) custom LD_LIBRARY_PATH to be used in the variants
    static std::string              custom_library_path;

    // Configuration read from MVEE.ini
    static struct mvee_config       config;

    // (optional) schedule type for this demo
    static unsigned int             demo_schedule_type;

    // (optional) set to true if we're running a program with over 100 simultaneous threads
    static bool                     demo_has_many_threads;

    // monitor object and id of the monitor we're running in this thread
    // we used to use this for almost everything but nowadays it's really just here
    // for logging...
    static __thread monitor*        active_monitor;
    static __thread int             active_monitorid;

	//
    // This is set when the mvee has been signalled for shutdown.
    // There are very frequent accesses to this variable and those
    // accesses are intentionally lock-free
	//
    static int                      shutdown_signal;

	// 
    // this maps syscalls onto the locks they need to execute reliably
	//
    static std::map<unsigned long, unsigned char>
                                    syslocks_table;

#ifdef MVEE_GENERATE_EXTRA_STATS
    static __thread bool            in_logging_handler;
#endif

    //
    // Lock/Cond that protects the variables below
    //
    static pthread_mutex_t          global_lock;
    static pthread_cond_t           global_cond;

    //
    // Global addr2line process cache
    //
    static std::map<std::string, std::weak_ptr<mmap_addr2line_proc> >
                                    addr2line_cache;
	//
    // Global dwarf cache
	//
    static std::map<std::string, std::weak_ptr<dwarf_info> >
                                    dwarf_cache;

    //
    // We use this to coordinate the initial transfer of the variants' ptrace 
	// control from the main MVEE process to the primary monitor thread.
	//
    volatile static unsigned long   can_run;

private:

	// *************************************************************************
    // Protected Logging functions - Implemented in MVEE_logging.cpp
	// *************************************************************************

	//
	// Wipes the Logs folder
	//
    static void clear_log_folder();

	// 
	// Opens the global log files (i.e. MVEE.log, MVEE_ptrace.log, ...)
	//
    static void log_init();

	//
	// Closes the global log files
	// 
    static void log_fini(bool terminated);

	// *************************************************************************
    // Variant Initialization
	// *************************************************************************

	//
	// Add the specified path to the LD_LIBRARY_PATH environment variable.  By
	// default, we prepend the specified @library_path with the path to the MVEE
	// root folder and append the library path suffix (e.g. "/amd64/") to the
	// path.
	// 
    static void        add_library_path       (const char* library_path, bool append_arch_suffix=true, bool prepend_mvee_root=true);

	// 
	// Serializes the argv vector for the current variant. This is called just
	// after forking the variants off from the main MVEE process. At this point,
	// the global state of the MVEE is still visible to the variants because 
	// they haven't execve'd yet.
	//
    static std::string prepare_argv           ();

	//
	// Implemented in MVEE_demos.cpp. This is where we configure the MVEE to run
	// the specified demo.  This function runs in the context of the main MVEE
	// process, after the variants have been forked off, but before they have
	// execve'd.
	// 
    static void        set_demo_options       (int demonum);

	//
	// Implemented in MVEE_demos.cpp. Set up the environment variables for the
	// current variant. This is called just after forking the variants off from
	// the main MVEE process, but before they have execve'd.
	//
    static void        setup_env              (int demonum, bool native);

	//
	// Implemented in MVEE_demos.cpp. This function starts the specified demo
	// in the context of one of the variant processes. This is usually as simple
	// as calling execve.
	//
    static void        start_demo             (int demonum, int variantindex, bool native);

	// 
	// Starts a variant directly (i.e. without using a shell to interpret the
	// startup command)
	// 
	static void        start_variant_direct   (const char* path, ...);

	// 
	// Starts a variant indirectly by executing a shell that interprets the
	// specified command.
	//
	static void        start_variant_indirect (const char* cmd);

	//
	// Get the name of the SPEC2006 profile to be used to run the current
	// variant
	//
	static const char* get_spec_profile       (bool native);

	// *************************************************************************
    // Config Initialization - This is our interface to the MVEE.ini file
	// *************************************************************************	
    static config_setting_t* config_setting_lookup_or_create(config_t* config, const char* path, int type);
    static void              config_store_uchar (config_t* config, const char* path, unsigned char value);
    static void              config_store_string (config_t* config, const char* path, const char* value);
    static void              config_store(unsigned char config_type, config_t* config, const char* path, void* value);
    static void              mvee_config_to_config_t (config_t* config);
    static void              config_lookup_uchar (config_t* config, const char* path, unsigned char* value);
    static void              config_lookup (unsigned char config_type, config_t* config, const char* path, void* value);
    static void              config_t_to_mvee_config (config_t* config);

	// *************************************************************************
    // Monitor management
	// *************************************************************************

	//
	// Opens /tmp/MVEE_signal_file.tmp. We use this file to request MVEE
	// shutdowns and/or backtraces remotely (using the MVEE_backtrace utility)
	//
    static char* open_signal_file();

	//
	// Shuts down the MVEE. This should not be called directly! Use
	// request_shutdown instead.
	// 
    static void  shutdown(int sig, int should_backtrace);

	// 
	// Runs the garbage collection loop to clean up the metadata for monitors
	// that have been shut down.
	// 
    static void  garbage_collect();

	// *************************************************************************
    // Monitor Management Variables
	// *************************************************************************

    // set to true when we've added new monitors to the garbage collection list
    static bool                                 should_garbage_collect;

    // list of monitors to be garbage collected
    static std::vector<monitor*>                monitor_gclist;

    // maps every variant pid onto the set of pids it's part of
    // i.e. this would contain M[A] -> {M[A], S[A]} and also S[A] -> {M[A], S[A]}
    static std::map<pid_t, std::vector<pid_t> > variant_pid_mapping;

    // maps every monitor id onto its monitor object
    static std::map<int, monitor*>              monitor_id_mapping;

    // monitor id to be used by the next monitor we spawn
    static int                                  next_monitorid;

    // variant threads that are in the process of being transferred from one monitor to the other
    static std::vector<detachedvariant*>        detachlist;

    //
    // OS/Environment configuration
    //
    static std::string                          orig_working_dir;
    static std::string                          mvee_root_dir;
    static unsigned int                         stack_limit;
    static int                                  num_cores;
    static int                                  num_physical_cpus;
    static pid_t                                process_pid;
    static __thread pid_t                       thread_pid;
    static std::map<std::string, std::string>   interp_map;

    //
    // Shutdown coordination
    //
    static std::vector<pid_t>                   shutdown_kill_list;
    static bool                                 shutdown_should_generate_backtraces;

    //
    // Logging Vars
    //
    static FILE*                                logfile;
    static FILE*                                ptrace_logfile;
    static FILE*                                datatransfer_logfile;
    static FILE*                                lockstats_logfile;
    static double                               initialtime;
    static pthread_mutex_t                      loglock;
    static bool                                 print_to_stdout;
};


#define warnf mvee::warnf

#ifdef MVEE_BENCHMARK
# ifdef __clang__
#  define debugf(...)
# else
#  define debugf(a...)
# endif
# define DEBUGVAR __attribute__((unused))
#else
# define debugf mvee::logf
# define DEBUGVAR
#endif


#endif /* MVEE_H_ */
