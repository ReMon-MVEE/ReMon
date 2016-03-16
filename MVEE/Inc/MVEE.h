/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
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
class detachedchild;
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

enum VariantArch
{
	ARCH_HOST,          // Variant should run natively
	ARCH_I386,          // Variant should run on top of qemu-i386
	ARCH_AMD64,         // Variant should run on top of qemu-amd64
	ARCH_ARM,           // Variant should run on top of qemu-arm
	ARCH_AARCH64        // Variant should run on top of qemu-aarch64
};


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
	const char*   mvee_qemu_path;
    config_t*     config;
};

//
// This represents the global state of the MVEE.
//
class mvee
{
public:

    //
    // Logging
    //
    static void        logf                        (const char* format, ...);
    static void        warnf                       (const char* format, ...);
    static void        log_ptrace_op               (int op_type, int op_subtype, int bytes);
    static void        log_dump_locking_stats      (monitor* mon, mmap_table* mmap_table, shm_table* shm_table);
    static std::string log_read_from_proc_pipe     (const char* proc, size_t* output_length);
    static std::string log_do_hex_dump             (const void* hexbuffer, int buffer_size);
    static void        log_register                (const char* register_name, unsigned long* register_ptr, void (*logfunc)(const char*, ...));
    static void        log_dwarf_rule              (unsigned int reg_num, void* _rule);
    static void        log_sigaction               (struct sigaction* action);

    //
    // MVEE Initialization/Shutdown
    //
    static void start_monitored             ();
    static void start_unmonitored           ();
    static void shutdown_add_to_kill_list   (pid_t kill_pid);
    static void init_config                 ();
    static void process_opt(char* opt);
    static void request_shutdown(bool should_backtrace);

    //
    // Monitor Management
    //
    static void                                 register_variants           (std::vector<pid_t>& pids);
    static void                                 register_monitor            (monitor* mon);
    static void                                 unregister_monitor          (monitor* mon);
    static bool                                 is_multiprocess             ();
	static std::set<int>                        get_unavailable_cores       (int* most_recent_core);
    static int                                  get_next_monitorid          ();
    static bool                                 get_should_generate_backtraces();
    static void                                 set_should_check_multithread_state (int monitorid);

    // Transfer support
    static void                                 add_detached_child          (detachedchild* child);
    static bool                                 have_detached_childs        (monitor* mon);
    static detachedchild*                       remove_detached_child (pid_t childpid);
    static int                                  have_pending_childs         (monitor* mon);

    // Debugging support
    static std::shared_ptr<mmap_addr2line_proc> get_addr2line_proc(const std::string& file_name);
    static std::shared_ptr<dwarf_info>          get_dwarf_info(const std::string& file_name);

    //
    // System call support functions that operate on global variables
    //
    static void init_syslocks               ();
    static bool map_master_to_slave_pids    (pid_t master_pid, std::vector<pid_t>& slave_pids);

    //
    // OS/Environment configuration
    //
    static std::string   os_get_orig_working_dir     ();
    static std::string   os_get_mvee_root_dir        ();
    static unsigned long os_get_stack_limit          ();
    static int           os_get_num_cores            ();
    static int           os_get_num_physical_cpus    ();
    static void          os_check_ptrace_scope       ();
    static void          os_check_kernel_cmdline     ();
    static bool          os_try_update_shmmax        ();
    static pid_t         os_getpid                   ();
    static pid_t         os_gettid                   ();
    static std::string   os_get_interp               ();
    static bool          os_add_interp_for_file      (std::deque<char*>& add_to_list, std::string& file);
    static void          os_register_interp          (std::string& file, const char* interp);
    static std::string   os_get_mvee_ld_loader       ();
    static void          os_reset_envp               ();
	static bool          os_alloc_sysv_sharedmem     (unsigned long alloc_size, int* id_ptr, int* size_ptr, void** ptr_ptr);
	static std::string   os_get_rpath                (std::string& binary);

    //
    // Miscellaneous Support Functions
    //
    static std::deque<std::string> strsplit(const std::string& s, char delim);
    static bool                    str_ends_with(std::string& search_in_str, const char* suffix);
    static char*                   strdup(const char* orig);
    static bool                    is_printable_string(char* str, int len);
    static sigset_t                old_sigset_to_new_sigset(unsigned long old_sigset);

    //
    // Access to global state - This lock protects the public variables that may be modified at run-time
    //
    static void lock                        ();
    static void unlock                      ();

    //
    // Monitor/Demo settings and properties. All of these are initialized during monitor
    // startup and not modified afterwards. It is therefore safe to read these without holding
    // the mvee lock
    //

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
    static __thread unsigned long   most_recent_fd;

    //
    // Shutdown Coordination
    //

    // This is set when the mvee has been signalled for shutdown.
    // There are very frequent accesses to this variable and those
    // accesses are intentionally lock-free
    static int                      shutdown_signal;

    //
    // Syscall support
    //

    // this maps syscalls onto the locks they need to execute reliably
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
    //
    volatile static unsigned long   can_run;
private:

    //
    // Logging
    //
    static void clear_log_folder();
    static void log_init();
    static void log_fini(bool terminated);

    //
    // Variant Initialization
    //
    static void        add_library_path       (const char* library_path, bool append_arch_suffix=true, bool prepend_mvee_root=true);
    static std::string prepare_argv           ();
    static void        set_demo_options       (int demonum, std::vector<VariantArch>& archs);
    static void        setup_env              (int demonum, bool native);
    static void        start_demo             (int demonum, int childindex, bool native);
	static void        start_variant_qemu     (VariantArch arch, const char* path, ...);
	static void        start_variant_direct   (const char* path, ...);
	static void        start_variant_indirect (const char* cmd);
	static const char* get_spec_profile       (bool native);

    //
    // Config Initialization
    //
    static config_setting_t* config_setting_lookup_or_create(config_t* config, const char* path, int type);
    static void              config_store_uchar (config_t* config, const char* path, unsigned char value);
    static void              config_store_string (config_t* config, const char* path, const char* value);
    static void              config_store(unsigned char config_type, config_t* config, const char* path, void* value);
    static void              mvee_config_to_config_t (config_t* config);
    static void              config_lookup_uchar (config_t* config, const char* path, unsigned char* value);
    static void              config_lookup (unsigned char config_type, config_t* config, const char* path, void* value);
    static void              config_t_to_mvee_config (config_t* config);

    //
    // Monitor management
    //
    static char* open_signal_file();
    static void  shutdown(int sig, int should_backtrace);
    static void  garbage_collect();

    //
    // Monitor Management
    //

    // set to true when we've added new monitors to the garbage collection list
    static bool                                 should_garbage_collect;

    // list of monitors to be garbage collected
    static std::vector<monitor*>                monitor_gclist;

    // maps every replica pid onto the set of pids it's part of
    // i.e. this would contain M[A] -> {M[A], S[A]} and also S[A] -> {M[A], S[A]}
    static std::map<pid_t, std::vector<pid_t> > replica_pid_mapping;

    // maps every monitor id onto its monitor object
    static std::map<int, monitor*>              monitor_id_mapping;

    // monitor id to be used by the next monitor we spawn
    static int                                  next_monitorid;

    // replica threads that are in the process of being transferred from one monitor to the other
    static std::vector<detachedchild*>          detachlist;

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
