/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <string.h>
#include <sstream>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_filedesc.h"
#include "MVEE_mman.h"
#include "MVEE_shm.h"
#include "MVEE_macros.h"
#include "MVEE_signals.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_syscalls.h"
#include "MVEE_syscalls_support.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "hde.h"

/*-----------------------------------------------------------------------------
    syscall_arg class - We use this to cache data arguments
-----------------------------------------------------------------------------*/
syscall_arg::syscall_arg()
{
    type  = ARG_BUFFER;
    buf   = NULL;
    cstr  = NULL;
    str   = "";
    valid = false;
}

syscall_arg::~syscall_arg()
{
    reset();
}

void syscall_arg::reset()
{
    if (!valid)
        return;

    switch(type)
    {
        case ARG_BUFFER:
        {
            if (buf)
            {
                delete[] ((unsigned char*)buf);
                buf = NULL;
            }
            break;
        }
        case ARG_CSTRING:
        {
            SAFEDELETEARRAY(cstr);
            break;
        }
        case ARG_STRING:
        {
            str = "";
            break;
        }
    }
    valid = false;
}

void syscall_arg::set_buf(void* b)
{
    type  = ARG_BUFFER;
    buf   = b;
    valid = true;
}

void syscall_arg::set_cstr(char* c)
{
    type  = ARG_CSTRING;
    cstr  = c;
    valid = true;
}

void syscall_arg::set_str(std::string& s)
{
    type  = ARG_STRING;
    str   = s;
    valid = true;
}

/*-----------------------------------------------------------------------------
    variantstate class
-----------------------------------------------------------------------------*/
variantstate::variantstate()
    : variantpid(0),
    prevcallnum(0),
    callnum(0),
    call_flags(0),
    return_value(0),
    extended_value(0),
    call_type(0),
    call_dispatched(false),
    regs_valid(false),
    return_valid(false),
    restarted_syscall(false),
    restarting_syscall(false),
    variant_terminated(false),
    variant_pending(false),
    variant_attached(false),
    variant_resumed(false),
    current_signal_ready(false),
	  fast_forward_to_entry_point(false),
	  entry_point_bp_set(false),
    last_lower_region_start(0),
    last_lower_region_size(0),
    last_upper_region_start(0),
    last_upper_region_size(0),
    last_mmap_result(0),
	entry_point_address(0),
	ipmon_region(NULL),
	hidden_buffer_array_id(0),
	hidden_buffer_array_base(0),
	hidden_buffer_array(NULL),
    varianttgid(0),
    pendingpid(0),
    infinite_loop_ptr(0),
    should_sync_ptr(0),
    callnumbackup(0),
    orig_controllen(0)
#ifdef __NR_socketcall
    , orig_arg1(0)
#endif
#ifdef CHECK_SYNC_PRIMITIVES
    , sync_primitives_bitmask(0),
    sync_primitives_ptr(NULL)
#endif
{
    memset(&regs, 0, sizeof(struct user_regs_struct));
    sigemptyset(&last_sigset);
    memset(&regsbackup, 0, sizeof(struct user_regs_struct));
    memset(hw_bps,      0, 4*sizeof(unsigned long));
    memset(hw_bps_type, 0, 4*sizeof(unsigned char));
    memset(tid_address, 0, 2*sizeof(void*));
}

/*-----------------------------------------------------------------------------
    is_logging_enabled
-----------------------------------------------------------------------------*/
bool monitor::is_logging_enabled()
{
#ifdef MVEE_FILTER_LOGGING
    if (!set_mmap_table || !set_mmap_table->set_logging_enabled)
        return false;
#endif
    return true;
}

/*-----------------------------------------------------------------------------
    is_group_shutting_down
-----------------------------------------------------------------------------*/
bool monitor::is_group_shutting_down()
{
    if (!set_mmap_table || set_mmap_table->thread_group_shutting_down)
        return true;
    return false;
}

/*-----------------------------------------------------------------------------
    monitor - creates and initializes a new monitor

    if the new monitor is a primary (i.e. monitor 0), the monitor is created
    with no variants. This monitor gets empty fd/mmap/shm/sighand tables and
    is not registered automatically.

    if the new monitor is a secondary monitor, the variants are created with
    the pids specified by the parent monitor. The fd/mmap/shm/sighand tables
    are either duplicated or attached and the new monitor is registered
    automatically.
-----------------------------------------------------------------------------*/
void monitor::init()
{
    monitor_log                    = NULL;
    created_by_vfork               = false;
    should_check_multithread_state = false;
    should_shutdown                = false;
    call_succeeded                 = false;
    in_new_heap_allocation         = false;
    monitor_registered             = false;
    monitor_terminating            = false;
    have_pending_signals           = false;
    ipmon_initialized              = false;
    monitorid                      = 0;
    parentmonitorid                = 0;
    state                          = STATE_NORMAL;
    atomic_buffer                  = NULL;
	atomic_buffer_hidden           = false;
    ipmon_buffer                   = NULL;
    current_signal                 = 0;
    current_signal_sent            = 0;
    current_signal_info            = NULL;
#ifdef MVEE_ALLOW_PERF
    perf                           = false;
#endif
    monitor_tid                    = 0;
	master_core                    = -1;

	blocked_signals.resize(mvee::numvariants);
	old_blocked_signals.resize(mvee::numvariants);
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		sigemptyset(&blocked_signals[i]);
		sigemptyset(&old_blocked_signals[i]);
	}

    variants.resize(mvee::numvariants);
    atomic_counters.resize(mvee::numvariants);
    atomic_queue_pos.resize(mvee::numvariants);

    monitorid                      = mvee::get_next_monitorid();
    log_init();

    pthread_mutex_init(&monitor_lock, NULL);
    pthread_cond_init(&monitor_cond, NULL);
}

monitor::monitor(monitor* parent_monitor, bool shares_fd_table, bool shares_mmap_table, bool shares_sighand_table, bool shares_tgid)
{
    init();

    parentmonitorid   = parent_monitor->monitorid;

    set_fd_table      = shares_fd_table ?
                        parent_monitor->set_fd_table :
                        std::shared_ptr<fd_table>(new fd_table(*parent_monitor->set_fd_table));

    set_mmap_table    = shares_mmap_table ?
                        parent_monitor->set_mmap_table :
                        std::shared_ptr<mmap_table>(new mmap_table(*parent_monitor->set_mmap_table));

    // after forking/cloning, the new variants continue to use the
    // parent's shm table...
    set_shm_table     = parent_monitor->set_shm_table;

    set_sighand_table = shares_sighand_table ?
                        parent_monitor->set_sighand_table :
                        std::shared_ptr<sighand_table> (new sighand_table(*parent_monitor->set_sighand_table));

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        init_variant(i, parent_monitor->variants[i].pendingpid,
                   shares_tgid ? parent_monitor->variants[i].varianttgid : parent_monitor->variants[i].pendingpid);
    }

    // variant monitors are a different story. New variants (forks/vforks/clones) always
    // start with a sigstop, regardless of what monitormode we run in
    state             = STATE_WAITING_ATTACH;

    std::vector<pid_t> newpids = getpids();
    mvee::register_variants(newpids);
    pthread_create(&monitor_thread, NULL, monitor::thread, this);
    debugf("Spawned variant monitor - id: %d\n", monitorid);
}

monitor::monitor(std::vector<pid_t>& pids)
{
    init();

    // the primary monitor starts with empty tables
    set_fd_table      = std::shared_ptr<fd_table>   (new fd_table());
    set_mmap_table    = std::shared_ptr<mmap_table> (new mmap_table());
    set_shm_table     = std::shared_ptr<shm_table>  (new shm_table());
    set_sighand_table = std::shared_ptr<sighand_table>(new sighand_table());

    // Monitor 0 runs in a seperate thread IF we do not run in singlethreaded mode
    // Consequently, monitor 0 starts in STATE_WAITING_ATTACH if we run in multithreaded mode
    // if we do not run in multithreaded mode, monitor 0 can start in normal mode
    state             = STATE_WAITING_ATTACH;

    for (int i = 0; i < mvee::numvariants; ++i)
        init_variant(i, pids[i], pids[i]);

    std::vector<pid_t> newpids = getpids();
    mvee::register_variants(newpids);
    pthread_create(&monitor_thread, NULL, monitor::thread, this);
    debugf("Spawned variant monitor - id: %d\n", monitorid);
}

// Just here so we don't instantiate an implicit destructor in MVEE.cpp
monitor::~monitor()
{

}

int monitor::get_master_core()
{
	// release the cores if the monitor is no longer active
	if (monitor_terminating)
		return -1;

	// consider the cores available if this thread is simply
	// waiting for other threads
	if (state == STATE_IN_SYSCALL && (variants[0].callnum == __NR_wait4
									  || variants[0].callnum == __NR_futex))
		return -1;

	return master_core;
}

/*-----------------------------------------------------------------------------
    mvee_mon_set_ptrace_options - Sets the ptrace options required by the
    monitor for the specified variant.
-----------------------------------------------------------------------------*/
int monitor::init_ptrace_options(int variantnum)
{
    return mvee_wrap_ptrace(PTRACE_SETOPTIONS, variants[variantnum].variantpid, 0,
                            (void*)(PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                                    PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                                    PTRACE_O_TRACESYSGOOD));
}

/*-----------------------------------------------------------------------------
    init_variant - Initializes the state info for a new variant traced by the monitor.
-----------------------------------------------------------------------------*/
void monitor::init_variant(int variantnum, pid_t variantpid, pid_t varianttgid)
{
    variants[variantnum].callnum   = NO_CALL;
    variants[variantnum].variantpid  = variantpid;
    variants[variantnum].varianttgid = varianttgid ? varianttgid : variantpid;
}

/*-----------------------------------------------------------------------------
    restart_variant - This is very fancy. We wait for the specified variant
    to hit its next rendez-vous point and then force it to execute a new execve
    call with its original arguments
-----------------------------------------------------------------------------*/
bool monitor::restart_variant(int variantnum)
{
    bool              result = false;

    // We can get the original argvs from the set_mmap_table and the original envps
    // from /proc/<pid>/environ
    int               pid    = variants[variantnum].variantpid, status;

    debugf("We're attempting to restart variant: %d (PID: %d)\n",
               variantnum, variants[variantnum].variantpid);

    // First of all, we have to wait until we reach the next syscall entry
    mvee_wrap_ptrace(PTRACE_SYSCALL, pid, 0, NULL);
    while (true)
    {
        if (should_shutdown)
        {
            shutdown(true);
            return false;
        }

        if (pid == wait4(pid, &status, 0, NULL))
        {
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSYSTRAP)
            {
                debugf("Hit the first syscall entrance!\n");
                break;
            }
            else
            {
                warnf("The variant we were restarting was signalled, but not because of a syscall entrance event - status: %08X\n", status);
                shutdown(true);
                return false;
            }
        }
    }

	rewrite_execve_args(variantnum, false, true);

    // dispatch the call and wait for the return
    debugf("Restarting variant...\n");
    mvee_wrap_ptrace(PTRACE_SYSCALL, pid, 0, NULL);
    while (true)
    {
        if (pid == wait4(pid, &status, 0, NULL))
        {
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSYSTRAP)
            {
                debugf("Hit first syscall after execve\n");
                result = true;
                break;
            }
            else if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))
            {
                debugf("got TRACE_EXEC event\n");
                mvee_wrap_ptrace(PTRACE_SYSCALL, pid, 0, NULL);
            }
            else
            {
                warnf("seen unknown event - restart failed\n");
                result = false;
                break;
            }
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    rewrite_execve_args
-----------------------------------------------------------------------------*/
void monitor::rewrite_execve_args(int variantnum, bool write_to_stack, bool rewrite_envp)
{
    std::string       image  = set_mmap_table->mmap_startup_info[variantnum].image;
    std::deque<char*> argv   = get_original_argv(variantnum);
	std::deque<char*> envp;
	pid_t pid = variants[variantnum].variantpid;

	// We might want to do this if we want to restart a variant altogether
	if (rewrite_envp)
	{
		// Get the original envp array
		char              cmd[256];
		sprintf(cmd, "strings /proc/%d/environ", variants[variantnum].variantpid);

		std::string       envps = mvee::log_read_from_proc_pipe(cmd, NULL);
		if (envps != "")
		{
			std::stringstream ss(envps);
			std::string       ln;

			while(std::getline(ss, ln, '\n'))
				envp.push_back(mvee::strdup(ln.c_str()));
		}
		envp.push_back(NULL);
	}

    // the original image becomes the first argument for our interpreter
    SAFEDELETEARRAY(argv.front());
    argv.pop_front();
    argv.push_front(mvee::strdup(image.c_str()));

	size_t argv_size = argv.size();
	if (!mvee::os_add_interp_for_file(argv, image))
	{
		warnf("ERROR: Could not determine interpreter for file: %s\n", image.c_str());
		shutdown(false);
		return;
	}

	// if we added an interpreter, then store its name in real_image
    if (argv.size() > argv_size)
	{
		set_mmap_table->mmap_startup_info[variantnum].real_image = 
			std::string(argv[0]);
	}

	// insert custom library path
    if (mvee::custom_library_path.length() > 0)
    {
		std::stringstream ss;
        if (mvee::custom_library_path.size() > 0)
        {
            if (ss.gcount() > 0)
                ss << ":";
            ss << mvee::custom_library_path;
        }

		argv.push_front(mvee::strdup(ss.str().c_str()));
		argv.push_front(mvee::strdup("--library-path"));
    }

	// insert ELF interpreter if necessary
	if (mvee::custom_library_path.length() > 0)
	{
		if (mvee::config.mvee_hide_vdso || mvee::config.mvee_use_dcl)
		{
			argv.push_front(mvee::strdup(MVEE_LD_LOADER_NAME));
			image = mvee::os_get_mvee_ld_loader();
		}
		else
		{
			argv.push_front(mvee::strdup(MVEE_ARCH_INTERP_NAME));
			image = mvee::os_get_interp();
		}
	}

	// Everything is set up and ready to write...
#ifndef MVEE_BENCHMARK
	std::stringstream full_serialized_argv;
	for (auto arg : argv)
		if (arg)
			full_serialized_argv << arg << " ";
	debugf("Injecting the following execve args - image: %s - argv: %s\n",
		 image.c_str(),
		 full_serialized_argv.str().c_str());
#endif

    // serialize, relocate, write, ...
    unsigned long argv_len = 0, envp_len = 0;

    for (unsigned i = 0; i < argv.size(); ++i)
        if (argv[i])
            argv_len += strlen(argv[i]) + 1;
    for (unsigned i = 0; i < envp.size(); ++i)
        if (envp[i])
            envp_len += strlen(envp[i]) + 1;

    char*             serialized_argv               = new char[argv_len];
    char*             serialized_envp               = (envp_len > 0) ? new char[envp_len] : NULL;
    char**            relocated_argv                = NULL;
    char**            relocated_envp                = NULL;

    // Find an appropriate location to write all of this stuff
    unsigned long     total_len                     =
        (image.length() + 1) +                      // the new execve image
        (sizeof(char*) * argv.size()) +             // the argv pointer array
        (sizeof(char*) * envp.size()) +             // the envp pointer array
        argv_len +
        envp_len;
	
	unsigned long image_target_address;
	if (write_to_stack)
	{
		image_target_address = SP(variants[variantnum].regs) - 1024 - total_len;
	}
	else
	{
		mmap_region_info* writable = set_mmap_table->find_writable_region(variantnum, total_len);
		if (!writable)
		{
			warnf("Could not find a writable region of at least %lu bytes long in the address space of variant: %d (PID: %d) => execve arguments writing failed\n",
				  total_len, variantnum, pid);
			shutdown(false);
			return;
		}
		image_target_address = writable->region_base_address;
	}

    // now serialize and relocate
    // We want the following layout in the writable region
    // +------------------+---------------+---------------+--------------+--------------+
    // | new execve image | argv pointers | envp pointers | argv strings | envp strings |
    // +------------------+---------------+---------------+--------------+--------------+
    //
    unsigned long     relocated_argv_target_address = image_target_address + image.length() + 1;
    unsigned long     relocated_envp_target_address = relocated_argv_target_address + (sizeof(char*) * argv.size());
    unsigned long     argv_target_address           = relocated_envp_target_address + (sizeof(char*) * envp.size());
    unsigned long     envp_target_address           = argv_target_address + argv_len;

    serialize_and_relocate_arr(argv, serialized_argv, relocated_argv, argv_target_address);
	if (rewrite_envp)
		serialize_and_relocate_arr(envp, serialized_envp, relocated_envp, envp_target_address);

    debugf("Writing new execve arguments...\n");
    if (mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)image.c_str(), pid, image_target_address, image.length() + 1) == -1
        || mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)relocated_argv, pid, relocated_argv_target_address, sizeof(char*) * argv.size()) == -1
        || (rewrite_envp && mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)relocated_envp, pid, relocated_envp_target_address, sizeof(char*) * envp.size()) == -1)
        || mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)serialized_argv, pid, argv_target_address, argv_len) == -1
        || (rewrite_envp && mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)serialized_envp, pid, envp_target_address, envp_len) == -1))
    {
        warnf("Couldn't copy execve arguments to address space of variant: %d (PID: %d) => execve arguments writing\n", variantnum, pid);
        shutdown(false);
        return;
    }

    // set the registers
    debugf("Setting execve registers...\n");
    SETARG1(variantnum, image_target_address);
    SETARG2(variantnum, relocated_argv_target_address);
	if (rewrite_envp)
		SETARG3(variantnum, relocated_envp_target_address);
    WRITE_SYSCALL_NO(variantnum, __NR_execve);

    SAFEDELETEARRAY(serialized_argv);
    SAFEDELETEARRAY(serialized_envp);
    SAFEDELETEARRAY(relocated_argv);
    SAFEDELETEARRAY(relocated_envp);
    for (unsigned i = 0; i < argv.size(); ++i)
        SAFEDELETEARRAY(argv[i]);
    for (unsigned i = 0; i < envp.size(); ++i)
        SAFEDELETEARRAY(envp[i]);
}

/*-----------------------------------------------------------------------------
  enable_sync - As of 04/2014, we have a should_sync flag in the MVEE
  glibc. A pointer to this flag is passed to the monitor during startup.
  Initially, every process is single threaded and their should_sync flag is set
  to 0. When we're entering multithreaded state (i.e. at the call site of the
  first fork-like call), we set the flag to 1 to enable synchronization from
  there on.
-----------------------------------------------------------------------------*/
void monitor::enable_sync()
{
#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
    debugf("variant is entering multithreaded state\n");
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].should_sync_ptr)
        {
            long current = mvee_wrap_ptrace(PTRACE_PEEKDATA, variants[i].variantpid,
                                            (unsigned long)variants[i].should_sync_ptr, NULL);
            *(unsigned char*)&current = 1;
            mvee_wrap_ptrace(PTRACE_POKEDATA, variants[i].variantpid,
                             (unsigned long)variants[i].should_sync_ptr, (void*)(long)2);
        }
    }
#endif
}

/*-----------------------------------------------------------------------------
  mvee_mon_disable_sync - Every time a thread dies, the monitor checks whether
  the variants are still multi-threaded. This is done at a rendez-vous point.
  If the variants are no longer multi-threaded, we can safely write a 0 to
  the should sync flag.
-----------------------------------------------------------------------------*/
void monitor::disable_sync()
{
#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
    debugf("variant is entering singlethreaded state\n");
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].should_sync_ptr)
        {
            long current = mvee_wrap_ptrace(PTRACE_PEEKDATA, variants[i].variantpid,
                                            (unsigned long)variants[i].should_sync_ptr, NULL);
            *(unsigned char*)&current = 0;
            mvee_wrap_ptrace(PTRACE_POKEDATA, variants[i].variantpid,
                             (unsigned long)variants[i].should_sync_ptr, (void*)(long)1);
        }
    }
#endif
}

/*-----------------------------------------------------------------------------
  is_program_multithreaded -
-----------------------------------------------------------------------------*/
bool monitor::is_program_multithreaded()
{
    // if noone else shares the address space, the variants are either
    // single threaded or multi-threaded without the possibility to communicate
    // with other threads. In either case, it is safe to assume that we're
    // now single threaded...
    if (set_mmap_table.use_count() == 1)
        return false;

    return true;
}

/*-----------------------------------------------------------------------------
  mvee_mon_check_multithread_state - should be called if the main thread in
  this group is at a rendez-vous point - otherwise this wouldn't be safe!!!
-----------------------------------------------------------------------------*/
void monitor::check_multithread_state()
{
    if (should_check_multithread_state)
    {
        should_check_multithread_state = false;
        if (!is_program_multithreaded())
            disable_sync();
    }
}

/*-----------------------------------------------------------------------------
    await_pending_transfers -
-----------------------------------------------------------------------------*/
void monitor::await_pending_transfers()
{
    // There's an interesting race that can happen here. If we shut down just after
    // our variants have cloned but the new monitor isn't detached to the new clones yet,
    // the new monitor might get -EPERM on the PTRACE_ATTACH request
    while (!mvee::shutdown_signal)
    {
        if (!mvee::have_detached_variants(this))
            break;

        // we might still have to detach from them... wait with non-blocking wait4
        int status, variant = wait4(-1, &status, __WALL | WUNTRACED | __WNOTHREAD | WNOHANG, NULL);
        if (variant > 0)
            handle_event(variant, status);
    }
}

/*-----------------------------------------------------------------------------
    signal_shutdown - can be called from outside this monitor's thread
    to force the monitor to shut down
-----------------------------------------------------------------------------*/
void monitor::signal_shutdown()
{
    MutexLock lock(&monitor_lock);

    // signal monitor for shutdown
    if (!should_shutdown)
        should_shutdown = 1;

    warnf("signalling monitor %d for shutdown - monitor state is: %s\n",
                monitorid, getTextualState(state));

    pthread_cond_signal(&monitor_cond);

    if (monitor_tid)
    {
        long result = syscall(__NR_tgkill, mvee::os_getpid(), monitor_tid, SIGUSR1);
        if (result)
        {
            warnf("tried to signal monitor %d for shutdown but tgkill failed: %s\n",
                        monitorid, strerror(errno));
        }
    }
}

/*-----------------------------------------------------------------------------
    signal_registration - signals the monitor thread when the registration
    is complete
-----------------------------------------------------------------------------*/
void monitor::signal_registration()
{
    MutexLock lock(&monitor_lock);
    monitor_registered = true;
    pthread_cond_signal(&monitor_cond);
}

/*-----------------------------------------------------------------------------
    getpids -
-----------------------------------------------------------------------------*/
std::vector<pid_t> monitor::getpids()
{
    std::vector<pid_t> result(mvee::numvariants);
    for (int i = 0; i < mvee::numvariants; ++i)
        result[i] = variants[i].variantpid;
    return result;
}

/*-----------------------------------------------------------------------------
    join_thread - called by the MVEE garbage collector
-----------------------------------------------------------------------------*/
void monitor::join_thread()
{
    pthread_join(monitor_thread, NULL);
}

/*-----------------------------------------------------------------------------
    get_mastertgid
-----------------------------------------------------------------------------*/
pid_t monitor::get_mastertgid()
{
    return variants[0].varianttgid;
}

/*-----------------------------------------------------------------------------
    set_should_check_multithread_state
-----------------------------------------------------------------------------*/
void monitor::set_should_check_multithread_state()
{
    should_check_multithread_state = true;
}

/*-----------------------------------------------------------------------------
    mvee_mon_return - Called by each monitor thread just before returning
-----------------------------------------------------------------------------*/
void monitor::shutdown(bool success)
{
	bool have_running_variants = false;

    debugf("monitor returning - success: %d\n", success);
    if (monitor_terminating)
        return;

    monitor_terminating = 1;

    // see if we can control the damage
    if (!success)
    {
        // if we have other monitors that monitor different processes,
        // then just kill this local process
        // and let the other monitors continue
        bool have_other_processes = mvee::is_multiprocess();

        if (!have_other_processes)
        {
            debugf("GHUMVEE is only monitoring one process group => we're shutting everything down\n");
            if (!set_mmap_table->thread_group_shutting_down)
                mvee::request_shutdown(true);
        }
        else
        {
            // just kill this group
            debugf("GHUMVEE is monitoring multiple process groups => we're only shutting this group down\n");

#ifndef MVEE_BENCHMARK
			if (!set_mmap_table->thread_group_shutting_down)
				log_dump_queues(set_shm_table.get());
#endif

            for (int i = 0; i < mvee::numvariants; ++i)
            {
                if (!variants[i].variant_terminated)
                {
#ifndef MVEE_BENCHMARK
					if (!set_mmap_table->thread_group_shutting_down)
						log_variant_backtrace(i);
#endif
                    variants[i].variant_terminated = true;
                    kill(variants[i].varianttgid, SIGKILL);
                }
            }

            // TODO: should we only do this if we shut down the last thread in the group???
            //if (!is_program_multithreaded())
            //{
            goto nobacktrace;
            //}
        }
    }

    if (mvee::get_should_generate_backtraces() &&
		!set_mmap_table->thread_group_shutting_down)
        log_backtraces();

nobacktrace:

    // this is hacky... haven't found a proper solution for this yet
    // we allow monitors to shut down at any point during their execution
    // even if they're holding locks...
    set_sighand_table->full_release_lock();
    set_mmap_table->full_release_lock();
    set_fd_table->full_release_lock();
    set_shm_table->full_release_lock();

    // We explicitly reset the shared pointers here so all of the tables get deleted if we were the last monitor referring to them
    set_fd_table.reset();
    if (set_shm_table.use_count() == 1)
    {
#ifdef MVEE_GENERATE_LOCKSTATS
        set_shm_table->update_all_lock_stats();
        mvee::log_dump_locking_stats(this, set_mmap_table.get(), set_shm_table.get());
#endif
#ifdef MVEE_ALWAYS_DUMP_QUEUES
        log_dump_queues(set_shm_table.get());
#endif
    }
    set_shm_table.reset();
    // if we're the second to last one holding a ref to this mmap table then let the main thread know that we're possible singlethreaded again
    if (set_mmap_table.use_count() == 2)
        mvee::set_should_check_multithread_state(set_mmap_table->mmap_execve_id);
    set_mmap_table.reset(); // must be freed AFTER the shm table
    set_sighand_table.reset();

    if (atomic_buffer)
        delete atomic_buffer;
    if (ipmon_buffer)
        delete ipmon_buffer;

	if (variants[0].hidden_buffer_array)
		for (int i = 0; i < mvee::numvariants; ++i)
			shmdt(variants[i].hidden_buffer_array);

    pthread_mutex_lock(&monitor_lock);
    local_detachlist.clear();
    pthread_mutex_unlock(&monitor_lock);

    for (int i = 0; i < mvee::numvariants; ++i)
	{
        if (!variants[i].variant_terminated)
		{
            mvee::shutdown_add_to_kill_list(variants[i].variantpid);
			have_running_variants = true;
		}
	}

#ifdef MVEE_ALLOW_PERF
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].perf_out.length() > 0)
        {
            warnf("Variant %d (PID: %d) Performance Counters:\n>>> START <<<\n%s\n>>> END <<<\n",
                        i, variants[i].variantpid, variants[i].perf_out.c_str());
        }
        variants[i].perf_out.erase();
    }
#endif

    // Successful return. Unregister the monitor from all mappings
    log_fini();
    mvee::unregister_monitor(this);

	// As soon as we shut this thread down, the remaining tracees will be able to run uncontrolled
	// => simply pause and wait for the management thread to shut us down if we still have
	// running variants
    if (!have_running_variants)
        pthread_exit(NULL);
    else
        pause();

    return;
}

/*-----------------------------------------------------------------------------
    get_original_argv - 
-----------------------------------------------------------------------------*/
std::deque<char*> monitor::get_original_argv(int variantnum)
{
    std::deque<char*> argv;

    for (unsigned i = 0; i < set_mmap_table->mmap_startup_info[variantnum].argv.size(); ++i)
        argv.push_back(mvee::strdup(set_mmap_table->mmap_startup_info[variantnum].argv[i].c_str()));

    argv.push_back(NULL);
    return argv;
}

/*-----------------------------------------------------------------------------
    serialize_and_relocate_arr - We can use this function to build
    a char array (e.g. argv or envp) that we will the write into a variant's
    address space at target_address.

    The function first serializes the array and then builds a pointer array
    with each pointer pointing to its corresponding element as if the serialized
    array had already been written into the variant's address space.
-----------------------------------------------------------------------------*/
void monitor::serialize_and_relocate_arr
(
    std::deque<char*>& arr,
    char*            & serialized,
    char**           & relocated,
    unsigned long    target_address
)
{
    unsigned int serialized_len = 0;

    if (!serialized)
    {
        for (unsigned i = 0; i < arr.size(); ++i)
            if (arr[i])
                serialized_len += strlen(arr[i]) + 1;
        serialized = new char[serialized_len];
    }

    if (!relocated)
        relocated = new char*[arr.size()];

    long         pos            = 0;
    for (unsigned i = 0; i < arr.size(); ++i)
    {
        if (arr[i])
        {
            int len = strlen(arr[i]);
            memcpy(serialized + pos, arr[i], len + 1);
            relocated[i] = (char*)pos;
            pos         += len + 1;
        }
        else
            relocated[i] = (char*)NULL;
    }

    for (unsigned i = 0; i < arr.size(); ++i)
    {
        if (relocated[i] || (i == 0))
        {
            relocated[i] = (char*)(target_address + (unsigned long)relocated[i]);
        }
    }
}

/*-----------------------------------------------------------------------------
    update_sync_primitives
-----------------------------------------------------------------------------*/
void monitor::update_sync_primitives ()
{
#ifdef MVEE_CHECK_SYNC_PRIMITIVES
    if (variants[0].sync_primitives_ptr)
        variants[0].sync_primitives_bitmask =
            mvee_wrap_ptrace(PTRACE_PEEKDATA, variants[0].variantpid, (long)variants[0].sync_primitives_ptr, NULL);
#endif
}

/*-----------------------------------------------------------------------------
    mvee_mon_handle_event - Every event we get from waitpid goes through this
    function
-----------------------------------------------------------------------------*/
void monitor::handle_event (pid_t variantpid, int status)
{
    int index;

    // find the variant index
    for (index = 0; index < mvee::numvariants; ++index)
        if (variants[index].variantpid == variantpid)
            break;

    // we intercepted an event that shouldn't be delivered to this monitor
    // perhaps this is a newly spawned variant that we haven't detached from yet?
    if (index >= mvee::numvariants)
    {
        for (std::vector<int>::iterator it = local_detachlist.begin();
             it != local_detachlist.end(); ++it)
        {
            if ((*it) == variantpid)
            {
                local_detachlist.erase(it);
                handle_detach_event(variantpid, status);
                return;
            }
        }

        debugf("Unknown variant event: %d - %s\n", variantpid, getTextualWaitEventType(status).c_str());
        unknown_variants.push_back(variantpid);
        return;
    }

    // check for exit events first
    if (unlikely(WIFEXITED(status)))
    {
        handle_exit_event(index);
        return;
    }
    else if (WIFSTOPPED(status))
    {
        // We use PTRACE_O_TRACESYSGOOD so all syscall events are delivered
        // with a SIGSYSTRAP stopsig rather than a SIGTRAP stopsig...
        if (WSTOPSIG(status) == SIGSYSTRAP)
        {
            handle_syscall_event(index);
            return;
        }
        // Other traps. These are either fork/clone events
        // or breakpoints
        else if (WSTOPSIG(status) == SIGTRAP)
        {
            int event = ((status & 0x000F0000) >> 16);
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE)
                handle_fork_event(index, event);
            else
                handle_trap_event(index);
            return;
        }
        // segmentation faults are usually triggered by RDTSC
        else if (WSTOPSIG(status) == SIGSEGV)
        {
            if (handle_rdtsc_event(index))
                return;
        }
        else if (WSTOPSIG(status) == SIGSTOP)
        {
            if (state == STATE_WAITING_ATTACH && !variants[index].variant_attached)
            {
                handle_attach_event(index, status);
                return;
            }
            if (state == STATE_WAITING_RESUME && !variants[index].variant_resumed)
            {
                handle_resume_event(index);
                return;
            }
        }
    }

    handle_signal_event(index, status);
}

/*-----------------------------------------------------------------------------
    handle_rdtsc_event - Checks if the current SIGSEGV of a variant is caused
    by executing the rdtsc instruction and if so, handles the signal.

    @param variantnum variant index

    @return true if the SIGSEGV signal was handled, false otherwise
-----------------------------------------------------------------------------*/
bool monitor::handle_rdtsc_event(int variantnum)
{
    // get signal info
    siginfo_t siginfo = {0};
    mvee_wrap_ptrace(PTRACE_GETSIGINFO, variants[variantnum].variantpid, 0, (void*)&siginfo);

    // SIGSEGV caused by rdtsc is always sent by the kernel
    if (siginfo.si_code == SI_KERNEL)
    {
        // read current opcode
        FETCH_IP(variantnum, eip);
        long current_opcode = mvee_wrap_ptrace(PTRACE_PEEKDATA, variants[variantnum].variantpid, eip, NULL);

        // rdtsc opcode should be in lower 2 bytes
        if ((short int)(current_opcode & 0x0000FFFF) == 0x310F)
        {
            debugf("Variant %d (PID: %d) is trying to execute the rdtsc instruction\n",
                       variantnum, variants[variantnum].variantpid);

			if (variants[variantnum].fast_forward_to_entry_point)
			{
				debugf("Variant is fast forwarding. Allowing rdtsc\n");

                unsigned int upper, lower;
                asm volatile ("rdtsc\n" : "=a" (lower), "=d" (upper));

				// write back result
				WRITE_RDTSC_RESULT(variantnum, lower, upper);

				// Move the instruction pointer just past the rdtsc instruction
				FETCH_IP(variantnum, eip);
				WRITE_IP(variantnum, eip + 2);
				
				// Now resume it
				mvee_wrap_ptrace(PTRACE_SYSCALL, variants[variantnum].variantpid, 0, NULL);
				return true;
			}

            // set syscall number to fake syscall that indicates rdtsc
            variants[variantnum].callnum = MVEE_RDTSC_FAKE_SYSCALL;

            int i;
            // Check if all variants have reached the synchronization point
            for (i = 1; i < mvee::numvariants; ++i)
                if (variants[i].callnum != variants[i-1].callnum)
                    break;

            // Check for callnumber mismatches
            if (i < mvee::numvariants)
            {
                // Mismatches occur in two cases:
                //     Either one of the variants hasn't reached the sync point yet (allowed)
                //     OR not all variants are executing the same call (NOT allowed)
                if (variants[i].callnum == NO_CALL
                    || variants[i-1].callnum == NO_CALL
                    || variants[i].call_type == MVEE_CALL_TYPE_UNSYNCED
                    || variants[i-1].call_type == MVEE_CALL_TYPE_UNSYNCED)
                {
                    return true;
                }
                else
                {
                    log_call_mismatch(i, i-1);
                    shutdown(false);
                    return true;
                }
            }
            // All variants have reached the sync point
            else
            {
                debugf("Sync point reached. Executing rdtsc and writing back result.\n");

                // execute rdtsc in the monitor
                unsigned int upper, lower;
                asm volatile ("rdtsc\n" : "=a" (lower), "=d" (upper));

                for (i = 0; i < mvee::numvariants; ++i)
                {
                    // write back result
                    WRITE_RDTSC_RESULT(i, lower, upper);

                    // Move the instruction pointer just past the rdtsc instruction
                    FETCH_IP(i, eip);
                    WRITE_IP(i, eip + 2);

                    // Now resume it
                    variants[i].callnum = NO_CALL;
                    mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
                }

                return true;
            }
        }
    }

    return false;
}

/*-----------------------------------------------------------------------------
    handle_attach_event
-----------------------------------------------------------------------------*/
void monitor::handle_attach_event(int index, int status)
{
    long success DEBUGVAR = mvee_wrap_ptrace(PTRACE_ATTACH, variants[index].variantpid, 0, NULL);
    variants[index].variant_attached = 1;
    debugf("Attached to variant: %d => success: %s\n", variants[index].variantpid, success ? "NO" : "YES");

    bool all_attached = true;
    for (int i = 0; i < mvee::numvariants; ++i)
        if (!variants[i].variant_attached)
            all_attached = false;

    if (all_attached)
        state = STATE_WAITING_RESUME;
}

/*-----------------------------------------------------------------------------
    handle_detach_event - this variant was created by our monitor
    but we shouldn't be tracing it
-----------------------------------------------------------------------------*/
void monitor::handle_detach_event(pid_t variantpid, int status)
{
    detachedvariant* new_variant = NULL;

    debugf("received event for variant: %d\n", variantpid);
    if (WIFSTOPPED(status))
        debugf("variant stopped with sig: %s\n", getTextualSig(WSTOPSIG(status)));

    // look for the variant in the global detach list
    new_variant = mvee::remove_detached_variant(variantpid);

    if (!new_variant)
    {
        warnf("couldn't find detached variant: %d in detachlist!\n", variantpid);
        shutdown(false);
        return;
    }

    if (!new_variant->transfer_func)
    {
        warnf("It seems that you are trying to run a multi-threaded or multi-process application.\n");
        warnf("For these applications, GHUMVEE currently requires a GHUMVEE-enabled\n");
        warnf("version of eglibc. The GHUMVEE eglibc contains a small infinite loop to\n");
        warnf("which we transfer the control while detaching a monitor from a variant\n");
        warnf("thread. By the time the new monitor attaches to this thread, the thread\n");
        warnf("will still be in this infinite loop (duh).\n");
        warnf("\n");
        warnf("Without this trick we'd have to wait until the first syscall in order to\n");
        warnf("safely detach from a thread.\n");
        warnf("\n");
        warnf("Install the GHUMVEE libc please kthnxbye\n");
        shutdown(false);
        return;
    }

    mvee_wrap_ptrace(PTRACE_GETREGS, new_variant->variantpid, 0, &new_variant->original_regs);
    // instruct the variant to execute the infinite loop WITH syscalls in it
    // WRITE_FASTCALL_ARG1_PID(new_variant->variantpid, 0);
    // WRITE_FASTCALL_ARG1_PID(new_variant->variantpid, 0);
    // WRITE_IP_PID(new_variant->variantpid, (unsigned long)new_variant->transfer_func + 2);

	user_regs_struct tmp;
	memcpy(&tmp, &new_variant->original_regs, sizeof(user_regs_struct));
	FASTCALL_ARG1(tmp) = 0;
	IP(tmp) = (unsigned long)new_variant->transfer_func/* + 2*/;
	mvee_wrap_ptrace(PTRACE_SETREGS, new_variant->variantpid, 0, &tmp);

    long success DEBUGVAR = mvee_wrap_ptrace(PTRACE_DETACH, new_variant->variantpid, 0, NULL);

    debugf("Used fast detach for variant: %d => ip: " PTRSTR " => success: %s\n",
               new_variant->variantpid, new_variant->transfer_func, success ? "NO" : "YES");

    new_variant->parent_has_detached = 1;
    monitor*       new_mon = new_variant->new_monitor;

    mvee::add_detached_variant(new_variant);

    // we can now register the new monitor
    if (mvee::have_pending_variants(new_mon) == mvee::numvariants)
    {
        debugf("Detached from all variants in this thread set!\n");

        // make sure that the pids don't stick around in the local detachlist
        int reset_it = 1;
        while (reset_it)
        {
            reset_it = 0;
            for (std::vector<pid_t>::iterator it = local_detachlist.begin();
                 it != local_detachlist.end(); ++it)
            {
                for (int i = 0; i < mvee::numvariants; ++i)
                {
                    if (*it == new_mon->variants[i].variantpid)
                    {
                        local_detachlist.erase(it);
                        reset_it = 1;
                        break;
                    }
                }

                if (reset_it)
                    break;
            }
        }

        mvee::register_monitor(new_mon);
    }
}

/*-----------------------------------------------------------------------------
    handle_resume_event
-----------------------------------------------------------------------------*/
void monitor::handle_resume_event(int index)
{
    variants[index].variant_resumed = true;
    init_ptrace_options(index);

    // before we resume the variant, we have to look for it in the global detachlist
    if (monitorid)
    {
        detachedvariant* attached_variant = mvee::remove_detached_variant(variants[index].variantpid);

        if (!attached_variant)
        {
            warnf("attached to a variant that did not appear in the detachlist - FIXME!\n");
            shutdown(false);
            return;
        }

        variants[index].infinite_loop_ptr = attached_variant->transfer_func;
//		attached_variant->original_regs.gs_base = 0;
        mvee_wrap_ptrace(PTRACE_SETREGS, variants[index].variantpid, 0, &attached_variant->original_regs);
        variants[index].tid_address[0]    = attached_variant->tid_address[0];
        variants[index].tid_address[1]    = attached_variant->tid_address[1];
        delete attached_variant;
    }
    else
    {
        // retarded hack
        //        WRITE_SYSCALL_RETURN(index, 1);
        mvee_wrap_ptrace(PTRACE_POKEDATA, variants[index].variantpid, (unsigned long)&mvee::can_run, (void*)(unsigned long)1);
    }

    // We do not actually resume until all of our variants are ready. This way we can set tids if needed
    //    mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);

    debugf("ready to resume variant: %d\n", variants[index].variantpid);

    bool all_resumed = true;
    for (int i = 0; i < mvee::numvariants; ++i)
        if (!variants[i].variant_resumed)
            all_resumed = false;

    if (all_resumed)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            // non-master variants need the master tids if they have cloned with CLONE_PARENT_SETTID and/or CLONE_CHILD_SETTID
            // the ptid/ctid pointers that point to the tid value are stored in tid_address
            if (i > 0)
            {
                for (int j = 0; j < 2; ++j)
                {
                    if (variants[i].tid_address[j])
                    {
                        debugf("setting master tid for variant: %d\n", variants[i].variantpid);
						
						mvee_rw_write_pid(variants[i].variantpid, 
										  (unsigned long)variants[i].tid_address[j], 
										  variants[0].variantpid);
                    }
                }
            }

            // And finally it's safe to resume the variant
            debugf("resumed variant: %d\n", variants[i].variantpid);
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
        }

        state = STATE_NORMAL;
    }
}

/*-----------------------------------------------------------------------------
    handle_exit_event
-----------------------------------------------------------------------------*/
void monitor::handle_exit_event(int index)
{
    debugf("SIGTERM variant: %d\n", variants[index].variantpid);
    variants[index].variant_terminated = true;
    // pretending like we've reached the end of the syscall to keep our
    // orchestra-like polling mechanism happy
    variants[index].callnum          = NO_CALL;

    bool bAllTerminated = true;
    for (index = 0; index < mvee::numvariants; ++index)
    {
        if (!variants[index].variant_terminated)
        {
            bAllTerminated = false;
            break;
        }
    }

    if (bAllTerminated)
    {
        debugf("All variant processes have terminated. Shutting down.\n");
        shutdown(true);
    }
}

/*-----------------------------------------------------------------------------
    handle_fork_event
-----------------------------------------------------------------------------*/
void monitor::handle_fork_event(int index, int event)
{
    // Store new pid in variantstate
    mvee_word word;
    mvee_wrap_ptrace(PTRACE_GETEVENTMSG,
                     variants[index].variantpid,
                     0, &word._long);
    variants[index].pendingpid = word._pid;

    debugf("Fork Event: %d - Variant: %d - Pending PID: %d\n",
               event, variants[index].variantpid,
               variants[index].pendingpid);

    bool      bSpawnMonitor = true;
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].pendingpid == 0)
        {
            bSpawnMonitor = false;
            break;
        }
    }

    if (bSpawnMonitor)
    {
        bool     shares_fd_table      = false;
        bool     shares_mmap_table    = false;
        bool     shares_sighand_table = false;
        bool     shares_threadgroup   = false;

        // We can't use if (event == PTRACE_EVENT_CLONE) because clone without CLONE_THREAD/CLONE_VM actually triggers a PTRACE_EVENT_FORK event
        if (variants[0].callnum == __NR_clone)
        {
            shares_fd_table      = ARG1(0) & CLONE_FILES;
            shares_mmap_table    = ARG1(0) & CLONE_VM;
            shares_sighand_table = ARG1(0) & CLONE_SIGHAND;
            shares_threadgroup   = ARG1(0) & CLONE_THREAD;
        }
        else if (variants[0].callnum == __NR_vfork)
        {
            // variants created by vfork share an address space with their parent
            // until they call execve
            shares_mmap_table = true;
        }

        monitor* new_monitor = new monitor(this,
                                           shares_fd_table, shares_mmap_table, shares_sighand_table, shares_threadgroup);
        if (variants[0].callnum == __NR_vfork)
            new_monitor->created_by_vfork = true;

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            detachedvariant* new_variant = new detachedvariant;
            memset(new_variant, 0, sizeof(detachedvariant));

            // init detachedvariant
            new_variant->variantpid            = variants[i].pendingpid;
            variants[i].pendingpid           = 0;
            new_variant->parentmonitorid     = monitorid;
            new_variant->parent_has_detached = 0;
            new_variant->transfer_func       = variants[i].infinite_loop_ptr;
            new_variant->new_monitor         = new_monitor;

            if (variants[0].callnum == __NR_clone)
            {
                if (ARG1(0) & CLONE_PARENT_SETTID)
                    new_variant->tid_address[0] = (void*)ARG3(i);
                if (ARG1(0) & CLONE_CHILD_SETTID)
                    new_variant->tid_address[1] = (void*)ARG4(i);
            }

            // register in global detachlist so the new monitor can see it
            mvee::add_detached_variant(new_variant);

            // register in the local detachlist so we can recognize the detach event
            local_detachlist.push_back(new_variant->variantpid);

            // look for variants we've already received an event from
            for (std::vector<pid_t>::iterator it = unknown_variants.begin();
                 it != unknown_variants.end(); ++it)
            {
                if (*it == new_variant->variantpid)
                {
                    handle_detach_event(new_variant->variantpid, 0);
                    unknown_variants.erase(it);
                    break;
                }
            }
        }

        for (int i =0; i < mvee::numvariants; ++i)
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);

        state = STATE_IN_SYSCALL;
    }
}

/*-----------------------------------------------------------------------------
    handle_trap_event
-----------------------------------------------------------------------------*/
void monitor::handle_trap_event(int index)
{
    // not a known event. Might be a breakpoint!
    siginfo_t siginfo = {0};
    mvee_wrap_ptrace(PTRACE_GETSIGINFO, variants[index].variantpid, 0, (void*)&siginfo);

    if (siginfo.si_code == MVEE_TRAP_HWBKPT)
	{
		if (variants[index].fast_forward_to_entry_point)
		{
			unsigned long dr6 = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[index].variantpid,
												 offsetof(user, u_debugreg) + 6*sizeof(long), NULL);

			for (int i = 0; i < 4; ++i)
			{
				if (dr6 & (1 << i))
				{
					if (variants[index].hw_bps[i] == variants[index].entry_point_address)
					{
						warnf("Variant %d has reached its entry point - Switching to lock-step execution\n",
							  index);
						variants[index].fast_forward_to_entry_point = false;
						hwbp_unset_watch(index, variants[index].entry_point_address);
						break;
					}
				}
			}
		}
		else
		{
			log_hw_bp_event(index, &siginfo);
		}
	}

    mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);
}

/*-----------------------------------------------------------------------------
    handle_syscall_entrance_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_entrance_event(int index)
{
    pid_t variant DEBUGVAR = variants[index].variantpid;
    long  i, precall_flags, call_flags;

    //    FETCH_SYSCALL_NO(index, callnum);
    // => we usually end up fetching all registers anyway, which would make the above a wasted ptrace call...

	// TODO/FIXME - stijn: possibly deliver signals for fastforwarding variants
	// here

    variants[index].regs_valid      = false;
    call_check_regs(index);

    for (int i = 0; i < 7; ++i)
        variants[index].args[i].reset();

    long  callnum = SYSCALL_NO(variants[index].regs);

    variants[index].callnum         = callnum;
    variants[index].call_dispatched = false;
    variants[index].call_type       =
        call_precall_get_call_type(index, variants[index].callnum);

    // the current syscall is unsynced. dispatch it!
    if (variants[index].call_type == MVEE_CALL_TYPE_UNSYNCED)
    {
        debugf("pid: %d - nonsynced syscall: %ld (%s) \n", variant,
                   variants[index].callnum,
                   getTextualSyscall(variants[index].callnum));

        variants[index].call_flags      = call_call_dispatch_unsynced(index);
        if (variants[index].call_flags & MVEE_CALL_DENY)
            WRITE_SYSCALL_NO(index, __NR_getpid);

        mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);
        variants[index].call_dispatched = true;
        return;
    }

    // Debug print
    debugf("pid: %d - synced syscall: %ld (%s)\n", variant,
               variants[index].callnum,
               getTextualSyscall(variants[index].callnum));

    // Check if all variants have reached the synchronization point
    for (i = 1; i < mvee::numvariants; ++i)
	{
        if ((variants[i].callnum != variants[i-1].callnum)
            || (variants[i].call_type != variants[i-1].call_type))
		{
            break;
		}
	}

    // Check for callnumber mismatches
    if (i < mvee::numvariants)
    {
        // Mismatches occur in four cases:
        //     Either one of the variants hasn't reached the sync point yet (allowed)
        //     OR one of the variants is executing an unsynced call (allowed)
        //     OR not all variants are executing the same call (NOT allowed)
        if (variants[i].callnum == NO_CALL
            || variants[i-1].callnum == NO_CALL
            || variants[i].call_type == MVEE_CALL_TYPE_UNSYNCED
            || variants[i-1].call_type == MVEE_CALL_TYPE_UNSYNCED)
        {
            return;
        }
        else if ((variants[i].callnum == __NR_exit || variants[i].callnum == -1)
                 && (variants[i-1].callnum == __NR_exit || variants[i-1].callnum == -1))
        {
            return;
        }
        else
        {
            log_call_mismatch(i, i-1);
            shutdown(false);
            return;
        }
    }
    // All variants have reached the sync point
    else
    {
        debugf("Sync point reached. Checking signal queue.\n");
        if (sig_prepare_delivery())
            return;

        // RVP => check if the should_sync flag needs toggling
        check_multithread_state();

        debugf("Checking call arguments for syscalls.\n");

        // Resume if the arguments are equivalent
        precall_flags = call_precall();

        // Arguments match => let's see how this call should be dispatched
        if (precall_flags & MVEE_PRECALL_ARGS_MATCH)
        {
            debugf("Call arguments match. RESUMING\n");

args_match:

            if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_NORMAL)
            {
                debugf("Dispatching as normal syscall\n");
                state = STATE_IN_SYSCALL;
            }
            else if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_MASTER)
            {
                debugf("Dispatching as mastercall\n");
                state = STATE_IN_MASTERCALL;
            }
            else if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_FORK)
            {
                debugf("Dispatching as normal syscall - FORK BASED\n");
                state = STATE_IN_FORKCALL;

                // Sick data race here!!!! Signals are not delivered to variants
                // while they are executing a fork call.
            }
            else if (precall_flags & MVEE_PRECALL_CALL_DENY)
            {
                debugf("Dispatching was denied. Shutting down monitor...\n");
                shutdown(false);
                return;
            }

            call_flags = call_call_dispatch();

            for (i = 0; i < mvee::numvariants; ++i)
            {
                variants[i].call_flags      = call_flags;
                variants[i].call_dispatched = true;
            }

            if (!(call_flags & MVEE_CALL_DENY))
            {
                if (state == STATE_IN_MASTERCALL)
                    for (i = 1; i < mvee::numvariants; ++i)
                        WRITE_SYSCALL_NO(i, __NR_getpid);

                call_resume_all();
            }
            else
                call_resume_fake_syscall(); // executes getpid instead
        }
        // Arguments do not match
        // => log error and shut down monitor
        else
        {
            if (!call_is_known_false_positive(&precall_flags))
            {
				dump_mismatch_info();
                log_callargs_mismatch();
                shutdown(false);
            }
            else
            {
				flush_mismatch_info();

				// clear call deny flag
				precall_flags &= ~MVEE_PRECALL_CALL_DENY;
                goto args_match;
            }
        }
    }
}

/*-----------------------------------------------------------------------------
    handle_syscall_exit_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_exit_event(int index)
{
    int i;

    variants[index].return_valid = false;
    call_postcall_get_variant_result(index);

    // Whether we decide to deliver the signal right away or not, we still have
    // to restart the syscall!
    if (variants[index].return_value == -ERESTARTNOHAND
        || variants[index].return_value == -ERESTARTSYS
        || variants[index].return_value == -ERESTART_RESTARTBLOCK
        || variants[index].return_value == -ERESTARTNOINTR)
    {
        if (current_signal && variants[index].return_value == -ERESTARTNOHAND)
        {
            debugf(">>> JUMPING TO SIGNAL HANDLER\n");
            variants[index].callnum = NO_CALL;
            state                 = STATE_NORMAL;
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);
            return;
        }

        sig_restart_syscall(index);
        return;
    }

    variants[index].prevcallnum       = variants[index].callnum;
    variants[index].callnum           = NO_CALL;
    variants[index].restarted_syscall = false;

    // if the last syscall we've entered was an unsynced call
    // then dispatch the return right away...
    if (variants[index].call_type == MVEE_CALL_TYPE_UNSYNCED)
    {
        if (variants[index].call_flags & MVEE_CALL_DENY)
        {
            long err = variants[index].call_flags >> 6;
            if (variants[index].call_flags & MVEE_CALL_ERROR)
            {
                WRITE_SYSCALL_RETURN(index, ((unsigned long)-err));
				debugf("pid %d - unsynced syscall return: %ld (%s) - writing ret: %ld\n",
					   variants[index].variantpid,
					   variants[index].prevcallnum,
					   getTextualSyscall(variants[index].prevcallnum),
					   -err);

            }
            else if (variants[index].call_flags & MVEE_CALL_RETURN_EXTENDED_VALUE)
            {
                WRITE_SYSCALL_RETURN(index, variants[index].extended_value);

				debugf("pid %d - unsynced syscall return: %ld (%s) - writing ret: 0x" PTRSTR "\n",
					   variants[index].variantpid,
					   variants[index].prevcallnum,
					   getTextualSyscall(variants[index].prevcallnum),
					   variants[index].extended_value);
            }
            else
            {
                WRITE_SYSCALL_RETURN(index, err);

				debugf("pid %d - unsynced syscall return: %ld (%s) - writing ret: %ld\n",
					   variants[index].variantpid,
					   variants[index].prevcallnum,
					   getTextualSyscall(variants[index].prevcallnum),
					   err);

            }

            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);
            variants[index].call_type       = MVEE_CALL_TYPE_UNKNOWN;
            variants[index].call_dispatched = 0;
            return;
        }

		call_succeeded = call_check_result(variants[index].return_value);
        call_postcall_return_unsynced(index);
        mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);
        variants[index].call_type       = MVEE_CALL_TYPE_UNKNOWN;
        variants[index].call_dispatched = false;
        debugf("pid: %d - nonsynced syscall return: %ld (%s) \n",
                   variants[index].variantpid,
                   variants[index].prevcallnum,
                   getTextualSyscall(variants[index].prevcallnum));
        return;
    }

    // Synced call => we have to wait until we reach the sync point
    // Do not resume until all variants have returned
    bool all_synced         = true;
    bool all_synced_at_exit = true;
    for (i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].callnum != NO_CALL)
        {
            all_synced_at_exit = false;

            // A pretty complex race might be happening.  If we're in
            // STATE_IN_SYSCALL and some variants have their syscall interrupted
            // while for some variants it returns normally, then we just have to
            // restart those that have been interrupted here.
            if (!variants[i].restarted_syscall)
            {
                all_synced = false;
                break;
            }
        }
    }

    // Sync point reached... It's safe to let the variants return now
    if (all_synced_at_exit)
    {
        if (current_signal && !current_signal_sent)
        {
            debugf("All variants have returned and we can now deliver the signal.\n");
            sig_finish_delivery();
            return;
        }

        if (variants[0].call_flags & MVEE_CALL_DENY)
        {
            debugf("GHUMVEE prevented this call from entering the kernel\n");
			debugf("> EITHER because GHUMVEE has denied the call\n");
			debugf("> OR because GHUMVEE wants to return a value directly.\n");

            long err = variants[0].call_flags >> 6;

            if (variants[0].call_flags & MVEE_CALL_ERROR)
            {
                debugf("> returning error in all variants: %d\n", -err);
                for (i = 0; i < mvee::numvariants; ++i)
                    WRITE_SYSCALL_RETURN(i, ((unsigned long)-err));
            }
            else if (variants[0].call_flags & MVEE_CALL_RETURN_EXTENDED_VALUE)
            {
                for (i = 0; i < mvee::numvariants; ++i)
				{
					debugf("> returning value: %ld - in variant: %d\n", variants[i].extended_value, i);
                    WRITE_SYSCALL_RETURN(i, variants[i].extended_value);
				}
            }
            else
            {
                debugf("> returning value in all variants: %d\n", err);
                for (i = 0; i < mvee::numvariants; ++i)
                    WRITE_SYSCALL_RETURN(i, err);
            }
            state = STATE_NORMAL;
            call_resume_all();
            return;
        }

        if (state == STATE_IN_MASTERCALL)
        {
            call_succeeded = call_check_result(variants[0].return_value);
            debugf("Mastercall has returned. Result: %d\n", variants[0].return_value);

            if (!call_succeeded)
            {
                long err DEBUGVAR = -variants[0].return_value;
                debugf("Mastercall returned error: %d (%s)\n", 
					   err, err == ERESTARTSYS ? "ERESTARTSYS" : strerror(err));
            }

            for (i = 1; i < mvee::numvariants; ++i)
                WRITE_SYSCALL_RETURN(i, variants[0].return_value);
        }
        else
        {
            call_succeeded = call_postcall_all_syscalls_succeeded();
            debugf("All variants have returned. Call success: %d\n", call_succeeded);
        }

        long resume_flags = call_postcall_return();

        if (state == STATE_IN_MASTERCALL)
            debugf("Mastercall results copied\n");

        state = STATE_NORMAL;

        if (resume_flags != MVEE_POSTCALL_DONTRESUME)
            call_resume_all();
        else
            debugf("WARNING: postcall handler handled resume. not resuming...\n");
    }
    // See comment above. We're dealing with a race here
    else if (state == STATE_IN_SYSCALL && all_synced)
    {
        sig_restart_partially_interrupted_syscall();
    }
}

/*-----------------------------------------------------------------------------
    handle_syscall_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_event(int index)
{
    // ERESTARTSYS handler
    if (variants[index].restarting_syscall
        && !variants[index].restarted_syscall)
    {
        bool all_restarted = true;
        bool all_synced    = true;

        debugf("restarted syscall is back at syscall entry for variant: %d\n",
                   variants[index].variantpid);

        if (variants[index].call_type != MVEE_CALL_TYPE_UNSYNCED
            && state != STATE_IN_FORKCALL)
        {
            variants[index].restarted_syscall = true;

            // This is retarded. Some variants can return normally from the
            // syscall, while others can see a -ERESTART* error
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                if (!variants[i].restarting_syscall || !variants[i].restarted_syscall)
                {
                    all_restarted = false;

                    // call is still in progress
                    if (variants[i].callnum != NO_CALL)
                    {
                        all_synced = false;
                    }
                }
            }

            // Do not blindly resume the variants here! If it's either a master call
            // OR a normal call that was restarted in _all_ variants, we still have
            // to check if we can maybe deliver that pending signal.
            if (all_restarted)
            {
                debugf("All variants were restarted and are now back at the syscall entry\n");
                if (sig_prepare_delivery())
                {
//					debugf("Signal delivery in progress!\n");
                    for (int i = 0; i < mvee::numvariants; ++i)
                        variants[i].restarting_syscall = false;
                    return;
                }
                else
                {
                    // no signal to be delivered. Was this a spurious wakeup?!
                    // can also happen if a signal was delivered during a master call!!!
                    debugf("no signal to be delivered...\n");
                    for (int i = 0; i < mvee::numvariants; ++i)
                    {
                        debugf("all restarted - resuming variant %d from restarted syscall entry\n", i);
                        variants[i].restarting_syscall = variants[i].restarted_syscall = false;
                        mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
                    }
                    return;
                }

            }
            else if (state != STATE_IN_MASTERCALL && all_synced)
            {
                sig_restart_partially_interrupted_syscall();
            }
            return;
        }
        else
        {
            debugf("unsynced or forkcall - resuming variant %d from restarted syscall entry\n", index);
            variants[index].restarting_syscall = variants[index].restarted_syscall = false;
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[index].variantpid, 0, NULL);
        }

        return;
    }

    if (variants[index].callnum == NO_CALL)
        handle_syscall_entrance_event(index);
    else
        handle_syscall_exit_event(index);
}

/*-----------------------------------------------------------------------------
    sig_restart_partially_interrupted_syscall
-----------------------------------------------------------------------------*/
void monitor::sig_restart_partially_interrupted_syscall()
{
    debugf("Some variants managed to return normally from this syscall\n");
    debugf("We'll resume the restarted variants without attempting to deliver any pending signals\n");

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].restarted_syscall)
        {
            debugf("not mastercall and all synced - resuming variant %d from restarted syscall entry\n", i);
            variants[i].restarting_syscall = variants[i].restarted_syscall = false;
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
        }
    }
}

/*-----------------------------------------------------------------------------
    handle_signal_event
-----------------------------------------------------------------------------*/
void monitor::handle_signal_event(int index, int status)
{
    if (WSTOPSIG(status) == SIGSTOP
        && state == STATE_WAITING_RESUME)
    {
        int i, j;

        debugf("Variant %d was stopped by signal 0x%08X (%s)\n",
                   variants[index].variantpid, WSTOPSIG(status), getTextualSig(WSTOPSIG(status)));

        if (!variants[index].variant_pending)
        {
            variants[index].variant_pending = true;

            // Don't resume the variants until they've all been stopped by sigstop.
            // Then they can all be resumed
            bool bResumeAll = true;
            for (j = 0; j < mvee::numvariants; ++j)
            {
                if (!variants[j].variant_pending)
                {
                    bResumeAll = false;
                    break;
                }
            }

            if (bResumeAll)
            {
                for (i = 0; i < mvee::numvariants; ++i)
                {
                    init_ptrace_options(i);
                    mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
                }

                state = STATE_NORMAL;
            }
        }
    }
    else
    {
        handle_sig_delivery_stop(index, status);
    }
}

/*-----------------------------------------------------------------------------
    mvee_sig_discard_pending_signal
-----------------------------------------------------------------------------*/
std::vector<mvee_pending_signal>::iterator
monitor::discard_pending_signal(std::vector<mvee_pending_signal>::iterator& it)
{
    std::vector<mvee_pending_signal>::iterator ret = pending_signals.erase(it);
    if (pending_signals.size() == 0)
		sig_set_pending_signals(false);
    return ret;
}

/*-----------------------------------------------------------------------------
    sig_set_pending_signals
-----------------------------------------------------------------------------*/
void monitor::sig_set_pending_signals(bool pending_signals)
{
	have_pending_signals = pending_signals;

	// This is perhaps not optimal...
	// We force IP-MON to dispatch all its syscalls as checked
	// as long as we have pending signals...
	if (ipmon_buffer)
	{
		struct ipmon_buffer* buffer = (struct ipmon_buffer*)(ipmon_buffer->ptr);
		buffer->ipmon_have_pending_signals = (pending_signals ? 1 : 0);
	}
}

/*-----------------------------------------------------------------------------
    in_ipmon_syscall
-----------------------------------------------------------------------------*/
bool monitor::in_ipmon_syscall(int variantnum, unsigned long ip)
{
//	if (mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 8 * R12, NULL) != 
//		(long)variants[variantnum].ipmon_key)
//		return false;		

	long current_opcode = mvee_wrap_ptrace(PTRACE_PEEKDATA, variants[variantnum].variantpid, ip - 2, NULL);
	if ((short int)((unsigned long)current_opcode & 0xFFFF) == 0x050F)
		return true;

	return false;
}

/*-----------------------------------------------------------------------------
    in_ipmon
-----------------------------------------------------------------------------*/
bool monitor::in_ipmon(int variantnum, unsigned long ip)
{
#ifndef MVEE_BENCHMARK
	std::string       caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, ip, 0);
	debugf("variant was in ins: %s\n", caller_info.c_str());
#endif

	mmap_region_info* region = set_mmap_table->get_region_info(variantnum, ip, 0);

#ifndef MVEE_BENCHMARK
	if (variants[variantnum].ipmon_region)
		debugf("> IP: 0x" PTRSTR " - ipmon_base: 0x" PTRSTR "\n",
			   ip, variants[variantnum].ipmon_region->region_base_address);

	if (region)
		region->print_region_info("> IP-MON REGION: ");
#endif

	if (region && region == variants[variantnum].ipmon_region)
		return true;

	return false;
}

/*-----------------------------------------------------------------------------
    mvee_sig_handle_sig_delivery_stop - Handles a signal sent to a variant.

    We execute this whenever a signal interrupts the execution of a variant.
    For asynchronous signals, we'll first call this when the initial signal
    is sent. We will then usually discard that signal and wait for a sync
    point. Then, at the sync point, we send the original signal ourselves
    and we let it go through from within this function.

    @param variantnum Variant index
    @param variantpid Variant PID
    @param status   Variant status, as returned by waitpid

    @return false if the variant was terminated by the signal, true otherwise
-----------------------------------------------------------------------------*/
void monitor::handle_sig_delivery_stop(int variantnum, int status)
{
    siginfo_t siginfo = {0};
	unsigned long ip = 0;

    // Terminated by unhandled signal
    if (WIFSIGNALED(status))
    {
        variants[variantnum].variant_terminated = true;
        warnf("Variant: %d was terminated by an unhandled %s signal, core dump: %s.\n",
                    variants[variantnum].variantpid, getTextualSig(WTERMSIG(status)),
                    WCOREDUMP(status) ? "yes" : "no");

        // Since we cannot recover from this, we might as well shut 
		// down the variants that have not received the signal
        shutdown(false);
        return;
    }
    else if (WIFSTOPPED(status)) // stopped by the delivery of a signal
    {
        int signal    = WSTOPSIG(status);
		bool skip_trapping_ins = false;

        if (signal == SIGALRM)
            debugf("caught SIGALRM in monitor %d - should_shutdown: %d\n", monitorid, should_shutdown);

        mvee_wrap_ptrace(PTRACE_GETSIGINFO, variants[variantnum].variantpid, 0, (void*)&siginfo);

        if (signal == SIGSEGV)
        {            
#ifdef MVEE_ENABLE_VALGRIND_HACKS
			if (!ip) FETCH_IP_DIRECT(variantnum, ip);
			mmap_region_info* region      = set_mmap_table->get_region_info(variantnum, ip, 0);
			if (!region || 
				(region && region->region_backing_file_fd == MVEE_ANONYMOUS_FD 
				 && (region->region_prot_flags & PROT_EXEC)))
			{
				warnf("intercepted segv from valgrind\n");
				goto dont_resolve_segv_origin;
			}
#endif

#ifndef MVEE_BENCHMARK
			if (!ip) FETCH_IP_DIRECT(variantnum, ip);
			std::string caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, ip, 0);
			debugf("variant %d crashed - trapping ins: %s\n", variantnum, caller_info.c_str());
#endif

			if ((unsigned long)siginfo.si_addr == 0x440 // intentional SEGV from the secure wall of clocks agent
				|| (unsigned long)siginfo.si_addr == 0x3c0) // intentional SEGV from IP-MON
				skip_trapping_ins = true;
        }

        if (skip_trapping_ins)
        {
			if (!ip) FETCH_IP_DIRECT(variantnum, ip);
            unsigned long instr[2];
			instr[0] = mvee_wrap_ptrace(PTRACE_PEEKTEXT, variants[variantnum].variantpid, ip, NULL);
			instr[1] = mvee_wrap_ptrace(PTRACE_PEEKTEXT, variants[variantnum].variantpid, ip + sizeof(long), NULL);
            HDE_INS(__instr);

            // attempt to disassemble instr
            HDE_DISAS(instr_len, &instr, &__instr);
            if (instr_len > 0)
            {
				debugf("Offending instruction is %d bytes long.\n", instr_len);
                WRITE_IP(variantnum, ip + instr_len);
                mvee_wrap_ptrace(PTRACE_SYSCALL, variants[variantnum].variantpid, 0, NULL);
            }
            else
            {
                warnf("couldn't skip offending instruction...\n");
            }

			return;
        }

#ifdef MVEE_ENABLE_VALGRIND_HACKS
dont_resolve_segv_origin:
#endif
        debugf("Signal %s (%d) received by variant %d.\n", getTextualSig(signal), signal, variants[variantnum].variantpid);

#ifndef MVEE_BENCHMARK
		if (!ip) FETCH_IP_DIRECT(variantnum, ip);		
		std::string caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, ip, 0);
		debugf("signal arrived while variant was executing ins: %s\n", caller_info.c_str());
		FETCH_SYSCALL_RETURN(variantnum, ret);
		debugf("ret is currently: %ld\n", ret);
#endif

        if (signal == SIGSEGV || signal == SIGBUS)
            log_segfault(variantnum);

        if (sighand_table::is_control_flow_signal(signal))
        {
#ifndef MVEE_BENCHMARK
            log_variant_backtrace(variantnum, 0, 0, 1);
#endif
            // immediately deliver signals that are probably caused by the
            // normal control flow
            debugf("Delivering control flow signal %s to variant %d.\n", getTextualSig(signal), variants[variantnum].variantpid);

#if 0 // MVEE_ENABLE_VALGRIND_HACKS
            if (siginfo.si_pid == variants[variantnum].variantpid
                && variantnum != 0)
            {
                siginfo.si_pid = variants[0].variantpid;
                mvee_wrap_ptrace(PTRACE_SETSIGINFO, variants[variantnum].variantpid, 0, (void*)&siginfo);
            }
#endif
            // deliver control flow signal
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[variantnum].variantpid, 0, (void*)(long)signal);
        }
		// if the MVEE is injecting the signal, then the monitor
		// will be the sender in siginfo.si_pid
        else if (siginfo.si_pid == mvee::os_getpid())
        {
            debugf("signal %s is ready for injection in variant: %d\n", getTextualSig(signal), variants[variantnum].variantpid);
            if (current_signal_info)
            {
				// restore the original sender
                siginfo.si_pid  = current_signal_info->si_pid;
                mvee_wrap_ptrace(PTRACE_SETSIGINFO, variants[variantnum].variantpid, 0, (void*)&siginfo);

                // if we're in a restarted sigsuspend, we will see the exit
				// site of the call before the actual sighandler is invoked
				//
                // if we're in a regular sigsuspend, we will not see the exit 
				// site but instead jump to the sighandler right away

                if (!variants[variantnum].restarting_syscall &&
                    !variants[variantnum].restarted_syscall)
                {
                    debugf("this is not a restarted call. We're expecting to see the signal handler right away!\n");
                    variants[variantnum].callnum = NO_CALL;
                    state                    = STATE_NORMAL;
                }

                variants[variantnum].current_signal_ready = true;
                bool all_ready = true;

                for (int i = 0; i < mvee::numvariants; ++i)
                    if (!variants[i].current_signal_ready)
                        all_ready = false;

                if (all_ready)
                {
                    debugf("signal is ready for injection in all variants. Injecting...\n");
                    debugf("releasing syslocks for %d (%s)\n", 
							   variants[0].callnumbackup, 
							   getTextualSyscall(variants[0].callnumbackup));

                    // thread sanitizer might complain about this! 
					// We should probably figure out at which point we injected the signal
                    call_release_syslocks(-1, variants[0].callnumbackup, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);
                    for (int i = 0; i < mvee::numvariants; ++i)
                        mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, (void*)(long)signal);
                }
            }
            else
            {
                debugf("signal NOT injected!!! Was this a shutdown signal???\n");
            }

            // Now it SHOULD be safe to release the sighand lock
            // There might still be a race (TODO: Check kernel implementation)
            // if another thread changes the signal disposition of the injected signal
            // before the current thread is effectively resumed, the signal might
            // be improperly handled
            // mvee_sig_release_lock();
        }
        else
        {
            bool insert_pending_sig = true;
            debugf("intercepted signal %s from pid: %d\n", getTextualSig(signal), siginfo.si_pid);

            if (signal > 0 && signal < 32)
            {
                // do not store duplicates for non-real time signals
                for (std::vector<mvee_pending_signal>::iterator it = pending_signals.begin();
                     it != pending_signals.end(); ++it)
                {
                    if (it->sig_no == signal)
                    {
                        debugf("found duplicate. Ignoring signal\n");

                        // but we should mark a bit in the recv mask
                        it->sig_recv_mask |= (1 << variantnum);
                        insert_pending_sig = false;
                        break;
                    }
                }
            }

            if (insert_pending_sig)
            {
                mvee_pending_signal tmp;
                tmp.sig_no           = siginfo.si_signo;
                tmp.sig_recv_mask    = (1 << variantnum);
                memcpy(&tmp.sig_info, &siginfo, sizeof(siginfo_t));
                pending_signals.push_back(tmp);
				sig_set_pending_signals(true);
                debugf("signal queued\n");
            }

			if (mvee::config.mvee_use_ipmon && variantnum == 0)
			{
				if (!ip) 
					FETCH_IP_DIRECT(variantnum, ip);		

				if (in_ipmon(0, ip))
				{
					if (in_ipmon_syscall(0, ip))
					{
						// force the syscall to return to user-space
						FETCH_SYSCALL_RETURN(0, ret);
						if (ret <= -512	&& ret >= -516)
						{
							debugf("forcing IP-MON syscall to return to user-space\n");

							// retarded hack. If we replace the orig_ax register by -1, 
							// the kernel will just bail out (in arch/x86/kernel/signal.c)
							// and return the fucking ERESTART error to user-space
							WRITE_SYSCALL_NO(0, -1);
						}
					}
                    // The chances of triggering this race are astronomically low...					
					/*else
					{
						std::string  caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, ip, 0);					
						// temporary hack to deal with this situation:
						//
						// master executes:
						// movq %gs:( UTCB_HIDDEN(SIGNAL_PENDING) ), %r11
						// <= signal arrives here
						// cmpq $0, %r11
						// jne utcb_execute_invalid_syscall
						// syscall
						//
						// the master might indefinitely block in the syscall instr
						// and the slaves will just wait for the result
						if (caller_info.find("utcb_unchecked_syscall") != std::string::npos)
						{
							// TODO: check if the syscall no is in rax yet
							debugf("RACE DETECTED - clearing syscall no\n");
							WRITE_SYSCALL_NO(0, -1);
						}
					}*/				
				}
			}

            // Continue normal execution for now.
            // When a signal is ignored, the variant that was about to execute the sighandler
            // will execute a sys_restart_syscall call.
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[variantnum].variantpid, 0, NULL);
        }
    }
}

/*-----------------------------------------------------------------------------
    sig_handle_sigchld_race - handles the annoying race that can trigger
	when a SIGCHLD is delivered during a (blocking) mastercall.

	If such a signal is delivered during a blocking call, then the master will
    have its call interrupted but we will also restart the slaves. If we do not
    receive the signal in the slaves by the time their syscalls have restarted
    however, then they will never see it.

	In this function we simply keep restarting the slaves until they also
	see the specified signal
-----------------------------------------------------------------------------*/
bool monitor::sig_handle_sigchld_race(std::vector<mvee_pending_signal>::iterator it)
{		
	int status;
	debugf("SIGCHLD race in mastercall!!!\n");

	std::vector<unsigned char> at_syscall_entry(mvee::numvariants);
	std::fill(at_syscall_entry.begin(), at_syscall_entry.end(), 1);

	unsigned short expected_recv_mask = 0;
	for (int i = 0; i < mvee::numvariants; ++i) 
		expected_recv_mask |= (1 << i);

	while (true)
	{
		if (it->sig_recv_mask == expected_recv_mask)
			break;

		for (int i = 1; i < mvee::numvariants; ++i)
		{
			// check if this variant has received the signal yet
			if (!(it->sig_recv_mask & (1 << i)))
			{
				// the variant is currently paused and must be resumed before we can see the SIGCHLD
				mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
				int err = wait4(variants[i].variantpid, &status, 0, NULL);

				if (err != variants[i].variantpid || !WIFSTOPPED(status))
				{
					if (!should_shutdown)
						warnf("ERROR while handling sigchld race in variant %d\n", i);
					return false;
				}

				if (WSTOPSIG(status) == SIGSYSTRAP)
				{
					// we're now at the syscall exit
					if (at_syscall_entry[i])
					{
						debugf("variant %d is at the syscall exit\n", i);
						WRITE_IP(i, IP(variants[i].regs) - 2);
						WRITE_NEW_SYSCALL_NO(i, __NR_getpid);
//						variants[i].callnum = NO_CALL;
						at_syscall_entry[i] = 0;
					}
					// back at the syscall entrance
					else
					{
						debugf("variant %d is at the syscall entry\n", i);
//						variants[i].callnum = __NR_getpid;
						at_syscall_entry[i] = 1;
					}
				}
				else if (WSTOPSIG(status) == it->sig_no)
				{
					debugf("variant %d has received the signal\n", i);
					it->sig_recv_mask |= (1 << i);
					at_syscall_entry[i] = 0;
				}
				else
				{
					warnf("ERROR: unexpected stop status while handling sigchld race in variant %d - stop status: %s\n", getTextualWaitEventType(status).c_str());
					return false;
				}				
			}
		}
	}

	debugf("all variants have received the signal\n");
	for (int i = 1; i < mvee::numvariants; ++i)
	{
		if (!at_syscall_entry[i])
		{
			mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
			int err = wait4(variants[i].variantpid, &status, 0, NULL);

			if (err != variants[i].variantpid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSYSTRAP)
			{
				warnf("error syncing variant %d at syscall entry - stopped: %d - stop status: %s\n",
							i, WIFSTOPPED(status), getTextualWaitEventType(status).c_str());
			}
			else
			{
				debugf("> variant %d is back at the syscall entry - ready to deliver signal\n", i);
			}
		}
	}

	return true;
}

/*-----------------------------------------------------------------------------
    sig_prepare_delivery - called from mvee_mon_handle_syscall_entrance_event
    when ALL variants are synced on the same syscall entrance.

    Should inspect the pending signal queue and the current blocked_signals mask
    and possibly prepare a signal for delivery. If a signal is prepared,
    the variants' contexts should be backed up and the current syscall should be
    skipped.
-----------------------------------------------------------------------------*/
bool monitor::sig_prepare_delivery ()
{
    if (current_signal || !have_pending_signals)
        return false;

    bool result = true;

    // keep the sighand table locked so the sig handlers cannot be changed
    // while we prepare a signal for delivery
    set_sighand_table->grab_lock();
    auto it     = pending_signals.begin();
    while (it != pending_signals.end())
    {
        // check if the group is willing to accept the signal
        if (sigismember(&blocked_signals[0], it->sig_no))
        {
            bool dont_block = false;

            if (variants[0].callnum == __NR_rt_sigsuspend
#ifdef __NR_sigsuspend
                || variants[0].callnum == __NR_sigsuspend
#endif
                )
            {
                // sigsuspend might be about to unblock the signal we're checking
                sigset_t _set = call_get_sigset(0, ARG1(0), OLDCALLIFNOT(__NR_rt_sigsuspend));

                if (!sigismember(&_set, it->sig_no))
                    dont_block = true;
            }

            if (!dont_block)
            {
                debugf("not delivering signal: %s (signal is currently blocked)\n", getTextualSig(it->sig_no));
                it++;
                continue;
            }
        }

        // check if the signal is handled
        if (set_sighand_table->action_table[it->sig_no].sa_handler == SIG_IGN
            || (set_sighand_table->action_table[it->sig_no].sa_handler == SIG_DFL
                && sighand_table::is_default_ignored_signal(it->sig_no)))
        {
            debugf("not delivering signal: %s (signal is currently ignored)\n", getTextualSig(it->sig_no));
            mvee::log_sigaction(&set_sighand_table->action_table[it->sig_no]);
            it = discard_pending_signal(it);
            continue;
        }

        // check if every variant has received the signal
        // TODO: Check which other signals this should apply to
        if (it->sig_no == SIGCHLD
            || it->sig_no == SIGCANCEL)
        {
            unsigned short expected_recv_mask = 0;
            for (int i = 0; i < mvee::numvariants; ++i) expected_recv_mask |= (1 << i);
            if (it->sig_recv_mask != expected_recv_mask)
            {
				if ((it->sig_recv_mask & 1) 
					&& state == STATE_IN_MASTERCALL
					&& it->sig_no == SIGCHLD)
				{
					if (!sig_handle_sigchld_race(it))
						return false;
				}
				else
				{
					debugf("not delivering signal: %s (signal has not been received by all variants)\n", getTextualSig(it->sig_no));
					it++;
					continue;
				}
            }
        }

        debugf("found that the group will accept signal: %s\n", getTextualSig(it->sig_no));

        // found a signal to deliver
        siginfo_t* tmp = new siginfo_t;
        memcpy(tmp, &it->sig_info, sizeof(siginfo_t));
        current_signal_sent = false;
        current_signal      = it->sig_no;
        current_signal_info = tmp;

        // delete from pending list
        it                  = discard_pending_signal(it);

        // backup context
        for (int i = 0; i < mvee::numvariants; ++i)
        {
//            mvee_wrap_ptrace(PTRACE_GETREGS, variants[i].variantpid, 0, &variants[i].regsbackup);
            memcpy(&variants[i].regsbackup, &variants[i].regs, sizeof(user_regs_struct));
            variants[i].callnumbackup = variants[i].callnum;
        }

        if (variants[0].callnum == __NR_rt_sigsuspend
#ifdef __NR_sigsuspend
            || variants[0].callnum == __NR_sigsuspend
#endif
            )
        {
            // we should be at the entry site now...
            if (variants[0].restarted_syscall)
            {
                debugf("We're in a restarted sys_[rt_]sigsuspend, we can deliver the signal right away!\n");
                result = true;
            }
            else
            {
                debugf("We're at the sys_[rt_]sigsuspend entry\n");
                result = false;
            }

            // do not skip the syscall, just deliver the signal right away
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                variants[i].current_signal_ready = false;

                int err = syscall(__NR_tgkill, variants[i].varianttgid,
                                  variants[i].variantpid, current_signal);

                if (err)
                {
                    warnf("signal delivery failed. sig: %s - target pid: %d - errno: %d (%s)\n",
                                getTextualSig(current_signal),
                                variants[i].variantpid,
                                -err, strerror(-err));
                }

                // If we're at the entry of a sigsuspend that hasn't been restarted yet, we will call the precall handler next
                if (result)
                    mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
            }

            current_signal_sent = true;
        }
        else
        {

            debugf("Skipping current syscall\n");
            call_resume_fake_syscall();
            result = true;
        }

        set_sighand_table->release_lock();
        return result;
    }

    // no eligible signal found, sighand lock can be released
    set_sighand_table->release_lock();
    return false;
}

/*-----------------------------------------------------------------------------
    sig_finish_delivery - we still have the sighand lock at this point
    It is not safe to release it yet until the signal is injected. This
    is called from mvee_mon_handle_syscall_exit_event
-----------------------------------------------------------------------------*/
void monitor::sig_finish_delivery ()
{
    debugf("delivering signal: %s\n", getTextualSig(current_signal));

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        // jump to the infinite loop while we wait for async signal delivery
        WRITE_FASTCALL_ARG1(i, 0);
        WRITE_IP(i, variants[i].infinite_loop_ptr);
        mvee_wrap_ptrace(PTRACE_CONT, variants[i].variantpid, 0, NULL);

        variants[i].current_signal_ready = false;

        int err = syscall(__NR_tgkill, variants[i].varianttgid,
                          variants[i].variantpid, current_signal);

        if (err)
        {
            warnf("signal delivery failed. sig: %s - target pid: %d - errno: %d (%s)\n",
                        getTextualSig(current_signal),
                        variants[i].variantpid,
                        -err, strerror(-err));
        }
    }

    current_signal_sent = true;
}

/*-----------------------------------------------------------------------------
    mvee_sig_return_from_sighandler - restores original context and resumes variants
-----------------------------------------------------------------------------*/
void monitor::sig_return_from_sighandler ()
{
    // restore normal execution after return from signal handler
    debugf("All variants have returned from the sig handler\n");

    // we only set mvee_active_monitor->current_signal for asynchronous signal delivery
    bool restore_context = current_signal ? true : false;
    current_signal      = 0;
    current_signal_sent = false;
    SAFEDELETE(current_signal_info);

    if (variants[0].callnumbackup == __NR_rt_sigsuspend
#ifdef __NR_sigsuspend
        || variants[0].callnumbackup == __NR_sigsuspend
#endif
        )
    {
        debugf("We delivered the signal during sys_[rt_]sigsuspend.\n");
        restore_context = false;
        for (int i = 0; i < mvee::numvariants; ++i)
            variants[i].callnum = variants[0].callnumbackup;
    }

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (restore_context)
        {
            debugf("restoring call site for call: %d (%s)\n", variants[i].callnumbackup,
                       getTextualSyscall(variants[i].callnumbackup));
            variants[i].callnum         = NO_CALL;
            state                     = STATE_NORMAL;

            // Move the instruction pointer back by 2 bytes to repeat the original syscall
            IP(variants[i].regsbackup) -= 2;
            mvee_wrap_ptrace(PTRACE_SETREGS, variants[i].variantpid,
                             0, &variants[i].regsbackup);

            // explicitly restore the original call number (sometimes required)
            debugf("variant %d - restoring rip: 0x" PTRSTR " - rax: 0x" PTRSTR "\n", i, IP(variants[i].regsbackup), variants[i].callnumbackup);
            WRITE_NEW_SYSCALL_NO(i, variants[i].callnumbackup);
            // explicitly restore EIP (sometimes required)
            WRITE_IP(i, IP(variants[i].regsbackup));

			mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
        }

		if (!restore_context && !current_signal)
			mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
    }
}

/*-----------------------------------------------------------------------------
    sig_restart_syscall - for ERESTART_RESTARTBLOCK the kernel will set
    the syscall no to __NR_restart_syscall.

    For other error codes, the syscall no is restored to the original one

    For all restart errors, the kernel will adjust the instruction pointer
    so that we're back at the start of the original syscall
-----------------------------------------------------------------------------*/
void monitor::sig_restart_syscall(int variantnum)
{
    debugf("Restarting syscall %d (%s) - previous call failed with %s\n",
               variants[variantnum].callnum,
               getTextualSyscall(variants[variantnum].callnum),
               getTextualKernelError(-variants[variantnum].return_value));

    mvee_wrap_ptrace(PTRACE_SYSCALL, variants[variantnum].variantpid, 0, NULL);
    variants[variantnum].restarting_syscall = true;
    variants[variantnum].restarted_syscall  = false;

    // We'll want to restart the other variants too.
    //
    // The other variants are either in ptrace-trace-stopped state or will soon
    // be when they return from the fake sys_getpid call.
    //
    // Unfortunately, the kernel won't send us signal delivery notifications
    // as long as our tracees are in trace-stopped.
    if (variantnum == 0 && state == STATE_IN_MASTERCALL)
    {
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            if (variants[i].callnum != NO_CALL)
            {
				debugf("Restarting syscall in variant %d too!\n", i);

                int status;
                int err = wait4(variants[i].variantpid, &status, 0, NULL);

                if (err == variants[i].variantpid)
                {
					if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSYSTRAP))
					{
						// TODO: call handle_sig_delivery_stop here???
						// ==> Yes! otherwise the signal might get lost!!!
						handle_sig_delivery_stop(i, status);

						if (!sighand_table::is_control_flow_signal(WSTOPSIG(status)))
						{
							err = wait4(variants[i].variantpid, &status, 0, NULL);

							if ((err != variants[i].variantpid)
								|| !(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSYSTRAP))
							{
								warnf("FIXME: Possible error while restarting variant %d - stop status: %s\n", i, getTextualWaitEventType(status).c_str());
							}
						}
					}					                    
                }
            }

            // restore regs for slaves?! Some args seem to get clobbered...
            WRITE_IP(i, IP(variants[i].regs) - 2);
            WRITE_NEW_SYSCALL_NO(i, variants[0].callnum);

            variants[i].regs_valid         = false;
            variants[i].callnum            = variants[0].callnum;
            mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
            variants[i].restarting_syscall = true;
            variants[i].restarted_syscall  = false;
        }
    }
}

/*-----------------------------------------------------------------------------
    hwbp_refresh_regs - helper function. rewrites all debugging
    registers for the specified task, based on the current values of the
    hw_bps and hw_bps_types arrays

    FIXME: Only works within the monitor's thread set
    TODO: Check if this still works for AMD64
-----------------------------------------------------------------------------*/
void monitor::hwbp_refresh_regs(int variantnum)
{
    unsigned long dr7;
    int           i;

    // Dr0-3 are linear addresses
    for (i = 0; i < 4; ++i)
    {
        if (variants[variantnum].hw_bps[i])
        {
            debugf("setting debug reg %d\n", i);
            mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid,
                             offsetof(user, u_debugreg) + i*sizeof(unsigned long), (void*)variants[variantnum].hw_bps[i]);
        }
    }

    // Dr6 is the status register, we shouldn't really touch it here...
    // Dr7 is the control register, it specifies whether or not a bp is
    // enabled (locally and/or globally), the length of the data to watch
    // and the type of bp (execution/writes/reads)
    dr7 = 0;

    for (i = 0; i < 4; ++i)
    {
        if (variants[variantnum].hw_bps[i])
        {
            // set locally enabled flag
            dr7 |= 0x1 << i*2;
            // set read/write flag
            dr7 |= variants[variantnum].hw_bps_type[i] << (16 + i*4);
            // set len flag (we always assume word length) - len should be 0 for EXEC-only breakpoints
			if (variants[variantnum].hw_bps_type[i] != MVEE_BP_EXEC_ONLY)
				dr7 |= 0x3 << (18 + i*4);
            //dr7 |= 0x0 << (18 + i*4);
        }
    }

    debugf("setting ctrl reg\n");
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid,
                     offsetof(user, u_debugreg) + 7*sizeof(long), (void*)dr7);
}

/*-----------------------------------------------------------------------------
    hwbp_set_watch - sets a hardware breakpoint on the specified data
    address (if debug registers are available)

    FIXME/TODO: This doesn't work properly! debug regs are only set for the
    local thread, not the entire process!
-----------------------------------------------------------------------------*/
bool monitor::hwbp_set_watch(int variantnum, unsigned long addr, unsigned char bp_type)
{
    int i;

    // check if we've already registered this data watch...
    for (i = 0; i < 4; ++i)
        if (variants[variantnum].hw_bps[i] == addr
            && variants[variantnum].hw_bps_type[i] == bp_type)
            return true;

    // check if we have room for another bp
    for (i = 0; i < 4; ++i)
        if (!variants[variantnum].hw_bps[i])
            break;

    if (i >= 4)
        return false;

    variants[variantnum].hw_bps[i]      = addr;
    variants[variantnum].hw_bps_type[i] = bp_type;
    hwbp_refresh_regs(variantnum);
    debugf("set hw bp: 0x" PTRSTR "\n", addr);
    return true;
}

/*-----------------------------------------------------------------------------
    hwbp_unset_watch - removes a hardware breakpoint on the specified
    data address
-----------------------------------------------------------------------------*/
bool monitor::hwbp_unset_watch(int variantnum, unsigned long addr)
{
    int i;

    for (i = 0; i < 4; ++i)
    {
        if (variants[variantnum].hw_bps[i] == addr)
        {
            variants[variantnum].hw_bps[i] = 0;
            break;
        }
    }

    if (i >= 4)
        return false;

    hwbp_refresh_regs(variantnum);
    return true;
}

/*-----------------------------------------------------------------------------
    register_hidden_buffer - used by the UTCB and the secure wall of clocks
	agent's atomic buffer
-----------------------------------------------------------------------------*/
void monitor::register_hidden_buffer(int buffer_id, _shm_info* info, std::vector<unsigned long>& addresses)
{
	// ensure that the hidden buffer array is mapped for each variant
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		if (!variants[i].hidden_buffer_array)
		{
			if (!mvee::os_alloc_sysv_sharedmem(PAGE_SIZE, &variants[i].hidden_buffer_array_id,
											   NULL, &variants[i].hidden_buffer_array))
			{
				warnf("couldn't allocate hidden buffer array!\n");
				shutdown(false);
				return;
			}

			debugf("Allocated hidden buffer array for variant %d: " PTRSTR "(" PTRSTR ")\n", i, variants[i].hidden_buffer_array, &(variants[i].hidden_buffer_array));
		}

		((struct hidden_buffer_array_entry*)variants[i].hidden_buffer_array)[buffer_id].hidden_buffer_address = (void*)addresses[i];
		
		if (info)
			((struct hidden_buffer_array_entry*)variants[i].hidden_buffer_array)[buffer_id].hidden_buffer_size = info->sz / sizeof(unsigned long);

		debugf("Registered buffer %d (%s) in hidden buffer array for variant %d => ptr: 0x" PTRSTR "\n",
				   buffer_id, getTextualBufferType(buffer_id), i, addresses[i]);
	}
}

/*-----------------------------------------------------------------------------
    schedule_threads
-----------------------------------------------------------------------------*/
void monitor::schedule_threads()
{
	int cores         = mvee::os_get_num_cores();
	int cpus          = mvee::os_get_num_physical_cpus();
	int cores_per_cpu = cores / cpus;
	int start_core    = 0;

	mvee::lock();
	std::set<int> cores_unavailable = mvee::get_unavailable_cores(&start_core);


	// Two things seem to work really well: 
	//
	// 1) Scheduling all of the threads we're monitoring in this monitor on the
	// same physical cpu 
	//
	// 2) Scheduling the monitor and the master thread on the same core
	
	start_core  = ROUND_DOWN(start_core, cores_per_cpu);
	master_core = start_core;
	
	// if we can't fit the slaves on the same socket, then move the master to the other socket too
	while (cores_unavailable.find(master_core) != cores_unavailable.end())
	{
//		warnf("core unavailable: %d\n", master_core);
		master_core = (master_core + mvee::numvariants) % cores;
		if (master_core == start_core)
		{
			master_core = ((mvee::active_monitorid * mvee::numvariants) % cores);
			break;
		}
		else if ((master_core / cores_per_cpu) != ((master_core + mvee::numvariants - 1) / (cores_per_cpu)))
		{
			master_core = (master_core + mvee::numvariants) % cores;
//			warnf("slaves wouldn't fit on the same socket. Moving to core: %d\n", master_core);
			continue;
		}
	}


	mvee::unlock();

	cpu_set_t master_set, slave_set;
	CPU_ZERO(&master_set);
	CPU_ZERO(&slave_set);
	CPU_SET(master_core, &master_set);
	for (int i = 1; i < mvee::numvariants; ++i)
		CPU_SET(master_core + i, &slave_set);

	if (sched_setaffinity(variants[0].variantpid, sizeof(cpu_set_t), &master_set) == 0
		&& sched_setaffinity(0, sizeof(cpu_set_t), &master_set) == 0)
		debugf("pinned master thread (TID: %d) on cpu: %d\n", variants[0].variantpid, master_core);
	else
		debugf("couldn't pin thread on core\n", master_core);

	for (int i = 1; i < mvee::numvariants; ++i)
	{
		if (sched_setaffinity(variants[i].variantpid, sizeof(cpu_set_t), &slave_set) == 0)
			debugf("pinned slave thread (TID: %d) on cpus: [%d, %d]\n", variants[i].variantpid, master_core, master_core + mvee::numvariants - 1);
		else
			debugf("couldn't pin thread\n");
	}
}

/*-----------------------------------------------------------------------------
    thread - monitors can either block on the cond_wait
    call in the beginning or on the waitpid call in their normal iteration.

    We can unblock the former by calling cond_signal from the primary thread
    and the latter by sending a signal.
-----------------------------------------------------------------------------*/
void  dummy_handler(int sig) {
}

void* monitor::thread(void* param)
{
    int              variant, status;
    monitor*         mon = (monitor*)param;
    mvee::active_monitor   = mon;
    mvee::active_monitorid = mon->monitorid;

    mon->monitor_tid       = mvee::os_gettid();

    debugf("monitor running! - created by monitor: %d\n", mon->parentmonitorid);

    // super hack! if we ignore SIGCHLD, we won't get a mini
    // thundering herd effect when another monitor thread's variant are reporting CLDSTOP
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &act, NULL);

    // We also ignore this one. It will still interrupt our wait4 calls though
    act.sa_handler = dummy_handler;
    if (sigaction(SIGUSR1, &act, NULL))
        warnf("couldn't ignore SIGUSR1\n");

    sigset_t         set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // wait until we can run
    while (1)
    {
        if (mon->should_shutdown)
        {
            mon->shutdown(true);
            return NULL;
        }

        pthread_mutex_lock(&mon->monitor_lock);
        if (mon->monitor_registered)
        {
            pthread_mutex_unlock(&mon->monitor_lock);
            break;
        }
        pthread_cond_wait(&mon->monitor_cond, &mon->monitor_lock);
        pthread_mutex_unlock(&mon->monitor_lock);
    }

    debugf("monitor is now registered!\n");

    //if (!mvee_active_monitorid)
    for (int i = 0; i < mvee::numvariants; ++i)
        mon->handle_attach_event(i, 0);

#ifdef MVEE_ALLOW_MONITOR_SCHEDULING
	mon->schedule_threads();
#endif

    while (1)
    {
        if (mon->should_shutdown)
        {
            mon->shutdown(true);
            return NULL;
        }

        variant = wait4(-1, &status, __WALL | WUNTRACED | __WNOTHREAD, NULL);
        if (variant != -1)
            mon->handle_event(variant, status);
        else
            debugf("wait4 returned -1 (%s) - interrupted?\n", strerror(errno));
    }

    mon->shutdown(true);
    return NULL;
}
