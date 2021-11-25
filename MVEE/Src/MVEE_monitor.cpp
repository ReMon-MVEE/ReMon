/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
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
#include "MVEE_interaction.h"
#ifdef MVEE_ARCH_SUPPORTS_DISASSEMBLY
#include "hde.h"
#endif

/*-----------------------------------------------------------------------------
    overwritten_syscall_arg
-----------------------------------------------------------------------------*/
overwritten_syscall_arg::overwritten_syscall_arg()
	: syscall_arg_num (0)
	, arg_old_value (0)
	, restore_data (false)
	, data_loc (NULL)
	, data_content (NULL)
	, data_len (0)
{
}

overwritten_syscall_arg::~overwritten_syscall_arg()
{
	if (data_content)
		delete[] (unsigned char*)data_content;
}

/*-----------------------------------------------------------------------------
    variantstate class
-----------------------------------------------------------------------------*/
variantstate::variantstate()
    : variantpid (0)
    , prevcallnum (0)
    , callnum (0)
    , call_flags (0)
    , return_value (0)
    , extended_value (0)
    , call_type (0)
    , call_dispatched (false)
    , regs_valid (false)
    , return_valid (false)
    , restarted_syscall (false)
    , restarting_syscall (false)
    , variant_terminated (false)
    , variant_pending (false)
    , variant_attached (false)
    , variant_resumed (false)
    , current_signal_ready (false)
	, fast_forwarding (false)
    , have_overwritten_args (false)
	, syscall_checking_disabled(false)
	, max_unchecked_syscalls (0)
    , last_lower_region_start (0)
    , last_lower_region_size (0)
    , last_upper_region_start (0)
    , last_upper_region_size (0)
    , last_mmap_result (0)
	, ipmon_region (NULL)
    , varianttgid (0)
    , pendingpid (0)
    , infinite_loop_ptr (0)
    , should_sync_ptr (0)
    , callnumbackup (0)
    , orig_controllen (0)
    , config (NULL)
    , instruction (&this->variantpid, &this->variant_num)
    , replaced_iovec(0)
#ifdef __NR_socketcall
    , orig_arg1 (0)
#endif
#ifdef CHECK_SYNC_PRIMITIVES
    , sync_primitives_bitmask (0)
    , sync_primitives_ptr (NULL)
#endif
{
    memset(&regs, 0, sizeof(PTRACE_REGS));
    sigemptyset(&last_sigset);
    memset(&regsbackup, 0, sizeof(PTRACE_REGS));
    memset(hw_bps,      0, 4*sizeof(unsigned long));
    memset(hw_bps_type, 0, 4*sizeof(unsigned char));
    memset(tid_address, 0, 2*sizeof(void*));
	SYSCALL_MASK_CLEAR(unchecked_syscalls);

#ifdef MVEE_ARCH_USE_LIBUNWIND
	unwind_as = unw_create_addr_space(&_UPT_accessors, 0);
	unwind_info = nullptr;
#endif
}

variantstate::~variantstate()
{
#ifdef MVEE_ARCH_USE_LIBUNWIND
	unw_destroy_addr_space(unwind_as);
	if (unwind_info)
		_UPT_destroy(unwind_info);
#endif
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
std::vector<std::unique_ptr<_shm_info>>     monitor::atomic_variantwide_buffer;
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
    ipmon_initialized              = false;
	ipmon_mmap_handling            = false;
	ipmon_fd_handling              = false;
	aliased_open                   = false;
    monitorid                      = 0;
    parentmonitorid                = 0;
    state                          = STATE_NORMAL;
    atomic_buffer                  = NULL;
    ipmon_buffer                   = NULL;
	ring_buffer                    = NULL;
	shm_buffer                     = NULL;
    current_signal                 = 0;
    current_signal_sent            = 0;
    current_signal_info            = NULL;
    perf                           = false;
    monitor_tid                    = 0;
	master_core                    = -1;
	last_mmap_requested_size       = 0;
	last_mmap_requested_alignment  = 0;
	current_shadow                 = NULL;

#ifdef MVEE_IP_PKU_ENABLED
	special_shmdt_count            = 0;
#endif

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

#ifdef MVEE_SHM_INSTRUCTION_ACCESS_DEBUGGING
    instruction_list = std::vector<std::vector<monitor::instruction_info_t>>();
    for (int i = 0; i < mvee::numvariants; i++)
        instruction_list.emplace_back(std::vector<monitor::instruction_info_t>());
#endif
}

monitor::monitor(monitor* parent_monitor, bool shares_fd_table, bool shares_mmap_table, bool shares_sighand_table, bool shares_tgid)
        : buffer(this)
{
    init();

    parentmonitorid   = parent_monitor->monitorid;

    set_fd_table      = shares_fd_table ?
                        parent_monitor->set_fd_table :
                        std::shared_ptr<fd_table>(new fd_table(*parent_monitor->set_fd_table));

    shm_setup_state   = shares_mmap_table ? SHM_SETUP_IDLE : SHM_SETUP_EXPECTING_ENTRY;
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
					 shares_tgid ? parent_monitor->variants[i].varianttgid : 
					 parent_monitor->variants[i].pendingpid);
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        variants[i].syscall_pointer = parent_monitor->variants[i].syscall_pointer;
#endif
        variants[i].shm_tag                  = parent_monitor->variants[i].shm_tag;

        // If this is a fork: Copy over the list of variables to reset
        if (!shares_mmap_table)
            variants[i].reset_atfork = parent_monitor->variants[i].reset_atfork;
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
        : buffer(this)
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
    init_variant - Initializes the state info for a new variant traced by the monitor.
-----------------------------------------------------------------------------*/
void monitor::init_variant(int variantnum, pid_t variantpid, pid_t varianttgid)
{
    variants[variantnum].callnum     = NO_CALL;
    variants[variantnum].variantpid  = variantpid;
    variants[variantnum].variant_num = variantnum;
    variants[variantnum].varianttgid = varianttgid ? varianttgid : variantpid;
	if (!mvee::config["variant"]["specs"] ||
		!mvee::config["variant"]["specs"]["test"])
		return;
	variants[variantnum].config      = &mvee::config["variant"]["specs"][mvee::variant_ids[variantnum]];
}

/*-----------------------------------------------------------------------------
    restart_variant - This is very fancy. We wait for the specified variant
    to hit its next rendez-vous point and then force it to execute a new execve
    call with its original arguments
-----------------------------------------------------------------------------*/
bool monitor::restart_variant(int variantnum)
{
    bool result = false;
	interaction::mvee_wait_status status;

    // We can get the original argvs from the set_mmap_table and the original envps
    // from /proc/<pid>/environ
    int pid = variants[variantnum].variantpid;

    debugf("%s - Attempting to restart this variant\n",
		   call_get_variant_pidstr(variantnum).c_str());

    // First of all, we have to wait until we reach the next syscall entry
	if (!interaction::resume_until_syscall(pid))
		throw ResumeFailure(variantnum, "variant restart");

    while (true)
    {
        if (should_shutdown)
        {
            shutdown(true);
            return false;
        }

		if (!interaction::wait(pid, status, false, false, false) ||
			status.reason != STOP_SYSCALL)
		{
			throw WaitFailure(variantnum, "variant restart", status);
		}
		else
		{
			debugf("%s - Hit the first syscall entrance!\n",
				   call_get_variant_pidstr(variantnum).c_str());
			break;
		}
    }

	rewrite_execve_args(variantnum, false, true);

    // dispatch the call and wait for the return
    debugf("%s - Restarting variant...\n", 
		   call_get_variant_pidstr(variantnum).c_str());

	if (!interaction::resume_until_syscall(pid))
		throw ResumeFailure(variantnum, "variant restart");

    while (true)
    {
		if (!interaction::wait(pid, status, false, false, false) ||
			(status.reason != STOP_SYSCALL && status.reason != STOP_EXECVE))
		{
			throw WaitFailure(variantnum, "variant restart", status);
		}
		else
		{
			if (status.reason == STOP_SYSCALL)
			{
				debugf("%s - Hit the first syscall entrance after execve!\n",
					   call_get_variant_pidstr(variantnum).c_str());
				return true;
			}
			else 
			{
				debugf("%s - saw execve\n",
					   call_get_variant_pidstr(variantnum).c_str());

				if (!interaction::resume_until_syscall(pid))
					throw ResumeFailure(variantnum, "variant restart");
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
	std::string lib_path_from_env;
	bool mveeroot_found_in_env = false;

	// See if we have any LD_LIBRARY_PATH in the envp vars
	for (auto envp : set_mmap_table->mmap_startup_info[variantnum].envp)
	{
		if (envp.find("LD_LIBRARY_PATH=") == 0)
		{
			lib_path_from_env = envp.substr(strlen("LD_LIBRARY_PATH="));
		}
		else if (envp.find("MVEEROOT=") == 0)
		{
			mveeroot_found_in_env = true;
		}
	}

	// our MVEE LD Loader relies on the MVEEROOT env variable to find the
	// program interpreter. If we do not find it (e.g., in Python3), then we
	// have to inject it manually
	if (!mveeroot_found_in_env)
		rewrite_envp = true;

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
		
		if (!mveeroot_found_in_env)
		{
			std::stringstream ss;
			ss << "MVEEROOT=" << mvee::os_get_mvee_root_dir();
			envp.push_back(mvee::strdup(ss.str().c_str()));
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
	std::stringstream lib_path;
    if (!(*mvee::config_variant_exec)["library_path"].isNull())
    {
		lib_path << (*mvee::config_variant_exec)["library_path"].asString();
		if (lib_path_from_env.length() > 0)
			lib_path << ":" << lib_path_from_env;
		argv.push_front(mvee::strdup(lib_path.str().c_str()));
		argv.push_front(mvee::strdup("--library-path"));
    }

	// insert ELF interpreter if necessary
	if (lib_path.str().length() > 0)
	{
		if (
#ifdef MVEE_ARCH_HAS_VDSO
			(*mvee::config_variant_global)["hide_vdso"].asBool() ||
#endif
			(*mvee::config_variant_global)["non_overlapping_mmaps"].asInt() 
#ifdef MVEE_ARCH_ALWAYS_USE_LD_LOADER
			|| true
#endif
			)
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
	debugf("%s - Injecting the following execve args - image: %s - argv: %s\n",
		   call_get_variant_pidstr(variantnum).c_str(),
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
		image_target_address = SP_IN_REGS(variants[variantnum].regs) - 1024 - total_len;
	}
	else
	{
		mmap_region_info* writable = set_mmap_table->find_writable_region(variantnum, total_len);
		if (!writable)
		{
			warnf("%s - Could not find a writable region of at least %lu bytes long in the address space of this variant => execve arguments writing failed\n",
				  call_get_variant_pidstr(variantnum).c_str(), total_len);
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

    debugf("%s - Writing new execve arguments...\n",
		   call_get_variant_pidstr(variantnum).c_str());
    if (rw::copy_data(mvee::os_gettid(), (void*)image.c_str(), pid, (void*)image_target_address, image.length() + 1) == -1
        || rw::copy_data(mvee::os_gettid(), (void*)relocated_argv, pid, (void*)relocated_argv_target_address, sizeof(char*) * argv.size()) == -1
        || (rewrite_envp && rw::copy_data(mvee::os_gettid(), (void*)relocated_envp, pid, (void*)relocated_envp_target_address, sizeof(char*) * envp.size()) == -1)
        || rw::copy_data(mvee::os_gettid(), (void*)serialized_argv, pid, (void*)argv_target_address, argv_len) == -1
        || (rewrite_envp && rw::copy_data(mvee::os_gettid(), (void*)serialized_envp, pid, (void*)envp_target_address, envp_len) == -1))
    {
		throw RwMemFailure(variantnum, "execve arguments copy");
    }

    // set the registers
    debugf("%s - Setting execve registers...\n",
		   call_get_variant_pidstr(variantnum).c_str());
    ARG1(variantnum) = image_target_address;
    ARG2(variantnum) = relocated_argv_target_address;
	if (rewrite_envp)
		ARG3(variantnum) = relocated_envp_target_address;	
	SYSCALL_NO(variantnum) = __NR_execve;

	if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
		throw RwRegsFailure(variantnum, "execve arguments rewrite");

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
    debugf("Program is entering multithreaded state - setting sync flag for all variants\n");
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].should_sync_ptr)
        {
			if (!rw::write_primitive<unsigned char>(variants[i].variantpid,
													(void*) variants[i].should_sync_ptr, 1))
			{
				warnf("%s - Couldn't set sync flag\n", call_get_variant_pidstr(i).c_str());
				return;
			}

			debugf("%s - sync flag set\n", call_get_variant_pidstr(i).c_str());
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
    debugf("Program is entering singlethreaded state - unsetting sync flag for all variants\n");
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].should_sync_ptr)
        {
			if (!rw::write_primitive<unsigned char>(variants[i].variantpid,
													(void*) variants[i].should_sync_ptr, 0))
			{
				warnf("%s - Couldn't unset sync flag\n", call_get_variant_pidstr(i).c_str());
				return;
			}

			debugf("%s - sync flag unset\n", call_get_variant_pidstr(i).c_str());
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
    await_pending_transfers - Used to stall the termination of a monitor until
	all of the variants that originally spawned under its supervision have been
	attached to a new monitor	
-----------------------------------------------------------------------------*/
void monitor::await_pending_transfers()
{
	interaction::mvee_wait_status status;

    // There's an interesting race that can happen here. If we shut down just
    // after our variants have cloned but the new monitor isn't detached to the
    // new clones yet, the new monitor might get -EPERM on the attach request
    while (!mvee::shutdown_signal)
    {
        if (!mvee::have_detached_variants(this))
            break;

        // we might still have to detach from them... 
		if (interaction::wait(-1, status, true, true) &&
			status.reason != STOP_NOTSTOPPED)
		{
            handle_event(status);
		}
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
                        monitorid, getTextualErrno(errno));
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
#ifdef MVEE_LOG_NON_INSTRUMENTED_INSTRUCTION
    mvee::flush_non_instrumented_log();
#endif
#ifdef MVEE_SHM_INSTRUCTION_ACCESS_DEBUGGING
    print_instruction_list();
#endif

#ifndef MVEE_BENCHMARK
	bool should_log = false;
#endif
	bool have_running_variants = false;

    debugf("monitor returning - success: %d\n", success);
	if (!success)
		debugf("> errno: %d (%s)\n", errno, getTextualErrno(errno));

    if (monitor_terminating)
        return;

    monitor_terminating = 1;

    // see if we can control the damage
    if (!success)
    {
		if (set_mmap_table)
			set_mmap_table->grab_lock();

        // if we have other monitors that monitor different processes,
        // then just kill this local process
        // and let the other monitors continue
        bool have_other_processes = mvee::is_multiprocess();

        if (!have_other_processes)
        {
            debugf("GHUMVEE is only monitoring one process group => we're shutting everything down\n");
			mvee::set_should_generate_backtraces();
        }
        else
        {
            // just kill this group
            debugf("GHUMVEE is monitoring multiple process groups => we're only shutting this group down\n");
			debugf("set_mmap_table->thread_group_shutting_down = %d\n", 
				   set_mmap_table->thread_group_shutting_down.load());

			if (!set_mmap_table->thread_group_shutting_down.exchange(true))
			{
				// only log if the group was not shutting down already
#ifndef MVEE_BENCHMARK
				should_log = true;
#endif
			}

            for (int i = 0; i < mvee::numvariants; ++i)
            {
                if (!variants[i].variant_terminated)
                {
#ifndef MVEE_BENCHMARK
					if (should_log)
						log_variant_backtrace(i);
#endif
                    variants[i].variant_terminated = true;
                    kill(variants[i].varianttgid, SIGKILL);
                }
            }

#ifndef MVEE_BENCHMARK
			if (should_log)
			{
				log_dump_queues(set_shm_table.get());
				log_ipmon_state();
			}
#endif
			
			if (set_mmap_table)
				set_mmap_table->release_lock();

            goto nobacktrace;
        }
    }

	debugf("Backtrace check - Should generate backtraces: %d - Thread group shutting down: %d\n",
		   mvee::get_should_generate_backtraces(), 
		   set_mmap_table->thread_group_shutting_down.load());

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

    // We explicitly reset the shared pointers here so all of the tables get
    // deleted if we were the last monitor referring to them
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
    // if we're the second to last one holding a ref to this mmap table then let
    // the main thread know that we're possible singlethreaded again
    if (set_mmap_table.use_count() == 2)
        mvee::set_should_check_multithread_state(set_mmap_table->mmap_execve_id);
    // must be freed AFTER the shm table
    set_mmap_table.reset(); 
    set_sighand_table.reset();

    if (atomic_buffer)
        delete atomic_buffer;
    if (ipmon_buffer)
        delete ipmon_buffer;
    if (ring_buffer)
        delete ring_buffer;
    if (shm_buffer)
        delete shm_buffer;

    pthread_mutex_lock(&monitor_lock);
    local_detachlist.clear();
    pthread_mutex_unlock(&monitor_lock);

    for (int i = 0; i < mvee::numvariants; ++i)
        if (!variants[i].variant_terminated)
			have_running_variants = true;

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (variants[i].perf_out.length() > 0)
        {
            warnf("%s - Performance Counters:\n>>> START <<<\n%s\n>>> END <<<\n",
				  call_get_variant_pidstr(i).c_str(), variants[i].perf_out.c_str());
        }
        variants[i].perf_out.erase();
    }

    // Successful return. Unregister the monitor from all mappings
    log_fini();
    mvee::unregister_monitor(this, !have_running_variants);

	// As soon as we shut this thread down, the remaining tracees will be able
	// to run uncontrolled => simply pause and wait for the management thread to
	// shut us down if we still have running variants
    if (!have_running_variants)
	{
        pthread_exit(nullptr);
	}
    else
	{
		pthread_mutex_lock(&monitor_lock);
		if (!should_shutdown)
			pthread_cond_wait(&monitor_cond, &monitor_lock);
        pthread_mutex_unlock(&monitor_lock);

		// Don't kill off our variants until every monitor
		// that's monitoring variants in the same thread group has
		// had a chance to backtrace
		if (mvee::get_should_generate_backtraces())
		{
			while (true)
			{
				mvee::lock();
				bool have_monitored_variants = false;
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					if (mvee::is_monitored_tgid(variants[i].varianttgid))
					{
						have_monitored_variants = true;
						pthread_cond_wait(&mvee::global_cond, &mvee::global_lock);
					}
				}
				mvee::unlock();												  

				if (!have_monitored_variants)
					break;
			}
		}

		// Kill off our variants now
		for (int i = 0; i < mvee::numvariants; ++i)
			if (!variants[i].variant_terminated)
				kill(variants[i].variantpid, SIGKILL);

		// now move it to the dead monitors list
		mvee::unregister_monitor(this, true);
		pthread_exit(NULL);
	}

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
	{
		if (!rw::read_primitive<int>(variants[0].variantpid, variants[0].sync_primitives_ptr, variants[0].sync_primitives_bitmask))
		{
			warnf("%s - Couldn't read synchronization primitives mask\n",
				  call_get_variant_pidstr(0).c_str());
		}
	}
#endif
}

/*-----------------------------------------------------------------------------
    mvee_mon_handle_event - Every event we get from waitpid goes through this
    function
-----------------------------------------------------------------------------*/
void monitor::handle_event (interaction::mvee_wait_status& status)
{
    int index;

    // find the variant index
    for (index = 0; index < mvee::numvariants; ++index)
        if (variants[index].variantpid == status.pid)
            break;

    // we intercepted an event that shouldn't be delivered to this monitor
    // perhaps this is a newly spawned variant that we haven't detached from yet?
    if (index >= mvee::numvariants)
    {
        for (auto it = local_detachlist.begin();
             it != local_detachlist.end(); ++it)
        {
            if ((*it) == status.pid)
            {
                local_detachlist.erase(it);
                handle_detach_event(status.pid);
                return;
            }
        }

        debugf("Unknown variant event: %d - %s\n", 
			   status.pid, 
			   getTextualMVEEWaitStatus(status).c_str());
        unknown_variants.push_back(status.pid);
        return;
    }

    // check for exit events first
    if (unlikely(status.reason == STOP_EXIT))
    {
        handle_exit_event(index);
        return;
    }
    else if (status.reason == STOP_SYSCALL)
	{
		handle_syscall_event(index);
		return;
	}
	else if (status.reason == STOP_FORK)
	{
		handle_fork_event(index, status);
		return;
	}
	else if (status.reason == STOP_SIGNAL)
	{
		if (status.data == SIGTRAP)
		{
			handle_trap_event(index);
		}
#ifdef MVEE_ARCH_HAS_RDTSC
		else if (status.data == SIGSEGV)
		{
			if (handle_rdtsc_event(index))
				return;
		}
#endif
		else if (status.data == SIGSTOP)
		{
			if (state == STATE_WAITING_ATTACH && !variants[index].variant_attached)
            {
                handle_attach_event(index);
                return;
            }
            if (state == STATE_WAITING_RESUME && !variants[index].variant_resumed)
            {
                handle_resume_event(index);
                return;
            }
		}		
	}
	else if (status.reason == STOP_EXECVE)
	{
		call_resume(index);
		return;
	}

	handle_signal_event(index, status);
}

/*-----------------------------------------------------------------------------
    handle_rdtsc_event - Checks if the current SIGSEGV of a variant is caused
    by executing the rdtsc instruction and if so, handles the signal.

    @param variantnum variant index

    @return true if the SIGSEGV signal was handled, false otherwise
-----------------------------------------------------------------------------*/
#ifdef MVEE_ARCH_HAS_RDTSC
bool monitor::handle_rdtsc_event(int variantnum)
{
    // get signal info
    siginfo_t siginfo;
	memset(&siginfo, 0, sizeof(siginfo_t));

    // SIGSEGV caused by rdtsc is always sent by the kernel
    if (interaction::get_signal_info(variants[variantnum].variantpid, &siginfo) &&
		siginfo.si_code == SI_KERNEL)
    {
		unsigned long eip;
		long current_opcode;

        // read current opcode
		if (!interaction::fetch_ip(variants[variantnum].variantpid, eip))
			throw RwRegsFailure(variantnum, "RDTSC signal check");

		if (!rw::read_primitive<long>(variants[variantnum].variantpid, (void*) eip, current_opcode))
			throw RwMemFailure(variantnum, "RDTSC signal check");

        // rdtsc opcode should be in lower 2 bytes
        if ((short int)(current_opcode & 0x0000FFFF) == 0x310F)
        {
            debugf("%s - Trapped rdtsc instruction\n",
				   call_get_variant_pidstr(variantnum).c_str());

			if (variants[variantnum].fast_forwarding)
			{
				debugf("%s - Variant is fast forwarding. Allowing rdtsc\n",
					   call_get_variant_pidstr(variantnum).c_str());

                unsigned int upper, lower;
                asm volatile ("rdtsc\n" : "=a" (lower), "=d" (upper));

				// write back result
				if (!interaction::write_specific_reg(variants[variantnum].variantpid, RDTSC_LOW_REG_OFFSET, lower) ||
					!interaction::write_specific_reg(variants[variantnum].variantpid, RDTSC_HIGH_REG_OFFSET, upper) ||
					!interaction::write_ip(variants[variantnum].variantpid, eip + 2))
				{
					throw RwRegsFailure(variantnum, "writing RDTSC result");
				}
				
				if (!interaction::resume_until_syscall(variants[variantnum].variantpid))
					throw ResumeFailure(variantnum, "RDTSC resume");

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
					if (!interaction::write_specific_reg(variants[i].variantpid, RDTSC_LOW_REG_OFFSET, lower) ||
						!interaction::write_specific_reg(variants[i].variantpid, RDTSC_HIGH_REG_OFFSET, upper) ||
						!interaction::fetch_ip(variants[i].variantpid, eip) ||
						!interaction::write_ip(variants[i].variantpid, eip + 2))
					{
						throw RwRegsFailure(i, "writing RDTSC result");
					}

					if (!interaction::resume_until_syscall(variants[i].variantpid))
						throw RwRegsFailure(i, "RDTSC resume");

                    variants[i].callnum = NO_CALL;
                }

                return true;
            }
        }
    }

    return false;
}
#endif

/*-----------------------------------------------------------------------------
    handle_attach_event
-----------------------------------------------------------------------------*/
void monitor::handle_attach_event(int index)
{
    variants[index].variant_attached = 1;

	if (!interaction::attach(variants[index].variantpid))
		throw AttachFailure(index);

    debugf("%s - Attached to variant\n", 
		   call_get_variant_pidstr(index).c_str());

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
void monitor::handle_detach_event(pid_t variantpid)
{
    detachedvariant* new_variant = NULL;

    debugf("received event for variant: %d\n", variantpid);

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
        warnf("version of (e)glibc. The GHUMVEE (e)glibc contains a small infinite loop to\n");
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

	if (!interaction::read_all_regs(new_variant->variantpid, &new_variant->original_regs))
		throw RwRegsFailure(-new_variant->variantpid, "pre-detach read");

	PTRACE_REGS tmp;
	memcpy(&tmp, &new_variant->original_regs, sizeof(PTRACE_REGS));
	// instruct the variant to execute the transfer func
	IP_IN_REGS(tmp) = (unsigned long)new_variant->transfer_func;

	if (!interaction::write_all_regs(new_variant->variantpid, &tmp))
		throw RwRegsFailure(-new_variant->variantpid, "pre-detach write");

	if (!interaction::detach(new_variant->variantpid))
		throw DetachFailure(-new_variant->variantpid, "pre-transfer");

    debugf("Detached from variant (PID: %d) => set ip to: " PTRSTR "\n",
		   new_variant->variantpid, new_variant->transfer_func);

    new_variant->parent_has_detached = 1;
    monitor*       new_mon = new_variant->new_monitor;

#ifdef MVEE_IP_PKU_ENABLED
    new_mon->special_shmdt_count = 2;
#endif

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
	if (!interaction::setoptions(variants[index].variantpid))
		throw RwInfoFailure(index, "post-attach");

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
		variants[index].should_sync_ptr   = attached_variant->should_sync_ptr;
        variants[index].tid_address[0]    = attached_variant->tid_address[0];
        variants[index].tid_address[1]    = attached_variant->tid_address[1];

		if (!interaction::write_all_regs(variants[index].variantpid, &attached_variant->original_regs))
			throw RwRegsFailure(index, "post-attach");

        delete attached_variant;
    }
    else
    {
		if (!rw::write_primitive<unsigned long>(variants[index].variantpid, (void*) &mvee::can_run, 1))
		{
			warnf("%s - Couldn't resume variant\n",
				  call_get_variant_pidstr(index).c_str());
			exit(-1);
			return;
		}
    }

    // We do not actually resume until all of our variants are ready. This way we can set tids if needed
    debugf("%s - ready to resume variant\n", call_get_variant_pidstr(index).c_str());

    // Reset some variables at fork in the new child
    for (const auto& v : variants[index].reset_atfork)
    {
        debugf("%s - Resetting ATFORK variable.\n", call_get_variant_pidstr(index).c_str());
        unsigned long tmp = 0;
        if (!interaction::write_memory(variants[index].variantpid, (void*)v.first, v.second, &tmp))
            warnf("Could not clear MVEE_RESET_ATFORK variable for variant %d (%d) - %d\n", index, variants[index].variantpid, errno);
    }
    variants[index].reset_atfork.clear();

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
                        debugf("%s - setting master tid for variant\n", 
							   call_get_variant_pidstr(i).c_str());
						
						if (!rw::write_primitive<int>(variants[i].variantpid, 
													  variants[i].tid_address[j], 
													  variants[0].variantpid))
							throw RwMemFailure(i, "couldn't replicate master tids post-attach");
                    }
                }
            }

            // And finally it's safe to resume the variant
            debugf("%s - resumed variant\n", call_get_variant_pidstr(i).c_str());
			call_resume(i);
        }

        state = STATE_NORMAL;
    }
}

/*-----------------------------------------------------------------------------
    handle_exit_event
-----------------------------------------------------------------------------*/
void monitor::handle_exit_event(int index)
{
#ifdef MVEE_DUMP_IPMON_BUFFER_ON_FLUSH
	if (!index)
		log_ipmon_state();
#endif

    debugf("%s - received SIGTERM\n", 
		   call_get_variant_pidstr(index).c_str());

	// we treat this as an entrance to a sys_exit call so
	// we can detect divergences where one variant is shut down
	// while others are still trying to execute lockstepped calls
    variants[index].variant_terminated = true;
    variants[index].callnum          = __NR_exit;
	variants[index].call_type        = MVEE_CALL_TYPE_NORMAL;

    bool bAllTerminated = true;
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (!variants[i].variant_terminated)
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

	// check if any of the other variants is waiting on the entrance of a lockstepped call
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		if (i != index &&
			(variants[i].callnum != NO_CALL) &&
			(variants[i].callnum != __NR_exit) &&
			(variants[i].call_type & MVEE_CALL_TYPE_NORMAL) &&
			(set_mmap_table && !set_mmap_table->thread_group_shutting_down) &&
			state <= STATE_NORMAL)
		{
			warnf("%s - Variant terminated while variant %s is at the entrance of a lockstepped call\n",
				  call_get_variant_pidstr(index).c_str(), call_get_variant_pidstr(i).c_str());
			warnf("%s - This is a deadlock - Shutting down the MVEE!\n",
				  call_get_variant_pidstr(index).c_str());
			shutdown(false);
		}
	}
}

/*-----------------------------------------------------------------------------
    handle_fork_event
-----------------------------------------------------------------------------*/
void monitor::handle_fork_event(int index, interaction::mvee_wait_status& status)
{
    // Store new pid in variantstate
    variants[index].pendingpid = (int) status.data;

    debugf("%s - Fork Event- Pending PID: %d\n",
		   call_get_variant_pidstr(index).c_str(),
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
        if (   variants[0].callnum == __NR_vfork
            || (variants[0].callnum == __NR_clone && (ARG1(0) & CLONE_VFORK))  )
            new_monitor->created_by_vfork = true;

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            detachedvariant* new_variant = new detachedvariant();// Zero-initialized

            // init detachedvariant
            new_variant->variantpid          = variants[i].pendingpid;
            variants[i].pendingpid           = 0;
            new_variant->parentmonitorid     = monitorid;
            new_variant->parent_has_detached = 0;
            new_variant->transfer_func       = variants[i].infinite_loop_ptr;
            new_variant->new_monitor         = new_monitor;
			new_variant->should_sync_ptr     = variants[i].should_sync_ptr;

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
            for (auto it = unknown_variants.begin();
                 it != unknown_variants.end(); ++it)
            {
                if (*it == new_variant->variantpid)
                {
                    handle_detach_event(new_variant->variantpid);
                    unknown_variants.erase(it);
                    break;
                }
            }
        }

		call_resume_all();
        state = STATE_IN_SYSCALL;
    }
}

/*-----------------------------------------------------------------------------
    handle_trap_event
-----------------------------------------------------------------------------*/
void monitor::handle_trap_event(int index)
{
    // not a known event. Might be a breakpoint!
    siginfo_t siginfo;

    if (interaction::get_signal_info(variants[index].variantpid, &siginfo) &&
		siginfo.si_code == MVEE_TRAP_HWBKPT)
	{
// old code for fast forwarding to entrypoint
#if 0
		if (variants[index].fast_forward_to_entry_point)
		{
#ifdef MVEE_ARCH_HAS_X86_HWBP
			unsigned long dr6;
			
			if (!interaction::read_specific_reg(variants[index].variantpid, 
									   offsetof(user, u_debugreg) + 6*sizeof(long), 
									   dr6))
				throw RwRegsFailure(index, "hwbp dr6");

			for (int i = 0; i < 4; ++i)
			{
				if (dr6 & (1 << i))
				{
					if (variants[index].hw_bps[i] == variants[index].entry_point_address)
					{
						warnf("%s - Variant has reached its entry point - Switching to lock-step execution\n",
							  call_get_variant_pidstr(index).c_str());
						variants[index].fast_forward_to_entry_point = false;
						hwbp_unset_watch(index, variants[index].entry_point_address);
						break;
					}
				}
			}
#else
			warnf("%s - fast forwarding is not supported on this architecture\n",
				  call_get_variant_pidstr(index).c_str());
#endif
		}
		else
		{
#endif
			log_hw_bp_event(index, &siginfo);
#if 0
		}
#endif
	}

	call_resume(index);
}

/*-----------------------------------------------------------------------------
    handle_syscall_entrance_event
-----------------------------------------------------------------------------*/
void monitor::handle_syscall_entrance_event(int index)
{
    long  i, precall_flags, call_flags;
    variants[index].regs_valid      = false;
    call_check_regs(index);

    long  callnum = SYSCALL_NO(index);

	// call GET_CALL_TYPE handler (if present)
    variants[index].callnum         = callnum;
    variants[index].call_dispatched = false;
    variants[index].call_type       =
        call_precall_get_call_type(index, variants[index].callnum);

	// Handle -1 IP-MON aborted calls
	if (callnum == -1 && ipmon_initialized)
	{
		variants[index].call_type  = MVEE_CALL_TYPE_UNSYNCED;
		variants[index].call_flags = MVEE_CALL_DENY;
		variants[index].callnum    = __NR_getpid;
	}
#ifndef MVEE_BENCHMARK
	else
	{
		// call LOG_ARGS handler (if present
		call_precall_log_args(index, variants[index].callnum);
	}
#endif

    // the current syscall is unsynced. dispatch it!
    if (variants[index].call_type == MVEE_CALL_TYPE_UNSYNCED)
    {
		debugf("%s - >>> Dispatch as UNSYNCED NORMAL\n",
			   mvee::upcase(getTextualSyscall(variants[index].callnum)).c_str());

		// call CALL handler (if present)
        variants[index].call_flags  = call_call_dispatch_unsynced(index);
        if (variants[index].call_flags & MVEE_CALL_DENY)
			call_resume_fake_syscall(index);
		else
			call_resume(index);
        variants[index].call_dispatched = true;

        return;
    }

    // Check if all variants have reached the synchronization point
    for (i = 1; i < mvee::numvariants; ++i)
        if ((variants[i].callnum != variants[i-1].callnum) ||
            (variants[i].call_type != variants[i-1].call_type))
            break;

    // Check for callnumber mismatches
    if (i < mvee::numvariants)
    {
        if (variants[i].callnum == NO_CALL
            || variants[i-1].callnum == NO_CALL
            || variants[i].call_type == MVEE_CALL_TYPE_UNSYNCED
            || variants[i-1].call_type == MVEE_CALL_TYPE_UNSYNCED)
        {
			// sync point not reached yet or one of the variants is executing an
			// unsynced call
            return;
        }
        else if ((variants[i].callnum == __NR_exit || variants[i].callnum == -1)
                 && (variants[i-1].callnum == __NR_exit || variants[i-1].callnum == -1))
        {
			// all variants are dead
            return;
        }
        else
        {
			// This is a true call number or call type mismatch
            log_call_mismatch(i, i-1);
            shutdown(false);
            return;
        }
    }


    // All variants have reached the sync point
	if (sig_prepare_delivery())
		return;

	// RVP => check if the should_sync flag needs toggling
	check_multithread_state();

	// Call PRECALL handler (if present)
	precall_flags = call_precall();

	// Arguments match => let's see how this call should be dispatched
	if (precall_flags & MVEE_PRECALL_ARGS_MATCH)
	{
	args_match:

		if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_NORMAL)
		{
			debugf("%s - >>> Dispatch as SYNCED NORMAL\n",
				   mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			state = STATE_IN_SYSCALL;
		}
		else if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_MASTER)
		{
			debugf("%s - >>> Dispatch as SYNCED MASTERCALL\n",
				   mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			state = STATE_IN_MASTERCALL;
		}
		else if (precall_flags & MVEE_PRECALL_CALL_DISPATCH_FORK)
		{
			debugf("%s - >>> Dispatch as SYNCED FORKCALL\n",
				   mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			state = STATE_IN_FORKCALL;
		}
		else if (precall_flags & MVEE_PRECALL_CALL_DENY)
		{
			// dispatch denied in PRECALL handler
			// This usually indicates a mismatch
			debugf("%s - >>> Dispatch DENIED - Shutting down monitor\n",
				   mvee::upcase(getTextualSyscall(variants[0].callnum)).c_str());
			shutdown(false);
			return;
		}

		// Call CALL handler (if present)
		call_flags = call_call_dispatch();

		for (i = 0; i < mvee::numvariants; ++i)
		{
			variants[i].call_flags      = call_flags;
			variants[i].call_dispatched = true;
		}

		if (call_flags & MVEE_CALL_DENY)
		{
			call_resume_fake_syscall_all();
			return;
		}

		if (state == STATE_IN_MASTERCALL)
		{
			for (i = 1; i < mvee::numvariants; ++i)
				if (!interaction::write_syscall_no(variants[i].variantpid, __NR_getpid))
					throw RwRegsFailure(i, "set slave fake call num at mastercall entrance");
		}

		call_resume_all();
		return;
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
			// Known false positive
			flush_mismatch_info();

			// clear call deny flag
			precall_flags &= ~MVEE_PRECALL_CALL_DENY;
			goto args_match;
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
        if (in_signal_handler() && variants[index].return_value == -ERESTARTNOHAND)
        {
            debugf("%s - >>> JUMPING TO SIGNAL HANDLER\n", 
				   call_get_variant_pidstr(index).c_str());		   
            variants[index].callnum = NO_CALL;
            state                 = STATE_NORMAL;
			call_resume(index);
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
			// Write the return value determined by the CALL handler
			call_write_denied_syscall_return(index);
        }
		else
		{
			call_succeeded = call_check_result(variants[index].return_value);
			// Call POSTCALL and LOG_RETURN handlers (if present)
			call_postcall_log_return(index);
			call_postcall_return_unsynced(index);
		}
		
		if (variants[index].have_overwritten_args)
			call_restore_args(index);

		call_resume(index);
        variants[index].call_type       = MVEE_CALL_TYPE_UNKNOWN;
        variants[index].call_dispatched = false;
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
        if (in_signal_handler() && !current_signal_sent)
        {
            debugf("All variants have returned and we can now deliver the signal.\n");
            sig_finish_delivery();
            return;
        }

        if (variants[0].call_flags & MVEE_CALL_DENY)
        {
			for (int i = 0; i < mvee::numvariants; ++i)
				call_write_denied_syscall_return(i);

            state = STATE_NORMAL;

			for (i = 0; i < mvee::numvariants; ++i)
				if (variants[i].have_overwritten_args)
					call_restore_args(i);

            call_resume_all();
            return;
        }

        if (state == STATE_IN_MASTERCALL)
        {
            call_succeeded = call_check_result(variants[0].return_value);

			// Replicate return value
            for (i = 1; i < mvee::numvariants; ++i)
				if (!interaction::write_syscall_return(variants[i].variantpid, variants[0].return_value))
					throw RwRegsFailure(i, "replicate mastercall result");

			// Call return logger
			call_postcall_log_return(0);
        }
        else
        {
            call_succeeded = call_postcall_all_syscalls_succeeded();
			for (int i = 0; i < mvee::numvariants; ++i)
				call_postcall_log_return(i);
        }

        long resume_flags = call_postcall_return();

        state = STATE_NORMAL;

        if (resume_flags != MVEE_POSTCALL_DONTRESUME)
		{
			for (i = 0; i < mvee::numvariants; ++i)
				if (variants[i].have_overwritten_args)
					call_restore_args(i);

            call_resume_all();
		}
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

        debugf("%s - restarted syscall is back at syscall entry\n",
			   call_get_variant_pidstr(index).c_str());

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
                        debugf("%s - all restarted - resuming variant from restarted syscall entry\n", 
							   call_get_variant_pidstr(i).c_str());
                        variants[i].restarting_syscall = variants[i].restarted_syscall = false;
						call_resume(i);
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
            debugf("%s - unsynced or forkcall - resuming variant from restarted syscall entry\n", 
				   call_get_variant_pidstr(index).c_str());
            variants[index].restarting_syscall = variants[index].restarted_syscall = false;
			call_resume(index);
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
            debugf("%s - not mastercall and all synced - resuming variant from restarted syscall entry\n", 
				   call_get_variant_pidstr(i).c_str());
            variants[i].restarting_syscall = variants[i].restarted_syscall = false;
			call_resume(i);
        }
    }
}

/*-----------------------------------------------------------------------------
    handle_signal_event - Handles a signal sent to a variant.

    We execute this whenever a signal interrupts the execution of a variant.
    For asynchronous signals, we'll first call this when the initial signal
    is sent. We will then usually discard that signal and wait for a sync
    point. Then, at the sync point, we send the original signal ourselves
    and we let it go through from within this function.
-----------------------------------------------------------------------------*/
void monitor::handle_signal_event(int variantnum, interaction::mvee_wait_status& status)
{
    siginfo_t siginfo;
	unsigned long ip = 0, ret;
#ifndef MVEE_BENCHMARK
	bool skip_segv = false;
#endif

    // Terminated by unhandled signal
    if (status.reason == STOP_KILLED)
    {
        variants[variantnum].variant_terminated = true;
		if (!is_group_shutting_down())
		{
			warnf("%s - terminated by an unhandled %s signal.\n",
				  call_get_variant_pidstr(variantnum).c_str(), 
				  getTextualSig(status.data));
		}

        // Since we cannot recover from this, we might as well shut 
		// down the variants that have not received the signal
        shutdown(false);
        return;
    }
    else if (status.reason == STOP_SIGNAL) // stopped by the delivery of a signal
    {
        int signal = status.data;

        if (signal == SIGALRM)
            debugf("%s - caught SIGALRM - should_shutdown: %d\n", 
				   call_get_variant_pidstr(variantnum).c_str(), should_shutdown);

		if (!interaction::get_signal_info(variants[variantnum].variantpid, &siginfo))
			throw RwInfoFailure(variantnum, "get signal info");

        if (signal == SIGSEGV)
        {
            // invalidate cached register content
            variantstate* variant = &variants[variantnum];
            variant->regs_valid = false;
            variant->fpregs_valid = false;

            call_check_regs(variantnum);

			if (!variant->regs.rip)
				throw RwRegsFailure(variantnum, "get trap location");
			ip = variant->regs.rip;

#if defined(MVEE_ALLOW_SHM) && defined(MVEE_EMULATE_SHARED_MEMORY)
            // shared memory access ====================================================================================
            // check if this SIGSEGV was caused by a genuine shared memory access
            if IS_SHARED_MEMORY_ACCESS(variantnum, siginfo)
            {
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
                // log instruction =====================================================================================
                mmap_region_info* variant_map_info = set_mmap_table->get_shared_info(variant->variant_num,
                        (unsigned long long) siginfo.si_addr);
                if (variant_map_info)
                {
                    if (instruction_tracing::log_shared_instruction(*this, variant, siginfo.si_addr,
                            variant_map_info) < 0)
                    {
                        // set_mmap_table->print_mmap_table(warnf);
                        mmap_region_info* region = set_mmap_table->get_region_info(variantnum, variant->regs.rip,
                                0);
                        if (region)
                            warnf("segfault in %s at offset %p\n", region->region_backing_file_path.c_str(),
                                  (void*) (variant->regs.rip - region->region_base_address));
                        else
                            warnf("no region could be determined\n");
                        instruction_intent* instruction = &variant->instruction;
                        instruction->update((void*) variant->regs.rip, siginfo.si_addr);
                        instruction->debug_print_minimal();
                        signal_shutdown();
                    }
                    return;
                }
                // log instruction =====================================================================================
#else
                // update the intent for the faulting variant
                variant->instruction.update((void*) variant->regs.rip, decode_address_tag(siginfo.si_addr, variant));
                instruction_intent_emulation::handle_emulation(variant, this);
                return;
#endif
            }
            // shared memory access ====================================================================================
#endif

            std::string caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, ip, 0);


			// check for cpuid exception
#ifdef MVEE_EMULATE_CPUID
			instruction_intent instruction(&variants[variantnum].variantpid, &variants[variantnum].variant_num);
			if (instruction.update((void*) variant->regs.rip) == 0 &&
			        instruction[0] == 0x0f && instruction[1] == 0xa2)
            {
			    if (instruction_intent_emulation::lookup_table[instruction[1]].emulator(instruction, *this, variant))
                {
			        warnf("something went wrong emulating cpuid");
			        signal_shutdown();
                    return;
                }

                variant->regs.rip += instruction.size;
                if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
                    warnf("\n\n\nerror\n\n\n");
                call_resume(variantnum);
                return;
            }
#endif

#ifndef MVEE_BENCHMARK
            debugf("%s - variant crashed - trapping ins: %s\n",
                   call_get_variant_pidstr(variantnum).c_str(), caller_info.c_str());
            if (caller_info.find("mvee_log_stack at") != std::string::npos)
                skip_segv = true;
#endif

			if (caller_info.find("rb_xcheck at") != std::string::npos)
			{
				warnf("%s - Failed ring buffer cross-check\n",
					  call_get_variant_pidstr(variantnum).c_str());
				log_clevrbuf_state(variantnum);
				log_variant_backtrace(variantnum, 0, 0, 1);
				shutdown(false);
				return;
			}
        }

        debugf("%s - Received signal %s (%d)\n", call_get_variant_pidstr(variantnum).c_str(), getTextualSig(signal), signal);

#ifndef MVEE_BENCHMARK
		if (skip_segv)
		{
			unsigned long instr[2];			
			if (!rw::read_struct(variants[variantnum].variantpid, (void*) ip, sizeof(unsigned long) * 2, instr))
				throw RwMemFailure(variantnum, "read trap instruction");

# ifdef MVEE_ARCH_SUPPORTS_DISASSEMBLY
			HDE_INS(disas_ins);
			HDE_DISAS(disas_ins_len, &instr, &disas_ins);
# else
			// We're assuming RISC here...
			long disas_ins_len = sizeof(long);
# endif
			if (disas_ins_len > 0)
			{
				if (!interaction::write_ip(variants[variantnum].variantpid, ip + disas_ins_len))
					throw RwRegsFailure(variantnum, "skip trap instruction");

				call_resume(variantnum);
				debugf("%s - skipped SIGSEGV\n", call_get_variant_pidstr(variantnum).c_str());
				return;
			}
		}
		else
		{
			if (!ip && !interaction::fetch_ip(variants[variantnum].variantpid, ip))
				throw RwRegsFailure(variantnum, "get trap location");

			std::string caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, ip, 0);
			debugf("%s - signal arrived while variant was executing ins: %s\n", 
				   call_get_variant_pidstr(variantnum).c_str(), caller_info.c_str());

			if (!interaction::fetch_syscall_return(variants[variantnum].variantpid, ret))
				throw RwRegsFailure(variantnum, "read syscall num/return at trap location");

			debugf("%s - ret is currently: %ld\n", call_get_variant_pidstr(variantnum).c_str(), ret);
		}
#endif

        if (signal == SIGSEGV || signal == SIGBUS)
		{
            log_segfault(variantnum);

			// segfault in signal handler. Pretend like nothing happened :)))
			if (in_signal_handler())
			{
				warnf("%s - A fatal signal was delivered while executing a signal handler.\n", 
					  call_get_variant_pidstr(variantnum).c_str());
				warnf("%s - We're just quietly shutting down this variant set and moving on ;)\n", 
					  call_get_variant_pidstr(variantnum).c_str());
				variants[variantnum].variant_terminated = true;
				shutdown(true);
				return;
			}
		}

        if (sighand_table::is_control_flow_signal(signal))
        {
#ifndef MVEE_BENCHMARK
            log_variant_backtrace(variantnum, 0, 0, 1);
#endif
            // immediately deliver signals that are probably caused by the
            // normal control flow
            debugf("%s Delivering control flow signal %s to variant.\n", call_get_variant_pidstr(variantnum).c_str(), getTextualSig(signal));

			if (set_sighand_table->will_cause_termination(signal))
				set_mmap_table->thread_group_shutting_down = true;

            // deliver control flow signal
			if (!interaction::resume_until_syscall(variants[variantnum].variantpid, signal))
				throw ResumeFailure(variantnum, "resume after signal injection");
        }
		// if the MVEE is injecting the signal, then the monitor
		// will be the sender in siginfo.si_pid
        else if (siginfo.si_pid == mvee::os_getpid())
        {
            debugf("%s - signal %s is ready for injection in variant\n", 
				   call_get_variant_pidstr(variantnum).c_str(), 
				   getTextualSig(signal));

            if (current_signal_info)
            {
				// restore the original sender
                siginfo.si_pid  = current_signal_info->si_pid;

				if (!interaction::set_signal_info(variants[variantnum].variantpid, &siginfo))
					throw RwInfoFailure(variantnum, "set original signal info");

                // if we're in a restarted sigsuspend, we will see the exit
				// site of the call before the actual sighandler is invoked
				//
                // if we're in a regular sigsuspend, we will not see the exit 
				// site but instead jump to the sighandler right away

                if (!variants[variantnum].restarting_syscall &&
                    !variants[variantnum].restarted_syscall)
                {
                    debugf("%s - this is not a restarted call. We're expecting to see the signal handler right away!\n", call_get_variant_pidstr(variantnum).c_str());
                    variants[variantnum].callnum = NO_CALL;
                    state                        = STATE_NORMAL;
                }

                variants[variantnum].current_signal_ready = true;
                bool all_ready = true;

                for (int i = 0; i < mvee::numvariants; ++i)
                    if (!variants[i].current_signal_ready)
                        all_ready = false;

                if (all_ready)
                {
                    debugf("%s - signal is ready for injection in all variants. Injecting...\n", 
						   call_get_variant_pidstr(variantnum).c_str());
                    debugf("%s - releasing syslocks for %lu (%s)\n", 
						   call_get_variant_pidstr(variantnum).c_str(),
						   variants[0].callnumbackup, 
						   getTextualSyscall(variants[0].callnumbackup));

					if (set_sighand_table->will_cause_termination(signal))
						set_mmap_table->thread_group_shutting_down = true;

                    // thread sanitizer might complain about this! 
					// We should probably figure out at which point we injected the signal
					/*
					bool was_in_call         =
						(state == STATE_IN_MASTERCALL
						 || state == STATE_IN_SYSCALL
						 || state == STATE_IN_FORKCALL);

					if (was_in_call)
						call_release_syslocks(-1, variants[0].callnumbackup, MVEE_SYSLOCK_FULL);
					else
						call_release_syslocks(-1, variants[0].callnumbackup, MVEE_SYSLOCK_PRECALL);
					*/

                    for (int i = 0; i < mvee::numvariants; ++i)
						if (!interaction::resume_until_syscall(variants[i].variantpid, signal))
							throw ResumeFailure(i, "resume after signal injection");
                }
            }
            else
            {
                debugf("%s - signal NOT injected!!! Was this a shutdown signal???\n",
					   call_get_variant_pidstr(variantnum).c_str());
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
            debugf("%s - intercepted signal %s from pid: %d\n", 
				   call_get_variant_pidstr(variantnum).c_str(), getTextualSig(signal), siginfo.si_pid);

            if (signal > 0 && signal <= 32)
            {
                // do not store duplicates for non-real time signals
                for (std::vector<mvee_pending_signal>::iterator it = pending_signals.begin();
                     it != pending_signals.end(); ++it)
                {
                    if (it->sig_no == signal)
                    {
                        debugf("%s - found duplicate signal in pending list. Ignoring signal\n",
							   call_get_variant_pidstr(variantnum).c_str());

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
				sig_set_pending_signals(true, in_signal_handler());
                debugf("%s - signal queued\n", call_get_variant_pidstr(variantnum).c_str());
            }

			if (variantnum == 0 && (*mvee::config_variant_global)["use_ipmon"].asBool())
			{
				if (!ip && !interaction::fetch_ip(variants[variantnum].variantpid, ip))
					throw RwRegsFailure(variantnum, "get trap location");

				if (in_ipmon(0, ip))
				{
					if (in_ipmon_syscall(0, ip))
					{
						// force the syscall to return to user-space
						if (!interaction::fetch_syscall_return(variants[0].variantpid, ret))
							throw RwRegsFailure(0, "get syscall return for trap inside IP-MON");

						// Check if this syscall would restart automatically
						// if we resumed it as-is
						if ((long) ret <= -512	&& (long) ret >= -516)
						{
							debugf("%s - forcing IP-MON syscall to return to user-space\n",
								   call_get_variant_pidstr(variantnum).c_str());

							// retarded hack. If we replace the orig_ax register by -1, 
							// the kernel will just bail out (in arch/x86/kernel/signal.c)
							// and return the ERESTART error to user-space
							if (!interaction::write_syscall_return(variants[0].variantpid, (unsigned long) -1))
								throw RwRegsFailure(0, "force syscall return inside IP-MON");
						}
					}
				}
			}

            // Continue normal execution for now.
            // When a signal is ignored, the variant that was about to execute the sighandler
            // will execute a sys_restart_syscall call.
			call_resume(variantnum);
        }
    }
}

/*-----------------------------------------------------------------------------
    discard_pending_signal
-----------------------------------------------------------------------------*/
std::vector<mvee_pending_signal>::iterator
monitor::discard_pending_signal(std::vector<mvee_pending_signal>::iterator& it)
{
    std::vector<mvee_pending_signal>::iterator ret = pending_signals.erase(it);
    return ret;
}

/*-----------------------------------------------------------------------------
    have_pending_signals
-----------------------------------------------------------------------------*/
bool monitor::have_pending_signals()
{
	return pending_signals.size() > 0;
}

/*-----------------------------------------------------------------------------
    in_signal_handler
-----------------------------------------------------------------------------*/
bool monitor::in_signal_handler()
{
	return current_signal != 0;
}

/*-----------------------------------------------------------------------------
    sig_set_pending_signals
-----------------------------------------------------------------------------*/
void monitor::sig_set_pending_signals(bool pending_signals, bool entering_signal_handler)
{
	// This is perhaps not optimal...
	// We force IP-MON to dispatch all its syscalls as checked
	// as long as we have pending signals...
	if (ipmon_buffer)
	{
		struct ipmon_buffer* buffer = (struct ipmon_buffer*)(ipmon_buffer->ptr);
		buffer->ipmon_have_pending_signals  = pending_signals ? 1 : 0;
		buffer->ipmon_have_pending_signals |= entering_signal_handler ? 2 : 0;
	}
}

/*-----------------------------------------------------------------------------
    in_ipmon_syscall - Checks if we're two bytes past the syscall instruction
-----------------------------------------------------------------------------*/
bool monitor::in_ipmon_syscall(int variantnum, unsigned long ip)
{
	unsigned short opcode;
	
	// TODO: Add support for other archs here
	if (rw::read_primitive<unsigned short>(variants[variantnum].variantpid, (void*) (ip - SYSCALL_INS_LEN), opcode) &&
		opcode == 0x050F)
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
	debugf("%s - variant was executing ins: %s\n", call_get_variant_pidstr(variantnum).c_str(), caller_info.c_str());
#endif

	mmap_region_info* region = set_mmap_table->get_region_info(variantnum, ip, 0);

#ifndef MVEE_BENCHMARK
	if (variants[variantnum].ipmon_region)
		debugf("%s - > IP: 0x" PTRSTR " - ipmon_base: 0x" PTRSTR "\n",
			   call_get_variant_pidstr(variantnum).c_str(), ip, variants[variantnum].ipmon_region->region_base_address);

	if (region)
		region->print_region_info("> IP-MON REGION: ");
#endif

	if (region && region == variants[variantnum].ipmon_region)
		return true;

	return false;
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
	interaction::mvee_wait_status status;

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
				call_resume(i);

				if (!interaction::wait(variants[i].variantpid, status, false, false, false) ||
					(status.reason != STOP_SYSCALL &&
					 status.reason != STOP_SIGNAL))
				{
					throw WaitFailure(i, "handling SIGCHLD race", status);
				}

				if (status.reason == STOP_SYSCALL)
				{
					// we're now at the syscall exit
					if (at_syscall_entry[i])
					{
						debugf("%s - variant is at the syscall exit\n", 
							   call_get_variant_pidstr(i).c_str());

						if (!interaction::write_ip(variants[i].variantpid, IP_IN_REGS(variants[i].regs) - SYSCALL_INS_LEN) ||
							!interaction::write_next_syscall_no(variants[i].variantpid, __NR_getpid))
						{
							throw RwRegsFailure(i, "rewinding syscall during SIGCHLD race");
						}

						at_syscall_entry[i] = 0;
					}
					// back at the syscall entrance
					else
					{
						debugf("%s - variant is at the syscall entry\n", call_get_variant_pidstr(i).c_str());
						at_syscall_entry[i] = 1;
					}
				}
				else if (status.reason == STOP_SIGNAL &&
						 status.data == it->sig_no)
				{
					debugf("%s - variant has received the signal\n", call_get_variant_pidstr(i).c_str());
					it->sig_recv_mask |= (1 << i);
					at_syscall_entry[i] = 0;
				}
				else
				{
					warnf("%s - ERROR: unexpected stop status while handling sigchld race - stop status: %s\n", 
						  call_get_variant_pidstr(i).c_str(), 
						  getTextualMVEEWaitStatus(status).c_str());
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
			call_resume(i);

			if (!interaction::wait(variants[i].variantpid, status, false, false, false) ||
				(status.reason != STOP_SYSCALL &&
				 status.reason != STOP_SIGNAL))
			{
				throw WaitFailure(i, "sync at syscall entrance during SIGCHLD race", status);
			}

			debugf("%s - variant is back at the syscall entry - ready to deliver signal\n", 
				   call_get_variant_pidstr(i).c_str());
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
    if (in_signal_handler() || 
		!have_pending_signals())
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
                sigset_t _set = call_get_sigset(0, (void*)ARG1(0), OLDCALLIFNOT(__NR_rt_sigsuspend));

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
			sig_set_pending_signals(have_pending_signals(), in_signal_handler());
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

		// reset handlers for SA_RESETHAND signals
		if (set_sighand_table->action_table[it->sig_no].sa_flags & SA_RESETHAND)
			set_sighand_table->action_table[it->sig_no].sa_handler = SIG_DFL;

        // delete from pending list
        it                  = discard_pending_signal(it);
		sig_set_pending_signals(have_pending_signals(), true);

        // backup context
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            memcpy(&variants[i].regsbackup, &variants[i].regs, sizeof(PTRACE_REGS));
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
				
                if (!interaction::signal(variants[i].variantpid,
										 variants[i].varianttgid,
										 current_signal))
                {
					throw SignalFailure(i, current_signal);
                }

                // If we're at the entry of a sigsuspend that hasn't been restarted yet, we will call the precall handler next
                if (result)
					call_resume(i);
            }

            current_signal_sent = true;
        }
        else
        {
            debugf("Skipping current syscall in all variants\n");
            call_resume_fake_syscall_all();
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
		PTRACE_REGS tmp;
		memcpy(&tmp, &variants[i].regs, sizeof(PTRACE_REGS));
		IP_IN_REGS(tmp) = (unsigned long) variants[i].infinite_loop_ptr;

		if (!interaction::write_all_regs(variants[i].variantpid, &tmp))
			throw RwRegsFailure(i, "jump to infinite loop");

		if (!interaction::resume(variants[i].variantpid))
			throw ResumeFailure(i, "resume in infinite loop");

        variants[i].current_signal_ready = false;

        if (!interaction::signal(variants[i].variantpid,
								 variants[i].varianttgid,
								 current_signal))
			throw SignalFailure(i, current_signal);
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
	sig_set_pending_signals(have_pending_signals(), false);

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
            debugf("%s - restoring call site for call: %lu (%s)\n", 
				   call_get_variant_pidstr(i).c_str(),
				   variants[i].callnumbackup,
				   getTextualSyscall(variants[i].callnumbackup));
            variants[i].callnum         = NO_CALL;
            state                       = STATE_NORMAL;

            // explicitly restore the original call number (sometimes required)
            debugf("%s - restoring instruction pointer: 0x" PTRSTR " - syscall no: 0x" PTRSTR "\n", 
				   call_get_variant_pidstr(i).c_str(), (unsigned long)IP_IN_REGS(variants[i].regsbackup), variants[i].callnumbackup);

            // Move the instruction pointer back by 2 bytes to repeat the original syscall
            IP_IN_REGS(variants[i].regsbackup) -= SYSCALL_INS_LEN;
			NEXT_SYSCALL_NO_IN_REGS(variants[i].regsbackup) = variants[i].callnumbackup;
			if (!interaction::write_all_regs(variants[i].variantpid, &variants[i].regsbackup))
				throw RwRegsFailure(i, "post-signal context restore");

			call_resume(i);
        }

		if (!restore_context && !current_signal)
			call_resume(i);
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
	interaction::mvee_wait_status status;

    debugf("%s - Restarting syscall %lu (%s) - previous call failed with error: %s\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   variants[variantnum].callnum,
		   getTextualSyscall(variants[variantnum].callnum),
		   getTextualKernelError(-variants[variantnum].return_value));

	call_resume(variantnum);
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
		debugf("%s - This was a mastercall - we need to restart the slaves after they return from their fake syscall\n",
		   call_get_variant_pidstr(variantnum).c_str());

        for (int i = 1; i < mvee::numvariants; ++i)
        {
			// Wait for the slaves to come back from the fake syscall
            if (variants[i].callnum != NO_CALL)
            {
				debugf("%s - Slave has not returned from the mastercall yet\n", 
					   call_get_variant_pidstr(i).c_str());

                if (interaction::wait(variants[i].variantpid, status, false, false, false))
                {
					if (status.reason != STOP_SYSCALL)
					{
						// TODO: call handle_signal_event here???
						// ==> Yes! otherwise the signal might get lost!!!
						int sig = status.data;

						handle_signal_event(i, status);

						if (!sighand_table::is_control_flow_signal(sig))
						{
							if (!interaction::wait(variants[i].variantpid, status, false, false, false) || 
								status.reason != STOP_SYSCALL)
								throw WaitFailure(i, "post signal-restart during master call", status);
						}
					}					                    
                }
				else
				{
					throw WaitFailure(i, "slave wait failure during mastercall restart", status);
				}

				debugf("%s - Slave has returned from the mastercall\n", 
					   call_get_variant_pidstr(i).c_str());
            }

            // restore regs for slaves?! Some args seem to get clobbered...
			IP_IN_REGS(variants[i].regs) -= SYSCALL_INS_LEN;
//			NEXT_SYSCALL_NO_IN_REGS(variants[i].regs) = variants[0].callnum;
			NEXT_SYSCALL_NO_IN_REGS(variants[i].regs) = __NR_getpid;

            variants[i].regs_valid         = false;
            variants[i].callnum            = variants[0].callnum;
            variants[i].restarting_syscall = true;
            variants[i].restarted_syscall  = false;

			if (!interaction::write_all_regs(variants[i].variantpid, &variants[i].regs))
				throw RwRegsFailure(i, "restoring original register context during syscall restart");

			call_resume(i);
			IP_IN_REGS(variants[i].regs) += SYSCALL_INS_LEN;

			debugf("%s - restarted syscall in variant\n",
				   call_get_variant_pidstr(i).c_str());
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
#ifdef MVEE_ARCH_HAS_X86_HWBP
    unsigned long dr7;
    int           i;

    // Dr0-3 are linear addresses
    for (i = 0; i < 4; ++i)
    {
        if (variants[variantnum].hw_bps[i])
        {
            debugf("%s - setting debug reg %d\n", 
				   call_get_variant_pidstr(variantnum).c_str(), i);

			if (!interaction::write_specific_reg(variants[variantnum].variantpid,
												 offsetof(user, u_debugreg) + i*sizeof(unsigned long), 
												 variants[variantnum].hw_bps[i]))
				throw RwRegsFailure(variantnum, "hwbp set debug reg");
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

    debugf("%s - setting ctrl reg\n", 
		   call_get_variant_pidstr(variantnum).c_str());

	if (!interaction::write_specific_reg(variants[variantnum].variantpid,
										 offsetof(user, u_debugreg) + 7*sizeof(long), 
										 dr7))
		throw RwRegsFailure(variantnum, "hwbp set dr7");

#else
	warnf("%s - hardware breakpoints are not supported on this architecture\n",
				  call_get_variant_pidstr(variantnum).c_str());
#endif
}

/*-----------------------------------------------------------------------------
    hwbp_set_watch - sets a hardware breakpoint on the specified data
    address (if debug registers are available)

    FIXME/TODO: This doesn't work properly! debug regs are only set for the
    local thread, not the entire process!
-----------------------------------------------------------------------------*/
bool monitor::hwbp_set_watch(int variantnum, unsigned long addr, unsigned char bp_type)
{
#ifdef MVEE_ARCH_HAS_X86_HWBP
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
    debugf("%s - set hw bp: 0x" PTRSTR "\n", 
		   call_get_variant_pidstr(variantnum).c_str(), addr);
    return true;
#else
	warnf("%s - hardware breakpoints are not supported on this architecture\n",
		  call_get_variant_pidstr(variantnum).c_str());
	return false;
#endif
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
	{
		debugf("%s - pinned master thread (TID: %d) on cpu: %d\n", 
			   call_get_variant_pidstr(0).c_str(), variants[0].variantpid, master_core);
	}
	else
	{
		debugf("%s - couldn't pin thread on core %d\n", 
			   call_get_variant_pidstr(0).c_str(), master_core);
	}

	for (int i = 1; i < mvee::numvariants; ++i)
	{
		if (sched_setaffinity(variants[i].variantpid, sizeof(cpu_set_t), &slave_set) == 0)
		{
			debugf("%s - pinned slave thread (TID: %d) on cpus: [%d, %d]\n", 
				   call_get_variant_pidstr(i).c_str(),
				   variants[i].variantpid, master_core, master_core + mvee::numvariants - 1);
		}
		else
		{
			debugf("%s - couldn't pin thread\n",
				   call_get_variant_pidstr(i).c_str());
		}
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
	interaction::mvee_wait_status status;
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

    // We also ignore this one. It will still interrupt our wait calls though
    act.sa_handler = dummy_handler;
    if (sigaction(SIGUSR1, &act, NULL))
        warnf("couldn't ignore SIGUSR1\n");

    sigset_t         set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // this is needed to prevent the mmap table sharing to mess up
    if (mon->shm_setup_state & SHM_SETUP_EXPECTING_ENTRY)
        mon->set_mmap_table->attach_shared_memory();

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
        mon->handle_attach_event(i);

#ifdef MVEE_ALLOW_MONITOR_SCHEDULING
	mon->schedule_threads();
#endif

	try
	{
		while (1)
		{
			if (mon->should_shutdown)
			{
				mon->shutdown(true);
				return NULL;
			}

			// Standard blocking wait for all of our variants
			if (interaction::wait(-1, status))
			{
				mon->handle_event(status);

				// Don't go back into a blocking wait right away... first
				// see if we already have a pending variant.
				if (interaction::wait(-1, status, true, true) &&
					status.reason != STOP_NOTSTOPPED)
				{
					mon->handle_event(status);

					// We had a pending variant... which means there might be others.
					// Try them one by one.
					for (int i = 0; i < mvee::numvariants; ++i)
					{
						if (interaction::wait(mon->variants[i].variantpid, status, true, true) &&
							status.reason != STOP_NOTSTOPPED)
                            mon->handle_event(status);
					}
				}			
			}
			else
				debugf("wait failed - error: %s - status: %s\n", 
					   getTextualErrno(errno),
					   getTextualMVEEWaitStatus(status).c_str());
		}
	}
	catch (MVEEBaseException& e)
	{
		if (mon->set_mmap_table && !mon->set_mmap_table->thread_group_shutting_down)
		{
			warnf("caught fatal monitor exception: %s\n", e.what());
		}
		else
		{
			debugf("caught monitor exception during shutdown: %s\n", e.what());
		}
		mon->shutdown(false);
		return NULL;
	}

    mon->shutdown(true);
    return NULL;
}
