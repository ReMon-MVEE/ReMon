/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
#include <stdarg.h>
#include <errno.h>
#include <sstream>
#include <dwarf.h>
#include <libdwarf.h>
#include <sys/time.h>
#include <string.h>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <numeric>
#include <execinfo.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_shm.h"
#include "MVEE_macros.h"
#include "MVEE_syscalls.h"
#include "MVEE_logging.h"
#include "MVEE_private_arch.h"
#include "MVEE_mman.h"
#include "MVEE_memory.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Static Variable Initialization
-----------------------------------------------------------------------------*/
FILE*             mvee::logfile              = NULL;
FILE*             mvee::ptrace_logfile       = NULL;
FILE*             mvee::datatransfer_logfile = NULL;
FILE*             mvee::lockstats_logfile    = NULL;
double            mvee::startup_time         = 0.0;
pthread_mutex_t   mvee::loglock              = PTHREAD_MUTEX_INITIALIZER;

/*-----------------------------------------------------------------------------
    cache_mismatch_info
-----------------------------------------------------------------------------*/
void monitor::cache_mismatch_info(const char* format, ...)
{
	char buffer[4096];
    va_list va;
    va_start(va, format);
	if (vsnprintf(buffer, 4096, format, va) > 0)
		mismatch_info << buffer;		
    va_end(va);
}

/*-----------------------------------------------------------------------------
    dump_mismatch_info
-----------------------------------------------------------------------------*/
void monitor::dump_mismatch_info()
{
	warnf(mismatch_info.str().c_str());
	flush_mismatch_info();
}

/*-----------------------------------------------------------------------------
    flush_mismatch_info
-----------------------------------------------------------------------------*/
void monitor::flush_mismatch_info()
{
	mismatch_info.str("");
}

/*-----------------------------------------------------------------------------
    get_ipmon_data
-----------------------------------------------------------------------------*/
struct ipmon_syscall_data* monitor::get_ipmon_data
(
	struct ipmon_syscall_entry* entry, 
	unsigned long start_offset,
	unsigned long end_offset,
	int data_num
)
{
	unsigned long data_offset = start_offset;
	int num = 0;

	while (data_offset < end_offset)
	{
		struct ipmon_syscall_data* data = (struct ipmon_syscall_data*)((unsigned long)entry + data_offset);

		if (num == data_num)
			return data;
		if (data->len <= 0)
			return nullptr;

		num++;
		data_offset += data->len;
	}

	return nullptr;
}

/*-----------------------------------------------------------------------------
    get_ipmon_arg
-----------------------------------------------------------------------------*/
struct ipmon_syscall_data* monitor::get_ipmon_arg(struct ipmon_syscall_entry* entry, int arg_num)
{
	return get_ipmon_data(entry, 
						  sizeof(struct ipmon_syscall_entry), 
						  sizeof(struct ipmon_syscall_entry) + entry->syscall_args_size, 
						  arg_num);
}

/*-----------------------------------------------------------------------------
    get_ipmon_ret
-----------------------------------------------------------------------------*/
struct ipmon_syscall_data* monitor::get_ipmon_ret(struct ipmon_syscall_entry* entry, int ret_num)
{
	return get_ipmon_data(entry,
						  sizeof(struct ipmon_syscall_entry) + entry->syscall_args_size,
						  entry->syscall_entry_size,
						  ret_num);
}

/*-----------------------------------------------------------------------------
    log_ipmon_entry
-----------------------------------------------------------------------------*/
bool monitor::log_ipmon_entry
(
	struct ipmon_buffer* buffer,
	struct ipmon_syscall_entry* entry, 
	void (*logfunc)(const char* format, ...)
)
{
	logfunc("\tsyscall           : %hu (%s)\n", (unsigned short)entry->syscall_no, getTextualSyscall((unsigned short)entry->syscall_no));
	logfunc("\tsyscall type (raw): %d\n", entry->syscall_type);
	logfunc("\tchecked           : %d\n", (entry->syscall_type & IPMON_EXEC_NO_IPMON) ? 1 : 0);
	logfunc("\tcanceled (signal) : %d\n", (entry->syscall_type & IPMON_WAIT_FOR_SIGNAL_CALL) ? 1 : 0);
	logfunc("\torder             : %d\n", entry->syscall_order);
	logfunc("\treplicate master  : %d\n", (entry->syscall_type & IPMON_REPLICATE_MASTER) ? 1 : 0);
	logfunc("\tblocking call     : %d\n", (entry->syscall_type & IPMON_BLOCKING_CALL) ? 1 : 0);
	logfunc("\tresults waiters   : %d\n", entry->syscall_results_available.u.s.have_waiters);
	logfunc("\tresults available : %d\n", entry->syscall_results_available.u.s.signaled);
	logfunc("\tlockstep waiters  : %d\n", entry->syscall_lockstep_barrier.u.s.count);
	logfunc("\tlockstep sequence : %d\n", entry->syscall_lockstep_barrier.u.s.seq >> 8);
	logfunc("\treturn value      : %ld (%lx)\n", entry->syscall_return_value, entry->syscall_return_value);
	logfunc("\tentrysize         : %d\n", entry->syscall_entry_size);

	if (entry->syscall_entry_size == 0)
		return false;

	int argnum = 0;
	while (true)
	{
		struct ipmon_syscall_data* arg = get_ipmon_arg(entry, argnum);

		if (!arg)
			break;

		logfunc("========ARG %02d==================================================================\n", argnum);

		logfunc("\tlen               : %ld\n", arg->len);

		if (arg->len + (unsigned long)entry > 
			(unsigned long)buffer + 64 * (1 + mvee::numvariants) + buffer->ipmon_usable_size)
		{
			logfunc("INVALID LENGTH!\n");
			return false;
		}

		if (!arg->len)
			break;

		std::string hex = mvee::log_do_hex_dump (arg->data, arg->len - sizeof(unsigned long));
		logfunc("\n%s", hex.c_str());
		argnum++;
	}

	int retnum = 0;
	while (true)
	{
		struct ipmon_syscall_data* ret = get_ipmon_ret(entry, retnum);

		if (!ret)
			break;

		logfunc("========RET %02d==================================================================\n", retnum);

		logfunc("\tlen               : %ld\n", ret->len);

		if (ret->len + (unsigned long)entry > 
			(unsigned long)buffer + 64 * (1 + mvee::numvariants) + buffer->ipmon_usable_size)
		{
			logfunc("INVALID LENGTH!\n");
			return false;
		}

		if (!ret->len)
			break;

		std::string hex = mvee::log_do_hex_dump (ret->data, ret->len - sizeof(unsigned long));
		logfunc("\n%s", hex.c_str());
		retnum++;
	}

	return true;
}

/*-----------------------------------------------------------------------------
    log_ipmon_state
-----------------------------------------------------------------------------*/
void monitor::log_ipmon_state()
{
#ifndef MVEE_BENCHMARK
	if (! ipmon_buffer)
		return;

	debugf("Dumping IPMON buffer " PTRSTR " ...\n", ipmon_buffer);

	std::vector<unsigned int> offsets(mvee::numvariants);
	unsigned int highest = 0;

	struct ipmon_buffer* buffer = (struct ipmon_buffer*) ipmon_buffer->ptr;

	debugf("Global state:\n");
	debugf("\tnumvariants = %d\n", buffer->ipmon_numvariants);
	debugf("\tusable_size = %d\n", buffer->ipmon_usable_size);
	debugf("\thave_pending_signals = %ld\n", buffer->ipmon_have_pending_signals);
	debugf("\tflush_count = %d\n", buffer->flush_count);
	debugf("\tpre_flush = [0x%04x,0x%04x]\n", buffer->pre_flush_barrier.u.s.seq, buffer->pre_flush_barrier.u.s.count);
	debugf("\tpost_flush = [0x%04x,0x%04x]\n", buffer->post_flush_barrier.u.s.seq, buffer->post_flush_barrier.u.s.count);

	for (int i = 0; i < mvee::numvariants; i++) 
	{
		offsets[i] = buffer->ipmon_variant_info[i].pos;
		if (offsets[i] > highest)
			highest = offsets[i];

		debugf("Variant %d\n", i);
		debugf("\tstatus %d, pos %d\n", 
			   buffer->ipmon_variant_info[i].status,
			   buffer->ipmon_variant_info[i].pos);
	}

	unsigned int offset = 0;
	unsigned int data_start = 64 * (1 + mvee::numvariants);
	int entry_num = 0;

	while (offset <= highest)
	{
		ipmon_syscall_entry* entry = (ipmon_syscall_entry*)((unsigned long)buffer + data_start + offset);

		debugf("================================================================================\n");
		std::stringstream ss;
		ss << "\tentry " << entry_num++ << " - offset: " << offset;
		for (int i = 0; i < mvee::numvariants; ++i)
		{
			if (offsets[i] == offset)
			{
				ss << " <= variant " <<  i;
			}
			else if (offsets[i] > offset && offsets[i] < entry->syscall_entry_size + offset)
			{
				ss << " <= variant " << i << " (call in progress)";
			}
		}
		ss << "\n";
		debugf(ss.str().c_str());

		if (offset + sizeof(struct ipmon_syscall_entry) > (unsigned long)buffer->ipmon_usable_size ||
			offsets[0] == offset)
			break;

		debugf("================================================================================\n");
		if (!log_ipmon_entry(buffer, entry, debugf))
			break;

		offset += entry->syscall_entry_size;
	}
	
#endif
}

/*-----------------------------------------------------------------------------
    log_monitor_state
-----------------------------------------------------------------------------*/
void monitor::log_monitor_state(void (*logfunc)(const char* format, ...))
{
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)

    if (!logfunc)
        logfunc = mvee::logf;

    logfunc("========================== CURRENT MONITOR STATE ==========================\n");
    logfunc("* monitorid: %d\n",          monitorid);
    logfunc("* monitor state: %s\n",      getTextualState(state));
    logfunc("* created by monitor: %d\n", parentmonitorid);

	for (int i = 0; i < mvee::numvariants; ++i)
	{
		logfunc("* monitoring variant %d: %s %s\n", i,				
				set_mmap_table->mmap_startup_info[i].image.c_str(),
				set_mmap_table->mmap_startup_info[i].serialized_argv.c_str());
	}
    logfunc("* monitoring main thread? %s\n", monitorid == set_mmap_table->mmap_execve_id ? "YES" : "NO");

    if (monitorid == set_mmap_table->mmap_execve_id)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            char        cmd[1000];
            sprintf(cmd, "ps ux | grep %s | grep \" %d \" | grep -v grep", set_mmap_table->mmap_startup_info[i].image.c_str(),
                    variants[i].variantpid);
            std::string buf = mvee::log_read_from_proc_pipe(cmd, NULL);
            logfunc("* variant %d ps: %s\n", i, buf.c_str());
        }
    }
    logfunc("===========================================================================\n");
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        bool call_dispatched = variants[i].call_dispatched;
        bool in_call         = (state == STATE_IN_MASTERCALL
                                || state == STATE_IN_SYSCALL
                                || state == STATE_IN_FORKCALL
                                || (variants[i].call_type == MVEE_CALL_TYPE_UNSYNCED && call_dispatched));
        bool at_call_entry   = (variants[i].callnum != NO_CALL);
        bool at_call_exit    = variants[i].callnum == NO_CALL;
		bool in_sigsuspend   = in_call && (
#ifdef __NR_sigsuspend
			variants[0].callnum == __NR_sigsuspend ||
#endif 
			variants[0].callnum == __NR_rt_sigsuspend);
        bool needs_sigstop   = true;

        if ((!in_call && at_call_entry && !call_dispatched)
            || (in_call && at_call_exit)
			// programs won't react to our SIGQUIT signal while in sys_sigsuspend
			|| in_sigsuspend)
            needs_sigstop = false;

        logfunc(">>> variant %d: pid %d\n", i, variants[i].variantpid);
        logfunc("    > in syscall: %s\n", in_call ? "YES" : "NO");
        logfunc("    > current syscall: %d (%s)\n",
                variants[i].callnum,
                getTextualSyscall(variants[i].callnum));
        logfunc("    > call type: %d\n",                  variants[i].call_type);
        logfunc("    > needs sigstop to interrupt: %s\n", needs_sigstop ? "YES" : "NO");
    }
    logfunc("===========================================================================\n");
#endif
}

/*-----------------------------------------------------------------------------
    log_backtraces
-----------------------------------------------------------------------------*/
void monitor::log_backtraces()
{
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
    warnf("Backtrace requested. current monitor state: %s\n",
                getTextualState(state));

	if (set_mmap_table->mmap_startup_info[0].image.length() == 0)
	{
		warnf("Can't backtrace because variants haven't been fully initialized yet\n");
	}
	else
	{
# if defined(MVEE_BENCHMARK) && defined(MVEE_FORCE_ENABLE_BACKTRACING)
    log_monitor_state(mvee::warnf);
# else
    log_monitor_state(mvee::logf);
# endif

		for (int i = 0; i < mvee::numvariants; ++i)
		{
			if (!variants[i].variant_terminated)
				log_variant_backtrace(i, 0, 1);
			else
				debugf("pid: %d was already TERMINATED - can't backtrace!\n", variants[i].variantpid);
		}

		log_ipmon_state();
		log_dump_queues(set_shm_table.get());
	}
#endif
}

/*-----------------------------------------------------------------------------
    log_init - opens the monitor-specific logfile
-----------------------------------------------------------------------------*/
void monitor::log_init()
{
#ifndef MVEE_BENCHMARK
    char filename[1024];
    sprintf(filename, LOCALLOGNAME, mvee::os_get_orig_working_dir().c_str(), monitorid);
    monitor_log = fopen64(filename, "w");
    if (!monitor_log)
        perror("Failed to open local logfile");
#endif
}

/*-----------------------------------------------------------------------------
    log_fini - closes the monitor-specific logfile
-----------------------------------------------------------------------------*/
void monitor::log_fini()
{
#ifndef MVEE_BENCHMARK
    if (monitor_log)
        fclose(monitor_log);
    monitor_log = NULL;
#endif
}

/*-----------------------------------------------------------------------------
  log_caller_info
-----------------------------------------------------------------------------*/
void monitor::log_caller_info
(
    int variantnum,
    int level,
    unsigned long address,
    int calculate_file_offsets,
    void (*logfunc)(const char*, ...)
)
{
    if (!logfunc)
        logfunc = mvee::logf;

    std::string caller_info = set_mmap_table->get_caller_info(variantnum, variants[variantnum].variantpid, address, calculate_file_offsets);
    logfunc("pid: %d - %03d: %s\n", variants[variantnum].variantpid, level, caller_info.c_str());
}

/*-----------------------------------------------------------------------------
    log_variant_backtrace -
-----------------------------------------------------------------------------*/
void monitor::log_variant_backtrace(int variantnum, int max_depth, int calculate_file_offsets, int is_segfault)
{
	interaction::mvee_wait_status status;
    int  i;
    void (*logfunc)(const char*, ...) = mvee::logf;
    bool should_suspend  = state != STATE_WAITING_RESUME;
    bool at_call_entry   = variants[variantnum].callnum != NO_CALL;
    bool call_returned   = variants[variantnum].callnum == NO_CALL;
    bool call_dispatched = variants[variantnum].call_dispatched;
    bool in_call         =
        (state == STATE_IN_MASTERCALL
         || state == STATE_IN_SYSCALL
         || state == STATE_IN_FORKCALL
         || (variants[variantnum].call_type == MVEE_CALL_TYPE_UNSYNCED && call_dispatched));
	bool in_sigsuspend   = in_call && (
#ifdef __NR_sigsuspend
		variants[variantnum].callnum == __NR_sigsuspend ||
#endif 
		variants[variantnum].callnum == __NR_rt_sigsuspend);

	set_mmap_table->grab_lock();

/*
	if (set_mmap_table->thread_group_shutting_down)
	{
		logfunc("This thread group is shutting down - not backtracing\n");
		set_mmap_table->release_lock();
		return;
	}
*/

#if defined(MVEE_BENCHMARK) && defined(MVEE_FORCE_ENABLE_BACKTRACING)
    logfunc = mvee::warnf;
#endif

    // we're in state normal but this variant has reached the entrance
    // of a call already and we haven't dispatched it yet
    // so the variant is definitely still blocked!
    if ((in_call && !call_dispatched)                      // from a call handler
        || (!in_call && at_call_entry && !call_dispatched) // from a get_call_type/log_args/precall handler
        || (in_call && call_returned)                      // from a postcall/log_return handler
        || (variants[variantnum].callnum == MVEE_RDTSC_FAKE_SYSCALL)
        || is_segfault                                     // from a signal-delivery-stop
		|| in_sigsuspend)
		should_suspend = false;

    logfunc("%s - ==================================\n", 
			call_get_variant_pidstr(variantnum).c_str());
    logfunc("%s - generating local backtrace for variant\n",
			call_get_variant_pidstr(variantnum).c_str());

    if (should_suspend)
    {
        logfunc("%s - > variant is currently running or in a syscall. Trying to suspend.\n",
				call_get_variant_pidstr(variantnum).c_str());
		
		if (!interaction::wait(variants[variantnum].variantpid, status, true, true, true))
		{
			logfunc("%s - > error while waiting for variant: %d (%s) - status: %s\n",
					call_get_variant_pidstr(variantnum).c_str(), 
					errno, getTextualErrno(errno),
					getTextualMVEEWaitStatus(status).c_str()
				);
			set_mmap_table->release_lock();
			return;
		}

        if (should_suspend && 
			status.reason == STOP_NOTSTOPPED)
        {
            if (interaction::is_suspended(variants[variantnum].variantpid))
            {
                logfunc("%s - > we were about to send SIGSTOP to this variant but it was already suspended!\n",
						call_get_variant_pidstr(variantnum).c_str());
                goto was_interrupted;
            }

            if (!interaction::suspend(variants[variantnum].variantpid, variants[variantnum].varianttgid))
            {
                logfunc("%s - > signal delivery failed... err = %d (%s)\n",
						call_get_variant_pidstr(variantnum).c_str(), errno, getTextualErrno(errno));
				set_mmap_table->release_lock();
                return;
            }

			if (interaction::wait(variants[variantnum].variantpid, status))
			{
				logfunc("%s - > variant stopped.\n",
						call_get_variant_pidstr(variantnum).c_str());
			}

			switch (status.reason)
			{
				case STOP_EXIT:
				{
					logfunc("%s - >>> Process exited. Status = %d\n",
							call_get_variant_pidstr(variantnum).c_str(), status.data);
					set_mmap_table->release_lock();
					return;
				}
				case STOP_KILLED:
				{
					logfunc("%s - >>> Process terminated by signal: %s\n",
							call_get_variant_pidstr(variantnum).c_str(), getTextualSig(status.data));
					if (WTERMSIG(status) != SIGSEGV)
					{
						set_mmap_table->release_lock();
						return;
					}
					break;
				}
				case STOP_SIGNAL:
				{
					logfunc("%s - >>> Process stopped by signal: %s\n",
							call_get_variant_pidstr(variantnum).c_str(), getTextualSig(status.data));
					break;
				}
				default:
				{
					warnf("%s - >>> Unexpected stop reason\n",
							call_get_variant_pidstr(variantnum).c_str());
					break;
				}
			}
        }
    }
    else
    {
was_interrupted:
        logfunc("%s - > variant is currently suspended\n", call_get_variant_pidstr(variantnum).c_str());

        mvee_syscall_logger logger;
        if (variants[variantnum].callnum > 0 && variants[variantnum].callnum <= MAX_CALLS)
        {
            logger = monitor::syscall_logger_table[variants[variantnum].callnum][MVEE_LOG_ARGS];
			(this->*logger)(variantnum);
        }
    }

    // read /proc/maps
//    unsigned long      stack_base = set_mmap_table->get_stack_base(variantnum);
    i = 1;

    // Stack walk
    unsigned long      prev_ip    = 0;
    mvee_dwarf_context context(variants[variantnum].variantpid);
    log_caller_info(variantnum, 0, IP_IN_REGS(context.regs), 0, logfunc);
    while (1)
    {
        if (set_mmap_table->dwarf_step(variantnum, variants[variantnum].variantpid, &context) != 1
/*            || (unsigned long)SP_IN_REGS(context.regs) > stack_base */
			|| (unsigned long)IP_IN_REGS(context.regs) == prev_ip)
        {
            logfunc(">>> end of stack\n");
            break;
        }

        log_caller_info(variantnum, i++, IP_IN_REGS(context.regs), 0, logfunc);
        prev_ip = IP_IN_REGS(context.regs);
    }

    log_registers(variantnum, logfunc);
	log_stack(variantnum);
	set_mmap_table->release_lock();
}

/*-----------------------------------------------------------------------------
    mvee_log_dump_queues -
-----------------------------------------------------------------------------*/
void monitor::log_dump_queues(shm_table* shm_table)
{
    unsigned int master_pos = 0, lowest;
    long*        buffer, *eip_buffer, *data;

//	MutexLock lock(&mvee::global_lock);

    if (atomic_buffer)
    {
        std::vector<unsigned long> pos(mvee::numvariants);
		std::fill(pos.begin(), pos.end(), 0);

        for (int i = 0; i < mvee::numvariants; ++i)
		{
            if (atomic_queue_pos[i] && !variants[i].variant_terminated)
			{
                if (!rw::read_primitive<unsigned long>(variants[i].variantpid, (void*) atomic_queue_pos[i], pos[i]))
				{
					warnf("%s - Couldn't read atomic buffer pos\n", call_get_variant_pidstr(i).c_str());
					return;
				}
			}
		}

        char                       logname[100];
        sprintf(logname, "%s/Logs/%s_%d.log", mvee::os_get_orig_working_dir().c_str(),
                getTextualBufferType(MVEE_LIBC_ATOMIC_BUFFER), monitorid);
        FILE*                      logfile = fopen(logname, "w");

        if (!logfile)
            return;

        debugf("dumping queue: %s\n", getTextualBufferType(MVEE_LIBC_ATOMIC_BUFFER));

//        warnf("dumping queue: %s - FILE: %s (%d - %s)\n",
//                    getTextualBufferType(MVEE_LIBC_ATOMIC_BUFFER), logname, logfile, getTextualErrno(errno));

        for (int i = 0; i < mvee::numvariants; ++i)
            fprintf(logfile, "VARIANT %d - POS: %05ld %s\n", i, pos[i],
					variants[i].variant_terminated ? "(terminated)" : " ");

        struct mvee_op_entry*      buffer  = (struct mvee_op_entry*)atomic_buffer->ptr;
        for (master_pos = 0; master_pos < SHARED_QUEUE_SLOTS; ++master_pos)
        {
            //warnf("dumping item %d\n", master_pos);
            fprintf(logfile, "%09d - idx: %05d - counter: %08ld",
                    master_pos, (unsigned short)(buffer[master_pos].counter_and_idx & 0xFFF),
                    buffer[master_pos].counter_and_idx >> 12);

            for (int i = 0; i < mvee::numvariants; ++i)
                if (master_pos == pos[i])
                    fprintf(logfile, " <= variant %d", i);
            fprintf(logfile, "\n");

            if (!buffer[master_pos].counter_and_idx)
                break;
        }

        for (int i = 0; i < mvee::numvariants; ++i)
        {
			if (variants[i].variant_terminated)
				continue;

            fprintf(logfile, "\n\n COUNTER DUMP FOR VARIANT: %d (PID: %d)\n",
                    i, variants[i].variantpid);

            struct mvee_counter* counters = (struct mvee_counter*)rw::read_data(variants[i].variantpid,
                                                                                    atomic_counters[i], MVEE_COUNTERS * sizeof(struct mvee_counter), 0);

            if (counters)
                for (int j = 0; j < MVEE_COUNTERS; ++j)
                    if (counters[j].counter)
                        fprintf(logfile, "\tCOUNTER: %05d - counter: %08ld\n", j, counters[j].counter);

            SAFEDELETEARRAY(counters);
        }

        fclose(logfile);
    }

    for (auto it : shm_table->table)
    {
        _shm_info* info = it.second.get();

        // check if we always need to dump or if it only needs to happen once
#ifndef MVEE_ALWAYS_DUMP_QUEUES
        if (!info->dumpcount) // i.e. if (first_dump)
        {
#endif
        buffer     = (long*)info->ptr;
        eip_buffer = (long*)info->eip_ptr;
        lowest     = 0xFFFFFFFF;
        info->dumpcount++;

        char logname[100];
        sprintf(logname, "%s/Logs/%s_%d_%d.log", mvee::os_get_orig_working_dir().c_str(),
                getTextualBufferType(it.first), info->id, info->dumpcount);
        FILE* logfile = fopen(logname, "w");

        if (!logfile)
            return;

        warnf("dumping queue: %s - FILE: %s (%d - %s)\n", getTextualBufferType(it.first), logname, logfile, getTextualErrno(errno));

        fprintf(logfile, "===============================================   \n");
        fprintf(logfile, "> Buffer Type             : %d (%s)               \n", it.first, getTextualBufferType(it.first));
        fprintf(logfile, "> Buffer Info                                     \n");
        fprintf(logfile, "> * SYSV IPC shm id       : %d                    \n", info->id);
        fprintf(logfile, "> * SYSV IPC shm size     : %d bytes              \n", info->sz);
        fprintf(logfile, "> * Has EIP Queue?        : %d                    \n", info->have_eip_segment);
        fprintf(logfile, "> * Buffer slot size      : %d                    \n", info->sz / ( SHARED_QUEUE_SLOTS));
        if (info->have_eip_segment)
        {
            fprintf(logfile, "> * EIP queue shm id      : %d                    \n", info->eip_id);
            fprintf(logfile, "> * EIP queue shm size    : %d bytes              \n", info->eip_sz);
            fprintf(logfile, "> * EIP queue stack depth : %d                    \n", info->eip_stack_depth);
        }
        fprintf(logfile, "> Variant Info                                      \n");

        // try to determine the last non-empty slot in this buffer
        for (int j = 0; j < mvee::numvariants; ++j)
        {
            unsigned int tmppos = *(unsigned int*)(ROUND_UP((unsigned long)info->ptr, 64) + j * 64 + sizeof(int));
            if (j == 0)
                master_pos = tmppos;
            fprintf(logfile, "> * Variant %d                                      \n", j);
            fprintf(logfile, ">   + pid               : %d                    \n",   variants[j].variantpid);
			fprintf(logfile, ">   + pos               : %d                    \n", tmppos);

            if (it.first == MVEE_LIBC_LOCK_BUFFER_PARTIAL)
            {
                unsigned int tmpflush = *(unsigned int*)(ROUND_UP((unsigned long)info->ptr, 64) + j * 64 + sizeof(int) * 2);
                fprintf(logfile, ">   + current position  : %d                    \n", tmppos);
                fprintf(logfile, ">   + current flushcnt  : %d                    \n", tmpflush);
            }
            if (tmppos < lowest)
                lowest = tmppos;
        }
        fprintf(logfile, "===============================================   \n");

        for (unsigned int j = 0; j <= master_pos; ++j)
        {
            char tempstr[4096];

            if (it.first == MVEE_LIBC_LOCK_BUFFER_PARTIAL)
            {
                // queue layout:
                // +------------+------------+...+------------+------------+...
                // | spinlock   | pos 0      |   | pos N      | data 0     |
                // +------------+------------+...+------------+------------+...
                unsigned long               word_ptr;
                unsigned short              tid;
                unsigned short              op_type = ___UNKNOWN_LOCK_TYPE___;
                std::vector<unsigned short> tags(mvee::numvariants -1);

                data     = (long*)((unsigned long)buffer + mvee::numvariants * 64);

                word_ptr = *(unsigned long* )((unsigned long)data + j * info->actual_slot_size);
                tid      = *(unsigned short*)((unsigned long)data + j * info->actual_slot_size + sizeof(unsigned long));

                //
                // data slot layout for normal queue:
                // +----------------+-----------------+----------------+----------------+...+----------------+----------------+
                // |    word ptr    | master threadid |   slave 1 tag  |   slave 2 tag  |   |   slave N tag  |     PADDING    |
                // +----------------+-----------------+----------------+----------------+...+----------------+----------------+
                //  <-sizeof(long)-> <-sizeof(short)-> <-sizeof(char)-> <-sizeof(char)->     <-sizeof(char)->
                //
                // PADDING pads to a sizeof(long) boundary
                // word ptr          = word affected by the operation
                // master thread id  = master thread that performed the operation
                // slave X tag       = has slave X replicated this order yet?
                //
                if (info->requested_slot_size == sizeof(long) + sizeof(short) + (mvee::numvariants - 1) * sizeof(char))
                {
                    // normal queue
                    for (int i = 0; i < mvee::numvariants - 1; ++i)
                        tags[i] = *(unsigned char*)((unsigned long)data + j * info->actual_slot_size + sizeof(unsigned long) + sizeof(unsigned short) + i);
                }
                //
                // data slot layout for extended queue:
                // +----------------+-----------------+-----------------+-----------------+-----------------+...+-----------------+----------------+
                // |    word ptr    | master threadid | op type         |   slave 1 tag   |   slave 2 tag   |   |   slave N tag   |     PADDING    |
                // +----------------+-----------------+-----------------+-----------------+-----------------+...+-----------------+----------------+
                //  <-sizeof(long)-> <-sizeof(short)-> <-sizeof(short)-> <-sizeof(short)-> <-sizeof(short)->     <-sizeof(short)->
                //
                // PADDING pads to a sizeof(long) boundary
                // word ptr          = word affected by the operation
                // master thread id  = master thread that performed the operation
                // op type           = type of operation (cfr. enum mvee_call_types in Inc/MVEE_private.h)
                // slave X tag       = logical order in which the slave has replicated this operation
                //    !!! THIS IS ONLY USEFUL TO COMPARE THE ORDER IN WHICH OPERATIONS ON THE SAME WORD HAVE BEEN REPLICATED !!!
                //
                else
                {
                    // extended queue
                    op_type = *(unsigned short*)((unsigned long)data + j * info->actual_slot_size + sizeof(unsigned long) + sizeof(unsigned short));
                    for (int i = 0; i < mvee::numvariants - 1; ++i)
                        tags[i] = *(unsigned short*)((unsigned long)data + j * info->actual_slot_size + sizeof(unsigned long) + sizeof(unsigned short) * (2 + i));
                }

                sprintf(tempstr, "> BUFFER[%05d]: word_ptr(0x" LONGPTRSTR ") - tid(%05d) - op_type(%-40s) - tags(",
                        j, word_ptr, tid, getTextualAtomicType(op_type));
                for (int i = 0; i < mvee::numvariants - 1; ++i)
                {
                    char tag[20];
                    sprintf(tag, "%05d", tags[i]);
                    if (i)
                        strcat(tempstr, "    ");
                    strcat(tempstr, tag);
                }
                strcat(tempstr, ")");
            }
            else if (it.first == MVEE_LIBC_LOCK_BUFFER)
            {
                data = (long*)((unsigned long)buffer + mvee::numvariants * 64);
                unsigned short tid =  *(unsigned short*)((unsigned long)data + j * info->actual_slot_size);

                if (info->requested_slot_size == 3 * sizeof(long))
                {
                    // extended queue
                    unsigned long word_ptr = *(unsigned long* )((unsigned long)data + j * info->actual_slot_size + sizeof(unsigned long));
                    short         op_type  = *(unsigned short*)((unsigned long)data + j * info->actual_slot_size + sizeof(short));
                    sprintf(tempstr, "> BUFFER[%05d]: word_ptr(0x" LONGPTRSTR ") - tid(%05d) - op_type(%-40s)",
                            j, word_ptr, tid, getTextualAtomicType(op_type));
                }
                else
                {
                    // normal queue
                    sprintf(tempstr, "> BUFFER[%05d]: tid(%05d)", j, tid);
                }
            }
            else if (it.first == MVEE_LIBC_MALLOC_DEBUG_BUFFER)
            {
//                int   slot_size       = 4*sizeof(int) + 3*sizeof(long);
                int   slot_size       = info->actual_slot_size;
                data = (long*)((unsigned long)buffer + mvee::numvariants * 64);

                int   tid             = *(int*)((unsigned long)data + j * slot_size);
                int   alloc_type      = *(int*)((unsigned long)data + j * slot_size + 2 * sizeof(int));
                int   alloc_msg       = *(int*)((unsigned long)data + j * slot_size + 3 * sizeof(int));
                long  alloc_chunksize = *(long*)((unsigned long)data + j * slot_size + 4 * sizeof(int));
                void* alloc_ar_ptr    = (void*)*(unsigned long*)((unsigned long)data + j * slot_size + 4 * sizeof(int) + sizeof(long));
                void* alloc_chunk_ptr = (void*)*(unsigned long*)((unsigned long)data + j * slot_size + 4 * sizeof(int) + 2 * sizeof(long));

                sprintf(tempstr, "> BUFFER[%05d]: tid(%05d) - alloc_type(%s) - alloc_msg(%d = %s) - alloc_size(%ld) - alloc_ar_ptr(0x" LONGPTRSTR ") - alloc_chunk_ptr(0x" LONGPTRSTR ")\n",
                        j, tid,
                        getTextualAllocType(alloc_type),
                        alloc_msg,
                        getTextualAllocResult(alloc_type, alloc_msg),
                        alloc_chunksize,
                        (unsigned long)alloc_ar_ptr,
                        (unsigned long)alloc_chunk_ptr);

            }

            if (lowest == j)
                strcat(tempstr, " <======");
            fprintf(logfile, "%s\n", tempstr);

            if (eip_buffer)
            {
                for (int x = 0; x < mvee::numvariants; ++x)
                {
                    for (unsigned char z = 0; z < info->eip_stack_depth; ++z)
                    {
                        std::string call_site = set_mmap_table->get_caller_info(x, variants[x].variantpid,
                                                                                eip_buffer[info->eip_stack_depth * (j * mvee::numvariants + x) + z], 0);
                        fprintf(logfile, ">>> %d:%d > %s\n", x, z, call_site.c_str());
                    }
                }
            }
        }
		
		warnf("Queue dump finished\n");
		
		if (logfile)
			fclose(logfile);

#ifndef MVEE_ALWAYS_DUMP_QUEUES
    }
    else
    {
        char logname[100];
        sprintf(logname, "%s/Logs/%s_%d.log", mvee::os_get_orig_working_dir().c_str(),
                getTextualBufferType(it.first), info->id);
        debugf("queue dumped to: %s\n", logname);
    }
#endif
    }
}

/*-----------------------------------------------------------------------------
    log_calculate_clock_spread
-----------------------------------------------------------------------------*/
void monitor::log_calculate_clock_spread()
{
	if (!atomic_counters[0] || variants[0].variant_terminated)
		return;

	int lowest_clock_used  = 0;
	int highest_clock_used = 0;
	double mean            = 0.0;
	double variance        = 0.0;

	std::vector<double> cntrs(MVEE_COUNTERS);

	struct mvee_counter* counters = (struct mvee_counter*)rw::read_data(variants[0].variantpid,
		atomic_counters[0], MVEE_COUNTERS * sizeof(struct mvee_counter), 0);

	for (int j = 0; j < MVEE_COUNTERS; ++j)
	{
		cntrs[j] = static_cast<double>(counters[j].counter);		
		if (counters[j].counter)
		{
			if (!lowest_clock_used)
				lowest_clock_used = j;
			highest_clock_used = j;
		}
	}

	cntrs.erase(std::remove(cntrs.begin(), cntrs.end(), 0.0), cntrs.end());
	mean = std::accumulate(cntrs.begin(), cntrs.end(), 0.0) / cntrs.size();
	std::vector<double> diff(cntrs.size());
	std::transform(cntrs.begin(), cntrs.end(), diff.begin(), 
				   std::bind2nd(std::minus<double>(), mean));
	variance = std::inner_product(diff.begin(), diff.end(), 
						   diff.begin(), 0.0) / (cntrs.size() - 1);

	SAFEDELETEARRAY(counters);

	warnf("Clock stats - clocks used: %d - range: [%d, %d] - mean: %le - variance: %le\n",
				cntrs.size(), lowest_clock_used, highest_clock_used, mean, variance);
}

/*-----------------------------------------------------------------------------
    log_monitor_state_short
-----------------------------------------------------------------------------*/
void monitor::log_monitor_state_short(int err)
{
    warnf("prevcall : %ld (%s)\n", variants[0].prevcallnum, getTextualSyscall(variants[0].prevcallnum));
    warnf("state    : %d (%s)\n",  state,                 getTextualState(state));
    warnf("errno    : %d (%s)\n",  err,                   getTextualErrno(err));
}

/*-----------------------------------------------------------------------------
    log_unhandled_sig
-----------------------------------------------------------------------------*/
void monitor::log_unhandled_sig(int status, int index)
{
    warnf("==================================\n");
    warnf("ERROR: Unhandled signal\n");
    warnf("pid      : %d\n",          variants[index].variantpid);
    warnf("status   : 0x%08X\n",      status);
    warnf("signal   : 0x%08X (%s)\n", WSTOPSIG(status),      getTextualSig(WSTOPSIG(status)));
    warnf("call     : %ld (%s)\n",    variants[index].callnum, getTextualSyscall(variants[index].callnum));
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
    log_monitor_state_short(0);
    log_variant_backtrace(index);
#endif
    warnf("==================================\n");
}

/*-----------------------------------------------------------------------------
    log_call_mismatch - Logs a syscall number mismatch.
-----------------------------------------------------------------------------*/
void monitor::log_call_mismatch(int index1, int index2)
{
    if (set_mmap_table->thread_group_shutting_down)
        return;

    warnf("==================================\n");
    warnf("ERROR: Callnumber mismatch\n");
    warnf("pid1     : %d\n",       variants[index1].variantpid);
    warnf("call1    : %ld (%s)\n", variants[index1].callnum, getTextualSyscall(variants[index1].callnum));
    warnf("type1    : %d\n",       variants[index1].call_type);
    warnf("pid2     : %d\n",       variants[index2].variantpid);
    warnf("call2    : %ld (%s)\n", variants[index2].callnum, getTextualSyscall(variants[index2].callnum));
    warnf("type2    : %d\n",       variants[index2].call_type);
    warnf("==================================\n");
    mvee_syscall_logger logger;
    if (variants[index1].callnum > 0 && variants[index1].callnum <= MAX_CALLS)
    {
        logger = monitor::syscall_logger_table[variants[index1].callnum][MVEE_LOG_ARGS];
		(this->*logger)(index1);
    }
    if (variants[index2].callnum > 0 && variants[index2].callnum <= MAX_CALLS)
    {
        logger = monitor::syscall_logger_table[variants[index2].callnum][MVEE_LOG_ARGS];
		(this->*logger)(index2);
    }
    log_monitor_state_short(0);
    warnf("==================================\n");
}

/*-----------------------------------------------------------------------------
    log_callargs_mismatch - Logs a syscall argument mismatch.
-----------------------------------------------------------------------------*/
void monitor::log_callargs_mismatch()
{
    if (set_mmap_table->thread_group_shutting_down)
        return;

    warnf("==================================\n");
    warnf("ERROR: Call arguments mismatch\n");
    warnf("call     : %ld (%s)\n",
                variants[0].callnum, getTextualSyscall(variants[0].callnum));
    for (int i = 0; i < mvee::numvariants; ++i)
        warnf("variant %d  : %d\n", i, variants[i].variantpid);
    log_monitor_state_short(0);
    warnf("==================================\n");
}

/*-----------------------------------------------------------------------------
    log_stack
-----------------------------------------------------------------------------*/
void monitor::log_stack(int variantnum)
{
#ifndef MVEE_BENCHMARK
	call_check_regs(variantnum);
	for (int i = -10; i < 10; ++i)
	{
		unsigned long stack_word;
		
		if (!rw::read_primitive<unsigned long>(variants[variantnum].variantpid, 
											   (void*) (SP_IN_REGS(variants[variantnum].regs) + i * sizeof(unsigned long)), 
											   stack_word))
			return;

		debugf("stack[rsp + %d] = " PTRSTR "\n", i*sizeof(unsigned long), stack_word);
	}
#endif
}

/*-----------------------------------------------------------------------------
    log_segfault - Logs segfault (SIGSEGV) info.
-----------------------------------------------------------------------------*/
void monitor::log_segfault(int variantnum)
{
	siginfo_t siginfo;
	unsigned long eip = 0;
	
	if (!interaction::get_signal_info(variants[variantnum].variantpid, &siginfo))
	{
		warnf("%s - Couldn't get signal info\n", 
			  call_get_variant_pidstr(variantnum).c_str());
		return;
	}
	
	if (!interaction::fetch_ip(variants[variantnum].variantpid, eip))
	{
		warnf("%s - Couldn't read instruction pointer\n", 
			  call_get_variant_pidstr(variantnum).c_str());
	}
	
#ifdef MVEE_SUPPORTS_IPMON
	if (ipmon_initialized && siginfo.si_addr == 0)
	{
		std::string crash_loc = set_mmap_table->get_caller_info(variantnum,
																variants[variantnum].variantpid,
																eip,
																0);

		// IP-MON crash dumps 
		if (crash_loc.find("ipmon_arg_verify_failed") != std::string::npos)
		{
			warnf("IP-MON verification failed in variant %d (PID: %d)\n", variantnum, variants[variantnum].variantpid);

			// force register refresh
			variants[variantnum].regs_valid  = false;
			call_check_regs(variantnum);

			unsigned long master_syscall_no = variants[variantnum].regs.rax;
			unsigned char arg_no            = master_syscall_no & 0xff;
			unsigned long slave_arg_val     = variants[variantnum].regs.rbx;
			ipmon_syscall_entry* entry      = nullptr;			
			struct ipmon_buffer* buffer     = nullptr;
			master_syscall_no >>= 8;

			// Get the relevant IP-MON entry
			if (ipmon_buffer)
			{
				buffer = (struct ipmon_buffer*) ipmon_buffer->ptr;

				// find the last valid entry before pos
				unsigned int offset = 0;
				unsigned int data_start = 64 * (1 + mvee::numvariants);

				while (offset <= buffer->ipmon_variant_info[variantnum].pos)
				{
					entry = (struct ipmon_syscall_entry*)((unsigned long)buffer + data_start + offset);
					if (offset + sizeof(struct ipmon_syscall_entry) > (unsigned int)buffer->ipmon_usable_size)
						break;
					if (entry->syscall_entry_size <= 0)
						break;
					offset += entry->syscall_entry_size;
				}				
			}
			
			if (arg_no == 0)
			{
				warnf("> Syscall Number Mismatch (Master: %d - %s, Slave: %d - %s)\n",
					  master_syscall_no, getTextualSyscall(master_syscall_no),
					  slave_arg_val, getTextualSyscall(slave_arg_val));
			}
			else if (master_syscall_no == (unsigned long)-1)
			{
				warnf("> Unknown cause - check log files\n");
			}
			else if ((char)arg_no < 0)
			{
				warnf("> Argument Length Mismatch (Syscall: %d - %s - Arg: %d - Slave Length: %d)\n",
					  master_syscall_no, getTextualSyscall(master_syscall_no),
					  -arg_no-1, slave_arg_val);

				if (entry)
				{
					warnf("========BUFFER ENTRY DUMP=======================================================\n");
					log_ipmon_entry(buffer, entry, warnf);
					warnf("================================================================================\n");
				}
			}
			else
			{
				warnf("> Argument Value Mismatch (Syscall: %d - %s - Arg: %d)\n",
					  master_syscall_no, getTextualSyscall(master_syscall_no), arg_no-1);

				// dump slave contents
				// we need to fetch the relevant entry to get the size of the data block
				if (entry)
				{
					struct ipmon_syscall_data* arg = get_ipmon_arg(entry, arg_no - 1);
				
					if (arg)
					{
						// try to read the slave block from mem
						unsigned char* slave_arg = rw::read_data(variants[variantnum].variantpid,
																	 (void*)slave_arg_val,
																	 arg->len - sizeof(unsigned long),
																	 0);
																 
						if (slave_arg)
						{
							std::string hex = mvee::log_do_hex_dump (slave_arg, arg->len - sizeof(unsigned long));
							warnf("\tSlave Value       :\n%s", hex.c_str());
							delete[] slave_arg;
						}
						else
						{
							warnf("> Couldn't read slave value\n");
						}
					}
					else
					{
						warnf("> Couldn't read argument from IP-MON buffer\n");
					}

					warnf("========BUFFER ENTRY DUMP=======================================================\n");
					log_ipmon_entry(buffer, entry, warnf);
					warnf("================================================================================\n");
				}
			}

			shutdown(false);
			return;
		}
	}
#endif


    warnf("Warning: %s in variant %d (PID: %d)\n",
                getTextualSig(siginfo.si_signo), variantnum,
                variants[variantnum].variantpid);
    warnf("IP: " PTRSTR ", Address: " PTRSTR ", Code: %s (%d), Errno: %d\n",
                eip, siginfo.si_addr, getTextualSEGVCode(siginfo.si_code),
                siginfo.si_code, siginfo.si_errno);
//    log_registers(variantnum, mvee::logf);
//    set_mmap_table->print_mmap_table(mvee::logf);
#if !defined(MVEE_ENABLE_VALGRIND_HACKS) && (!defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING))
    log_variant_backtrace(variantnum, 0, 1, 1);
#endif

	log_ipmon_state();
//	log_stack(variantnum);
	set_mmap_table->print_mmap_table();
}

/*-----------------------------------------------------------------------------
    log_hw_bp_event -
-----------------------------------------------------------------------------*/
void monitor::log_hw_bp_event (int variantnum, siginfo_t* sig)
{
    int i;
    unsigned long dr6;

    debugf("Hardware Breakpoint hit by variant: %d\n", variants[variantnum].variantpid);

    if (!interaction::read_specific_reg(variants[variantnum].variantpid,
										offsetof(user, u_debugreg) + 6*sizeof(long), dr6))
	{
		warnf("%s - Coulnd't read dr6\n", call_get_variant_pidstr(variantnum).c_str());
		return;
	}

    for (i = 0; i < 4; ++i)
    {
        if (dr6 & (1 << i))
        {
			unsigned long ptr;
			if (!rw::read_primitive<unsigned long>(variants[variantnum].variantpid, (void*) variants[variantnum].hw_bps[i], ptr))
			{
				warnf("%s - Coulnd't read value at address 0x" PTRSTR " - This address was set in HW BP register %d\n", 
					  call_get_variant_pidstr(variantnum).c_str(), variants[variantnum].hw_bps[i], i);
			}
			else
			{
				debugf("> this BP at address " PTRSTR " is registered in slot %d and has type %s\n",
					   variants[variantnum].hw_bps[i], i,
					   getTextualBreakpointType(variants[variantnum].hw_bps_type[i]));
				debugf("> current value -> " LONGRESULTSTR " \n", ptr);
			}
            break;
        }
    }

    if (i >= 4)
        warnf("> couldn't find the BP in the BP list...\n");

#ifndef MVEE_BENCHMARK
    log_variant_backtrace(variantnum, 0, 1, 1);
#endif
}

/*-----------------------------------------------------------------------------
    clear_log_folder - called during startup
-----------------------------------------------------------------------------*/
void mvee::clear_log_folder()
{
    char cmd[1024];

    // create the folder if needed
    sprintf(cmd, "mkdir -p %s", LOGDIR);
    if (system(cmd) < 0)
        printf("Couldn't create MVEE log folder: %s\n", LOGDIR);

    // delete any existing logfiles
    sprintf(cmd, "rm -f %s*.log 2>&1", LOGDIR);
    if (system(cmd) < 0)
        printf("Couldn't clear MVEE log folder: %s\n", LOGDIR);
}

/*-----------------------------------------------------------------------------
    log_init - opens the global monitor log
-----------------------------------------------------------------------------*/
void mvee::log_init()
{
#ifndef MVEE_BENCHMARK
    mvee::clear_log_folder();
    printf("Opening MVEE Monitor Log @ %s\n", LOGNAME);
    mvee::logfile              = fopen64(LOGNAME, "w");
    if (mvee::logfile == NULL)
        perror("Failed to open monitor log");
#endif

    struct timeval tv;
    gettimeofday(&tv, NULL);
    mvee::startup_time          = tv.tv_sec + tv.tv_usec / 1000000.0;

#ifdef MVEE_GENERATE_EXTRA_STATS
    printf("Opening PTRACE Log @ %s\n", PTRACE_LOGNAME);
    mvee::ptrace_logfile       = fopen(PTRACE_LOGNAME, "w");
    if (mvee::ptrace_logfile == NULL)
        perror("Failed to open ptrace log");

    printf("Opening DATATRANSFER Log @ %s\n", DATATRANSFER_LOGNAME);
    mvee::datatransfer_logfile = fopen(DATATRANSFER_LOGNAME, "w");
    if (mvee::datatransfer_logfile == NULL)
        perror("Failed to open datatransfer log");
#endif

#ifdef MVEE_GENERATE_LOCKSTATS
    printf("Opening LOCKSTATS Log @ %s\n", LOCKSTATS_LOGNAME);
    mvee::lockstats_logfile    = fopen(LOCKSTATS_LOGNAME, "w");
    if (mvee::lockstats_logfile == NULL)
        perror("Failed to open lockstats log");
#endif
}

/*-----------------------------------------------------------------------------
    log_fini
-----------------------------------------------------------------------------*/
void mvee::log_fini(bool terminated)
{
    if (terminated)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        double currenttime = tv.tv_sec + tv.tv_usec / 1000000.0;

#ifndef MVEE_BENCHMARK
        printf("Program terminated after: %lf seconds\n", currenttime - mvee::startup_time);
#else
        fprintf(stderr, "%lf\n", currenttime - mvee::startup_time);
#endif
    }

#ifndef MVEE_BENCHMARK
    sync();
    if (mvee::logfile)
        fclose(mvee::logfile);
#endif

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (mvee::ptrace_logfile)
        fclose(mvee::ptrace_logfile);
    if (mvee::datatransfer_logfile)
        fclose(mvee::datatransfer_logfile);
#endif

#ifdef MVEE_GENERATE_LOCKSTATS
    if (mvee::lockstats_logfile)
        fclose(mvee::lockstats_logfile);
#endif
}

/*-----------------------------------------------------------------------------
    warnf - print a warning. Will always log to stdout as well
-----------------------------------------------------------------------------*/
void mvee::warnf(const char* format, ...)
{
#ifdef MVEE_FILTER_LOGGING
    if (!mvee::active_monitor
        || !mvee::active_monitor->is_logging_enabled())
        return;
#endif

    MutexLock lock(&mvee::loglock);
    va_list va;
    va_start(va, format);
    printf("MONITOR[%d] - WARNING: ", mvee::active_monitorid);
    vfprintf(stdout, format, va);
    va_end(va);

#ifndef MVEE_BENCHMARK
    struct timeval tv;
    double curtime;
    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec + tv.tv_usec / 1000000.0 - mvee::startup_time;
    if (mvee::active_monitor && mvee::active_monitor->monitor_log)
    {
        va_list va;
        va_start(va, format);
        fprintf(mvee::active_monitor->monitor_log, "%f - MONITOR[%d] - WARNING: ", curtime, mvee::active_monitorid);
        vfprintf(mvee::active_monitor->monitor_log, format, va);
        va_end(va);
    }
    if (mvee::logfile)
    {
        va_list va;
        va_start(va, format);
        fprintf(mvee::logfile, "%f - MONITOR[%d] - WARNING: ", curtime, mvee::active_monitorid);
        vfprintf(mvee::logfile, format, va);
        va_end(va);
    }
#endif
    va_end(va);
}

//
// Logging functions
//

/*-----------------------------------------------------------------------------
  log_ptrace_op -
-----------------------------------------------------------------------------*/

#ifdef MVEE_GENERATE_EXTRA_STATS
void mvee::log_ptrace_op(int op_type, int op_subtype, int bytes)
{
#ifdef MVEE_FILTER_LOGGING
    if (!mvee::active_monitor
        || !mvee::active_monitor->is_logging_enabled())
        return;
#endif

    // ptrace operation
    if (op_type == 0)
    {
        if (mvee::ptrace_logfile)
            fprintf(mvee::ptrace_logfile, "%d;%s\n", op_subtype, getTextualRequest(op_subtype));
    }
    // datatransfer operation
    else
    {
        if (mvee::datatransfer_logfile)
            fprintf(mvee::datatransfer_logfile, "%s %d\n", getTextualRequest(op_subtype), bytes);
    }
}
#endif

/*-----------------------------------------------------------------------------
    logf - print formatted text into the logfile
-----------------------------------------------------------------------------*/
void mvee::logf(const char* format, ...)
{
#ifndef MVEE_BENCHMARK
    struct timeval tv;
    double curtime;

#ifdef MVEE_FILTER_LOGGING
    if (!mvee::active_monitor
        || !mvee::active_monitor->is_logging_enabled())
        return;
#endif

    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec + tv.tv_usec / 1000000.0 - mvee::startup_time;

    if (mvee::active_monitor && mvee::active_monitor->monitor_log)
    {
        va_list va;
        va_start(va, format);
        fprintf(mvee::active_monitor->monitor_log, "%f - MONITOR[%d] - ", curtime, mvee::active_monitorid);
        vfprintf(mvee::active_monitor->monitor_log, format, va);
        va_end(va);
    }

    MutexLock lock(&mvee::loglock);
    if ((*mvee::config_monitor)["log_to_stdout"].asBool())
    {
        va_list va;
        va_start(va, format);
        printf("MONITOR[%d] - ", mvee::active_monitorid);
        vfprintf(stdout, format, va);
        va_end(va);
    }
    if (mvee::logfile)
    {
        va_list va;
        va_start(va, format);
        fprintf(mvee::logfile, "%f - MONITOR[%d] - ", curtime, mvee::active_monitorid);
        vfprintf(mvee::logfile, format, va);
        va_end(va);
    }
#endif
#if defined(MVEE_BENCHMARK) && defined(MVEE_FORCE_ENABLE_BACKTRACING)
    if ((*mvee::config_monitor)["log_to_stdout"].asBool())
    {
        va_list va;
        va_start(va, format);
        printf("MONITOR[%d] - ", mvee::active_monitorid);
        vfprintf(stdout, format, va);
        va_end(va);
    }
#endif
}

/*-----------------------------------------------------------------------------
    log_read_from_proc_pipe
-----------------------------------------------------------------------------*/
std::string mvee::log_read_from_proc_pipe(const char* proc, size_t* output_length)
{
    int read;
    char tmp_buf[1025];
    std::stringstream ss;
    FILE* fp = popen(proc, "r");

    if (!fp || feof(fp))
    {
        warnf("ERROR: couldn't create procpipe: %s\n", proc);
        if (output_length)
            *output_length = 0;
        return "";
    }

    while (!feof(fp))
    {
        read = fread(tmp_buf, 1, 1024, fp);
        if (read > 0)
        {
            tmp_buf[read] = '\0';
            ss << tmp_buf;
        }
    }

    pclose(fp);
    if (output_length)
        *output_length = ss.str().length();
    return ss.str();
}

/*-----------------------------------------------------------------------------
    log_dump_locking_stats - called when a shared segment is detached
    (i.e. it has no more variants referencing it)
-----------------------------------------------------------------------------*/
void mvee::log_dump_locking_stats(monitor* mon, mmap_table* mmap_table, shm_table* shm_table)
{
    if (!mon->is_logging_enabled())
        return;

#ifdef MVEE_GENERATE_LOCKSTATS
    MutexLock lock(&mvee::loglock);
    if (!mvee::lockstats_logfile)
        return;
    fprintf(mvee::lockstats_logfile, "================================================================================\n");
    {
        mmap_table->grab_lock();
        fprintf(mvee::lockstats_logfile, "Stats for process:\n    > PROC: %s\n    > ARGS: %s\n",
				mmap_table->mmap_startup_info[0].image.c_str(),
                mmap_table->mmap_startup_info[0].serialized_argv.c_str());
        fprintf(mvee::lockstats_logfile, "Process was created by monitor: %d\n",
                mmap_table->mmap_execve_id);
        fprintf(mvee::lockstats_logfile, "Stats were dumped by monitor: %d\n",
                mon->monitorid);
        shm_table->release_lock();
    }

    fprintf(lockstats_logfile, "================================================================================\n\n");

    // This is deprecated. Need to fix sometime!
#ifdef MVEE_CHECK_SYNC_PRIMITIVES
    if (mon->variants[0].sync_primitives_ptr)
    {
        fprintf(mvee::lockstats_logfile, "HIGH-LEVEL SYNC PRIMITIVES IN THIS PROGRAM:\n");

#define CHECK_PRIMITIVE(a) \
    fprintf(mvee::lockstats_logfile, "%s : %s\n", #a, (mon->variants[0].sync_primitives_bitmask & (1 << a)) ? "YES" : "NO");

        CHECK_PRIMITIVE(PTHREAD_BARRIER);
        CHECK_PRIMITIVE(PTHREAD_COND);
        CHECK_PRIMITIVE(PTHREAD_COND_TIMED);
        CHECK_PRIMITIVE(PTHREAD_MUTEX);
        CHECK_PRIMITIVE(PTHREAD_MUTEX_TIMED);
        CHECK_PRIMITIVE(PTHREAD_RWLOCK);
        CHECK_PRIMITIVE(PTHREAD_RWLOCK_TIMED);
        CHECK_PRIMITIVE(PTHREAD_SPIN);
        CHECK_PRIMITIVE(PTHREAD_SEM);
        CHECK_PRIMITIVE(LIBC_BARRIER);
        CHECK_PRIMITIVE(LIBC_LOCK);
        CHECK_PRIMITIVE(LIBC_ATOMIC);
        CHECK_PRIMITIVE(CUSTOM_SYNC_LIBRARY);

        fprintf(mvee::lockstats_logfile, "================================================================================\n\n");
    }
#endif

    fprintf(mvee::lockstats_logfile, "Total number of operations: %llu\n",             shm_table->op_cnt_total);
    fprintf(mvee::lockstats_logfile, "Total number of individual atomic words: %lu\n", shm_table->op_cnt_per_word.size());
    fprintf(mvee::lockstats_logfile, "Bounce count: %llu\n",                           shm_table->bounce_cnt);
    fprintf(mvee::lockstats_logfile, "Bounce density: %Lf\n",                          (long double)shm_table->bounce_cnt / (long double)shm_table->op_cnt_total);
    fprintf(mvee::lockstats_logfile, "================================================================================\n");

    fprintf(mvee::lockstats_logfile, "Per type counters:\n");

    for (std::map<unsigned short, unsigned long long>::iterator it =
             shm_table->op_cnt_per_type.begin();
         it != shm_table->op_cnt_per_type.end();
         it++)
    {
        fprintf(mvee::lockstats_logfile, "%40s : %llu\n", getTextualAtomicType(it->first), it->second);
    }

    fprintf(mvee::lockstats_logfile, "================================================================================\n");

    fprintf(mvee::lockstats_logfile, "Per thread counters:\n\n");

    for (std::map<unsigned short, unsigned long long>::iterator it =
             shm_table->op_cnt_per_thread.begin();
         it != shm_table->op_cnt_per_thread.end();
         it++)
    {
        fprintf(mvee::lockstats_logfile, "PID %05d : %llu\n", it->first, it->second);
    }

    fprintf(mvee::lockstats_logfile, "================================================================================\n");

    fprintf(mvee::lockstats_logfile, "Per word counters:\n\n");

    for (std::map<unsigned long, unsigned long long>::iterator it =
             shm_table->op_cnt_per_word.begin();
         it != shm_table->op_cnt_per_word.end();
         it++)
    {
        fprintf(mvee::lockstats_logfile, "0x" LONGPTRSTR " : %llu\n", it->first, it->second);
    }

    fprintf(mvee::lockstats_logfile, "================================================================================\n");

#endif
}

/*-----------------------------------------------------------------------------
    log_do_hex_dump
-----------------------------------------------------------------------------*/
std::string mvee::log_do_hex_dump (const void* hexbuffer, int buffer_size)
{
    std::stringstream out;
    std::string chars;
    size_t line_len         = strlen("    xxxxxxxx    xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx    ................") + strlen("\n");
    size_t partial_line_len = strlen("    xxxxxxxx    xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx    ");

    for (int i = 0; i < buffer_size; ++i)
    {
        char c = *(char*)((unsigned long)hexbuffer + i);

        // new line
        if (i % 16 == 0)
            out << "    " << STDHEXSTR(8, i) << "    ";

        out << STDHEXSTR(2, ((unsigned char)c));
        chars += (c > 32) ? c : '.';

        // end of group
        if (i % 4 == 3)
            out << " ";

        // end of line
        if (i % 16 == 15)
        {
            out << std::setw(partial_line_len - (out.str().length() % line_len)) << " " << std::setw(0);
            out << chars << "\n";
            chars = "";
        }
    }

    if (chars != "")
    {
        out << std::setw(partial_line_len - (out.str().length() % line_len)) << " " << std::setw(0);
        out << chars << "\n";
        chars = "";
    }

    return out.str();
}

/*-----------------------------------------------------------------------------
    log_register
-----------------------------------------------------------------------------*/
void mvee::log_register(const char* register_name, unsigned long* register_ptr, void (*logfunc)(const char*, ...))
{
    logfunc("reg[%s] = 0x" PTRSTR "\n", register_name, *register_ptr);
}

/*-----------------------------------------------------------------------------
    log_dwarf_rule
-----------------------------------------------------------------------------*/
void mvee::log_dwarf_rule (unsigned int reg_num, void* _rule)
{
    Dwarf_Regtable_Entry3* rule = (Dwarf_Regtable_Entry3*)_rule;
    std::stringstream ss;

    ss << "reg: " << getTextualDWARFReg(reg_num) << " - value type: ";

    switch (rule->dw_value_type)
    {
        case DW_EXPR_EXPRESSION:        ss << "DW_EXPR_EXPRESSION";     break;
        case DW_EXPR_OFFSET:            ss << "DW_EXPR_OFFSET";         break;
        case DW_EXPR_VAL_EXPRESSION:    ss << "DW_EXPR_VAL_EXPRESSION"; break;
        case DW_EXPR_VAL_OFFSET:        ss << "DW_EXPR_VAL_OFFSET";     break;
    }

    ss << " - offset relevant: " << (int)rule->dw_offset_relevant;
    ss << " - reg num: " << rule->dw_regnum << " (";
    ss << getTextualDWARFReg(rule->dw_regnum) << ") - offset: " << STDHEXSTR(sizeof(unsigned long), rule->dw_offset_or_block_len);

    debugf("DWARF: > %s\n", ss.str().c_str());
}

/*-----------------------------------------------------------------------------
    mvee_log_print_sigaction
-----------------------------------------------------------------------------*/
void mvee::log_sigaction(struct sigaction* action)
{
#ifndef MVEE_BENCHMARK
    const char* handler = "SIG_PTR";

    if (action->sa_handler == SIG_IGN)
        handler = "SIG_IGN";
    else if (action->sa_handler == SIG_DFL)
        handler = "SIG_DFL";

    debugf("> SIGACTION sa_handler   : 0x" PTRSTR " (= %s)\n", action->sa_handler, handler);
    debugf("> SIGACTION sa_sigaction : 0x" PTRSTR "\n",        action->sa_sigaction);
    debugf("> SIGACTION sa_restorer  : 0x" PTRSTR "\n",        action->sa_restorer);
    debugf("> SIGACTION sa_flags     : 0x%08x (= %s)\n",       action->sa_flags,   getTextualSigactionFlags(action->sa_flags).c_str());
    debugf("> SIGACTION sa_mask      : %s\n",                  getTextualSigSet(action->sa_mask).c_str());
#endif
}

/*-----------------------------------------------------------------------------
  mvee_log_local_backtrace - log a monitor backtrace to stderr
-----------------------------------------------------------------------------*/
void mvee_log_local_backtrace() 
{
	void *trace[16];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, 16);
	messages = backtrace_symbols(trace, trace_size);
	warnf("Local Backtrace:\n");
	for (i=0; i<trace_size; ++i)
		warnf("[%d] %s\n", i, messages[i]);
	free(messages);
}
