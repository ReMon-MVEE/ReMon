/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

// *****************************************************************************
// This file implements the high-level syscall handling logic and implements
// syscall handlers for the "fake" syscalls we use in some of our
// synchronization agents (cfr. MVEE_fake_syscalls.h).
// *****************************************************************************

#include <memory>
#include <random>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <sstream>
#include <sys/mman.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_private_arch.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_syscalls.h"
#include "MVEE_memory.h"
#include "MVEE_macros.h"
#include "MVEE_mman.h"
#include "MVEE_logging.h"
#include "MVEE_shm.h"
#include "MVEE_filedesc.h"
#include "MVEE_signals.h"
#include "MVEE_interaction.h"
#include "MVEE_numcalls.h"
#define PMVEE_LEADER
#define PMVEE_COPY_STATE
#include "PMVEE.h"

/*-----------------------------------------------------------------------------
  handler and logger table
-----------------------------------------------------------------------------*/
#include "MVEE_syscall_handler_table.h"

/*-----------------------------------------------------------------------------
    call_is_known_false_positive
-----------------------------------------------------------------------------*/
unsigned char monitor::call_is_known_false_positive(long* precall_flags)
{
    set_mmap_table->grab_lock();
    char*         program_name = (set_mmap_table->mmap_startup_info[0].image.length() == 0) ? 
		NULL : mvee::strdup(set_mmap_table->mmap_startup_info[0].image.c_str());
    set_mmap_table->release_lock();

    long          callnum      = variants[0].callnum;
    unsigned char result       = handle_is_known_false_positive(program_name, callnum, precall_flags);

    SAFEDELETEARRAY(program_name);
    return result;
}

/*-----------------------------------------------------------------------------
    call_resume - 
-----------------------------------------------------------------------------*/
void monitor::call_resume(int variantnum)
{
	if (!interaction::resume_until_syscall(variants[variantnum].variantpid))
		throw ResumeFailure(variantnum, "syscall resume");
}

/*-----------------------------------------------------------------------------
    call_resume_all - Resumes all variants attached to the current monitor thread.
-----------------------------------------------------------------------------*/
void monitor::call_resume_all()
{
    for (int i = 0; i < mvee::numvariants; ++i)
		call_resume(i);
}

/*-----------------------------------------------------------------------------
    call_resume_fake_syscall - 
-----------------------------------------------------------------------------*/
void monitor::call_resume_fake_syscall(int variantnum)
{
	// let the variants execute a dummy getpid syscall instead
	if (!interaction::write_syscall_no(variants[variantnum].variantpid, __NR_getpid))
		throw RwRegsFailure(variantnum, "set fake syscall no");

	if (!interaction::resume_until_syscall(variants[variantnum].variantpid))
		throw ResumeFailure(variantnum, "fake syscall resume");
}

/*-----------------------------------------------------------------------------
    call_resume_fake_syscall_all - 
-----------------------------------------------------------------------------*/
void monitor::call_resume_fake_syscall_all()
{
    for (int i = 0; i < mvee::numvariants; ++i)
		call_resume_fake_syscall(i);
}

/*-----------------------------------------------------------------------------
  pseudo handlers
-----------------------------------------------------------------------------*/
long monitor::handle_donthave(int variantnum) { return 0; }
long monitor::handle_dontneed(int variantnum) { return 0; }

/*-----------------------------------------------------------------------------
  log_donthave - This logger gets called if we don't have a specialized logger
  for the syscall we're executing
-----------------------------------------------------------------------------*/
void monitor::log_donthave(int variantnum)
{
	bool entry = (variants[variantnum].callnum != NO_CALL);

	if (entry)
	{
		const char* syscall_name = getTextualSyscall(variants[variantnum].callnum);
		if (strcmp(syscall_name, "sys_unknown") == 0)
		{
			debugf("%s - SYS_UNKNOWN - CALLNO: %ld (0x" PTRSTR ")\n", 
				   call_get_variant_pidstr(variantnum).c_str(),
				   variants[variantnum].callnum,
				   variants[variantnum].callnum);			
		}
		else
		{			
			debugf("%s - %s(...)\n", 
				call_get_variant_pidstr(variantnum).c_str(),
				mvee::upcase(syscall_name).c_str());
		}
	}
	else
	{
		debugf("%s - %s return: %ld\n", 
			   call_get_variant_pidstr(variantnum).c_str(),
			   mvee::upcase(getTextualSyscall(variants[variantnum].prevcallnum)).c_str(),
			   call_postcall_get_variant_result(variantnum)
			);
	}
}

void monitor::log_dontneed(int variantnum) 
{
	log_donthave(variantnum);
}

/*-----------------------------------------------------------------------------
    call_write_denied_syscall_return - 
-----------------------------------------------------------------------------*/
void monitor::call_write_denied_syscall_return(int variantnum)
{
	long err = variants[variantnum].call_flags >> 6;
	if (variants[variantnum].call_flags & MVEE_CALL_ERROR)
	{
		debugf("%s - %s forced return (error): %ld (%s)\n",
			   call_get_variant_pidstr(variantnum).c_str(),
			   mvee::upcase(getTextualSyscall(variants[variantnum].prevcallnum)).c_str(),
			   -err,
			   getTextualErrno(err));

		if (!interaction::write_syscall_return(variants[variantnum].variantpid, (unsigned long) -err))
			throw RwRegsFailure(variantnum, "write denied syscall error");
	}
	else if (variants[variantnum].call_flags & MVEE_CALL_RETURN_EXTENDED_VALUE)
	{
		debugf("%s - %s forced return (extended value): %ld\n",
			   call_get_variant_pidstr(variantnum).c_str(),
			   mvee::upcase(getTextualSyscall(variants[variantnum].prevcallnum)).c_str(),
			   variants[variantnum].extended_value);

		if (!interaction::write_syscall_return(variants[variantnum].variantpid, variants[variantnum].extended_value))
			throw RwRegsFailure(variantnum, "write denied syscall extended return");
	}
	else
	{
		debugf("%s - %s forced return (value): %ld\n",
			   call_get_variant_pidstr(variantnum).c_str(),
			   mvee::upcase(getTextualSyscall(variants[variantnum].prevcallnum)).c_str(),
			   err);

		if (!interaction::write_syscall_return(variants[variantnum].variantpid, err))
			throw RwRegsFailure(variantnum, "write denied syscall return");
	}
}

#if 0
static void print_migration_targets(char* pmvee_migration_mon_pt)
{
    unsigned long* current_migration_count = (unsigned long*) pmvee_migration_mon_pt;
    unsigned long* current_pointer_count   = &((unsigned long*)pmvee_migration_mon_pt)[1];
    warnf(" > <%p> current migration count: %ld\n", (void*)current_migration_count, *current_migration_count);
    warnf(" > <%p> current pointer count:   %ld\n", (void*)current_pointer_count, *current_pointer_count);
    auto variant_migration_infos = (mvee::pmvee_migration_info_t*)
            (((char*)pmvee_migration_mon_pt) + 2*sizeof(unsigned long));
    auto variant_pointer_infos = (unsigned long*) (
            ((char*)pmvee_migration_mon_pt) +
            (2*sizeof(unsigned long)) + ((*current_migration_count) * sizeof(mvee::pmvee_migration_info_t)));
    for (unsigned long migration_i = 0; migration_i < *current_migration_count; migration_i++)
        warnf( " > <%p> migration[%s%lu]: %p (%lu)\n",
            (void*)&variant_migration_infos[migration_i],
            migration_i < 100 ? (migration_i < 10 ? "00" : "0") : "", migration_i,
            (void*)variant_migration_infos[migration_i].offset, variant_migration_infos[migration_i].size);
    for (unsigned long pointer_i = 0; pointer_i < *current_pointer_count; pointer_i++)
        warnf( " > <%p> pointer[%s%lu]: %p\n",
            (void*)&variant_pointer_infos[pointer_i],
            pointer_i < 100 ? (pointer_i < 10 ? "00" : "0") : "", pointer_i,
            (void*)variant_pointer_infos[pointer_i]);
}
#endif

/*-----------------------------------------------------------------------------
    call_precall_get_call_type - called at every syscall entrance. Determines
    whether or not a call is synchronized.
-----------------------------------------------------------------------------*/
unsigned char monitor::call_precall_get_call_type (int variantnum, long callnum)
{
    mvee_syscall_handler handler;
    unsigned char        result = MVEE_CALL_TYPE_NORMAL;

    call_grab_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

    if (callnum >= 0 && callnum < MAX_CALLS)
    {
		if (variants[variantnum].fast_forwarding)
		{
			result = MVEE_CALL_TYPE_UNSYNCED;
		}
		// RAVEN syscall check toggling support
		else if (variants[variantnum].syscall_checking_disabled)
		{
			if (--variants[variantnum].max_unchecked_syscalls < 0)
			{
				warnf("%s - exceeded maximum number of allowed unchecked syscalls\n",
					  call_get_variant_pidstr(variantnum).c_str());
				shutdown(false);
			}
			else if (!SYSCALL_MASK_ISSET(variants[variantnum].unchecked_syscalls, callnum))
			{
				warnf("%s - syscall %ld (%s) is not in the unchecked calls list\n",
					  call_get_variant_pidstr(variantnum).c_str(),
					  callnum, getTextualSyscall(callnum));
				shutdown(false);
			}
			else
			{
				result = MVEE_CALL_TYPE_UNSYNCED;
			}
		}
		else
		{
			handler = monitor::syscall_handler_table[callnum][MVEE_GET_CALL_TYPE];
			if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
				result = ((this->*handler)(variantnum) & 0xff);
		}
    }
    else
    {
        // Handle fake calls
        switch(callnum)
        {
            case MVEE_GET_MASTERTHREAD_ID:
			case MVEE_GET_THREAD_NUM:
			case MVEE_RESOLVE_SYMBOL:
			case MVEE_SET_SYNC_PRIMITIVES_PTR:
			case MVEE_INVOKE_LD:
			case MVEE_RUNS_UNDER_MVEE_CONTROL:
			case MVEE_ENABLE_XCHECKS:
			case MVEE_DISABLE_XCHECKS:
			case MVEE_GET_LEADER_SHM_TAG:
            case MVEE_GET_PMVEE_INFO:
            case MVEE_GET_PMVEE_TRANSLATION_UNIT:
            case MVEE_GET_PMVEE_SYNC:
            case MVEE_GET_PMVEE_COMMUNICATION:
            case MVEE_PMVEE_GET_JUMP_TABLE:
            {
                result = MVEE_CALL_TYPE_UNSYNCED;
                break;
            }
            case MVEE_PMVEE_REQUEST:
            {
                variants[variantnum].callnum = __NR_pmvee_switch;
                result = MVEE_CALL_TYPE_UNSYNCED;
                break;
            }

			case MVEE_ALL_HEAPS_ALIGNED:
			{
				if ((*mvee::config_variant_global)["relaxed_mman_xchecks"].asBool())
					result = MVEE_CALL_TYPE_UNSYNCED;
				break;
			}

			case MVEE_GET_VIRTUALIZED_ARGV0: 
			{
                // TODO: Review this. We might want this to be synced even while fast forwarding
				if (variants[variantnum].fast_forwarding)
					result = MVEE_CALL_TYPE_UNSYNCED;
                break;
			}

#ifdef MVEE_ENABLE_PMVEE
            case __NR_pmvee_switch:
            {
                variants[variantnum].pmvee_state = 0;

                if (ARG1(variantnum) == PMVEE_LIBC_REQUEST ||
                        ARG1(variantnum) == PMVEE_LIBC_SET ||
                        ARG1(variantnum) == PMVEE_HANDLER_REQUEST ||
                        ARG1(variantnum) == PMVEE_COMMUNICATION_REQUEST ||
                        ARG1(variantnum) == PMVEE_MAPPINGS_REQUEST ||
                        ARG1(variantnum) == PMVEE_MIGRATION_INFO_REQUEST ||
                        ARG1(variantnum) == PMVEE_ZONE_REQUEST)
                {
                    variants[variantnum].pmvee_state = ARG1(variantnum);
                    result = MVEE_CALL_TYPE_UNSYNCED;
                    break;
                }
                else if (ARG1(variantnum) == PMVEE_PRINT_BACKTRACE || ARG1(variantnum) == PMVEE_DIFF_MEMORY)
                {
                    variants[variantnum].pmvee_state = ARG1(variantnum);
                    result = MVEE_CALL_TYPE_NORMAL;
                    break;
                }

                if (!variantnum)
                {
                    if (ARG1(0) == PMVEE_REGION_REQUEST)
                    {
                        variants[variantnum].pmvee_state = ARG1(variantnum);
                        result = MVEE_CALL_TYPE_UNSYNCED;
                        break;
                    }
                    call_jump_to_equivalent_function_addresses();
                    SET_MULTI_EXEC(1);
                    debugf("MULTI-VARIANT ENTER\n");
                    for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
                        call_resume(variant_i);
                    if (pmvee_zone_pt == (unsigned long) -1)
                        pmvee_zone_pt = variants[0].regs.rdi;
                    pmvee_state_copy_zone.state_copy_start = variants[0].regs.rsi;
                    pmvee_state_copy_zone.state_alter_start = variants[0].regs.rdx;
                    pmvee_state_copy_zone.state_copy_end = variants[0].regs.r10;
                    copy_migration(); // TODO: Make this between two given variants.
                }
                else if (variants[variantnum].pmvee_communication_id != -1 &&
                        !variants[variantnum].pmvee_communication_pt)
                {
                    variants[variantnum].pmvee_state = PMVEE_COMMUNICATION_REQUEST;
                }
                result = MVEE_CALL_TYPE_NORMAL;
                break;
            }

            case __NR_pmvee_check:
            {
                result = MVEE_CALL_TYPE_NORMAL;
                break;
            }
#endif

			default:
			{
				if (variants[variantnum].fast_forwarding)
				{
					warnf("Don't have an unsynced call handler for call: %lu (%s)\n",
						  callnum, getTextualSyscall(callnum));
					shutdown(false);
					break;
				}
			}
        }
    }

    call_release_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_precall_log_args
-----------------------------------------------------------------------------*/
void monitor::call_precall_log_args (int variantnum, long callnum)
{
#ifndef MVEE_BENCHMARK
	mvee_syscall_logger logger;
	if (callnum >= 0 && callnum < MAX_CALLS)
		logger = monitor::syscall_logger_table[callnum][MVEE_LOG_ARGS];
	else
		logger = &monitor::log_donthave;

	mvee::in_logging_handler = true;
	(this->*logger)(variantnum);
	mvee::in_logging_handler = false;
#endif
}

/*-----------------------------------------------------------------------------
    call_precall - called when the variants have reached the sync point at
    a synced call's entrance. Verifies if the call arguments match and decides
    how the call should be dispatched.
-----------------------------------------------------------------------------*/
long monitor::call_precall ()
{
    long                 result = MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    long                 callnum;
    mvee_syscall_handler handler;

    // We already know that the syscall number matches so this is safe
    callnum = variants[0].callnum;
    call_grab_syslocks(-1, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

    if (callnum >= 0 && callnum < MAX_CALLS)
    {
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_PRECALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            result = (this->*handler)(-1);
        else if (handler == MVEE_HANDLER_DONTHAVE)
        {
            warnf("ERROR: missing PRECALL handler for syscall: %lu (%s)\n", callnum, getTextualSyscall(callnum));
            shutdown(false);
        }
    }
	else
	{
		if (callnum == MVEE_ALL_HEAPS_ALIGNED)
		{
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				debugf("%s - SYS_MVEE_ALL_HEAPS_ALIGNED(heap: 0x" PTRSTR ", requested alignment: 0x" PTRSTR ", requested size: 0x" PTRSTR")\n", 
					   call_get_variant_pidstr(i).c_str(), (unsigned long)ARG1(i), (unsigned long)ARG2(i), (unsigned long)ARG3(i));

				if (i >= 1 &&
					(ARG2(i) != ARG2(0) ||
					 ARG3(i) != ARG3(0)))
				{
					result = MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(2);
				}
			}
		}
	}

    if (result & MVEE_PRECALL_CALL_DENY)
        call_release_syslocks(-1, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_call_dispatch_unsynced - dispatches an unsynced call.
    unsynced syscalls don't have a precall handler so we grab the syslocks
    here and release them if the call doesn't really get dispatched
-----------------------------------------------------------------------------*/
long monitor::call_call_dispatch_unsynced (int variantnum)
{
    long                 result  = 0;
    mvee_syscall_handler handler;
    long                 callnum = variants[variantnum].callnum;
	
    call_grab_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_CALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            result = (this->*handler)(variantnum);
#ifndef MVEE_BENCHMARK
        if (handler == MVEE_HANDLER_DONTHAVE)
            warnf("missing CALL handler for syscall: %lu (%s)\n", callnum, getTextualSyscall(callnum));
#endif
    }
    else
    {
        switch(callnum)
        {
			//
			// This is called by every variant thread the first time they
			// encounter an interposed function in the synchronization agents.
			//
			// The variants need to know the tid of the master's thread because
			// this will be the tid that is logged into the sychronization
			// buffer.
			//
			case MVEE_GET_MASTERTHREAD_ID:
			{
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(variants[0].variantpid);
				break;
			}

			//
            // This is also called from within the function that sets up the
            // shared buffers
			//
            case MVEE_GET_THREAD_NUM:
            {
				if (ARG1(variantnum) &&
					!rw::write_primitive<unsigned short>(variants[variantnum].variantpid, (void*) ARG1(variantnum), (unsigned short) variantnum))
					throw RwMemFailure(variantnum, "replicate variantnum in get_thread_num");

				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(mvee::numvariants);
                break;
            }

#ifdef MVEE_CHECK_SYNC_PRIMITIVES
			//
            // arg1 is a pointer to a bitmask that keeps track of the high-level
            // sync primitives an application is using
			//
            case MVEE_SET_SYNC_PRIMITIVES_PTR:
            {
                variants[variantnum].sync_primitives_ptr = (void*)ARG1(variantnum);
				result = MVEE_CALL_ALLOW;
                break;
            }
#endif

            //
            // Resolves a symbol using debugging info
            //
            case MVEE_RESOLVE_SYMBOL:
            {
				std::string sym = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
                if (sym.length() == 0)
                {
                    warnf("%s - couldn't read sym\n", call_get_variant_pidstr(variantnum).c_str());
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    break;
                }
				std::string lib_name = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
                if (lib_name.length() == 0)
                {
                    warnf("%s - couldn't read lib_name\n", call_get_variant_pidstr(variantnum).c_str());
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    break;
                }

                unsigned long ptr      = set_mmap_table->resolve_symbol(variantnum, (const char*)sym.c_str(), (const char*)lib_name.c_str());
                if (!rw::write_primitive<unsigned long>(variants[variantnum].variantpid, (void*) ARG3(variantnum), ptr))
					throw RwMemFailure(variantnum, "replicate resolved symbol address in resolve_symbol");

                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                break;
            }

            case MVEE_INVOKE_LD:
            {
#ifndef MVEE_BENCHMARK
                debugf("%s - Variant requested control transfer to manually mapped program interpreter\n", call_get_variant_pidstr(variantnum).c_str());
#endif

                // force an munmap of the MVEE_LD_loader program - the loader is compiled
                // to always be at base address 0x08048000 regardless of ALSR
				unsigned long loader_base, loader_size;
				if (set_mmap_table->get_ld_loader_bounds(variantnum, loader_base, loader_size))
				{
					if (!SETSYSCALLNO(variantnum, __NR_munmap) || 
						!SETARG1(variantnum, loader_base) || 
						!SETARG2(variantnum, loader_size))
					{
						throw RwRegsFailure(variantnum, "unmapping LD Loader");
					}

#ifndef MVEE_BENCHMARK
					debugf("%s - unmapping loader at: 0x" PTRSTR "-0x" PTRSTR "\n",
						   call_get_variant_pidstr(variantnum).c_str(),
						   loader_base,
						   loader_base + loader_size);
#endif

					// we also want to unmap it from our mmap_table since we won't run the
					// munmap postcall handler but rather, the INVOKE_LD handler
					set_mmap_table->munmap_range(variantnum, loader_base, loader_size);
				}
                break;
            }

            case MVEE_RUNS_UNDER_MVEE_CONTROL:
            {
                // as of 19/05/2014, this call is now invoked as follows (pseudocode):
                // syscall(MVEE_RUNS_UNDER_MVEE_CONTROL, &mvee_sync_enabled, &mvee_infinite_loop, &mvee_num_variants, &mvee_variant_num, &mvee_master_variant);
                //
                // arguments:
                // unsigned char  mvee_sync_enabled    : 0 = lock replication disabled, 1 = lock replication enabled
                // void*          mvee_infinite_loop   : pointer to the infinite loop we're using for fast detaching/signal delivery
                // unsinged short mvee_num_variants      : number of variants we're currently monitoring
                // unsigned short mvee_variant_num       : the calling variant's index into the monitor's variant array
                // unsigned char  mvee_master_variant  : 0 = slave variant (lock following), 1 = master variant (lock recording)
                //
				variants[variantnum].should_sync_ptr   = ARG1(variantnum);
				variants[variantnum].infinite_loop_ptr = ARG2(variantnum);

				if (ARG3(variantnum) && 
					!rw::write_primitive<unsigned short>(variants[variantnum].variantpid, (void*) ARG3(variantnum), (unsigned short) mvee::numvariants))
					throw RwMemFailure(variantnum, "write runs_under_mvee_control numvariants");

				if (ARG4(variantnum) &&	
					!rw::write_primitive<unsigned short>(variants[variantnum].variantpid, (void*) ARG4(variantnum), (unsigned short) variantnum))
					throw RwMemFailure(variantnum, "write runs_under_mvee_control variantnum");

				if (variantnum == 0 && ARG5(variantnum) && 
					!rw::write_primitive<unsigned char>(variants[variantnum].variantpid, (void*) ARG5(variantnum), 1))
					throw RwMemFailure(variantnum, "write runs_under_mvee_control master byte");

#ifdef MVEE_ALLOW_SHM
                if (ARG6(variantnum))
                {
                    std::random_device rd;
                    unsigned long shm_tag = 0;
                    while (!shm_tag)
                    {
                        // We can only use 15 bits for our secret, but will generate 32 bits
                        // The most significant bits are set anyway, and we're going to OR this
                        uint32_t secret = rd();
                        shm_tag = SHARED_MEMORY_ADDRESS_TAG | ((unsigned long)secret << 32);
                        debugf("%s - SHM TAG => %lx\n", call_get_variant_pidstr(variantnum).c_str(), shm_tag);

                        // Check whether there any duplicates. If so, re-generate the secret
                        for (int iii = 0; iii < variantnum; iii++)
                        {
                            if (variants[variantnum].shm_tag == shm_tag)
                            {
                                shm_tag = 0;
                                break;
                            }
                        }
                    }

                    variants[variantnum].shm_tag = shm_tag;
                    if(!rw::write_primitive<unsigned long>(variants[variantnum].variantpid, (void*) ARG6(variantnum), shm_tag))
                        throw RwMemFailure(variantnum, "write runs_under_mvee_control shared memory tag");
                }
#endif

#ifdef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
#else
                if (is_program_multithreaded())
                    enable_sync();

                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(1);
#endif
                break;
            }

			case MVEE_GET_VIRTUALIZED_ARGV0:
			{
				// This is fine, though we might want to change this policy later
                break;
			}

			//
			// Only works if we're fast forwarding, which only happens if 
			// variants.global.settings.xchecks_initially_enabled is set to false at the
			// time we see a sys_execve.
			//
			case MVEE_ENABLE_XCHECKS:
			{
				if (variants[variantnum].fast_forwarding)
				{
					debugf("%s - SYS_ENABLE_XCHECKS() => variant is leaving fast-forwarding state\n", 
					   call_get_variant_pidstr(variantnum).c_str());
					variants[variantnum].fast_forwarding = false;
				}
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}

			//
			// And turn it back on...
			// 
			case MVEE_DISABLE_XCHECKS:
			{
				if (!(*mvee::config_variant_global)["xchecks_initially_enabled"].asBool())
				{
					debugf("%s - SYS_DISABLE_XCHECKS() => variant is re-entering fast-forwarding state\n", 
					   call_get_variant_pidstr(variantnum).c_str());
					variants[variantnum].fast_forwarding = true;
				}
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}

			case MVEE_GET_LEADER_SHM_TAG:
			{
        variants[variantnum].extended_value = variants[0].shm_tag;
        result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
				break;
			}

            case MVEE_GET_PMVEE_INFO:
            {
                struct ipmon_pmvee_info_t ipmon_pmvee_info =
                {
                    variants[0].variantpid,
                    variants[variantnum].variantpid,
                    (void*)mp_start,
                    PMVEE_ZONE_ONE_DEFAULT_SIZE,
                    PMVEE_ZONE_TWO_DEFAULT_SIZE,
                };
                if (!interaction::write_memory(variants[variantnum].variantpid, (void*)ARG1(variantnum), sizeof(struct ipmon_pmvee_info_t), &ipmon_pmvee_info))
                    shutdown(false);
                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                break;
            }

            case MVEE_GET_PMVEE_TRANSLATION_UNIT:
            {
                if (variantnum)
                    shutdown(false);
                variants[variantnum].regs.orig_rax = __NR_shmat;
                variants[variantnum].regs.rax = __NR_shmat;
                variants[variantnum].regs.rdi = translation_id;
                variants[variantnum].regs.rsi = 0;
                variants[variantnum].regs.rdx = 0;

                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                {
                    warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                            variantnum, errno);
                    shutdown(false);
                }
                result = MVEE_CALL_ALLOW;
                break;
            }

#ifdef IPMON_PMVEE_HANDLING
            case MVEE_GET_PMVEE_SYNC:
            {
                // if (variantnum)
                //     shutdown(false);
                variants[variantnum].regs.orig_rax = __NR_shmat;
                variants[variantnum].regs.rax = __NR_shmat;
                variants[variantnum].regs.rdi = multi_exec->pmvee_sync_id;
                variants[variantnum].regs.rsi = 0;
                variants[variantnum].regs.rdx = 0;

                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                {
                    warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                            variantnum, errno);
                    shutdown(false);
                }
                result = MVEE_CALL_ALLOW;
                break;
            }
#endif
            case MVEE_GET_PMVEE_COMMUNICATION:
            {
                variants[variantnum].regs.orig_rax = __NR_shmat;
                variants[variantnum].regs.rax = __NR_shmat;
                variants[variantnum].regs.rdi = variants[!variantnum ? ARG1(0) : variantnum].pmvee_communication_id;
                variants[variantnum].regs.rsi = 0;
                variants[variantnum].regs.rdx = 0;

                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                {
                    warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                            variantnum, errno);
                    shutdown(false);
                }
                result = MVEE_CALL_ALLOW;
                break;
            }
            case MVEE_PMVEE_GET_JUMP_TABLE:
            {
                if (variantnum)
                    shutdown(false);
                variants[variantnum].regs.orig_rax = __NR_shmat;
                variants[variantnum].regs.rax = __NR_shmat;
                variants[variantnum].regs.rdi = pmvee_translations->jumps_id;
                variants[variantnum].regs.rsi = 0;
                variants[variantnum].regs.rdx = 0;

                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                {
                    warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                            variantnum, errno);
                    shutdown(false);
                }
                result = MVEE_CALL_ALLOW;
                break;
            }

			// This is only ever dispatched as unsynced if we have enabled relaxed_mman_xchecks
			case MVEE_ALL_HEAPS_ALIGNED:
			{
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(1);
				break;
			}

#ifdef MVEE_ENABLE_PMVEE
            case __NR_pmvee_switch:
            {
                if (ARG1(variantnum) == PMVEE_REGION_REQUEST)
                {
                    debugf(">PMVEE_REGION_REQUEST\n\n");
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
                    variants[variantnum].extended_value = mp_start;
                }
                else if (ARG1(variantnum) == PMVEE_ZONE_REQUEST)
                {
                    debugf(">PMVEE_ZONE_REQUEST\n\n");
                    if (variantnum)
                        shutdown(false);
                    if (!pmvee_copy_zone)
                        pmvee_copy_zone = set_mmap_table->calculate_joint_base(PMVEE_ZONE_DEFAULT_SIZE, 1);
                    SETSYSCALLNO(variantnum, __NR_mmap);
                    SETARG1(variantnum, pmvee_copy_zone);
                    SETARG2(variantnum, PMVEE_ZONE_DEFAULT_SIZE);
                    SETARG3(variantnum, PROT_READ | PROT_WRITE);
                    SETARG4(variantnum, MAP_ANONYMOUS | MAP_PRIVATE | (variantnum ? MAP_FIXED : 0));
                    SETARG5(variantnum, -1);
                    SETARG6(variantnum, 0);
                    result = MVEE_CALL_ALLOW;
                    variants[variantnum].extended_value = mp_start;
                }
                else if (ARG1(variantnum) == PMVEE_LIBC_REQUEST)
                {
                    debugf(">PMVEE_LIBC_REQUEST\n\n");
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
                    variants[variantnum].extended_value = variantnum ? variants[variantnum].pmvee_libc_state_copy_follower_addr : variants[variantnum].pmvee_libc_state_copy_leader_addr;
                }
                else if (ARG1(variantnum) == PMVEE_LIBC_SET)
                {
                    debugf(">PMVEE_LIBC_SET\n\n");
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    variants[variantnum].pmvee_libc_state_copy_leader_addr = ARG2(variantnum);
                    variants[variantnum].pmvee_libc_state_copy_follower_addr = ARG3(variantnum);
                }
                else if (ARG1(variantnum) == PMVEE_PRINT_BACKTRACE)
                {
                    debugf(">PMVEE_PRINT_BACKTRACE\n\n");
                    log_variant_backtrace(variantnum);
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                }
                else if (ARG1(variantnum) == PMVEE_HANDLER_REQUEST)
                {
                    debugf(">PMVEE_HANDLER_REQUEST\n\n");
                    struct __pmvee_state_copies_t variant_state_copies  =
                    {
                        (int)0,
                        {},
                        (int)0,
                        {}
                    };

                    debugf(" > passing handlers for %d\n", variantnum);
                    for (std::vector<long unsigned int> state_copy: pmvee_state_copies)
                    {
                        if (variant_state_copies.copy_count >= PMVEE_COPY_COUNT)
                            shutdown(false);
                        variant_state_copies.__pmvee_state_copies[variant_state_copies.copy_count] =
                                (void (*) (char*, size_t*, void*))state_copy[variantnum];
                        debugf(" > copy[%d] = %p\n", variant_state_copies.copy_count, (void*)variant_state_copies.__pmvee_state_copies[variant_state_copies.copy_count]);
                        variant_state_copies.copy_count++;
                    }
                    for (std::vector<long unsigned int> state_migration: pmvee_state_migrations)
                    {
                        if (variant_state_copies.migration_count >= PMVEE_COPY_COUNT)
                            shutdown(false);
                        variant_state_copies.__pmvee_state_migrations[variant_state_copies.migration_count] =
                                (void (*) (char*, size_t*, void*))state_migration[variantnum];
                        debugf(" > state[%d] = %p\n", variant_state_copies.migration_count, (void*)variant_state_copies.__pmvee_state_migrations[variant_state_copies.migration_count]);
                        variant_state_copies.migration_count++;
                    }

                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    if (!interaction::write_memory(variants[variantnum].variantpid, (void*)ARG2(variantnum), sizeof(__pmvee_state_copies_t), &variant_state_copies))
                    {
                        shutdown(false);
                    }
                }
                else if (variants[variantnum].pmvee_state == PMVEE_COMMUNICATION_REQUEST)
                {
                    debugf(">PMVEE_COMMUNICATION_REQUEST | %d\n\n", variants[variantnum].pmvee_communication_id);
                    variants[variantnum].regs.orig_rax = __NR_shmat;
                    variants[variantnum].regs.rax = __NR_shmat;
                    variants[variantnum].regs.rdi = variants[variantnum].pmvee_communication_id;
                    variants[variantnum].regs.rsi = 0;
                    variants[variantnum].regs.rdx = variantnum ? SHM_RDONLY : 0;
                    
	                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                    {
                        warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                                variantnum, errno);
                        shutdown(false);
                    }
                    result = MVEE_CALL_ALLOW;
                }
                else if (variants[variantnum].pmvee_state == PMVEE_MAPPINGS_REQUEST)
                {
                    debugf(">PMVEE_MAPPINGS_REQUEST | %d\n\n", simple_mappings_id);
                    variants[variantnum].regs.orig_rax = __NR_shmat;
                    variants[variantnum].regs.rax = __NR_shmat;
                    variants[variantnum].regs.rdi = simple_mappings_id;
                    variants[variantnum].regs.rsi = 0;
                    variants[variantnum].regs.rdx = variantnum ? SHM_RDONLY : 0;
                    
	                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                    {
                        warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                                variantnum, errno);
                        shutdown(false);
                    }
                    result = MVEE_CALL_ALLOW;
                }
                else if (variants[variantnum].pmvee_state == PMVEE_MIGRATION_INFO_REQUEST)
                {
                    debugf(">PMVEE_MIGRATION_INFO_REQUEST\n\n");
                    variants[variantnum].regs.orig_rax = __NR_shmat;
                    variants[variantnum].regs.rax = __NR_shmat;
                    variants[variantnum].regs.rdi = variants[variantnum].pmvee_migration_id;
                    variants[variantnum].regs.rsi = 0;
                    variants[variantnum].regs.rdx = variantnum ? SHM_RDONLY : 0;
                    
	                if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
                    {
                        warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                                variantnum, errno);
                        shutdown(false);
                    }
                    result = MVEE_CALL_ALLOW;
                }
                else
                {
                    log_variant_backtrace(variantnum);
                    warnf("unsynched switch not allowed!\n");
                    shutdown(false);

                    if (!variantnum)
                    {
                        if (pmvee_zone_pt == (unsigned long) -1)
                            pmvee_zone_pt = variants[0].regs.rdi;
                        pmvee_state_copy_zone.state_copy_start = variants[0].regs.rsi;
                        pmvee_state_copy_zone.state_alter_start = variants[0].regs.rdx;
                        pmvee_state_copy_zone.state_copy_end = variants[0].regs.r10;
                        copy_migration();
                        SET_MULTI_EXEC(1);
                    }

                    debugf(" [%d] swtich <%d> [ 0x%lx ; 0x%lx )\n", variantnum, variants[0].variantpid,
                            (unsigned long) mp_start, (unsigned long) (mp_start + mp_size));

                    // rdi: source
                    // rsi: destination
                    // rdx: from
                    // r10: size_one
                    // r08: size_two
                    // r09: flags
                    variants[variantnum].regs.rdi = variants[0].variantpid;
                    variants[variantnum].regs.rsi = variantnum ? 0 : (mvee::numvariants > 1 ? variants[1].variantpid : 0);
                    variants[variantnum].regs.rdx = mp_start;
                    variants[variantnum].regs.r10 = PMVEE_ZONE_ONE_DEFAULT_SIZE;
                    variants[variantnum].regs.r8 = PMVEE_ZONE_TWO_DEFAULT_SIZE;
                    #ifdef PMVEE_CONFIG_REMOVE_PERMISSIONS
                    variants[variantnum].regs.r9 = PMVEE_FLAGS_DUP_EXEC;
                    #else
                    variants[variantnum].regs.r9 = 0;
                    #endif

                    interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs);
                    result = MVEE_CALL_ALLOW;
                }
                break;
            }
#endif

			//
			// 
			//
			default:
			{
				warnf("Don't have an unsynced call handler for call: %lu (%s)\n",
					  callnum, getTextualSyscall(callnum));
				result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}
        }
    }

    if (result & MVEE_CALL_DENY)
        call_release_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
    else
        call_release_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_call_dispatch - syslocks for synced calls are already taken in
    call_precall
-----------------------------------------------------------------------------*/
long monitor::call_call_dispatch ()
{
    int                  i;
    mvee_syscall_handler handler;
    long                 result  = 0;

    long                 callnum = variants[0].callnum;
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
        handler = monitor::syscall_handler_table[callnum][MVEE_HANDLE_CALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            result = (this->*handler)(-1);
#ifndef MVEE_BENCHMARK
        if (handler == MVEE_HANDLER_DONTHAVE)
            warnf("missing CALL handler for syscall: %ld (%s)\n", callnum, getTextualSyscall(callnum));
#endif
    }
    else
    {
        //
        // Handlers for fake syscalls. All of these calls will be denied.
        //
        switch(callnum)
        {
            // Used for the new-style interposers! Allocates a shared buffer when needed.
            // Then returns the id and size of the allocated buffer.
            case MVEE_GET_SHARED_BUFFER:
            {
                std::map<unsigned char, std::shared_ptr<_shm_info> >::iterator it;
                _shm_info*                                                     info                = NULL;
                unsigned char                                                  is_eip_buffer       = (unsigned char)ARG1(0);
                unsigned char                                                  buffer_type         = (unsigned char)ARG2(0);
                unsigned char                                                  slot_size           = (unsigned char)ARG4(0);
                unsigned char                                                  stack_depth         = (unsigned char)ARG5(0);
                unsigned int                                                   requested_slot_size = slot_size;
                unsigned int                                                   actual_slot_size    = ROUND_UP(slot_size, 64);
                unsigned long                                                  alloc_size          = 0;

				debugf("MVEE_GET_SHARED_BUFFER call for buffer %d (%s)\n",
						   buffer_type, getTextualBufferType(buffer_type));

                if (buffer_type == MVEE_LIBC_ATOMIC_BUFFER)
                {
                    is_eip_buffer = 0;

					for (i = 0; i < mvee::numvariants; ++i)
					{
						atomic_counters[i]  = (void*)ARG1(i);
						if (buffer_type == MVEE_LIBC_ATOMIC_BUFFER)
							atomic_queue_pos[i] = (void*)ARG4(i);
					}

                    if (!atomic_buffer)
                    {
						bool have_many_threads =
							!(*mvee::config_variant_global)["have_many_threads"].isNull() &&
							(*mvee::config_variant_global)["have_many_threads"].asBool();
						
                        info                = new _shm_info();
                        atomic_buffer       = info;
                        requested_slot_size = sizeof(unsigned long);
                        alloc_size          = requested_slot_size * SHARED_QUEUE_SLOTS / (have_many_threads ? 64 : 1);
                    }
                    else
                    {
                        info = atomic_buffer;
                    }
                }
				else if (buffer_type == MVEE_IPMON_BUFFER)
				{
					debugf("Requested IP-MON Replication Buffer\n");

					bool have_many_threads =
							!(*mvee::config_variant_global)["have_many_threads"].isNull() &&
							(*mvee::config_variant_global)["have_many_threads"].asBool();
					int ipmon_buffer_size = (MVEE_IPMON_BUFFER_SIZE /(have_many_threads ? 64 : 1));

					// warnf("IPMON buffer size is %d\n", ipmon_buffer_size);

					// return size of the buffer
					for (i = 0; i < mvee::numvariants; ++i)
						if (ARG3(i) && !rw::write_primitive<unsigned int>(variants[i].variantpid, (void*) ARG3(i), (unsigned int) ipmon_buffer_size))
							throw RwMemFailure(i, "write shared buffer size");

					// this happens when a variant makes a subsequent sys_execve
					// in this case we do not re-create the shared memory segment (we do not need to ... the monitor has already created it)
					// for example if we run ./MVEE -- ls, ReMon (normally) launches a /bin/bash -c /bin/ls, and bash subsequently calls sys_execve of /bin/ls
					// !!! Note that bash has its own implementations for some of the simpler (than ls) unix utilities such as pwd and echo!!!!
					if (ipmon_buffer)
					{
						debugf("MVEE_IPMON_BUFFER already initialized\n");
						for (i = 0; i < mvee::numvariants; ++i) {
							// the following two commented lines are not needed
							// if (ARG6(i) && !rw::write_primitive<char>(variants[i].variantpid, (void*) ARG6(i), (char) 1))
							//     throw RwMemFailure(i, "write already initialized MVEE_IPMON_BUFFER ");
							variants[i].extended_value = (long) ipmon_buffer->id;
						}
						result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
						break;
					}

					ipmon_buffer = new _shm_info();
					if (!mvee::os_alloc_sysv_sharedmem(ipmon_buffer_size ,
													   &(ipmon_buffer->id),
													   &(ipmon_buffer->sz),
													   &(ipmon_buffer->ptr)))
					{
						result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
						break;
					}
                    // This is kinda needed for pmvee setup.
                    ((struct ipmon_buffer*)ipmon_buffer->ptr)->ipmon_numvariants = mvee::numvariants;

					// deny the call and return id of the buffer
					for (i = 0; i < mvee::numvariants; ++i)
						variants[i].extended_value = (long)ipmon_buffer->id;

					result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
					break;
				}
				else if (buffer_type == MVEE_IPMON_REG_FILE_MAP)
				{
					int id = 0;

					debugf("Requested IP-MON File Map\n");
					
					call_grab_locks(MVEE_SYSLOCK_FD);
					id = set_fd_table->file_map_id();
					call_release_locks(MVEE_SYSLOCK_FD);

					for (i = 0; i < mvee::numvariants; ++i)
                        variants[i].extended_value = id;

                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
					break;
				}
				else if (buffer_type == MVEE_RING_BUFFER)
				{
                    if (!ring_buffer)
                    {
                        ring_buffer = new _shm_info();
						
						int requested_capacity = 4096;

						if (ARG3(0) && !rw::read_primitive<int>(variants[0].variantpid, (void*) ARG3(0), requested_capacity))
							throw RwMemFailure(0, "read ring buffer capacity");

						alloc_size = requested_slot_size * requested_capacity + (mvee::numvariants + 1) * 64;
                    }

					info = ring_buffer;
				}
                else if (buffer_type == MVEE_SHM_BUFFER)
                {
                    if (!shm_buffer)
                    {
                      shm_buffer = new _shm_info();
                      alloc_size =  SHARED_QUEUE_SLOTS * actual_slot_size;
                    }

                    info = shm_buffer;
                }
                else if (buffer_type == MVEE_LIBC_VARIANTWIDE_ATOMIC_BUFFER)
                {
                    if (monitor::atomic_variantwide_buffer.empty())
                    {
                        for (int iii = 0; iii < mvee::numvariants; ++iii)
                        {
                            debugf("Allocating variantwide atomic buffer for variant %d\n", iii);
                            monitor::atomic_variantwide_buffer.push_back(std::make_unique<_shm_info>());
                            auto& info = monitor::atomic_variantwide_buffer[iii];
                            alloc_size = ARG4(iii);
                            if (!mvee::os_alloc_sysv_sharedmem(alloc_size, &(info->id), &(info->sz), &(info->ptr)))
                            {
                                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
                                break;
                            }
                        }
                    }

                    // deny the call and return id of the buffer
                    for (int iii = 0; iii < mvee::numvariants; ++iii)
                        variants[iii].extended_value = monitor::atomic_variantwide_buffer[iii]->id;

                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
                    break;
                }
                else if (buffer_type <= MVEE_MAX_SHM_TYPES)
                {
                    it         = set_shm_table->table.find(buffer_type);

                    if (it == set_shm_table->table.end())
                        info = set_shm_table->create_info(buffer_type).get();
                    else
                        info = it->second.get();

                    alloc_size = 64 * (mvee::numvariants + 1) + SHARED_QUEUE_SLOTS * actual_slot_size;
                }

                if (info)
                {
                    int*   id_ptr   = is_eip_buffer ? &info->eip_id : &info->id;
                    int*   size_ptr = is_eip_buffer ? &info->eip_sz : &info->sz;
                    void** ptr_ptr  = is_eip_buffer ? &info->eip_ptr : &info->ptr;

                    // Check if we need to allocate
                    if (*id_ptr == -1)
                    {					  
						if (!mvee::os_alloc_sysv_sharedmem(alloc_size, id_ptr, size_ptr, ptr_ptr))
						{
							result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
							break;
						}

                        if (is_eip_buffer)
                        {
                            info->have_eip_segment = true;
                            info->eip_stack_depth  = stack_depth;
                        }
                        else
                        {
                            info->requested_slot_size = requested_slot_size;
                            info->actual_slot_size    = actual_slot_size;
                        }

                        debugf("allocated new shared buffer. type = %d (%s) - size = %d bytes - id = %d - eip: %d (stack depth: %d)\n",
                                   buffer_type, getTextualBufferType(buffer_type),
                                   *size_ptr,
                                   *id_ptr,
                                   is_eip_buffer, is_eip_buffer ? stack_depth : 0
                                   );
                    }

                    // return size of the buffer
                    for (i = 0; i < mvee::numvariants; ++i)
                        if (ARG3(i) && !rw::write_primitive<unsigned int>(variants[i].variantpid, (void*) ARG3(i), (unsigned int) *size_ptr))
							throw RwMemFailure(i, "write shared buffer size");

                    // deny the call and return id of the buffer
                    for (i = 0; i < mvee::numvariants; ++i)
                        variants[i].extended_value = (long)*id_ptr;
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
                    break;
                }

                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
                break;
            }

            //
            // Shared buffer is full. Flush it, then return 0
            //
            case MVEE_FLUSH_SHARED_BUFFER:
            {
                // ARG1 = buffer type
                std::map<unsigned char, std::shared_ptr<_shm_info> >::iterator it;
                _shm_info*                                                     info               = NULL;
                unsigned char                                                  clear_whole_buffer = 1;

                if (ARG1(0) == MVEE_LIBC_ATOMIC_BUFFER)
                {
                    info = atomic_buffer;
                }
                else if (ARG1(0) == MVEE_IPMON_BUFFER)
                {
                    debugf("flushing ipmon_buffer: " PTRSTR "\n", (unsigned long)ipmon_buffer);
                    if (ipmon_buffer)
                    {
#ifdef MVEE_LOG_IPMON_BUFFER_ON_FLUSH
						log_ipmon_state();
#endif
                        memset((unsigned char*)(ipmon_buffer->ptr) + 64, 0, ipmon_buffer->sz - 64);
                        __sync_synchronize();
                        result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                        break;
                    }
                }
                else if (ARG1(0) == MVEE_SHM_BUFFER)
                {
                    info = shm_buffer;
                }
                else if (ARG1(0) <= MVEE_MAX_SHM_TYPES)
                {
                    it = set_shm_table->table.find(ARG1(0));

                    if (it != set_shm_table->table.end())
                        info = it->second.get();
                    else
                        warnf("flush of unregistered queue: %s\n", getTextualBufferType(ARG1(0)));

                    if (ARG1(0) == MVEE_LIBC_LOCK_BUFFER
                        || ARG1(0) == MVEE_LIBC_LOCK_BUFFER_PARTIAL)
                        clear_whole_buffer = 0;
                }

                if (!info)
                {
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
                    break;
                }

#ifdef MVEE_GENERATE_LOCKSTATS
                set_shm_table->update_lock_stats(ARG1(0), info);
#endif

#ifdef MVEE_ALWAYS_DUMP_QUEUES
                log_dump_queues();
#endif

                if (info->ptr)
                {
                    if (!clear_whole_buffer)
                        memset((void*)(ROUND_UP((unsigned long)info->ptr, 64) + 64*(mvee::numvariants)),
                               0, info->sz - 64*(mvee::numvariants) -(ROUND_UP((unsigned long)info->ptr, 64) - (unsigned long)info->ptr));
                    else
                        memset(info->ptr, 0, info->sz);
                }
                if (info->eip_ptr)
                    memset(info->eip_ptr, 0, info->eip_sz);
                __sync_synchronize();
                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                break;
            }

			// 
			// Called by the variants to check if the heaps have the requested
			// alignment 
			//
            // syntax: syscall(MVEE_ALL_HEAPS_ALIGNED, heap pointer, requested
			// alignment, requested size);
			//
			// If the heaps are not aligned in any of the variants, then this
			// call should return false, even for variants that DO have an
			// aligned heap. The variants can then unmap the heap and fall back
			// to the forced alignment method.
			//
            case MVEE_ALL_HEAPS_ALIGNED:
            {
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					if (!ARG1(i) || (ARG1(i) & (ARG2(i) - 1)))
					{
						last_mmap_requested_alignment = ARG2(i);
						last_mmap_requested_size      = ARG3(i);
						result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
						break;
					}
				}
                if (!result)
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(1);
                break;
            }

            // Syntax: 
			//
			// syscall(MVEE_GET_VIRTUALIZED_ARGV0, old_argv0,
			// virtualized_argv0_buf, virtualized_argv0_buf_sz)
			//
            // With: 
            // - old_argv0 is a pointer to the original argv[0] string
            // - virtualized_argv0_buf is where the mvee should write the
            // virtualized string
            // - virtualized_argv0_buf_sz is the size of the aforementioned
            // buffer
			case MVEE_GET_VIRTUALIZED_ARGV0:
			{
				std::string master_argv0 = rw::read_string(variants[0].variantpid, (void*)ARG1(0));

				debugf("Returning virtualized argv[0]: %s\n",
					 master_argv0.c_str());

				// We copy the master's arg[0] value into the buffer.
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					if (ARG2(i) && ARG3(i) > master_argv0.length() + 1)
					{
						if (!rw::write_data(variants[i].variantpid, (void*) ARG2(i), 
											master_argv0.length() + 1, 
											(void*) master_argv0.c_str()))
							throw RwMemFailure(i, "write virtualized argv[0]");
					}
				}

				if (!result)
					result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}

            //
            // Syntax: 
			//
			// syscall(MVEE_RESET_ATFORK, address, size)
			//
            // With: 
            // - address is a pointer to the variable to reset in a forked child
            // - size is the size of the variable
			case MVEE_RESET_ATFORK:
			{
				// Store the data
				for (int i = 0; i < mvee::numvariants; ++i)
                    variants[i].reset_atfork.emplace_back(ARG1(i), ARG2(i));

                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
				break;
			}

#ifdef MVEE_ENABLE_PMVEE
            case __NR_pmvee_switch:
            {
                if (ARG1(0) == PMVEE_REGION_REQUEST)
                {
                    warnf(" > shutting down\n");
                    shutdown(false);
                    break;
                }
                else if (ARG1(0) == PMVEE_PRINT_BACKTRACE)
                {
                    warnf(">PMVEE_PRINT_BACKTRACE\n");
                    log_backtraces();
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    break;
                }
                else if (ARG1(0) == PMVEE_DIFF_MEMORY)
                {
                    warnf(">PMVEE_DIFF_MEMORY\n");
#ifdef MVEE_CONNECTED_MMAP_REGIONS
                    set_mmap_table->diff_memory(variants[0].variantpid, 1, variants[1].variantpid, 1, 0);
#else
                    warnf("PMVEE_DIFF_MEMORY requires MVEE_CONNECTED_MMAP_REGIONS.\n");
#endif
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    break;
                }

                if (pmvee_zone_pt == (unsigned long) -1)
                    pmvee_zone_pt = variants[0].regs.rdi;
                pmvee_state_copy_zone.state_copy_start = variants[0].regs.rsi;
                pmvee_state_copy_zone.state_alter_start = variants[0].regs.rdx;
                pmvee_state_copy_zone.state_copy_end = variants[0].regs.r10;

                for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
                {
                    // rdi: source
                    // rsi: destination
                    // rdx: from
                    // r10: size_one
                    // r08: size_two
                    // r09: flags
                    debugf(" [%d] swtich <%d> [ 0x%lx ; 0x%lx )\n", variant_i, variants[0].variantpid,
                            (unsigned long) mp_start, (unsigned long) (mp_start + mp_size));
                    variants[variant_i].regs.rdi = variants[0].variantpid;
                    variants[variant_i].regs.rsi = variants[variant_i].variantpid;
                    variants[variant_i].regs.rdx = mp_start;
                    variants[variant_i].regs.r10 = PMVEE_ZONE_ONE_DEFAULT_SIZE;
                    variants[variant_i].regs.r8 = PMVEE_ZONE_TWO_DEFAULT_SIZE;
                    #ifdef PMVEE_CONFIG_REMOVE_PERMISSIONS
                    variants[variant_i].regs.r9 = PMVEE_FLAGS_DUP_EXEC;
                    #else
                    variants[variant_i].regs.r9 = 0;
                    #endif

                    interaction::write_all_regs(variants[variant_i].variantpid, &variants[variant_i].regs);
                }
                SET_MULTI_EXEC(1);

                result = MVEE_CALL_ALLOW;
                break;
            }
            case __NR_pmvee_check:
            {
                for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
                {
                    debugf(" [%d] check  <%d> [ 0x%lx ; 0x%lx )\n", variant_i, variants[variant_i].variantpid,
                            (unsigned long) mp_start, (unsigned long) (mp_start + mp_size));
                    // rdi: source
                    // rsi: destination
                    // rdx: from
                    // r10: size_one
                    // r08: size_two
                    // r09: flags
                    if (variants[variant_i].rollback_rsp == (unsigned long) -1)
                        variants[variant_i].rollback_rsp = variants[variant_i].regs.rdi;
                    variants[variant_i].regs.rdi = variants[0].variantpid;
                    variants[variant_i].regs.rsi = variants[variant_i].variantpid;
                    variants[variant_i].regs.rdx = mp_start;
                    variants[variant_i].regs.r10 = PMVEE_ZONE_ONE_DEFAULT_SIZE;
                    variants[variant_i].regs.r8 = PMVEE_ZONE_TWO_DEFAULT_SIZE;
                    #ifdef PMVEE_CONFIG_REMOVE_PERMISSIONS
                    variants[variant_i].regs.r9 = PMVEE_FLAGS_DUP_EXEC;
                    #else
                    variants[variant_i].regs.r9 = 0;
                    #endif

                    interaction::write_all_regs(variants[variant_i].variantpid, &variants[variant_i].regs);
                }

                result = MVEE_CALL_ALLOW;
                break;
            }
#endif
        }
    }

    if (result & MVEE_CALL_DENY)
        call_release_syslocks(-1, callnum, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_PRECALL);
    else
        call_release_syslocks(-1, callnum, MVEE_SYSLOCK_PRECALL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_postcall_log_return
-----------------------------------------------------------------------------*/
void monitor::call_postcall_log_return (int variantnum)
{
#ifndef MVEE_BENCHMARK
	mvee_syscall_logger logger;
	long callnum = variants[variantnum].prevcallnum;
	if (callnum >= 0 && callnum < MAX_CALLS)
		logger = monitor::syscall_logger_table[callnum][MVEE_LOG_RETURN];
	else
		logger = &monitor::log_donthave;


	mvee::in_logging_handler = true;
	long result  = call_postcall_get_variant_result(variantnum);
	bool success = call_check_result(result);

	if (!success)
	{
		debugf("%s - %s return: %ld (%s)\n",
			   call_get_variant_pidstr(variantnum).c_str(),
			   mvee::upcase(getTextualSyscall(callnum)).c_str(),
			   result,
			   getTextualErrno(-result));
	}
	else
	{
		(this->*logger)(variantnum);
	}
	mvee::in_logging_handler = false;
#endif
}

/*-----------------------------------------------------------------------------
    call_postcall_return_unsynced
-----------------------------------------------------------------------------*/
long monitor::call_postcall_return_unsynced (int variantnum)
{
    long                 result  = 0;
    mvee_syscall_handler handler;
    long                 callnum = variants[variantnum].prevcallnum;
	
    call_grab_syslocks(variantnum, callnum, MVEE_SYSLOCK_POSTCALL);
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_POSTCALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
		{
            result = (this->*handler)(variantnum);

			if (!(result & MVEE_POSTCALL_HANDLED_UNSYNCED_CALL))
			{
				warnf("FIXME - stijn: POSTCALL handler for syscall %ld (%s) was not unsync-aware\n",
					  callnum, getTextualSyscall(callnum));				
				shutdown(false);				
			}
		}
#ifndef MVEE_BENCHMARK
        else if (handler == MVEE_HANDLER_DONTHAVE)
            warnf("missing POSTCALL handler for syscall: %ld (%s)\n", callnum, getTextualSyscall(callnum));
#endif
    }
	else
	{
		if (callnum == MVEE_INVOKE_LD)
        {
			unsigned long initial_stack = ARG1(variantnum);
			unsigned long ld_entry      = ARG2(variantnum);

#ifndef MVEE_BENCHMARK
			debugf("%s - munmap returned. Transfering control to program interpreter - entry point: 0x" PTRSTR " - initial stack pointer: 0x" PTRSTR "\n",
				   call_get_variant_pidstr(variantnum).c_str(), ld_entry, initial_stack);
#endif

			SP_IN_REGS(variants[variantnum].regs) = initial_stack;
			IP_IN_REGS(variants[variantnum].regs) = ld_entry;
			if (!interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs))
				throw RwRegsFailure(variantnum, "transfer control to interpreter");

#if defined(MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING) || defined(MVEE_ENABLE_PMVEE)
			variants[variantnum].syscall_pointer = (void*) ARG3(variantnum);
#endif
		}
#ifdef MVEE_ENABLE_PMVEE
        else if (callnum == __NR_pmvee_switch)
        {
            if (variants[variantnum].pmvee_state == PMVEE_COMMUNICATION_REQUEST)
            {
                variants[variantnum].pmvee_communication_pt = call_postcall_get_variant_result(variantnum);
                set_mmap_table->map_range(variantnum, variants[variantnum].pmvee_communication_pt, PMVEE_COMMUNICATION_SIZE, MAP_PRIVATE | MAP_ANONYMOUS, PROT_WRITE | PROT_READ, nullptr, 0, nullptr);
                if (variants[variantnum].pmvee_communication_pt == (unsigned long)-1)
                {
                    warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                            variantnum, errno);
                    shutdown(false);
                }
                SETARG1(variantnum, pmvee_state_copy_zone.state_copy_start - pmvee_zone_pt);
            }
            else if (variants[variantnum].pmvee_state == PMVEE_MAPPINGS_REQUEST)
            {
                simple_mappings_pt = call_postcall_get_variant_result(variantnum);
                set_mmap_table->map_range(variantnum, simple_mappings_pt, PMVEE_SIMPLE_MAPPINGS_SIZE, MAP_PRIVATE | MAP_ANONYMOUS, PROT_WRITE | PROT_READ, nullptr, 0, nullptr);
                if (simple_mappings_pt == (unsigned long)-1)
                {
                    warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                            variantnum, errno);
                    shutdown(false);
                }
            }
            else if (variants[variantnum].pmvee_state == PMVEE_ZONE_REQUEST)
            {
                pmvee_copy_zone = call_postcall_get_variant_result(variantnum);
                set_mmap_table->map_range(variantnum, pmvee_copy_zone, PMVEE_ZONE_DEFAULT_SIZE, MAP_PRIVATE | MAP_ANONYMOUS, PROT_WRITE | PROT_READ, nullptr, 0, nullptr);
                if (pmvee_copy_zone == (unsigned long)-1)
                {
                    shutdown(false);
                }
            }
            else if (variants[variantnum].pmvee_state == PMVEE_LIBC_REQUEST ||
                        variants[variantnum].pmvee_state == PMVEE_LIBC_SET ||
                        variants[variantnum].pmvee_state == PMVEE_HANDLER_REQUEST ||
                        variants[variantnum].pmvee_state == PMVEE_REGION_REQUEST ||
                        variants[variantnum].pmvee_state == PMVEE_MIGRATION_INFO_REQUEST)
            {
            }
            else if (variantnum)
            {
                // warnf(" > assumed application size: %ld - %ld = %ld\n", pmvee_state_copy_zone.state_copy_start, pmvee_zone_pt, pmvee_state_copy_zone.state_copy_start - pmvee_zone_pt);
                // warnf(" > assumed alter size: %ld - %ld = %ld\n", pmvee_state_copy_zone.state_alter_start, pmvee_state_copy_zone.state_copy_end, pmvee_state_copy_zone.state_copy_end - pmvee_state_copy_zone.state_alter_start);
                // warnf(" > assumed total size: %ld - %ld = %ld\n", pmvee_state_copy_zone.state_copy_end, pmvee_zone_pt, pmvee_state_copy_zone.state_copy_end - pmvee_zone_pt);
                // warnf(" > 0x%lx - 0x%lx - 0x%lx - 0x%lx\n", pmvee_zone_pt, pmvee_state_copy_zone.state_copy_start, pmvee_state_copy_zone.state_alter_start, pmvee_state_copy_zone.state_copy_end);
                variants[variantnum].regs.rdi = pmvee_state_copy_zone.state_copy_start - pmvee_zone_pt;

                variants[variantnum].regs.rax = variants[variantnum].pmvee_communication_pt;
                variants[variantnum].regs.orig_rax = variants[variantnum].pmvee_communication_pt;
                interaction::write_all_regs(variants[variantnum].variantpid, &variants[variantnum].regs);
            }
            result = MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
        }
#endif
	}

    call_release_syslocks(variantnum, callnum, MVEE_SYSLOCK_POSTCALL | MVEE_SYSLOCK_FULL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_postcall_return
-----------------------------------------------------------------------------*/
long monitor::call_postcall_return ()
{
    long                 result  = 0;
    mvee_syscall_handler handler;
    long                 callnum = variants[0].prevcallnum;
	
    call_grab_syslocks(-1, callnum, MVEE_SYSLOCK_POSTCALL);
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_POSTCALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            result = (this->*handler)(-1);
#ifndef MVEE_BENCHMARK
        if (handler == MVEE_HANDLER_DONTHAVE)
            debugf("WARNING: missing POSTCALL handler for syscall: %ld (%s)\n", callnum, getTextualSyscall(callnum));
#endif
    }
    else
    {
#ifdef MVEE_ENABLE_PMVEE
        if (callnum == __NR_pmvee_switch)
        {
            for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
            {
                if (variants[variant_i].pmvee_state == PMVEE_COMMUNICATION_REQUEST)
                {
                    variants[variant_i].regs.orig_rax = __NR_pmvee_switch;
                    variants[variant_i].regs.rax = __NR_pmvee_switch;
                    variants[variant_i].regs.rdi = PMVEE_COMMUNICATION_REQUEST;
                    variants[variant_i].regs.rsi = 0;
                    variants[variant_i].regs.rdx = 0;
                    variants[variant_i].regs.rip -= 2;

	                if (!interaction::write_all_regs(variants[variant_i].variantpid, &variants[variant_i].regs))
                    {
                        warnf(" > Could not write registers to variant %d for injecting shmat call | erno: %d\n",
                                variant_i, errno);
                        shutdown(false);
                    }
                }
                else
                {
                    debugf(" > assumed application size: %ld - %ld = %ld\n", pmvee_state_copy_zone.state_copy_start, pmvee_zone_pt, pmvee_state_copy_zone.state_copy_start - pmvee_zone_pt);
                    debugf(" > assumed aler size: %ld - %ld = %ld\n", pmvee_state_copy_zone.state_alter_start, pmvee_state_copy_zone.state_copy_start, pmvee_state_copy_zone.state_copy_start - pmvee_state_copy_zone.state_copy_start);
                    debugf(" > assumed total size: %ld - %ld = %ld\n", pmvee_state_copy_zone.state_copy_end, pmvee_zone_pt, pmvee_state_copy_zone.state_copy_end - pmvee_zone_pt);
                    debugf(" > 0x%lx - 0x%lx - 0x%lx - 0x%lx\n", pmvee_zone_pt, pmvee_state_copy_zone.state_copy_start, pmvee_state_copy_zone.state_alter_start, pmvee_state_copy_zone.state_copy_end);
                    variants[variant_i].regs.rdi = pmvee_state_copy_zone.state_copy_start - pmvee_zone_pt;
                    // convert_equivalent_pointer_array();

                    variants[variant_i].regs.rax = variants[variant_i].pmvee_communication_pt;
                    variants[variant_i].regs.orig_rax = variants[variant_i].pmvee_communication_pt;
                    interaction::write_all_regs(variants[variant_i].variantpid, &variants[variant_i].regs);
                }
            }
        }
        if (callnum == __NR_pmvee_check)
        {
            SET_MULTI_EXEC(0);
            debugf("SINGLE-VARIANT ENTER\n");
        }
#endif
    }

    call_release_syslocks(-1, callnum, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_POSTCALL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_shift_args - this function shifts arguments of multiplexed
    calls like sys_ipc and sys_socketcall so we can handle them with the
    AMD64 syscall handlers
-----------------------------------------------------------------------------*/
void monitor::call_shift_args (int variantnum, int cnt)
{
    bool shift_right = (cnt < 0) ? true : false;

    for (int i = 0; i < abs(cnt); ++i)
    {
        if (shift_right)
        {
            unsigned long tmp = ARG6(variantnum);
            ARG6(variantnum) = ARG5(variantnum);
            ARG5(variantnum) = ARG4(variantnum);
            ARG4(variantnum) = ARG3(variantnum);
            ARG3(variantnum) = ARG2(variantnum);
            ARG2(variantnum) = ARG1(variantnum);
            ARG1(variantnum) = tmp;
        }
        else
        {
            unsigned long tmp = ARG1(variantnum);
            ARG1(variantnum) = ARG2(variantnum);
            ARG2(variantnum) = ARG3(variantnum);
            ARG3(variantnum) = ARG4(variantnum);
            ARG4(variantnum) = ARG5(variantnum);
            ARG5(variantnum) = ARG6(variantnum);
            ARG6(variantnum) = tmp;
        }
    }
}

/*-----------------------------------------------------------------------------
    call_grab_locks - centralized lock management for system call handlers

    We enforce the following lock order:
      shm > fd > mman > sig > monitor > global
-----------------------------------------------------------------------------*/
void monitor::call_grab_locks(unsigned char syslocks)
{
    if (syslocks & MVEE_SYSLOCK_SHM)
        set_shm_table->grab_lock();
    if (syslocks & MVEE_SYSLOCK_FD)
        set_fd_table->grab_lock();
    if (syslocks & MVEE_SYSLOCK_MMAN)
        set_mmap_table->grab_lock();
    if (syslocks & MVEE_SYSLOCK_SIG)
        set_sighand_table->grab_lock();
}

/*-----------------------------------------------------------------------------
    call_release_locks
-----------------------------------------------------------------------------*/
void monitor::call_release_locks(unsigned char syslocks)
{
    if (syslocks & MVEE_SYSLOCK_SIG)
        set_sighand_table->release_lock();
    if (syslocks & MVEE_SYSLOCK_MMAN)
        set_mmap_table->release_lock();
    if (syslocks & MVEE_SYSLOCK_FD)
        set_fd_table->release_lock();
    if (syslocks & MVEE_SYSLOCK_SHM)
        set_shm_table->release_lock();
}

/*-----------------------------------------------------------------------------
    call_grab_syslocks
-----------------------------------------------------------------------------*/
void monitor::call_grab_syslocks(int variantnum, unsigned long callnum, unsigned char which)
{
    std::map<unsigned long, unsigned char>::iterator it =
        mvee::syslocks_table.find(callnum);
    if (it != mvee::syslocks_table.end())
    {
        if (it->second & which)
            call_grab_locks(it->second);
    }
    // ridiculous i386 hack to handle socketcall and its many minions
#ifdef __NR_socketcall
    else if (callnum == __NR_socketcall)
    {
        // This relies on the fact that we synchronize on all socket calls!!!!!
        // ORIGARG1 is set in the get_call_type handler
        // before that, we'll find the actual call in ARG1(variantnum)
        unsigned long sock = (variantnum != -1) ? ARG1(variantnum) : ORIGARG1(0);
        long          tmp  = -(*(long*)&sock);
        it = mvee::syslocks_table.find((unsigned long)tmp);
        if (it != mvee::syslocks_table.end())
        {
            if (it->second & which)
                call_grab_locks(it->second);
        }
    }
#endif
}

/*-----------------------------------------------------------------------------
    call_release_syslocks
-----------------------------------------------------------------------------*/
void monitor::call_release_syslocks(int variantnum, unsigned long callnum, unsigned char which)
{
    std::map<unsigned long, unsigned char>::iterator it =
        mvee::syslocks_table.find(callnum);
    if (it != mvee::syslocks_table.end())
    {
        if (it->second & which)
            call_release_locks(it->second);
    }
    // ridiculous i386 hack to handle socketcall and its many minions
#ifdef __NR_socketcall
    else if (callnum == __NR_socketcall)
    {
        if (variantnum < 0)
            variantnum = 0;
        unsigned long sock = ORIGARG1(variantnum);
        long          tmp  = -(*(long*)&sock);
        it = mvee::syslocks_table.find((unsigned long)tmp);
        if (it != mvee::syslocks_table.end())
        {
            if (it->second & which)
                call_release_locks(it->second);
        }
    }
#endif
}

/*-----------------------------------------------------------------------------
    call_wait_all -
-----------------------------------------------------------------------------*/
void monitor::call_wait_all()
{
	interaction::mvee_wait_status status;
    std::vector<unsigned char> synced(mvee::numvariants);
    std::fill(synced.begin(), synced.end(), 0);

    while (1)
    {
        if (should_shutdown)
        {
            shutdown(true);
            return;
        }

		if (!interaction::wait(-1, status) ||
			status.reason != STOP_SIGNAL || 
			status.data != SIGSYSTRAP)
			throw WaitFailure(0, "wait_all failure", status);

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            if (variants[i].variantpid == status.pid)
            {
                synced[i] = 1;
                break;
            }
        }

        if (synced[0] && std::adjacent_find(synced.begin(), synced.end(), std::not_equal_to<unsigned char>()) == synced.end())
            return;
    }
}

/*-----------------------------------------------------------------------------
    call_execute_synced_call -
-----------------------------------------------------------------------------*/
void monitor::call_execute_synced_call(bool at_syscall_exit, unsigned long callnum, std::vector<std::deque<unsigned long> >& call_args)
{
    debugf("Injecting synced syscall: %lu (%s)\n", 
		   callnum, 
		   getTextualSyscall(callnum));

    // If we're at a syscall exit, we should "rewind" the call
    if (at_syscall_exit)
    {
        debugf("We're at a syscall exit. Rewinding call...\n");

        for (int i = 0; i < mvee::numvariants; ++i)
            if (!interaction::write_ip(variants[i].variantpid, IP_IN_REGS(variants[i].regs) - SYSCALL_INS_LEN))
				throw RwRegsFailure(i, "rewind syscall");

        call_resume_all();
        call_wait_all();

        debugf("> call rewinded\n");
    }

    // OK, we're now at a syscall entry. Replace the call args
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        SYSCALL_NO(i) = callnum;

        switch(call_args[i].size())
        {
            case 6: ARG6(i) = call_args[i][5]; /* fallthrough */
            case 5: ARG5(i) = call_args[i][4]; /* fallthrough */
            case 4: ARG4(i) = call_args[i][3]; /* fallthrough */
            case 3: ARG3(i) = call_args[i][2]; /* fallthrough */
            case 2: ARG2(i) = call_args[i][1]; /* fallthrough */
            case 1: ARG1(i) = call_args[i][0]; /* fallthrough */
            default:
                break;
        }

		if (!interaction::write_all_regs(variants[i].variantpid, &variants[i].regs))
			throw RwRegsFailure(i, "inject syscall args");
    }

    debugf("> injected arguments\n");

    call_resume_all();
    call_wait_all();

    debugf("> syscall executed and returned\n");

    for (int i = 0; i < mvee::numvariants; ++i)
        variants[i].return_valid = false;
}
