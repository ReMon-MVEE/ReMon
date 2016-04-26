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
//
// *****************************************************************************

#include <memory>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <string.h>
#include <sstream>
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
    call_resume_all - Resumes all variants attached to the current monitor thread.
-----------------------------------------------------------------------------*/
void monitor::call_resume_all()
{
    for (int i = 0; i < mvee::numvariants; ++i)
        mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
}

/*-----------------------------------------------------------------------------
    call_resume_fake_syscall - Resumes all variants attached to the current monitor
    thread in case the current syscall is a fake syscall.
-----------------------------------------------------------------------------*/
void monitor::call_resume_fake_syscall()
{
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        // let the variants execute a dummy getpid syscall instead
        WRITE_SYSCALL_NO(i, __NR_getpid);
        mvee_wrap_ptrace(PTRACE_SYSCALL, variants[i].variantpid, 0, NULL);
    }
}

/*-----------------------------------------------------------------------------
    call_precall_get_call_type - called at every syscall entrance. Determines
    whether or not a call is synchronized.
-----------------------------------------------------------------------------*/
unsigned char monitor::call_precall_get_call_type (int variantnum, long callnum)
{
#ifdef MVEE_MINIMAL_MONITORING
    return MVEE_CALL_TYPE_UNSYNCED;
#else

    mvee_syscall_handler handler;
    unsigned char        result = MVEE_CALL_TYPE_NORMAL;

    call_grab_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

    if (callnum >= 0 && callnum < MAX_CALLS)
    {
		if (variants[variantnum].fast_forward_to_entry_point)
		{
			result = MVEE_CALL_TYPE_UNSYNCED;
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
#ifdef MVEE_CHECK_SYNC_PRIMITIVES
			case MVEE_SET_SYNC_PRIMITIVES_PTR:
#endif
			case MVEE_INVOKE_LD:
			case MVEE_RUNS_UNDER_MVEE_CONTROL:
            {
                result = MVEE_CALL_TYPE_UNSYNCED;
                break;
            }

			default:
			{
				if (variants[variantnum].fast_forward_to_entry_point)
				{
					warnf("Don't have an unsynced call handler for call: %d (%s)\n",
						  callnum, getTextualSyscall(callnum));
					shutdown(false);
					break;
				}
			}
        }
    }

    call_release_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
    return result;
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

#ifdef MVEE_MINIMAL_MONITORING
    return result;
#else

    long                 callnum;
    mvee_syscall_handler handler;

    // We already know that the syscall number matches so this is safe
    callnum = variants[0].callnum;
    call_grab_syslocks(-1, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

    if (callnum >= 0 && callnum < MAX_CALLS)
    {
#ifndef MVEE_BENCHMARK
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = true;
    #endif
        handler                  = monitor::syscall_logger_table[callnum][MVEE_LOG_ARGS];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            (this->*handler)(-1);
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = false;
    #endif
#endif
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_PRECALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            result = (this->*handler)(-1);
        else if (handler == MVEE_HANDLER_DONTHAVE)
        {
            warnf("ERROR: missing PRECALL handler for syscall: %d (%s)\n", callnum, getTextualSyscall(callnum));
            shutdown(false);
        }
    }

    if (result & MVEE_PRECALL_CALL_DENY)
        call_release_syslocks(-1, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);

    return result;

#endif
}

/*-----------------------------------------------------------------------------
    call_call_dispatch_unsynced - dispatches an unsynced call.
    unsynced syscalls don't have a precall handler so we grab the syslocks
    here and release them if the call doesn't really get dispatched
-----------------------------------------------------------------------------*/
long monitor::call_call_dispatch_unsynced (int variantnum)
{
#ifdef MVEE_MINIMAL_MONITORING
    long                 callnum = variants[variantnum].callnum;

    if (callnum == MVEE_RUNS_UNDER_MVEE_CONTROL)
    {
        variants[variantnum].should_sync_ptr   = ARG1(variantnum);
        variants[variantnum].infinite_loop_ptr = ARG2(variantnum);
    }

    return 0;
#else

    long                 result  = 0;
    mvee_syscall_handler handler;
    long                 callnum = variants[variantnum].callnum;
    call_grab_syslocks(variantnum, callnum, MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_FULL);
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
#ifndef MVEE_BENCHMARK
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = true;
    #endif
        handler                  = monitor::syscall_logger_table[callnum][MVEE_LOG_ARGS];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            (this->*handler)(variantnum);
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = false;
    #endif
#endif
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_CALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
		{
            result = (this->*handler)(variantnum);

			if ((result & MVEE_CALL_ALLOW) && !(result & MVEE_CALL_HANDLED_UNSYNCED_CALL))
			{
				warnf("FIXME - stijn: CALL handler for syscall %d (%s) was not unsync-aware\n",
					  callnum, getTextualSyscall(callnum));				
				shutdown(false);				
			}

		}
#ifndef MVEE_BENCHMARK
        if (handler == MVEE_HANDLER_DONTHAVE)
            warnf("missing CALL handler for syscall: %d (%s)\n", callnum, getTextualSyscall(callnum));
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
                //
                // mvee_num_variants = (ushort)syscall(MVEE_GET_THREAD_NUM,
                // (ushort*)&mvee_variant_num);
                //
				
				// dirty hack: we need to write an unsigned short-sized value
				// but ptrace always writes a full word
				mvee_rw_write_ushort(variants[variantnum].variantpid, ARG1(variantnum), variantnum);
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
                char*         sym      = mvee_rw_read_string(variants[variantnum].variantpid, ARG1(variantnum));
                if (!sym)
                {
                    warnf("couldn't read sym\n");
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    break;
                }
                char*         lib_name = mvee_rw_read_string(variants[variantnum].variantpid, ARG2(variantnum));
                if (!lib_name)
                {
                    warnf("couldn't read lib_name\n");
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                    break;
                }

                unsigned long ptr      = set_mmap_table->resolve_symbol(variantnum, (const char*)sym, (const char*)lib_name);

                SAFEDELETEARRAY(sym);
                mvee_rw_write_data(variants[variantnum].variantpid, ARG3(variantnum), sizeof(unsigned long), (unsigned char*)&ptr);
                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                break;
            }

            case MVEE_INVOKE_LD:
            {
#ifndef MVEE_BENCHMARK
                debugf("Variant %d requested control transfer to manually mapped program interpreter\n", variantnum);
#endif

                // force an munmap of the MVEE_LD_loader program - the loader is compiled
                // to always be at base address 0x08048000 regardless of ALSR
				unsigned long loader_base, loader_size;
				if (set_mmap_table->get_ld_loader_bounds(variantnum, loader_base, loader_size))
				{
					WRITE_SYSCALL_NO(variantnum, __NR_munmap);
					SETARG1(variantnum, loader_base);
					SETARG2(variantnum, loader_size);
#ifndef MVEE_BENCHMARK
					debugf("variant %d -> unmapping loader at: 0x" PTRSTR "-0x" PTRSTR "\n",
						   variantnum,
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

				if (ARG3(variantnum))
					mvee_rw_write_ushort(variants[variantnum].variantpid, ARG3(variantnum), mvee::numvariants);

				if (ARG4(variantnum))
					mvee_rw_write_ushort(variants[variantnum].variantpid, ARG4(variantnum), variantnum);

				if (variantnum == 0 && ARG5(variantnum))
					mvee_rw_write_uchar(variants[variantnum].variantpid, ARG5(variantnum), 1);

#ifdef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
#else
                if (is_program_multithreaded())
                    enable_sync();

                result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(1);
#endif
                break;
            }


			//
			// 
			//
			default:
			{
				warnf("Don't have an unsynced call handler for call: %d (%s)\n",
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
#endif
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
            warnf("missing CALL handler for syscall: %d (%s)\n", callnum, getTextualSyscall(callnum));
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

                if (buffer_type == MVEE_LIBC_ATOMIC_BUFFER
                    || buffer_type == MVEE_LIBC_ATOMIC_BUFFER_HIDDEN)
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
                        info                = new _shm_info();
                        atomic_buffer       = info;
                        requested_slot_size = sizeof(unsigned long);
                        alloc_size          = requested_slot_size * SHARED_QUEUE_SLOTS / (mvee::demo_has_many_threads ? 64 : 1);
						if (buffer_type == MVEE_LIBC_ATOMIC_BUFFER_HIDDEN)
							atomic_buffer_hidden = true;
                    }
                    else
                    {
                        info = atomic_buffer;
                    }
                }
				else if (buffer_type == MVEE_LIBC_HIDDEN_BUFFER_ARRAY)
				{
					debugf("Requested Hidden Buffer Array\n");

					if (!variants[0].hidden_buffer_array)
					{
						std::vector<unsigned long> addresses(mvee::numvariants);
						std::fill(addresses.begin(), addresses.end(), NULL);
						register_hidden_buffer(0, NULL, addresses);						
					}

					// deny the call and return id of the buffer
                    for (i = 0; i < mvee::numvariants; ++i)
                        variants[i].extended_value = (long)variants[i].hidden_buffer_array_id;
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;

					debugf("Variants requested the id for the hidden buffer array\n");
					break;
				}
				else if (buffer_type == MVEE_IPMON_BUFFER)
				{
					debugf("Requested IP-MON Replication Buffer\n");
					if (ipmon_buffer) 
					{
						debugf("MVEE_IPMON_BUFFER already initialized\n");
						for (i = 0; i < mvee::numvariants; ++i)
							variants[i].extended_value = (long)ipmon_buffer->id;
						result = MVEE_CALL_DENY | MVEE_CALL_RETURN_EXTENDED_VALUE;
						break;
					}

					ipmon_buffer = new _shm_info();

					if (!mvee::os_alloc_sysv_sharedmem(MVEE_IPMON_BUFFER_SIZE / (mvee::demo_has_many_threads ? 64 : 1),  &(ipmon_buffer->id), &(ipmon_buffer->sz), &(ipmon_buffer->ptr)))
					{
						result = MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(1);
						break;
					}

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
                        if (ARG3(i))
							mvee_rw_write_uint(variants[i].variantpid, ARG3(i), *size_ptr);

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

                if (ARG1(0) == MVEE_LIBC_ATOMIC_BUFFER
                    || ARG1(0) == MVEE_LIBC_ATOMIC_BUFFER_HIDDEN)
                {
                    info = atomic_buffer;
                }
                else if (ARG1(0) == MVEE_IPMON_BUFFER)
                {
                    debugf("flushing ipmon_buffer: " PTRSTR "\n", ipmon_buffer);
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

            case MVEE_ALL_HEAPS_ALIGNED:
            {
                for (int i = 0; i < mvee::numvariants; ++i)
                {
                    if (variants[i].last_mmap_result & (HEAP_MAX_SIZE - 1))
                    {
                        result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
                        break;
                    }
                }
                if (!result)
                    result = MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(1);
                break;
            }
        }
    }

    if (result & MVEE_CALL_DENY)
        call_release_syslocks(-1, callnum, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_PRECALL);
    else
        call_release_syslocks(-1, callnum, MVEE_SYSLOCK_PRECALL);
    return result;
}

/*-----------------------------------------------------------------------------
    call_postcall_return_unsynced
-----------------------------------------------------------------------------*/
long monitor::call_postcall_return_unsynced (int variantnum)
{
    long                 result  = 0;

#ifdef MVEE_MINIMAL_MONITORING
    return result;
#else
    mvee_syscall_handler handler;
    long                 callnum = variants[variantnum].prevcallnum;
    call_grab_syslocks(variantnum, callnum, MVEE_SYSLOCK_POSTCALL);
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
#ifndef MVEE_BENCHMARK
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = true;
    #endif
        handler                  = monitor::syscall_logger_table[callnum][MVEE_LOG_RETURN];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            (this->*handler)(variantnum);		
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = false;
    #endif
#endif
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_POSTCALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
		{
            result = (this->*handler)(variantnum);

			if (!(result & MVEE_POSTCALL_HANDLED_UNSYNCED_CALL))
			{
				warnf("FIXME - stijn: POSTCALL handler for syscall %d (%s) was not unsync-aware\n",
					  callnum, getTextualSyscall(callnum));				
				shutdown(false);				
			}
		}
#ifndef MVEE_BENCHMARK
        else if (handler == MVEE_HANDLER_DONTHAVE)
            warnf("missing POSTCALL handler for syscall: %d (%s)\n", callnum, getTextualSyscall(callnum));
#endif
    }
	else
	{
		if (callnum == MVEE_INVOKE_LD)
        {
			unsigned long initial_stack = ARG1(variantnum);
			unsigned long ld_entry      = ARG2(variantnum);

#ifndef MVEE_BENCHMARK
			debugf("variant %d -> munmap returned. Transfering control to program interpreter - entry point: 0x" PTRSTR " - initial stack pointer: 0x" PTRSTR "\n",
				   variantnum, ld_entry, initial_stack);
#endif

			WRITE_SP(variantnum, initial_stack);
			WRITE_IP(variantnum, ld_entry);
		}
	}

    call_release_syslocks(variantnum, callnum, MVEE_SYSLOCK_POSTCALL | MVEE_SYSLOCK_FULL);
    return result;
#endif
}

/*-----------------------------------------------------------------------------
    call_postcall_return
-----------------------------------------------------------------------------*/
long monitor::call_postcall_return ()
{
    long                 result  = 0;

#ifdef MVEE_MINIMAL_MONITORING
    return result;
#else
    mvee_syscall_handler handler;

    long                 callnum = variants[0].prevcallnum;
    call_grab_syslocks(-1, callnum, MVEE_SYSLOCK_POSTCALL);
    if (callnum >= 0 && callnum < MAX_CALLS)
    {
#ifndef MVEE_BENCHMARK
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = true;
    #endif
        handler                  = monitor::syscall_logger_table[callnum][MVEE_LOG_RETURN];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            (this->*handler)(-1);
    #ifdef MVEE_GENERATE_EXTRA_STATS
        mvee::in_logging_handler = false;
    #endif
#endif
        handler                  = monitor::syscall_handler_table[callnum][MVEE_HANDLE_POSTCALL];
        if (handler != MVEE_HANDLER_DONTHAVE && handler != MVEE_HANDLER_DONTNEED)
            result = (this->*handler)(-1);
#ifndef MVEE_BENCHMARK
        if (handler == MVEE_HANDLER_DONTHAVE)
            debugf("WARNING: missing POSTCALL handler for syscall: %d (%s)\n", callnum, getTextualSyscall(callnum));
#endif
    }

    call_release_syslocks(-1, callnum, MVEE_SYSLOCK_FULL | MVEE_SYSLOCK_POSTCALL);
    return result;
#endif
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
    pid_t                      variant;
    int                        status;
    std::vector<unsigned char> synced(mvee::numvariants);
    std::fill(synced.begin(), synced.end(), 0);

    while (1)
    {
        if (should_shutdown)
        {
            shutdown(true);
            return;
        }

        variant = wait4(-1, &status, __WALL | WUNTRACED | __WNOTHREAD, NULL);

        if (variant == -1)
            continue;

        if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSYSTRAP))
        {
            warnf("call_wait_all error: expected SIGSYSTRAP stop for variant: %d but got status: 0x%08x\n",
                        variant, status);
            shutdown(false);
            break;
        }

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            if (variants[i].variantpid == variant)
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
    debugf("> injecting synced syscall: %d (%s)\n", callnum, getTextualSyscall(callnum));

    // If we're at a syscall exit, we should "rewind" the call
    if (at_syscall_exit)
    {
        debugf("> we're at a syscall exit. Rewinding call...\n");

        for (int i = 0; i < mvee::numvariants; ++i)
            WRITE_IP(i, IP(variants[i].regs) - 2);

        call_resume_all();
        call_wait_all();

        debugf("> call rewinded\n");
    }

    // OK, we're now at a syscall entry. Replace the call args
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        SYSCALL_NO(variants[i].regs) = callnum;

        switch(call_args[i].size())
        {
            case 6: ARG6(i) = call_args[i][5];
            case 5: ARG5(i) = call_args[i][4];
            case 4: ARG4(i) = call_args[i][3];
            case 3: ARG3(i) = call_args[i][2];
            case 2: ARG2(i) = call_args[i][1];
            case 1: ARG1(i) = call_args[i][0];
            default:
                break;
        }

        mvee_wrap_ptrace(PTRACE_SETREGS, variants[i].variantpid, 0, &variants[i].regs);
    }

    debugf("> injected arguments\n");

    call_resume_all();
    call_wait_all();

    debugf("> syscall executed and returned\n");

    for (int i = 0; i < mvee::numvariants; ++i)
        variants[i].return_valid = false;
}
