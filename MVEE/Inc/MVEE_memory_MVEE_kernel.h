/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <sys/user.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_memory.h"

/*-----------------------------------------------------------------------------
    mvee_rw_check_args
-----------------------------------------------------------------------------*/
void mvee_rw_check_args(pid_t source_pid, unsigned long source_addr, pid_t dest_pid, unsigned long dest_addr)
{
    if (!source_addr || !source_pid || !dest_addr || !dest_pid)
    {
        warnf("invalid arguments for PTRACE_EXT_COPYMEM: source -> 0x" PTRSTR " (PID: %d) => dest -> 0x" PTRSTR " (PID: %d)\n",
                    source_addr, source_pid, dest_addr, dest_pid);
    }
}

/*-----------------------------------------------------------------------------
    mvee_rw_copy_data
-----------------------------------------------------------------------------*/
long mvee_rw_copy_data (pid_t source_pid, unsigned long source_addr, pid_t dest_pid, unsigned long dest_addr, ssize_t len)
{
    struct pt_copymem mem;

    mem.source_pid = source_pid;
    mem.source_va  = source_addr;
    mem.dest_pid   = dest_pid;
    mem.dest_va    = dest_addr;
    mem.copy_size  = len;

    mvee_rw_check_args(mem.source_pid, mem.source_va, mem.dest_pid, mem.dest_va);

    long              result = mvee_wrap_ptrace((__ptrace_request)PTRACE_EXT_COPYMEM, 0, 0, &mem);

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (!mvee::in_logging_handler)
        mvee::log_ptrace_op(1, PTRACE_EXT_COPYMEM, len);
#endif

    return result;
}

/*-----------------------------------------------------------------------------
    mvee_rw_write_data - Write data into the VA of the variant process
-----------------------------------------------------------------------------*/
bool mvee_rw_write_data (pid_t variantpid, unsigned long addr, ssize_t datalength, unsigned char* databuf)
{
    struct pt_copymem mem;

    mem.source_pid = mvee::os_getpid();
    mem.source_va  = (unsigned long)databuf;
    mem.dest_pid   = variantpid;
    mem.dest_va    = (unsigned long)addr;
    mem.copy_size  = datalength;

    mvee_rw_check_args(mem.source_pid, mem.source_va, mem.dest_pid, mem.dest_va);

    bool              result = (mvee_wrap_ptrace((__ptrace_request)PTRACE_EXT_COPYMEM, 0, 0, &mem) != -1) ? true : false;

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (!mvee::in_logging_handler)
        mvee::log_ptrace_op(1, PTRACE_EXT_COPYMEM, datalength);
#endif

    return result;
}

/*-----------------------------------------------------------------------------
    mvee_rw_read_data - Read data from the VA of the variant process
-----------------------------------------------------------------------------*/
unsigned char* mvee_rw_read_data(pid_t variantpid, unsigned long addr, ssize_t datalength, int append_zero_byte)
{
    ssize_t           alloc_length = append_zero_byte ? datalength+1 : datalength;
    unsigned char*    result       = new unsigned char[alloc_length];
#ifndef MVEE_BENCHMARK
    // valgrind doesn't know the PTRACE_EXT_* calls so it
    // thinks result never gets initialized...
    //
    // => we do a pointless memset here just to
    // keep valgrind happy
    memset(result, 0, alloc_length);
#else
    result[alloc_length-1] = 0;
#endif
    struct pt_copymem mem;

    mem.source_pid         = variantpid;
    mem.source_va          = addr;
    mem.dest_pid           = mvee::os_getpid();
    mem.dest_va            = (unsigned long)result;
    mem.copy_size          = datalength;

    mvee_rw_check_args(mem.source_pid, mem.source_va, mem.dest_pid, mem.dest_va);

    mvee_wrap_ptrace((__ptrace_request)PTRACE_EXT_COPYMEM, 0, 0, &mem);

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (!mvee::in_logging_handler)
        mvee::log_ptrace_op(1, PTRACE_EXT_COPYMEM, datalength);
#endif

    return result;
}

/*-----------------------------------------------------------------------------
    mvee_rw_read_string - Reads a string from the VA of the variant process

    @param variantpid pid of the variant to read from
    @param addr VA of the start of the string
    @param maxlength    Maximum number of characters to read (optional, can be 0)

    @return Pointer to the string that was read, or NULL if reading was unsuccessful
-----------------------------------------------------------------------------*/
char* mvee_rw_read_string(pid_t variantpid, unsigned long addr, ssize_t maxlength)
{
    char* result = NULL;
    long  ret    = 0;
    char  buffer[PAGE_SIZE];

    if (!addr)
        return result;

    if (maxlength != 0)
    {
        result            = (char*)mvee_rw_read_data(variantpid, addr, maxlength + 1);
        result[maxlength] = '\0';
    }
    else
    {
        struct pt_copystring mem;
        mem.dest_buffer_va   = (unsigned long)buffer;
        mem.dest_buffer_size = PAGE_SIZE;
        mem.source_va        = addr;
        mem.out_string_size  = 0;
        mvee_rw_check_args(variantpid, mem.source_va, mvee::os_getpid(), mem.dest_buffer_va);
        ret                  = mvee_wrap_ptrace((__ptrace_request)PTRACE_EXT_COPYSTRING, variantpid, 0, &mem);

        while (true)
        {
            SAFEDELETE(result);
            if (ret < 0)
            {
                if (errno == ENOMEM)
                {
                    result = new char[mem.out_string_size];
                    mvee_rw_check_args(variantpid, mem.source_va, mvee::os_getpid(), mem.dest_buffer_va);
                    ret    = mvee_wrap_ptrace((__ptrace_request)PTRACE_EXT_COPYSTRING, variantpid, 0, &mem);
#ifdef MVEE_GENERATE_EXTRA_STATS
                    if (!mvee::in_logging_handler)
                        mvee::log_ptrace_op(2, PTRACE_EXT_COPYSTRING, mem.out_string_size);
#endif
                }
                else
                    return NULL;
            }
            else
            {
                result = new char[mem.out_string_size];
                memcpy(result, buffer, mem.out_string_size);
#ifdef MVEE_GENERATE_EXTRA_STATS
                if (!mvee::in_logging_handler)
                    mvee::log_ptrace_op(2, PTRACE_EXT_COPYSTRING, mem.out_string_size);
#endif
                return result;
            }
        }
    }


    return result;
}

/*-----------------------------------------------------------------------------
    mvee_rw_read_struct - Reads a structure of a fixed size from a variant's
    address space.

    @param variantpid pid of the variant to read from
    @param addr Address of the struct (in the variant's address space)
    @param datalength   Length of the struct to read, in bytes
-----------------------------------------------------------------------------*/
bool mvee_rw_read_struct(pid_t variantpid, unsigned long addr, ssize_t datalength, void* buf)
{
    unsigned char* result = mvee_rw_read_data(variantpid, addr, datalength);
    if (!result)
        return false;
    memcpy(buf, result, datalength);
    SAFEDELETEARRAY(result);
    return true;
}
