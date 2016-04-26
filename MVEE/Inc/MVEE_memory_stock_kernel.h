/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */
/*
 * This version of MVEE_memory.cpp is entirely based on the process_vm_[readv|writev]
 * system calls added in linux kernel 3.2. Even though these calls perform
 * much better than standard ptrace calls, I still expect them to be much
 * slower than the MVEE ptrace extensions
 */

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <errno.h>
#include <string.h>
#include "MVEE.h"
#include "MVEE_memory.h"
#include "MVEE_macros.h"

/*-----------------------------------------------------------------------------
    mvee_rw_copy_data - copy data from one process to another. Without the
    MVEE ptrace extension, we have to redirect all copies through the monitor
-----------------------------------------------------------------------------*/
long mvee_rw_copy_data (pid_t source_pid, unsigned long source_addr, pid_t dest_pid, unsigned long dest_addr, ssize_t len)
{
    bool mvee_is_source = false;
    bool mvee_is_dest   = false;

    if (len <= 0)
        return -1;

    if (source_pid == mvee::os_getpid() || source_pid == mvee::os_gettid())
        mvee_is_source = true;
    if (dest_pid == mvee::os_getpid() || dest_pid == mvee::os_gettid())
        mvee_is_dest = true;

    if (mvee_is_source)
    {
        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base  = (void*)source_addr;
        local[0].iov_len   = len;
        remote[0].iov_base = (void*)dest_addr;
        remote[0].iov_len  = len;

        ssize_t      nwritten = process_vm_writev(dest_pid, local, 1, remote, 1, 0);
        if (nwritten != len)
            warnf("mvee_rw_copy_data failed. tried to write %d bytes - actually wrote %d bytes\n", len, nwritten);

#ifdef MVEE_GENERATE_EXTRA_STATS
        if (!mvee::in_logging_handler)
            mvee::log_ptrace_op(1, PROCESS_VM_WRITEV, nwritten);
#endif

        return nwritten;
    }
    else if (mvee_is_dest)
    {
        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base  = (void*)dest_addr;
        local[0].iov_len   = len;
        remote[0].iov_base = (void*)source_addr;
        remote[0].iov_len  = len;

        ssize_t      nread = process_vm_readv(source_pid, local, 1, remote, 1, 0);
        if (nread != len)
            warnf("mvee_rw_copy_data failed. tried to read %d bytes - actually read %d bytes\n", len, nread);

#ifdef MVEE_GENERATE_EXTRA_STATS
        if (!mvee::in_logging_handler)
            mvee::log_ptrace_op(1, PROCESS_VM_READV, nread);
#endif

        return nread;
    }
    else
    {
        // this is awkward...
        unsigned char* buf   = mvee_rw_safe_alloc(len);
        if (!buf)
            return -1;

        struct iovec   local[1];
        struct iovec   remote[1];

        local[0].iov_base  = buf;
        local[0].iov_len   = len;
        remote[0].iov_base = (void*)source_addr;
        remote[0].iov_len  = len;

        ssize_t        nread = process_vm_readv(source_pid, local, 1, remote, 1, 0);
        if (nread != len)
        {
            warnf("mvee_rw_copy_data failed. tried to read %d bytes - actually read %d bytes (errno: %s)\n", len, nread, strerror(errno));
            SAFEDELETEARRAY(buf);
            return -1;
        }

#ifdef MVEE_GENERATE_EXTRA_STATS
        if (!mvee::in_logging_handler)
            mvee::log_ptrace_op(1, PROCESS_VM_READV, nread);
#endif


        remote[0].iov_base = (void*)dest_addr;
        nread              = process_vm_writev(dest_pid, local, 1, remote, 1, 0);

        if (nread != len)
            warnf("mvee_rw_copy_data failed. tried to write %d bytes - actually wrote %d bytes\n", len, nread);

#ifdef MVEE_GENERATE_EXTRA_STATS
        if (!mvee::in_logging_handler)
            mvee::log_ptrace_op(1, PROCESS_VM_WRITEV, nread);
#endif

        SAFEDELETEARRAY(buf);
        return nread;
    }
}

/*-----------------------------------------------------------------------------
    mvee_rw_copy_string -
-----------------------------------------------------------------------------*/
bool mvee_rw_copy_string (pid_t source_pid, unsigned long source_addr, pid_t dest_pid, unsigned long dest_addr)
{
    // We REALLY shouldn't use this one without the PTRACE_EXT_COPYSTRING extension
    bool mvee_is_source = false;
    bool mvee_is_dest   = false;

    if (source_pid == mvee::os_getpid() || source_pid == mvee::os_gettid())
        mvee_is_source = true;
    if (dest_pid == mvee::os_getpid() || dest_pid == mvee::os_gettid())
        mvee_is_dest = true;

    if (mvee_is_source)
    {
        long bytes_copied = mvee_rw_copy_data(source_pid, source_addr, dest_pid, dest_addr, strlen((char*)source_addr) + 1);

        if (bytes_copied > 0 && (unsigned long)bytes_copied == strlen((char*)source_addr) + 1)
            return true;
        return false;
    }
    else
    {
        char* str = mvee_rw_read_string(source_pid, source_addr, 0);
        if (str)
        {
            if (mvee_is_dest)
            {
                memcpy((void*)dest_addr, str, strlen(str) + 1);
                SAFEDELETEARRAY(str);
                return true;
            }
            else
            {
                bool result = mvee_rw_write_data(dest_pid, dest_addr, strlen(str) + 1, (unsigned char*)str);
                SAFEDELETEARRAY(str);
                return result;
            }
        }
    }
    return false;

}

/*-----------------------------------------------------------------------------
    mvee_rw_write_data - write databuf to target variant's address space - we
    probably don't need PTRACE_EXT_COPYMEM for good performance here
-----------------------------------------------------------------------------*/
bool mvee_rw_write_data (pid_t variantpid, unsigned long addr, ssize_t datalength, unsigned char* databuf)
{
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base  = (void*)databuf;
    local[0].iov_len   = datalength;
    remote[0].iov_base = (void*)addr;
    remote[0].iov_len  = datalength;

    ssize_t      nwritten = process_vm_writev(variantpid, local, 1, remote, 1, 0);

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (!mvee::in_logging_handler)
        mvee::log_ptrace_op(1, PROCESS_VM_WRITEV, nwritten);
#endif

	if (nwritten != datalength)
		warnf("mvee_rw_copy_data failed. tried to write %d bytes - actually wrote %d bytes\n", datalength, nwritten);


    if (nwritten != -1)
        return true;
    return false;
}

/*-----------------------------------------------------------------------------
    mvee_rw_read_data - same as above. This should be pretty fast with the
    stock 3.2+ kernel
-----------------------------------------------------------------------------*/
unsigned char* mvee_rw_read_data (pid_t variantpid, unsigned long addr, ssize_t datalength, int append_zero_byte)
{
    if (datalength <= 0)
        return NULL;

    unsigned char* buf   = mvee_rw_safe_alloc(datalength + (append_zero_byte ? 1 : 0));
    if (!buf)
        return NULL;

    if (append_zero_byte)
        buf[datalength] = '\0';

    struct iovec   local[1];
    struct iovec   remote[1];

    local[0].iov_base  = buf;
    local[0].iov_len   = datalength;
    remote[0].iov_base = (void*)addr;
    remote[0].iov_len  = datalength;

    ssize_t        nread = process_vm_readv(variantpid, local, 1, remote, 1, 0);
    if (nread != datalength)
    {
        SAFEDELETEARRAY(buf);
        warnf("mvee_rw_read_data failed!!! nread: %d - datalen: %d\n", nread, datalength);
        return NULL;
    }

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (!mvee::in_logging_handler)
        mvee::log_ptrace_op(1, PROCESS_VM_READV, nread);
#endif


    return buf;
}

/*-----------------------------------------------------------------------------
    mvee_rw_read_string - and this is where the stock kernel really sucks...
    If we don't know the size of the string, we have to copy it word
    by word...
-----------------------------------------------------------------------------*/
char* mvee_rw_read_string (pid_t variantpid, unsigned long addr, ssize_t maxlength)
{
    char* result = NULL;

    if (maxlength != 0)
    {
        result            = (char*)mvee_rw_read_data(variantpid, addr, maxlength + 1);
        result[maxlength] = '\0';
    }
    else
    {
        std::string  tmpstr = "";
        int          pos    = 0;
        unsigned int i;

        while(true)
        {
            long tmp = mvee_wrap_ptrace(PTRACE_PEEKDATA,
                                        variantpid, addr + (pos++) * sizeof(long), NULL);

#ifdef MVEE_GENERATE_EXTRA_STATS
            if (!mvee::in_logging_handler)
                mvee::log_ptrace_op(1, PTRACE_PEEKDATA, sizeof(long));
#endif
            if (tmp == -1)
                return NULL;

            // extract bytes
            for (i = 0; i < sizeof(long); ++i)
            {
                char c = (char)((tmp >> (i*8)) & 0xFF);
                if (c)
                    tmpstr += c;
                else
                    break;
            }

            if (i < sizeof(long))
                break;
        }

        result = mvee::strdup(tmpstr.c_str());
    }

    return result;
}

/*-----------------------------------------------------------------------------
    mvee_rw_read_struct - read directly into buf
-----------------------------------------------------------------------------*/
bool mvee_rw_read_struct (pid_t variantpid, unsigned long addr, ssize_t datalength, void* buf)
{
    struct iovec local[1];
    struct iovec remote[1];

    if (datalength <= 0)
        return -1;

    local[0].iov_base  = buf;
    local[0].iov_len   = datalength;
    remote[0].iov_base = (void*)addr;
    remote[0].iov_len  = datalength;

    ssize_t      nread = process_vm_readv(variantpid, local, 1, remote, 1, 0);

#ifdef MVEE_GENERATE_EXTRA_STATS
    if (!mvee::in_logging_handler)
        mvee::log_ptrace_op(1, PROCESS_VM_READV, nread);
#endif


    if (nread != -1)
        return true;

    memset(buf, 0, datalength);
    return false;
}
