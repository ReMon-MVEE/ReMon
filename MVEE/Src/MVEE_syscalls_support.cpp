/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/un.h>
#include <string.h>
#include <signal.h>
#include <sstream>
#include <net/if.h>
#include <iomanip>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_logging.h"
#include "MVEE_memory.h"
#include "MVEE_macros.h"
#include "MVEE_signals.h"
#include "MVEE_mman.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    call_check_regs
-----------------------------------------------------------------------------*/
void monitor::call_check_regs (int variantnum)
{
    if (!variants[variantnum].regs_valid)
    {
        if (!interaction::read_all_regs(variants[variantnum].variantpid, 
										&variants[variantnum].regs))
		{
			warnf("%s - couldn't read regs\n", 
				  call_get_variant_pidstr(variantnum).c_str());
			return;
		}
		variants[variantnum].regs_valid = true;
    }
}

/*-----------------------------------------------------------------------------
    call_check_result - Checks the result value of a system call and
    returns false if the result value indicates an error.
-----------------------------------------------------------------------------*/
bool monitor::call_check_result(long int result)
{
    /*
     * from unix/sysv/linux/sysdep.h:
     * Linux uses a negative return value to indicate syscall errors,
     * unlike most Unices, which use the condition codes' carry flag.
     * Since version 2.1 the return value of a system call might be
     * negative even if the call succeeded.  E.g., the `lseek' system call
     * might return a large offset.  Therefore we must not anymore test
     * for < 0, but test for a real error by making sure the value in %eax
     * is a real error number.  Linus said he will make sure the no syscall
     * returns a value in -1 .. -4095 as a valid result so we can savely
     * test with -4095.
     */
    return ((result > -1) || (result < -4095)) ? true : false;
}

/*-----------------------------------------------------------------------------
    call_postcall_all_syscalls_succeeded - On a syscall return, checks if
    the current syscall has succeeded in all variants.
-----------------------------------------------------------------------------*/
bool monitor::call_postcall_all_syscalls_succeeded()
{
    // get results
	bool result = true;
    std::vector<unsigned long> results = call_postcall_get_result_vector();

    // check for error codes
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (!call_check_result(results[i]))
        {
			result = false;
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    call_postcall_get_variant_result
-----------------------------------------------------------------------------*/
long monitor::call_postcall_get_variant_result(int variantnum)
{
    if (!variants[variantnum].return_valid)
    {
		unsigned long tmp;
		if (interaction::fetch_syscall_return(variants[variantnum].variantpid, tmp))
		{
			variants[variantnum].return_valid = 1;
			variants[variantnum].return_value = (long) tmp;
		}
		else
			warnf("%s - couldn't read syscall result\n",
				  call_get_variant_pidstr(variantnum).c_str());
    }
    return variants[variantnum].return_value;
}

/*-----------------------------------------------------------------------------
    call_postcall_set_variant_result
-----------------------------------------------------------------------------*/
void monitor::call_postcall_set_variant_result(int variantnum, unsigned long result)
{
    variants[variantnum].return_valid = 1;
    variants[variantnum].return_value = result;
	if (!interaction::write_syscall_return(variants[variantnum].variantpid, result))
		warnf("%s - couldn't write syscall result\n",
			  call_get_variant_pidstr(variantnum).c_str());
}

/*-----------------------------------------------------------------------------
    call_postcall_get_result_vector - On a syscall return, fills an array with the result of
    the current syscall for all variants.

    @param results  Array with for each variant, the result of the syscall in that variant
-----------------------------------------------------------------------------*/
std::vector<unsigned long> monitor::call_postcall_get_result_vector()
{
    std::vector<unsigned long> results(mvee::numvariants);
    if (state == STATE_IN_MASTERCALL)
    {
        std::fill(results.begin(), results.end(), call_postcall_get_variant_result(0));
    }
    else
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            results[i] = call_postcall_get_variant_result(i);
    }
    return results;
}

/*-----------------------------------------------------------------------------
    call_compare_variant_strings - Compares strings in the address spaces of the
    variants.

    @param strings Array with for each variant, the pointer to the string in the address space of that variant
    @param maxlength    Maximum number of characters to read and compare

    @return true if all strings are equal (case sensitive), false otherwise
-----------------------------------------------------------------------------*/
bool monitor::call_compare_variant_strings(std::vector<const char*>& stringptrs, size_t maxlength)
{
	std::string str1, str2;
    bool  match = true;

    // compare each string with the previous one
    for (int i = 0; i < mvee::numvariants - 1; ++i)
    {
        str1 = str2;

        if (str1.length() == 0)
            str1 = rw::read_string(variants[i].variantpid, (void*) stringptrs[i], maxlength);
        str2 = rw::read_string(variants[i+1].variantpid, (void*) stringptrs[i + 1], maxlength);

        if (str1.length() == 0 || str2.length() == 0)
        {
            match = false;
            break;
        }
        else if (str1 != str2)
        {
            match = false;
            break;
        }
    }

    return match;
}

/*-----------------------------------------------------------------------------
    compare_variant_buffers - Compares the bytes in buffers in the address spaces
    of the variants.

    @param buffers  Array with for each variant, the pointer to the buffer in the address space of that variant
    @param size Size in bytes of the buffers

    @return true if the contents of all buffers are equal, false otherwise
-----------------------------------------------------------------------------*/
bool monitor::call_compare_variant_buffers(std::vector<const unsigned char*>& bufferptrs, size_t size)
{
    unsigned char* buf1  = NULL;
    unsigned char* buf2  = NULL;
    bool           match = true;

    // compare each buffer with the previous one
    for (int i = 0; i < mvee::numvariants - 1; ++i)
    {
        SAFEDELETEARRAY(buf1);
        buf1 = buf2;

        if (buf1 == NULL)
            buf1 = rw::read_data(variants[i].variantpid, (void*) bufferptrs[i], size);
        buf2 = rw::read_data(variants[i+1].variantpid, (void*) bufferptrs[i + 1], size);

        if (!buf1 || !buf2)
        {
            match = false;
            break;
        }
        else if (memcmp(buf1, buf2, size) != 0)
        {
            match = false;
            break;
        }
    }

    SAFEDELETEARRAY(buf1);
    SAFEDELETEARRAY(buf2);
    return match;
}

/*-----------------------------------------------------------------------------
    call_compare_wait_pids - Compares the pid arguments of a sys_waitpid or
    sys_wait4 call of the variants.

    @param pids Array with for each variant, the value of the pid argument

    @return true if all PIDs match, false otherwise
-----------------------------------------------------------------------------*/
bool monitor::call_compare_wait_pids(std::vector<pid_t>& pids)
{
    if (pids[0] < -1)
        // no support for process group IDs yet
        return false;
    else
    {
        for (int i = 0; i < mvee::numvariants - 1; ++i)
        {
            if (pids[i] != pids[i + 1])
                return false;
        }
        return true;
    }
}

/*-----------------------------------------------------------------------------
    call_compare_signal_handlers - Compares signal handler arguments of the variants
    (handler for sys_signal, sa_handler for sys_sigaction and sys_rt_sigaction).

    @param handlers Array with for each variant, the value of the signal handler argument

    @return true if all handlers are equivalent, false otherwise
-----------------------------------------------------------------------------*/
bool monitor::call_compare_signal_handlers(std::vector<unsigned long>& handlers)
{
    // only compare for "ignore" or "default" handlers, in all other cases the
    // handlers are pointers to functions which will probable differ among the
    // variants, so we can't compare these
    if ((sighandler_t)handlers[0] == SIG_IGN
        || (sighandler_t)handlers[0] == SIG_DFL)
    {
        for (int i = 0; i < mvee::numvariants - 1; ++i)
        {
            if (handlers[i] != handlers[i + 1])
                return false;
        }
    }
    return true;
}

/*-----------------------------------------------------------------------------
    call_compare_sigactions - Compares the sa_handler and sa_flags fields of the
    sigaction arguments of a sys_sigaction or sys_rt_sigaction call of the
    variants.

    @param handlers Array with for each variant, the value of the sa_handler field
    @param sa_flags Array with for each variant, the value of the sa_flags field

    @return true if all fields are equivalent, false otherwise
-----------------------------------------------------------------------------*/
bool monitor::call_compare_sigactions(std::vector<unsigned long>& handlers, std::vector<unsigned long>& sa_flags)
{
    // compare sa_flags
    for (int i = 0; i < mvee::numvariants - 1; ++i)
    {
        if (sa_flags[i] != sa_flags[i + 1])
            return false;
    }

    // if SA_SIGINFO is specified, sa_sigaction is used instead of sa_handler
    if ( (sa_flags[0] & SA_SIGINFO) == 0)
    {
        if (!call_compare_signal_handlers(handlers))
            return false;
    }

    return true;
}

/*-----------------------------------------------------------------------------
    call_compare_sigsets - compares two sigsets
-----------------------------------------------------------------------------*/
bool monitor::call_compare_sigsets(sigset_t* set1, sigset_t* set2)
{
    for (int i = 1; i < SIGRTMAX+1; ++i)
    {
        if ((sigismember(set1, i) && !sigismember(set2, i))
            || (!sigismember(set1, i) && sigismember(set2, i)))
        {
            warnf("sigset not equal: %d - %s <=> %s\n",
                        i, getTextualSigSet(*set1).c_str(), getTextualSigSet(*set2).c_str());
            return false;
        }
    }
    return true;
}

/*-----------------------------------------------------------------------------
  call_compare_pointers - check whether all pointers are either NULL
  or pointers to valid memory regions.

  Returns 0 for OK, 1 for NULL-NONNULL mismatch, 2 for invalid region
-----------------------------------------------------------------------------*/
unsigned char monitor::call_compare_pointers(std::vector<void*>& pointers)
{
    int i;
    for (i = 0; i < mvee::numvariants; ++i)
        if (pointers[i])
            break;

    // all NULL, this is OK
    if (i >= mvee::numvariants)
        return 0;

    // check for NULL-NONNULL mismatch
    for (i = 1; i < mvee::numvariants; ++i)
        if ((!pointers[i] && pointers[i-1]) || (!pointers[i-1] && pointers[i]))
            return 1;

    // check for invalid regions
    /*  for (i = 0; i < mvee::numvariants; ++i)
        if (!mvee_mman_get_region_info(i, pointers[i], 0))
        return 2;*/

    // OK, every pointer points to a valid region
    return 0;
}

/*-----------------------------------------------------------------------------
    call_compare_io_vectors
-----------------------------------------------------------------------------*/
bool monitor::call_compare_io_vectors(std::vector<struct iovec*>& addresses, size_t len, bool layout_only)
{
    bool                        result     = true;
    struct iovec*               slave_vec  = NULL;
    struct iovec*               master_vec = (struct iovec*)rw::read_data(variants[0].variantpid, addresses[0], sizeof(struct iovec) * len);

    if (!master_vec)
    {
        warnf("couldn't read master I/O vector\n");
        return false;
    }

    // get the contents of the master vector first
    std::vector<unsigned char*> master_io(len);
    if (!layout_only)
    {
        for (size_t i = 0; i < len; ++i)
        {
            master_io[i] = master_vec[i].iov_base ?
                           rw::read_data(variants[0].variantpid, master_vec[i].iov_base, master_vec[i].iov_len) :
                           NULL;
        }
    }

    for (int i = 1; i < mvee::numvariants; ++i)
    {
        slave_vec = (struct iovec*)rw::read_data(variants[i].variantpid, addresses[i], sizeof(struct iovec) * len);
        if (!slave_vec)
        {
            warnf("couldn't read slave I/O vector\n");
            result = false;
            goto out;
        }

        for (size_t j = 0; j < len; ++j)
        {
            if (slave_vec[j].iov_len != master_vec[j].iov_len)
            {
                warnf("I/O vector mismatch - iovlen - syscall: %ld (%s)\n",
                            variants[0].callnum,
                            getTextualSyscall(variants[0].callnum));
                result = false;
                goto out;
            }
            if ((!slave_vec[j].iov_base || !master_vec[j].iov_base)
                && !(slave_vec[j].iov_base == master_vec[j].iov_base))
            {
                warnf("I/O vector mismatch - null-nonnull - syscall: %ld (%s)\n",
                            variants[0].callnum,
                            getTextualSyscall(variants[0].callnum));
                result = false;
                goto out;
            }
            if (!layout_only)
            {
                if (slave_vec[j].iov_base)
                {
                    unsigned char* io = rw::read_data(variants[i].variantpid, slave_vec[j].iov_base, slave_vec[j].iov_len);
                    if ((!io || !master_io[j])
                        && (io || master_io[j]))
                    {
                        warnf("couldn't read I/O vector data - iov_base @ 0x" PTRSTR " - len: %d - j: %d\n", slave_vec[j].iov_base, len, j);
                        result = false;
                        goto out;
                    }

                    if (memcmp(io, master_io[j], slave_vec[j].iov_len) != 0)
                    {
                        warnf("I/O vector mismatch - content %d - syscall: %ld (%s)\n",
                                    j, variants[0].callnum,
                                    getTextualSyscall(variants[0].callnum));
                        SAFEDELETEARRAY(io);
                        result = false;
                        goto out;
                    }
                    SAFEDELETEARRAY(io);
                }
            }
        }
    }

out:
    SAFEDELETEARRAY(master_vec);
    SAFEDELETEARRAY(slave_vec);
    if (!layout_only)
    {
        for (size_t i = 0; i < len; ++i)
            SAFEDELETEARRAY(master_io[i]);
    }
    return result;
}

/*-----------------------------------------------------------------------------
    call_compare_msgvectors
-----------------------------------------------------------------------------*/
bool monitor::call_compare_msgvectors(std::vector<struct msghdr*>& addresses, bool layout_only)
{
    bool                       result = true;
    struct msghdr              master_msg;
    struct msghdr              msg;
    std::vector<struct iovec*> iovecs(mvee::numvariants);
    memset(&master_msg, 0, sizeof(struct msghdr));
    memset(&msg,        0, sizeof(struct msghdr));

    if (!rw::read_struct(variants[0].variantpid, addresses[0], sizeof(struct msghdr), &master_msg))
    {
        warnf("couldn't read master msgvector\n");
        return false;
    }

    iovecs[0]                   = master_msg.msg_iov;
    variants[0].orig_controllen = master_msg.msg_controllen;

    // get the contents of the master vector first
    if (!layout_only)
    {
        if (master_msg.msg_controllen)
        {
            master_msg.msg_control = (void*)rw::read_data(variants[0].variantpid, master_msg.msg_control, master_msg.msg_controllen);
            if (!master_msg.msg_control)
            {
                warnf("couldn't read msgvector control data - possible fuzzing?\n");
                shutdown(false);
                return false;
            }
        }
        if (master_msg.msg_namelen)
        {
            master_msg.msg_name = (void*)rw::read_data(variants[0].variantpid, master_msg.msg_name, master_msg.msg_namelen);
            if (!master_msg.msg_name)
            {
                warnf("couldn't read msgvector name data - possible fuzzing?\n");
                shutdown(false);
                return false;
            }
        }
    }

    for (int i = 1; i < mvee::numvariants; ++i)
    {
        if (!rw::read_struct(variants[i].variantpid, addresses[i], sizeof(struct msghdr), &msg))
        {
            warnf("couldn't read slave msgvector\n");
            result = false;
            goto out;
        }

        if (msg.msg_iovlen != master_msg.msg_iovlen)
        {
            warnf("message header mismatch - msg_iovlen - syscall: %ld (%s)\n",
                        variants[0].callnum,
                        getTextualSyscall(variants[0].callnum));
            result = false;
            goto out;
        }

        iovecs[i] = msg.msg_iov;

        if (!layout_only)
        {
            if (msg.msg_controllen != master_msg.msg_controllen)
            {
                warnf("message header mismatch - msg controllen - syscall: %ld (%s)\n",
                            variants[0].callnum,
                            getTextualSyscall(variants[0].callnum));
                result = false;
                goto out;
            }

            if (msg.msg_namelen != master_msg.msg_namelen)
            {
                warnf("message header mismatch - msg namelen - syscall: %ld (%s)\n",
                            variants[0].callnum,
                            getTextualSyscall(variants[0].callnum));
                result = false;
                goto out;
            }

            if (msg.msg_controllen)
            {
                msg.msg_control = (void*)rw::read_data(variants[i].variantpid, msg.msg_control, msg.msg_controllen);
                if (!msg.msg_control)
                {
                    warnf("couldn't read msgvector control data - possible fuzzing?\n");
                    shutdown(false);
                    return false;
                }
            }
            if (msg.msg_namelen)
            {
                msg.msg_name = (void*)rw::read_data(variants[i].variantpid, msg.msg_name, msg.msg_namelen);
                if (!msg.msg_name)
                {
                    warnf("couldn't read msgvector name data - possible fuzzing?\n");
                    shutdown(false);
                    return false;
                }
            }

            if (COMPARE_NULL(msg.msg_name, master_msg.msg_name)
                && master_msg.msg_name
                && memcmp(msg.msg_name, master_msg.msg_name, msg.msg_namelen) != 0)
            {
                warnf("message header mismatch - msg name - syscall: %ld (%s)\n",
                            variants[0].callnum,
                            getTextualSyscall(variants[0].callnum));

                if (master_msg.msg_name)
                {
                    std::string __master_name = mvee::log_do_hex_dump(master_msg.msg_name, msg.msg_namelen);
                    std::string __slave_name  = mvee::log_do_hex_dump(msg.msg_name, msg.msg_namelen);
                    warnf("master name: %s\n", __master_name.c_str());
                    warnf("slave name: %s\n",  __slave_name.c_str());
                }

                result = false;
                goto out;
            }


            if (COMPARE_NULL(msg.msg_control, master_msg.msg_control)
                && master_msg.msg_control
                && memcmp(msg.msg_control, master_msg.msg_control, msg.msg_controllen) != 0)
            {
                warnf("message header mismatch - msg name - syscall: %ld (%s)\n",
                            variants[0].callnum,
                            getTextualSyscall(variants[0].callnum));

                struct cmsghdr* master_cmsg = CMSG_FIRSTHDR(&master_msg);
                struct cmsghdr* slave_cmsg  = CMSG_FIRSTHDR(&msg);

                while (master_cmsg || slave_cmsg)
                {
                    if ((!master_cmsg || !slave_cmsg)
                        || (master_cmsg->cmsg_len != slave_cmsg->cmsg_len)
                        || (memcmp(CMSG_DATA(master_cmsg), CMSG_DATA(slave_cmsg), master_cmsg->cmsg_len) != 0))
                    {
                        result = false;
                        goto out;
                    }

                    master_cmsg = CMSG_NXTHDR(&master_msg, master_cmsg);
                    slave_cmsg  = CMSG_NXTHDR(&msg, slave_cmsg);
                }
            }

            // UGH
            if (msg.msg_control)
            {
                delete ((unsigned char*)msg.msg_control);
                msg.msg_control = NULL;
            }
            if (msg.msg_name)
            {
                delete ((unsigned char*)msg.msg_name);
                msg.msg_name = NULL;
            }
        }
    }

    result = call_compare_io_vectors(iovecs, master_msg.msg_iovlen, layout_only);

out:
    if (!layout_only)
    {
        if (msg.msg_control)
        {
            delete ((unsigned char*)msg.msg_control);
            msg.msg_control = NULL;
        }
        if (msg.msg_name)
        {
            delete ((unsigned char*)msg.msg_name);
            msg.msg_name = NULL;
        }
        if (master_msg.msg_control)
        {
            delete ((unsigned char*)master_msg.msg_control);
            master_msg.msg_control = NULL;
        }
        if (master_msg.msg_name)
        {
            delete ((unsigned char*)master_msg.msg_name);
            master_msg.msg_name = NULL;
        }
    }
    return result;
}

/*-----------------------------------------------------------------------------
    call_compare_mmsgvectors
-----------------------------------------------------------------------------*/
bool monitor::call_compare_mmsgvectors(std::vector<struct mmsghdr*>& addresses, bool layout_only)
{
	int i = 0;
	std::vector<struct msghdr*> cast(mvee::numvariants);
	for (auto vec : addresses)
		cast[i++] = (struct msghdr*)vec;
	return call_compare_msgvectors(cast, layout_only);
}

/*-----------------------------------------------------------------------------
    call_compare_fd_sets
-----------------------------------------------------------------------------*/
bool monitor::call_compare_fd_sets(std::vector<fd_set*>& addresses, int nfds)
{
    std::vector<fd_set> sets(mvee::numvariants);

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (!rw::read_struct(variants[i].variantpid, addresses[i], sizeof(fd_set), &sets[i]))
        {
            warnf("couldn't read fd_set for variant %d\n", i);
            return false;
        }
    }

    if (nfds % 8)
    {
        for (int j = 0; j < mvee::numvariants; ++j)
        {
            for (int i = 0; i < 7 - (nfds % 8); ++i)
            {
                FD_CLR(nfds + 1 + i, &sets[j]);
            }
        }
    }

    for (int i = 1; i < mvee::numvariants; ++i)
    {
        if (memcmp(&sets[i], &sets[0], ROUND_UP(nfds + 1, sizeof(unsigned long))) != 0)
        {
            return false;
        }
    }

    return true;
}

/*-----------------------------------------------------------------------------
    call_replicate_io_vector
-----------------------------------------------------------------------------*/
void monitor::call_replicate_io_vector(std::vector<struct iovec*>& addresses, long bytes_copied)
{
    int  i, j;
    long bytes_remaining = bytes_copied;
    for (i = 0; bytes_remaining > 0; ++i)
    {
        struct iovec master_vec;
        if (!rw::read_struct(variants[0].variantpid, addresses[0] + i, sizeof(struct iovec), &master_vec))
        {
            warnf("couldn't read master I/O vector\n");
            return;
        }

        long         to_copy = ((unsigned long)bytes_remaining > master_vec.iov_len) ? (long)master_vec.iov_len : bytes_remaining;

        for (j = 1; j < mvee::numvariants; ++j)
        {
            struct iovec variant_vec;
            if (!rw::read_struct(variants[j].variantpid, addresses[j] + i, sizeof(struct iovec), &variant_vec))
            {
                warnf("couldn't read slave I/O vector\n");
                return;
            }

            long         copied = rw::copy_data(variants[0].variantpid, master_vec.iov_base,
                                                    variants[j].variantpid, variant_vec.iov_base, to_copy);

            if (copied != to_copy)
            {
                warnf("Failed to replicate io vector. tried to replicate %d bytes - actually replicated %d bytes - errno: %s\n", to_copy, copied, getTextualErrno(errno));
            }
        }

        bytes_remaining -= to_copy;
    }
}

/*-----------------------------------------------------------------------------
    call_replicate_msgvector
-----------------------------------------------------------------------------*/
void monitor::call_replicate_msgvector(std::vector<struct msghdr*>& addresses, long bytes_sent)
{
    int                        i;
    std::vector<struct msghdr> hdrs(mvee::numvariants);
	
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        if (!rw::read_struct(variants[i].variantpid, addresses[i], sizeof(struct msghdr), &hdrs[i]))
        {
            warnf("couldn't read msgvector %d\n", i);
            return;
        }
    }

    // replicate name and namelen
    if (hdrs[0].msg_namelen && hdrs[0].msg_name)
    {
        unsigned char* master_name = rw::read_data(variants[0].variantpid, hdrs[0].msg_name, hdrs[0].msg_namelen);
        if (!master_name)
        {
            warnf("couldn't read name from master msgvector\n");
            return;
        }
        for (i = 1; i < mvee::numvariants; ++i)
        {
            if (!rw::write_data(variants[i].variantpid, hdrs[i].msg_name, hdrs[0].msg_namelen, master_name))
            {
                warnf("couldn't replicate name in msgvector\n");
                return;
            }
            if (!rw::write_data(variants[i].variantpid, &addresses[i]->msg_namelen, sizeof(socklen_t), &hdrs[0].msg_namelen))
            {
                warnf("couldn't replicate namelen in msgvector\n");
                return;
            }
        }
        SAFEDELETEARRAY(master_name);
    }

    // replicate flags
    for (i = 1; i < mvee::numvariants; ++i)
    {
        if (!rw::write_data(variants[i].variantpid, &addresses[i]->msg_flags, sizeof(int), &hdrs[0].msg_flags))
        {
            warnf("couldn't replicate flags in msgvector\n");
            break;
        }
    }

//	if (hdrs[0].msg_controllen)
    if (variants[0].orig_controllen)
    {
        unsigned char* master_control = rw::read_data(variants[0].variantpid, hdrs[0].msg_control, variants[0].orig_controllen);

        if (!master_control)
        {
            warnf("couldn't read control from master msgvector - msg_control: 0x" PTRSTR " - msg_controllen: %d\n", hdrs[0].msg_control, variants[0].orig_controllen);
        }

        // replicate control data
        for (i = 1; i < mvee::numvariants; ++i)
        {
            if (!rw::write_data(variants[i].variantpid, hdrs[i].msg_control, variants[0].orig_controllen, master_control))
            {
                warnf("couldn't replicate name in msgvector\n");
            }
            if (!rw::write_data(variants[i].variantpid, &((struct msghdr*)addresses[i])->msg_controllen, sizeof(size_t), &hdrs[0].msg_controllen))
            {
                warnf("couldn't replicate controllen in msgvector\n");
            }
        }

        SAFEDELETEARRAY(master_control);
    }


    // replicate vector data
    std::vector<struct iovec*> vec_addresses(mvee::numvariants);
    for (i = 0; i < mvee::numvariants; ++i)
        vec_addresses[i] = hdrs[i].msg_iov;

    call_replicate_io_vector(vec_addresses, bytes_sent);
}

/*-----------------------------------------------------------------------------
    call_replicate_mmsgvector
-----------------------------------------------------------------------------*/
void monitor::call_replicate_mmsgvector(std::vector<struct mmsghdr*>& addresses, int vlen)
{
    struct mmsghdr master_mmsg;

    while (vlen > 0)
    {
        if (!rw::read_struct(variants[0].variantpid, addresses[0], sizeof(struct mmsghdr), &master_mmsg))
        {
            warnf("couldn't read master message message header\n");
            return;
        }

		for (int i = 1; i < mvee::numvariants; ++i)
		{
            if (!rw::write_data(variants[i].variantpid, &addresses[i]->msg_len, sizeof(master_mmsg.msg_len), &master_mmsg.msg_len))
			{
				warnf("couldn't write slave message message header\n");
				return;
			}
		}

        if (master_mmsg.msg_len > 0)
        {
			int i = 0;
			std::vector<struct msghdr*> cast(mvee::numvariants);
			for (auto vec : addresses)
				cast[i++] = (struct msghdr*)vec;			
			/*
			  struct mmsghdr {
			      struct msghdr hdr;
                  unsigned int len;
              }

			  => we intentionally pass a vector of mmsghdr addresses to a
			  function that accepts vectors to msghdr addresses because the
			  msghdr field in mmsghdr is at offset 0
			 */
            call_replicate_msgvector(cast, master_mmsg.msg_len);
            vlen--;
            for (int i = 0; i < mvee::numvariants; ++i)
                addresses[i]++;
        }
    }
}

/*-----------------------------------------------------------------------------
    call_replicate_ifconfs
-----------------------------------------------------------------------------*/
void monitor::call_replicate_ifconfs(std::vector<struct ifconf*>& addresses)
{
	std::vector<struct ifconf> real_ifconfs(mvee::numvariants);
	
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		if (!rw::read_struct(variants[i].variantpid, addresses[i], sizeof(struct ifconf), &real_ifconfs[i]))
		{
			warnf("Couldn't read ifconf\n");
			return;
		}
	}

	struct ifreq* master_reqs = (struct ifreq*)rw::read_data(variants[0].variantpid, real_ifconfs[0].ifc_ifcu.ifcu_req, real_ifconfs[0].ifc_len);

	if (!master_reqs)
	{
		warnf("couldn't read master ifcu_reqs\n");
		return;
	}

	for (int i = 1; i < mvee::numvariants; ++i)
	{
		if (!rw::write_data(variants[i].variantpid, &addresses[i]->ifc_len, sizeof(int), &real_ifconfs[0].ifc_len))
		{
			warnf("Couldn't replicate master ifc_len\n");
			break;
		}

		if (!rw::write_data(variants[i].variantpid, real_ifconfs[i].ifc_ifcu.ifcu_req, real_ifconfs[0].ifc_len, master_reqs))
		{
			warnf("Couldn't replicate master ifcu_reqs\n");
			break;
		}
	}

	delete[] (unsigned char*)master_reqs;
}

/*-----------------------------------------------------------------------------
    call_replicate_mmsgvectorlens
-----------------------------------------------------------------------------*/
void monitor::call_replicate_mmsgvectorlens(std::vector<mmsghdr*>& addresses, int sent, int attempted)
{
    struct mmsghdr     master_mmsg;
    std::vector<struct msghdr*> msgvecs(mvee::numvariants);

    // do we need this?
    // this handles partially sent messages but I'm not sure if partially sent messages are even possible
    if (attempted > sent)
        sent++;

    while (sent > 0)
    {
        if (!rw::read_struct(variants[0].variantpid, addresses[0], sizeof(struct mmsghdr), &master_mmsg))
        {
            warnf("couldn't read master message message header\n");
            return;
        }

        for (int i = 1; i < mvee::numvariants; ++i)
        {
            if (!rw::write_data(variants[i].variantpid, &addresses[i]->msg_len, sizeof(master_mmsg.msg_len), &master_mmsg.msg_len))
            {
                warnf("couldn't replicate message message length\n");
                return;
            }

            addresses[i]++;;
        }

        sent--;
    }
}

/*-----------------------------------------------------------------------------
    call_replicate_buffer -
-----------------------------------------------------------------------------*/
void monitor::call_replicate_buffer(std::vector<const unsigned char*>& buffers, int size)
{
    long result;

    if (size == 0)
        return;

    for (int i = 1; i < mvee::numvariants; ++i)
    {
        if ((result = rw::copy_data(variants[0].variantpid, (void*) buffers[0], variants[i].variantpid, (void*) buffers[i], size)) != size)
        {
            warnf("Failed to replicate buffer. tried to replicate %d bytes - actually replicated %d bytes - errno: %s\n", size, result, getTextualErrno(errno));
        }
    }
}

/*-----------------------------------------------------------------------------
    call_get_sigset
-----------------------------------------------------------------------------*/
sigset_t monitor::call_get_sigset(int variantnum, void* sigset_ptr, bool is_old_call)
{
    sigset_t set;
    sigemptyset(&set);

    if (sigset_ptr)
    {
        if (is_old_call)
        {
            unsigned int __set;
            if (!rw::read_struct(variants[variantnum].variantpid, sigset_ptr, sizeof(unsigned int), &__set))
            {
                warnf("couldn't read sigset\n");
                return set;
            }
            set = mvee::old_sigset_to_new_sigset(__set);
        }
        else
        {
            if (!rw::read_struct(variants[variantnum].variantpid, sigset_ptr, sizeof(sigset_t), &set))
            {
                warnf("couldn't read sigset\n");
                return set;
            }
        }
    }

    return set;
}

/*-----------------------------------------------------------------------------
    call_get_sigaction
-----------------------------------------------------------------------------*/
struct sigaction monitor::call_get_sigaction(int variantnum, void* sigaction_ptr, bool is_old_call)
{
    struct sigaction result;
    memset(&result, 0, sizeof(struct sigaction));

    if (sigaction_ptr)
    {
        if (is_old_call)
        {
            old_kernel_sigaction action;

            if (!rw::read_struct(variants[variantnum].variantpid, sigaction_ptr, sizeof(action), &action))
            {
                warnf("couldn't read sigaction\n");
                return result;
            }

            result.sa_handler  = action.k_sa_handler;
            result.sa_restorer = action.sa_restorer;
            result.sa_flags    = action.sa_flags;
            result.sa_mask     = mvee::old_sigset_to_new_sigset(action.sa_mask);
        }
        else
        {
            struct kernel_sigaction action;

            if (!rw::read_struct(variants[variantnum].variantpid, sigaction_ptr, sizeof(action), &action))
            {
                warnf("couldn't read sigaction\n");
                return result;
            }

            result.sa_handler  = action.k_sa_handler;
            result.sa_restorer = action.sa_restorer;
            result.sa_flags    = action.sa_flags;
            memcpy(&result.sa_mask, &action.sa_mask, sizeof(sigset_t));
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
    call_serialize_io_vector
-----------------------------------------------------------------------------*/
std::string monitor::call_serialize_io_vector(int variantnum, struct iovec* vec, unsigned int vecsz)
{
	size_t max_bytes = 0;

#ifdef MVEE_NO_RW_LOGGING
# if MVEE_NO_RW_LOGGING == 2
    return std::string("<rw logging disabled>");
# else 
	max_bytes = 80;
# endif
#endif

    if (vecsz == 0)
    {
        warnf("serializing zero-sized I/O vector\n");
        return NULL;
    }

    std::stringstream ss;

    for (unsigned int i = 0; i < vecsz; ++i)
    {
		size_t vec_len = (max_bytes == 0) ? vec[i].iov_len : MIN(max_bytes, vec[i].iov_len);
		bool truncated = (vec_len - vec[i].iov_len) > 0;

        char* elem = (char*)rw::read_data(variants[variantnum].variantpid, 
											  vec[i].iov_base, 
											  vec_len, 
											  1);

        if (elem)
        {
            if (ss.str().length() > 0)
                ss << ", ";
            ss << i << " => \n";

            if (!mvee::is_printable_string(elem, vec_len))
                ss << mvee::log_do_hex_dump(elem, vec_len);
            else
                ss << std::string(elem);
			if (truncated)
				ss << "...[TRUNCATED]";
            ss << "\n";

            SAFEDELETEARRAY(elem);
        }
    }

    return ss.str();
}

/*-----------------------------------------------------------------------------
    call_serialize_msgvector
-----------------------------------------------------------------------------*/
std::string monitor::call_serialize_msgvector(int variantnum, struct msghdr* msg)
{
    if (msg->msg_iovlen > 0)
    {
        struct iovec* tmp    = new(std::nothrow) struct iovec[msg->msg_iovlen];
        if (!tmp)
        {
            warnf("msgvector serialization failed - could not allocate memory - iovlen: %d\n", msg->msg_iovlen);
            return NULL;
        }
        if (!rw::read_struct(variants[variantnum].variantpid, msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen, tmp))
        {
            warnf("failed to read msgvector I/O vector\n");
            SAFEDELETEARRAY(tmp);
            return NULL;
        }

        std::string   result = call_serialize_io_vector(variantnum, tmp, msg->msg_iovlen);
        SAFEDELETEARRAY(tmp);
        return result;
    }

    return "";
}

/*-----------------------------------------------------------------------------
    call_serialize_io_buffer
-----------------------------------------------------------------------------*/
std::string monitor::call_serialize_io_buffer(int variantnum, const unsigned char* buf, unsigned long buflen)
{
	size_t max_bytes = 0;

#ifdef MVEE_NO_RW_LOGGING
# if MVEE_NO_RW_LOGGING == 2
    return std::string("<rw logging disabled>");
# else 
	max_bytes = 80;
# endif
#endif

	size_t real_buflen = (max_bytes == 0) ? buflen : MIN(buflen, max_bytes);
	bool truncated = (real_buflen - buflen) > 0;
    char* result = (char*)rw::read_data(variants[variantnum].variantpid, 
		(void*) buf, 
		real_buflen, 
		1);

    if (result)
    {
        std::string res;

        if (!mvee::is_printable_string(result, real_buflen))
            res = mvee::log_do_hex_dump(result, real_buflen);
        else
            res = std::string(result);

		if (truncated)
			res += "...[TRUNCATED]";

        SAFEDELETEARRAY(result);
        return res;
    }

    return "";
}

/*-----------------------------------------------------------------------------
    call_get_variant_pidstr
-----------------------------------------------------------------------------*/
std::string monitor::call_get_variant_pidstr(int variantnum)
{
	std::stringstream ss;
	ss << "Variant:" << variantnum 
	   << " [PID:" << std::setw(5) << std::setfill('0') << variants[variantnum].variantpid << std::setw(0) << "]";
	return ss.str();
}

/*-----------------------------------------------------------------------------
    call_get_sockaddr
-----------------------------------------------------------------------------*/
struct sockaddr* monitor::call_get_sockaddr(int variantnum, struct sockaddr* ptr, socklen_t addr_len)
{
    struct sockaddr* tmp = (struct sockaddr*)
                           rw::read_data(variants[variantnum].variantpid, ptr, addr_len);

    if (!tmp)
        return NULL;

#define CAST_TO(family, type)                                                                  \
    case family:                                                                               \
    {                                                                                          \
        struct type * out = (struct type*)new char[sizeof(struct type)];                       \
        memcpy(out, tmp, addr_len);                                                            \
        if (sizeof(struct type) > addr_len)                                                    \
            memset((void*)((unsigned long)out + addr_len), 0, sizeof(struct type) - addr_len); \
        delete[] tmp;                                                                          \
        return (struct sockaddr*)out;                                                          \
    }

    switch(tmp->sa_family)
    {
        CAST_TO(AF_INET,  sockaddr_in);
        CAST_TO(AF_INET6, sockaddr_in6);
        CAST_TO(AF_FILE,  sockaddr_un);
        default:
            return tmp;
    }
}

/*-----------------------------------------------------------------------------
    call_overwrite_arg_value
-----------------------------------------------------------------------------*/
void monitor::call_overwrite_arg_value(int variantnum, int argnum, long new_value, bool needs_restore)
{
	long old_value;

	switch(argnum)
	{
#define SWAP(num)									\
		case num:									\
			old_value = ARG##num(variantnum);		\
			SETARG##num(variantnum, new_value);	\
			break;
		SWAP(1);
		SWAP(2);
		SWAP(3);
		SWAP(4);
		SWAP(5);
		SWAP(6);
		default:
			warnf("Tried to overwrite invalid syscall arg: %d\n", argnum);
			return;
	}

	if (needs_restore)
	{
		variants[variantnum].have_overwritten_args = true;
		overwritten_syscall_arg arg;
		arg.syscall_arg_num = argnum;
		arg.arg_old_value = old_value;
		arg.restore_data = false;
		variants[variantnum].overwritten_args.push_back(arg);
	}
}

/*-----------------------------------------------------------------------------
    call_overwrite_arg_data
-----------------------------------------------------------------------------*/
void monitor::call_overwrite_arg_data
(
	int variantnum,
	int argnum,
	unsigned old_len,
	void* data,
	unsigned new_len,
	bool needs_restore
)
{
	long old_value;

	switch(argnum)
	{
#define GETVAL(num)									\
		case num:									\
			old_value = ARG##num(variantnum);		\
			break;
		GETVAL(1);
		GETVAL(2);
		GETVAL(3);
		GETVAL(4);
		GETVAL(5);
		GETVAL(6);
		default:
			warnf("Tried to read invalid syscall arg: %d\n", argnum);
			return;
	}


	// if the original data doesn't need to be restored,
	// we can just try to overwrite the current data
	if (!needs_restore && new_len <= old_len)
	{
		if (!rw::write_data(variants[variantnum].variantpid, (void*) old_value, new_len, data))
		{
			warnf("syscall overwrite failed\n");
			shutdown(false);
			return;
		}
	}

	// We have to find some region to write the new data.
	// Check if we can use the stack
	unsigned long stack_pointer = SP_IN_REGS(variants[variantnum].regs);

	// If we pass true as the third argument (look_for_thread),
	// the find_writable_region function will always return the
	// stack info
	auto stack_info = set_mmap_table->find_writable_region(
		variantnum, new_len, variants[variantnum].variantpid, 
		variants[variantnum].variantpid == variants[variantnum].varianttgid);

	// sanity check
	if (!stack_info || stack_info->region_backing_file_path.find("[stack") == std::string::npos)
	{
		warnf("syscall overwrite failed - couldn't find stack for thread %d (TID: %d) in variant %d\n",
			  mvee::active_monitorid, variants[variantnum].variantpid, variantnum);
		shutdown(false);
		return;
	}

	// Got it. Check if we have enough space below the stack pointer
	// TODO: Should we check if we've already written a new block of data here?
	if (stack_pointer - stack_info->region_base_address < new_len)
	{
		warnf("syscall overwrite failed - not enough space on the stack to write an arg of size %d in thread %d (TID: %d) in variant %d\n",
			  new_len, mvee::active_monitorid, variants[variantnum].variantpid, variantnum);
		shutdown(false);
		return;
	}

	// Lezgo
	// TODO: Store old contents at the stack base?
	if (!rw::write_data(variants[variantnum].variantpid, (void*)stack_info->region_base_address, new_len, data))
	{
		warnf("syscall overwrite failed - failed to write an arg of size %d on the stack of thread %d (TID: %d) in variant %d\n",
			  new_len, mvee::active_monitorid, variants[variantnum].variantpid, variantnum);
		shutdown(false);
		return;
	}

	switch(argnum)
	{
#define SETVAL(num)														\
		case num:														\
			SETARG##num(variantnum, stack_info->region_base_address);	\
			ARG##num(variantnum) = stack_info->region_base_address;		\
			break;
		SETVAL(1);
		SETVAL(2);
		SETVAL(3);
		SETVAL(4);
		SETVAL(5);
		SETVAL(6);
		default: break;
	}

	if (needs_restore)
	{
		variants[variantnum].have_overwritten_args = true;
		overwritten_syscall_arg arg;
		arg.syscall_arg_num = argnum;
		arg.arg_old_value = old_value;
		arg.restore_data = false;
		variants[variantnum].overwritten_args.push_back(arg);
	}

	debugf("Overwrote syscall arg %d in variant %d\n", argnum, variantnum);
}

/*-----------------------------------------------------------------------------
    call_restore_args
-----------------------------------------------------------------------------*/
void monitor::call_restore_args(int variantnum)
{
	variants[variantnum].have_overwritten_args = false;

	for (auto arg : variants[variantnum].overwritten_args)
	{
		if (arg.restore_data)
		{
			if (!rw::write_data(variants[variantnum].variantpid, arg.data_loc, arg.data_len,  arg.data_content))
			{
				warnf("Failed to restore syscall arg data %d for variant %d\n", arg.syscall_arg_num, variantnum);
				shutdown(false);
				return;
			}
		}
		
		switch(arg.syscall_arg_num)
		{
#define RESTOREVAL(num)													\
			case num:													\
				SETARG##num(variantnum, arg.arg_old_value);			\
				break;
			RESTOREVAL(1);
			RESTOREVAL(2);
			RESTOREVAL(3);
			RESTOREVAL(4);
			RESTOREVAL(5);
			RESTOREVAL(6);
			default: break;
		}		
	}

	variants[variantnum].overwritten_args.clear();

	debugf("Restored syscall args in variant %d\n", variantnum);
}

/*-----------------------------------------------------------------------------
    call_resolve_open_paths
-----------------------------------------------------------------------------*/
bool monitor::call_resolve_open_paths
(
	std::vector<unsigned long>& fds,
	std::vector<unsigned long>& path_ptrs,
	std::vector<std::string>& resolved_paths,
	bool& unsynced_access,
	unsigned long open_at_fd
)
{
	std::vector<std::string> tmp_path(mvee::numvariants);
	unsynced_access = aliased_open;

	tmp_path[0] = set_fd_table->get_full_path(0, variants[0].variantpid, open_at_fd, (void*)path_ptrs[0]);

	if (tmp_path[0].find("/proc/") == 0)
	{
		char maps[30];
		sprintf(maps, "/proc/%d/maps", variants[0].variantpid);

		if (tmp_path[0].compare(maps) == 0)
			unsynced_access = true;
		else if (tmp_path[0].compare("/proc/self/maps") == 0)
			unsynced_access = true;
	}
	else if (tmp_path[0].compare(set_mmap_table->mmap_startup_info[0].image) == 0)
	{
		debugf("Granting unsynced access to main program binary\n");
		unsynced_access = true;
	}
		
	resolved_paths[0] = mvee::os_normalize_path_name(tmp_path[0]);
	if (resolved_paths[0].size() == 0)
		return false;

	if (resolved_paths[0].find("/dev/shm/") == 0 ||
		resolved_paths[0].find("/run/shm/") == 0)
		unsynced_access = true;

	// Fetch additional paths if this is an unsynced file
	// + resolve relative path specifiers and symlinks
	if (unsynced_access)
	{
		for (auto i = 0; i < mvee::numvariants; ++i)
		{
			// We already did the fetch for the master
			if (i > 0)
				tmp_path[i] = set_fd_table->get_full_path(i, variants[i].variantpid, open_at_fd, (void*)path_ptrs[i]);

			// Substitute actual pid into the self field for /proc/self/ paths
			if (tmp_path[i].find("/proc/self") == 0)
			{
				std::stringstream pathbuilder;
				pathbuilder << "/proc/" << variants[i].variantpid << tmp_path[i].substr(strlen("/proc/self/"));
				tmp_path[i] = pathbuilder.str();
			}

			if (i > 0)
				resolved_paths[i] = mvee::os_normalize_path_name(tmp_path[i]);

			if (resolved_paths[i].size() == 0)
				return false;
		}
	}
	else
	{
		for (auto i = 1; i < mvee::numvariants; ++i)
			resolved_paths[i] = resolved_paths[0];
	}

	return true;
}
