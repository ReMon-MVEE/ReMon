/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

/*-----------------------------------------------------------------------------
  !!! Differences between i386 and amd64 kernel interfaces !!!

  * On i386 there's two flavors for every signal related syscall:
  The RT-flavor (e.g. sys_rt_sigaction) and the non-RT-flavor
  (e.g. sys_sigaction).
  The non-RT syscalls use an older version of the sigaction struct
  (it's defined in MVEE/Inc/MVEE_private.h as old_kernel_sigaction).
  The RT-syscalls use the normal sigaction struct (which is defined in
  the system headers as struct sigaction).

  On AMD64 the two flavors are merged and they always use the regular
  struct sigaction.

  * Consequently:
  + sys_sigaction is deprecated. AMD64 uses only sys_rt_sigaction
  + sys_sigreturn is deprecated. AMD64 uses only sys_rt_sigreturn
  + sys_sigsuspend is deprecated. AMD64 uses only sys_rt_sigsuspend

  * In this file, we implement only the handlers for the RT-flavor but the
  functions we use to read/write sigactions are non-RT aware.

  * sys_mmap2 and sys_mmap are aliases now
  * syscalls that have a "32" suffix on i386 lose the suffix on AMD64
  => examples: sys_geteuid, sys_getuid, ...
  * sys_fadvise64_64 and sys_fadvise64 (on i386) are simply sys_fadvise64 on AMD64
  * sys_fcntl64 and sys_fcntl (on i386) are simply sys_fcntl on AMD64
  * sys_ipc has been split into sys_shmat/sys_shmdt/sys_shmctl/sys_shmget
  * sys_socketcall has been split into sys_socket/sys_socketpair/sys_bind/
  sys_connect/sys_accept/sys_accept4/sys_getsockname/sys_getpeername/
  sys_listen/sys_recv/sys_recvfrom/sys_recvmsg/sys_setsockopt/sys_getsockopt
  * stat related calls only exist in their non-64 forms on AMD64
  * on i386, mmap's page offset is in units of page size. On AMD64, it's
  in bytes
-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
  Includes
-----------------------------------------------------------------------------*/
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/inotify.h>
#include <sys/vfs.h>
#include <string.h>
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <utime.h>
#include <termios.h>
#include <sys/quota.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <linux/sysinfo.h>
#include <sys/ptrace.h>
#include <sys/poll.h>
#include <sstream>
#include <signal.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/net.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/timerfd.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_macros.h"
#include "MVEE_filedesc.h"
#include "MVEE_mman.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_private_arch.h"
#include "MVEE_syscalls.h"
#include "MVEE_syscalls_support.h"
#include "MVEE_shm.h"
#include "MVEE_signals.h"
#include "MVEE_fake_syscall.h"

/*-----------------------------------------------------------------------------
  old_kernel_stat
  -----------------------------------------------------------------------------*/
struct old_kernel_stat
{
    unsigned short dev;
    unsigned short ino;
    unsigned short mode;
    unsigned short nlink;
    unsigned short uid;
    unsigned short gid;
    unsigned short rdev;
    unsigned int   size;
    unsigned int   atime;
    unsigned int   mtime;
    unsigned int   ctime;
};

/*-----------------------------------------------------------------------------
  kernel_termios is not compatible with termios (doh!)
-----------------------------------------------------------------------------*/
#define __KERNEL_NCCS 19
struct __kernel_termios
{
    tcflag_t c_iflag;             /* input mode flags */
    tcflag_t c_oflag;             /* output mode flags */
    tcflag_t c_cflag;             /* control mode flags */
    tcflag_t c_lflag;             /* local mode flags */
    cc_t     c_line;              /* line discipline */
    cc_t     c_cc[__KERNEL_NCCS]; /* control characters */
};

/*-----------------------------------------------------------------------------
  arg struct for old_mmap syscall, see linux/syscalls.h
-----------------------------------------------------------------------------*/
struct mmap_arg_struct
{
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
};

/*-----------------------------------------------------------------------------
  Macros
-----------------------------------------------------------------------------*/
#define MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)           \
    int start, lim;                                              \
                                                                 \
    start = (childnum == -1) ? 0 : childnum;                     \
    lim   = (childnum == -1) ? mvee::numvariants : childnum + 1; \
                                                                 \
    if (childnum != -1)                                          \
        call_check_regs(childnum);

#define MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, results)                                     \
    int start, lim;                                                                                   \
                                                                                                      \
    start = (childnum == -1) ? 0 : childnum;                                                          \
    lim   = (childnum == -1) ? (state == STATE_IN_MASTERCALL ? 1 : mvee::numvariants) : childnum + 1; \
    std::vector<unsigned long> results(mvee::numvariants);                                            \
    if (childnum == -1)                                                                               \
        results = call_postcall_get_result_vector();                                                  \
    else                                                                                              \
        for (int i = start; i < lim; ++i)                                                             \
            results[i] = call_postcall_get_child_result(i);

/*-----------------------------------------------------------------------------
  pseudo handlers
-----------------------------------------------------------------------------*/
long monitor::handle_donthave(int childnum)
{
    return 0;
}

long monitor::handle_dontneed(int childnum)
{
    return 0;
}

/*-----------------------------------------------------------------------------
  handle_is_known_false_positive
-----------------------------------------------------------------------------*/
bool monitor::handle_is_known_false_positive(const char* program_name, long callnum, long* precall_flags)
{
    std::vector<char*> data(mvee::numvariants);
    std::fill(data.begin(), data.end(), (char*)NULL);

    if (set_mmap_table->thread_group_shutting_down)
        return true;

    bool               result = false;

	// progran_name is not set until the first variant has called execve
	if (!program_name)
	{
		debugf("Mismatch allowed because it happened during MVEE initialization\n");
		return true;
	}

    // check the program name first
    if (callnum == __NR_write && program_name && strstr(program_name, "416.gamess"))
    {
		warnf("checking for known false positives\n");
        // 416.gamess uses a broken TIME function to print stuff like "GENERATED AT ...."
        // the broken time function returns a block of non-allocated memory, rather than
        // the actual time (doh!)

        // first check if the buffer lengths match
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            if (ARG3(i) != ARG3(i-1))
            {
                warnf("buffer length mismatch\n");
                goto out;
            }
        }

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            if ((data[i] = (char*)mvee_rw_read_data(childs[i].childpid, ARG2(i), ARG3(i))) == NULL)
            {
                warnf("couldn't get buffer for child %d\n", i);
                goto out;
            }
        }

        unsigned long size = ARG3(0);

        // We find every occurence of "GENERATED AT" and clear out the 20 bytes that follow
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            int replaced = 0;

            for (unsigned long pos = 0; pos < size - strlen("GENERATED AT") - 20; ++pos)
            {
                if (memcmp((void*)((unsigned long)data[i] + pos), "GENERATED AT", strlen("GENERATED AT")) == 0)
                {
                    memset((void*)((unsigned long)data[i] + pos), 0, strlen("GENERATED AT") + 20);
                    replaced++;
                }
            }

            warnf("masked %d occurences of \"GENERATED AT\" in data for child %d\n", replaced, i);
        }

        // Now check again...
		result = true;
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            if (memcmp(data[i], data[i-1], size))
            {
                result = false;
                break;
            }
        }

        // all good
        if (result)
        {
            warnf("this is a known false positive. Allowing it!\n");
            *precall_flags = MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
        }
        else
            warnf("this is an unkown false positive :(\n");
    }
    else if (callnum == __NR_open)
    {
        bool true_positive = false;

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            char* str = mvee_rw_read_string(childs[i].childpid, ARG1(i));
            char  tmp[20];
            sprintf(tmp, "MVEE Child %d >", i);

            if (str && strcmp(str, tmp))
            {
                //				warnf("true positve - str is %s - tmp is %s\n", str, tmp);
                true_positive = true;
                SAFEDELETEARRAY(str);
                break;
            }
            SAFEDELETEARRAY(str);
        }

        if (true_positive)
            return false;
        return true;
    }
	else if (callnum == __NR_execve)
	{
		// execve might mismatch because we're starting different binaries.
		// We allow this in very specific cases
		if (MVEE_PRECALL_MISMATCHING_ARG((*precall_flags)) == 1)
		{
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				char* str = mvee_rw_read_string(childs[i].childpid, ARG1(i));
				std::string file;
				
				if (!str)
					return false;
				
				file = std::string(str);
				SAFEDELETEARRAY(str);
				
				VariantArch arch;
				if (!mvee::is_qemu_executable(file, arch))
					return false;
			}

			return true;
		}
		
		return false;			
	}

out:
    for (int i = 0; i < mvee::numvariants; ++i)
        SAFEDELETEARRAY(data[i]);
    return result;
}

/*-----------------------------------------------------------------------------
  Helper Functions
-----------------------------------------------------------------------------*/
long monitor::handle_check_open_call(const std::string& full_path, int* flags, int mode)
{
    int err = 0;

    if (full_path == "/dev/port")
    {
        cache_mismatch_info("The program is trying to access I/O ports (open(/dev/port...)). This call has been denied.\n");
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
    }
    else if (full_path == "/dev/dri/")
    {
        cache_mismatch_info("The program is trying to do direct rendering (open(%s)). This call has been denied.\n", full_path.c_str());
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
    }
    else
    {
        //
        // open() with O_CREAT and O_EXCL will fail if the file already exists.
        // This call will thus only succeed in the first child that executes it.
        // So let the monitor create the file first, and then let the children
        // execute the same open() call without O_CREAT and O_EXCL.
        //
        if ( (*flags & O_CREAT) && (*flags & O_EXCL) )
        {
            //warnf("> O_CREAT & O_EXCL\n");
            err = open(full_path.c_str(), *flags, mode);
            //warnf("> SYS_OPEN returned: %d (%s) %d (%s) for O_CREAT & O_EXCL call...\n", err, strerror(-err), errno, strerror(errno));
            if (err != -1)
            {
                // remove O_CREAT and O_EXCL from the flags and set the new flags
                // for each child
                *flags &= (~O_CREAT & ~O_EXCL);
                close(err);
                err     = 0;
            }
        }
    }

    if (err)
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(errno);
    return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_restart_syscall
-----------------------------------------------------------------------------*/
long monitor::handle_restart_syscall_get_call_type(int childnum)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_exit
-----------------------------------------------------------------------------*/
long monitor::handle_exit_precall(int childnum)
{
    update_sync_primitives();
#ifdef MVEE_CALCULATE_CLOCK_SPREAD
	log_calculate_clock_spread();
#endif
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_fork
-----------------------------------------------------------------------------*/
long monitor::handle_fork_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

long monitor::handle_fork_postcall(int childnum)
{
    // get PID returned in master child
    long result = call_postcall_get_child_result(0);

    // set the same master PID in all non-master children
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_child_result(i, result);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_vfork
-----------------------------------------------------------------------------*/
long monitor::handle_vfork_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

long monitor::handle_vfork_postcall(int childnum)
{
    // get PID returned in master child
    long result = call_postcall_get_child_result(0);

    // set the same master PID in all non-master children
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_child_result(i, result);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_read - (unsigned int fd, char __user *buf, size_t count)
-----------------------------------------------------------------------------*/
long monitor::handle_read_get_call_type(int childnum)
{
    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_read_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_READ(%d, 0x" PTRSTR ", %d)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i));

    return 0;
}

long monitor::handle_read_precall(int childnum)
{
    CHECKARG(3);
    CHECKFD(1);
    CHECKPOINTER(2);

#ifdef MVEE_ENABLE_VALGRIND_HACKS
    if (ARG1(0) > 1024)
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
#endif

    if (set_fd_table->is_fd_unsynced(ARG1(0)))
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_read_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, result)

    for (int i = start; i < lim; ++i)
    {
        if (call_succeeded)
        {
            std::string result_str = call_serialize_io_buffer(i, ARG2(i), result[i]);
            debugf("pid: %d - SYS_READ RETURN: %d => %s\n", childs[i].childpid, result[i], result_str.c_str());
        }
        else
        {
            debugf("pid: %d - SYS_READ FAIL: %d (%s)\n", childs[i].childpid, result[i], strerror(-result[i]));
        }
    }

    return 0;
}

long monitor::handle_read_postcall(int childnum)
{
    if (state == STATE_IN_MASTERCALL)
    {
        REPLICATEBUFFER(2);
    }
    else
    {
        UNMAPFDS(1);
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_write - (unsigned int fd, const char * buf, unsigned long count)
-----------------------------------------------------------------------------*/
long monitor::handle_write_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        std::string buf_str = call_serialize_io_buffer(i, ARG2(i), ARG3(i));
        debugf("pid: %d - SYS_WRITE(%d, 0x" PTRSTR " (%s), %d)\n",
                   childs[i].childpid, ARG1(i), ARG2(i), buf_str.c_str(), ARG3(i));
    }

    return 0;
}

long monitor::handle_write_precall(int childnum)
{
    //    mvee_log_child_backtrace(0);
    CHECKFD(1);
    CHECKPOINTER(2);

#ifdef MVEE_ALLOW_PERF
    std::vector<unsigned long> argarray(mvee::numvariants);
    FILLARGARRAY(2, argarray);

    if (perf && ARG1(0) <= 2)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            unsigned char* buf = mvee_rw_read_data(childs[i].childpid, ARG2(i), ARG3(i), 1);
            if (buf)
                childs[i].perf_out += std::string((char*)buf);
            SAFEDELETEARRAY(buf);
        }

        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    }
#endif

    CHECKARG(3);
    CHECKBUFFER(2, ARG3(0));

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_write_log_return(int childnum)
{
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_open - (const char* filename, int flags, int mode)
-----------------------------------------------------------------------------*/
long monitor::handle_open_log_args(int childnum)
{
    char* str1;
    int   i;

    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (i = start; i < lim; ++i)
    {
        str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_OPEN(%s, 0x%08X = %s, 0x%08X = %s)\n", childs[i].childpid,
                   str1,
                   ARG2(i), getTextualFileFlags(ARG2(i)).c_str(),
                   ARG3(i), getTextualFileMode(ARG3(i) & S_FILEMODEMASK).c_str());
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_open_precall(int childnum)
{
    for (int i = 0; i < mvee::numvariants - 1; ++i)
	{
        if ((ARG2(i) & O_FILEFLAGSMASK) != (ARG2(i+1) & O_FILEFLAGSMASK))
			return MVEE_PRECALL_ARGS_MISMATCH(2) | MVEE_PRECALL_CALL_DENY;
		if ((ARG2(i) & O_CREAT) && ((ARG3(i) & S_FILEMODEMASK) != (ARG3(i+1) & S_FILEMODEMASK)))
			return MVEE_PRECALL_ARGS_MISMATCH(3) | MVEE_PRECALL_CALL_DENY;
	}            

    CHECKPOINTER(1);
    CHECKSTRING(1);

    std::string full_path = set_fd_table->get_full_path(childs[0].childpid, AT_FDCWD, (void*)ARG1(0));
    if (full_path == "")
        return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;

    childs[0].args[1].set_str(full_path);

    if (full_path.find("/proc/self/") == 0
        && full_path != "/proc/self/maps"
        && full_path != "/proc/self/exe")
    {
        debugf("master sys_open for: %s\n", full_path.c_str());
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    }

    if (full_path.find("/dev/") == 0)
    {
        debugf("master sys_open for: %s\n", full_path.c_str());
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_open_call(int childnum)
{
    int         i, result, old_flags, flags;
    std::string str1 = STRINGARG(0, 1);

    flags  = old_flags = ARG2(0);
    result = handle_check_open_call(str1.c_str(), &flags, ARG3(0));

    /*
     * LIBREOFFICE MADNESS: They use fcntl calls after
     * open (with O_CREAT | O_EXCL) to check if the file was opened with the correct flags......
     * ==> we should manipulate the call arguments but store the original flags in the fd_info...
     if (flags != old_flags)
     for (i = 0; i < mvee::numvariants; ++i)
     SETARG2(i, flags);

     => should be:
     mvee_wrap_ptrace(PTRACE_POKEUSER, childs[i].childpid, 4*ECX, (void*)flags);

     for LibreOffice
     */
    if (flags != old_flags)
        for (i = 0; i < mvee::numvariants; ++i)
            SETARG2(i, flags);

    return result;
}

long monitor::handle_open_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, fds)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_OPEN return: %d\n", childs[i].childpid, fds[i]);

    return 0;
}

void switch_pid(char* resolved_path, char* path, pid_t old_id, pid_t new_id) // Copies path in resolved_path while replacing old_id with new_id
{
    char *childpid   =(char *)malloc(sizeof(int));
    int   childpidlen=sprintf(childpid, "%d", old_id);
    char *ptr        =strstr(path, childpid);                                /* Ptr points to the occurence of childpid */
    if (ptr!=NULL)
    {
        int len      = ptr-path;
        snprintf(resolved_path, len+1, "%s", path);                          /* Copies path into resolved_path until the occurence of chilpid */
        int new_idlen=sprintf(resolved_path+len, "%d", new_id);              /* Copies the new pid*/
        sprintf(resolved_path+(len+new_idlen), "%s", ptr+childpidlen);       /*copies the end of path */
    }
    free(childpid);
}

long monitor::handle_open_postcall(int childnum)
{
    unsigned char              unsynced = 0;

    std::vector<unsigned long> fds      = call_postcall_get_result_vector();
    REPLICATEFDRESULT();

    if (call_succeeded)
    {
        // get full path and add new file descriptor mapping for the
        // opened file if the call hasn't been denied
        char*       resolved_path = NULL;
        std::string tmp_path      = STRINGARG(0, 1);

        if (tmp_path.find("/proc/") == 0)
        {
            char maps[30];
            sprintf(maps, "/proc/%d/maps", childs[0].childpid);

            if (!tmp_path.compare(maps))
                unsynced = 1;
        }
        if (!tmp_path.compare("/proc/self/maps"))
            unsynced = 1;

        resolved_path = realpath(tmp_path.c_str(), NULL);

		FileType type = (unsynced == 0) ? FT_REGULAR : FT_SPECIAL;
        set_fd_table->create_fd_info(type, fds, resolved_path, ARG2(0), ARG2(0) & O_CLOEXEC, state == STATE_IN_MASTERCALL, unsynced);

#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
        free(resolved_path);
    }

    return 0;
}


/*-----------------------------------------------------------------------------
  sys_close - (int filedescriptor)
-----------------------------------------------------------------------------*/
long monitor::handle_close_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_CLOSE(%d)\n", childs[i].childpid, ARG1(i));

    return 0;
}

long monitor::handle_close_precall(int childnum)
{
    CHECKFD(1);

    fd_info* info = set_fd_table->get_fd_info(ARG1(0));
    if (!info)
    {
#ifdef MVEE_ENABLE_VALGRIND_HACKS
        if (ARG1(0) > 1024)
            return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
#endif

        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }

    if (info->master_file)
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;

    MAPFDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_close_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_close_postcall(int childnum)
{
    if (call_succeeded)
    {
        set_fd_table->free_fd_info(ARG1(0));
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }
    if (state != STATE_IN_MASTERCALL)
        UNMAPFDS(1);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_waitpid - (pid_t pid, int __user *stat_addr, int options)
-----------------------------------------------------------------------------*/
long monitor::handle_waitpid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_WAITPID(%d, 0x" PTRSTR ", %d)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i));

    return 0;
}

long monitor::handle_waitpid_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    MAPPIDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_waitpid_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, pids)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_WAITPID return: %d\n", childs[i].childpid, pids[i]);

    return 0;
}

long monitor::handle_waitpid_postcall(int childnum)
{
    long tmp    = ARG4(0);
    ARG4(0) = 0;
    long result = handle_wait4_postcall(childnum);
    ARG4(0) = tmp;
    return result;
}

/*-----------------------------------------------------------------------------
  sys_link - (const char __user *oldname, const char __user *newname)
-----------------------------------------------------------------------------*/
long monitor::handle_link_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKSTRING(2);

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_unlink - (const char __user *pathname)
-----------------------------------------------------------------------------*/
long monitor::handle_unlink_get_call_type(int childnum)
{
#ifdef MVEE_ENABLE_VALGRIND_HACKS
    char* unlink_fd = mvee_rw_read_string(childs[childnum].childpid, ARG1(childnum));
    if (unlink_fd && strstr(unlink_fd, "/tmp/vgdb-pipe-"))
    {
        SAFEDELETEARRAY(unlink_fd);
        return MVEE_CALL_TYPE_UNSYNCED;
    }
    SAFEDELETEARRAY(unlink_fd);
#endif
    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_unlink_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* unlink_fd = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_UNLINK(%s)\n", childs[i].childpid,
                   unlink_fd);

        SAFEDELETEARRAY(unlink_fd);
    }

    return 0;
}

long monitor::handle_unlink_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_unlink_postcall(int childnum)
{
#ifdef MVEE_ENABLE_VALGRIND_HACKS
    if (childnum != -1)
    {
        char* unlink_fd = mvee_rw_read_string(childs[childnum].childpid, ARG1(childnum));
        if (unlink_fd && strstr(unlink_fd, "/tmp/vgdb-pipe") == unlink_fd)
            WRITE_SYSCALL_RETURN(childnum, 0)
            SAFEDELETEARRAY(unlink_fd);
    }
#endif
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_execve - (char __user *filename, char __user * __user *argv,
  char __user * __user *envp);
-----------------------------------------------------------------------------*/
// Fetching the execve arguments is very costly, especially without PTRACE_EXT_COPYSTRING
// it must only be done once!
void monitor::handle_execve_get_args(int childnum)
{
    set_mmap_table->mmap_execve_id = monitorid;
    unsigned int      argc = 0;

    std::stringstream args;

    set_mmap_table->mmap_execve_argv.clear();

    // determine number of arguments
    if (ARG2(childnum))
    {
        while (true)
        {
            long res = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[childnum].childpid, ARG2(childnum) + sizeof(long)*argc++, NULL);
            if (res == 0 || res == -1)
            {
                argc--;
                break;
            }
        }

        if (argc > 0)
        {
            for (unsigned int i = 0; i < argc; ++i)
            {
                unsigned long argvp = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[childnum].childpid,
                                                       ARG2(childnum) + sizeof(long)*i, NULL);
//				warnf("Reading argv[%d] data\n", i);
                char*         tmp   = mvee_rw_read_string(childs[childnum].childpid, argvp);
//				warnf("done\n");
                if (tmp)
                {
                    set_mmap_table->mmap_execve_argv.push_back(std::string(tmp));
                    args << tmp << " ";
                }
                SAFEDELETEARRAY(tmp);
            }
        }
    }

    set_mmap_table->mmap_execve_image = set_fd_table->get_full_path(childs[childnum].childpid, AT_FDCWD, (void*)ARG1(childnum));
    set_mmap_table->mmap_execve_args  = args.str();

#if defined(MVEE_FILTER_LOGGING) && !defined(MVEE_BENCHMARK)
    if (set_mmap_table->mmap_execve_image.find("parsec-2.1") != std::string::npos
        || set_mmap_table->mmap_execve_image.find("parsec-3.0") != std::string::npos
        || set_mmap_table->mmap_execve_image.find("spec2006") != std::string::npos)
    {
        set_mmap_table->set_logging_enabled = 1;
        warnf("Logging enabled for binary: %s\n", set_mmap_table->mmap_execve_image.c_str());
    }
#endif
}

long monitor::handle_execve_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        handle_execve_get_args(i);

        debugf("pid: %d - SYS_EXECVE(%s (0x" PTRSTR ") -- %s (0x" PTRSTR ")\n",
                   childs[i].childpid,
                   set_mmap_table->mmap_execve_image.c_str(),
                   ARG1(i),
                   set_mmap_table->mmap_execve_args.c_str(),
                   ARG2(i));
    }

    return 0;
}

long monitor::handle_execve_precall(int childnum)
{
	VariantArch arch;

    handle_execve_get_args(0);
    std::string orig_image = set_mmap_table->mmap_execve_image;
    std::string orig_args  = set_mmap_table->mmap_execve_args;

	if (mvee::is_qemu_executable(orig_image, arch))
		warnf("Variant %d is switching to ISA: %s\n", 0, getTextualISA(arch));

    for (int i = 1; i < mvee::numvariants; ++i)
    {
        handle_execve_get_args(i);
		if (mvee::is_qemu_executable(set_mmap_table->mmap_execve_image, arch))
			warnf("Variant %d is switching to ISA: %s\n", i, getTextualISA(arch));

        if (set_mmap_table->mmap_execve_image != orig_image)
        {
            cache_mismatch_info("execve image mismatch\n");
            return MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(1);
        }
        if (set_mmap_table->mmap_execve_args != orig_args)
        {
            cache_mismatch_info("execve args mismatch\n");
            return MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(2);
		}
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_execve_call(int childnum)
{
#ifndef MVEE_BENCHMARK
    warnf("Children are executing another program: %s -- %s\n",
                set_mmap_table->mmap_execve_image.c_str(),
                set_mmap_table->mmap_execve_args.c_str());
#endif

#ifdef MVEE_ALLOW_PERF
    if (set_mmap_table->mmap_execve_image.find("perf/perf") != std::string::npos)
        perf = 1;
#endif

    if (!mvee::config.mvee_hide_vdso
        && !mvee::config.mvee_use_dcl
        && mvee::custom_library_path.size() == 0)
        return MVEE_CALL_ALLOW;

    unsigned int      i, argv_len = 0;

    std::deque<char*> original_argv = get_original_argv();

    // we're going to use the MVEE_LD_Loader to load the original program indirectly
    // the full path to the original image is now MVEE_LD_Loader's argv[1]
    if (original_argv.size() > 1)
    {
        SAFEDELETEARRAY(original_argv.front());
        original_argv.pop_front();
    }
    original_argv.push_front(mvee::strdup(set_mmap_table->mmap_execve_image.c_str()));

    // the program might be trying to exec a script
    if (!mvee::os_add_interp_for_file(original_argv, set_mmap_table->mmap_execve_image))
    {
        SAFEDELETEARRAY(original_argv.front());
        original_argv.pop_front();
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(ENOENT);
    }

//	std::string rpath = mvee::os_get_rpath(set_mmap_table->mmap_execve_image);

    if (mvee::custom_library_path.size() > 0/* || rpath.size() > 0*/)
    {
		std::stringstream ss;
/*		if (rpath.size() > 0)
		ss << rpath;*/
		if (mvee::custom_library_path.size() > 0)
		{
			if (ss.gcount() > 0)
				ss << ":";
			ss << mvee::custom_library_path;
		}

		char* tmp = mvee::strdup(ss.str().c_str());
        original_argv.push_front(tmp);
        original_argv.push_front(mvee::strdup("--library-path"));
    }

    if (mvee::config.mvee_hide_vdso || mvee::config.mvee_use_dcl)
        original_argv.push_front(mvee::strdup(MVEE_LD_LOADER_NAME));
    else
        original_argv.push_front(mvee::strdup(MVEE_ARCH_INTERP_NAME));

    for (i = 0; i < original_argv.size(); ++i)
        if (original_argv[i])
            argv_len += strlen(original_argv[i]) + 1;

    char*       serialized_argv = (char*)mvee_rw_safe_alloc(argv_len);
    char**      relocated_argv  = NULL;
    serialize_and_relocate_arr(original_argv, serialized_argv, relocated_argv, 0);

    // get new file image
    set_mmap_table->mmap_execve_loader =
        (mvee::config.mvee_hide_vdso || mvee::config.mvee_use_dcl) ?
        mvee::os_get_mvee_ld_loader() : mvee::os_get_interp();

    for (i = 0; i < (unsigned int)mvee::numvariants; ++i)
    {
        long int child_stack_pointer = SP(childs[i].regs) - 1024 - argv_len;

        for (unsigned j = 0; j < original_argv.size(); ++j)
            // relocated_argv[0] will be NULL at this point because it's at position 0 in the serialized array
            if (relocated_argv[j] || (j == 0))
                relocated_argv[j] += child_stack_pointer;

        // write new argv strings
        mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)serialized_argv,
                          childs[i].childpid, child_stack_pointer, argv_len);
        // write new argv array
        mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)relocated_argv,
                          childs[i].childpid,
                          child_stack_pointer - sizeof(char*)*(original_argv.size()), sizeof(char*)*(original_argv.size()));

        mvee_rw_copy_data(mvee::os_gettid(), (unsigned long)set_mmap_table->mmap_execve_loader.c_str(),
                          childs[i].childpid,
                          child_stack_pointer - sizeof(char*)*(original_argv.size()) - set_mmap_table->mmap_execve_loader.length() - 1,
                          set_mmap_table->mmap_execve_loader.length() + 1);

        // set new execve arguments
        SETARG1(i, (child_stack_pointer - sizeof(char*)*(original_argv.size()) - set_mmap_table->mmap_execve_loader.length() - 1));
        SETARG2(i, (child_stack_pointer - sizeof(char*)*(original_argv.size())));

        for (unsigned j = 0; j < original_argv.size(); ++j)
            if (relocated_argv[j])
                relocated_argv[j] -= child_stack_pointer;
    }

    for (i = 0; i < original_argv.size(); ++i)
        SAFEDELETEARRAY(original_argv[i]);
    SAFEDELETEARRAY(relocated_argv);
    SAFEDELETEARRAY(serialized_argv);

    return MVEE_CALL_ALLOW;
}

long monitor::handle_execve_postcall(int childnum)
{
    if (call_succeeded)
    {
        int i;

        // "During an execve(2), the dispositions of handled signals are
        // reset to the default; the dispositions of ignored signals are
        // left unchanged."
        set_sighand_table->reset();

        // close all file descriptors that have O_CLOEXEC set
        set_fd_table->free_cloexec_fds();

        if (created_by_vfork)
        {
            created_by_vfork = false;

            std::shared_ptr<mmap_table> new_table = std::shared_ptr<mmap_table>(new mmap_table());
            call_release_syslocks(childnum, __NR_execve, MVEE_SYSLOCK_FULL);
            set_mmap_table.reset();
            set_mmap_table   = new_table;
            call_grab_syslocks(childnum, __NR_execve, MVEE_SYSLOCK_FULL);
        }

		set_mmap_table->truncate_table();
		for (i = 0; i < mvee::numvariants; ++i)
			set_mmap_table->refresh_child_maps(i, childs[i].childpid);

		ipmon_initialized = false;

        for (i = 0; i < mvee::numvariants; ++i)
            set_mmap_table->verify_mman_table(i, childs[i].childpid);

        if (mvee::config.mvee_use_dcl)
        {
            // We need to check whether the initial VDSO pages overlap since we have
            // no control over where these are mapped...
            std::vector<bool> should_restart(mvee::numvariants);
            int               ret;
            // static int restart_test = 0;

            for (int i = 1; i < mvee::numvariants; ++i)
            {
                if ((ret = set_mmap_table->check_vdso_overlap(i)) > -1 /* || restart_test++ == 0*/)
                {
                    warnf("Detected vdso overlap for childs %d (PID: %d) and %d (PID: %d)\n",
                                i, childs[i].childpid,
                                ret, childs[ret].childpid);
                    should_restart[i] = true;
                }
            }

            int               tries = 0;
            for (int j = 1; j < mvee::numvariants; ++j)
            {
                while (should_restart[j])
                {
                    if (!restart_child(j))
                    {
                        warnf("Restart failed for child %d\n", j);
                        shutdown(false);
                        return 0;
                    }
                    set_mmap_table->truncate_table_child(i);
                    set_mmap_table->refresh_child_maps(j, childs[j].childpid);
                    if ((ret = set_mmap_table->check_vdso_overlap(j)) > -1)
                    {
                        warnf("Still detected vdso overlap...\n");
                        tries++;

                        if (tries > 5)
                        {
                            warnf("Are you trying to be funny by disabling ASLR?!\n");
                            shutdown(false);
                            return 0;
                        }
                    }
                    else
                    {
                        should_restart[j] = false;
                    }
                }
            }
        }
    }
	else
	{		
		if (mvee::str_ends_with(set_mmap_table->mmap_execve_loader, MVEE_LD_LOADER_NAME))
		{
			warnf("Could not start the variants (EXECVE error).\n");
			warnf("You probably forgot to compile the MVEE LD Loader. Please refer to MVEE/README.txt\n");
			shutdown(true);
		}
	}

#ifdef MVEE_FD_DEBUG
    for (int i = 0; i < mvee::numvariants; ++i)
        set_fd_table->print_fd_table_proc(childs[i].childpid);
#endif

#ifdef MVEE_FD_DEBUG
    set_fd_table->verify_fd_table(getpids());
#endif

    // create a new shm table...
    // man page: "Attached System V shared memory segments are detached (shmat(2))."
    call_release_syslocks(childnum, __NR_execve, MVEE_SYSLOCK_FULL);
    set_shm_table.reset();
    set_shm_table = std::shared_ptr<shm_table>(new shm_table);
    call_grab_syslocks(childnum, __NR_execve, MVEE_SYSLOCK_FULL);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_chdir - (const char __user *filename)
-----------------------------------------------------------------------------*/
long monitor::handle_chdir_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_chdir_postcall(int childnum)
{
    char* str;

    if (call_succeeded)
    {
        str = mvee_rw_read_string(childs[0].childpid, ARG1(0));
        if (str)
            set_fd_table->chdir(str);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_time - (time_t __user *tloc)
-----------------------------------------------------------------------------*/
long monitor::handle_time_precall(int childnum)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_time_postcall(int childnum)
{
    if (ARG1(0))
        REPLICATEBUFFERFIXEDLEN(1, sizeof(time_t));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_chmod - (const char __user *filename, mode_t mode)
-----------------------------------------------------------------------------*/
long monitor::handle_chmod_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fchmod - (unsigned int fd, mode_t mode)
-----------------------------------------------------------------------------*/
long monitor::handle_fchmod_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_lseek - (unsigned int fd, off_t offset, unsigned int origin)
-----------------------------------------------------------------------------*/
long monitor::handle_lseek_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_LSEEK(%d, 0x%08X, %d)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i));

    return 0;
}

long monitor::handle_lseek_precall(int childnum)
{
    CHECKARG(3);
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_alarm - (unsigned int seconds)
-----------------------------------------------------------------------------*/
long monitor::handle_alarm_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_setitimer - (int which, const struct itimerval* new_value, struct itimerval* old_value)
-----------------------------------------------------------------------------*/
long monitor::handle_setitimer_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    if (ARG2(0))
        CHECKBUFFER(2, sizeof(struct itimerval));
    CHECKPOINTER(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_setitimer_postcall(int childnum)
{
    if (call_succeeded && ARG3(0))
        REPLICATEBUFFERFIXEDLEN(3, sizeof(struct itimerval));
    return 0;
}

/*-----------------------------------------------------------------------------
    sys_getpid
-----------------------------------------------------------------------------*/
long monitor::handle_getpid_postcall(int childnum)
{
    for (int i = 1; i < mvee::numvariants; ++i)
    {
        WRITE_SYSCALL_RETURN(i, childs[0].childtgid);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sendfile - (int out_fd, int in_fd, off_t __user * offset, size_t count)
-----------------------------------------------------------------------------*/
long monitor::handle_sendfile_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SENDFILE(OUT: %d, IN: %d, CNT: %d)\n",
                   childs[i].childpid, ARG1(i), ARG2(i), ARG4(i));

    return 0;
}

long monitor::handle_sendfile_precall(int childnum)
{
    CHECKFD(1);
    CHECKFD(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ptrace
-----------------------------------------------------------------------------*/
long monitor::handle_ptrace_call(int childnum)
{
    cache_mismatch_info("The program is trying to use ptrace. This call has been denied.\n");
    cache_mismatch_info("request: %s\n",        getTextualRequest(ARG1(0)));
    cache_mismatch_info("pid: %d\n",            ARG2(0));
    cache_mismatch_info("addr: 0x" PTRSTR "\n", ARG3(0));
    cache_mismatch_info("data: 0x" PTRSTR "\n", ARG4(0));

    return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
}

/*-----------------------------------------------------------------------------
  sys_pause
-----------------------------------------------------------------------------*/
long monitor::handle_pause_get_call_type(int childnum)
{
    // There is a slight chance that we will see the return site of
    // the initial pause call
    return MVEE_CALL_TYPE_UNSYNCED;
}

long monitor::handle_pause_call(int childnum)
{
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
}

long monitor::handle_pause_postcall(int childnum)
{
    return MVEE_POSTCALL_RESUME;
}

/*-----------------------------------------------------------------------------
  sys_rt_sigsuspend - (const sigset_t* sigset)
-----------------------------------------------------------------------------*/
long monitor::handle_rt_sigsuspend_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_RT_SIGSUSPEND(%s)\n", childs[i].childpid, 
			   getTextualSigSet(call_get_sigset(i, ARG1(i), OLDCALLIFNOT(__NR_rt_sigsuspend))).c_str());

    return 0;

}

long monitor::handle_rt_sigsuspend_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSIGSET(1, OLDCALLIFNOT(__NR_rt_sigsuspend));

    memcpy(&old_blocked_signals, &blocked_signals, sizeof(sigset_t));
    sigemptyset(&blocked_signals);

    if (ARG1(0))
    {
        sigset_t _set = call_get_sigset(0, ARG1(0), OLDCALLIFNOT(__NR_rt_sigsuspend));

        for (int i = SIGINT; i < __SIGRTMAX; ++i)
            if (sigismember(&_set, i))
                sigaddset(&blocked_signals, i);
    }

    debugf("> SIGSUSPEND ENTRY - blocked signals are now: %s\n",
               getTextualSigSet(blocked_signals).c_str());

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_rt_sigsuspend_postcall(int childnum)
{
    memcpy(&blocked_signals, &old_blocked_signals, sizeof(sigset_t));
    sigemptyset(&old_blocked_signals);

    debugf("> SIGSUSPEND EXIT - blocked signals are now: %s\n",
               getTextualSigSet(blocked_signals).c_str());

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_utime - change access and/or modification times of an inode
  (char __user *, filename, struct utimbuf __user *, times)
-----------------------------------------------------------------------------*/
long monitor::handle_utime_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKBUFFER(2, sizeof(struct utimbuf));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_mknod - (const char *pathname, mode_t mode, dev_t dev)
-----------------------------------------------------------------------------*/
long monitor::handle_mknod_precall(int childnum)
{
	CHECKPOINTER(1);
	CHECKARG(2);
	CHECKARG(3);
	CHECKSTRING(1);
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_access - (const char * filename, int mode)
-----------------------------------------------------------------------------*/
long monitor::handle_access_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_ACCESS(%s, 0x%08X = %s)\n", childs[i].childpid,
                   str1, ARG2(i), getTextualAccessMode(ARG2(i)).c_str());
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_access_precall(int childnum)
{
    //  for (int i = 0; i < mvee::numvariants; ++i)
    //    log_child_backtrace(i);
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_kill - (int pid, int sig)
-----------------------------------------------------------------------------*/
long monitor::handle_kill_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_KILL(%d, %s)\n", childs[i].childpid, ARG1(i), getTextualSig(ARG2(i)));

    return 0;
}

long monitor::handle_kill_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_rename - (const char __user *oldname, const char __user *newname)
-----------------------------------------------------------------------------*/
long monitor::handle_rename_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_mkdir - (const char __user *pathname, int mode)
-----------------------------------------------------------------------------*/
long monitor::handle_mkdir_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_rmdir - (const char __user *pathname)
-----------------------------------------------------------------------------*/
long monitor::handle_rmdir_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_creat - (const char __user* pathname, umode_t mode)
-----------------------------------------------------------------------------*/
long monitor::handle_creat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_CREAT(%s, %d)\n", childs[i].childpid, str, ARG2(i));
        SAFEDELETEARRAY(str);
    }

    return 0;
}

long monitor::handle_creat_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_creat_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds = call_postcall_get_result_vector();
        char*                      str = mvee_rw_read_string(childs[0].childpid, ARG1(0));

        set_fd_table->create_fd_info(FT_REGULAR, fds, str, O_WRONLY, false, false, false, 0);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif

        SAFEDELETEARRAY(str);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
    sys_dup - (unsigned int oldfd)
-----------------------------------------------------------------------------*/
long monitor::handle_dup_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_DUP(%d)\n", childs[i].childpid, ARG1(i));

    return 0;
}

long monitor::handle_dup_precall(int childnum)
{
    CHECKFD(1);

    if (set_fd_table->is_fd_master_file(ARG1(0)))
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    else
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
}

long monitor::handle_dup_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_dup_log_return(int childnum)
{
    if (childnum == -1 && state == STATE_IN_MASTERCALL)
        childnum = 0;

    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, fds)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_DUP(%d) return: %d\n", childs[i].childpid, ARG1(i), fds[i]);

    return 0;
}

long monitor::handle_dup_postcall(int childnum)
{
    std::vector<unsigned long> fds;
    bool                       master_file = false;

    if (state == STATE_IN_MASTERCALL)
    {
        fds.resize(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
        master_file = true;
    }
    else
    {
        fds = call_postcall_get_result_vector();
        UNMAPFDS(1);
        REPLICATEFDRESULT();
    }

    // dups succeeded => add new fds
    if (call_succeeded)
    {
        fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
        if (!fd_info)
        {
            warnf("WTF IS GOING ON HERE? DUP FAIL!!!");
            return 0;
        }
        set_fd_table->create_fd_info(fd_info->file_type, fds, fd_info->path.c_str(), fd_info->access_flags, false, master_file, fd_info->unsynced_reads, fd_info->original_file_size);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif

    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pipe - (int __user * fildes)
-----------------------------------------------------------------------------*/
long monitor::handle_pipe_precall(int childnum)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_pipe_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_pipe_postcall(int childnum)
{
    if (call_succeeded)
    {
        int                        fildes[2];
        std::vector<unsigned long> read_fds(mvee::numvariants);
        std::vector<unsigned long> write_fds(mvee::numvariants);

        if (!mvee_rw_read_struct(childs[0].childpid, ARG1(0), 2 * sizeof(int), fildes))
        {
            warnf("couldn't read fds\n");
            return 0;
        }

        std::fill(read_fds.begin(),  read_fds.end(),  fildes[0]);
        std::fill(write_fds.begin(), write_fds.end(), fildes[1]);

        REPLICATEBUFFERFIXEDLEN(1, sizeof(int) * 2);

        // add new file descriptor mappings for the created pipe
        set_fd_table->create_fd_info(FT_PIPE_BLOCKING, read_fds,  "pipe:read",  O_RDONLY, false, true);
        set_fd_table->create_fd_info(FT_PIPE_BLOCKING, write_fds, "pipe:write", O_WRONLY, false, true);

#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_times - (struct tms  *  tbuf)
-----------------------------------------------------------------------------*/
long monitor::handle_times_precall(int childnum)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_times_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct tms));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_brk
-----------------------------------------------------------------------------*/
long monitor::handle_brk_call(int childnum)
{
    //mvee_log_child_backtrace(0);
    return MVEE_CALL_ALLOW;
}

long monitor::handle_brk_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, addrs);

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_BRK(0x" LONGPTRSTR ") return = 0x" LONGPTRSTR "\n",
                   childs[i].childpid, ARG1(i), addrs[i]);

    return 0;
}

long monitor::handle_brk_postcall(int childnum)
{
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        long              result      = call_postcall_get_child_result(i);
        mmap_region_info* heap_region = set_mmap_table->get_heap_region(i);
        fd_info           backing_file;

        // BRK only returns the current end of the heap, not the start.
        // consequently, if we do not have the heap region in our maps yet, we have no choice
        // but to read it from /proc/%d/maps
        //
        // Do note that a heap MAY not be allocated until the first BRK call with a non-NULL arg
        //
        // In the old days we could've assumed that the heap started right after the last
        // mapped region of the current program (i.e., its last bss section). Thanks
        // to ASLR that is no longer true though.
        //
        // We could technically also read the __currbrk syms from the program's GOT..
        if (!heap_region)
        {
            char          cmd[512];
            std::string   output;
            unsigned long heap_start;
            unsigned long heap_end;

            /*
               warnf("VDSO BACKTRACE TEST!!!\n");
               mvee_log_child_backtrace(i);
             */

            sprintf(cmd, "cat /proc/%d/maps | grep \"\\[heap\\]\"", childs[i].childpid);
            output                          = mvee::log_read_from_proc_pipe(cmd, NULL);

            if (output == "" || sscanf(output.c_str(), LONGPTRSTR "-" LONGPTRSTR " %*s %*08x %*s %*s %*s", &heap_start, &heap_end) != 2)
            {
                // There is no heap yet...
                set_mmap_table->verify_mman_table(i, childs[i].childpid);
                return 0;
            }

            backing_file.fds.resize(mvee::numvariants);
            backing_file.fds[i]             = MVEE_UNKNOWN_FD;
            backing_file.path               = "[heap]";
            backing_file.access_flags       = 0;
            backing_file.original_file_size = 0;

            set_mmap_table->map_range(i, heap_start, result-heap_start, MAP_ANONYMOUS | MAP_PRIVATE, PROT_READ | PROT_WRITE, &backing_file, 0);
        }
        else
        {
            // the kernel will not allow us to:
            // a) change the base of the heap
            // b) request a new size that would cause overlaps with existing vma's (mapped regions)
            // it is therefore safe to just update the heap_region's size here
            heap_region->region_size = ROUND_UP(result - heap_region->region_base_address, 4096);
        }

        set_mmap_table->verify_mman_table(i, childs[i].childpid);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getgid
-----------------------------------------------------------------------------*/
long monitor::handle_getgid_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, gids)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_GETGID return: %d (%s)\n", childs[i].childpid,
                   gids[i], getTextualGroupId(gids[i]).c_str());

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_syslog - (int type, char __user * buf, int len)
-----------------------------------------------------------------------------*/
long monitor::handle_syslog_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SYSLOG(%s, 0x" PTRSTR ", %d)\n", childs[i].childpid,
                   getTextualSyslogAction(ARG1(i)),
                   ARG2(i),
                   ARG3(i));

    return 0;
}

long monitor::handle_syslog_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(3);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_syslog_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        if (ARG1(0) == SYSLOG_ACTION_READ ||
            ARG1(0) == SYSLOG_ACTION_READ_ALL ||
            ARG1(0) == SYSLOG_ACTION_READ_CLEAR)
        {
            char* str = (rets[i] > 0) ? mvee_rw_read_string(childs[i].childpid, ARG2(i), rets[i]) : NULL;
            debugf("pid: %d - SYS_SYSLOG return: %s\n", childs[i].childpid, str);
            SAFEDELETEARRAY(str);
        }
        else
        {
            debugf("pid: %d - SYS_SYSLOG return: %d\n", childs[i].childpid, rets[i]);
        }
    }

    return 0;
}

long monitor::handle_syslog_postcall(int childnum)
{
    if (call_succeeded
        && (ARG1(0) == SYSLOG_ACTION_READ
            || ARG1(0) == SYSLOG_ACTION_READ_ALL
            || ARG1(0) == SYSLOG_ACTION_READ_CLEAR))
    {
        REPLICATEBUFFER(2);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setuid
-----------------------------------------------------------------------------*/
long monitor::handle_setuid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SETUID(%d = %s)\n", childs[i].childpid,
                   ARG1(i), getTextualGroupId(ARG1(i)).c_str());

    return 0;
}

long monitor::handle_setuid_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_setgid
-----------------------------------------------------------------------------*/
long monitor::handle_setgid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SETGID(%d = %s)\n", childs[i].childpid,
                   ARG1(i), getTextualGroupId(ARG1(i)).c_str());

    return 0;
}

long monitor::handle_setgid_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_signal - (int sig, __sighandler_t handler)
-----------------------------------------------------------------------------*/
long monitor::handle_signal_precall(int childnum)
{
    CHECKARG(1);
    CHECKSIGHAND(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_signal_postcall(int childnum)
{
    if (call_succeeded)
    {
        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = (__sighandler_t)ARG2(0);
        action.sa_flags   = SA_ONESHOT | SA_NOMASK;
        sigemptyset(&action.sa_mask);
        set_sighand_table->set_sigaction(ARG1(0), &action);
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_ioctl - (unsigned int fd, unsigned int cmd, unsigned long arg)
-----------------------------------------------------------------------------*/
long monitor::handle_ioctl_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_IOCTL(%d, %d, 0x" PTRSTR ")\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i));

    return 0;
}

// there are many many ioctls we don't know yet
// http://man7.org/linux/man-pages/man2/ioctl_list.2.html
long monitor::handle_ioctl_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    CHECKPOINTER(3);

//	log_child_backtrace(0);

    unsigned char is_master = 0;
    switch(ARG2(0))
    {
        case TCGETS:     // struct termios *
            is_master = set_fd_table->is_fd_master_file(ARG1(0));
            break;

        case FIONREAD:   // int*
        case TIOCGWINSZ: // struct winsize *
        case TIOCGPGRP:  // pid_t *
        case TIOCSPGRP:  // const pid_t *
            is_master = 1;
            break;
        case TCSETS:     // const struct termios *
        case TCSETSW:    // const struct termios *
        case TCSETSF:    // const struct termios *
            CHECKBUFFER(3, sizeof(struct __kernel_termios));
            is_master = 1;
            break;
        case FIONBIO:    // int*
        case FIOASYNC:
            is_master = 1;
            CHECKBUFFER(3, sizeof(int));
            break;
        case TIOCSWINSZ:
            CHECKBUFFER(3, sizeof(struct winsize));
            is_master = 1;
            break;
        case FIOCLEX:
        case FIONCLEX:
            break;
        default:
            warnf("unknown ioctl: %d (0x%08x)\n", ARG2(0), ARG2(0));
            //			log_child_backtrace(0);
            shutdown(false);
            break;
    }

    if (!is_master)
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
    else
    {
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    }
}

long monitor::handle_ioctl_postcall(int childnum)
{
    switch(ARG2(0))
    {
        case FIONREAD:
            REPLICATEBUFFERFIXEDLEN(3, sizeof(int));
            break;
        case TCGETS:
            REPLICATEBUFFERFIXEDLEN(3, sizeof(struct __kernel_termios));
            break;
        case TIOCGPGRP:
            REPLICATEBUFFERFIXEDLEN(3, sizeof(pid_t));
            break;
        case TIOCGWINSZ:
            REPLICATEBUFFERFIXEDLEN(3, sizeof(struct winsize));
            break;
        // sets cloexec on the fd
        case FIOCLEX:
            if (call_succeeded)
            {
                fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
                if (fd_info)
                    fd_info->close_on_exec = true;
            }
            break;
        // clears cloexec on the fd
        case FIONCLEX:
            if (call_succeeded)
            {
                fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
                if (fd_info)
                    fd_info->close_on_exec = false;
            }
            break;
    }

    if (state != STATE_IN_MASTERCALL)
        UNMAPFDS(1);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fcntl - (unsigned int fd, unsigned int cmd, unsigned long arg)
-----------------------------------------------------------------------------*/
long monitor::handle_fcntl_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_FCNTL(%d, %s, 0x" PTRSTR ")\n", childs[i].childpid, ARG1(i), getTextualFcntlCmd(ARG2(i)), ARG3(i));

    return 0;
}

long monitor::handle_fcntl_precall(int childnum)
{
    CHECKARG(2);

    if (ARG2(0) == F_DUPFD || ARG2(0) == F_DUPFD_CLOEXEC || ARG2(0) == F_SETFD)
        CHECKFD(1);

    if (ARG2(0) == F_DUPFD || ARG2(0) == F_DUPFD_CLOEXEC
        || (ARG2(0) == F_SETFD && ARG3(0) == FD_CLOEXEC))
    {
        if (!set_fd_table->is_fd_master_file(ARG1(0)))
        {
            MAPFDS(1);
            return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
        }
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fcntl_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_fcntl_postcall(int childnum)
{
    //warnf("fcntl postcall. %s\n", getTextualFcntlCmd(ARG2(0)));

    if (call_succeeded)
    {
        if (ARG2(0) == F_GETLK || ARG2(0) == F_GETLK64) // locking operations
        {
            REPLICATEBUFFERFIXEDLEN(3, sizeof(struct flock));
        }
        else if (ARG2(0) == F_SETFD)
        {
            if (ARG3(0) == FD_CLOEXEC)
            {
                fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
                if (fd_info)
                    fd_info->close_on_exec = true;
                if (state != STATE_IN_MASTERCALL)
                    UNMAPFDS(1);
            }
        }
        else if (ARG2(0) == F_DUPFD || ARG2(0) == F_DUPFD_CLOEXEC)
        {
            // This can be dispatched as either a mastercall or as a normal call
            // Mastercall IFF the fd is a master_file
            // else normal call
            if (call_succeeded)
            {
                std::vector<unsigned long> fds;
                if (state == STATE_IN_MASTERCALL)
                {
                    fds.resize(mvee::numvariants);
                    std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
                }
                else
                {
                    fds = call_postcall_get_result_vector();
                    REPLICATEFDRESULT();
                    UNMAPFDS(1);
                }

                fd_info*                   fd_info = set_fd_table->get_fd_info(ARG1(0));
                if (!fd_info)
                {
                    set_fd_table->print_fd_table();
                    warnf("WTF IS GOING ON HERE? FCNTL FAIL!!!");
                    return 0;
                }

                set_fd_table->create_fd_info(fd_info->file_type, fds, fd_info->path.c_str(), fd_info->access_flags, (ARG2(0) == F_DUPFD_CLOEXEC) ? true : fd_info->close_on_exec, state == STATE_IN_MASTERCALL, fd_info->unsynced_reads, fd_info->original_file_size);

#ifdef MVEE_FD_DEBUG
                set_fd_table->verify_fd_table(getpids());
#endif
            }
			else if (ARG2(0) == F_SETFL)
			{
				if (ARG3(0) & O_NONBLOCK)
					set_fd_table->set_non_blocking(ARG1(0));
				else
					set_fd_table->set_blocking(ARG1(0));
			}
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_flock - (unsigned int fd, unsigned int operation)
-----------------------------------------------------------------------------*/
long monitor::handle_flock_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_FLOCK(%u, %u (%s))\n", childs[i].childpid,
                   ARG1(i), ARG2(i), getTextualFlockType(ARG2(i)));

    return 0;
}

long monitor::handle_flock_precall(int childnum)
{
    CHECKFD(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_umask - (int mask)
-----------------------------------------------------------------------------*/
long monitor::handle_umask_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_UMASK(%d = %s)\n", childs[i].childpid,
                   ARG1(i), getTextualFileMode(ARG1(i)).c_str());

    return 0;
}

long monitor::handle_umask_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_umask_postcall(int childnum)
{
    syscall(__NR_umask, ARG1(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_dup2 - (unsigned int oldfd, unsigned int newfd)
-----------------------------------------------------------------------------*/
long monitor::handle_dup2_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_DUP2(%d, %d)\n", childs[i].childpid, ARG1(i), ARG2(i));

    return 0;
}

long monitor::handle_dup2_precall(int childnum)
{
    CHECKFD(1);
    CHECKFD(2);

#ifdef MVEE_FD_DEBUG
    set_fd_table->print_fd_table();
    for (int i = 0; i < mvee::numvariants; ++i)
        set_fd_table->print_fd_table_proc(childs[i].childpid);
#endif

    if (set_fd_table->is_fd_master_file(ARG1(0)))
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    else
    {
        MAPFDS(1);
        MAPFDS(2);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
}

long monitor::handle_dup2_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_dup2_log_return(int childnum)
{
    if (childnum == -1 && state == STATE_IN_MASTERCALL)
        childnum = 0;

    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, fds)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_DUP2(%d, %d) return: %d\n", childs[i].childpid, ARG1(i), ARG2(i), fds[i]);

    return 0;
}

long monitor::handle_dup2_postcall(int childnum)
{
    std::vector<unsigned long> fds;

    if (state == STATE_IN_MASTERCALL)
    {
        fds.resize(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
    }
    else
    {
        fds = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
        UNMAPFDS(1);
        UNMAPFDS(2);
    }

    // dups succeeded => add new fds
    // if newfd == oldfd, dup2 does nothing and returns newfd...
    if (call_succeeded)
    {
        if (ARG1(0) != ARG2(0))
        {
            // if newfd already exists, dup2 will close it first
            // and then duplicate oldfd as newfd.
            //
            // freeing a non-existing fd will do nothing
            set_fd_table->free_fd_info(ARG2(0));

            // now dup a file with the same path, access flags
            // and close_on_exec flag as before
            fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
            if (!fd_info)
            {
                warnf("WTF IS GOING ON HERE? DUP2 FAIL!!!");
                return 0;
            }

            set_fd_table->create_fd_info(fd_info->file_type, fds, fd_info->path.c_str(), fd_info->access_flags, false, fd_info->master_file, fd_info->unsynced_reads, fd_info->original_file_size);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setpgid
-----------------------------------------------------------------------------*/
long monitor::handle_setpgid_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getppid
-----------------------------------------------------------------------------*/
long monitor::handle_getppid_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getppid_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, pids)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_GETPPID() return: %d\n", childs[i].childpid, pids[i]);

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpgrp
-----------------------------------------------------------------------------*/
long monitor::handle_getpgrp_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setsid
-----------------------------------------------------------------------------*/
long monitor::handle_setsid_precall(int childnum)
{
    warnf("Process is creating a new session (i.e. it's becoming a daemon!)\n");
    for (int i = 0; i < mvee::numvariants; ++i)
        warnf("> Process %d PID: %d\n", i, childs[i].childpid);
    warnf("> Process Name: %s\n", set_mmap_table->mmap_execve_image.c_str());
    warnf("> Process Args: %s\n", set_mmap_table->mmap_execve_args.c_str());
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getgroups - (int gidsetsize, gid_t __user* grouplist)
-----------------------------------------------------------------------------*/
long monitor::handle_getgroups_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_getgroups_log_return(int childnum)
{
    if (call_succeeded)
    {
        MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

        for (int i = start; i < lim; ++i)
        {
            if (ARG2(i))
            {
                gid_t* grouplist = (gid_t*)mvee_rw_safe_alloc(sizeof(gid_t) * rets[i]);
                if (!mvee_rw_read_struct(childs[i].childpid, ARG2(i), sizeof(gid_t) * rets[i], grouplist))
                {
                    warnf("couldn't read grouplist\n");
                    SAFEDELETEARRAY(grouplist);
                    return 0;
                }

                debugf("pid: %d - SYS_GETGROUPS return: %s\n", childs[i].childpid,
                           getTextualGroups(rets[i], grouplist).c_str());
                SAFEDELETEARRAY(grouplist);
            }
            else
            {
                debugf("pid: %d - SYS_GETGROUPS return: %d\n", childs[i].childpid,
                           rets[i]);
            }
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setgroups - (int gidsetsize, gid_t __user* grouplist)
-----------------------------------------------------------------------------*/
long monitor::handle_setgroups_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        if (ARG1(i) && ARG2(i))
        {
            gid_t* grouplist = (gid_t*)mvee_rw_safe_alloc(sizeof(gid_t) * ARG1(i));
            memset(grouplist, 0, sizeof(gid_t) * ARG1(i));
            if (!mvee_rw_read_struct(childs[i].childpid, ARG2(i), sizeof(gid_t) * ARG1(i), grouplist))
            {
                warnf("couldn't read grouplist\n");
                SAFEDELETEARRAY(grouplist);
                return 0;
            }

            debugf("pid: %d - SYS_SETGROUPS (%s)\n", childs[i].childpid,
                       getTextualGroups(ARG1(i), grouplist).c_str());
            SAFEDELETEARRAY(grouplist);
        }
    }

    return 0;
}

long monitor::handle_setgroups_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKBUFFER(2, ARG1(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_setresuid
-----------------------------------------------------------------------------*/
long monitor::handle_setresuid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_SETRESUID (%d (= %s), %d (= %s), %d (= %s))\n",
                   childs[i].childpid,
                   ARG1(i), getTextualUserId(ARG1(i)).c_str(),
                   ARG2(i), getTextualUserId(ARG2(i)).c_str(),
                   ARG3(i), getTextualUserId(ARG3(i)).c_str());
    }

    return 0;
}

long monitor::handle_setresuid_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_setresgid
-----------------------------------------------------------------------------*/
long monitor::handle_setresgid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_SETRESGID (%d (= %s), %d (= %s), %d (= %s))\n",
                   childs[i].childpid,
                   ARG1(i), getTextualGroupId(ARG1(i)).c_str(),
                   ARG2(i), getTextualGroupId(ARG2(i)).c_str(),
                   ARG3(i), getTextualGroupId(ARG3(i)).c_str());
    }

    return 0;
}

long monitor::handle_setresgid_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
    sys_rt_sigaction - (int sig, const struct sigaction __user *act,
    struct sigaction __user *oact, size_t sigsetsize)
-----------------------------------------------------------------------------*/
long monitor::handle_rt_sigaction_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        struct sigaction action DEBUGVAR = call_get_sigaction(i, ARG2(i), OLDCALLIFNOT(__NR_rt_sigaction));

        debugf("pid: %d - SYS_RT_SIGACTION(%d - %s - %s)\n", childs[i].childpid, ARG1(i), getTextualSig(ARG1(i)),
                   (action.sa_handler == SIG_DFL) ? "SIG_DFL" :
                   (action.sa_handler == SIG_IGN) ? "SIG_IGN" :
                   (action.sa_handler == (__sighandler_t)-2) ? "---" : "SIG_PTR"
                   );
    }

    return 0;
}

long monitor::handle_rt_sigaction_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(4);
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKSIGACTION(2, OLDCALLIFNOT(__NR_rt_sigaction));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_rt_sigaction_postcall(int childnum)
{
    if (call_succeeded && ARG2(0))
    {
        struct sigaction action = call_get_sigaction(0, ARG2(0), OLDCALLIFNOT(__NR_rt_sigaction));
        set_sighand_table->set_sigaction(ARG1(0), &action);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_arch_prctl - (int code, unsigned long addr)
-----------------------------------------------------------------------------*/
long monitor::handle_arch_prctl_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_arch_prctl_postcall(int childnum)
{
    //	log_child_backtrace(0);
    return 0;
}

/*-----------------------------------------------------------------------------
    sys_sync
-----------------------------------------------------------------------------*/
long monitor::handle_sync_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_setrlimit - (int resource, const struct rlimit *rlim)
-----------------------------------------------------------------------------*/
long monitor::handle_setrlimit_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        struct rlimit  rlim;
        unsigned char* tmp = mvee_rw_read_data(childs[i].childpid, ARG2(i), sizeof(struct rlimit));
        if (!tmp)
        {
            warnf("couldn't read rlimit\n");
            return 0;
        }
        memcpy(&rlim, tmp, sizeof(struct rlimit));
        SAFEDELETEARRAY(tmp);

        debugf("pid: %d - SYS_SETRLIMIT(%s, CUR: %d, MAX: %d)\n", childs[i].childpid,
                   getTextualRlimitType(ARG1(i)), rlim.rlim_cur, rlim.rlim_max);
    }

    return 0;
}

long monitor::handle_setrlimit_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*long monitor::hndle_setrlimit_call(int childnum)
{
	if (ARG1(0) == RLIMIT_NOFILE)
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	return MVEE_CALL_ALLOW;
}*/


/*-----------------------------------------------------------------------------
  sys_getrusage - (int who, struct rusage *usage)
-----------------------------------------------------------------------------*/
long monitor::handle_getrusage_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getrusage_postcall(int childnum)
{
    if (ARG2(0))
        REPLICATEBUFFERFIXEDLEN(2, sizeof(struct rusage));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sysinfo - (struct sysinfo *info)
-----------------------------------------------------------------------------*/
long monitor::handle_sysinfo_precall(int childnum)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_sysinfo_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct sysinfo));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_gettimeofday - (struct timeval *tv, struct timezone *tz)
-----------------------------------------------------------------------------*/
long monitor::handle_gettimeofday_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(1);
//	log_child_backtrace(0);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_gettimeofday_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct timeval));
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct timezone));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getrlimit (unsigned int resource, struct rlimit __user* limit)
-----------------------------------------------------------------------------*/
long monitor::handle_getrlimit_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_getrlimit_postcall(int childnum)
{
    //    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct rlimit));
    return 0;
}


/*-----------------------------------------------------------------------------
  sys_symlink - (const char  *  oldname, const char  *  newname)
-----------------------------------------------------------------------------*/
long monitor::handle_symlink_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_readlink - (const char __user *path, char __user *buf, int bufsiz)
-----------------------------------------------------------------------------*/
long monitor::handle_readlink_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_readlink_call(int childnum)
{
	char* str = mvee_rw_read_string(childs[0].childpid, ARG1(0));

	// ridiculous hack for java and other shit
	if (str && !strcmp(str, "/proc/self/exe"))
	{
		if (ARG3(0) > set_mmap_table->mmap_execve_image.length())
		{
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				mvee_rw_write_data(childs[i].childpid, ARG2(i), 
								   set_mmap_table->mmap_execve_image.length(), 
								   (unsigned char*)set_mmap_table->mmap_execve_image.c_str());
			}

			return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(set_mmap_table->mmap_execve_image.length());
		}
	}

	return MVEE_CALL_ALLOW;
}

long monitor::handle_readlink_postcall(int childnum)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_munmap
-----------------------------------------------------------------------------*/
long monitor::handle_munmap_get_call_type(int childnum)
{
    // We do NOT want to sync on the munmap of the lower region
    if (in_new_heap_allocation)
    {
        if ((unsigned long)ARG1(childnum) == childs[childnum].last_lower_region_start
            && (unsigned long)ARG2(childnum) == childs[childnum].last_lower_region_size)
            return MVEE_CALL_TYPE_UNSYNCED;
    }

    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_munmap_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_MUNMAP(0x" PTRSTR ", %d)\n", childs[i].childpid, ARG1(i), ARG2(i));

    return 0;
}

bool monitor::handle_munmap_precall_callback(mmap_table* table, std::vector<mmap_region_info*>& infos, void* mon)
{
    infos[0]->print_region_info("munmap precall callback - region 0 >>>");

    // writeback region, fetch the buffer, compare it
    // take partial unmaps, offset, etc into account here! ugh!
    if (infos[0]->region_map_flags & MAP_MVEE_WASSHARED)
    {
        std::vector<childstate> & childs       = ((monitor*)mon)->childs;

        unsigned long           actual_base    = MAX(infos[0]->region_base_address, (unsigned long)ARG1(0));
        unsigned long           actual_limit   = MIN(infos[0]->region_size + infos[0]->region_base_address, (unsigned long)ARG1(0) + (unsigned long)ARG2(0));
        unsigned long           actual_size    = actual_limit - actual_base;
        unsigned long           actual_offset  = actual_base - infos[0]->region_base_address + infos[0]->region_backing_file_offset;
        int                     writeback_size = MIN(infos[0]->region_backing_file_size - actual_offset, actual_size - actual_offset);

        debugf("actual size of munmap: %d\n",                                      actual_size);
        debugf("writeback_size: %d (actual offset: %d - backing_file_size: %d)\n", writeback_size, actual_offset, infos[0]->region_backing_file_size);
        debugf("writeback region - we will write back %d bytes at offset: %08x in file: %s\n",
                   writeback_size, actual_offset, infos[0]->region_backing_file_path.c_str());

        writeback_info          info;
        info.writeback_regions     = new mmap_region_info*[mvee::numvariants];
        for (int i = 0; i < mvee::numvariants; ++i)
            info.writeback_regions[i] = infos[i];
        info.writeback_buffer_size = writeback_size;
        info.writeback_buffer      = new unsigned char[writeback_size];

        mvee_rw_copy_data(childs[0].childpid, actual_base, mvee::os_getpid(), (unsigned long)info.writeback_buffer, writeback_size);

        bool                    mismatch       = false;

        for (int i = 1; i < mvee::numvariants; ++i)
        {
            unsigned char* child_region = new unsigned char[writeback_size];
            mvee_rw_copy_data(childs[i].childpid, MAX(infos[i]->region_base_address, (unsigned long)ARG1(i)),
                              mvee::os_getpid(), (unsigned long)child_region, writeback_size);

            if (memcmp(info.writeback_buffer, child_region, writeback_size))
            {
                mismatch = true;

                debugf("write_back region mismatch!!!\n");
                debugf("> master region hex dump: %s\n", mvee::log_do_hex_dump(info.writeback_buffer, writeback_size).c_str());
                debugf("> child region hex dump: %s\n",  mvee::log_do_hex_dump(child_region, writeback_size).c_str());

                SAFEDELETEARRAY(child_region);
                break;
            }

            SAFEDELETEARRAY(child_region);
        }

        if (mismatch)
        {
            warnf("writeback region mismatch\n");
            SAFEDELETEARRAY(info.writeback_regions);
            SAFEDELETEARRAY(info.writeback_buffer);
            return false;
        }
        else
        {
            ((monitor*)mon)->writeback_infos.push_back(info);
        }
    }

    return true;
}

long monitor::handle_munmap_precall(int childnum)
{
    /*  if (childnum != -1)
    mvee_log_child_backtrace(childnum);
    else
    {
    for (int i = 0; i < mvee::numvariants; ++i)
    mvee_log_child_backtrace(i);
    }    */

    // We ONLY allow unsynced munmaps for the unmapping
    // of the region below the newly allocated heap.
    // Check the comments about ptmalloc in MVEE_private.h
    // for further information
    if (childnum != -1)
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    if (in_new_heap_allocation)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            if ((unsigned long)ARG1(i) != childs[i].last_upper_region_start)
				return MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(1);
			if ((unsigned long)ARG2(i) != childs[i].last_upper_region_size)
				return MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(2);
        }
    }
    else
    {
        CHECKARG(2);

        // compare regions
        CHECKREGION(1, ARG2(0));

        // finally, check whether these are writeback regions
        std::vector<unsigned long> addresses(mvee::numvariants);
        FILLARGARRAY(1, addresses);
        if (set_mmap_table->foreach_region(addresses, ARG2(0), this, handle_munmap_precall_callback) != 0)
            return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_munmap_postcall(int childnum)
{
    int release_locks = 0;

    // lower region munmap
    if (childnum != -1)
    {
        if (call_postcall_get_child_result(childnum) == 0)
            set_mmap_table->munmap_range(childnum, ARG1(childnum), ARG2(childnum));
        return 0;
    }

    if (call_succeeded)
    {
        // perform the writebacks
        for (std::vector<writeback_info>::iterator it = writeback_infos.begin();
             it != writeback_infos.end(); ++it)
        {
            warnf("writing back private mapping - FILE: %s\n", it->writeback_regions[0]->region_backing_file_path.c_str());
            FILE* fp = fopen(it->writeback_regions[0]->region_backing_file_path.c_str(), "wb+");

            if (!fp)
                warnf("can't open writeback file!\n");
            else
            {
                if (it->writeback_buffer_offset)
                    fseek(fp, it->writeback_buffer_offset, SEEK_SET);
                fwrite(it->writeback_buffer, 1, it->writeback_buffer_size, fp);
                fclose(fp);
                warnf("finished writing back to file!\n");
            }
        }

        for (int i = 0; i < mvee::numvariants; ++i)
            set_mmap_table->munmap_range(i, ARG1(i), ARG2(i));
    }

    while (writeback_infos.size() > 0)
    {
        writeback_info info = writeback_infos.back();
        SAFEDELETEARRAY(info.writeback_regions);
        SAFEDELETEARRAY(info.writeback_buffer);
        writeback_infos.pop_back();
    }

    // this is the unmap of the upper region!!! we need to release those
    // extra locks we took in mmap here
    if (in_new_heap_allocation)
    {
        in_new_heap_allocation = false;
        release_locks          = 1;
    }

    if (childnum != -1)
        set_mmap_table->verify_mman_table(childnum, childs[childnum].childpid);
    else
        for (int i = 0; i < mvee::numvariants; ++i)
            set_mmap_table->verify_mman_table(i, childs[i].childpid);

#ifdef MVEE_MMAN_DEBUG
    set_mmap_table->print_mmap_table();
#endif
    if (release_locks)
        call_release_locks(MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN);

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_truncate - (const char  *  path, long  length)
-----------------------------------------------------------------------------*/
long monitor::handle_truncate_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ftruncate - (unsigned int  fd, unsigned long  length)
-----------------------------------------------------------------------------*/
long monitor::handle_ftruncate_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ioperm
-----------------------------------------------------------------------------*/
long monitor::handle_ioperm_call(int childnum)
{
    cache_mismatch_info("The program is trying to access I/O ports. This call has been denied.\n");
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
}

/*-----------------------------------------------------------------------------
  sys_quotactl - (unsigned int cmd, const char* special, qid_t id, void* addr)
-----------------------------------------------------------------------------*/
long monitor::handle_quotactl_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);

    unsigned int subcmd = ((ARG1(0)) >> SUBCMDSHIFT);

    switch(subcmd)
    {
        /* The id argument is the identification number of the quota format to be used. */
        /* The addr argument points to the pathname of a file containing the quotas for the filesystem. */
        case Q_QUOTAON:
        {
            CHECKARG(3);
            CHECKPOINTER(4);
            CHECKSTRING(4);
            break;
        }
        /* Get disk quota limits and current usage for user or group id. */
        /* The addr argument is a pointer to a dqblk structure */
        case Q_GETQUOTA:
        {
            CHECKARG(3);
            CHECKPOINTER(4);
            break;
        }
        case Q_SETQUOTA:
        {
            CHECKARG(3);
            CHECKPOINTER(4);
            CHECKBUFFER(4, sizeof(dqblk));
            break;
        }
        /* The addr argument should be a pointer to a dqinfo structure. */
        /* The id argument is ignored. */
        case Q_GETINFO:
        {
            CHECKPOINTER(4);
            break;
        }
        case Q_SETINFO:
        {
            CHECKPOINTER(4);
            CHECKBUFFER(4, sizeof(dqinfo));
            break;
        }
        /* The addr argument should be a pointer to a 4-byte buffer where the format number will be stored. */
        case Q_GETFMT:
        {
            CHECKPOINTER(4);
            break;
        }
        /* The addr and id arguments are ignored. */
        case Q_SYNC:
        case Q_QUOTAOFF:
        {
            break;
        }
        default:
        {
            cache_mismatch_info("unknown sys_quotactl subcommand: %d - FIXME!\n", subcmd);
            return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;
        }
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_quotactl_postcall(int childnum)
{
    unsigned int subcmd = ((ARG1(0)) >> SUBCMDSHIFT);

    switch(subcmd)
    {
        case Q_GETQUOTA:
        {
            REPLICATEBUFFERFIXEDLEN(4, sizeof(dqblk));
            break;
        }
        case Q_GETINFO:
        {
            REPLICATEBUFFERFIXEDLEN(4, sizeof(dqinfo));
            break;
        }
        case Q_GETFMT:
        {
            REPLICATEBUFFERFIXEDLEN(4, sizeof(unsigned int));
            break;
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_socket - (int family, int type, int protocol)
-----------------------------------------------------------------------------*/
long monitor::handle_socket_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_SOCKET(%d = %s, %d = %s, %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), getTextualSocketFamily(ARG1(i)),
                   ARG2(i), getTextualSocketType(ARG2(i)).c_str(),
                   ARG3(i), getTextualSocketProtocol(ARG3(i)));
    }

    return 0;
}

long monitor::handle_socket_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_socket_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
		
		FileType type = (ARG2(0) & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING;
        set_fd_table->create_fd_info(type, fds, "sock:unnamed", 0, (ARG2(0) & SOCK_CLOEXEC) ? true : false, true);

#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif

    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_bind - (int fd, struct sockaddr __user * umyaddr, int addrlen)
-----------------------------------------------------------------------------*/
long monitor::handle_bind_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        GETTEXTADDRDIRECT(i, text_addr, 2, ARG3(i));
        debugf("pid: %d - SYS_BIND(%d, %s, %d)\n",
                   childs[i].childpid,
                   ARG1(i), text_addr.c_str(), ARG3(i));
    }

    return 0;
}

long monitor::handle_bind_precall(int childnum)
{
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKBUFFER(2, ARG3(0));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_bind_postcall(int childnum)
{
    if (call_succeeded)
    {
        GETTEXTADDRDIRECT(0, text_addr, 2, ARG3(0));
        fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0), 0);
        if (fd_info && text_addr != "")
            fd_info->path = std::string("srvsock:") + text_addr;
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_connect - (int fd, struct sockaddr __user * uservaddr, int addrlen)
-----------------------------------------------------------------------------*/
long monitor::handle_connect_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        GETTEXTADDRDIRECT(i, text_addr, 2, ARG3(i));
        debugf("pid: %d - SYS_CONNECT(%d, %s, %d)\n",
                   childs[i].childpid,
                   ARG1(i), text_addr.c_str(), ARG3(i));
    }
    return 0;
}

long monitor::handle_connect_precall(int childnum)
{
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKSOCKADDR(2, ARG3(0));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_connect_postcall(int childnum)
{
    if (call_succeeded)
    {
        GETTEXTADDRDIRECT(0, text_addr, 2, ARG3(0));
        fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0), 0);
        if (fd_info && text_addr != "")
            fd_info->path = std::string("clientsock:") + text_addr;
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_listen - (int fd, int backlog)
-----------------------------------------------------------------------------*/
long monitor::handle_listen_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_LISTEN(%d, %d)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i));
    }

    return 0;
}

long monitor::handle_listen_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getsockname - (int fd, struct sockaddr __user * usockaddr,
  int __user * usockaddr_len)
-----------------------------------------------------------------------------*/
long monitor::handle_getsockname_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_GETSOCKNAME(%d, 0x" PTRSTR ")\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i));
    }

    return 0;
}

long monitor::handle_getsockname_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKBUFFER(3, sizeof(int));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getsockname_postcall(int childnum)
{
    REPLICATEBUFFERANDLEN(2, 3, sizeof(int));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpeername - (int fd, struct sockaddr __user * usockaddr,
  int __user * usockaddr_len)
-----------------------------------------------------------------------------*/
long monitor::handle_getpeername_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_GETPEERNAME(%d, 0x" PTRSTR ")\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i));
    }

    return 0;
}

long monitor::handle_getpeername_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKBUFFER(3, sizeof(int));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getpeername_postcall(int childnum)
{
    REPLICATEBUFFERANDLEN(2, 3, sizeof(int));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_socketpair - (int family, int type, int protocol,
  int __user * usockvec)
-----------------------------------------------------------------------------*/
long monitor::handle_socketpair_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_SOCKETPAIR(%d = %s, %d = %s, %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), getTextualSocketFamily(ARG1(i)),
                   ARG2(i), getTextualSocketType(ARG2(i)).c_str(),
                   ARG3(i), getTextualSocketProtocol(ARG3(i)));
    }

    return 0;
}

long monitor::handle_socketpair_precall(int childnum)
{
    CHECKPOINTER(4);
    CHECKARG(3);
    CHECKARG(2);
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_socketpair_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        mvee_word word1 DEBUGVAR, word2 DEBUGVAR;
        word1._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG4(i), NULL);
        word2._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG4(i) + sizeof(int), NULL);

        debugf("pid: %d - SYS_SOCKETPAIR return: [%d, %d]\n", childs[i].childpid, word1._int, word2._int);
    }

    return 0;
}

long monitor::handle_socketpair_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::vector<unsigned long> fds2(mvee::numvariants);

        mvee_word                  word;
        word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[0].childpid, ARG4(0), NULL);
        std::fill(fds.begin(),  fds.end(),  word._int);
        word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[0].childpid, ARG4(0) + sizeof(int), NULL);
        std::fill(fds2.begin(), fds2.end(), word._int);

		FileType type = (ARG2(0) & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING;
        set_fd_table->create_fd_info(type, fds,  "sock:unnamed", 0, (ARG2(0) & SOCK_CLOEXEC) ? true : false, true);
        set_fd_table->create_fd_info(type, fds2, "sock:unnamed", 0, (ARG2(0) & SOCK_CLOEXEC) ? true : false, true);

#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif

        for (int i = 1; i < mvee::numvariants; ++i)
        {
            word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG4(i), NULL);
            word._int  = fds[0];
            mvee_wrap_ptrace(PTRACE_POKEDATA, childs[i].childpid, ARG4(i),               (void*)word._long);
            word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG4(i) + sizeof(int), NULL);
            word._int  = fds2[0];
            mvee_wrap_ptrace(PTRACE_POKEDATA, childs[i].childpid, ARG4(i) + sizeof(int), (void*)word._long);

        }
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sendto -  (int fd, void __user * buff, size_t len,
  unsigned int flags, struct sockaddr __user * addr, int addr_len)
-----------------------------------------------------------------------------*/
long monitor::handle_sendto_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        GETTEXTADDRDIRECT(i, text_addr, 5, ARG6(i));
        std::string buf_str = call_serialize_io_buffer(i, ARG2(i), ARG3(i));
        debugf("pid: %d - SYS_SENDTO(%d, " PTRSTR " (%s), %d, %d = %s, 0x" PTRSTR " (%s), %d)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), buf_str.c_str(),
                   ARG3(i),
                   ARG4(i), getTextualSocketMsgFlags(ARG4(i)).c_str(),
                   ARG5(i), text_addr.c_str(),
                   ARG6(i));
    }

    return 0;
}

long monitor::handle_sendto_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(5);
    CHECKARG(6);
    CHECKARG(4);
    CHECKARG(3);
    CHECKBUFFER(5, ARG6(0));
    CHECKBUFFER(2, ARG3(0));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_send -  (int fd, void __user * buff, size_t len,
  unsigned int flags)

  WRAPPER AROUND SENDTO!!!

  Is this deprecated now?!
-----------------------------------------------------------------------------*/
long monitor::handle_send_get_call_type(int childnum)
{
    ARG5(childnum) = 0;
    ARG6(childnum) = 0;
    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_send_log_args(int childnum)
{
    return handle_sendto_log_args(childnum);
}

long monitor::handle_send_precall(int childnum)
{
    return handle_sendto_precall(childnum);
}

/*-----------------------------------------------------------------------------
  sys_recvfrom - (int fd, void __user * ubuf, size_t size,
  unsigned int flags, struct sockaddr __user * addr,
  int __user * addr_len)
-----------------------------------------------------------------------------*/
long monitor::handle_recvfrom_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_RECVFROM(%d, " PTRSTR ", %d, %d = %s, 0x" PTRSTR ", %d)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i),
                   ARG3(i),
                   ARG4(i), getTextualSocketMsgFlags(ARG4(i)).c_str(),
                   ARG5(i),
                   ARG6(i));
    }

    return 0;
}

long monitor::handle_recvfrom_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(5);
    CHECKPOINTER(6);
    CHECKARG(4);
    CHECKARG(3);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_recvfrom_postcall(int childnum)
{
    REPLICATEBUFFER(2);
    REPLICATEBUFFERANDLEN(5, 6, sizeof(int));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_shutdown - (int fd, int how)
-----------------------------------------------------------------------------*/
long monitor::handle_shutdown_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_SHUTDOWN(%d, %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), getTextualSocketShutdownHow(ARG2(i)));
    }

    return 0;
}

long monitor::handle_shutdown_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setsockopt - (int fd, int level, int optname,
  char __user * optval, int optlen)
-----------------------------------------------------------------------------*/
long monitor::handle_setsockopt_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        std::string str = call_serialize_io_buffer(i, ARG4(i), ARG5(i));
        debugf("pid: %d - SYS_SETSOCKOPT(%d, %d, %d, %s, %d)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), str.c_str(), ARG5(i));
    }

    return 0;
}

long monitor::handle_setsockopt_precall(int childnum)
{
    CHECKPOINTER(4);
    CHECKARG(5);
    CHECKARG(3);
    CHECKARG(2);
    CHECKFD(1);
    CHECKBUFFER(4, ARG5(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getsockopt - (int fd, int level, int optname,
  char __user * optval, int __user * optlen)
-----------------------------------------------------------------------------*/
long monitor::handle_getsockopt_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_GETSOCKOPT(%d, %d, %d, 0x" PTRSTR ", 0x" PTRSTR ")\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), ARG4(i), ARG5(i));
    }

    return 0;
}

long monitor::handle_getsockopt_precall(int childnum)
{
    CHECKARG(3);
    CHECKARG(2);
    CHECKFD(1);
    CHECKPOINTER(4);
    CHECKPOINTER(5);
    CHECKBUFFER(5, sizeof(int));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getsockopt_postcall(int childnum)
{
    REPLICATEBUFFERANDLEN(4, 5, sizeof(int));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sendmsg - (int fd, struct msghdr __user * msg, unsigned int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_sendmsg_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        struct msghdr msg;
        if (!mvee_rw_read_struct(childs[i].childpid, ARG2(i), sizeof(struct msghdr), &msg))
        {
            warnf("couldn't read msghdr\n");
            return 0;
        }

        std::string   msg_str = call_serialize_msgvector(i, &msg);
        debugf("pid: %d - SYS_SENDMSG(%d, 0x" PTRSTR " (%s), %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), msg_str.c_str(),
                   ARG3(i), getTextualSocketMsgFlags(ARG3(i)).c_str());
    }

    return 0;
}

long monitor::handle_sendmsg_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKMSGVECTOR(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_sendmmsg - (int fd, struct mmsghdr __user * mmsg,
  unsigned int vlen, unsigned int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_sendmmsg_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_SENDMMSG(%d, 0x" PTRSTR ", %d, %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), ARG4(i), getTextualSocketMsgFlags(ARG4(i)).c_str());
    }

    return 0;
}

long monitor::handle_sendmmsg_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKMMSGVECTOR(2, ARG3(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_sendmmsg_postcall(int childnum)
{
    // update msg_len fields
    REPLICATEMMSGVECTORLENS(2, ARG3(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_recvmsg - (int fd, struct msghdr __user * msg,
  unsigned int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_recvmsg_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_RECVMSG(%d, 0x" PTRSTR ", %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), getTextualSocketMsgFlags(ARG3(i)).c_str());
    }

    return 0;
}

long monitor::handle_recvmsg_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKMSGVECTORLAYOUT(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_recvmsg_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        struct msghdr msg;
        if (!mvee_rw_read_struct(childs[i].childpid, ARG2(i), sizeof(struct msghdr), &msg))
        {
            warnf("couldn't read msghdr\n");
            return 0;
        }

        std::string   _msg = call_serialize_msgvector(i, &msg);
        debugf("pid: %d - SYS_RECVMSG return: %d - %s\n", childs[i].childpid, rets[i], _msg.c_str());
    }

    return 0;
}

long monitor::handle_recvmsg_postcall(int childnum)
{
    REPLICATEMSGVECTOR(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_recvmmsg - (int fd, struct mmsghdr __user * mmsg,
  unsigned int vlen, unsigned int flags,
  struct timespec __user * timeout)
-----------------------------------------------------------------------------*/
long monitor::handle_recvmmsg_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKPOINTER(5);
    CHECKBUFFER(5, sizeof(struct timespec));
    CHECKMMSGVECTORLAYOUT(2, ARG3(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_recvmmsg_postcall(int childnum)
{
    REPLICATEMMSGVECTOR(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_accept4 - (int fd, struct sockaddr __user * upeer_sockaddr,
  int __user * upeer_addrlen, int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_accept4_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_ACCEPT4(%d, 0x" PTRSTR ", 0x" PTRSTR ", %d = %s)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), ARG4(i), getTextualSocketType(ARG4(i)).c_str());
    }

    return 0;
}

long monitor::handle_accept4_precall(int childnum)
{
    CHECKARG(4);
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_accept4_postcall(int childnum)
{
    REPLICATEBUFFERANDLEN(2, 3, sizeof(int));

    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));

        if (ARG2(0) && ARG3(0))
        {
            GETTEXTADDR(0, text_addr, 2, 3);

			FileType type = (ARG4(0) & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING;
            set_fd_table->create_fd_info(type, fds, text_addr, 0, (ARG4(0) & SOCK_CLOEXEC) ? true : false, true, 0);

#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
        else
        {
			FileType type = (ARG4(0) & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING;
            set_fd_table->create_fd_info(type, fds, "sock:unknown", 0, (ARG4(0) & SOCK_CLOEXEC) ? true : false, true);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_eventfd2 - (unsigned int count, int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_eventfd2_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EVENTFD2(%d, %d = %s)\n", childs[i].childpid, ARG1(i), ARG2(i) & 0xffffffff, getTextualEventFdFlags(ARG2(i)  & 0xffffffff));

    return 0;
}

long monitor::handle_eventfd2_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_eventfd2_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EVENTFD2 return: %d\n", childs[i].childpid, rets[i]);

    return 0;
}

long monitor::handle_eventfd2_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));

		FileType type = (ARG2(0) & EFD_NONBLOCK) ? FT_POLL_NON_BLOCKING : FT_POLL_BLOCKING;
        set_fd_table->create_fd_info(type, fds, "eventfd", 0, (ARG2(0) & EFD_CLOEXEC) ? true : false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_epoll_create1 - (int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_epoll_create1_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EPOLL_CREATE1(%d = %s)\n", childs[i].childpid, ARG1(i), getTextualEpollFlags(ARG1(i)));

    return 0;
}

long monitor::handle_epoll_create1_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_epoll_create1_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EPOLL_CREATE1 return: %d\n", childs[i].childpid, rets[i]);

    return 0;
}

long monitor::handle_epoll_create1_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));

        set_fd_table->create_fd_info(FT_POLL_BLOCKING, fds, "epoll_sock", 0, (ARG1(0) & EPOLL_CLOEXEC) ? true : false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }
    return 0;
}


/*-----------------------------------------------------------------------------
  sys_accept - (int fd, struct sockaddr __user * upeer_sockaddr,
  int __user * upeer_addrlen)

  WRAPPER AROUND sys_accept4!!!
-----------------------------------------------------------------------------*/
long monitor::handle_accept_get_call_type(int childnum)
{
    ARG4(childnum) = 0;
    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_accept_log_args(int childnum)
{
    return handle_accept4_log_args(childnum);
}

long monitor::handle_accept_precall(int childnum)
{
    return handle_accept4_precall(childnum);
}

long monitor::handle_accept_postcall(int childnum)
{
    return handle_accept4_postcall(childnum);
}

/*-----------------------------------------------------------------------------
  sys_socketcall - (int call, unsigned long __user *args)

  This is i386 only!!! The syscall has now been split up. See the comment at
  the top. We extract the arguments in handle_socketcall_get_call_type
  and from there on, we use the specialized handlers even on i386!!!
-----------------------------------------------------------------------------*/
// WARNING: do NOT disable this handler!!!
#ifdef __NR_socketcall
long monitor::handle_socketcall_get_call_type(int childnum)
{
    unsigned int  nargs = 0;

#define NARGS(callnum, n) case callnum: nargs = n; break;

    switch(ARG1(childnum))
    {
        NARGS(SYS_SOCKET,      3);
        NARGS(SYS_BIND,        3);
        NARGS(SYS_CONNECT,     3);
        NARGS(SYS_LISTEN,      2);
        NARGS(SYS_ACCEPT,      3);
        NARGS(SYS_GETSOCKNAME, 3);
        NARGS(SYS_GETPEERNAME, 3);
        NARGS(SYS_SOCKETPAIR,  4);
        NARGS(SYS_SEND,        4);
        NARGS(SYS_SENDTO,      6);
        NARGS(SYS_RECV,        4);
        NARGS(SYS_RECVFROM,    6);
        NARGS(SYS_SHUTDOWN,    2);
        NARGS(SYS_SETSOCKOPT,  5);
        NARGS(SYS_GETSOCKOPT,  5);
        NARGS(SYS_SENDMSG,     3);
        NARGS(SYS_RECVMSG,     3);
        NARGS(SYS_ACCEPT4,     4);
    }

    // extract arguments - unspecified arguments are INTENTIONALLY set to zero!!!
    // do not change this behavior, we rely on it!!!
    unsigned long real_args[6];
    memset(real_args, 0, sizeof(unsigned long)*6);
    if (!mvee_rw_read_struct(childs[childnum].childpid, ARG2(childnum), nargs * sizeof(unsigned long), real_args))
    {
        warnf("couldn't read real_args\n");
        return 0;
    }

    ORIGARG1(childnum) = ARG1(childnum);
    ARG1(childnum)     = real_args[0];
    ARG2(childnum)     = real_args[1];
    ARG3(childnum)     = real_args[2];
    ARG4(childnum)     = real_args[3];
    ARG5(childnum)     = real_args[4];
    ARG6(childnum)     = real_args[5];

    switch(ORIGARG1(childnum))
    {
        case SYS_ACCEPT:    return handle_accept_get_call_type(childnum);
    }

    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_socketcall_log_args(int childnum)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKET:    return handle_socket_log_args(childnum);
        case SYS_BIND:      return handle_bind_log_args(childnum);
        case SYS_CONNECT:   return handle_connect_log_args(childnum);
        case SYS_LISTEN:    return handle_listen_log_args(childnum);
        case SYS_ACCEPT:    return handle_accept4_log_args(childnum);  // wrapper
        case SYS_GETSOCKNAME: return handle_getsockname_log_args(childnum);
        case SYS_GETPEERNAME: return handle_getpeername_log_args(childnum);
        case SYS_SOCKETPAIR:  return handle_socketpair_log_args(childnum);
        case SYS_SEND:      return handle_sendto_log_args(childnum);   // wrapper
        case SYS_SENDTO:    return handle_sendto_log_args(childnum);
        case SYS_RECV:      return handle_recvfrom_log_args(childnum); // wrapper
        case SYS_RECVFROM:    return handle_recvfrom_log_args(childnum);
        case SYS_SHUTDOWN:    return handle_shutdown_log_args(childnum);
        case SYS_SETSOCKOPT:  return handle_setsockopt_log_args(childnum);
        case SYS_GETSOCKOPT:  return handle_getsockopt_log_args(childnum);
        case SYS_SENDMSG:   return handle_sendmsg_log_args(childnum);
        case SYS_RECVMSG:   return handle_recvmsg_log_args(childnum);
        case SYS_ACCEPT4:   return handle_accept4_log_args(childnum);
    }

    return 0;
}

long monitor::handle_socketcall_precall(int childnum)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKET:    return handle_socket_precall(childnum);
        case SYS_BIND:      return handle_bind_precall(childnum);
        case SYS_CONNECT:   return handle_connect_precall(childnum);
        case SYS_LISTEN:    return handle_listen_precall(childnum);
        case SYS_ACCEPT:    return handle_accept4_precall(childnum);   // wrapper
        case SYS_GETSOCKNAME: return handle_getsockname_precall(childnum);
        case SYS_GETPEERNAME: return handle_getpeername_precall(childnum);
        case SYS_SOCKETPAIR:  return handle_socketpair_precall(childnum);
        case SYS_SEND:      return handle_sendto_precall(childnum);    // wrapper
        case SYS_SENDTO:    return handle_sendto_precall(childnum);
        case SYS_RECV:      return handle_recvfrom_precall(childnum);  // wrapper
        case SYS_RECVFROM:    return handle_recvfrom_precall(childnum);
        case SYS_SHUTDOWN:    return handle_shutdown_precall(childnum);
        case SYS_SETSOCKOPT:  return handle_setsockopt_precall(childnum);
        case SYS_GETSOCKOPT:  return handle_getsockopt_precall(childnum);
        case SYS_SENDMSG:   return handle_sendmsg_precall(childnum);
        case SYS_RECVMSG:   return handle_recvmsg_precall(childnum);
        case SYS_ACCEPT4:   return handle_accept4_precall(childnum);
    }

    return 0;
}

long monitor::handle_socketcall_postcall(int childnum)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKET:    return handle_socket_postcall(childnum);
        case SYS_BIND:      return handle_bind_postcall(childnum);
        case SYS_CONNECT:   return handle_connect_postcall(childnum);
        case SYS_ACCEPT:    return handle_accept4_postcall(childnum);  // wrapper
        case SYS_GETSOCKNAME: return handle_getsockname_postcall(childnum);
        case SYS_GETPEERNAME: return handle_getpeername_postcall(childnum);
        case SYS_SOCKETPAIR:  return handle_socketpair_postcall(childnum);
        case SYS_RECV:      return handle_recvfrom_postcall(childnum); // wrapper
        case SYS_RECVFROM:    return handle_recvfrom_postcall(childnum);
        case SYS_GETSOCKOPT:  return handle_getsockopt_postcall(childnum);
        case SYS_RECVMSG:   return handle_recvmsg_postcall(childnum);
        case SYS_ACCEPT4:   return handle_accept4_postcall(childnum);
    }

    return 0;
}

long monitor::handle_socketcall_log_return(int childnum)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKETPAIR: return handle_socketpair_log_return(childnum);
        case SYS_RECVMSG: return handle_recvmsg_log_return(childnum);
    }

    return 0;

}

#endif

/*-----------------------------------------------------------------------------
  sys_wait4 - (pid_t pid, int __user *stat_addr,
  int options, struct rusage __user *ru)
-----------------------------------------------------------------------------*/
long monitor::handle_wait4_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_WAIT4(%d, 0x" PTRSTR ", %d, 0x" PTRSTR ")\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), ARG4(i));

    return 0;
}

long monitor::handle_wait4_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKPOINTER(4);
    MAPPIDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_wait4_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, pids)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_WAIT4 return: %d\n", childs[i].childpid, pids[i]);

    return 0;
}

long monitor::handle_wait4_postcall(int childnum)
{
    UNMAPPIDS(1);

    // we want to replicate the master result even if the call fails
    unsigned long master_result = call_postcall_get_child_result(0);

    // if the result is a PID, set the same master PID in
    // all non-master children
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_child_result(i, master_result);

    // hack - the status is set even if the call fails!!!!
    if (ARG2(0))
    {
        MonitorState tmp                = state;
        bool         old_call_succeeded = call_succeeded;
        call_succeeded = true;
        state          = STATE_IN_MASTERCALL;
        REPLICATEBUFFERFIXEDLEN(2, sizeof(int));
        state          = tmp;
        call_succeeded = old_call_succeeded;
    }

    if (ARG4(0))
        REPLICATEBUFFERFIXEDLEN(4, sizeof(struct rusage));

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_shmat - (int shmid, char __user * shmaddr, int shmflg)

  AMD64-only!!! this used to be sys_ipc(SHMAT, shmid, shmaddr, shmflg)
-----------------------------------------------------------------------------*/
long monitor::handle_shmat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SHMAT(%d, 0x" PTRSTR ", %d (= %s))\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), getTextualShmFlags(ARG3(i)).c_str());

    return 0;
}

long monitor::handle_shmat_precall(int childnum)
{
#ifndef MVEE_ALLOW_SHM
	CHECKSHMID(1);
#endif
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_shmat_call(int childnum)
{
	long result = MVEE_CALL_ALLOW;
	bool disjoint_bases = true;
	long shm_sz = PAGE_SIZE;

    if (atomic_buffer &&
        ((int)ARG1(0) == atomic_buffer->id || (int)ARG1(0) == atomic_buffer->eip_id))
	{
        disjoint_bases = false;
		if ((int)ARG1(0) == atomic_buffer->id)
			shm_sz = atomic_buffer->sz;
		else
			shm_sz = atomic_buffer->eip_sz;
	}
	else if (set_fd_table->file_map_exists()
		&& (int)ARG1(0) == set_fd_table->file_map_id())
	{
		disjoint_bases = false;
		shm_sz = PAGE_SIZE;
	}
	else if (childs[0].hidden_buffer_array &&
		(int)ARG1(0) == childs[0].hidden_buffer_array_id) {
		disjoint_bases = true;
		shm_sz = PAGE_SIZE;
	}
	else if (ipmon_buffer && (int)ARG1(0) == ipmon_buffer->id)
	{
		debugf("attach to IP-MON buffer requested\n");
		//disjoint_bases = true;
		disjoint_bases = false;
		shm_sz = ipmon_buffer->sz;
	}
	else
	{
		bool found = false;

		for (std::map<unsigned char, std::shared_ptr<_shm_info> >::iterator it = set_shm_table->table.begin();
			 it != set_shm_table->table.end();
			 ++it)
		{
			if ((int)ARG1(0) == it->second->id
				|| (int)ARG1(0) == it->second->eip_id)
			{
				disjoint_bases = false;
				shm_sz = ((int)ARG1(0) == it->second->id) ? it->second->sz : it->second->eip_sz;
				debugf("this is buffer type: %d\n", it->first);
				found = true;
				break;
			}
		}

		if (!found)
			result = MVEE_CALL_DENY;
	}

	if (result == MVEE_CALL_ALLOW)
	{
		if (disjoint_bases)
		{
			std::vector<unsigned long> bases(mvee::numvariants);
			set_mmap_table->calculate_disjoint_bases(shm_sz, bases);

			for (int i = 0; i < mvee::numvariants; ++i)
			{
				// temporary hack for VARAN experiments
				//				SETARG2(i, bases[0]);

				// this should of course be:
				SETARG2(i, bases[i]);
			}
		}

		return MVEE_CALL_ALLOW;
	}

#ifndef MVEE_ALLOW_SHM
    warnf("The program is trying to attach to shared memory. This call has been denied.\n");
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#else
	return MVEE_CALL_ALLOW;
#endif
}

long monitor::handle_shmat_postcall(int childnum)
{
	std::vector<unsigned long> addresses = call_postcall_get_result_vector();
	std::string region_name = "[anonymous-sys V shm]";
	unsigned long region_size = 0;

	if (!call_succeeded)
	{
		warnf("shmat failed!!!\n");
		return 0;
	}

	if (atomic_buffer &&
		(int)ARG1(0) == atomic_buffer->id && 
		atomic_buffer_hidden)
	{
		region_name = "[atomic-buffer-hidden]";
		region_size = atomic_buffer->sz;

		// register into hidden buffer array
		register_hidden_buffer(MVEE_LIBC_ATOMIC_BUFFER_HIDDEN, atomic_buffer, addresses);
		
		// clear the return value
		for (int i = 0; i < mvee::numvariants; ++i)
			call_postcall_set_child_result(i, 0);
	}
	else if (childs[0].hidden_buffer_array && 
			 (int)ARG1(0) == childs[0].hidden_buffer_array_id)
	{
		region_name = "[hidden-buffer-array]";
		region_size = 4096;

		for (int i = 0; i < mvee::numvariants; ++i)
		{
			childs[i].hidden_buffer_array_base = addresses[i];
			mvee_wrap_ptrace(PTRACE_GETREGS, childs[i].childpid, 0, &childs[i].regsbackup);
            childs[i].regsbackup.gs_base = addresses[i];
			mvee_wrap_ptrace(PTRACE_SETREGS, childs[i].childpid, 0, &childs[i].regsbackup);
			call_postcall_set_child_result(i, 0);

			atomic_queue_pos[i] = (void*)(addresses[i] + 64 * MVEE_LIBC_ATOMIC_BUFFER_HIDDEN + sizeof(void*) + sizeof(unsigned long));
		}
	}
	else if (ipmon_buffer && (int)ARG1(0) == ipmon_buffer->id)
	{
		region_name = "[ipmon-buffer]";
		region_size = ipmon_buffer->sz;
		hwbp_set_watch(0, addresses[0], MVEE_BP_WRITE_ONLY); // detects overwrites of numchilds
		hwbp_set_watch(0, addresses[0] + 64 * (1 + mvee::numvariants), MVEE_BP_WRITE_ONLY); // detects writes of first syscall no
	}
	else if (set_fd_table->file_map_exists() 
			 && (int)ARG1(0) == set_fd_table->file_map_id())
	{
		_shm_info* info = set_fd_table->file_map_get();
		region_name = "[ipmon-file-map]";
		region_size = info->sz;
	}
	else
	{
		for (std::map<unsigned char, std::shared_ptr<_shm_info> >::iterator it = set_shm_table->table.begin();
			 it != set_shm_table->table.end();
			 ++it)
		{
			if ((int)ARG1(0) == it->second->id
				|| (int)ARG1(0) == it->second->eip_id)
			{
				region_name = getTextualBufferType(it->first);			   
				region_size = ((int)ARG1(0) == it->second->id) ? it->second->sz : it->second->eip_sz; 
				break;
			}
		}
	}

	fd_info info;
	info.path = region_name;

	for (int i = 0; i < mvee::numvariants; ++i)
		set_mmap_table->map_range(i, addresses[i], region_size, MAP_SHARED | MAP_ANONYMOUS, PROT_READ | PROT_WRITE, &info, 0);


	return 0;
}

long monitor::handle_shmat_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, results);

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SHMAT return: 0x" PTRSTR "\n", childs[i].childpid, results[i]);

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_ipc - i386 only!!!
-----------------------------------------------------------------------------*/
long monitor::handle_ipc_precall(int childnum)
{
    if (ARG1(0) == SHMAT)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, 1);
        long result = handle_shmat_call(childnum);
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, -1);
        return result;
    }

    return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;
}

long monitor::handle_ipc_call(int childnum)
{
    if (ARG1(0) == SHMAT)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, 1);
        long result = handle_shmat_call(childnum);
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, -1);
        return result;
    }

    return MVEE_CALL_ALLOW;
}

long monitor::handle_ipc_log_return(int childnum)
{
    if (ARG1(0) == SHMAT)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, 1);
        long result = handle_shmat_log_return(childnum);
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, -1);
        return result;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fsync - unsigned int fd
-----------------------------------------------------------------------------*/
long monitor::handle_fsync_precall(int childnum)
{
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_sigreturn -
-----------------------------------------------------------------------------*/
long monitor::handle_rt_sigreturn_call(int childnum)
{
    if (childs[0].callnumbackup == __NR_rt_sigsuspend
#ifdef __NR_sigsuspend
        || childs[0].callnumbackup == __NR_sigsuspend
#endif
        )
    {
        // in this case sigreturn returns straight to sigsuspend and we don't see
        // a sigreturn return...
        // return_from_sighandler will change the callnum so that the next
        // syscall site will be the return of sigsuspend
        sig_return_from_sighandler();
    }
    return MVEE_CALL_ALLOW;
}

long monitor::handle_rt_sigreturn_postcall(int childnum)
{
    // if we did not deliver during sigsuspend, we will actually see sigreturn return -1
    // return_from_sighandler will restore the original context and resume
    sig_return_from_sighandler();
    return MVEE_POSTCALL_DONTRESUME;
}

/*-----------------------------------------------------------------------------
  sys_clone - (unsigned long clone_flags, unsigned long newsp,
  void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
-----------------------------------------------------------------------------*/
long monitor::handle_clone_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim);

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_CLONE(%s)\n", childs[i].childpid, getTextualCloneFlags(ARG1(i)).c_str());

    return 0;
}

long monitor::handle_clone_precall(int childnum)
{
    CHECKARG(1);

    // we weren't multithreaded yet but will be after this call!
    if (!is_program_multithreaded() && (ARG1(0) & CLONE_VM))
        enable_sync();

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

long monitor::handle_clone_postcall(int childnum)
{
    int i, result;

    if (call_succeeded)
    {
        // I DARE YOU TO TRIGGER THIS DATA RACE
        if (ARG1(0) & CLONE_PARENT_SETTID)
        {
            debugf("setting TID of the newly created thread in the address space of the parent\n");
            for (int i = 1; i < mvee::numvariants; ++i)
            {
                mvee_word word;
                word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG3(i), NULL);
                word._pid  = (pid_t)call_postcall_get_child_result(0);
                mvee_wrap_ptrace(PTRACE_POKEDATA, childs[i].childpid, ARG3(i), (void*)word._long);
            }
        }

        // update stack regions (if applicable)
        if (ARG2(0))
        {
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                mmap_region_info* stack_info = set_mmap_table->get_region_info(i, ARG2(i)-1, 0);
                int               tid        = call_postcall_get_child_result(i);

                if (stack_info)
                {
                    std::stringstream ss;
                    ss << "[stack:" << tid << "]";

                    stack_info->region_backing_file_path = ss.str();
                    stack_info->region_map_flags         = MAP_PRIVATE | MAP_GROWSDOWN | MAP_STACK;
                }
            }
        }

        result = call_postcall_get_child_result(0);
        for (i = 1; i < mvee::numvariants; ++i)
            call_postcall_set_child_result(i, result);
    }

    return 0;
    //	return MVEE_POSTCALL_DONTRESUME;
}

/*-----------------------------------------------------------------------------
  sys_mprotect - (unsigned long start, size_t len, unsigned long prot)

  Unfortunately, it appears that this function must be synced. MMAP2 has a
  tendency to align new regions to existing bordering regions with the same
  protection flags. This behaviour CAN cause problems if we do not sync
  mprotect.

TODO: Verify/Further documentation
-----------------------------------------------------------------------------*/
long monitor::handle_mprotect_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_MPROTECT(0x" PTRSTR ", 0x" PTRSTR ", 0x%08X = %s)\n",
                   childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), getTextualProtectionFlags(ARG3(i)).c_str());

    return 0;
}

long monitor::handle_mprotect_precall(int childnum)
{
    CHECKARG(2);
    CHECKARG(3);
    CHECKREGION(1, ARG2(0));
    //	log_child_backtrace(0);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_mprotect_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, ret)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_MPROTECT return: %d\n", childs[i].childpid, ret[i]);

    return 0;
}

long monitor::handle_mprotect_postcall(int childnum)
{
    if (call_succeeded)
        for (int i = 0; i < mvee::numvariants; ++i)
            set_mmap_table->mprotect_range(i, ARG1(i), ARG2(i), ARG3(i));

    for (int i = 0; i < mvee::numvariants; ++i)
        set_mmap_table->verify_mman_table(i, childs[i].childpid);

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpgid
-----------------------------------------------------------------------------*/
long monitor::handle_getpgid_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_capget - (cap_user_header_t header, cap_user_data_t dataptr)
-----------------------------------------------------------------------------*/
long monitor::handle_capget_precall(int childnum)
{
    CHECKPOINTER(1);
    if (ARG1(0))
        CHECKBUFFER(1, sizeof(__user_cap_header_struct));
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_capget_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(__user_cap_header_struct));
    if (call_succeeded && ARG2(0))
    {
        REPLICATEBUFFERFIXEDLEN(2, (sizeof(long) == 8 ? 2 : 1) * sizeof(__user_cap_data_struct));
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fchdir - (unsigned int fd)
-----------------------------------------------------------------------------*/
long monitor::handle_fchdir_precall(int childnum)
{
    CHECKFD(1);
    MAPFDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_fchdir_postcall(int childnum)
{
    UNMAPFDS(1);
    if (call_succeeded)
    {
        fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
        if (fd_info && fd_info->path != "")
            set_fd_table->chdir(fd_info->path.c_str());
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys__llseek - (unsigned int fd, unsigned long offset_high,
  unsigned long offset_low, loff_t __user * result,
  unsigned int origin)
-----------------------------------------------------------------------------*/
long monitor::handle__llseek_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_LLSEEK(%d, %ld, %ld, 0x" PTRSTR ", %d)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), ARG4(i), ARG5(i));

    return 0;
}

long monitor::handle__llseek_precall(int childnum)
{
    CHECKPOINTER(4);
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(5);
    CHECKFD(1);

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle__llseek_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(4, sizeof(loff_t));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getdents - (unsigned int fd,
  struct linux_dirent __user * dirent, unsigned int count)
-----------------------------------------------------------------------------*/
long monitor::handle_getdents_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getdents_postcall(int childnum)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys__newselect - (int n, fd_set __user *inp, fd_set __user *outp,
  fd_set __user *exp, struct timeval __user *tvp)
-----------------------------------------------------------------------------*/
long monitor::handle_select_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SELECT(%d, 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ")\n", childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), ARG4(i), ARG5(i));

    return 0;
}

long monitor::handle_select_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(5);
    CHECKPOINTER(4);
    CHECKPOINTER(3);
    CHECKPOINTER(2);
    CHECKFDSET(4, ARG1(0));
    CHECKFDSET(3, ARG1(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_select_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, ROUND_UP(ARG1(0) + 1, sizeof(unsigned long)));
    REPLICATEBUFFERFIXEDLEN(3, ROUND_UP(ARG1(0) + 1, sizeof(unsigned long)));
    REPLICATEBUFFERFIXEDLEN(4, ROUND_UP(ARG1(0) + 1, sizeof(unsigned long)));
    REPLICATEBUFFERFIXEDLEN(5, sizeof(struct timeval));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_msync - (unsigned long start, size_t len, int flags)

  syncs a shared mapping with the backing file. i.e., writes changes
  to the memory mapping back to the file.

  Shared mappings with O_WRONLY or O_RDWR backing files are made private
  by the monitor by default. As such, we should first check whether the
  regions we're msyncing are MVEE_MAP_WASSHARED and if so, we should
  compare the regions and perform an early writeback.
  The actual msync call should not go into the kernel!
-----------------------------------------------------------------------------*/
long monitor::handle_msync_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_MSYNC(0x" PTRSTR ", %d, %s)\n", childs[i].childpid,
                   ARG1(i), ARG2(i), getTextualMSyncFlags(ARG3(i)).c_str());

    return 0;
}

long monitor::handle_msync_precall(int childnum)
{
    int               private_mapping = 1;

    CHECKARG(2);
    CHECKARG(3);
    CHECKREGION(1, ARG2(0));

    // check the flags. We can satisy MS_SYNC and MS_ASYNC requests
    // but we cannot garantuee the correct semantics for
    // MS_INVALIDATE requests.
    //
    // MS_INVALIDATE should invalidate other mappings of the same
    // backing file. We currently have no way to force an invalidate
    // of an MVEE_MAP_WASSHARED mapping that was mapped elsewhere
    // in the MVEE.
    mmap_region_info* region          = set_mmap_table->get_region_info(0, ARG1(0), 0);
    if (region)
    {
        debugf("msync on region: 0x" PTRSTR "-0x" PTRSTR " (%s)\n", region->region_base_address, region->region_base_address + region->region_size, region->region_backing_file_path.c_str());
        if (region->region_map_flags & MAP_MVEE_WASSHARED)
            private_mapping = 0;
    }

    if (ARG3(0) & MS_INVALIDATE)
        debugf("child is requesting an MS_INVALIDATE - private mapping: %d\n", private_mapping);

    if ((ARG3(0) & MS_SYNC) || (ARG3(0) & MS_ASYNC))
        debugf("child is requesting an MS_[A]SYNC - private mapping: %d\n", private_mapping);

    // any operation on a private mapping is permissible
    // -> INVALIDATE on a private mapping re-reads the backing file
    // -> [A]_SYNC on a private mapping is a void operation
    if (private_mapping)
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    if (region)
        cache_mismatch_info("msync on region: 0x" PTRSTR "-0x" PTRSTR " (%s)\n", region->region_base_address, region->region_base_address + region->region_size, region->region_backing_file_path.c_str());
    else
        cache_mismatch_info("msync on unknown region\n");
    cache_mismatch_info("msyncing a shared mapping -> this is not implemented yet. FIXME\n");
    return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;
}

/*-----------------------------------------------------------------------------
  sys_readv - (unsigned long  fd, const struct iovec  *  vec,
  unsigned long  vlen)
-----------------------------------------------------------------------------*/
long monitor::handle_readv_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKVECTORLAYOUT(2, ARG3(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_readv_postcall(int childnum)
{
    REPLICATEVECTOR(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_writev - (unsigned long  fd, const struct iovec  *  vec,
  unsigned long  vlen)
-----------------------------------------------------------------------------*/
long monitor::handle_writev_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_WRITEV(%d, 0x" PTRSTR ", %d)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i));
        struct iovec* vec = (struct iovec*)mvee_rw_read_data(childs[i].childpid, ARG2(i), sizeof(struct iovec) * ARG3(i));
        if (!vec)
        {
            warnf("couldn't read iovec\n");
            return 0;
        }

        std::string   str = call_serialize_io_vector(i, vec, ARG3(i));
        debugf("    => \n%s\n", str.c_str());
        SAFEDELETEARRAY(vec);
    }

    return 0;
}

long monitor::handle_writev_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKVECTOR(2, ARG3(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fdatasync - unsigned int fd
-----------------------------------------------------------------------------*/
long monitor::handle_fdatasync_precall(int childnum)
{
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_sched_yield
-----------------------------------------------------------------------------*/
long monitor::handle_sched_yield_get_call_type(int childnum)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_nanosleep
-----------------------------------------------------------------------------*/
long monitor::handle_nanosleep_get_call_type(int childnum)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_mremap - unsigned long, addr, unsigned long, old_len,
  unsigned long, new_len, unsigned long, flags,
  unsigned long, new_addr
-----------------------------------------------------------------------------*/
long monitor::handle_mremap_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_MREMAP(0x" PTRSTR ", %d, %d, 0x" PTRSTR ", 0x" PTRSTR ")\n",
                   childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), ARG4(i));
    }

    return 0;
}

long monitor::handle_mremap_precall(int childnum)
{
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKREGION(1, ARG2(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_mremap_postcall(int childnum)
{
    if (call_succeeded)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            // unmap target pages
            std::vector<unsigned long> new_addresses = call_postcall_get_result_vector();

            //
            mmap_region_info*          info          = set_mmap_table->get_region_info(i, ARG1(i), ARG2(i));
            if (info)
            {
                mmap_region_info* new_region = new mmap_region_info(*info);

                new_region->region_base_address = new_addresses[i];
                new_region->region_size         = ARG3(i);

                set_mmap_table->munmap_range(i, ARG1(i),          ARG2(i));
                set_mmap_table->munmap_range(i, new_addresses[i], ARG3(i));

                //warnf("remapped - child %d - from: 0x" PTRSTR "-0x" PTRSTR " - to: 0x" PTRSTR "-0x" PTRSTR "\n",
                //        i, ARG1(i), ARG1(i) + ARG2(i), new_addresses[i], ARG3(i) + new_addresses[i]);
                set_mmap_table->insert_region(i, new_region);
            }
            else
            {
                warnf("remap range not found: 0x" PTRSTR "-0x" PTRSTR "\n",
                            ARG1(i), ARG1(i) + ARG2(i));
                shutdown(false);
            }

            set_mmap_table->verify_mman_table(i, childs[i].childpid);
        }
    }

    return 0;
}

long monitor::handle_mremap_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_MREMAP return: 0x" PTRSTR "\n", childs[i].childpid, rets[i]);

#ifdef MVEE_MMAN_DEBUG
    set_mmap_table->print_mmap_table();
#endif

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_poll - (struct pollfd __user *ufds, unsigned int nfds, long timeout)
-----------------------------------------------------------------------------*/
long monitor::handle_poll_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_POLL(0x" PTRSTR ", %d, %d)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i));

    return 0;
}

long monitor::handle_poll_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKARG(3);
    CHECKBUFFER(1, sizeof(struct pollfd) * ARG2(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_poll_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_POLL return: %d\n", childs[i].childpid, rets[i]);

        for (unsigned int j = 0; j < rets[i]; ++j)
        {
            struct pollfd fds;
            if (!mvee_rw_read_struct(childs[i].childpid, ARG1(i) + j * sizeof(struct pollfd), sizeof(struct pollfd), &fds))
            {
                warnf("couldn't read pollfd\n");
                return 0;
            }

            debugf("> fd: %d - events: %s - revents: %s\n",
                       fds.fd,
                       getTextualPollRequest(fds.events).c_str(),
                       getTextualPollRequest(fds.revents).c_str());
        }
    }

    return 0;
}

long monitor::handle_poll_postcall(int childnum)
{
//    long result = call_postcall_get_child_result(0);
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct pollfd) * ARG2(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_prctl - (int option, unsigned long arg2, unsigned long arg3,
  unsigned long arg4, unsigned long arg5)
-----------------------------------------------------------------------------*/
long monitor::handle_prctl_precall(int childnum)
{
    // TODO: not all arguments are always used here, comparing unused args may cause false positives
    /*
     * int i;
     for (i = 0; i < mvee::numvariants - 1; ++i)
     if (ARG1(i) != ARG1(i+1) || ARG2(i) != ARG2(i+1) ||
     ARG3(i) != ARG3(i+1) || ARG4(i) != ARG4(i+1) ||
     ARG5(i) != ARG5(i+1))
     return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;
     */

    CHECKARG(1);

    // syntax: sys_prctl(PR_REGISTER_IPMON, syscall_mask_ptr, syscall_mask_size)
    if (ARG1(0) == PR_REGISTER_IPMON)
    {
        CHECKARG(3);
        CHECKPOINTER(2);
        CHECKBUFFER(2, ARG3(0));
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_prctl_call(int childnum)
{
    // check if the children are trying to re-enable rdtsc
    if (ARG1(0) == PR_SET_TSC && ARG2(0) == PR_TSC_ENABLE)
    {
        cache_mismatch_info("The program is trying to enable directly reading the time stamp counter. This call has been denied.\n");
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
    }
    return MVEE_CALL_ALLOW;
}

long monitor::handle_prctl_postcall(int childnum)
{
#ifdef MVEE_SUPPORTS_IPMON
    // PR_REGISTER_IPMON returns the IP-MON key
    if (ARG1(0) == PR_REGISTER_IPMON && call_succeeded)
    {
        if (!ipmon_buffer) 
		{
			warnf("prctl(PR_REGISTER_IPMON) called, but the IP-MON buffer was not yet initialized");
			return 0;
		}

        // Write the IP-MON buffer header
        struct ipmon_buffer* buffer = (struct ipmon_buffer*) ipmon_buffer->ptr;
		// The first cacheline contains the key, number of variants and usable size.
		// Then we have one cacheline for each variant to store its current position within the IP-MON buffer
        unsigned usable_size = ipmon_buffer->sz - 64 * (1 + mvee::numvariants);
		buffer->ipmon_numvariants = mvee::numvariants;
		buffer->ipmon_usable_size = usable_size;

		// remember the base addresses and keys for IP-MON
		for (int i = 0; i < mvee::numvariants; ++i)
		{
			FETCH_IP(i, ip);
			childs[i].ipmon_region = set_mmap_table->get_region_info(i, ip, 0);
			debugf("Initializing IP-MON - IP: 0x" PTRSTR "\n", ip);
			if (childs[i].ipmon_region)
				childs[i].ipmon_region->print_region_info("> IP-MON REGION: ");
		}

		debugf("IP-MON initialized\n");
		ipmon_initialized = true;
    }
#endif

    return 0;
}

/*-----------------------------------------------------------------------------
  long sys32_rt_sigprocmask(int how,
  compat_sigset_t __user *set,
  compat_sigset_t __user *oset,
  unsigned int sigsetsize)
-----------------------------------------------------------------------------*/
long monitor::handle_rt_sigprocmask_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_RT_SIGPROCMASK(%s, 0x" PTRSTR " - %s)\n", childs[i].childpid,
			   getTextualSigHow(ARG1(i)), ARG2(i), 
			   getTextualSigSet(call_get_sigset(i, ARG2(i), OLDCALLIFNOT(__NR_rt_sigprocmask))).c_str());
    }

    return 0;
}

long monitor::handle_rt_sigprocmask_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKSIGSET(2, OLDCALLIFNOT(__NR_rt_sigprocmask));
    CHECKPOINTER(3);
    childs[0].last_sigset = call_get_sigset(0, ARG2(0), OLDCALLIFNOT(__NR_rt_sigprocmask));
    //	log_child_backtrace(0);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_rt_sigprocmask_postcall(int childnum)
{
    if (call_succeeded && ARG2(0))
    {
        sigset_t _set = childs[0].last_sigset;

        switch (ARG1(0))
        {
            case SIG_BLOCK:
            {
                for (int i = 1; i < SIGRTMAX+1; ++i)
                    if (sigismember(&_set, i))
                        sigaddset(&blocked_signals, i);
                break;
            }
            case SIG_UNBLOCK:
            {
                for (int i = 1; i < SIGRTMAX+1; ++i)
                {
                    if (sigismember(&_set, i))
                        sigdelset(&blocked_signals, i);
                }
                break;
            }
            case SIG_SETMASK:
            {
                sigemptyset(&blocked_signals);
                for (int i = 1; i < SIGRTMAX+1; ++i)
                    if (sigismember(&_set, i))
                        sigaddset(&blocked_signals, i);
                break;
            }
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pread64 - (unsigned int fd, char __user *buf, size_t count, loff_t pos)
-----------------------------------------------------------------------------*/
long monitor::handle_pread64_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_PREAD64(%d, 0x" PTRSTR ", %d, %d)\n",
                   childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), ARG4(i));

    return 0;
}

long monitor::handle_pread64_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_pread64_postcall(int childnum)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pwrite64 - (unsigned int fd, const char __user *buf,
  size_t count, loff_t pos)
-----------------------------------------------------------------------------*/
long monitor::handle_pwrite64_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        std::string buf_str = call_serialize_io_buffer(i, ARG2(i), ARG3(i));
        debugf("pid: %d - SYS_PWRITE64(%d, %s, %d, %d)\n", childs[i].childpid, ARG1(i), buf_str.c_str(), ARG3(i), ARG4(i));
    }

    return 0;
}

long monitor::handle_pwrite64_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKBUFFER(2, ARG3(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_chown - (const char  *  filename, uid_t  user, gid_t  group)
-----------------------------------------------------------------------------*/
long monitor::handle_chown_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(3);
    CHECKARG(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fcown - (int fd, uid_t user, gid_t group)
-----------------------------------------------------------------------------*/
long monitor::handle_fchown_precall(int childnum)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getcwd - (char* buf, int buflen)
-----------------------------------------------------------------------------*/
long monitor::handle_getcwd_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getrlimit - (unsigned int  resource, struct rlimit  *  rlim)
-----------------------------------------------------------------------------*/
long monitor::handle_ugetrlimit_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_mmap2 - (unsigned long  addr, unsigned long  len, unsigned long  prot,
  unsigned long  flags, int  fd, unsigned long  pgoff)

  !!!!! fd is implicitly cast from unsigned long to int on AMD64 !!!
-----------------------------------------------------------------------------*/
long monitor::handle_mmap_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_MMAP(0x" PTRSTR ", %lu, %s, %s, %d, %lu)\n",
                   childs[i].childpid, ARG1(i), ARG2(i),
                   getTextualProtectionFlags(ARG3(i)).c_str(),
                   getTextualMapType(ARG4(i)).c_str(), (int)ARG5(i), ARG6(i));
    }

    return 0;
}

#ifdef MVEE_ENABLE_VALGRIND_HACKS
static int first_mmap2_call = 1;
#endif

long monitor::handle_mmap_precall(int childnum)
{
    /*  if (childnum != -1)
    mvee_log_child_backtrace(childnum);
    else
    {
    for (int i = 0; i < mvee::numvariants; ++i)
    mvee_log_child_backtrace(i);
    }    */

//	if (ARG2(0) == 4295237632)
//		log_child_backtrace(0);

#ifdef MVEE_ENABLE_VALGRIND_HACKS
    if (first_mmap2_call)
    {
        first_mmap2_call = 0;
        for (int i = 0; i < mvee::numvariants; ++i)
			set_mmap_table->refresh_child_maps(i, childs[i].childpid);
    }
#endif

    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKFD(5);

    // offset is ignored for anonymous mappings
    if ((int)ARG5(0) !=-1 || (ARG4(0) & MAP_ANONYMOUS))
        CHECKARG(6);

    MAPFDS(5);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_mmap_call(int childnum)
{
    for (int i = 0; i < mvee::numvariants; ++i)
        childs[i].last_mmap_result = 0;

    // anonymous shared mapping maps /dev/zero into our address space.
    // this mapping is only shared between the calling process and its decendants
    // => this is a safe form of shared memory
    if (ARG4(0) & MAP_ANONYMOUS)
        return MVEE_CALL_ALLOW;

    // non-anonymous ==> it must have a backing file
    if (ARG5(0) && (int)ARG5(0) != -1)
    {
        fd_info* info = set_fd_table->get_fd_info(ARG5(0));

        if (!info)
        {
            warnf("mmap2 request with an unknown backing file!!!\n");
            return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
        }

        if ((info->access_flags & O_RDWR) && (ARG4(0) & MAP_SHARED))
        {
//#ifndef MVEE_BENCHMARK
            warnf("childs are opening a shared memory mapping backed by an O_RDWR file!!!\n");
            warnf("> file = %s\n",           info->path.c_str());
            warnf("> map prot flags = %s\n", getTextualProtectionFlags(ARG3(0)).c_str());
            //			mvee_log_child_backtrace(0);
//#endif

            if (ARG3(0) & PROT_WRITE)
            {
                if (info->path != "")
                {
                    // if the path exists, assume that it's a regular file. Don't
                    // check if it's a regular file here because the file might've
                    // been unlinked (LibreOffice)
#ifndef MVEE_BENCHMARK
                    warnf("> this is a regular file! changing to private mapping\n");
#endif
                    for (int i = 0; i < mvee::numvariants; ++i)
                    {
                        ARG4(i) = ((ARG4(i) & ~MAP_SHARED) | MAP_PRIVATE | MAP_MVEE_WASSHARED);
                        SETARG4(i, ARG4(i));
                    }
                    return MVEE_CALL_ALLOW;
                }

                warnf("MAP_SHARED mapping request with PROT_WRITE detected!\n");
                warnf("This call has been denied.\n");
                return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
            }
            // Temporary hack for LibreOffice.
            //
            // LibreOffice has some startup code that maps certain files in twice!
            // Once as a shared READ/WRITE mapping, which we change to a private READ/WRITE mapping
            // and once as a shared EXEC mapping ==> we should return the address of the private mapping here
            //
            // TODO: Check if the specified file region has already been mapped
            // as a private mapping.
            else if (ARG3(0) & PROT_EXEC)
            {
                warnf("> Temporary LibreOffice hack. Call denied!!! FIXME!!!\n");
                return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
            }
        }
        else if ((ARG3(0) & PROT_EXEC))
        {
            if (mvee::config.mvee_use_dcl)
            {
                if (ARG4(0) & MAP_FIXED)
                {
                    warnf("GHUMVEE is running with use_dcl enabled but the following binary is not position independent: %s\n", info->path.c_str());
                    warnf("> We cannot enforce disjunct code within this address space!!!\n");
                }
                else
                {
                    std::vector<unsigned long> bases(mvee::numvariants);
                    set_mmap_table->calculate_disjoint_bases(ARG2(0), bases);

                    debugf("GHUMVEE is overriding the base address of a new code region backed by file: %s\n",
                               info->path.c_str());

                    for (int i = 0; i < mvee::numvariants; ++i)
                    {
                        /*
                           warnf("> child %d => region span: 0x" PTRSTR "-0x" PTRSTR "\n",
                           i, bases[i], ROUND_UP(bases[i] + ARG2(0), 4096));
                         */
                        SETARG1(i, bases[i]);
                    }
                }
            }
        }
    }

    return MVEE_CALL_ALLOW;
}

long monitor::handle_mmap_postcall(int childnum)
{
    UNMAPFDS(5);
    if (call_succeeded)
    {
        fd_info*                   info      = NULL;
        int                        free_info = 0;
        std::vector<unsigned long> results   = call_postcall_get_result_vector();

        for (int i = 0; i < mvee::numvariants; ++i)
            childs[i].last_mmap_result = results[i];

        if (ARG5(0) && (int)ARG5(0) != -1)
        {
            info = set_fd_table->get_fd_info(ARG5(0));
            if (!info)
            {
                warnf("mmap2 request with backing file but backing file info not found!\n");
                shutdown(false);
                return 0;
            }
            if (ARG4(0) & MAP_MVEE_WASSHARED)
            {
                /* from mmap2 manpages:
                 * A file is mapped in multiples of the page size.  For a file that is
                 not a multiple of the page size, the remaining memory is zeroed when
                 mapped, and writes to that region are not written out to the file.
                 The effect of changing the size of the underlying file of a mapping
                 on the pages that correspond to added or removed regions of the file
                 is unspecified.

                 => i.e., you CAN map x pages backed by a y byte file. If x > y however,
                 only the pages containing the y bytes will be valid. When munmapping,
                 only y bytes will be written back
                 */
                struct stat _st;
                if (stat(info->path.c_str(), &_st))
                {
                    warnf("couldn't get the original file size for: %s\n", info->path.c_str());
                    shutdown(false);
                    return 0;
                }

                info->original_file_size = _st.st_size;
                warnf("size for: %s - %d bytes\n", info->path.c_str(), _st.st_size);
            }
        }

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            unsigned int actual_offset = ARG6(0);
#ifdef __NR_mmap2
            if (childs[0].prevcallnum == __NR_mmap2)
                actual_offset *= 4096;
#endif
            set_mmap_table->map_range(i, results[i], ARG2(0), ARG4(0), ARG3(0), info, actual_offset);
        }

        // 2 * 2 * (4 * 1024 * 1024 * sizeof(long))
        // check if this was a new heap allocation by ptmalloc
        if (ARG1(0) == 0                                                // no base address
            && ARG2(0) == 2 * HEAP_MAX_SIZE                             // size = 2*HEAP_MAX_SIZE
            && ARG3(0) == PROT_NONE                                     // no protection flags yet
            && ARG4(0) == (MAP_PRIVATE | MAP_NORESERVE | MAP_ANONYMOUS) //
            && (int)ARG5(0) == -1)                                      // backed by /dev/zero
        {
            in_new_heap_allocation = true;

            debugf("this seems to be a heap allocation by ptmalloc\n");

            // bump the lock counter for the fd/mman locks - we'll unlock when we see the last munmap
            call_grab_locks(MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN);

            // pre-calculate the parameters for the next munmap calls
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                unsigned long start_of_heap = (results[i] + (HEAP_MAX_SIZE - 1)) & ~(HEAP_MAX_SIZE - 1);
                childs[i].last_lower_region_start = results[i];
                childs[i].last_lower_region_size  = start_of_heap - results[i];
                childs[i].last_upper_region_start = start_of_heap + HEAP_MAX_SIZE;
                childs[i].last_upper_region_size  = results[i] + HEAP_MAX_SIZE - start_of_heap;
            }
        }

        if (free_info)
        {
            SAFEDELETE(info);
        }
    }

    for (int i = 0; i < mvee::numvariants; ++i)
        set_mmap_table->verify_mman_table(i, childs[i].childpid);

    return 0;
}

long monitor::handle_mmap_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_MMAP2 return: 0x" PTRSTR "\n", childs[i].childpid, rets[i]);
    }

#ifdef MVEE_MMAN_DEBUG
    set_mmap_table->print_mmap_table();
#endif

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_truncate64 - (const char __user * path, loff_t length)
-----------------------------------------------------------------------------*/
long monitor::handle_truncate64_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ftruncate64 - (unsigned int fd, loff_t length)
-----------------------------------------------------------------------------*/
long monitor::handle_ftruncate64_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_stat64 - (char __user *filename, struct stat64 __user *statbuf);
-----------------------------------------------------------------------------*/
long monitor::handle_stat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_STAT(%s)\n", childs[i].childpid, str1);
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_stat_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_stat_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat));
    return 0;
}

long monitor::handle_stat64_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_STAT64(%s)\n", childs[i].childpid, str1);
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_stat64_precall(int childnum)
{
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_stat64_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_lstat64 - (char __user *filename, struct stat64 __user *statbuf);
-----------------------------------------------------------------------------*/
long monitor::handle_lstat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_LSTAT(%s)\n", childs[i].childpid, str1);
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_lstat_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_lstat_postcall(int childnum)
{
    if (sizeof(unsigned long) == 4)
    {
        REPLICATEBUFFERFIXEDLEN(2, sizeof(struct old_kernel_stat));
    }
    else
    {
        REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat));
    }
    return 0;
}

long monitor::handle_lstat64_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        debugf("pid: %d - SYS_LSTAT64(%s)\n", childs[i].childpid, str1);
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_lstat64_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_lstat64_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fstat - (unsigned long fd, struct stat64 * statbuf)
-----------------------------------------------------------------------------*/
long monitor::handle_fstat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_FSTAT(%d, 0x" PTRSTR ")\n",
                   childs[i].childpid, ARG1(i), ARG2(i));

    return 0;
}

long monitor::handle_fstat_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKFD(1);

    if (!set_fd_table->is_fd_master_file(ARG1(0)))
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fstat_log_return(int childnum)
{
    std::vector<unsigned long> argarray(mvee::numvariants);
    if (state == STATE_IN_SYSCALL)
    {
        FILLARGARRAY(2, argarray);
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            struct stat* sb = (struct stat*)mvee_rw_read_data(childs[i].childpid, argarray[i], sizeof(struct stat));
            if (sb)
            {
                /*
                   struct stat {
                   dev_t     st_dev;     // ID of device containing file
                   ino_t     st_ino;     // inode number
                   mode_t    st_mode;    // protection
                   nlink_t   st_nlink;   // number of hard links
                   uid_t     st_uid;     // user ID of owner
                   gid_t     st_gid;     // group ID of owner
                   dev_t     st_rdev;    // device ID (if special file)
                   off_t     st_size;    // total size, in bytes
                   blksize_t st_blksize; // blocksize for file system I/O
                   blkcnt_t  st_blocks;  // number of 512B blocks allocated
                   time_t    st_atime;   // time of last access
                   time_t    st_mtime;   // time of last modification
                   time_t    st_ctime;   // time of last status change
                   };
                 */
                debugf("pid: %d - SYS_FSTAT64 return\n", childs[i].childpid);

                switch (sb->st_mode & S_IFMT) {
                    case S_IFBLK:  debugf("File type:                block device\n");            break;
                    case S_IFCHR:  debugf("File type:                character device\n");        break;
                    case S_IFDIR:  debugf("File type:                directory\n");               break;
                    case S_IFIFO:  debugf("File type:                FIFO/pipe\n");               break;
                    case S_IFLNK:  debugf("File type:                symlink\n");                 break;
                    case S_IFREG:  debugf("File type:                regular file\n");            break;
                    case S_IFSOCK: debugf("File type:                socket\n");                  break;
                    default:       debugf("File type:                unknown?\n");                break;
                }

                debugf("I-node number:            %ld\n", (long) sb->st_ino);

                debugf("Mode:                     %lo (octal)\n",
                           (unsigned long) sb->st_mode);

                debugf("Link count:               %ld\n", (long) sb->st_nlink);
                debugf("Ownership:                UID=%ld   GID=%ld\n",
                           (long) sb->st_uid,
                           (long) sb->st_gid);

                debugf("Preferred I/O block size: %ld bytes\n",
                           (long) sb->st_blksize);
                debugf("File size:                %lld bytes\n",
                           (long long) sb->st_size);
                debugf("Blocks allocated:         %lld\n",
                           (long long) sb->st_blocks);

                debugf("Last status change:       %s", ctime(&sb->st_ctime));
                debugf("Last file access:         %s", ctime(&sb->st_atime));
                debugf("Last file modification:   %s", ctime(&sb->st_mtime));
            }
            SAFEDELETEARRAY(sb);
        }
    }

    return 0;
}

long monitor::handle_fstat_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat));
    if (state != STATE_IN_MASTERCALL)
        UNMAPFDS(1);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fstat64 - (unsigned long fd, struct stat64 * statbuf)
-----------------------------------------------------------------------------*/
long monitor::handle_fstat64_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_FSTAT64(%d, 0x" PTRSTR ")\n", childs[i].childpid, ARG1(i), ARG2(i));

    return 0;
}

long monitor::handle_fstat64_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKFD(1);

    if (!set_fd_table->is_fd_master_file(ARG1(0)))
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fstat64_log_return(int childnum)
{
    std::vector<unsigned long> argarray(mvee::numvariants);
    if (state == STATE_IN_SYSCALL)
    {
        FILLARGARRAY(2, argarray);
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            struct stat64* sb = (struct stat64*)mvee_rw_read_data(childs[i].childpid, argarray[i], sizeof(struct stat64));
            if (sb)
            {
                /*
                   struct stat {
                   dev_t     st_dev;     // ID of device containing file
                   ino_t     st_ino;     // inode number
                   mode_t    st_mode;    // protection
                   nlink_t   st_nlink;   // number of hard links
                   uid_t     st_uid;     // user ID of owner
                   gid_t     st_gid;     // group ID of owner
                   dev_t     st_rdev;    // device ID (if special file)
                   off_t     st_size;    // total size, in bytes
                   blksize_t st_blksize; // blocksize for file system I/O
                   blkcnt_t  st_blocks;  // number of 512B blocks allocated
                   time_t    st_atime;   // time of last access
                   time_t    st_mtime;   // time of last modification
                   time_t    st_ctime;   // time of last status change
                   };
                 */
                debugf("pid: %d - SYS_FSTAT64 return\n", childs[i].childpid);

                switch (sb->st_mode & S_IFMT) {
                    case S_IFBLK:  debugf("File type:                block device\n");            break;
                    case S_IFCHR:  debugf("File type:                character device\n");        break;
                    case S_IFDIR:  debugf("File type:                directory\n");               break;
                    case S_IFIFO:  debugf("File type:                FIFO/pipe\n");               break;
                    case S_IFLNK:  debugf("File type:                symlink\n");                 break;
                    case S_IFREG:  debugf("File type:                regular file\n");            break;
                    case S_IFSOCK: debugf("File type:                socket\n");                  break;
                    default:       debugf("File type:                unknown?\n");                break;
                }

                debugf("I-node number:            %ld\n", (long) sb->st_ino);

                debugf("Mode:                     %lo (octal)\n",
                           (unsigned long) sb->st_mode);

                debugf("Link count:               %ld\n", (long) sb->st_nlink);
                debugf("Ownership:                UID=%ld   GID=%ld\n",
                           (long) sb->st_uid,
                           (long) sb->st_gid);

                debugf("Preferred I/O block size: %ld bytes\n",
                           (long) sb->st_blksize);
                debugf("File size:                %lld bytes\n",
                           (long long) sb->st_size);
                debugf("Blocks allocated:         %lld\n",
                           (long long) sb->st_blocks);

                debugf("Last status change:       %s", ctime(&sb->st_ctime));
                debugf("Last file access:         %s", ctime(&sb->st_atime));
                debugf("Last file modification:   %s", ctime(&sb->st_mtime));
            }
            SAFEDELETEARRAY(sb);
        }
    }

    return 0;
}

long monitor::handle_fstat64_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat64));
    if (state != STATE_IN_MASTERCALL)
        UNMAPFDS(1);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_madvise
-----------------------------------------------------------------------------*/
long monitor::handle_madvise_get_call_type(int childnum)
{
    //  mvee_log_child_backtrace(childnum);
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_shmget
-----------------------------------------------------------------------------*/
long monitor::handle_shmget_call(int childnum)
{
#ifndef MVEE_ALLOW_SHM
    warnf("The program is trying to allocate shared memory. This call has been denied.\n");
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#else
	return MVEE_CALL_ALLOW;
#endif
}

/*-----------------------------------------------------------------------------
  sys_getdents64 - (unsigned int  fd, struct linux_dirent64  *  dirent,
  unsigned int  count)
-----------------------------------------------------------------------------*/
long monitor::handle_getdents64_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getdents64_postcall(int childnum)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_gettid
-----------------------------------------------------------------------------*/
long monitor::handle_gettid_get_call_type(int childnum)
{
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
    if (ARG1(childnum) == 1337 && ARG2(childnum) == 10000001
        && (ARG3(childnum) == 91 || ARG3(childnum) == 92 || ARG3(childnum) == 94 || ARG3(childnum) == 95 || ARG3(childnum) == 97))
        return MVEE_CALL_TYPE_NORMAL;
    return MVEE_CALL_TYPE_UNSYNCED;
#endif
    return MVEE_CALL_TYPE_NORMAL;
}

long monitor::handle_gettid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        if (ARG1(i) == 1337 && ARG2(i) == 10000001)
        {
            if (ARG3(i) == 74)
            {
                struct mvee_malloc_error err;
                mvee_rw_read_struct(childs[i].childpid, ARG4(i), sizeof(mvee_malloc_error), &err);
                warnf("[PID:%05d] - [MALLOC_MISMATCH - MASTER INFO] - [FUNC: %s] - [MSG: %d (%s)] - [CHUNKSIZE: %ld] - [ARENA PTR: 0x" PTRSTR "] - [CHUNK PTR: 0x" PTRSTR "]\n",
                            childs[i].childpid,
                            getTextualAllocType(err.alloc_type),
                            err.msg,
                            getTextualAllocResult(err.alloc_type, err.msg),
                            err.chunksize,
                            err.ar_ptr,
                            err.chunk_ptr
                            );
            }
            else if (ARG3(i) == 75)
            {
                struct mvee_malloc_error err;
                mvee_rw_read_struct(childs[i].childpid, ARG4(i), sizeof(mvee_malloc_error), &err);
                warnf("[PID:%05d] - [MALLOC_MISMATCH - SLAVE INFO] - [FUNC: %s] - [MSG: %d (%s)] - [CHUNKSIZE: %ld] - [ARENA PTR: 0x" PTRSTR "] - [CHUNK PTR: 0x" PTRSTR "]\n",
                            childs[i].childpid,
                            getTextualAllocType(err.alloc_type),
                            err.msg,
                            getTextualAllocResult(err.alloc_type, err.msg),
                            err.chunksize,
                            err.ar_ptr,
                            err.chunk_ptr
                            );
                shutdown(false);
            }
            else if (ARG3(i) == 76)
            {
                warnf("[PID:%05d] - [INTERPOSER_DATA_SIZE_MISMATCH] - [POS:%d] - [SLOT_SIZE:%d] - [DATA_SIZE:%d]\n",
                            childs[i].childpid, ARG4(i), ARG5(i), ARG6(i));
                shutdown(false);
            }
        }
    }

    return 0;
}

long monitor::handle_gettid_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_gettid_call(int childnum)
{
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
    if (childnum != -1 && ARG1(childnum) == 1337 && ARG2(childnum) == 10000001 && ARG3(childnum) == 71)
        log_child_backtrace(childnum);
    if (childnum != -1)
    {
        int i = childnum;
        if (ARG1(i) == 1337 && ARG2(i) == 10000001)
        {
            if (ARG3(i) == 10)
            {
                warnf("[PID:%05d] - [LIBC_LOCK_BUFFER_ATTACHED:0x" PTRSTR "]\n",
                            childs[i].childpid, ARG4(i));
            }
            if (ARG3(i) == 59)
            {
                //mvee_log_child_backtrace(i, 1, 0, 0);
                warnf("[PID:%05d] - [INVALID_LOCK_TYPE=>READ:%d (%s) - EXPECTED:%d (%s)]\n",
                            childs[i].childpid, ARG4(i), getTextualAtomicType(ARG4(i)),
                            ARG5(i), getTextualAtomicType(ARG5(i)));
                shutdown(false);
            }
            else if (ARG3(i) == 60)
            {
                warnf("[PID:%05d] - [INVALID_LOCK_TYPE] - [SLOT_SIZE:%d] - TMPPOS:%d\n",
                            childs[i].childpid, ARG4(i), ARG5(i));
            }
            else if (ARG3(i) == 90)
            {
                std::string master_callee = set_mmap_table->get_caller_info(0, childs[0].childpid, ARG5(i));
                std::string actual_callee = set_mmap_table->get_caller_info(i, childs[i].childpid, ARG6(i));

                warnf("[PID:%05d] - [INVALID_LOCK_CALLEE] - [LOCK_TYPE:%d (%s)] - [MASTER CALLEE:%s] - [ACTUAL CALLEE:%s]\n",
                            childs[i].childpid, ARG4(i), getTextualAtomicType(ARG4(i)),
                            master_callee.c_str(), actual_callee.c_str());

                shutdown(false);
            }
        }
    }
#endif

#ifdef MVEE_ENABLE_VALGRIND_HACKS
	return MVEE_CALL_ALLOW;
#endif

    return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(childs[0].childpid);
}

/*-----------------------------------------------------------------------------
  sys_readahead - (int fd, loff_t offset, size_t sz)
-----------------------------------------------------------------------------*/
long monitor::handle_readahead_precall(int childnum)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKARG(3);
    MAPFDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_readahead_postcall(int childnum)
{
    long result = call_postcall_get_child_result(0);
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_child_result(i, result);
    UNMAPFDS(1);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setxattr - (const char __user *, pathname,
  const char __user *, name, void __user *, value, size_t, size, int, flags)
-----------------------------------------------------------------------------*/
long monitor::handle_setxattr_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char*       path  = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        char*       name  = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_SETXATTR(%s, %s, %d, 0x" PTRSTR ", %d, %s)\n",
                   childs[i].childpid, path, name, ARG3(i), ARG4(i), getTextualXattrFlags(ARG5(i)));
        SAFEDELETEARRAY(path);
        SAFEDELETEARRAY(name);
    }

    return 0;
}

long monitor::handle_setxattr_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKSTRING(2);
    CHECKARG(4);
    CHECKPOINTER(3);
    CHECKBUFFER(3, ARG4(0));
    CHECKARG(5);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setxattr - (int, fd,
  const char __user *, name, void __user *, value, size_t, size, int, flags)
-----------------------------------------------------------------------------*/
long monitor::handle_fsetxattr_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char*       name  = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_FSETXATTR(%d, %s, %d, 0x" PTRSTR ", %d, %s)\n",
                   childs[i].childpid, ARG1(i), name, ARG3(i), ARG4(i), getTextualXattrFlags(ARG5(i)));
        SAFEDELETEARRAY(name);
    }

    return 0;
}

long monitor::handle_fsetxattr_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKARG(4);
    CHECKPOINTER(3);
    CHECKBUFFER(3, ARG4(0));
    CHECKARG(5);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getxattr - (const char __user *, pathname,
  const char __user *, name, void __user *, value, size_t, size)
-----------------------------------------------------------------------------*/
long monitor::handle_getxattr_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* path = mvee_rw_read_string(childs[i].childpid, ARG1(i));
        char* name = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_GETXATTR(%s, %s, %d, 0x" PTRSTR ", %d)\n",
                   childs[i].childpid, path, name, ARG3(i), ARG4(i));
        SAFEDELETEARRAY(path);
        SAFEDELETEARRAY(name);
    }

    return 0;
}

long monitor::handle_getxattr_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_getxattr_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(3, call_postcall_get_child_result(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fgetxattr - (int, fd,
  const char __user *, name, void __user *, value, size_t, size)
-----------------------------------------------------------------------------*/
long monitor::handle_fgetxattr_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* name = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_FGETXATTR(%d, %s, %d, 0x" PTRSTR ", %d)\n",
                   childs[i].childpid, ARG1(i), name, ARG3(i), ARG4(i));
        SAFEDELETEARRAY(name);
    }

    return 0;
}

long monitor::handle_fgetxattr_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fgetxattr_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(3, call_postcall_get_child_result(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_futex - (u32* uaddr, int op, u32 val, struct timespec* utime,
  u32* uaddr2, u32 val3)
-----------------------------------------------------------------------------*/
long monitor::handle_futex_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_FUTEX(0x" PTRSTR ", %s, %d, 0x" PTRSTR ", 0x" PTRSTR ", %d)\n",
                   childs[i].childpid, ARG1(i),
                   getTextualFutexOp(ARG2(i)), ARG3(i),
                   ARG4(i), ARG5(i), ARG6(i));
    }

    return 0;
}

long monitor::handle_futex_precall(int childnum)
{
#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
    CHECKARG(2);

    // if CLONE_CLEARTID is set, the kernel will clear
    // the tid and cause a futex wake on the tid address
    // the kernel (obviously) cannot guarantuee that it will
    // have cleared all tids by the time the master returns
    //
    // we therefore changed the futex op for LLL_(TIMED)WAIT_TID
    // this way, we can MANUALLY clear the tid if needed
    if (ARG2(0) == MVEE_FUTEX_WAIT_TID)
        SETARG2(0, FUTEX_WAIT);

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
#else
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
#endif
}

long monitor::handle_futex_call(int childnum)
{
#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
    mvee_word word;
    // tid was already cleared
    if (ARG2(0) == MVEE_FUTEX_WAIT_TID && ARG3(0) == 0)
    {
        // clear it for the slaves too and deny the call
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG1(i), NULL);
            word._uint = 0;
            mvee_wrap_ptrace(PTRACE_POKEDATA, childs[i].childpid, ARG1(i), (void*)word._long);
        }
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
    }
#endif
    return MVEE_CALL_ALLOW;
}

long monitor::handle_futex_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_FUTEX return: %d %s%s%s\n", childs[i].childpid, (long)rets[i],
                   ((long)rets[i] < 0) ? "(" : "",
                   ((long)rets[i] < 0) ? strerror(-(long)rets[i]) : "",
                   ((long)rets[i] < 0) ? ")" : "");
        /* if (rets[i] == (unsigned long)-EINVAL)*/
        //		log_child_backtrace(i);
    }

    return 0;
}

long monitor::handle_futex_postcall(int childnum)
{
#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
    mvee_word master_word;
    mvee_word slave_word;
    // sync the tids
    if (ARG2(0) == MVEE_FUTEX_WAIT_TID)
    {
        master_word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[0].childpid, ARG1(0), NULL);
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            slave_word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA, childs[i].childpid, ARG1(i), NULL);
            slave_word._pid  = master_word._pid;
            mvee_wrap_ptrace(PTRACE_POKEDATA, childs[i].childpid, ARG1(i), (void*)slave_word._long);
        }
    }
#endif
    return 0;
}

/*-----------------------------------------------------------------------------
  int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
-----------------------------------------------------------------------------*/
long monitor::handle_sched_setaffinity_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        cpu_set_t mask;
        if (!mvee_rw_read_struct(childs[i].childpid, ARG3(i), sizeof(cpu_set_t), &mask))
        {
            warnf("couldn't read cpu_set_t\n");
            return 0;
        }
        debugf("pid: %d - SYS_SCHED_SETAFFINITY(%d, %d, %s)\n",
                   childs[i].childpid, ARG1(i),
                   ARG2(i), getTextualCPUSet(&mask).c_str());
    }
    return 0;
}

long monitor::handle_sched_setaffinity_precall(int childnum)
{
#ifdef MVEE_ALLOW_SETAFFINITY
    // manipulate the mask so that each child runs on its own "virtual" cpu
    CHECKPOINTER(3);

    if (ARG3(0))
    {
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            cpu_set_t available_cores;
            int       num_cores_total      = mvee_env_get_num_cores();
            int       num_cores_child      = num_cores_total / mvee::numvariants;
            int       first_core_available = num_cores_child * i;
            int       modified_mask        = 0;

            if (!mvee_rw_read_struct(childs[i].childpid, ARG3(i), sizeof(cpu_set_t), &available_cores))
            {
                warnf("couldn't read cpu_set_t\n");
                return 0;
            }

            for (int j = 0; j < sizeof(cpu_set_t) * 8; ++j)
            {
                if (CPU_ISSET(j, &available_cores) &&
                    (j < first_core_available || j >= first_core_available + num_cores_child))
                {
                    CPU_CLR(j, &available_cores);
                    if (j < num_cores_child)
                        CPU_SET(j + first_core_available, &available_cores);
                    modified_mask = 1;
                }
            }

            if (modified_mask)
            {
#ifndef MVEE_BENCHMARK
                debugf("manipulated virtual CPU mask for the child: %d - %s\n", i,
                           getTextualCPUSet(&available_cores).c_str());
#endif
                mvee_rw_write_data(childs[i].childpid, ARG3(i), sizeof(cpu_set_t), (unsigned char*)&available_cores);
            }
        }
    }
#endif
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_sched_setaffinity_call(int childnum)
{
#ifndef MVEE_ALLOW_SETAFFINITY
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#else
    return MVEE_CALL_ALLOW;
#endif
}

long monitor::handle_sched_setaffinity_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_SCHED_SETAFFINITY return: %ld %s%s%s\n", childs[i].childpid, (long)rets[i],
                   ((long)rets[i] < 0) ? "(" : "",
                   ((long)rets[i] < 0) ? strerror(-(long)rets[i]) : "",
                   ((long)rets[i] < 0) ? ")" : "");
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sched_getaffinity - SYSCALL_DEFINE3(
  sched_getaffinity, pid_t, pid, unsigned int, len,
  unsigned long __user *, user_mask_ptr)
-----------------------------------------------------------------------------*/
long monitor::handle_sched_getaffinity_get_call_type(int childnum)
{
    // this is unsynced to work around a "harmless data race" in glibc
    return MVEE_CALL_TYPE_UNSYNCED;
}

long monitor::handle_sched_getaffinity_postcall(int childnum)
{
    // mask the return with the CPU cores we wish to make available to this child

    //debugf("pid: %d - SYS_SCHED_GETAFFINITY return: %d\n",
    //     childs[childnum].childpid,
    //     call_postcall_get_child_result(childnum));


    int res = call_postcall_get_child_result(childnum);
    if (call_check_result(res) && ARG3(childnum))
    {
        cpu_set_t    available_cores;

        unsigned int num_cores_total      = (unsigned int)mvee::os_get_num_cores();
        unsigned int num_cores_child      = num_cores_total / mvee::numvariants;
        unsigned int first_core_available = num_cores_child * childnum;
        int          modified_mask        = 0;

        CPU_ZERO(&available_cores);

        if (!mvee_rw_read_struct(childs[childnum].childpid, ARG3(childnum), ROUND_UP(num_cores_total, 8) / 8, &available_cores))
        {
            warnf("couldn't read cpu_set_t\n");
            return 0;
        }
        //        memset((char *) &available_cores + res, '\0', sizeof(cpu_set_t) - res);

        for (unsigned int i = 0; i < ROUND_UP(num_cores_total, 8); ++i)
        {
            if (CPU_ISSET(i, &available_cores)
                && (i < first_core_available || i >= first_core_available + num_cores_child))
            {
                CPU_CLR(i, &available_cores);
                modified_mask = 1;
            }
        }

        if (modified_mask)
            mvee_rw_write_data(childs[childnum].childpid, ARG3(childnum), ROUND_UP(num_cores_total, 8) / 8, (unsigned char*)&available_cores);
    }


    return 0;
}

/*-----------------------------------------------------------------------------
  sys_epoll_create - (int size)
-----------------------------------------------------------------------------*/
long monitor::handle_epoll_create_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EPOLL_CREATE(%d)\n", childs[i].childpid, ARG1(i));

    return 0;
}

long monitor::handle_epoll_create_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_epoll_create_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EPOLL_CREATE return: %d\n", childs[i].childpid, rets[i]);

    return 0;
}

long monitor::handle_epoll_create_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
        set_fd_table->create_fd_info(FT_POLL_BLOCKING, fds, "epoll_sock", 0, false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_exit_group -
-----------------------------------------------------------------------------*/
#ifdef MVEE_DUMP_MEM_STATS
static void handle_get_mem_size(int pid, unsigned long* phys_sz, unsigned long* virt_sz)
{
    char              cmd[1024];
    sprintf(cmd, "cat /proc/%d/status | sed 's/[ |\\t]\\+/ /' | egrep \"(VmPeak|VmHWM)\" | sed 's/ kB//' | tr -d ':'", pid);
    std::string       status_dump = mvee::log_read_from_proc_pipe(cmd, NULL);

    if (status_dump == "")
        return;

    std::stringstream ss(status_dump);
    std::string       ln;
    unsigned long     tmpsz, virt, phys;

    while (std::getline(ss, ln, '\n'))
    {
        char property[100];
        if (sscanf(ln.c_str(), "%s %ld\n", property, &tmpsz) == 2)
        {
            if (!strcmp(property, "VmPeak"))
                virt = tmpsz;
            if (!strcmp(property, "VmHWM"))
                phys = tmpsz;
        }
    }

    if (phys_sz)
        *phys_sz = phys;
    if (virt_sz)
        *virt_sz = virt;
}
#endif

long monitor::handle_exit_group_call(int childnum)
{
#ifdef MVEE_DUMP_MEM_STATS
    unsigned long mvee_phys, child_virt, child_phys;
    double        overhead = 0.0;
    handle_get_mem_size(syscall(__NR_getpid), &mvee_phys,  NULL);
    handle_get_mem_size(childs[0].childpid,   &child_phys, &child_virt);
    overhead                                   = ((double)child_virt + (double)child_phys + (double)mvee_phys) / (double)child_virt;

    warnf("child virt hwm: %ld bytes - child phys hwm: %ld bytes - mvee phys hwm: %ld bytes - memory footprint overhead: %lf\n",
                child_virt, child_phys, mvee_phys, overhead);
#endif

#ifdef MVEE_CALCULATE_CLOCK_SPREAD
	log_calculate_clock_spread();
#endif

    update_sync_primitives();
    //	mvee_mon_return(true);

    // don't let the exit_group call go through while we have "dangling childs"
    await_pending_transfers();

    // I needed this for raytrace and some other parsecs. They do a sys_exit_group
    // while a bunch of threads are still running.
    // This can cause mismatches in those other threads because some replicae might still perform syscalls while the others are dead
    set_mmap_table->thread_group_shutting_down = 1;
    __sync_synchronize();
    return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_set_tid_address
-----------------------------------------------------------------------------*/
long monitor::handle_set_tid_address_postcall(int childnum)
{
    unsigned long master_result = call_postcall_get_child_result(0);
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_child_result(i, master_result);
    return 0;
}

/*-----------------------------------------------------------------------------
  clock_gettime - (clockid_t which_clock, struct timespec __user* tp)
-----------------------------------------------------------------------------*/
long monitor::handle_clock_gettime_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_clock_gettime_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct timespec));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_statfs - (const char  *  pathname, struct statfs64  *  buf)
-----------------------------------------------------------------------------*/
long monitor::handle_statfs_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_statfs_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct statfs64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_statfs64 - (const char  *  pathname, size_t  sz, struct statfs64  *  buf)
-----------------------------------------------------------------------------*/
long monitor::handle_statfs64_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKARG(2);
    CHECKPOINTER(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_statfs64_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct statfs64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fstatfs - (int fd, struct statfs* buf)
  sys_fstatfs64 - (int fd, size_t  sz, struct statfs64  *  buf)
-----------------------------------------------------------------------------*/
long monitor::handle_fstatfs_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fstatfs_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct statfs));
    return 0;
}

long monitor::handle_fstatfs64_precall(int childnum)
{
    CHECKARG(2);
    CHECKFD(1);
    CHECKPOINTER(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fstatfs64_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct statfs64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpriority - (int which, int who)
-----------------------------------------------------------------------------*/
long monitor::handle_getpriority_precall (int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setpriority - (int which, int who, int niceval)
-----------------------------------------------------------------------------*/
long monitor::handle_setpriority_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    if (ARG1(0) != PRIO_USER)
    {
        MAPPIDS(2);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_setpriority_postcall(int childnum)
{
    if (ARG1(0) != PRIO_USER)
    {
        UNMAPPIDS(2);
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_epoll_wait - (int epfd, struct epoll_event __user* events, int maxevents, int timeout)
-----------------------------------------------------------------------------*/
long monitor::handle_epoll_wait_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_EPOLL_WAIT(%d, 0x" PTRSTR ", %d, %d)\n",
                   childs[i].childpid,
                   ARG1(i),
                   ARG2(i),
                   ARG3(i),
                   ARG4(i));

    return 0;
}

long monitor::handle_epoll_wait_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_epoll_wait_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, rets)

    for (int i = start; i < lim; ++i)
    {
        debugf("pid: %d - SYS_EPOLL_WAIT return: %d\n", childs[i].childpid, rets[i]);
        if ((int)rets[i] > 0)
        {
            struct epoll_event* events = (struct epoll_event*)mvee_rw_safe_alloc(sizeof(struct epoll_event) * rets[i]);
            if (!mvee_rw_read_struct(childs[i].childpid, ARG2(i), sizeof(struct epoll_event) * rets[i], events))
            {
                warnf("couldn't read epoll_event\n");
                return 0;
            }

            for (unsigned int j = 0; j < rets[i]; ++j)
                debugf("pid: %d - > SYS_EPOLL_WAIT fd ready: 0x" PTRSTR " - events: %s\n",
                           childs[i].childpid, (unsigned long)events[j].data.ptr, getTextualEpollEvents(events[j].events).c_str());

            SAFEDELETEARRAY(events);
        }
    }

    return 0;
}

long monitor::handle_epoll_wait_postcall(int childnum)
{
    if (call_succeeded)
    {
        unsigned long master_result = call_postcall_get_child_result(0);
        if (master_result > 0)
        {
            struct epoll_event* master_events = (struct epoll_event*)mvee_rw_safe_alloc(sizeof(struct epoll_event) * master_result);
            if (!mvee_rw_read_struct(childs[0].childpid, ARG2(0), sizeof(struct epoll_event) * master_result, master_events))
            {
                warnf("couldn't replicate epoll_events\n");
                return 0;
            }

            for (int j = 1; j < mvee::numvariants; ++j)
            {
                struct epoll_event* slave_events = (struct epoll_event*)mvee_rw_safe_alloc(sizeof(struct epoll_event) * master_result);
                memcpy(slave_events, master_events, sizeof(struct epoll_event) * master_result);
                for (unsigned int i = 0; i < master_result; ++i)
                {
					if ((unsigned long)master_events[i].data.ptr > 4096)
					{
						std::vector<unsigned long> ids = set_fd_table->epoll_id_map(ARG1(0), 
						    (unsigned long)master_events[i].data.ptr);

						slave_events[i].data.ptr = (void*)ids[j];

						debugf("mapped master id 0x" PTRSTR " to slave id 0x" PTRSTR " for slave %d\n",
							   (unsigned long)master_events[i].data.ptr,
							   (unsigned long)slave_events[i].data.ptr,
							   j);
					}
                }

                if (!mvee_rw_write_data(childs[j].childpid, ARG2(j), sizeof(epoll_event) * master_result, (unsigned char*)slave_events))
                    warnf("failed to replicate epoll_events to slave replica %d\n", j);
                SAFEDELETEARRAY(slave_events);
            }

            SAFEDELETEARRAY(master_events);
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_epoll_ctl - (int epfd, int op, int fd, struct epoll_event __user* event)
-----------------------------------------------------------------------------*/
long monitor::handle_epoll_ctl_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        struct epoll_event event;
        std::string        events;
        memset(&event, 0, sizeof(struct epoll_event));
        if (ARG4(i))
        {
            if (!mvee_rw_read_struct(childs[i].childpid, ARG4(i), sizeof(struct epoll_event), &event))
            {
                warnf("couldn't read epoll_event\n");
                return 0;
            }
            events = getTextualEpollEvents(event.events);
        }

        debugf("pid: %d - SYS_EPOLL_CTL(%d, %s, %d, %s, ID = 0x" PTRSTR ")\n",
                   childs[i].childpid,
                   ARG1(i),
                   getTextualEpollOp(ARG2(i)),
                   ARG3(i),
                   events.c_str(),
                   (unsigned long)event.data.ptr);
    }

    return 0;
}

long monitor::handle_epoll_ctl_precall(int childnum)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKFD(3);
    CHECKPOINTER(4);
    CHECKEPOLLEVENT(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_epoll_ctl_postcall(int childnum)
{
    if (call_succeeded && mvee::numvariants > 1)
    {
        if (ARG2(0) == EPOLL_CTL_ADD || ARG2(0) == EPOLL_CTL_MOD)
        {
            std::vector<unsigned long> ids(mvee::numvariants);

            for (int i = 0; i < mvee::numvariants; ++i)
            {
                struct epoll_event event;
                memset(&event, 0, sizeof(struct epoll_event));
                if (!mvee_rw_read_struct(childs[i].childpid, ARG4(i), sizeof(struct epoll_event), &event))
                {
                    warnf("couldn't read epoll_event\n");
                    return 0;
                }
                ids[i] = (unsigned long)event.data.ptr;
            }

            set_fd_table->epoll_id_register(ARG1(0), ARG3(0), ids);
        }
        else if (ARG2(0) == EPOLL_CTL_DEL)
        {
            set_fd_table->epoll_id_remove(ARG1(0), ARG3(0));
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_tgkill - (int tgid, int pid, int sig)
-----------------------------------------------------------------------------*/
long monitor::handle_tgkill_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_TGKILL(%d, %d, %d = %s)\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), getTextualSig(ARG3(i)));

    return 0;
}

long monitor::handle_tgkill_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_utimes - (char* filename, struct timeval utimes[2])
-----------------------------------------------------------------------------*/
long monitor::handle_utimes_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        struct timeval utimes[2];
        char*          str1 = mvee_rw_read_string(childs[i].childpid, ARG1(i));

        if (ARG2(i))
        {
            if (!mvee_rw_read_struct(childs[i].childpid, ARG2(i), 2 * sizeof(struct timeval), utimes))
            {
                warnf("couldn't read utimes\n");
                return 0;
            }
        }
        else
        {
            gettimeofday(utimes, NULL);
        }

        debugf("pid: %d - SYS_UTIMES(%s, access time = %ld.%06ld, modification time = %ld.%06ld)\n", childs[i].childpid,
                   str1,
                   utimes[0].tv_sec, utimes[0].tv_usec,
                   utimes[1].tv_sec, utimes[1].tv_usec);

        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_utimes_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKBUFFER(2, 2 * sizeof(struct timeval));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_waitid - (int which, pid_t pid, struct siginfo __user *infop,
  int options, struct rusage __user *ru);
-----------------------------------------------------------------------------*/
long monitor::handle_waitid_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_WAITID(%d, %d, 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ")\n", childs[i].childpid, ARG1(i), ARG2(i), ARG3(i), ARG4(i), ARG5(i));

    return 0;
}

long monitor::handle_waitid_precall(int childnum)
{
    CHECKARG(1);
    CHECKPOINTER(3);
    CHECKPOINTER(5);
    CHECKARG(4);
    CHECKARG(2);
    MAPPIDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_waitid_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, pids)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_WAITID return: %d\n", childs[i].childpid, pids[i]);

    return 0;
}

long monitor::handle_waitid_postcall(int childnum)
{
    UNMAPPIDS(1);

    // we want to replicate the master result even if the call fails
    unsigned long master_result = call_postcall_get_child_result(0);

    // if the result is a PID, set the same master PID in
    // all non-master children
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_child_result(i, master_result);

    // the siginfo is set even if the call fails
    if (ARG3(0))
    {
        MonitorState tmp                = state;
        bool         old_call_succeeded = call_succeeded;
        call_succeeded = true;
        state          = STATE_IN_MASTERCALL;
        REPLICATEBUFFERFIXEDLEN(3, sizeof(siginfo_t));
        state          = tmp;
        call_succeeded = old_call_succeeded;
    }

    if (ARG5(0))
        REPLICATEBUFFERFIXEDLEN(5, sizeof(struct rusage));

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_inotify_init
-----------------------------------------------------------------------------*/
long monitor::handle_inotify_init_precall(int childnum)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_inotify_init_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_inotify_init_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
        set_fd_table->create_fd_info(FT_POLL_BLOCKING, fds, "inotify_init", 0, false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_inotify_add_watch
-----------------------------------------------------------------------------*/
long monitor::handle_inotify_add_watch_precall(int childnum)
{
    // TODO: Check arguments?
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_inotify_add_watch_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_inotify_add_watch_postcall(int childnum)
{
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_inotify_rm_watch
-----------------------------------------------------------------------------*/
long monitor::handle_inotify_rm_watch_precall(int childnum)
{
    // TODO: Check arguments?
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_inotify_rm_watch_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_inotify_rm_watch_postcall(int childnum)
{
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_openat - (int dfd, const char __user *filename, int flags, int mode)
-----------------------------------------------------------------------------*/
long monitor::handle_openat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* filename = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_OPENAT(%d, %s, 0x%08X, 0x%08X)\n", childs[i].childpid, ARG1(i), filename, ARG3(i), ARG4(i));
        SAFEDELETEARRAY(filename);
    }

    return 0;
}

long monitor::handle_openat_precall(int childnum)
{
    for (int i = 0; i < mvee::numvariants - 1; ++i)
	{
        if ((ARG3(i) & O_FILEFLAGSMASK) != (ARG3(i+1) & O_FILEFLAGSMASK))
            return MVEE_PRECALL_ARGS_MISMATCH(3) | MVEE_PRECALL_CALL_DENY;
		if ((ARG3(i) & O_CREAT) && ((ARG4(i) & S_FILEMODEMASK) != (ARG4(i+1) & S_FILEMODEMASK)))
			return MVEE_PRECALL_ARGS_MISMATCH(4) | MVEE_PRECALL_CALL_DENY;
	}

    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);

    if ((int)ARG1(0) > 0)
        MAPFDS(1);

    std::string full_path = set_fd_table->get_full_path(childs[0].childpid, (unsigned long)(int)ARG1(0), (void*)ARG2(0));
    //	warnf("openat: %s\n", full_path.c_str());

    if (full_path == "")
        return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;

    if (full_path.find("/proc/self/") == 0
        && full_path != "/proc/self/maps"
        && full_path != "/proc/self/exe")
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

long monitor::handle_openat_call(int childnum)
{
    int         i, result, old_flags, flags;
    std::string str1 = set_fd_table->get_full_path(childs[0].childpid, (unsigned long)(int)ARG1(0), (void*)ARG2(0));

    flags  = old_flags = ARG3(0);
    result = handle_check_open_call(str1, &flags, ARG4(0));

    /* MORE LIBREOFFICE HACKS. See comment in handle_open_call

       if (flags != old_flags)
       for (i = 0; i < mvee::numvariants; ++i)
       SETARG3(i, flags);

       =>
       mvee_wrap_ptrace(PTRACE_POKEUSER, childs[i].childpid, 4*EDX, (void*)flags);
     */

    if (flags != old_flags)
        for (i = 0; i < mvee::numvariants; ++i)
            SETARG3(i, flags);

    return result;
}

long monitor::handle_openat_log_return(int childnum)
{
    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, fds)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_OPENAT return: %d\n", childs[i].childpid, fds[i]);

    return 0;
}

long monitor::handle_openat_postcall(int childnum)
{
    if ((int)ARG1(0) > 0)
        UNMAPFDS(1);

    if (call_succeeded)
    {
        char*                      resolved_path = NULL;
        std::string                tmp_path      = set_fd_table->get_full_path(childs[0].childpid, (unsigned long)(int)ARG1(0), (void*)ARG2(0));

        resolved_path = realpath(tmp_path.c_str(), NULL);

        std::vector<unsigned long> fds           = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
        set_fd_table->create_fd_info(FT_REGULAR, fds, resolved_path, ARG3(0), ARG3(0) & O_CLOEXEC, state == STATE_IN_MASTERCALL, false);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif

        free(resolved_path);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_mkdirat - (int dirfd, const char *pathname, mode_t mode)
-----------------------------------------------------------------------------*/
long monitor::handle_mkdirat_precall(int childnum)
{
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fstatat64 - (int dirfd, const char *pathname, struct stat *buf, int flags)

  sys_newfstatat - (int dfd, const char __user * filename,
  struct stat __user * statbuf, int flag)
-----------------------------------------------------------------------------*/
long monitor::handle_newfstatat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* path = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_NEWFSTATAT(%d, %s, 0x" PTRSTR ", 0x%08X)\n", childs[i].childpid, ARG1(i), path, ARG3(i), ARG4(i));
        SAFEDELETEARRAY(path);
    }

    return 0;
}

long monitor::handle_newfstatat_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_newfstatat_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct stat64));
    return 0;
}

long monitor::handle_fstatat64_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* path = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_FSTATAT64(%d, %s, 0x" PTRSTR ", 0x%08X)\n", childs[i].childpid, ARG1(i), path, ARG3(i), ARG4(i));
        SAFEDELETEARRAY(path);
    }

    return 0;
}

long monitor::handle_fstatat64_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_fstatat64_log_return(int childnum)
{
    std::vector<unsigned long> argarray(mvee::numvariants);
    if (state == STATE_IN_SYSCALL)
    {
        FILLARGARRAY(3, argarray);
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            struct stat64* sb = (struct stat64*)mvee_rw_read_data(childs[i].childpid, argarray[i], sizeof(struct stat64));
            if (sb)
            {
                debugf("pid: %d - SYS_FSTATAT64 return\n", childs[i].childpid);

                switch (sb->st_mode & S_IFMT) {
                    case S_IFBLK:  debugf("File type:                block device\n");            break;
                    case S_IFCHR:  debugf("File type:                character device\n");        break;
                    case S_IFDIR:  debugf("File type:                directory\n");               break;
                    case S_IFIFO:  debugf("File type:                FIFO/pipe\n");               break;
                    case S_IFLNK:  debugf("File type:                symlink\n");                 break;
                    case S_IFREG:  debugf("File type:                regular file\n");            break;
                    case S_IFSOCK: debugf("File type:                socket\n");                  break;
                    default:       debugf("File type:                unknown?\n");                break;
                }

                debugf("I-node number:            %ld\n", (long) sb->st_ino);

                debugf("Mode:                     %lo (octal)\n",
                           (unsigned long) sb->st_mode);

                debugf("Link count:               %ld\n", (long) sb->st_nlink);
                debugf("Ownership:                UID=%ld   GID=%ld\n",
                           (long) sb->st_uid, (long) sb->st_gid);

                debugf("Preferred I/O block size: %ld bytes\n",
                           (long) sb->st_blksize);
                debugf("File size:                %lld bytes\n",
                           (long long) sb->st_size);
                debugf("Blocks allocated:         %lld\n",
                           (long long) sb->st_blocks);

                debugf("Last status change:       %s", ctime(&sb->st_ctime));
                debugf("Last file access:         %s", ctime(&sb->st_atime));
                debugf("Last file modification:   %s", ctime(&sb->st_mtime));
            }
            SAFEDELETEARRAY(sb);
        }
    }

    return 0;
}

long monitor::handle_fstatat64_postcall(int childnum)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_unlinkat - (int dirfd, const char *pathname, int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_unlinkat_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_renameat - (int olddirfd, const char *oldpath,
  int newdirfd, const char *newpath)
-----------------------------------------------------------------------------*/
long monitor::handle_renameat_precall(int childnum)
{
    CHECKFD(3);
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKPOINTER(4);
    CHECKSTRING(4);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_linkat - (int olddirfd, const char *oldpath,
  int newdirfd, const char *newpath, int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_linkat_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(4);
    CHECKARG(5);
    CHECKFD(3);
    CHECKFD(1);
    CHECKSTRING(4);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_symlinkat - (const char *oldpath, int newdirfd, const char *newpath)
-----------------------------------------------------------------------------*/
long monitor::handle_symlinkat_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKPOINTER(3);
    CHECKFD(2);
    CHECKSTRING(3);
    CHECKSTRING(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_readlinkat - (int dirfd, const char *pathname,
  char *buf, size_t bufsiz)
-----------------------------------------------------------------------------*/
long monitor::handle_readlinkat_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_readlinkat_postcall(int childnum)
{
    REPLICATEBUFFER(3);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fchmodat - (int, dfd, const char __user *, filename, umode_t, mode)
-----------------------------------------------------------------------------*/
long monitor::handle_fchmodat_precall (int childnum)
{
    CHECKPOINTER(2);
    CHECKFD(1);
    CHECKSTRING(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_faccessat - (int dirfd, const char *pathname, int mode)
-----------------------------------------------------------------------------*/
long monitor::handle_faccessat_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
    {
        char* str1 = mvee_rw_read_string(childs[i].childpid, ARG2(i));
        debugf("pid: %d - SYS_FACCESSAT(%d, %s, 0x%08X = %s, 0x%08x)\n",
                   childs[i].childpid, ARG1(i), str1, ARG3(i),
                   getTextualAccessMode(ARG3(i)).c_str(), ARG4(i));
        SAFEDELETEARRAY(str1);
    }

    return 0;
}

long monitor::handle_faccessat_precall(int childnum)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKSTRING(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_utimensat - (int dirfd, const char *pathname,
  const struct timespec times[2], int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_utimensat_precall(int childnum)
{
    std::vector<unsigned long> argarray(mvee::numvariants);

    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);

    FILLARGARRAY(2, argarray);
    bool                       should_compare = true;
    for (int i = 0; i < mvee::numvariants; ++i)
        if (!argarray[i])
            should_compare = false;
    if (should_compare && !call_compare_child_strings(argarray, 0))
        return MVEE_PRECALL_ARGS_MISMATCH(2) | MVEE_PRECALL_CALL_DENY;

    if (ARG3(0))
    {
        unsigned char* master_times = mvee_rw_read_data(childs[0].childpid, ARG3(0), sizeof(struct timespec)*2);
        if (!master_times)
        {
            cache_mismatch_info("couldn't read master times\n");
            return MVEE_PRECALL_ARGS_MISMATCH(3) | MVEE_PRECALL_CALL_DENY;
        }
        bool           mismatch     = false;
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            unsigned char* slave_times = mvee_rw_read_data(childs[i].childpid, ARG3(i), sizeof(struct timespec)*2);
            if (!slave_times)
            {
                cache_mismatch_info("couldn't read slave times\n");
                return MVEE_PRECALL_ARGS_MISMATCH(3) | MVEE_PRECALL_CALL_DENY;
            }

            if (memcmp(master_times, slave_times, sizeof(struct timespec)*2))
                mismatch = true;
            SAFEDELETEARRAY(slave_times);
        }
        SAFEDELETEARRAY(master_times);

        if (mismatch)
            return MVEE_PRECALL_ARGS_MISMATCH(3) | MVEE_PRECALL_CALL_DENY;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_timerfd_create - (int clockid, int flags)
-----------------------------------------------------------------------------*/
long monitor::handle_timerfd_create_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_TIMERFD_CREATE(%d (%s), %d (%s))\n",
                   childs[i].childpid,
                   ARG1(i), getTextualTimerType(ARG1(i)),
                   ARG2(i), getTextualTimerFlags(ARG2(i)).c_str());

    return 0;
}

long monitor::handle_timerfd_create_precall(int childnum)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_timerfd_create_log_return(int childnum)
{
    if (childnum == -1 && state == STATE_IN_MASTERCALL)
        childnum = 0;

    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, fds)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_TIMERFD_CREATE return: %d\n", childs[i].childpid, fds[i]);

    return 0;
}

long monitor::handle_timerfd_create_postcall(int childnum)
{
    std::vector<unsigned long> fds;
    fds.resize(mvee::numvariants);
    std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));

    if (call_succeeded)
    {
		FileType type = (ARG2(0) & TFD_NONBLOCK) ? FT_POLL_NON_BLOCKING : FT_POLL_BLOCKING;
        set_fd_table->create_fd_info(type, fds, "timer", O_RDWR, (ARG2(0) & TFD_CLOEXEC) ? true : false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fallocate - (int fd, int mode, off_t offset, off_t len)
-----------------------------------------------------------------------------*/
long monitor::handle_fallocate_precall(int childnum)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_timerfd_settime - (int ufd, int flags,
  const struct itimerspec* utmr, struct itimerspec* otmr)
-----------------------------------------------------------------------------*/
long monitor::handle_timerfd_settime_precall(int childnum)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKPOINTER(3);
    CHECKPOINTER(4);
    CHECKBUFFER(3, sizeof(struct itimerspec));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_timerfd_settime_postcall(int childnum)
{
    if (ARG4(0))
        REPLICATEBUFFERFIXEDLEN(4, sizeof(struct itimerspec));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_timerfd_gettime - (int ufd, struct itimerspec* otmr)
-----------------------------------------------------------------------------*/
long monitor::handle_timerfd_gettime_precall(int childnum)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_timerfd_gettime_postcall(int childnum)
{
    if (ARG2(0))
        REPLICATEBUFFERFIXEDLEN(2, sizeof(struct itimerspec));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_dup3 - (unsigned int oldfd, unsigned int newfd, int flags)
  the only valid flag that can be passed to dup3 through the flags field is O_CLOEXEC!!!
-----------------------------------------------------------------------------*/
long monitor::handle_dup3_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_DUP3(%d, %d, %s)\n", childs[i].childpid,
                   ARG1(i), ARG2(i), getTextualFileFlags(ARG3(i)).c_str());

    return 0;
}

long monitor::handle_dup3_precall(int childnum)
{
    CHECKARG(3);
    CHECKFD(2);
    CHECKFD(1);

    if (set_fd_table->is_fd_master_file(ARG1(0)))
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    else
    {
        MAPFDS(1);
        MAPFDS(2);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }
}

long monitor::handle_dup3_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_dup3_log_return(int childnum)
{
    if (childnum == -1 && state == STATE_IN_MASTERCALL)
        childnum = 0;

    MVEE_HANDLER_RETURN_LOGGER(childnum, start, lim, fds)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_DUP3(%d, %d) return: %d\n", childs[i].childpid, ARG1(i), ARG2(i), fds[i]);

    return 0;
}

long monitor::handle_dup3_postcall(int childnum)
{
    std::vector<unsigned long> fds;

    if (state == STATE_IN_MASTERCALL)
    {
        fds.resize(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
    }
    else
    {
        fds = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
        UNMAPFDS(1);
        UNMAPFDS(2);
    }

    // dups succeeded => add new fds
    if (call_succeeded)
    {
        if (ARG1(0) != ARG2(0))
        {
            // if newfd already exists, dup2 will close it first
            // and then duplicate oldfd as newfd.
            //
            // freeing a non-existing fd will do nothing
            set_fd_table->free_fd_info(ARG2(0));

            // now dup a file with the same path, access flags
            // and close_on_exec flag as before
            fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
            if (!fd_info)
            {
                warnf("WTF IS GOING ON HERE? DUP3 FAIL!!!");
                return 0;
            }			
            set_fd_table->create_fd_info(fd_info->file_type, fds, fd_info->path.c_str(), fd_info->access_flags, (ARG3(0) != 0) ? true : false, fd_info->master_file, fd_info->unsynced_reads, fd_info->original_file_size);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pipe2
-----------------------------------------------------------------------------*/
long monitor::handle_pipe2_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_pipe2_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_pipe2_postcall(int childnum)
{
    if (call_succeeded)
    {
        int                        fildes[2];
        std::vector<unsigned long> read_fds(mvee::numvariants);
        std::vector<unsigned long> write_fds(mvee::numvariants);

        if (!mvee_rw_read_struct(childs[0].childpid, ARG1(0), 2 * sizeof(int), fildes))
        {
            warnf("couldn't read master fds\n");
            return 0;
        }

        std::fill(read_fds.begin(),  read_fds.end(),  fildes[0]);
        std::fill(write_fds.begin(), write_fds.end(), fildes[1]);

        REPLICATEBUFFERFIXEDLEN(1, sizeof(int) * 2);

        // add new file descriptor mappings for the created pipe
		FileType type = (ARG2(0) & O_NONBLOCK) ? FT_PIPE_NON_BLOCKING : FT_PIPE_BLOCKING;
        set_fd_table->create_fd_info(type, read_fds,  "pipe2:read",  O_RDONLY, ARG2(0) & O_CLOEXEC, true);
        set_fd_table->create_fd_info(type, write_fds, "pipe2:write", O_WRONLY, ARG2(0) & O_CLOEXEC, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_inotify_init1
-----------------------------------------------------------------------------*/
long monitor::handle_inotify_init1_precall(int childnum)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

long monitor::handle_inotify_init1_call(int childnum)
{
    return MVEE_CALL_ALLOW;
}

long monitor::handle_inotify_init1_postcall(int childnum)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));

		FileType type = (ARG1(0) & IN_NONBLOCK) ? FT_POLL_NON_BLOCKING : FT_POLL_BLOCKING;
        set_fd_table->create_fd_info(type, fds, "inotify_init1", 0, (ARG1(0) & IN_CLOEXEC) ? true : false, false);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_perf_event_open
-----------------------------------------------------------------------------*/
long monitor::handle_perf_event_open_log_args(int childnum)
{
    MVEE_HANDLER_ARGS_LOGGER(childnum, start, lim)

    for (int i = start; i < lim; ++i)
        debugf("pid: %d - SYS_PERF_EVENT_OPEN(0x" PTRSTR ", %d, %d, %d, %s)\n",
                   childs[i].childpid,
                   ARG1(i), ARG2(i), ARG3(i), ARG4(i), getTextualPerfFlags(ARG5(i)).c_str());

    return 0;
}

long monitor::handle_perf_event_open_precall(int childnum)
{
    CHECKPOINTER(1);
    CHECKBUFFER(1, sizeof(struct perf_event_attr));
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKARG(5);

#ifdef MVEE_ALLOW_PERF
    if (ARG2(0))
        MAPPIDS(2);

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
#else
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
#endif
}

long monitor::handle_perf_event_open_postcall(int childnum)
{
    if (call_succeeded)
    {
        bool cloexec = false;
#ifdef PERF_FLAG_FD_CLOEXEC
        if (ARG5(0) & PERF_FLAG_FD_CLOEXEC)
            cloexec = true;
#endif
        if (state != STATE_IN_MASTERCALL)
        {
            UNMAPFDS(2);
            std::vector<unsigned long> fds = call_postcall_get_result_vector();
            REPLICATEFDRESULT();
            set_fd_table->create_fd_info(FT_SPECIAL, fds, "perf_event", 0, cloexec, false, true);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
        else
        {
            std::vector<unsigned long> fds(mvee::numvariants);
            std::fill(fds.begin(), fds.end(), call_postcall_get_child_result(0));
            set_fd_table->create_fd_info(FT_SPECIAL, fds, "perf_event", 0, cloexec, true, false);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  handlers_setalias
-----------------------------------------------------------------------------*/
static void mvee_handlers_setalias(int callnum, int alias)
{
    std::map<unsigned long, unsigned char>::iterator it = mvee::syslocks_table.find(callnum);
    if (it != mvee::syslocks_table.end())
        mvee::syslocks_table.insert(std::pair<unsigned long, unsigned char>(alias, it->second));
}

/*-----------------------------------------------------------------------------
  init_syslocks -
-----------------------------------------------------------------------------*/
void mvee::init_syslocks()
{
    /*
    These annotations get picked up by the generate_syscall_table.sh script
	DONTNEED monitor::handle_shmctl_precall
    DONTNEED monitor::handle_brk_precall
    DONTNEED monitor::handle_shmget_precall
    DONTNEED monitor::handle_uname_precall
    DONTNEED monitor::handle_sched_getparam_precall
    DONTNEED monitor::handle_sched_getscheduler_precall
    DONTNEED monitor::handle_sched_get_priority_max_precall
    DONTNEED monitor::handle_sched_get_priority_min_precall
    DONTNEED monitor::handle_getuid32_precall
    DONTNEED monitor::handle_getuid_precall
    DONTNEED monitor::handle_getgid32_precall
    DONTNEED monitor::handle_getgid_precall
    DONTNEED monitor::handle_geteuid32_precall
    DONTNEED monitor::handle_geteuid_precall
    DONTNEED monitor::handle_getegid32_precall
    DONTNEED monitor::handle_getegid_precall
    DONTNEED monitor::handle_getresuid32_precall
    DONTNEED monitor::handle_getresuid_precall
    DONTNEED monitor::handle_getresgid32_precall
    DONTNEED monitor::handle_getresgid_precall
    DONTNEED monitor::handle_madvise_precall
    DONTNEED monitor::handle_set_thread_area_precall
    DONTNEED monitor::handle_exit_group_precall
    DONTNEED monitor::handle_set_tid_address_precall
    DONTNEED monitor::handle_clock_getres_precall
    DONTNEED monitor::handle_set_robust_list_precall
    DONTNEED monitor::handle_fadvise64_64_precall
    DONTNEED monitor::handle_fadvise64_precall
    DONTNEED monitor::handle_sched_getaffinity_precall
    DONTNEED monitor::handle_rt_sigreturn_precall
    DONTNEED monitor::handle_getpid_precall
    DONTNEED monitor::handle_prlimit64_precall
    DONTNEED monitor::handle_sigaltstack_precall
    DONTNEED monitor::handle_shmdt_precall
	DONTNEED monitor::handle_rt_sigtimedwait_precall
    ALIAS mmap mmap2
    ALIAS fcntl fcntl64
    ALIAS rt_sigaction sigaction
    ALIAS rt_sigreturn sigreturn
    ALIAS rt_sigsuspend sigsuspend
    ALIAS select _newselect
    ALIAS getxattr lgetxattr
    ALIAS setxattr lsetxattr
    ALIAS getgroups getgroups32
    */

    // Syslock init
#define REG_LOCKS(callnum, locks) \
    mvee::syslocks_table.insert(std::pair<unsigned long, unsigned char>(callnum, locks))

    // i386 hack
#ifdef __NR_socketcall
#define __NR_socket      (unsigned long)-SYS_SOCKET
#define __NR_socketpair  (unsigned long)-SYS_SOCKETPAIR
#define __NR_bind        (unsigned long)-SYS_BIND
#define __NR_accept      (unsigned long)-SYS_ACCEPT
#define __NR_accept4     (unsigned long)-SYS_ACCEPT4
#define __NR_listen      (unsigned long)-SYS_LISTEN
#define __NR_connect     (unsigned long)-SYS_CONNECT
#define __NR_getsockname (unsigned long)-SYS_GETSOCKNAME
#define __NR_getsockopt  (unsigned long)-SYS_GETSOCKOPT
#define __NR_getpeername (unsigned long)-SYS_GETPEERNAME
#define __NR_setsockopt  (unsigned long)-SYS_SETSOCKOPT
#define __NR_sendto      (unsigned long)-SYS_SENDTO
#define __NR_sendmsg     (unsigned long)-SYS_SENDMSG
#define __NR_recvfrom    (unsigned long)-SYS_RECVFROM
#define __NR_recvmsg     (unsigned long)-SYS_RECVMSG
#define __NR_shutdown    (unsigned long)-SYS_SHUTDOWN
#endif


    REG_LOCKS(MVEE_GET_SHARED_BUFFER,   MVEE_SYSLOCK_SHM  | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(MVEE_FLUSH_SHARED_BUFFER, MVEE_SYSLOCK_SHM  | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(MVEE_INVOKE_LD,           MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);

    // syscalls that create a new process or load a new process image
    REG_LOCKS(__NR_fork,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_SHM | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_execve,              MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_SHM | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_clone,               MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_SHM | MVEE_SYSLOCK_FULL);

    // normal syscalls that create/destroy/modify file descriptors
    REG_LOCKS(__NR_open,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_openat,              MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_dup,                 MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_dup2,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_dup3,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_pipe,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_pipe2,               MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_close,               MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_inotify_init,        MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_inotify_init1,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_fcntl,               MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_socket,              MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_socketpair,          MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_epoll_create,        MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_epoll_create1,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_epoll_ctl,           MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);

    // normal syscalls that read the file system
    REG_LOCKS(__NR_chdir,               MVEE_SYSLOCK_FD | MVEE_SYSLOCK_POSTCALL);
    REG_LOCKS(__NR_fchdir,              MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);

    // master calls that create/destroy/modify file descriptors
    REG_LOCKS(__NR_bind,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_select,              MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    REG_LOCKS(__NR_accept,              MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    REG_LOCKS(__NR_accept4,             MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
    REG_LOCKS(__NR_connect,             MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL); // may block
#ifdef __NR__newselect
    REG_LOCKS(__NR__newselect,          MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);
#endif

    // syscalls with fd arguments
    REG_LOCKS(__NR_fstat,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#ifdef __NR_fstat64
    REG_LOCKS(__NR_fstat64,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#endif
    REG_LOCKS(__NR_fstatfs,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#ifdef __NR_fstatfs64
    REG_LOCKS(__NR_fstatfs64,   MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#endif
    REG_LOCKS(__NR_getdents,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_getdents64,  MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_read,        MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#ifdef __NR_read64
    REG_LOCKS(__NR_read64,      MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#endif
    REG_LOCKS(__NR_readv,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_pread64,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_preadv,      MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_write,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#ifdef __NR_write64
    REG_LOCKS(__NR_write64,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#endif
    REG_LOCKS(__NR_writev,      MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_pwrite64,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_pwritev,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_linkat,      MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_unlinkat,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_lseek,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#ifdef __NR__llseek
    REG_LOCKS(__NR__llseek,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
#endif
    REG_LOCKS(__NR_fsync,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_ioctl,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_symlinkat,   MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_listen,      MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_getsockname, MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_getsockopt,  MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_getpeername, MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_setsockopt,  MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_sendto,      MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_sendmmsg,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_sendmsg,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_recvfrom,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_recvmmsg,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_recvmsg,     MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_shutdown,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_fdatasync,   MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_poll,        MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);
    REG_LOCKS(__NR_sendfile,    MVEE_SYSLOCK_FD | MVEE_SYSLOCK_PRECALL);

    // normal syscalls with mman creations/deletions/modifications
    REG_LOCKS(__NR_msync,       MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_mmap,        MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_mremap,      MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_brk,         MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_mprotect,    MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_munmap,      MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_prctl,       MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);

    // non-blocking syscalls that read/modify the sighand table
#ifdef __NR_signal
    REG_LOCKS(__NR_signal,         MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_FULL);
#endif
    REG_LOCKS(__NR_rt_sigaction,   MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_FULL);
    REG_LOCKS(__NR_rt_sigprocmask, MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_FULL);

    // blocking syscalls that read/modify the sighand table
    REG_LOCKS(__NR_rt_sigsuspend,  MVEE_SYSLOCK_SIG | MVEE_SYSLOCK_PRECALL | MVEE_SYSLOCK_POSTCALL);


    // syscalls that read the process name
    REG_LOCKS(__NR_setsid, MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_PRECALL);

    // IPC calls
#ifdef __NR_shmat
    REG_LOCKS(__NR_shmat, MVEE_SYSLOCK_SHM | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
#endif

#ifdef __NR_ipc
    REG_LOCKS(__NR_ipc, MVEE_SYSLOCK_SHM | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_FULL);
#endif

#include "MVEE_syscall_alias_locks.h"
}
