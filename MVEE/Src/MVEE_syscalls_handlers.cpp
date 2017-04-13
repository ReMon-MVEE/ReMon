/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

// *****************************************************************************
//
// PLEASE READ THE INSTRUCTIONS IN MVEE/INC/MVEE_SYSCALLS.H BEFORE WRITING 
// SYSCALL HANDLERS!!!
//
// *****************************************************************************


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
#include <sys/poll.h>
#include <sstream>
#include <signal.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/net.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <net/if.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/timerfd.h>
#include <iomanip>
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
#include "MVEE_interaction.h"
#include "hde.h"

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
  handle_is_known_false_positive
-----------------------------------------------------------------------------*/
bool monitor::handle_is_known_false_positive(const char* program_name, long callnum, long* precall_flags)
{
    std::vector<char*> data(mvee::numvariants);
	std::fill(data.begin(), data.end(), (char*) NULL);

    if (set_mmap_table->thread_group_shutting_down)
        return true;

    bool               result = false;

	// Mismatches during early initialization are allowed
	if (!program_name)
		return true;

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
            if ((data[i] = (char*)rw::read_data(variants[i].variantpid, (void*) ARG2(i), ARG3(i))) == NULL)
            {
                warnf("couldn't get buffer for variant %d\n", i);
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

            warnf("masked %d occurences of \"GENERATED AT\" in data for variant %d\n", replaced, i);
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
    else if (callnum == __NR_open && MVEE_PRECALL_MISMATCHING_ARG((*precall_flags)) == 1)
    {
        bool true_positive = false;
		std::vector<std::string> files(mvee::numvariants);

		for (int i = 0; i < mvee::numvariants; ++i)
			files[i] = rw::read_string(variants[i].variantpid, (void*) ARG1(i));

		// Allow variants to open "> MVEE Variant <num> >" with mismatching nums
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            char  tmp[20];
            sprintf(tmp, "MVEE Variant %d >", i);

            if (files[i].compare(tmp) != 0)
            {
                true_positive = true;
                break;
            }
        }

        if (!true_positive)
			return true;

		// Allow MVEE_LD_Loader to open compile-time diversified variants
		true_positive = false;
		if (set_mmap_table->have_diversified_variants)
		{
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				if (files[i].compare(set_mmap_table->mmap_startup_info[i].image) != 0)
				{
					true_positive = true;
					break;
				}
			}
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
			set_mmap_table->have_diversified_variants = true;
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
long monitor::handle_check_open_call(const std::string& full_path, int flags, int mode)
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
    else if (full_path.find("/dev/nvidia") == 0)
	{
		warnf("refusing nvidia diver request\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
	else
    {
        //
        // open() with O_CREAT and O_EXCL will fail if the file already exists.
        // This call will thus only succeed in the first variant that executes it.
        // So let the monitor create the file first, and then let the variants
        // execute the same open() call without O_CREAT and O_EXCL.
        //
        if ( (flags & O_CREAT) && (flags & O_EXCL) )
        {
            //warnf("> O_CREAT & O_EXCL\n");
            err = open(full_path.c_str(), flags, mode);
            //warnf("> SYS_OPEN returned: %d (%s) %d (%s) for O_CREAT & O_EXCL call...\n", err, getTextualErrno(-err), errno, getTextualErrno(errno));
            if (err != -1)
            {
                // remove O_CREAT and O_EXCL from the flags and set the new flags
                // for each variant
                close(err);
                err = 0;
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
GET_CALL_TYPE(restart_syscall)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_exit - terminates the calling thread. Note that sys_exit and exit(3) have
  different semantics. exit(3) is a wrapper around sys_exit_group, which 
  terminates the entire thread group and not just the calling thread!
-----------------------------------------------------------------------------*/
PRECALL(exit)
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
PRECALL(fork)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

POSTCALL(fork)
{
    // get PID returned in master variant
    long result = call_postcall_get_variant_result(0);

    // set the same master PID in all non-master variants
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_variant_result(i, result);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_vfork - similar to fork but suspends the calling process until the
  child process terminates
-----------------------------------------------------------------------------*/
PRECALL(vfork)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

POSTCALL(vfork)
{
    // get PID returned in master variant
    long result = call_postcall_get_variant_result(0);

    // set the same master PID in all non-master variants
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_variant_result(i, result);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_read - (unsigned int fd, char __user *buf, size_t count)
-----------------------------------------------------------------------------*/
LOG_ARGS(read)
{
	debugf("%s - SYS_READ(%d, 0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

PRECALL(read)
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

LOG_RETURN(read)
{
	long result  = call_postcall_get_variant_result(variantnum);
	auto result_str = call_serialize_io_buffer(variantnum, (const unsigned char*) ARG2(variantnum), result);
	
	debugf("%s - SYS_READ return: %d => %s\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   result, 
		   result_str.c_str());
}

POSTCALL(read)
{
	if IS_SYNCED_CALL
	{
		if (state == STATE_IN_MASTERCALL)
		{
			REPLICATEBUFFER(2);
		}
	}
	else
	{
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
	}
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_write - (unsigned int fd, const char * buf, unsigned long count)
-----------------------------------------------------------------------------*/
LOG_ARGS(write)
{
	// writes to negative file descriptors are RAVEN pseudo-syscalls
	if ((int)ARG1(variantnum) < 0)
	{
		debugf("%s - SYS_WRITE(%d (%s), %d, %d)\n",
			   call_get_variant_pidstr(variantnum).c_str(), 
			   ARG1(variantnum), 
			   getTextualRAVENCall((int)ARG1(variantnum)),
			   ARG2(variantnum), 
			   ARG3(variantnum));
	}
	else
	{
		auto buf_str = call_serialize_io_buffer(variantnum, (const unsigned char*) ARG2(variantnum), ARG3(variantnum));

		debugf("%s - SYS_WRITE(%d, 0x" PTRSTR " (%s), %d)\n",
			   call_get_variant_pidstr(variantnum).c_str(), 
			   ARG1(variantnum), 
			   ARG2(variantnum), 
			   buf_str.c_str(), 
			   ARG3(variantnum));
	}
}

PRECALL(write)
{
    CHECKFD(1);
    CHECKPOINTER(2);

    if (perf && ARG1(0) <= 2)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
			variants[i].perf_out += rw::read_string(variants[i].variantpid, (void*) ARG2(i), ARG3(i));

        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
    }

    CHECKARG(3);

	if ((int)ARG1(0) >= 0)
	{
		CHECKBUFFER(2, ARG3(0));

		if (set_fd_table->is_fd_unsynced(ARG1(0)))
		{
			MAPFDS(1);
			return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
		}
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_open - (const char* filename, int flags, int mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(open)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_OPEN(%s, 0x%08X = %s, 0x%08X = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   str1.c_str(),
		   ARG2(variantnum), getTextualFileFlags(ARG2(variantnum)).c_str(),
		   ARG3(variantnum), getTextualFileMode(ARG3(variantnum) & S_FILEMODEMASK).c_str());
}

PRECALL(open)
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

	if (!ipmon_fd_handling)
	{
		auto orig_path = rw::read_string(variants[0].variantpid, (void*) ARG1(0));
		if (orig_path.find("/proc/self/") == 0 &&
			orig_path != "/proc/self/maps" &&
			orig_path != "/proc/self/exe")
		{
			debugf("master sys_open for: %s\n", orig_path.c_str());
			return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
		}

		auto full_path = set_fd_table->get_full_path(0, variants[0].variantpid, AT_FDCWD, (void*)ARG1(0));
		if (full_path == "")
			return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;

		if (full_path.find("/dev/shm/") == 0 ||
			full_path.find("/run/shm/") == 0)
			return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

		if (full_path.find("/dev/") == 0)
		{
			debugf("master sys_open for: %s\n", full_path.c_str());
			return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
		}
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

//
// Some "magic" happens in this call handler.  In most cases, open calls get
// dispatched as "normal" calls, which means that _ALL_ variants will open the
// file. This is fine, as it will not increase the system load. There is a bit
// of a problem when the file is opened with the O_CREAT | O_EXCL flags,
// however. O_CREAT | O_EXCL ensures that the specified file is created. If it
// already exists, the call will fail. In GHUMVEE, the first variant to complete
// the sys_open call will create the file (if it doesn't exist yet) and return a
// valid fd. Subsequent sys_open completions from other variants will fail
// because the file already exists. 
//
// We work around this by creating the file in the monitor, and stripping the
// O_EXCL flag.
// 
CALL(open)
{
	if IS_UNSYNCED_CALL
		return MVEE_CALL_ALLOW;

	int result = MVEE_CALL_ALLOW;

	// If do_alias returns true, we will have found aliases for at least
	// one variant. In this case, we want to repeat the check_open_call + 
	// flag stripping iteration below for each variant
	if (call_do_alias<1>())
	{
		for (auto i = 0; i < mvee::numvariants; ++i)
		{
			auto file = set_fd_table->get_full_path(i, variants[i].variantpid, AT_FDCWD, (void*) ARG1(i));

			result = handle_check_open_call(file.c_str(), ARG2(i), ARG3(i));

			// strip off the O_CREAT and O_EXCL flags
			// GHUMVEE will already have created the file in the handle_check_open_call function
			if (result & MVEE_CALL_ALLOW)
				if ((ARG2(i) & O_CREAT) && (ARG2(i) & O_EXCL))
					call_overwrite_arg_value(i, 2, ARG2(i) & (~(O_CREAT | O_EXCL)), true);
		}

		aliased_open = true;
	}
	else
	{
		auto file = set_fd_table->get_full_path(0, variants[0].variantpid, AT_FDCWD, (void*) ARG1(0));
		result = handle_check_open_call(file.c_str(), ARG2(0), ARG3(0));

		if ((result & MVEE_CALL_ALLOW) && (ARG2(0) & O_CREAT) && (ARG2(0) & O_EXCL))
			for (auto i = 0; i < mvee::numvariants; ++i)
				call_overwrite_arg_value(i, 2, ARG2(i) & (~(O_CREAT | O_EXCL)), true);

		aliased_open = false;
	}

    return result;
}

POSTCALL(open)
{
	if (!call_succeeded)
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;

	if IS_SYNCED_CALL
	{
		unsigned char              unsynced = 0;
		std::vector<unsigned long> fds      = call_postcall_get_result_vector();
		char* resolved_path       = NULL;
		std::string tmp_path      = set_fd_table->get_full_path(0, variants[0].variantpid, AT_FDCWD, (void*)ARG1(0));

		if (tmp_path.find("/proc/") == 0)
		{
			char maps[30];
			sprintf(maps, "/proc/%d/maps", variants[0].variantpid);

			if (tmp_path.compare(maps) == 0)
				unsynced = 1;
			else if (tmp_path.compare("/proc/self/maps") == 0)
				unsynced = 1;
		}
		else if (tmp_path.compare(set_mmap_table->mmap_startup_info[0].real_image) == 0)
		{
			debugf("Granting unsynced access to img: %s\n",
				   set_mmap_table->mmap_startup_info[0].real_image.c_str());
			unsynced = 1;
		}

		if (tmp_path.find("/proc/self") == 0)
		{
			std::stringstream pathbuilder;
			pathbuilder << "/proc/" << variants[0].variantpid << tmp_path.substr(strlen("/proc/self/"));
			tmp_path = pathbuilder.str();
		}

		resolved_path = realpath(tmp_path.c_str(), NULL);

		if (!resolved_path)
		{
			if (ipmon_fd_handling)
				return 0;
			warnf("Couldn't resolve path in postcall handler for sys_open - %s - FIXME!\n",
				  tmp_path.c_str());
			return 0;
		}

		if (strstr(resolved_path, "/dev/shm/") == resolved_path ||
			strstr(resolved_path, "/run/shm/") == resolved_path ||
			aliased_open)
			unsynced = 1;

		FileType type = (unsynced == 0) ? FT_REGULAR : FT_SPECIAL;
		set_fd_table->create_fd_info(type, fds, resolved_path, ARG2(0), ARG2(0) & O_CLOEXEC, state == STATE_IN_MASTERCALL, unsynced);
#ifdef MVEE_FD_DEBUG
		set_fd_table->verify_fd_table(getpids());
#endif
		free(resolved_path);
		REPLICATEFDRESULT();
	}
	else
	{
		std::string path = set_fd_table->get_full_path(variantnum, variants[variantnum].variantpid, AT_FDCWD, (void*)ARG1(variantnum));
		char* resolved_path = realpath(path.c_str(), NULL);

		set_fd_table->create_temporary_fd_info(variantnum, call_postcall_get_variant_result(variantnum), resolved_path, ARG2(variantnum), ARG2(variantnum) & O_CLOEXEC);

		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
	}

    return 0;
}


/*-----------------------------------------------------------------------------
  sys_close - (int filedescriptor)
-----------------------------------------------------------------------------*/
LOG_ARGS(close)
{
	debugf("%s - SYS_CLOSE(%d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum));
}

PRECALL(close)
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

POSTCALL(close)
{
	if IS_SYNCED_CALL
	{
		if (call_succeeded)
			set_fd_table->free_fd_info(ARG1(0));
#ifdef MVEE_FD_DEBUG
		set_fd_table->verify_fd_table(getpids());
#endif
	}
	else
	{
		if (call_succeeded)
			set_fd_table->free_temporary_fd_info(variantnum, ARG1(variantnum));
	}

    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_waitpid - (pid_t pid, int __user *stat_addr, int options)
-----------------------------------------------------------------------------*/
LOG_ARGS(waitpid)
{
	debugf("%s - SYS_WAITPID(%d, 0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

PRECALL(waitpid)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    MAPPIDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(waitpid)
{
    long tmp    = ARG4(0);
    ARG4(0) = 0;
    long result = handle_wait4_postcall(variantnum);
    ARG4(0) = tmp;
    return result;
}

/*-----------------------------------------------------------------------------
  sys_link - (const char __user *oldname, const char __user *newname)
-----------------------------------------------------------------------------*/
LOG_ARGS(link)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto str2 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_LINK(%s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   str2.c_str());
}

PRECALL(link)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKSTRING(2);

	bool alias1 = call_do_alias<1>();
	bool alias2 = call_do_alias<2>();

	if (alias1 || alias2)
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_unlink - (const char __user *pathname)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(unlink)
{
#ifdef MVEE_ENABLE_VALGRIND_HACKS
    auto unlink_fd = rw::read_string(variants[variantnum].variantpid, ARG1(variantnum));
    if (unlink_fd.find("/tmp/vgdb-pipe-") == 0)
        return MVEE_CALL_TYPE_UNSYNCED;
#endif
    return MVEE_CALL_TYPE_NORMAL;
}

LOG_ARGS(unlink)
{
	auto unlink_fd = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));
	
	debugf("%s - SYS_UNLINK(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   unlink_fd.c_str());
}

PRECALL(unlink)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
	
	// we do this at the precall site so we can still resolve the file name
	auto unlink_file = rw::read_string(variants[0].variantpid, (void*)ARG1(0));
	set_fd_table->set_file_unlinked(unlink_file.c_str());

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(unlink)
{
#ifdef MVEE_ENABLE_VALGRIND_HACKS
    if IS_UNSYNCED_CALL
    {
        auto unlink_fd = rw::read_string(variants[variantnum].variantpid, ARG1(variantnum));
        if (unlink_fd.find("/tmp/vgdb-pipe") == 0)
		{
			if (!interaction::write_syscall_return(variants[variantnum].variantpid, 0))
			{
				warnf("%s - failed to replicate syscall return\n",
					  call_get_variant_pidstr(variantnum).c_str());
			}			
		}
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
    }
#endif
#ifndef MVEE_FD_DEBUG
	set_fd_table->verify_fd_table(getpids());
#endif

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_execve - (char __user *filename, char __user * __user *argv,
  char __user * __user *envp);
-----------------------------------------------------------------------------*/
// Fetching the execve arguments is very costly, especially without the GHUMVEE
// ptrace extension.  it must only be done once!
void monitor::handle_execve_get_args(int variantnum)
{
    set_mmap_table->mmap_execve_id = monitorid;
    unsigned int      argc = 0;
	unsigned int      envc = 0;

    std::stringstream args;
	std::stringstream envs;

    set_mmap_table->mmap_startup_info[variantnum].argv.clear();
	set_mmap_table->mmap_startup_info[variantnum].envp.clear();

    if (ARG2(variantnum))
    {
        while (true)
        {
			unsigned long argvp;

			if (!rw::read_primitive<unsigned long>(variants[variantnum].variantpid,
												   (void*) (ARG2(variantnum) + sizeof(long)*argc++), argvp) || argvp == 0)
			{
				argc--;
				break;
			}

			auto tmp = rw::read_string(variants[variantnum].variantpid, (void*)argvp);
			if (tmp.length() > 0)
			{
				set_mmap_table->mmap_startup_info[variantnum].argv.push_back(tmp);
				args << tmp << " ";
			}
        }
    }

	if (ARG3(variantnum))
	{
		while (true)
		{
			unsigned long envp;
			
			if (!rw::read_primitive<unsigned long>(variants[variantnum].variantpid,
												   (void*) (ARG3(variantnum) + sizeof(long)*envc++), envp) || envp == 0)
			{
				envc--;
				break;
			}
			
			auto tmp = rw::read_string(variants[variantnum].variantpid, (void*)envp);
			if (tmp.length() > 0)
			{
				set_mmap_table->mmap_startup_info[variantnum].envp.push_back(tmp);
				envs << tmp << " ";
			}
		}
	}


	if (ipmon_fd_handling)
		set_fd_table->refresh_fd_table(getpids());

    set_mmap_table->mmap_startup_info[variantnum].image = 
		mvee::os_normalize_path_name(set_fd_table->get_full_path(variantnum, variants[variantnum].variantpid, AT_FDCWD, (void*) ARG1(variantnum)));
    set_mmap_table->mmap_startup_info[variantnum].serialized_argv = args.str();
	set_mmap_table->mmap_startup_info[variantnum].serialized_envp = envs.str();

#if defined(MVEE_FILTER_LOGGING) && !defined(MVEE_BENCHMARK)
    if (set_mmap_table->mmap_startup_info[variantnum].image.find("parsec-2.1") != std::string::npos
        || set_mmap_table->mmap_startup_info[variantnum].image.find("parsec-3.0") != std::string::npos
        || set_mmap_table->mmap_startup_info[variantnum].image.find("spec2006") != std::string::npos)
    {
        set_mmap_table->set_logging_enabled = 1;
        warnf("Logging enabled for binary: %s\n", set_mmap_table->mmap_startup_info[variantnum].image.c_str());
    }
#endif
}

LOG_ARGS(execve)
{
	handle_execve_get_args(variantnum);

	debugf("%s - SYS_EXECVE(PATH: %s -- ARGS: %s -- ENV: %s \n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   set_mmap_table->mmap_startup_info[variantnum].image.c_str(),
		   set_mmap_table->mmap_startup_info[variantnum].serialized_argv.c_str(),
		   set_mmap_table->mmap_startup_info[variantnum].serialized_envp.c_str()
		);
}

PRECALL(execve)
{
	handle_execve_get_args(0);

	// This is the default, but we might set it to true if
	// sys_execve mismatches on the first arg
	set_mmap_table->have_diversified_variants = false;

    for (int i = 1; i < mvee::numvariants; ++i)
    {
        handle_execve_get_args(i);
		
        if (set_mmap_table->mmap_startup_info[i].image.compare(
				set_mmap_table->mmap_startup_info[0].image))
        {
            cache_mismatch_info("execve image mismatch\n");
            return MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(1);
        }
        if (set_mmap_table->mmap_startup_info[i].serialized_argv.compare(
				set_mmap_table->mmap_startup_info[0].serialized_argv))
        {
            cache_mismatch_info("execve args mismatch\n");
            return MVEE_PRECALL_CALL_DENY | MVEE_PRECALL_ARGS_MISMATCH(2);
		}
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(execve)
{
	if IS_UNSYNCED_CALL
	{
		warnf("unsynced execve dispatch - was this intentional?\n");
		variants[variantnum].entry_point_bp_set = false;
		return MVEE_CALL_ALLOW;
	}

	// check if the file exists first
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		std::string alias = mvee::get_alias(i, set_mmap_table->mmap_startup_info[i].image);
		if (alias == "" && access(set_mmap_table->mmap_startup_info[i].image.c_str(), F_OK) == -1)
		{
			debugf("variant %d is trying to launch a non-existing program: %s\n", 
				   i, set_mmap_table->mmap_startup_info[i].image.c_str());
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(ENOENT);
		}
		else if (alias != "" && access(alias.c_str(), F_OK) == -1)
		{
			debugf("variant %d is trying to launch a non-existing program alias: %s\n", 
				   i, alias.c_str());
			return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(ENOENT);
		}					
	}

#ifndef MVEE_BENCHMARK
	if (set_mmap_table->have_diversified_variants)
	{
		warnf("Executing compile-time diversified variants\n");
		
		for (int i = 0; i < mvee::numvariants; ++i)
		{
			warnf("Variant %d: %s -- %s\n", i,
				  set_mmap_table->mmap_startup_info[i].image.c_str(),
				  set_mmap_table->mmap_startup_info[i].serialized_argv.c_str());
		}
	}
	else
	{
		warnf("Executing non-diversified variants: %s -- %s\n",
			  set_mmap_table->mmap_startup_info[0].image.c_str(),
			  set_mmap_table->mmap_startup_info[0].serialized_argv.c_str());		
	}
#endif

    if (set_mmap_table->mmap_startup_info[0].image.find("perf/perf") != std::string::npos)
        perf = 1;

	// return immediately if we don't have to use the MVEE_LD_Loader
	if (!(*mvee::config_variant_global)["hide_vdso"].asBool() && 
		!(*mvee::config_variant_global)["non_overlapping_mmaps"].asInt() && 
		(!(*mvee::config_variant_exec)["library_path"]
		 || (*mvee::config_variant_exec)["library_path"].asString().length() == 0))
		return MVEE_CALL_ALLOW;

	// check if we can load indirectly
	if (!mvee::os_can_load_indirect(set_mmap_table->mmap_startup_info[0].image))
	{
		warnf("File %s is statically linked and position dependent. We will not be able to use"
			  " any of our GHUMVEE goodies (DCL, custom libraries, ...)\n", 
			  set_mmap_table->mmap_startup_info[0].image.c_str());
		return MVEE_CALL_ALLOW; 
	}

	for (int i = 0; i < mvee::numvariants; ++i)
	{
		rewrite_execve_args(i, true, false);
		variants[i].entry_point_bp_set = false;
	}

    return MVEE_CALL_ALLOW;
}

POSTCALL(execve)
{
    if (call_succeeded)
    {
        int i;

        // "During an execve(2), the dispositions of handled signals are
        // reset to the default; the dispositions of ignored signals are
        // left unchanged."
        set_sighand_table->reset();

		// if IP-MON is running, we don't know anything about the open
		// fds before the execve call -> wipe the table and try to repopulate
		if (ipmon_fd_handling)
			set_fd_table->refresh_fd_table(getpids());

        // close all file descriptors that have O_CLOEXEC set
		else
			set_fd_table->free_cloexec_fds();

        if (created_by_vfork)
        {
            created_by_vfork = false;

            std::shared_ptr<mmap_table> new_table = std::shared_ptr<mmap_table>(new mmap_table());
            call_release_syslocks(variantnum, __NR_execve, MVEE_SYSLOCK_FULL);
            set_mmap_table.reset();
            set_mmap_table   = new_table;
            call_grab_syslocks(variantnum, __NR_execve, MVEE_SYSLOCK_FULL);
        }

		for (i = 0; i < mvee::numvariants; ++i)
			variants[i].should_sync_ptr = 0;

		set_mmap_table->truncate_table();
		for (i = 0; i < mvee::numvariants; ++i)
			set_mmap_table->refresh_variant_maps(i, variants[i].variantpid);

		ipmon_initialized = false;

        for (i = 0; i < mvee::numvariants; ++i)
            set_mmap_table->verify_mman_table(i, variants[i].variantpid);

        if ((*mvee::config_variant_global)["non_overlapping_mmaps"].asInt())
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
                    warnf("Detected vdso overlap for variants %d (PID: %d) and %d (PID: %d)\n",
                                i, variants[i].variantpid,
                                ret, variants[ret].variantpid);
                    should_restart[i] = true;
                }
            }

            int               tries = 0;
            for (int j = 1; j < mvee::numvariants; ++j)
            {
                while (should_restart[j])
                {
                    if (!restart_variant(j))
                    {
                        warnf("Restart failed for variant %d\n", j);
                        shutdown(false);
                        return 0;
                    }
                    set_mmap_table->truncate_table_variant(i);
                    set_mmap_table->refresh_variant_maps(j, variants[j].variantpid);
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

		// enable fast forwarding?
		/*for (int i = 0; i < mvee::numvariants; ++i)
		{
			variants[i].entry_point_address = 
				mvee::os_get_entry_point_address(...);
			
			variants[i].fast_forward_to_entry_point = true;				
		 }*/
    }
	else
	{		
		warnf("Could not start the variants (EXECVE error).\n");
		warnf("You probably forgot to compile the MVEE LD Loader. Please refer to MVEE/README.txt\n");
		shutdown(true);
	}

#ifdef MVEE_FD_DEBUG
    for (int i = 0; i < mvee::numvariants; ++i)
        set_fd_table->print_fd_table_proc(variants[i].variantpid);
    set_fd_table->verify_fd_table(getpids());
#endif

    // create a new shm table...
    // man page: "Attached System V shared memory segments are detached (shmat(2))."
    call_release_syslocks(variantnum, __NR_execve, MVEE_SYSLOCK_FULL);
    set_shm_table.reset();
    set_shm_table = std::shared_ptr<shm_table>(new shm_table);
    call_grab_syslocks(variantnum, __NR_execve, MVEE_SYSLOCK_FULL);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_chdir - (const char __user *filename)
-----------------------------------------------------------------------------*/
LOG_ARGS(chdir)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_CHDIR(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str());
}

PRECALL(chdir)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);

	if (call_do_alias<1>())
	{
		// TODO/FIXME: set_fd_table's cwd needs to be a vector
		warnf("Aliased chdir - this is not fully supported right now\n");
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(chdir)
{
    if (call_succeeded)
    {
        auto str = rw::read_string(variants[0].variantpid, (void*) ARG1(0));
        if (str.length() > 0)
            set_fd_table->chdir(str.c_str());
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_time - (time_t __user *tloc)
-----------------------------------------------------------------------------*/
PRECALL(time)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(time)
{
    if (ARG1(0))
        REPLICATEBUFFERFIXEDLEN(1, sizeof(time_t));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_chmod - (const char __user *filename, mode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(chmod)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto mode = getTextualFileMode(ARG2(variantnum));
	
	debugf("%s - SYS_CHMOD(%s, 0x%08x = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum), 
		   mode.c_str());
}

PRECALL(chmod)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fchmod - (unsigned int fd, mode_t mode)
-----------------------------------------------------------------------------*/
PRECALL(fchmod)
{
    CHECKARG(2);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_lseek - (unsigned int fd, off_t offset, unsigned int origin)
-----------------------------------------------------------------------------*/
LOG_ARGS(lseek)
{
	debugf("%s - SYS_LSEEK(%d, 0x%08X, %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

PRECALL(lseek)
{
    CHECKARG(3);
    CHECKARG(2);
    CHECKFD(1);

    if (set_fd_table->is_fd_unsynced(ARG1(0)))
    {
        MAPFDS(1);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_alarm - (unsigned int seconds)
-----------------------------------------------------------------------------*/
PRECALL(alarm)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_setitimer - (int which, const struct itimerval* new_value, struct itimerval* old_value)
-----------------------------------------------------------------------------*/
PRECALL(setitimer)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    if (ARG2(0))
        CHECKBUFFER(2, sizeof(struct itimerval));
    CHECKPOINTER(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(setitimer)
{
	REPLICATEBUFFERFIXEDLEN(3, sizeof(struct itimerval));
    return 0;
}

/*-----------------------------------------------------------------------------
    sys_getpid
-----------------------------------------------------------------------------*/
POSTCALL(getpid)
{
	if IS_UNSYNCED_CALL
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;

    for (int i = 1; i < mvee::numvariants; ++i)
	{
		if (!interaction::write_syscall_return(variants[i].variantpid, variants[0].varianttgid))
		{
			warnf("%s - failed to replicate syscall return\n",
				  call_get_variant_pidstr(i).c_str());
			return 0;
		}
	}
	
	return 0;
}

/*-----------------------------------------------------------------------------
  sys_sendfile - (int out_fd, int in_fd, off_t __user * offset, size_t count)
-----------------------------------------------------------------------------*/
LOG_ARGS(sendfile)
{
	debugf("%s - SYS_SENDFILE(OUT: %d, IN: %d, CNT: %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG4(variantnum));
}

PRECALL(sendfile)
{
    CHECKFD(1);
    CHECKFD(2);
    CHECKPOINTER(3);
    CHECKARG(4);

    if (set_fd_table->is_fd_unsynced(ARG1(0)) ||
		set_fd_table->is_fd_unsynced(ARG2(0)))
    {
        MAPFDS(1);
		MAPFDS(2);
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
    }

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ptrace
-----------------------------------------------------------------------------*/
CALL(ptrace)
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
GET_CALL_TYPE(pause)
{
	// There is a slight chance that we will see the return site of
    // the initial pause call
	//
	// TODO: check if this is still true. I think this was a race that got fixed
	// a while back...
    return MVEE_CALL_TYPE_UNSYNCED;
}

CALL(pause)
{
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
}

POSTCALL(pause)
{
    return MVEE_POSTCALL_RESUME | MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_rt_sigsuspend - (const sigset_t* sigset)
-----------------------------------------------------------------------------*/
LOG_ARGS(rt_sigsuspend)
{
	debugf("%s - SYS_RT_SIGSUSPEND(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   getTextualSigSet(call_get_sigset(variantnum, (void*)ARG1(variantnum), OLDCALLIFNOT(__NR_rt_sigsuspend))).c_str());
}

PRECALL(rt_sigsuspend)
{
    CHECKPOINTER(1);
    CHECKSIGSET(1, OLDCALLIFNOT(__NR_rt_sigsuspend));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(rt_sigsuspend)
{
	if IS_SYNCED_CALL
		variantnum = 0;

	memcpy(&old_blocked_signals[variantnum], &blocked_signals[variantnum], sizeof(sigset_t));
    sigemptyset(&blocked_signals[variantnum]);

    if (ARG1(variantnum))
    {
        sigset_t _set = call_get_sigset(variantnum, (void*)ARG1(variantnum), OLDCALLIFNOT(__NR_rt_sigsuspend));

        for (int i = SIGINT; i < __SIGRTMAX; ++i)
            if (sigismember(&_set, i))
                sigaddset(&blocked_signals[variantnum], i);
    }

    debugf("> SIGSUSPEND ENTRY - blocked signals are now: %s\n",
               getTextualSigSet(blocked_signals[variantnum]).c_str());

	return MVEE_CALL_ALLOW;
}

POSTCALL(rt_sigsuspend)
{
	if IS_SYNCED_CALL
		variantnum = 0;

    memcpy(&blocked_signals[variantnum], &old_blocked_signals[variantnum], sizeof(sigset_t));
    sigemptyset(&old_blocked_signals[variantnum]);

    debugf("> SIGSUSPEND EXIT - blocked signals are now: %s\n",
               getTextualSigSet(blocked_signals[variantnum]).c_str());

    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_utime - change access and/or modification times of an inode
  (char __user * filename, struct utimbuf __user * times)
-----------------------------------------------------------------------------*/
LOG_ARGS(utime)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	struct utimbuf times;
	std::stringstream timestr;
	
	if (ARG2(variantnum))
	{
		if (!rw::read<struct utimbuf>(variants[variantnum].variantpid, (void*) ARG2(variantnum), times))
			return;
		timestr << "ACTIME: " << times.actime << ", MODTIME: " << times.modtime;
	}
	else
	{
		timestr << "ACTIME: current, MODTIME: current";
	}
	
	debugf("%s - SYS_UTIME(%s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   timestr.str().c_str());
}

PRECALL(utime)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKBUFFER(2, sizeof(struct utimbuf));

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_mknod - (const char *pathname, mode_t mode, dev_t dev)
-----------------------------------------------------------------------------*/
LOG_ARGS(mknod)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto mode = getTextualFileMode(ARG2(variantnum));
	
	debugf("%s - SYS_MKNOD(%s, %08x - %s, %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum), 
		   mode.c_str(), 
		   ARG3(variantnum));
}

PRECALL(mknod)
{
	CHECKPOINTER(1);
	CHECKARG(2);
	CHECKARG(3);
	CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_access - (const char * filename, int mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(access)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	
	debugf("%s - SYS_ACCESS(%s, 0x%08X = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   str1.c_str(), 
		   ARG2(variantnum), 
		   getTextualAccessMode(ARG2(variantnum)).c_str());
}

PRECALL(access)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_kill - (int pid, int sig)
-----------------------------------------------------------------------------*/
LOG_ARGS(kill)
{
	debugf("%s - SYS_KILL(%d, %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   getTextualSig(ARG2(variantnum)));
}

PRECALL(kill)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_rename - (const char __user *oldname, const char __user *newname)
-----------------------------------------------------------------------------*/
LOG_ARGS(rename)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto str2 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	
	debugf("%s - SYS_RENAME(%s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   str2.c_str());
}

PRECALL(rename)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKSTRING(2);

	bool alias1 = call_do_alias<1>();
	bool alias2 = call_do_alias<2>();

	if (alias1 || alias2)
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_mkdir - (const char __user *pathname, int mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(mkdir)
{
	auto str = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	
	debugf("%s - SYS_MKDIR(%s, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   str.c_str(), 
		   ARG2(variantnum));
}

PRECALL(mkdir)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_rmdir - (const char __user *pathname)
-----------------------------------------------------------------------------*/
LOG_ARGS(rmdir)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	
	debugf("%s - SYS_RMDIR(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str());
}

PRECALL(rmdir)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_creat - (const char __user* pathname, umode_t mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(creat)
{
	auto str = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	
	debugf("%s - SYS_CREAT(%s, %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str.c_str(),
		   ARG2(variantnum));
}

PRECALL(creat)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKARG(2);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(creat)
{
    if (call_succeeded)
    {
        auto fds = call_postcall_get_result_vector();
        auto str = rw::read_string(variants[0].variantpid, (void*)ARG1(0));

        set_fd_table->create_fd_info(FT_REGULAR, fds, str.c_str(), O_WRONLY, false, false);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
    sys_dup - (unsigned int oldfd)
-----------------------------------------------------------------------------*/
LOG_ARGS(dup)
{
	debugf("%s - SYS_DUP(%d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum));
}

PRECALL(dup)
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

POSTCALL(dup)
{
    std::vector<unsigned long> fds;
    bool                       master_file = false;

    if (state == STATE_IN_MASTERCALL)
    {
        fds.resize(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
        master_file = true;
    }
    else
    {
        fds = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
    }

    // dups succeeded => add new fds
    if (call_succeeded)
    {
        fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
        if (!fd_info)
            return 0;

        set_fd_table->create_fd_info(fd_info->file_type, 
									 fds, 
									 fd_info->path.c_str(), 
									 fd_info->access_flags, 
									 false, 
									 master_file,
									 fd_info->unsynced_reads, 
									 fd_info->unlinked, 
									 fd_info->original_file_size);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pipe - (int __user * fildes)
-----------------------------------------------------------------------------*/
PRECALL(pipe)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(pipe)
{
    if (call_succeeded)
    {
        int                        fildes[2];
        std::vector<unsigned long> read_fds(mvee::numvariants);
        std::vector<unsigned long> write_fds(mvee::numvariants);

        if (!rw::read_struct(variants[0].variantpid, (void*)ARG1(0), 2 * sizeof(int), fildes))
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
PRECALL(times)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(times)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct tms));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_brk - (void* addr)
-----------------------------------------------------------------------------*/
LOG_RETURN(brk)
{
	debugf("%s - SYS_BRK(0x" LONGPTRSTR ") return = 0x" LONGPTRSTR "\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   call_postcall_get_variant_result(variantnum));
}

POSTCALL(brk)
{	
	if IS_SYNCED_CALL
	{
		for (int i = 0; i < mvee::numvariants; ++i)
		{
			long              result      = call_postcall_get_variant_result(i);
			mmap_region_info* heap_region = set_mmap_table->get_heap_region(i);
			fd_info           backing_file;

//			log_variant_backtrace(i);

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

				sprintf(cmd, "cat /proc/%d/maps | grep \"\\[heap\\]\"", variants[i].variantpid);
				output                          = mvee::log_read_from_proc_pipe(cmd, NULL);

				if (output == "" || sscanf(output.c_str(), LONGPTRSTR "-" LONGPTRSTR " %*s %*08x %*s %*s %*s", &heap_start, &heap_end) != 2)
				{
					// There is no heap yet...
					set_mmap_table->verify_mman_table(i, variants[i].variantpid);
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

			set_mmap_table->verify_mman_table(i, variants[i].variantpid);
		}
	}
	else
	{
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
	}

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getgid - (void)
-----------------------------------------------------------------------------*/
LOG_RETURN(getgid)
{
	long result DEBUGVAR =  call_postcall_get_variant_result(variantnum);
	debugf("%s - SYS_GETGID return: %d (%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   result, 
		   getTextualGroupId(result).c_str());
}

/*-----------------------------------------------------------------------------
  sys_syslog - (int type, char __user * buf, int len)
-----------------------------------------------------------------------------*/
LOG_ARGS(syslog)
{
	debugf("%s - SYS_SYSLOG(%s, 0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   getTextualSyslogAction(ARG1(variantnum)),
		   ARG2(variantnum),
		   ARG3(variantnum));
}

PRECALL(syslog)
{
    CHECKARG(1);
    CHECKARG(3);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(syslog)
{
	long result  = call_postcall_get_variant_result(variantnum);

	if (ARG1(variantnum) == SYSLOG_ACTION_READ ||
		ARG1(variantnum) == SYSLOG_ACTION_READ_ALL ||
		ARG1(variantnum) == SYSLOG_ACTION_READ_CLEAR)
	{
		auto str = (result > 0) ? rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum), result) : "";

		debugf("%s - SYS_SYSLOG return: %s\n", 
			   call_get_variant_pidstr(variantnum).c_str(), 
			   str.c_str());
	}
	else
	{
		debugf("%s - SYS_SYSLOG return: %d\n", 
			   call_get_variant_pidstr(variantnum).c_str(), result);
	}
}

POSTCALL(syslog)
{
    if (ARG1(0) == SYSLOG_ACTION_READ
		|| ARG1(0) == SYSLOG_ACTION_READ_ALL
		|| ARG1(0) == SYSLOG_ACTION_READ_CLEAR)
    {
        REPLICATEBUFFER(2);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setuid - (uid_t uid)
-----------------------------------------------------------------------------*/
LOG_ARGS(setuid)
{
	debugf("%s - SYS_SETUID(%d = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   getTextualGroupId(ARG1(variantnum)).c_str());
}

PRECALL(setuid)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_setgid - (gid_t gid)
-----------------------------------------------------------------------------*/
LOG_ARGS(setgid)
{
	debugf("%s - SYS_SETGID(%d = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   getTextualGroupId(ARG1(variantnum)).c_str());
}

PRECALL(setgid)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_signal - (int sig, __sighandler_t handler)
-----------------------------------------------------------------------------*/
PRECALL(signal)
{
    CHECKARG(1);
    CHECKSIGHAND(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(signal)
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
LOG_ARGS(ioctl)
{
	debugf("%s - SYS_IOCTL(%d, %d, 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

// there are many many ioctls we don't know yet
// http://man7.org/linux/man-pages/man2/ioctl_list.2.html
PRECALL(ioctl)
{
    CHECKARG(2);
    CHECKFD(1);
    CHECKPOINTER(3);

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
		// takes a struct ifconf *.  The ifc_buf field points to a buffer of
		// length ifc_len bytes, into which the kernel writes a list of type
		// struct ifreq [].
		// 
		// struct ifconf
		// {
		// 	int ifc_len;
		// 	union
		// 	{
		// 		__caddr_t ifcu_buf;
		// 		struct ifreq *ifcu_req;
		// 	} ifc_ifcu;
		// };
		case SIOCGIFCONF: // struct ifconf*
			CHECKBUFFER(3, sizeof(int)); // check if the length is equal
			is_master = 1;
			break;
		// struct ifreq * (in+out)
		//
		// struct ifreq
		// {
		// # define IFHWADDRLEN    6
		// # define IFNAMSIZ   IF_NAMESIZE
		//   union
		//	 {
		//     char ifrn_name[IFNAMSIZ];   /* Interface name, e.g. "en0".  */
		//   } ifr_ifrn;
		//   union
		//   {
		//     struct sockaddr ifru_addr;
		//     struct sockaddr ifru_dstaddr;
		//     struct sockaddr ifru_broadaddr;
		//     struct sockaddr ifru_netmask;
		//     struct sockaddr ifru_hwaddr;
		//     short int ifru_flags;
		//     int ifru_ivalue;
		//     int ifru_mtu;
		//     struct ifmap ifru_map;
		//     char ifru_slave[IFNAMSIZ];  /* Just fits the size */
		//     char ifru_newname[IFNAMSIZ];
		//     __caddr_t ifru_data;
		//   } ifr_ifru;
		// };			
		// Not documented in the man pages but as far as I can tell:
		// * The kernel loads the necessary network module based on the ifrn_name
		// * The MAC address of the specified interface is returned in the ifr_ifru.ifru_hwaddr field		
		case SIOCGIFHWADDR:
			CHECKBUFFER(3, IFNAMSIZ);
			is_master = 1;
			break;

        default:
		{
			// TODO: Remove this. temporary whitelist of nvidia ioctls
			// fd_info* fd_info = set_fd_table->get_fd_info(ARG1(0));
			// if (fd_info->path.find("nvidia") != std::string::npos)
			//	break;
            warnf("unknown ioctl: %d (0x%08x)\n", ARG2(0), ARG2(0));
            shutdown(false);
            break;
		}
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

POSTCALL(ioctl)
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
		case SIOCGIFCONF:
			REPLICATEIFCONF(3);
			break;
		case SIOCGIFHWADDR:
			REPLICATEBUFFERFIXEDLEN(3, sizeof(struct ifreq));
			break;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fcntl - (unsigned int fd, unsigned int cmd, unsigned long arg)
-----------------------------------------------------------------------------*/
LOG_ARGS(fcntl)
{
	debugf("%s - SYS_FCNTL(%d, %s, 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   getTextualFcntlCmd(ARG2(variantnum)), 
		   ARG3(variantnum));
}

PRECALL(fcntl)
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

POSTCALL(fcntl)
{
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
                    std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
                }
                else
                {
                    fds = call_postcall_get_result_vector();
                    REPLICATEFDRESULT();
                }

                fd_info*                   fd_info = set_fd_table->get_fd_info(ARG1(0));
                if (!fd_info)
                    return 0;

                set_fd_table->create_fd_info(fd_info->file_type, 
											 fds, 
											 fd_info->path.c_str(),
											 fd_info->access_flags, 
											 (ARG2(0) == F_DUPFD_CLOEXEC) ? true : fd_info->close_on_exec, 
											 state == STATE_IN_MASTERCALL, 
											 fd_info->unsynced_reads, 
											 fd_info->unlinked,
											 fd_info->original_file_size);
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
LOG_ARGS(flock)
{
	debugf("%s - SYS_FLOCK(%u, %u (%s))\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   getTextualFlockType(ARG2(variantnum)));
}

PRECALL(flock)
{
    CHECKFD(1);
    CHECKARG(2);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_umask - (int mask)
-----------------------------------------------------------------------------*/
LOG_ARGS(umask)
{
	debugf("%s - SYS_UMASK(%d = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   getTextualFileMode(ARG1(variantnum)).c_str());
}

PRECALL(umask)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(umask)
{
    syscall(__NR_umask, ARG1(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_dup2 - (unsigned int oldfd, unsigned int newfd)
-----------------------------------------------------------------------------*/
LOG_ARGS(dup2)
{
	debugf("%s - SYS_DUP2(%d, %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(dup2)
{
    CHECKFD(1);
    CHECKFD(2);

#ifdef MVEE_FD_DEBUG
    set_fd_table->print_fd_table();
    for (int i = 0; i < mvee::numvariants; ++i)
        set_fd_table->print_fd_table_proc(variants[i].variantpid);
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

POSTCALL(dup2)
{
    std::vector<unsigned long> fds;

    if (state == STATE_IN_MASTERCALL)
    {
        fds.resize(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
    }
    else
    {
        fds = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
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
                return 0;

            set_fd_table->create_fd_info(fd_info->file_type, 
										 fds, 
										 fd_info->path.c_str(), 
										 fd_info->access_flags, 
										 false, 
										 fd_info->master_file, 
										 fd_info->unsynced_reads, 
										 fd_info->unlinked,
										 fd_info->original_file_size);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setpgid - (pid_t pid, pid_t pgid)
-----------------------------------------------------------------------------*/
PRECALL(setpgid)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getppid - (void)
-----------------------------------------------------------------------------*/
PRECALL(getppid)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getpgrp - (void)
-----------------------------------------------------------------------------*/
PRECALL(getpgrp)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setsid - (void)
-----------------------------------------------------------------------------*/
PRECALL(setsid)
{
    warnf("Process is creating a new session (i.e. it's becoming a daemon!)\n");
    for (int i = 0; i < mvee::numvariants; ++i)
	{
        warnf("> Process %d PID: %d\n", i, variants[i].variantpid);
		warnf("> Process %d Name: %s\n", i, set_mmap_table->mmap_startup_info[i].image.c_str());
		warnf("> Process %d Args: %s\n", i, set_mmap_table->mmap_startup_info[i].serialized_argv.c_str());
	}
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getgroups - (int gidsetsize, gid_t __user* grouplist)
-----------------------------------------------------------------------------*/
PRECALL(getgroups)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

LOG_RETURN(getgroups)
{
	long result  = call_postcall_get_variant_result(variantnum);

	if (ARG2(variantnum))
	{
		gid_t* grouplist = new(std::nothrow) gid_t[result];
		if (!grouplist || !rw::read_struct(variants[variantnum].variantpid, (void*)ARG2(variantnum), sizeof(gid_t) * result, grouplist))
		{
			warnf("couldn't read grouplist\n");
			SAFEDELETEARRAY(grouplist);
			return;
		}

		debugf("%s - SYS_GETGROUPS return: %s\n", 
			   call_get_variant_pidstr(variantnum).c_str(),
			   getTextualGroups(result, grouplist).c_str());
		SAFEDELETEARRAY(grouplist);
	}
	else
	{
		debugf("%s - SYS_GETGROUPS return: %d\n", 
			   call_get_variant_pidstr(variantnum).c_str(),
			   result);
	}
}

/*-----------------------------------------------------------------------------
  sys_setgroups - (int gidsetsize, gid_t __user* grouplist)
-----------------------------------------------------------------------------*/
LOG_ARGS(setgroups)
{
	if (ARG1(variantnum) && ARG2(variantnum))
	{
		gid_t* grouplist = new(std::nothrow) gid_t[ARG1(variantnum)];
		if (grouplist)
			memset(grouplist, 0, sizeof(gid_t) * ARG1(variantnum));
		if (!grouplist || 
			!rw::read_struct(variants[variantnum].variantpid, (void*) ARG2(variantnum), sizeof(gid_t) * ARG1(variantnum), grouplist))
		{
			warnf("couldn't read grouplist\n");
			SAFEDELETEARRAY(grouplist);
			return;
		}

		debugf("%s - SYS_SETGROUPS (%s)\n", 
			   call_get_variant_pidstr(variantnum).c_str(),
			   getTextualGroups(ARG1(variantnum), grouplist).c_str());
		SAFEDELETEARRAY(grouplist);
	}
	else
	{
		debugf("%s - SYS_SETGROUPS ()\n", 
			   call_get_variant_pidstr(variantnum).c_str());
	}
}

PRECALL(setgroups)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKBUFFER(2, ARG1(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_setresuid - (uid_t ruid, uid_t euid, uid_t suid)
-----------------------------------------------------------------------------*/
LOG_ARGS(setresuid)
{
	debugf("%s - SYS_SETRESUID (%d (= %s), %d (= %s), %d (= %s))\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), getTextualUserId(ARG1(variantnum)).c_str(),
		   ARG2(variantnum), getTextualUserId(ARG2(variantnum)).c_str(),
		   ARG3(variantnum), getTextualUserId(ARG3(variantnum)).c_str());
}

PRECALL(setresuid)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_setresgid - (gid_t rgid, gid_t egid, gid_t sgid)
-----------------------------------------------------------------------------*/
LOG_ARGS(setresgid)
{
	debugf("%s - SYS_SETRESGID (%d (= %s), %d (= %s), %d (= %s))\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), getTextualGroupId(ARG1(variantnum)).c_str(),
		   ARG2(variantnum), getTextualGroupId(ARG2(variantnum)).c_str(),
		   ARG3(variantnum), getTextualGroupId(ARG3(variantnum)).c_str());
}

PRECALL(setresgid)
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
LOG_ARGS(rt_sigaction)
{
	struct sigaction DEBUGVAR action = call_get_sigaction(variantnum, (void*) ARG2(variantnum), OLDCALLIFNOT(__NR_rt_sigaction));

	debugf("%s - SYS_RT_SIGACTION(%d - %s - %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   getTextualSig(ARG1(variantnum)),
		   (action.sa_handler == SIG_DFL) ? "SIG_DFL" :
		   (action.sa_handler == SIG_IGN) ? "SIG_IGN" :
		   (action.sa_handler == (__sighandler_t)-2) ? "---" : "SIG_PTR"
		);
}

PRECALL(rt_sigaction)
{
    CHECKARG(1);
    CHECKARG(4);
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKSIGACTION(2, OLDCALLIFNOT(__NR_rt_sigaction));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(rt_sigaction)
{
	// TODO/FIXME - stijn: We might see mismatches by not tracking sigactions
	// while fast forwarding at some point
	if IS_UNSYNCED_CALL
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;

    if (call_succeeded && ARG2(0))
    {
        struct sigaction action = call_get_sigaction(0, (void*) ARG2(0), OLDCALLIFNOT(__NR_rt_sigaction));
        set_sighand_table->set_sigaction(ARG1(0), &action);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
    sys_arch_prctl - (int code, unsigned long addr)

	This is used to get/set the FS/GS base on x86
-----------------------------------------------------------------------------*/
PRECALL(arch_prctl)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
    sys_sync - (void)
-----------------------------------------------------------------------------*/
PRECALL(sync)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
    sys_setrlimit - (int resource, const struct rlimit *rlim)
-----------------------------------------------------------------------------*/
LOG_ARGS(setrlimit)
{
	struct rlimit  rlim;
	if (!rw::read<struct rlimit>(variants[variantnum].variantpid, (void*) ARG2(variantnum), rlim))
	{
		warnf("couldn't read rlimit\n");
		return;
	}
	
	debugf("%s - SYS_SETRLIMIT(%s, CUR: %d, MAX: %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   getTextualRlimitType(ARG1(variantnum)), 
		   rlim.rlim_cur, 
		   rlim.rlim_max);
}

PRECALL(setrlimit)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getrusage - (int who, struct rusage *usage)
-----------------------------------------------------------------------------*/
PRECALL(getrusage)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getrusage)
{
    if (ARG2(0))
        REPLICATEBUFFERFIXEDLEN(2, sizeof(struct rusage));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sysinfo - (struct sysinfo *info)
-----------------------------------------------------------------------------*/
PRECALL(sysinfo)
{
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(sysinfo)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct sysinfo));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_gettimeofday - (struct timeval *tv, struct timezone *tz)
-----------------------------------------------------------------------------*/
PRECALL(gettimeofday)
{
    CHECKPOINTER(2);
    CHECKPOINTER(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(gettimeofday)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct timeval));
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct timezone));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getrlimit (unsigned int resource, struct rlimit __user* limit)
-----------------------------------------------------------------------------*/
PRECALL(getrlimit)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_symlink - (const char  *  oldname, const char  *  newname)
-----------------------------------------------------------------------------*/
LOG_ARGS(symlink)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto str2 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	
	debugf("%s - SYS_SYMLINK(%s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   str2.c_str());
}

PRECALL(symlink)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKSTRING(1);

	bool alias1 = call_do_alias<1>();
	bool alias2 = call_do_alias<2>();

	if (alias1 || alias2)
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_readlink - (const char __user *path, char __user *buf, int bufsiz)
-----------------------------------------------------------------------------*/
LOG_ARGS(readlink)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	debugf("%s - SYS_READLINK(%s, 0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(),
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

PRECALL(readlink)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

CALL(readlink)
{
	auto str = rw::read_string(variants[0].variantpid, (void*) ARG1(0));

	// ridiculous hack for java and other shit
	if (str.compare("/proc/self/exe") == 0)
	{
		if (ARG3(0) > set_mmap_table->mmap_startup_info[0].image.length())
		{
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				rw::write_data(variants[i].variantpid, (void*) ARG2(i), 
								   set_mmap_table->mmap_startup_info[0].image.length(), 
								   (void*) set_mmap_table->mmap_startup_info[0].image.c_str());
			}

			return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(set_mmap_table->mmap_startup_info[0].image.length());
		}
	}

	return MVEE_CALL_ALLOW;
}

POSTCALL(readlink)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_munmap - (void* addr, size_t length)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(munmap)
{
    // We do NOT want to sync on the munmap of the lower region
    if (in_new_heap_allocation)
    {
        if ((unsigned long)ARG1(variantnum) == variants[variantnum].last_lower_region_start
            && (unsigned long)ARG2(variantnum) == variants[variantnum].last_lower_region_size)
		{
			variants[variantnum].last_lower_region_start = 
				variants[variantnum].last_lower_region_size = 0;			
            return MVEE_CALL_TYPE_UNSYNCED;
		}

        if ((unsigned long)ARG1(variantnum) == variants[variantnum].last_upper_region_start
            && (unsigned long)ARG2(variantnum) == variants[variantnum].last_upper_region_size)
		{
			variants[variantnum].last_upper_region_start = 
				variants[variantnum].last_upper_region_size = 0;			
            return MVEE_CALL_TYPE_UNSYNCED;
		}

    }

    return MVEE_CALL_TYPE_NORMAL;
}

LOG_ARGS(munmap)
{
	debugf("%s - SYS_MUNMAP(0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

bool monitor::handle_munmap_precall_callback(mmap_table* table, std::vector<mmap_region_info*>& infos, void* mon)
{
    infos[0]->print_region_info("munmap precall callback - region 0 >>>");

	try
	{
		// writeback region, fetch the buffer, compare it
		// take partial unmaps, offset, etc into account here! ugh!
		if (infos[0]->region_map_flags & MAP_MVEE_WASSHARED)
		{
			std::vector<variantstate> & variants       = ((monitor*)mon)->variants;

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

			rw::copy_data(variants[0].variantpid, (void*) actual_base, mvee::os_getpid(), info.writeback_buffer, writeback_size);

			bool                    mismatch       = false;

			for (int i = 1; i < mvee::numvariants; ++i)
			{
				unsigned char* variant_region = new unsigned char[writeback_size];
				rw::copy_data(variants[i].variantpid, (void*) MAX(infos[i]->region_base_address, (unsigned long)ARG1(i)),
								  mvee::os_getpid(), variant_region, writeback_size);

				if (memcmp(info.writeback_buffer, variant_region, writeback_size))
				{
					mismatch = true;

					debugf("write_back region mismatch!!!\n");
					debugf("> master region hex dump: %s\n", mvee::log_do_hex_dump(info.writeback_buffer, writeback_size).c_str());
					debugf("> variant region hex dump: %s\n",  mvee::log_do_hex_dump(variant_region, writeback_size).c_str());

					SAFEDELETEARRAY(variant_region);
					break;
				}

				SAFEDELETEARRAY(variant_region);
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
	catch (...)
	{
		warnf("munmap writeback failed\n");
		return false;
	}
}

PRECALL(munmap)
{
    // We ONLY allow unsynced munmaps for the unmapping
    // of the region below the newly allocated heap.
    // Check the comments about ptmalloc in MVEE_private.h
    // for further information
    if IS_UNSYNCED_CALL
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

	CHECKARG(2);

	// compare regions
	CHECKREGION(1, ARG2(0));

	// finally, check whether these are writeback regions
	std::vector<unsigned long> addresses(mvee::numvariants);
	FILLARGARRAY(1, addresses);
	if (set_mmap_table->foreach_region(addresses, ARG2(0), this, handle_munmap_precall_callback) != 0)
		return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(munmap)
{
    if (call_succeeded)
    {
		if IS_UNSYNCED_CALL
		{
			if (in_new_heap_allocation)
			{
				int i = 0;
				for (; i < mvee::numvariants; ++i)
				{
					if (variants[i].last_lower_region_start || 
						variants[i].last_upper_region_start)
						break;
				}

				if (i >= mvee::numvariants)
				{
					in_new_heap_allocation = false;
					call_release_locks(MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN);
				}
			}

			set_mmap_table->munmap_range(variantnum, ARG1(variantnum), ARG2(variantnum));
			set_mmap_table->verify_mman_table(variantnum, variants[variantnum].variantpid);
		}
		else
		{
			// perform the writebacks
			for (auto it = writeback_infos.begin(); it != writeback_infos.end(); ++it)
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

			while (writeback_infos.size() > 0)
			{
				writeback_info info = writeback_infos.back();
				SAFEDELETEARRAY(info.writeback_regions);
				SAFEDELETEARRAY(info.writeback_buffer);
				writeback_infos.pop_back();
			}

			for (int i = 0; i < mvee::numvariants; ++i)
				set_mmap_table->verify_mman_table(i, variants[i].variantpid);

#ifdef MVEE_MMAN_DEBUG
			set_mmap_table->print_mmap_table();
#endif
		}
    }

    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_truncate - (const char  *  path, long  length)
-----------------------------------------------------------------------------*/
LOG_ARGS(truncate)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_TRUNCATE(%s, %ld)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum));
}

PRECALL(truncate)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ftruncate - (unsigned int  fd, unsigned long  length)
-----------------------------------------------------------------------------*/
LOG_ARGS(ftruncate)
{
	debugf("%s - SYS_FTRUNCATE(%d, %ld)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   (unsigned int)ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(ftruncate)
{
    CHECKARG(2);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ioperm - (unsigned long from, unsigned long num, int turn_on)
-----------------------------------------------------------------------------*/
CALL(ioperm)
{
    cache_mismatch_info("The program is trying to access I/O ports. This call has been denied.\n");
    return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
}

/*-----------------------------------------------------------------------------
  sys_quotactl - (unsigned int cmd, const char* special, qid_t id, void* addr)
-----------------------------------------------------------------------------*/
PRECALL(quotactl)
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

POSTCALL(quotactl)
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
LOG_ARGS(socket)
{
	debugf("%s - SYS_SOCKET(%d = %s, %d = %s, %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), getTextualSocketFamily(ARG1(variantnum)),
		   ARG2(variantnum), getTextualSocketType(ARG2(variantnum)).c_str(),
		   ARG3(variantnum), getTextualSocketProtocol(ARG3(variantnum)));
}

PRECALL(socket)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(socket)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
		
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
LOG_ARGS(bind)
{
	GETTEXTADDRDIRECT(variantnum, text_addr, 2, ARG3(variantnum));

	debugf("%s - SYS_BIND(%d, %s, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   text_addr.c_str(), 
		   ARG3(variantnum));
}

PRECALL(bind)
{
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKBUFFER(2, ARG3(0));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(bind)
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
LOG_ARGS(connect)
{
	GETTEXTADDRDIRECT(variantnum, text_addr, 2, ARG3(variantnum));

	debugf("%s - SYS_CONNECT(%d, %s, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   text_addr.c_str(), 
		   ARG3(variantnum));
}

PRECALL(connect)
{
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKSOCKADDR(2, ARG3(0));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(connect)
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
LOG_ARGS(listen)
{
	debugf("%s - SYS_LISTEN(%d, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(listen)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getsockname - (int fd, struct sockaddr __user * usockaddr,
  int __user * usockaddr_len)
-----------------------------------------------------------------------------*/
LOG_ARGS(getsockname)
{
	debugf("%s - SYS_GETSOCKNAME(%d, 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(getsockname)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKBUFFER(3, sizeof(int));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getsockname)
{
    REPLICATEBUFFERANDLEN(2, 3, int);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpeername - (int fd, struct sockaddr __user * usockaddr,
  int __user * usockaddr_len)
-----------------------------------------------------------------------------*/
LOG_ARGS(getpeername)
{
	debugf("%s - SYS_GETPEERNAME(%d, 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(getpeername)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKBUFFER(3, sizeof(int));
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getpeername)
{
    REPLICATEBUFFERANDLEN(2, 3, int);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_socketpair - (int family, int type, int protocol,
  int __user * usockvec)
-----------------------------------------------------------------------------*/
LOG_ARGS(socketpair)
{
	debugf("%s - SYS_SOCKETPAIR(%d = %s, %d = %s, %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), getTextualSocketFamily(ARG1(variantnum)),
		   ARG2(variantnum), getTextualSocketType(ARG2(variantnum)).c_str(),
		   ARG3(variantnum), getTextualSocketProtocol(ARG3(variantnum)));
}

PRECALL(socketpair)
{
    CHECKPOINTER(4);
    CHECKARG(3);
    CHECKARG(2);
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(socketpair)
{
	int fd1, fd2;
	if (!rw::read_primitive<int>(variants[variantnum].variantpid, (void*) ARG4(variantnum), fd1) ||
		!rw::read_primitive<int>(variants[variantnum].variantpid, (void*) (ARG4(variantnum) + sizeof(int)), fd2))
	{
		warnf("Couldn't read socketpair return values\n");
		return;
	}

	debugf("%s - SYS_SOCKETPAIR return: [%d, %d]\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   fd1, 
		   fd2);
}

POSTCALL(socketpair)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::vector<unsigned long> fds2(mvee::numvariants);

		int fd1, fd2;
		if (!rw::read_primitive<int>(variants[0].variantpid, (void*) ARG4(0), fd1) ||
			!rw::read_primitive<int>(variants[0].variantpid, (void*) (ARG4(0) + sizeof(int)), fd2))
		{
			warnf("Couldn't read socketpair return values\n");
			return 0;
		}

        std::fill(fds.begin(),  fds.end(),  fd1);
        std::fill(fds2.begin(), fds2.end(), fd2);

		FileType type = (ARG2(0) & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING;
        set_fd_table->create_fd_info(type, fds,  "sock:unnamed", 0, (ARG2(0) & SOCK_CLOEXEC) ? true : false, true);
        set_fd_table->create_fd_info(type, fds2, "sock:unnamed", 0, (ARG2(0) & SOCK_CLOEXEC) ? true : false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif

		// replicate the pair
        for (int i = 1; i < mvee::numvariants; ++i)
        {
			if (!rw::write_primitive<int>(variants[i].variantpid, (void*) ARG4(i), fds[0]) ||
				!rw::write_primitive<int>(variants[i].variantpid, (void*) (ARG4(i) + sizeof(int)), fds2[0]))
			{
				warnf("Couldn't replicate socketpair return values\n");
				return 0;
			}
        }
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sendto -  (int fd, void __user * buff, size_t len,
  unsigned int flags, struct sockaddr __user * addr, int addr_len)
-----------------------------------------------------------------------------*/
LOG_ARGS(sendto)
{
	GETTEXTADDRDIRECT(variantnum, text_addr, 5, ARG6(variantnum));
	auto buf_str = call_serialize_io_buffer(variantnum, (const unsigned char*) ARG2(variantnum), ARG3(variantnum));

	debugf("%s - SYS_SENDTO(%d, " PTRSTR " (%s), %d, %d = %s, 0x" PTRSTR " (%s), %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), ARG2(variantnum), buf_str.c_str(),
		   ARG3(variantnum),
		   ARG4(variantnum), getTextualSocketMsgFlags(ARG4(variantnum)).c_str(),
		   ARG5(variantnum), text_addr.c_str(),
		   ARG6(variantnum));
}
 
PRECALL(sendto)
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
GET_CALL_TYPE(send)
{
    ARG5(variantnum) = 0;
    ARG6(variantnum) = 0;
    return MVEE_CALL_TYPE_NORMAL;
}

LOG_ARGS(send)
{
    handle_sendto_log_args(variantnum);
}

PRECALL(send)
{
    return handle_sendto_precall(variantnum);
}

/*-----------------------------------------------------------------------------
  sys_recvfrom - (int fd, void __user * ubuf, size_t size,
  unsigned int flags, struct sockaddr __user * addr,
  int __user * addr_len)
-----------------------------------------------------------------------------*/
LOG_ARGS(recvfrom)
{
	debugf("%s - SYS_RECVFROM(%d, " PTRSTR ", %d, %d = %s, 0x" PTRSTR ", %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), ARG2(variantnum),
		   ARG3(variantnum),
		   ARG4(variantnum), getTextualSocketMsgFlags(ARG4(variantnum)).c_str(),
		   ARG5(variantnum),
		   ARG6(variantnum));
}

PRECALL(recvfrom)
{
    CHECKPOINTER(2);
    CHECKPOINTER(5);
    CHECKPOINTER(6);
    CHECKARG(4);
    CHECKARG(3);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(recvfrom)
{
    REPLICATEBUFFER(2);
    REPLICATEBUFFERANDLEN(5, 6, int);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_shutdown - (int fd, int how)
-----------------------------------------------------------------------------*/
LOG_ARGS(shutdown)
{
	debugf("%s - SYS_SHUTDOWN(%d, %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   getTextualSocketShutdownHow(ARG2(variantnum)));
}

PRECALL(shutdown)
{
    CHECKARG(2);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setsockopt - (int fd, int level, int optname,
  char __user * optval, int optlen)
-----------------------------------------------------------------------------*/
LOG_ARGS(setsockopt)
{
	auto str = call_serialize_io_buffer(variantnum, (const unsigned char*) ARG4(variantnum), ARG5(variantnum));

	debugf("%s - SYS_SETSOCKOPT(%d, %d, %d, %s, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum),
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   str.c_str(), 
		   ARG5(variantnum));
}

PRECALL(setsockopt)
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
  sys_getsockopt - (int fd, int level, int optname, char __user * optval, 
  int __user * optlen)
-----------------------------------------------------------------------------*/
LOG_ARGS(getsockopt)
{
	debugf("%s - SYS_GETSOCKOPT(%d, %d, %d, 0x" PTRSTR ", 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   ARG5(variantnum));
}

PRECALL(getsockopt)
{
    CHECKARG(3);
    CHECKARG(2);
    CHECKFD(1);
    CHECKPOINTER(4);
    CHECKPOINTER(5);
    CHECKBUFFER(5, sizeof(int));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getsockopt)
{
    REPLICATEBUFFERANDLEN(4, 5, int);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_sendmsg - (int fd, struct msghdr __user * msg, unsigned int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(sendmsg)
{
	struct msghdr msg;
	if (!rw::read<struct msghdr>(variants[variantnum].variantpid, (void*) ARG2(variantnum), msg))
	{
		warnf("couldn't read msghdr\n");
		return;
	}

	auto msg_str = call_serialize_msgvector(variantnum, &msg);

	debugf("%s - SYS_SENDMSG(%d, 0x" PTRSTR " (%s), %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   msg_str.c_str(),
		   ARG3(variantnum), 
		   getTextualSocketMsgFlags(ARG3(variantnum)).c_str());
}

PRECALL(sendmsg)
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
LOG_ARGS(sendmmsg)
{
	debugf("%s - SYS_SENDMMSG(%d, 0x" PTRSTR ", %d, %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum),
		   ARG4(variantnum), 
		   getTextualSocketMsgFlags(ARG4(variantnum)).c_str());
}

PRECALL(sendmmsg)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKMMSGVECTOR(2, ARG3(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(sendmmsg)
{
    // update msg_len fields
    REPLICATEMMSGVECTORLENS(2, ARG3(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_recvmsg - (int fd, struct msghdr __user * msg,
  unsigned int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(recvmsg)
{
	debugf("%s - SYS_RECVMSG(%d, 0x" PTRSTR ", %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   getTextualSocketMsgFlags(ARG3(variantnum)).c_str());
}

PRECALL(recvmsg)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKMSGVECTORLAYOUT(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(recvmsg)
{
	struct msghdr msg;
	if (!rw::read<struct msghdr>(variants[variantnum].variantpid, (void*) ARG2(variantnum), msg))
	{
		warnf("couldn't read msghdr\n");
		return;
	}

	auto _msg = call_serialize_msgvector(variantnum, &msg);
	debugf("%s - SYS_RECVMSG return: %d - %s\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   call_postcall_get_variant_result(variantnum), 
		   _msg.c_str());
}

POSTCALL(recvmsg)
{
    REPLICATEMSGVECTOR(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_recvmmsg - (int fd, struct mmsghdr __user * mmsg,
  unsigned int vlen, unsigned int flags,
  struct timespec __user * timeout)
-----------------------------------------------------------------------------*/
PRECALL(recvmmsg)
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

POSTCALL(recvmmsg)
{
    REPLICATEMMSGVECTOR(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_accept4 - (int fd, struct sockaddr __user * upeer_sockaddr,
  int __user * upeer_addrlen, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(accept4)
{
	debugf("%s - SYS_ACCEPT4(%d, 0x" PTRSTR ", 0x" PTRSTR ", %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   getTextualSocketType(ARG4(variantnum)).c_str());
}

PRECALL(accept4)
{
    CHECKARG(4);
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKFD(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(accept4)
{
    REPLICATEBUFFERANDLEN(2, 3, int);

    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));

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
LOG_ARGS(eventfd2)
{
	debugf("%s - SYS_EVENTFD2(%d, %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   (int)ARG2(variantnum), 
		   getTextualEventFdFlags((int)ARG2(variantnum)));
}

PRECALL(eventfd2)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(eventfd2)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));

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
LOG_ARGS(epoll_create1)
{
	debugf("%s - SYS_EPOLL_CREATE1(%d = %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   (int)ARG1(variantnum), 
		   getTextualEpollFlags((int)ARG1(variantnum)));
}

PRECALL(epoll_create1)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(epoll_create1)
{
    if (call_succeeded)
    {		
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));

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
GET_CALL_TYPE(accept)
{
    ARG4(variantnum) = 0;
    return MVEE_CALL_TYPE_NORMAL;
}

LOG_ARGS(accept)
{
   handle_accept4_log_args(variantnum);
}

PRECALL(accept)
{
    return handle_accept4_precall(variantnum);
}

POSTCALL(accept)
{
    return handle_accept4_postcall(variantnum);
}

/*-----------------------------------------------------------------------------
  sys_socketcall - (int call, unsigned long __user *args)

  This is i386 only!!! The syscall has now been split up. See the comment at
  the top. We extract the arguments in handle_socketcall_get_call_type
  and from there on, we use the specialized handlers even on i386!!!
-----------------------------------------------------------------------------*/
// WARNING: do NOT disable this handler!!!
#ifdef __NR_socketcall
GET_CALL_TYPE(socketcall)
{
    unsigned int  nargs = 0;

#define NARGS(callnum, n) case callnum: nargs = n; break;

    switch(ARG1(variantnum))
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
    if (!rw::read_struct(variants[variantnum].variantpid, ARG2(variantnum), nargs * sizeof(unsigned long), real_args))
    {
        warnf("couldn't read real_args\n");
        return 0;
    }

    ORIGARG1(variantnum) = ARG1(variantnum);
    ARG1(variantnum)     = real_args[0];
    ARG2(variantnum)     = real_args[1];
    ARG3(variantnum)     = real_args[2];
    ARG4(variantnum)     = real_args[3];
    ARG5(variantnum)     = real_args[4];
    ARG6(variantnum)     = real_args[5];

    switch(ORIGARG1(variantnum))
    {
        case SYS_ACCEPT:    return handle_accept_get_call_type(variantnum);
    }

    return MVEE_CALL_TYPE_NORMAL;
}

LOG_ARGS(socketcall)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKET:    handle_socket_log_args(variantnum); return;
        case SYS_BIND:      handle_bind_log_args(variantnum); return;
        case SYS_CONNECT:   handle_connect_log_args(variantnum); return;
        case SYS_LISTEN:    handle_listen_log_args(variantnum); return;
        case SYS_ACCEPT:    handle_accept4_log_args(variantnum); return;  // wrapper
        case SYS_GETSOCKNAME: handle_getsockname_log_args(variantnum); return;
        case SYS_GETPEERNAME: handle_getpeername_log_args(variantnum); return;
        case SYS_SOCKETPAIR:  handle_socketpair_log_args(variantnum); return;
        case SYS_SEND:      handle_sendto_log_args(variantnum); return;   // wrapper
        case SYS_SENDTO:    handle_sendto_log_args(variantnum); return;
        case SYS_RECV:      handle_recvfrom_log_args(variantnum); return; // wrapper
        case SYS_RECVFROM:    handle_recvfrom_log_args(variantnum); return;
        case SYS_SHUTDOWN:    handle_shutdown_log_args(variantnum); return;
        case SYS_SETSOCKOPT:  handle_setsockopt_log_args(variantnum); return;
        case SYS_GETSOCKOPT:  handle_getsockopt_log_args(variantnum); return;
        case SYS_SENDMSG:   handle_sendmsg_log_args(variantnum); return;
        case SYS_RECVMSG:   handle_recvmsg_log_args(variantnum); return;
        case SYS_ACCEPT4:   handle_accept4_log_args(variantnum); return;
    }
}

PRECALL(socketcall)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKET:    return handle_socket_precall(variantnum);
        case SYS_BIND:      return handle_bind_precall(variantnum);
        case SYS_CONNECT:   return handle_connect_precall(variantnum);
        case SYS_LISTEN:    return handle_listen_precall(variantnum);
        case SYS_ACCEPT:    return handle_accept4_precall(variantnum);   // wrapper
        case SYS_GETSOCKNAME: return handle_getsockname_precall(variantnum);
        case SYS_GETPEERNAME: return handle_getpeername_precall(variantnum);
        case SYS_SOCKETPAIR:  return handle_socketpair_precall(variantnum);
        case SYS_SEND:      return handle_sendto_precall(variantnum);    // wrapper
        case SYS_SENDTO:    return handle_sendto_precall(variantnum);
        case SYS_RECV:      return handle_recvfrom_precall(variantnum);  // wrapper
        case SYS_RECVFROM:    return handle_recvfrom_precall(variantnum);
        case SYS_SHUTDOWN:    return handle_shutdown_precall(variantnum);
        case SYS_SETSOCKOPT:  return handle_setsockopt_precall(variantnum);
        case SYS_GETSOCKOPT:  return handle_getsockopt_precall(variantnum);
        case SYS_SENDMSG:   return handle_sendmsg_precall(variantnum);
        case SYS_RECVMSG:   return handle_recvmsg_precall(variantnum);
        case SYS_ACCEPT4:   return handle_accept4_precall(variantnum);
    }

    return 0;
}

POSTCALL(socketcall)
{
    switch(ORIGARG1(0))
    {
        case SYS_SOCKET:    return handle_socket_postcall(variantnum);
        case SYS_BIND:      return handle_bind_postcall(variantnum);
        case SYS_CONNECT:   return handle_connect_postcall(variantnum);
        case SYS_ACCEPT:    return handle_accept4_postcall(variantnum);  // wrapper
        case SYS_GETSOCKNAME: return handle_getsockname_postcall(variantnum);
        case SYS_GETPEERNAME: return handle_getpeername_postcall(variantnum);
        case SYS_SOCKETPAIR:  return handle_socketpair_postcall(variantnum);
        case SYS_RECV:      return handle_recvfrom_postcall(variantnum); // wrapper
        case SYS_RECVFROM:    return handle_recvfrom_postcall(variantnum);
        case SYS_GETSOCKOPT:  return handle_getsockopt_postcall(variantnum);
        case SYS_RECVMSG:   return handle_recvmsg_postcall(variantnum);
        case SYS_ACCEPT4:   return handle_accept4_postcall(variantnum);
    }

    return 0;
}

LOG_RETURN(socketcall)
{
    switch(ORIGARG1(variantnum))
    {
        case SYS_SOCKETPAIR: handle_socketpair_log_return(variantnum); return;
        case SYS_RECVMSG: handle_recvmsg_log_return(variantnum); return;
    }
}

#endif

/*-----------------------------------------------------------------------------
  sys_wait4 - (pid_t pid, int __user *stat_addr,
  int options, struct rusage __user *ru)
-----------------------------------------------------------------------------*/
LOG_ARGS(wait4)
{
	debugf("%s - SYS_WAIT4(%d, 0x" PTRSTR ", %d, 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(wait4)
{
    CHECKARG(1);
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKPOINTER(4);
    MAPPIDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(wait4)
{
    // we want to replicate the master result even if the call fails
    unsigned long master_result = call_postcall_get_variant_result(0);

    // if the result is a PID, set the same master PID in
    // all non-master variants
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_variant_result(i, master_result);

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
LOG_ARGS(shmat)
{
	debugf("%s - SYS_SHMAT(%d, 0x" PTRSTR ", %d (= %s))\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   getTextualShmFlags(ARG3(variantnum)).c_str());
}

PRECALL(shmat)
{
#ifndef MVEE_ALLOW_SHM
	CHECKARG(1);
#endif
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(shmat)
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
		debugf("attach to atomic buffer requested - size = %ld\n", shm_sz);
	}
	else if (set_fd_table->file_map_exists()
		&& (int)ARG1(0) == set_fd_table->file_map_id())
	{
		disjoint_bases = false;
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
				SETARG2(i, bases[i]);
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

POSTCALL(shmat)
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
		(int)ARG1(0) == atomic_buffer->id)
	{
		region_size = atomic_buffer->sz;
		region_name = "[atomic-buffer]";
	}
	else if (ipmon_buffer && (int)ARG1(0) == ipmon_buffer->id)
	{
		region_name = "[ipmon-buffer]";
		region_size = ipmon_buffer->sz;
#ifndef MVEE_BENCHMARK
		hwbp_set_watch(0, addresses[0], MVEE_BP_WRITE_ONLY); // detects overwrites of numvariants
//		hwbp_set_watch(0, addresses[0] + 64 * (1 + mvee::numvariants), MVEE_BP_WRITE_ONLY); // detects writes of first syscall no
#endif
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

LOG_RETURN(shmat)
{
	debugf("%s - SYS_SHMAT return: 0x" PTRSTR "\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   call_postcall_get_variant_result(variantnum));
}

/*-----------------------------------------------------------------------------
  sys_ipc - i386 only!!!
-----------------------------------------------------------------------------*/
PRECALL(ipc)
{
    if (ARG1(0) == SHMAT)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, 1);
        long result = handle_shmat_call(variantnum);
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, -1);
        return result;
    }

    return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;
}

CALL(ipc)
{
    if (ARG1(0) == SHMAT)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, 1);
        long result = handle_shmat_call(variantnum);
        for (int i = 0; i < mvee::numvariants; ++i)
            call_shift_args(i, -1);
        return result;
    }

    return MVEE_CALL_ALLOW;
}

LOG_RETURN(ipc)
{
    if (ARG1(variantnum) == SHMAT)
    {
		call_shift_args(variantnum, 1);
        handle_shmat_log_return(variantnum);
		call_shift_args(variantnum, -1);
    }
}

/*-----------------------------------------------------------------------------
  sys_fsync - (unsigned int fd)
-----------------------------------------------------------------------------*/
PRECALL(fsync)
{
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_sigreturn -
-----------------------------------------------------------------------------*/
CALL(rt_sigreturn)
{
    if (variants[0].callnumbackup == __NR_rt_sigsuspend
#ifdef __NR_sigsuspend
        || variants[0].callnumbackup == __NR_sigsuspend
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

POSTCALL(rt_sigreturn)
{
    // if we did not deliver during sigsuspend, we will actually see sigreturn return -1
    // return_from_sighandler will restore the original context and resume
    sig_return_from_sighandler();
    return MVEE_POSTCALL_DONTRESUME;
}

/*-----------------------------------------------------------------------------
  sys_clone - (unsigned long clone_flags, unsigned long newsp,
  void __user *parent_tid, void __user *variant_tid, struct pt_regs *regs)
-----------------------------------------------------------------------------*/
LOG_ARGS(clone)
{
	debugf("%s - SYS_CLONE(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   getTextualCloneFlags(ARG1(variantnum)).c_str());
}

PRECALL(clone)
{
    CHECKARG(1);

    // we weren't multithreaded yet but will be after this call!
    if (!is_program_multithreaded() && (ARG1(0) & CLONE_VM))
        enable_sync();

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_FORK;
}

POSTCALL(clone)
{
    int i, result;

    if (call_succeeded)
    {
        // I DARE YOU TO TRIGGER THIS DATA RACE
        if (ARG1(0) & CLONE_PARENT_SETTID)
        {
            debugf("setting TID of the newly created thread in the address space of the parent\n");
            for (int i = 1; i < mvee::numvariants; ++i)
				rw::write_primitive<int>(variants[i].variantpid, (void*)ARG3(i), 
											 (int)call_postcall_get_variant_result(0));
        }

        // update stack regions (if applicable)
        if (ARG2(0))
        {
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                mmap_region_info* stack_info = set_mmap_table->get_region_info(i, ARG2(i)-1, 0);
                int               tid        = call_postcall_get_variant_result(i);

                if (stack_info)
                {
                    std::stringstream ss;
                    ss << "[stack:" << tid << "]";

                    stack_info->region_backing_file_path = ss.str();
                    stack_info->region_map_flags         = MAP_PRIVATE | MAP_GROWSDOWN | MAP_STACK;
                }
            }
        }

        result = call_postcall_get_variant_result(0);
        for (i = 1; i < mvee::numvariants; ++i)
            call_postcall_set_variant_result(i, result);
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
LOG_ARGS(mprotect)
{
	debugf("%s - SYS_MPROTECT(0x" PTRSTR ", 0x" PTRSTR ", 0x%08X = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   getTextualProtectionFlags(ARG3(variantnum)).c_str());
}

PRECALL(mprotect)
{
    CHECKARG(2);
    CHECKARG(3);
    CHECKREGION(1, ARG2(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

LOG_RETURN(mprotect)
{
	debugf("%s - SYS_MPROTECT return: %d\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   call_postcall_get_variant_result(variantnum));
}

POSTCALL(mprotect)
{
	if IS_SYNCED_CALL
	{
		if (call_succeeded)
			for (int i = 0; i < mvee::numvariants; ++i)
				set_mmap_table->mprotect_range(i, ARG1(i), ARG2(i), ARG3(i));

		for (int i = 0; i < mvee::numvariants; ++i)
			set_mmap_table->verify_mman_table(i, variants[i].variantpid);

#ifdef MVEE_DUMP_JIT_CACHES
		if (ARG3(0) & PROT_EXEC)
		{
			mmap_region_info* region = set_mmap_table->get_region_info(0, ARG1(0), 0);
			
			if (region && (region->region_map_flags & MAP_ANONYMOUS))
			{
				std::vector<unsigned char*> raw_bytes(mvee::numvariants);
				std::vector<std::string> disas(mvee::numvariants);
				std::vector<std::map<unsigned long, unsigned long>> indirect_jmp_targets(mvee::numvariants);

				// Read raw JIT bytes
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					raw_bytes[i] = rw::read_data(variants[i].variantpid, (void*)ARG1(i), ARG2(i));

					if (!raw_bytes[i])
					{
						warnf("Couldn't read JIT cache in variant %d\n", i);
						break;
					}
				}

				// Preprocess disassembly to identify vmcall patterns (they use data in code and screw up the objdump disassembly)
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					HDE_INS(ins);
					int offset = 0;

					while (offset < ARG2(i))
					{
						HDE_DISAS(len, &raw_bytes[i][offset], &ins);

						if (len == 0)
						{
							warnf("disassembly failure while preprocessing JIT cache in variant %d\n", i);
							break;
						}

						// look for jmp QWORD PTR [rip + 0x2] 
						// This is a near jump (FF /4)
						if (ins.opcode == 0xFF &&
							ins.modrm == 0x25 &&
							ins.modrm_mod == 0 &&  // 00B
							ins.modrm_reg == 4 &&  // 100B - Selects jmp near
							ins.modrm_rm == 5 &&   // 101B - Selects RIP-relative addressing
							ins.disp.disp32 == 2)  // +2 - Selects RIP+2
						{
							indirect_jmp_targets[i].insert(std::make_pair(ARG1(i) + offset, *(unsigned long*)&raw_bytes[i][offset + len + 2]));

							// NOP out original bytes
							if (sizeof(unsigned long) == 8)
								*(unsigned long*)&raw_bytes[i][offset + len + 2] = 0x9090909090909090;
							else
								*(unsigned long*)&raw_bytes[i][offset + len + 2] = 0x90909090;
						}

						offset += len;
					}
				}

				// Disassemble raw JIT bytes
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					FILE* fp = tmpfile();

					if (!fp)
					{
						warnf("Couldn't dump JIT cache for variant %d - tmpfile failed: %s\n", i, getTextualErrno(errno));
						break;
					}

					// Don't dump trailing 0xed/0x00 bytes
					size_t dump_offset = 0;
/*					while (raw_bytes[i][dump_offset] == 0xed || 
						   raw_bytes[i][dump_offset] == 0x00)
						dump_offset++;
*/

					size_t dump_size = ARG2(i) - dump_offset;
					if (dump_size > 0)
					{
/*						while (raw_bytes[i][dump_offset + dump_size - 1] == 0xed || 
							   raw_bytes[i][dump_offset + dump_size - 1] == 0x00)
							dump_size--;
*/

						if (fwrite(raw_bytes[i] + dump_offset, 1, dump_size, fp) != dump_size)
						{
							warnf("Couldn't dump JIT cache for variant %d - fwrite failed: %s\n", i, getTextualErrno(errno));
							break;
						}

						std::stringstream cmd;
						std::stringstream file;

						file << " /proc/" << getpid() << "/fd/" << fileno(fp);
						cmd << "objdump -z -D -Mintel," << OBJDUMP_SUBARCH << " -b binary -m " << OBJDUMP_ARCH << ":" << OBJDUMP_SUBARCH << " --adjust-vma=0x" << STDPTRSTR(ARG1(i) + dump_offset) << file.str();
						debugf("Dumping: %s - size: %d\n", cmd.str().c_str(), dump_size);
						disas[i] = mvee::log_read_from_proc_pipe(cmd.str().c_str(), NULL);
					}

					fclose(fp);
				}

				// Annotate and dump disassembly
				for (int i = 0; i < mvee::numvariants; ++i)
				{
					debugf("JIT cache dump for variant %d - cache size is %d bytes (disassembled):\n", i, disas[i].length());

					std::stringstream ss;
					ss << disas[i];
					std::string line;

					while (std::getline(ss, line))
					{
						size_t call = line.find("call   0x");
						size_t vmcall = line.find("jmp    QWORD PTR [rip+0x2]");
						if (call != std::string::npos)
						{
							std::string addr = line.substr(call + strlen("call   0x"));
							std::stringstream hexstr;
							unsigned long real_addr;
							hexstr << std::hex << addr;
							hexstr >> real_addr;
							std::string func = set_mmap_table->get_caller_info(i, variants[i].variantpid, real_addr);

							debugf("%s (%s)\n", line.c_str(), func.c_str());
						}
						else if (vmcall != std::string::npos)
						{
							std::string addr = line.substr(0, line.find(":"));
							std::stringstream hexstr;
							unsigned long real_addr;
							hexstr << std::hex << addr;
							hexstr >> real_addr;

							auto target = indirect_jmp_targets[i].find(real_addr);
							if (target != indirect_jmp_targets[i].end())
							{
								std::string func = set_mmap_table->get_caller_info(i, variants[i].variantpid, target->second);
								debugf("%s (%s)\n", line.substr(0, line.find("#")).c_str(), func.c_str());
							}
						}
						else
						{
							debugf("%s\n", line.c_str());
						}
					}
				}

				// Cleanup
				for (int i = 0; i < mvee::numvariants; ++i)
					SAFEDELETEARRAY(raw_bytes[i]);
			}		
		}
#endif
	}
	else
	{
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
	}

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpgid
-----------------------------------------------------------------------------*/
PRECALL(getpgid)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_capget - (cap_user_header_t header, cap_user_data_t dataptr)
-----------------------------------------------------------------------------*/
PRECALL(capget)
{
    CHECKPOINTER(1);
    if (ARG1(0))
        CHECKBUFFER(1, sizeof(__user_cap_header_struct));
    CHECKPOINTER(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(capget)
{
    REPLICATEBUFFERFIXEDLEN(1, sizeof(__user_cap_header_struct));
	REPLICATEBUFFERFIXEDLEN(2, (sizeof(long) == 8 ? 2 : 1) * sizeof(__user_cap_data_struct));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fchdir - (unsigned int fd)
-----------------------------------------------------------------------------*/
PRECALL(fchdir)
{
    CHECKFD(1);
    MAPFDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(fchdir)
{
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
LOG_ARGS(_llseek)
{
	debugf("%s - SYS_LLSEEK(%d, %ld, %ld, 0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   ARG5(variantnum));
}

PRECALL(_llseek)
{
    CHECKPOINTER(4);
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(5);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(_llseek)
{
    REPLICATEBUFFERFIXEDLEN(4, sizeof(loff_t));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getdents - (unsigned int fd,
  struct linux_dirent __user * dirent, unsigned int count)
-----------------------------------------------------------------------------*/
PRECALL(getdents)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getdents)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys__newselect - (int n, fd_set __user *inp, fd_set __user *outp,
  fd_set __user *exp, struct timeval __user *tvp)
-----------------------------------------------------------------------------*/
LOG_ARGS(select)
{
	debugf("%s - SYS_SELECT(%d, 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   ARG5(variantnum));
}

PRECALL(select)
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

POSTCALL(select)
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
LOG_ARGS(msync)
{
	debugf("%s - SYS_MSYNC(0x" PTRSTR ", %d, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   getTextualMSyncFlags(ARG3(variantnum)).c_str());
}

PRECALL(msync)
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
        debugf("variant is requesting an MS_INVALIDATE - private mapping: %d\n", private_mapping);

    if ((ARG3(0) & MS_SYNC) || (ARG3(0) & MS_ASYNC))
        debugf("variant is requesting an MS_[A]SYNC - private mapping: %d\n", private_mapping);

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
PRECALL(readv)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKVECTORLAYOUT(2, ARG3(0));

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(readv)
{
    REPLICATEVECTOR(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_writev - (unsigned long  fd, const struct iovec  *  vec,
  unsigned long  vlen)
-----------------------------------------------------------------------------*/
LOG_ARGS(writev)
{
	debugf("%s - SYS_WRITEV(%d, 0x" PTRSTR ", %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum));

	struct iovec* vec = new(std::nothrow) struct iovec[ARG3(variantnum)];

	if (!vec || 
		!rw::read_struct(variants[variantnum].variantpid, (void*) ARG2(variantnum), sizeof(struct iovec) * ARG3(variantnum), vec))
	{
		warnf("couldn't read iovec\n");
		SAFEDELETEARRAY(vec);
		return;
	}

	auto str = call_serialize_io_vector(variantnum, vec, ARG3(variantnum));
	debugf("    => \n%s\n", str.c_str());
	SAFEDELETEARRAY(vec);
}

PRECALL(writev)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKVECTOR(2, ARG3(0));

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fdatasync - (unsigned int fd)
-----------------------------------------------------------------------------*/
PRECALL(fdatasync)
{
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_sched_yield
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(sched_yield)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_nanosleep - (const struct timespec* req, struct timespec* rem)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(nanosleep)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_mremap - unsigned long, addr, unsigned long, old_len,
  unsigned long, new_len, unsigned long, flags,
  unsigned long, new_addr
-----------------------------------------------------------------------------*/
LOG_ARGS(mremap)
{
	debugf("%s - SYS_MREMAP(0x" PTRSTR ", %d, %d, 0x" PTRSTR ", 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(mremap)
{
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKREGION(1, ARG2(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(mremap)
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
                mmap_region_info* new_region = new(std::nothrow) mmap_region_info(*info);

				if (new_region)
				{
					new_region->region_base_address = new_addresses[i];
					new_region->region_size         = ARG3(i);
					
					set_mmap_table->munmap_range(i, ARG1(i),          ARG2(i));
					set_mmap_table->munmap_range(i, new_addresses[i], ARG3(i));

					//warnf("remapped - variant %d - from: 0x" PTRSTR "-0x" PTRSTR " - to: 0x" PTRSTR "-0x" PTRSTR "\n",
					//        i, ARG1(i), ARG1(i) + ARG2(i), new_addresses[i], ARG3(i) + new_addresses[i]);
					set_mmap_table->insert_region(i, new_region);
				}
            }
            else
            {
                warnf("remap range not found: 0x" PTRSTR "-0x" PTRSTR "\n",
                            ARG1(i), ARG1(i) + ARG2(i));
                shutdown(false);
            }

            set_mmap_table->verify_mman_table(i, variants[i].variantpid);
        }
    }

    return 0;
}

LOG_RETURN(mremap)
{
	debugf("%s - SYS_MREMAP return: 0x" PTRSTR "\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   call_postcall_get_variant_result(variantnum));

#ifdef MVEE_MMAN_DEBUG
    set_mmap_table->print_mmap_table();
#endif
}

/*-----------------------------------------------------------------------------
  sys_poll - (struct pollfd __user *ufds, unsigned int nfds, long timeout)
-----------------------------------------------------------------------------*/
LOG_ARGS(poll)
{
	debugf("%s - SYS_POLL(0x" PTRSTR ", %d, %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

PRECALL(poll)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKARG(3);
    CHECKBUFFER(1, sizeof(struct pollfd) * ARG2(0));
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(poll)
{
	long result  = call_postcall_get_variant_result(variantnum);

	debugf("%s - SYS_POLL return: %d\n", call_get_variant_pidstr(variantnum).c_str(), result);

	for (unsigned int j = 0; j < result; ++j)
	{
		struct pollfd fds;
		if (!rw::read<struct pollfd>(variants[variantnum].variantpid, (struct pollfd*)ARG1(variantnum) + j, fds))
		{
			warnf("couldn't read pollfd\n");
			return;
		}
			
		debugf("> fd: %d - events: %s - revents: %s\n",
			   fds.fd,
			   getTextualPollRequest(fds.events).c_str(),
			   getTextualPollRequest(fds.revents).c_str());
	}
}

POSTCALL(poll)
{
//    long result = call_postcall_get_variant_result(0);
    REPLICATEBUFFERFIXEDLEN(1, sizeof(struct pollfd) * ARG2(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_prctl - (int option, unsigned long arg2, unsigned long arg3,
  unsigned long arg4, unsigned long arg5)
-----------------------------------------------------------------------------*/
PRECALL(prctl)
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

unsigned char ipmon_is_unchecked_syscall(unsigned char* mask, unsigned long syscall_no)
{
    unsigned long no_to_byte, bit_in_byte;

    if (syscall_no > ROUND_UP(MAX_CALLS, 8))
		return 0;

    no_to_byte  = syscall_no / 8;
    bit_in_byte = syscall_no % 8;

    if (mask[no_to_byte] & (1 << (7 - bit_in_byte)))
		return 1;
    return 0;
}


CALL(prctl)
{
    // check if the variants are trying to re-enable rdtsc
    if (ARG1(0) == PR_SET_TSC && ARG2(0) == PR_TSC_ENABLE)
    {
        cache_mismatch_info("The program is trying to enable directly reading the time stamp counter. This call has been denied.\n");
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
    }
	else if (ARG1(0) == PR_REGISTER_IPMON)
	{
		// inspect the list of syscalls
		unsigned char* ipmon_mask = rw::read_data(variants[0].variantpid, (void*) ARG2(0), ARG3(0));

		if (ipmon_mask)
		{
			if (ipmon_is_unchecked_syscall(ipmon_mask, __NR_mmap))
				ipmon_mmap_handling = true;
			if (ipmon_is_unchecked_syscall(ipmon_mask, __NR_open))
				ipmon_fd_handling = true;
			
			debugf("IP-MON handling mmap: %d - fd: %d\n", ipmon_mmap_handling, ipmon_fd_handling);

			delete[] ipmon_mask;
		}
	}
	else if (ARG1(0) == PR_SET_SECCOMP && ARG2(0) == SECCOMP_MODE_FILTER)
	{
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EINVAL);
	}
    return MVEE_CALL_ALLOW;
}

POSTCALL(prctl)
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
			unsigned long ip;

			if (!interaction::fetch_ip(variants[i].variantpid, ip))
			{
				warnf("%s - Couldn't read instruction pointer\n", 
					  call_get_variant_pidstr(i).c_str());
				return 0;
			}
			variants[i].ipmon_region = set_mmap_table->get_region_info(i, ip, 0);
			debugf("Initializing IP-MON - IP: 0x" PTRSTR "\n", ip);
			if (variants[i].ipmon_region)
				variants[i].ipmon_region->print_region_info("> IP-MON REGION: ");
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
LOG_ARGS(rt_sigprocmask)
{
	debugf("%s - SYS_RT_SIGPROCMASK(%s, 0x" PTRSTR " - %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   getTextualSigHow(ARG1(variantnum)), ARG2(variantnum), 
		   getTextualSigSet(call_get_sigset(variantnum, (void*) ARG2(variantnum), OLDCALLIFNOT(__NR_rt_sigprocmask))).c_str());
}

PRECALL(rt_sigprocmask)
{
    CHECKARG(1);
    CHECKPOINTER(2);
    CHECKSIGSET(2, OLDCALLIFNOT(__NR_rt_sigprocmask));
    CHECKPOINTER(3);    
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(rt_sigprocmask)
{
	if IS_SYNCED_CALL
		variantnum = 0;

	variants[variantnum].last_sigset = call_get_sigset(variantnum, (void*) ARG2(variantnum), OLDCALLIFNOT(__NR_rt_sigprocmask));
	return MVEE_CALL_ALLOW;
}

POSTCALL(rt_sigprocmask)
{
	if IS_SYNCED_CALL
		variantnum = 0;

    if (call_succeeded && ARG2(variantnum))
    {
        sigset_t _set = variants[variantnum].last_sigset;

        switch (ARG1(variantnum))
        {
            case SIG_BLOCK:
            {
                for (int i = 1; i < SIGRTMAX+1; ++i)
                    if (sigismember(&_set, i))
                        sigaddset(&blocked_signals[variantnum], i);
                break;
            }
            case SIG_UNBLOCK:
            {
                for (int i = 1; i < SIGRTMAX+1; ++i)
                {
                    if (sigismember(&_set, i))
                        sigdelset(&blocked_signals[variantnum], i);
                }
                break;
            }
            case SIG_SETMASK:
            {
                sigemptyset(&blocked_signals[variantnum]);
                for (int i = 1; i < SIGRTMAX+1; ++i)
                    if (sigismember(&_set, i))
                        sigaddset(&blocked_signals[variantnum], i);
                break;
            }
        }
    }

    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_pread64 - (unsigned int fd, char __user *buf, size_t count, loff_t pos)
-----------------------------------------------------------------------------*/
LOG_ARGS(pread64)
{
	debugf("%s - SYS_PREAD64(%d, 0x" PTRSTR ", %d, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(pread64)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(pread64)
{
	long result  = call_postcall_get_variant_result(variantnum);
	auto result_str = call_serialize_io_buffer(variantnum, (const unsigned char*) ARG2(variantnum), result);
	
	debugf("%s - SYS_PREAD64 RETURN: %d => %s\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   result, 
		   result_str.c_str());
}

POSTCALL(pread64)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pwrite64 - (unsigned int fd, const char __user *buf,
  size_t count, loff_t pos)
-----------------------------------------------------------------------------*/
LOG_ARGS(pwrite64)
{
	auto buf_str = call_serialize_io_buffer(variantnum, (const unsigned char*) ARG2(variantnum), ARG3(variantnum));

	debugf("%s - SYS_PWRITE64(%d, %s, %d, %d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   buf_str.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(pwrite64)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKBUFFER(2, ARG3(0));

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_chown - (const char  *  filename, uid_t  user, gid_t  group)
-----------------------------------------------------------------------------*/
LOG_ARGS(chown)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto user = getTextualUserId(ARG2(variantnum));
	auto group = getTextualGroupId(ARG3(variantnum));

	debugf("%s - SYS_CHOWN(%s, %ld - %s, %ld - %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum), user.c_str(),
		   ARG3(variantnum), group.c_str());
}

PRECALL(chown)
{
    CHECKPOINTER(1);
    CHECKARG(3);
    CHECKARG(2);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fchown - (int fd, uid_t user, gid_t group)
-----------------------------------------------------------------------------*/
PRECALL(fchown)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKARG(3);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getcwd - (char* buf, int buflen)
-----------------------------------------------------------------------------*/
PRECALL(getcwd)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

/*-----------------------------------------------------------------------------
  sys_getrlimit - (unsigned int  resource, struct rlimit  *  rlim)
-----------------------------------------------------------------------------*/
PRECALL(ugetrlimit)
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
LOG_ARGS(mmap)
{
	debugf("%s - SYS_MMAP(0x" PTRSTR ", %lu, %s, %s, %d, %lu)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum),
		   getTextualProtectionFlags(ARG3(variantnum)).c_str(),
		   getTextualMapType(ARG4(variantnum)).c_str(), 
		   (int)ARG5(variantnum), 
		   ARG6(variantnum));
}

#ifdef MVEE_ENABLE_VALGRIND_HACKS
static int first_mmap2_call = 1;
#endif

PRECALL(mmap)
{
#ifdef MVEE_ENABLE_VALGRIND_HACKS
    if (first_mmap2_call)
    {
        first_mmap2_call = 0;
        for (int i = 0; i < mvee::numvariants; ++i)
			set_mmap_table->refresh_variant_maps(i, variants[i].variantpid);
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

CALL(mmap)
{
	if IS_UNSYNCED_CALL
		return MVEE_CALL_ALLOW;

    for (int i = 0; i < mvee::numvariants; ++i)
        variants[i].last_mmap_result = 0;

    // anonymous shared mapping maps /dev/zero into our address space.
    // this mapping is only shared between the calling process and its decendants
    // => this is a safe form of shared memory
    if (ARG4(0) & MAP_ANONYMOUS)
        return MVEE_CALL_ALLOW;

    // non-anonymous ==> it must have a backing file
    if (ARG5(0) && (int)ARG5(0) != -1)
    {
        fd_info* info = set_fd_table->get_fd_info(ARG5(0));

		// Handle firefox shm corner case here.  FF has threads that create
		// temporary shm backing files.  These files are created, unlinked,
		// dupped, mmaped, and then closed (both the original and the dupped
		// version).  At some point, a copy of the file pops up in the fd table.
		// I don't know precisely why, but I'm assuming it happens when the file
		// is written to for the first time.  Unfortunately, we currently have
		// no way to see when/where this fd gets created.  As a temporary
		// workaround, we can resynchronize the MVEE fd table with the fd table
		// in /proc/pid/fd here.
		//
		// A better workaround would probably be to install an inotify_watch
		// on the /proc/pid/fd folders for all of our variants.
		if (!info && !ipmon_fd_handling)
		{
			if (!set_fd_table->add_missing_fds(getpids()))
				shutdown(false);
			info = set_fd_table->get_fd_info(ARG5(0));
		}

        if (!info)
        {		
			if (ipmon_fd_handling)
				return MVEE_CALL_ALLOW;

            warnf("mmap2 request with an unknown backing file!!!\n");

#ifndef MVEE_BENCHMARK
			set_fd_table->print_fd_table_proc(variants[0].variantpid);
			log_variant_backtrace(0);
#endif

#ifndef MVEE_ALLOW_SHM
            return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
#else
			return MVEE_CALL_ALLOW;
#endif
        }

        if ((info->access_flags & O_RDWR) && (ARG4(0) & MAP_SHARED))
        {
			if (!info->unlinked)
			{
				warnf("variants are opening a shared memory mapping backed by an O_RDWR file!!!\n");
				warnf("> file = %s\n",           info->path.c_str());
				warnf("> map prot flags = %s\n", getTextualProtectionFlags(ARG3(0)).c_str());
			}

#ifndef MVEE_ALLOW_SHM
            if ((ARG3(0) & PROT_WRITE) || (ARG3(0) & PROT_EXEC))
            {
                if (!info->unlinked)
                {
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
				else
				{
					// check if any process outside the MVEE has this region mapped into their address space
					std::stringstream ultimate_grep_command_of_doom;
					ultimate_grep_command_of_doom << "grep \"" << info->path << " (deleted)$\" $(find /proc/ 2>&1 | grep \"/maps\" | grep -v \"/task/\") 2>&1 | grep \"^/proc\" | cut -d'/' -f3";
					std::string output = mvee::log_read_from_proc_pipe(ultimate_grep_command_of_doom.str().c_str(), NULL);

					std::stringstream lines;
					lines << output;

					while (std::getline(lines, output, '\n'))
					{
						pid_t pid;
						std::stringstream tmp;
						tmp << output;
						tmp >> pid;

						if (!mvee::is_monitored_variant(pid))
						{
							warnf("MAP_SHARED mapping request of unlinked file denied.");
							warnf("> file: %s\n", info->path.c_str()); 
							warnf("> reason: also mapped into the address space of non-monitored process %d\n", pid);
							return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
						}
					}

					return MVEE_CALL_ALLOW;
				}

                warnf("MAP_SHARED mapping request with PROT_WRITE detected!\n");
                warnf("This call has been denied.\n");
                return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
            }
        }
        else if ((ARG3(0) & PROT_EXEC))
        {
            if ((*mvee::config_variant_global)["non_overlapping_mmaps"].asInt())
            {
                if (ARG4(0) & MAP_FIXED)
                {
                    warnf("GHUMVEE is running with non_overlapping_mmaps enabled but the following binary is not position independent: %s\n", info->path.c_str());
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
                           warnf("> variant %d => region span: 0x" PTRSTR "-0x" PTRSTR "\n",
                           i, bases[i], ROUND_UP(bases[i] + ARG2(0), 4096));
                         */
                        SETARG1(i, bases[i]);
                    }
                }
            }
#endif
        }
    }

    return MVEE_CALL_ALLOW;
}

POSTCALL(mmap)
{
	if (!call_succeeded)
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;

#ifdef MVEE_FD_DEBUG
	set_fd_table->verify_fd_table(getpids());
#endif

	if IS_SYNCED_CALL
	{
		fd_info*                   info      = NULL;
		int                        free_info = 0;
		std::vector<unsigned long> results   = call_postcall_get_result_vector();

		for (int i = 0; i < mvee::numvariants; ++i)
			variants[i].last_mmap_result = results[i];

		if (ARG5(0) && (int)ARG5(0) != -1)
		{
			info = set_fd_table->get_fd_info(ARG5(0));
			if (!info)
			{
				warnf("mmap2 request with backing file but backing file info not found!\n");
#ifdef MVEE_ALLOW_SHM
				return 0;
#endif
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
			if (variants[0].prevcallnum == __NR_mmap2)
				actual_offset *= 4096;
#endif
			set_mmap_table->map_range(i, results[i], ARG2(0), ARG4(0), ARG3(0), info, actual_offset);
		}

		//
		// Check if this is an aligned mmap request
        //
		// If we want to map a block of x bytes, aligned to a y-byte boundary,
		// and we cannot use MAP_ALIGN, then we extend the allocation size by y
		// to ensure that the heap crosses an alignment boundary.
		//
		// We then unmap the lower region and the upper region.  The lower
		// region is the part below the alignment boundary.  Since the OS MIGHT
		// give us a y-aligned block, there might not be a lower region.  The
		// upper region is the excess memory we still have after unmapping the
		// lower region.
		//
		if (ARG1(0) == 0                                                // no base address
			&& last_mmap_requested_alignment                            // syscall(MVEE_ALL_HEAPS_ALIGNED) must have been called prior to this mmap
			&& (ARG4(0) & (MAP_PRIVATE | MAP_ANONYMOUS))                // must be a private anonymous mapping
			&& (int)ARG5(0) == -1                                       // backed by /dev/zero
			&& !ipmon_mmap_handling)
		{
			in_new_heap_allocation = true;

			// bump the lock counter for the fd/mman locks - we'll unlock when we see the munmap of the upper region
			call_grab_locks(MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN);

			unsigned long requested_alignment = last_mmap_requested_alignment;
			unsigned long requested_size      = last_mmap_requested_size;

			last_mmap_requested_alignment =
				last_mmap_requested_size = 0;			

			// ptmalloc allocates <requested alloc size> + <requested alignment> bytes
			// jemalloc allocates <requested alloc size> + <requested alignment> - <page size> bytes

			// We can now calculate the lower and upper region bounds
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				unsigned long start_of_aligned_heap = (results[i] + (requested_alignment - 1)) & ~(requested_alignment - 1);
				variants[i].last_lower_region_start = results[i];
				variants[i].last_lower_region_size  = start_of_aligned_heap - results[i];
				variants[i].last_upper_region_start = start_of_aligned_heap + requested_size;
				variants[i].last_upper_region_size  = results[i] + ARG2(i) - (start_of_aligned_heap + requested_size);

				std::stringstream ss;

				if (variants[i].last_lower_region_size)
				{
					ss << "LOWER REGION [0x" << STDPTRSTR(variants[i].last_lower_region_start)
					   << "-0x" << STDPTRSTR(variants[i].last_lower_region_start + variants[i].last_lower_region_size)
					   << "]";
				}
				else
				{
					variants[i].last_lower_region_start = 0;
				}
				if (variants[i].last_upper_region_size)
				{
					if (ss.str().length() > 0)
						ss << " - ";
					
					ss << "UPPER REGION [0x" << STDPTRSTR(variants[i].last_upper_region_start)
					   << "-0x" << STDPTRSTR(variants[i].last_upper_region_start + variants[i].last_upper_region_size)
					   << "]";
				}
				else
				{
					variants[i].last_upper_region_start = 0;
				}
				debugf("Variant %d expected sys_munmaps: %s\n", i, ss.str().c_str());
			}
		}

		if (free_info)
			SAFEDELETE(info);

		for (int i = 0; i < mvee::numvariants; ++i)
			set_mmap_table->verify_mman_table(i, variants[i].variantpid);
	}
	else
	{
		fd_info*      info      = NULL;
		unsigned long result = call_postcall_get_variant_result(variantnum);

		if (ARG5(variantnum) && (int)ARG5(variantnum) != -1)
		{
			info = set_fd_table->get_fd_info(ARG5(variantnum), variantnum);
			if (!info)
			{
				warnf("mmap2 request with backing file but backing file info not found!\n");
				shutdown(false);
				return 0;
			}
		}

		unsigned int actual_offset = ARG6(variantnum);
#ifdef __NR_mmap2
		if (variants[variantnum].prevcallnum == __NR_mmap2)
			actual_offset *= 4096;
#endif
		set_mmap_table->map_range(variantnum, result, ARG2(variantnum), ARG4(variantnum), ARG3(variantnum), info, actual_offset);
		set_mmap_table->verify_mman_table(variantnum, variants[variantnum].variantpid);

		// Check if we mapped the main binary
		/*if (info &&
			variants[variantnum].fast_forward_to_entry_point &&
			!variants[variantnum].entry_point_bp_set)
		{
			std::string& program_image = (set_mmap_table->mmap_startup_info[variantnum].real_image.length() > 0) ? 
				set_mmap_table->mmap_startup_info[variantnum].real_image :
				set_mmap_table->mmap_startup_info[variantnum].image;

//			warnf("Mapping %s\n", info->path.c_str());

			if ((ARG3(variantnum) & PROT_EXEC) &&
				info->path.compare(program_image) == 0)
			{
				// see if we can get a handle to the executable region that
				// contains the entry point
				unsigned long region_base = set_mmap_table->find_image_base(variantnum, info->path);

				if (region_base)
				{
					mmap_region_info* region_info = 
						set_mmap_table->get_region_info(variantnum, 
														region_base + variants[variantnum].entry_point_address);

					// Set hardware breakpoint on the entry point
					if (region_info)
					{
						// Update the address so it becomes an EFFECTIVE (rather
						// than RELATIVE) address
						variants[variantnum].entry_point_address = 
							region_base + variants[variantnum].entry_point_address;
						hwbp_set_watch(variantnum, variants[variantnum].entry_point_address, MVEE_BP_EXEC_ONLY);
						variants[variantnum].entry_point_bp_set = true;

						warnf("The region containing the main program entry point has been mapped in variant %d - Set hardware breakpoint!\n", variantnum);
					}
				}
			}
			}*/

		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
	}

    return 0;
}

LOG_RETURN(mmap)
{
	debugf("%s - SYS_MMAP2 return: 0x" PTRSTR "\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   call_postcall_get_variant_result(variantnum));

#ifdef MVEE_MMAN_DEBUG
    set_mmap_table->print_mmap_table();
#endif
}

/*-----------------------------------------------------------------------------
  sys_truncate64 - (const char __user * path, loff_t length)
-----------------------------------------------------------------------------*/
LOG_ARGS(truncate64)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_TRUNCATE64(%s, %ld)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum));
}

PRECALL(truncate64)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_ftruncate64 - (unsigned int fd, loff_t length)
-----------------------------------------------------------------------------*/
PRECALL(ftruncate64)
{
    CHECKARG(2);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_stat64 - (char __user *filename, struct stat64 __user *statbuf);
-----------------------------------------------------------------------------*/
LOG_ARGS(stat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));

	debugf("%s - SYS_STAT(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str());
}

PRECALL(stat)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(stat)
{
	if IS_SYNCED_CALL
		REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat));
    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

LOG_ARGS(stat64)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));
	
	debugf("%s - SYS_STAT64(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str());
}

PRECALL(stat64)
{
    CHECKSTRING(1);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(stat64)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_lstat64 - (char __user *filename, struct stat64 __user *statbuf);
-----------------------------------------------------------------------------*/
LOG_ARGS(lstat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));

	debugf("%s - SYS_LSTAT(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str());
}

PRECALL(lstat)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(lstat)
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

LOG_ARGS(lstat64)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));

	debugf("%s - SYS_LSTAT64(%s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str());
}

PRECALL(lstat64)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(lstat64)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fstat - (unsigned long fd, struct stat64 * statbuf)
-----------------------------------------------------------------------------*/
LOG_ARGS(fstat)
{
	debugf("%s - SYS_FSTAT(%d, 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(fstat)
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

LOG_RETURN(fstat)
{
	struct stat sb;
	if (!rw::read<struct stat>(variants[variantnum].variantpid, (void*) ARG2(variantnum), sb))
	{
		warnf("Couldn't read stat\n");
		return;
	}

	debugf("%s - SYS_FSTAT64 return\n", 
		   call_get_variant_pidstr(variantnum).c_str());

	switch (sb.st_mode & S_IFMT) {
		case S_IFBLK:  debugf("File type:                block device\n");            break;
		case S_IFCHR:  debugf("File type:                character device\n");        break;
		case S_IFDIR:  debugf("File type:                directory\n");               break;
		case S_IFIFO:  debugf("File type:                FIFO/pipe\n");               break;
		case S_IFLNK:  debugf("File type:                symlink\n");                 break;
		case S_IFREG:  debugf("File type:                regular file\n");            break;
		case S_IFSOCK: debugf("File type:                socket\n");                  break;
		default:       debugf("File type:                unknown?\n");                break;
	}

	debugf("I-node number:            %ld\n", (long) sb.st_ino);

	debugf("Mode:                     %lo (octal)\n",
		   (unsigned long) sb.st_mode);

	debugf("Link count:               %ld\n", (long) sb.st_nlink);
	debugf("Ownership:                UID=%ld   GID=%ld\n",
		   (long) sb.st_uid,
		   (long) sb.st_gid);

	debugf("Preferred I/O block size: %ld bytes\n",
		   (long) sb.st_blksize);
	debugf("File size:                %lld bytes\n",
		   (long long) sb.st_size);
	debugf("Blocks allocated:         %lld\n",
		   (long long) sb.st_blocks);

	debugf("Last status change:       %s", ctime(&sb.st_ctime));
	debugf("Last file access:         %s", ctime(&sb.st_atime));
	debugf("Last file modification:   %s", ctime(&sb.st_mtime));
}

POSTCALL(fstat)
{
	if IS_SYNCED_CALL
	{
		REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat));
	}
	else
	{
		return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
	}
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fstat64 - (unsigned long fd, struct stat64 * statbuf)
-----------------------------------------------------------------------------*/
LOG_ARGS(fstat64)
{
	debugf("%s - SYS_FSTAT64(%d, 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum));
}

PRECALL(fstat64)
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

LOG_RETURN(fstat64)
{
	struct stat64 sb;
	if (!rw::read<struct stat64>(variants[variantnum].variantpid, (void*) ARG2(variantnum), sb))
	{
		warnf("Couldn't read stat64\n");
		return;
	}
	debugf("%s - SYS_FSTAT64 return\n", 
		   call_get_variant_pidstr(variantnum).c_str());

	switch (sb.st_mode & S_IFMT) {
		case S_IFBLK:  debugf("File type:                block device\n");            break;
		case S_IFCHR:  debugf("File type:                character device\n");        break;
		case S_IFDIR:  debugf("File type:                directory\n");               break;
		case S_IFIFO:  debugf("File type:                FIFO/pipe\n");               break;
		case S_IFLNK:  debugf("File type:                symlink\n");                 break;
		case S_IFREG:  debugf("File type:                regular file\n");            break;
		case S_IFSOCK: debugf("File type:                socket\n");                  break;
		default:       debugf("File type:                unknown?\n");                break;
	}

	debugf("I-node number:            %ld\n", (long) sb.st_ino);

	debugf("Mode:                     %lo (octal)\n",
		   (unsigned long) sb.st_mode);

	debugf("Link count:               %ld\n", (long) sb.st_nlink);
	debugf("Ownership:                UID=%ld   GID=%ld\n",
		   (long) sb.st_uid,
		   (long) sb.st_gid);

	debugf("Preferred I/O block size: %ld bytes\n",
		   (long) sb.st_blksize);
	debugf("File size:                %lld bytes\n",
		   (long long) sb.st_size);
	debugf("Blocks allocated:         %lld\n",
		   (long long) sb.st_blocks);

	debugf("Last status change:       %s", ctime(&sb.st_ctime));
	debugf("Last file access:         %s", ctime(&sb.st_atime));
	debugf("Last file modification:   %s", ctime(&sb.st_mtime));
}

POSTCALL(fstat64)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_madvise - (void* addr, size_t length, int advice)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(madvise)
{
    return MVEE_CALL_TYPE_UNSYNCED;
}

/*-----------------------------------------------------------------------------
  sys_shmget - (key_t key, size_t size, int shmflg)
-----------------------------------------------------------------------------*/
CALL(shmget)
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
PRECALL(getdents64)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getdents64)
{
    REPLICATEBUFFER(2);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_gettid - We use this as a secret MVEE debugging interface :)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(gettid)
{
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
	// Check if the variant passed the magic values
	if (!(ARG1(variantnum) == 1337 && ARG2(variantnum) == 10000001))
		return MVEE_CALL_TYPE_NORMAL;

	// The variant is trying to log something into the MVEE log.
	// Depending on the message type (ARG3), this might or might
	// not happen in lockstep.
    if (ARG3(variantnum) == 91 ||
		ARG3(variantnum) == 92 ||
		ARG3(variantnum) == 94 ||
		ARG3(variantnum) == 95 ||
		ARG3(variantnum) == 97)
        return MVEE_CALL_TYPE_NORMAL; // need lockstep

	// No lockstep needed
    return MVEE_CALL_TYPE_UNSYNCED;
#endif
    return MVEE_CALL_TYPE_NORMAL;
}

LOG_ARGS(gettid)
{
	if (ARG1(variantnum) == 1337 && ARG2(variantnum) == 10000001)
	{
		if (ARG3(variantnum) == 74)
		{
			struct mvee_malloc_error err;
			if (rw::read<struct mvee_malloc_error>(variants[variantnum].variantpid, (void*) ARG4(variantnum), err))
			{
				warnf("[PID:%05d] - [MALLOC_MISMATCH - MASTER INFO] - [FUNC: %s] - [MSG: %d (%s)] - [CHUNKSIZE: %ld] - [ARENA PTR: 0x" PTRSTR "] - [CHUNK PTR: 0x" PTRSTR "]\n",
					  variants[variantnum].variantpid,
					  getTextualAllocType(err.alloc_type),
					  err.msg,
					  getTextualAllocResult(err.alloc_type, err.msg),
					  err.chunksize,
					  err.ar_ptr,
					  err.chunk_ptr
					);
			}
		}
		else if (ARG3(variantnum) == 75)
		{
			struct mvee_malloc_error err;
			if (rw::read<struct mvee_malloc_error>(variants[variantnum].variantpid, (void*) ARG4(variantnum), err))
			{
				warnf("[PID:%05d] - [MALLOC_MISMATCH - SLAVE INFO] - [FUNC: %s] - [MSG: %d (%s)] - [CHUNKSIZE: %ld] - [ARENA PTR: 0x" PTRSTR "] - [CHUNK PTR: 0x" PTRSTR "]\n",
					  variants[variantnum].variantpid,
					  getTextualAllocType(err.alloc_type),
					  err.msg,
					  getTextualAllocResult(err.alloc_type, err.msg),
					  err.chunksize,
					  err.ar_ptr,
					  err.chunk_ptr
					);
			}
			shutdown(false);
		}
		else if (ARG3(variantnum) == 76)
		{
			warnf("[PID:%05d] - [INTERPOSER_DATA_SIZE_MISMATCH] - [POS:%d] - [SLOT_SIZE:%d] - [DATA_SIZE:%d]\n",
				  variants[variantnum].variantpid, ARG4(variantnum), ARG5(variantnum), ARG6(variantnum));
			shutdown(false);
		}
	}
	else
	{
		debugf("%s - SYS_GETTID()\n",
			   call_get_variant_pidstr(variantnum).c_str());
	}
}

PRECALL(gettid)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

CALL(gettid)
{
#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
    if (IS_UNSYNCED_CALL && ARG1(variantnum) == 1337 && ARG2(variantnum) == 10000001)
    {
		if (ARG3(variantnum) == 71)
			log_variant_backtrace(variantnum);
		
        int i = variantnum;
		if (ARG3(i) == 10)
		{
			warnf("[PID:%05d] - [LIBC_LOCK_BUFFER_ATTACHED:0x" PTRSTR "]\n",
				  variants[i].variantpid, ARG4(i));
		}
		if (ARG3(i) == 59)
		{
			warnf("[PID:%05d] - [INVALID_LOCK_TYPE=>READ:%d (%s) - EXPECTED:%d (%s)]\n",
				  variants[i].variantpid, ARG4(i), getTextualAtomicType(ARG4(i)),
				  ARG5(i), getTextualAtomicType(ARG5(i)));
			shutdown(false);
		}
		else if (ARG3(i) == 60)
		{
			warnf("[PID:%05d] - [INVALID_LOCK_TYPE] - [SLOT_SIZE:%d] - TMPPOS:%d\n",
				  variants[i].variantpid, ARG4(i), ARG5(i));
		}
		else if (ARG3(i) == 61)
		{
			warnf("[PID:%05d] - [INVALID_LOCK_PTR] - [SLAVE_PTR:0x" PTRSTR "] - TMPPOS:%d\n",
				  variants[i].variantpid, ARG4(i), ARG5(i));
			shutdown(false);
			
		}
		else if (ARG3(i) == 90)
		{
			std::string master_callee = set_mmap_table->get_caller_info(0, variants[0].variantpid, ARG5(i));
			std::string actual_callee = set_mmap_table->get_caller_info(i, variants[i].variantpid, ARG6(i));

			warnf("[PID:%05d] - [INVALID_LOCK_CALLEE] - [LOCK_TYPE:%d (%s)] - [MASTER CALLEE:%s] - [ACTUAL CALLEE:%s]\n",
				  variants[i].variantpid, ARG4(i), getTextualAtomicType(ARG4(i)),
				  master_callee.c_str(), actual_callee.c_str());

			shutdown(false);
		}

		return MVEE_CALL_ALLOW;
    }
#endif

#ifdef MVEE_ENABLE_VALGRIND_HACKS
	return MVEE_CALL_ALLOW;
#endif

    return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(variants[0].variantpid);
}

/*-----------------------------------------------------------------------------
  sys_readahead - (int fd, loff_t offset, size_t sz)
-----------------------------------------------------------------------------*/
PRECALL(readahead)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKARG(3);
    MAPFDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(readahead)
{
    long result = call_postcall_get_variant_result(0);
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_variant_result(i, result);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_setxattr - (const char __user * pathname,
  const char __user * name, void __user * value, size_t size, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(setxattr)
{
	auto path  = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));
	auto name  = rw::read_string(variants[variantnum].variantpid, (void*) ARG2(variantnum));

	debugf("%s - SYS_SETXATTR(%s, %s, %d, 0x" PTRSTR ", %d, %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   path.c_str(), 
		   name.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   getTextualXattrFlags(ARG5(variantnum)));
}

PRECALL(setxattr)
{
    CHECKPOINTER(1);
    CHECKPOINTER(2);
    CHECKSTRING(1);
    CHECKSTRING(2);
    CHECKARG(4);
    CHECKPOINTER(3);
    CHECKBUFFER(3, ARG4(0));
    CHECKARG(5);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fsetxattr - (int fd,
  const char __user * name, void __user * value, size_t size, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(fsetxattr)
{
	auto name  = rw::read_string(variants[variantnum].variantpid, (void*) ARG2(variantnum));

	debugf("%s - SYS_FSETXATTR(%d, %s, %d, 0x" PTRSTR ", %d, %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   name.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   getTextualXattrFlags(ARG5(variantnum)));
}

PRECALL(fsetxattr)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKARG(4);
    CHECKPOINTER(3);
    CHECKBUFFER(3, ARG4(0));
    CHECKARG(5);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_getxattr - (const char __user *, pathname,
  const char __user *, name, void __user *, value, size_t, size)
-----------------------------------------------------------------------------*/
LOG_ARGS(getxattr)
{
	auto path = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));
	auto name = rw::read_string(variants[variantnum].variantpid, (void*) ARG2(variantnum));

	debugf("%s - SYS_GETXATTR(%s, %s, %d, 0x" PTRSTR ", %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   path.c_str(), 
		   name.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(getxattr)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKPOINTER(3);
    CHECKARG(4);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(getxattr)
{
    REPLICATEBUFFERFIXEDLEN(3, call_postcall_get_variant_result(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fgetxattr - (int fd,
  const char __user * name, void __user * value, size_t size)
-----------------------------------------------------------------------------*/
LOG_ARGS(fgetxattr)
{
	auto name = rw::read_string(variants[variantnum].variantpid, (void*) ARG2(variantnum));

	debugf("%s - SYS_FGETXATTR(%d, %s, %d, 0x" PTRSTR ", %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   name.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(fgetxattr)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKPOINTER(3);
    CHECKARG(4);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(fgetxattr)
{
    REPLICATEBUFFERFIXEDLEN(3, call_postcall_get_variant_result(0));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_futex - (u32* uaddr, int op, u32 val, struct timespec* utime,
  u32* uaddr2, u32 val3)
-----------------------------------------------------------------------------*/
LOG_ARGS(futex)
{
	debugf("%s - SYS_FUTEX(0x" PTRSTR ", %s, %d, 0x" PTRSTR ", 0x" PTRSTR ", %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum),
		   getTextualFutexOp(ARG2(variantnum)), 
		   ARG3(variantnum),
		   ARG4(variantnum), 
		   ARG5(variantnum),
		   ARG6(variantnum));
}

PRECALL(futex)
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

CALL(futex)
{
	if IS_UNSYNCED_CALL
		return MVEE_CALL_ALLOW;

#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
    // tid was already cleared
    if (ARG2(0) == MVEE_FUTEX_WAIT_TID && ARG3(0) == 0)
    {
        // clear it for the slaves too and deny the call
        for (int i = 1; i < mvee::numvariants; ++i)
			rw::write_primitive<unsigned int>(variants[i].variantpid, (void*) ARG1(i), 0);
        return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
    }
#endif
    return MVEE_CALL_ALLOW;
}

POSTCALL(futex)
{
#ifndef MVEE_DISABLE_SYNCHRONIZATION_REPLICATION
	if IS_SYNCED_CALL
	{
		// sync the tids
		if (ARG2(0) == MVEE_FUTEX_WAIT_TID)
		{
			pid_t master_pid;
			if (!rw::read_primitive<int>(variants[0].variantpid, (void*) ARG1(0), master_pid))
				warnf("Failed to replicate pids\n");
			for (int i = 1; i < mvee::numvariants; ++i)
				if (!rw::write_primitive<int>(variants[i].variantpid, (void*) ARG1(i), master_pid))
					warnf("Failed to replicate pids\n");
		}
	}
#endif
    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
-----------------------------------------------------------------------------*/
LOG_ARGS(sched_setaffinity)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);

	if (ARG2(variantnum) > sizeof(cpu_set_t) ||
		!rw::read_struct(variants[variantnum].variantpid, (void*) ARG3(variantnum), ARG2(variantnum), &mask))
	{
		warnf("couldn't read cpu_set_t\n");
		return;
	}

	debugf("%s - SYS_SCHED_SETAFFINITY(%d, %d, %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum),
		   ARG2(variantnum), 
		   getTextualCPUSet(&mask).c_str());
}

PRECALL(sched_setaffinity)
{
	if ((*mvee::config_variant_global)["allow_setaffinity"].asBool())
	{
		// manipulate the mask so that each variant runs on its own "virtual" cpu
		CHECKPOINTER(3);

		if (ARG3(0))
		{
			for (int i = 0; i < mvee::numvariants; ++i)
			{
				cpu_set_t available_cores;
				int       num_cores_total      = mvee::os_get_num_cores();
				int       num_cores_variant      = num_cores_total / mvee::numvariants;
				int       first_core_available = num_cores_variant * i;
				int       modified_mask        = 0;

				CPU_ZERO(&available_cores);

				if (ARG2(i) > sizeof(cpu_set_t) ||
					!rw::read_struct(variants[i].variantpid, (void*) ARG3(i), ARG2(i), &available_cores))
				{
					warnf("couldn't read cpu_set_t\n");
					return 0;
				}

				for (int j = 0; j < (int)ARG2(i) * 8; ++j)
				{
					if (CPU_ISSET(j, &available_cores) &&
						(j < first_core_available || j >= first_core_available + num_cores_variant))
					{
						CPU_CLR(j, &available_cores);
						if (j < num_cores_variant)
							CPU_SET(j + first_core_available, &available_cores);
						modified_mask = 1;
					}
				}

				if (modified_mask)
				{
#ifndef MVEE_BENCHMARK
					debugf("manipulated virtual CPU mask for the variant: %d - %s\n", i,
                           getTextualCPUSet(&available_cores).c_str());
#endif
					if (!rw::write_data(variants[i].variantpid, (void*) ARG3(i), ARG2(i), &available_cores))
						warnf("Couldn't write cpu_set_t\n");
				}
			}
		}
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(sched_setaffinity)
{
	if (!(*mvee::config_variant_global)["allow_setaffinity"].asBool())
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
    return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
  sys_sched_getaffinity - (pid_t pid, unsigned int len,
  unsigned long __user * user_mask_ptr)
-----------------------------------------------------------------------------*/
GET_CALL_TYPE(sched_getaffinity)
{
    // this is unsynced to work around a "harmless data race" in glibc
    return MVEE_CALL_TYPE_UNSYNCED;
}

POSTCALL(sched_getaffinity)
{
    // mask the return with the CPU cores we wish to make available to this variant

    //debugf("%s - SYS_SCHED_GETAFFINITY return: %d\n",
    //     variants[variantnum].variantpid,
    //     call_postcall_get_variant_result(variantnum));


    int res = call_postcall_get_variant_result(variantnum);
    if (call_check_result(res) && ARG3(variantnum))
    {
        cpu_set_t    available_cores;

        unsigned int num_cores_total      = (unsigned int)mvee::os_get_num_cores();
        unsigned int num_cores_variant      = num_cores_total / mvee::numvariants;
        unsigned int first_core_available = num_cores_variant * variantnum;
        int          modified_mask        = 0;

        CPU_ZERO(&available_cores);

        if (ARG2(variantnum) > sizeof(cpu_set_t) ||
			!rw::read_struct(variants[variantnum].variantpid, (void*) ARG3(variantnum), ARG2(variantnum), &available_cores))
        {
            warnf("couldn't read cpu_set_t\n");
            return 0;
        }

        for (unsigned int i = 0; i < ARG2(variantnum) * 8; ++i)
        {
            if (CPU_ISSET(i, &available_cores)
                && (i < first_core_available || i >= first_core_available + num_cores_variant))
            {
                CPU_CLR(i, &available_cores);
                modified_mask = 1;
            }
        }

        if (modified_mask)
		{
            if (!rw::write_data(variants[variantnum].variantpid, (void*) ARG3(variantnum), ARG2(variantnum), &available_cores))
				warnf("Failed to write cpu_set_t\n");
		}
    }


    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  sys_epoll_create - (int size)
-----------------------------------------------------------------------------*/
LOG_ARGS(epoll_create)
{
	debugf("%s - SYS_EPOLL_CREATE(%d)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum));
}

PRECALL(epoll_create)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(epoll_create)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
        set_fd_table->create_fd_info(FT_POLL_BLOCKING, fds, "epoll_sock", 0, false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_exit_group - NOTE: this syscall does not seem to complete until all
  variants have exited
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

CALL(exit_group)
{
#ifdef MVEE_DUMP_MEM_STATS
    unsigned long mvee_phys, variant_virt, variant_phys;
    double        overhead = 0.0;
    handle_get_mem_size(syscall(__NR_getpid), &mvee_phys,  NULL);
    handle_get_mem_size(variants[0].variantpid,   &variant_phys, &variant_virt);
    overhead                                   = ((double)variant_virt + (double)variant_phys + (double)mvee_phys) / (double)variant_virt;

    warnf("variant virt hwm: %ld bytes - variant phys hwm: %ld bytes - mvee phys hwm: %ld bytes - memory footprint overhead: %lf\n",
                variant_virt, variant_phys, mvee_phys, overhead);
#endif

#ifdef MVEE_CALCULATE_CLOCK_SPREAD
	log_calculate_clock_spread();
#endif

    update_sync_primitives();

    // don't let the exit_group call go through while we have "dangling variants"
    await_pending_transfers();

    // I needed this for raytrace and some other parsecs. They do a sys_exit_group
    // while a bunch of threads are still running.
    // This can cause mismatches in those other threads because some variants might still perform syscalls while the others are dead
//	warnf("thread group shutting down\n");

    set_mmap_table->thread_group_shutting_down = 1;
    return MVEE_CALL_ALLOW;
}

/*-----------------------------------------------------------------------------
    sys_set_tid_address - (int* tidptr)
-----------------------------------------------------------------------------*/
POSTCALL(set_tid_address)
{
	// Always returns the caller's thread ID
	for (int i = 0; i < mvee::numvariants; ++i)
		call_postcall_set_variant_result(i, variants[0].variantpid);
    return MVEE_POSTCALL_HANDLED_UNSYNCED_CALL;
}

/*-----------------------------------------------------------------------------
  clock_gettime - (clockid_t which_clock, struct timespec __user* tp)
-----------------------------------------------------------------------------*/
PRECALL(clock_gettime)
{
    CHECKPOINTER(2);
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(clock_gettime)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct timespec));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_statfs - (const char  *  pathname, struct statfs64  *  buf)
-----------------------------------------------------------------------------*/
LOG_ARGS(statfs)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_STATFS(%s, 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum));
}

PRECALL(statfs)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKPOINTER(2);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(statfs)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct statfs64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_statfs64 - (const char  *  pathname, size_t  sz, struct statfs64  *  buf)
-----------------------------------------------------------------------------*/
LOG_ARGS(statfs64)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));

	debugf("%s - SYS_STATFS64(%s, %ld, 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum), 
		   ARG3(variantnum));
}

PRECALL(statfs64)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKARG(2);
    CHECKPOINTER(3);

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(statfs64)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct statfs64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fstatfs - (int fd, struct statfs* buf)
  sys_fstatfs64 - (int fd, size_t  sz, struct statfs64  *  buf)
-----------------------------------------------------------------------------*/
PRECALL(fstatfs)
{
    CHECKFD(1);
    CHECKPOINTER(2);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(fstatfs)
{
    REPLICATEBUFFERFIXEDLEN(2, sizeof(struct statfs));
    return 0;
}

PRECALL(fstatfs64)
{
    CHECKARG(2);
    CHECKFD(1);
    CHECKPOINTER(3);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(fstatfs64)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct statfs64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_getpriority - (int which, int who)
-----------------------------------------------------------------------------*/
PRECALL(getpriority)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_setpriority - (int which, int who, int niceval)
-----------------------------------------------------------------------------*/
PRECALL(setpriority)
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

/*-----------------------------------------------------------------------------
  sys_sched_setscheduler
-----------------------------------------------------------------------------*/
PRECALL(sched_setscheduler)
{
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(sched_setscheduler)
{
	return MVEE_CALL_DENY | MVEE_CALL_RETURN_VALUE(0);
}

/*-----------------------------------------------------------------------------
  sys_epoll_wait - (int epfd, struct epoll_event __user* events, 
  int maxevents, int timeout)
-----------------------------------------------------------------------------*/
LOG_ARGS(epoll_wait)
{
	debugf("%s - SYS_EPOLL_WAIT(%d, 0x" PTRSTR ", %d, %d)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum),
		   ARG2(variantnum),
		   ARG3(variantnum),
		   ARG4(variantnum));
}

PRECALL(epoll_wait)
{
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKARG(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(epoll_wait)
{
	long result  = call_postcall_get_variant_result(variantnum);

	debugf("%s - SYS_EPOLL_WAIT return: %d\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   result);

	if ((int)result > 0)
	{
		struct epoll_event* events = new(std::nothrow) struct epoll_event[result];
		if (!events || 
			!rw::read_struct(variants[variantnum].variantpid, (void*) ARG2(variantnum), sizeof(struct epoll_event) * result, events))
		{
			warnf("couldn't read epoll_event\n");
			SAFEDELETEARRAY(events);
			return;
		}

		for (unsigned int j = 0; j < result; ++j)
			debugf("%s - > SYS_EPOLL_WAIT fd ready: 0x" PTRSTR " - events: %s\n",
				   call_get_variant_pidstr(variantnum).c_str(), 
				   (unsigned long)events[j].data.ptr, 
				   getTextualEpollEvents(events[j].events).c_str());
		
		SAFEDELETEARRAY(events);
	}
}

POSTCALL(epoll_wait)
{
    if (call_succeeded)
    {
        unsigned long master_result = call_postcall_get_variant_result(0);
        if (master_result > 0)
        {
            struct epoll_event* master_events = new(std::nothrow) struct epoll_event[master_result];
            if (!master_events ||
				!rw::read_struct(variants[0].variantpid, (void*) ARG2(0), sizeof(struct epoll_event) * master_result, master_events))
            {
                warnf("couldn't replicate epoll_events\n");
				SAFEDELETEARRAY(master_events);
                return 0;
            }

            for (int j = 1; j < mvee::numvariants; ++j)
            {
                struct epoll_event* slave_events = new(std::nothrow) struct epoll_event[master_result];
				if (!slave_events)
				{
					warnf("couldn't replicate epoll_events\n");
					SAFEDELETEARRAY(master_events);
					return 0;
				}

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

                if (!rw::write_data(variants[j].variantpid, (void*) ARG2(j), sizeof(epoll_event) * master_result, (unsigned char*)slave_events))
                    warnf("failed to replicate epoll_events to slave variant %d\n", j);
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
LOG_ARGS(epoll_ctl)
{
	struct epoll_event event;
	std::string        events;
	memset(&event, 0, sizeof(struct epoll_event));
	if (ARG4(variantnum))
	{
		if (!rw::read<struct epoll_event>(variants[variantnum].variantpid, (void*) ARG4(variantnum), event))
		{
			warnf("couldn't read epoll_event\n");
			return;
		}
		events = getTextualEpollEvents(event.events);
	}

	debugf("%s - SYS_EPOLL_CTL(%d, %s, %d, %s, ID = 0x" PTRSTR ")\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum),
		   getTextualEpollOp(ARG2(variantnum)),
		   ARG3(variantnum),
		   events.c_str(),
		   (unsigned long)event.data.ptr);
}

PRECALL(epoll_ctl)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKFD(3);
    CHECKPOINTER(4);
    CHECKEPOLLEVENT(4);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(epoll_ctl)
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
                if (!rw::read<struct epoll_event>(variants[i].variantpid, (void*) ARG4(i), event))
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
LOG_ARGS(tgkill)
{
	debugf("%s - SYS_TGKILL(%d, %d, %d = %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   getTextualSig(ARG3(variantnum)));
}

PRECALL(tgkill)
{
    CHECKARG(1);
    CHECKARG(2);
    CHECKARG(3);

	// Figure out if this signal is being sent to a process we're monitoring
	std::vector<pid_t> slave_pids(mvee::numvariants);
	if (mvee::map_master_to_slave_pids(ARG1(0), slave_pids))
	{
		// OK. We're going to dispatch this as a normal call
		MAPPIDS(1);
		MAPPIDS(2);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}
	
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_utimes - (char* filename, struct timeval utimes[2])
-----------------------------------------------------------------------------*/
LOG_ARGS(utimes)
{
	struct timeval utimes[2];
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*) ARG1(variantnum));
	std::stringstream timestr;

	if (ARG2(variantnum))
	{
		if (!rw::read_struct(variants[variantnum].variantpid, (void*) ARG2(variantnum), 2 * sizeof(struct timeval), utimes))
		{
			warnf("couldn't read utimes\n");
			return;
		}

		timestr << "ACTIME: " << utimes[0].tv_sec << "." << std::setw(6) << std::setfill('0') << utimes[0].tv_usec << std::setw(0)
				<< ", MODTIME: " << utimes[1].tv_sec << "." << std::setw(6) << std::setfill('0') << utimes[1].tv_usec;
	}
	else
	{
		timestr << "ACTIME: current, MODTIME: current";
	}

	debugf("%s - SYS_UTIMES(%s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   str1.c_str(),
		   timestr.str().c_str());
}

PRECALL(utimes)
{
    CHECKPOINTER(1);
    CHECKSTRING(1);
    CHECKBUFFER(2, 2 * sizeof(struct timeval));

	if (call_do_alias<1>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_waitid - (int which, pid_t pid, struct siginfo __user *infop,
  int options, struct rusage __user *ru);
-----------------------------------------------------------------------------*/
LOG_ARGS(waitid)
{
	debugf("%s - SYS_WAITID(%d, %d, 0x" PTRSTR ", 0x" PTRSTR ", 0x" PTRSTR ")\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   ARG5(variantnum));
}

PRECALL(waitid)
{
    CHECKARG(1);
    CHECKPOINTER(3);
    CHECKPOINTER(5);
    CHECKARG(4);
    CHECKARG(2);
    MAPPIDS(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(waitid)
{
    // we want to replicate the master result even if the call fails
    unsigned long master_result = call_postcall_get_variant_result(0);

    // if the result is a PID, set the same master PID in
    // all non-master variants
    for (int i = 1; i < mvee::numvariants; ++i)
        call_postcall_set_variant_result(i, master_result);

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
  sys_inotify_init - (void)
-----------------------------------------------------------------------------*/
PRECALL(inotify_init)
{
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(inotify_init)
{
    if (call_succeeded)
    {
        std::vector<unsigned long> fds(mvee::numvariants);
        std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
        set_fd_table->create_fd_info(FT_POLL_BLOCKING, fds, "inotify_init", 0, false, true);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_inotify_add_watch - (int fd, const char* path, uint32_t mask)
-----------------------------------------------------------------------------*/
LOG_ARGS(inotify_add_watch)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	auto mask = getTextualInotifyMask((unsigned long)(int)ARG3(variantnum));

	debugf("%s - SYS_INOTIFY_ADD_WATCH(%d, %s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   mask.c_str());
}

PRECALL(inotify_add_watch)
{
    CHECKARG(1);
	CHECKSTRING(2);
	CHECKARG(3);

	if (call_do_alias<2>())
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_inotify_rm_watch - (int fd, int wd)
-----------------------------------------------------------------------------*/
PRECALL(inotify_rm_watch)
{
	CHECKARG(1);
	CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_openat - (int dfd, const char __user *filename, int flags, int mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(openat)
{
	auto filename = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));

	debugf("%s - SYS_OPENAT(%d, %s, 0x%08X (%s), 0x%08X (%s))\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   filename.c_str(), 		   
		   ARG3(variantnum), getTextualFileFlags(ARG3(variantnum)).c_str(),
		   ARG4(variantnum), getTextualFileMode(ARG4(variantnum) & S_FILEMODEMASK).c_str());
}

PRECALL(openat)
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

    std::string full_path = set_fd_table->get_full_path(0, variants[0].variantpid, (unsigned long)(int)ARG1(0), (void*)ARG2(0));
//    warnf("openat: %s\n", full_path.c_str());

    if (full_path == "")
        return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;

    if (full_path.find("/proc/self/") == 0
        && full_path != "/proc/self/maps"
        && full_path != "/proc/self/exe")
        return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

// See comment above CALL(open) for info on what this function does
CALL(openat)
{
	int result = MVEE_CALL_ALLOW;

	// If do_alias returns true, we will have found aliases for at least
	// one variant. In this case, we want to repeat the check_open_call + 
	// flag stripping iteration below for each variant
	if (call_do_alias_at<1, 2>())
	{
		for (auto i = 0; i < mvee::numvariants; ++i)
		{
			auto file = set_fd_table->get_full_path(i, variants[i].variantpid, (unsigned long)(int)ARG1(i), (void*) ARG2(i));

			result = handle_check_open_call(file.c_str(), ARG3(i), ARG4(i));

			// strip off the O_CREAT and O_EXCL flags
			// GHUMVEE will already have created the file in the handle_check_open_call function
			if (result & MVEE_CALL_ALLOW)
				if ((ARG3(i) & O_CREAT) && (ARG3(i) & O_EXCL))
					call_overwrite_arg_value(i, 3, ARG3(i) & (~(O_CREAT | O_EXCL)), true);
		}

		aliased_open = true;
	}
	else
	{
		auto file = set_fd_table->get_full_path(0, variants[0].variantpid, (unsigned long)(int)ARG1(0), (void*) ARG2(0));		
		result = handle_check_open_call(file.c_str(), ARG3(0), ARG4(0));
		
		if ((result & MVEE_CALL_ALLOW) && (ARG3(0) & O_CREAT) && (ARG3(0) & O_EXCL))
			for (auto i = 0; i < mvee::numvariants; ++i)
				call_overwrite_arg_value(i, 3, ARG3(i) & (~(O_CREAT | O_EXCL)), true);
		
		aliased_open = false;
	}

    return result;
}

POSTCALL(openat)
{
    if (call_succeeded)
    {
        char*                      resolved_path = NULL;
        std::string                tmp_path      = set_fd_table->get_full_path(0, variants[0].variantpid, (unsigned long)(int)ARG1(0), (void*)ARG2(0));

        resolved_path = realpath(tmp_path.c_str(), NULL);

        std::vector<unsigned long> fds           = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
        set_fd_table->create_fd_info(FT_REGULAR, fds, resolved_path, ARG3(0), ARG3(0) & O_CLOEXEC, state == STATE_IN_MASTERCALL, aliased_open);
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
LOG_ARGS(mkdirat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	auto mode = getTextualFileMode(ARG3(variantnum));

	debugf("%s - SYS_MKDIRAT(%d, %s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   mode.c_str());
}

PRECALL(mkdirat)
{
    CHECKARG(3);
    CHECKPOINTER(2);
    CHECKSTRING(2);
    CHECKFD(1);

	if (call_do_alias_at<1, 2>() ||
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_fstatat64 - (int dirfd, const char *pathname, struct stat *buf, int flags)

  sys_newfstatat - (int dfd, const char __user * filename,
  struct stat __user * statbuf, int flag)
-----------------------------------------------------------------------------*/
LOG_ARGS(newfstatat)
{
	auto path = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));

	debugf("%s - SYS_NEWFSTATAT(%d, %s, 0x" PTRSTR ", 0x%08X)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   path.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(newfstatat)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKSTRING(2);

	if (call_do_alias_at<1, 2>() || 
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(newfstatat)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct stat64));
    return 0;
}

LOG_ARGS(fstatat64)
{
	auto path = rw::read_string(variants[variantnum].variantpid, (void*) ARG2(variantnum));

	debugf("%s - SYS_FSTATAT64(%d, %s, 0x" PTRSTR ", 0x%08X)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   path.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(fstatat64)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKSTRING(2);

	if (call_do_alias_at<1, 2>() || 
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

LOG_RETURN(fstatat64)
{
	struct stat64 sb;
	if (!rw::read<struct stat64>(variants[variantnum].variantpid, (void*) ARG3(variantnum), sb))
	{
		warnf("Couldn't read stat64\n");
		return;
	}
	debugf("%s - SYS_FSTATAT64 return\n", 
		   variants[variantnum].variantpid);

	switch (sb.st_mode & S_IFMT) {
		case S_IFBLK:  debugf("File type:                block device\n");            break;
		case S_IFCHR:  debugf("File type:                character device\n");        break;
		case S_IFDIR:  debugf("File type:                directory\n");               break;
		case S_IFIFO:  debugf("File type:                FIFO/pipe\n");               break;
		case S_IFLNK:  debugf("File type:                symlink\n");                 break;
		case S_IFREG:  debugf("File type:                regular file\n");            break;
		case S_IFSOCK: debugf("File type:                socket\n");                  break;
		default:       debugf("File type:                unknown?\n");                break;
	}

	debugf("I-node number:            %ld\n", (long) sb.st_ino);

	debugf("Mode:                     %lo (octal)\n",
		   (unsigned long) sb.st_mode);

	debugf("Link count:               %ld\n", (long) sb.st_nlink);
	debugf("Ownership:                UID=%ld   GID=%ld\n",
		   (long) sb.st_uid, (long) sb.st_gid);

	debugf("Preferred I/O block size: %ld bytes\n",
		   (long) sb.st_blksize);
	debugf("File size:                %lld bytes\n",
		   (long long) sb.st_size);
	debugf("Blocks allocated:         %lld\n",
		   (long long) sb.st_blocks);

	debugf("Last status change:       %s", ctime(&sb.st_ctime));
	debugf("Last file access:         %s", ctime(&sb.st_atime));
	debugf("Last file modification:   %s", ctime(&sb.st_mtime));
}

POSTCALL(fstatat64)
{
    REPLICATEBUFFERFIXEDLEN(3, sizeof(struct stat64));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_unlinkat - (int dirfd, const char *pathname, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(unlinkat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	auto flags = getTextualUnlinkFlags((int)ARG3(variantnum));

	debugf("%s - SYS_UNLINKAT(%d, %s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   flags.c_str());
}

PRECALL(unlinkat)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKSTRING(2);
	
	std::string full_path = set_fd_table->get_full_path(0, variants[0].variantpid, (unsigned long)(int)ARG1(0), (void*)ARG2(0));
	set_fd_table->set_file_unlinked(full_path.c_str());

	if (call_do_alias_at<1, 2>() ||
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_renameat - (int olddirfd, const char *oldpath,
  int newdirfd, const char *newpath)
-----------------------------------------------------------------------------*/
LOG_ARGS(renameat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	auto str2 = rw::read_string(variants[variantnum].variantpid, (void*)ARG4(variantnum));

	debugf("%s - SYS_RENAMEAT(%d, %s, %d, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   ARG3(variantnum), 
		   str2.c_str());
}

PRECALL(renameat)
{
    CHECKFD(3);
    CHECKFD(1);
    CHECKPOINTER(2);
    CHECKPOINTER(4);
    CHECKSTRING(4);
    CHECKSTRING(2);

	bool alias1 = call_do_alias_at<1, 2>();
	bool alias2 = call_do_alias_at<3, 4>();

	if (alias1 || 
		alias2 ||
		set_fd_table->is_fd_unsynced(ARG1(0)) ||
		set_fd_table->is_fd_unsynced(ARG3(0)))
	{
		MAPFDS(1);
		MAPFDS(2);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_linkat - (int olddirfd, const char *oldpath,
  int newdirfd, const char *newpath, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(linkat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	auto str2 = rw::read_string(variants[variantnum].variantpid, (void*)ARG4(variantnum));
	auto flags = getTextualLinkFlags(ARG5(variantnum));

	debugf("%s - SYS_LINKAT(%d, %s, %d, %s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   ARG3(variantnum), 
		   str2.c_str(), 
		   flags.c_str());
}

PRECALL(linkat)
{
    CHECKPOINTER(2);
    CHECKPOINTER(4);
    CHECKARG(5);
    CHECKFD(3);
    CHECKFD(1);
    CHECKSTRING(4);
    CHECKSTRING(2);

	bool alias1 = call_do_alias_at<1, 2>();
	bool alias2 = call_do_alias_at<3, 4>();

	if (alias1 || 
		alias2 ||
		set_fd_table->is_fd_unsynced(ARG1(0)) ||
		set_fd_table->is_fd_unsynced(ARG3(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_symlinkat - (const char *oldpath, int newdirfd, const char *newpath)
-----------------------------------------------------------------------------*/
LOG_ARGS(symlinkat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG1(variantnum));
	auto str2 = rw::read_string(variants[variantnum].variantpid, (void*)ARG3(variantnum));

	debugf("%s - SYS_SYMLINKAT(%s, %d, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   str1.c_str(), 
		   ARG2(variantnum), 
		   str2.c_str());
}

PRECALL(symlinkat)
{
    CHECKPOINTER(1);
    CHECKPOINTER(3);
    CHECKFD(2);
    CHECKSTRING(3);
    CHECKSTRING(1);

	bool alias1 = call_do_alias<1>();
	bool alias2 = call_do_alias_at<2, 3>();

	if (alias1 || 
		alias2 || 
		set_fd_table->is_fd_unsynced(ARG2(0)))
	{
		MAPFDS(2);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_readlinkat - (int dirfd, const char *pathname,
  char *buf, size_t bufsiz)
-----------------------------------------------------------------------------*/
LOG_ARGS(readlinkat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));

	debugf("%s - SYS_READLINKAT(%d, %s, 0x" PTRSTR", %ld)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   ARG3(variantnum), 
		   ARG4(variantnum));
}

PRECALL(readlinkat)
{
    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);
    CHECKSTRING(2);

	if (call_do_alias_at<1, 2>() || 
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(readlinkat)
{
    REPLICATEBUFFER(3);
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_fchmodat - (int dfd, const char __user * filename, umode_t mode, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(fchmodat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));
	auto mode = getTextualFileMode(ARG3(variantnum));
	auto flags = getTextualChmodFlags(ARG4(variantnum));

	debugf("%s - SYS_FCHMODAT(%d, %s, %s, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   mode.c_str(), 
		   flags.c_str());
}

PRECALL(fchmodat)
{
    CHECKPOINTER(2);
    CHECKFD(1);
    CHECKSTRING(2);
    CHECKARG(3);

	if (call_do_alias_at<1, 2>() || 
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_faccessat - (int dirfd, const char *pathname, int mode)
-----------------------------------------------------------------------------*/
LOG_ARGS(faccessat)
{
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*)ARG2(variantnum));

	debugf("%s - SYS_FACCESSAT(%d, %s, 0x%08X = %s, 0x%08x)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum), 
		   str1.c_str(), 
		   ARG3(variantnum),
		   getTextualAccessMode(ARG3(variantnum)).c_str(), 
		   ARG4(variantnum));
}

PRECALL(faccessat)
{
    CHECKPOINTER(2);
    CHECKARG(3);
    CHECKFD(1);
    CHECKSTRING(2);

	if (call_do_alias_at<1, 2>() || 
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_unshare - (int flags)

  reverses the effect of sharing certain kernel data structures through
  sys_clone
-----------------------------------------------------------------------------*/
LOG_ARGS(unshare)
{
	debugf("%s - SYS_UNSHARE(%d)\n",
		   call_get_variant_pidstr(variantnum).c_str(), 
		   ARG1(variantnum));
}

PRECALL(unshare)
{
	CHECKARG(1);
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(unshare)
{
	// 
	// This may be downright impossible to do in the general case as we do not
	// have a stop-the-world primitive in the MVEE.  There are two cases that we
	// COULD handle right now:
	// 
	// 1) Unshare is called with arg 0. This is a no-op 
	// 2) Unshare is called by a single-threaded process. In this case, we leave
	// the tables of the parent process intact, and we create new copies of
	// whatever tables are being unshared by this process
	//

	if (ARG1(0) == 0)
	{
		// this is a no-op... fine
		return MVEE_CALL_ALLOW;
	}
	else if (!is_program_multithreaded())
	{
		// We can handle this...
		warnf("Unshare called by singlethreaded process. This is not implemented yet!\n");
		return MVEE_CALL_ALLOW;
	}
	else
	{
		// Program is multithreaded and tables are being unshared.
		// No way to handle this right now
		warnf("Unshare called by multithreaded process. This is not implemented yet!\n");
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EPERM);
	}
}

/*-----------------------------------------------------------------------------
  sys_utimensat - (int dirfd, const char *pathname,
  const struct timespec times[2], int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(utimensat)
{
	struct timespec times[2];
	std::stringstream timestr;
	auto str1 = rw::read_string(variants[variantnum].variantpid, (void*) ARG2(variantnum));

	if (ARG3(variantnum))
	{
		if (!rw::read_struct(variants[variantnum].variantpid, (void*) ARG3(variantnum), 2 * sizeof(struct timespec), times))
		{
			warnf("%s - couldn't read timespec\n",
				  call_get_variant_pidstr(variantnum).c_str());
			return;
		}

		timestr << "ACTIME: " << times[0].tv_sec << std::setw(9) << std::setfill('0') << times[0].tv_nsec << std::setw(0)
				<< ", MODTIME: " << times[1].tv_sec << std::setw(9) << std::setfill('0') << times[1].tv_nsec;
	}
	else
	{
		timestr << "ACTIME: current, MODTIME: current";
	}

	debugf("%s - SYS_UTIMENSAT(%d, %s, %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum),
		   str1.c_str(),
		   timestr.str().c_str());
}

PRECALL(utimensat)
{
    std::vector<const char*> argarray(mvee::numvariants);

    CHECKPOINTER(2);
    CHECKPOINTER(3);
    CHECKARG(4);
    CHECKFD(1);

    FILLARGARRAY(2, argarray);
    bool should_compare = true;
    for (int i = 0; i < mvee::numvariants; ++i)
        if (!argarray[i])
            should_compare = false;
    if (should_compare && !call_compare_variant_strings(argarray, 0))
        return MVEE_PRECALL_ARGS_MISMATCH(2) | MVEE_PRECALL_CALL_DENY;

    if (ARG3(0))
    {
        unsigned char* master_times = rw::read_data(variants[0].variantpid, (void*)ARG3(0), sizeof(struct timespec)*2);
        if (!master_times)
        {
            cache_mismatch_info("couldn't read master times\n");
            return MVEE_PRECALL_ARGS_MISMATCH(3) | MVEE_PRECALL_CALL_DENY;
        }
        bool           mismatch     = false;
        for (int i = 1; i < mvee::numvariants; ++i)
        {
            unsigned char* slave_times = rw::read_data(variants[i].variantpid, (void*)ARG3(i), sizeof(struct timespec)*2);
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

	if (call_do_alias_at<1, 2>() || 
		set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_timerfd_create - (int clockid, int flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(timerfd_create)
{
	debugf("%s - SYS_TIMERFD_CREATE(%d (%s), %d (%s))\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), getTextualTimerType(ARG1(variantnum)),
		   ARG2(variantnum), getTextualTimerFlags(ARG2(variantnum)).c_str());
}

PRECALL(timerfd_create)
{
    CHECKARG(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(timerfd_create)
{
    std::vector<unsigned long> fds;
    fds.resize(mvee::numvariants);
    std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));

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
PRECALL(fallocate)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_timerfd_settime - (int ufd, int flags,
  const struct itimerspec* utmr, struct itimerspec* otmr)
-----------------------------------------------------------------------------*/
PRECALL(timerfd_settime)
{
    CHECKFD(1);
    CHECKARG(2);
    CHECKPOINTER(3);
    CHECKPOINTER(4);
    CHECKBUFFER(3, sizeof(struct itimerspec));

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(timerfd_settime)
{
    if (ARG4(0))
        REPLICATEBUFFERFIXEDLEN(4, sizeof(struct itimerspec));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_timerfd_gettime - (int ufd, struct itimerspec* otmr)
-----------------------------------------------------------------------------*/
PRECALL(timerfd_gettime)
{
    CHECKFD(1);
    CHECKPOINTER(2);

	if (set_fd_table->is_fd_unsynced(ARG1(0)))
	{
		MAPFDS(1);
		return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
	}

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(timerfd_gettime)
{
    if (ARG2(0))
        REPLICATEBUFFERFIXEDLEN(2, sizeof(struct itimerspec));
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_dup3 - (unsigned int oldfd, unsigned int newfd, int flags)
  the only valid flag that can be passed to dup3 through the flags field is O_CLOEXEC!!!
-----------------------------------------------------------------------------*/
LOG_ARGS(dup3)
{
	debugf("%s - SYS_DUP3(%d, %d, %s)\n", 
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   getTextualFileFlags(ARG3(variantnum)).c_str());
}

PRECALL(dup3)
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

POSTCALL(dup3)
{
	std::vector<unsigned long> fds;

    if (state == STATE_IN_MASTERCALL)
    {
        fds.resize(mvee::numvariants);
		std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));
    }
    else
    {
        fds = call_postcall_get_result_vector();
        REPLICATEFDRESULT();
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
                return 0;

            set_fd_table->create_fd_info(fd_info->file_type, 
										 fds, 
										 fd_info->path.c_str(), 
										 fd_info->access_flags, 
										 (ARG3(0) != 0) ? true : false, 
										 fd_info->master_file, 
										 fd_info->unsynced_reads, 
										 fd_info->unlinked,
										 fd_info->original_file_size);
#ifdef MVEE_FD_DEBUG
            set_fd_table->verify_fd_table(getpids());
#endif
        }
    }
    return 0;
}

/*-----------------------------------------------------------------------------
  sys_pipe2 - (int* pipefd, int flags)
-----------------------------------------------------------------------------*/
PRECALL(pipe2)
{
    CHECKPOINTER(1);
    CHECKARG(2);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(pipe2)
{
    if (call_succeeded)
    {
        int                        fildes[2];
		std::vector<unsigned long> read_fds(mvee::numvariants);
		std::vector<unsigned long> write_fds(mvee::numvariants);

        if (!rw::read_struct(variants[0].variantpid, (void*)ARG1(0), 2 * sizeof(int), fildes))
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
  sys_inotify_init1 - (int flags)
-----------------------------------------------------------------------------*/
PRECALL(inotify_init1)
{
    CHECKARG(1);
    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

POSTCALL(inotify_init1)
{
    if (call_succeeded)
    {
		std::vector<unsigned long> fds(mvee::numvariants);
		std::fill(fds.begin(), fds.end(), call_postcall_get_variant_result(0));

		FileType type = (ARG1(0) & IN_NONBLOCK) ? FT_POLL_NON_BLOCKING : FT_POLL_BLOCKING;
        set_fd_table->create_fd_info(type, fds, "inotify_init1", 0, (ARG1(0) & IN_CLOEXEC) ? true : false, false);
#ifdef MVEE_FD_DEBUG
        set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_rt_tgsigqueueinfo - (pid_t tgid, pid_t pid, int sig, siginfo_t* uinfo)
-----------------------------------------------------------------------------*/
PRECALL(rt_tgsigqueueinfo)
{
	CHECKARG(1);
	CHECKARG(2);
	CHECKARG(3);
	// there might be uninitialized data in the siginfo_t struct so we probably
	// can't do a plain memcmp
	CHECKBUFFER(4, 3 * sizeof(int)); // compare signo, errno, code
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_MASTER;
}

/*-----------------------------------------------------------------------------
  sys_perf_event_open - (struct perf_event_attr* attr, pid_t pid, int cpu, 
  int group_fd, unsigned long flags)
-----------------------------------------------------------------------------*/
LOG_ARGS(perf_event_open)
{
	debugf("%s - SYS_PERF_EVENT_OPEN(0x" PTRSTR ", %d, %d, %d, %s)\n",
		   call_get_variant_pidstr(variantnum).c_str(),
		   ARG1(variantnum), 
		   ARG2(variantnum), 
		   ARG3(variantnum), 
		   ARG4(variantnum), 
		   getTextualPerfFlags(ARG5(variantnum)).c_str());
}

PRECALL(perf_event_open)
{
    CHECKPOINTER(1);
    CHECKBUFFER(1, sizeof(struct perf_event_attr));
    CHECKARG(2);
    CHECKARG(3);
    CHECKARG(4);
    CHECKARG(5);

    if (ARG2(0))
        MAPPIDS(2);

    return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

POSTCALL(perf_event_open)
{
    if (call_succeeded)
    {
        bool cloexec = false;
#ifdef PERF_FLAG_FD_CLOEXEC
        if (ARG5(0) & PERF_FLAG_FD_CLOEXEC)
            cloexec = true;
#endif
		std::vector<unsigned long> fds = call_postcall_get_result_vector();
		REPLICATEFDRESULT();
		set_fd_table->create_fd_info(FT_SPECIAL, fds, "perf_event", 0, cloexec, false, true);
#ifdef MVEE_FD_DEBUG
		set_fd_table->verify_fd_table(getpids());
#endif
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  sys_seccomp - seccomp can be used to filter syscalls based on the syscall
  numbers or arguments. We currently disable this syscall as our sync agents
  might trigger seccomp violations.

  In the future, we could either emulate seccomp (which is easy to do but will
  involve a lot of engineering), or we could manipulate the filters passed
  to seccomp so they become sync agent-aware.
-----------------------------------------------------------------------------*/
PRECALL(seccomp)
{
	CHECKARG(1);
	switch(ARG1(0))
	{
		// only allow read/write/exit
		case SECCOMP_SET_MODE_STRICT:
			break;
		// installs filters for a set of syscalls
		case SECCOMP_SET_MODE_FILTER:
			break;
		default:
			warnf("unknown seccomp option used: %d\n", ARG1(0));
			return MVEE_PRECALL_ARGS_MISMATCH(1) | MVEE_PRECALL_CALL_DENY;

	}
	return MVEE_PRECALL_ARGS_MATCH | MVEE_PRECALL_CALL_DISPATCH_NORMAL;
}

CALL(seccomp)
{
	// Unless the program is GHUMVEE-aware, these filters will not work
	// well. We'll just pretend like the kernel doesn't support seccomp-filtering
	if (ARG1(0) == SECCOMP_SET_MODE_FILTER)
		return MVEE_CALL_DENY | MVEE_CALL_RETURN_ERROR(EINVAL);
	return MVEE_CALL_ALLOW;	
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
    These annotations get picked up by the generate_syscall_table.rb script
	DONTNEED PRECALL(shmctl)
    DONTNEED PRECALL(brk)
    DONTNEED PRECALL(shmget)
    DONTNEED PRECALL(uname)
    DONTNEED PRECALL(sched_getparam)
    DONTNEED PRECALL(sched_getscheduler)
    DONTNEED PRECALL(sched_get_priority_max)
    DONTNEED PRECALL(sched_get_priority_min)
    DONTNEED PRECALL(getuid32)
    DONTNEED PRECALL(getuid)
    DONTNEED PRECALL(getgid32)
    DONTNEED PRECALL(getgid)
    DONTNEED PRECALL(geteuid32)
    DONTNEED PRECALL(geteuid)
    DONTNEED PRECALL(getegid32)
    DONTNEED PRECALL(getegid)
    DONTNEED PRECALL(getresuid32)
    DONTNEED PRECALL(getresuid)
    DONTNEED PRECALL(getresgid32)
    DONTNEED PRECALL(getresgid)
    DONTNEED PRECALL(madvise)
    DONTNEED PRECALL(set_thread_area)
    DONTNEED PRECALL(exit_group)
    DONTNEED PRECALL(set_tid_address)
    DONTNEED PRECALL(clock_getres)
    DONTNEED PRECALL(set_robust_list)
    DONTNEED PRECALL(fadvise64_64)
    DONTNEED PRECALL(fadvise64)
    DONTNEED PRECALL(sched_getaffinity)
    DONTNEED PRECALL(rt_sigreturn)
    DONTNEED PRECALL(getpid)
    DONTNEED PRECALL(prlimit64)
    DONTNEED PRECALL(sigaltstack)
    DONTNEED PRECALL(shmdt)
	DONTNEED PRECALL(rt_sigtimedwait)
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

	// Special case that affects all tables
    REG_LOCKS(__NR_unshare,             MVEE_SYSLOCK_FD | MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_SHM | MVEE_SYSLOCK_FULL);

    // normal syscalls that create/destroy/modify file descriptors
    REG_LOCKS(__NR_open,                MVEE_SYSLOCK_FD | MVEE_SYSLOCK_FULL); // There seem to be blocking open calls in FF
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
	REG_LOCKS(__NR_exit_group,  MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_PRECALL);
	REG_LOCKS(__NR_exit,        MVEE_SYSLOCK_MMAN | MVEE_SYSLOCK_PRECALL);

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
