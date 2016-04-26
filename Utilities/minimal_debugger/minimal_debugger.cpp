/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <map>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <asm/unistd_64.h>
#include <sys/reg.h>

/*-----------------------------------------------------------------------------
    Whitelisted syscalls
-----------------------------------------------------------------------------*/
static unsigned long utcb_allowed_syscalls [] =
  {
    __NR_getxattr,
    __NR_lgetxattr,
    __NR_fgetxattr,
    __NR_listxattr,
    __NR_llistxattr,
    __NR_flistxattr,
    __NR_getcwd,
    __NR_ioprio_get,
    __NR_read,
    __NR_write,
    __NR_readv,
    __NR_writev,
    __NR_pread64,
    __NR_pwrite64,
    __NR_preadv,
    __NR_pwritev,
    __NR_sendfile,
    __NR_capget,
    __NR_getitimer,
    __NR_timer_gettime,
    __NR_timer_getoverrun,
    __NR_clock_gettime,
    __NR_clock_getres,
    __NR_sched_getscheduler,
    __NR_sched_getparam,
    __NR_sched_getaffinity,
    __NR_sched_yield,
    __NR_sched_get_priority_max,
    __NR_sched_get_priority_min,
    __NR_sched_rr_get_interval,
    __NR_getpriority,
    __NR_getresuid,
    __NR_getresgid,
    __NR_times,
    __NR_getpgid,
    __NR_getsid,
    __NR_getgroups,
    __NR_getrlimit,
    __NR_getrusage,
    __NR_getcpu,
    __NR_gettimeofday,
    __NR_getpid,
    __NR_getppid,
    __NR_getuid,
    __NR_geteuid,
    __NR_getgid,
    __NR_getegid,
    __NR_gettid,
    __NR_getsockname,
    __NR_getpeername,
    __NR_sendto,
    __NR_recvfrom,
    __NR_getsockopt,
    __NR_sendmsg,
    __NR_recvmsg,
    __NR_recvmmsg,
    __NR_sendmmsg
  };

/*-----------------------------------------------------------------------------
    Structures
-----------------------------------------------------------------------------*/
struct minimal_childstate
{
	pid_t 			child_pid;
	unsigned char 	child_exited 		: 1;
	unsigned char   child_in_syscall 	: 1;
	unsigned char   child_set_options   : 1;
	unsigned char   child_resumed       : 1;
	unsigned long   child_syscalls_whitelisted;
	unsigned long	child_syscalls;
	unsigned long	child_signals;
};

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
pid_t main_child;
std::map<pid_t, struct minimal_childstate*> childs;
timeval start_time, end_time;

/*-----------------------------------------------------------------------------
    is_whitelisted_syscall
-----------------------------------------------------------------------------*/
unsigned char is_whitelisted_syscall(long syscall_no)
{
	for (int i = 0; i < sizeof(utcb_allowed_syscalls) / sizeof(unsigned long); ++i)
		if (utcb_allowed_syscalls[i] == syscall_no)
			return 1;
	return 0;
}

/*-----------------------------------------------------------------------------
    init_child
-----------------------------------------------------------------------------*/
struct minimal_childstate* init_child(pid_t pid)
{
	struct minimal_childstate* result = new struct minimal_childstate;

	memset(result, 0, sizeof(struct minimal_childstate));
	result->child_pid = pid;

	return result;
}

/*-----------------------------------------------------------------------------
    check_shutdown - some child died. Check if we have any running tracees left
-----------------------------------------------------------------------------*/
void check_shutdown()
{
	unsigned char all_terminated = 1;
	std::map<pid_t, struct minimal_childstate*>::iterator it;

	for (it = childs.begin(); it != childs.end(); ++it)
	{
		if (!it->second->child_exited)
		{
			all_terminated = 0;
			break;
		}
	}

	if (all_terminated)
	{
		unsigned long long total_syscalls 				= 0;
		unsigned long long total_syscalls_whitelisted 	= 0;
		unsigned long long total_signals  				= 0;

		gettimeofday(&end_time, NULL);

		double total_time = (end_time.tv_sec - start_time.tv_sec) +
			((end_time.tv_usec - start_time.tv_usec) / 1000000.0);

		fprintf(stderr, "TOTAL_RUNTIME: %lf seconds\n", total_time);

		for (it = childs.begin(); it != childs.end(); ++it)
		{
			if (it->second->child_pid != main_child)
			{
				total_syscalls 				+= it->second->child_syscalls;
				total_syscalls_whitelisted 	+= it->second->child_syscalls_whitelisted;
				total_signals  				+= it->second->child_signals;
			}
		}

		fprintf(stderr, "TOTAL_SYSCALLS: %llu\n", total_syscalls);
		fprintf(stderr, "SYSCALL_DENSITY: %lf\n", total_syscalls / total_time);

		fprintf(stderr, "TOTAL_SYSCALLS_WHITELISTED: %llu\n", total_syscalls_whitelisted);
		fprintf(stderr, "SYSCALL_WHITELISTED_DENSITY: %lf\n", total_syscalls_whitelisted / total_time);

		fprintf(stderr, "TOTAL_SIGNALS: %llu\n", total_signals);
		fprintf(stderr, "SIGNAL_DENSITY: %lf\n", total_signals / total_time);

		const char* home = getenv("HOME");
		char* file = new char[strlen(home) + strlen("syscall-density.tmp") + 2];
		sprintf(file, "%s/syscall-density.tmp", home);

		FILE* fp = fopen(file, "w+");

		if (fp)
		{
			fprintf(fp, "%lf;%llu;%lf;%llu;%lf;%llu;%lf;\n", total_time,
				total_syscalls, total_syscalls / total_time,
				total_syscalls_whitelisted, total_syscalls_whitelisted / total_time,
				total_signals, total_signals / total_time);
			fclose(fp);
		}

		exit(0);
	}
}

/*-----------------------------------------------------------------------------
    force_shutdown
-----------------------------------------------------------------------------*/
void force_shutdown()
{
	std::map<pid_t, struct minimal_childstate*>::iterator it;

	for (it = childs.begin(); it != childs.end(); ++it)
	{
		if (!it->second->child_exited)
		{
			kill(it->second->child_pid, SIGKILL);
			break;
		}
	}

	exit(0);
}

/*-----------------------------------------------------------------------------
    child_set_options
-----------------------------------------------------------------------------*/
void child_set_options(struct minimal_childstate* child)
{
	child->child_set_options = 1;
	child->child_resumed = 1;
	ptrace(PTRACE_SETOPTIONS, child->child_pid, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD);
}

/*-----------------------------------------------------------------------------
    main
-----------------------------------------------------------------------------*/
int main(int argc, char** argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "Syntax: %s <tracee> [<tracee args>]\n", argv[0]);
		return -1;
	}

	main_child = fork();
	if (main_child == 0)
	{
		int argv_len = 0;

		for (int i = 1; i < argc; ++i)
			if (argv[i])
				argv_len += strlen(argv[i]) + 1;

		char* new_argv = new char[argv_len + 1];
		for (int i = 1; i < argc; ++i)
		{
			if (i > 1)
				strcat(new_argv, " ");
			strcat(new_argv, argv[i]);
		}
		char* execve_args[] = {(char*)"sh", (char*)"-c", new_argv, NULL};

		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execv("/bin/sh", execve_args);
	}
	else
	{
		unsigned char first_fork = 1;
		int status;
		pid_t pid;
		std::map<pid_t, struct minimal_childstate*>::iterator it;
		struct minimal_childstate* child = init_child(main_child);

		childs.insert(std::pair<pid_t, struct minimal_childstate*>(main_child, child));

		// wait for the main child first to set the ptrace options
		if ((waitpid(-1, &status, 0) == main_child) && WIFSTOPPED(status))
		{
			child_set_options(child);
			ptrace(PTRACE_SYSCALL, main_child, NULL, 0);
		}
		else
		{
			fprintf(stderr, "ERROR: Main child initialization failed\n");
			force_shutdown();
		}

		while ((pid = waitpid(-1, &status, __WALL | WUNTRACED)) != -1)
		{
			it = childs.find(pid);
			if (it == childs.end())
			{
				if (childs.find(pid) == childs.end())
					childs.insert(std::pair<pid_t, struct minimal_childstate*>(pid, init_child(pid)));
			}
			else
			{
				child = it->second;
			}

			if (WIFEXITED(status))
			{
				child->child_exited = 1;
				check_shutdown();
				ptrace(PTRACE_SYSCALL, pid, NULL, 0);
			}
			else if (WIFSTOPPED(status))
			{
				if (WSTOPSIG(status) == (SIGTRAP|0x80))
				{
					if (!child->child_in_syscall)
					{
						long syscall_no = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
						if (is_whitelisted_syscall(syscall_no))
							child->child_syscalls_whitelisted++;
						child->child_syscalls++;
					}
					child->child_in_syscall = !child->child_in_syscall;
					ptrace(PTRACE_SYSCALL, pid, NULL, 0);
				}
				else if (WSTOPSIG(status) == SIGTRAP)
				{
					int event = ((status & 0x000F0000) >> 16);
					if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE)
					{
						long newpid;
						ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
						if (childs.find(newpid) == childs.end())
							childs.insert(std::pair<pid_t, struct minimal_childstate*>(newpid, init_child(newpid)));

						//printf("fork event from child: %d [== FORK ==>] %d\n", pid, (pid_t)newpid);

						if (first_fork)
						{
							first_fork = 0;
							gettimeofday(&start_time, NULL);
						}
					}
					else
					{
						//fprintf(stderr, "ERROR: Unexpected SIGTRAP from child %d - event: %d\n", pid, event);
						//force_shutdown();
					}

					ptrace(PTRACE_SYSCALL, pid, NULL, 0);
				}
				else if (WSTOPSIG(status) == SIGSTOP)
				{
					if (!child->child_resumed)
						child->child_resumed = 1;
					else
						child->child_signals++;
					ptrace(PTRACE_SYSCALL, pid, NULL, 0);
				}
				else
				{
					child->child_signals++;
					ptrace(PTRACE_SYSCALL, pid, NULL, (void*)WSTOPSIG(status));
				}
			}
			else
			{
				fprintf(stderr, "ERROR: Unexpected status from child %d\n", pid);
				force_shutdown();
			}
		}

		return 0;
	}
}
