#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <signal.h>
#include <unistd.h>
#include <bits/siginfo.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <map>

#define SIGSYSTRAP (SIGTRAP | 0x80)

// grep _HZ /boot/config-`uname -r` | grep =y | cut -d'_' -f3 | cut -d'=' -f1

struct monitor
{
  int childs[16];
};

std::map<int, int> replica_to_monitor_mapping;
std::map<int, struct monitor*> monitor_to_state_mapping;

void register_monitor(struct monitor* mon)
{

}

int main(int argc, char** argv)
{
  if (argc < 4)
    {
      printf("minimal monitor syntax: %s <demonum> <replica_count> <monitormode>\n", argv[0]);
      printf("monitor modes: \n");
      printf("* 0 = single threaded blocking monitor (GDB-like)\n");
      printf("* 1 = multi-threaded non-blocking monitor (original GHUMVEE/Orchestra)\n");
      printf("* 2 = multi-threaded blocking monitor (DISPATCHER)\n");
      exit(-1);
      return;
    }

  int demonum = atoi(argv[1]);
  int childcnt = atoi(argv[2]);
  int monitormode = atoi(argv[3]);
  int childs[childcnt];
  int callcount = 0;
  int i;

  printf("demonum: %d\n", demonum);
  printf("replica count: %d\n", childcnt);
  printf("monitor mode: %s\n", monitormode == 0 ? "single threaded - blocking" : monitormode == 1 ? "multi-threaded - non-blocking" : "multi-threaded blocking");

  if (child == 0)
    {
      ptrace(PTRACE_TRACEME, 0, 0, NULL);
      kill(getpid(), SIGSTOP);
      execl("./WriteBenchmark", "WriteBenchmark", "1", "95", NULL);
    }
  else
    {
      int status;
      int pid = waitpid(-1, &status, 0);

      if (pid == child && WIFSTOPPED(status))
        {
          if (WSTOPSIG(status) == SIGSTOP)
            {
              ptrace(PTRACE_SETOPTIONS, pid, 0, (void*)PTRACE_O_TRACESYSGOOD);
              printf("set opts\n");
              ptrace(PTRACE_SYSCALL, pid, 0, NULL);
            }
        }

      int entrance = 0;

      while (1)
        {
          pid = waitpid(-1, &status, __WALL | WUNTRACED);

	  if (pid != child || WIFEXITED(status))
	    {
	      printf("Tis gedaan! Calls: %d\n", callcount/2);
	      return 0;
	    }

	  if (WIFSTOPPED(status))
	    {
	      if (WSTOPSIG(status) == SIGSYSTRAP)
		{
		  entrance = !entrance;

		  int callnum = ptrace(PTRACE_PEEKUSER, pid, 4*ORIG_EAX, NULL);
		  //		  printf("syscall: %d - entrance: %d\n", callnum, entrance);
		  ptrace(PTRACE_SYSCALL, pid, 0, NULL);
		  callcount++;
		  continue;
		}
	      ptrace(PTRACE_SYSCALL, pid, 0, NULL);
	      continue;
	    }
	}
    }
}
