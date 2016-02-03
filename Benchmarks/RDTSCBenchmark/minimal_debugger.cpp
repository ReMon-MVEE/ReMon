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
#include <sys/prctl.h>

#define SIGSYSTRAP (SIGTRAP | 0x80)

int main(int argc, char** argv)
{
  int child = fork();
  int callcount = 0;
  int rdtscs = 0;

  if (child == 0)
    {
      ptrace(PTRACE_TRACEME, 0, 0, NULL);
      prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0);
      kill(getpid(), SIGSTOP);
      execl("./RDTSCBenchmark", "RDTSCBenchmark", NULL);
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

	  if (WIFEXITED(status))
	    {
	      printf("Tis gedaan! syscalls: %d - rdtscs onderschept: %d - time: \n", callcount/2, rdtscs);
	      return 0;
	    }

	  if (WIFSTOPPED(status))
	    {
	      if (WSTOPSIG(status) == SIGSYSTRAP)
		{
		  entrance = !entrance;

		  int callnum = ptrace(PTRACE_PEEKUSER, pid, 4*ORIG_EAX, NULL);
		  ptrace(PTRACE_SYSCALL, pid, 0, NULL);
		  callcount++;
		  continue;
		}
	      else if (WSTOPSIG(status) == SIGSEGV)
		{
		  siginfo_t siginfo = {0};
		  ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
		  if (siginfo.si_code == SI_KERNEL)
		    {
		      int eip = ptrace(PTRACE_PEEKUSER, pid, 4*EIP, NULL);
		      int opcode = ptrace(PTRACE_PEEKTEXT, pid, eip, NULL);
		      
		      if ((short int)(opcode & 0x0000FFFF) == 0x310F)
			{
			  unsigned int lower, upper;
			  rdtscs++;
			  asm volatile("rdtsc\n" : "=a"(lower), "=d"(upper));
			  ptrace(PTRACE_POKEUSER, pid, 4*EDX, (void*)upper);
			  ptrace(PTRACE_POKEUSER, pid, 4*EAX, (void*)lower);
			  ptrace(PTRACE_POKEUSER, pid, 4*EIP, (void*)(eip + 2));
			  ptrace(PTRACE_SYSCALL, pid, 0, NULL);
			}
		    }
		}
	      ptrace(PTRACE_SYSCALL, pid, 0, NULL);
	      continue;
	    }
	}
    }
}
