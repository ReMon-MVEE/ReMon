#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

int main(int argc, char** argv)
{
  int pid = fork();

  // child
  if (pid == 0)
    {
      ptrace(PTRACE_TRACEME, 0, 0, NULL);
      kill(getpid(), SIGSTOP);
      for (;;)
	{
	  sleep(1);
	}
    }
  else
    {
      int status;
      int bla;
      int result = waitpid(-1, &status, 0);

      if (result > 0 && WIFSTOPPED(status))
	{
	  struct timeval s1, s2, s3, s4;
	  struct user_regs_struct regs;
	  gettimeofday(&s1, NULL);
	  for (int i = 0; i < 1000000; ++i)
	    {
	      ptrace(PTRACE_GETREGS, pid, 0, &regs);
	    }
	  gettimeofday(&s2, NULL);
	  for (int i = 0; i < 1000000; ++i)
	    {
	      bla = ptrace(PTRACE_PEEKUSER, pid, 4*ORIG_EAX, NULL);
	    }
	  gettimeofday(&s3, NULL);
	  
	  double t1,t2,t3;
	  t1 = s1.tv_sec+(s1.tv_usec/1000000.0);
	  t2 = s2.tv_sec+(s2.tv_usec/1000000.0);
	  t3 = s3.tv_sec+(s3.tv_usec/1000000.0);

	  printf("getregs => %lf sec - peekuser => %lf sec\n", t2-t1, t3-t2);
	  exit(0);
	}
    }

  return 0;
}
