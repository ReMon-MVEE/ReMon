#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
//#include <bits/libc-lock.h>
//#include <sysdep-cancel.h>

int main(int argc, char** argv)
{  
  return system(argv[1]);
}
