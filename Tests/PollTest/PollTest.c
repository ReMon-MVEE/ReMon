/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program polls stdin for two seconds and prints out the resulting
    revents. It can be used to test if the monitor correctly handles sys_poll.
    During execution of this program in the MVEE, no mismatches should occur.

    To get "revents: 1", press Enter during the two seconds this program is
    polling.
=============================================================================*/

#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  struct pollfd pfd[1];
  char buf[BUFSIZ];
  int nfds;

  printf("Polling for 2 seconds (press Enter to stop)...\n");

  pfd[0].fd = STDIN_FILENO;
  pfd[0].events = POLLIN;
  nfds = poll(pfd, 1, 2000);
  printf("revents: %d\n", pfd[0].revents);
  if (nfds == -1 || (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL)))
	  errx(1, "poll error");
  if (nfds == 0)
	  errx(1, "time out");
  if (read(STDIN_FILENO, buf, sizeof(buf)) == -1)
	  errx(1, "read");
}