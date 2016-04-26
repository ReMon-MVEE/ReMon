/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test if the monitor correctly delivers signals
    to the children. To do so, run this program in the MVEE and execute the
    following in a different terminal:
    
      killall -USR1 TestApp8
=============================================================================*/

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void sig_handler(int sig)
{
	int temp = getpid();
	printf("SigHandler executing! pid = %d\n", temp);
}

int main()
{
	signal(SIGUSR1, sig_handler);
	//signal(SIGUSR1, SIG_IGN);

	for(int i = 0; i < 120; ++i)
	{
		printf("%d...\n", i);
		sleep(1);
	}
}
