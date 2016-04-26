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
    
      killall TestApp6
      
    Known issue: a segfault occurs in all children after the signal handler
    has been executed. So far, no solution has been found.
=============================================================================*/

#include <iostream>
#include <signal.h>
#include <unistd.h>

using namespace std;

static void termhandler (int sig, siginfo_t *siginfo, void *context)
{
    cout << "Signal Handler executed: " << sig << endl;
}

int main()
{
    struct sigaction termaction;

    termaction.sa_sigaction = &termhandler;
    termaction.sa_flags = SA_SIGINFO;

    sigaction(SIGTERM, &termaction, NULL);
    sigaction(SIGILL, &termaction, NULL);
    sigaction(SIGCONT, &termaction, NULL);

    for (int i = 0; i < 60; ++i)
    {
        cout << "Hello world! " << i << endl;
        sleep(1);
    }
    return 0;
}
