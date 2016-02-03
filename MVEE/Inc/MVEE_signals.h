/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

#ifndef MVEE_SIGNALS_H_
#define MVEE_SIGNALS_H_

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <signal.h>
#include "MVEE_config.h"

/*-----------------------------------------------------------------------------
  SIGSETXID define, see nptl/pthreadP.h
-----------------------------------------------------------------------------*/
#define SIGCANCEL (__SIGRTMIN)
// Signal used to implement the setuid et.al. functions.
#define SIGSETXID (__SIGRTMIN + 1)

/*-----------------------------------------------------------------------------
    sigaction structures, see sysdeps/unix/sysv/linux/kernel_sigaction.h
-----------------------------------------------------------------------------*/
//
// This is the sigaction structure from the Linux 2.1.20 kernel.
//
struct old_kernel_sigaction
{
    __sighandler_t k_sa_handler;
    unsigned long  sa_mask;
    unsigned long  sa_flags;
    void           (*sa_restorer) (void);
};
//
/// This is the sigaction structure from the Linux 2.1.68 kernel.
//
struct kernel_sigaction
{
    __sighandler_t k_sa_handler;
    unsigned long  sa_flags;
    void           (*sa_restorer) (void);
    sigset_t       sa_mask;
};

/*-----------------------------------------------------------------------------
    Class Definitions
-----------------------------------------------------------------------------*/
class sighand_table
{
public:
    void        grab_lock();
    void        release_lock();
    void        full_release_lock();

    sighand_table();
    sighand_table(const sighand_table& parent);
    void        reset();
    void        set_sigaction(int signum, struct sigaction* action);

    static bool is_control_flow_signal (int signo);
    static bool is_default_ignored_signal (int signo);

    pthread_mutex_t  sighand_lock;
    struct sigaction action_table[_NSIG-1];           // signal disposition rules
private:
    void init();
};


#endif /* MVEE_SIGNALS_H_ */
