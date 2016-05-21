/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <new>
#include <sys/ptrace.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_memory.h"

/*-----------------------------------------------------------------------------
    mvee_rw_safe_alloc
-----------------------------------------------------------------------------*/
unsigned char* mvee_rw_safe_alloc(long alloc_size)
{
    unsigned char* result = NULL;
    try
    {
        result = new unsigned char[alloc_size];
    }
    catch (std::bad_alloc& ba)
    {
        fprintf(stderr, "mvee_rw_safe_alloc - bad allocation: %s\n", ba.what());
    }
    return result;
}

/*-----------------------------------------------------------------------------
    mvee_rw_write_... - ptrace can only read/write word-sized values but
    sometimes we need to write a smaller value and we must avoid overwriting the
    rest of the word when doing so
-----------------------------------------------------------------------------*/
void mvee_rw_write_uchar(pid_t pid, unsigned long addr, unsigned char val)
{
	mvee_word word;
	word._long  = mvee_wrap_ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	word._uchar = val;
	mvee_wrap_ptrace(PTRACE_POKEDATA, pid, addr, (void*)word._long);
}

void mvee_rw_write_ushort(pid_t pid, unsigned long addr, unsigned short val)
{
	mvee_word word;
	word._long  = mvee_wrap_ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	word._ushort = val;
	mvee_wrap_ptrace(PTRACE_POKEDATA, pid, addr, (void*)word._long);
}

void mvee_rw_write_uint(pid_t pid, unsigned long addr, unsigned int val)
{
	mvee_word word;
	word._long  = mvee_wrap_ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	word._uint   = val;
	mvee_wrap_ptrace(PTRACE_POKEDATA, pid, addr, (void*)word._long);
}

void mvee_rw_write_pid(pid_t pid, unsigned long addr, pid_t val)
{
	mvee_word word;
	word._long  = mvee_wrap_ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	word._pid   = val;
	mvee_wrap_ptrace(PTRACE_POKEDATA, pid, addr, (void*)word._long);
}

#ifdef MVEE_HAVE_MVEE_KERNEL
  #include "MVEE_memory_MVEE_kernel.h"
#else
  #include "MVEE_memory_stock_kernel.h"
#endif
