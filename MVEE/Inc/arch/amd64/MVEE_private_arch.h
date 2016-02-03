/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

#ifndef MVEE_PRIVATE_ARCH_H_
#define MVEE_PRIVATE_ARCH_H_

#include <asm/unistd_64.h>
#include <sys/reg.h>

/*-----------------------------------------------------------------------------
  IP-MON Stuff
-----------------------------------------------------------------------------*/
#define MVEE_SUPPORTS_IPMON

/*-----------------------------------------------------------------------------
  SPEC PROFILES
-----------------------------------------------------------------------------*/
#define SPECPROFILENOPIE           "build_base_spec2006_MVEE_thereisnopie_amd64-nn.0000"
#define SPECPROFILEPIE             "build_base_spec2006_MVEE_pie_amd64-nn.0000"
#define SPECCONFIGNOPIE            "spec2006_MVEE_thereisnopie_amd64"
#define SPECCONFIGPIE              "spec2006_MVEE_pie_amd64"

/*-----------------------------------------------------------------------------
  MVEE LD Loader
-----------------------------------------------------------------------------*/
#define MVEE_ARCH_SUFFIX           "/amd64/"
#define MVEE_ARCH_INTERP_PATH      "/lib64/"
#define MVEE_ARCH_INTERP_NAME      "ld-linux-x86-64.so.2"
#define MVEE_LD_LOADER_PATH        "/MVEE_LD_Loader/"
#define MVEE_LD_LOADER_NAME        "MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib64_slash_ld-linux-x86-64.so.2_times_two"
// From the AMD64 ABI, Section 3.3.2:
// Although the AMD64 architecture uses 64-bit pointers, implementations are only
// required to handle 48-bit addresses. Therefore, conforming processes may only
// use addresses from 0x0000000000000000 to 0x00007fffffffffff
#define HIGHEST_USERMODE_ADDRESS   0x0000800000000000

/*-----------------------------------------------------------------------------
  PTMalloc constants
-----------------------------------------------------------------------------*/
#define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
#define HEAP_MAX_SIZE              2 * DEFAULT_MMAP_THRESHOLD_MAX

/*-----------------------------------------------------------------------------
  String Constants
-----------------------------------------------------------------------------*/
#define STDHEXSTR(w, x) std::setw(w) << std::hex << std::setfill('0') << (unsigned long)(x) << std::setfill(' ') << std::setw(0)
#define STDPTRSTR(x)    STDHEXSTR(16, x)
#define LONGPTRSTR                 "%016lx"
#define PTRSTR                     "%016lx"
#define LONGRESULTSTR              "%016ld"

/*-----------------------------------------------------------------------------
  DWARF Constants
-----------------------------------------------------------------------------*/
/* DWARF register numbers for GCC. These don't match the register nums in reg.h */
/* source: x86-64 ABI Draft 0.21 - September 13,2002 */
#define DWARF_RAX                  0
#define DWARF_RBX                  1
#define DWARF_RCX                  2
#define DWARF_RDX                  3
#define DWARF_RSI                  4
#define DWARF_RDI                  5
#define DWARF_RBP                  6
#define DWARF_RSP                  7
#define DWARF_R8                   8
#define DWARF_R9                   9
#define DWARF_R10                  10
#define DWARF_R11                  11
#define DWARF_R12                  12
#define DWARF_R13                  13
#define DWARF_R14                  14
#define DWARF_R15                  15
#define DWARF_RAR                  16  /* return address register */

/*-----------------------------------------------------------------------------
  Register selection
-----------------------------------------------------------------------------*/
#define SYSCALL_REG                "rax"
// platform independent gs_base
#define _GS_BASE(regs)                          regs.gs_base
// platform independent fastcall arg
#define FASTCALL_ARG1(regs)                     regs.rdi
// platform independent program counter selection
#define IP(regs)                                regs.rip
// platform independent stack pointer selection
#define SP(regs)                                regs.rsp
// platform independent function arg1 selection
#define FUNCTION_ARG1(regs)                     regs.rdi
//
#define SYSCALL_NO(regs)                        regs.orig_rax
// platform independent program counter fetch (through ptrace)
#define FETCH_IP(childnum, rip)                 long rip     = mvee_wrap_ptrace(PTRACE_PEEKUSER, childs[childnum].childpid, 8*RIP, NULL);
#define FETCH_IP_DIRECT(childnum, rip)          rip = mvee_wrap_ptrace(PTRACE_PEEKUSER, childs[childnum].childpid, 8*RIP, NULL);
// platform independent program counter write
#define WRITE_IP(childnum, eip)                 mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*RIP, (void*)(long)(eip));
#define WRITE_IP_PID(pid, eip)                  mvee_wrap_ptrace(PTRACE_POKEUSER, pid, 8*RIP, (void*)(eip));
// platform independent stack pointer write
#define WRITE_SP(childnum, sp)                  mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*RSP, (void*)(long)(sp));
// platform independent rdtsc result write
#define WRITE_RDTSC_RESULT(childnum, low, high)                                               \
    mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*RDX, (void*)(long)(high)); \
    mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*RAX, (void*)(long)(low));
// platform independent orig syscall no fetch
#define FETCH_SYSCALL_NO(childnum, callno)      long callno  = mvee_wrap_ptrace(PTRACE_PEEKUSER, childs[childnum].childpid, 8*ORIG_RAX, NULL);
#define FETCH_SYSCALL_NO_PID(pid, callno)       long callno  = mvee_wrap_ptrace(PTRACE_PEEKUSER, pid, 8*ORIG_RAX, NULL);
// platform independent orig syscall write (e.g. for resuming fake syscalls)
#define WRITE_SYSCALL_NO(childnum, callno)      mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*ORIG_RAX, (void*)(long)(callno));
// platform independent syscall return fetch
#define FETCH_SYSCALL_RETURN(childnum, callret) long callret = mvee_wrap_ptrace(PTRACE_PEEKUSER, childs[childnum].childpid, 8*RAX, NULL);
// platform independent new syscall write (e.g. restoring syscall no after sighandler return)
#define WRITE_NEW_SYSCALL_NO(childnum, callno)  mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*RAX, (void*)(long)(callno));
#define WRITE_SYSCALL_RETURN(childnum, callret) WRITE_NEW_SYSCALL_NO(childnum, callret)
// platform independent function argument passing
#define WRITE_FASTCALL_ARG1(childnum, arg)      mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8*RDI, (void*)(long)(arg));
#define WRITE_FASTCALL_ARG1_PID(pid, arg)       mvee_wrap_ptrace(PTRACE_POKEUSER, pid, 8*RDI, (void*)(arg));

/*-----------------------------------------------------------------------------
  Syscall argument macros
-----------------------------------------------------------------------------*/

//
// Retrieve the syscall argument of a child
//
#define ARG1(childnum)                          childs[childnum].regs.rdi
#define ARG2(childnum)                          childs[childnum].regs.rsi
#define ARG3(childnum)                          childs[childnum].regs.rdx
#define ARG4(childnum)                          childs[childnum].regs.r10
#define ARG5(childnum)                          childs[childnum].regs.r8
#define ARG6(childnum)                          childs[childnum].regs.r9

//
// Set a child's CPU register
//
#define SET_CHILD_REGISTER(childnum, reg, value)                          \
    mvee_wrap_ptrace(PTRACE_POKEUSER, childs[childnum].childpid, 8 * reg, \
                     (void*)value)

//
// Change the syscall argument of a child
//
#define SETARG1(childnum, value)                SET_CHILD_REGISTER(childnum, RDI, (long)(value))
#define SETARG2(childnum, value)                SET_CHILD_REGISTER(childnum, RSI, (long)(value))
#define SETARG3(childnum, value)                SET_CHILD_REGISTER(childnum, RDX, (long)(value))
#define SETARG4(childnum, value)                SET_CHILD_REGISTER(childnum, R10, (long)(value))
#define SETARG5(childnum, value)                SET_CHILD_REGISTER(childnum, R8, (long)(value))
#define SETARG6(childnum, value)                SET_CHILD_REGISTER(childnum, R9, (long)(value))

/*-----------------------------------------------------------------------------
  HDE Macros
-----------------------------------------------------------------------------*/
#define HDE_INS(ins)                            hde64s ins;
#define HDE_DISAS(len, textptr, insptr)         unsigned long len = hde64_disasm((const void*)(textptr), (insptr));

/*-----------------------------------------------------------------------------
  Print Registers
-----------------------------------------------------------------------------*/
#define PRINT_REG(childnum, logfunc, reg) \
    mvee::log_register(#reg, (unsigned long*)&childs[childnum].regs.reg, logfunc);

#define log_registers(childnum, logfunc)      \
    {                                         \
        childs[childnum].regs_valid = false;  \
        call_check_regs(childnum);            \
        PRINT_REG(childnum, logfunc, rax);    \
        PRINT_REG(childnum, logfunc, rbx);    \
        PRINT_REG(childnum, logfunc, rcx);    \
        PRINT_REG(childnum, logfunc, rdx);    \
        PRINT_REG(childnum, logfunc, rdi);    \
        PRINT_REG(childnum, logfunc, rsi);    \
        PRINT_REG(childnum, logfunc, rip);    \
        PRINT_REG(childnum, logfunc, eflags); \
        PRINT_REG(childnum, logfunc, rsp);    \
        PRINT_REG(childnum, logfunc, rbp);    \
        PRINT_REG(childnum, logfunc, r8);     \
        PRINT_REG(childnum, logfunc, r9);     \
        PRINT_REG(childnum, logfunc, r10);    \
        PRINT_REG(childnum, logfunc, r11);    \
        PRINT_REG(childnum, logfunc, r12);    \
        PRINT_REG(childnum, logfunc, r13);    \
        PRINT_REG(childnum, logfunc, r14);    \
        PRINT_REG(childnum, logfunc, r15);    \
    }                                         \


#endif /* MVEE_PRIVATE_ARCH_H_ */
