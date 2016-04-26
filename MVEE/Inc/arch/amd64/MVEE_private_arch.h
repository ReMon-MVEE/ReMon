/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
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
#define FETCH_IP(variantnum, rip)                 long rip     = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 8*RIP, NULL);
#define FETCH_IP_DIRECT(variantnum, rip)          rip = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 8*RIP, NULL);
// platform independent program counter write
#define WRITE_IP(variantnum, eip)                 mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*RIP, (void*)(long)(eip));
#define WRITE_IP_PID(pid, eip)                  mvee_wrap_ptrace(PTRACE_POKEUSER, pid, 8*RIP, (void*)(eip));
// platform independent stack pointer write
#define WRITE_SP(variantnum, sp)                  mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*RSP, (void*)(long)(sp));
// platform independent rdtsc result write
#define WRITE_RDTSC_RESULT(variantnum, low, high)                                               \
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*RDX, (void*)(long)(high)); \
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*RAX, (void*)(long)(low));
// platform independent orig syscall no fetch
#define FETCH_SYSCALL_NO(variantnum, callno)      long callno  = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 8*ORIG_RAX, NULL);
#define FETCH_SYSCALL_NO_PID(pid, callno)       long callno  = mvee_wrap_ptrace(PTRACE_PEEKUSER, pid, 8*ORIG_RAX, NULL);
// platform independent orig syscall write (e.g. for resuming fake syscalls)
#define WRITE_SYSCALL_NO(variantnum, callno)      mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*ORIG_RAX, (void*)(long)(callno));
// platform independent syscall return fetch
#define FETCH_SYSCALL_RETURN(variantnum, callret) long callret = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 8*RAX, NULL);
// platform independent new syscall write (e.g. restoring syscall no after sighandler return)
#define WRITE_NEW_SYSCALL_NO(variantnum, callno)  mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*RAX, (void*)(long)(callno));
#define WRITE_SYSCALL_RETURN(variantnum, callret) WRITE_NEW_SYSCALL_NO(variantnum, callret)
// platform independent function argument passing
#define WRITE_FASTCALL_ARG1(variantnum, arg)      mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8*RDI, (void*)(long)(arg));
#define WRITE_FASTCALL_ARG1_PID(pid, arg)       mvee_wrap_ptrace(PTRACE_POKEUSER, pid, 8*RDI, (void*)(arg));

/*-----------------------------------------------------------------------------
  Syscall argument macros
-----------------------------------------------------------------------------*/

//
// Retrieve the syscall argument of a variant
//
#define ARG1(variantnum)                          variants[variantnum].regs.rdi
#define ARG2(variantnum)                          variants[variantnum].regs.rsi
#define ARG3(variantnum)                          variants[variantnum].regs.rdx
#define ARG4(variantnum)                          variants[variantnum].regs.r10
#define ARG5(variantnum)                          variants[variantnum].regs.r8
#define ARG6(variantnum)                          variants[variantnum].regs.r9

//
// Set a variant's CPU register
//
#define SET_VARIANT_REGISTER(variantnum, reg, value)                          \
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 8 * reg, \
                     (void*)value)

//
// Change the syscall argument of a variant
//
#define SETARG1(variantnum, value)                SET_VARIANT_REGISTER(variantnum, RDI, (long)(value))
#define SETARG2(variantnum, value)                SET_VARIANT_REGISTER(variantnum, RSI, (long)(value))
#define SETARG3(variantnum, value)                SET_VARIANT_REGISTER(variantnum, RDX, (long)(value))
#define SETARG4(variantnum, value)                SET_VARIANT_REGISTER(variantnum, R10, (long)(value))
#define SETARG5(variantnum, value)                SET_VARIANT_REGISTER(variantnum, R8, (long)(value))
#define SETARG6(variantnum, value)                SET_VARIANT_REGISTER(variantnum, R9, (long)(value))

/*-----------------------------------------------------------------------------
  HDE Macros
-----------------------------------------------------------------------------*/
#define HDE_INS(ins)                            hde64s ins;
#define HDE_DISAS(len, textptr, insptr)         unsigned long len = hde64_disasm((const void*)(textptr), (insptr));

/*-----------------------------------------------------------------------------
  Print Registers
-----------------------------------------------------------------------------*/
#define PRINT_REG(variantnum, logfunc, reg) \
    mvee::log_register(#reg, (unsigned long*)&variants[variantnum].regs.reg, logfunc);

#define log_registers(variantnum, logfunc)			\
    {												\
        variants[variantnum].regs_valid = false;	\
        call_check_regs(variantnum);				\
        PRINT_REG(variantnum, logfunc, rax);		\
        PRINT_REG(variantnum, logfunc, rbx);		\
        PRINT_REG(variantnum, logfunc, rcx);		\
        PRINT_REG(variantnum, logfunc, rdx);		\
        PRINT_REG(variantnum, logfunc, rdi);		\
        PRINT_REG(variantnum, logfunc, rsi);		\
        PRINT_REG(variantnum, logfunc, rip);		\
        PRINT_REG(variantnum, logfunc, eflags);		\
        PRINT_REG(variantnum, logfunc, rsp);		\
        PRINT_REG(variantnum, logfunc, rbp);		\
        PRINT_REG(variantnum, logfunc, r8);			\
        PRINT_REG(variantnum, logfunc, r9);			\
        PRINT_REG(variantnum, logfunc, r10);		\
        PRINT_REG(variantnum, logfunc, r11);		\
        PRINT_REG(variantnum, logfunc, r12);		\
        PRINT_REG(variantnum, logfunc, r13);		\
        PRINT_REG(variantnum, logfunc, r14);		\
        PRINT_REG(variantnum, logfunc, r15);		\
    }												\


#endif /* MVEE_PRIVATE_ARCH_H_ */
