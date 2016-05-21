/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_PRIVATE_ARCH_H_
#define MVEE_PRIVATE_ARCH_H_

#include <asm/unistd_32.h>
#include <sys/reg.h>

/*-----------------------------------------------------------------------------
  IP-MON Stuff
-----------------------------------------------------------------------------*/
//#define MVEE_SUPPORTS_IPMON

/*-----------------------------------------------------------------------------
  SPEC PROFILES
-----------------------------------------------------------------------------*/
#define SPECPROFILENOPIE           "build_base_spec2006_MVEE_thereisnopie_i386-nn.0000"
#define SPECPROFILEPIE             "build_base_spec2006_MVEE_pie_i386-nn.0000"
#define SPECCONFIGNOPIE            "spec2006_MVEE_thereisnopie_i386"
#define SPECCONFIGPIE              "spec2006_MVEE_pie_i386"

/*-----------------------------------------------------------------------------
  MVEE LD Loader
-----------------------------------------------------------------------------*/
#define MVEE_ARCH_SUFFIX           "/i386/"
#define MVEE_ARCH_INTERP_PATH      "/lib/"
#define MVEE_ARCH_INTERP_NAME      "ld-linux.so.2"
#define MVEE_LD_LOADER_PATH        "/MVEE_LD_Loader/"
#define MVEE_LD_LOADER_NAME        "MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux.so.2_times_two"
// Assuming the 3G/1G split...
#define HIGHEST_USERMODE_ADDRESS   0xc0000000

/*-----------------------------------------------------------------------------
  PTMalloc constants
-----------------------------------------------------------------------------*/
#define DEFAULT_MMAP_THRESHOLD_MAX (512 * 1024)
#define HEAP_MAX_SIZE              2 * DEFAULT_MMAP_THRESHOLD_MAX

/*-----------------------------------------------------------------------------
  String Constants
-----------------------------------------------------------------------------*/
#define STDHEXSTR(w, x) std::setw(w) << std::hex << std::setfill('0') << (unsigned long)(x) << std::setfill(' ') << std::setw(0)
#define STDPTRSTR(x)    STDHEXSTR(8, x)
#define LONGPTRSTR                 "%08lx"
#define PTRSTR                     "%08x"
#define LONGRESULTSTR              "%08d"

/*-----------------------------------------------------------------------------
  DWARF Constants
-----------------------------------------------------------------------------*/
/* DWARF register numbers for GCC. These don't match the register nums in reg.h */
#define DWARF_EAX                  0
#define DWARF_ECX                  1
#define DWARF_EDX                  2
#define DWARF_EBX                  3
#define DWARF_ESP                  4
#define DWARF_EBP                  5
#define DWARF_ESI                  6
#define DWARF_EDI                  7
#define DWARF_EIP                  8
#define DWARF_EFL                  9
#define DWARF_TRAPNO               10
#define DWARF_ST0                  11
#define DWARF_RAR                  12  /* return address register */

/*-----------------------------------------------------------------------------
  Register selection
-----------------------------------------------------------------------------*/
#define SYSCALL_REG                "eax"
#define _GS_BASE(regs)                          regs.gs_base
#define FASTCALL_ARG1(regs)                     regs.ecx
#define IP(regs)                                regs.eip
#define SP(regs)                                regs.esp
#define FUNCTION_ARG1(regs)                     regs.ecx
#define SYSCALL_NO(regs)                        regs.orig_eax
#define FETCH_IP(variantnum, eip)                 int eip      = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 4*EIP, NULL);
#define FETCH_IP_DIRECT(variantnum, eip)          eip = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 4*EIP, NULL);
#define WRITE_IP(variantnum, eip)                 mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*EIP, (void*)(eip));
#define WRITE_IP_PID(pid, eip)                  mvee_wrap_ptrace(PTRACE_POKEUSER, pid, 4*EIP, (void*)(eip));
#define WRITE_SP(variantnum, eip)                 mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*UESP, (void*)(eip));
#define WRITE_RDTSC_RESULT(variantnum, low, high)                                       \
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*EDX, (void*)high); \
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*EAX, (void*)low);
#define FETCH_SYSCALL_NO(variantnum, callno)      long callno  = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 4*ORIG_EAX, NULL);
#define FETCH_SYSCALL_NO_PID(pid, callno)       long callno  = mvee_wrap_ptrace(PTRACE_PEEKUSER, pid, 4*ORIG_EAX, NULL);
#define FETCH_SYSCALL_RETURN(variantnum, callret) long callret = mvee_wrap_ptrace(PTRACE_PEEKUSER, variants[variantnum].variantpid, 4*EAX, NULL);
#define WRITE_SYSCALL_NO(variantnum, callno)      mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*ORIG_EAX, (void*)(callno));
#define WRITE_NEW_SYSCALL_NO(variantnum, callno)  mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*EAX, (void*)(callno));
#define WRITE_SYSCALL_RETURN(variantnum, callret) WRITE_NEW_SYSCALL_NO(variantnum, callret)
#define WRITE_FASTCALL_ARG1(variantnum, arg)      mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4*ECX, (void*)(arg));
#define WRITE_FASTCALL_ARG1_PID(pid, arg)       mvee_wrap_ptrace(PTRACE_POKEUSER, pid, 4*ECX, (void*)(arg));

/*-----------------------------------------------------------------------------
  Syscall argument macros
-----------------------------------------------------------------------------*/

//
// Retrieve the syscall argument of a variant
//
#define ARG1(variantnum)                          variants[variantnum].regs.ebx
#define ARG2(variantnum)                          variants[variantnum].regs.ecx
#define ARG3(variantnum)                          variants[variantnum].regs.edx
#define ARG4(variantnum)                          variants[variantnum].regs.esi
#define ARG5(variantnum)                          variants[variantnum].regs.edi
#define ARG6(variantnum)                          variants[variantnum].regs.ebp
#define ORIGARG1(variantnum)                      variants[variantnum].orig_arg1

//
// Set a variant's CPU register
//
#define SET_VARIANT_REGISTER(variantnum, reg, value)						\
    mvee_wrap_ptrace(PTRACE_POKEUSER, variants[variantnum].variantpid, 4 * reg, \
                     (void*)value)

//
// Change the syscall argument of a variant
//
#define SETARG1(variantnum, value)                SET_VARIANT_REGISTER(variantnum, EBX, (value))
#define SETARG2(variantnum, value)                SET_VARIANT_REGISTER(variantnum, ECX, (value))
#define SETARG3(variantnum, value)                SET_VARIANT_REGISTER(variantnum, EDX, (value))
#define SETARG4(variantnum, value)                SET_VARIANT_REGISTER(variantnum, ESI, (value))
#define SETARG5(variantnum, value)                SET_VARIANT_REGISTER(variantnum, EDI, (value))
#define SETARG6(variantnum, value)                SET_VARIANT_REGISTER(variantnum, EBP, (value))

/*-----------------------------------------------------------------------------
  HDE Macros
-----------------------------------------------------------------------------*/
#define HDE_INS(ins)                            hde32s ins;
#define HDE_DISAS(len, textptr, insptr)         unsigned long len = hde32_disasm((const void*)(textptr), (insptr));

/*-----------------------------------------------------------------------------
  Print Registers
-----------------------------------------------------------------------------*/
#define PRINT_REG(variantnum, logfunc, reg) \
    mvee::log_register(#reg, (unsigned long*)&variants[variantnum].regs.reg, logfunc);

#define log_registers(variantnum, logfunc)			\
    {												\
        variants[variantnum].regs_valid = false;	\
        call_check_regs(variantnum);				\
        PRINT_REG(variantnum, logfunc, eax);		\
        PRINT_REG(variantnum, logfunc, ebx);		\
        PRINT_REG(variantnum, logfunc, ecx);		\
        PRINT_REG(variantnum, logfunc, edx);		\
        PRINT_REG(variantnum, logfunc, edi);		\
        PRINT_REG(variantnum, logfunc, esi);		\
        PRINT_REG(variantnum, logfunc, eip);		\
        PRINT_REG(variantnum, logfunc, eflags);		\
        PRINT_REG(variantnum, logfunc, esp);		\
        PRINT_REG(variantnum, logfunc, ebp);		\
    }												\


#endif /* MVEE_PRIVATE_ARCH_H_ */
