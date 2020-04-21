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
  Architecture-specific features
-----------------------------------------------------------------------------*/
//
// MVEE_ARCH_SUPPORTS_IPMON: if this is defined, we allow the variants to 
// load and initialize IP-MON via sys_prctl.
//
#define MVEE_ARCH_SUPPORTS_IPMON

//
// MVEE_ARCH_SUPPORTS_DISASSEMBLY: we define this if we can disassemble
// executable code for this architecture. We currently only support disassembly
// on AMD64 and i386. We primarily use this disassembly feature to calculate the
// lengths of instructions that caused certain events requiring monitor
// intervention (e.g., syscall traps, segmentation faults, ...)  Calculating the
// instruction length allows us to skip specific instructions.
//
#define MVEE_ARCH_SUPPORTS_DISASSEMBLY

//
// MVEE_ARCH_HAS_X86_HWBP: this is defined if we have hardware breakpoint
// support for this architecture.
//
#define MVEE_ARCH_HAS_X86_HWBP

//
// MVEE_ARCH_HAS_RDTSC: this is defined if this architecture has a Read
// TimeStamp Counter (RDTSC) instruction that can be disabled by the monitor.
// If we disable RDTSC, then any attempt to execute this instruction will
// result in a trap.
//
#define MVEE_ARCH_HAS_RDTSC

//
// MVEE_ARCH_HAS_ARCH_PRCTL: this is defined if this architecture implements
// sys_arch_prctl. This syscall is currently only used to set/get the fs/gs
// segment bases on x86.
//
#define MVEE_ARCH_HAS_ARCH_PRCTL

// 
// MVEE_ARCH_HAS_VSYSCALL: this is defined if this architecture has a vsyscall
// page that might need to be disabled. NOTE: the vsyscall page is the older
// version of the VDSO.  vsyscall and vdso coexist on AMD64. i386 uses only the
// vdso page.
//
#define MVEE_ARCH_HAS_VSYSCALL

//
// MVEE_ARCH_HAS_YAMA_LSM: this is defined if this architecture is expected to
// be using the Yama Linux Security Modules. Yama has an annoying ptrace bug
// that prevents us from monitoring variant subprocesses whose parent process
// has died.
// More info here: https://lkml.org/lkml/2014/12/24/196
//
#define MVEE_ARCH_HAS_YAMA_LSM

//
// MVEE_ARCH_HAS_VDSO: this is defined if this architecture has a Virtual
// Dynamic Shared Object (VDSO) page that implements user-space syscalls.
// The user-space syscalls exposed by the VDSO are not reported to the monitor
// and must therefore be disabled if we want to give equivalent input
// to all variants.
//
#define MVEE_ARCH_HAS_VDSO

// 
// MVEE_ARCH_REG_TYPE: primitive type of the register fields in the
// user_regs_struct. These are the structs we read using PTRACE_GETREGS.
//
#define MVEE_ARCH_REG_TYPE unsigned long long

//
// MVEE_ARCH_IS_64BIT: defined on 64-bit architectures. On 64-bit archs, we
// don't need to do any fancy register shifting for syscalls that accept
// unsigned long long arguments.
//
#define MVEE_ARCH_IS_64BIT

//
// MVEE_ARCH_LITTLE_ENDIAN: defined on little-endian architectures. The
// endianness of the platform affects how we do register shifting for syscalls
// that accept unsigned long long arguments.
//
#define MVEE_ARCH_LITTLE_ENDIAN

//
// MVEE_ARCH_ALWAYS_USE_LD_LOADER: this is defined if we always want to load
// variants indirectly using the LD Loader. Normally, the LD Loader is
// only used if we want to hide the VDSO or if we want to apply Disjoint
// Code Layouts.
//
#define MVEE_ARCH_ALWAYS_USE_LD_LOADER

//
// the base constant from which all fake syscall numbers used by the monitor
// are derived
//
#define MVEE_FAKE_SYSCALL_BASE   0x6FFFFFFF

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
#define MVEE_LD_LOADER_BASE        0x10000000
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
#define STDHEXSTR(w, x) std::setw(w) << std::hex << std::setfill('0') << (unsigned long)(x) << std::setfill(' ') << std::setw(0) << std::dec
#define STDPTRSTR(x)    STDHEXSTR(16, x)
#define LONGPTRSTR                 "%016lx"
#define PTRSTR                     "%016lx"
#define LONGRESULTSTR              "%016ld"
#define OBJDUMP_ARCH               "i386"
#define OBJDUMP_SUBARCH            "x86-64"
#define MVEE_ARCH_FIND_ATOMIC_OPS_STRING "egrep \"lock |xchg|mvee\\_atomic\" | grep -v \"xchg *%[a-z0-9]*,%[a-z0-9]*$\""

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
#define PTRACE_REGS   struct user_regs_struct
#define PTRACE_FPREGS struct user_fpregs_struct
#define SYSCALL_INS_LEN            2

//
// Offsets in user_regs_struct
//
#define SYSCALL_NO_REG_OFFSET      (ORIG_RAX * 8)
#define SYSCALL_RETURN_REG_OFFSET  (RAX * 8)
#define SYSCALL_NEXT_REG_OFFSET    (RAX * 8)
#define IP_REG_OFFSET              (RIP * 8)
#define SP_REG_OFFSET              (RSP * 8)
#define FASTCALL_ARG1_REG_OFFSET   (RDI * 8)
#define RDTSC_LOW_REG_OFFSET       (RAX * 8)
#define RDTSC_HIGH_REG_OFFSET      (RDX * 8)

// platform independent fastcall arg
#define FASTCALL_ARG1_IN_REGS(regs)                     regs.rdi
// platform independent program counter selection
#define IP_IN_REGS(regs)                                regs.rip
// platform independent stack pointer selection
#define SP_IN_REGS(regs)                                regs.rsp
// platform independent function arg1 selection
#define FUNCTION_ARG1_IN_REGS(regs)                     regs.rdi
// platform independent syscall no selection
#define SYSCALL_NO_IN_REGS(regs)                        regs.orig_rax
// platform independent next syscall no selection
#define NEXT_SYSCALL_NO_IN_REGS(regs)                   regs.rax

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
#define SYSCALL_NO(variantnum)                    variants[variantnum].regs.orig_rax
#define NEXT_SYSCALL_NO(variantnum)               variants[variantnum].regs.rax

//
// Change the syscall argument of a variant
//
#define SETARG1(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, RDI * 8, (long)(value))
#define SETARG2(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, RSI * 8, (long)(value))
#define SETARG3(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, RDX * 8, (long)(value))
#define SETARG4(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, R10 * 8, (long)(value))
#define SETARG5(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, R8 * 8, (long)(value))
#define SETARG6(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, R9 * 8, (long)(value))
#define SETSYSCALLNO(variantnum, value)           interaction::write_specific_reg(variants[variantnum].variantpid, ORIG_RAX * 8, (long)(value))

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

#define PRINT_REG_DIRECT(regs, logfunc, reg) \
    mvee::log_register(#reg, (unsigned long*)&regs.reg, logfunc);

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

#define log_registers_direct(regs, logfunc)			\
    {												\
        PRINT_REG_DIRECT(regs, logfunc, rax);		\
        PRINT_REG_DIRECT(regs, logfunc, rbx);		\
        PRINT_REG_DIRECT(regs, logfunc, rcx);		\
        PRINT_REG_DIRECT(regs, logfunc, rdx);		\
        PRINT_REG_DIRECT(regs, logfunc, rdi);		\
        PRINT_REG_DIRECT(regs, logfunc, rsi);		\
        PRINT_REG_DIRECT(regs, logfunc, rip);		\
        PRINT_REG_DIRECT(regs, logfunc, eflags);	\
        PRINT_REG_DIRECT(regs, logfunc, rsp);		\
        PRINT_REG_DIRECT(regs, logfunc, rbp);		\
        PRINT_REG_DIRECT(regs, logfunc, r8);		\
        PRINT_REG_DIRECT(regs, logfunc, r9);		\
        PRINT_REG_DIRECT(regs, logfunc, r10);		\
        PRINT_REG_DIRECT(regs, logfunc, r11);		\
        PRINT_REG_DIRECT(regs, logfunc, r12);		\
        PRINT_REG_DIRECT(regs, logfunc, r13);		\
        PRINT_REG_DIRECT(regs, logfunc, r14);		\
        PRINT_REG_DIRECT(regs, logfunc, r15);		\
    }												\



#endif /* MVEE_PRIVATE_ARCH_H_ */
