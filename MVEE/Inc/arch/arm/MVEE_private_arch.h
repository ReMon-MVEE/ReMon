/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_PRIVATE_ARCH_H_
#define MVEE_PRIVATE_ARCH_H_

#include <asm/unistd.h>
#include <sys/ucontext.h>

/*-----------------------------------------------------------------------------
  Architecture-specific features
-----------------------------------------------------------------------------*/
// #define MVEE_ARCH_SUPPORTS_IPMON
// #define MVEE_ARCH_SUPPORTS_DISASSEMBLY
// #define MVEE_ARCH_HAS_X86_HWBP
// #define MVEE_ARCH_HAS_RDTSC
// #define MVEE_ARCH_HAS_ARCH_PRCTL
#define MVEE_ARCH_HAS_PTRACE_SET_SYSCALL
#define MVEE_ARCH_USE_LIBUNWIND
#define PAGE_SIZE 4096

/*-----------------------------------------------------------------------------
  SPEC PROFILES
-----------------------------------------------------------------------------*/
#define SPECPROFILENOPIE           "build_base_spec2006_MVEE_thereisnopie_arm-nn.0000"
#define SPECPROFILEPIE             "build_base_spec2006_MVEE_pie_arm-nn.0000"
#define SPECCONFIGNOPIE            "spec2006_MVEE_thereisnopie_arm"
#define SPECCONFIGPIE              "spec2006_MVEE_pie_arm"

/*-----------------------------------------------------------------------------
  MVEE LD Loader
-----------------------------------------------------------------------------*/
#define MVEE_ARCH_SUFFIX           "/arm/"
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
#define STDHEXSTR(w, x) std::setw(w) << std::hex << std::setfill('0') << (unsigned long)(x) << std::setfill(' ') << std::setw(0) << std::dec
#define STDPTRSTR(x)    STDHEXSTR(8, x)
#define LONGPTRSTR                 "%08lx"
#define PTRSTR                     "%08lx"
#define LONGRESULTSTR              "%08ld"
#define OBJDUMP_ARCH               "arm"
#define OBJDUMP_SUBARCH            "arm"

/*-----------------------------------------------------------------------------
  DWARF Constants
-----------------------------------------------------------------------------*/
/* DWARF register numbers for GCC. These don't match the register nums in reg.h */
/* You can get these in libdwarf/dwarfdump/dwarfdump.conf */
#define DWARF_R0 0
#define DWARF_R1 1
#define DWARF_R2 2
#define DWARF_R3 3
#define DWARF_R4 4
#define DWARF_R5 5
#define DWARF_R6 6
#define DWARF_R7 7
#define DWARF_R8 8
#define DWARF_R9 9
#define DWARF_R10 10
#define DWARF_R11 11
#define DWARF_R12 12
#define DWARF_R13 13
#define DWARF_R14 14
#define DWARF_R15 15
#define DWARF_RAR 15

/*-----------------------------------------------------------------------------
  Register selection
-----------------------------------------------------------------------------*/
#define PTRACE_REGS struct user_regs

#define SYSCALL_INS_LEN            4

#define SYSCALL_NO_REG_OFFSET      (REG_R7 * 4)
#define SYSCALL_RETURN_REG_OFFSET  (REG_R0 * 4)
#define SYSCALL_NEXT_REG_OFFSET    (REG_R7 * 4)
#define IP_REG_OFFSET              (REG_R15 * 4)
#define SP_REG_OFFSET              (REG_R13 * 4)
#define FASTCALL_ARG1_REG_OFFSET   (REG_R0 * 4)

#define FASTCALL_ARG1_IN_REGS(regs)   regs.uregs[REG_R0]
#define IP_IN_REGS(regs)              regs.uregs[REG_R15]
#define SP_IN_REGS(regs)              regs.uregs[REG_R13]
#define FUNCTION_ARG1_IN_REGS(regs)   regs.uregs[REG_R0]
#define SYSCALL_NO_IN_REGS(regs)      regs.uregs[REG_R7]
#define NEXT_SYSCALL_NO_IN_REGS(regs) regs.uregs[REG_R7]

/*-----------------------------------------------------------------------------
  Syscall argument macros
-----------------------------------------------------------------------------*/

//
// Retrieve the syscall argument of a variant
//
#define ARG1(variantnum)                          variants[variantnum].regs.uregs[REG_R0]
#define ARG2(variantnum)                          variants[variantnum].regs.uregs[REG_R1]
#define ARG3(variantnum)                          variants[variantnum].regs.uregs[REG_R2]
#define ARG4(variantnum)                          variants[variantnum].regs.uregs[REG_R3]
#define ARG5(variantnum)                          variants[variantnum].regs.uregs[REG_R4]
#define ARG6(variantnum)                          variants[variantnum].regs.uregs[REG_R5]
#define SYSCALL_NO(variantnum)                    variants[variantnum].regs.uregs[REG_R7]
#define NEXT_SYSCALL_NO(variantnum)               variants[variantnum].regs.uregs[REG_R7]

//
// Change the syscall argument of a variant
//
#define SETARG1(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, REG_R0 * 4, (value))
#define SETARG2(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, REG_R1 * 4, (value))
#define SETARG3(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, REG_R2 * 4, (value))
#define SETARG4(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, REG_R3 * 4, (value))
#define SETARG5(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, REG_R4 * 4, (value))
#define SETARG6(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, REG_R5 * 4, (value))
#define SETSYSCALLNO(variantnum, value)           interaction::write_specific_reg(variants[variantnum].variantpid, REG_R7 * 4, (value))

/*-----------------------------------------------------------------------------
  Print Registers
-----------------------------------------------------------------------------*/
#define PRINT_REG(variantnum, logfunc, reg) \
    mvee::log_register(#reg, (unsigned long*)&variants[variantnum].regs.uregs[reg], logfunc);

#define log_registers(variantnum, logfunc)	\
  {						\
    variants[variantnum].regs_valid = false;	\
    call_check_regs(variantnum);		\
    PRINT_REG(variantnum, logfunc, REG_R0);	\
    PRINT_REG(variantnum, logfunc, REG_R1);	\
    PRINT_REG(variantnum, logfunc, REG_R2);	\
    PRINT_REG(variantnum, logfunc, REG_R3);	\
    PRINT_REG(variantnum, logfunc, REG_R4);	\
    PRINT_REG(variantnum, logfunc, REG_R5);	\
    PRINT_REG(variantnum, logfunc, REG_R6);	\
    PRINT_REG(variantnum, logfunc, REG_R7);	\
    PRINT_REG(variantnum, logfunc, REG_R8);	\
    PRINT_REG(variantnum, logfunc, REG_R9);	\
    PRINT_REG(variantnum, logfunc, REG_R10);	\
    PRINT_REG(variantnum, logfunc, REG_R11);	\
    PRINT_REG(variantnum, logfunc, REG_R12);	\
    PRINT_REG(variantnum, logfunc, REG_R13);	\
    PRINT_REG(variantnum, logfunc, REG_R14);	\
    PRINT_REG(variantnum, logfunc, REG_R15);	\
  }						\


#endif /* MVEE_PRIVATE_ARCH_H_ */
