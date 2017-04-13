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
  Hardware Breakpoint Support
-----------------------------------------------------------------------------*/
#define MVEE_HWBP_X86

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
#define STDHEXSTR(w, x) std::setw(w) << std::hex << std::setfill('0') << (unsigned long)(x) << std::setfill(' ') << std::setw(0) << std::dec
#define STDPTRSTR(x)    STDHEXSTR(8, x)
#define LONGPTRSTR                 "%08lx"
#define PTRSTR                     "%08x"
#define LONGRESULTSTR              "%08d"
#define OBJDUMP_ARCH               "i386"
#define OBJDUMP_SUBARCH            "i386"

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
#define SYSCALL_INS_LEN            2

#define SYSCALL_NO_REG_OFFSET      (ORIG_EAX * 4)
#define SYSCALL_RETURN_REG_OFFSET  (EAX * 4)
#define SYSCALL_NEXT_REG_OFFSET    (EAX * 4
#define IP_REG_OFFSET              (EIP * 4)
#define SP_REG_OFFSET              (UESP * 4)
#define FASTCALL_ARG1_REG_OFFSET   (ECX * 4)
#define RDTSC_LOW_REG_OFFSET       (EAX * 4)
#define RDTSC_HIGH_REG_OFFSET      (EDX * 4)

#define _GS_BASE_IN_REGS(regs)        regs.gs_base
#define FASTCALL_ARG1_IN_REGS(regs)   regs.ecx
#define IP_IN_REGS(regs)              regs.eip
#define SP_IN_REGS(regs)              regs.esp
#define FUNCTION_ARG1_IN_REGS(regs)   regs.ecx
#define SYSCALL_NO_IN_REGS(regs)      regs.orig_eax
#define NEXT_SYSCALL_NO_IN_REGS(regs) regs.eax


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
#define SYSCALL_NO(variantnum)                    variants[variantnum].regs.orig_eax
#define NEXT_SYSCALL_NO(variantnum)               variants[variantnum].regs.eax

//
// Change the syscall argument of a variant
//
#define SETARG1(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, EBX * 4, (value))
#define SETARG2(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, ECX * 4, (value))
#define SETARG3(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, EDX * 4, (value))
#define SETARG4(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, ESI * 4, (value))
#define SETARG5(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, EDI * 4, (value))
#define SETARG6(variantnum, value)                interaction::write_specific_reg(variants[variantnum].variantpid, EBP * 4, (value))
#define SETSYSCALLNO(variantnum, value)           interaction::write_specific_reg(variants[variantnum].variantpid, ORIG_EAX * 4, (value))

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
