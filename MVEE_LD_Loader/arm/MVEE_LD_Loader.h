/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include "/usr/include/arm-linux-gnueabihf/asm/unistd.h"

#define INTERP              "/lib/ld-linux-armhf.so.3"
#define INTERP_SHORT        "MVEE Variant %d >"
#define INTERP_ARCH         "arm"

//#define MVEE_HIDE_DSO
//#define MVEE_DEBUG
#define MVEE_USE_MVEE_LD

typedef Elf32_auxv_t Elf_auxv_t;
typedef Elf32_Ehdr   Elf_Ehdr;
typedef Elf32_Addr   Elf_Addr;
typedef Elf32_Phdr   Elf_Phdr;
typedef Elf32_Off    Elf_Off;

#define PTRSTR              "%08x"
#define LONGINTSTR          "%ld"

#define REAL_AT_PHDR_OFFSET 0x34
#define REAL_AT_PHENT       32

#define ARCH_JMP_TO_LD(new_sp, new_entry)		\
    __asm__ __volatile__						\
    (											\
		"mov %%r0, %0\n\t"						\
        "mov %%r13, %0\n\t"						\
        "bx %1\n\t"								\
        :: "g" (new_sp), "r" (new_entry) :)


#define FSTAT_NO            __NR_fstat64
#define MVEE_FAKE_SYSCALL_BASE 0x6FF
