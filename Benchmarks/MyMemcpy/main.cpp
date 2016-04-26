/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program can be used to test the memcpy asm code that is injected into
    the children for the optimized reading/writing of child buffers through
    shared memory.
=============================================================================*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <errno.h>

#include "memcpy_asm.h"

int main(int argc, char *argv[])
{
    char* text = "Don't interpret addr as a hint: place the mapping at exactly that address.  addr must be a multiple of the page size.  If the memory region specified by addr and len overlaps pages of any existing mapping(s), then the overlapped part of the existing mapping(s) will be discarded.  If the specified address cannot be used, mmap() will fail. Because requiring a fixed address for a mapping is less portable, the use of this option is discouraged.";
    char* copy = (char*)calloc(strlen(text) + 1, 1);
    int len = strlen(text) + 1;
    int res;
    asm ("movl %1,%%edi;    \
          movl %2,%%esi;    \
          movl %3,%%ecx;    \
          call memcpy_asm"
         : "=a" (res)
         : "g" (copy), "g" (text), "g" (len)
         : "edi", "esi", "ecx"
         );

    printf("%s\n", copy);
    printf("0x%08X\n", res);
    printf("size: %d\n", memcpy_asm_size);
    unsigned char instr = *(unsigned char*)(memcpy_asm + memcpy_asm_size - 1);
    printf("last instr: 0x%02x\n", instr);;
}
