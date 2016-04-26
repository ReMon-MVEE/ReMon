/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>
#include "MVEE.h"
#include "MVEE_logging.h"
#include "MVEE_mman.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
    getTextualDWARFReg
-----------------------------------------------------------------------------*/
const char* getTextualDWARFReg(int reg)
{
    const char* result = "(unknown)";

  #define DEF_REG(a) \
    case a:          \
        result = #a; \
        break;

    switch(reg)
    {
        DEF_REG(DWARF_R8);
        DEF_REG(DWARF_R9);
        DEF_REG(DWARF_R10);
        DEF_REG(DWARF_R11);
        DEF_REG(DWARF_R12);
        DEF_REG(DWARF_R13);
        DEF_REG(DWARF_R14);
        DEF_REG(DWARF_R15);
        DEF_REG(DWARF_RDI);
        DEF_REG(DWARF_RSI);
        DEF_REG(DWARF_RBP);
        DEF_REG(DWARF_RBX);
        DEF_REG(DWARF_RDX);
        DEF_REG(DWARF_RAX);
        DEF_REG(DWARF_RCX);
        DEF_REG(DWARF_RSP);
        DEF_REG(DWARF_RAR);
        DEF_REG(DW_FRAME_CFA_COL3);
        DEF_REG(DW_FRAME_UNDEFINED_VAL);
        DEF_REG(DW_FRAME_SAME_VAL);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    mvee_mman_dwarf_select_dwarf_reg
-----------------------------------------------------------------------------*/
long int* mmap_table::select_dwarf_reg(mvee_dwarf_context* context, int dwarf_reg)
{
    switch(dwarf_reg)
    {
        case DWARF_R8: return (long int*)&context->regs.r8;
        case DWARF_R9: return (long int*)&context->regs.r9;
        case DWARF_R10: return (long int*)&context->regs.r10;
        case DWARF_R11: return (long int*)&context->regs.r11;
        case DWARF_R12: return (long int*)&context->regs.r12;
        case DWARF_R13: return (long int*)&context->regs.r13;
        case DWARF_R14: return (long int*)&context->regs.r14;
        case DWARF_R15: return (long int*)&context->regs.r15;
        case DWARF_RDI: return (long int*)&context->regs.rdi;
        case DWARF_RSI: return (long int*)&context->regs.rsi;
        case DWARF_RBP: return (long int*)&context->regs.rbp;
        case DWARF_RBX: return (long int*)&context->regs.rbx;
        case DWARF_RDX: return (long int*)&context->regs.rdx;
        case DWARF_RAX: return (long int*)&context->regs.rax;
        case DWARF_RCX: return (long int*)&context->regs.rcx;
        case DWARF_RSP: return (long int*)&context->regs.rsp;
        case DWARF_RAR: return (long int*)&context->regs.rip;
        case DW_FRAME_CFA_COL3: return (long int*)&context->cfa;
    }
    return NULL;
}

