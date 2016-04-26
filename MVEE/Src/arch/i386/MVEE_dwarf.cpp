/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>
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
        DEF_REG(DWARF_EAX);
        DEF_REG(DWARF_ECX);
        DEF_REG(DWARF_EDX);
        DEF_REG(DWARF_EBX);
        DEF_REG(DWARF_ESP);
        DEF_REG(DWARF_EBP);
        DEF_REG(DWARF_ESI);
        DEF_REG(DWARF_EDI);
        DEF_REG(DWARF_EIP);
        DEF_REG(DWARF_EFL);
        DEF_REG(DWARF_TRAPNO);
        DEF_REG(DWARF_ST0);
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
        case DWARF_EAX: return &context->regs.eax;
        case DWARF_ECX: return &context->regs.ecx;
        case DWARF_EDX: return &context->regs.edx;
        case DWARF_EBX: return &context->regs.ebx;
        case DWARF_ESP: return &context->regs.esp;
        case DWARF_EBP: return &context->regs.ebp;
        case DWARF_ESI: return &context->regs.esi;
        case DWARF_EDI: return &context->regs.edi;
        case DWARF_EIP: return &context->regs.eip;
        case DWARF_EFL: return &context->regs.eflags;
        case DWARF_TRAPNO: return &context->regs.xss;
        case DWARF_ST0: return &context->regs.xss;
        case DW_FRAME_CFA_COL3: return &context->cfa;
    }

    return NULL;
}
