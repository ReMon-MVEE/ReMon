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
        DEF_REG(DWARF_R0);
	DEF_REG(DWARF_R1);
	DEF_REG(DWARF_R2);
	DEF_REG(DWARF_R3);
	DEF_REG(DWARF_R4);
	DEF_REG(DWARF_R5);
	DEF_REG(DWARF_R6);
	DEF_REG(DWARF_R7);
	DEF_REG(DWARF_R8);
	DEF_REG(DWARF_R9);	
        DEF_REG(DWARF_R10);
	DEF_REG(DWARF_R11);
	DEF_REG(DWARF_R12);
	DEF_REG(DWARF_R13);
	DEF_REG(DWARF_R14);	
        DEF_REG(DWARF_R15);
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
    case DWARF_R0: return (long int*)&context->regs.uregs[REG_R0];
    case DWARF_R1: return (long int*)&context->regs.uregs[REG_R1];
    case DWARF_R2: return (long int*)&context->regs.uregs[REG_R2];
    case DWARF_R3: return (long int*)&context->regs.uregs[REG_R3];
    case DWARF_R4: return (long int*)&context->regs.uregs[REG_R4];
    case DWARF_R5: return (long int*)&context->regs.uregs[REG_R5];
    case DWARF_R6: return (long int*)&context->regs.uregs[REG_R6];
    case DWARF_R7: return (long int*)&context->regs.uregs[REG_R7];
    case DWARF_R8: return (long int*)&context->regs.uregs[REG_R8];
    case DWARF_R9: return (long int*)&context->regs.uregs[REG_R9];
    case DWARF_R10: return (long int*)&context->regs.uregs[REG_R10];
    case DWARF_R11: return (long int*)&context->regs.uregs[REG_R11];
    case DWARF_R12: return (long int*)&context->regs.uregs[REG_R12];
    case DWARF_R13: return (long int*)&context->regs.uregs[REG_R13];
    case DWARF_R14: return (long int*)&context->regs.uregs[REG_R14];
    case DWARF_R15: return (long int*)&context->regs.uregs[REG_R15];      
    case DW_FRAME_CFA_COL3: return (long int*)&context->cfa;
    }
    return NULL;
}

