/* This file is based on code copied from the internals of dyninst, which is licensed as follows: */

/*
 * See the dyninst/COPYRIGHT file for copyright information.
 * 
 * We provide the Paradyn Tools (below described as "Paradyn")
 * on an AS IS basis, and do not warrant its validity or performance.
 * We reserve the right to update, modify, or discontinue this
 * software at any time.  We shall have no obligation to supply such
 * updates or modifications or any other form of support to you.
 * 
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_basicBlock.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_object.h"

#include "liveness.h"

#include "PatchMgr.h"
#include "PatchModifier.h"
#include "Point.h"
#include "Snippet.h"

#include "BinaryFunction.h"
#include "Dereference.h"
#include "Immediate.h"

#include "dyninst-internals.h"

/* from snippetGen.c */
BPatch_snippet *findRegister(BPatch_binaryEdit* addrspace, const char *name){
    std::vector<BPatch_register> registers;

   if(!addrspace->getRegisters(registers)){
      printf("Could not retrive registers. Register access may not be available on this platform.\n");
      return NULL;
   }

   for(unsigned int i = 0; i < registers.size(); i++){
      BPatch_register r = registers[i];
      if(r.name() == name){
         return new BPatch_registerExpr(r);
      }
   }

   printf("Register %s not found\n", name);
   return NULL;
}

/* from emit-x86.C */
void emitRex(bool is_64, Register* r, Register* x, Register* b, Buffer &gen)
{
    unsigned char rex = 0x40;

    // need rex for 64-bit ops in most cases
    if (is_64)
       rex |= 0x08;

    // need rex for use of new registers
    // if a new register is used, we mask off the high bit before
    // returning since we account for it in the rex prefix

    // "R" register - extension to ModRM reg field
    if (r && *r & 0x08) {
       rex |= 0x04;
       *r &= 0x07;
    }

    // "X" register - extension to SIB index field
    if (x && *x & 0x08) {
       rex |= 0x02;
       *x &= 0x07;
    }

    // "B" register - extension to ModRM r/m field, SIB base field,
    // or opcode reg field
    if (b && *b & 0x08) {
       rex |= 0x01;
       *b &= 0x07;
    }

    // emit the rex, if needed
    // (note that some other weird cases not covered here
    //  need a "blank" rex, like using %sil or %dil)
    if (rex & 0x0f)
       gen.push_back(uint8_t{rex});
}

/* TODO: from inst-x86.C */
/* 
   Emit the ModRM byte and displacement for addressing modes.
   base is a register (EAX, ECX, REGNUM_EDX, EBX, EBP, REGNUM_ESI, REGNUM_EDI)
   disp is a displacement
   reg_opcode is either a register or an opcode
*/
void emitAddressingMode(unsigned base, RegValue disp,
                        unsigned reg_opcode, Buffer& gen)
{
   // MT linux uses ESP+4
   // we need an SIB in that case
   if (base == REGNUM_ESP) {
      emitAddressingMode(REGNUM_ESP, Null_Register, 0, disp, reg_opcode, gen);
      return;
   }

   if (base == Null_Register) {
      gen.push_back(makeModRMbyte(0, reg_opcode, 5));
      gen.push_back(uint32_t{disp});
   } else if (disp == 0 && base != REGNUM_EBP) {
      gen.push_back(makeModRMbyte(0, reg_opcode, base));
   } else if (disp >= -128 && disp <= 127) {
      gen.push_back(makeModRMbyte(1, reg_opcode, base));
      gen.push_back(uint8_t{disp});
   } else {
      gen.push_back(makeModRMbyte(2, reg_opcode, base));
      gen.push_back(uint32_t{disp});
   }
}

/* from inst-x86.C */
// VG(7/30/02): emit a fully fledged addressing mode: base+index<<scale+disp
void emitAddressingMode(unsigned base, unsigned index,
                        unsigned int scale, RegValue disp,
                        int reg_opcode, Buffer& gen)
{
   bool needSIB = (base == REGNUM_ESP) || (index != Null_Register);

   if(!needSIB) {
      emitAddressingMode(base, disp, reg_opcode, gen);
      return;
   }

   // This isn't true for AMD-64...
   //assert(index != REGNUM_ESP);

   if(index == Null_Register) {
      assert(base == REGNUM_ESP); // not necessary, but sane
      index = 4;           // (==REGNUM_ESP) which actually means no index in SIB
   }

   if(base == Null_Register) { // we have to emit [index<<scale+disp32]
      gen.push_back(makeModRMbyte(0, reg_opcode, 4));
      gen.push_back(makeSIBbyte(scale, index, 5));
      gen.push_back(uint32_t{disp});
   }
   else if(disp == 0 && base != REGNUM_EBP) { // EBP must have 0 disp8; emit [base+index<<scale]
       gen.push_back(makeModRMbyte(0, reg_opcode, 4));
       gen.push_back(makeSIBbyte(scale, index, base));
   }
   else if (disp >= -128 && disp <= 127) { // emit [base+index<<scale+disp8]
      gen.push_back(makeModRMbyte(1, reg_opcode, 4));
      gen.push_back(makeSIBbyte(scale, index, base));
      gen.push_back(uint8_t{disp});
   }
   else { // emit [base+index<<scale+disp32]
      gen.push_back(makeModRMbyte(2, reg_opcode, 4));
      gen.push_back(makeSIBbyte(scale, index, base));
      gen.push_back(uint32_t{disp});
   }
}

/* from inst-x86.C */
// VG(07/30/02): Emit a lea dest, [base + index * scale + disp]; dest is a
// real GPR
void emitLEA(RealRegister base, RealRegister index, unsigned int scale,
             RegValue disp, RealRegister dest, Buffer &gen)
{
   gen.push_back(uint8_t{0x8D});
   emitAddressingMode(base, index, scale, disp, dest, gen);
}


/* from emit-x86.C */
void emitLEA64Bit(Register base, Register index, unsigned int scale, int disp, Register dest, Buffer& gen)
{
    Register tmp_base = base;
    Register tmp_index = index;
    Register tmp_dest = dest;
    emitRex(/*is_64*/true, &tmp_dest,
	    tmp_index == Null_Register ? NULL : &tmp_index,
	    tmp_base == Null_Register ? NULL : &tmp_base,
	    gen);
   emitLEA(RealRegister(tmp_base), RealRegister(tmp_index), scale, disp,
            RealRegister(tmp_dest), gen);
}

