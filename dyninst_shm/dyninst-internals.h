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

// General definitions
typedef uint8_t Register;
typedef Register RealRegister; // not really but ok for me here
typedef uint32_t RegValue; // Sounds good? :-) For immediates in lea

static const Register Null_Register = (Register)(-1);

/* from arch-x86.h */
// 32-bit
#define REGNUM_EAX 0
#define REGNUM_ECX 1
#define REGNUM_EDX 2
#define REGNUM_EBX 3
#define REGNUM_ESP 4
#define REGNUM_EBP 5
#define REGNUM_ESI 6
#define REGNUM_EDI 7

/* from arch-x86.h */
// 64-bit
enum AMD64_REG_NUMBERS {
    REGNUM_RAX = 0,
    REGNUM_RCX,
    REGNUM_RDX,
    REGNUM_RBX,
    REGNUM_RSP,
    REGNUM_RBP,
    REGNUM_RSI,
    REGNUM_RDI,
    REGNUM_R8,
    REGNUM_R9,
    REGNUM_R10,
    REGNUM_R11,
    REGNUM_R12,
    REGNUM_R13,
    REGNUM_R14,
    REGNUM_R15,
};


BPatch_snippet *findRegister(BPatch_binaryEdit* addrspace, const char *name); /* from snippetGen.c */
void emitRex(bool is_64, Register* r, Register* x, Register* b, Buffer &gen); /* from emit-x86.C */
void emitAddressingMode(unsigned base, unsigned index,
                        unsigned int scale, RegValue disp,
                        int reg_opcode, Buffer& gen); /* from inst-x86.C */
// VG(7/30/02): emit a fully fledged addressing mode: base+index<<scale+disp
void emitAddressingMode(unsigned base, unsigned index,
                        unsigned int scale, RegValue disp,
                        int reg_opcode, Buffer& gen); /* from inst-x86.C */

// VG(07/30/02): Emit a lea dest, [base + index * scale + disp]; dest is a
// real GPR
void emitLEA(RealRegister base, RealRegister index, unsigned int scale,
             RegValue disp, RealRegister dest, Buffer &gen); /* from inst-x86.C */

void emitLEA64Bit(Register base, Register index, unsigned int scale, int disp, Register dest, Buffer& gen); /* from emit-x86.C */

/* from inst-x86.C */
/* build the MOD/RM byte of an instruction */
static inline unsigned char makeModRMbyte(unsigned Mod, unsigned Reg,
                                          unsigned RM)
{
   return static_cast<unsigned char>(((Mod & 0x3) << 6) + ((Reg & 0x7) << 3) + (RM & 0x7));
}

/* from inst-x86.C */
// VG(7/30/02): Build the SIB byte of an instruction */
static inline unsigned char makeSIBbyte(unsigned Scale, unsigned Index,
                                        unsigned Base)
{
   return static_cast<unsigned char>(((Scale & 0x3) << 6) + ((Index & 0x7) << 3) + (Base & 0x7));
}

