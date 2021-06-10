/* Written by Bart Coppens, 2021. Based on the Dyninst example plugin */
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

using namespace std;
using namespace Dyninst;
using namespace Dyninst::PatchAPI;

// Create an instance of class BPatch
BPatch bpatch;

// Attach, create, or open a file for rewriting
BPatch_binaryEdit* startInstrumenting(const char* name) {
    bpatch.forceSaveFPR(false);

    // Open the binary file; do not open dependencies
    BPatch_binaryEdit* handle = bpatch.openBinary(name, false);
    if (!handle) { fprintf(stderr, "openBinary failed\n"); }

    //handle->loadLibrary("libc.so.6");
    handle->loadLibrary("/opt/repo/patched_binaries/libc/amd64/libc-2.31.so");
    return handle;
}

void finishInstrumenting(BPatch_addressSpace* app, const char* newName) {
    BPatch_binaryEdit* appBin = dynamic_cast<BPatch_binaryEdit*>(app);

    if (!appBin->writeFile(newName)) {
        fprintf(stderr, "writeFile failed\n");
    }
}

class NopSnippet: public Snippet {
public:
  bool generate(Point *pt, Buffer &buffer){
    buffer.push_back(uint8_t{0x90}); // nop
    return true;
  }
};

class SkipSingleByteInstructionSnippet: public Snippet {
  uint8_t skip;
public:
  SkipSingleByteInstructionSnippet(uint8_t skip) : skip(skip) {}
  bool generate(Point *pt, Buffer &buffer){
    // jmp 5 (== eb 03 <- 2+3=5)
    buffer.push_back(uint8_t{0xeb});
    buffer.push_back(skip);
    return true;
  }
};

void insertByteVectorInBuffer(const vector<uint8_t>& vec, Buffer& buffer) {
    for (auto val: vec)
        buffer.push_back(val);
}

// objdump --insn-width 15 -d lol.o  | grep --after 1 '<store' | grep -v '^--' | sed 'N;s/\n/ /' | sed -E 's#^(.*)store_([^>]+)>:[^:]+:([^m]+)(.*)# DO_STORE(\2, (vector<uint8_t>{ \3 }) ) // \4 #'   
// objdump --insn-width 15 -d lol.o  | grep --after 1 '<restore' | grep -v '^--' | sed 'N;s/\n/ /' | sed -E 's#^(.*)restore_([^>]+)>:[^:]+:([^m]+)(.*)# DO_RESTORE(\2, (vector<uint8_t>{ \3 }) ) // \4 #' 

#define DO_STORE(reg, vec) \
     if ( la.getIndex(x86_64:: reg ) >= 0 && liveVec.test(la.getIndex(x86_64:: reg ))) \
         insertByteVectorInBuffer(vec, buffer);

#define DO_RESTORE(reg, vec) DO_STORE(reg, vec)

/* I *could* look into doing this codegen automatically, but this also works and is less error-prone :-) */

class StoreRegisters: public Snippet {
  bitArray liveVec;
  LivenessAnalyzer la;
public:
  // TODO: really the liveness should be liveout here, rather than the livein!
  StoreRegisters(const bitArray& liveVec, const LivenessAnalyzer& la): liveVec(liveVec), la(la) {}
  bool generate(Point *pt, Buffer &buffer) {
    /* TODO: use rbp and and, %rsp to align stack, also leaveq in RestoreRegisters */
    //   55                      push   %rbp
    buffer.push_back(uint8_t{0x55});
    //   48 89 e5                mov    %rsp,%rbp
    insertByteVectorInBuffer(vector<uint8_t>{0x48, 0x89, 0xe5}, buffer);
    // 48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
    insertByteVectorInBuffer(vector<uint8_t>{0x48, 0x83, 0xe4, 0xf0}, buffer);

    buffer.push_back(uint8_t{0x9c}); // pushfq TODO optional?
    // 48 81 ec 90 01 00 00    sub    $0x1b8,%rsp
    insertByteVectorInBuffer(vector<uint8_t>{0x48, 0x81, 0xec, 0xb8, 0x01, 0x00, 0x00}, buffer);

/* These need to be kept up-to-date with RestoreRegisters/allregs */
 DO_STORE(rax, (vector<uint8_t>{         0x48, 0x89, 0x04, 0x24                                      }) ) // mov    %rax,(%rsp) 
 DO_STORE(rbx, (vector<uint8_t>{         0x48, 0x89, 0x5c, 0x24, 0x08                                   }) ) // mov    %rbx,0x8(%rsp) 
 DO_STORE(rcx, (vector<uint8_t>{         0x48, 0x89, 0x4c, 0x24, 0x10                                   }) ) // mov    %rcx,0x10(%rsp) 
 DO_STORE(rdx, (vector<uint8_t>{         0x48, 0x89, 0x54, 0x24, 0x18                                   }) ) // mov    %rdx,0x18(%rsp) 
 DO_STORE(rsi, (vector<uint8_t>{         0x48, 0x89, 0x74, 0x24, 0x20                                   }) ) // mov    %rsi,0x20(%rsp) 
 DO_STORE(rdi, (vector<uint8_t>{         0x48, 0x89, 0x7c, 0x24, 0x28                                   }) ) // mov    %rdi,0x28(%rsp) 
 DO_STORE(rbp, (vector<uint8_t>{         0x48, 0x89, 0x6c, 0x24, 0x30                                   }) ) // mov    %rbp,0x30(%rsp) 
 // rsp
 DO_STORE(r8,  (vector<uint8_t>{          0x4c, 0x89, 0x44, 0x24, 0x40                                   }) ) // mov    %r8,0x40(%rsp) 
 DO_STORE(r9,  (vector<uint8_t>{          0x4c, 0x89, 0x4c, 0x24, 0x48                                   }) ) // mov    %r9,0x48(%rsp) 
 DO_STORE(r10, (vector<uint8_t>{         0x4c, 0x89, 0x54, 0x24, 0x50                                   }) ) // mov    %r10,0x50(%rsp) 
 DO_STORE(r11, (vector<uint8_t>{         0x4c, 0x89, 0x5c, 0x24, 0x58                                   }) ) // mov    %r11,0x58(%rsp) 
 DO_STORE(r12, (vector<uint8_t>{         0x4c, 0x89, 0x64, 0x24, 0x60                                   }) ) // mov    %r12,0x60(%rsp) 
 DO_STORE(r13, (vector<uint8_t>{         0x4c, 0x89, 0x6c, 0x24, 0x68                                   }) ) // mov    %r13,0x68(%rsp) 
 DO_STORE(r14, (vector<uint8_t>{         0x4c, 0x89, 0x74, 0x24, 0x70                                   }) ) // mov    %r14,0x70(%rsp) 
 DO_STORE(r15, (vector<uint8_t>{         0x4c, 0x89, 0x7c, 0x24, 0x78                                   }) ) // mov    %r15,0x78(%rsp) 
 DO_STORE(xmm0, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00                       })) // movdqu %xmm0,0x80(%rsp) 
 DO_STORE(xmm1, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00                       })) // movdqu %xmm1,0x90(%rsp) 
 DO_STORE(xmm2, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00                       })) // movdqu %xmm2,0xa0(%rsp) 
 DO_STORE(xmm3, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00                       })) // movdqu %xmm3,0xb0(%rsp) 
 DO_STORE(xmm4, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00                       })) // movdqu %xmm4,0xc0(%rsp) 
 DO_STORE(xmm5, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00                       })) // movdqu %xmm5,0xd0(%rsp) 
 DO_STORE(xmm6, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00                       })) // movdqu %xmm6,0xe0(%rsp) 
 DO_STORE(xmm7, (vector<uint8_t>{        0xf3, 0x0f, 0x7f, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00                       })) // movdqu %xmm7,0xf0(%rsp) 
 DO_STORE(xmm8, (vector<uint8_t>{        0xf3, 0x44, 0x0f, 0x7f, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00                 })) // movdqu %xmm8,0x100(%rsp) 
 DO_STORE(xmm9, (vector<uint8_t>{        0xf3, 0x44, 0x0f, 0x7f, 0x8c, 0x24, 0x10, 0x01, 0x00, 0x00                 })) // movdqu %xmm9,0x110(%rsp) 
 DO_STORE(xmm10, (vector<uint8_t>{       0xf3, 0x44, 0x0f, 0x7f, 0x94, 0x24, 0x20, 0x01, 0x00, 0x00                 })) // movdqu %xmm10,0x120(%rsp) 
 DO_STORE(xmm11, (vector<uint8_t>{       0xf3, 0x44, 0x0f, 0x7f, 0x9c, 0x24, 0x30, 0x01, 0x00, 0x00                 })) // movdqu %xmm11,0x130(%rsp) 
 DO_STORE(xmm12, (vector<uint8_t>{       0xf3, 0x44, 0x0f, 0x7f, 0xa4, 0x24, 0x40, 0x01, 0x00, 0x00                 })) // movdqu %xmm12,0x140(%rsp) 
 DO_STORE(xmm13, (vector<uint8_t>{       0xf3, 0x44, 0x0f, 0x7f, 0xac, 0x24, 0x50, 0x01, 0x00, 0x00                 })) // movdqu %xmm13,0x150(%rsp) 
 DO_STORE(xmm14, (vector<uint8_t>{       0xf3, 0x44, 0x0f, 0x7f, 0xb4, 0x24, 0x60, 0x01, 0x00, 0x00                 })) // movdqu %xmm14,0x160(%rsp) 
 DO_STORE(xmm15, (vector<uint8_t>{       0xf3, 0x44, 0x0f, 0x7f, 0xbc, 0x24, 0x70, 0x01, 0x00, 0x00                 })) // movdqu %xmm15,0x170(%rsp) 

 DO_STORE(mm0, (vector<uint8_t>{        0x0f, 0x7f, 0x84, 0x24, 0x80, 0x01, 0x00, 0x00                          }) ) // movq   %mm0,0x180(%rsp)
 DO_STORE(mm1, (vector<uint8_t>{        0x0f, 0x7f, 0x8c, 0x24, 0x88, 0x01, 0x00, 0x00                          }) ) // movq   %mm1,0x188(%rsp)
 DO_STORE(mm2, (vector<uint8_t>{        0x0f, 0x7f, 0x94, 0x24, 0x90, 0x01, 0x00, 0x00                          }) ) // movq   %mm2,0x190(%rsp)
 DO_STORE(mm3, (vector<uint8_t>{        0x0f, 0x7f, 0x9c, 0x24, 0x98, 0x01, 0x00, 0x00                          }) ) // movq   %mm3,0x198(%rsp)
 DO_STORE(mm4, (vector<uint8_t>{        0x0f, 0x7f, 0xa4, 0x24, 0xa0, 0x01, 0x00, 0x00                          }) ) // movq   %mm4,0x1a0(%rsp)

 // TODO: other registers???
 return true;
  }
};

class RestoreRegisters : public Snippet {
  bitArray liveVec;
  LivenessAnalyzer la;
public:
  RestoreRegisters(const bitArray& liveVec, const LivenessAnalyzer& la): liveVec(liveVec), la(la) {}
  bool generate(Point *pt, Buffer &buffer){
/* These need to be kept up-to-date with StoreRegisters/allregs */
 DO_RESTORE(rax, (vector<uint8_t>{       0x48, 0x8b, 0x04, 0x24                                      }) ) // mov    (%rsp),%rax 
 DO_RESTORE(rbx, (vector<uint8_t>{       0x48, 0x8b, 0x5c, 0x24, 0x08                                   }) ) // mov    0x8(%rsp),%rbx 
 DO_RESTORE(rcx, (vector<uint8_t>{       0x48, 0x8b, 0x4c, 0x24, 0x10                                   }) ) // mov    0x10(%rsp),%rcx 
 DO_RESTORE(rdx, (vector<uint8_t>{       0x48, 0x8b, 0x54, 0x24, 0x18                                   }) ) // mov    0x18(%rsp),%rdx 
 DO_RESTORE(rsi, (vector<uint8_t>{       0x48, 0x8b, 0x74, 0x24, 0x20                                   }) ) // mov    0x20(%rsp),%rsi 
 DO_RESTORE(rdi, (vector<uint8_t>{       0x48, 0x8b, 0x7c, 0x24, 0x28                                   }) ) // mov    0x28(%rsp),%rdi 
 DO_RESTORE(rbp, (vector<uint8_t>{       0x48, 0x8b, 0x6c, 0x24, 0x30                                   }) ) // mov    0x30(%rsp),%rbp 
 // rsp
 DO_RESTORE(r8,  (vector<uint8_t>{        0x4c, 0x8b, 0x44, 0x24, 0x40                                   }) ) // mov    0x40(%rsp),%r8 
 DO_RESTORE(r9,  (vector<uint8_t>{        0x4c, 0x8b, 0x4c, 0x24, 0x48                                   }) ) // mov    0x48(%rsp),%r9 
 DO_RESTORE(r10, (vector<uint8_t>{       0x4c, 0x8b, 0x54, 0x24, 0x50                                   }) ) // mov    0x50(%rsp),%r10 
 DO_RESTORE(r11, (vector<uint8_t>{       0x4c, 0x8b, 0x5c, 0x24, 0x58                                   }) ) // mov    0x58(%rsp),%r11 
 DO_RESTORE(r12, (vector<uint8_t>{       0x4c, 0x8b, 0x64, 0x24, 0x60                                   }) ) // mov    0x60(%rsp),%r12 
 DO_RESTORE(r13, (vector<uint8_t>{       0x4c, 0x8b, 0x6c, 0x24, 0x68                                   }) ) // mov    0x68(%rsp),%r13 
 DO_RESTORE(r14, (vector<uint8_t>{       0x4c, 0x8b, 0x74, 0x24, 0x70                                   }) ) // mov    0x70(%rsp),%r14 
 DO_RESTORE(r15, (vector<uint8_t>{       0x4c, 0x8b, 0x7c, 0x24, 0x78                                   }) ) // mov    0x78(%rsp),%r15 
 DO_RESTORE(xmm0, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00                       })) // movdqu 0x80(%rsp),%xmm0 
 DO_RESTORE(xmm1, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00                       })) // movdqu 0x90(%rsp),%xmm1 
 DO_RESTORE(xmm2, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00                       })) // movdqu 0xa0(%rsp),%xmm2 
 DO_RESTORE(xmm3, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00                       })) // movdqu 0xb0(%rsp),%xmm3 
 DO_RESTORE(xmm4, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00                       })) // movdqu 0xc0(%rsp),%xmm4 
 DO_RESTORE(xmm5, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00                       })) // movdqu 0xd0(%rsp),%xmm5 
 DO_RESTORE(xmm6, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00                       })) // movdqu 0xe0(%rsp),%xmm6 
 DO_RESTORE(xmm7, (vector<uint8_t>{      0xf3, 0x0f, 0x6f, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00                       })) // movdqu 0xf0(%rsp),%xmm7 
 DO_RESTORE(xmm8, (vector<uint8_t>{      0xf3, 0x44, 0x0f, 0x6f, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00                 })) // movdqu 0x100(%rsp),%xmm8 
 DO_RESTORE(xmm9, (vector<uint8_t>{      0xf3, 0x44, 0x0f, 0x6f, 0x8c, 0x24, 0x10, 0x01, 0x00, 0x00                 })) // movdqu 0x110(%rsp),%xmm9 
 DO_RESTORE(xmm10, (vector<uint8_t>{     0xf3, 0x44, 0x0f, 0x6f, 0x94, 0x24, 0x20, 0x01, 0x00, 0x00                 })) // movdqu 0x120(%rsp),%xmm10 
 DO_RESTORE(xmm11, (vector<uint8_t>{     0xf3, 0x44, 0x0f, 0x6f, 0x9c, 0x24, 0x30, 0x01, 0x00, 0x00                 })) // movdqu 0x130(%rsp),%xmm11 
 DO_RESTORE(xmm12, (vector<uint8_t>{     0xf3, 0x44, 0x0f, 0x6f, 0xa4, 0x24, 0x40, 0x01, 0x00, 0x00                 })) // movdqu 0x140(%rsp),%xmm12 
 DO_RESTORE(xmm13, (vector<uint8_t>{     0xf3, 0x44, 0x0f, 0x6f, 0xac, 0x24, 0x50, 0x01, 0x00, 0x00                 })) // movdqu 0x150(%rsp),%xmm13 
 DO_RESTORE(xmm14, (vector<uint8_t>{     0xf3, 0x44, 0x0f, 0x6f, 0xb4, 0x24, 0x60, 0x01, 0x00, 0x00                 })) // movdqu 0x160(%rsp),%xmm14 
 DO_RESTORE(xmm15, (vector<uint8_t>{     0xf3, 0x44, 0x0f, 0x6f, 0xbc, 0x24, 0x70, 0x01, 0x00, 0x00                 })) // movdqu 0x170(%rsp),%xmm15 
 
 DO_RESTORE(mm0, (vector<uint8_t>{      0x0f, 0x6f, 0x84, 0x24, 0x80, 0x01, 0x00, 0x00                          }) ) // movq   0x180(%rsp),%mm0
 DO_RESTORE(mm1, (vector<uint8_t>{      0x0f, 0x6f, 0x8c, 0x24, 0x88, 0x01, 0x00, 0x00                          }) ) // movq   0x188(%rsp),%mm1
 DO_RESTORE(mm2, (vector<uint8_t>{      0x0f, 0x6f, 0x94, 0x24, 0x90, 0x01, 0x00, 0x00                          }) ) // movq   0x190(%rsp),%mm2
 DO_RESTORE(mm3, (vector<uint8_t>{      0x0f, 0x6f, 0x9c, 0x24, 0x98, 0x01, 0x00, 0x00                          }) ) // movq   0x198(%rsp),%mm3
 DO_RESTORE(mm4, (vector<uint8_t>{      0x0f, 0x6f, 0xa4, 0x24, 0xa0, 0x01, 0x00, 0x00                          }) ) // movq   0x1a0(%rsp),%mm4

    //    48 81 c4 90 01 00 00    add    $0x1b8,%rsp
    insertByteVectorInBuffer(vector<uint8_t>{0x48, 0x81, 0xc4, 0xb8, 0x01, 0x00, 0x00}, buffer);

    buffer.push_back(uint8_t{0x9d}); // popfq
    buffer.push_back(uint8_t{0xc9}); // leaveq  // TODO more efficient: get rid of the add 0x190 together with leave

    // TODO: other registers???

    return true;
  }
};

/* These need to be kept up-to-date with RestoreRegisters/StoreRegisters */
// TODO: flags
static vector<MachRegister> allregs {
    x86_64::rax, x86_64::rbx, x86_64::rcx, x86_64::rdx, x86_64::rsi, x86_64::rdi, x86_64::rbp, x86_64::rsp, /* TODO rsp is here for padding of the struct */
    x86_64::r8, x86_64::r9, x86_64::r10, x86_64::r11, x86_64::r12, x86_64::r13, x86_64::r14, x86_64::r15,
    x86_64::xmm0, x86_64::xmm1, x86_64::xmm2, x86_64::xmm3, x86_64::xmm4, x86_64::xmm5, x86_64::xmm6, x86_64::xmm7,
    x86_64::xmm8, x86_64::xmm9, x86_64::xmm10, x86_64::xmm11, x86_64::xmm12, x86_64::xmm13, x86_64::xmm14, x86_64::xmm15,
    x86_64::st0, x86_64::st1, x86_64::st2, x86_64::st3 }; // TODO the other registers (TODO st0 ... and mm0 are the same, but Dyninst picks st0??

uint32_t getTargetMemcpyStackOffsetForRegister(const MachRegister& tbd) {
    auto offset = uint32_t{ 0 };
    for (auto reg: allregs) {
        if (tbd == reg)
            return offset;
        //printf("%s -> %i\n", reg.name().c_str(), offset);
        if (reg.val() & x86_64::XMM)
            offset += 16;
        else if (reg.val() & x86_64::GPR)
            offset += 8;
        else if (reg.val() & x86_64::MMX)
            offset += 8;
    }

    printf("Couldn't find offset for register %s\n", tbd.name().c_str());
    assert(false);
    return -1;
}

// URGH Dyninst should provide this for me. Also the Visitor pattern they provide here seems not quite right.
// So HACK pattern match it to the limit!
struct DecodeAddressCalculation {
    Register base = Null_Register;
    Register index = Null_Register;
    uint8_t scale = 0;
    uint64_t displacement = 0;

    void updateWith(InstructionAST* ast) {
        construct(ast, /* fillInScale */ false, /* mustBeDeref */ true);
    }

private:
    void construct(InstructionAST* ast, bool fillInScale=false, bool mustBeDeref=false) {
        auto binOp = dynamic_cast<InstructionAPI::BinaryFunction*>(ast);
        auto reg = dynamic_cast<InstructionAPI::RegisterAST*>(ast);
        auto imm = dynamic_cast<InstructionAPI::Immediate*>(ast);
        auto deref = dynamic_cast<InstructionAPI::Dereference*>(ast);

        if (mustBeDeref && !deref) {
            printf("Not a dereference, skipping operand\n");
            return;
        }

        if (binOp)  {
            vector<InstructionAST::Ptr> children;
            binOp->getChildren(children);

            // Given that this should be an addres calculation, either add or multiply. The add can either be the displacement or the base PLUS index
            // The displacement should only happen at the top level, i.e., recursion == 0
            if (binOp->isAdd()) {
                // The two children should be both registers:
                assert(children.size() == 2);
                construct(children.at(0).get(), /* fillInScale */ false);
                construct(children.at(1).get(), /* fillInScale */ true); // Also fills in base & index
            } else if (binOp->isMultiply()) {
                assert(fillInScale);
                // Fill in index & scale
                construct(children.at(0).get(), /* fillInScale */ true);
                construct(children.at(1).get(), /* fillInScale */ true);
            } else {
                assert(false);
            }
        } else if (reg) {
            // NOTE this follows the order of AMD64_REG_NUMBERS:
            auto machreg = reg->getID();
            unsigned char amd64_reg_idx = 0;
            bool found = false;
            vector<MachRegister> regs {x86_64::rax, x86_64::rcx, x86_64::rdx, x86_64::rbx, x86_64::rsp, x86_64::rbp, x86_64::rsi, x86_64::rdi, x86_64::r8, x86_64::r9, x86_64::r10, x86_64::r11, x86_64::r12, x86_64::r13, x86_64::r14, x86_64::r15 };
            for (auto r: regs) {
                if (machreg == r) {
                    found = true;
                    break;
                }
                amd64_reg_idx++;
            }
            assert(found);

            if (base == Null_Register) {
                base = Register{amd64_reg_idx};
                printf("Base = %i\n", amd64_reg_idx);
            } else {
                assert(index == Null_Register);
                index = Register{amd64_reg_idx};
                printf("Index = %i\n", amd64_reg_idx);
            }
        } else if (imm) {
            // URGH BAH BAH BAH THIS IS JUST WRONG THAT I HAVE TO DO IT THIS WAY
            // stringstream s(imm->format(defaultStyle));

            if (fillInScale) {
                scale = atoi(imm->format(defaultStyle).c_str());
                printf("scale: %u\n", scale);
                // Scale is really encoded as the numer with which the index is shifted, convert that here:
                switch(scale) {
                    case 1: scale = 0; break;
                    case 2: scale = 1; break;
                    case 4: scale = 2; break;
                    case 8: scale = 3; break;
                    default: assert(false);
                }
            } else {
                displacement = atol(imm->format(defaultStyle).c_str());
                printf("disp: %u\n", displacement);
            }
        } else if (deref) {
            printf("Deref!\n");
            vector<InstructionAST::Ptr> children;
            deref->getChildren(children);
            assert(children.size() == 1);

            construct(children.at(0).get());
        } else {
            assert(false);
        }
    }
};

/*
 * memcpy(dst, src, len) =>
 *   isMemWrite : rdi = lea original register [memory address computation]; rsi = lea of stack-offset [address computation]
 *   !isMemWrite: rdi = lea of stack-offset; rsi = lea/mov of original register/memory address computation.
 * We need to be careful to not have overwritten any of these registers => we might need to restore/remap them first :-( (TODO NOT IMPLEMENTED YET)
 */
class Hack : public Snippet {
  bool isMemWrite;
  uint32_t rsp_offset;
  uint8_t rax_offset;
  uint8_t len;
  DecodeAddressCalculation addressCalc;
public:
  Hack(bool isMemWrite, uint32_t rsp_offset, const DecodeAddressCalculation& addressCalc, uint8_t len) : isMemWrite(isMemWrite), rsp_offset(rsp_offset), addressCalc(addressCalc), len(len) {}
  bool generate(Point *pt, Buffer &buffer){
      // TODO FOR NOW HACK

      Register base = addressCalc.base;
      Register index = addressCalc.index;
      uint8_t scale = addressCalc.scale;
      uint64_t displacement = addressCalc.displacement;

      Register destination = Null_Register;

      // First, we write the location in shm. Depending on if this is a read or write, we put this into an other register.

      // TODO: see my above note about the order in which we emit these: I think this should be OK because we first emit the
      // shm address which depends on registers in the original application, and then do the other registers which do not longer
      // depend on the original values.

      if (isMemWrite) {
          destination = REGNUM_RDI;
      } else {
          destination = REGNUM_RSI;
      }

      emitLEA64Bit(base, index, scale, displacement, destination, buffer);

      // Now comes the memory location on the stack, again, into which register we write this depends on if it is a read or write
      base = REGNUM_ESP;
      index = Null_Register;

      if (isMemWrite) {
          destination = REGNUM_RSI;
      } else {
          destination = REGNUM_RDI;
      }

      scale = 0;
      displacement = rsp_offset;

      emitLEA64Bit(base, index, scale, displacement, destination, buffer);

   // 48 c7 c2 10 00 00 00    mov    $<len>,%rdx
   buffer.push_back(uint8_t{0x48});
   buffer.push_back(uint8_t{0xc7});
   buffer.push_back(uint8_t{0xc2});
   buffer.push_back(uint8_t{len});
   buffer.push_back(uint8_t{0x00}); // TODO do these bits as well, cfr rsp_offset
   buffer.push_back(uint8_t{0x00});
   buffer.push_back(uint8_t{0x00});
   // 65 ff 14 25 00 00 00 00   callq  *%gs:0x0
   buffer.push_back(uint8_t{0x65});
   buffer.push_back(uint8_t{0xff});
   buffer.push_back(uint8_t{0x14});
   buffer.push_back(uint8_t{0x25});
   buffer.push_back(uint8_t{0x00});
   buffer.push_back(uint8_t{0x00});
   buffer.push_back(uint8_t{0x00});
   buffer.push_back(uint8_t{0x00});

    return true;
  }
};

/* TODO: I *could* emit mvee_shm_op for small (8 byte) stores / loads I guess */
/* TODO: do the IS_TAGGED_ADDRESS() check in dyninst codegen rather than in the function we call, saves the overhead of the call, will also
   allow the rewritten binary to be run outside the MVEE again */
void skipThis(Patcher& patcher, BPatch_point* point) {
    InstructionAPI::Instruction insn = point->getInsnAtPoint();
    auto skipInstruction = SkipSingleByteInstructionSnippet::create(new SkipSingleByteInstructionSnippet(insn.size()));

    PatchAPI::Point* patchpointBefore = PatchAPI::convert(point, BPatch_callBefore); // TODO callBefore -> instructionBefore oid?
    patcher.add(PushBackCommand::create(patchpointBefore, skipInstruction));
}

RegisterAST* getRegisterOperand(const InstructionAPI::Instruction& insn) {
    vector<Operand> operands;
    insn.getOperands(operands);

    assert(operands.size() == 2);
    // TODO unsupported/unneeded for now: instructions like push %(rax) reads/writes at the same time
    assert(! (insn.readsMemory() && insn.writesMemory()) );

    /* I need the opposite of  getMemoryWriteOperands()/getMemoryReadOperands() here.
       Idea is here: one of the operands will be a memory read/write operation, which will contain a deref, and the other one should
       be the register that is read from/written to, and that is the one we need! */
    Operand operand;
    if (operands.at(0).readsMemory() || operands.at(0).writesMemory())
        operand = operands.at(1);
    else
        operand = operands.at(0);
    assert(! (operand.readsMemory() || operand.writesMemory()) );

    auto registerAST = dynamic_cast<RegisterAST*>(operand.getValue().get());
    assert(registerAST);

    return registerAST;
}

uint32_t getTargetMemcpyStackOffsetForInstruction(const InstructionAPI::Instruction& insn) {
    return getTargetMemcpyStackOffsetForRegister(getRegisterOperand(insn)->getID());
};

void hackSingleInstruction(Patcher& patcher, BPatch_point* point, bool isMemWrite, uint8_t rax_offset, uint8_t len) {
    auto function = point->getFunction();
    printf("Found function %s\n", point->getFunction()->getName().c_str());

    PatchAPI::Point* patchpointBefore = PatchAPI::convert(point, BPatch_callBefore); // TODO callBefore -> instructionBefore oid?
    PatchAPI::Point* patchpointAfter = PatchAPI::convert(point, BPatch_callAfter);

    LivenessAnalyzer live(8 /* address size of x86_64 */);
    bool isLive;

    InstructionAPI::Instruction insn = point->getInsnAtPoint();
    DecodeAddressCalculation addressCalc;
    printf("Visiting this instruction's first operand!\n");
    std::vector<Operand> operands;
    insn.getOperands(operands);
    addressCalc.updateWith(operands.at(0).getValue().get());
    printf("Visiting this instruction's second operand!\n");
    addressCalc.updateWith(operands.at(1).getValue().get());

    uint32_t rsp_offset = getTargetMemcpyStackOffsetForInstruction(insn);

    auto block = Dyninst::ParseAPI::convert(point->getBlock());
    // TODO this is really just the address? (should be near block->start() in any case looking at related code. insnAddr() - func()->obj()->codeBase();?
    Offset offset = (uint64_t) point->getAddress() - (uint64_t)function->getModule()->getLoadAddr();

    ParseAPI::InsnLoc insnLoc(block, offset, insn);
    ParseAPI::Location location(ParseAPI::convert(point->getFunction()), insnLoc); // data flow requires the function to be set!
    LivenessAnalyzer la(8 /* address width of x86_64*/); // TODO ->getAddressWidth()

    // Query live registers before patch point
    bitArray liveVec;

    if (!la.query(location, LivenessAnalyzer::Before, liveVec)) {
        printf("Cannot look up liveness!!!\n");
    }

    auto skipInstruction = SkipSingleByteInstructionSnippet::create(new SkipSingleByteInstructionSnippet(insn.size()));
    auto hack = Hack::create(new Hack(isMemWrite, rsp_offset, addressCalc, len));
    
    auto storeSnippet = StoreRegisters::create(new StoreRegisters(liveVec, la));
    auto restoreSnippet = RestoreRegisters::create(new RestoreRegisters(liveVec, la)); // TODO! this should be liveout, so we don't need to restore xmm0 needlessly!

    // ignore the cmp arg to mvee_shm_op for now (TODO: ask bert about this)
    cerr << "Patching @ " << patchpointBefore << endl;
    patcher.add(PushBackCommand::create(patchpointBefore, storeSnippet));

    // storeSnippet already sets these args for now... (otherwise argAddress and argValue are wrong atm, TODO check why)

    patcher.add(PushBackCommand::create(patchpointBefore, hack));

    patcher.add(PushBackCommand::create(patchpointBefore, skipInstruction));
    cerr << "Patching @ " << patchpointAfter << endl;
    patcher.add(PushBackCommand::create(patchpointAfter, restoreSnippet));
    
    /* TODO: redzone? */
}

void handleRequest(Patcher& patcher, std::vector<BPatch_point*>& request) {
    bool do_skip = false;
    for (auto point: request) {
        if (do_skip) {
            printf("Skipping %p\n", point->getAddress());
            skipThis(patcher, point);
        } else {
            printf("Creating a request for %p\n", point->getAddress());
            do_skip = true; // next points in this request should be skipped

            auto insn = point->getInsnAtPoint();
            auto operandSize = getRegisterOperand(insn)->getID().size(); // 16 for xmm regs, 80 for mm registers, etc

            switch (insn.getOperation().getID()) {
                case e_movq: operandSize = 8; break;
                case e_movntps: operandSize = operandSize; break;
                default: assert(false && "Unsupported instruction type!");
            }

            // Each instruction copies operandSize bytes, but we have a group which contains potentially more than one of these instructions!
            operandSize = operandSize * request.size();
            printf("This %s request has an aggregated size of %u\n", insn.writesMemory() ? "write" : "read", operandSize);

            hackSingleInstruction(patcher, point, insn.writesMemory(), 0 /* rax_offset */, operandSize);
        }
    }
}

void patchInstruction(BPatch_binaryEdit* addrspace, vector<Address>& addresses) {
    PatchMgrPtr patchMgr = PatchAPI::convert(addrspace->getImage());
    Patcher patcher(patchMgr);

    std::sort(addresses.begin(), addresses.end(), std::greater<Address>()); // sort descending order, so we kan pop_back()

    /* We try and merge adjacent requests. Requirements: adjacent instructions, src/dst should be adjacent memory locations or adjacent registers! */
    std::vector<BPatch_point*> current_request;

    while (!addresses.empty()) {
        vector<BPatch_point *> points;

        Address first = addresses.back();
        addresses.pop_back();

        /* TODO factor this out with the code from the while loop */
        addrspace->getImage()->findPoints(first, points);
        assert(points.size() == 1); // TODO right now this doesn't handle addresses occuring in multiple functions

        BPatch_point* point = points[0];
        points.clear();
        InstructionAPI::Instruction insn = point->getInsnAtPoint();
        auto request_operation = insn.getOperation().getID();

        current_request.push_back(point);

        while (!addresses.empty()) {
            Address next = addresses.back();
            if (first + insn.size() != next)
                break;

            addrspace->getImage()->findPoints(next, points);
            assert(points.size() == 1);

            point = points[0];
            points.clear();

            if (request_operation != point->getInsnAtPoint().getOperation().getID())
                break;

            // TODO TODO FIXME checked for compatibility: memory locations for store/read for merging!
            // This should be relatively easy by using DecodeAddressCalculation and verifying that all registers
            // are identical, the scale should be identical, and only displacements *must* differ with a stride that equals the operation
            // size (which we now only compute in handleRequest but that can easily be factored out)
            printf("Merging %p with %p (TODO: not yet checked for compatibility: memory locations)\n", first, next);

            addresses.pop_back();
            current_request.push_back(point);

            first = next;
            insn = point->getInsnAtPoint();
        }

        handleRequest(patcher, current_request);
        current_request.clear();
    }

    patcher.commit();
}

int main(int argc, char** argv) {
    // Set up information about the program to be instrumented
	if (argc != 3) {
		printf("Usage: %s binary-to-rewrite offsets-to-rewrite-file.dyninst\n", argv[0]);
        printf("(Generate that second file with grep mplayer non-instrumented-mplayer-default.csv | cut '-d;' -f4 > mplayer-default.dyninst)\n");
        exit(1);
	}
	const char* progName = argv[1]; //"InterestingProgram";
    const char* instructionsFile = argv[2];

    // Create/attach/open a binary
    printf("Analysing %s ...\n", progName);

    BPatch_binaryEdit* app = startInstrumenting(progName);
    if (!app) {
        fprintf(stderr, "startInstrumenting failed\n");
        exit(1);
    }

    vector<Address> addresses;
    ifstream f;
    f.open(instructionsFile, ios::in);

    Address a;
    while (f >> hex >> a) {
        if (a) {
            addresses.push_back(a);
            printf("Will process instruction @ 0x%x\n", a);
        }
    }

    printf("Rewriting %s ...\n", progName);
	patchInstruction(app, addresses);

    // Finish instrumentation 
    const char* progName2 = "InterestingProgram-rewritten";
    printf("Writing output binary as %s\n", progName2),
    finishInstrumenting(app, progName2);
}
