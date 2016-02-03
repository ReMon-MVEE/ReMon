/*=============================================================================
    Linux Detours v1.0 - (c) 2011 Stijn Volckaert (svolckae@elis.ugent.be)

    This is a partial port of Microsoft's Detours Library (x86 only).

    Revision History:
        * Created by Stijn Volckaert
=============================================================================*/

#ifndef _LINUX_DETOURS_H
#define _LINUX_DETOURS_H

/*-----------------------------------------------------------------------------
    Trampoline Macros
-----------------------------------------------------------------------------*/
#define GENERATE_TRAMPOLINE \
    asm ("nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         "nop\n\t"          \
         );                 \

/*-----------------------------------------------------------------------------
    Structures
-----------------------------------------------------------------------------*/
typedef struct
{
    void* pOriginalFunction;  // Address where the patch was written
    int   OriginalOffset;     // Original jump destination offset (relative to the program counter - only for thunktable detours)
    void* pTrampoline;        // Trampoline address (only for non-thunktable detours)
    int   TrampolineSize;     // number of bytes copied from original function to trampoline
    void* nextDetour;         // Linked list
} DetourInfo;

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
extern DetourInfo* DetourList;

/*-----------------------------------------------------------------------------
    Detour Functions
-----------------------------------------------------------------------------*/
//
// This only works for thunktable detours. e.g. (Intel asm syntax):
//
// pOriginalFunction:
//   jmp pOriginalFunctionInternal
//
// pOriginalFunctionInternal:
//   push ebp
//   mov ebp, esp
//   ...
//
int  DetourFunction(void* pOriginalFunction, void* pTargetFunction);

//
// This works for any function but is only partially implemented for now
//
int  DetourFunctionWithTrampoline(void* pOriginalFunction, void* pTargetFunction, void* pTrampoline);

//
// Uses the DetourList!
//
int  DetourRemove(void* pOriginalFunction);

#endif
