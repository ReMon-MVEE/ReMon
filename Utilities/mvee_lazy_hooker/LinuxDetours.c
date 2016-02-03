/*=============================================================================
    Linux Detours v1.0 - (c) 2011 Stijn Volckaert (svolckae@elis.ugent.be)

    Revision History:
        * Created by Stijn Volckaert
=============================================================================*/

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "LinuxDetours.h"
#include "hde32.h"
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
DetourInfo* DetourList = (DetourInfo*)0;

/*-----------------------------------------------------------------------------
    CheckDetourList - Initialize Linked List
-----------------------------------------------------------------------------*/
void  CheckDetourList()
{
    if (DetourList == (DetourInfo*)0)
    {
        DetourList                    = (DetourInfo*)malloc(sizeof(DetourInfo));
        DetourList->nextDetour        = (void*)0;
        DetourList->pOriginalFunction = (void*)0;
        DetourList->OriginalOffset    = 0;
        DetourList->pTrampoline       = (void*)0;
        DetourList->TrampolineSize    = 0;
    }
}

void* align_to_page(void* address, int pagesize)
{
    return (void*)((unsigned int)address - (unsigned int)address % pagesize);
}

/*-----------------------------------------------------------------------------
    DetourFunctionWithTrampoline
-----------------------------------------------------------------------------*/
int  DetourFunctionWithTrampoline(void* pOriginalFunction, void* pTargetFunction, void* pTrampoline)
{
    int          pagesize              = sysconf(_SC_PAGE_SIZE);
    void*        pOriginalFunctionPage = align_to_page(pOriginalFunction, pagesize);
    void*        pTrampolinePage       = align_to_page(pTrampoline, pagesize);
    void*        pOriginalFunctionPage2;
    void*        pTrampolinePage2;
    int          mprotect_error        = 0;
    unsigned int cpysize               = 0;
    hde32s       s;
    DetourInfo*  newInfo;

    while (cpysize < 5)
    {
        cpysize += hde32_disasm((void*)((unsigned int)pOriginalFunction + cpysize), &s);

        /* this would require reassembling at the trampoline location */
        if (s.flags & F_RELATIVE)
        {
            printf("ERROR: DetourFunctionWithTrampoline - found function with relative addressing. Bailing out :(\n");
            return -1;
        }
    }

    /* check if the end of the areas that are about to be overwritten lie in a different page */
    pOriginalFunctionPage2 = align_to_page((void*)((unsigned int)pOriginalFunction + sizeof(__uint32_t)), pagesize);
    pTrampolinePage2       = align_to_page((void*)((unsigned int)pTrampoline + cpysize - 1), pagesize);

    if (mprotect(pOriginalFunctionPage, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1
        || mprotect(pTrampolinePage, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        mprotect_error = 1;

    /* if the end of the areas lie in a different page, mprotect needs to be called for that page too */
    if (!mprotect_error && pOriginalFunctionPage2 != pOriginalFunctionPage)
    {
        if (mprotect(pOriginalFunctionPage2, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
            mprotect_error = 1;
    }

    if (!mprotect_error && pTrampolinePage2 != pTrampolinePage)
    {
        if (mprotect(pTrampolinePage2, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
            mprotect_error = 1;
    }

    if (mprotect_error)
    {
        printf("ERROR: DetourFunctionWithTrampoline - Couldn't set memory access rights - errno: %d (%s)\n", errno, strerror(errno));
        return -1;
    }

    /* copy original code */
    memcpy(pTrampoline, pOriginalFunction, cpysize);
    /* assemble jmp instruction in the original function */
    *(unsigned char*)pOriginalFunction                      = 0xE9;
    /* addressing is relative to the program counter */
    *(__uint32_t*)((unsigned int)pOriginalFunction + 1)     = (__uint32_t)pTargetFunction - (__uint32_t)pOriginalFunction - 5;
    /* assemble jmp instruction in the trampoline */
    *(unsigned char*)((unsigned int)pTrampoline + cpysize)  = 0xE9;
    /* Still relative, jump over partial instructions (if any!) */
    *(__uint32_t*)((unsigned int)pTrampoline + cpysize + 1) = (__uint32_t)pOriginalFunction + cpysize - (__uint32_t)pTrampoline - 5 - cpysize;

    /* Add to detour list */
    CheckDetourList();

    /* Skip to the end of the list */
    for (newInfo = DetourList; newInfo->nextDetour != (void*)0; newInfo = (DetourInfo*)newInfo->nextDetour) ;

    /* Initialize */
    newInfo->nextDetour                                     = (DetourInfo*)malloc(sizeof(DetourInfo));
    newInfo                                                 = (DetourInfo*)newInfo->nextDetour;
    newInfo->nextDetour                                     = (void*)0;
    newInfo->pOriginalFunction                              = pOriginalFunction;
    newInfo->OriginalOffset                                 = 0;
    newInfo->pTrampoline                                    = pTrampoline;
    newInfo->TrampolineSize                                 = cpysize;

    return 0;
}

/*-----------------------------------------------------------------------------
    DetourFunction
-----------------------------------------------------------------------------*/
int  DetourFunction(void* pOriginalFunction, void* pTargetFunction)
{
    int         pagesize = sysconf(_SC_PAGE_SIZE);
    int         orig     = 0;
    DetourInfo* newInfo;

    if (mprotect((void*)((int)pOriginalFunction - (int)pOriginalFunction % pagesize), pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        printf("ERROR: DetourFunction - Couldn't set memory access rights - errno: %d (%s)\n", errno, strerror(errno));
        return -1;
    }

    /* check if the original function is a thunk */
    if (*(unsigned char*)pOriginalFunction != 0xE9)
    {
        printf("ERROR: DetourFunction - OriginalFunction is not a thunk! Use DetourFunctionWithTrampoline instead!\n");
        return -1;
    }

    orig                                                  = *(int*)((unsigned int)pOriginalFunction + 1);
    *(unsigned int*)((unsigned int)pOriginalFunction + 1) = (__uint32_t)pTargetFunction - (__uint32_t)pOriginalFunction - 5;

    /* Add to detour list */
    CheckDetourList();

    /* Skip to the end of the list */
    for (newInfo = DetourList; newInfo->nextDetour != (void*)0; newInfo = (DetourInfo*)newInfo->nextDetour) ;

    /* Initialize */
    newInfo->nextDetour                                   = (DetourInfo*)malloc(sizeof(DetourInfo));
    newInfo                                               = (DetourInfo*)newInfo->nextDetour;
    newInfo->nextDetour                                   = (void*)0;
    newInfo->pOriginalFunction                            = pOriginalFunction;
    newInfo->OriginalOffset                               = orig;
    newInfo->pTrampoline                                  = (void*)0;
    newInfo->TrampolineSize                               = 0;

    return 0;
}

/*-----------------------------------------------------------------------------
    DetourRemove
-----------------------------------------------------------------------------*/
int  DetourRemove(void* pOriginalFunction)
{
    DetourInfo* info;
    DetourInfo* prev;

    CheckDetourList();

    for (info = DetourList, prev = (DetourInfo*)0; info; prev = info, info = (DetourInfo*)info->nextDetour)
    {
        if(info->pOriginalFunction == pOriginalFunction)
        {
            if (info->pTrampoline)
            {
                memcpy(pOriginalFunction, info->pTrampoline, info->TrampolineSize);
            }
            else
            {
                *(int*)((unsigned int)info->pOriginalFunction + 1) = info->OriginalOffset;
            }

            if (info->nextDetour && prev)
                prev->nextDetour = info->nextDetour;
            free(info);
            return 0;
        }
    }

    printf("ERROR: DetourRemove - No Detour found there!\n");
    return -1;
}
