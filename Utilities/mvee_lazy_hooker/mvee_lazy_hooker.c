/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <link.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "mvee_lazy_hooker.h"
#include "LinuxDetours.h"
#include "../MVEE_multipolling/Inc/MVEE_fake_syscall.h"

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
hook_info*      pending_list   = NULL; // list of hooks to install
hook_info*      installed_list = NULL; // list of installed hooks
pthread_mutex_t hook_mutex     = PTHREAD_MUTEX_INITIALIZER;
static void*    (*orig_dlopen)(const char*, int) = NULL;
static void*    (*orig_dlmopen)(Lmid_t, const char*, int) = NULL;
int             initialized    = 0;
int             no_recurse     = 0;
//extern int mvee_is_interposer_region(int);

/*-----------------------------------------------------------------------------
    mvee_refresh_hook_lists
-----------------------------------------------------------------------------*/
void  mvee_check_init()
{
    //  printf("check init\n");
    //  mvee_is_interposer_region(1);
    if (!initialized)
    {
        initialized    = 1;
        pending_list   = malloc(sizeof(hook_info));
        memset(pending_list,   0, sizeof(hook_info));
        installed_list = malloc(sizeof(hook_info));
        memset(installed_list, 0, sizeof(hook_info));
    }
    //  mvee_is_interposer_region(0);
    //  printf("check init end\n");
}

/*-----------------------------------------------------------------------------
    mvee_refresh_hook_lists
-----------------------------------------------------------------------------*/
void  mvee_refresh_hook_lists()
{
    //  printf("refresh hook lists begin\n");
    mvee_check_init();

    // mvee_is_interposer_region(1);
    int        pending_hooks = 0;
    pthread_mutex_lock(&hook_mutex);
    hook_info* prev          = pending_list;
    hook_info* next_info;
    for (hook_info* info = pending_list->next_hook_info; info; info = next_info)
    {
        next_info  = info->next_hook_info;
        pending_hooks++;

        // check if the target library has been loaded yet...
        no_recurse = 1;
        void* lib_handle = !strcmp(info->target_library, "*") ? RTLD_NEXT : dlopen(info->target_library, RTLD_NOLOAD);
        no_recurse = 0;
        if (lib_handle)
        {
            //            printf("LAZY HOOKER: found lib: %s\n", info->target_library);
            // find the symbol
            void* sym = dlsym(lib_handle, info->target_func);

            if (!sym && info->use_debug_syms && info->target_library[0] != '*')
                syscall(MVEE_RESOLVE_SYMBOL, info->target_func, info->target_library, &sym);

            if (sym)
            {
                int success;
                if (info->use_trampoline)
                    success = (DetourFunctionWithTrampoline(sym, info->hook_func, info->trampoline_func) == 0);
                else
                    success = (DetourFunction(sym, info->hook_func) == 0);

                if (success)
                {
                    info->hook_installed = 1;
                    pending_hooks--;

                    //	    printf("LAZY HOOKER: successfully hooked symbol: %s in lib: %s (handle: 0x%08x)\n",
                    //	     info->target_func, info->target_library, lib_handle);

                    // move to installed list
                    if (info->hook_once)
                    {
                        prev->next_hook_info           = info->next_hook_info;
                        info->next_hook_info           = installed_list->next_hook_info;
                        installed_list->next_hook_info = info;
                    }
                }
                else
                {
                    printf("LAZY HOOKER: failed to patch func: %s\n", info->target_func);
                    prev = info;
                }

                if (info->callback_func)
                    info->callback_func(info->target_func, sym);
                continue;
            }
        }
        prev = info;
    }
    pthread_mutex_unlock(&hook_mutex);
    //  mvee_is_interposer_region(0);
    //  printf("refresh hook lists end\n");
}

/*-----------------------------------------------------------------------------
    mvee_register_hook_func

    @param target_func      symbolic name of the function to be hooked
    @param target_library   name of the library in which the target func resides
                            (or "*" if the lazy hooker can look for the func
                            in any library)
    @param hook_func        address to the func to which target func calls
                            should be redirected
    @param trampoline_func  (optional) address of the empty trampoline (use
                            INTERPOSER_DETOUR_GENERATE_HOOKFUNC to generate both
                            the hook func and the trampoline!!!)
    @param use_trampoline   if 1, LinuxDetours will assemble a trampoline which
                            can be used to call the original func
    @param hook_once        if 1, the lazy hooker will remove the hook from the
                            pending list if it was successfully installed
    @param use_debug_syms   if 1, the lazy hooker will use readelf -s -W output
                            to look for the target func. readelf can see debug
                            symbols. dladdr can not...
    @param callback_func    (optional) pointer to a callback func. Will be
                            invoked when the target func was successfully hooked
-----------------------------------------------------------------------------*/
void  mvee_register_hook_func
(
    const char*        target_func,
    const char*        target_library,
    void*              hook_func,
    void*              trampoline_func,
    int                use_trampoline,
    int                hook_once,
    int                use_debug_syms,
    mvee_hook_callback callback_func
)
{
    mvee_check_init();

    //  mvee_is_interposer_region(1);
    hook_info* info = malloc(sizeof(hook_info));
    memset(info, 0, sizeof(hook_info));
    info->target_func            = strdup(target_func);
    info->target_library         = strdup(target_library);
    info->hook_func              = hook_func;
    info->trampoline_func        = trampoline_func;
    info->hook_once              = hook_once;
    info->use_trampoline         = use_trampoline;
    info->use_debug_syms         = use_debug_syms;
    info->callback_func          = callback_func;

    pthread_mutex_lock(&hook_mutex);
    info->next_hook_info         = pending_list->next_hook_info;
    pending_list->next_hook_info = info;
    pthread_mutex_unlock(&hook_mutex);

    // mvee_is_interposer_region(0);

    mvee_refresh_hook_lists();
}

/*-----------------------------------------------------------------------------
    dlopen - interposer func
-----------------------------------------------------------------------------*/
void * dlopen(const char *pathname, int mode)
{
    if (!orig_dlopen)
        orig_dlopen = (void* (*)(const char*, int))dlsym(RTLD_NEXT, "dlopen");
    //  printf("dlopen: %s\n", pathname);
    void* result = orig_dlopen(pathname, mode);
    if (!no_recurse)
        mvee_refresh_hook_lists();
    return result;
}

/*-----------------------------------------------------------------------------
    dlmopen - interposer func
-----------------------------------------------------------------------------*/
void * dlmopen(Lmid_t lmid, const char *pathname, int mode)
{
    if (!orig_dlmopen)
        orig_dlmopen = (void* (*)(Lmid_t, const char*, int))dlsym(RTLD_NEXT, "dlmopen");
    //  printf("dlmopen: %s\n", pathname);
    void* result = orig_dlmopen(lmid, pathname, mode);
    mvee_refresh_hook_lists();
    return result;
}
