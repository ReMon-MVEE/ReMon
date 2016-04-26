/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Structure Definitions
-----------------------------------------------------------------------------*/
typedef struct _hook_info hook_info;
typedef void              (*mvee_hook_callback)(const char*, void*);

struct _hook_info
{
    char*              target_func;     // name of the function that should be detoured
    char*              target_library;  // name of the library in which the target function resides
    void*              hook_func;       // pointer to the function the detour should point to
    void*              trampoline_func; // pointer to the trampoline function (optional)
    int                use_trampoline;  // do we want to use a trampoline?
    int                use_debug_syms;  // do we want to use debugging symbols to resolve the target func?
    int                hook_once;       // set to 1 if the struct should be removed from the pending list once the hook is installed
    int                hook_installed;  // set to 1 when the hook is installed
    mvee_hook_callback callback_func;   // function to call when the hook has been installed
    struct _hook_info* next_hook_info;  // pointer to the next element in the list
};

/*-----------------------------------------------------------------------------
    MVEE Lazy Hooker API
-----------------------------------------------------------------------------*/
extern void  mvee_register_hook_func
(
    const char*        target_func,
    const char*        target_library,
    void*              hook_func,
    void*              trampoline_func,
    int                use_trampoline,
    int                hook_once,
    int                use_debug_syms,
    mvee_hook_callback callback_func
);
extern void  mvee_refresh_hook_lists(void);
