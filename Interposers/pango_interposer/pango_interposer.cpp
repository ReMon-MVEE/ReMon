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
#define PANGO_ENABLE_ENGINE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <glib.h>
#include <pango/pango-ot.h>
#include <stdio.h>
#include "pango_interposer.h"

/*-----------------------------------------------------------------------------
  Custom types
-----------------------------------------------------------------------------*/
#define DECL_guint(type, a) DECL_generic(type, a)
#define ASN_guint(a) ASN_generic(a)

/*-----------------------------------------------------------------------------
    pango_ot_ruleset_description_hash_hook
-----------------------------------------------------------------------------*/
// symbol exported by libpangoft2-1.0.so
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, pango_ot_ruleset_description_hash, (const PangoOTRulesetDescription* desc))
{
  DO_SYNC(guint,                                   /* return type for the original func */
	  pango_ot_ruleset_description_hash,       /* pointer to original func */
	  (desc),                                  /* arguments to original func */
	  MVEE_PANGO_HASH_BUFFER,                  /* identifier constant for the buffer */
	  SLAVES_DONT_CALL_ORIGINAL_FUNCTION,      /* whether or not slaves should call the function */
	  SLAVES_DONT_CHECK_RESULT,                /* whether or not slaves should check if their result matches the master's result */
	  EXECUTE_BEFORE_LOCK,                     /* execute the original function first, then lock the queue and log the result */
	  WITHOUT_STACK_LOGGING,                   /* debugging feature: should we log a partial callstack for each invocation of the hook? */
	  0);                                      /* debugging feature: depth of the callstack */
    return result;
}

/*-----------------------------------------------------------------------------
    pango_fc_font_key_hash
-----------------------------------------------------------------------------*/
// symbol was static... patch required (pango/pangofc-fontmap.c)
/*INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, pango_fc_font_key_hash, (const guint* key))
{
    DO_SYNC(guint, pango_fc_font_key_hash, __pango_fc_font_key_hash, (key), MVEE_PANGO_HASH_BUFFER, 2*sizeof(int), write_pango_guint_operation, read_pango_guint_operation, is_mythread_pango_operation, 0, 0, 1, 1, 2);
    return result;
    }*/

/*-----------------------------------------------------------------------------
    pango_fc_fontset_key_hash
-----------------------------------------------------------------------------*/
// symbol was static... patch required (pango/pangofc-fontmap.c)
/*INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, pango_fc_fontset_key_hash, (const guint* key))
{
    DO_SYNC(guint, pango_fc_fontset_key_hash, __pango_fc_fontset_key_hash, (key), MVEE_PANGO_HASH_BUFFER, 2*sizeof(int), write_pango_guint_operation, read_pango_guint_operation, is_mythread_pango_operation, 0, 0, 1, 1, 2);
    return result;
    }*/

/*-----------------------------------------------------------------------------
    pango_interposer_init
-----------------------------------------------------------------------------*/
static void __attribute__((constructor)) init()
{
    printf("Registering LIBPANGO Hooks...\n");

    INTERPOSER_DETOUR_HOOK(*, pango_ot_ruleset_description_hash, 0);
    /*    INTERPOSER_DETOUR_HOOK(*, pango_fc_font_key_hash, 0);
	  INTERPOSER_DETOUR_HOOK(*, pango_fc_fontset_key_hash, 0);*/
}
