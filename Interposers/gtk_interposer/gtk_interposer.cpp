/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This shared library instruments usermode hash functions that are used by
    internal hash tables in GTK. Because the hash values for these tables are
    calculated from pointers, the hash values can differ among the children.
    The different hash values lead to a different layout of the hash tables,
    which in turn can cause a table to be resized in one child but not another,
    causing mismatches.

    When one of the instrumented hash functions is intercepted, the library
    first calls the original hash function and then passes the address to the
    calculated hash value to the monitor. The monitor uses these addresses to
    give all non-master children the same hash value as the master child.

    Currently, only gtk_gc_key_hash and gtk_gc_value_hash in gtk/gtkgc.c are
    intercepted. Because these are internal functions that are not exported by
    the GTK library as symbols, simply exporting the instrumented functions
    with the same name doesn't work. Instead, this library uses debugging
    symbols to get the function addresses and then hooks them using Detours.
=============================================================================*/

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE 1
#include <stdio.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib/gtypes.h>
#include <glib/goption.h>
#include <glib.h>

#include "gtk_interposer.h"

/*-----------------------------------------------------------------------------
    write_gtk_operation
-----------------------------------------------------------------------------*/
void write_gtk_operation(int pos, guint hash)
{
    *(volatile guint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = hash;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    is_mythread_gtk_operation
-----------------------------------------------------------------------------*/
bool is_mythread_gtk_operation(int pos)
{
    return (*(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos)) == masterthread_id;
}

/*-----------------------------------------------------------------------------
    read_gtk_operation
-----------------------------------------------------------------------------*/
void read_gtk_operation(int pos, guint* result)
{
    *result = *(volatile guint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
}

/*-----------------------------------------------------------------------------
    gtk_rc_styles_hash
-----------------------------------------------------------------------------*/
// symbol not visible. Patch required in gtk/gtkrc.c
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, gtk_rc_styles_hash, (const GSList* rc_styles))
{
  DO_SYNC(guint, gtk_rc_styles_hash, __gtk_rc_styles_hash, (rc_styles), MVEE_GTK_HASH_BUFFER, sizeof(int)*2, write_gtk_operation, read_gtk_operation, is_mythread_gtk_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    gtk_gc_key_hash_hook - Calls the original gtk_gc_key_hash function and then
    passes the calculated hash value to the monitor by executing a fake syscall.
-----------------------------------------------------------------------------*/
// symbol not visible. Patch required in gtk/gtkgc.c
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, gtk_gc_key_hash, (gpointer key))
{
  DO_SYNC(guint, gtk_gc_key_hash, __gtk_gc_key_hash, (key), MVEE_GTK_HASH_BUFFER, sizeof(int)*2, write_gtk_operation, read_gtk_operation, is_mythread_gtk_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    gtk_gc_value_hash_hook - Calls the original gtk_gc_value_hash function and
    then passes the calculated hash value to the monitor by executing a fake
    syscall.
-----------------------------------------------------------------------------*/
// symbol not visible. Patch required in gtk/gtkgc.c
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, gtk_gc_value_hash, (gpointer key))
{
  DO_SYNC(guint, gtk_gc_value_hash, __gtk_gc_value_hash, (key), MVEE_GTK_HASH_BUFFER, sizeof(int)*2, write_gtk_operation, read_gtk_operation, is_mythread_gtk_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    gtk_interposer_init
-----------------------------------------------------------------------------*/
static void __attribute((constructor)) init()
{
    printf("Registering LIBGTK+2.0 Hooks...\n");

    INTERPOSER_DETOUR_HOOK(*, gtk_rc_styles_hash, 0);
    INTERPOSER_DETOUR_HOOK(*, gtk_gc_key_hash, 0);
    INTERPOSER_DETOUR_HOOK(*, gtk_gc_value_hash, 0);
}
